/* radare - LGPL - Copyright 2024-2026 - pancake */

#include <r_util.h>
#include <r_anal.h>

typedef struct {
	RStrs key;
	RStrs value;
} KVCAttr;

R_VEC_TYPE (RVecKVCAttr, KVCAttr);

typedef struct {
	Sdb *types;
	Sdb *host_types;
	bool layout_ready;
	size_t synced;
	RStrBuf *sb;
	int line;
	RVecKVCAttr attrs;
	RStrs s;
	const char *error;
	char *error_msg;
	int struct_pack;
} KVCParser;

typedef bool(*KVCParserCallback)(KVCParser *, const char *);

// serialized later with r_anal_base_type_to_kv() so parser and importers share one sdb schema
static void kvc_basetype_add_member(RAnalBaseType *bt, const char *name, const char *type, int offset, int count) {
	RAnalTypeMember *m = RVecAnalTypeMember_emplace_back (r_anal_base_type_members (bt));
	if (m) {
		m->name = strdup (name);
		m->type = strdup (type);
		m->offset = offset;
		m->count = (count > 0)? (size_t)count: 0;
	}
}

static char *collapse_whitespace(RStrs s) {
	r_strs_trim (&s);
	char *out = r_strs_tostring (s);
	if (!out) {
		return NULL;
	}
	char *d = out;
	bool in_space = false;
	for (const char *src = out; *src; src++) {
		if (isspace ((unsigned char)*src)) {
			if (!in_space) {
				*d++ = ' ';
				in_space = true;
			}
		} else {
			*d++ = *src;
			in_space = false;
		}
	}
	*d = 0;
	return out;
}

#include "pp.inc.c"

static const char kvc_getch(KVCParser *kvc) {
	if (!r_strs_empty (kvc->s)) {
		const char ch = *(kvc->s.a);
		if (ch == '\n') {
			kvc->line++;
		}
		kvc->s.a++;
		return ch;
	}
	return 0; // EOF
}

static const char kvc_peek(KVCParser *kvc, int delta) {
	return (delta >= 0)? r_strs_at (kvc->s, (size_t)delta): 0;
}

static void kvc_error(KVCParser *kvc, const char *msg) {
	free (kvc->error_msg);
	kvc->error_msg = r_str_newf ("at line %d: %s", kvc->line, msg);
	kvc->error = "Cannot parse C declaration";
	kvc->s.a = kvc->s.b;
}

static const char *kvc_peekn(KVCParser *kvc, size_t amount) {
	return (r_strs_len (kvc->s) >= amount)? kvc->s.a: NULL;
}

static const char *kvc_find(KVCParser *kvc, const char *needle) {
	return r_strs_find_strs (kvc->s, r_strs_from (needle));
}

static inline void kvc_skipn(KVCParser *kvc, size_t amount) {
	if (amount <= r_strs_len (kvc->s)) {
		size_t i;
		for (i = 0; i < amount; i++) {
			if (kvc->s.a[i] == '\n') {
				kvc->line++;
			}
		}
		kvc->s.a += amount;
	} else {
		// should not reach this, implies a bug somewhere else
		kvc->s.a = kvc->s.b;
	}
}

static const char *scan_to_semicolon(KVCParser *kvc) {
	int depth = 0;
	while (!r_strs_empty (kvc->s)) {
		char ch = kvc_peek (kvc, 0);
		if (!depth && (ch == ';' || ch == '}')) {
			return ch == ';'? kvc->s.a: NULL;
		}
		if (ch == '(' || ch == '[') {
			depth++;
		} else if (ch == ')' || ch == ']') {
			depth--;
		}
		kvc_getch (kvc);
	}
	return NULL;
}

static bool skip_until(KVCParser *kvc, char ch) {
	while (!r_strs_empty (kvc->s)) {
		const char c = kvc_peek (kvc, 0);
		if (c == ch) {
			return true;
		}
		kvc_getch (kvc);
	}
	return false;
}

static inline void skip_only_spaces(KVCParser *kvc) {
	RStrs s = kvc->s;
	r_strs_skip_chars (&s, " \t\n\r\v\f");
	kvc_skipn (kvc, s.a - kvc->s.a);
}

static void skip_spaces(KVCParser *kvc) {
	bool again;
	do {
		again = false;
		skip_only_spaces (kvc);
		const char *p = kvc_peekn (kvc, 2);
		if (p && p[0] == '/' && p[1] == '*') {
			kvc_skipn (kvc, 2);
			const char *closing = kvc_find (kvc, "*/");
			if (!closing) {
				kvc_error (kvc, "Unclosed comment");
				return;
			}
			kvc_skipn (kvc, 1 + closing - p);
			again = true;
		}
		p = kvc_peekn (kvc, 3);
		if (p && p[0] == '/' && p[1] == '/' && p[2] != '/') {
			skip_until (kvc, '\n');
			again = true;
		}
	} while (again);
}

static void skip_semicolons(KVCParser *kvc) {
	RStrs s = kvc->s;
	r_strs_skip_chars (&s, " \t\r\v\f;");
	kvc_skipn (kvc, s.a - kvc->s.a);
}

static void skip_ws(KVCParser *kvc) {
	skip_spaces (kvc);
	skip_semicolons (kvc);
	skip_spaces (kvc);
}

static const char *consume_word(KVCParser *kvc) {
	skip_only_spaces (kvc);
	const char *word = kvc->s.a;
	while (true) {
		const char ch = kvc_peek (kvc, 0);
		if (!ch) {
			return false;
		}
		if (!isalnum (ch) && ch != '_' && ch != '-') {
			break;
		}
		if (isspace (ch)) {
			break;
		}
		kvc_getch (kvc);
	}
	return word;
}

static const char *kvc_attr(KVCParser *kvc, const char *k) {
	RStrs s = r_strs_from (k);
	KVCAttr *attr;
	R_VEC_FOREACH (&kvc->attrs, attr) {
		if (r_strs_equals (attr->key, s)) {
			return r_strs_tostring (attr->value);
		}
	}
	return NULL;
}

static bool kvc_attr_add(KVCParser *kvc, RStrs key, RStrs value) {
	KVCAttr *attr = RVecKVCAttr_emplace_back (&kvc->attrs);
	if (!attr) {
		kvc_error (kvc, "Cannot allocate attribute");
		return false;
	}
	attr->key = key;
	attr->value = value;
	return true;
}

static bool parse_attributes(KVCParser *kvc) {
	skip_spaces (kvc);
	const char *begin = kvc_peekn (kvc, 3);
	if (!begin || !r_str_startswith (begin, "///")) {
		return false;
	}
	kvc_skipn (kvc, 3);

	while (true) {
		int line = kvc->line;
		skip_spaces (kvc);
		if (line != kvc->line) {
			// newline found
			return true;
		}
		char ch = kvc_peek (kvc, 0);
		if (ch != '@') {
			R_LOG_ERROR ("unexpected attribute name must start with @ its '%c'", ch);
			break;
		}
		kvc_getch (kvc);
		const char *name_start = consume_word (kvc);
		if (!name_start) {
			R_LOG_ERROR ("Cannot consume word");
			return false;
		}
		RStrs attr_name = r_strs_new (name_start, kvc->s.a);
		ch = kvc_peek (kvc, 0);
		RStrs attr_value = { 0 };
		if (ch == '(') {
			kvc_getch (kvc);
			const char *val_start = consume_word (kvc);
			if (!val_start) {
				R_LOG_ERROR ("Cannot consume word in value");
				return false;
			}
			ch = kvc_peek (kvc, 0);
			if (ch != ')') {
				R_LOG_ERROR ("Expected )");
				return false;
			}
			attr_value = r_strs_new (val_start, kvc->s.a);
			kvc_getch (kvc);
		} else {
			attr_value = R_STRS_LIT ("true");
		}
		KVCAttr *existing = NULL;
		KVCAttr *attr;
		R_VEC_FOREACH (&kvc->attrs, attr) {
			if (r_strs_equals (attr->key, attr_name)) {
				existing = attr;
				break;
			}
		}
		if (existing) {
			existing->value = attr_value;
		} else if (!kvc_attr_add (kvc, attr_name, attr_value)) {
			return false;
		}
	}
	skip_until (kvc, '\n');
	return true;
}

static bool parse_trailing_attributes(KVCParser *kvc) {
	r_strs_skip_chars (&kvc->s, " \t");
	const char *begin = kvc_peekn (kvc, 3);
	if (!begin || !r_str_startswith (begin, "///")) {
		return false;
	}
	return parse_attributes (kvc);
}

static void apply_attributes(KVCParser *kvc, const char *type, const char *scope) {
	KVCAttr *attr;
	R_VEC_FOREACH (&kvc->attrs, attr) {
		RStrs key = attr->key;
		RStrs val = attr->value;
		r_strbuf_appendf (kvc->sb, "%s.%s.@.", type, scope);
		r_strbuf_append_n (kvc->sb, key.a, r_strs_len (key));
		r_strbuf_append (kvc->sb, "=");
		r_strbuf_append_n (kvc->sb, val.a, r_strs_len (val));
		r_strbuf_append (kvc->sb, "\n");
	}
	RVecKVCAttr_clear (&kvc->attrs);
}

static void trim_underscores(RStrs *t) {
	while (t->a[0] == '_') {
		t->a++;
	}
	while (t->b > t->a) {
		t->b--;
		if (t->b[0] != '_') {
			t->b++;
			break;
		}
	}
}

static bool parse_c_attributes(KVCParser *kvc) {
	const char *p = kvc_peekn (kvc, strlen ("__attribute__"));
	if (!p || !r_str_startswith (p, "__attribute__")) {
		return false;
	}
	kvc_skipn (kvc, strlen ("__attribute__"));
	skip_spaces (kvc);
	// Expect double parentheses
	if (kvc_getch (kvc) != '(' || kvc_getch (kvc) != '(') {
		kvc_error (kvc, "Expected __attribute__ ( (...))");
		return false;
	}
	// Parse attribute name
	const char *name_start = kvc->s.a;
	while (isalnum (*kvc->s.a) || *kvc->s.a == '_') {
		kvc_getch (kvc);
	}
	RStrs attr_name = r_strs_new (name_start, kvc->s.a);
	skip_spaces (kvc);
	trim_underscores (&attr_name);
	// Parse optional value
	RStrs attr_value;
	if (kvc_peek (kvc, 0) == '(') {
		kvc_getch (kvc);
		const char *val_start = kvc->s.a;
		const char *close = kvc_find (kvc, ")");
		if (!close) {
			kvc_error (kvc, "Missing ')' in __attribute__");
			return false;
		}
		attr_value = r_strs_new (val_start, close);
		kvc_skipn (kvc, close - val_start + 1);
	} else {
		attr_value = R_STRS_LIT ("true");
	}
	skip_spaces (kvc);
	if (kvc_getch (kvc) != ')') {
		kvc_error (kvc, "Expected ')' after __attribute__");
		return false;
	}
	skip_spaces (kvc);
	// Store attribute
	if (!kvc_attr_add (kvc, attr_name, attr_value)) {
		return false;
	}
	kvc_getch (kvc);
	return true;
}

static void kvc_register_typedef(KVCParser *kvc, const char *name, const char *type) {
	sdb_set (kvc->types, name, "typedef", 0);
	sdb_setf (kvc->types, type, 0, "typedef.%s", name);
}

static char *kvc_resolve_typedef(KVCParser *kvc, const char *name) {
	const char *current = name;
	int links;
	for (links = 0; links < 4096; links++) {
		const char *target = sdb_const_getf (kvc->types, NULL, "typedef.%s", current);
		if (!target && !kvc->layout_ready && kvc->host_types) {
			target = sdb_const_getf (kvc->host_types, NULL, "typedef.%s", current);
			if (target) {
				sdb_setf (kvc->types, target, 0, "typedef.%s", current);
			}
		}
		if (!target) {
			break;
		}
		current = target;
	}
	return r_type_resolve_typedef (kvc->types, name);
}

static RTypeDecl *kvc_declaration(KVCParser *kvc, RStrs span) {
	char *text = collapse_whitespace (span);
	char *error = NULL;
	RTypeDecl *decl = text? r_type_decl_parse (text, &error): NULL;
	if (!decl) {
		kvc_error (kvc, error? error: "Cannot parse declaration");
	}
	free (error);
	free (text);
	return decl;
}

static void emit_func_signature(KVCParser *kvc, const char *name, const RTypeDeclNode *function, bool is_static) {
	RStrBuf *names = r_strbuf_new ("");
	RListIter *iter;
	RTypeDecl *param;
	int index = 0;
	r_list_foreach (function->function.parameters, iter, param) {
		RTypeDecl adjusted = *param;
		RTypeDeclNode pointer = { .kind = R_TYPE_DECL_POINTER };
		RTypeDecl *resolved = NULL;
		RTypeDeclNode *type_node = param->type;
		if (type_node->kind == R_TYPE_DECL_BASE) {
			char *target = kvc_resolve_typedef (kvc, type_node->base.name);
			resolved = target? r_type_decl_parse (target, NULL): NULL;
			free (target);
			if (resolved) {
				type_node = resolved->type;
			}
		}
		bool function_type = type_node->kind == R_TYPE_DECL_FUNCTION
			|| (type_node->kind == R_TYPE_DECL_BASE && r_str_startswith (type_node->base.name, "func."));
		if (type_node->kind == R_TYPE_DECL_ARRAY || function_type) {
			pointer.child = function_type? param->type: type_node->child;
			if (!function_type && resolved) {
				pointer.child->qualifiers |= param->type->qualifiers;
			}
			adjusted.type = &pointer;
		}
		char *type = r_type_decl_render (&adjusted, false);
		char *argument = param->name? strdup (param->name): r_str_newf ("arg%d", index);
		if (!type || !argument) {
			free (type);
			free (argument);
			r_type_decl_free (resolved);
			kvc_error (kvc, "Cannot serialize function parameter");
			break;
		}
		r_strbuf_appendf (kvc->sb, "func.%s.arg.%d=%s,%s\n", name, index, type, argument);
		r_strbuf_appendf (names, "%s%s", index? ",": "", argument);
		free (argument);
		free (type);
		r_type_decl_free (resolved);
		index++;
	}
	if (kvc->error) {
		r_strbuf_free (names);
		return;
	}
	if (function->function.variadic) {
		r_strbuf_appendf (kvc->sb, "func.%s.arg.%d=,...\n", name, index);
		r_strbuf_appendf (names, "%s...", index? ",": "");
		index++;
	}
	RTypeDecl result = { .type = function->child };
	char *ret = r_type_decl_render (&result, false);
	if (!ret) {
		kvc_error (kvc, "Cannot serialize function return type");
		r_strbuf_free (names);
		return;
	}
	r_strbuf_appendf (kvc->sb, "func.%s.cc=cdecl\nfunc.%s=%s\nfunc.%s.args=%d\nfunc.%s.ret=%s\n", name, name, r_strbuf_get (names), name, index, name, ret);
	if (is_static) {
		r_strbuf_appendf (kvc->sb, "func.%s.@.static=true\n", name);
	}
	free (ret);
	r_strbuf_free (names);
}

static char *kvc_object_type(KVCParser *kvc, RTypeDecl *decl, const char *scope) {
	RTypeDeclNode **slot = &decl->type;
	while ((*slot)->kind != R_TYPE_DECL_BASE && (*slot)->kind != R_TYPE_DECL_FUNCTION) {
		slot = &(*slot)->child;
	}
	if ((*slot)->kind == R_TYPE_DECL_BASE) {
		return r_type_decl_render (decl, false);
	}
	RTypeDeclNode *function = *slot;
	emit_func_signature (kvc, scope, function, false);
	if (kvc->error) {
		return NULL;
	}
	r_strbuf_appendf (kvc->sb, "%s=func\n", scope);
	RTypeDeclNode reference = { .kind = R_TYPE_DECL_BASE };
	reference.base.name = r_str_newf ("func.%s", scope);
	if (!reference.base.name) {
		kvc_error (kvc, "Cannot allocate function reference");
		return NULL;
	}
	*slot = &reference;
	char *type = r_type_decl_render (decl, false);
	*slot = function;
	free (reference.base.name);
	return type;
}

static bool emit_typedef_declaration(KVCParser *kvc, const char *prefix) {
	const char *start = kvc->s.a;
	const char *end = scan_to_semicolon (kvc);
	if (!end) {
		kvc_error (kvc, "Missing semicolon in typedef");
		return false;
	}
	char *text = r_str_newf ("%s%.*s", prefix? prefix: "", (int)(end - start), start);
	RTypeDecl *decl = text? kvc_declaration (kvc, r_strs_from (text)): NULL;
	free (text);
	if (!decl) {
		return false;
	}
	if (!decl->name) {
		kvc_error (kvc, "Missing typedef name");
		r_type_decl_free (decl);
		return false;
	}
	char *type = kvc_object_type (kvc, decl, decl->name);
	if (!type) {
		kvc_error (kvc, "Cannot serialize typedef");
		r_type_decl_free (decl);
		return false;
	}
	r_strbuf_appendf (kvc->sb, "typedef.%s=%s\n%s=typedef\n", decl->name, type, decl->name);
	kvc_register_typedef (kvc, decl->name, type);
	free (type);
	r_type_decl_free (decl);
	kvc_getch (kvc);
	skip_ws (kvc);
	return true;
}

static char *lookahead_alias_after_brace(KVCParser *kvc, const char *anon_prefix) {
	const char *closing = kvc_find (kvc, "}");
	if (closing) {
		const char *p = closing + 1;
		while (p < kvc->s.b && (isspace ((unsigned char)*p) || *p == ';')) {
			p++;
		}
		const char *start = p;
		while (p < kvc->s.b && (isalnum ((unsigned char)*p) || *p == '_')) {
			p++;
		}
		if (p > start) {
			return r_str_ndup (start, p - start);
		}
	}
	return r_str_newf ("%s_%d", anon_prefix, kvc->line);
}

#include "layout.inc.c"

static bool parse_struct_body(KVCParser *kvc, const char *type, const char *sn, bool is_typedef);

static bool parse_typedef(KVCParser *kvc, const char *unused) {
	skip_spaces (kvc);
	const char *next = kvc_peekn (kvc, 6);
	bool is_union = next && r_str_startswith (next, "union");
	if (next && (r_str_startswith (next, "struct") || is_union)) {
		const char *kind = is_union? "union": "struct";
		kvc_skipn (kvc, strlen (kind));
		skip_spaces (kvc);
		RStrs tag = { 0 };
		bool has_tag = kvc_peek (kvc, 0) != '{';
		if (has_tag) {
			const char *start = consume_word (kvc);
			if (!start) {
				kvc_error (kvc, "Expected aggregate tag in typedef");
				return false;
			}
			tag = r_strs_new (start, kvc->s.a);
			skip_spaces (kvc);
		}
		parse_c_attributes (kvc);
		if (kvc->error) {
			return false;
		}
		skip_spaces (kvc);
		if (kvc_peek (kvc, 0) != '{') {
			char *tag_str = has_tag? r_strs_tostring (tag): strdup ("");
			char *prefix = r_str_newf ("%s %s ", kind, tag_str);
			bool res = emit_typedef_declaration (kvc, prefix);
			free (prefix);
			free (tag_str);
			return res;
		}
		kvc_getch (kvc);
		char *name = has_tag? r_strs_tostring (tag): lookahead_alias_after_brace (kvc, is_union? "anon_union": "anon_struct");
		bool res = parse_struct_body (kvc, kind, name, true);
		free (name);
		return res;
	} else if (next && r_str_startswith (next, "enum")) {
		/* typedef enum [Tag]? { ... } Alias; */
		kvc_skipn (kvc, strlen ("enum"));
		skip_spaces (kvc);
		RStrs tag = { 0 };
		bool has_tag = false;
		if (*kvc->s.a != '{') {
			const char *tag_start = consume_word (kvc);
			if (!tag_start) {
				kvc_error (kvc, "Expected enum tag in typedef");
				return false;
			}
			tag = r_strs_new (tag_start, kvc->s.a);
			has_tag = true;
			skip_spaces (kvc);
		}
		if (kvc_peek (kvc, 0) != '{') {
			skip_spaces (kvc);
			char *tag_str = has_tag? r_strs_tostring (tag): strdup ("");
			char *prefix = r_str_newf ("enum %s ", tag_str);
			bool res = emit_typedef_declaration (kvc, prefix);
			free (prefix);
			free (tag_str);
			return res;
		}
		kvc_getch (kvc);
		char *enum_tag = has_tag? r_strs_tostring (tag): lookahead_alias_after_brace (kvc, "anon_enum");
		r_strbuf_appendf (kvc->sb, "%s=enum\n", enum_tag);
		RStrBuf *enumstr = NULL;
		apply_attributes (kvc, "enum", enum_tag);
		ut64 value = 0;
		bool closing = false;
		while (!closing) {
			parse_attributes (kvc);
			skip_spaces (kvc);
			RStrs member_value = { 0 };
			const char *name_start = consume_word (kvc);
			if (!name_start) {
				R_LOG_ERROR ("a");
				free (enum_tag);
				return false;
			}
			RStrs member_name = r_strs_new (name_start, kvc->s.a);
			skip_spaces (kvc);
			char ch = kvc_getch (kvc);
			if (ch == '=') {
				skip_spaces (kvc);
				const char *val_start = consume_word (kvc);
				if (!val_start) {
					R_LOG_ERROR ("a");
					free (enum_tag);
					return false;
				}
				member_value = r_strs_new (val_start, kvc->s.a);
				skip_spaces (kvc);
				ch = kvc_getch (kvc);
				// equal
			}
			if (ch == '}') {
				closing = true;
			} else if (ch == ',') {
				// next
			} else {
				kvc_error (kvc, "Expected , or } inside enum");
				free (enum_tag);
				return false;
			}

			char *mn = r_strs_tostring (member_name);
			apply_attributes (kvc, "enum", enum_tag);
			r_strf_var (full_scope, 512, "%s.%s", enum_tag, mn);
			if (member_value.a) {
				st64 nv = (st64)r_strs_tonum (member_value, 0, NULL);
				r_strbuf_appendf (kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, nv);
				r_strbuf_appendf (kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", enum_tag, nv, mn);
				value = nv;
			} else {
				r_strbuf_appendf (kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, (ut64)value);
				r_strbuf_appendf (kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", enum_tag, (ut64)value, mn);
			}
			if (enumstr) {
				r_strbuf_appendf (enumstr, ",%s", mn);
			} else {
				enumstr = r_strbuf_new (mn);
			}
			free (mn);
			value++;
		}
		if (enumstr) {
			char *es = r_strbuf_drain (enumstr);
			r_strbuf_appendf (kvc->sb, "enum.%s=%s\n", enum_tag, es);
			free (es);
		}
		// After the closing '}', we expect the typedef alias:
		skip_spaces (kvc);
		RStrs alias = { .a = consume_word (kvc) };
		if (!alias.a) {
			kvc_error (kvc, "Missing alias in typedef enum");
			free (enum_tag);
			return false;
		}
		alias.b = kvc->s.a;
		char *alias_str = r_strs_tostring (alias);
		r_strbuf_appendf (kvc->sb, "typedef.%s=enum %s\n", alias_str, enum_tag);
		r_strbuf_appendf (kvc->sb, "%s=enum\n", alias_str);
		skip_ws (kvc);
		free (enum_tag);
		free (alias_str);
		return true;
	} else {
		return emit_typedef_declaration (kvc, NULL);
	}
}

static bool parse_struct(KVCParser *kvc, const char *type) {
	RStrs struct_name = { .a = consume_word (kvc) };
	if (!struct_name.a) {
		R_LOG_ERROR ("Cannot consume word");
		return false;
	}
	struct_name.b = kvc->s.a;
	skip_spaces (kvc);
	parse_c_attributes (kvc);
	if (kvc->error) {
		return false;
	}
	skip_spaces (kvc);
	const char p0 = kvc_peek (kvc, 0);
	if (p0 == ';') {
		// forward declaration: struct Foo;
		kvc_getch (kvc);
		return true;
	}
	if (p0 != '{') {
		char *sn = r_strs_tostring (struct_name);
		R_LOG_ERROR ("Expected { after '%s' at line %d in struct", sn, kvc->line);
		free (sn);
		return false;
	}
	kvc_getch (kvc);
	char *sn = r_strs_tostring (struct_name);
	bool res = parse_struct_body (kvc, type, sn, false);
	free (sn);
	return res;
}

static bool parse_struct_body(KVCParser *kvc, const char *type, const char *sn, bool is_typedef) {
	const bool is_union = !strcmp (type, "union");
	RAnalBaseType *bt = r_anal_base_type_new (is_union
		? R_ANAL_BASE_TYPE_KIND_UNION: R_ANAL_BASE_TYPE_KIND_STRUCT);
	if (!bt) {
		return false;
	}
	bt->name = strdup (sn);
	const char *pack_attr = kvc_attr (kvc, "pack");
	const char *packed_attr = kvc_attr (kvc, "packed");
	if (pack_attr) {
		kvc->struct_pack = atoi (pack_attr);
	} else if (packed_attr) {
		kvc->struct_pack = 1;
	} else {
		kvc->struct_pack = 0;
	}
	free ((void *)pack_attr);
	free ((void *)packed_attr);
	const char *aligned_attr = kvc_attr (kvc, "aligned");
	int align = aligned_attr? R_MAX (1, atoi (aligned_attr)): 1;
	free ((void *)aligned_attr);
	apply_attributes (kvc, type, sn);
	int off = 0;
	while (true) {
		parse_attributes (kvc);
		if (kvc->error) {
			break;
		}
		skip_spaces (kvc);
		if (kvc_peek (kvc, 0) == '}') {
			kvc_getch (kvc);
			break;
		}
		const char *start = kvc->s.a;
		const char *end = scan_to_semicolon (kvc);
		if (!end) {
			kvc_error (kvc, "Missing semicolon in struct member");
			break;
		}
		const char *attr = r_strs_find_strs (r_strs_new (start, end), R_STRS_LIT ("__attribute__"));
		const char *decl_end = attr? attr: end;
		if (attr) {
			kvc->s.a = attr;
			if (!parse_c_attributes (kvc)) {
				break;
			}
			kvc->s.a = end;
		}
		RTypeDecl *decl = kvc_declaration (kvc, r_strs_new (start, decl_end));
		if (!decl) {
			break;
		}
		if (!decl->name) {
			kvc_error (kvc, "Missing struct member name");
			r_type_decl_free (decl);
			break;
		}
		kvc_getch (kvc);
		parse_trailing_attributes (kvc);
		int count = 0;
		RTypeDeclNode *outer = decl->type;
		if (outer->kind == R_TYPE_DECL_ARRAY && *outer->array.count) {
			ut64 dimension;
			const char *error = NULL;
			if (!r_type_array_bound_from_db (kvc->host_types, outer->array.count, &dimension, &error) || !dimension || dimension > INT_MAX) {
				kvc_error (kvc, error? error: "Array dimension exceeds parser limit");
				r_type_decl_free (decl);
				break;
			}
			count = dimension;
			decl->type = outer->child;
		}
		char *scope = r_str_newf ("%s.%s", sn, decl->name);
		char *member_type = scope? kvc_object_type (kvc, decl, scope): NULL;
		if (!member_type) {
			free (scope);
			decl->type = outer;
			r_type_decl_free (decl);
			kvc_error (kvc, "Cannot serialize aggregate member");
			break;
		}
		int member_off = kvc_layout_member (kvc, bt, member_type, count? count: 1, &off, &align);
		kvc_basetype_add_member (bt, decl->name, member_type, member_off, count);
		if (is_typedef && !is_union) {
			r_strbuf_appendf (kvc->sb, "struct.%s.meta=0\n", scope);
		}
		apply_attributes (kvc, type, scope);
		free (scope);
		free (member_type);
		decl->type = outer;
		r_type_decl_free (decl);
		if (kvc->error) {
			break;
		}
	}
	if (kvc->error) {
		r_anal_base_type_free (bt);
		return false;
	}
	skip_ws (kvc);
	if (is_typedef) {
		RStrs alias = { .a = consume_word (kvc) };
		if (!alias.a || alias.a == kvc->s.a) {
			kvc_error (kvc, "Missing alias in aggregate typedef");
			r_anal_base_type_free (bt);
			return false;
		}
		alias.b = kvc->s.a;
		char *alias_str = r_strs_tostring (alias);
		bool distinct_alias = strcmp (alias_str, sn);
		if (distinct_alias) {
			char *target = r_str_newf ("%s %s", type, sn);
			r_strbuf_appendf (kvc->sb, "typedef.%s=%s\n", alias_str, target);
			kvc_register_typedef (kvc, alias_str, target);
			free (target);
		}
		kvc_basetype_emit (kvc, bt, align);
		if (distinct_alias) {
			r_strbuf_appendf (kvc->sb, "%s=typedef\n", alias_str);
		}
		free (alias_str);
		skip_ws (kvc);
	} else {
		kvc_basetype_emit (kvc, bt, align);
	}
	return !kvc->error;
}

static bool parse_enum(KVCParser *kvc, const char *name) {
	parse_attributes (kvc);
	RStrs enum_name = { .a = consume_word (kvc) };
	if (!enum_name.a) {
		R_LOG_ERROR ("Cannot consume a word");
		return false;
	}
	enum_name.b = kvc->s.a;
	char *en = r_strs_tostring (enum_name);
	r_strbuf_appendf (kvc->sb, "%s=enum\n", en);
	RStrBuf *enumstr = NULL;
	apply_attributes (kvc, "enum", en);
	skip_spaces (kvc);
	const char p0 = kvc_peek (kvc, 0);
	if (p0 != '{') {
		R_LOG_ERROR ("Expected { after '%s' at line %d in enum", en, kvc->line);
		free (en);
		return false;
	}
	kvc_getch (kvc);
	ut64 value = 0;
	bool closing = false;
	while (!closing) {
		parse_attributes (kvc);
		skip_spaces (kvc);
		RStrs member_value = { 0 };
		const char *name_start = consume_word (kvc);
		if (!name_start) {
			R_LOG_ERROR ("a");
			return false;
		}
		RStrs member_name = r_strs_new (name_start, kvc->s.a);
		skip_spaces (kvc);
		char ch = kvc_getch (kvc);
		if (ch == '=') {
			skip_spaces (kvc);
			const char *val_start = consume_word (kvc);
			if (!val_start) {
				R_LOG_ERROR ("a");
				return false;
			}
			member_value = r_strs_new (val_start, kvc->s.a);
			skip_spaces (kvc);
			ch = kvc_getch (kvc);
			// equal
		}
		if (ch == '}') {
			closing = true;
		} else if (ch == ',') {
			// next
		} else {
			kvc_error (kvc, "Expected , or } inside enum");
			free (en);
			return false;
		}

		char *mn = r_strs_tostring (member_name);
		apply_attributes (kvc, "enum", en);
		r_strf_var (full_scope, 512, "%s.%s", en, mn);
		if (member_value.a) {
			st64 nv = (st64)r_strs_tonum (member_value, 0, NULL);
			r_strbuf_appendf (kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, nv);
			r_strbuf_appendf (kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", en, nv, mn);
			value = nv;
		} else {
			r_strbuf_appendf (kvc->sb, "enum.%s=0x%" PFMT64x "\n", full_scope, (ut64)value);
			r_strbuf_appendf (kvc->sb, "enum.%s.0x%" PFMT64x "=%s\n", en, (ut64)value, mn);
		}
		if (enumstr) {
			r_strbuf_appendf (enumstr, ",%s", mn);
		} else {
			enumstr = r_strbuf_new (mn);
		}
		free (mn);
		value++;
	}
	if (enumstr) {
		char *es = r_strbuf_drain (enumstr);
		r_strbuf_appendf (kvc->sb, "enum.%s=%s\n", en, es);
		free (es);
	}
	skip_ws (kvc);
	free (en);
	return true;
}

static bool parse_function(KVCParser *kvc) {
	parse_attributes (kvc);
	skip_spaces (kvc);
	while (parse_c_attributes (kvc)) {
		skip_spaces (kvc);
	}
	if (kvc->error) {
		return false;
	}
	const char *prefix = kvc_peekn (kvc, 7);
	bool is_static = prefix && !strncmp (prefix, "static", 6) && isspace ((ut8)prefix[6]);
	if (is_static) {
		kvc_skipn (kvc, 6);
		skip_spaces (kvc);
	}
	const char *start = kvc->s.a;
	const char *end = scan_to_semicolon (kvc);
	if (!end) {
		end = kvc->s.a;
	}
	RTypeDecl *decl = kvc_declaration (kvc, r_strs_new (start, end));
	if (!decl) {
		return false;
	}
	if (!decl->name || decl->type->kind != R_TYPE_DECL_FUNCTION) {
		kvc_error (kvc, "Expected a named function declaration");
		r_type_decl_free (decl);
		return false;
	}
	r_strbuf_appendf (kvc->sb, "%s=func\n", decl->name);
	apply_attributes (kvc, "func", decl->name);
	emit_func_signature (kvc, decl->name, decl->type, is_static);
	r_type_decl_free (decl);
	skip_ws (kvc);
	return true;
}

static void kvcparser_init(KVCParser *kvc, const char *data) {
	RVecKVCAttr_init (&kvc->attrs);
	kvc->types = sdb_new0 ();
	kvc->line = 1;
	kvc->sb = r_strbuf_new ("");
	kvc->s.a = data;
	kvc->s.b = data + strlen (data);
}

static void kvcparser_fini(KVCParser *kvc) {
	RVecKVCAttr_fini (&kvc->attrs);
	sdb_free (kvc->types);
	r_strbuf_free (kvc->sb);
	free (kvc->error_msg);
}

static bool tryparse(KVCParser *kvc, const char *word, const char *type, KVCParserCallback cb) {
	if (r_str_startswith (word, type)) {
		kvc_skipn (kvc, strlen (type));
		const char ch = kvc_getch (kvc);
		if (isspace (ch)) {
			skip_spaces (kvc);
			return cb? cb (kvc, type): true;
		}
	}
	return false;
}

R_IPI char *kvc_parse(RAnal *anal, const char *header_content, char **errmsg) {
	// Initialize a preprocessing state for this parse
	PPState *pps = pp_new ();
	char *pre = pp_preprocess (pps, header_content);
	if (!pre) {
		pp_free (pps);
		return NULL;
	}
	pp_free (pps);
	KVCParser _kvc = { 0 };
	KVCParser *kvc = &_kvc;
	kvcparser_init (&_kvc, pre);
	kvc->host_types = anal? anal->sdb_types: NULL;
	while (!r_strs_empty (kvc->s)) {
		skip_ws (kvc);
		if (r_strs_empty (kvc->s)) {
			break;
		}
		const char *word = kvc_peekn (kvc, 6);
		bool hasparse = false;
		if (word) {
#if 1
			hasparse = tryparse (kvc, word, "typedef", parse_typedef);
			hasparse |= tryparse (kvc, word, "struct", parse_struct);
			hasparse |= tryparse (kvc, word, "union", parse_struct);
			hasparse |= tryparse (kvc, word, "enum", parse_enum);
#else
			hasparse = tryparse (kvc, word, "typedef", parse_typedef);
			if (!hasparse) {
				hasparse = tryparse (kvc, word, "struct", parse_struct);
			}
			if (!hasparse) {
				hasparse = tryparse (kvc, word, "union", parse_struct);
			}
			if (!hasparse) {
				hasparse = tryparse (kvc, word, "enum", parse_enum);
			}
#endif
		}
		if (kvc->error) {
			break;
		}
		if (hasparse) {
			continue;
		}
		if (parse_attributes (kvc)) {
			continue;
		}
		if (!parse_function (kvc)) {
			kvc_getch (kvc);
		}
	}
	char *res = NULL;
	if (kvc->error && errmsg) {
		*errmsg = strdup (r_str_get_fail (kvc->error_msg, kvc->error));
	}
	if (!kvc->error) {
		res = r_strbuf_drain (kvc->sb);
		kvc->sb = NULL;
	}
	kvcparser_fini (kvc);
	free (pre);
	return res;
}

#if MAIN
int main(int argc, char *argv[]) {
	if (argc < 2) {
		eprintf ("Usage: %s <header_file.h>\n", argv[0]);
		return 1;
	}

	char *content = r_file_slurp (argv[1], NULL);
	if (!content) {
		R_LOG_ERROR ("Failed to read file: %s", argv[1]);
		return 1;
	}

	char *errmsg = NULL;
	char *result = kvc_parse (NULL, (const char *)content, &errmsg);
	if (errmsg) {
		R_LOG_ERROR ("Parsing problem %s", errmsg);
		free (errmsg);
	}
	if (result) {
		printf ("%s\n", result);
		free (result);
	}

	free (content);
	return 0;
}
#endif
