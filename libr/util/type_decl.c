/* radare - LGPL - Copyright 2026 - Codex */

#include <r_util.h>

typedef struct {
	const char *text;
	const char *cursor;
	const char *error;
	unsigned int depth;
	Sdb *types;
	RList *ordinary;
} DeclParser;

typedef struct {
	RTypeDeclNode *head;
	RTypeDeclNode **tail;
} DeclChain;

static void decl_node_free(RTypeDeclNode *node) {
	while (node) {
		RTypeDeclNode *child = node->child;
		switch (node->kind) {
		case R_TYPE_DECL_BASE:
			free (node->base.name);
			break;
		case R_TYPE_DECL_ARRAY:
			free (node->array.count);
			break;
		case R_TYPE_DECL_FUNCTION:
			r_list_free (node->function.parameters);
			break;
		case R_TYPE_DECL_POINTER:
		case R_TYPE_DECL_LVALUE_REFERENCE:
		case R_TYPE_DECL_RVALUE_REFERENCE:
			break;
		}
		free (node);
		node = child;
	}
}

R_API void r_type_decl_free(RTypeDecl *decl) {
	if (decl) {
		free (decl->name);
		decl_node_free (decl->type);
		free (decl);
	}
}

static bool decl_error(DeclParser *parser, const char *message) {
	if (!parser->error) {
		parser->error = message;
	}
	return false;
}

static void decl_skip_space(DeclParser *parser) {
	while (isspace ((ut8)*parser->cursor)) {
		parser->cursor++;
	}
}

static bool decl_ident_start(char ch) {
	return isalpha ((ut8)ch) || ch == '_';
}

static bool decl_ident_char(char ch) {
	return isalnum ((ut8)ch) || ch == '_';
}

static bool decl_word(DeclParser *parser, const char *word) {
	decl_skip_space (parser);
	size_t len = strlen (word);
	if (!strncmp (parser->cursor, word, len) && !decl_ident_char (parser->cursor[len]) && parser->cursor[len] != '.') {
		parser->cursor += len;
		return true;
	}
	return false;
}

static unsigned int decl_qualifier(DeclParser *parser) {
	if (decl_word (parser, "const")) {
		return R_TYPE_DECL_CONST;
	}
	if (decl_word (parser, "volatile")) {
		return R_TYPE_DECL_VOLATILE;
	}
	if (decl_word (parser, "restrict")) {
		return R_TYPE_DECL_RESTRICT;
	}
	if (decl_word (parser, "atomic") || decl_word (parser, "_Atomic")) {
		return R_TYPE_DECL_ATOMIC;
	}
	return 0;
}

static char *decl_identifier(DeclParser *parser, bool base) {
	decl_skip_space (parser);
	const char *start = parser->cursor;
	if (!decl_ident_start (*start)) {
		return NULL;
	}
	parser->cursor++;
	while (decl_ident_char (*parser->cursor) || *parser->cursor == '.') {
		parser->cursor++;
	}
	if (base && *parser->cursor == '<') {
		unsigned int depth = 0;
		do {
			if (*parser->cursor == '<') {
				depth++;
			} else if (*parser->cursor == '>') {
				depth--;
			}
			parser->cursor++;
		} while (*parser->cursor && depth);
		if (depth) {
			decl_error (parser, "Unclosed opaque base name");
			return NULL;
		}
	}
	char *word = r_str_ndup (start, parser->cursor - start);
	if (!word) {
		decl_error (parser, "Cannot allocate identifier");
	}
	return word;
}

typedef enum {
	DECL_BINDING_UNKNOWN,
	DECL_BINDING_TYPE,
	DECL_BINDING_ORDINARY
} DeclBinding;

static DeclBinding decl_binding(DeclParser *parser, const char *name) {
	RListIter *iter;
	const char *ordinary;
	r_list_foreach_prev (parser->ordinary, iter, ordinary) {
		if (!strcmp (ordinary, name)) {
			return DECL_BINDING_ORDINARY;
		}
	}
	const char *kind = parser->types? sdb_const_get (parser->types, name, NULL): NULL;
	if (kind && (!strcmp (kind, "typedef") || !strcmp (kind, "type"))) {
		return DECL_BINDING_TYPE;
	}
	return DECL_BINDING_UNKNOWN;
}

static bool decl_visible_type(DeclParser *parser, const char *cursor) {
	DeclParser lookahead = *parser;
	lookahead.cursor = cursor;
	char *name = decl_identifier (&lookahead, false);
	if (lookahead.error) {
		decl_error (parser, lookahead.error);
	}
	bool visible = name && decl_binding (parser, name) == DECL_BINDING_TYPE;
	free (name);
	return visible;
}

enum {
	DECL_BUILTIN_VOID, DECL_BUILTIN_CHAR, DECL_BUILTIN_SHORT, DECL_BUILTIN_INT,
	DECL_BUILTIN_LONG, DECL_BUILTIN_FLOAT, DECL_BUILTIN_DOUBLE,
	DECL_BUILTIN_SIGNED, DECL_BUILTIN_UNSIGNED, DECL_BUILTIN_BOOL, DECL_BUILTIN_CBOOL,
	DECL_BUILTIN_COUNT
};

static bool decl_builtin_valid(const unsigned int *counts) {
	if ((counts[DECL_BUILTIN_SIGNED] && counts[DECL_BUILTIN_UNSIGNED])
			|| (counts[DECL_BUILTIN_SHORT] && counts[DECL_BUILTIN_LONG])) {
		return false;
	}
	unsigned int primary = counts[DECL_BUILTIN_VOID] + counts[DECL_BUILTIN_CHAR] + counts[DECL_BUILTIN_INT]
		+ counts[DECL_BUILTIN_FLOAT] + counts[DECL_BUILTIN_DOUBLE] + counts[DECL_BUILTIN_BOOL] + counts[DECL_BUILTIN_CBOOL];
	if (primary > 1) {
		return false;
	}
	if (counts[DECL_BUILTIN_CHAR]) {
		return !counts[DECL_BUILTIN_SHORT] && !counts[DECL_BUILTIN_LONG];
	}
	if (counts[DECL_BUILTIN_DOUBLE]) {
		return !counts[DECL_BUILTIN_SIGNED] && !counts[DECL_BUILTIN_UNSIGNED]
			&& !counts[DECL_BUILTIN_SHORT] && counts[DECL_BUILTIN_LONG] <= 1;
	}
	if (counts[DECL_BUILTIN_VOID] || counts[DECL_BUILTIN_FLOAT] || counts[DECL_BUILTIN_BOOL] || counts[DECL_BUILTIN_CBOOL]) {
		return !counts[DECL_BUILTIN_SIGNED] && !counts[DECL_BUILTIN_UNSIGNED]
			&& !counts[DECL_BUILTIN_SHORT] && !counts[DECL_BUILTIN_LONG];
	}
	return true;
}

static const char *const decl_builtins[] = {
	"void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "_Bool", NULL
};

static bool decl_name_keyword(DeclParser *parser) {
	static const char *const keywords[] = {
		"auto", "break", "case", "continue", "default", "do", "else", "enum", "extern", "for", "goto", "if",
		"inline", "register", "return", "sizeof", "static", "struct", "switch", "typedef", "union", "while",
		"_Alignas", "_Alignof", "_Complex", "_Generic", "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local", NULL
	};
	DeclParser lookahead = *parser;
	if (decl_qualifier (&lookahead)) {
		return true;
	}
	int i;
	for (i = 0; decl_builtins[i]; i++) {
		if (decl_word (&lookahead, decl_builtins[i])) {
			return true;
		}
	}
	for (i = 0; keywords[i]; i++) {
		if (decl_word (&lookahead, keywords[i])) {
			return true;
		}
	}
	return false;
}

static RTypeDeclNode *decl_base(DeclParser *parser) {
	RTypeDeclNode *base = R_NEW0 (RTypeDeclNode);
	base->kind = R_TYPE_DECL_BASE;
	RStrBuf name;
	r_strbuf_init (&name);
	bool have_type = false;
	bool builtin = false;
	unsigned int counts[DECL_BUILTIN_COUNT] = { 0 };
	while (true) {
		unsigned int qualifier = decl_qualifier (parser);
		if (qualifier) {
			base->qualifiers |= qualifier;
			continue;
		}
		const char *start = parser->cursor;
		int i;
		for (i = 0; decl_builtins[i]; i++) {
			if (decl_word (parser, decl_builtins[i])) {
				break;
			}
		}
		if (decl_builtins[i] && (!have_type || builtin)) {
			if (++counts[i] > (i == DECL_BUILTIN_LONG? 2: 1)) {
				decl_error (parser, "Repeated fundamental type specifier");
				break;
			}
			if ((have_type && !r_strbuf_append (&name, " ")) || !r_strbuf_append (&name, decl_builtins[i])) {
				decl_error (parser, "Cannot allocate base type");
				break;
			}
			have_type = builtin = true;
			continue;
		}
		parser->cursor = start;
		if (have_type) {
			break;
		}
		char *word = decl_identifier (parser, true);
		if (!word) {
			decl_error (parser, "Expected a base type");
			break;
		}
		bool tagged = !strcmp (word, "struct") || !strcmp (word, "union") || !strcmp (word, "enum");
		if (!tagged && decl_binding (parser, word) == DECL_BINDING_ORDINARY) {
			free (word);
			decl_error (parser, "Ordinary identifier is not a type name");
			break;
		}
		bool ok = r_strbuf_append (&name, word);
		free (word);
		if (tagged) {
			word = decl_identifier (parser, true);
			ok = ok && word && r_strbuf_append (&name, " ") && r_strbuf_append (&name, word);
			free (word);
		}
		if (!ok) {
			decl_error (parser, "Expected a named base type");
			break;
		}
		have_type = true;
	}
	if (!parser->error && builtin && !decl_builtin_valid (counts)) {
		decl_error (parser, "Contradictory fundamental type specifiers");
	}
	if (!parser->error) {
		base->base.name = r_strbuf_drain_nofree (&name);
		if (!base->base.name) {
			decl_error (parser, "Cannot allocate base type");
		}
	}
	r_strbuf_fini (&name);
	if (parser->error) {
		decl_node_free (base);
		return NULL;
	}
	return base;
}

static void decl_chain_append(DeclChain *chain, RTypeDeclNode *node) {
	*chain->tail = node;
	chain->tail = &node->child;
}

static RTypeDecl *decl_parse(DeclParser *parser, RTypeDeclContext context, bool require_name);

static bool decl_parameters(DeclParser *parser, RTypeDeclNode *node) {
	node->function.parameters = r_list_newf ((RListFree)r_type_decl_free);
	parser->cursor++;
	decl_skip_space (parser);
	if (*parser->cursor == ')') {
		parser->cursor++;
		return true;
	}
	node->function.prototype = true;
	while (true) {
		if (!strncmp (parser->cursor, "...", 3)) {
			node->function.variadic = true;
			parser->cursor += 3;
			decl_skip_space (parser);
			if (*parser->cursor != ')') {
				return decl_error (parser, "Expected ) after ...");
			}
			parser->cursor++;
			return true;
		}
		RTypeDecl *param = decl_parse (parser, R_TYPE_DECL_CONTEXT_NAMED, false);
		if (!param) {
			return false;
		}
		bool plain_void = !param->name && param->type->kind == R_TYPE_DECL_BASE
			&& !param->type->qualifiers && !strcmp (param->type->base.name, "void");
		if (plain_void) {
			r_type_decl_free (param);
			if (*parser->cursor != ')' || !r_list_empty (node->function.parameters)) {
				return decl_error (parser, "void must be the only parameter");
			}
		} else if (!r_list_append (node->function.parameters, param)) {
			r_type_decl_free (param);
			return decl_error (parser, "Cannot allocate parameter list");
		} else if (param->name && !r_list_append (parser->ordinary, param->name)) {
			return decl_error (parser, "Cannot allocate parameter binding");
		}
		if (*parser->cursor == ')') {
			parser->cursor++;
			return true;
		}
		if (*parser->cursor != ',') {
			return decl_error (parser, "Expected , or ) after parameter");
		}
		parser->cursor++;
		decl_skip_space (parser);
	}
}

static bool decl_array(DeclParser *parser, RTypeDeclNode *node) {
	const char *start = ++parser->cursor;
	unsigned int parentheses = 0;
	while (*parser->cursor && (*parser->cursor != ']' || parentheses)) {
		char ch = *parser->cursor;
		if (ch == '(') {
			parentheses++;
		} else if (ch == ')' && parentheses) {
			parentheses--;
		} else if (ch == ')' || ch == '[' || ch == ']' || ch == ';' || ch == '{' || ch == '}') {
			return decl_error (parser, "Invalid array bound");
		}
		parser->cursor++;
	}
	if (*parser->cursor != ']') {
		return decl_error (parser, "Expected ] after array bound");
	}
	node->array.count = r_str_ndup (start, parser->cursor - start);
	if (!node->array.count) {
		return decl_error (parser, "Cannot allocate array bound");
	}
	r_str_trim (node->array.count);
	parser->cursor++;
	return true;
}

static RTypePointerKind decl_pointer_kind(DeclParser *parser) {
	DeclParser lookahead = *parser;
	RTypePointerKind kind = R_TYPE_POINTER_DEFAULT;
	if (decl_word (&lookahead, "near")) {
		kind = R_TYPE_POINTER_NEAR;
	} else if (decl_word (&lookahead, "far")) {
		kind = R_TYPE_POINTER_FAR;
	}
	decl_skip_space (&lookahead);
	if (kind != R_TYPE_POINTER_DEFAULT && *lookahead.cursor == '*') {
		parser->cursor = lookahead.cursor;
		return kind;
	}
	return R_TYPE_POINTER_DEFAULT;
}

static bool decl_declarator(DeclParser *parser, DeclChain *chain, char **name, RTypeDeclContext context, bool parameter) {
	if (parser->depth >= 64) {
		return decl_error (parser, "Declaration nesting is too deep");
	}
	parser->depth++;
	int bindings = r_list_length (parser->ordinary);
	DeclChain pointers = { 0 };
	pointers.tail = &pointers.head;
	while (true) {
		RTypePointerKind kind = decl_pointer_kind (parser);
		decl_skip_space (parser);
		bool reference = *parser->cursor == '&' && kind == R_TYPE_POINTER_DEFAULT;
		if (*parser->cursor != '*' && !reference) {
			break;
		}
		parser->cursor++;
		RTypeDeclNode *node = R_NEW0 (RTypeDeclNode);
		node->kind = R_TYPE_DECL_POINTER;
		node->pointer.kind = kind;
		if (reference) {
			node->kind = R_TYPE_DECL_LVALUE_REFERENCE;
			if (*parser->cursor == '&') {
				node->kind = R_TYPE_DECL_RVALUE_REFERENCE;
				parser->cursor++;
			}
			decl_skip_space (parser);
		} else {
			unsigned int qualifier;
			while ((qualifier = decl_qualifier (parser))) {
				node->qualifiers |= qualifier;
			}
		}
		node->child = pointers.head;
		if (!pointers.head) {
			pointers.tail = &node->child;
		}
		pointers.head = node;
	}
	if (!parser->error && *parser->cursor == '(') {
		DeclParser lookahead = *parser;
		lookahead.cursor++;
		decl_skip_space (&lookahead);
		bool grouped = *lookahead.cursor == '*' || *lookahead.cursor == '&' || *lookahead.cursor == '(' || *lookahead.cursor == '['
			|| decl_pointer_kind (&lookahead) != R_TYPE_POINTER_DEFAULT
			|| (context == R_TYPE_DECL_CONTEXT_NAMED && decl_ident_start (*lookahead.cursor) && !decl_name_keyword (&lookahead) && (!parameter || !decl_visible_type (parser, lookahead.cursor)));
		if (grouped) {
			parser->cursor++;
			if (decl_declarator (parser, chain, name, context, parameter)) {
				if (*parser->cursor == ')') {
					parser->cursor++;
				} else {
					decl_error (parser, "Expected ) after declarator");
				}
			}
		}
	} else if (!parser->error && context == R_TYPE_DECL_CONTEXT_NAMED && decl_ident_start (*parser->cursor)) {
		if (decl_name_keyword (parser)) {
			decl_error (parser, "A declaration name cannot be a keyword");
		} else {
			*name = decl_identifier (parser, false);
		}
	}
	decl_skip_space (parser);
	while (!parser->error) {
		RTypeDeclNode *node;
		if (*parser->cursor == '[') {
			node = R_NEW0 (RTypeDeclNode);
			node->kind = R_TYPE_DECL_ARRAY;
			decl_array (parser, node);
		} else if (*parser->cursor == '(') {
			node = R_NEW0 (RTypeDeclNode);
			node->kind = R_TYPE_DECL_FUNCTION;
			decl_parameters (parser, node);
		} else {
			break;
		}
		decl_chain_append (chain, node);
		decl_skip_space (parser);
	}
	*chain->tail = pointers.head;
	if (pointers.head) {
		chain->tail = pointers.tail;
	}
	while (r_list_length (parser->ordinary) > bindings) {
		r_list_pop (parser->ordinary);
	}
	parser->depth--;
	return !parser->error;
}

static RTypeDecl *decl_parse(DeclParser *parser, RTypeDeclContext context, bool require_name) {
	RTypeDeclNode *base = decl_base (parser);
	if (!base) {
		return NULL;
	}
	RTypeDecl *decl = R_NEW0 (RTypeDecl);
	DeclChain chain = { 0 };
	chain.tail = &chain.head;
	bool ok = decl_declarator (parser, &chain, &decl->name, context, !require_name);
	if (ok && require_name && !decl->name) {
		ok = decl_error (parser, "Expected a declaration name");
	}
	*chain.tail = base;
	decl->type = chain.head;
	if (!ok) {
		r_type_decl_free (decl);
		return NULL;
	}
	return decl;
}

R_API R_OWNED RTypeDecl *r_type_decl_parse(const char *text, RTypeDeclContext context, Sdb *types, char **error) {
	R_RETURN_VAL_IF_FAIL (text && (context == R_TYPE_DECL_CONTEXT_NAMED || context == R_TYPE_DECL_CONTEXT_ABSTRACT), NULL);
	if (error) {
		*error = NULL;
	}
	if (strlen (text) > INT_MAX) {
		if (error) {
			*error = strdup ("Declaration is too long");
		}
		return NULL;
	}
	DeclParser parser = { .text = text, .cursor = text, .types = types, .ordinary = r_list_new () };
	RTypeDecl *decl = decl_parse (&parser, context, context == R_TYPE_DECL_CONTEXT_NAMED);
	if (decl) {
		if (*parser.cursor == ';') {
			parser.cursor++;
			decl_skip_space (&parser);
		}
		if (*parser.cursor) {
			decl_error (&parser, "Unexpected text after declaration");
			r_type_decl_free (decl);
			decl = NULL;
		}
	}
	if (error && parser.error) {
		*error = r_str_newf ("at offset %zu: %s", (size_t)(parser.cursor - parser.text), parser.error);
	}
	r_list_free (parser.ordinary);
	return decl;
}

static bool decl_render_qualifiers(RStrBuf *out, unsigned int qualifiers) {
	return (!(qualifiers & R_TYPE_DECL_CONST) || r_strbuf_append (out, "const "))
		&& (!(qualifiers & R_TYPE_DECL_VOLATILE) || r_strbuf_append (out, "volatile "))
		&& (!(qualifiers & R_TYPE_DECL_RESTRICT) || r_strbuf_append (out, "restrict "))
		&& (!(qualifiers & R_TYPE_DECL_ATOMIC) || r_strbuf_append (out, "_Atomic "));
}

R_API R_OWNED char *r_type_decl_render(const RTypeDecl *decl, bool include_name) {
	R_RETURN_VAL_IF_FAIL (decl && decl->type, NULL);
	RStrBuf out;
	r_strbuf_init (&out);
	bool ok = !include_name || !decl->name || r_strbuf_append (&out, decl->name);
	RTypeDeclKind previous = R_TYPE_DECL_BASE;
	const RTypeDeclNode *previous_node = NULL;
	const RTypeDeclNode *node;
	for (node = decl->type; node && ok; node = node->child) {
		if (node->kind == R_TYPE_DECL_BASE || node->kind == R_TYPE_DECL_POINTER
				|| node->kind == R_TYPE_DECL_LVALUE_REFERENCE || node->kind == R_TYPE_DECL_RVALUE_REFERENCE) {
			RStrBuf prefix;
			r_strbuf_init (&prefix);
			if (node->kind == R_TYPE_DECL_BASE) {
				ok = decl_render_qualifiers (&prefix, node->qualifiers)
					&& r_strbuf_append (&prefix, node->base.name);
				if (ok && r_strbuf_length (&out)) {
					ok = r_strbuf_append (&prefix, " ");
				}
			} else {
				if (node->kind == R_TYPE_DECL_POINTER && node->pointer.kind == R_TYPE_POINTER_NEAR) {
					ok = r_strbuf_append (&prefix, "near ");
				} else if (node->kind == R_TYPE_DECL_POINTER && node->pointer.kind == R_TYPE_POINTER_FAR) {
					ok = r_strbuf_append (&prefix, "far ");
				}
				const char *symbol = "*";
				if (node->kind == R_TYPE_DECL_LVALUE_REFERENCE) {
					symbol = "&";
				} else if (node->kind == R_TYPE_DECL_RVALUE_REFERENCE) {
					symbol = "&&";
				}
				ok = ok && r_strbuf_append (&prefix, symbol);
				bool previous_prefix = previous == R_TYPE_DECL_POINTER || previous == R_TYPE_DECL_LVALUE_REFERENCE || previous == R_TYPE_DECL_RVALUE_REFERENCE;
				bool compact = node->kind == R_TYPE_DECL_POINTER && node->pointer.kind == R_TYPE_POINTER_DEFAULT && !node->qualifiers
					&& previous_node && previous_node->kind == R_TYPE_DECL_POINTER && previous_node->pointer.kind == R_TYPE_POINTER_DEFAULT && !previous_node->qualifiers;
				if (ok && (node->qualifiers || (previous_prefix && !compact && r_strbuf_length (&out)))) {
					ok = r_strbuf_append (&prefix, " ") && decl_render_qualifiers (&prefix, node->qualifiers);
				}
			}
			ok = ok && r_strbuf_prepend (&out, r_strbuf_get (&prefix));
			r_strbuf_fini (&prefix);
		} else {
			if (previous == R_TYPE_DECL_POINTER || previous == R_TYPE_DECL_LVALUE_REFERENCE || previous == R_TYPE_DECL_RVALUE_REFERENCE) {
				ok = r_strbuf_prepend (&out, "(") && r_strbuf_append (&out, ")");
			}
			if (node->kind == R_TYPE_DECL_ARRAY) {
				ok = ok && r_strbuf_appendf (&out, "[%s]", node->array.count);
			} else if (node->kind == R_TYPE_DECL_FUNCTION) {
				ok = ok && r_strbuf_append (&out, "(");
				RListIter *iter;
				RTypeDecl *param;
				r_list_foreach (node->function.parameters, iter, param) {
					char *text = r_type_decl_render (param, true);
					ok = ok && text && r_strbuf_append (&out, text);
					free (text);
					if (iter->n) {
						ok = ok && r_strbuf_append (&out, ", ");
					}
				}
				if (node->function.variadic) {
					ok = ok && (r_list_empty (node->function.parameters) || r_strbuf_append (&out, ", "))
						&& r_strbuf_append (&out, "...");
				} else if (node->function.prototype && r_list_empty (node->function.parameters)) {
					ok = ok && r_strbuf_append (&out, "void");
				}
				ok = ok && r_strbuf_append (&out, ")");
			} else {
				ok = false;
			}
		}
		previous = node->kind;
		previous_node = node;
	}
	char *text = ok? r_strbuf_drain_nofree (&out): NULL;
	r_strbuf_fini (&out);
	if (text) {
		r_str_trim (text);
	}
	return text;
}
