/* radare - LGPL - Copyright 2013-2026 - pancake, oddcoder, sivaramaaa */

// R2R db/cmd/types

#include <r_util.h>

R_API bool r_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val) {
	const char *kind = sdb_const_getf (TDB, NULL, "link.%08" PFMT64x, at);
	if (kind) {
		const char *p = sdb_const_get (TDB, kind, NULL);
		if (p) {
			char *v = r_str_newf ("%s.%s.%s", p, kind, field);
			ut64 off = 0;
			char *mtype = r_type_get_member (TDB, v, &off, NULL);
			free (mtype);
			free (v);
			eprintf ("wv 0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", val, at + off);
			return true;
		}
		R_LOG_ERROR ("Invalid kind of type");
	}
	return false;
}

static char *type_unqualified(const char *type) {
	RTypeDecl *decl = r_type_decl_parse (type, NULL);
	if (!decl || decl->name) {
		r_type_decl_free (decl);
		return NULL;
	}
	RTypeDeclNode *node;
	for (node = decl->type; node; node = node->child) {
		node->qualifiers = 0;
	}
	char *text = r_type_decl_render (decl, false);
	r_type_decl_free (decl);
	return text;
}

static const char *type_aggregate_prefixed(const char *R_NONNULL type, const char **R_NONNULL name) {
	const char *kind = r_str_startswith (type, "struct")? "struct": r_str_startswith (type, "union")? "union": NULL;
	if (kind) {
		size_t klen = strlen (kind);
		if (IS_WHITESPACE (type[klen])) {
			*name = r_str_trim_head_ro (type + klen);
			return R_STR_ISNOTEMPTY (*name)? kind: NULL;
		}
	}
	return NULL;
}

R_API RTypeKind r_type_kind(Sdb *TDB, const char *name) {
	R_RETURN_VAL_IF_FAIL (TDB && name, R_TYPE_INVALID);
	RTypeDecl *decl = r_type_decl_parse (name, NULL);
	if (!decl || decl->name || decl->type->kind != R_TYPE_DECL_BASE) {
		r_type_decl_free (decl);
		return R_TYPE_INVALID;
	}
	const char *bare = decl->type->base.name;
	if (r_str_startswith (bare, "struct ") || r_str_startswith (bare, "union ") || r_str_startswith (bare, "enum ")) {
		bare = strchr (bare, ' ') + 1;
	}
	const char *kind = sdb_const_get (TDB, bare, NULL);
	RTypeKind result = R_TYPE_INVALID;
	if (kind) {
		if (!strcmp (kind, "type")) {
			result = R_TYPE_BASIC;
		} else if (!strcmp (kind, "struct")) {
			result = R_TYPE_STRUCT;
		} else if (!strcmp (kind, "union")) {
			result = R_TYPE_UNION;
		} else if (!strcmp (kind, "enum")) {
			result = R_TYPE_ENUM;
		} else if (!strcmp (kind, "typedef")) {
			result = R_TYPE_TYPEDEF;
		} else if (!strcmp (kind, "func")) {
			result = R_TYPE_FUNCTION;
		}
	}
	r_type_decl_free (decl);
	return result;
}

// key is "struct.name.member" holding "type,offset,count"; split from the end since the type may itself contain commas
R_API R_OWNED char *r_type_get_member(Sdb *TDB, const char *key, ut64 *offset, int *count) {
	R_RETURN_VAL_IF_FAIL (TDB && key, NULL);
	if (offset) {
		*offset = 0;
	}
	if (count) {
		*count = 0;
	}
	char *val = sdb_get (TDB, key, NULL);
	if (R_STR_ISEMPTY (val)) {
		free (val);
		return NULL;
	}
	char *last = (char *)r_str_rchr (val, NULL, ',');
	if (!last) {
		return val;
	}
	*last = 0;
	char *mid = (char *)r_str_rchr (val, last - 1, ',');
	const char *offstr = last + 1;
	if (mid) {
		*mid = 0;
		offstr = mid + 1;
		if (count) {
			*count = (int)sdb_atoi (last + 1);
		}
	}
	if (offset) {
		*offset = sdb_atoi (offstr);
	}
	return val;
}

R_API RList *r_type_get_enum(Sdb *TDB, const char *name) {
	R_RETURN_VAL_IF_FAIL (TDB && name, NULL);
	char *p, var[130];
	int n;

	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	RList *res = r_list_newf ( (RListFree)r_type_enum_free);
	snprintf (var, sizeof (var), "enum.%s", name);
	for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
		RTypeEnum *member = R_NEW0 (RTypeEnum);
		if (member) {
			char *var2 = r_str_newf ("%s.%s", var, p);
			if (var2) {
				char *val = sdb_array_get (TDB, var2, 0, NULL);
				if (val) {
					member->name = p;
					member->val = val;
					r_list_append (res, member);
				} else {
					free (member);
				}
				free (var2);
			} else {
				free (member);
			}
		}
	}
	return res;
}

R_API void r_type_enum_free(RTypeEnum *member) {
	if (member) {
		free (member->name);
		free (member->val);
		free (member);
	}
}

R_API char *r_type_enum_member(Sdb *TDB, const char *name, const char *member, ut64 val) {
	R_RETURN_VAL_IF_FAIL (TDB && name, NULL);
	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	const char *res = member
		? sdb_const_getf (TDB, NULL, "enum.%s.%s", name, member)
		: sdb_const_getf (TDB, NULL, "enum.%s.0x%" PFMT64x, name, val);
	if (!res) {
		res = sdb_const_getf (TDB, NULL, "enum.%s.%" PFMT64d, name, val);
	}
	return res? strdup (res): NULL;
}

R_API char *r_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val) {
	R_RETURN_VAL_IF_FAIL (TDB && name, NULL);
	if (r_type_kind (TDB, name) != R_TYPE_ENUM) {
		return NULL;
	}
	bool isFirst = true;
	RStrBuf *sb = r_strbuf_newf ("0x%08" PFMT64x " : ", val);
	int i;
	for (i = 0; i < 32; i++) {
		ut32 n = 1ULL << i;
		if (! (val & n)) {
			continue;
		}
		const char *res = sdb_const_getf (TDB, NULL, "enum.%s.0x%x", name, n);
		if (isFirst) {
			isFirst = false;
		} else {
			r_strbuf_append (sb, " | ");
		}
		if (res) {
			r_strbuf_append (sb, res);
		} else {
			r_strbuf_appendf (sb, "0x%x", n);
		}
	}
	return r_strbuf_drain (sb);
}


static bool type_ident_char(char c) {
	return c == '_' || isalnum ((ut8)c);
}

// word-boundary match, so "long unsigned int" is unsigned but a "myunsigned_t" typedef is not
static bool type_has_word(const char *R_NONNULL type, const char *R_NONNULL word) {
	const size_t wlen = strlen (word);
	const char *p = type;
	while ((p = strstr (p, word))) {
		if ((p == type || !type_ident_char (p[-1])) && !type_ident_char (p[wlen])) {
			return true;
		}
		p += wlen;
	}
	return false;
}

static bool type_has_any_word(const char *R_NONNULL type, const char *const *R_NONNULL words) {
	int i;
	for (i = 0; words[i]; i++) {
		if (type_has_word (type, words[i])) {
			return true;
		}
	}
	return false;
}

// Bound on the typedef links one resolution follows. It is a work budget, not
// the cycle test: a chain longer than this without a cycle is refused too.
#define TYPEDEF_MAX_CHAIN 4096

static inline const char *typedef_target(Sdb *R_NONNULL TDB, const char *R_NONNULL name) {
	return sdb_const_getf (TDB, NULL, "typedef.%s", name);
}

// Follow typedef.<name> to the first name that is not a typedef. The links form
// a functional graph, so Brent's algorithm finds a cycle exactly in O(chain)
// lookups and O(1) memory; a cycle has no end, and resolves to NULL.
R_API R_OWNED char *r_type_resolve_typedef(Sdb *R_NONNULL TDB, const char *R_NONNULL type) {
	R_RETURN_VAL_IF_FAIL (TDB && type, NULL);
	// a typedef may be spelled with qualifiers; the sdb keys it bare
	char *normalized = type_unqualified (type);
	if (!normalized) {
		return NULL;
	}
	const char *tortoise = normalized;
	const char *hare = typedef_target (TDB, tortoise);
	int power = 1, lam = 1, links;
	for (links = 1; hare && links <= TYPEDEF_MAX_CHAIN; links++) {
		if (!strcmp (tortoise, hare)) {
			R_LOG_DEBUG ("typedef %s is cyclic", type);
			free (normalized);
			return NULL;
		}
		const char *next = typedef_target (TDB, hare);
		if (!next) {
			char *result = strdup (hare);
			free (normalized);
			return result;
		}
		if (power == lam) {
			tortoise = hare;
			power *= 2;
			lam = 0;
		}
		hare = next;
		lam++;
	}
	if (hare) {
		R_LOG_DEBUG ("typedef %s is longer than %d links", type, TYPEDEF_MAX_CHAIN);
	}
	free (normalized);
	return NULL;
}

// floats are listed here because this answers "may i sign-extend a raw slot", not "may it be negative"
static const char *const unsigned_type_words[] = {
	"unsigned", "float", "double", NULL
};

static const char *const signed_type_words[] = {
	"signed", "short", "int", "long", // bare char signedness is per-ABI, so it stays unsigned here
	"ssize_t", "ptrdiff_t", "off_t", "pid_t", "time_t", NULL
};

static bool type_name_is_signed(const char *R_NONNULL t) {
	if (type_has_any_word (t, unsigned_type_words)) {
		return false;
	}
	// intN_t and friends; their unsigned twins start with "u", so no word matches them
	return type_has_any_word (t, signed_type_words)
		|| (r_str_startswith (t, "int") && r_str_endswith (t, "_t"));
}

R_API bool r_type_is_signed(Sdb *TDB, const char *type) {
	R_RETURN_VAL_IF_FAIL (TDB && type, false);
	char *resolved = r_type_resolve_typedef (TDB, type);
	RTypeDecl *decl = r_type_decl_parse (resolved? resolved: type, NULL);
	bool result = decl && !decl->name && decl->type->kind == R_TYPE_DECL_BASE && type_name_is_signed (decl->type->base.name);
	r_type_decl_free (decl);
	free (resolved);
	return result;
}

static bool type_kind_is_aggregate(const char *R_NONNULL kind) {
	return !strcmp (kind, "struct") || !strcmp (kind, "union");
}

#define TYPE_CHAIN_MAX 32

static const char *type_aggregate_kind(Sdb *TDB, const char *type, char **name) {
	*name = NULL;
	RTypeDecl *decl = r_type_decl_parse (type, NULL);
	if (!decl || decl->name || decl->type->kind != R_TYPE_DECL_BASE) {
		r_type_decl_free (decl);
		return NULL;
	}
	const char *bare = decl->type->base.name;
	const char *kind = type_aggregate_prefixed (bare, &bare);
	if (!kind) {
		const char *stored = sdb_const_get (TDB, bare, NULL);
		kind = stored && type_kind_is_aggregate (stored)? stored: NULL;
	}
	if (kind) {
		*name = strdup (bare);
	}
	r_type_decl_free (decl);
	return kind;
}

static char *type_get_memb(Sdb *R_NONNULL TDB, const char *R_NONNULL kind, const char *R_NONNULL type, int offset, const char *R_NONNULL path) {
	int i, next_offset = 0;

	if (offset < 0) {
		return NULL;
	}
	const char *value = sdb_const_getf (TDB, NULL, "%s.%s", kind, type);
	char *members = value? strdup (value): NULL;
	if (!members) {
		return NULL;
	}
	char *res = NULL;
	bool is_struct = !strcmp (kind, "struct");
	int nargs = r_str_split (members, ',');
	for (i = 0; i < nargs; i++) {
		const char *name = r_str_word_get0 (members, i);
		const char *value = sdb_const_getf (TDB, NULL, "%s.%s.%s", kind, type, name);
		char *subtype = value? strdup (value): NULL;
		if (!subtype) {
			break;
		}
		int len = r_str_split (subtype, ',');
		if (len < 3) {
			free (subtype);
			break;
		}
		int cur_offset = r_num_math (NULL, r_str_word_get0 (subtype, len - 2));
		if (is_struct) {
			if (cur_offset > 0 && cur_offset < next_offset) {
				free (subtype);
				break;
			}
			if (!cur_offset) {
				cur_offset = next_offset;
			}
		}
		if (cur_offset == offset) {
			res = r_str_newf ("%s.%s", path, name);
			free (subtype);
			break;
		}
		int arrsz = r_num_math (NULL, r_str_word_get0 (subtype, len - 1));
		int fsize = (r_type_get_bitsize (TDB, subtype) * (arrsz ? arrsz : 1)) / 8;
		if (!fsize) {
			free (subtype);
			if (is_struct) {
				break;
			}
			continue;
		}
		int member_end = cur_offset + fsize;
		if (is_struct) {
			next_offset = member_end;
		}
		if (offset > cur_offset && offset < member_end) {
			const char *nested_type = r_str_word_get0 (subtype, 0);
			char *nested_name = NULL;
			const char *nested_kind = type_aggregate_kind (TDB, nested_type, &nested_name);
			if (nested_kind) {
				char *nested_path = r_str_newf ("%s.%s", path, name);
				if (nested_path) {
					res = type_get_memb (TDB, nested_kind, nested_name, offset - cur_offset, nested_path);
					free (nested_path);
				}
				if (res) {
					free (nested_name);
					free (subtype);
					break;
				}
			}
			free (nested_name);
		}
		free (subtype);
	}
	free (members);
	return res;
}

R_API char *r_type_get_struct_memb(Sdb *R_NONNULL TDB, const char *R_NONNULL type, int offset) {
	R_RETURN_VAL_IF_FAIL (TDB && type, NULL);
	return type_get_memb (TDB, "struct", type, offset, type);
}

// XXX this function is slow!
R_API RList *r_type_get_by_offset(Sdb *R_NONNULL TDB, ut64 offset) {
	R_RETURN_VAL_IF_FAIL (TDB, NULL);
	RList *offtypes = r_list_newf (free);
	if (offset > ST32_MAX) {
		return offtypes;
	}
	SdbList *ls = sdb_foreach_list (TDB, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		const char *kk = sdbkv_key (kv);
		const char *vv = sdbkv_value (kv);
		if (type_kind_is_aggregate (vv)
			&& !r_str_startswith (kk, "struct.") && !r_str_startswith (kk, "union.")) {
			char *res = type_get_memb (TDB, vv, kk, offset, kk);
			if (res) {
				r_list_append (offtypes, res);
			}
		}
	}
	ls_free (ls);
	return offtypes;
}

#define TYPE_RANGE_BASE(x) ( (x) >> 16)

static RList *types_range_list(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE (addr);
	const char *value = sdb_const_getf (db, NULL, "range.%" PFMT64x, base);
	return value? r_str_split_duplist (value, " ", true): NULL;
}

static void types_range_del(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE (addr);
	r_strf_var (k, 64, "range.%" PFMT64x, base);
	char valstr[SDB_NUM_BUFSZ];
	const char *v = sdb_itoa (addr, SDB_NUM_BASE, valstr, sizeof (valstr));
	sdb_array_remove (db, k, v, 0);
}

static void types_range_add(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE (addr);
	r_strf_var (k, 64, "range.%" PFMT64x, base);
	(void)sdb_array_add_num (db, k, addr, 0);
}

R_API char *r_type_link_at(Sdb *TDB, ut64 addr) {
	if (addr == UT64_MAX || addr == (UT64_MAX - 1)) {
		return NULL;
	}
	const char *value = sdb_const_getf (TDB, NULL, "link.%08" PFMT64x, addr);
	char *res = value? strdup (value): NULL;
	if (res) {
		return res;
	}
	// resolve struct memb if possible for given addr
	RList *list = types_range_list (TDB, addr);
	RListIter *iter;
	const char *s;
	r_list_foreach (list, iter, s) {
		ut64 laddr = r_num_get (NULL, s);
		if (addr > laddr) {
			int delta = addr - laddr;
			const char *link = sdb_const_getf (TDB, NULL, "link.%08" PFMT64x, laddr);
			char *k = link? strdup (link): NULL;
			if (k) {
				res = r_type_get_struct_memb (TDB, k, delta);
				free (k);
				if (res) {
					break;
				}
			}
		}
	}
	r_list_free (list);
	return res;
}

R_API int r_type_set_link(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get (TDB, type, 0) || r_type_get_bitsize (TDB, type)) {
		sdb_setf (TDB, type, 0, "link.%08" PFMT64x, addr);
		types_range_add (TDB, addr);
		return true;
	}
	return false;
}

R_API int r_type_link_offset(Sdb *TDB, const char *type, ut64 addr) {
	if (sdb_const_get (TDB, type, 0)) {
		sdb_setf (TDB, type, 0, "offset.%08" PFMT64x, addr);
		return true;
	}
	return false;
}

R_API int r_type_unlink(Sdb *TDB, ut64 addr) {
	char *laddr = r_str_newf ("link.%08" PFMT64x, addr);
	sdb_unset (TDB, laddr, 0);
	free (laddr);
	types_range_del (TDB, addr);
	return true;
}

static char *type_format(Sdb *TDB, const char *t, int depth);
static char *type_format_base(Sdb *TDB, const char *t, int depth);

static RTypeDecl *type_format_resolve(Sdb *db, const char *text, RTypeDeclNode **element, ut64 *elements) {
	RTypeDecl *decl = r_type_decl_parse (text, NULL);
	*elements = 1;
	int depth;
	for (depth = 0; decl && !decl->name && depth < TYPE_CHAIN_MAX; depth++) {
		RTypeDeclNode *node = decl->type;
		while (node->kind == R_TYPE_DECL_ARRAY) {
			if (*node->array.count) {
				char *end;
				errno = 0;
				ut64 count = strtoull (node->array.count, &end, 0);
				if (errno == ERANGE || !isdigit ((ut8)*node->array.count) || !count || *end || r_mul_overflow (*elements, count, elements)) {
					r_type_decl_free (decl);
					return NULL;
				}
			}
			node = node->child;
		}
		const char *target = node->kind == R_TYPE_DECL_BASE? sdb_const_getf (db, NULL, "typedef.%s", node->base.name): NULL;
		if (!target || !strcmp (target, "struct") || !strcmp (target, "union")) {
			*element = node;
			return decl;
		}
		RTypeDecl *next = r_type_decl_parse (target, NULL);
		r_type_decl_free (decl);
		decl = next;
	}
	r_type_decl_free (decl);
	return NULL;
}

static char *type_pointer_format(Sdb *db, const RTypeDeclNode *node) {
	RTypeLayout layout;
	if (!r_type_decl_layout (db, node, &layout)) {
		return NULL;
	}
	if (node->pointer.kind == R_TYPE_POINTER_DEFAULT && node->child->kind == R_TYPE_DECL_BASE && !strcmp (node->child->base.name, "char")) {
		return strdup ("z");
	}
	if (node->pointer.kind == R_TYPE_POINTER_DEFAULT && node->child->kind == R_TYPE_DECL_POINTER
			&& node->child->pointer.kind == R_TYPE_POINTER_DEFAULT && node->child->child->kind == R_TYPE_DECL_BASE
			&& !strcmp (node->child->child->base.name, "char")) {
		return strdup ("*z");
	}
	return layout.bits == sdb_num_get (db, "type.char *.size", NULL)? strdup ("p"): r_str_newf ("p%" PFMT64u, layout.bits / 8);
}

static char *type_format_repeat(const char *body, ut64 elements) {
	if (*body == '[') {
		char *end;
		errno = 0;
		ut64 repeat = strtoull (body + 1, &end, 0);
		if (errno == ERANGE || !isdigit ((ut8)body[1]) || *end != ']' || r_mul_overflow (elements, repeat, &elements)) {
			return NULL;
		}
		body = end + 1;
	}
	return r_str_newf ("[%" PFMT64u "]%s", elements, body);
}

static char *fmt_struct_union(Sdb *db, char *var, bool is_typedef) {
	char *fields = is_typedef? r_str_newf ("%s.fields", var): strdup (var);
	if (!fields) {
		return NULL;
	}
	RStrBuf *fmt = r_strbuf_new ("");
	RStrBuf *names = r_strbuf_new ("");
	ut64 current = 0;
	bool complete = true;
	char *member;
	int i;
	for (i = 0; (member = sdb_array_get (db, fields, i, NULL)); i++) {
		char *key = r_str_newf ("%s.%s", var, member);
		if (!key) {
			free (member);
			complete = false;
			break;
		}
		ut64 offset;
		int count;
		char *text = r_type_get_member (db, key, &offset, &count);
		RTypeDeclNode *element = NULL;
		ut64 elements = 1;
		RTypeDecl *decl = text? type_format_resolve (db, text, &element, &elements): NULL;
		RTypeLayout layout;
		bool measured = text && r_type_get_layout (db, text, &layout);
		ut64 bytes = measured? layout.bits / 8: 0;
		bool reference = element && (element->kind == R_TYPE_DECL_LVALUE_REFERENCE || element->kind == R_TYPE_DECL_RVALUE_REFERENCE);
		if (reference) {
			// Address formatting consumes target-sized slots; this does not define a reference ABI.
			ut64 slot = sdb_num_get (db, "type.char *.size", NULL) / 8;
			complete = slot && !r_mul_overflow (slot, elements, &bytes);
		}
		if (count > 0 && (r_mul_overflow (elements, (ut64)count, &elements) || r_mul_overflow (bytes, (ut64)count, &bytes))) {
			complete = false;
		}
		if (offset > current) {
			r_strbuf_appendf (fmt, "[%" PFMT64u "].", offset - current);
		}
		const char *visibility = sdb_const_getf (db, NULL, "%s.@.visibility", key);
		if (!decl || !complete) {
			complete = false;
		} else if (visibility && !strcmp (visibility, "hidden")) {
			if (!measured && !reference) {
				complete = false;
			} else {
				r_strbuf_appendf (fmt, "[%" PFMT64u "].", bytes);
			}
		} else {
			char *body = NULL;
			char *aggregate_name = NULL;
			bool aggregate = false;
			bool enumeration = false;
			const char *base = element->kind == R_TYPE_DECL_BASE? element->base.name: NULL;
			if (element->kind == R_TYPE_DECL_POINTER) {
				body = type_pointer_format (db, element);
			} else if (reference) {
				body = strdup ("p");
			} else if (base) {
				aggregate = type_aggregate_kind (db, base, &aggregate_name) != NULL;
				enumeration = r_type_kind (db, base) == R_TYPE_ENUM;
				if (aggregate) {
					body = strdup ("?");
				} else if (enumeration) {
					body = strdup ("E");
				} else if (!strcmp (base, "char") && (count > 0 || decl->type->kind == R_TYPE_DECL_ARRAY)) {
					body = strdup ("z");
				} else {
					body = type_format_base (db, base, 0);
				}
			}
			if (body && (elements > 1 || count > 0)) {
				char *repeated = type_format_repeat (body, elements);
				free (body);
				body = repeated;
			}
			if (!body) {
				complete = false;
			} else {
				r_strbuf_append (fmt, body);
				if (aggregate || enumeration) {
					const char *name = aggregate? aggregate_name: base;
					if (enumeration && r_str_startswith (base, "enum ")) {
						name = base + 5;
					}
					r_strbuf_appendf (names, "(%s)%s ", name, member);
				} else {
					r_strbuf_appendf (names, "%s ", member);
				}
			}
			free (aggregate_name);
			free (body);
		}
		ut64 end;
		if (r_add_overflow (offset, bytes, &end)) {
			complete = false;
		} else {
			current = R_MAX (current, end);
		}
		r_type_decl_free (decl);
		free (text);
		free (key);
		free (member);
		if (!complete) {
			break;
		}
	}
	free (fields);
	if (complete) {
		r_strbuf_appendf (fmt, " %s", r_strbuf_get (names));
	}
	r_strbuf_free (names);
	if (!complete) {
		r_strbuf_free (fmt);
		return NULL;
	}
	return r_strbuf_drain (fmt);
}

static char *type_format_base(Sdb *TDB, const char *t, int depth) {
	const char *kind = sdb_const_get (TDB, t, NULL);
	if (!kind) {
		return NULL;
	}
	if (!strcmp (kind, "type")) {
		const char *fmt = sdb_const_getf (TDB, NULL, "type.%s", t);
		return fmt? strdup (fmt): NULL;
	}
	char var[130];
	snprintf (var, sizeof (var), "%s.%s", kind, t);
	if (!strcmp (kind, "struct")) {
		return fmt_struct_union (TDB, var, false);
	} else if (!strcmp (kind, "union")) {
		char *fmt = fmt_struct_union (TDB, var, false);
		if (fmt) {
			char *res = r_str_newf ("0%s", fmt);
			free (fmt);
			return res;
		}
		return NULL;
	}
	if (!strcmp (kind, "typedef")) {
		const char *type = sdb_const_getf (TDB, NULL, "typedef.%s", t);
		if (type && !strcmp (type, "struct")) {
			return fmt_struct_union (TDB, var, true);
		}
		if (type && !strcmp (type, "union")) {
			char *fmt = fmt_struct_union (TDB, var, true);
			if (fmt) {
				char *res = r_str_newf ("0%s", fmt);
				free (fmt);
				return res;
			}
			return NULL;
		}
		// a typedef of a scalar formats as its target: typedef.size_t=uint64_t is a q
		char *target = r_type_resolve_typedef (TDB, t);
		char *fmt = target? type_format (TDB, target, depth + 1): NULL;
		free (target);
		return fmt;
	}
	return NULL;
}

static char *type_format(Sdb *TDB, const char *t, int depth) {
	if (depth >= TYPE_CHAIN_MAX) {
		return NULL;
	}
	RTypeDeclNode *element = NULL;
	ut64 elements;
	RTypeDecl *decl = type_format_resolve (TDB, t, &element, &elements);
	if (!decl) {
		return NULL;
	}
	char *fmt = NULL;
	if (element->kind == R_TYPE_DECL_POINTER) {
		fmt = type_pointer_format (TDB, element);
	} else if (element->kind == R_TYPE_DECL_LVALUE_REFERENCE || element->kind == R_TYPE_DECL_RVALUE_REFERENCE) {
		fmt = strdup ("p");
	} else if (element->kind == R_TYPE_DECL_BASE) {
		const char *name = element->base.name;
		const char *bare = NULL;
		if (type_aggregate_prefixed (name, &bare)) {
			name = bare;
		}
		fmt = type_format_base (TDB, name, depth);
	}
	if (fmt && elements > 1) {
		char *array = r_str_newf (*fmt == '0'? "[%" PFMT64u "]? (pf %s)": "%" PFMT64u "%s", elements, fmt);
		free (fmt);
		fmt = array;
	}
	r_type_decl_free (decl);
	return fmt;
}

R_API char *r_type_format(Sdb *TDB, const char *t) {
	R_RETURN_VAL_IF_FAIL (TDB && t, NULL);
	return type_format (TDB, t, 0);
}

R_API void r_type_del(Sdb *TDB, const char *name) {
	r_strf_buffer (512);
	if (strstr (name, ".arg.")) {
		// ignore func argument definitions as they are not types
		return;
	}
	if (r_str_endswith (name, ".include")) {
		// ignore .include headers
		return;
	}
	const char *kind = sdb_const_get (TDB, name, 0);
	if (!kind) {
		return;
	}
	const char *comma = strchr (kind, ',');
	if (comma) {
		R_LOG_WARN ("Unexpected comma in kind (%s) for (%s)", kind, name);
	}
	if (!strcmp (kind, "type")) {
		sdb_unset (TDB, r_strf ("type.%s", name), 0);
		sdb_unset (TDB, r_strf ("type.%s.size", name), 0);
		sdb_unset (TDB, r_strf ("type.%s.meta", name), 0);
		sdb_unset (TDB, name, 0);
	} else if (!strcmp (kind, "struct") || !strcmp (kind, "union")) {
		char *elements_key = r_str_newf ("%s.%s", kind, name);
		int i, n = sdb_array_length (TDB, elements_key);
		for (i = 0; i < n; i++) {
			char *p = sdb_array_get (TDB, elements_key, i, NULL);
			sdb_unset (TDB, r_strf ("%s.%s", elements_key, p), 0);
			sdb_unset (TDB, r_strf ("%s.%s.meta", elements_key, p), 0);
			free (p);
		}
		sdb_unset (TDB, elements_key, 0);
		sdb_unsetf (TDB, 0, "type.%s.size", name);
		sdb_unset (TDB, name, 0);
		free (elements_key);
	} else if (!strcmp (kind, "func")) {
		int i, n = sdb_num_getf (TDB, NULL, "func.%s.args", name);
		for (i = 0; i < n; i++) {
			sdb_unset (TDB, r_strf ("func.%s.arg.%d", name, i), 0);
		}
		sdb_unset (TDB, r_strf ("func.%s.ret", name), 0);
		sdb_unset (TDB, r_strf ("func.%s.cc", name), 0);
		sdb_unset (TDB, r_strf ("func.%s.noreturn", name), 0);
		sdb_unset (TDB, r_strf ("func.%s.args", name), 0);
		sdb_unset (TDB, name, 0);
	} else if (!strcmp (kind, "enum")) {
		RList *list = r_type_get_enum (TDB, name);
		RTypeEnum *member;
		RListIter *iter;
		r_list_foreach (list, iter, member) {
			char *k = r_str_newf ("enum.%s.%s", name, member->name);
			sdb_unset (TDB, k, 0);
			free (k);
			k = r_str_newf ("enum.%s.%s", name, member->val);
			sdb_unset (TDB, k, 0);
			free (k);
		}
		sdb_unset (TDB, name, 0);
		r_list_free (list);
	} else if (!strcmp (kind, "typedef")) {
		char *buf = r_str_newf ("typedef.%s", name);
		sdb_unset (TDB, buf, 0);
		free (buf);
		sdb_unset (TDB, name, 0);
	} else {
		R_LOG_WARN ("Unrecognized type kind \"%s\" for (%s)", kind, name);
	}
}

// Strip leading __ prefix for type database lookup when the exact name
// is not registered. This allows __strcpy_chk to match strcpy_chk
static inline const char *trim_lodashes(Sdb *TDB, const char *name) {
	while (r_str_startswith (name, "__") && !sdb_const_get (TDB, name, 0)
		&& !sdb_const_getf (TDB, NULL, "func.%s.ret", name)) {
		name += 2;
	}
	return name;
}

// Function prototypes api
R_API int r_type_func_exist(Sdb *TDB, const char *func_name) {
	const char *fcn = sdb_const_get (TDB, trim_lodashes (TDB, func_name), 0);
	return fcn && !strcmp (fcn, "func");
}

R_API bool r_type_func_prototype_exist(Sdb *TDB, const char *func_name) {
	R_RETURN_VAL_IF_FAIL (TDB && func_name, false);
	const char *name = trim_lodashes (TDB, func_name);
	const char *kind = sdb_const_get (TDB, name, 0);
	// Argument recovery also writes func.*.args; only declarations have a kind or return type.
	// struct stat overwrites stat=func, but the prototype under func.stat.* is still there
	return (kind && !strcmp (kind, "func")) || sdb_const_getf (TDB, NULL, "func.%s.ret", name);
}

R_API const char *r_type_func_ret(Sdb *TDB, const char *func_name) {
	return sdb_const_getf (TDB, NULL, "func.%s.ret", trim_lodashes (TDB, func_name));
}

R_API bool r_type_func_args_count(Sdb *TDB, const char *name, int *argc) {
	R_RETURN_VAL_IF_FAIL (TDB && name && argc, false);
	while (true) {
		const char *kind = sdb_const_get (TDB, name, 0);
		// Recovered arguments alone do not declare a prototype; a struct may overwrite its kind.
		if ((kind && !strcmp (kind, "func")) || sdb_const_getf (TDB, NULL, "func.%s.ret", name)) {
			break;
		}
		if (kind || !r_str_startswith (name, "__")) {
			return false;
		}
		name += 2;
	}
	const char *value = sdb_const_getf (TDB, NULL, "func.%s.args", name);
	if (!value || !isdigit ((ut8)*value)) {
		return false;
	}
	char *end;
	ut64 count = strtoull (value, &end, 0);
	if (*end || count > ST32_MAX) {
		return false;
	}
	*argc = (int)count;
	return true;
}

R_API R_OWNED char *r_type_func_args_type(Sdb *TDB, const char *R_NONNULL func_name, int i) {
	const char *value = sdb_const_getf (TDB, NULL, "func.%s.arg.%d", trim_lodashes (TDB, func_name), i);
	char *ret = value? strdup (value): NULL;
	if (ret) {
		char *comma = strrchr (ret, ',');
		if (comma) {
			*comma = 0;
		}
	}
	return ret;
}

static const char *const argnames[10] = {
	"arg0", "arg1", "arg2", "arg3", "arg4",
	"arg5", "arg6", "arg7", "arg8", "arg9",
};

R_API const char *r_type_func_args_name(Sdb *TDB, const char *R_NONNULL func_name, int i) {
	const char *row = sdb_const_getf (TDB, NULL, "func.%s.arg.%d", trim_lodashes (TDB, func_name), i);
	if (row) {
		const char *ret = strrchr (row, ',');
		if (ret) {
			return ret + 1;
		}
	}
	return (i >= 0 && i < 10)? argnames[i]: "arg";
}

R_API bool r_type_func_is_variadic(Sdb *TDB, const char *R_NONNULL func_name, int argc) {
	R_RETURN_VAL_IF_FAIL (TDB && func_name, false);
	if (argc < 1) {
		return false;
	}
	const char *row = sdb_const_getf (TDB, NULL, "func.%s.arg.%d", trim_lodashes (TDB, func_name), argc - 1);
	if (!row) {
		return false;
	}
	const char *comma = strrchr (row, ',');
	// Current declarations store "..." in the name; older ones used the type.
	return comma? !strcmp (comma + 1, "...") || (comma - row == 3 && !strncmp (row, "...", 3)): !strcmp (row, "...");
}

#define MIN_MATCH_LEN 4

static inline bool is_function(const char *name) {
	return name && !strcmp ("func", name);
}

static R_OWNED char *type_func_try_guess(Sdb *TDB, const char *name) {
	if (strlen (name) < MIN_MATCH_LEN) {
		return NULL;
	}
	const char *res = sdb_const_get (TDB, name, NULL);
	if (is_function (res)) {
		return strdup (name);
	}
	// strip leading underscores (e.g., __libc_start_main -> libc_start_main)
	if (r_str_startswith (name, "__")) {
		const char *stripped = name;
		while (*stripped == '_') {
			stripped++;
		}
		res = sdb_const_get (TDB, stripped, NULL);
		if (is_function (res)) {
			return strdup (stripped);
		}
	}
	return NULL;
}

static inline bool is_auto_named(const char *func_name, size_t slen) {
	return slen > 4 && (r_str_startswith (func_name, "fcn.") || r_str_startswith (func_name, "loc."));
}

static inline bool has_r_prefixes(const char *func_name, int offset, size_t slen) {
	return slen > 4 && (offset + 3 < slen) && func_name[offset + 3] == '.';
}

static const char *strip_r_prefixes(const char *func_name, size_t slen) {
	// strip r2 prefixes (sym, sym.imp, etc')
	int offset = 0;
	while (has_r_prefixes (func_name, offset, slen)) {
		offset += 4;
	}
	return func_name + offset;
}

static const char *strip_common_prefixes_stdlib(const char *func_name) {
	// strip common prefixes from standard lib functions
	if (r_str_startswith (func_name, "__isoc99_")) {
		func_name += 9;
	} else if (r_str_startswith (func_name, "__libc_") && !strstr (func_name, "_main")) {
		func_name += 7;
	} else if (r_str_startswith (func_name, "__GI_")) {
		func_name += 5;
	}
	return func_name;
}

static const char *strip_dll_prefix(const char *func_name, bool *stripped) {
	const char *tmp = strstr (func_name, "dll_");
	if (tmp) {
		if (stripped) {
			*stripped = true;
		}
		return tmp + 4;
	}
	if (stripped) {
		*stripped = false;
	}
	return func_name;
}

static void clean_function_name(char *func_name) {
	char *last = (char *)r_str_lchr (func_name, '_');
	if (!last || !r_str_isnumber (last + 1)) {
		return;
	}
	*last = '\0';
}

// TODO:
// - symbol names are long and noisy, some of them might not be matched due
//	 to additional information added around name
R_API R_OWNED char *r_type_func_guess(Sdb *TDB, const char *R_NONNULL func_name) {
	R_RETURN_VAL_IF_FAIL (TDB && func_name, NULL);
	const char *str = func_name;
	char *result = NULL;

	size_t slen = strlen (str);
	if (slen < MIN_MATCH_LEN || is_auto_named (str, slen)) {
		return NULL;
	}

	str = strip_r_prefixes (str, slen);
	str = strip_common_prefixes_stdlib (str);
	bool dll_stripped = false;
	str = strip_dll_prefix (str, &dll_stripped);

	if ((result = type_func_try_guess (TDB, str))) {
		return result;
	}

	// afs stores prototypes under the prefixed name, retry it unstripped
	if (str != func_name && (result = type_func_try_guess (TDB, func_name))) {
		return result;
	}

	char *str_copy = strdup (str);

	// If we stripped dll_ prefix, try matching the cleaned name directly
	if (dll_stripped) {
		clean_function_name (str_copy);
		result = type_func_try_guess (TDB, str_copy);
	}
	if (!result && *str_copy == '_') {
		// Also try without leading underscore
		result = type_func_try_guess (TDB, str_copy + 1);
	}

	// auto-detect JNI native functions and callbacks
	if (!result && (r_str_startswith (str, "Java_") || r_str_startswith (str, "JNI_"))) {
		result = type_func_try_guess (TDB, "jni_native");
	}
	free (str_copy);
	return result;
}

// walks name, then the last dotted component, then the fuzzy guesser; `key` returns the db key matched
static char *type_func_lookup(Sdb *types, const char *fname, bool key) {
	R_RETURN_VAL_IF_FAIL (types && fname, NULL);
	if (r_type_func_prototype_exist (types, fname)) {
		return strdup (key? trim_lodashes (types, fname): fname);
	}
	const char *dot = strrchr (fname, '.');
	if (dot && r_type_func_prototype_exist (types, dot + 1)) {
		return strdup (key? trim_lodashes (types, dot + 1): dot + 1);
	}
	return r_type_func_guess (types, fname);
}

R_API char *r_type_func_name(Sdb *types, const char *fname) {
	return type_func_lookup (types, fname, false);
}

// same walk as r_type_func_name, but hands back the db key the match went through
R_API char *r_type_func_key(Sdb *types, const char *fname) {
	return type_func_lookup (types, fname, true);
}
