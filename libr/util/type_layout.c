/* radare - LGPL - Copyright 2026 - Codex */

#include <r_util.h>

#define TYPE_LAYOUT_MAX_DEPTH 64

static bool type_layout_node(Sdb *db, const RTypeDeclNode *node, RTypeLayout *layout, RTypeIdentity *chain, int depth);

static bool type_layout_text(Sdb *db, const char *text, RTypeLayout *layout, RTypeIdentity *chain, int depth) {
	RTypeDecl *decl = r_type_decl_parse (text, R_TYPE_DECL_CONTEXT_ABSTRACT, db, NULL);
	bool ok = decl && !decl->name && type_layout_node (db, decl->type, layout, chain, depth);
	r_type_decl_free (decl);
	return ok;
}

static ut64 type_natural_alignment(ut64 bits) {
	return R_MAX (bits / 8, 1);
}

static const char *type_signed_primitive(const char *name) {
	if (!r_str_startswith (name, "signed ") && !r_str_startswith (name, "unsigned ")) {
		return NULL;
	}
	const char *base = strchr (name, ' ') + 1;
	if (!strcmp (base, "char") || !strcmp (base, "short") || !strcmp (base, "int") || !strcmp (base, "long") || !strcmp (base, "long long")) {
		return base;
	}
	if (!strcmp (base, "short int")) {
		return "short";
	}
	if (!strcmp (base, "long int")) {
		return "long";
	}
	if (!strcmp (base, "long long int")) {
		return "long long";
	}
	return NULL;
}

static bool type_layout_aggregate(Sdb *types, Sdb *db, const char *name, const char *kind, RTypeLayout *layout, RTypeIdentity *chain, int depth) {
	const ut64 recorded = sdb_num_getf (db, NULL, "type.%s.size", name);
	const ut64 pack = sdb_const_getf (db, NULL, "%s.%s.@.packed", kind, name)? 1: sdb_num_getf (db, NULL, "%s.%s.@.pack", kind, name);
	layout->align = sdb_num_getf (db, NULL, "%s.%s.@.aligned", kind, name);
	layout->align = R_MAX (layout->align, 1);
	const char *members = sdb_const_getf (db, NULL, "%s.%s", kind, name);
	if (!members) {
		layout->bits = recorded;
		return recorded != 0;
	}
	char *list = strdup (members);
	if (!list) {
		return false;
	}
	bool ok = true;
	char *member, *next = NULL;
	for (member = sdb_anext (list, &next); member; member = next? sdb_anext (next, &next): NULL) {
		char *key = r_str_newf ("%s.%s.%s", kind, name, member);
		if (!key) {
			ok = false;
			break;
		}
		ut64 offset;
		int count;
		char *text = r_type_get_member (db, key, &offset, &count);
		ut64 explicit_align = sdb_num_getf (db, NULL, "%s.@.aligned", key);
		free (key);
		RTypeLayout field = { 0 };
		bool measured = text && type_layout_text (types, text, &field, chain, depth + 1);
		free (text);
		if (!measured) {
			if (recorded) {
				continue;
			}
			ok = false;
			break;
		}
		ut64 align = explicit_align? explicit_align: field.align;
		if (pack) {
			align = R_MIN (align, pack);
		}
		layout->align = R_MAX (layout->align, align);
		ut64 end;
		if (count < 0 || r_mul_overflow (field.bits, (ut64)(count? count: 1), &end)
				|| r_mul_overflow (offset, (ut64)8, &offset) || r_add_overflow (offset, end, &end)) {
			ok = false;
			break;
		}
		layout->bits = R_MAX (layout->bits, end);
	}
	free (list);
	if (recorded) {
		layout->bits = recorded;
	}
	return ok && layout->bits != 0;
}

static bool type_layout_base(Sdb *types, Sdb *db, const char *name, RTypeLayout *layout, RTypeIdentity *chain, int depth) {
	const char *kind = sdb_const_get (db, name, NULL);
	int i;
	for (i = 0; i < depth; i++) {
		if (chain[i].db == db && chain[i].key && !strcmp (chain[i].key, name)) {
			layout->bits = sdb_num_getf (db, NULL, "type.%s.size", name);
			layout->align = type_natural_alignment (layout->bits);
			return layout->bits != 0;
		}
	}
	chain[depth] = (RTypeIdentity){ .db = db, .key = (char *)name };
	if (kind && (!strcmp (kind, "struct") || !strcmp (kind, "union"))) {
		return type_layout_aggregate (types, db, name, kind, layout, chain, depth);
	}
	if (kind && !strcmp (kind, "typedef")) {
		const char *target = sdb_const_getf (db, NULL, "typedef.%s", name);
		RTypeDecl *decl = target? r_type_decl_parse (target, R_TYPE_DECL_CONTEXT_ABSTRACT, types, NULL): NULL;
		bool ok = decl && !decl->name && type_layout_node (types, decl->type, layout, chain, depth + 1);
		ut64 recorded = sdb_num_getf (db, NULL, "type.%s.size", name);
		if (ok && recorded && decl->type->kind == R_TYPE_DECL_BASE) {
			layout->bits = recorded;
		}
		r_type_decl_free (decl);
		return ok;
	}
	if (!kind || (strcmp (kind, "type") && strcmp (kind, "enum"))) {
		return false;
	}
	layout->bits = sdb_num_getf (db, NULL, "type.%s.size", name);
	if (!layout->bits && !strcmp (kind, "enum")) {
		layout->bits = sdb_num_get (types, "type.int.size", NULL);
	}
	layout->align = sdb_num_getf (db, NULL, "type.%s.align", name);
	if (!layout->align) {
		layout->align = type_natural_alignment (layout->bits);
	}
	return layout->bits != 0;
}

static bool type_layout_node(Sdb *db, const RTypeDeclNode *node, RTypeLayout *layout, RTypeIdentity *chain, int depth) {
	if (depth >= TYPE_LAYOUT_MAX_DEPTH) {
		return false;
	}
	if (node->kind == R_TYPE_DECL_POINTER) {
		const char *name = "char *";
		if (node->pointer.kind == R_TYPE_POINTER_NEAR) {
			name = "near *";
		} else if (node->pointer.kind == R_TYPE_POINTER_FAR) {
			name = "far *";
		}
		layout->bits = sdb_num_getf (db, NULL, "type.%s.size", name);
		layout->align = sdb_num_get (db, "type.pointer.align", NULL);
		if (!layout->align) {
			layout->align = sdb_num_get (db, "type.char *.size", NULL) / 8;
		}
		return layout->bits && layout->align;
	}
	if (node->kind == R_TYPE_DECL_ARRAY) {
		chain[depth] = (RTypeIdentity){ 0 };
		if (!type_layout_node (db, node->child, layout, chain, depth + 1)) {
			return false;
		}
		ut64 count;
		if (!r_type_array_bound_from_db (db, node->array.count, &count, NULL)) {
			return false;
		}
		if (!count) {
			layout->bits = 0;
			return true;
		}
		return !r_mul_overflow (layout->bits, count, &layout->bits);
	}
	if (node->kind != R_TYPE_DECL_BASE) {
		return false;
	}
	char *key = NULL;
	Sdb *selected = r_type_base_db (db, node->base.name, &key);
	if (!selected) {
		const char *primitive = type_signed_primitive (node->base.name);
		selected = primitive? r_type_base_db (db, primitive, &key): NULL;
	}
	bool ok = selected && type_layout_base (db, selected, key, layout, chain, depth);
	free (key);
	return ok;
}

R_API bool r_type_decl_layout(Sdb *db, const RTypeDeclNode *type, RTypeLayout *layout) {
	R_RETURN_VAL_IF_FAIL (db && type && layout, false);
	*layout = (RTypeLayout){ 0 };
	RTypeIdentity chain[TYPE_LAYOUT_MAX_DEPTH] = { 0 };
	return type_layout_node (db, type, layout, chain, 0);
}

R_API bool r_type_get_layout(Sdb *db, const char *type, RTypeLayout *layout) {
	R_RETURN_VAL_IF_FAIL (db && type && layout, false);
	*layout = (RTypeLayout){ 0 };
	RTypeIdentity chain[TYPE_LAYOUT_MAX_DEPTH] = { 0 };
	return type_layout_text (db, type, layout, chain, 0);
}

R_API ut64 r_type_get_bitsize(Sdb *db, const char *type) {
	RTypeLayout layout;
	return r_type_get_layout (db, type, &layout)? layout.bits: 0;
}
