/* radare - LGPL - Copyright 2026 - pancake */

R_IPI int kvc_type_size(const char *name, int dimension, int ptr_size) {
	if (strchr (name, '*')) {
		return ptr_size * dimension;
	}
	if (!strcmp (name, "char") || r_str_endswith (name, "8")) {
		return 1 * dimension;
	}
	if (!strcmp (name, "short") || r_str_endswith (name, "16")) {
		return 2 * dimension;
	}
	if (!strcmp (name, "long long") || !strcmp (name, "double") || r_str_endswith (name, "64")) {
		return 8 * dimension;
	}
	if (r_str_startswith (name, "int") || !strcmp (name, "float") || !strcmp (name, "long")) {
		return 4 * dimension;
	}
	if (dimension > 1) {
		return dimension;
	}
	return 4;
}

R_IPI int kvc_type_align(const char *name, int ptr_size) {
	if (strchr (name, '*')) {
		return ptr_size;
	}
	if (!strcmp (name, "char") || r_str_endswith (name, "8")) {
		return 1;
	}
	if (!strcmp (name, "short") || r_str_endswith (name, "16")) {
		return 2;
	}
	if (!strcmp (name, "long long") || !strcmp (name, "double") || r_str_endswith (name, "64")) {
		return 8;
	}
	return 4;
}

static void kvc_type_layout_free(void *data) {
	KVCTypeLayout *layout = data;
	r_anal_base_type_free (layout->type);
	free (layout);
}

static KVCTypeLayout *kvc_find_type(KVCParser *kvc, const char *name) {
	RListIter *iter;
	KVCTypeLayout *layout;
	r_list_foreach_prev (kvc->types, iter, layout) {
		if (!strcmp (layout->type->name, name)) {
			return layout;
		}
	}
	if (!kvc->anal) {
		return NULL;
	}
	RAnalBaseType *bt = r_anal_get_base_type (kvc->anal, name);
	if (!bt) {
		return NULL;
	}
	layout = R_NEW0 (KVCTypeLayout);
	layout->type = bt;
	r_list_append (kvc->types, layout);
	return layout;
}

static bool kvc_type_layout(KVCParser *kvc, const char *name, int *size, int *align, int depth);

static int kvc_saved_attr(KVCParser *kvc, const char *kind, const char *name, const char *attr) {
	return kvc->anal? sdb_num_getf (kvc->anal->sdb_types, NULL, "%s.%s.@.%s", kind, name, attr): 0;
}

static bool kvc_composite_layout(KVCParser *kvc, KVCTypeLayout *layout, int *size, int *align, int depth) {
	RAnalBaseType *bt = layout->type;
	if (layout->align) {
		*size = bt->size / 8;
		*align = layout->align;
		return true;
	}
	const char *kind = bt->kind == R_ANAL_BASE_TYPE_KIND_STRUCT? "struct": "union";
	int pack = kvc_saved_attr (kvc, kind, bt->name, "pack");
	if (kvc->anal && sdb_const_getf (kvc->anal->sdb_types, NULL, "%s.%s.@.packed", kind, bt->name)) {
		pack = 1;
	}
	ut64 extent = 0;
	int max_align = 1;
	RAnalTypeMember *member;
	R_VEC_FOREACH (r_anal_base_type_members (bt), member) {
		int member_size, member_align;
		if (!kvc_type_layout (kvc, member->type, &member_size, &member_align, depth + 1)) {
			return false;
		}
		char *scope = r_str_newf ("%s.%s", bt->name, member->name);
		int explicit_align = kvc_saved_attr (kvc, kind, scope, "aligned");
		free (scope);
		if (explicit_align > 0) {
			member_align = explicit_align;
		}
		if (pack > 0) {
			member_align = R_MIN (member_align, pack);
		}
		max_align = R_MAX (max_align, member_align);
		ut64 bytes;
		ut64 count = member->count? member->count: 1;
		if (r_mul_overflow ((ut64)member_size, count, &bytes)
				|| r_add_overflow ((ut64)member->offset, bytes, &bytes)) {
			return false;
		}
		extent = R_MAX (extent, bytes);
	}
	int explicit_align = kvc_saved_attr (kvc, kind, bt->name, "aligned");
	max_align = R_MAX (max_align, explicit_align);
	if (bt->size) {
		extent = bt->size / 8;
	} else if (extent % max_align) {
		extent += max_align - extent % max_align;
	}
	if (extent > INT_MAX) {
		return false;
	}
	bt->size = extent * 8;
	layout->align = max_align;
	*size = extent;
	*align = max_align;
	return true;
}

static bool kvc_type_layout(KVCParser *kvc, const char *name, int *size, int *align, int depth) {
	if (depth > 64) {
		return false;
	}
	char *type = collapse_whitespace (r_strs_from (name));
	if (!type) {
		return false;
	}
	bool ok = true;
	ut64 count = 1;
	// Function-parameter arrays do not dimension the enclosing callback pointer.
	char *array = (char *)scan_toplevel (r_strs_from (type), '[');
	if (array) {
		char *p = array;
		while (*p == '[') {
			char *end = strchr (p, ']');
			if (!end) {
				ok = false;
				break;
			}
			*end = 0;
			ut64 dimension = r_num_math (NULL, p + 1);
			if (r_mul_overflow (count, dimension, &count)) {
				ok = false;
				break;
			}
			p = end + 1;
			while (isspace ((ut8)*p)) {
				p++;
			}
		}
		ok &= !*p;
		*array = 0;
		r_str_trim (type);
	}
	char *base = type;
	while (r_str_startswith (base, "const ") || r_str_startswith (base, "volatile ")) {
		base = strchr (base, ' ') + 1;
	}
	bool tagged = false;
	if (r_str_startswith (base, "struct ") || r_str_startswith (base, "union ") || r_str_startswith (base, "enum ")) {
		base = strchr (base, ' ') + 1;
		tagged = true;
	}
	if (ok && strchr (base, '*')) {
		*size = *align = kvc->ptr_size;
	} else if (ok) {
		const char *alias = tagged? NULL: kvc_lookup_typedef (kvc, base);
		if (!alias && !tagged && kvc->anal) {
			alias = sdb_const_getf (kvc->anal->sdb_types, NULL, "typedef.%s", base);
		}
		if (alias) {
			ok = kvc_type_layout (kvc, alias, size, align, depth + 1);
		} else {
			KVCTypeLayout *layout = kvc_find_type (kvc, base);
			RAnalBaseType *bt = layout? layout->type: NULL;
			const char *kind = kvc->anal? sdb_const_get (kvc->anal->sdb_types, base, NULL): NULL;
			if (bt && (bt->kind == R_ANAL_BASE_TYPE_KIND_STRUCT || bt->kind == R_ANAL_BASE_TYPE_KIND_UNION)) {
				ok = kvc_composite_layout (kvc, layout, size, align, depth);
			} else if (bt && bt->kind == R_ANAL_BASE_TYPE_KIND_TYPEDEF) {
				ok = kvc_type_layout (kvc, bt->type, size, align, depth + 1);
			} else if (bt && bt->size) {
				ok = bt->size / 8 <= INT_MAX;
				*size = bt->size / 8;
				*align = *size > 0? *size: 1;
			} else if (r_str_startswith (base, "func.") || (kind && !strcmp (kind, "func"))) {
				*size = *align = kvc->ptr_size;
			} else {
				*size = kvc_type_size (base, 1, kvc->ptr_size);
				*align = kvc_type_align (base, kvc->ptr_size);
			}
		}
	}
	ut64 bytes;
	if (ok) {
		ok = !r_mul_overflow ((ut64)*size, count, &bytes) && bytes <= INT_MAX;
		if (ok) {
			*size = bytes;
		}
	}
	free (type);
	return ok;
}

static int kvc_layout_member(KVCParser *kvc, RAnalBaseType *bt, const char *type, int count, int *off, int *align) {
	int size, av;
	if (!kvc_type_layout (kvc, type, &size, &av, 0) || count < 0 || (count && size > INT_MAX / count)) {
		kvc_error (kvc, "Cannot measure member type");
		return 0;
	}
	const char *aligned = kvc_attr (kvc, "aligned");
	if (aligned) {
		int explicit_align = atoi (aligned);
		if (explicit_align > 0) {
			av = explicit_align;
		}
		free ((void *)aligned);
	}
	if (kvc->struct_pack > 0) {
		av = R_MIN (av, kvc->struct_pack);
	}
	*align = R_MAX (*align, av);
	int member_off = bt->kind == R_ANAL_BASE_TYPE_KIND_UNION? 0: *off;
	ut64 end = member_off;
	if (end % av) {
		end += av - end % av;
	}
	member_off = end;
	end += (ut64)size * count;
	if (end > INT_MAX) {
		kvc_error (kvc, "Aggregate size exceeds parser limit");
		return 0;
	}
	bt->size = R_MAX (bt->size, end * 8);
	if (bt->kind == R_ANAL_BASE_TYPE_KIND_STRUCT) {
		*off = end;
	}
	return member_off;
}

static void kvc_basetype_emit(KVCParser *kvc, RAnalBaseType *bt, int align) {
	ut64 size = bt->size / 8;
	if (size % align) {
		size += align - size % align;
	}
	bt->size = size * 8;
	char *kv = r_anal_base_type_to_kv (bt);
	if (kv) {
		r_strbuf_append (kvc->sb, kv);
		free (kv);
	}
	KVCTypeLayout *layout = R_NEW0 (KVCTypeLayout);
	layout->type = bt;
	layout->align = align;
	r_list_append (kvc->types, layout);
}
