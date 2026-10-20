/* radare - LGPL - Copyright 2026 - pancake, Codex */

static bool kvc_type_layout(KVCParser *kvc, const char *name, int *size, int *align) {
	const char *records = r_strbuf_get (kvc->sb);
	sdb_query_lines (kvc->types, records + kvc->synced);
	kvc->synced = r_strbuf_length (kvc->sb);
	RTypeLayout layout;
	if (!r_type_get_layout (kvc->types, name, &layout) || layout.bits % 8 || layout.bits / 8 > INT_MAX || layout.align > INT_MAX) {
		return false;
	}
	*size = layout.bits / 8;
	*align = layout.align;
	return true;
}

static int kvc_layout_member(KVCParser *kvc, RAnalBaseType *bt, const char *type, int count, int *off, int *align) {
	int size, av;
	if (!kvc_type_layout (kvc, type, &size, &av) || count < 0 || (count && size > INT_MAX / count)) {
		char *message = r_str_newf ("Cannot measure member type: %s", type);
		kvc_error (kvc, message? message: "Cannot measure member type");
		free (message);
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
	r_anal_base_type_free (bt);
}
