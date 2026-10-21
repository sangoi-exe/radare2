/* radare - LGPL - Copyright 2026 - pancake, Codex */

static void kvc_sync_types(KVCParser *kvc) {
	if (!kvc->layout_ready) {
		Sdb *types = sdb_new0 ();
		if (kvc->host_types) {
			sdb_copy (kvc->host_types, types);
		}
		sdb_free (kvc->types);
		kvc->types = types;
		kvc->layout_ready = true;
	}
	const char *records = r_strbuf_get (kvc->sb);
	sdb_query_lines (kvc->types, records + kvc->synced);
	kvc->synced = r_strbuf_length (kvc->sb);
}

static bool kvc_type_layout(KVCParser *kvc, const RTypeDecl *decl, RTypeLayout *layout) {
	kvc_sync_types (kvc);
	if (!r_type_decl_layout (kvc->types, decl->type, layout) || layout->bits % 8 || layout->bits / 8 > INT_MAX || layout->align > INT_MAX) {
		char *type = r_type_decl_render (decl, false);
		char *message = r_str_newf ("Cannot measure member type: %s", r_str_get (type));
		kvc_error (kvc, message? message: "Cannot measure member type");
		free (message);
		free (type);
		return false;
	}
	return true;
}

static int kvc_layout_member(KVCParser *kvc, RAnalBaseType *bt, const RTypeLayout *layout, int *off, int *align) {
	int av = layout->align;
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
	end += layout->bits / 8;
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
