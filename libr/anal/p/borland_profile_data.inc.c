/* radare - LGPL - Copyright 2026 */

typedef struct {
	RAnal *anal;
	ut64 address;
	ut64 end;
	const char *type;
	const RAnalBaseType *layout;
	bool raw_array;
	bool linked;
	bool defined;
	bool head_field;
	bool conflict;
} BorlandDataCheck;

static bool profile_data_link(void *user, const char *key, const char *type) {
	BorlandDataCheck *check = user;
	if (!r_str_startswith (key, "link.")) {
		return true;
	}
	char *tail;
	errno = 0;
	ut64 address = strtoull (key + 5, &tail, 16);
	if (errno || tail == key + 5 || *tail) {
		check->conflict = true;
		return false;
	}
	if (address >= check->end) {
		return true;
	}
	ut64 bits = r_type_get_bitsize (check->anal->sdb_types, type);
	if (!bits && r_type_kind (check->anal->sdb_types, type) == R_TYPE_FUNCTION) {
		// A native prototype link is code state, not an unknown-width data object.
		check->conflict |= address >= check->address;
		return !check->conflict;
	}
	ut64 size = bits / 8;
	if (!bits || bits % 8 || address > UT64_MAX - size) {
		R_LOG_WARN ("Borland profile: preserving unbounded object link %s at 0x%08"PFMT64x, type, address);
		check->conflict = true;
		return false;
	}
	if (address + size <= check->address) {
		return true;
	}
	if (address == check->address && address + size == check->end && !strcmp (type, check->type)) {
		check->linked = true;
		return true;
	}
	check->conflict = true;
	R_LOG_WARN ("Borland profile: preserving object link %s at [0x%08"PFMT64x",0x%08"PFMT64x")", type, address, address + size);
	return false;
}

static bool profile_data_field(const BorlandDataCheck *check, const RIntervalNode *node, bool raw_bytes) {
	if (!check->layout || check->layout->kind != R_ANAL_BASE_TYPE_KIND_STRUCT) {
		return false;
	}
	RAnalTypeMember *member;
	R_VEC_FOREACH (&check->layout->struct_data.members, member) {
		if (member->bitsize || (raw_bytes && (!member->count || strcmp (member->type, "uint8_t")))) {
			continue;
		}
		ut64 bits = r_type_get_bitsize (check->anal->sdb_types, member->type);
		if (!bits || (raw_bytes && bits != 8) || (member->count && r_mul_overflow (bits, (ut64)member->count, &bits)) || bits % 8) {
			continue;
		}
		ut64 size = bits / 8;
		if (member->offset > check->end - check->address || size > check->end - check->address - member->offset) {
			continue;
		}
		ut64 start = check->address + member->offset, end = start + size - 1;
		if (raw_bytes? node->start >= start && node->end <= end: node->start == start && node->end == end) {
			return true;
		}
	}
	return false;
}

static bool profile_data_meta(RIntervalNode *node, void *user) {
	BorlandDataCheck *check = user;
	RAnalMetaItem *item = node->data;
	if (item->type == R_META_TYPE_COMMENT || item->type == R_META_TYPE_HIGHLIGHT) {
		return true;
	}
	if (item->type == R_META_TYPE_STRING && node->start >= check->address && node->end < check->end) {
		if (check->raw_array || profile_data_field (check, node, true)) {
			return true;
		}
	}
	if (item->type == R_META_TYPE_DATA && !item->subtype && R_STR_ISEMPTY (item->str)) {
		if (node->start == check->address && node->end == check->end - 1) {
			check->defined = true;
			return true;
		}
		if (profile_data_field (check, node, false)) {
			check->head_field |= node->start == check->address;
			return true;
		}
	}
	check->conflict = true;
	R_LOG_WARN ("Borland profile: preserving metadata %c at [0x%08"PFMT64x",0x%08"PFMT64x"]", item->type, node->start, node->end);
	return false;
}

static bool profile_data(BorlandProfileContext *ctx, ut64 physical, int size, const char *type) {
	RAnal *anal = ctx->anal;
	ut64 address = profile_mapped (ctx, physical, size, false);
	if (size < 1 || address == UT64_MAX || r_type_get_bitsize (anal->sdb_types, type) != (ut64)size * 8) {
		return false;
	}
	ut8 *current = malloc (size);
	bool qualified = current && profile_current (ctx, physical, size, address, current);
	free (current);
	if (!qualified) {
		return false;
	}
	char raw_array[64];
	snprintf (raw_array, sizeof (raw_array), "uint8_t [%d]", size);
	RAnalBaseType *layout = r_anal_get_base_type (anal, type);
	BorlandDataCheck check = {
		.anal = anal, .address = address, .end = address + size, .type = type, .layout = layout,
		.raw_array = !strcmp (type, raw_array) && r_type_get_bitsize (anal->sdb_types, "uint8_t") == 8
	};
	check.conflict |= !sdb_foreach (anal->sdb_types, profile_data_link, &check);
	// Query the native interval tree directly: a selected metadata space must not hide other owners.
	r_interval_tree_all_intersect (&anal->meta, address, check.end - 1, true, profile_data_meta, &check);
	if (layout) {
		r_anal_base_type_free (layout);
	}
	RList *blocks = r_anal_get_blocks_intersect (anal, address, size);
	check.conflict |= !r_list_empty (blocks);
	r_list_free (blocks);
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, iter, fcn) {
		check.conflict |= fcn->addr >= address && fcn->addr < check.end;
	}
	if (check.conflict) {
		R_LOG_WARN ("Borland profile: preserving data/type/link/code at FILE 0x%08"PFMT64x, physical);
		return false;
	}
	if (!check.linked && !r_anal_types_set_link (anal, type, address)) {
		return false;
	}
	// Same-type/start metadata setters would resize a retained first field; the aggregate link already carries its layout.
	return check.defined || check.head_field || r_meta_set (anal, R_META_TYPE_DATA, address, size, NULL);
}
