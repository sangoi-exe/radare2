/* radare - LGPL - Copyright 2026 */

typedef struct {
	RAnal *anal;
	ut64 address;
	ut64 end;
	const char *type;
	const RAnalBaseType *layout;
	ut64 element_size;
	bool linked;
	bool defined;
	bool link_only;
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
	if (item->type == R_META_TYPE_STRING) {
		if (check->element_size) {
			// The complete native STRING view is independent of the qualified array link.
			check->link_only = true;
			return true;
		}
		if (node->start >= check->address && node->end < check->end && profile_data_field (check, node, true)) {
			return true;
		}
	}
	if (item->type == R_META_TYPE_DATA && !item->subtype && R_STR_ISEMPTY (item->str)) {
		if (node->start == check->address && node->end == check->end - 1) {
			check->defined = true;
			return true;
		}
		bool element = check->element_size && node->start >= check->address && node->end < check->end
			&& (node->start - check->address) % check->element_size == 0 && node->end - node->start + 1 == check->element_size;
		if (element || profile_data_field (check, node, false)) {
			check->link_only |= node->start == check->address;
			return true;
		}
	}
	check->conflict = true;
	R_LOG_WARN ("Borland profile: preserving metadata %c at [0x%08"PFMT64x",0x%08"PFMT64x"]", item->type, node->start, node->end);
	return false;
}

static bool profile_data_preflight(BorlandProfileContext *ctx, ut64 physical, int size, const char *type, ut64 element_size, BorlandDataCheck *result) {
	RAnal *anal = ctx->anal;
	ut64 address = profile_mapped (ctx, physical, size, false);
	ut64 bits = r_type_get_bitsize (anal->sdb_types, type);
	if (size < 1 || address == UT64_MAX || (bits && bits != (ut64)size * 8)
			|| (!bits && sdb_const_get (anal->sdb_types, type, NULL))) {
		return false;
	}
	ut8 *current = malloc (size);
	bool qualified = current && profile_current (ctx, physical, size, address, current);
	free (current);
	if (!qualified) {
		return false;
	}
	RAnalBaseType *layout = r_anal_get_base_type (anal, type, R_TYPE_NAMESPACE_ORDINARY);
	BorlandDataCheck check = {
		.anal = anal, .address = address, .end = address + size, .type = type, .layout = layout,
		.element_size = element_size
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
	check.layout = NULL;
	*result = check;
	return true;
}

static bool profile_data_region(BorlandProfileContext *ctx, ut64 physical, int size, const char *type, ut64 element_size) {
	BorlandDataCheck check;
	if (r_type_get_bitsize (ctx->anal->sdb_types, type) != (ut64)size * 8
			|| !profile_data_preflight (ctx, physical, size, type, element_size, &check)) {
		return false;
	}
	RAnal *anal = ctx->anal;
	ut64 address = check.address;
	if (!check.linked && !r_anal_types_set_link (anal, type, address)) {
		return false;
	}
	// Preserve first-field DATA widths and complete overlapping STRING views; the native link carries the aggregate layout.
	return check.defined || check.link_only || r_meta_set (anal, R_META_TYPE_DATA, address, size, NULL);
}

static bool profile_data(BorlandProfileContext *ctx, ut64 physical, int size, const char *type) {
	return profile_data_region (ctx, physical, size, type, 0);
}

static bool profile_data_array(BorlandProfileContext *ctx, ut64 physical, const char *element_type, ut32 count) {
	ut64 bits = r_type_get_bitsize (ctx->anal->sdb_types, element_type), total;
	if (!count || !bits || bits % 8 || r_mul_overflow (bits / 8, (ut64)count, &total) || total > INT_MAX) {
		return false;
	}
	char *type = r_str_newf ("%s [%u]", element_type, count);
	bool applied = type && profile_data_region (ctx, physical, total, type, bits / 8);
	free (type);
	return applied;
}
