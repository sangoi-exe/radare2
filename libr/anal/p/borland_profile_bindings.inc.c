/* radare - LGPL - Copyright 2026 */

typedef struct {
	int type;
	int flags;
	int word0;
	int word1;
	ut64 target_file;
	const char *module;
	bool singleton;
	bool executable;
	bool reference;
} BorlandProfileBinding;

static bool profile_binding(BorlandProfileContext *ctx, ut64 physical, const BorlandProfileBinding *fact) {
	int width = fact->type == 3? 4: 2;
	if ((fact->type != 2 && fact->type != 3 && fact->type != 5) || (fact->flags & ~5) || (fact->reference && fact->target_file == UT64_MAX)) {
		return false;
	}
	ut64 address = profile_mapped (ctx, physical, width, fact->executable);
	ut64 target = fact->target_file == UT64_MAX? UT64_MAX: profile_mapped (ctx, fact->target_file, 1, false);
	ut8 original[4], current[4];
	if (address == UT64_MAX || (fact->target_file != UT64_MAX && target == UT64_MAX)
			|| !profile_current (ctx, physical, width, address, current)
			|| r_buf_read_at (ctx->file->buf, physical, original, width) != width) {
		return false;
	}
	char segment[48];
	snprintf (segment, sizeof (segment), "ne.reloc.%"PFMT64u, address >> 32);
	ut64 count;
	if (!profile_number (ctx, segment, "count", &count) || count > r_buf_size (ctx->file->buf) / 8) {
		return false;
	}
	int matches = 0;
	ut64 record;
	for (record = 0; record < count; record++) {
		char key[72];
		snprintf (key, sizeof (key), "%s.%"PFMT64u, segment, record);
		ut64 applications;
		if (!profile_number (ctx, key, "application_count", &applications) || applications > 65536) {
			return false;
		}
		ut64 application;
		for (application = 0; application < applications; application++) {
			char field[112];
			snprintf (field, sizeof (field), "%s.application.%"PFMT64u, key, application);
			if (!profile_number_is (ctx, field, "paddr", physical)) {
				continue;
			}
			ut64 resolved;
			if (!profile_number_is (ctx, key, "source_segment", address >> 32)
					|| !profile_number_is (ctx, key, "type", fact->type) || !profile_number_is (ctx, key, "flags", fact->flags)
					|| !profile_number_is (ctx, key, "additive", !!(fact->flags & 4))
					|| !profile_number_is (ctx, key, "target_word0", fact->word0) || !profile_number_is (ctx, key, "target_word1", fact->word1)
					|| !profile_number_is (ctx, field, "vaddr", address) || !profile_number_is (ctx, field, "width", width)
					|| !profile_number (ctx, key, "target_vaddr", &resolved) || resolved == UT64_MAX
					|| !profile_number_is (ctx, field, "target_vaddr", resolved) || (target != UT64_MAX && resolved != target)) {
				return false;
			}
			char original_key[128], hex[9];
			snprintf (original_key, sizeof (original_key), "%s.original", field);
			r_hex_bin2str (original, width, hex);
			const char *stored = sdb_const_get (ctx->ne, original_key, NULL);
			if (!stored || strcmp (stored, hex) || (fact->singleton && (applications != 1 || (fact->flags & 4)
					|| !profile_number_is (ctx, key, "source_offset", address & UT32_MAX)
					|| (width == 4? r_read_le32 (original): r_read_le16 (original)) != UT16_MAX))) {
				return false;
			}
			int kind = fact->flags & 3;
			if (kind == 1) {
				char import_key[96];
				snprintf (import_key, sizeof (import_key), "%s.import_name", key);
				const char *name = sdb_const_get (ctx->ne, import_key, NULL);
				if (!fact->module || !name || strncmp (name, fact->module, strlen (fact->module))
						|| name[strlen (fact->module)] != '.' || !profile_number_is (ctx, key, "import_ordinal", fact->word1)) {
					return false;
				}
			} else if (kind || fact->module || target == UT64_MAX) {
				return false;
			}
			int native_matches = 0;
			RBinReloc *reloc;
			R_VEC_FOREACH (ctx->file->bo->relocs, reloc) {
				if (reloc->paddr == physical) {
					if (reloc->vaddr != address || reloc->ntype != fact->type || reloc->type / 8 != width
							|| reloc->additive != !!(fact->flags & 4) || !!reloc->import != !!kind
							|| (reloc->import? reloc->laddr: reloc->addend) != resolved) {
						return false;
					}
					native_matches++;
				}
			}
			ut64 value = resolved;
			if (fact->type == 2) {
				value = resolved >> 32;
			} else if (fact->type == 3) {
				value = ((ut32)(resolved >> 32) << 16) | (resolved & UT16_MAX);
			}
			if (fact->flags & 4) {
				value += width == 4? r_read_le32 (original): r_read_le16 (original);
			}
			if (native_matches != 1 || (width == 4? r_read_le32 (current) != (ut32)value: r_read_le16 (current) != (ut16)value)) {
				return false;
			}
			matches++;
		}
	}
	if (matches != 1) {
		R_LOG_WARN ("Borland profile: refused native field binding at FILE 0x%08"PFMT64x, physical);
		return false;
	}
	return !fact->reference || profile_reference (ctx->anal, address, target, R_ANAL_REF_TYPE_DATA);
}

static bool profile_word(BorlandProfileContext *ctx, ut64 physical, ut16 expected) {
	ut64 address = profile_mapped (ctx, physical, 2, false);
	ut8 current[2], original[2];
	return address != UT64_MAX && profile_current (ctx, physical, 2, address, current)
		&& r_buf_read_at (ctx->file->buf, physical, original, 2) == 2
		&& r_read_le16 (original) == expected && r_read_le16 (current) == expected;
}

static bool profile_offset(BorlandProfileContext *ctx, ut64 physical, ut16 expected, ut64 target_file) {
	ut64 source = profile_mapped (ctx, physical, 2, false);
	ut64 target = profile_mapped (ctx, target_file, 1, false);
	return source != UT64_MAX && target != UT64_MAX && profile_word (ctx, physical, expected)
		&& profile_reference (ctx->anal, source, target, R_ANAL_REF_TYPE_DATA);
}

static bool profile_near(BorlandProfileContext *ctx, ut64 physical, ut64 target_file, bool converted) {
	int size = converted? 5: 3, call = converted? 2: 0;
	ut64 address = profile_mapped (ctx, physical, size, true);
	ut64 target = profile_mapped (ctx, target_file, 1, true);
	HelperOp ops[5];
	ut8 original[5];
	int selector_shift = !strcmp (ctx->file->bo->plugin->meta.name, "ne")? 32: 16;
	if (address == UT64_MAX || target == UT64_MAX || address >> selector_shift != target >> selector_shift
			|| !profile_code (ctx, physical, size, address, ops) || r_buf_read_at (ctx->file->buf, physical, original, size) != size
			|| (converted && (original[0] != 0x90 || original[1] != 0x0e || ops[0].type != R_ANAL_OP_TYPE_NOP || ops[1].type != (R_ANAL_OP_TYPE_RPUSH & R_ANAL_OP_TYPE_MASK)))
			|| original[call] != 0xe8 || r_read_le16 (original + call + 1) != (ut16)(target - address - call - 3)
			|| ops[call].size != 3 || ops[call].type != R_ANAL_OP_TYPE_CALL || ops[call].jump != target) {
		return false;
	}
	return profile_reference (ctx->anal, address + call, target, R_ANAL_REF_TYPE_CALL);
}
