/* radare - LGPL - Copyright 2026 */

typedef struct {
	RAnal *anal;
	RBinFile *file;
	Sdb *ne;
} BorlandProfileContext;

static bool profile_identity(RAnal *anal, BorlandProfileContext *ctx, const char *format, int size, const char *sha256) {
	RBinFile *file = anal->binb.bin? anal->binb.bin->cur: NULL;
	if (!file || !file->bo || !file->bo->plugin || strcmp (file->bo->plugin->meta.name, format)
			|| !file->buf || r_buf_size (file->buf) != size || !anal->mb.hash) {
		return false;
	}
	RIODesc *desc = anal->iob.desc_get? anal->iob.desc_get (anal->iob.io, file->fd): NULL;
	if (!desc || (desc->perm & R_PERM_W)) {
		return false;
	}
	ut8 *original = malloc (size);
	if (!original) {
		return false;
	}
	bool valid = r_buf_read_at (file->buf, 0, original, size) == size;
	int digest_size = 0;
	ut8 *digest = valid? anal->mb.hash (&anal->mb, "sha256", original, size, &digest_size): NULL;
	char hex[65] = {0};
	if (digest && digest_size == 32) {
		r_hex_bin2str (digest, digest_size, hex);
	}
	free (digest);
	free (original);
	if (strcmp (hex, sha256)) {
		return false;
	}
	*ctx = (BorlandProfileContext){ anal, file, file->bo->plugin->get_sdb? file->bo->plugin->get_sdb (file): file->sdb_info };
	return ctx->ne != NULL;
}

static ut64 profile_mapped(BorlandProfileContext *ctx, ut64 physical, int size, bool executable) {
	RAnal *anal = ctx->anal;
	if (size < 1 || physical > r_buf_size (ctx->file->buf) || size > r_buf_size (ctx->file->buf) - physical
			|| !anal->iob.map_get_at || !anal->iob.bank_get || !anal->iob.map_get || !anal->iob.io->va) {
		return UT64_MAX;
	}
	ut64 address = UT64_MAX;
	RBinSection *section;
	R_VEC_FOREACH (&ctx->file->bo->sections_vec, section) {
		ut64 length = R_MIN (section->size, section->vsize);
		if (!length || section->paddr >= physical + size || (section->paddr < physical && physical - section->paddr >= length)) {
			continue;
		}
		if (address != UT64_MAX || physical < section->paddr || size > length - (physical - section->paddr)
				|| section->vaddr > UT64_MAX - length || (executable && !(section->perm & R_PERM_X))) {
			return UT64_MAX;
		}
		address = section->vaddr + physical - section->paddr;
	}
	RIOBank *bank = anal->iob.bank_get (anal->iob.io, anal->iob.io->bank);
	if (address == UT64_MAX || !bank) {
		return UT64_MAX;
	}
	int i;
	for (i = 0; i < size; i++) {
		RIOMap *active = anal->iob.map_get_at (anal->iob.io, address + i);
		if (!active || active->fd != ctx->file->fd || !(active->perm & R_PERM_R)
				|| (executable && !(active->perm & R_PERM_X))
				|| active->delta > physical + i || address + i - active->itv.addr != physical + i - active->delta) {
			return UT64_MAX;
		}
		RListIter *iter;
		RIOMapRef *ref;
		r_list_foreach (bank->maprefs, iter, ref) {
			RIOMap *map = anal->iob.map_get (anal->iob.io, ref->id);
			if (!map || map->ts != ref->ts || map->fd != ctx->file->fd || map->delta > physical + i
					|| physical + i - map->delta >= map->itv.size) {
				continue;
			}
			// A whole-file physical backing view is not another canonical image projection.
			if (!map->itv.addr && !map->delta && map->itv.size == r_buf_size (ctx->file->buf)) {
				continue;
			}
			ut64 alias = map->itv.addr + physical + i - map->delta;
			if (alias != address + i && anal->iob.map_get_at (anal->iob.io, alias) == map) {
				return UT64_MAX;
			}
		}
	}
	return address;
}

static bool profile_number(BorlandProfileContext *ctx, const char *key, const char *field, ut64 *value) {
	char name[160];
	snprintf (name, sizeof (name), "%s.%s", key, field);
	if (!sdb_const_get (ctx->ne, name, NULL)) {
		return false;
	}
	*value = sdb_num_get (ctx->ne, name, NULL);
	return true;
}

static bool profile_number_is(BorlandProfileContext *ctx, const char *key, const char *field, ut64 expected) {
	ut64 value;
	return profile_number (ctx, key, field, &value) && value == expected;
}

static bool profile_relocated(BorlandProfileContext *ctx, ut64 physical, int size, ut64 address, ut8 *expected, bool *relocated) {
	RBinReloc *reloc;
	R_VEC_FOREACH (ctx->file->bo->relocs, reloc) {
		int width = reloc->type / 8;
		if (reloc->paddr >= physical + size || (reloc->paddr < physical && physical - reloc->paddr >= width)) {
			continue;
		}
		if (reloc->paddr < physical || width < 1 || width > physical + size - reloc->paddr
				|| reloc->vaddr != address + reloc->paddr - physical) {
			return false;
		}
		ut64 target = reloc->import? reloc->laddr: reloc->addend;
		if (target == UT64_MAX) {
			return false;
		}
		int off = reloc->paddr - physical;
		switch (reloc->ntype) {
		case 0:
			if (width != 1) {
				return false;
			}
			expected[off] = target + (reloc->additive? expected[off]: 0);
			break;
		case 2:
		case 5:
			if (width != 2) {
				return false;
			}
			r_write_le16 (expected + off, (reloc->ntype == 2? target >> 16: target) + (reloc->additive? r_read_le16 (expected + off): 0));
			break;
		case 3:
			if (width != 4) {
				return false;
			}
			r_write_le32 (expected + off, target + (reloc->additive? r_read_le32 (expected + off): 0));
			break;
		default:
			return false;
		}
		int i;
		for (i = off; i < off + width; i++) {
			if (relocated[i]) {
				return false;
			}
			relocated[i] = true;
		}
	}
	char segment[48];
	snprintf (segment, sizeof (segment), "ne.reloc.%"PFMT64u, address >> 16);
	ut64 count;
	if (!profile_number (ctx, segment, "count", &count) || count > r_buf_size (ctx->file->buf) / 8) {
		return false;
	}
	ut64 record;
	for (record = 0; record < count; record++) {
		char key[72];
		snprintf (key, sizeof (key), "%s.%"PFMT64u, segment, record);
		ut64 flags;
		if (!profile_number (ctx, key, "flags", &flags)) {
			return false;
		}
		// The native NE loader leaves OS instruction fixups unchanged, not address-relocated.
		if ((flags & 3) == 3) {
			continue;
		}
		ut64 applications;
		// Unexpanded address records could hide fields in this segment; they do not qualify it.
		if (!profile_number (ctx, key, "application_count", &applications) || !applications || applications > 65536) {
			return false;
		}
		ut64 application;
		for (application = 0; application < applications; application++) {
			char field[112];
			snprintf (field, sizeof (field), "%s.application.%"PFMT64u, key, application);
			ut64 at, width;
			if (!profile_number (ctx, field, "paddr", &at) || !profile_number (ctx, field, "width", &width) || !width || width > 6) {
				return false;
			}
			if (at >= physical + size || (at < physical && physical - at >= width)) {
				continue;
			}
			if (at < physical || width > physical + size - at) {
				return false;
			}
			ut64 i;
			for (i = at - physical; i < at - physical + width; i++) {
				if (!relocated[i]) {
					return false;
				}
			}
		}
	}
	return true;
}

static bool profile_current(BorlandProfileContext *ctx, ut64 physical, int size, ut64 address, ut8 *current) {
	RAnal *anal = ctx->anal;
	if (size < 1 || address == UT64_MAX || profile_mapped (ctx, physical, size, false) != address
			|| borland_eligible (anal) < 0 || !anal->iob.read_at || !ctx->file->bo->relocs) {
		return false;
	}
	ut8 *expected = malloc (size);
	bool *relocated = calloc (size, sizeof (bool));
	bool valid = expected && relocated
		&& r_buf_read_at (ctx->file->buf, physical, expected, size) == size
		&& anal->iob.read_at (anal->iob.io, address, current, size) == size
		&& profile_relocated (ctx, physical, size, address, expected, relocated)
		&& !memcmp (expected, current, size);
	free (expected);
	free (relocated);
	if (!valid) {
		return false;
	}
	int off;
	for (off = 0; off < size; off++) {
		ut64 at = address + off;
		int bits = r_anal_hint_bits_at (anal, at, NULL);
		const char *arch = r_anal_hint_arch_at (anal, at, NULL);
		bool override = false;
		const RVecAnalAddrHintRecord *hints = r_anal_addr_hints_at (anal, at);
		if (hints) {
			RAnalAddrHintRecord *hint;
			R_VEC_FOREACH (hints, hint) {
				override |= hint->type != R_ANAL_ADDR_HINT_TYPE_IMMBASE && hint->type != R_ANAL_ADDR_HINT_TYPE_SYNTAX
					&& hint->type != R_ANAL_ADDR_HINT_TYPE_HIGH && hint->type != R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET
					&& hint->type != R_ANAL_ADDR_HINT_TYPE_ENUM;
			}
		}
		if ((bits && bits != 16) || (arch && strcmp (arch, "x86")) || override) {
			return false;
		}
	}
	return true;
}

static bool profile_code(BorlandProfileContext *ctx, ut64 physical, int size, ut64 address, HelperOp *ops) {
	size_t allocation;
	if (size < 1 || address == UT64_MAX || profile_mapped (ctx, physical, size, true) != address
			|| r_mul_overflow ((size_t)size, sizeof (HelperOp), &allocation)) {
		return false;
	}
	memset (ops, 0, allocation);
	ut8 *current = malloc (size);
	if (!current) {
		return false;
	}
	bool valid = profile_current (ctx, physical, size, address, current);
	int off = 0;
	while (valid && off < size) {
		RAnalOp op = {0};
		int length = r_anal_op (ctx->anal, &op, address + off, current + off, size - off, R_ARCH_OP_MASK_BASIC);
		valid = length > 0 && length <= size - off && op.type != R_ANAL_OP_TYPE_ILL && op.type != R_ANAL_OP_TYPE_UNK && ctx->anal->config->bits == 16;
		ops[off] = (HelperOp){ length, op.type & R_ANAL_OP_TYPE_MASK, op.jump, op.fail };
		r_anal_op_fini (&op);
		off += length;
	}
	free (current);
	return valid;
}

static bool profile_label(BorlandProfileContext *ctx, ut64 address, const char *name) {
	RFlag *flags = ctx->anal->flb.f;
	if (!flags) {
		return false;
	}
	RFlagItem *flag = r_flag_get (flags, name);
	if (flag) {
		if (flag->addr != address) {
			R_LOG_WARN ("Borland profile: preserving label %s", name);
			return false;
		}
		return true;
	}
	return r_flag_set (flags, name, address, 1) != NULL;
}

static bool profile_reference(RAnal *anal, ut64 from, ut64 to, ut32 type) {
	RVecAnalRef *refs = r_anal_refs_get (anal, from);
	RAnalRef *ref;
	if (refs) {
		R_VEC_FOREACH (refs, ref) {
			if (ref->addr == to) {
				bool equivalent = R_ANAL_REF_TYPE_MASK (ref->type) == type;
				if (!equivalent) {
					R_LOG_WARN ("Borland profile: preserving reference type at 0x%08"PFMT64x" -> 0x%08"PFMT64x, from, to);
				}
				RVecAnalRef_free (refs);
				return equivalent;
			}
		}
	}
	RVecAnalRef_free (refs);
	return r_anal_xrefs_set (anal, from, to, type);
}

typedef struct {
	ut64 physical;
	int size;
} BorlandProfileRange;

static bool profile_leaders(const BorlandCodeRange *ranges, int count, bool *leaders) {
	size_t index = 0;
	int i, j, off;
	for (i = 0; i < count; i++) {
		const BorlandCodeRange *range = &ranges[i];
		leaders[index] = true;
		for (off = 0; off < range->size; off += range->ops[off].size) {
			const HelperOp *op = &range->ops[off];
			if (borland_ends_block (op)) {
				ut64 edges[] = { op->jump, op->fail };
				int edge;
				for (edge = 0; edge < R_ARRAY_SIZE (edges); edge++) {
					size_t target_index = 0;
					for (j = 0; j < count; j++) {
						if (edges[edge] >= ranges[j].address && edges[edge] - ranges[j].address < ranges[j].size) {
							int target = edges[edge] - ranges[j].address;
							if (!ranges[j].ops[target].size) {
								return false;
							}
							leaders[target_index + target] = true;
							break;
						}
						target_index += ranges[j].size;
					}
				}
				if (off + op->size < range->size) {
					leaders[index + off + op->size] = true;
				}
			}
		}
		index += range->size;
	}
	return true;
}

static bool profile_function_ranges(BorlandProfileContext *ctx, const BorlandProfileRange *input, int count, const char *name, int purge, const char *comment) {
	RAnal *anal = ctx->anal;
	size_t allocation, total = 0;
	if (count < 1 || r_mul_overflow ((size_t)count, sizeof (BorlandCodeRange), &allocation)) {
		return false;
	}
	BorlandCodeRange *ranges = calloc (1, allocation);
	if (!ranges) {
		return false;
	}
	bool applied = false;
	bool *leaders = NULL;
	int i;
	for (i = 0; i < count; i++) {
		int size = input[i].size;
		ut64 address = profile_mapped (ctx, input[i].physical, size, true);
		if (size < 1 || address == UT64_MAX || (i && address < ranges[i - 1].address + ranges[i - 1].size)
				|| r_add_overflow (total, (size_t)size, &total) || r_mul_overflow ((size_t)size, sizeof (HelperOp), &allocation)) {
			goto beach;
		}
		ranges[i] = (BorlandCodeRange){ address, size, calloc (1, allocation) };
		if (!ranges[i].ops || !profile_code (ctx, input[i].physical, size, address, ranges[i].ops)) {
			R_LOG_WARN ("Borland profile: refused current mapping/bytes/context at FILE 0x%08"PFMT64x, input[i].physical);
			goto beach;
		}
	}
	leaders = calloc (total, sizeof (bool));
	if (!leaders || !profile_leaders (ranges, count, leaders)) {
		goto beach;
	}
	ut64 address = ranges[0].address;
	RAnalFunction *fcn = r_anal_get_function_at (anal, address);
	RListIter *iter;
	RAnalBlock *bb;
	bool conflict = false;
	for (i = 0; i < count; i++) {
		RList *blocks = r_anal_get_blocks_intersect (anal, ranges[i].address, ranges[i].size);
		r_list_foreach (blocks, iter, bb) {
			conflict |= !fcn || !r_list_contains (fcn->bbs, bb) || r_list_length (bb->fcns) != 1;
		}
		r_list_free (blocks);
		RAnalFunction *other;
		r_list_foreach (anal->fcns, iter, other) {
			conflict |= other != fcn && other->addr >= ranges[i].address && other->addr - ranges[i].address < ranges[i].size;
		}
		RVecIntervalNodePtr *metadata = r_meta_get_all_intersect (anal, ranges[i].address, ranges[i].size, R_META_TYPE_ANY);
		RIntervalNode **node;
		if (metadata) {
			R_VEC_FOREACH (metadata, node) {
				RAnalMetaItem *item = (*node)->data;
				conflict |= item->type != R_META_TYPE_COMMENT && item->type != R_META_TYPE_HIGHLIGHT;
			}
		}
		RVecIntervalNodePtr_free (metadata);
	}
	if (fcn) {
		RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
		const char *cc = r_anal_cc_default (anal);
		conflict |= fcn->bits != 16 || !borland_body_ranges (fcn, ranges, count)
			|| (strcmp (fcn->name, name) && !borland_generic_name (fcn->name))
			|| (purge != R_ANAL_CC_STACK_POP_UNKNOWN && fcn->meta.stack_pop != R_ANAL_CC_STACK_POP_UNKNOWN && fcn->meta.stack_pop != purge)
			|| (fcn->callconv && (!cc || strcmp (cc, fcn->callconv))) || fcn->is_noreturn
			|| (signature && (signature->ret_type || !r_list_empty (signature->params)));
		r_anal_function_signature_free (signature);
	}
	RFlagItem *flag = anal->flb.f? r_flag_get (anal->flb.f, name): NULL;
	conflict |= flag && (flag->addr != address || !fcn);
	if (conflict) {
		R_LOG_WARN ("Borland profile: preserving function/body/name/contract/data at FILE 0x%08"PFMT64x, input[0].physical);
		goto beach;
	}
	if (!fcn) {
		fcn = r_anal_create_function (anal, name, address, R_ANAL_FCN_TYPE_FCN, NULL);
		if (!fcn) {
			goto beach;
		}
		size_t index = 0;
		for (i = 0; i < count; i++) {
			BorlandCodeRange *range = &ranges[i];
			int off = 0;
			while (off < range->size) {
				int start = off, instructions = 0;
				const HelperOp *last;
				do {
					last = &range->ops[off];
					off += last->size;
					instructions++;
				} while (off < range->size && !leaders[index + off]);
				bb = r_anal_create_block (anal, range->address + start, off - start);
				if (!bb) {
					goto beach;
				}
				bb->ninstr = instructions;
				int cursor = start, instruction = 0;
				while (cursor < off) {
					r_anal_bb_set_offset (bb, instruction++, cursor - start);
					cursor += range->ops[cursor].size;
				}
				borland_edges (last, range->address + off, &bb->jump, &bb->fail);
				r_anal_function_add_block (fcn, bb);
				r_unref (bb);
			}
			index += range->size;
		}
	}
	if (purge != R_ANAL_CC_STACK_POP_UNKNOWN && fcn->meta.stack_pop == R_ANAL_CC_STACK_POP_UNKNOWN) {
		fcn->meta.stack_pop = purge;
	}
	// Unknown source net cleanup supplies no override to independently derived native inference.
	if (!profile_label (ctx, address, name)) {
		goto beach;
	}
	borland_comment (anal, address, comment);
	for (i = 0; i < count; i++) {
		int off;
		for (off = 0; off < ranges[i].size; off += ranges[i].ops[off].size) {
			HelperOp *op = &ranges[i].ops[off];
			if (op->jump != UT64_MAX && (op->type == R_ANAL_OP_TYPE_CALL || op->type == R_ANAL_OP_TYPE_JMP || op->type == R_ANAL_OP_TYPE_CJMP)) {
				profile_reference (anal, ranges[i].address + off, op->jump, op->type == R_ANAL_OP_TYPE_CALL? R_ANAL_REF_TYPE_CALL: R_ANAL_REF_TYPE_CODE);
			}
		}
	}
	applied = true;
beach:
	for (i = 0; i < count; i++) {
		free (ranges[i].ops);
	}
	free (ranges);
	free (leaders);
	return applied;
}

static bool profile_function(BorlandProfileContext *ctx, ut64 physical, int size, const char *name, int purge, const char *comment) {
	BorlandProfileRange range = { physical, size };
	return profile_function_ranges (ctx, &range, 1, name, purge, comment);
}
