/* radare - LGPL - Copyright 2026 */

#define BORLAND_PROFILE_BCC20_INCLUDED
#define BCC20_MARKER "[LegacyToolchains bcc20-qualified] "
#define BCC20_DS 0xeef0

static const struct { ut16 identifier; ut16 paragraph; ut32 physical; ut16 code; ut16 fixups; } bcc20_bodies[] = {
	{ 0x0338, 0x0c85, 0x43a60, 0x10c7, 0x009a },
	{ 0x0378, 0x0caf, 0x4b6b0, 0x0522, 0x0048 },
	{ 0x03e0, 0x0ce6, 0x54350, 0x0151, 0x0008 },
	{ 0x0458, 0x0d30, 0x62db0, 0x019c, 0x002a },
	{ 0x0460, 0x0d33, 0x62f80, 0x01fb, 0x0024 },
	{ 0x0470, 0x0d38, 0x631b0, 0x10c4, 0x0044 },
	{ 0x0488, 0x0d48, 0x650a0, 0x0753, 0x0028 },
	{ 0x0490, 0x0d4f, 0x65830, 0x0f2e, 0x003c },
	{ 0x0498, 0x0d58, 0x667c0, 0x02b1, 0x0012 },
	{ 0x04a0, 0x0d5c, 0x66a90, 0x2251, 0x0184 },
	{ 0x04c8, 0x0d6d, 0x69d70, 0x0ceb, 0x008a },
	{ 0x04f8, 0x0d8e, 0x6e460, 0x11b5, 0x0110 },
	{ 0x0508, 0x0d96, 0x6f8c0, 0x09f3, 0x0010 },
	{ 0x0510, 0x0d9d, 0x702d0, 0x1209, 0x00aa },
	{ 0x0598, 0x0dd8, 0x78700, 0x1057, 0x014a }
};

static const struct { ut64 start; ut64 end; const char *name; int purge; const char *comment; } bcc20_functions[] = {
	{ 0x43d7a, 0x43db2, "bcc20_submit_option_table", 6, BCC20_MARKER "R1740338:[031a,0352); far wrapper RETF6; I/L+zero and other+ffff bypasses; normal return restores SI." },
	{ 0x43db2, 0x43dfc, "bcc20_dispatch_near_options", 6, BCC20_MARKER "R1740338:[0352,039c); near RET6, FF5402 handler call. Tagged INC-BP/POP-BP/DEC-BP frame; cleanup is six argument bytes, not a FAR prototype. Successful handlers do not end scanning." },
	{ 0x43dfc, 0x43e65, "bcc20_boolean_option_handler", 6, BCC20_MARKER "R1740338:[039c,0405); near RET6, tagged BP frame; saves/restores SI/DI only with intact frame. First suffix byte only, no suffix validation or rollback invented." },
	{ 0x43fc7, 0x43fe1, "bcc20_delegate_option_table", 6, BCC20_MARKER "R1740338:[0567,0581); near RET6 forwards descriptor+4 and unchanged input FAR pair." },
	{ 0x43d5b, 0x43d7a, "bcc20_transfer_option_bytes60", 0, BCC20_MARKER "R1740338:[02fb,031a); copies current643a+i to08bc+4*i, i0..59; not S/B/c intake." },
	{ 0x54350, 0x54386, "bcc20_reuse_linked_slot_or_append", 6, BCC20_MARKER "R13703e0:[0000,0036); separate reuse helper calls0056 when empty. Constructor bypasses this helper." },
	{ 0x543a6, 0x54435, "bcc20_append_arena", 6, BCC20_MARKER "R13703e0:[0056,00e5); returns saved old used offset, restores incoming SI/DI on normal intact-frame return. Capacity/growth and ffff error handling are conditional; descendant effects unproved." },
	{ 0x66899, 0x66900, "bcc20_construct_two_array_node", 8, BCC20_MARKER "R117/R1370498:[00d9,0140); two four-byte appends; first returned U selects immediate primary stores. Counter C read after opaque04e0 callback; U=4*C, U=V and callback SI/base preservation remain unproved." },
	{ 0x6526e, 0x6529d, "bcc20_record_for_current_id", 2, BCC20_MARKER "R1170488:[01ce,01fd); current889e list, reload current8894 at access groups; zero return does not add a caller guard." },
	{ 0x67e1a, 0x6802c, "bcc20_recognize_current_text_section", 0, BCC20_MARKER "R11704a0:[138a,159c); exact_TEXT comparator can OR88ac bit8 before other guards. Mismatch does not clear it; remaining branches/descendants not fully recovered." },
	{ 0x6824e, 0x682c1, "bcc20_construct_helper_prefix_node", 4, BCC20_MARKER "R11704a0:[17be,1831); model16ef and88ac bit8 choose N_/F_; rereads bit AFTER814c callback to choose77/78. No buffer bounds, arbitrary callback preservation or historical invocation inferred." },
	{ 0x682c1, 0x682ec, "bcc20_select_helper_suffix", 2, BCC20_MARKER "R11704a0:[1831,185c); suffix index4*record0+2*record2 wraps16, no bounds check; selected526b/526d contain528b (lxmul@)." },
	{ 0xba87, 0xbaa8, "bcc20_compare_terminated_bytes", 8, BCC20_MARKER "R117 resident0110:0007; sign-extended eight-bit difference, CLD/LODSB/SCASB, restores DS/SI/DI; not unrestricted strcmp semantics." },
	{ 0xc072, 0xc09d, "bcc20_copy_terminated_wrapper", 8, BCC20_MARKER "R117 resident0160:0002; source length+1 passed to transfer boundary, not arbitrary extent/pointer validity." },
	{ 0xc146, 0xc180, "bcc20_append_terminated_wrapper", 8, BCC20_MARKER "R117 resident0170:0006; adds destination length only to offset, no segment carry." },
	{ 0x62dc6, 0x62f0b, "bcc20_section_reset_caller", 4, BCC20_MARKER "R1250458:[0016,015b); conditional caller, not per-file scheduling proof." },
	{ 0x62f80, 0x6317b, "bcc20_initialize_section_state_and_backend", 4, BCC20_MARKER "R125/R1600460:[0000,01fb); selected fill zeros889e..88b9 including88ac at fill return only. Final fresh BYTE1714 chooses installed backend; downstream state survival unproved." },
	{ 0x650a0, 0x651f0, "bcc20_construct_section_list_record", 8, BCC20_MARKER "R1250488:[0000,0150); selected27-byte record name+11 from frame+0a, counter+4 and link state; no upstream name/CLI handoff inferred." },
	{ 0x65930, 0x659a8, "bcc20_capture_current_section_id", 20, BCC20_MARKER "R1250490:[0100,0178); frame+0e ->86d6; independent clear86d4..86f4 does not include88ac; descendant effects remain conditional." },
	{ 0x65db7, 0x65e44, "bcc20_dispatch_section_recognition", 6, BCC20_MARKER "R1250490:[0587,0614); conditional direct recognizer call after opaque callbacks/current addressed tests." },
	{ 0xbf23, 0xbf51, "bcc20_fill_bytes", 8, BCC20_MARKER "R125 resident0150:0003; CLD/alignment/STOSW/tail, returns incoming destination DX:AX and restores SI/DI on normal return; valid extent required." },
	{ 0x1402, 0x1418, "bcc20_copy_callback_table_bytes", 8, BCC20_MARKER "R131 resident0000:0402; CLD/REP MOVSB forward copy, restores DS/SI/DI on normal return.96-byte installation requires valid views/no defeating aliases." },
	{ 0x633c8, 0x6344c, "bcc20_install_obj_callbacks", 4, BCC20_MARKER "R1600470:[0218,029c); source546e,current87cc,count0060.86d2&1 controls optional.obj suffix, not backend selection." },
	{ 0x78803, 0x788fa, "bcc20_install_asm_callbacks", 4, BCC20_MARKER "R1310598:[0103,01fa); source5552,current87cc,count0060; lifetime and output descendants remain conditional." },
	{ 0x631b0, 0x63200, "bcc20_append_backend_byte", 2, BCC20_MARKER "R1600470:[0000,0050); low argument BYTE only; current883e/8840 bound, growth path and current883c segment; ADD/ADC current section+0c/+0e after returning store, no physical writer semantics." },
	{ 0x78f38, 0x79244, "bcc20_asm_instruction_serializer", 2, BCC20_MARKER "R1310598:[0838,0b44); saves SI/DI on intact returning protocol. Selected77/78 near/far selectors and conditional78 PUSH-CS/near-CALL request; callbacks/current context and physical output remain unproved." },
	{ 0x78de6, 0x78e86, "bcc20_instruction_size_contribution", 2, BCC20_MARKER "R1310598:[06e6,0786); sign-extended descriptor byte+2 plus operand contributions, not raw byte+2 alone as final encoded size." },
	{ 0x78e86, 0x78f30, "bcc20_operand_size_contribution", 4, BCC20_MARKER "R1310598:[0786,0830); selected operand contribution, not complete encoding proof." },
	{ 0x792ca, 0x795a6, "bcc20_asm_operand_formatter", 4, BCC20_MARKER "R1310598:[0bca,0ea6); selected kind5 selectors12/15 request near/far and ptr literals; other kinds/context have separate paths." },
	{ 0x795da, 0x79622, "bcc20_asm_segment_prefix", 2, BCC20_MARKER "R1310598:[0eda,0f22); current record/group/name predicates and opaque callbacks remain conditional." },
	{ 0x6a642, 0x6a6a5, "bcc20_request_output_character", 2, BCC20_MARKER "R13104c8:[08d2,0935); buffered or opaque descendant requests, not completed physical output/preservation proof." },
	{ 0x6a9bc, 0x6aa04, "bcc20_request_output_string", 4, BCC20_MARKER "R13104c8:[0c4c,0c94); traversal or forwarded FAR pair; descendant effects unexpanded." },
	{ 0x6ea47, 0x6ee25, "bcc20_request_function_frame", 0, BCC20_MARKER "R14804f8:[05e7,09c5); fresh frame predicates select ENTER0092 or numeric-selector PUSH0094/MOV009c/SUB0028 requests; no historical control or physical output claim." },
	{ 0x6fa2e, 0x6fa53, "bcc20_capture_immediate_request", 6, BCC20_MARKER "R1480508:[016e,0193); frame amount+6,selector+8,tag+0a; initializes only selected8b28/8b2c/8b31/8b36 fields then near0243." },
	{ 0x6f982, 0x6f99f, "bcc20_lower_node_tag_request", 4, BCC20_MARKER "R1310508:[00c2,00df); builds current operand workspace, clears second kind and dispatches tag." },
	{ 0x6fb03, 0x6fda5, "bcc20_normalize_instruction_request", 2, BCC20_MARKER "R131/R1480508:[0243,04e5); current SUB0028 amount2/kind4/firstkind1 can request DEC005b twice. Pending/auxiliary/current87f4 callbacks can intervene; no unconditional flags, context or output equivalence." },
	{ 0x6fda5, 0x6fe45, "bcc20_flush_auxiliary_request", 2, BCC20_MARKER "R1310508:[04e5,0585); saves/restores SI/DI normally, current pending0057 and operand-kind edits remain conditional." },
	{ 0x6fe45, 0x700e1, "bcc20_build_operand_workspace", 4, BCC20_MARKER "R1310508:[0585,0821); nine-byte workspace, ID*4 array addressing;77/78 can select kind5 only under recorded record predicates, not universally." },
	{ 0x6405a, 0x64137, "bcc20_shorten_immediate_request", 6, BCC20_MARKER "R1680470:[0eaa,0f87); near RET6; tested descriptor flag WORD+3, selected current SUB amount2 yields conditional83/EC/02 byte requests, not physical encoding proof." },
	{ 0x64137, 0x641a1, "bcc20_request_immediate_bytes", 2, BCC20_MARKER "R1680470:[0f87,0ff1); near RET2; current kind4/adjustment3 requests low amount BYTE once; descendant effects remain open." },
	{ 0x63251, 0x63265, "bcc20_map_register_selector", 2, BCC20_MARKER "R1680470:[00a1,00b5); near RET2; signed BYTE index and signed BYTE result; selected0b maps04, not a universal unsigned register enum." },
	{ 0x70107, 0x70168, "bcc20_conditionally_fill_selector", 2, BCC20_MARKER "R357/R3630508:[0847,08a8); tagged BP frame, near RET2. Incoming argument is an already-scaled byte offset. Only an ff selector plus current tag08 or tag10/11 with current record bit mask02 can write primary+2; fresh segment/word reads and AL-only loads matter. A return need not change the selector; numeric selectors are not CPU register identities." },
	{ 0x70168, 0x7028f, "bcc20_construct_operand_fields", 4, BCC20_MARKER "R357/R3630508:[08a8,09cf); tagged BP frame, near RET4. Destination comes from current frame+6; current frame+4 ID is scaled modulo65536. Calls0847 before fresh selector reads. Selected bytes+3/+4 overwrite; word+5 accumulates modulo65536; selected word+7 replaces. No whole-record initialization or source-add expression inferred. Tag1f recursively processes first child, then freshly reloads second child after return; aliases may change globals, records, destination and saved stack. No valid graph or recursion termination inferred; AL loads retain AH unless explicitly cleared." },
	{ 0x64007, 0x64021, "bcc20_select_operand_prefix_byte", 2, BCC20_MARKER "R3350470:[0e57,0e71); tagged BP frame, near RET2. Current operand kind5 returns byte+2 in AL, otherwise AL=ff; AH is not cleared. Saves/restores SI on an intact normal-return stack; no general flags or arbitrary alias preservation contract." },
};

static bool bcc20_body(ut64 accepted, ut64 physical, int size) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bcc20_functions); i++) {
		if (physical < bcc20_functions[i].end && physical + size > bcc20_functions[i].start && !(accepted & (1ULL << i))) {
			return false;
		}
	}
	return true;
}

static bool bcc20_current(BorlandProfileContext *ctx, ut64 physical, int size) {
	ut64 address = profile_mapped (ctx, physical, size, false);
	ut8 *bytes = malloc (size);
	bool valid = bytes && profile_current (ctx, physical, size, address, bytes);
	free (bytes);
	return valid;
}

static bool bcc20_note(BorlandProfileContext *ctx, ut64 accepted, ut64 physical, int size, const char *name, const char *comment) {
	if (!bcc20_body (accepted, physical, size) || !bcc20_current (ctx, physical, size)) {
		return false;
	}
	ut64 address = profile_mapped (ctx, physical, size, false);
	if (name && !profile_label (ctx, address, name)) {
		return false;
	}
	borland_comment (ctx->anal, address, comment);
	return true;
}

static bool bcc20_data(BorlandProfileContext *ctx, ut64 physical, const char *element, ut32 count, const char *name) {
	if (!(count == 1? profile_data (ctx, physical, r_type_get_bitsize (ctx->anal->sdb_types, element) / 8, element): profile_data_array (ctx, physical, element, count))) {
		return false;
	}
	return !name || profile_label (ctx, profile_mapped (ctx, physical, 1, false), name);
}

static bool bcc20_reference(BorlandProfileContext *ctx, ut64 accepted, ut64 from, ut64 to) {
	ut64 source = profile_mapped (ctx, from, 2, false), target = profile_mapped (ctx, to, 1, false);
	return bcc20_body (accepted, from, 2) && bcc20_body (accepted, to, 1)
		&& bcc20_current (ctx, from, 2) && bcc20_current (ctx, to, 1)
		&& profile_reference (ctx->anal, source, target, R_ANAL_REF_TYPE_DATA);
}

static bool bcc20_mz_word(BorlandProfileContext *ctx, ut64 physical, ut16 paragraph) {
	ut64 address = profile_mapped (ctx, physical, 2, false);
	ut64 target = profile_mapped (ctx, 0x1000 + 16ULL * paragraph, 1, false);
	if (address == UT64_MAX || target != 16ULL * paragraph || !profile_word (ctx, physical, paragraph)) {
		return false;
	}
	int matches = 0;
	RBinReloc *reloc;
	R_VEC_FOREACH (ctx->file->bo->relocs, reloc) {
		if (reloc->paddr == physical) {
			if (reloc->vaddr != address || reloc->type != R_BIN_RELOC_16 || reloc->ntype || reloc->additive
					|| reloc->import || reloc->symbol || reloc->addend || reloc->laddr || reloc->is_ifunc) {
				return false;
			}
			matches++;
		}
	}
	return matches == 1;
}

static bool bcc20_view(BorlandProfileContext *ctx, size_t index) {
	RAnal *anal = ctx->anal;
	ut64 physical = bcc20_bodies[index].physical, address = 0x40010000 + index * 0x10000;
	ut64 size = bcc20_bodies[index].code + bcc20_bodies[index].fixups;
	ut64 resident = 0x1000 + 16ULL * bcc20_bodies[index].paragraph;
	ut8 descriptor[12];
	if (!bcc20_mz_word (ctx, 0xc390 + bcc20_bodies[index].identifier, bcc20_bodies[index].paragraph)
			|| !bcc20_current (ctx, resident, 2) || !bcc20_current (ctx, resident + 4, 2)
			|| !bcc20_current (ctx, resident + 6, 2) || !bcc20_current (ctx, resident + 8, 2) || !bcc20_current (ctx, resident + 10, 2)
			|| r_buf_read_at (ctx->file->buf, resident, descriptor, sizeof (descriptor)) != sizeof (descriptor)
			|| r_read_le16 (descriptor) != 0x3fcd || r_read_le32 (descriptor + 4) + 0x18cf0ULL != physical
			|| r_read_le16 (descriptor + 8) != bcc20_bodies[index].code || r_read_le16 (descriptor + 10) != bcc20_bodies[index].fixups
			|| !anal->iob.map_add) {
		return false;
	}
	char name[48];
	snprintf (name, sizeof (name), "bcc20_fbov_%04x_analysis", bcc20_bodies[index].identifier);
	RBinSection *section;
	int sections = 0, maps = 0;
	R_VEC_FOREACH (&ctx->file->bo->sections_vec, section) {
		bool overlap = (section->vaddr < address + size && address < section->vaddr + section->vsize)
			|| (section->add && section->paddr < physical + size && physical < section->paddr + section->size);
		if (!strcmp (section->name, name) || overlap) {
			if (strcmp (section->name, name) || section->paddr != physical || section->vaddr != address || section->size != size
					|| section->vsize != size || section->perm != R_PERM_RX || !section->add || section->bits != 16 || section->backing_fd != ctx->file->fd) {
				return false;
			}
			sections++;
		}
	}
	RIOBank *bank = anal->iob.bank_get (anal->iob.io, anal->iob.io->bank);
	if (!bank) {
		return false;
	}
	RListIter *iter;
	RIOMapRef *ref;
	r_list_foreach (bank->maprefs, iter, ref) {
		RIOMap *map = anal->iob.map_get (anal->iob.io, ref->id);
		if (!map || map->ts != ref->ts) {
			return false;
		}
		bool backing = map->fd == ctx->file->fd && map->delta < physical + size && physical < map->delta + map->itv.size;
		if (backing && !map->itv.addr && !map->delta && map->itv.size == r_buf_size (ctx->file->buf)) {
			backing = false;
		}
		if ((map->name && !strcmp (map->name, name)) || backing || (map->itv.addr < address + size && address < map->itv.addr + map->itv.size)) {
			if (!map->name || strcmp (map->name, name) || map->fd != ctx->file->fd || map->delta != physical
					|| map->itv.addr != address || map->itv.size != size || map->perm != R_PERM_RX) {
				return false;
			}
			maps++;
		}
	}
	if (sections != maps || sections > 1) {
		return false;
	}
	if (!sections) {
		if (!RVecRBinSection_reserve (&ctx->file->bo->sections_vec, RVecRBinSection_length (&ctx->file->bo->sections_vec) + 1)) {
			return false;
		}
		RIOMap *map = anal->iob.map_add (anal->iob.io, ctx->file->fd, R_PERM_RX, physical, address, size);
		if (!map) {
			return false;
		}
		r_io_map_set_name (map, name);
		RBinSection view = { .name = strdup (name), .paddr = physical, .vaddr = address, .size = size, .vsize = size,
			.perm = R_PERM_RX, .bits = 16, .add = true, .backing_fd = ctx->file->fd };
		RVecRBinSection_push_back (&ctx->file->bo->sections_vec, &view);
	}
	return profile_mapped (ctx, physical, size, true) == address && bcc20_current (ctx, physical, size);
}

static bool bcc20_stub(BorlandProfileContext *ctx, ut64 accepted, int identifier, int offset, int body_offset, ut64 *file) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bcc20_bodies); i++) {
		if (bcc20_bodies[i].identifier != identifier) {
			continue;
		}
		*file = 0x1000 + 16ULL * bcc20_bodies[i].paragraph + offset;
		ut64 target = bcc20_bodies[i].physical + body_offset;
		ut8 stub[5];
		if (body_offset >= bcc20_bodies[i].code || !bcc20_body (accepted, target, 1) || !bcc20_current (ctx, *file, 5)
				|| r_buf_read_at (ctx->file->buf, *file, stub, sizeof (stub)) != sizeof (stub)
				|| r_read_le16 (stub) != 0x3fcd || r_read_le16 (stub + 2) != body_offset || stub[4]
				|| !bcc20_reference (ctx, accepted, *file + 2, target)) {
			return false;
		}
		char name[64];
		snprintf (name, sizeof (name), "bcc20_fbov_%04x_stub_%04x", identifier, offset);
		return bcc20_note (ctx, accepted, *file, 5, name, BCC20_MARKER "Qualified INT3f stub DATA projection into the original static view; not a loaded selector or executable-call rewrite.");
	}
	return false;
}

static bool bcc20_overlay_far(BorlandProfileContext *ctx, ut64 accepted, int owner, ut64 source, int identifier, int offset, int target_offset, bool resident) {
	if (!bcc20_body (accepted, source, 4) || !profile_word (ctx, source, offset) || !profile_word (ctx, source + 2, identifier) || (identifier & 7)) {
		return false;
	}
	size_t i;
	bool found = false;
	for (i = 0; i < R_ARRAY_SIZE (bcc20_bodies); i++) {
		if (bcc20_bodies[i].identifier == owner && bcc20_data (ctx, bcc20_bodies[i].physical + bcc20_bodies[i].code, "uint16_t", bcc20_bodies[i].fixups / 2, NULL)) {
			ut64 at;
			for (at = bcc20_bodies[i].physical + bcc20_bodies[i].code; at < bcc20_bodies[i].physical + bcc20_bodies[i].code + bcc20_bodies[i].fixups; at += 2) {
				found |= profile_word (ctx, at, source + 2 - bcc20_bodies[i].physical);
			}
		}
	}
	if (!found) {
		return false;
	}
	ut64 target;
	if (resident) {
		target = 0x1000 + 16ULL * target_offset + offset;
		if (!bcc20_mz_word (ctx, 0xc390 + identifier, target_offset)) {
			return false;
		}
	} else {
		ut64 stub;
		if (!bcc20_stub (ctx, accepted, identifier, offset, target_offset, &stub) || !bcc20_reference (ctx, accepted, source, stub)) {
			return false;
		}
		for (i = 0; bcc20_bodies[i].identifier != identifier; i++) {
		}
		target = bcc20_bodies[i].physical + target_offset;
	}
	return bcc20_reference (ctx, accepted, source, target)
		&& bcc20_note (ctx, accepted, source, 4, NULL, BCC20_MARKER "Selected fixup-listed low-three-bits-zero FBOV field: manager/stub/body or native MZ resident DATA join only. Raw words remain unchanged; low-bit-one handling, runtime selectors and executed calls are unproved.");
}
// Original offset and segment storage; interpretation is qualified separately for each MZ or FBOV source. Unknown bytes remain undefined; analysis roles, not historical C.
static bool bcc20_type_FarStorage16(RAnal *anal) {
	const HelperMember members[] = {
		{ "offset", "uint16_t", 0 },
		{ "segment_field", "uint16_t", 2 },
	};
	return borland_record (anal, "bcc20_FarStorage16", 32, members, R_ARRAY_SIZE (members));
}

// R117 manager descriptor; only this image's selected rows are projected. Header/stub allocation is not an executable runtime model. Unknown bytes remain undefined; analysis roles, not historical C.
static bool bcc20_type_RecordedOverlayDescriptor32Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "archive_relative_file_offset_low", "uint16_t", 4 },
		{ "archive_relative_file_offset_high", "uint16_t", 6 },
		{ "body_bytes", "uint16_t", 8 },
		{ "fixup_list_bytes", "uint16_t", 10 },
	};
	return borland_record (anal, "bcc20_RecordedOverlayDescriptor32Partial", 256, members, R_ARRAY_SIZE (members));
}

// R174 same-CS near-handler option row. Qualification sign-extends BYTE1 against signed current WORD14e4, not the BCC3.1 unsigned-byte test. Unknown bytes remain undefined; analysis roles, not historical C.
static bool bcc20_type_OptionDescriptor8Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "literal_key", "uint8_t", 0 },
		{ "signed_qualification", "uint8_t", 1 },
		{ "near_handler", "uint16_t", 2 },
		{ "current_ds_target", "uint16_t", 4 },
	};
	return borland_record (anal, "bcc20_OptionDescriptor8Partial", 64, members, R_ARRAY_SIZE (members));
}

// R137 independent append arena. Growth effects/base validity and returned-offset/counter identity are not established. Unknown bytes remain undefined; analysis roles, not historical C.
static bool bcc20_type_AppendDescriptor8Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "current_segment", "uint16_t", 0 },
		{ "capacity", "uint16_t", 2 },
		{ "used_offset", "uint16_t", 4 },
		{ "linked_reuse_head", "uint16_t", 6 },
	};
	return borland_record (anal, "bcc20_AppendDescriptor8Partial", 64, members, R_ARRAY_SIZE (members));
}

// R117/R137 separate four-byte primary array, not a BCC3.1 five-WORD record. Unknown bytes remain undefined; analysis roles, not historical C.
static bool bcc20_type_PrimaryNode4Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "node_tag", "uint8_t", 0 },
		{ "flags", "uint8_t", 1 },
		{ "temporary_selector", "uint8_t", 2 },
	};
	return borland_record (anal, "bcc20_PrimaryNode4Partial", 32, members, R_ARRAY_SIZE (members));
}

// Separate secondary array; no equality of arena offsets or identity with returned node counter asserted. Unknown bytes remain undefined; analysis roles, not historical C.
static bool bcc20_type_SecondaryNode4Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "callback_result", "uint16_t", 0 },
		{ "argument_word", "uint16_t", 2 },
	};
	return borland_record (anal, "bcc20_SecondaryNode4Partial", 32, members, R_ARRAY_SIZE (members));
}

// R148/R168 tag-indexed descriptor at3f98+19*tag. Overlapping WORD+4 is not the tested flag field+3. Unknown bytes remain undefined; analysis roles, not historical C.
static bool bcc20_type_InstructionDescriptor19Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "mnemonic_ds_offset", "uint16_t", 0 },
		{ "signed_size_contribution", "uint8_t", 2 },
		{ "unaligned_flags", "uint16_t", 3 },
		{ "immediate_class", "uint8_t", 7 },
		{ "encoding_word_0d", "uint16_t", 13 },
		{ "encoding_word_0f", "uint16_t", 15 },
		{ "encoding_word_11", "uint16_t", 17 },
	};
	return borland_record (anal, "bcc20_InstructionDescriptor19Partial", 152, members, R_ARRAY_SIZE (members));
}

static void bcc20_types(RAnal *anal) {
	bcc20_type_PrimaryNode4Partial (anal);
	bcc20_type_SecondaryNode4Partial (anal);
	const BorlandEnumCase nodes[] = { { "selected77", 0x77 }, { "selected78", 0x78 } };
	borland_enum (anal, "bcc20_NodeTag8", 8, nodes, R_ARRAY_SIZE (nodes));
	const BorlandEnumCase requests[] = {
		{ "xor_request", 0x4f }, { "mov98_request", 0x98 }, { "mov99_request", 0x99 }, { "sub_request", 0x28 },
		{ "dec_request", 0x5b }, { "enter_request", 0x92 }, { "push_request", 0x94 }, { "mov_request", 0x9c },
		{ "call77_request", 0x77 }, { "call78_request", 0x78 }
	};
	borland_enum (anal, "bcc20_InstructionRequestTag16", 16, requests, R_ARRAY_SIZE (requests));
}

static void bcc20_view_facts(BorlandProfileContext *ctx, size_t index) {
	ut64 resident = 0x1000 + 16ULL * bcc20_bodies[index].paragraph;
	ut64 physical = bcc20_bodies[index].physical;
	int fields[] = { 4, 6, 8, 10 };
	size_t i;
	bool descriptor = true;
	for (i = 0; i < R_ARRAY_SIZE (fields); i++) {
		descriptor &= bcc20_data (ctx, resident + fields[i], "uint16_t", 1, NULL);
	}
	char name[64];
	if (descriptor) {
		snprintf (name, sizeof (name), "bcc20_fbov_%04x_descriptor", bcc20_bodies[index].identifier);
		if (profile_label (ctx, profile_mapped (ctx, resident, 1, false), name)) {
			bcc20_reference (ctx, UT64_MAX, 0xc390 + bcc20_bodies[index].identifier, resident);
			bcc20_reference (ctx, UT64_MAX, resident + 4, physical);
		}
	}
	snprintf (name, sizeof (name), "bcc20_fbov_%04x_raw_fixup_sites", bcc20_bodies[index].identifier);
	bcc20_data (ctx, physical + bcc20_bodies[index].code, "uint16_t", bcc20_bodies[index].fixups / 2, name);
	snprintf (name, sizeof (name), "bcc20_fbov_%04x_body", bcc20_bodies[index].identifier);
	bcc20_note (ctx, UT64_MAX, physical, 1, name, BCC20_MARKER "Recorded original body + appended raw fixup WORDs. Offset zero is a static analysis coordinate, not loaded CS or simultaneous residency. Unreviewed body bytes remain unclassified. FAR segment words are manager IDs, not paragraphs/selectors; qualified joins are DATA only. No code, segment word or fixup is patched.");
}

static void bcc20_options(BorlandProfileContext *ctx, ut64 accepted) {
	if (bcc20_type_OptionDescriptor8Partial (ctx->anal)) {
		const ut64 rows[] = { 0x1075e, 0x10766, 0x10796 };
		const char *names[] = { "bcc20_option_B_row", "bcc20_option_S_row", "bcc20_option_c_row" };
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (rows); i++) {
			ut8 original[8];
			if (bcc20_data (ctx, rows[i], "bcc20_OptionDescriptor8Partial", 1, names[i])
					&& r_buf_read_at (ctx->file->buf, rows[i], original, sizeof (original)) == sizeof (original)
					&& profile_word (ctx, rows[i] + 2, 0x39c)
					&& bcc20_reference (ctx, accepted, rows[i] + 2, 0x43dfc)) {
				bcc20_reference (ctx, accepted, rows[i] + 4, BCC20_DS + r_read_le16 (original + 4));
			}
		}
	}
	const int offsets[] = { 0x16fc, 0x1714, 0x1715 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (offsets); i++) {
		char name[48];
		snprintf (name, sizeof (name), "bcc20_initial_state_%04x", offsets[i]);
		bcc20_data (ctx, BCC20_DS + offsets[i], "uint8_t", 1, name);
	}
	if (bcc20_type_AppendDescriptor8Partial (ctx->anal)) {
		bcc20_data (ctx, BCC20_DS + 0x8680, "bcc20_AppendDescriptor8Partial", 1, "bcc20_primary_node_array_descriptor");
		bcc20_data (ctx, BCC20_DS + 0x8698, "bcc20_AppendDescriptor8Partial", 1, "bcc20_secondary_node_array_descriptor");
	}
}

static void bcc20_backends(BorlandProfileContext *ctx, ut64 accepted) {
	if (!bcc20_type_FarStorage16 (ctx->anal)) {
		return;
	}
	int family, i;
	for (family = 0; family < 2; family++) {
		ut64 table = family? 0x14442: 0x1435e;
		bool valid = true;
		ut8 cells[96];
		valid &= r_buf_read_at (ctx->file->buf, table, cells, sizeof (cells)) == sizeof (cells);
		for (i = 0; valid && i < 24; i++) {
			valid &= bcc20_mz_word (ctx, table + 4 * i + 2, r_read_le16 (cells + 4 * i + 2));
		}
		if (!valid || !bcc20_data (ctx, table, "bcc20_FarStorage16", 24, family? "bcc20_asm_source_callbacks24": "bcc20_obj_source_callbacks24")) {
			continue;
		}
		for (i = 0; i < 24; i++) {
			bcc20_reference (ctx, accepted, table + 4 * i, 0x1000 + 16ULL * r_read_le16 (cells + 4 * i + 2) + r_read_le16 (cells + 4 * i));
		}
		ut64 stub;
		if (bcc20_stub (ctx, accepted, family? 0x598: 0x470, family? 0x2a: 0x57, family? 0x838: 0x3e6, &stub)
				&& bcc20_reference (ctx, accepted, table + 0x28, stub)) {
			bcc20_reference (ctx, accepted, table + 0x28, family? 0x78f38: 0x63596);
		}
		bcc20_note (ctx, accepted, table, 96, NULL, BCC20_MARKER "Initial24 FAR cells/96bytes, native unchanged MZ paragraph relocation records. Conditional CLD/REP MOVSB install to current DS87cc..882b requires DF0, valid views and no defeating aliases. Slot+28 reaches current87f4 only while table/context survive. Static source/stub DATA alternatives, not copied runtime state or unconditional calls.");
	}
}

static void bcc20_arrays(BorlandProfileContext *ctx, ut64 accepted) {
	const struct { ut64 physical; int count; const char *element; const char *name; } arrays[] = {
		{ 0x43e65, 8, "uint16_t", "bcc20_boolean_handler_key_target_words" },
		{ 0x141b8, 6, "uint8_t", NULL }, { 0x141e7, 3, "uint8_t", NULL }, { 0x141ea, 3, "uint8_t", NULL }, { 0x1417b, 7, "uint8_t", NULL },
		{ 0x1415b, 2, "uint16_t", "bcc20_selected_helper_suffix_cells" },
		{ 0x79264, 6, "uint16_t", "bcc20_asm_call_selector_words" },
		{ 0x795a6, 26, "uint16_t", "bcc20_operand_formatter_dispatch_words" },
		{ 0x7105b, 1, "uint16_t", "bcc20_node77_consumer_dispatch_cell" },
		{ 0x143be, 12, "uint8_t", "bcc20_register_encoding_map12" },
		{ 0x63eab, 1, "uint16_t", "bcc20_SUB_dispatch_cell" }, { 0x63f11, 1, "uint16_t", "bcc20_DEC_dispatch_cell" },
		{ 0x63ef9, 1, "uint16_t", "bcc20_XOR_dispatch_cell" }, { 0x13f8d, 4, "uint8_t", NULL }, { 0x1405c, 4, "uint8_t", NULL }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (arrays); i++) {
		if (!profile_data_array (ctx, arrays[i].physical, arrays[i].element, arrays[i].count)
				|| (arrays[i].name && !profile_label (ctx, profile_mapped (ctx, arrays[i].physical, 1, false), arrays[i].name))) {
			continue;
		}
		switch (arrays[i].physical) {
		case 0x1415b:
			bcc20_reference (ctx, accepted, 0x1415b, 0x1417b);
			bcc20_reference (ctx, accepted, 0x1415d, 0x1417b);
			break;
		case 0x63eab: case 0x63ef9:
			if (profile_word (ctx, arrays[i].physical, 0xb02)) {
				bcc20_reference (ctx, accepted, arrays[i].physical, 0x63cb2);
			}
			break;
		case 0x63f11:
			if (profile_word (ctx, arrays[i].physical, 0x64b)) {
				bcc20_reference (ctx, accepted, arrays[i].physical, 0x637fb);
			}
			break;
		}
	}
	if (bcc20_type_InstructionDescriptor19Partial (ctx->anal)) {
		const struct { int value; const char *name; } tags[] = {
			{ 0x4f, "xor_request" }, { 0x98, "mov98_request" }, { 0x99, "mov99_request" }, { 0x28, "sub_request" },
			{ 0x5b, "dec_request" }, { 0x92, "enter_request" }, { 0x94, "push_request" }, { 0x9c, "mov_request" },
			{ 0x77, "call77_request" }, { 0x78, "call78_request" }
		};
		for (i = 0; i < R_ARRAY_SIZE (tags); i++) {
			ut64 file = BCC20_DS + 0x3f98 + 19 * tags[i].value;
			ut8 word[2];
			char name[64];
			snprintf (name, sizeof (name), "bcc20_descriptor_%s", tags[i].name);
			if (bcc20_data (ctx, file, "bcc20_InstructionDescriptor19Partial", 1, name) && r_buf_read_at (ctx->file->buf, file, word, 2) == 2) {
				bcc20_reference (ctx, accepted, file, BCC20_DS + r_read_le16 (word));
			}
		}
	}
}

static void bcc20_notes(BorlandProfileContext *ctx, ut64 accepted) {
	const struct { ut64 physical; int size; const char *name; const char *comment; } notes[] = {
		{ 0x4ba9a, 0x25, "bcc20_post_parser_ordered_OR_fragment", BCC20_MARKER "R174 partial0378:[03ea,040f): first c16fc|=freshS1714, then S1714|=freshB1715, no retroactive B-to-c OR. Not a complete containing function or established parser-to-selector lifetime." },
		{ 0x43ade, 0x56, "bcc20_mode_supplier_fragment", BCC20_MARKER "R174 partial preceding-result/callback route reaches stores1715=1 then1714=1 at43b2b..43b33; not proof literal S/B handlers are the only suppliers." },
		{ 0x63596, 0x70, "bcc20_obj_instruction_callback_prefix", BCC20_MARKER "R160/R168 partial0470:[03e6,0456),112bytes/46instructions through computed dispatch; NOT a complete function. Descriptor3f98+19*tag, workspaces8b28/8b31; preparation descendants and other arms unreviewed." },
		{ 0x70b80, 0x3a, "bcc20_common_node77_78_consumer_fragment", BCC20_MARKER "R1310510:[08b0,08ea) partial common path; temporary primary+2=ff, secondary WORD+2=0, current post-call SI/base controls restoration. Not a whole consumer function, nor proof U=4*C." },
		{ 0x63cb2, 0x3c, "bcc20_SUB_XOR_byte_request_fragment", BCC20_MARKER "R168/R335 partial shared0470:[0b02,0b3e),60bytes/27instructions; NOT a complete function or exclusive XOR arm. SUB0028 and XOR004f dispatch here with distinct descriptors. Shortening0eaa tests current second kind and returns AX=0 for kind1; fallback tests that returned AX, then snapshots current descriptor+0f. Firstkind1 requests saved descriptor+0f low BYTE+2 through append0000. Only AFTER append returns, fresh first selector8b2c goes through signed-BYTE mapping00a1 and three low-word shifts;0ff1 freshly tests second kind/selector and adds low extra+C0. Under continued004f descriptor/workspace/context, equal00/00 or02/02 selectors request33c0 or33d2; not physical output or an unconditional callback preservation claim." },
		{ 0x6fc89, 0x27, "bcc20_zero_to_self_XOR_fragment", BCC20_MARKER "R335 partial0508:[03c9,03f0) inside complete0243. MOV0098/0099/009c descriptors join literal mov; current firstkind1,secondkind4,amount0 select SI=004f, secondkind=1, then copy freshly read first selector BYTE8b2c to8b35. Equality holds at that copy, not across arbitrary later effects. Pending88b1 work precedes this arm; auxiliary04e5 runs before the then-current87f4 callback. This individual-request rule does not prove the upstream producer of two wide-argument zero requests or any historical invocation." },
		{ 0x7005b, 0x45, NULL, BCC20_MARKER "R357/R363 selected partial0508:[079b,07e0) within complete0585, not a separate function. Near07a3 calls08a8; only AFTER return current tag1b can add2 at destination+5. Current second ID is scaled/stored then freshly reread from frame BP-2 for near07cd->0847. After return the frame is read AGAIN;07d8 loads only AL, leaving AH for the full WORD pushed to opaque09cf at07dd. Do not cache frame/child/global reads or infer zero-extended selector arguments." },
		{ 0x635ad, 0x24, NULL, BCC20_MARKER "R335 partial callback prefix:0401 and conditional0411 near-call complete0e57 with8b28/8b31. For current kind1/kind1 both return AL=ff, skipping optional0e71 prefix; actual004f descriptor+0d=0 skips its other prefix request. No whole callback or backend lifetime proof." },
		{ 0x641a1, 0x1d, "bcc20_ModRM_register_prefix_fragment", BCC20_MARKER "R168/R335 partial0470:[0ff1,100e) plus tail[10b8,10c4); NOT a complete function. Current kind1 reads operand BYTE+4 only AFTER opcode append, maps signed BYTE via00a1, then adds current frame extra low BYTE and c0 modulo256; shared tail requests AL through append0000. Other operand paths remain unreviewed." },
		{ 0x637fb, 0x18, "bcc20_DEC_register_request_fragment", BCC20_MARKER "R168 partial0470:[064b,0663): current firstkind1,selector0b ->map04,+48->BYTE4c request. No whole callback or guaranteed two-DEC traversal inferred." },
		{ 0x6fd99, 0x4, NULL, BCC20_MARKER "R160 actual indirect CALL current DS87f4 at0508:04d9;04d8 is preceding PUSH SI. Initial source tables give static alternatives only; no current installed-state or unconditional body call reference." },
		{ 0x64268, 0xc, "bcc20_ModRM_byte_request_tail_fragment", NULL },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (notes); i++) {
		bcc20_note (ctx, accepted, notes[i].physical, notes[i].size, notes[i].name, notes[i].comment);
	}
	bcc20_note (ctx, accepted, BCC20_DS + 0x88ac, 2, "bcc20_initial_section_flags", BCC20_MARKER "Initial compiler DS projection only: _TEXT equality ORs0008; reset fill clears it only at its return boundary. Prefix and post-callback tag reads are separate current reads, not a snapshotted invariant.");
	if (bcc20_type_OptionDescriptor8Partial (ctx->anal) && profile_data (ctx, 0x10766, 8, "bcc20_OptionDescriptor8Partial")) {
		bcc20_note (ctx, accepted, 0x10766, 8, NULL, BCC20_MARKER "R174 literal B/S/c rows target current1715/1714/16fc, qualification0 requires signed WORD14e4<=0. NUL/+ stores1, '-'0, '.' SAVES current byte into819e+(target-16ee) when14e4!=0; not BCC3.1 restoration. No complete CLI/default/scheduling claim.");
	}
}

static void bcc20_joins(BorlandProfileContext *ctx, ut64 accepted) {
	const struct { int owner; ut64 source; int identifier; int stub; int body; bool resident; } fields[] = {
		{ 0x498, 0x668a9, 0x3e0, 0x2f, 0x56, false }, { 0x498, 0x668b9, 0x3e0, 0x2f, 0x56, false },
		{ 0x4a0, 0x67e27, 0x488, 0x61, 0x1ce, false }, { 0x4a0, 0x682b5, 0x498, 0x34, 0xd9, false },
		{ 0x4a0, 0x67e43, 0x110, 7, 0xaa8, true }, { 0x4a0, 0x6827e, 0x160, 2, 0xb07, true },
		{ 0x4a0, 0x6828c, 0x170, 6, 0xb14, true }, { 0x458, 0x62f03, 0x460, 0x20, 0, false },
		{ 0x490, 0x65e3a, 0x4a0, 0x48, 0x138a, false }, { 0x460, 0x63166, 0x598, 0x34, 0x103, false },
		{ 0x460, 0x63173, 0x470, 0x25, 0x218, false }, { 0x470, 0x631c6, 0x3e0, 0x2f, 0x56, false },
		{ 0x510, 0x70ba8, 0x508, 0x2a, 0xc2, false }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (fields); i++) {
		bcc20_overlay_far (ctx, accepted, fields[i].owner, fields[i].source, fields[i].identifier, fields[i].stub, fields[i].body, fields[i].resident);
	}
	const struct { ut64 source; ut64 target; } near[] = {
		{ 0x635b1, 0x64007 }, { 0x635c1, 0x64007 }, { 0x63cb5, 0x6405a }, { 0x63cd3, 0x631b0 },
		{ 0x63cde, 0x63251 }, { 0x63ce8, 0x641a1 }, { 0x641b3, 0x63251 }, { 0x6426a, 0x631b0 }
	};
	for (i = 0; i < R_ARRAY_SIZE (near); i++) {
		ut64 address = profile_mapped (ctx, near[i].source, 3, true), target = profile_mapped (ctx, near[i].target, 1, true);
		HelperOp ops[3];
		ut8 bytes[3];
		if (bcc20_body (accepted, near[i].source, 3) && bcc20_body (accepted, near[i].target, 1)
				&& profile_code (ctx, near[i].source, 3, address, ops) && r_buf_read_at (ctx->file->buf, near[i].source, bytes, 3) == 3
				&& bytes[0] == 0xe8 && (ut16)r_read_le16 (bytes + 1) == (ut16)(near[i].target - near[i].source - 3)
				&& ops[0].jump == target && ops[0].type == R_ANAL_OP_TYPE_CALL) {
			bcc20_reference (ctx, accepted, near[i].source + 1, near[i].target);
		}
	}
	const int stubs[][3] = { { 0x4f8, 0x20, 0x5e7 }, { 0x508, 0x4d, 0x16e }, { 0x488, 0x66, 0 }, { 0x490, 0x20, 0x100 } };
	for (i = 0; i < R_ARRAY_SIZE (stubs); i++) {
		ut64 file;
		bcc20_stub (ctx, accepted, stubs[i][0], stubs[i][1], stubs[i][2], &file);
	}
}

static int borland_bcc20_profile(RAnal *anal) {
	BorlandProfileContext ctx;
	if (borland_eligible (anal) < 0 || anal->config->seggrn != 4
			|| !profile_identity (anal, &ctx, "mz", 502432, "dd5744b99c6fa61dc1d95c580a1f1d6f1b3e97ae8b920dd6e9cfedce29f82fb6")) {
		return 0;
	}
	ut8 header[4];
	if (r_buf_read_at (ctx.file->buf, 0x18ce0, header, 4) != 4 || memcmp (header, "FBOV", 4) || !bcc20_mz_word (&ctx, 0x1001, 0xdef)) {
		return 0;
	}
	r_anal_types_prepare (anal);
	bcc20_type_RecordedOverlayDescriptor32Partial (anal);
	bool views[R_ARRAY_SIZE (bcc20_bodies)];
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bcc20_bodies); i++) {
		views[i] = bcc20_view (&ctx, i);
		R_LOG_INFO ("Borland bcc20-qualified: static row %04x %s", bcc20_bodies[i].identifier, views[i]? "qualified": "preserved/refused");
	}
	for (i = 0; i < R_ARRAY_SIZE (views); i++) {
		if (!views[i]) {
			return 0;
		}
	}
	ctx.bcc20_static_views = true;
	ut64 accepted = 0;
	int count = 0;
	for (i = 0; i < R_ARRAY_SIZE (bcc20_functions); i++) {
		bool applied = profile_function (&ctx, bcc20_functions[i].start, bcc20_functions[i].end - bcc20_functions[i].start,
			bcc20_functions[i].name, bcc20_functions[i].purge, bcc20_functions[i].comment);
		R_LOG_INFO ("Borland bcc20-qualified: FILE %08"PFMT64x" %s", bcc20_functions[i].start, applied? "qualified": "preserved/refused");
		if (applied) {
			accepted |= 1ULL << i;
			count++;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (bcc20_bodies); i++) {
		if (views[i]) {
			bcc20_view_facts (&ctx, i);
		}
	}
	bcc20_types (anal);
	bcc20_options (&ctx, accepted);
	bcc20_backends (&ctx, accepted);
	bcc20_arrays (&ctx, accepted);
	bcc20_notes (&ctx, accepted);
	bcc20_joins (&ctx, accepted);
	return count;
}

#undef BCC20_DS
#undef BCC20_MARKER
