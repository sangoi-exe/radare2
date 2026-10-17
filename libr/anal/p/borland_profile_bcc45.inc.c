/* radare - LGPL - Copyright 2026 */

#define BCC45_MARKER "[LegacyToolchains bcc45-qualified] "

static const struct {
	ut64 start;
	ut64 end;
	const char *name;
	int purge;
	const char *comment;
} bcc45_functions[] = {
	{ 0xa700b, 0xa7121, "bcc45_install_asm_callbacks", 4, BCC45_MARKER "BI01 NE62:[040b,0521), selected forward-copy installer; no CLD in this body. ASM suffix/header requests are conditional." },
	{ 0xa9412, 0xa9493, "bcc45_install_obj_callbacks", 4, BCC45_MARKER "BI01 NE63:[0612,0693), selected forward-copy installer; no CLD in this body." },
	{ 0xa7845, 0xa7c50, "bcc45_asm_instruction_serializer", 2, BCC45_MARKER "BI01 NE62:[0c45,1050), instruction-tag consumer; operand formatting and output requests remain conditional." },
	{ 0xa95dd, 0xa9f3c, "bcc45_obj_instruction_serializer", 2, BCC45_MARKER "BI01 NE63:[07dd,113c), instruction-tag consumer; fixup queues and physical output remain distinct." },
	{ 0xa7e8b, 0xa7ea9, "bcc45_asm_width_selector", 2, BCC45_MARKER "BI01/RF02 NE62:[128b,12a9); descriptor-selected width is not a node category or backend-record tag." },
	{ 0xa7ea9, 0xa82e1, "bcc45_asm_operand_formatter", 4, BCC45_MARKER "BI01/RF02 NE62:[12a9,16e1); selected kind1 and offset-prefix paths only, no whole-operand semantic claim." },
	{ 0xa6cca, 0xa6ce3, "bcc45_asm_branch_wrapper", 6, BCC45_MARKER "RF04 NE62:[00ca,00e3), forwards three frame WORDs to NE56:0207; current9966 alternative, not instruction994e." },
	{ 0xa90e7, 0xa9100, "bcc45_obj_branch_wrapper", 6, BCC45_MARKER "RF04 NE63:[02e7,0300), forwards three frame WORDs to NE56:0207; current9966 alternative." },
	{ 0x98441, 0x9849d, "bcc45_allocate_section_piece28", 0, BCC45_MARKER "RF04 NE56:[0041,009d);001c allocation records section/text positions; allocator effects remain opaque." },
	{ 0x9849d, 0x984df, "bcc45_close_section_piece", 0, BCC45_MARKER "RF04 NE56:[009d,00df); final extent is distinct from branch reservation." },
	{ 0x98532, 0x9858c, "bcc45_queue_fixup8", 6, BCC45_MARKER "BI01 NE56:[0132,018c); writes position+0, incoming DWORD+2, class+6 and increments current piece count." },
	{ 0x98607, 0x986cd, "bcc45_construct_branch_piece", 6, BCC45_MARKER "RF04 NE56:[0207,02cd); BP+a code, BP+8 target, BP+6 short control. Reservation2/3/4/5 differs from final extent; signed1974 gate. No stronger parameter/storage prototype inferred." },
	{ 0x894a3, 0x89521, "bcc45_allocate_control_arenas16", 0, BCC45_MARKER "RF04 NE48:[0aa3,0b21); independently allocates and zero-fills three16-byte contributions via9b0a/9b12/9b1a, saves each result separately. First-offset writes across arenas do not establish equal-offset validity." },
	{ 0xae33a, 0xae436, "bcc45_construct_parallel_backend_record", 8, BCC45_MARKER "RF02/NR03 NE65:[0f3a,1036);1036 is exclusive end, never the entry. Five chronological two-byte allocations under9b2a/32/3a/42/4a; first returned storage offset used for writes, outward AX is old9a99 then incremented. Equality of storage offsets/counter/index and runtime survival are unproved." },
	{ 0x67360, 0x67389, "bcc45_current_symbol_selector", 4, BCC45_MARKER "RF02 NE32:[0f60,0f89); class9 redirects through symbol FAR0, class7 reads current WORD16. Not cached node WORD10." },
	{ 0x5cefb, 0x5cf65, "bcc45_construct_symbol_reference_node", 14, BCC45_MARKER "RF02 NE27:[04fb,0565); allocation remains opaque; selected tag/type/symbol/selector/flags writes only." },
	{ 0x88a4d, 0x88ae1, "bcc45_lookup_register_spelling", 4, BCC45_MARKER "RF02 NE48:[004d,00e1); selector/type lookup in seven-byte table, characters1..3 for type0a (two otherwise), conditional case conversion into current96e6..96e9. Not an unconditional EAX ABI." },
	{ 0x6d6b5, 0x6d6cc, "bcc45_option_byte_store", 6, BCC45_MARKER "BI02 NE36:[08b5,08cc); handler-specific row BYTE6 -> current DS:[row WORD4], returns AX1 without suffix validation." },
	{ 0x6d436, 0x6d4a9, "bcc45_boolean_option_handler", 6, BCC45_MARKER "BI02/RF03 NE36:[0636,06a9); current row/input/snapshot state and signed threshold acceptance are conditions." },
	{ 0x94200, 0x9423d, "bcc45_frame_needed_predicate", 0, BCC45_MARKER "BI04/RF03 NE54:[0000,003d); independent current WORD9a7c/9a80, BYTE9a15, BYTE9a0c&4, BYTE1997, or nonzero199a with9a91&1. Clearing1997 alone does not universally remove frames;1a0f has separate setup/DS-save/alignment consumers." },
	{ 0x895f1, 0x8968e, "bcc45_capture_function_policy", 26, BCC45_MARKER "RF03 NE48:[0bf1,0c8e), RETF1ah. Post-helper ordered state writes: zero-extend incoming BYTE[BP+10] into WORD9a91, then clear0200; separately clear register-use WORD9a9b at0c68. No9a9b-to9a91 assignment. Callback/current-segment/lifetime joins remain conditional." },
	{ 0x9430e, 0x94491, "bcc45_windows_frame_builder", 0, BCC45_MARKER "BI04/RF03 NE54:[010e,0291); selected BYTE9a9c masks01/02 request SI/DI saves after real helper/current-state tests. Register-use WORD9a9b gets1<<selector from actual selector lookup;8/9 can set these high-byte bits. No historical function save-state or physical emission inferred." },
	{ 0xad705, 0xadb49, "bcc45_normalize_instruction_workspace", 2, BCC45_MARKER "ZF01 NE65:[0305,0749). Selected009c CMP arm requires current A64c kind1, A659 kind4 and A65e DWORD0; transforms tag009c to005e OR, source kind1, destination selector copied to source. This arm tests neither1000 nor prior arithmetic flags. Cache invalidation, operand/request identity, current994e callback and physical output remain unproved." },
	{ 0x8be9e, 0x8becb, "bcc45_cached_selector_query", 2, BCC45_MARKER "RF30 NE49:[109e,10cb); zero index or indexed9b2a bit01 returns ALff, otherwise current9b3a indexed BYTE returns in AL. AH is uncleared; BX/DX/ES are not restored on paths that change them. No scaled-address construction, allocation or emission." },
	{ 0xad68a, 0xad6bf, "bcc45_prepare_imul_result_selector", 8, BCC45_MARKER "RF26 NE65:[028a,02bf); prepares parent via0848 atA64c, sign-extends incoming low WORD into kind4 A659 DWORD+5, and separately copies incoming selector BYTE into kind1 A666. Helpers and actual RF24 state remain unjoined." },
	{ 0x937c0, 0x93a29, "bcc45_dispatch_pending_entries", 2, BCC45_MARKER "RF26 NE53:[19c0,1c29); guard and request-index equality condition entry processing. Selected kind3 requests a transfer, then reloads current9b3a and stores the cached desired selector; other kinds differ. Complete boundary, selected semantics only; no unconditional drain or schedule/lifetime invariant." },
	{ 0x8c770, 0x8c7b7, "bcc45_construct_pending_entry9", 10, BCC45_MARKER "RF26 NE49:[1970,19b7); opaque allocation requests9 bytes under9ac2, then stores kind/policy/desired-selector and request/tracked/linked indices. Request index reads current9750 after the call. No proved heap instance, publication, failure handling or allocator/index correspondence." },
	{ 0x8cf15, 0x8cf81, "bcc45_lookup_prior_selector", 2, BCC45_MARKER "RF26 NE49:[2115,2181); backward nine-byte scan, kind6 index substitution, matching non6 desired-selector BYTE or current indexed9b3a fallback. No validated arena extent, entry history or scheduling invariant." },
	{ 0x8b69e, 0x8be65, "bcc45_select_record_result", 2, BCC45_MARKER "RF26 NE49:[089e,1065); complete boundary accounting, selected descriptor capture, tag2/4 association/annotation and conditional selector-reuse paths only. Captured state is not a fresh read; direct IMUL003e and actual RF24 allocation are not the tag2/4 association path. Full semantics remain unreviewed." },
	{ 0x8c523, 0x8c64e, "bcc45_select_from_masks", 4, BCC45_MARKER "RF26 NE49:[1723,184e); finite current-state special cases, conditional mask filtering and lowest-set-bit selection; zero/exhausted path retries through opaque184e. Not an unconditional preference or guaranteed terminating allocator." },
	{ 0x96d0c, 0x96d2c, "bcc45_annotate_selector_type", 4, BCC45_MARKER "RF26 NE55:[090c,092c); sign-extends incoming selector BYTE, adds1 for type WORD1 or9 otherwise; caller consumes AL. Annotation low6 bits index a mask table, not universally a singleton fixed-register demand." },
	{ 0xae5ca, 0xae651, "bcc45_construct_backend_constant_record", 6, BCC45_MARKER "RF31 NE65:[11ca,1251); five independent two-byte allocation requests; first returned offset supplies stores, incoming tag and DWORD retained in separate arenas, outward AX is old9a99 before increment. Allocator equality, counter/index identity, aliases and lifetime unproved; backend0c is not frontend tag2." },
	{ 0x5cadd, 0x5cb35, "bcc45_construct_typed_frontend_constant", 8, BCC45_MARKER "RF31 NE27:[00dd,0135); frontend tag2 typed constant, distinct from backend record0c. Storage0063 and transitive effects remain opaque; not an RF24 node-instance observation." },
	{ 0xa767c, 0xa7756, "bcc45_asm_callback_size", 2, BCC45_MARKER "RF31 NE62:[0a7c,0b56); current record/descriptor size calculation calls only0b56; no explicit record stores. Complete boundary does not close descriptor semantics or establish global nonaliasing." },
	{ 0xa7756, 0xa783d, "bcc45_asm_record_size", 4, BCC45_MARKER "RF31 NE62:[0b56,0c3d); reads current record/descriptor, no calls or explicit non-stack stores. Adjacent four-WORD switch data excluded; no global nonaliasing or whole formatter semantics inferred." },
	{ 0x99afc, 0x99b24, "bcc45_asm_signed_word_wrapper", 2, BCC45_MARKER "RF31 NE56:[16fc,1724); signed WORD negative path submits '-' then reloads and negates frame WORD modulo65536 before forwarding. Character/numeric sinks remain opaque, not physical-output proof." },
};

// Descriptive selected BCC4.5 values only; numeric domain is not interchangeable with adjacent enums or recovered historical identifiers.
static bool bcc45_type_NodeTag(RAnal *anal) {
	const BorlandEnumCase cases[] = {
		{ "typed_literal", 2 },
		{ "symbol_reference", 5 },
		{ "or_capable", 0x1c },
		{ "outer_comparison", 0x1f },
	};
	return borland_enum (anal, "bcc45_NodeTag", 16, cases, R_ARRAY_SIZE (cases));
}

// Descriptive selected BCC4.5 values only; numeric domain is not interchangeable with adjacent enums or recovered historical identifiers.
static bool bcc45_type_NodeCategory(RAnal *anal) {
	const BorlandEnumCase cases[] = {
		{ "category7", 7 },
		{ "category8", 8 },
		{ "category9", 9 },
		{ "category10", 10 },
	};
	return borland_enum (anal, "bcc45_NodeCategory", 16, cases, R_ARRAY_SIZE (cases));
}

// Descriptive selected BCC4.5 values only; numeric domain is not interchangeable with adjacent enums or recovered historical identifiers.
static bool bcc45_type_BackendRecordTag(RAnal *anal) {
	const BorlandEnumCase cases[] = {
		{ "selector16", 9 },
		{ "selector32", 10 },
		{ "literal", 12 },
		{ "conditional_cf", 0xcf },
	};
	return borland_enum (anal, "bcc45_BackendRecordTag", 16, cases, R_ARRAY_SIZE (cases));
}

// Descriptive selected BCC4.5 values only; numeric domain is not interchangeable with adjacent enums or recovered historical identifiers.
static bool bcc45_type_InstructionRequestTag(RAnal *anal) {
	const BorlandEnumCase cases[] = {
		{ "or_request", 0x5e },
		{ "cmp_request", 0x9c },
		{ "push_request", 0xae },
		{ "mov_request", 0xbb },
		{ "shld_request", 0xfe },
	};
	return borland_enum (anal, "bcc45_InstructionRequestTag", 16, cases, R_ARRAY_SIZE (cases));
}

// Offset and selector words; not a flat pointer or selector-resolution assertion. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_FarStorage16(RAnal *anal) {
	const HelperMember members[] = {
		{ "offset", "uint16_t", 0 },
		{ "selector", "uint16_t", 2 },
	};
	return borland_record (anal, "bcc45_FarStorage16", 32, members, R_ARRAY_SIZE (members));
}

// RF26 descriptive dynamic pending-entry layout; no proved heap address or allocated instance. Current arena, index correspondence, scheduling and lifetime remain conditional. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_PendingEntry9(RAnal *anal) {
	const HelperMember members[] = {
		{ "kind", "uint8_t", 0 },
		{ "policy", "uint8_t", 1 },
		{ "desired_selector", "uint8_t", 2 }, // Only the low byte of some pushed WORDs is freshly assigned.
		{ "request_index", "uint16_t", 3 }, // Constructor reads current9750 after opaque allocation.
		{ "tracked_index", "uint16_t", 5 },
		{ "linked_index", "uint16_t", 7 }, // Kind-dependent use, not a resolved pointer.
	};
	return borland_record (anal, "bcc45_PendingEntry9", 72, members, R_ARRAY_SIZE (members));
}

// RF04 NE56:0041 allocation of001c through9a26; separate from control arenas and fixup records. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_SectionPiece28Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "text_buffer_position", "uint16_t", 2 },
		{ "final_extent", "uint16_t", 4 }, // Closure computes section position minus start unless WORD12=ffff; not only reserved branch bytes.
		{ "section_start", "uint16_t", 0xa },
		{ "branch_code_flags", "uint16_t", 0xc },
		{ "target_link", "uint16_t", 0xe }, // Actual9b12/9b1a resolution remains conditional.
		{ "fixup_count_or_sentinel", "uint16_t", 0x12 },
		{ "piece_flags", "uint16_t", 0x1a }, // Branch code18 sets mask02.
	};
	return borland_record (anal, "bcc45_SectionPiece28Partial", 224, members, R_ARRAY_SIZE (members));
}

// RF04 first arena9b0a contribution; three0010 allocations are independent. No synchronized arena offsets inferred. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_ControlNode16Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "control_flags", "uint16_t", 2 }, // 0100 is BYTE3 mask01, not code WORD8 high flags.
		{ "logical_request_index", "uint16_t", 4 }, // Captured9a99, not allocator offset or physical-byte position.
		{ "request_count", "uint16_t", 6 },
		{ "control_code", "uint16_t", 8 },
		{ "target", "uint16_t", 0xe },
	};
	return borland_record (anal, "bcc45_ControlNode16Partial", 128, members, R_ARRAY_SIZE (members));
}

// BI01 NE56:0132 requests8 under9a2e; not the later independently allocated parallel99de/99e6 records. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_FixupQueueRecord8(RAnal *anal) {
	const HelperMember members[] = {
		{ "piece_relative_position", "uint16_t", 0 },
		{ "request_pair", "bcc45_FarStorage16", 2 }, // Incoming DWORD, not an inferred resolved symbol pointer.
		{ "fixup_class", "uint16_t", 6 }, // Class1 is a fixup domain, not operand kind1.
	};
	return bcc45_type_FarStorage16 (anal)
		&& borland_record (anal, "bcc45_FixupQueueRecord8", 64, members, R_ARRAY_SIZE (members));
}

// RF02 current registration reads name WORD0, selector WORD2 and type-selector BYTE4; trailing bytes unknown. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_PseudoregisterRow7(RAnal *anal) {
	const HelperMember members[] = {
		{ "name_offset", "uint16_t", 0 }, // Qualified initial NE7 table spelling, not a flat pointer.
		{ "register_selector", "uint16_t", 2 },
		{ "type_selector", "uint8_t", 4 }, // Category-indexed current6eaa FAR-pointer table.
	};
	return borland_record (anal, "bcc45_PseudoregisterRow7", 56, members, R_ARRAY_SIZE (members));
}

// RF02 class7 registration/current-symbol selector path; extent is a minimum touched-field envelope, not proven allocation size. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_SymbolPartial(RAnal *anal) {
	const HelperMember members[] = {
		{ "type_pair", "bcc45_FarStorage16", 0xe },
		{ "register_selector", "uint16_t", 0x16 }, // Selector lookup reads current symbol, not node cached WORD10.
		{ "symbol_class", "uint8_t", 0x22 },
	};
	return bcc45_type_FarStorage16 (anal)
		&& borland_record (anal, "bcc45_SymbolPartial", 280, members, R_ARRAY_SIZE (members));
}

// RF02 tag5 constructor writes selected fields; not a control-node16 or complete allocation contract. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_SymbolReferenceNodePartial(RAnal *anal) {
	const HelperMember members[] = {
		{ "node_tag", "uint16_t", 0 },
		{ "node_category", "uint16_t", 2 }, // Current type WORD0, distinct numeric domain from node tag.
		{ "flags", "uint16_t", 4 }, // Incoming flags masked001f.
		{ "type_pair", "bcc45_FarStorage16", 8 },
		{ "symbol_pair", "bcc45_FarStorage16", 0xc },
		{ "cached_selector", "uint16_t", 0x10 }, // Not the field used by current-symbol lookup32:0f60.
	};
	return bcc45_type_FarStorage16 (anal)
		&& borland_record (anal, "bcc45_SymbolReferenceNodePartial", 144, members, R_ARRAY_SIZE (members));
}

// BI02/RF03 initial option row; handler interpretation is conditional and current-DS based. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_BooleanOptionRow8(RAnal *anal) {
	const HelperMember members[] = {
		{ "key", "uint8_t", 0 },
		{ "threshold", "uint8_t", 1 },
		{ "near_handler", "uint16_t", 2 }, // Current NE36 CS, not a FAR callback.
		{ "runtime_ds_destination", "uint16_t", 4 }, // Offset only; runtime DS validity and state are not inferred from initial image bytes.
	};
	return borland_record (anal, "bcc45_BooleanOptionRow8", 64, members, R_ARRAY_SIZE (members));
}

// BI02 byte-store handler08b5 row, distinct from Boolean0636 and delegation089d interpretations. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc45_type_ByteStoreOptionRow8(RAnal *anal) {
	const HelperMember members[] = {
		{ "key", "uint8_t", 0 },
		{ "threshold", "uint8_t", 1 },
		{ "near_handler", "uint16_t", 2 },
		{ "runtime_ds_destination", "uint16_t", 4 }, // Offset only, not a resolved live DS address.
		{ "stored_byte", "uint8_t", 6 }, // Read before destination WORD; no trailing-input validation in this handler.
	};
	return borland_record (anal, "bcc45_ByteStoreOptionRow8", 64, members, R_ARRAY_SIZE (members));
}

static const ut32 bcc45_asm_callbacks[][3] = {
	{ 62, 0x09bb, 0xa75bb },
	{ 56, 0x1237, 0x99637 },
	{ 56, 0x11a9, 0x995a9 },
	{ 56, 0x0fe4, 0x993e4 },
	{ 56, 0x1123, 0x99523 },
	{ 56, 0x11d1, 0x995d1 },
	{ 56, 0x13f1, 0x997f1 },
	{ 56, 0x14c0, 0x998c0 },
	{ 62, 0x06aa, 0xa72aa },
	{ 56, 0x15de, 0x999de },
	{ 62, 0x0c45, 0xa7845 },
	{ 62, 0x008c, 0xa6c8c },
	{ 62, 0x009a, 0xa6c9a },
	{ 62, 0x08c4, 0xa74c4 },
	{ 56, 0x13d9, 0x997d9 },
	{ 62, 0x00b7, 0xa6cb7 },
	{ 62, 0x00ca, 0xa6cca },
	{ 56, 0x15b5, 0x999b5 },
	{ 56, 0x1580, 0x99980 },
	{ 62, 0x0841, 0xa7441 },
	{ 62, 0x096d, 0xa756d },
	{ 62, 0x0886, 0xa7486 },
	{ 62, 0x09a0, 0xa75a0 },
	{ 62, 0x00e3, 0xa6ce3 },
	{ 62, 0x10c2, 0xa7cc2 },
	{ 62, 0x0220, 0xa6e20 },
};

static const ut32 bcc45_obj_callbacks[][3] = {
	{ 59, 0x1344, 0xa1b44 },
	{ 60, 0x078c, 0xa318c },
	{ 60, 0x060d, 0xa300d },
	{ 60, 0x0207, 0xa2c07 },
	{ 60, 0x05a0, 0xa2fa0 },
	{ 60, 0x0673, 0xa3073 },
	{ 60, 0x07f2, 0xa31f2 },
	{ 60, 0x08b7, 0xa32b7 },
	{ 59, 0x13c7, 0xa1bc7 },
	{ 60, 0x0301, 0xa2d01 },
	{ 63, 0x07dd, 0xa95dd },
	{ 56, 0x018c, 0x9858c },
	{ 56, 0x01b3, 0x985b3 },
	{ 63, 0x06e1, 0xa94e1 },
	{ 59, 0x17ae, 0xa1fae },
	{ 63, 0x02d4, 0xa90d4 },
	{ 63, 0x02e7, 0xa90e7 },
	{ 60, 0x07c9, 0xa31c9 },
	{ 56, 0x01f4, 0x985f4 },
	{ 63, 0x0693, 0xa9493 },
	{ 63, 0x0787, 0xa9587 },
	{ 63, 0x06c0, 0xa94c0 },
	{ 63, 0x0747, 0xa9547 },
	{ 63, 0x0319, 0xa9119 },
	{ 63, 0x00b1, 0xa8eb1 },
	{ 63, 0x0433, 0xa9233 },
};

static bool bcc45_body(ut64 accepted, ut64 physical) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bcc45_functions); i++) {
		if (physical >= bcc45_functions[i].start && physical < bcc45_functions[i].end) {
			return !!(accepted & (1ULL << i));
		}
	}
	return true;
}

static bool bcc45_note(BorlandProfileContext *ctx, ut64 accepted, ut64 physical, int size, const char *name, const char *comment) {
	ut64 address = profile_mapped (ctx, physical, size, true);
	HelperOp *ops = calloc (size, sizeof (HelperOp));
	bool valid = ops && address != UT64_MAX && bcc45_body (accepted, physical)
		&& profile_code (ctx, physical, size, address, ops);
	free (ops);
	if (!valid || (name && !profile_label (ctx, address, name))) {
		return false;
	}
	borland_comment (ctx->anal, address, comment);
	return true;
}

static bool bcc45_data(BorlandProfileContext *ctx, ut64 physical, int size, const char *type, const char *name, const char *comment) {
	if (!profile_data (ctx, physical, size, type)) {
		return false;
	}
	ut64 address = profile_mapped (ctx, physical, size, false);
	if (name && !profile_label (ctx, address, name)) {
		return false;
	}
	borland_comment (ctx->anal, address, comment);
	return true;
}

static bool bcc45_array(BorlandProfileContext *ctx, ut64 physical, const char *element, ut32 count, const char *name, const char *comment) {
	if (!profile_data_array (ctx, physical, element, count)) {
		return false;
	}
	ut64 address = profile_mapped (ctx, physical, 1, false);
	if (name && !profile_label (ctx, address, name)) {
		return false;
	}
	borland_comment (ctx->anal, address, comment);
	return true;
}

static bool bcc45_far(BorlandProfileContext *ctx, ut64 accepted, ut64 physical, int word0, int word1, ut64 target, bool executable) {
	const BorlandProfileBinding binding = { 3, 0, word0, word1, target, NULL, true, executable, true };
	return (!executable || bcc45_body (accepted, physical)) && profile_binding (ctx, physical, &binding);
}

static bool bcc45_words(BorlandProfileContext *ctx, ut64 start, ut64 end, const char *name, const char *comment) {
	return bcc45_array (ctx, start, "uint16_t", (end - start) / 2, name, comment);
}

static bool bcc45_backends(BorlandProfileContext *ctx, ut64 accepted) {
	if (bcc45_type_FarStorage16 (ctx->anal)) {
		int family;
		for (family = 0; family < 2; family++) {
			ut64 source = family? 0x1751c: 0x16fb2;
			const ut32 (*callbacks)[3] = family? bcc45_obj_callbacks: bcc45_asm_callbacks;
			if (bcc45_array (ctx, source, "bcc45_FarStorage16", 26, family? "bcc45_obj_source_callbacks26": "bcc45_asm_source_callbacks26", BCC45_MARKER "BI01: 26 singleton nonadditive native NE FAR relocations. Conditional REP MOVSW installation to current DS:[9926,998e), CX=0034 requires DF=0, valid current segments and preservation. Displacement28h -> current994e instruction serializer; displacement40h -> current9966 branch wrapper. These source-table DATA references are not unconditional calls or proof of installed runtime state.")) {
				int i;
				for (i = 0; i < 26; i++) {
					bcc45_far (ctx, accepted, source + 4 * i, callbacks[i][0], callbacks[i][1], callbacks[i][2], false);
				}
			}
		}
	}
	bcc45_far (ctx, accepted, 0xa6cd9, 56, 0x207, 0x98607, true);
	bcc45_far (ctx, accepted, 0xa90f6, 56, 0x207, 0x98607, true);
	bool asm_switch = bcc45_words (ctx, 0xa7c50, 0xa7cc2, "bcc45_asm_callback_switch_words", BCC45_MARKER "BI01: adjacent switch data, not another function or extension of the preceding terminal-inclusive body. Near WORD targets stay in the containing CS; no FAR prototype inferred.");
	bcc45_words (ctx, 0xa9f3c, 0xaa146, "bcc45_obj_callback_switch_words", NULL);
	bcc45_words (ctx, 0xa82e1, 0xa8327, "bcc45_asm_operand_switch_words", NULL);
	bcc45_words (ctx, 0xa24d0, 0xa24d8, "bcc45_fixup_serializer_switch_words", NULL);
	return asm_switch;
}

static void bcc45_selectors(BorlandProfileContext *ctx, ut64 accepted, bool asm_switch) {
	// TYPE ONLY: no source-established instance or arena exists for PendingEntry9.
	bcc45_type_PendingEntry9 (ctx->anal);
	bcc45_words (ctx, 0x93a29, 0x93a3b, "bcc45_pending_kind_switch_words9", BCC45_MARKER "RF26 nine WORD targets for bounded kinds1..9, outside complete19c0 body; current CS near offsets, not FAR pointers or further instructions.");
	bcc45_words (ctx, 0xa783d, 0xa7845, "bcc45_asm_size_switch_words4", NULL);
	bcc45_array (ctx, 0x17414, "uint8_t", 7, "bcc45_literal_ax_ax", NULL);
	if (asm_switch && bcc45_body (accepted, 0xa7b6a) && profile_offset (ctx, 0xa7c98, 0xf6a, 0xa7b6a)) {
		ut64 address = profile_mapped (ctx, 0xa7c98, 2, false);
		if (profile_label (ctx, address, "bcc45_asm_tag0039_dispatch_cell")) {
			borland_comment (ctx->anal, address, BCC45_MARKER "RF30/RF31 native near WORD0f6a selects literal-AX branch for tag0039. Other IMUL tags use different cells; ASM text alone does not identify003e or allocated operand count.");
		}
	}
	bcc45_far (ctx, accepted, 0x931a4, 49, 0x109e, 0x8be9e, true);
	bcc45_far (ctx, accepted, 0xa7b76, 56, 0xf08, 0x99308, true);
	bcc45_far (ctx, accepted, 0x939bf, 65, 0x160, 0xad560, true);
	bcc45_note (ctx, accepted, 0x9c51a, 0x7f, "bcc45_direct_imul_admission_fragment", BCC45_MARKER "RF31 NE58:[0b1a,0b99), partial containing function: current type bits/exclusions, tag0b path and right-child frontend tag2 admission. Not a complete frontend function or source-expression equivalence.");
	if (bcc45_note (ctx, accepted, 0x9c66e, 0x61, "bcc45_direct_imul_construction_fragment", BCC45_MARKER "RF31 NE58:[0c6e,0ccf), partial path: nonzero1974 and signed32 amount in[-65536,65536) admit recursive left index, backend constant0c via65:11ca, then new003e request via65:0f3a. This constructs003e directly, not a proved0039 rewrite; low-WORD later preparation, allocator/index/lifetime and RF24 instance joins remain limits.")) {
		bcc45_far (ctx, accepted, 0x9c6b1, 65, 0x11ca, 0xae5ca, true);
		bcc45_far (ctx, accepted, 0x9c6b7, 65, 0xf3a, 0xae33a, true);
	}
	bcc45_note (ctx, accepted, 0xa7b6a, 5, NULL, BCC45_MARKER "RF30/RF31 tag0039 branch tests current A64c.kind4 and conditionally submits literal ax,ax, before common0f5d. It does not read three allocated register operands or prove0039-to-003e rewriting.");
	bcc45_note (ctx, accepted, 0xa7b5d, 3, NULL, BCC45_MARKER "RF30/RF31 common tail pushes addressA659, not WORD[A659], then obtains width from128b. Formatter12a9 reads that record's own current kind/fields after prior helper effects; A64c.kind4 does not fix A659's kind/value. Actual RF24 traversal, aliases, lifetime and output remain unobserved.");
}

static void bcc45_records(BorlandProfileContext *ctx) {
	bcc45_type_SectionPiece28Partial (ctx->anal);
	bcc45_type_ControlNode16Partial (ctx->anal);
	bcc45_type_FixupQueueRecord8 (ctx->anal);
}

static void bcc45_pseudoregisters(BorlandProfileContext *ctx, ut64 accepted) {
	if (bcc45_type_PseudoregisterRow7 (ctx->anal)) {
		bcc45_data (ctx, 0x165c6, 7, "bcc45_PseudoregisterRow7", "bcc45_pseudoregister_EAX_row", BCC45_MARKER "RF02: seven-byte rows; _EAX selector0/type0a, _EDX selector2/type0a, _AX selector0/type08. BYTE1979!=0 prefixes @ only for selected selectors and skips others (_EDX skipped); no unconditional spelling registration, game ABI or historical compiler attribution.");
		bcc45_data (ctx, 0x165cd, 7, "bcc45_PseudoregisterRow7", "bcc45_pseudoregister_EDX_row", NULL);
		bcc45_data (ctx, 0x1660c, 7, "bcc45_PseudoregisterRow7", "bcc45_pseudoregister_AX_row", NULL);
	}
	bcc45_type_SymbolPartial (ctx->anal);
	bcc45_type_SymbolReferenceNodePartial (ctx->anal);
	bcc45_type_NodeTag (ctx->anal);
	bcc45_type_NodeCategory (ctx->anal);
	bcc45_type_BackendRecordTag (ctx->anal);
	bcc45_type_InstructionRequestTag (ctx->anal);
	bcc45_note (ctx, accepted, 0x6ea71, 0x143, "bcc45_pseudoregister_registration_fragment", BCC45_MARKER "RF02 NE36:[1c71,1db4) is registration-loop coverage, not a complete function extent: stride7 until name WORD0; intern15:383f, class7 creation31:089b, row WORD2 -> symbol WORD16. No whole containing-function boundary inferred.");
	bcc45_array (ctx, 0x17584, "uint8_t", 12, "bcc45_register_encoding_map12", NULL);
}

static void bcc45_controls(BorlandProfileContext *ctx, ut64 accepted) {
	if (bcc45_type_BooleanOptionRow8 (ctx->anal)) {
		bcc45_data (ctx, 0x140c6, 8, "bcc45_BooleanOptionRow8", "bcc45_option_k_row", BCC45_MARKER "RF03: lowercase k/threshold2/near0636/destination1997. '-' writes0, '+' or NUL1, '.' conditional snapshot restore; store precedes suffix validation without rollback. This row does not write199a or1a0f.");
	}
	if (bcc45_type_ByteStoreOptionRow8 (ctx->anal)) {
		static const struct { ut64 physical; const char *name; const char *comment; } rows[] = {
			{ 0x14306, "bcc45_W_wildcard_state_rows", BCC45_MARKER "BI02 ordered W wildcard stores199a=0 then96ae=1; later S delegation reaches WS NUL row1ca6 ->1a0f=4. A cleared199a therefore does not imply the header gate is zero. Current rows/input/segments, signed threshold and preservation are required; no accepted-run state inferred." },
			{ 0x1430e, NULL, NULL },
			{ 0x142a6, "bcc45_WS_state_rows", NULL },
			{ 0x142ae, NULL, NULL },
			{ 0x143ce, "bcc45_Y_state_rows", BCC45_MARKER "BI02/RF03 Y NUL/-/f/n rows select199a=1/0/1/2. Separate root Y rows clear96ae and1a0f first; these rows do not clear1997." },
			{ 0x143d6, NULL, NULL },
			{ 0x143de, NULL, NULL },
			{ 0x143e6, NULL, NULL }
		};
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (rows); i++) {
			if (bcc45_data (ctx, rows[i].physical, 8, "bcc45_ByteStoreOptionRow8", rows[i].name, rows[i].comment)
					&& bcc45_body (accepted, 0x6d6b5)) {
				profile_offset (ctx, rows[i].physical + 2, 0x8b5, 0x6d6b5);
			}
		}
	}
	bcc45_note (ctx, accepted, 0xad8df, 6, NULL, BCC45_MARKER "ZF01 selected normalizer stores: source kind1, selector copy after tag009c + ffc2 ->005e; no general claim that arithmetic flags survive C statements or categories retype their operands.");
}

static int borland_bcc45_profile(RAnal *anal) {
	BorlandProfileContext ctx;
	if (borland_eligible (anal) < 0 || !profile_identity (anal, &ctx, "ne", 768026, "6e58346640ca94e32b547c4df872d06905e58c5ef6d473d0b6a6a3903d640a46")) {
		return 0;
	}
	r_anal_types_prepare (anal);
	ut64 accepted = 0;
	int count = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bcc45_functions); i++) {
		bool applied = profile_function (&ctx, bcc45_functions[i].start, bcc45_functions[i].end - bcc45_functions[i].start, bcc45_functions[i].name, bcc45_functions[i].purge, bcc45_functions[i].comment);
		if (applied) {
			accepted |= 1ULL << i;
			count++;
		}
		R_LOG_INFO ("Borland bcc45-qualified: FILE 0x%08"PFMT64x" %s", bcc45_functions[i].start, applied? "qualified (including unchanged)": "preserved/refused; dependent facts skipped");
	}
	bool asm_switch = bcc45_backends (&ctx, accepted);
	bcc45_records (&ctx);
	bcc45_pseudoregisters (&ctx, accepted);
	bcc45_controls (&ctx, accepted);
	bcc45_selectors (&ctx, accepted, asm_switch);
	return count;
}

#undef BCC45_MARKER
