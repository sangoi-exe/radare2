/* radare - LGPL - Copyright 2026 */

#define BCC31_MARKER "[LegacyToolchains bcc31-qualified] "

static const struct {
	ut64 start;
	ut64 end;
	const char *name;
	int purge;
	const char *comment;
} bcc31_functions[] = {
	{ 0x55d58, 0x55d98, "bcc31_option_table_wrapper", 6, BCC31_MARKER "R174/R294 NE38:[0558,0598), FAR wrapper with mode-dependent I/L/FFFF bypasses; preserves SI on intact normal return, not arbitrary callee effects." },
	{ 0x55d98, 0x55deb, "bcc31_near_option_dispatch", 6, BCC31_MARKER "R174 NE38:[0598,05eb), tagged INC BP near frame, wildcard and unsigned BYTE qualification; current descriptor WORD+2 is a near call, not FAR callback." },
	{ 0x55deb, 0x55e5b, "bcc31_boolean_option_store", 6, BCC31_MARKER "R174 NE38:[05eb,065b), near RET6; empty/plus stores1, leading minus stores0, other first bytes fail except guarded dot. Dot requires nonzero1827 and RESTORES saved DS[6d98+u16(target-1a65)] to freshly reread target. This guard conflicts with the selected zero-qualified rows' dispatch guard; no successful B/S/c dot spelling inferred. Saves SI/DI on intact normal return; no universal ES/flags ABI." },
	{ 0x56045, 0x5605f, "bcc31_option_descriptor_delegate", 6, BCC31_MARKER "R174 NE38:[0845,085f), near RET6; delegates current descriptor+4 table and unchanged far input to dispatcher." },
	{ 0x56713, 0x567a6, "bcc31_P_control_supplier", 6, BCC31_MARKER "R294 NE38:[0f13,0fa6), near RET6. Stores DS1aed=1 before opaque NE2:51c9; freshly reads suffix after call, leading '-' stores0 even with trailing bytes. Optional dot and up-to-three copied bytes into1829..182b, tail NUL up to182c, scan length unbounded. All three local exits AX1, not invalid-suffix rejection. Survival to callback selection0166, other writers/defaults and historical -P use unknown. Same-image help advertises Force C++ compile, not command execution evidence." },
	{ 0x8eae6, 0x8eb6d, "bcc31_install_object_callbacks", 4, BCC31_MARKER "R160 NE66:[06e6,076d), complete RETF4 installer. Source DS5974->8b36, CX0034 REP MOVSW; forward-copy contract conditional DF0. Later882a&1 controls lowercase .obj suffix request, not backend selection." },
	{ 0x92312, 0x9243c, "bcc31_install_asm_callbacks", 4, BCC31_MARKER "R160 NE68:[0512,063c), complete RETF4 installer. Source DS5a5a->8b36, CX0034 REP MOVSW; forward-copy contract conditional DF0. Later882a&1 controls lowercase .asm suffix request, not CLI policy." },
	{ 0x7241a, 0x724ac, "bcc31_word_array_append", 6, BCC31_MARKER "R143 NE51:[121a,12ac), RETF6. Saves old descriptor+4, compares finite17-bit size sum againstffff, error and growth calls opaque. Fresh LES stores actual post-call SI capacity+2 and DI used+4; AX reloads saved old used-offset. Saves/restores SI/DI on intact normal return, not global ABI/base/copy/allocation effects." },
	{ 0x7a0b0, 0x7a177, "bcc31_construct_five_word_array_node", 10, BCC31_MARKER "R143 NE55:[18b0,1977), RETF10. Five independent WORD2 appends; only first returned offset U retained in DI. Immediate stores use U through fresh array selectors. Tag overwrites all AX before low-kind AL replacement, so kind AH comes from tag (0090/0091->0), not last append return. Unexpanded08aa can change later DI/state. Counter8859 read/increment occurs afterward; no U=2*C or five-array synchronization proved." },
	{ 0x804b4, 0x80548, "bcc31_construct_qualified_helper_node", 4, BCC31_MARKER "R117/R143 NE58:[2eb4,2f48), RETF4. Model1a66=0 or flags8ab8&8 gates naming path; actual returned FAR pair and current post-call SI feed node025d with tag0090/0091. Returned counter C is doubled and used with fresh8871 to OR1000, distinct from allocation offset U. No historical naming-control invocation inferred." },
	{ 0x8e49b, 0x8e4af, "bcc31_signed_selector_mapping", 2, BCC31_MARKER "R168 NE66:[009b,00af), near RET2 including full c20200 at00ac. CBW indexes current DS59dc by signed input BYTE then sign-extends result; old00ae end was truncated." },
	{ 0x8fb88, 0x8fce9, "bcc31_shorten_immediate_request", 6, BCC31_MARKER "R168 NE66:[1788,18e9), near RET6. Actual unaligned descriptor+3 test and current kind/selector/model/high-low amount select adjustment; subsequent opaque byte/ModRM effects and fresh descriptor+7 remain prerequisites. Selected SUB2 arithmetic requests83 ec02 conditionally, not a universal shortening theorem." },
	{ 0x8fce9, 0x8fdbe, "bcc31_request_immediate_bytes", 2, BCC31_MARKER "R168 NE66:[18e9,19be), near RET2. Fresh second-kind dispatch; selected kind4 reads current low amount BYTE, adjustment3 avoids additional-byte routes. Post-child SI preservation and other helper effects not inferred from local epilogue." },
	{ 0x8e400, 0x8e44d, "bcc31_append_backend_byte", 2, BCC31_MARKER "R168 NE66:[0000,004d), RETF2. Consumes low argument BYTE only; below current capacity stores/increments used, otherwise calls opaque NE51:121a. Fresh record+0e/+10 ADD/ADC accounts one; no complete OMF or physical output contract." },
	{ 0x73b30, 0x73ba8, "bcc31_event_factory", 0, BCC31_MARKER "R275 NE52:[0330,03a8), RETF. Three independent0010-byte allocations, separate event/metadata/pending views. Initializes event+4 from8859 and metadata+a=ffff indexed by event SI, not demonstrably the independent metadata allocation return; returns first offset, does not select JE or prove equal offsets/free-list histories." },
	{ 0x7403d, 0x740ad, "bcc31_insert_event_chain", 6, BCC31_MARKER "R275 NE52:[083d,08ad), RETF6. Opaque084d precedes current-state link writes. Updates883a or anchor.next, prev links and pending WORD0; final zero successor unguarded, writable sentinel/valid view required. No universal arena/lifetime proof." },
	{ 0x74b23, 0x74c4f, "bcc31_compose_event_chains", 4, BCC31_MARKER "R275 NE52:[1323,144f), RETF4. Conditional zero-kind/code or contiguous-position merge copies code+8 then target+e then ORs flags+2 before free-list calls. Otherwise links source.prev/destination.next; opaque free-list effects and aliases remain unproved." },
	{ 0x74eec, 0x74f15, "bcc31_walk_kind4_events", 0, BCC31_MARKER "R275 NE52:[16ec,1715), RETF. Loads main root883a, saves current event.next+a before kind4 dispatch; saved-register protocol permits subsequent saved-next advance, not list validity/termination or unchanged arbitrary state." },
	{ 0x8b200, 0x8b21d, "bcc31_prepend_private_event", 2, BCC31_MARKER "R275 NE64:[0000,001d), near RET2. Private root8e1a, not main root883a; no shared membership claim." },
	{ 0x8b21d, 0x8b37f, "bcc31_dispatch_event_input", 2, BCC31_MARKER "R275 NE64:[001d,017f), RETF2. Follows metadata+4/+6 pair; zero pair clears kind. Current flags0004, finite span/count and1a79 select producer017f or unreviewed05c0. Saves SI/DI on intact returning protocol, not acyclicity/count nonwrap." },
	{ 0x8b37f, 0x8b7c0, "bcc31_produce_selected_branch_events", 8, BCC31_MARKER "R275 NE64:[017f,05c0), near RET8. Saved q uses model1a67=3 and earlier flags0004; later fresh flags0004 and saved q select JE or JNE-plus-JE. Distinct allocation provenance is not proved numerical inequality: JE target saved02ef return, JNE target later0429 return. Composition may transfer code/target identity before consumer; opaque request effects/current frame/selector/alias premises remain." },
	{ 0x79644, 0x79b29, "bcc31_copy_selected_event", 4, BCC31_MARKER "R275 reused NE55:[0e44,1329), RETF4. Copies old code+8/target+e after factory124a, clears old fields; new flags0010 at1300, NOT0100. Does not initially choose JE or establish whole caller lifetime." },
	{ 0x85200, 0x8543d, "bcc31_consume_branch_events", 4, BCC31_MARKER "R275 reused NE61:[0000,023d), RETF4. Selected kind0/4/5 reads code+8,target+e through current8891 after preludes/callbacks; downstream current branch wrappers separate from historical event creation/traversal." },
	{ 0x3ee24, 0x3ee31, "bcc31_identity_far_pair", 4, BCC31_MARKER "R289 NE28:[4824,4831), complete13-byte/6-instruction RETF4 leaf: loads frame BP+8->DX and BP+6->AX, no dereference/helper. Returns supplied pair only with valid frame/return protocol; does not establish current7f64 selects it." },
	{ 0x9400, 0x950b, "bcc31_argument_selection_helper", 4, BCC31_MARKER "R291 NE3:[0000,010b), complete267-byte/88-instruction RETF4 body. Argument FAR+8/+a reaches sampled BYTE+d and followed FAR+4 WORD0 comparison0012; alternative FAR+10/+12 or finite current pair tables remain raw fields, not Event16. Physical argument chronology and current indirect8b42/8b3e/8b3a are conditional. Both local exits forward actual final opaque call DX:AX, not an explicit reload of input or saved pair; numerical identity/replacement and transitive effects unproved." },
	{ 0x74826, 0x74af2, "bcc31_prepare_record_children", 4, BCC31_MARKER "R329/R333 NE52:[1026,12f2), complete716-byte/261-instruction RETF4 body; adjacent five-WORD dispatch table excluded. Recursively replaces child pairs high-before-low through freshly loaded parent views and conditionally writes BYTE6 using finite signed/partial-register arithmetic. All eight exits freshly load current frame BP+8 into DX, THEN BP+6 into AX; not an unconditional input identity, different-pointer result or pure function. Opaque12fc, aliases, recursion termination, descendant cleanup and actual R310 traversal/source type remain unproved." },
	{ 0x7ebfc, 0x7ef99, "bcc31_lower_numeric_record", 4, BCC31_MARKER "R320 NE58:[15fc,1999), complete925-byte/350-instruction RETF4 body; adjacent16-WORD table excluded. Actual021d result overwrites current frame high then low. Numeric WORD2 dispatch, current1a67 and signed BYTE6 select ordered requests and current saved child/result words. Fifteen real FAR fields and24 near calls do not establish P/E/K/2172 prototypes or operation names. Thirteen POP SI/LEAVE/RETF4 envelopes restore saved SI only with intact frame/stack and applicable descendant cleanup; return DX:AX/effects are route-dependent, not a universal ABI or source-type theorem." },
	{ 0x7eff2, 0x7f607, "bcc31_numeric_lowering_parent", 6, BCC31_MARKER "R320 NE58:[19f2,2007), byte-complete1557-byte/553-instruction RETF6 body with PARTIAL semantic coverage only: [19f2,1ac3),[1ebb,1ee8),[1f92,2007). Actual021d result overwrites BP+a/BP+8; current post-2281 SI and fresh saved-second fields gate the numeric0010 zero-pair arm. Qualified success calls15fc then jumps1fe6, bypassing immediate pcmp@ construction; no actual R310 path or source type proved. Remaining arms, opaque calls and transitive effects unreviewed. Existing2eb4 constructor is reused, not a duplicate function or stronger ABI." },
};

// R117/R143 selected node tags only, not an instruction/event enum or a recovered historical name.
static bool bcc31_type_HelperNodeTag(RAnal *anal) {
	const BorlandEnumCase cases[] = {
		{ "flag8_set_request", 0x90 },
		{ "flag8_clear_request", 0x91 },
	};
	return borland_enum (anal, "bcc31_HelperNodeTag", 16, cases, R_ARRAY_SIZE (cases));
}

// R168 selected request/dispatch tags only, distinct from HelperNodeTag and EventBranchCode.
static bool bcc31_type_InstructionRequestTag(RAnal *anal) {
	const BorlandEnumCase cases[] = {
		{ "SUB", 0x2e },
		{ "DEC", 0x73 },
	};
	return borland_enum (anal, "bcc31_InstructionRequestTag", 16, cases, R_ARRAY_SIZE (cases));
}

// R275 actual mnemonic/opcode/inverse-table join, not historical instruction emission.
static bool bcc31_type_EventBranchCode(RAnal *anal) {
	const BorlandEnumCase cases[] = {
		{ "JE", 0xa },
		{ "JNE", 0xb },
	};
	return borland_enum (anal, "bcc31_EventBranchCode", 16, cases, R_ARRAY_SIZE (cases));
}

// Stored offset/selector pair, not a flat pointer or a selector-validity assertion. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_FarStorage16(RAnal *anal) {
	const HelperMember members[] = {
		{ "offset", "uint16_t", 0 },
		{ "selector", "uint16_t", 2 },
	};
	return borland_record (anal, "bcc31_FarStorage16", 32, members, R_ARRAY_SIZE (members));
}

// R174/R294: case-exact key, unsigned qualifier, same-CS near handler and descriptor-dependent WORD+4. Final WORD has no established role. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_NearOptionDescriptor8Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "key", "uint8_t", 0 },
		{ "minimumQualifier", "uint8_t", 1 },
		{ "nearHandlerOffset", "uint16_t", 2 }, // Current CS, not FAR storage
		{ "handlerArgument", "uint16_t", 4 }, // B/S/c: target DS byte; P: no role inferred
	};
	return borland_record (anal, "bcc31_NearOptionDescriptor8Partial", 64, members, R_ARRAY_SIZE (members));
}

// R143: separate WORD-array segment and append capacity/used offsets. Unknown trailing WORD; no interleaved node record or allocator ABI. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_WordArrayAppendDescriptor8Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "currentArraySelector", "uint16_t", 0 }, // Node reloads this word as a segment, not a near array pointer
		{ "capacityOffset", "uint16_t", 2 }, // Unsigned append capacity comparison
		{ "usedOffset", "uint16_t", 4 }, // Saved old used-offset returned by append
	};
	return borland_record (anal, "bcc31_WordArrayAppendDescriptor8Partial", 64, members, R_ARRAY_SIZE (members));
}

// R168 selected SUB descriptor; tested unaligned WORD+3 is not the distinct overlapping WORD+4 read. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_InstructionDescriptor19Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "mnemonicOffset", "uint16_t", 0 }, // Current DS near literal offset
		{ "testedMaskWord", "uint16_t", 3 }, // Actual unaligned WORD+3; SUB=c100, mask8000
		{ "immediateAdjustmentSelector", "uint8_t", 7 },
		{ "word0d", "uint16_t", 13 },
		{ "modrmExtraWord", "uint16_t", 15 },
		{ "word11", "uint16_t", 17 },
	};
	return borland_record (anal, "bcc31_InstructionDescriptor19Partial", 152, members, R_ARRAY_SIZE (members));
}

// Alternative overlapping view, not a second physical field after WORD+3: SUB WORD+4=03c1 differs from tested+3=c100. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_InstructionDescriptor19OverlapReadPartial(RAnal *anal) {
	const HelperMember members[] = {
		{ "overlappingWord4", "uint16_t", 4 },
	};
	return borland_record (anal, "bcc31_InstructionDescriptor19OverlapReadPartial", 152, members, R_ARRAY_SIZE (members));
}

// R275 separate event allocation through current selector8891; no metadata/pending allocation identity implied. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_Event16Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "kind", "uint16_t", 0 },
		{ "flags", "uint16_t", 2 },
		{ "factoryCounterWord", "uint16_t", 4 }, // Factory stores current DS8859; no stronger global position identity
		{ "positionLengthWord", "uint16_t", 6 }, // Finite arithmetic quantity; not universal source or output length
		{ "branchCode", "bcc31_EventBranchCode", 8 }, // Only selected JE/JNE values named; other codes remain numeric
		{ "nextOffset", "uint16_t", 10 },
		{ "previousOffset", "uint16_t", 12 },
		{ "targetOffset", "uint16_t", 14 },
	};
	return bcc31_type_EventBranchCode (anal)
		&& borland_record (anal, "bcc31_Event16Partial", 128, members, R_ARRAY_SIZE (members));
}

// R275 separate metadata allocation through current8889; only selected followed far input and initialized link are established. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_EventMetadata16Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "inputNodePair", "bcc31_FarStorage16", 4 },
		{ "suppliedCount", "uint16_t", 8 },
		{ "factoryInitializedWordA", "uint16_t", 10 }, // FFFF store indexes metadata view with event SI; equal independent allocation offsets unproved
	};
	return bcc31_type_FarStorage16 (anal)
		&& borland_record (anal, "bcc31_EventMetadata16Partial", 128, members, R_ARRAY_SIZE (members));
}

// R275 independent pending allocation, current8881 view; insertion writes WORD0, not proof of shared-offset allocation correspondence. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_EventPending16Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "insertionWord", "uint16_t", 0 },
		{ "producerReadPair", "bcc31_FarStorage16", 10 }, // Observed offset/segment reads only; meaning unknown
	};
	return bcc31_type_FarStorage16 (anal)
		&& borland_record (anal, "bcc31_EventPending16Partial", 128, members, R_ARRAY_SIZE (members));
}

// R329/R333 descriptive addressed-record view only, not Event16, a source-language type or permission to type unproved dynamic addresses. Unknown bytes remain undefined; analysis field roles, not recovered historical C.
static bool bcc31_type_PreparationRecord20Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "numericClassification", "uint16_t", 0 },
		{ "numericLoweringClass", "uint16_t", 2 },
		{ "testedFlags", "uint16_t", 4 }, // Selected class1 tests0010
		{ "annotationByte", "uint8_t", 6 }, // Signed reads and modulo-byte writes; later reloads remain fresh
		{ "firstChildPair", "bcc31_FarStorage16", 12 }, // Recursive return stores high+e before low+c
		{ "secondChildPair", "bcc31_FarStorage16", 16 }, // Recursive return stores high+12 before low+10
	};
	return bcc31_type_FarStorage16 (anal)
		&& borland_record (anal, "bcc31_PreparationRecord20Partial", 160, members, R_ARRAY_SIZE (members));
}

static const ut32 bcc31_object_callbacks[][3] = {
	{ 0xff, 0x02aa, 0x9093a },
	{ 0xff, 0x02ae, 0x9197a },
	{ 0xff, 0x02b2, 0x917f2 },
	{ 0xff, 0x02af, 0x91452 },
	{ 0xff, 0x02b0, 0x91772 },
	{ 0xff, 0x029d, 0x91868 },
	{ 0xff, 0x02ab, 0x919d6 },
	{ 0xff, 0x02ad, 0x91a10 },
	{ 0xff, 0x02a9, 0x909c8 },
	{ 0xff, 0x02ac, 0x91531 },
	{ 0xff, 0x02bb, 0x8ecb3 },
	{ 0xff, 0x02a6, 0x8c0b8 },
	{ 0xff, 0x02a5, 0x8c0df },
	{ 0xff, 0x02ba, 0x8ebb3 },
	{ 0xff, 0x02a8, 0x90d47 },
	{ 0xff, 0x02b9, 0x8e75c },
	{ 0xff, 0x02b8, 0x8e76b },
	{ 0xff, 0x02b1, 0x919b1 },
	{ 0xff, 0x02a7, 0x8c120 },
	{ 0xff, 0x02c1, 0x8eb6d },
	{ 0xff, 0x02b7, 0x8ec62 },
	{ 0xff, 0x02b4, 0x8eb96 },
	{ 0xff, 0x02b6, 0x8ec20 },
	{ 0xff, 0x02b5, 0x8e7e9 },
	{ 0xff, 0x02c0, 0x8e4af },
	{ 0xff, 0x02bf, 0x8e941 },
};

static const ut32 bcc31_asm_callbacks[][3] = {
	{ 0xff, 0x02de, 0x928b6 },
	{ 0xff, 0x02c8, 0x9466a },
	{ 0xff, 0x02ce, 0x945d6 },
	{ 0xff, 0x02c9, 0x94400 },
	{ 0xff, 0x02ca, 0x94542 },
	{ 0xff, 0x02cd, 0x945fd },
	{ 0xff, 0x02c6, 0x947a9 },
	{ 0xff, 0x02c7, 0x94848 },
	{ 0xff, 0x02da, 0x9259c },
	{ 0xff, 0x02c5, 0x9492e },
	{ 0xff, 0x02dd, 0x92b33 },
	{ 0xff, 0x02d9, 0x91f80 },
	{ 0xff, 0x02d8, 0x91f8e },
	{ 0xff, 0x02df, 0x927ac },
	{ 0xff, 0x02c4, 0x9478e },
	{ 0xff, 0x02db, 0x91fa9 },
	{ 0xff, 0x02dc, 0x91fb8 },
	{ 0xff, 0x02cb, 0x94909 },
	{ 0xff, 0x02cc, 0x948d8 },
	{ 0xff, 0x02e0, 0x9272d },
	{ 0xff, 0x02d6, 0x92863 },
	{ 0xff, 0x02d5, 0x92772 },
	{ 0xff, 0x02d4, 0x92896 },
	{ 0xff, 0x02d3, 0x91fcd },
	{ 0xff, 0x02d2, 0x930ab },
	{ 0xff, 0x02d1, 0x92126 },
};

static bool bcc31_body(ut64 accepted, ut64 physical) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bcc31_functions); i++) {
		if (physical >= bcc31_functions[i].start && physical < bcc31_functions[i].end) {
			return !!(accepted & (1ULL << i));
		}
	}
	return true;
}

static bool bcc31_note(BorlandProfileContext *ctx, ut64 accepted, ut64 physical, int size, const char *name, const char *comment) {
	ut64 address = profile_mapped (ctx, physical, size, true);
	HelperOp *ops = calloc (size, sizeof (HelperOp));
	bool valid = ops && address != UT64_MAX && bcc31_body (accepted, physical)
		&& profile_code (ctx, physical, size, address, ops);
	free (ops);
	if (!valid || (name && !profile_label (ctx, address, name))) {
		return false;
	}
	borland_comment (ctx->anal, address, comment);
	return true;
}

static bool bcc31_data(BorlandProfileContext *ctx, ut64 physical, int size, const char *type, const char *name, const char *comment) {
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

static bool bcc31_array(BorlandProfileContext *ctx, ut64 physical, const char *element, ut32 count, const char *name, const char *comment) {
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

static bool bcc31_far(BorlandProfileContext *ctx, ut64 accepted, ut64 physical, int word0, int word1, ut64 target, bool executable) {
	const BorlandProfileBinding binding = { 3, 0, word0, word1, target, NULL, true, executable, true };
	return (!executable || bcc31_body (accepted, physical)) && profile_binding (ctx, physical, &binding);
}

static void bcc31_options(BorlandProfileContext *ctx, ut64 accepted) {
	static const struct { ut64 physical; const char *name; ut16 handler; ut64 target; ut16 destination; } rows[] = {
		{ 0x1581d, "bcc31_option_B", 0x5eb, 0x55deb, 0x1a98 },
		{ 0x15825, "bcc31_option_S", 0x5eb, 0x55deb, 0x1a97 },
		{ 0x15855, "bcc31_option_c", 0x5eb, 0x55deb, 0x1a73 },
		{ 0x1589d, "bcc31_option_P", 0xf13, 0x56713, 0 }
	};
	size_t i;
	if (bcc31_type_NearOptionDescriptor8Partial (ctx->anal)) {
		for (i = 0; i < R_ARRAY_SIZE (rows); i++) {
			if (bcc31_data (ctx, rows[i].physical, 8, "bcc31_NearOptionDescriptor8Partial", rows[i].name, i? NULL: BCC31_MARKER "R174: selected eight-byte rows before the disk handler sentinel, not whole-parser/CLI coverage. Zero-qualified B/S/c require current BYTE DS1827=0 (unsigned comparison); FF wildcard behavior exists separately. Dispatcher advances input offset only modulo65536, calls current near WORD+2 and continues scanning after nonzero AX. No case folding or invocation/history inferred.")) {
				if (bcc31_body (accepted, rows[i].target)) {
					profile_offset (ctx, rows[i].physical + 2, rows[i].handler, rows[i].target);
				}
				if (rows[i].destination) {
					profile_offset (ctx, rows[i].physical + 4, rows[i].destination, 0x13c00 + rows[i].destination);
				}
			}
		}
	}
	static const struct { ut64 physical; const char *name; } state[] = {
		{ 0x15427, "bcc31_current_option_qualifier" },
		{ 0x15673, "bcc31_current_c_supplier" },
		{ 0x15697, "bcc31_current_backend_selector" },
		{ 0x15698, "bcc31_current_B_supplier" },
		{ 0x156ed, "bcc31_current_P_control" }
	};
	for (i = 0; i < R_ARRAY_SIZE (state); i++) {
		bcc31_data (ctx, state[i].physical, 1, "uint8_t", state[i].name, i == 2? BCC31_MARKER "On-disk initial byte is not historical compiler state. R160 NE57:01e3 freshly selects nonzero ASM/zero object only if current loaded context and intervening effects permit.": NULL);
	}
	bcc31_note (ctx, accepted, 0x523ea, 0x19, "bcc31_ordered_mode_join_fragment", BCC31_MARKER "R174 NE35:[03ea,0403) is a partial tail, not a complete function: first BYTE1a73 |= current1a97, then BYTE1a97 |= current1a98. B's newly set S does not retroactively enter c. Separate partial NE38:021b..0223 can store1 to B then S; no only-writer or initialized/default/history claim.");
	bcc31_far (ctx, accepted, 0x56726, 2, 0x51c9, 0x7dc9, true);
}

static void bcc31_backends(BorlandProfileContext *ctx, ut64 accepted) {
	if (!bcc31_type_FarStorage16 (ctx->anal)) {
		return;
	}
	int family;
	for (family = 0; family < 2; family++) {
		ut64 source = family? 0x1965a: 0x19574;
		const ut32 (*callbacks)[3] = family? bcc31_asm_callbacks: bcc31_object_callbacks;
		if (bcc31_array (ctx, source, "bcc31_FarStorage16", 26, family? "bcc31_asm_source_callbacks26": "bcc31_object_source_callbacks26", BCC31_MARKER "R160:26 singleton nonadditive NE FAR cells, raw target ff/movable entry ordinal, not imported segment paragraphs. Conditional REP MOVSW installation to current DS8b36 copies52 WORDs/104 bytes only with DF=0 at copy, valid views and no defeating effects/aliases. No local CLD; preceding NE2:51c9 does not prove DF/DS preservation. Displacement28h supplies current8b5e; DATA references are static possibilities, not unconditional calls or installed-state proof.")) {
			int i;
			for (i = 0; i < 26; i++) {
				bcc31_far (ctx, accepted, source + 4 * i, callbacks[i][0], callbacks[i][1], callbacks[i][2], false);
			}
		}
	}
	bcc31_array (ctx, 0x1c736, "bcc31_FarStorage16", 26, "bcc31_mutable_callback_workspace26", BCC31_MARKER "Mutable FAR storage, not direct calls. Current8b5e source slot+28 is object entry02bb->NE66:08b3 or ASM02dd->NE68:0d33 only while qualifying forward installation and current values survive. Other callback writers, scheduling and lifetime remain unknown.");
	bcc31_note (ctx, accepted, 0x8ecb3, 0x8d, "bcc31_object_callback_partial", BCC31_MARKER "R160 only NE66:[08b3,0940) prefix through computed dispatch is covered; not a complete function extent. Uses19-byte descriptor4128 and current8e2b/8e38 workspace. Preparation/output descendants unproved.");
	bcc31_note (ctx, accepted, 0x92b33, 0x9e, "bcc31_asm_callback_partial", BCC31_MARKER "R160 only NE68:[0d33,0dd1) prefix and separate[0e6d,0e7c) mnemonic fragment are covered; not a complete function extent. Tag91 requests push/call literals conditionally; whole formatter/sink/encoding effects unproved.");
}

static void bcc31_append(BorlandProfileContext *ctx, ut64 accepted) {
	bcc31_type_HelperNodeTag (ctx->anal);
	if (bcc31_type_WordArrayAppendDescriptor8Partial (ctx->anal)) {
		static const ut16 offsets[] = { 0x8871, 0x87ca, 0x87c2, 0x87ba, 0x87b2 };
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (offsets); i++) {
			char name[64];
			snprintf (name, sizeof (name), "bcc31_word_array_descriptor_%x", offsets[i]);
			bcc31_data (ctx, 0x13c00 + offsets[i], 8, "bcc31_WordArrayAppendDescriptor8Partial", name, BCC31_MARKER "R143 one of five independent two-byte append descriptors, not a field of an interleaved node. Equal append sizes do not establish equal old offsets, synchronized histories or valid corresponding storage. First returned offset U must equal u16(2*C) for returned counter C to address the same slot; that invariant is unproved.");
		}
	}
	bcc31_data (ctx, 0x1c459, 2, "uint16_t", "bcc31_node_counter_not_allocation_offset", NULL);
	static const ut64 calls[] = { 0x7a0bc, 0x7a0c9, 0x7a0d4, 0x7a0df, 0x7a0ea };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (calls); i++) {
		bcc31_far (ctx, accepted, calls[i], 51, 0x121a, 0x7241a, true);
	}
	bcc31_far (ctx, accepted, 0x8051b, 0xff, 0x25d, 0x7a0b0, true);
	bcc31_far (ctx, accepted, 0x80530, 0xff, 0x25d, 0x7a0b0, true);
}

static void bcc31_instructions(BorlandProfileContext *ctx, ut64 accepted) {
	bcc31_type_InstructionRequestTag (ctx->anal);
	bcc31_type_InstructionDescriptor19OverlapReadPartial (ctx->anal);
	if (bcc31_type_InstructionDescriptor19Partial (ctx->anal)
			&& bcc31_data (ctx, 0x18092, 19, "bcc31_InstructionDescriptor19Partial", "bcc31_SUB_descriptor_tag002e", BCC31_MARKER "R168 DS4128+19*002e=4492. Exact19 bytes2955fe00c1030002020a0a0a00000029002d00. WORD+3=c100 versus overlapping WORD+4=03c1; +7=02,+0f=0029,+11=002d. No whole-instruction or node/event enum equivalence.")) {
		profile_offset (ctx, 0x18092, 0x5529, 0x19129);
		ut64 base = profile_mapped (ctx, 0x17d28, 1, false);
		if (base != UT64_MAX) {
			profile_label (ctx, base, "bcc31_instruction_descriptors_base");
		}
	}
	bcc31_array (ctx, 0x195dc, "uint8_t", 12, "bcc31_selected_selector_mapping12", BCC31_MARKER "R168 selected12-byte window000402060307010506070504, not complete signed-index table extent. Mapping sign-extends input BYTE and result BYTE; selector0b reads04. No unrestricted unsigned register enum.");
	if (bcc31_data (ctx, 0x8f984, 2, "uint16_t", "bcc31_SUB_dispatch_cell", NULL)
			&& profile_offset (ctx, 0x8f984, 0x12c0, 0x8f6c0)) {
		bcc31_note (ctx, accepted, 0x8f6c0, 0x10, "bcc31_SUB_dispatch_fragment", BCC31_MARKER "R168 partial NE66:[12c0,12d0), not a complete function. Tag002e static same-CS dispatch from1528+2*tag. Selected current ordinary route can request83 ec02; not a complete byte/object output or historical traversal.");
	}
	if (bcc31_data (ctx, 0x8fa0e, 2, "uint16_t", "bcc31_DEC_dispatch_cell", NULL)
			&& profile_offset (ctx, 0x8fa0e, 0xb81, 0x8ef81)) {
		bcc31_note (ctx, accepted, 0x8ef81, 0x1b, "bcc31_DEC_register_fragment", BCC31_MARKER "R168 partial NE66:[0b81,0b9c), not a complete function. DEC tag0073 and current register selector0b can request4c. Existence does not import BCC2.0's amount-two normalizer rule.");
	}
	bcc31_note (ctx, accepted, 0x8fdbe, 0x26, "bcc31_ModRM_register_fragment", BCC31_MARKER "R168 partial NE66:[19be,19e4), not a complete function; only selected register ModRM branch, memory/fallback routes unreviewed.");
	bcc31_far (ctx, accepted, 0x8e413, 51, 0x121a, 0x7241a, true);
}

static void bcc31_callback_control(BorlandProfileContext *ctx, ut64 accepted) {
	if (bcc31_type_FarStorage16 (ctx->anal)) {
		if (bcc31_data (ctx, 0x13cc2, 4, "bcc31_FarStorage16", "bcc31_identity_callback_source_cell", NULL)) {
			bcc31_far (ctx, accepted, 0x13cc2, 0xff, 0xa, 0x3ee24, false);
		}
		if (bcc31_data (ctx, 0x13cca, 4, "bcc31_FarStorage16", "bcc31_transformer_callback_source_cell", NULL)) {
			bcc31_far (ctx, accepted, 0x13cca, 0xff, 0x9, 0x480b1, false);
		}
		bcc31_array (ctx, 0x1bb64, "bcc31_FarStorage16", 2, "bcc31_mutable_argument_callback_pair", BCC31_MARKER "R289 four-WORD conditional installation atNE38:018e; requires DF0 at REP MOVSW, valid current segments/stack and nondefeating aliases/effects. Current indirect calls through7f64/7f68 are not unconditional static calls or historical invocation proof.");
	}
	bool installer = bcc31_note (ctx, accepted, 0x55943, 0x59, "bcc31_argument_callback_install_fragment", BCC31_MARKER "R289 NE38:[0143,019c) partial installation prefix, not a complete function. Earlier four-WORD00c2/00ca->7f64 copy is distinct from later32-WORD0114->81d5 constructor copy. Source selection uses fresh post-helper1aed&1; no CLD or lifetime proof.");
	if (installer && bcc31_body (accepted, 0x56713)
			&& bcc31_data (ctx, 0x156ed, 1, "uint8_t", "bcc31_current_P_control", NULL)) {
		borland_comment (ctx->anal, profile_mapped (ctx, 0x156ed, 1, false), BCC31_MARKER "R294 supplier/control join to R289: installer NE38:0166 samples post-0161-call BYTE1aed bit0 into8188; zero selects identity NE28:4824, nonzero transformer NE30:64b1. Handler store survival through callbacks/writers/installer0161, defaults and historical -P ordering remain unproved. No direct calls inferred from mutable7f64.");
	}
	bcc31_data (ctx, 0x1bd88, 1, "uint8_t", "bcc31_sampled_callback_control_bit", NULL);
	if (bcc31_note (ctx, accepted, 0x480b1, 438, "bcc31_argument_transformer_partial", BCC31_MARKER "R289 only NE30:[64b1,6667)438-byte prefix is covered, not a complete function despite local RETF4 exits. WORD2=0015/saved WORD0=4 forwards actual NE3:0000 result. WORD2=0014 call-free path follows old FAR+8, reads target+e then+c, writes input+a then+8, follows NOW-current FAR+8 and writes classification+2. Replacement/restart and opaque helpers remain qualified; current SI is not refreshed after rewrite; computed dispatch/table arms unreviewed.")) {
		bcc31_far (ctx, accepted, 0x480e5, 3, 0, 0x9400, true);
	}
}

static void bcc31_events(BorlandProfileContext *ctx, ut64 accepted) {
	bcc31_type_Event16Partial (ctx->anal);
	bcc31_type_EventMetadata16Partial (ctx->anal);
	bcc31_type_EventPending16Partial (ctx->anal);
	if (bcc31_array (ctx, 0x1947c, "uint16_t", 2, "bcc31_JE_JNE_mnemonic_offsets", BCC31_MARKER "R275 pre-load DS587c/587e->58d0/58d3 je/jne;58a2/58a3=74/75;5960/5962=000b/000a. Current loaded DS/tables may change; static identity is not executed historical output.")) {
		profile_offset (ctx, 0x1947c, 0x58d0, 0x194d0);
		profile_offset (ctx, 0x1947e, 0x58d3, 0x194d3);
	}
	bcc31_array (ctx, 0x194a2, "uint8_t", 2, "bcc31_JE_JNE_short_opcodes", NULL);
	if (bcc31_type_EventBranchCode (ctx->anal)) {
		bcc31_array (ctx, 0x19560, "bcc31_EventBranchCode", 2, "bcc31_JE_JNE_inverse_codes", NULL);
	}
	bcc31_array (ctx, 0x8543d, "uint16_t", 6, "bcc31_event_consumer_switch_words", NULL);
	if (bcc31_note (ctx, accepted, 0x74cc9, 5, "bcc31_kind4_walker_driver_fragment", BCC31_MARKER "R275 NE52:[14c9,14ce) one actual CALL, not complete driver. Other partial driver[16ae,16bc) passes actual post-pass DI to consumer; no whole-pass/historical lifetime inferred.")) {
		bcc31_far (ctx, accepted, 0x74cca, 0xff, 0x22b, 0x74eec, true);
	}
	bcc31_far (ctx, accepted, 0x74f07, 0xff, 0x298, 0x8b21d, true);
	static const ut64 factory[] = { 0x8b38c, 0x8b41b, 0x8b4e9, 0x8b4f0, 0x8b58b, 0x8b5a0, 0x8b62a };
	static const ut64 compose[] = { 0x8b625, 0x8b68a, 0x8b783, 0x8b78c };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (factory); i++) {
		bcc31_far (ctx, accepted, factory[i], 0xff, 0x21e, 0x73b30, true);
	}
	for (i = 0; i < R_ARRAY_SIZE (compose); i++) {
		bcc31_far (ctx, accepted, compose[i], 0xff, 0x21f, 0x74b23, true);
	}
	bcc31_far (ctx, accepted, 0x8b79c, 0xff, 0x220, 0x7403d, true);
	bcc31_callback_control (ctx, accepted);
}

static bool bcc31_dispatch(BorlandProfileContext *ctx, ut64 physical, ut64 segment, const ut16 *targets, int count, const char *name, const char *comment) {
	if (!bcc31_array (ctx, physical, "uint16_t", count, name, comment)) {
		return false;
	}
	int i;
	for (i = 0; i < count; i++) {
		profile_offset (ctx, physical + 2 * i, targets[i], segment + targets[i]);
	}
	return true;
}

static void bcc31_records(BorlandProfileContext *ctx, ut64 accepted) {
	bcc31_type_PreparationRecord20Partial (ctx->anal);
	static const ut16 preparation[] = { 0x1081, 0x1091, 0x1091, 0x1120, 0x1091 };
	static const ut16 lowering[] = { 0x188d, 0x188d, 0x17ad, 0x17ad, 0x17ad, 0x17ad, 0x162b, 0x162b, 0x196d, 0x196d, 0x196d, 0x1994, 0x17ad, 0x17ad, 0x162b, 0x162b };
	static const ut16 parent[] = { 0x1e12, 0x1e12, 0x1d37, 0x1d37, 0x1d37, 0x1d37, 0x1ac3, 0x1ac3, 0x1e99, 0x1e99, 0x1e99, 0x1fe6, 0x1d37, 0x1d37, 0x1acd, 0x1ebb };
	bcc31_dispatch (ctx, 0x74af2, 0x73800, preparation, R_ARRAY_SIZE (preparation), "bcc31_record_preparation_dispatch5", BCC31_MARKER "R329/R333 literal CS12f2 five-WORD data, outside the complete body. DATA references are static same-CS projections, not unconditional executable edges or proof that the table remains unchanged.");
	bcc31_dispatch (ctx, 0x7ef99, 0x7d600, lowering, R_ARRAY_SIZE (lowering), "bcc31_numeric_lowering_dispatch16", BCC31_MARKER "R320 separate literal CS1999 WORD table for u16(WORD2-1)<=000f. Numeric classifications are not source types; same-CS DATA projections do not establish historical traversal or descendant semantics.");
	bcc31_dispatch (ctx, 0x7f613, 0x7d600, parent, R_ARRAY_SIZE (parent), "bcc31_parent_numeric_dispatch16", BCC31_MARKER "R320 literal parent CS2013 table; cell2031=1ebb for numeric WORD2=0010. Other targets are literal projections only, not full semantic coverage of the parent arms.");
	bcc31_far (ctx, accepted, 0x7ec0a, 0xff, 0x21d, 0x74826, true);
	bcc31_far (ctx, accepted, 0x7f004, 0xff, 0x21d, 0x74826, true);
	bcc31_note (ctx, accepted, 0x748ad, 8, NULL, BCC31_MARKER "R333 current recursive DX is stored to parent+e BEFORE AX to+c through the same freshly loaded parent. Later LES reads the updated pair; calls/aliases may change the argument frame.");
	bcc31_note (ctx, accepted, 0x74aa4, 4, NULL, BCC31_MARKER "R333 BYTE6 store precedes fresh L/R frame-local reads. Later12db reloads the parent before reading/negating BYTE6;12e4 store precedes fresh BP+8 then BP+6 return loads. Do not cache across these alias-sensitive stores.");
	if (bcc31_array (ctx, 0x1938d, "uint8_t", 6, "bcc31_pcmp_suffix", NULL) && bcc31_body (accepted, 0x7f5dd)) {
		profile_offset (ctx, 0x7f5dd, 0x578d, 0x1938d);
	}
	if (bcc31_array (ctx, 0x193c2, "uint8_t", 3, "bcc31_near_helper_prefix", NULL) && bcc31_body (accepted, 0x804d4)) {
		profile_offset (ctx, 0x804d4, 0x57c2, 0x193c2);
	}
	if (bcc31_array (ctx, 0x193c5, "uint8_t", 3, "bcc31_far_helper_prefix", NULL) && bcc31_body (accepted, 0x804e4)) {
		profile_offset (ctx, 0x804e4, 0x57c5, 0x193c5);
	}
	static const ut16 request[] = { 0x16bc, 0x1718, 0x174f, 0x176f, 0x17a4, 0x1834, 0x1873, 0x1914, 0x1953, 0x198a, 0x1fa2, 0x1fb2, 0x1fc2, 0x1fd2 };
	static const ut16 alternate[] = { 0x175f, 0x1863, 0x1943 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (request); i++) {
		bcc31_far (ctx, accepted, 0x7d600 + request[i], 0xff, 0x218, 0x79fc4, true);
	}
	for (i = 0; i < R_ARRAY_SIZE (alternate); i++) {
		bcc31_far (ctx, accepted, 0x7d600 + alternate[i], 0xff, 0x25e, 0x7a22e, true);
	}
	bcc31_far (ctx, accepted, 0x7ef90, 0xff, 0x273, 0x844cb, true);
	if (bcc31_note (ctx, accepted, 0x745b1, 0xc, NULL, BCC31_MARKER "R320 NE52:[0db1,0dbd) partial caller window only: pushes current BP+8,BP+6,DI before actual FAR call toNE58:19f2. Not a complete caller body or universal argument declaration.")) {
		bcc31_far (ctx, accepted, 0x745b9, 0xff, 0x217, 0x7eff2, true);
	}
	bcc31_note (ctx, accepted, 0x7f4bb, 0x2d, NULL, BCC31_MARKER "R320 selected zero-pair arm: saved-second WORD0=2, CURRENT post-2281 SI=000a/000b and fresh second-record WORD+c OR WORD+e=0. Push saved-first high then low, call15fc at1ee2, jump1fe6. Qualified bypass of immediate pcmp@ constructor, not actual R310 traversal or source type; failed predicates enter unreviewed request arms.");
	bcc31_note (ctx, accepted, 0x7f592, 5, NULL, BCC31_MARKER "R320 fresh1a95 zero selects immediate pcmp@ path1fdc; nonzero makes four actual0218 requests then jumps1c2b, not1fe6. This observed branch does not generalize to all parent arms or historical optimizer policy.");
	bcc31_note (ctx, accepted, 0x7f5dc, 3, NULL, BCC31_MARKER "R320 literal lowercase pcmp@ suffix, then0055 and actual PUSH-CS/near call2eb4. Existing qualified constructor selects N_/F_ from current1a66/8ab8; no later case conversion, external spelling, serialization or executed call inferred.");
}

static int borland_bcc31_profile(RAnal *anal) {
	BorlandProfileContext ctx;
	if (borland_eligible (anal) < 0 || !profile_identity (anal, &ctx, "ne", 672150, "87c6dfbad817eeca31c069043f08063f7122663e51932ad089e6d1c563450d3b")) {
		return 0;
	}
	r_anal_types_prepare (anal);
	ut64 accepted = 0;
	int count = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bcc31_functions); i++) {
		bool applied = profile_function (&ctx, bcc31_functions[i].start, bcc31_functions[i].end - bcc31_functions[i].start, bcc31_functions[i].name, bcc31_functions[i].purge, bcc31_functions[i].comment);
		if (applied) {
			accepted |= 1ULL << i;
			count++;
		}
		R_LOG_INFO ("Borland bcc31-qualified: FILE 0x%08"PFMT64x" %s", bcc31_functions[i].start, applied? "qualified (including unchanged)": "preserved/refused; dependent facts skipped");
	}
	bcc31_options (&ctx, accepted);
	bcc31_backends (&ctx, accepted);
	bcc31_append (&ctx, accepted);
	bcc31_instructions (&ctx, accepted);
	bcc31_events (&ctx, accepted);
	bcc31_records (&ctx, accepted);
	return count;
}

#undef BCC31_MARKER
