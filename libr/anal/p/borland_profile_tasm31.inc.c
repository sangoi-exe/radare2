/* radare - LGPL - Copyright 2026 */

#define TASM31_MARKER "[LegacyToolchains tasm31-qualified] "

static const struct {
	ut64 start;
	ut64 end;
	const char *name;
	const char *comment;
} tasm31_functions[] = {
	{ 0x744d, 0x748d, "tasm31_encode_call", TASM31_MARKER "Logical 0:[6c4d,6c8d). R119/TI01: current tag29 and8C90 CF choose ordinary16-bit four-byte0E E8 or five-byte9A. Four-byte branch has NO NOP; later linker90 0E E8 rewrite is distinct. Three terminal tails to36D6; alternative indirect/operand-size descendants remain opaque." },
	{ 0x9490, 0x9501, "tasm31_call_far_predicate_cf", TASM31_MARKER "Logical 0:[8c90,8d01). R119/R145: CF1 retains FAR. Requires current SMART705E:20, zero operand06 and qualified identity. Ordinary branch installs postlookup AX as ES (including0), reads1A BEFORE04, then restores operand ES/CX; not simply7060 equality. IDEAL branch normalizes target first/current second. No numeric AX-bool contract." },
	{ 0x84aa, 0x84e9, "tasm31_emit_near_operand", TASM31_MARKER "Logical 0:[7caa,7ce9). R152/TI01: ordinary16-bit branch includes already emitted prefix count in displacement, prepares current operand, emits CL then word.8DF7 CF1 alternate width is separate; opaque helpers are not assumed to preserve arbitrary registers." },
	{ 0x84e9, 0x850a, "tasm31_emit_far_operand", TASM31_MARKER "Logical 0:[7ce9,7d0a). R119/TI01: ordinary16-bit branch emits CL9A plus low offset/word16; alternative-width branch is not generalized. Terminal tail910F, not inline data." },
	{ 0x48f6, 0x4913, "tasm31_emit_byte", TASM31_MARKER "Logical 0:[40f6,4113). TI01: writes AL at6F4E+old6F4C, increments word count, ancillary425E conditional. Adjacent4113 literal90 is NOT part of body or NOP-fill owner." },
	{ 0x4914, 0x492f, "tasm31_emit_word", TASM31_MARKER "Logical 0:[4114,412f). TI01: current AX write/count+2; tails425E. Adjacent412F excluded." },
	{ 0x4930, 0x494f, "tasm31_emit_word_pair", TASM31_MARKER "Logical 0:[4130,414f). TI01: current AX/CX write/count+4; tails425E. No flat pointer prototype." },
	{ 0x8682, 0x8694, "tasm31_prepare_call_operand", TASM31_MARKER "Logical 0:[7e82,7e94). R133: save operand ES to7406, reset emission, explicitly save CX around9698. Materialization effects remain conditional." },
	{ 0x874b, 0x876e, "tasm31_classify_immediate_cf", TASM31_MARKER "Logical 0:[7f4b,7f6e). R139 corrected complete end includes failure RET7F6D. Tags28/29 accepted CF0; tag20 has additional current mode/word14 tests." },
	{ 0x4db3, 0x4e1e, "tasm31_restore_replay_record", TASM31_MARKER "Logical 0:[45b3,461e). TI01: record05:10 compact restores selected fields/endpoint; otherwise forward20-word06..2E→7050..7078 requires DF0 and valid DS/SS. Regenerates7078 callback after restore;05:20 invokes near record30 with DI32. Current ES/DS changes are real." },
	{ 0x4ef5, 0x4f15, "tasm31_snapshot_and_dispatch", TASM31_MARKER "Logical 0:[46f5,4715). TI01: forward24-word7050..7080→71B6..71E6 includes7078 at71DE; indirect CALL[7078]. AFTER callback freshly rereads7056/7058 to overwrite71B6/71B8; no arbitrary callback/global/record-ES preservation." },
	{ 0x4f15, 0x4f93, "tasm31_admit_replay_record", TASM31_MARKER "Logical 0:[4715,4793). TI01:47F2 returned CF selects compact/full. One paragraph compact; three paragraphs full with20-word snapshot copy ending before71DE; extension size derives from current707A, stores2E/30 and invokes snapshot71E2 with DI32. Valid finite allocation/DF/aliases remain conditions." },
	{ 0x4f93, 0x4ff2, "tasm31_allocate_link_replay_record", TASM31_MARKER "Logical 0:[4793,47f2). TI01: paragraph pool71EA/71EC, save record ES around3016, store actual returned AX at02;04 uses current43D7 plus POST3016 CX. LES/XCHG list insertion stores replaced selector at00. Allocator descendants opaque." },
	{ 0x4ff2, 0x5022, "tasm31_compact_replay_predicate_cf", TASM31_MARKER "Logical 0:[47f2,4822). TI01: rejects extension71E4, missing prior71F2 or14-word current context mismatch; SUB/SBB endpoint difference returns CF, not only numeric low difference. REPE comparison geometry requires DF0/valid storage." },
	{ 0x167d2, 0x1685a, "tasm31_select_replay_callback", TASM31_MARKER "Logical f90:[66d2,675a). TI01: current705F:10 selects F3A9 versusF50D into7078. Clear branch indexes current7077*8 into selected2BC8/2C68/2B78/2C18; set branch indexes2CB8 by*4. Valid table/state extent conditional; selection is not historical pass attribution." },
	{ 0x5389, 0x53df, "tasm31_finalize_expression", TASM31_MARKER "Logical 0:[4b89,4bdf). R139:05 bit10 has priority; save POST5989 word04 across95FB. Bit20-only calls6311 then FRESH word04. After4BED read CURRENT05:40, transfer current25&0F→tag and1C→02. Deferred29 becomes09, not an unconditional FAR encoder request." },
	{ 0x53ed, 0x53fc, "tasm31_materialize_expression", TASM31_MARKER "Logical 0:[4bed,4bfc). R139:5F26→9698,600F,6096,4BFC then tail5F2D reloads CURRENT global7406 as ES. Not arbitrary record/global preservation." },
	{ 0x53fc, 0x542c, "tasm31_mask_materialized_tag", TASM31_MARKER "Logical 0:[4bfc,4c2c). R139:clear tag20,set04:80; conditional04:08 and05 nibble updates. Immediate29 can become09 independently of deferred transfer." },
	{ 0x6189, 0x61eb, "tasm31_save_tag_or_resolve_identity", TASM31_MARKER "Logical 0:[5989,59eb). R139:tag20 saves00/02→25/1C then clears tag/value and pending fields;4B89 immediately95FB discards this temporary saved tag. Other branch stores actual returned170A CX to18. Descendant effects qualified." },
	{ 0x9dfb, 0x9e0c, "tasm31_clear_deferred_tag", TASM31_MARKER "Logical 0:[95fb,960c). R133/R139:clear05:40,25,1C only; not pending06 or identity18." },
	{ 0x6b11, 0x6b61, "tasm31_transfer_pending_identity", TASM31_MARKER "Logical 0:[6311,6361). R139:copy1E/20→14/16 before tag test; only nonzero22 updates18 and conditionally1A/current subtype/04:04. Does not directly write pending06; not transitive preservation." },
	{ 0x2248, 0x2251, "tasm31_lookup_expression", TASM31_MARKER "Logical 0:[1a48,1a51). R145:1C65 selects state in ES, tail4A75 with DI08; sometimes AX0 while ES remains selected state. No unconditional pointer-return prototype." },
	{ 0x2465, 0x24e7, "tasm31_select_symbol_state", TASM31_MARKER "Logical 0:[1c65,1ce7). R145:current43D6/cache0E selects state; strictJA successor choice versus initialJAE, conditional cache write. Valid terminating links/finite arithmetic required; returned ES need not equal AX." },
	{ 0x5275, 0x52c6, "tasm31_reconstruct_selected_expression", TASM31_MARKER "Logical 0:[4a75,4ac6). R145:nonzero state08→fresh scalar;else nonzero0A→fresh cached40-byte copy after REREADING0A postallocation;else AX0 leaves ES selected. Qualified normal returns CF0/ZF1, not constant AX or safe null-record. DF0/valid storage/aliases conditional." },
	{ 0x50e2, 0x50f2, "tasm31_clear_expression_view", TASM31_MARKER "Logical 0:[48e2,48f2). R145 shared clear entry: genuine near CALL at logical0:5137/FILE5937 targets48e2/FILE50e2, independently of allocation entry48cc. XORAX/MOVDIAX/MOVCX14h/REPSTOSW clear40 bytes then set byte10=1; DF=0, valid selected ES storage and aliases remain conditions. This clear size is not the THREE-paragraph pool allocation." },
	{ 0x9d0c, 0x9d2e, "tasm31_map_type_word_to_al", TASM31_MARKER "Logical 0:[950c,952e). R133:negative branch complements ALL16 AX bits;FFFE→0001→table09. Only AL replaced, AH not zero-extended. OR20 by caller forms29." },
	{ 0x22dc, 0x2302, "tasm31_project_current_handle", TASM31_MARKER "Logical 0:[1adc,1b02). R152:current handle07 bit20 clear returns word0E on ALL masked-class alternatives;bit20 set returns10. Numeric projections, not formal external IDs." },
	{ 0x13cb2, 0x13d65, "tasm31_append_internal_queue9", TASM31_MARKER "Logical f90:[3bb2,3c65). R152:normal existing-block route publishes updated06 before nine ordered stores CL,BX,DX,SI,saved DI. New-block route uses POST3F38 returnedAX/DL/DI, internal type06. DF0/valid nonaliased storage and ordinary stack required; alternate3B48/drain/allocators opaque." },
	{ 0x13688, 0x1369b, "tasm31_construct_class0a", TASM31_MARKER "Logical f90:[3588,359b). R182:after3E85 set class0A,zero0A,return currentES inAX;08 NOT initialized." },
	{ 0x136dd, 0x136ee, "tasm31_construct_class0c", TASM31_MARKER "Logical f90:[35dd,35ee). R164:after3E85 set class0C,posthelperBP→0A,return currentES inAX;08 NOT initialized." },
	{ 0x136ee, 0x13718, "tasm31_construct_class0d", TASM31_MARKER "Logical f90:[35ee,3618). R176:class0D;posthelperBP/BX/DX/SI/DI→0A/0C/0E/10/12,CH→14. Fresh selected caller givesCH0, not selector-one observation;08 NOT initialized." },
	{ 0x13f85, 0x13fcd, "tasm31_link_class_record", TASM31_MARKER "Logical f90:[3e85,3ecd). R164:two-paragraph request, global linking precedes06/05 stores;clears only1C/1E. Explicit saves restore AX/CX, not blanket zero-fill or arbitrary descendant preservation." },
	{ 0x14bc7, 0x14be5, "tasm31_walk_class_callback_bx", TASM31_MARKER "Logical f90:[4ac7,4ae5). R164:save CURRENT record02 before class04 comparison and conditional CALL BX;restore saved next plus AX/BX. Valid acyclic list/normal returns required, not reread-next semantics." },
	{ 0x1476f, 0x1479d, "tasm31_publish_class0a_index", TASM31_MARKER "Logical f90:[466f,469d). R182:5107 fresh current6F2E return→record08 BEFORE link walk. Current linked0A reread AFTER512F; terminal5142, not arbitrary originalES restoration." },
	{ 0x1479d, 0x147cf, "tasm31_publish_class0d_index", TASM31_MARKER "Logical f90:[469d,46cf). R176:current14 normalized0/1,read current0C/0E/10/12;524B actual fresh current6F32 return→08. Not class0C payload semantics." },
	{ 0x14803, 0x1482d, "tasm31_publish_class0c_index", TASM31_MARKER "Logical f90:[4703,472d). R164:current06/05→5201,restore recordES,actual fresh current6F32 return→08 before optional tail. Counter wrap allowed;no universal first-index-one." },
	{ 0x14b96, 0x14bc7, "tasm31_consume_current_class_index", TASM31_MARKER "Logical f90:[4a96,4ac7). R157/R164:current queued handle08 and04 supply numeric method table then5446. Class0A→01,0C/0D→02;not formal LOCAT/FIXDAT or captured historical queue association." },
	{ 0x9461, 0x9490, "tasm31_push_sign_extension_cf", TASM31_MARKER "Logical 0:[8c61,8c90). RF08:call-free;06 zero,04:04 clear,CBW low byte requires AH=current0B. Current705E:04 additionally requires CWD DX=current0C. CF0 admits sign extension, CF1 rejects;not a numeric bool, source-type or actual historical operand trace." },
	{ 0xfe06, 0xfe45, "tasm31_padding_gate_zf", TASM31_MARKER "Logical 0:[f606,f645). TI04/R207:consumeF687 ZF;fresh70AB:80/706C tests. Six work descendants274E,F827,2283,F6BA,22A9,23DD opaque;explicit XOR/DEC givesALFF/ZF0,other routeAL0/ZF1,AH not guaranteed. Saves BX/CX/DX on work route,not SI/ES/DS purity." },
	{ 0xfe87, 0xfeba, "tasm31_current_state_predicate_zf", TASM31_MARKER "Logical 0:[f687,f6ba). TI04:after optional074B, F69A FRESH70AF compare defines normal ZF1 exactly when that byte0;later current tests/explicit XOR DEC giveZF0. AL is not constant on direct returns;leaf flags do not define final predicate." },
	{ 0x1084b, 0x10858, "tasm31_conditional_store_leaf", TASM31_MARKER "Logical f90:[74b,758). TI04:call-free43C3:80 test;clear writes4598=1,otherwise none. Does not supply finalF687 flags;validDS/stack and noninterfering storage required." },
	{ 0x4e1e, 0x4e94, "tasm31_conditional_nop_fill", TASM31_MARKER "Logical 0:[461e,4694). TI01/R193/R199:SUB/SBB saved endpoint-current position;borrow has separate correction path. Nonborrow lowAX0 returns even ifDX nonzero.43C4 nonzero/43D6:08 clear adjusts record then BYPASSES7064 gate. Other route PUSHAX/CALLF606/POPAX consumes ZF,not AX.7064:08 diagnostic may return and fall through;465F uses THEN-CURRENT AX.4665 reloadsAL90 each iteration,emits into fresh buffer,then36D6. Conditional trailing90 is NOT linker's leading90 rewrite or proof of a historical CALL instance." },
	{ 0x4e94, 0x4eb2, "tasm31_correct_replay_record", TASM31_MARKER "Logical 0:[4694,46b2). TI01:sets43DC=FF;05:10 chooses SUB record0C,AX else SUB06,AX/SBB08,DX. Does not changeAX/DX;not blanket signed subtraction or shrink-success return." },
};

static const BorlandProfileRange tasm31_allocation[] = { { 0x50cc, 0x16 }, { 0x50f2, 0x28 } };

// R133/R139/R145: clearing/copying20 words is40 bytes;48CC advances its allocation pool by THREE paragraphs, independently of this view size. Clearing and literal forward-copy geometry require DF=0, valid selected storage and noninterfering aliases. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_Expression40Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "tag", "uint8_t", 0 }, // 29 can be immediate FAR request; finalization can clear bit20 or transfer deferred29 as09.
		{ "subtype", "uint8_t", 1 }, // Low three bits and independent upper bits are current numeric controls.
		{ "tag_value", "uint16_t", 2 },
		{ "flags04", "uint8_t", 4 }, // Current bit04 qualifies identity; bit80 changes CALL admission.
		{ "flags05", "uint8_t", 5 }, // Finalizer priority10 before20;40 controls deferred transfer.
		{ "pending_selector", "uint16_t", 6 }, // Raw selector/handle, not a resolved pointer.
		{ "value_low", "uint16_t", 0xa }, // Ordinary fresh FAR left storesFFFE here; IDEAL direct type29 instead leaves0A zero.
		{ "value_high", "uint16_t", 0xc },
		{ "word10", "uint16_t", 0x10 }, // Fresh clear sets byte10=1; cached copy overwrites the whole word.
		{ "word14", "uint16_t", 0x14 },
		{ "word16", "uint16_t", 0x16 },
		{ "target_identity", "uint16_t", 0x18 },
		{ "selected_identity", "uint16_t", 0x1a },
		{ "deferred_word", "uint16_t", 0x1c },
		{ "pending_word1e", "uint16_t", 0x1e },
		{ "pending_word20", "uint16_t", 0x20 },
		{ "pending_identity", "uint16_t", 0x22 },
		{ "value_extension", "uint8_t", 0x24 },
		{ "deferred_tag", "uint8_t", 0x25 }, // Transfer masks0F;95FB clears this byte and word1C, not pending06 or identity18.
		{ "format_handle", "uint16_t", 0x26 }, // Selected94A4 format1 branch reads this raw handle.
	};
	return borland_record (anal, "tasm31_Expression40Partial", 320, members, R_ARRAY_SIZE (members));
}

// R145: selected state consumed by4A75; scalar discriminator and cached-expression alternative are distinct. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_SelectedState16Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "key_low", "uint16_t", 0 },
		{ "key_selector", "uint16_t", 2 },
		{ "successor_selector", "uint16_t", 4 },
		{ "scalar_discriminator", "uint8_t", 8 },
		{ "scalar_extension", "uint8_t", 9 },
		{ "scalar_low_or_cached_selector", "uint16_t", 0xa }, // Reread after allocation in cached-copy branch.
		{ "scalar_high", "uint16_t", 0xc },
		{ "scalar_pending_selector", "uint16_t", 0xe },
	};
	return borland_record (anal, "tasm31_SelectedState16Partial", 128, members, R_ARRAY_SIZE (members));
}

// TI01:7050..7078 copied20 words. Does NOT include the callback at7078. Names refer to this context origin, not a live DS assertion. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_ReplayContext40Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "endpoint_low", "uint16_t", 0 },
		{ "endpoint_high", "uint16_t", 2 },
		{ "source_word7054", "uint16_t", 4 },
		{ "position_low", "uint16_t", 6 },
		{ "position_high", "uint16_t", 8 },
		{ "source_word705a", "uint16_t", 0xa },
		{ "source_word705c", "uint16_t", 0xc },
		{ "control705e", "uint8_t", 0xe },
		{ "control705f", "uint8_t", 0xf },
		{ "current_identity7060", "uint16_t", 0x10 },
		{ "control7064", "uint16_t", 0x14 }, // Bit08 diagnostic is not guaranteed suppression of fill.
		{ "descriptor_index7077", "uint8_t", 0x27 },
	};
	return borland_record (anal, "tasm31_ReplayContext40Partial", 320, members, R_ARRAY_SIZE (members));
}

// TI01:24-word7050→71B6 copy includes callback7078 at snapshot+28; post-callback current7056/7058 overwrite snapshot+0/+2. Not an immutable old-state snapshot. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_CallbackSnapshot48Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "copied_context", "tasm31_ReplayContext40Partial", 0 }, // First pair subsequently overwritten with current position.
		{ "selected_near_callback", "uint16_t", 0x28 }, // Source7078; excluded from the full-record20-word transfer.
		{ "extension_size", "uint16_t", 0x2a },
		{ "extension_save_callback", "uint16_t", 0x2c }, // Snapshot71E2, current near address.
		{ "extension_restore_callback", "uint16_t", 0x2e }, // Snapshot71E4, current near address.
	};
	return tasm31_type_ReplayContext40Partial (anal)
		&& borland_record (anal, "tasm31_CallbackSnapshot48Partial", 384, members, R_ARRAY_SIZE (members));
}

// TI01: one paragraph requested; record05 bit10 selects compact interpretation. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_CompactReplayRecord16Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "next_selector", "uint16_t", 0 },
		{ "returned3016_word", "uint16_t", 2 },
		{ "current_control_word", "uint16_t", 4 }, // Current43D7 high flags maskedC000 plus actual post3016 CX; byte05 masks10/20
		{ "saved_source7054", "uint16_t", 6 },
		{ "saved_position_low", "uint16_t", 8 },
		{ "saved_position_high", "uint16_t", 0xa },
		{ "extent_word", "uint16_t", 0xc }, // Added to saved position with ADD/ADC, not unrestricted signed length.
		{ "saved_source705a", "uint16_t", 0xe },
	};
	return borland_record (anal, "tasm31_CompactReplayRecord16Partial", 128, members, R_ARRAY_SIZE (members));
}

// TI01: three paragraphs requested independently; bit10 clear restores record06..2E→7050..7078. Payload excludes7078 callback. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_FullReplayRecord46Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "next_selector", "uint16_t", 0 },
		{ "returned3016_word", "uint16_t", 2 },
		{ "current_control_word", "uint16_t", 4 }, // Current43D7 high flags maskedC000 plus actual post3016 CX; byte05 masks10/20
		{ "saved_context", "tasm31_ReplayContext40Partial", 6 }, // 06/08 are post-callback endpoint;0C/0E are pre-callback position under qualified copy.
	};
	return tasm31_type_ReplayContext40Partial (anal)
		&& borland_record (anal, "tasm31_FullReplayRecord46Partial", 368, members, R_ARRAY_SIZE (members));
}

// TI01: bit20 extension form; request paragraphs=u16(current707A+0041)>>4, not a fixed allocation or safe wrap guarantee; extension payload begins32. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_ExtendedReplayHeader50Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "full_record", "tasm31_FullReplayRecord46Partial", 0 },
		{ "extension_size", "uint16_t", 0x2e },
		{ "extension_near_callback", "uint16_t", 0x30 }, // Restore invokes with DI32 only when current record05 bit20 set.
	};
	return tasm31_type_FullReplayRecord46Partial (anal)
		&& borland_record (anal, "tasm31_ExtendedReplayHeader50Partial", 400, members, R_ARRAY_SIZE (members));
}

// TI01 selector indexes current7077*8 into one of four initial tables; valid index extent remains conditional. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_CallbackDescriptor8Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "token_base_delta", "uint16_t", 0 }, // Adds current7618 before publishing761E.
		{ "word7620", "uint16_t", 2 },
		{ "word7622", "uint16_t", 4 },
		{ "word7624", "uint16_t", 6 },
	};
	return borland_record (anal, "tasm31_CallbackDescriptor8Partial", 64, members, R_ARRAY_SIZE (members));
}

// TI01 mode-bit10 branch indexes7077*4 and publishes only761E/7620. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_CallbackDescriptor4Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "token_base_delta", "uint16_t", 0 },
		{ "word7620", "uint16_t", 2 },
	};
	return borland_record (anal, "tasm31_CallbackDescriptor4Partial", 32, members, R_ARRAY_SIZE (members));
}

// R164/R176/R182:3E85 requests two paragraphs, links globally, clears only1C/1E and writes06/05. Constructors do NOT initialize08; no blanket zero-fill. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_ClassTaggedRecord32Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "previous_selector", "uint16_t", 0 },
		{ "next_selector", "uint16_t", 2 }, // 4AC7 saves current next before callback; not reread afterward.
		{ "record_class", "uint8_t", 4 }, // Selected0A/0C/0D, not external OMF types.
		{ "count_byte", "uint8_t", 5 },
		{ "source_handle", "uint16_t", 6 },
		{ "published_index", "uint16_t", 8 }, // Current callback result: class0A uses6F2E, classes0C/0D6F32; later consumer rereads current08.
		{ "link_or_class_word", "uint16_t", 0xa }, // Class0A link walk freshly rereads0A after emission; class0C post-helper BP.
		{ "class0d_word0c", "uint16_t", 0xc },
		{ "class0d_word0e", "uint16_t", 0xe },
		{ "class0d_word10", "uint16_t", 0x10 },
		{ "class0d_word12", "uint16_t", 0x12 },
		{ "class0d_selector", "uint8_t", 0x14 }, // Selected fresh caller supplies zero; selector-one callback is code, not observed caller state.
		{ "pending_block1c", "uint16_t", 0x1c },
		{ "pending_block1e", "uint16_t", 0x1e },
	};
	return borland_record (anal, "tasm31_ClassTaggedRecord32Partial", 256, members, R_ARRAY_SIZE (members));
}

// R152: ordered STOS stores at old block06, conditional on DF=0 and valid nonaliased storage; not an external OMF structure. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_InternalQueuePayload9(RAnal *anal) {
	const HelperMember members[] = {
		{ "internal_class", "uint8_t", 0 }, // Current CL.
		{ "location_low", "uint16_t", 1 }, // Current BX.
		{ "location_high", "uint16_t", 3 }, // Current DX.
		{ "first_projection", "uint16_t", 5 }, // Current SI.
		{ "second_projection", "uint16_t", 7 }, // Saved original DI popped into AX; save occurs after any preceding drain.
	};
	return borland_record (anal, "tasm31_InternalQueuePayload9", 72, members, R_ARRAY_SIZE (members));
}

// R283:1615 execution-CS selected record; accepted constructor values do not freeze later current fields. Unknown bytes remain undefined; descriptive analysis view, not historical source or a flat-pointer contract.
static bool tasm31_type_InputControlRecord18Partial(RAnal *anal) {
	const HelperMember members[] = {
		{ "word0", "uint16_t", 0x0 },
		{ "word2", "uint16_t", 0x2 },
		{ "word4", "uint16_t", 0x4 }, // Advertised object-code selection; consumer freshly loads into43D2
		{ "word6", "uint16_t", 0x6 },
		{ "word8", "uint16_t", 0x8 },
		{ "worda", "uint16_t", 0xa },
		{ "wordc", "uint16_t", 0xc },
		{ "worde", "uint16_t", 0xe },
		{ "word10", "uint16_t", 0x10 },
	};
	return borland_record (anal, "tasm31_InputControlRecord18Partial", 144, members, R_ARRAY_SIZE (members));
}

static bool tasm31_type_InternalRecordClass(RAnal *anal) {
	const BorlandEnumCase cases[] = { { "linked_index_class0a", 0xa }, { "counted_class0c", 0xc }, { "payload_class0d", 0xd } };
	return borland_enum (anal, "tasm31_InternalRecordClass", 8, cases, R_ARRAY_SIZE (cases));
}

// Independent masks; post3016 CX contributes to04/05, not an exclusive enumeration or observed historical record.
static bool tasm31_type_ReplayRecord05Mask(RAnal *anal) {
	const BorlandEnumCase cases[] = { { "compact_interpretation", 0x10 }, { "extension_callback", 0x20 } };
	return borland_enum (anal, "tasm31_ReplayRecord05Mask", 8, cases, R_ARRAY_SIZE (cases));
}

static bool tasm31_body(ut64 accepted, ut64 physical, int size) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tasm31_functions); i++) {
		if (physical < tasm31_functions[i].end && physical + size > tasm31_functions[i].start && !(accepted & (1ULL << i))) {
			return false;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (tasm31_allocation); i++) {
		if (physical < tasm31_allocation[i].physical + tasm31_allocation[i].size
				&& physical + size > tasm31_allocation[i].physical && !(accepted & (1ULL << R_ARRAY_SIZE (tasm31_functions)))) {
			return false;
		}
	}
	return true;
}

// Annotation windows qualify current bytes/context without assigning complete code ownership.
static bool tasm31_note(BorlandProfileContext *ctx, ut64 accepted, ut64 physical, int size, bool code, const char *name, const char *comment) {
	ut64 address = profile_mapped (ctx, physical, size, code);
	if (address == UT64_MAX || !tasm31_body (accepted, physical, size)) {
		return false;
	}
	ut8 *current = malloc (size);
	bool valid = current && profile_current (ctx, physical, size, address, current);
	free (current);
	if (!valid || (name && !profile_label (ctx, address, name))) {
		return false;
	}
	borland_comment (ctx->anal, address, comment);
	return true;
}

static bool tasm31_data(BorlandProfileContext *ctx, ut64 physical, int size, const char *type, const char *name, const char *comment) {
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

static bool tasm31_array(BorlandProfileContext *ctx, ut64 physical, const char *element, ut32 count, const char *name, const char *comment) {
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

// These exact six pairs join unchanged resident paragraph words to actual native MZ records, not Java relocation receipts.
static bool tasm31_mz_reference(BorlandProfileContext *ctx, ut64 accepted, ut64 physical, ut16 source_segment, ut16 source_offset, ut16 target_segment, ut16 target_offset, ut64 target_file) {
	ut64 address = profile_mapped (ctx, physical, 4, true);
	ut64 target = profile_mapped (ctx, target_file, 1, true);
	ut8 current[4];
	if (physical + 2 != 0x800 + 16ULL * source_segment + source_offset
			|| target_file != 0x800 + 16ULL * target_segment + target_offset || address == UT64_MAX || target == UT64_MAX
			|| !tasm31_body (accepted, physical, 4) || !tasm31_body (accepted, target_file, 1)
			|| !profile_current (ctx, physical, 4, address, current)
			|| r_read_le16 (current) != target_offset || r_read_le16 (current + 2) != target_segment
			|| 16ULL * r_read_le16 (current + 2) + r_read_le16 (current) != target) {
		return false;
	}
	int matches = 0;
	RBinReloc *reloc;
	R_VEC_FOREACH (ctx->file->bo->relocs, reloc) {
		if (reloc->paddr == physical + 2) {
			if (reloc->vaddr != address + 2 || reloc->type != R_BIN_RELOC_16 || reloc->ntype || reloc->additive
					|| reloc->import || reloc->symbol || reloc->addend || reloc->laddr || reloc->is_ifunc) {
				return false;
			}
			matches++;
		}
	}
	if (matches != 1 || !profile_reference (ctx->anal, address, target, R_ANAL_REF_TYPE_DATA)) {
		return false;
	}
	char *comment = r_str_newf (TASM31_MARKER "Qualified native MZ unchanged FAR pair -> logical %x:%x, original FILE %"PFMT64x". Native zero-origin DATA relationship complements the decoded instruction; original paragraphs are not Ghidra imported addresses.", target_segment, target_offset, target_file);
	borland_comment (ctx->anal, address, comment);
	free (comment);
	return true;
}

static void tasm31_facts(BorlandProfileContext *ctx, ut64 accepted) {
	tasm31_note (ctx, accepted, 0xfba9, 0x88, true, "tasm31_callback_f3a9_prefix", TASM31_MARKER "TI01: selected callback/dispatch partition, not a proved complete single function. F419..F431 token range check/indirect dispatch; descendants opaque. F50D has corresponding F535..F540 branch.");
	tasm31_note (ctx, accepted, 0x4f04, 0x4, true, NULL, TASM31_MARKER "TI01 actual indirect CALL[7078]. Selected targetsF3A9/F50D depend on current state; no unconditional call references fabricated from zero initial storage.");
	if (tasm31_body (accepted, 0x50e2, 16) && profile_near (ctx, 0x5937, 0x50e2, false)) {
		tasm31_note (ctx, accepted, 0x5937, 0x3, true, "tasm31_expression_clear_near_call", TASM31_MARKER "Original E8a8f7 near CALL targets shared clear entry logical0:48e2/FILE50e2, not allocation entry48cc. No runtime execution or allocator success inferred.");
	}
	tasm31_note (ctx, accepted, 0x4e4a, 0x7, true, NULL, TASM31_MARKER "TI04: PUSH AX;CALLF606;POP AX;JNE4670 restores residualAX WITHOUT changing returnedZF. Later diagnostic can still change currentAX;no pure AX-bool prototype applied.");
	tasm31_note (ctx, accepted, 0x4e65, 0x2, true, NULL, TASM31_MARKER "TI01 literal NOP supplier MOV AL,90 within461E..4694;reload every loop. Positive route reaches LOOP even for currentCX0, yielding65536 iterations under stable ordinary state;not unrestricted safe padding length.");
	tasm31_note (ctx, accepted, 0x16aba, 0x18, true, NULL, TASM31_MARKER "R283:execution1615:016A,not0F90:69BA execution claim. FRESH selectedES:[DI+4]→DS43D2;record02/06/08 independently supply current controls. Constructor default0 is not immutable or an observed invocation. DS43D2==1 retains subtype10 at94A4;other current values maskEF.");
	tasm31_note (ctx, accepted, 0x11bee, 0xd, true, NULL, TASM31_MARKER "Qualified entry0F90:1AEE setsCLD and relocatedDS/SS from17B1;initial data projection18310+offset is conditional on this segment. HeaderSS:SP1F32:0400 differs. Native zero-origin resident maps are analysis coordinates,not claims about DOS runtime selectors; later1615 execution-CS is distinct.");
	tasm31_note (ctx, accepted, 0xfd0d, 0x33, true, "tasm31_callback_f50d_prefix", NULL);
	tasm31_note (ctx, accepted, 0x172ab, 72, false, "tasm31_case_sensitivity_help_literal", TASM31_MARKER "Literal same-image help advertises /ml all,/mx globals,/mu none case sensitivity. Frozen source production used /ml /l;source/control observations are annotations only,no tool execution,historical setting or universal token-policy inference.");
	tasm31_note (ctx, accepted, 0x1739d, 76, false, "tasm31_object_code_help_literal", TASM31_MARKER "R283/R287:literal /os,/o,/op,/oi help. One retained unchanged-source /o assembly produced OFF16L at0073 while preserving all180 CODE bytes/all other fields;no captured internal state,whole-OMF equality or historical producer claim. Profile does not configure or execute TASM.");
	if (tasm31_array (ctx, 0x1aa34, "uint16_t", 554, "tasm31_token_dispatch_words554", TASM31_MARKER "R119/TI01: initial DS-relative near dispatch table,554 words. Selected current token minus7618 is range-checked before indirect dispatch; raw entries are not unconditional calls or554 proved complete functions. Initialized-data projection18310+DS is conditional on the startup-selected segment, not every live DS.")) {
		if (tasm31_note (ctx, accepted, 0xd705, 0x28, true, NULL, NULL) && profile_offset (ctx, 0x1aaca, 0xcf05, 0xd705)) {
			tasm31_note (ctx, accepted, 0xd705, 0x28, true, NULL, TASM31_MARKER "R119: selected ordinary ingressCF1C directly calls6C4D then tailsF5DC;CF05..CF2D is a selected partition with external alternatives, not a proven complete encompassing function.");
			profile_label (ctx, profile_mapped (ctx, 0x1aaca, 2, false), "tasm31_call_dispatch_slot");
		}
	}
	tasm31_array (ctx, 0x1b310, "uint8_t", 5, "tasm31_call_pascal_token", TASM31_MARKER "R119:04 CALL, zero-based token75 among554 registered length-prefixed names. Successful token registration/actual parser state required; spelling alone does not prove traversal.");
	static const ut16 descriptors[] = { 0x2b78, 0x2bc8, 0x2c18, 0x2c68, 0x2cb8 };
	bool descriptor8 = tasm31_type_CallbackDescriptor8Partial (ctx->anal);
	bool descriptor4 = tasm31_type_CallbackDescriptor4Partial (ctx->anal);
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (descriptors); i++) {
		bool small = descriptors[i] == 0x2cb8;
		if (small? descriptor4: descriptor8) {
			char name[64];
			snprintf (name, sizeof (name), "tasm31_initial_descriptor_%x", descriptors[i]);
			tasm31_data (ctx, 0x18310 + descriptors[i], small? 4: 8, small? "tasm31_CallbackDescriptor4Partial": "tasm31_CallbackDescriptor8Partial", name, TASM31_MARKER "TI01: selected initial descriptor base; only first row typed. Runtime index bound is NOT inferred from spacing or current7077; current705F bits select base/stride.");
		}
	}
	if (tasm31_type_ReplayContext40Partial (ctx->anal)) {
		tasm31_data (ctx, 0x1f360, 40, "tasm31_ReplayContext40Partial", "tasm31_initial_replay_context_storage", TASM31_MARKER "TI01: qualified initialized-data storage projection18310+offset only; startup DS/SS agree after relocation-backed setup, not all later runtime segments. Dynamic allocated replay records are NOT placed at fixed file addresses.20-word full record excludes7078;48-byte temporary snapshot includes it.");
	}
	if (tasm31_type_CallbackSnapshot48Partial (ctx->anal)) {
		tasm31_data (ctx, 0x1f4c6, 48, "tasm31_CallbackSnapshot48Partial", "tasm31_initial_snapshot_storage", NULL);
	}
	tasm31_array (ctx, 0x1f388, "uint16_t", 1, "tasm31_initial_selected_callback_storage", NULL);
	tasm31_array (ctx, 0x1a20c, "uint8_t", 3, "tasm31_negative_type_map_08_09_01", NULL);
	tasm31_array (ctx, 0x1a21e, "uint16_t", 1, "tasm31_ordinary_far_type_fffe", TASM31_MARKER "R133:fresh ordinary FAR numeric left word0A=FFFE under accepted initialization/class00 and DF0 clear. IDEAL direct left tag29/zero0A is different. PTR may defer29 at25 or set tag29 immediately; finalizer/encoder still consume actual current fields.");
	tasm31_array (ctx, 0x19fc4, "uint8_t", 14, "tasm31_internal_class_method14", TASM31_MARKER "R164/R176/R182:literal method map00x10,01,00,02,02;internal class0A/0C/0D domain. Not serialized record tags or a complete external OMF schema.");
	if (tasm31_array (ctx, 0x17faf, "uint8_t", 78, "tasm31_cs1615_option_dispatch_table", TASM31_MARKER "R283:CS1615 header/default16AD,count25,three-byte rows. This is DATA,not25 complete functions;row13 FILE17FD9 is6F→17D9. Execution-CS1615 qualified by FAR target plusCS-relative table,not linear0F90 coordinate arithmetic.")) {
		if (tasm31_note (ctx, accepted, 0x18129, 0x33, true, NULL, NULL) && profile_offset (ctx, 0x17fda, 0x17d9, 0x18129)) {
			tasm31_note (ctx, accepted, 0x18129, 0x33, true, "tasm31_cs1615_object_control_writer", TASM31_MARKER "R283:1615:17D9 literal suffix p/i/s maps2/3/0 with saved AX across1596;other branch selects1. FILE18152 LES DI,[433A] reloads pointer AFTER helpers,18156 writes selected current record+4. Advertised /os,/o,/op,/oi are standard/standard with overlays/Phar Lap/IBM. Not automatic settings,external format proof or historical compiler classification.");
		}
	}
	static const struct { ut64 source; ut16 source_segment; ut16 source_offset; ut16 target_segment; ut16 target_offset; ut64 target; } pairs[] = {
		{ 0x4dec, 0, 0x45ee, 0xf90, 0x66d2, 0x167d2 },
		{ 0x4e05, 0, 0x4607, 0xf90, 0x66d2, 0x167d2 },
		{ 0x4ee4, 0, 0x46e6, 0xf90, 0x66d2, 0x167d2 },
		{ 0xfe96, 0, 0xf698, 0xf90, 0x074b, 0x1084b },
		{ 0xfeb1, 0, 0xf6b3, 0xf90, 0x074b, 0x1084b },
		{ 0x11ce0, 0xf90, 0x1be2, 0x1615, 0x0c9f, 0x175ef },
	};
	for (i = 0; i < R_ARRAY_SIZE (pairs); i++) {
		tasm31_mz_reference (ctx, accepted, pairs[i].source, pairs[i].source_segment, pairs[i].source_offset, pairs[i].target_segment, pairs[i].target_offset, pairs[i].target);
	}
}

// Finite retained-state analysis contracts, not historical C prototypes or a universal TASM ABI.
static bool tasm31_function(BorlandProfileContext *ctx, size_t index) {
	const ut64 start = tasm31_functions[index].start;
	const ut64 size = tasm31_functions[index].end - start;
	// These preservation contracts require current callee code, not callee metadata acceptance.
	if (start == 0xfe87 || start == 0xfe06) {
		ut8 leaf[0xd];
		if (!profile_current (ctx, 0x1084b, sizeof (leaf), profile_mapped (ctx, 0x1084b, sizeof (leaf), true), leaf)) {
			return false;
		}
	}
	if (start == 0xfe06) {
		ut8 predicate[0x33];
		if (!profile_current (ctx, 0xfe87, sizeof (predicate), profile_mapped (ctx, 0xfe87, sizeof (predicate), true), predicate)) {
			return false;
		}
	}
	RAnalFunctionParam params[4] = {0};
	const char *ret, *cc, *effects;
	int count;
	switch (start) {
	case 0x9461:
		ret = "Tasm31SignExtensionState5";
		cc = "tasm31_sign_extension_state_16near";
		params[0] = (RAnalFunctionParam){ "entry_ax", "uint16_t" };
		params[1] = (RAnalFunctionParam){ "entry_dx", "uint16_t" };
		params[2] = (RAnalFunctionParam){ "entry_ds", "uint16_t" };
		params[3] = (RAnalFunctionParam){ "entry_es", "uint16_t" };
		count = 4;
		effects = TASM31_MARKER "Analysis CF/AX/DX tuple retains path-dependent CBW/CWD and early-return entry values. BX/CX/BP/SI/DI/DS/ES/SS/CS/DF untouched locally; no calls or memory writes. Other arithmetic flags clobbered. Valid selected memory and intact near-return stack required; purge0. CALL7675/JB7678 consumes CF but does not prove AH/DX dead before opaque descendants.";
		break;
	case 0xfe87:
		ret = "Tasm31CurrentState2";
		cc = "tasm31_current_state_16near";
		params[0] = (RAnalFunctionParam){ "entry_al", "uint8_t" };
		params[1] = (RAnalFunctionParam){ "entry_ds", "uint16_t" };
		count = 2;
		effects = TASM31_MARKER "Analysis ZF/AL tuple retains direct-return AL and explicit ALFF paths. AH and other GPR/segment registers plus DF untouched through qualified074B leaf; arithmetic flags otherwise clobbered. Optional leaf writes4598, so no memory-purity claim. FRESH70AF read determines returned ZF; valid memory/intact near/far frames and noninterfering storage required; purge0.";
		break;
	case 0x1084b:
		ret = "void";
		cc = "tasm31_conditional_store_16far";
		params[0] = (RAnalFunctionParam){ "entry_ds", "uint16_t" };
		count = 1;
		effects = TASM31_MARKER "Qualified074B far leaf analysis contract: currentDS selects43C3:80 test and optional4598=1 store; no GPR/segment write apart from ordinary RETF frame restoration. AX/BX/CX/DX/BP/SI/DI/DS/ES/SS/CS/DF retained; far-return delta4, purge0. TEST arithmetic flags clobbered, not a returned predicate; no result or purity claim. Valid selected memory, intact far frame and noninterfering storage required.";
		break;
	case 0xfe06:
		ret = "Tasm31PaddingState5";
		cc = "tasm31_padding_state_16near";
		params[0] = (RAnalFunctionParam){ "entry_ds", "uint16_t" };
		params[1] = (RAnalFunctionParam){ "entry_es", "uint16_t" };
		count = 2;
		effects = TASM31_MARKER "Analysis ZF/currentDS/currentES tuple retains consumed flag and then-current selectors, not preserved selectors. BX/CX/DX restored on work path and untouched through qualified predicate. Unsaved AH/SI/BP/DI/DF/segment effects of six opaque descendants remain unknown; AL/arithmetic flags clobbered, no purity or blanket kill. Caller464A saves AX/464E restores AX without changing ZF; continuation4651 reads currentDS and4661 saves currentES. Ordinary balanced noninterfering stack/normal returns required; purge0.";
		break;
	default:
		return profile_function (ctx, start, size, tasm31_functions[index].name, 0, tasm31_functions[index].comment);
	}
	if (!borland_type (ctx->anal, ret)) {
		return false;
	}
	RList *list = r_list_new ();
	int i;
	for (i = 0; i < count; i++) {
		r_list_append (list, &params[i]);
	}
	RAnalFunctionSignature signature = { .ret_type = (char *)ret, .callconv = (char *)cc, .params = list };
	const BorlandProfileRange range = { start, size };
	bool applied = profile_function_ranges_contract (ctx, &range, 1, tasm31_functions[index].name, 0, tasm31_functions[index].comment, &signature);
	r_list_free (list);
	if (applied) {
		borland_comment (ctx->anal, profile_mapped (ctx, start, size, true), effects);
	}
	return applied;
}

static int borland_tasm31_profile(RAnal *anal) {
	BorlandProfileContext ctx;
	if (borland_eligible (anal) < 0 || !profile_identity (anal, &ctx, "mz", 129266, "80534cd6a1e2c2b4376ae3f21954c6dbfa77a6998d5e0bf8b8bee6153f3174ea")) {
		return 0;
	}
	r_anal_types_prepare (anal);
	tasm31_type_Expression40Partial (anal);
	tasm31_type_SelectedState16Partial (anal);
	tasm31_type_CompactReplayRecord16Partial (anal);
	tasm31_type_FullReplayRecord46Partial (anal);
	tasm31_type_ExtendedReplayHeader50Partial (anal);
	tasm31_type_ClassTaggedRecord32Partial (anal);
	tasm31_type_InternalQueuePayload9 (anal);
	tasm31_type_InputControlRecord18Partial (anal);
	tasm31_type_InternalRecordClass (anal);
	tasm31_type_ReplayRecord05Mask (anal);
	ut64 accepted = 0;
	int count = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tasm31_functions); i++) {
		bool applied = tasm31_function (&ctx, i);
		if (applied) {
			accepted |= 1ULL << i;
			count++;
		}
		R_LOG_INFO ("Borland tasm31-qualified: FILE 0x%08"PFMT64x" %s", tasm31_functions[i].start, applied? "qualified (including unchanged)": "preserved/refused; dependent facts skipped");
	}
	if (profile_function_ranges (&ctx, tasm31_allocation, R_ARRAY_SIZE (tasm31_allocation), "tasm31_allocate_expression_view", 0, TASM31_MARKER "R145 qualified allocation body FILE[50cc,50e2)+[50f2,511a), logical0:[48cc,48e2)+[48f2,491a). THREE-paragraph pool allocation is independent of the40-byte clear/copy. Ordinary fallthrough48de→48e2 reaches the separately called clear entry; final4918 backedge reaches48d3. No exclusive ownership of that shared routine. Nonlocal exhaustion and opaque allocator descendants are not normal returns.")) {
		accepted |= 1ULL << R_ARRAY_SIZE (tasm31_functions);
		count++;
	}
	tasm31_facts (&ctx, accepted);
	return count;
}

#undef TASM31_MARKER
