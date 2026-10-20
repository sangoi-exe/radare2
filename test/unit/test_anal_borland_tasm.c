#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_tasm_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland

static RCore *tasm_original(void) {
	const char *path = getenv ("R2_TEST_TASM31");
	if (!path) {
		return NULL;
	}
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "bin.relocs.apply", true);
	if (!r_core_file_open (core, path, R_PERM_RX, 0) || !r_core_bin_load (core, path, UT64_MAX)) {
		r_core_free (core);
		return NULL;
	}
	r_config_set_b (core->config, "io.va", true);
	return core;
}

static bool tasm_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "mz", 129266, "80534cd6a1e2c2b4376ae3f21954c6dbfa77a6998d5e0bf8b8bee6153f3174ea");
}

static int tasm_reference(RAnal *anal, ut64 from, ut64 to) {
	RVecAnalRef *refs = r_anal_refs_get (anal, from);
	int type = 0;
	RAnalRef *ref;
	if (refs) {
		R_VEC_FOREACH (refs, ref) {
			if (ref->addr == to) {
				type = R_ANAL_REF_TYPE_MASK (ref->type);
			}
		}
	}
	RVecAnalRef_free (refs);
	return type;
}

static bool tasm_comment(RAnal *anal, ut64 physical, const char *text) {
	const char *comment = r_meta_get_string (anal, R_META_TYPE_COMMENT, physical - 0x800);
	return comment && strstr (comment, text);
}

// Independent finite expectations from complete Java profile and validator at ghidra 9ba90c3.
static const struct { ut64 start; ut64 end; const char *name; int instructions; const char *comment; } expected_functions[] = {
	{ 0x744d, 0x748d, "tasm31_encode_call", 22, "R119/TI01: current tag29 and8C90 CF choose ordinary16-bit four-byte0E E8 or five-byte9A. Four-byte branch has NO NOP; later linker90 0E E8 rewrite is distinct. Three terminal tails to36D6; alternative indirect/operand-size descendants remain opaque." },
	{ 0x9490, 0x9501, "tasm31_call_far_predicate_cf", 46, "R119/R145: CF1 retains FAR. Requires current SMART705E:20, zero operand06 and qualified identity. Ordinary branch installs postlookup AX as ES (including0), reads1A BEFORE04, then restores operand ES/CX; not simply7060 equality. IDEAL branch normalizes target first/current second. No numeric AX-bool contract." },
	{ 0x84aa, 0x84e9, "tasm31_emit_near_operand", 0, "R152/TI01: ordinary16-bit branch includes already emitted prefix count in displacement, prepares current operand, emits CL then word.8DF7 CF1 alternate width is separate; opaque helpers are not assumed to preserve arbitrary registers." },
	{ 0x84e9, 0x850a, "tasm31_emit_far_operand", 0, "R119/TI01: ordinary16-bit branch emits CL9A plus low offset/word16; alternative-width branch is not generalized. Terminal tail910F, not inline data." },
	{ 0x48f6, 0x4913, "tasm31_emit_byte", 11, "TI01: writes AL at6F4E+old6F4C, increments word count, ancillary425E conditional. Adjacent4113 literal90 is NOT part of body or NOP-fill owner." },
	{ 0x4914, 0x492f, "tasm31_emit_word", 8, "TI01: current AX write/count+2; tails425E. Adjacent412F excluded." },
	{ 0x4930, 0x494f, "tasm31_emit_word_pair", 9, "TI01: current AX/CX write/count+4; tails425E. No flat pointer prototype." },
	{ 0x8682, 0x8694, "tasm31_prepare_call_operand", 0, "R133: save operand ES to7406, reset emission, explicitly save CX around9698. Materialization effects remain conditional." },
	{ 0x874b, 0x876e, "tasm31_classify_immediate_cf", 0, "R139 corrected complete end includes failure RET7F6D. Tags28/29 accepted CF0; tag20 has additional current mode/word14 tests." },
	{ 0x4db3, 0x4e1e, "tasm31_restore_replay_record", 0, "TI01: record05:10 compact restores selected fields/endpoint; otherwise forward20-word06..2E→7050..7078 requires DF0 and valid DS/SS. Regenerates7078 callback after restore;05:20 invokes near record30 with DI32. Current ES/DS changes are real." },
	{ 0x4ef5, 0x4f15, "tasm31_snapshot_and_dispatch", 0, "TI01: forward24-word7050..7080→71B6..71E6 includes7078 at71DE; indirect CALL[7078]. AFTER callback freshly rereads7056/7058 to overwrite71B6/71B8; no arbitrary callback/global/record-ES preservation." },
	{ 0x4f15, 0x4f93, "tasm31_admit_replay_record", 0, "TI01:47F2 returned CF selects compact/full. One paragraph compact; three paragraphs full with20-word snapshot copy ending before71DE; extension size derives from current707A, stores2E/30 and invokes snapshot71E2 with DI32. Valid finite allocation/DF/aliases remain conditions." },
	{ 0x4f93, 0x4ff2, "tasm31_allocate_link_replay_record", 0, "TI01: paragraph pool71EA/71EC, save record ES around3016, store actual returned AX at02;04 uses current43D7 plus POST3016 CX. LES/XCHG list insertion stores replaced selector at00. Allocator descendants opaque." },
	{ 0x4ff2, 0x5022, "tasm31_compact_replay_predicate_cf", 0, "TI01: rejects extension71E4, missing prior71F2 or14-word current context mismatch; SUB/SBB endpoint difference returns CF, not only numeric low difference. REPE comparison geometry requires DF0/valid storage." },
	{ 0x167d2, 0x1685a, "tasm31_select_replay_callback", 45, "TI01: current705F:10 selects F3A9 versusF50D into7078. Clear branch indexes current7077*8 into selected2BC8/2C68/2B78/2C18; set branch indexes2CB8 by*4. Valid table/state extent conditional; selection is not historical pass attribution." },
	{ 0x5389, 0x53df, "tasm31_finalize_expression", 0, "R139:05 bit10 has priority; save POST5989 word04 across95FB. Bit20-only calls6311 then FRESH word04. After4BED read CURRENT05:40, transfer current25&0F→tag and1C→02. Deferred29 becomes09, not an unconditional FAR encoder request." },
	{ 0x53ed, 0x53fc, "tasm31_materialize_expression", 0, "R139:5F26→9698,600F,6096,4BFC then tail5F2D reloads CURRENT global7406 as ES. Not arbitrary record/global preservation." },
	{ 0x53fc, 0x542c, "tasm31_mask_materialized_tag", 0, "R139:clear tag20,set04:80; conditional04:08 and05 nibble updates. Immediate29 can become09 independently of deferred transfer." },
	{ 0x6189, 0x61eb, "tasm31_save_tag_or_resolve_identity", 0, "R139:tag20 saves00/02→25/1C then clears tag/value and pending fields;4B89 immediately95FB discards this temporary saved tag. Other branch stores actual returned170A CX to18. Descendant effects qualified." },
	{ 0x9dfb, 0x9e0c, "tasm31_clear_deferred_tag", 0, "R133/R139:clear05:40,25,1C only; not pending06 or identity18." },
	{ 0x6b11, 0x6b61, "tasm31_transfer_pending_identity", 0, "R139:copy1E/20→14/16 before tag test; only nonzero22 updates18 and conditionally1A/current subtype/04:04. Does not directly write pending06; not transitive preservation." },
	{ 0x2248, 0x2251, "tasm31_lookup_expression", 0, "R145:1C65 selects state in ES, tail4A75 with DI08; sometimes AX0 while ES remains selected state. No unconditional pointer-return prototype." },
	{ 0x2465, 0x24e7, "tasm31_select_symbol_state", 0, "R145:current43D6/cache0E selects state; strictJA successor choice versus initialJAE, conditional cache write. Valid terminating links/finite arithmetic required; returned ES need not equal AX." },
	{ 0x5275, 0x52c6, "tasm31_reconstruct_selected_expression", 0, "R145:nonzero state08→fresh scalar;else nonzero0A→fresh cached40-byte copy after REREADING0A postallocation;else AX0 leaves ES selected. Qualified normal returns CF0/ZF1, not constant AX or safe null-record. DF0/valid storage/aliases conditional." },
	{ 0x50e2, 0x50f2, "tasm31_clear_expression_view", 6, "R145 shared clear entry: genuine near CALL at logical0:5137/FILE5937 targets48e2/FILE50e2, independently of allocation entry48cc. XORAX/MOVDIAX/MOVCX14h/REPSTOSW clear40 bytes then set byte10=1; DF=0, valid selected ES storage and aliases remain conditions. This clear size is not the THREE-paragraph pool allocation." },
	{ 0x9d0c, 0x9d2e, "tasm31_map_type_word_to_al", 0, "R133:negative branch complements ALL16 AX bits;FFFE→0001→table09. Only AL replaced, AH not zero-extended. OR20 by caller forms29." },
	{ 0x22dc, 0x2302, "tasm31_project_current_handle", 16, "R152:current handle07 bit20 clear returns word0E on ALL masked-class alternatives;bit20 set returns10. Numeric projections, not formal external IDs." },
	{ 0x13cb2, 0x13d65, "tasm31_append_internal_queue9", 0, "R152:normal existing-block route publishes updated06 before nine ordered stores CL,BX,DX,SI,saved DI. New-block route uses POST3F38 returnedAX/DL/DI, internal type06. DF0/valid nonaliased storage and ordinary stack required; alternate3B48/drain/allocators opaque." },
	{ 0x13688, 0x1369b, "tasm31_construct_class0a", 5, "R182:after3E85 set class0A,zero0A,return currentES inAX;08 NOT initialized." },
	{ 0x136dd, 0x136ee, "tasm31_construct_class0c", 5, "R164:after3E85 set class0C,posthelperBP→0A,return currentES inAX;08 NOT initialized." },
	{ 0x136ee, 0x13718, "tasm31_construct_class0d", 10, "R176:class0D;posthelperBP/BX/DX/SI/DI→0A/0C/0E/10/12,CH→14. Fresh selected caller givesCH0, not selector-one observation;08 NOT initialized." },
	{ 0x13f85, 0x13fcd, "tasm31_link_class_record", 0, "R164:two-paragraph request, global linking precedes06/05 stores;clears only1C/1E. Explicit saves restore AX/CX, not blanket zero-fill or arbitrary descendant preservation." },
	{ 0x14bc7, 0x14be5, "tasm31_walk_class_callback_bx", 0, "R164:save CURRENT record02 before class04 comparison and conditional CALL BX;restore saved next plus AX/BX. Valid acyclic list/normal returns required, not reread-next semantics." },
	{ 0x1476f, 0x1479d, "tasm31_publish_class0a_index", 16, "R182:5107 fresh current6F2E return→record08 BEFORE link walk. Current linked0A reread AFTER512F; terminal5142, not arbitrary originalES restoration." },
	{ 0x1479d, 0x147cf, "tasm31_publish_class0d_index", 15, "R176:current14 normalized0/1,read current0C/0E/10/12;524B actual fresh current6F32 return→08. Not class0C payload semantics." },
	{ 0x14803, 0x1482d, "tasm31_publish_class0c_index", 0, "R164:current06/05→5201,restore recordES,actual fresh current6F32 return→08 before optional tail. Counter wrap allowed;no universal first-index-one." },
	{ 0x14b96, 0x14bc7, "tasm31_consume_current_class_index", 0, "R157/R164:current queued handle08 and04 supply numeric method table then5446. Class0A→01,0C/0D→02;not formal LOCAT/FIXDAT or captured historical queue association." },
	{ 0x9461, 0x9490, "tasm31_push_sign_extension_cf", 17, "RF08:call-free;06 zero,04:04 clear,CBW low byte requires AH=current0B. Current705E:04 additionally requires CWD DX=current0C. CF0 admits sign extension, CF1 rejects;not a numeric bool, source-type or actual historical operand trace." },
	{ 0xfe06, 0xfe45, "tasm31_padding_gate_zf", 27, "TI04/R207:consumeF687 ZF;fresh70AB:80/706C tests. Six work descendants274E,F827,2283,F6BA,22A9,23DD opaque;explicit XOR/DEC givesALFF/ZF0,other routeAL0/ZF1,AH not guaranteed. Saves BX/CX/DX on work route,not SI/ES/DS purity." },
	{ 0xfe87, 0xfeba, "tasm31_current_state_predicate_zf", 16, "TI04:after optional074B, F69A FRESH70AF compare defines normal ZF1 exactly when that byte0;later current tests/explicit XOR DEC giveZF0. AL is not constant on direct returns;leaf flags do not define final predicate." },
	{ 0x1084b, 0x10858, "tasm31_conditional_store_leaf", 4, "TI04:call-free43C3:80 test;clear writes4598=1,otherwise none. Does not supply finalF687 flags;validDS/stack and noninterfering storage required." },
	{ 0x4e1e, 0x4e94, "tasm31_conditional_nop_fill", 0, "TI01/R193/R199:SUB/SBB saved endpoint-current position;borrow has separate correction path. Nonborrow lowAX0 returns even ifDX nonzero.43C4 nonzero/43D6:08 clear adjusts record then BYPASSES7064 gate. Other route PUSHAX/CALLF606/POPAX consumes ZF,not AX.7064:08 diagnostic may return and fall through;465F uses THEN-CURRENT AX.4665 reloadsAL90 each iteration,emits into fresh buffer,then36D6. Conditional trailing90 is NOT linker's leading90 rewrite or proof of a historical CALL instance." },
	{ 0x4e94, 0x4eb2, "tasm31_correct_replay_record", 0, "TI01:sets43DC=FF;05:10 chooses SUB record0C,AX else SUB06,AX/SBB08,DX. Does not changeAX/DX;not blanket signed subtraction or shrink-success return." },
};

static const struct { const char *name; int size; int count; HelperMember members[20]; } expected_records[] = {
	{ "Tasm31SignExtensionState5", 5, 3, { { "reject_cf", "bool", 0 }, { "ax", "uint16_t", 1 }, { "dx", "uint16_t", 3 } } },
	{ "Tasm31CurrentState2", 2, 2, { { "zero_zf", "bool", 0 }, { "al", "uint8_t", 1 } } },
	{ "Tasm31PaddingState5", 5, 3, { { "zero_zf", "bool", 0 }, { "ds", "uint16_t", 1 }, { "es", "uint16_t", 3 } } },
	{ "tasm31_Expression40Partial", 40, 20, {
		{ "tag", "uint8_t", 0 },
		{ "subtype", "uint8_t", 1 },
		{ "tag_value", "uint16_t", 2 },
		{ "flags04", "uint8_t", 4 },
		{ "flags05", "uint8_t", 5 },
		{ "pending_selector", "uint16_t", 6 },
		{ "value_low", "uint16_t", 0xa },
		{ "value_high", "uint16_t", 0xc },
		{ "word10", "uint16_t", 0x10 },
		{ "word14", "uint16_t", 0x14 },
		{ "word16", "uint16_t", 0x16 },
		{ "target_identity", "uint16_t", 0x18 },
		{ "selected_identity", "uint16_t", 0x1a },
		{ "deferred_word", "uint16_t", 0x1c },
		{ "pending_word1e", "uint16_t", 0x1e },
		{ "pending_word20", "uint16_t", 0x20 },
		{ "pending_identity", "uint16_t", 0x22 },
		{ "value_extension", "uint8_t", 0x24 },
		{ "deferred_tag", "uint8_t", 0x25 },
		{ "format_handle", "uint16_t", 0x26 },
	} },
	{ "tasm31_SelectedState16Partial", 16, 8, {
		{ "key_low", "uint16_t", 0 },
		{ "key_selector", "uint16_t", 2 },
		{ "successor_selector", "uint16_t", 4 },
		{ "scalar_discriminator", "uint8_t", 8 },
		{ "scalar_extension", "uint8_t", 9 },
		{ "scalar_low_or_cached_selector", "uint16_t", 0xa },
		{ "scalar_high", "uint16_t", 0xc },
		{ "scalar_pending_selector", "uint16_t", 0xe },
	} },
	{ "tasm31_ReplayContext40Partial", 40, 12, {
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
		{ "control7064", "uint16_t", 0x14 },
		{ "descriptor_index7077", "uint8_t", 0x27 },
	} },
	{ "tasm31_CallbackSnapshot48Partial", 48, 5, {
		{ "copied_context", "tasm31_ReplayContext40Partial", 0 },
		{ "selected_near_callback", "uint16_t", 0x28 },
		{ "extension_size", "uint16_t", 0x2a },
		{ "extension_save_callback", "uint16_t", 0x2c },
		{ "extension_restore_callback", "uint16_t", 0x2e },
	} },
	{ "tasm31_CompactReplayRecord16Partial", 16, 8, {
		{ "next_selector", "uint16_t", 0 },
		{ "returned3016_word", "uint16_t", 2 },
		{ "current_control_word", "uint16_t", 4 },
		{ "saved_source7054", "uint16_t", 6 },
		{ "saved_position_low", "uint16_t", 8 },
		{ "saved_position_high", "uint16_t", 0xa },
		{ "extent_word", "uint16_t", 0xc },
		{ "saved_source705a", "uint16_t", 0xe },
	} },
	{ "tasm31_FullReplayRecord46Partial", 46, 4, {
		{ "next_selector", "uint16_t", 0 },
		{ "returned3016_word", "uint16_t", 2 },
		{ "current_control_word", "uint16_t", 4 },
		{ "saved_context", "tasm31_ReplayContext40Partial", 6 },
	} },
	{ "tasm31_ExtendedReplayHeader50Partial", 50, 3, {
		{ "full_record", "tasm31_FullReplayRecord46Partial", 0 },
		{ "extension_size", "uint16_t", 0x2e },
		{ "extension_near_callback", "uint16_t", 0x30 },
	} },
	{ "tasm31_CallbackDescriptor8Partial", 8, 4, {
		{ "token_base_delta", "uint16_t", 0 },
		{ "word7620", "uint16_t", 2 },
		{ "word7622", "uint16_t", 4 },
		{ "word7624", "uint16_t", 6 },
	} },
	{ "tasm31_CallbackDescriptor4Partial", 4, 2, {
		{ "token_base_delta", "uint16_t", 0 },
		{ "word7620", "uint16_t", 2 },
	} },
	{ "tasm31_ClassTaggedRecord32Partial", 32, 14, {
		{ "previous_selector", "uint16_t", 0 },
		{ "next_selector", "uint16_t", 2 },
		{ "record_class", "uint8_t", 4 },
		{ "count_byte", "uint8_t", 5 },
		{ "source_handle", "uint16_t", 6 },
		{ "published_index", "uint16_t", 8 },
		{ "link_or_class_word", "uint16_t", 0xa },
		{ "class0d_word0c", "uint16_t", 0xc },
		{ "class0d_word0e", "uint16_t", 0xe },
		{ "class0d_word10", "uint16_t", 0x10 },
		{ "class0d_word12", "uint16_t", 0x12 },
		{ "class0d_selector", "uint8_t", 0x14 },
		{ "pending_block1c", "uint16_t", 0x1c },
		{ "pending_block1e", "uint16_t", 0x1e },
	} },
	{ "tasm31_InternalQueuePayload9", 9, 5, {
		{ "internal_class", "uint8_t", 0 },
		{ "location_low", "uint16_t", 1 },
		{ "location_high", "uint16_t", 3 },
		{ "first_projection", "uint16_t", 5 },
		{ "second_projection", "uint16_t", 7 },
	} },
	{ "tasm31_InputControlRecord18Partial", 18, 9, {
		{ "word0", "uint16_t", 0x0 },
		{ "word2", "uint16_t", 0x2 },
		{ "word4", "uint16_t", 0x4 },
		{ "word6", "uint16_t", 0x6 },
		{ "word8", "uint16_t", 0x8 },
		{ "worda", "uint16_t", 0xa },
		{ "wordc", "uint16_t", 0xc },
		{ "worde", "uint16_t", 0xe },
		{ "word10", "uint16_t", 0x10 },
	} },
};

static const struct { ut64 physical; int size; const char *type; } expected_data[] = {
	{ 0x1aa34, 1108, "uint16_t [554]" },
	{ 0x1b310, 5, "uint8_t [5]" },
	{ 0x1ae88, 8, "tasm31_CallbackDescriptor8Partial" },
	{ 0x1aed8, 8, "tasm31_CallbackDescriptor8Partial" },
	{ 0x1af28, 8, "tasm31_CallbackDescriptor8Partial" },
	{ 0x1af78, 8, "tasm31_CallbackDescriptor8Partial" },
	{ 0x1afc8, 4, "tasm31_CallbackDescriptor4Partial" },
	{ 0x1f360, 40, "tasm31_ReplayContext40Partial" },
	{ 0x1f4c6, 48, "tasm31_CallbackSnapshot48Partial" },
	{ 0x1f388, 2, "uint16_t [1]" },
	{ 0x1a20c, 3, "uint8_t [3]" },
	{ 0x1a21e, 2, "uint16_t [1]" },
	{ 0x19fc4, 14, "uint8_t [14]" },
	{ 0x17faf, 78, "uint8_t [78]" },
};

static const struct { ut64 physical; const char *name; } expected_labels[] = {
	{ 0x1aa34, "tasm31_token_dispatch_words554" },
	{ 0x1aaca, "tasm31_call_dispatch_slot" },
	{ 0x1b310, "tasm31_call_pascal_token" },
	{ 0xfba9, "tasm31_callback_f3a9_prefix" },
	{ 0xfd0d, "tasm31_callback_f50d_prefix" },
	{ 0x1ae88, "tasm31_initial_descriptor_2b78" },
	{ 0x1aed8, "tasm31_initial_descriptor_2bc8" },
	{ 0x1af28, "tasm31_initial_descriptor_2c18" },
	{ 0x1af78, "tasm31_initial_descriptor_2c68" },
	{ 0x1afc8, "tasm31_initial_descriptor_2cb8" },
	{ 0x1f360, "tasm31_initial_replay_context_storage" },
	{ 0x1f4c6, "tasm31_initial_snapshot_storage" },
	{ 0x1f388, "tasm31_initial_selected_callback_storage" },
	{ 0x5937, "tasm31_expression_clear_near_call" },
	{ 0x1a20c, "tasm31_negative_type_map_08_09_01" },
	{ 0x1a21e, "tasm31_ordinary_far_type_fffe" },
	{ 0x19fc4, "tasm31_internal_class_method14" },
	{ 0x17faf, "tasm31_cs1615_option_dispatch_table" },
	{ 0x18129, "tasm31_cs1615_object_control_writer" },
	{ 0x172ab, "tasm31_case_sensitivity_help_literal" },
	{ 0x1739d, "tasm31_object_code_help_literal" },
};

static const struct { ut64 physical; const char *text; } expected_comments[] = {
	{ 0x1aa34, "R119/TI01: initial DS-relative near dispatch table,554 words. Selected current token minus7618 is range-checked before indirect dispatch; raw entries are not unconditional calls or554 proved complete functions. Initialized-data projection18310+DS is conditional on the startup-selected segment, not every live DS." },
	{ 0xd705, "R119: selected ordinary ingressCF1C directly calls6C4D then tailsF5DC;CF05..CF2D is a selected partition with external alternatives, not a proven complete encompassing function." },
	{ 0x1b310, "R119:04 CALL, zero-based token75 among554 registered length-prefixed names. Successful token registration/actual parser state required; spelling alone does not prove traversal." },
	{ 0xfba9, "TI01: selected callback/dispatch partition, not a proved complete single function. F419..F431 token range check/indirect dispatch; descendants opaque. F50D has corresponding F535..F540 branch." },
	{ 0x1ae88, "TI01: selected initial descriptor base; only first row typed. Runtime index bound is NOT inferred from spacing or current7077; current705F bits select base/stride." },
	{ 0x1aed8, "TI01: selected initial descriptor base; only first row typed. Runtime index bound is NOT inferred from spacing or current7077; current705F bits select base/stride." },
	{ 0x1af28, "TI01: selected initial descriptor base; only first row typed. Runtime index bound is NOT inferred from spacing or current7077; current705F bits select base/stride." },
	{ 0x1af78, "TI01: selected initial descriptor base; only first row typed. Runtime index bound is NOT inferred from spacing or current7077; current705F bits select base/stride." },
	{ 0x1afc8, "TI01: selected initial descriptor base; only first row typed. Runtime index bound is NOT inferred from spacing or current7077; current705F bits select base/stride." },
	{ 0x1f360, "TI01: qualified initialized-data storage projection18310+offset only; startup DS/SS agree after relocation-backed setup, not all later runtime segments. Dynamic allocated replay records are NOT placed at fixed file addresses.20-word full record excludes7078;48-byte temporary snapshot includes it." },
	{ 0x4f04, "TI01 actual indirect CALL[7078]. Selected targetsF3A9/F50D depend on current state; no unconditional call references fabricated from zero initial storage." },
	{ 0x5937, "Original E8a8f7 near CALL targets shared clear entry logical0:48e2/FILE50e2, not allocation entry48cc. No runtime execution or allocator success inferred." },
	{ 0x1a21e, "R133:fresh ordinary FAR numeric left word0A=FFFE under accepted initialization/class00 and DF0 clear. IDEAL direct left tag29/zero0A is different. PTR may defer29 at25 or set tag29 immediately; finalizer/encoder still consume actual current fields." },
	{ 0x19fc4, "R164/R176/R182:literal method map00x10,01,00,02,02;internal class0A/0C/0D domain. Not serialized record tags or a complete external OMF schema." },
	{ 0x4e4a, "TI04: PUSH AX;CALLF606;POP AX;JNE4670 restores residualAX WITHOUT changing returnedZF. Later diagnostic can still change currentAX;no pure AX-bool prototype applied." },
	{ 0x4e65, "TI01 literal NOP supplier MOV AL,90 within461E..4694;reload every loop. Positive route reaches LOOP even for currentCX0, yielding65536 iterations under stable ordinary state;not unrestricted safe padding length." },
	{ 0x17faf, "R283:CS1615 header/default16AD,count25,three-byte rows. This is DATA,not25 complete functions;row13 FILE17FD9 is6F→17D9. Execution-CS1615 qualified by FAR target plusCS-relative table,not linear0F90 coordinate arithmetic." },
	{ 0x18129, "R283:1615:17D9 literal suffix p/i/s maps2/3/0 with saved AX across1596;other branch selects1. FILE18152 LES DI,[433A] reloads pointer AFTER helpers,18156 writes selected current record+4. Advertised /os,/o,/op,/oi are standard/standard with overlays/Phar Lap/IBM. Not automatic settings,external format proof or historical compiler classification." },
	{ 0x16aba, "R283:execution1615:016A,not0F90:69BA execution claim. FRESH selectedES:[DI+4]→DS43D2;record02/06/08 independently supply current controls. Constructor default0 is not immutable or an observed invocation. DS43D2==1 retains subtype10 at94A4;other current values maskEF." },
	{ 0x172ab, "Literal same-image help advertises /ml all,/mx globals,/mu none case sensitivity. Frozen source production used /ml /l;source/control observations are annotations only,no tool execution,historical setting or universal token-policy inference." },
	{ 0x1739d, "R283/R287:literal /os,/o,/op,/oi help. One retained unchanged-source /o assembly produced OFF16L at0073 while preserving all180 CODE bytes/all other fields;no captured internal state,whole-OMF equality or historical producer claim. Profile does not configure or execute TASM." },
	{ 0x11bee, "Qualified entry0F90:1AEE setsCLD and relocatedDS/SS from17B1;initial data projection18310+offset is conditional on this segment. HeaderSS:SP1F32:0400 differs. Native zero-origin resident maps are analysis coordinates,not claims about DOS runtime selectors; later1615 execution-CS is distinct." },
};

static const struct { ut64 source; ut64 target; } expected_relations[] = {
	{ 0x1aaca, 0xd705 }, { 0x17fda, 0x18129 },
	{ 0x4dec, 0x167d2 }, { 0x4e05, 0x167d2 }, { 0x4ee4, 0x167d2 },
	{ 0xfe96, 0x1084b }, { 0xfeb1, 0x1084b }, { 0x11ce0, 0x175ef },
};
static const struct {
	ut64 start;
	const char *ret;
	const char *cc;
	int count;
	HelperParam params[4];
} expected_contracts[] = {
	{ 0x9461, "Tasm31SignExtensionState5", "tasm31_sign_extension_state_16near", 4, { { "entry_ax", "uint16_t" }, { "entry_dx", "uint16_t" }, { "entry_ds", "uint16_t" }, { "entry_es", "uint16_t" } } },
	{ 0xfe87, "Tasm31CurrentState2", "tasm31_current_state_16near", 2, { { "entry_al", "uint8_t" }, { "entry_ds", "uint16_t" } } },
	{ 0xfe06, "Tasm31PaddingState5", "tasm31_padding_state_16near", 2, { { "entry_ds", "uint16_t" }, { "entry_es", "uint16_t" } } },
	{ 0x1084b, "void", "tasm31_conditional_store_16far", 1, { { "entry_ds", "uint16_t" } } },
};

static bool tasm_check_function(RCore *core, ut64 start, ut64 end, const char *name, int instructions) {
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, start - 0x800);
	mu_assert_notnull (fcn, "each source-established complete function");
	mu_assert_streq (fcn->name, name, "qualified descriptive function name");
	mu_assert_eq (fcn->bits, 16, "native x86-16 body");
	mu_assert_eq (fcn->meta.stack_pop, 0, "source-established zero argument cleanup, not a flat signature");
	mu_assert_eq (r_anal_function_realsize (fcn), end - start, "complete exclusive extent");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	size_t contract;
	for (contract = 0; contract < R_ARRAY_SIZE (expected_contracts); contract++) {
		if (expected_contracts[contract].start == start) {
			break;
		}
	}
	if (contract == R_ARRAY_SIZE (expected_contracts)) {
		mu_assert_true (!signature || (!signature->ret_type && r_list_empty (signature->params)), "no unqualified C return or parameter ABI");
	} else {
		mu_assert_notnull (signature, "qualified retained-state analysis signature");
		mu_assert_notnull (signature->ret_type, "qualified signature must contain its explicit return type");
		mu_assert_streq (signature->ret_type, expected_contracts[contract].ret, "finite flag/current-register tuple");
		mu_assert_streq (signature->callconv, expected_contracts[contract].cc, "named native convention, not generic group conversion");
		mu_assert_streq (fcn->callconv, expected_contracts[contract].cc, "function convention propagated");
		mu_assert_eq (r_list_length (signature->params), expected_contracts[contract].count, "explicit qualified inputs only");
		mu_assert_false (signature->noreturn, "normal qualified return");
		int param;
		for (param = 0; param < expected_contracts[contract].count; param++) {
			RAnalFunctionParam *value = r_list_get_n (signature->params, param);
			mu_assert_streq (value->name, expected_contracts[contract].params[param].name, "entry-state input name");
			mu_assert_streq (value->type, expected_contracts[contract].params[param].type, "native register-width input");
		}
	}
	r_anal_function_signature_free (signature);
	ut64 cursor = start - 0x800;
	int count = 0;
	while (cursor < end - 0x800) {
		RAnalBlock *bb = r_anal_function_bbget_in (core->anal, fcn, cursor);
		mu_assert_notnull (bb, "every original instruction belongs to its selected native body");
		mu_assert_true (bb->addr >= start - 0x800 && bb->addr + bb->size <= end - 0x800, "no overwide block");
		RAnalOp *op = r_core_anal_op (core, cursor, R_ARCH_OP_MASK_BASIC);
		mu_assert_notnull (op, "actual native original instruction");
		mu_assert_true (op->size > 0 && cursor + op->size <= end - 0x800, "complete terminal instruction");
		cursor += op->size;
		r_anal_op_free (op);
		count++;
	}
	mu_assert_true (!instructions || count == instructions, "original validator instruction count");
	mu_assert_eq (cursor, end - 0x800, "terminal-inclusive instruction partition");
	return true;
}

static bool tasm_check_complete_facts(RCore *core, BorlandProfileContext *ctx) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (expected_functions); i++) {
		mu_assert_true (tasm_check_function (core, expected_functions[i].start, expected_functions[i].end, expected_functions[i].name, expected_functions[i].instructions), "all43 contiguous source functions");
		mu_assert_true (tasm_comment (core->anal, expected_functions[i].start, expected_functions[i].comment), "every complete qualification retained");
	}
	RAnalFunction *allocation = r_anal_get_function_at (core->anal, 0x48cc);
	RAnalFunction *clear = r_anal_get_function_at (core->anal, 0x48e2);
	mu_assert_notnull (allocation, "separate discontiguous allocation entry");
	mu_assert_streq (allocation->name, "tasm31_allocate_expression_view", "allocation descriptive identity");
	mu_assert_eq (allocation->meta.stack_pop, 0, "allocation cleanup remains zero");
	mu_assert_eq (r_anal_function_realsize (allocation), 62, "allocation excludes all16 shared-clear bytes");
	mu_assert_true (tasm_comment (core->anal, 0x50cc, "THREE-paragraph pool allocation is independent of the40-byte clear/copy"), "allocation is not a40-byte request");
	RListIter *iter;
	RAnalBlock *bb;
	int allocation_instructions = 0;
	r_list_foreach (allocation->bbs, iter, bb) {
		mu_assert_true ((bb->addr >= 0x48cc && bb->addr + bb->size <= 0x48e2) || (bb->addr >= 0x48f2 && bb->addr + bb->size <= 0x491a), "exact two native ranges, not bounding extent");
		allocation_instructions += bb->ninstr;
	}
	mu_assert_eq (allocation_instructions, 19, "allocation original instruction count");
	mu_assert_eq (r_anal_function_realsize (clear), 16, "independent shared-clear extent");
	bb = r_anal_function_bbget_in (core->anal, allocation, 0x48de);
	mu_assert_notnull (bb, "allocation fallthrough block");
	mu_assert_eq (bb->jump, 0x48e2, "native single successor is the actual fallthrough to separately owned clear entry");
	bb = r_anal_function_bbget_in (core->anal, allocation, 0x4918);
	mu_assert_notnull (bb, "allocation final backedge block");
	mu_assert_eq (bb->jump, 0x48d3, "actual final backedge");
	RAnalOp *op = r_core_anal_op (core, 0x5137, R_ARCH_OP_MASK_BASIC);
	mu_assert_notnull (op, "real independent shared-clear call instruction");
	mu_assert_eq (op->size, 3, "near call length");
	mu_assert_eq (op->type & R_ANAL_OP_TYPE_MASK, R_ANAL_OP_TYPE_CALL, "real near CALL");
	mu_assert_eq (op->jump, 0x48e2, "shared clear, not allocation entry");
	mu_assert_eq (tasm_reference (core->anal, 0x5137, 0x48e2), R_ANAL_REF_TYPE_CALL, "real independent near CALL reference");
	r_anal_op_free (op);
	for (i = 0; i < R_ARRAY_SIZE (expected_records); i++) {
		RAnalBaseType *type = r_anal_get_base_type (core->anal, expected_records[i].name);
		mu_assert_notnull (type, "all12 native descriptive partial layouts");
		mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_STRUCT, "native record kind");
		mu_assert_eq (type->size, expected_records[i].size * 8, "full partial view size includes undefined gaps");
		mu_assert_eq (RVecAnalTypeMember_length (&type->struct_data.members), expected_records[i].count, "only source-established fields");
		int field;
		for (field = 0; field < expected_records[i].count; field++) {
			RAnalTypeMember *member = RVecAnalTypeMember_at (&type->struct_data.members, field);
			const HelperMember *expected = &expected_records[i].members[field];
			mu_assert_streq (member->name, expected->name, "every established descriptive field name");
			mu_assert_streq (member->type, expected->type, "every established scalar or nested view");
			mu_assert_eq (member->offset, expected->offset, "every native field offset");
			mu_assert_eq (member->count, 0, "undefined bytes are not invented arrays");
			mu_assert_eq (member->bitsize, 0, "independent masks are not invented bitfields");
		}
		r_anal_base_type_free (type);
	}
	const struct { const char *name; int count; BorlandEnumCase cases[3]; } enums[] = {
		{ "tasm31_InternalRecordClass", 3, { { "linked_index_class0a", 0xa }, { "counted_class0c", 0xc }, { "payload_class0d", 0xd } } },
		{ "tasm31_ReplayRecord05Mask", 2, { { "compact_interpretation", 0x10 }, { "extension_callback", 0x20 } } }
	};
	for (i = 0; i < R_ARRAY_SIZE (enums); i++) {
		RAnalBaseType *type = r_anal_get_base_type (core->anal, enums[i].name);
		mu_assert_notnull (type, "both established native enums");
		mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_ENUM, "native enum kind");
		mu_assert_eq (type->size, 8, "one-byte numeric/mask domains");
		mu_assert_eq (RVecAnalEnumCase_length (&type->enum_data.cases), enums[i].count, "only established cases");
		int field;
		for (field = 0; field < enums[i].count; field++) {
			RAnalEnumCase *entry = RVecAnalEnumCase_at (&type->enum_data.cases, field);
			mu_assert_streq (entry->name, enums[i].cases[field].name, "each enum name");
			mu_assert_eq (entry->val, enums[i].cases[field].value, "each enum value");
		}
		r_anal_base_type_free (type);
	}
	for (i = 0; i < R_ARRAY_SIZE (expected_data); i++) {
		char key[48];
		ut64 address = expected_data[i].physical - 0x800;
		snprintf (key, sizeof (key), "link.%08"PFMT64x, address);
		mu_assert_streq (sdb_const_get (core->anal->sdb_types, key, NULL), expected_data[i].type, "all14 native data/structured array links");
		mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, expected_data[i].type), expected_data[i].size * 8, "complete data extent");
		RList *blocks = r_anal_get_blocks_intersect (core->anal, address, expected_data[i].size);
		mu_assert_true (r_list_empty (blocks), "table/raw data has no profile instruction ownership");
		r_list_free (blocks);
	}
	for (i = 0; i < R_ARRAY_SIZE (expected_labels); i++) {
		RFlagItem *flag = r_flag_get (core->flags, expected_labels[i].name);
		mu_assert_notnull (flag, "every explicit source label");
		mu_assert_eq (flag->addr, expected_labels[i].physical - 0x800, "canonical MZ resident coordinate");
	}
	for (i = 0; i < R_ARRAY_SIZE (expected_comments); i++) {
		mu_assert_true (tasm_comment (core->anal, expected_comments[i].physical, expected_comments[i].text), "every qualified partial, data, literal and control annotation");
	}
	for (i = 0; i < R_ARRAY_SIZE (expected_relations); i++) {
		ut64 from = expected_relations[i].source - 0x800, to = expected_relations[i].target - 0x800;
		mu_assert_eq (tasm_reference (core->anal, from, to), R_ANAL_REF_TYPE_DATA, "all eight qualified static DATA relationships, not unconditional indirect CALLs");
		if (i >= 2) {
			int matches = 0;
			RBinReloc *reloc;
			R_VEC_FOREACH (ctx->file->bo->relocs, reloc) {
				if (reloc->paddr == expected_relations[i].source + 2) {
					mu_assert_eq (reloc->vaddr, from + 2, "actual native MZ segment-field address");
					mu_assert_eq (reloc->type, R_BIN_RELOC_16, "native unchanged paragraph WORD record");
					matches++;
				}
			}
			mu_assert_eq (matches, 1, "one native relocation owns each selected FAR segment field");
			mu_assert_true (tasm_comment (core->anal, expected_relations[i].source, "Native zero-origin DATA relationship"), "native rather than Java relocation semantics");
		}
	}
	mu_assert_eq (tasm_reference (core->anal, 0x4704, 0xf3a9), 0, "mutable indirect callback does not acquire an unconditional target");
	mu_assert_eq (tasm_reference (core->anal, 0x4704, 0xf50d), 0, "other callback remains conditional");
	const ut64 partial[] = { 0xfba9, 0xfd0d, 0xd705, 0x17faf, 0x18129, 0x4913 };
	for (i = 0; i < R_ARRAY_SIZE (partial); i++) {
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, partial[i] - 0x800);
		mu_assert_true (!fcn || !r_str_startswith (fcn->name, "tasm31_"), "unproved prefixes/literals never become profile-authored complete functions");
	}
	const struct { ut64 physical; const char *hex; } bytes[] = {
		{ 0x1b310, "0443414c4c" }, { 0x1aaca, "05cf" }, { 0x1a20c, "080901" }, { 0x1a21e, "feff" },
		{ 0x19fc4, "0000000000000000000001000202" }, { 0x17fd9, "6fd917" }, { 0x4e65, "b090" },
		{ 0x4e4a, "50e8b8af5875" }, { 0x5937, "e8a8f7" }, { 0x50cc, "833e1c7400" }, { 0x50d7, "b80300" },
		{ 0x50e2, "33c08bf8b91400f3ab26c606100001c3" }
	};
	for (i = 0; i < R_ARRAY_SIZE (bytes); i++) {
		ut8 expected[16], actual[16];
		int length = r_hex_str2bin (bytes[i].hex, expected);
		mu_assert_eq (r_buf_read_at (ctx->file->buf, bytes[i].physical, actual, length), length, "actual source-byte witness read");
		mu_assert_eq (memcmp (expected, actual, length), 0, "independent original-byte validator witness");
	}
	return true;
}

static bool test_tasm_complete_owner(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		eprintf ("TASM exact-original proof not run: set R2_TEST_TASM31 to the read-only exact original; no synthetic input establishes the source facts\n");
		mu_end;
	}
	RCore *core = tasm_original ();
	mu_assert_notnull (core, "normal native MZ load of named original");
	BorlandProfileContext ctx;
	mu_assert_true (tasm_context (core, &ctx), "actual format, read-only descriptor, original size/SHA identity");
	size_t size;
	char *named = r_file_slurp (getenv ("R2_TEST_TASM31"), &size);
	mu_assert_notnull (named, "read named original without execution");
	ut8 *original = malloc (size);
	mu_assert_notnull (original, "complete original comparison buffer");
	mu_assert_eq (r_buf_size (ctx.file->buf), size, "original native file size");
	mu_assert_eq (r_buf_read_at (ctx.file->buf, 0, original, size), size, "complete original native read");
	mu_assert_eq (memcmp (named, original, size), 0, "native original buffer literally equals named input");
	free (original);
	free (named);
	mu_assert_null (r_anal_get_function_at (core->anal, 0x6c4d), "no direct prepopulation");
	mu_assert_eq (borland_tasm31_profile (core->anal), 44, "direct production fact owner, distinct from registered-path tests");
	mu_assert_true (tasm_check_complete_facts (core, &ctx), "complete finite production-owner facts");
	int functions = r_list_length (core->anal->fcns), labels = r_flag_count (core->flags, NULL);
	ut64 references = r_anal_xrefs_count (core->anal);
	char *types = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
	char *comment = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x461e));
	mu_assert_eq (borland_tasm31_profile (core->anal), 44, "equivalent full owner reapply");
	mu_assert_eq (r_list_length (core->anal->fcns), functions, "no duplicated functions");
	mu_assert_eq (r_flag_count (core->flags, NULL), labels, "no duplicated labels");
	mu_assert_eq (r_anal_xrefs_count (core->anal), references, "no duplicated references");
	char *after_types = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
	mu_assert_streq (after_types, types, "stable complete native type/link database");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x461e), comment, "no duplicate qualification comments");
	free (types);
	free (after_types);
	free (comment);
	r_core_free (core);
	mu_end;
}

static bool test_tasm_function_preservation(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 8; scenario++) {
		RCore *core = tasm_original ();
		mu_assert_notnull (core, "original for independent function boundary");
		mu_assert_eq (borland_tasm31_profile (core->anal), 44, "initial fact owner");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x461e);
		mu_assert_notnull (fcn, "real padding function");
		RAnalBlock *bb = r_list_first (fcn->bbs);
		switch (scenario) {
		case 0: r_anal_function_rename (fcn, "user_owned_tasm_padding"); break;
		case 1: bb->size--; break;
		case 2: fcn->meta.stack_pop = 12; break;
		case 3: bb->jump = 0x461f; break;
		case 4: {
			RAnalFunctionSignature signature = { .ret_type = "uint32_t", .params = r_list_new () };
			mu_assert_true (r_anal_function_set_signature (core->anal, fcn, &signature), "independent native return contract");
			r_list_free (signature.params);
			break;
		}
		case 5: r_anal_hint_set_type (core->anal, 0x4665, R_ANAL_OP_TYPE_CALL); break;
		case 6: {
			ut8 patch = 0x91;
			mu_assert_eq (core->anal->iob.overlay_write_at (core->io, 0x4666, &patch, 1), 1, "disposable current literal patch");
			break;
		}
		case 7: r_meta_set (core->anal, R_META_TYPE_DATA, 0x4665, 2, "manual inline data"); break;
		}
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x461e, "manual function comment");
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x464a, "manual flags annotation");
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x4665, "manual literal annotation");
		ut64 size = bb->size, jump = bb->jump;
		int pop = fcn->meta.stack_pop;
		char *name = strdup (fcn->name);
		mu_assert_eq (borland_tasm31_profile (core->anal), 43, "only incompatible body refuses");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x461e), fcn, "native independent function identity retained");
		mu_assert_streq (fcn->name, name, "manual function name retained");
		mu_assert_eq (bb->size, size, "manual body retained");
		mu_assert_eq (bb->jump, jump, "manual flow retained");
		mu_assert_eq (fcn->meta.stack_pop, pop, "manual cleanup retained");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x461e), "manual function comment", "preserved body stops dependent function annotation");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x464a), "manual flags annotation", "preserved body stops dependent returned-flag annotation");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x4665), "manual literal annotation", "preserved body stops dependent inline literal annotation");
		if (scenario == 4) {
			RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
			mu_assert_streq (signature->ret_type, "uint32_t", "user return contract retained");
			r_anal_function_signature_free (signature);
		} else if (scenario == 5) {
			RAnalHint *hint = r_anal_hint_get (core->anal, 0x4665);
			mu_assert_notnull (hint, "independent hint retained");
			mu_assert_eq (hint->type, R_ANAL_OP_TYPE_CALL, "independent semantic override retained");
			r_anal_hint_free (hint);
		} else if (scenario == 6) {
			ut8 current;
			mu_assert_true (r_io_read_at (core->io, 0x4666, &current, 1), "patched current byte");
			mu_assert_eq (current, 0x91, "literal byte edit retained");
		} else if (scenario == 7) {
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_DATA, 0x4665), "manual inline data", "independent inline data retained");
		}
		free (name);
		r_core_free (core);
	}
	mu_end;
}

static bool test_tasm_data_reference_preservation(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 8; scenario++) {
		RCore *core = tasm_original ();
		mu_assert_notnull (core, "original for actual data/reference boundary");
		r_anal_types_prepare (core->anal);
		const ut64 table = 0x177af, source = 0x177da, target = 0x17929;
		switch (scenario) {
		case 0: mu_assert_true (r_anal_types_set_link (core->anal, "uint16_t [39]", table), "independent array type link"); break;
		case 1: r_meta_set (core->anal, R_META_TYPE_DATA, table + 2, 3, "manual data"); break;
		case 2: mu_assert_true (r_anal_xrefs_set (core->anal, source, target, R_ANAL_REF_TYPE_CODE), "independent same-pair reference type"); break;
		case 3: {
			ut8 original;
			mu_assert_true (r_io_read_at (core->io, table + 77, &original, 1), "actual current table tail");
			ut8 patch = original ^ 1;
			mu_assert_eq (core->anal->iob.overlay_write_at (core->io, table + 77, &patch, 1), 1, "current table tail patch");
			break;
		}
		case 4: r_anal_hint_set_size (core->anal, table + 77, 2); break;
		case 5: {
			ut8 patch = 0x90;
			mu_assert_eq (core->anal->iob.overlay_write_at (core->io, target + 1, &patch, 1), 1, "partial writer current-byte patch");
			break;
		}
		case 6: r_anal_hint_set_bits (core->anal, target + 1, 32); r_anal_hint_set_bits (core->anal, target + 2, 16); break;
		case 7: mu_assert_notnull (r_flag_set (core->flags, "tasm31_cs1615_option_dispatch_table", table + 1, 1), "independent qualified-label name at another address"); break;
		}
		mu_assert_eq (borland_tasm31_profile (core->anal), 44, "independent data/reference refusal does not discard unrelated bodies");
		if (scenario != 2) {
			mu_assert_eq (tasm_reference (core->anal, source, target), 0, "preserved data/current target stops dependent DATA join");
		} else {
			mu_assert_eq (tasm_reference (core->anal, source, target), R_ANAL_REF_TYPE_CODE, "manual reference type remains independent");
		}
		mu_assert_null (r_flag_get (core->flags, "tasm31_cs1615_object_control_writer"), "preserved prerequisite stops writer label");
		mu_assert_false (tasm_comment (core->anal, 0x18129, "R283:"), "preserved prerequisite stops writer annotation");
		if (scenario < 2 || scenario == 3 || scenario == 4) {
			mu_assert_null (r_flag_get (core->flags, "tasm31_cs1615_option_dispatch_table"), "refused table does not add a dependent label");
		}
		if (!scenario) {
			mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.000177af", NULL), "uint16_t [39]", "manual table type link retained");
		} else if (scenario == 1) {
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_DATA, table + 2), "manual data", "manual table data retained");
		} else if (scenario == 7) {
			mu_assert_eq (r_flag_get (core->flags, "tasm31_cs1615_option_dispatch_table")->addr, table + 1, "manual label location retained");
		}
		r_core_free (core);
	}
	mu_end;
}

static bool test_tasm_type_dependencies(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	RCore *core = tasm_original ();
	mu_assert_notnull (core, "original for nested type preservation");
	r_anal_types_prepare (core->anal);
	const HelperMember independent[] = { { "user_owned_field", "uint8_t", 0 } };
	mu_assert_true (borland_record (core->anal, "tasm31_ReplayContext40Partial", 320, independent, 1), "independent same-name partial layout");
	const BorlandEnumCase independent_case[] = { { "user_owned_mask", 1 } };
	mu_assert_true (borland_enum (core->anal, "tasm31_ReplayRecord05Mask", 8, independent_case, 1), "independent enum domain");
	mu_assert_eq (borland_tasm31_profile (core->anal), 44, "type refusal is independent of established code functions");
	RAnalBaseType *type = r_anal_get_base_type (core->anal, "tasm31_ReplayContext40Partial");
	mu_assert_eq (RVecAnalTypeMember_length (&type->struct_data.members), 1, "manual type fields retained");
	mu_assert_streq (RVecAnalTypeMember_at (&type->struct_data.members, 0)->name, "user_owned_field", "manual type role retained");
	r_anal_base_type_free (type);
	type = r_anal_get_base_type (core->anal, "tasm31_ReplayRecord05Mask");
	mu_assert_eq (RVecAnalEnumCase_length (&type->enum_data.cases), 1, "manual enum retained");
	mu_assert_streq (RVecAnalEnumCase_at (&type->enum_data.cases, 0)->name, "user_owned_mask", "manual enum meaning retained");
	r_anal_base_type_free (type);
	mu_assert_null (r_anal_get_base_type (core->anal, "tasm31_CallbackSnapshot48Partial"), "incompatible context stops dependent snapshot type");
	mu_assert_null (r_anal_get_base_type (core->anal, "tasm31_FullReplayRecord46Partial"), "incompatible context stops dependent full record");
	mu_assert_null (r_anal_get_base_type (core->anal, "tasm31_ExtendedReplayHeader50Partial"), "incompatible full record stops dependent extended header");
	mu_assert_null (r_flag_get (core->flags, "tasm31_initial_replay_context_storage"), "type refusal stops dependent context instance");
	mu_assert_null (r_flag_get (core->flags, "tasm31_initial_snapshot_storage"), "type refusal stops dependent snapshot instance");
	mu_assert_null (sdb_const_get (core->anal->sdb_types, "link.0001eb60", NULL), "type refusal adds no context object link");
	mu_assert_null (sdb_const_get (core->anal->sdb_types, "link.0001ecc6", NULL), "type refusal adds no snapshot object link");
	r_core_free (core);
	mu_end;
}

static bool test_tasm_far_preservation(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 5; scenario++) {
		RCore *core = tasm_original ();
		mu_assert_notnull (core, "original for native FAR relationship preservation");
		BorlandProfileContext ctx;
		mu_assert_true (tasm_context (core, &ctx), "exact original FAR context");
		const ut64 source = 0x45ec, target = 0x15fd2;
		if (scenario == 0) {
			mu_assert_true (r_anal_xrefs_set (core->anal, source, target, R_ANAL_REF_TYPE_CODE), "independent same-pair FAR reference");
		} else if (scenario == 1) {
			ut8 patch = 0x91;
			mu_assert_eq (core->anal->iob.overlay_write_at (core->io, source + 2, &patch, 1), 1, "current paragraph field patch");
		} else if (scenario == 2) {
			RBinReloc *reloc;
			R_VEC_FOREACH (ctx.file->bo->relocs, reloc) {
				if (reloc->paddr == 0x4dee) {
					reloc->vaddr++;
				}
			}
		} else if (scenario == 3) {
			mu_assert_true (profile_function (&ctx, 0x167d2, 0x88, "user_owned_selector", 0, NULL), "independent FAR target function");
		} else {
			r_anal_hint_set_bits (core->anal, source + 2, 32);
			r_anal_hint_set_bits (core->anal, source + 3, 16);
		}
		int expected = scenario == 1 || scenario == 2 || scenario == 3 || scenario == 4? 43: 44;
		mu_assert_eq (borland_tasm31_profile (core->anal), expected, "current FAR source/target function qualification remains independent");
		mu_assert_eq (tasm_reference (core->anal, source, target), !scenario? R_ANAL_REF_TYPE_CODE: 0, "preserved FAR prerequisite stops DATA relationship");
		mu_assert_false (tasm_comment (core->anal, 0x4dec, "Qualified native MZ"), "preserved FAR prerequisite stops pair annotation");
		if (scenario == 3) {
			mu_assert_eq (tasm_reference (core->anal, 0x4605, target), 0, "preserved target also stops second FAR DATA relationship");
			mu_assert_eq (tasm_reference (core->anal, 0x46e4, target), 0, "preserved target also stops unowned third caller DATA relationship");
		}
		r_core_free (core);
	}
	mu_end;
}

static bool test_tasm_allocation_preservation(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 2; scenario++) {
		RCore *core = tasm_original ();
		mu_assert_notnull (core, "original for exact partition preservation");
		BorlandProfileContext ctx;
		mu_assert_true (tasm_context (core, &ctx), "actual allocation identity");
		if (!scenario) {
			mu_assert_true (profile_function (&ctx, 0x50e2, 16, "user_owned_clear_entry", 0, NULL), "independent shared-clear function");
		} else {
			ut8 original;
			mu_assert_true (r_io_read_at (core->io, 0x48f3, &original, 1), "second allocation-range original byte");
			ut8 patch = original ^ 1;
			mu_assert_eq (core->anal->iob.overlay_write_at (core->io, 0x48f3, &patch, 1), 1, "second-range current patch");
		}
		mu_assert_eq (borland_tasm31_profile (core->anal), 43, "only the independent clear or patched allocation refuses");
		RAnalFunction *clear = r_anal_get_function_at (core->anal, 0x48e2);
		mu_assert_notnull (clear, "independent clear always retained");
		mu_assert_eq (r_anal_function_realsize (clear), 16, "clear never absorbed into allocation");
		if (!scenario) {
			mu_assert_streq (clear->name, "user_owned_clear_entry", "independent clear name preserved");
			RAnalFunction *allocation = r_anal_get_function_at (core->anal, 0x48cc);
			mu_assert_notnull (allocation, "separately qualified allocation union");
			mu_assert_eq (r_anal_function_realsize (allocation), 62, "allocation still excludes independent clear");
			mu_assert_eq (tasm_reference (core->anal, 0x5137, 0x48e2), 0, "preserved target stops dependent shared-clear call reference");
			mu_assert_null (r_flag_get (core->flags, "tasm31_expression_clear_near_call"), "preserved target stops dependent caller label");
			mu_assert_false (tasm_comment (core->anal, 0x5937, "Original E8a8f7"), "preserved target stops dependent caller annotation");
		} else {
			mu_assert_null (r_anal_get_function_at (core->anal, 0x48cc), "second-range patch refuses entire union");
			mu_assert_eq (tasm_reference (core->anal, 0x5137, 0x48e2), R_ANAL_REF_TYPE_CALL, "separate clear relationship remains independently qualified");
		}
		r_core_free (core);
	}
	mu_end;
}

static bool tasm_command(RCore *core, int *count) {
	char *output = r_core_cmd_str (core, "a:borland");
	mu_assert_notnull (output, "actual registered RCore command output");
	mu_assert_eq (sscanf (output, "Borland: %d function contracts qualified", count), 1, "production command count");
	eprintf ("Registered TASM path: %s", output);
	free (output);
	return true;
}

static bool tasm_default_pre(RCore *core) {
	mu_assert_streq (r_config_get (core->config, "anal.plugins.pre"), "", "unchanged default registered PRE selection");
	r_anal_plugin_action (core->anal, R_ANAL_PLUGIN_ACTION_PRE_ANALYSIS, NULL);
	eprintf ("Default registered TASM PRE boundary invoked; downstream aaa execution is not claimed\n");
	return true;
}

static bool test_tasm_registered_command_and_default_pre(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	int pre;
	for (pre = 0; pre < 2; pre++) {
		RCore *core = tasm_original ();
		mu_assert_notnull (core, "normal-path exact MZ original");
		BorlandProfileContext ctx;
		mu_assert_true (tasm_context (core, &ctx), "normal-path exact original identity");
		mu_assert_null (r_anal_get_function_at (core->anal, 0x6c4d), "no private apply before registered path");
		int count = 0;
		if (pre) {
			mu_assert_true (tasm_default_pre (core), "actual default PRE hook");
		} else {
			mu_assert_true (tasm_command (core, &count), "actual registered RCore command");
		}
		mu_assert_true (tasm_check_complete_facts (core, &ctx), "either registered path installs all finite facts without private apply");
		int functions = r_list_length (core->anal->fcns), labels = r_flag_count (core->flags, NULL);
		ut64 references = r_anal_xrefs_count (core->anal), epoch = r_anal_types_dirty_epoch (core->anal);
		char *comment = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x461e));
		if (pre) {
			mu_assert_true (tasm_default_pre (core), "default PRE equivalent rerun");
			mu_assert_true (tasm_check_complete_facts (core, &ctx), "PRE rerun retains every finite fact");
		}
		int repeated = 0;
		mu_assert_true (tasm_command (core, &repeated), "registered equivalent command rerun after either route");
		mu_assert_true (repeated >= 44, "production count includes all44 exact TASM bodies");
		if (!pre) {
			mu_assert_eq (repeated, count, "unchanged registered production count");
		}
		mu_assert_eq (r_list_length (core->anal->fcns), functions, "registered rerun adds no duplicate functions");
		mu_assert_eq (r_flag_count (core->flags, NULL), labels, "registered rerun adds no duplicate labels");
		mu_assert_eq (r_anal_xrefs_count (core->anal), references, "registered rerun adds no duplicate references");
		mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "registered rerun adds no duplicate native type/link state");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x461e), comment, "registered rerun adds no duplicate comments");
		free (comment);
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x461e);
		ut64 size = r_anal_function_realsize (fcn);
		r_anal_function_rename (fcn, "user_owned_normal_tasm");
		RAnalFunctionSignature signature = { .ret_type = "uint32_t", .params = r_list_new () };
		mu_assert_true (r_anal_function_set_signature (core->anal, fcn, &signature), "independent normal-path native signature");
		r_list_free (signature.params);
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x461e, "manual registered function comment");
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x464a, "manual registered flags annotation");
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x4665, "manual registered literal annotation");
		int preserved = 0;
		if (pre) {
			mu_assert_true (tasm_default_pre (core), "default PRE preserves manual state");
		} else {
			mu_assert_true (tasm_command (core, &preserved), "registered command preserves manual state");
			mu_assert_eq (preserved, repeated - 1, "registered count reports one independent function refusal");
		}
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x461e), fcn, "registered route preserves independent function identity");
		mu_assert_streq (fcn->name, "user_owned_normal_tasm", "registered route preserves independent name");
		mu_assert_eq (r_anal_function_realsize (fcn), size, "registered route preserves independent body");
		RAnalFunctionSignature *after = r_anal_function_get_signature (fcn);
		mu_assert_notnull (after, "independent normal signature retained");
		mu_assert_streq (after->ret_type, "uint32_t", "registered route preserves independent return contract");
		r_anal_function_signature_free (after);
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x461e), "manual registered function comment", "preserved function stops dependent annotation through registered route");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x464a), "manual registered flags annotation", "preserved function stops dependent flags annotation through registered route");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x4665), "manual registered literal annotation", "preserved function stops dependent literal annotation through registered route");
		r_core_free (core);
	}
	mu_end;
}

static bool test_tasm_registered_reference_and_current_refusal(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	int pre, scenario;
	for (pre = 0; pre < 2; pre++) {
		for (scenario = 0; scenario < 2; scenario++) {
			RCore *core = tasm_original ();
			mu_assert_notnull (core, "normal-path refusal exact original");
			BorlandProfileContext ctx;
			mu_assert_true (tasm_context (core, &ctx), "normal-path refusal original identity");
			if (!scenario) {
				mu_assert_true (r_anal_xrefs_set (core->anal, 0x177da, 0x17929, R_ANAL_REF_TYPE_CODE), "independent actual option-cell reference");
			} else {
				ut8 original;
				mu_assert_true (r_io_read_at (core->io, 0x177fc, &original, 1), "actual78-byte table tail");
				ut8 patch = original ^ 1;
				mu_assert_eq (core->anal->iob.overlay_write_at (core->io, 0x177fc, &patch, 1), 1, "current table-tail edit before registered application");
				patch = 0x91;
				mu_assert_eq (core->anal->iob.overlay_write_at (core->io, 0x4666, &patch, 1), 1, "current literal edit before registered application");
			}
			int count = 0;
			if (pre) {
				mu_assert_true (tasm_default_pre (core), "default PRE refuses independently edited inputs");
			} else {
				mu_assert_true (tasm_command (core, &count), "registered command refuses independently edited inputs");
			}
			mu_assert_eq (tasm_reference (core->anal, 0x177da, 0x17929), !scenario? R_ANAL_REF_TYPE_CODE: 0, "registered route preserves manual reference or refuses changed source table");
			mu_assert_null (r_flag_get (core->flags, "tasm31_cs1615_object_control_writer"), "registered prerequisite refusal stops dependent writer label");
			mu_assert_false (tasm_comment (core->anal, 0x18129, "R283:"), "registered prerequisite refusal stops dependent writer annotation");
			if (scenario) {
				mu_assert_null (r_anal_get_function_at (core->anal, 0x461e), "registered route does not install changed literal body");
				mu_assert_false (tasm_comment (core->anal, 0x4e65, "TI01 literal"), "changed body stops dependent inline literal annotation");
				mu_assert_null (r_flag_get (core->flags, "tasm31_cs1615_option_dispatch_table"), "changed table stops its aggregate label");
				mu_assert_null (sdb_const_get (core->anal->sdb_types, "link.000177af", NULL), "changed table stops its aggregate type link");
				ut8 current;
				mu_assert_true (r_io_read_at (core->io, 0x4666, &current, 1), "registered route retains patched current byte");
				mu_assert_eq (current, 0x91, "registered route does not repair current literal");
			} else {
				mu_assert_notnull (r_anal_get_function_at (core->anal, 0x461e), "manual data reference leaves independently qualified body intact");
			}
			mu_assert_true (tasm_check_function (core, 0x50e2, 0x50f2, "tasm31_clear_expression_view", 6), "registered refusal leaves separate clear independent");
			RAnalFunction *allocation = r_anal_get_function_at (core->anal, 0x48cc);
			mu_assert_notnull (allocation, "registered refusal leaves allocation independent");
			mu_assert_eq (r_anal_function_realsize (allocation), 62, "registered refusal keeps exact discontiguous ownership");
			r_core_free (core);
		}
	}
	mu_end;
}

static bool test_tasm_flag_contract_preservation(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	size_t contract;
	int scenario;
	for (contract = 0; contract < R_ARRAY_SIZE (expected_contracts); contract++) {
		for (scenario = !strcmp (expected_contracts[contract].ret, "void")? 1: 0; scenario < 3; scenario++) {
			RCore *core = tasm_original ();
			mu_assert_notnull (core, "exact original for contract preservation");
			r_anal_types_prepare (core->anal);
			ut64 address = expected_contracts[contract].start - 0x800;
			if (scenario == 0) {
				const HelperMember independent[] = { { "manual_field", "uint8_t", 0 } };
				mu_assert_true (borland_record (core->anal, expected_contracts[contract].ret, 8, independent, 1), "independent same-name return layout");
			} else {
				mu_assert_eq (borland_tasm31_profile (core->anal), 44, "initial qualified contract application");
				RAnalFunction *fcn = r_anal_get_function_at (core->anal, address);
				mu_assert_notnull (fcn, "qualified helper exists");
				if (scenario == 1) {
					RAnalFunctionSignature signature = { .ret_type = "uint32_t", .params = r_list_new () };
					mu_assert_true (r_anal_function_set_signature (core->anal, fcn, &signature), "independent user return contract");
					r_list_free (signature.params);
				} else {
					mu_assert_true (r_anal_types_set_link (core->anal, "uint16_t", address), "independent data link at helper entry");
				}
			}
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, address, "manual contract annotation");
			mu_assert_eq (borland_tasm31_profile (core->anal), 43, "only conflicting qualified helper refuses");
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, address), "manual contract annotation", "no dependent contract annotation on refusal");
			if (scenario == 0) {
				mu_assert_null (r_anal_get_function_at (core->anal, address), "conflicting result type stops function/signature creation");
				RAnalBaseType *type = r_anal_get_base_type (core->anal, expected_contracts[contract].ret);
				mu_assert_eq (type->size, 8, "manual return type retained");
				mu_assert_streq (RVecAnalTypeMember_at (&type->struct_data.members, 0)->name, "manual_field", "manual field retained");
				r_anal_base_type_free (type);
			} else if (scenario == 1) {
				RAnalFunctionSignature *signature = r_anal_function_get_signature (r_anal_get_function_at (core->anal, address));
				mu_assert_streq (signature->ret_type, "uint32_t", "manual signature retained");
				r_anal_function_signature_free (signature);
			} else {
				char *linked = r_type_link_at (core->anal->sdb_types, address);
				mu_assert_streq (linked, "uint16_t", "manual data link retained");
				free (linked);
			}
			r_core_free (core);
		}
	}
	mu_end;
}

static bool all_tests(void) {
	mu_run_test (test_tasm_complete_owner);
	mu_run_test (test_tasm_flag_contract_preservation);
	mu_run_test (test_tasm_function_preservation);
	mu_run_test (test_tasm_data_reference_preservation);
	mu_run_test (test_tasm_type_dependencies);
	mu_run_test (test_tasm_far_preservation);
	mu_run_test (test_tasm_allocation_preservation);
	mu_run_test (test_tasm_registered_command_and_default_pre);
	mu_run_test (test_tasm_registered_reference_and_current_refusal);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
