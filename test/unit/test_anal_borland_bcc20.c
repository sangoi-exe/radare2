#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_bcc20_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland
#ifndef BORLAND_PROFILE_BCC20_INCLUDED
#include "../../libr/anal/p/borland_profile_bcc20.inc.c"
#endif

static RCore *bcc20_original(void) {
	const char *path = getenv ("R2_TEST_BCC20");
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

static bool bcc20_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "mz", 502432, "dd5744b99c6fa61dc1d95c580a1f1d6f1b3e97ae8b920dd6e9cfedce29f82fb6");
}

// Independent terminal-inclusive partitions and instruction counts from ValidateBcc20Profile at Ghidra9ba90c3.
static const struct { ut64 start; ut64 end; int purge; int instructions; const char *name; } expected_functions[] = {

	{ 0x43d7a, 0x43db2, 6, 24, "bcc20_submit_option_table" }, { 0x43db2, 0x43dfc, 6, 36, "bcc20_dispatch_near_options" }, { 0x43dfc, 0x43e65, 6, 47, "bcc20_boolean_option_handler" },
	{ 0x43fc7, 0x43fe1, 6, 13, "bcc20_delegate_option_table" }, { 0x43d5b, 0x43d7a, 0, 16, "bcc20_transfer_option_bytes60" },
	{ 0x54350, 0x54386, 6, 22, "bcc20_reuse_linked_slot_or_append" }, { 0x543a6, 0x54435, 6, 57, "bcc20_append_arena" }, { 0x66899, 0x66900, 8, 40, "bcc20_construct_two_array_node" },
	{ 0x6526e, 0x6529d, 2, 21, "bcc20_record_for_current_id" }, { 0x67e1a, 0x6802c, 0, 197, "bcc20_recognize_current_text_section" }, { 0x6824e, 0x682c1, 4, 51, "bcc20_construct_helper_prefix_node" },
	{ 0x682c1, 0x682ec, 2, 19, "bcc20_select_helper_suffix" }, { 0xba87, 0xbaa8, 8, 20, "bcc20_compare_terminated_bytes" }, { 0xc072, 0xc09d, 8, 16, "bcc20_copy_terminated_wrapper" }, { 0xc146, 0xc180, 8, 22, "bcc20_append_terminated_wrapper" },
	{ 0x62dc6, 0x62f0b, 4, 116, "bcc20_section_reset_caller" }, { 0x62f80, 0x6317b, 4, 180, "bcc20_initialize_section_state_and_backend" }, { 0x650a0, 0x651f0, 8, 111, "bcc20_construct_section_list_record" },
	{ 0x65930, 0x659a8, 20, 42, "bcc20_capture_current_section_id" }, { 0x65db7, 0x65e44, 6, 48, "bcc20_dispatch_section_recognition" }, { 0xbf23, 0xbf51, 8, 24, "bcc20_fill_bytes" },
	{ 0x1402, 0x1418, 8, 14, "bcc20_copy_callback_table_bytes" }, { 0x633c8, 0x6344c, 4, 51, "bcc20_install_obj_callbacks" }, { 0x78803, 0x788fa, 4, 95, "bcc20_install_asm_callbacks" }, { 0x631b0, 0x63200, 2, 27, "bcc20_append_backend_byte" },
	{ 0x78f38, 0x79244, 2, 290, "bcc20_asm_instruction_serializer" }, { 0x78de6, 0x78e86, 2, 71, "bcc20_instruction_size_contribution" }, { 0x78e86, 0x78f30, 4, 75, "bcc20_operand_size_contribution" },
	{ 0x792ca, 0x795a6, 4, 271, "bcc20_asm_operand_formatter" }, { 0x795da, 0x79622, 2, 29, "bcc20_asm_segment_prefix" }, { 0x6a642, 0x6a6a5, 2, 34, "bcc20_request_output_character" }, { 0x6a9bc, 0x6aa04, 4, 26, "bcc20_request_output_string" },
	{ 0x6ea47, 0x6ee25, 0, 347, "bcc20_request_function_frame" }, { 0x6fa2e, 0x6fa53, 6, 12, "bcc20_capture_immediate_request" }, { 0x6f982, 0x6f99f, 4, 11, "bcc20_lower_node_tag_request" },
	{ 0x6fb03, 0x6fda5, 2, 232, "bcc20_normalize_instruction_request" }, { 0x6fda5, 0x6fe45, 2, 59, "bcc20_flush_auxiliary_request" }, { 0x6fe45, 0x700e1, 4, 220, "bcc20_build_operand_workspace" },
	{ 0x6405a, 0x64137, 6, 84, "bcc20_shorten_immediate_request" }, { 0x64137, 0x641a1, 2, 44, "bcc20_request_immediate_bytes" }, { 0x63251, 0x63265, 2, 11, "bcc20_map_register_selector" },
	{ 0x70107, 0x70168, 2, 33, "bcc20_conditionally_fill_selector" }, { 0x70168, 0x7028f, 4, 100, "bcc20_construct_operand_fields" }, { 0x64007, 0x64021, 2, 14, "bcc20_select_operand_prefix_byte" }
};

static const struct { int identifier; ut64 physical; int code; int fixups; } expected_views[] = {
	{ 0x0338, 0x43a60, 0x10c7, 0x9a }, { 0x0378, 0x4b6b0, 0x522, 0x48 }, { 0x03e0, 0x54350, 0x151, 8 },
	{ 0x0458, 0x62db0, 0x19c, 0x2a }, { 0x0460, 0x62f80, 0x1fb, 0x24 }, { 0x0470, 0x631b0, 0x10c4, 0x44 },
	{ 0x0488, 0x650a0, 0x753, 0x28 }, { 0x0490, 0x65830, 0xf2e, 0x3c }, { 0x0498, 0x667c0, 0x2b1, 0x12 },
	{ 0x04a0, 0x66a90, 0x2251, 0x184 }, { 0x04c8, 0x69d70, 0xceb, 0x8a }, { 0x04f8, 0x6e460, 0x11b5, 0x110 },
	{ 0x0508, 0x6f8c0, 0x9f3, 0x10 }, { 0x0510, 0x702d0, 0x1209, 0xaa }, { 0x0598, 0x78700, 0x1057, 0x14a }
};

static ut64 bcc20_address(ut64 physical) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (expected_views); i++) {
		if (physical >= expected_views[i].physical && physical < expected_views[i].physical + expected_views[i].code + expected_views[i].fixups) {
			return 0x40010000 + 0x10000 * i + physical - expected_views[i].physical;
		}
	}
	return physical - 0x1000;
}

static int bcc20_ref(RAnal *anal, ut64 from, ut64 to) {
	RVecAnalRef *refs = r_anal_refs_get (anal, bcc20_address (from));
	RAnalRef *ref;
	int type = 0;
	if (refs) {
		R_VEC_FOREACH (refs, ref) {
			if (ref->addr == bcc20_address (to)) {
				type = R_ANAL_REF_TYPE_MASK (ref->type);
			}
		}
	}
	RVecAnalRef_free (refs);
	return type;
}

static bool bcc20_link(RAnal *anal, ut64 physical, const char *type) {
	char *linked = r_type_link_at (anal->sdb_types, bcc20_address (physical));
	bool same = linked && !strcmp (linked, type);
	free (linked);
	return same;
}

static bool bcc20_check_views(RCore *core, BorlandProfileContext *ctx) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (expected_views); i++) {
		ut64 physical = expected_views[i].physical, address = 0x40010000 + i * 0x10000;
		int size = expected_views[i].code + expected_views[i].fixups;
		mu_assert_eq (profile_mapped (ctx, physical, size, true), address, "original-FD section AND active map qualification");
		RIOMap *map = r_io_map_get_at (core->io, address);
		mu_assert_notnull (map, "original-FD static view map");
		mu_assert_eq (map->fd, ctx->file->fd, "static map never allocates a copied backing descriptor");
		mu_assert_eq (map->perm, R_PERM_RX, "static view is read-executable only");
		mu_assert_eq (map->itv.size, size, "body plus unmodified raw fixups");
		ut8 *original = malloc (size), *current = malloc (size);
		mu_assert_eq (r_buf_read_at (ctx->file->buf, physical, original, size), size, "complete original body/fixup extent");
		mu_assert_true (r_io_read_at (core->io, address, current, size), "complete mapped body/fixup bytes");
		mu_assert_memeq (original, current, size, "mapped raw body/fixups literally equal original");
		free (original);
		free (current);
		char *type = r_str_newf ("uint16_t [%u]", expected_views[i].fixups / 2);
		mu_assert_true (bcc20_link (core->anal, physical + expected_views[i].code, type), "all15 raw fixup arrays native linked data");
		free (type);
		ut8 entry[2];
		mu_assert_eq (r_buf_read_at (ctx->file->buf, 0xc390 + expected_views[i].identifier, entry, 2), 2, "original manager table WORD");
		ut64 descriptor = 0x1000 + 16ULL * r_read_le16 (entry);
		mu_assert_eq (bcc20_ref (core->anal, 0xc390 + expected_views[i].identifier, descriptor), R_ANAL_REF_TYPE_DATA, "all15 manager IDs join their resident descriptors as DATA");
		mu_assert_eq (bcc20_ref (core->anal, descriptor + 4, physical), R_ANAL_REF_TYPE_DATA, "all15 ADD/ADC archive offsets join original body as DATA");
		int field;
		for (field = 4; field <= 10; field += 2) {
			mu_assert_true (bcc20_link (core->anal, descriptor + field, "uint16_t"), "descriptor fields remain separate native WORD data");
		}
	}
	mu_assert_eq (core->anal->config->seggrn, 4, "native MZ paragraph granularity is unchanged");
	return true;
}

static bool bcc20_check_types(RCore *core) {
	const struct { const char *name; int bits; int offsets[7]; int count; } layouts[] = {
		{ "bcc20_FarStorage16", 32, { 0, 2 }, 2 },
		{ "bcc20_RecordedOverlayDescriptor32Partial", 256, { 4, 6, 8, 10 }, 4 },
		{ "bcc20_OptionDescriptor8Partial", 64, { 0, 1, 2, 4 }, 4 },
		{ "bcc20_AppendDescriptor8Partial", 64, { 0, 2, 4, 6 }, 4 },
		{ "bcc20_PrimaryNode4Partial", 32, { 0, 1, 2 }, 3 },
		{ "bcc20_SecondaryNode4Partial", 32, { 0, 2 }, 2 },
		{ "bcc20_InstructionDescriptor19Partial", 152, { 0, 2, 3, 7, 13, 15, 17 }, 7 }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (layouts); i++) {
		RAnalBaseType *type = r_anal_get_base_type (core->anal, layouts[i].name);
		mu_assert_notnull (type, "every source partial layout exists");
		mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_STRUCT, "native structured type owner");
		mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, layouts[i].name), layouts[i].bits, "partial extent retains undefined bytes");
		mu_assert_eq (RVecAnalTypeMember_length (&type->struct_data.members), layouts[i].count, "no fabricated fields in partial records");
		int field;
		for (field = 0; field < layouts[i].count; field++) {
			mu_assert_eq (RVecAnalTypeMember_at (&type->struct_data.members, field)->offset, layouts[i].offsets[field], "exact source field offset including unaligned WORD+3");
		}
		r_anal_base_type_free (type);
	}
	RAnalBaseType *nodes = r_anal_get_base_type (core->anal, "bcc20_NodeTag8");
	mu_assert_notnull (nodes, "separate BYTE node-tag domain");
	mu_assert_eq (RVecAnalEnumCase_length (&nodes->enum_data.cases), 2, "only selected77/78 named");
	mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, "bcc20_NodeTag8"), 8, "node tag is BYTE, not instruction WORD");
	r_anal_base_type_free (nodes);
	RAnalBaseType *requests = r_anal_get_base_type (core->anal, "bcc20_InstructionRequestTag16");
	mu_assert_notnull (requests, "separate numeric instruction-request domain");
	mu_assert_eq (RVecAnalEnumCase_length (&requests->enum_data.cases), 10, "all10 selected request tags");
	mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, "bcc20_InstructionRequestTag16"), 16, "request tag remains WORD");
	r_anal_base_type_free (requests);
	return true;
}

static bool bcc20_check_facts(RCore *core, BorlandProfileContext *ctx) {
	mu_assert_true (bcc20_check_views (core, ctx), "every static view and descriptor fact");
	mu_assert_true (bcc20_check_types (core), "all source partial layouts and finite enum domains");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (expected_functions); i++) {
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, bcc20_address (expected_functions[i].start));
		mu_assert_notnull (fcn, "all44 complete functions exist");
		mu_assert_streq (fcn->name, expected_functions[i].name, "all44 source-qualified function names");
		mu_assert_eq (r_anal_function_realsize (fcn), expected_functions[i].end - expected_functions[i].start, "all44 terminal-inclusive bodies");
		mu_assert_eq (fcn->meta.stack_pop, expected_functions[i].purge, "all44 recorded net cleanup values");
		int instructions = 0;
		RListIter *iter;
		RAnalBlock *bb;
		r_list_foreach (fcn->bbs, iter, bb) {
			instructions += bb->ninstr;
		}
		mu_assert_eq (instructions, expected_functions[i].instructions, "independent source native instruction count");
		mu_assert_eq (fcn->bits, 16, "analysis window does not change 16-bit CPU mode");
	}
	const struct { ut64 file; const char *type; } objects[] = {
		{ 0x1075e, "bcc20_OptionDescriptor8Partial" }, { 0x10766, "bcc20_OptionDescriptor8Partial" }, { 0x10796, "bcc20_OptionDescriptor8Partial" },
		{ 0x17570, "bcc20_AppendDescriptor8Partial" }, { 0x17588, "bcc20_AppendDescriptor8Partial" },
		{ 0x1435e, "bcc20_FarStorage16 [24]" }, { 0x14442, "bcc20_FarStorage16 [24]" },
		{ 0x43e65, "uint16_t [8]" }, { 0x79264, "uint16_t [6]" }, { 0x795a6, "uint16_t [26]" },
		{ 0x7105b, "uint16_t [1]" }, { 0x63eab, "uint16_t [1]" }, { 0x63f11, "uint16_t [1]" }, { 0x63ef9, "uint16_t [1]" },
		{ 0x143be, "uint8_t [12]" }, { 0x1415b, "uint16_t [2]" },
		{ 0x141b8, "uint8_t [6]" }, { 0x141e7, "uint8_t [3]" }, { 0x141ea, "uint8_t [3]" }, { 0x1417b, "uint8_t [7]" },
		{ 0x13f8d, "uint8_t [4]" }, { 0x1405c, "uint8_t [4]" }, { 0x105ec, "uint8_t" }, { 0x10604, "uint8_t" }, { 0x10605, "uint8_t" }
	};
	for (i = 0; i < R_ARRAY_SIZE (objects); i++) {
		mu_assert_true (bcc20_link (core->anal, objects[i].file, objects[i].type), "all finite native object/array links");
	}
	const int tags[] = { 0x4f, 0x98, 0x99, 0x28, 0x5b, 0x92, 0x94, 0x9c, 0x77, 0x78 };
	for (i = 0; i < R_ARRAY_SIZE (tags); i++) {
		ut64 file = 0xeef0 + 0x3f98 + 19 * tags[i];
		mu_assert_true (bcc20_link (core->anal, file, "bcc20_InstructionDescriptor19Partial"), "all10 request descriptors");
		ut8 word[2];
		r_buf_read_at (ctx->file->buf, file, word, 2);
		mu_assert_eq (bcc20_ref (core->anal, file, 0xeef0 + r_read_le16 (word)), R_ANAL_REF_TYPE_DATA, "all10 actual mnemonic offsets");
	}
	const ut64 joins[][2] = {
		{ 0x668a9, 0x543a6 }, { 0x668b9, 0x543a6 }, { 0x67e27, 0x6526e }, { 0x682b5, 0x66899 },
		{ 0x67e43, 0xba87 }, { 0x6827e, 0xc072 }, { 0x6828c, 0xc146 }, { 0x62f03, 0x62f80 },
		{ 0x65e3a, 0x67e1a }, { 0x63166, 0x78803 }, { 0x63173, 0x633c8 }, { 0x631c6, 0x543a6 }, { 0x70ba8, 0x6f982 },
		{ 0x14386, 0x63596 }, { 0x1446a, 0x78f38 }, { 0xe3d9, 0x63596 },
		{ 0x10760, 0x43dfc }, { 0x10768, 0x43dfc }, { 0x10798, 0x43dfc },
		{ 0x10762, 0x10605 }, { 0x1076a, 0x10604 }, { 0x1079a, 0x105ec },
		{ 0x1415b, 0x1417b }, { 0x1415d, 0x1417b }, { 0x63eab, 0x63cb2 }, { 0x63ef9, 0x63cb2 }, { 0x63f11, 0x637fb },
		{ 0x635b2, 0x64007 }, { 0x635c2, 0x64007 }, { 0x63cb6, 0x6405a }, { 0x63cd4, 0x631b0 },
		{ 0x63cdf, 0x63251 }, { 0x63ce9, 0x641a1 }, { 0x641b4, 0x63251 }, { 0x6426b, 0x631b0 }
	};
	for (i = 0; i < R_ARRAY_SIZE (joins); i++) {
		mu_assert_eq (bcc20_ref (core->anal, joins[i][0], joins[i][1]), R_ANAL_REF_TYPE_DATA, "source-qualified joins remain DATA only");
	}
	int family, cell;
	for (family = 0; family < 2; family++) {
		ut64 table = family? 0x14442: 0x1435e;
		for (cell = 0; cell < 24; cell++) {
			ut8 pair[4];
			r_buf_read_at (ctx->file->buf, table + 4 * cell, pair, 4);
			mu_assert_eq (bcc20_ref (core->anal, table + 4 * cell, 0x1000 + 16ULL * r_read_le16 (pair + 2) + r_read_le16 (pair)), R_ANAL_REF_TYPE_DATA, "all48 original native MZ callback cells");
		}
	}
	const struct { ut64 physical; const char *label; const char *qualification; } notes[] = {
		{ 0x4ba9a, "bcc20_post_parser_ordered_OR_fragment", "no retroactive B-to-c OR" },
		{ 0x43ade, "bcc20_mode_supplier_fragment", "not proof literal S/B handlers" },
		{ 0x63596, "bcc20_obj_instruction_callback_prefix", "NOT a complete function" },
		{ 0x70b80, "bcc20_common_node77_78_consumer_fragment", "nor proof U=4*C" },
		{ 0x63cb2, "bcc20_SUB_XOR_byte_request_fragment", "Only AFTER append returns" },
		{ 0x6fc89, "bcc20_zero_to_self_XOR_fragment", "does not prove the upstream producer" },
		{ 0x641a1, "bcc20_ModRM_register_prefix_fragment", "Other operand paths remain unreviewed" },
		{ 0x637fb, "bcc20_DEC_register_request_fragment", "No whole callback" },
		{ 0x64268, "bcc20_ModRM_byte_request_tail_fragment", NULL },
		{ 0x7005b, NULL, "Do not cache frame/child/global reads" }, { 0x635ad, NULL, "No whole callback or backend lifetime proof" },
		{ 0x6fd99, NULL, "no current installed-state" }, { 0x10766, "bcc20_option_S_row", "not BCC3.1 restoration" },
		{ 0x1779c, "bcc20_initial_section_flags", "separate current reads" }
	};
	for (i = 0; i < R_ARRAY_SIZE (notes); i++) {
		if (notes[i].label) {
			RFlagItem *flag = r_flag_get (core->flags, notes[i].label);
			mu_assert_notnull (flag, "every qualified partial/source label");
			mu_assert_eq (flag->addr, bcc20_address (notes[i].physical), "qualified label stays in its own coordinate domain");
		}
		if (notes[i].qualification) {
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, bcc20_address (notes[i].physical));
			mu_assert_true (comment && strstr (comment, notes[i].qualification), "every finite note retains its source semantic qualification");
		}
	}
	const ut64 partial[] = { 0x63596, 0x70b80, 0x63cb2, 0x641a1, 0x64268, 0x637fb, 0x4ba9a, 0x43ade };
	for (i = 0; i < R_ARRAY_SIZE (partial); i++) {
		mu_assert_null (r_anal_get_function_at (core->anal, bcc20_address (partial[i])), "partial semantic coverage never fabricates a complete function");
	}
	const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, bcc20_address (0x70168));
	mu_assert_true (comment && strstr (comment, "aliases may change") && strstr (comment, "AL loads retain AH"), "operand current-state/alias/partial-register limits retained");
	comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, bcc20_address (0x63cb2));
	mu_assert_true (comment && strstr (comment, "NOT a complete function") && strstr (comment, "AFTER append returns"), "shared partial SUB/XOR arm and fresh reads retained");
	return true;
}
static bool test_bcc20_complete_owner(void) {
	if (!getenv ("R2_TEST_BCC20")) {
		eprintf ("SKIP exact BCC2.0 original branches: set R2_TEST_BCC20\n");
		mu_end;
	}
	RCore *core = bcc20_original ();
	mu_assert_notnull (core, "read-only actual BCC2.0 MZ original");
	BorlandProfileContext ctx;
	mu_assert_true (bcc20_context (core, &ctx), "exact native MZ original identity");
	ut8 before[0x17ce0], after[0x17ce0];
	mu_assert_true (r_io_read_at (core->io, 0, before, sizeof (before)), "native resident image before preparation");
	mu_assert_eq (borland_bcc20_profile (core->anal), 44, "direct production owner installs all44 complete facts");
	mu_assert_true (bcc20_check_facts (core, &ctx), "complete finite profile facts");
	mu_assert_true (r_io_read_at (core->io, 0, after, sizeof (after)), "native resident image after preparation");
	mu_assert_memeq (before, after, sizeof (before), "resident bytes/native MZ relocations never rewritten");
	int functions = r_list_length (core->anal->fcns), labels = r_flag_count (core->flags, NULL);
	ut64 references = r_anal_xrefs_count (core->anal), epoch = r_anal_types_dirty_epoch (core->anal);
	size_t sections = RVecRBinSection_length (&ctx.file->bo->sections_vec);
	char *comment = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, bcc20_address (0x63cb2)));
	mu_assert_eq (borland_bcc20_profile (core->anal), 44, "equivalent direct reapply");
	mu_assert_true (bcc20_check_facts (core, &ctx), "every finite fact remains present after reapply");
	mu_assert_eq (r_list_length (core->anal->fcns), functions, "no duplicate functions");
	mu_assert_eq (r_flag_count (core->flags, NULL), labels, "no duplicate labels");
	mu_assert_eq (r_anal_xrefs_count (core->anal), references, "no duplicate DATA/executable references");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "no duplicate types/object links");
	mu_assert_eq (RVecRBinSection_length (&ctx.file->bo->sections_vec), sections, "no duplicate static sections");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, bcc20_address (0x63cb2)), comment, "no duplicate qualification comments");
	free (comment);
	mu_assert_true (bcc20_context (core, &ctx), "original buffer still has exact named-source identity");
	r_core_free (core);
	mu_end;
}

static bool test_bcc20_control_edges(void) {
	if (!getenv ("R2_TEST_BCC20")) {
		mu_end;
	}
	RCore *core = bcc20_original ();
	mu_assert_notnull (core, "actual BCC2.0 control-edge witness");
	mu_assert_eq (borland_bcc20_profile (core->anal), 44, "qualified raw static views");
	BorlandProfileContext ctx;
	mu_assert_true (bcc20_context (core, &ctx), "actual control-edge identity");
	ut64 address = bcc20_address (0x668a8);
	ut8 raw[5];
	mu_assert_true (r_io_read_at (core->io, address, raw, 5), "unmodified original constructor CALLF");
	const ut8 expected[] = { 0x9a, 0x2f, 0, 0xe0, 3 };
	mu_assert_memeq (raw, expected, 5, "manager03e0/stub002f raw operand retained");
	RAnalOp op = {0};
	mu_assert_eq (r_anal_op (core->anal, &op, address, raw, 5, R_ARCH_OP_MASK_BASIC), 5, "actual native raw FAR decoding");
	mu_assert_eq (op.jump, 0x3e2f, "native paragraph decoder witness is not rewritten/rebound");
	r_anal_op_fini (&op);
	ctx.bcc20_static_views = true;
	HelperOp qualified[5];
	mu_assert_true (profile_code (&ctx, 0x668a8, 5, address, qualified), "qualified static view decoding");
	mu_assert_eq (qualified[0].jump, UT64_MAX, "unproved external executable target unresolved before consumers");
	RVecAnalRef *refs = r_anal_refs_get (core->anal, address);
	RAnalRef *ref;
	if (refs) {
		R_VEC_FOREACH (refs, ref) {
			mu_assert_true (R_ANAL_REF_TYPE_MASK (ref->type) != R_ANAL_REF_TYPE_CALL && R_ANAL_REF_TYPE_MASK (ref->type) != R_ANAL_REF_TYPE_CODE, "raw CALLF produces no false executable references");
		}
	}
	RVecAnalRef_free (refs);
	mu_assert_eq (bcc20_ref (core->anal, 0x668a9, 0x543a6), R_ANAL_REF_TYPE_DATA, "proved manager/stub/body join remains inspectable as DATA");
	const ut64 near[][2] = { { 0x6fa4c, 0x6fb03 }, { 0x70063, 0x70168 }, { 0x7008d, 0x70107 }, { 0x7017b, 0x70107 }, { 0x70279, 0x70168 }, { 0x70285, 0x70168 } };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (near); i++) {
		mu_assert_eq (bcc20_ref (core->anal, near[i][0], near[i][1]), R_ANAL_REF_TYPE_CALL, "actual original near CALL retains high window coordinates");
	}
	RListIter *iter, *block_iter;
	RAnalFunction *fcn;
	RAnalBlock *bb;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (fcn->addr < 0x40010000) {
			continue;
		}
		r_list_foreach (fcn->bbs, block_iter, bb) {
			mu_assert_true (bb->jump == UT64_MAX || bb->jump >> 16 == fcn->addr >> 16, "no out-of-window executable BB jump");
			mu_assert_true (bb->fail == UT64_MAX || bb->fail >> 16 == fcn->addr >> 16, "no out-of-window executable BB fail");
		}
	}
	// The same actual resident helper is decoded normally; qualification never changes global MZ mode/granularity.
	mu_assert_eq (core->anal->config->seggrn, 4, "native MZ granularity unchanged after edge qualification");
	r_core_free (core);
	mu_end;
}

static bool test_bcc20_contiguous_native_mapping(void) {
	if (!getenv ("R2_TEST_BCC20")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 7; scenario++) {
		RCore *core = bcc20_original ();
		mu_assert_notnull (core, "actual contiguous native MZ section boundary");
		BorlandProfileContext ctx;
		mu_assert_true (bcc20_context (core, &ctx), "original contiguous mapping identity");
		mu_assert_eq (profile_mapped (&ctx, 0x1402, 0x16, true), 0x402, "complete copy function spans administrative native section boundary");
		mu_assert_eq (profile_mapped (&ctx, 0xba87, 0x21, true), 0xaa87, "complete compare function spans native section boundary");
		mu_assert_eq (profile_mapped (&ctx, 0xbf23, 0x2e, true), 0xaf23, "complete fill function spans native section boundary");
		ut8 copy[2], terminal[3];
		mu_assert_true (profile_current (&ctx, 0x140f, 2, 0x40f, copy), "whole REP MOVSB qualifies across native sections/maps");
		mu_assert_memeq (copy, "\xf3\xa4", 2, "native two-byte REP instruction is not split");
		mu_assert_true (profile_current (&ctx, 0xbf4e, 3, 0xaf4e, terminal), "whole RETF8 qualifies across native sections/maps");
		mu_assert_memeq (terminal, "\xca\x08\x00", 3, "native three-byte RETF instruction is not split");
		RBinSection *section, *first = NULL, *second = NULL;
		R_VEC_FOREACH (&ctx.file->bo->sections_vec, section) {
			if (section->add && section->paddr == 0x1000) {
				first = section;
			} else if (section->add && section->paddr == 0x1410) {
				second = section;
			}
		}
		mu_assert_notnull (first, "native leading section");
		mu_assert_notnull (second, "native adjacent section");
		RIOMap *map = r_io_map_get_at (core->io, 0x410);
		mu_assert_notnull (map, "native adjacent original-FD map");
		switch (scenario) {
		case 0: second->paddr++; second->vaddr++; second->size--; second->vsize--; break;
		case 1: second->vaddr++; break;
		case 2: first->size++; first->vsize++; break;
		case 3: map->fd++; break;
		case 4: map->perm = R_PERM_R; break;
		case 5: mu_assert_notnull (r_io_map_add (core->io, ctx.file->fd, R_PERM_RX, 0x140f, 0x5000040f, 2), "independent competing original-FD projection"); break;
		case 6: second->perm &= ~R_PERM_X; break;
		}
		mu_assert_eq (profile_mapped (&ctx, 0x1402, 0x16, true), UT64_MAX, "gaps/competing projections/wrong FD/section or active-map permission/aliases still refuse");
		r_core_free (core);
	}
	mu_end;
}

static bool test_bcc20_view_preservation(void) {
	if (!getenv ("R2_TEST_BCC20")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 3; scenario++) {
		RCore *core = bcc20_original ();
		mu_assert_notnull (core, "actual original for view conflict");
		BorlandProfileContext ctx;
		mu_assert_true (bcc20_context (core, &ctx), "exact original view context");
		RIOMap *map;
		if (!scenario) {
			map = r_io_map_add (core->io, ctx.file->fd, R_PERM_RX, 0x667c1, 0x40090000, 0x2c3);
			mu_assert_notnull (map, "independent map at fixed canonical coordinate");
		} else {
			mu_assert_true (bcc20_view (&ctx, 8), "exact constructor raw static view before independent edit");
			map = r_io_map_get_at (core->io, 0x40090000);
			if (scenario == 1) {
				ut8 patch = 0x90;
				mu_assert_eq (core->anal->iob.overlay_write_at (core->io, 0x400900e8, &patch, 1), 1, "manual raw CALLF opcode edit");
			} else {
				RBinSection *section;
				R_VEC_FOREACH (&ctx.file->bo->sections_vec, section) {
					if (!strcmp (section->name, "bcc20_fbov_0498_analysis")) {
						section->vaddr++;
					}
				}
			}
		}
		ut32 id = map->id;
		ut64 backing = map->delta;
		mu_assert_eq (borland_bcc20_profile (core->anal), 0, "view conflict stops dependent finite fact application");
		mu_assert_ptreq (r_io_map_get (core->io, id), map, "conflicting map identity is never replaced");
		mu_assert_eq (map->delta, backing, "conflicting original-FD backing remains unchanged");
		mu_assert_eq (map->itv.addr, 0x40090000, "no alternate analysis namespace chosen");
		mu_assert_null (r_anal_get_function_at (core->anal, 0x400900d9), "no constructor fact after view refusal");
		mu_assert_null (r_flag_get (core->flags, "bcc20_construct_two_array_node"), "no dependent function label");
		if (scenario == 1) {
			ut8 current;
			mu_assert_true (r_io_read_at (core->io, 0x400900e8, &current, 1), "retained current opcode");
			mu_assert_eq (current, 0x90, "manual byte is never repaired");
		}
		r_core_free (core);
	}
	mu_end;
}

static bool test_bcc20_function_preservation(void) {
	if (!getenv ("R2_TEST_BCC20")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 5; scenario++) {
		RCore *core = bcc20_original ();
		mu_assert_notnull (core, "actual constructor function preservation");
		BorlandProfileContext ctx;
		mu_assert_true (bcc20_context (core, &ctx), "actual function identity");
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (expected_views); i++) {
			mu_assert_true (bcc20_view (&ctx, i), "production original-backed view preparation only");
		}
		ctx.bcc20_static_views = true;
		mu_assert_true (profile_function (&ctx, 0x66899, 0x67, "bcc20_construct_two_array_node", 8, NULL), "actual complete constructor before independent edit");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x400900d9);
		if (!scenario) {
			r_anal_function_rename (fcn, "user_owned_bcc20_constructor");
		} else if (scenario == 1) {
			RAnalFunctionSignature signature = { .ret_type = "uint32_t", .params = r_list_new () };
			mu_assert_true (r_anal_function_set_signature (core->anal, fcn, &signature), "independent user return contract");
			r_list_free (signature.params);
		} else if (scenario == 2) {
			RAnalBlock *last = r_list_last (fcn->bbs);
			r_anal_block_set_size (last, last->size - 1);
		} else if (scenario == 3) {
			r_meta_set (core->anal, R_META_TYPE_DATA, 0x400900d9, 1, "user owned constructor data");
		} else {
			r_anal_hint_set_size (core->anal, 0x400900e8, 1);
		}
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x400900d9, "manual constructor annotation");
		int expected = scenario == 4? 0: 43;
		mu_assert_eq (borland_bcc20_profile (core->anal), expected, "independent function/body/metadata/contract/hint preserved and refused");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x400900d9), fcn, "independent function identity retained");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x400900d9), "manual constructor annotation", "refused body stops dependent function qualification comment");
		mu_assert_eq (bcc20_ref (core->anal, 0x668a9, 0x543a6), 0, "refused constructor stops dependent FAR DATA relation");
		if (!scenario) {
			mu_assert_streq (fcn->name, "user_owned_bcc20_constructor", "manual function name retained");
		} else if (scenario == 1) {
			RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
			mu_assert_streq (signature->ret_type, "uint32_t", "manual return type retained");
			r_anal_function_signature_free (signature);
		} else if (scenario == 3) {
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_DATA, 0x400900d9), "user owned constructor data", "manual data metadata retained");
		}
		r_core_free (core);
	}
	mu_end;
}

static bool test_bcc20_data_and_reference_preservation(void) {
	if (!getenv ("R2_TEST_BCC20")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 4; scenario++) {
		RCore *core = bcc20_original ();
		mu_assert_notnull (core, "actual finite data/reference preservation");
		r_anal_types_prepare (core->anal);
		if (!scenario) {
			mu_assert_true (r_anal_types_set_link (core->anal, "uint16_t [3]", 0xf766), "independent option object type");
		} else if (scenario == 1) {
			r_meta_set (core->anal, R_META_TYPE_DATA, 0xf766, 8, "manual option bytes");
		} else if (scenario == 2) {
			BorlandProfileContext ctx;
			mu_assert_true (bcc20_context (core, &ctx), "original source-pair context");
			mu_assert_true (bcc20_view (&ctx, 2) && bcc20_view (&ctx, 8), "actual raw source/target views before independent reference");
			mu_assert_true (r_anal_xrefs_set (core->anal, 0x400900e9, 0x40030056, R_ANAL_REF_TYPE_CODE), "independent actual source-pair reference type");
		} else {
			const HelperMember independent[] = { { "user_owned", "uint8_t", 0 } };
			mu_assert_true (borland_record (core->anal, "bcc20_InstructionDescriptor19Partial", 152, independent, 1), "independent descriptor type layout");
		}
		mu_assert_eq (borland_bcc20_profile (core->anal), 44, "independent data/reference state does not redefine complete code");
		if (scenario < 2) {
			mu_assert_null (r_flag_get (core->flags, "bcc20_option_S_row"), "preserved row stops dependent label");
			mu_assert_eq (bcc20_ref (core->anal, 0x10768, 0x43dfc), 0, "preserved data object stops dependent handler DATA join");
			if (!scenario) {
				mu_assert_true (bcc20_link (core->anal, 0x10766, "uint16_t [3]"), "independent row type retained");
			} else {
				mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_DATA, 0xf766), "manual option bytes", "manual metadata retained");
			}
		} else if (scenario == 2) {
			mu_assert_eq (bcc20_ref (core->anal, 0x668a9, 0x543a6), R_ANAL_REF_TYPE_CODE, "manual same-pair reference not rewritten to DATA");
			mu_assert_null (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x400900e9), "refused relation stops dependent raw-FAR annotation");
		} else {
			RAnalBaseType *type = r_anal_get_base_type (core->anal, "bcc20_InstructionDescriptor19Partial");
			mu_assert_eq (RVecAnalTypeMember_length (&type->struct_data.members), 1, "manual partial type not replaced");
			mu_assert_streq (RVecAnalTypeMember_at (&type->struct_data.members, 0)->name, "user_owned", "manual field role retained");
			r_anal_base_type_free (type);
			mu_assert_null (r_flag_get (core->flags, "bcc20_descriptor_xor_request"), "type refusal stops all dependent descriptor labels");
			mu_assert_false (bcc20_link (core->anal, 0x13465, "bcc20_InstructionDescriptor19Partial"), "type refusal installs no descriptor instance");
		}
		r_core_free (core);
	}
	mu_end;
}

static bool bcc20_activate(RCore *core, bool pre, int *count) {
	if (pre) {
		mu_assert_streq (r_config_get (core->config, "anal.plugins.pre"), "", "unchanged default registered PRE selection");
		r_anal_plugin_action (core->anal, R_ANAL_PLUGIN_ACTION_PRE_ANALYSIS, NULL);
		eprintf ("Default registered BCC20 PRE boundary invoked; downstream aa/aaa is not claimed\n");
		return true;
	}
	char *output = r_core_cmd_str (core, "a:borland");
	mu_assert_notnull (output, "ordinary registered RCore command output");
	mu_assert_eq (sscanf (output, "Borland: %d function contracts qualified", count), 1, "registered production count");
	eprintf ("Registered BCC20 command: %s", output);
	free (output);
	return true;
}

static bool test_bcc20_registered_facts_and_preservation(void) {
	if (!getenv ("R2_TEST_BCC20")) {
		mu_end;
	}
	int pre;
	for (pre = 0; pre < 2; pre++) {
		RCore *core = bcc20_original ();
		mu_assert_notnull (core, "exact original for registered BCC20 path");
		BorlandProfileContext ctx;
		mu_assert_true (bcc20_context (core, &ctx), "registered original identity without private application");
		mu_assert_null (r_io_map_get_at (core->io, 0x40090000), "no private view preparation before registered path");
		mu_assert_null (r_anal_get_function_at (core->anal, 0x400900d9), "no private constructor application before registered path");
		int count = 0;
		mu_assert_true (bcc20_activate (core, pre, &count), "actual ordinary command or default PRE");
		mu_assert_true (bcc20_check_facts (core, &ctx), "registered path alone installs every source-accounted fact");
		RVecAnalRef *refs = r_anal_refs_get (core->anal, 0x400900e8);
		RAnalRef *ref;
		if (refs) {
			R_VEC_FOREACH (refs, ref) {
				mu_assert_true (R_ANAL_REF_TYPE_MASK (ref->type) != R_ANAL_REF_TYPE_CALL && R_ANAL_REF_TYPE_MASK (ref->type) != R_ANAL_REF_TYPE_CODE, "registered raw CALLF witness has no false executable reference");
			}
		}
		RVecAnalRef_free (refs);
		if (!pre) {
			mu_assert_eq (count, 44, "ordinary command qualifies all44 BCC20 functions");
		}
		int functions = r_list_length (core->anal->fcns), labels = r_flag_count (core->flags, NULL);
		ut64 references = r_anal_xrefs_count (core->anal), epoch = r_anal_types_dirty_epoch (core->anal);
		size_t sections = RVecRBinSection_length (&ctx.file->bo->sections_vec);
		RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
		mu_assert_notnull (bank, "native bank for registered static views");
		int maps = r_list_length (bank->maprefs);
		char *comment = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, bcc20_address (0x63cb2)));
		mu_assert_true (bcc20_activate (core, pre, &count), "equivalent rerun through the same registered route");
		mu_assert_true (bcc20_check_facts (core, &ctx), "all facts survive equivalent registered rerun");
		mu_assert_true (bcc20_activate (core, false, &count), "ordinary command after either registered route");
		mu_assert_eq (count, 44, "equivalent registered count remains44");
		mu_assert_eq (r_list_length (core->anal->fcns), functions, "registered rerun creates no duplicate functions");
		mu_assert_eq (r_flag_count (core->flags, NULL), labels, "registered rerun creates no duplicate labels");
		mu_assert_eq (r_anal_xrefs_count (core->anal), references, "registered rerun creates no duplicate references");
		mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "registered rerun creates no duplicate types or links");
		mu_assert_eq (RVecRBinSection_length (&ctx.file->bo->sections_vec), sections, "registered rerun creates no duplicate sections");
		mu_assert_eq (r_list_length (bank->maprefs), maps, "registered rerun creates no duplicate maps");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, bcc20_address (0x63cb2)), comment, "registered rerun creates no duplicate qualifications");
		free (comment);
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x400900d9);
		ut64 size = r_anal_function_realsize (fcn);
		r_anal_function_rename (fcn, "user_owned_registered_bcc20_constructor");
		RAnalFunctionSignature signature = { .ret_type = "uint32_t", .params = r_list_new () };
		mu_assert_true (r_anal_function_set_signature (core->anal, fcn, &signature), "independent registered function return contract");
		r_list_free (signature.params);
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x400900d9, "manual registered constructor");
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x400900e9, "manual registered FAR operand");
		mu_assert_true (bcc20_activate (core, pre, &count), "same registered route preserves independent function state");
		mu_assert_true (bcc20_activate (core, false, &count), "ordinary command retains the registered refusal");
		mu_assert_eq (count, 43, "registered count reports exactly one independent function refusal");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x400900d9), fcn, "registered route retains independent function identity");
		mu_assert_streq (fcn->name, "user_owned_registered_bcc20_constructor", "registered route retains independent function name");
		mu_assert_eq (r_anal_function_realsize (fcn), size, "registered route retains independent function body");
		RAnalFunctionSignature *actual = r_anal_function_get_signature (fcn);
		mu_assert_streq (actual->ret_type, "uint32_t", "registered route retains independent return contract");
		r_anal_function_signature_free (actual);
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x400900d9), "manual registered constructor", "refused function gets no dependent qualification");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x400900e9), "manual registered FAR operand", "refused function stops dependent FAR annotation");
		r_core_free (core);
	}
	mu_end;
}

static bool test_bcc20_registered_current_refusal(void) {
	if (!getenv ("R2_TEST_BCC20")) {
		mu_end;
	}
	int pre, scenario;
	for (pre = 0; pre < 2; pre++) {
		for (scenario = 0; scenario < 2; scenario++) {
			RCore *core = bcc20_original ();
			mu_assert_notnull (core, "registered current-state preservation original");
			int count = 0;
			mu_assert_true (bcc20_activate (core, pre, &count), "registered preparation before independent current edit");
			BorlandProfileContext ctx;
			mu_assert_true (bcc20_context (core, &ctx), "registered current-state exact identity");
			mu_assert_true (bcc20_check_facts (core, &ctx), "all facts exist before independent current edit");
			RIOMap *map = r_io_map_get_at (core->io, 0x40090000);
			mu_assert_notnull (map, "registered original-FD constructor map");
			ut32 id = map->id;
			if (scenario) {
				map->delta++;
			} else {
				ut8 patch = 0x90;
				mu_assert_eq (core->anal->iob.overlay_write_at (core->io, 0x400900e8, &patch, 1), 1, "manual current CALLF opcode edit");
			}
			ut64 backing = map->delta;
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x400900d9, "manual current constructor");
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x400900e9, "manual current FAR operand");
			mu_assert_true (bcc20_activate (core, pre, &count), "same registered route refuses the current edit");
			mu_assert_true (bcc20_activate (core, false, &count), "ordinary command retains current-view refusal");
			mu_assert_eq (count, 0, "registered view refusal stops dependent profile facts");
			mu_assert_ptreq (r_io_map_get (core->io, id), map, "registered refusal does not replace the independent map");
			mu_assert_eq (map->delta, backing, "registered refusal does not repair independent backing geometry");
			mu_assert_eq (map->itv.addr, 0x40090000, "registered refusal does not choose another namespace");
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x400900d9), "manual current constructor", "current refusal stops dependent function annotation");
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x400900e9), "manual current FAR operand", "current refusal stops dependent FAR annotation");
			if (!scenario) {
				ut8 current;
				mu_assert_true (r_io_read_at (core->io, 0x400900e8, &current, 1), "retained current opcode after registered refusal");
				mu_assert_eq (current, 0x90, "registered refusal never repairs current bytes");
			}
			r_core_free (core);
		}
	}
	mu_end;
}

static bool all_tests(void) {
	mu_run_test (test_bcc20_complete_owner);
	mu_run_test (test_bcc20_control_edges);
	mu_run_test (test_bcc20_contiguous_native_mapping);
	mu_run_test (test_bcc20_view_preservation);
	mu_run_test (test_bcc20_function_preservation);
	mu_run_test (test_bcc20_data_and_reference_preservation);
	mu_run_test (test_bcc20_registered_facts_and_preservation);
	mu_run_test (test_bcc20_registered_current_refusal);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
