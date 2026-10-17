#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_simtower_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland

static RCore *simtower_core(void) {
	const char *path = getenv ("R2_TEST_SIMTOWER");
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

static bool command_profile(RCore *core) {
	char *output = r_core_cmd_str (core, "a:borland");
	bool valid = output && strstr (output, "function contracts qualified");
	free (output);
	return valid;
}

static bool original_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "ne", 6566400, "2825a3c53f77945c63b6d72e26faa7dde5ddd56c31ca668e67a12576d7feca96");
}

static int reference_type(RAnal *anal, ut64 from, ut64 to) {
	RVecAnalRef *refs = r_anal_refs_get (anal, from);
	int type = 0;
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			if (ref->addr == to) {
				type = ref->type;
			}
		}
	}
	RVecAnalRef_free (refs);
	return type;
}

static bool profile_comment(RAnal *anal, ut64 at, const char *text) {
	const char *comment = r_meta_get_string (anal, R_META_TYPE_COMMENT, at);
	return comment && strstr (comment, text);
}

static bool label_at(RCore *core, const char *name, ut64 at) {
	RFlagItem *flag = r_flag_get (core->flags, name);
	return flag && flag->addr == at;
}

static bool test_simtower_production_complete_facts(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		eprintf ("Complete SimTower production proof not run: set R2_TEST_SIMTOWER to the read-only exact original; no synthetic substitute establishes these facts\n");
		mu_end;
	}
	RCore *core = simtower_core ();
	mu_assert_notnull (core, "actual native SimTower open");
	BorlandProfileContext ctx;
	mu_assert_true (original_context (core, &ctx), "actual original SHA/format/size/read-only identity");
	mu_assert_null (r_anal_get_function_at (core->anal, 0x1200a), "not prepopulated by a direct profile helper");
	char *output = r_core_cmd_str (core, "a:borland");
	mu_assert_notnull (output, "ordinary production command output");
	mu_assert_notnull (strstr (output, "35 function contracts qualified"), "28 profile facts plus the existing7 native helpers ran through dispatch");
	free (output);
	const struct { ut64 address; int size; int purge; const char *name; } functions[] = {
		{0x100c9,18,0,"simtower_crt45_candidate_cleanup"}, {0x100db,1,0,"simtower_crt45_candidate_checknull"},
		{0x100dc,1,0,"simtower_crt45_candidate_restorezero"}, {0x100f2,3,0,"simtower_crt45_candidate_GetDGROUP"},
		{0x100f5,68,0,"simtower_startup_init_dispatch"}, {0x10139,65,0,"simtower_startup_exit_dispatch"},
		{0x12e24,69,10,"simtower_sprintf_copy_callback"}, {0x12e69,39,0,"simtower_crt45_candidate_sprintf"},
		{0x12e90,38,0,"simtower_crt45_candidate_vsprintf"}, {0x1200a,1095,12,"simtower_crt45_candidate_VPRINTER"},
		{0x12024,13,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_vprinter_scan_entry"}, {0x12031,9,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_vprinter_emit_entry"},
		{0x1203a,52,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_vprinter_flush_entry"}, {0x13e6a,5,0,"simtower_crt45_candidate_exit_dummy"},
		{0x13e6f,124,6,"simtower_crt45_candidate_exit_local_helper"}, {0x13eeb,21,0,"simtower_crt45_candidate_exit"},
		{0x13f00,21,0,"simtower_crt45_candidate__exit"}, {0x13f15,14,0,"simtower_crt45_candidate__cexit"},
		{0x13f23,14,0,"simtower_crt45_candidate__c_exit"}, {0x4f0000,10,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_terminate"},
		{0x4f000a,92,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_set_terminate"}, {0x4f0090,179,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_call_terminate"},
		{0x4f0143,9,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_unexpected"}, {0x4f014c,92,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_set_unexpected"},
		{0x4f01a8,131,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_call_unexpected"}, {0x4f022b,84,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_GetPolymorphicDTC"},
		{0x4f027f,88,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_GetPolymorphicDTCfar"}, {0x4f02d7,122,R_ANAL_CC_STACK_POP_UNKNOWN,"simtower_crt45_candidate_ExceptInit"}
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (functions); i++) {
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, functions[i].address);
		mu_assert_notnull (fcn, "each of28 source-established native entries");
		mu_assert_streq (fcn->name, functions[i].name, "qualified analysis name, not historical debug identity");
		mu_assert_eq (r_anal_function_realsize (fcn), functions[i].size, "complete exclusive body, not bounding region");
		mu_assert_eq (fcn->meta.stack_pop, functions[i].purge, "known integer versus source UNKNOWN");
		mu_assert_true (profile_comment (core->anal, functions[i].address, "not original debug symbols"), "qualification limits retained on every function");
	}
	RAnalFunction *main = r_anal_get_function_at (core->anal, 0x1200a);
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (main->bbs, iter, bb) {
		mu_assert_true (bb->addr + bb->size <= 0x12024 || bb->addr >= 0x1206e, "main excludes all74 independent helper bytes");
	}
	mu_assert_null (r_anal_get_function_at (core->anal, 0x1206e), "continuation is not a manufactured callee");
	RAnalBlock *entry = r_list_first (main->bbs);
	mu_assert_eq (entry->jump, 0x1206e, "literal EB4A remains native branch");
	const int helper_calls[][2] = {{0x22db,0x2024},{0x233b,0x2024},{0x236d,0x2024},{0x23c1,0x2031},{0x23d2,0x2031},{0x23d8,0x2031},{0x23f7,0x2031},{0x2402,0x2031},{0x2425,0x2031},{0x2474,0x2031},{0x2090,0x203a},{0x2418,0x203a},{0x2483,0x203a}};
	for (i = 0; i < R_ARRAY_SIZE (helper_calls); i++) {
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x10000 + helper_calls[i][0], 0x10000 + helper_calls[i][1])), R_ANAL_REF_TYPE_CALL, "all13 real private near CALLs");
	}
	RAnalFunction *emitter = r_anal_get_function_at (core->anal, 0x12031);
	bb = r_list_first (emitter->bbs);
	mu_assert_eq (bb->jump, 0x1206d, "emitter shared RET edge");
	mu_assert_eq (bb->fail, 0x1203a, "emitter independent flush fallthrough");
	const struct { ut64 address; int size; const char *type; } data[] = {
		{0x520030,70,"StartupData70Partial"},{0x1249b,48,"uint16_t [24]"},{0x520b5c,7,"uint8_t [7]"},
		{0x520b63,96,"uint8_t [96]"},{0x521036,14,"ExitData14Partial"},{0x4f0066,42,"uint8_t [42]"},{0x5207ec,296,"XxvInitialized296Partial"}
	};
	for (i = 0; i < R_ARRAY_SIZE (data); i++) {
		char key[48];
		snprintf (key, sizeof (key), "link.%08"PFMT64x, data[i].address);
		mu_assert_streq (sdb_const_get (core->anal->sdb_types, key, NULL), data[i].type, "all seven native aggregate/array type links");
		mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, data[i].type), data[i].size * 8, "full data extent including undefined gaps");
		mu_assert_null (r_anal_get_function_at (core->anal, data[i].address), "raw data is not another selected function");
	}
	const struct { const char *name; int count; int offsets[11]; int widths[11]; } layouts[] = {
		{"FarStorage16",2,{0,2},{2,2}},
		{"StartupData70Partial",11,{2,4,6,8,10,12,14,16,18,25,27},{2,2,2,2,2,2,2,2,2,2,43}},
		{"ExitData14Partial",4,{0,4,8,12},{4,4,4,2}},
		{"XxvInitialized296Partial",4,{10,14,18,20},{4,4,2,2}}
	};
	for (i = 0; i < R_ARRAY_SIZE (layouts); i++) {
		RAnalBaseType *layout = r_anal_get_base_type (core->anal, layouts[i].name);
		mu_assert_notnull (layout, "production-created partial native record");
		mu_assert_eq (RVecAnalTypeMember_length (&layout->struct_data.members), layouts[i].count, "only source-established fields, no inferred gap/public extents");
		int field;
		for (field = 0; field < layouts[i].count; field++) {
			RAnalTypeMember *member = RVecAnalTypeMember_at (&layout->struct_data.members, field);
			mu_assert_eq (member->offset, layouts[i].offsets[field], "each established native field offset");
			mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, member->type) * (member->count? member->count: 1), layouts[i].widths[field] * 8, "each established field/array width");
			mu_assert_eq (member->bitsize, 0, "no invented bitfields");
		}
		r_anal_base_type_free (layout);
	}
	ut64 field_size;
	r_meta_get_at (core->anal, 0x521036, R_META_TYPE_DATA, &field_size);
	mu_assert_eq (field_size, 4, "EXIT aggregate does not resize the retained first FAR field");
	mu_assert_notnull (r_meta_get_in (core->anal, 0x52004b, R_META_TYPE_STRING), "copyright STRING view retained");
	const struct { ut64 address; const char *name; } labels[] = {
		{0x10000,"simtower_c0wl45_startup_correspondence"},{0x10056,"simtower_c0wl45_public_candidate_56"},{0x100b2,"simtower_c0wl45_public_candidate_b2"},{0x100dd,"simtower_c0wl45_public_candidate_dd"},{0x520030,"simtower_c0wl45_initialized_data70"},
		{0x11ff2,"simtower_vprinter_conversion_cluster24"},{0x1206d,"simtower_vprinter_emit_flush_shared_ret"},{0x1249b,"simtower_vprinter_dispatch_words24"},{0x520b5c,"simtower_vprinter_null_text7"},{0x520b63,"simtower_vprinter_dispatch_indices96"},
		{0x521036,"simtower_crt45_candidate___exitbuf"},{0x52103a,"simtower_crt45_candidate___exitfopen"},{0x52103e,"simtower_crt45_candidate___exitopen"},{0x4f0066,"simtower_xxv_raw_table42"},
		{0x5207ec,"simtower_crt45_candidate_CPPexceptionList"},{0x5207f0,"simtower_crt45_candidate_exceptFlags"},{0x5207f2,"simtower_crt45_candidate_savedDS"},{0x5207f4,"simtower_crt45_candidate_savedSI"},{0x5207f6,"simtower_crt45_candidate_terminatePTR"},{0x5207fa,"simtower_crt45_candidate_unexpectdPTR"},
		{0x5207fe,"simtower_crt45_candidate_terminate_DS"},{0x520800,"simtower_crt45_candidate_unexpectd_DS"},{0x520802,"simtower_crt45_candidate_throwFileName"},{0x520806,"simtower_crt45_candidate_throwLineNumber"},{0x520808,"simtower_crt45_candidate_throwExceptionName"},{0x52080c,"simtower_crt45_candidate_exceptStaticBuffP"},{0x520810,"simtower_crt45_candidate_exceptMemAllocVars"},{0x520814,"simtower_crt45_candidate_exceptionNameBuff"},{0x520894,"simtower_crt45_candidate_ExceptStaticXbuff"}
	};
	for (i = 0; i < R_ARRAY_SIZE (labels); i++) {
		mu_assert_true (label_at (core, labels[i].name, labels[i].address), "all29 explicit source labels");
	}
	mu_assert_null (r_flag_get (core->flags, "simtower_crt45_candidate_DestructorCountPtr"), "unplaced BSS remains unplaced");
	const ut64 far_refs[][2] = {{0x10007,0x4f02d7},{0x100b3,0x4e0013},{0x521036,0x13e6a},{0x52103a,0x13e6a},{0x52103e,0x13e6a},{0x5207f6,0x4f0000},{0x5207fa,0x4f0143},{0x4f006a,0x4f0129},{0x4f0088,0x4f0066}};
	for (i = 0; i < R_ARRAY_SIZE (far_refs); i++) {
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, far_refs[i][0], far_refs[i][1])), R_ANAL_REF_TYPE_DATA, "selected native FAR DATA relation");
	}
	const int client_fields[] = {0x15,0x3d,0xae,0xd3,0xec,0x102,0x157,0x17f,0x1b3,0x1d3,0x1ec,0x202,0x2fc,0x311,0x32c};
	for (i = 0; i < R_ARRAY_SIZE (client_fields); i++) {
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x4f0000 + client_fields[i], 0x11d4c)), R_ANAL_REF_TYPE_DATA, "all15 native EH_GetClientData bindings, not prototypes");
	}
	const int dependencies[][2] = {{3,0x3e26},{0x132,0x3e26},{0x222,0x3e26},{0xa8,0x259e},{0x2ef,0x1a55},{0x304,0x1e47}};
	for (i = 0; i < R_ARRAY_SIZE (dependencies); i++) {
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x4f0000 + dependencies[i][0], 0x10000 + dependencies[i][1])), R_ANAL_REF_TYPE_DATA, "all six native supplier dependencies");
	}
	const int dispatch[] = {0x20f9,0x20e3,0x212e,0x20ee,0x215c,0x2169,0x21a7,0x21ae,0x21b3,0x2117,0x21dc,0x21ba,0x21be,0x21c2,0x223c,0x22e9,0x228c,0x22ac,0x242d,0x2469,0x2469,0x2469,0x2109,0x210f};
	for (i = 0; i < R_ARRAY_SIZE (dispatch); i++) {
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x1249b + 2 * i, 0x10000 + dispatch[i])), R_ANAL_REF_TYPE_DATA, "all24 dispatch cells remain DATA relations");
	}
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x120de, 0x1249b)), R_ANAL_REF_TYPE_DATA, "separate table operand relation");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x12e77, 0x12e24)), R_ANAL_REF_TYPE_DATA, "first SPRINTF callback offset");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x12e9e, 0x12e24)), R_ANAL_REF_TYPE_DATA, "second SPRINTF callback offset");
	const ut64 converted[] = {0x100bf,0x100c4,0x100e9,0x12e3c,0x13eb5,0x13ebe,0x13ec3,0x13edf,0x4f009f,0x4f012c,0x4f0139};
	for (i = 0; i < R_ARRAY_SIZE (converted); i++) {
		mu_assert_true (profile_comment (core->anal, converted[i], "complete five-byte NOP/PUSH CS/near CALL window"), "all11 complete converted-call windows");
	}
	const struct { ut64 address; const char *name; } imports[] = {{0x10010,"INITTASK"},{0x10049,"WAITEVENT"},{0x10052,"USER5"},{0x10065,"GETWINFLAGS"},{0x13e87,"GETMODULEUSAGE"}};
	for (i = 0; i < R_ARRAY_SIZE (imports); i++) {
		mu_assert_true (profile_comment (core->anal, imports[i].address, imports[i].name), "all five qualified native import observations, including distinct USER");
	}
	const ut64 direct_calls[] = {0x12e88,0x12eae,0x1222a,0x12325};
	for (i = 0; i < R_ARRAY_SIZE (direct_calls); i++) {
		mu_assert_true (profile_comment (core->anal, direct_calls[i], "No stronger callee effects inferred"), "all four explicit direct near-call observations");
	}
	mu_assert_true (profile_comment (core->anal, 0x120cf, "stored DATA0b63"), "dispatch-index DATA placement observation");
	mu_assert_true (profile_comment (core->anal, 0x122d9, "NULL-fallback DATA0b5c"), "separate NULL-fallback DATA placement observation");
	mu_assert_true (profile_comment (core->anal, 0x12022, "original EB4A JMP"), "qualified native main branch annotation, not override removal");
	mu_assert_true (profile_comment (core->anal, 0x4f009a, "native SEG relocation"), "selector field remains independently observed");
	mu_assert_true (profile_comment (core->anal, 0x4f009d, "native OFF16L relocation"), "offset field remains independently observed");
	const int startup_words[] = {0x24,0x28,0x2c,0x30,0x34,0x3b,0x3e,0x4f,0x62,0x70,0x7b,0x8f,0x96,0x99,0xa0,0xa4,0xa8,0xac,0xb0,0xba,0xd0,0xd3};
	for (i = 0; i < R_ARRAY_SIZE (startup_words); i++) {
		mu_assert_true (profile_comment (core->anal, 0x10000 + startup_words[i], "stored startup binding WORD"), "all22 stored startup observations");
	}
	const int exit_words[] = {0x1a,0x28,0x2f,0x37,0x3b,0x42,0x46,0x52,0x6c,0x70};
	for (i = 0; i < R_ARRAY_SIZE (exit_words); i++) {
		mu_assert_true (profile_comment (core->anal, 0x13e6a + exit_words[i], "Stored placement correspondence only"), "all10 EXIT stored bindings");
	}
	const int xxv_words[] = {0x2db,0x2e6,0x2ea,0x2f5,0x2f8,0x30a,0x30d,0x349,0x34c};
	for (i = 0; i < R_ARRAY_SIZE (xxv_words); i++) {
		mu_assert_true (profile_comment (core->anal, 0x4f0000 + xxv_words[i], "stored NE82 offset"), "all nine XXV stored bindings");
	}
	mu_assert_true (profile_comment (core->anal, 0x4f0349, "DATA0800 corresponds to supplier0014"), "initializer source-field correspondence is retained without live DS inference");
	mu_assert_true (profile_comment (core->anal, 0x4f034c, "DATA07fe corresponds to supplier0012"), "separate initializer source-field correspondence");
	ut64 epoch = r_anal_types_dirty_epoch (core->anal);
	char *before = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x10000));
	r_flag_set (core->flags, "manual_equivalent_data", 0x520031, 1);
	r_anal_xrefs_set (core->anal, 0x520030, 0x10000, R_ANAL_REF_TYPE_DATA);
	RAnalFunction *unknown = r_anal_get_function_at (core->anal, 0x4f0000);
	unknown->meta.stack_pop = 8;
	mu_assert_true (command_profile (core), "ordinary production rerun");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "repeat does not recreate types/links");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x10000), before, "repeat comment idempotence");
	mu_assert_eq (unknown->meta.stack_pop, 8, "source UNKNOWN supplies no override to independent native inference");
	mu_assert_true (label_at (core, "manual_equivalent_data", 0x520031), "independent equivalent-data label retained");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x520030, 0x10000)), R_ANAL_REF_TYPE_DATA, "independent equivalent-data reference retained");
	free (before);
	r_core_free (core);
	mu_end;
}

static bool test_simtower_production_function_preservation(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 7; scenario++) {
		RCore *core = simtower_core ();
		mu_assert_notnull (core, "actual preservation input");
		BorlandProfileContext ctx;
		mu_assert_true (original_context (core, &ctx), "actual immutable original");
		const BorlandProfileRange ranges[] = {{0x420a,26},{0x426e,1069}};
		mu_assert_true (profile_function_ranges (&ctx, ranges, 2, "simtower_crt45_candidate_VPRINTER", 12, NULL), "install only the real main body as an independently edited fixture");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x1200a);
		RAnalBlock *entry = r_list_first (fcn->bbs);
		switch (scenario) {
		case 0: r_anal_hint_set_type (core->anal, 0x12022, R_ANAL_OP_TYPE_CALL); break;
		case 1: entry->jump = 0x12024; break;
		case 2: entry->size--; break;
		case 3: fcn->meta.stack_pop = 0; break;
		case 4: {
			ut8 zero = 0;
			core->anal->iob.overlay_write_at (core->io, 0x12499, &zero, 1);
			fcn->meta.stack_pop = 0;
			break;
		}
		case 5: r_anal_hint_set_bits (core->anal, 0x1200b, 32); r_anal_hint_set_bits (core->anal, 0x1200c, 16); break;
		case 6: {
			ut8 nop = 0x90;
			core->anal->iob.overlay_write_at (core->io, 0x1200a, &nop, 1);
			break;
		}
		}
		ut64 size = entry->size, jump = entry->jump;
		int pop = fcn->meta.stack_pop;
		mu_assert_true (command_profile (core), "actual production dispatch after independent edit");
		mu_assert_true (original_context (core, &ctx), "current overlay is not original-file identity");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x1200a), fcn, "main object not replaced");
		mu_assert_eq (entry->size, size, "independent main block extent retained");
		mu_assert_eq (entry->jump, jump, "independent main flow retained");
		mu_assert_eq (fcn->meta.stack_pop, pop, "independent main purge retained");
		mu_assert_false (profile_comment (core->anal, 0x1200a, "[LegacyToolchains simtower-runtime-qualified]"), "refused function receives no false profile-contract comment");
		mu_assert_false (profile_comment (core->anal, 0x12022, "original EB4A JMP"), "dependent main-flow annotation stopped");
		mu_assert_false (profile_comment (core->anal, 0x12e88, "supplier __VPRINTER dependency"), "refused main stops dependent selected-callee annotation");
		if (!scenario) {
			RAnalHint *hint = r_anal_hint_get (core->anal, 0x12022);
			mu_assert_notnull (hint, "override-only hint remains present");
			mu_assert_eq (hint->type, R_ANAL_OP_TYPE_CALL, "ordinary name/signature do not permit clearing intentional flow override");
			r_anal_hint_free (hint);
		}
		r_core_free (core);
	}
	RCore *core = simtower_core ();
	mu_assert_notnull (core, "actual manual name/signature input");
	BorlandProfileContext ctx;
	mu_assert_true (original_context (core, &ctx), "manual original identity");
	mu_assert_true (profile_function (&ctx, 0x5069, 39, "simtower_crt45_candidate_sprintf", 0, NULL), "real wrapper body fixture only");
	RAnalFunction *wrapper = r_anal_get_function_at (core->anal, 0x12e69);
	r_anal_function_rename (wrapper, "manual_sprintf");
	RAnalFunctionSignature signature = { .ret_type = "uint32_t" };
	mu_assert_true (r_anal_function_set_signature (core->anal, wrapper, &signature), "independent native prototype");
	r_meta_set_string (core->anal, R_META_TYPE_COMMENT, wrapper->addr, "manual comment");
	mu_assert_true (command_profile (core), "production name/signature preservation path");
	mu_assert_streq (wrapper->name, "manual_sprintf", "manual name retained");
	RAnalFunctionSignature *actual = r_anal_function_get_signature (wrapper);
	mu_assert_streq (actual->ret_type, "uint32_t", "manual prototype retained");
	r_anal_function_signature_free (actual);
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, wrapper->addr), "manual comment", "manual comment not changed by a refused function");
	mu_assert_eq (reference_type (core->anal, 0x12e77, 0x12e24), 0, "refused wrapper stops its dependent callback-offset DATA relation");
	r_core_free (core);
	core = simtower_core ();
	mu_assert_notnull (core, "actual imported field patch input");
	mu_assert_true (original_context (core, &ctx), "imported field original identity");
	mu_assert_true (profile_function (&ctx, 0x606f, 124, "simtower_crt45_candidate_exit_local_helper", 6, NULL), "real EXIT local body fixture");
	RAnalFunction *helper = r_anal_get_function_at (core->anal, 0x13e6f);
	ut8 field;
	r_io_read_at (core->io, 0x13e87, &field, 1);
	field ^= 1;
	core->anal->iob.overlay_write_at (core->io, 0x13e87, &field, 1);
	helper->meta.stack_pop = 0;
	mu_assert_true (command_profile (core), "production imported-current-field refusal");
	mu_assert_eq (helper->meta.stack_pop, 0, "patched import does not restore original purge6");
	mu_assert_eq (r_anal_function_realsize (helper), 124, "patched helper body retained");
	mu_assert_false (profile_comment (core->anal, 0x13e87, "GETMODULEUSAGE"), "patched import receives no dependent binding annotation");
	mu_assert_false (profile_comment (core->anal, 0x13eb5, "complete five-byte"), "refused source body stops converted-window annotations");
	r_core_free (core);
	mu_end;
}

static bool test_simtower_production_data_preservation(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 3; scenario++) {
		RCore *core = simtower_core ();
		mu_assert_notnull (core, "actual DATA70 conflict input");
		ut64 start = 0x520030;
		int size = 70;
		if (!scenario) {
			start -= 2;
			size = 74;
		} else if (scenario == 2) {
			start += 68;
			size = 4;
		}
		mu_assert_true (borland_record (core->anal, "ManualDataObject", size * 8, NULL, 0), "independent native sized object");
		mu_assert_true (r_anal_types_set_link (core->anal, "ManualDataObject", start), "independent object link");
		mu_assert_true (r_meta_set (core->anal, R_META_TYPE_DATA, start, size, NULL), "independent unsymbolized/crossing/tail definition");
		RAnalMetaItem *meta = r_meta_get_at (core->anal, start, R_META_TYPE_DATA, NULL);
		r_anal_xrefs_set (core->anal, start, 0x10000, R_ANAL_REF_TYPE_DATA);
		r_anal_xrefs_set (core->anal, start + size - 1, 0x10001, R_ANAL_REF_TYPE_CODE);
		if (!scenario) {
			r_flag_set (core->flags, "manual_crossing_data", start, size);
		}
		mu_assert_true (command_profile (core), "ordinary dispatch preserves conflicting native data");
		ut64 preserved_size;
		mu_assert_ptreq (r_meta_get_at (core->anal, start, R_META_TYPE_DATA, &preserved_size), meta, "full data object identity retained");
		mu_assert_eq (preserved_size, size, "full crossing/tail extent retained");
		char key[48];
		snprintf (key, sizeof (key), "link.%08"PFMT64x, start);
		mu_assert_streq (sdb_const_get (core->anal->sdb_types, key, NULL), "ManualDataObject", "independent type retained");
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, start, 0x10000)), R_ANAL_REF_TYPE_DATA, "first outgoing reference retained");
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, start + size - 1, 0x10001)), R_ANAL_REF_TYPE_CODE, "tail outgoing reference retained");
		mu_assert_null (r_flag_get (core->flags, "simtower_c0wl45_initialized_data70"), "refused data blocks dependent profile label");
		mu_assert_false (profile_comment (core->anal, 0x10024, "stored startup binding WORD"), "refused data blocks dependent layout assumptions");
		if (!scenario) {
			mu_assert_true (label_at (core, "manual_crossing_data", start), "independent crossing-object flag retained");
		}
		r_core_free (core);
	}
	RCore *core = simtower_core ();
	mu_assert_notnull (core, "actual pointer-valued switch cell input");
	r_anal_types_prepare (core->anal);
	mu_assert_true (r_anal_types_set_link (core->anal, "uint16_t *", 0x1249b), "independent pointer interpretation of real stored20f9");
	r_meta_set (core->anal, R_META_TYPE_DATA, 0x1249b, 2, NULL);
	RAnalMetaItem *cell = r_meta_get_at (core->anal, 0x1249b, R_META_TYPE_DATA, NULL);
	r_anal_xrefs_set (core->anal, 0x1249b, 0x120f9, R_ANAL_REF_TYPE_CODE);
	r_anal_xrefs_set (core->anal, 0x120db, 0x1249b, R_ANAL_REF_TYPE_DATA);
	mu_assert_true (command_profile (core), "production pointer-cell conflict path");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.0001249b", NULL), "uint16_t *", "pointer type not replaced by array");
	ut64 size;
	mu_assert_ptreq (r_meta_get_at (core->anal, 0x1249b, R_META_TYPE_DATA, &size), cell, "pointer cell not recreated");
	mu_assert_eq (size, 2, "pointer cell not resized to48");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x1249b, 0x120f9)), R_ANAL_REF_TYPE_CODE, "independent cell edge not retyped DATA");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x120db, 0x1249b)), R_ANAL_REF_TYPE_DATA, "independent incoming table edge retained");
	mu_assert_eq (reference_type (core->anal, 0x120de, 0x1249b), 0, "refused table blocks dependent stored-operand relation");
	mu_assert_null (r_flag_get (core->flags, "simtower_vprinter_dispatch_words24"), "refused table blocks dependent label");
	r_core_free (core);
	mu_end;
}

static bool test_simtower_production_switch_and_automatic_dispatch(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		mu_end;
	}
	RCore *core = simtower_core ();
	mu_assert_notnull (core, "actual automatic registry input");
	r_config_set (core->config, "anal.plugins.pre", "borland");
	r_anal_plugin_action (core->anal, R_ANAL_PLUGIN_ACTION_PRE_ANALYSIS, NULL);
	mu_assert_true (label_at (core, "simtower_c0wl45_startup_correspondence", 0x10000), "actual registered pre-analysis hook selected the full profile");
	mu_assert_true (label_at (core, "simtower_xxv_raw_table42", 0x4f0066), "automatic hook included late-group data");
	mu_assert_notnull (r_anal_get_function_at (core->anal, 0x4f02d7), "automatic hook included final XXV function");
	r_core_cmd0 (core, "afbt tbl=0x1249b esz=2 n=24 base=0x10000 @0x120db");
	RList *blocks = r_anal_get_blocks_in (core->anal, 0x120db);
	RAnalBlock *bb = r_list_first (blocks);
	mu_assert_notnull (bb, "real dispatch block");
	RAnalSwitchOp *switch_op = bb->switch_op;
	mu_assert_notnull (switch_op, "native switch from actual24 WORDs");
	mu_assert_eq (r_list_length (switch_op->cases), 24, "all cases including duplicates");
	ut64 cell_size;
	RAnalMetaItem *cells[24];
	RAnalCaseOp *cases[24], values[24];
	int cell_refs[24], case_refs[24];
	int i;
	for (i = 0; i < 24; i++) {
		cases[i] = r_list_get_n (switch_op->cases, i);
		values[i] = *cases[i];
		cells[i] = r_meta_get_at (core->anal, 0x1249b + 2 * i, R_META_TYPE_DATA, &cell_size);
		mu_assert_notnull (cells[i], "native afbt materialized each actual switch cell");
		mu_assert_eq (cell_size, 2, "native afbt independently divided aggregate markup into WORD cells");
		cell_refs[i] = reference_type (core->anal, 0x1249b + 2 * i, values[i].jump);
		case_refs[i] = reference_type (core->anal, 0x120db, values[i].jump);
	}
	// Reappearance of only this profile-owned marker decides successful dependent array dispatch.
	mu_assert_true (r_flag_unset_name (core->flags, "simtower_vprinter_dispatch_words24"), "remove only the profile marker before requalification");
	mu_assert_true (command_profile (core), "ordinary full-profile rerun with native switch metadata");
	mu_assert_true (label_at (core, "simtower_vprinter_dispatch_words24", 0x1249b), "structured array qualification now succeeds over independent native WORD cells");
	mu_assert_ptreq (bb->switch_op, switch_op, "real switch metadata not deleted/recreated");
	mu_assert_eq (r_list_length (switch_op->cases), 24, "all independent cases retained");
	for (i = 0; i < 24; i++) {
		mu_assert_ptreq (r_list_get_n (switch_op->cases, i), cases[i], "each independent case object retained");
		mu_assert_eq (cases[i]->addr, values[i].addr, "each case address retained");
		mu_assert_eq (cases[i]->jump, values[i].jump, "each case target retained");
		mu_assert_eq (cases[i]->value, values[i].value, "each case value retained");
		mu_assert_ptreq (r_meta_get_at (core->anal, 0x1249b + 2 * i, R_META_TYPE_DATA, &cell_size), cells[i], "each independent native cell retained");
		mu_assert_eq (cell_size, 2, "no cell resized to force an aggregate marker");
		mu_assert_eq (reference_type (core->anal, 0x1249b + 2 * i, values[i].jump), cell_refs[i], "each stored-cell reference retained");
		mu_assert_eq (reference_type (core->anal, 0x120db, values[i].jump), case_refs[i], "each native switch reference retained");
	}
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.0001249b", NULL), "uint16_t [24]", "qualified aggregate type link remains available alongside preserved cells");
	mu_assert_eq (r_anal_function_realsize (r_anal_get_function_at (core->anal, 0x1200a)), 1095, "independent switch views do not change exact main ownership");
	r_list_free (blocks);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_simtower_production_complete_facts);
	mu_run_test (test_simtower_production_function_preservation);
	mu_run_test (test_simtower_production_data_preservation);
	mu_run_test (test_simtower_production_switch_and_automatic_dispatch);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
