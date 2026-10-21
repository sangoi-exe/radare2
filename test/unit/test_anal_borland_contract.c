#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_contract_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland

#define WRITER_ADDR 0x3058
#define WRITER_NAME "tlink401_rewrite_far_window_cf"
#define WRITER_CC "tlink_writer_state_16near"
#define WRITER_RETURN "NearWriterAnalysisState7"

static const BorlandProfileRange writer_range = { 0x3458, 150 };

static RCore *writer_core(void) {
	const char *path = getenv ("R2_TEST_TLINK401");
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "bin.relocs.apply", true);
	if (!path || !r_core_file_open (core, path, R_PERM_RX, 0) || !r_core_bin_load (core, path, UT64_MAX)) {
		r_core_free (core);
		return NULL;
	}
	r_config_set_b (core->config, "io.va", true);
	r_anal_types_prepare (core->anal);
	// Native test fixture only; production runtime type creation belongs to the profile's type owner.
	RAnalBaseType *boolean = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	boolean->name = strdup ("bool");
	boolean->type = strdup ("b");
	boolean->size = 8;
	r_anal_save_base_type (core->anal, boolean);
	r_anal_base_type_free (boolean);
	const HelperMember members[] = {
		{ "accepted_cf", "bool", 0 }, { "dx", "uint16_t", 1 }, { "cx", "uint16_t", 3 }, { "es", "uint16_t", 5 }
	};
	if (!borland_record (core->anal, WRITER_RETURN, 56, members, R_ARRAY_SIZE (members))) {
		r_core_free (core);
		return NULL;
	}
	return core;
}

static bool writer_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "mz", 73401, "df1be38b22d43cc912992f1fcca93a5b630197721744ef2eea399f22d1415f0c");
}

static RAnalFunctionSignature writer_signature(void) {
	static RAnalFunctionParam params[] = {
		{ "entry_bx", "uint16_t" }, { "entry_cx", "uint16_t" }, { "entry_dx", "uint16_t" }, { "entry_ds", "uint16_t" }
	};
	RList *list = r_list_new ();
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (params); i++) {
		r_list_append (list, &params[i]);
	}
	return (RAnalFunctionSignature){ .prototype = R_TYPE_FUNC_PROTOTYPE_FIXED, .ret_type = WRITER_RETURN, .callconv = WRITER_CC, .params = list };
}

static bool writer_apply(BorlandProfileContext *ctx) {
	RAnalFunctionSignature signature = writer_signature ();
	bool result = profile_function_ranges_contract (ctx, &writer_range, 1, WRITER_NAME, 0,
		"Analysis-only CF/DX/CX/ES tuple; four native entry WORDs, not historical C or physical-I/O success.", &signature);
	r_list_free (signature.params);
	return result;
}

static bool test_writer_install_and_reapply(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		eprintf ("Typed writer original proof not run: set R2_TEST_TLINK401; native fixture types alone do not establish production profile application\n");
		mu_end;
	}
	int existing;
	for (existing = 0; existing < 3; existing++) {
		RCore *core = writer_core ();
		mu_assert_notnull (core, "normally loaded read-only TLINK401 original");
		BorlandProfileContext ctx;
		mu_assert_true (writer_context (core, &ctx), "exact original identity");
		mu_assert_eq (profile_mapped (&ctx, 0x3458, 150, true), WRITER_ADDR, "native resident writer coordinate");
		mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, WRITER_RETURN), 56, "seven-byte analysis tuple fixture");
		mu_assert_false (r_anal_cc_exist (core->anal, WRITER_CC), "opaque engine model needs no invented host definition");
		if (existing) {
			mu_assert_true (profile_function (&ctx, 0x3458, 150, WRITER_NAME, 0, "initial untyped body"), "ordinary qualified body");
			if (existing == 2) {
				r_anal_function_rename (r_anal_get_function_at (core->anal, WRITER_ADDR), "fcn.00003058");
			}
		}
		RAnalFunction *previous = r_anal_get_function_at (core->anal, WRITER_ADDR);
		mu_assert_true (writer_apply (&ctx), "four-input typed function admitted in the function owner");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, WRITER_ADDR);
		mu_assert_notnull (fcn, "native typed writer");
		if (previous) {
			mu_assert_ptreq (fcn, previous, "existing function retained");
		}
		mu_assert_eq (r_anal_function_realsize (fcn), 150, "complete writer body");
		mu_assert_eq (r_anal_function_max_addr (fcn), 0x30ee, "exclusive end");
		mu_assert_eq (fcn->meta.stack_pop, 0, "ordinary near return argument purge zero");
		mu_assert_streq (fcn->callconv, WRITER_CC, "exact source-established convention");
		RAnalFunctionSignature *actual = r_anal_function_get_signature (fcn);
		mu_assert_notnull (actual, "native signature snapshot");
		mu_assert_streq (actual->ret_type, WRITER_RETURN, "named analysis return");
		mu_assert_streq (actual->callconv, WRITER_CC, "signature convention");
		mu_assert_eq (actual->prototype, R_TYPE_FUNC_PROTOTYPE_FIXED, "the typed analysis contract has explicit fixed inputs");
		mu_assert_eq (r_list_length (actual->params), 4, "all four inputs survive the native API");
		const char *names[] = { "entry_bx", "entry_cx", "entry_dx", "entry_ds" };
		int i;
		for (i = 0; i < R_ARRAY_SIZE (names); i++) {
			RAnalFunctionParam *param = r_list_get_n (actual->params, i);
			mu_assert_streq (param->name, names[i], "entry WORD order");
			mu_assert_streq (param->type, "uint16_t", "native WORD type");
		}
		r_anal_function_signature_free (actual);
		RListIter *iter;
		RAnalBlock *bb;
		int instructions = 0;
		r_list_foreach (fcn->bbs, iter, bb) {
			instructions += bb->ninstr;
		}
		mu_assert_eq (instructions, 51, "all source-established instructions");
		mu_assert_false (profile_function (&ctx, 0x3458, 150, WRITER_NAME, 0, "untyped dependent annotation"), "untyped admission still refuses a typed contract");
		RAnalBlock *entry = r_list_first (fcn->bbs);
		RFlagItem *flag = r_flag_get (core->flags, WRITER_NAME);
		const char *cc = fcn->callconv;
		ut64 types_epoch = r_anal_types_dirty_epoch (core->anal), fcn_epoch = r_anal_function_dirty_epoch (fcn);
		char *types = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
		mu_assert_true (writer_apply (&ctx), "equivalent typed rerun is admitted");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, WRITER_ADDR), fcn, "same native function");
		mu_assert_ptreq (r_list_first (fcn->bbs), entry, "same native blocks");
		mu_assert_ptreq (r_flag_get (core->flags, WRITER_NAME), flag, "same native label");
		mu_assert_ptreq (fcn->callconv, cc, "same convention object");
		mu_assert_eq (r_anal_types_dirty_epoch (core->anal), types_epoch, "no repeated signature setter");
		mu_assert_eq (r_anal_function_dirty_epoch (fcn), fcn_epoch, "no repeated contract mutation");
		char *after = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
		mu_assert_streq (after, types, "no alternate prototype keys or links");
		free (types);
		free (after);
		r_core_free (core);
	}
	mu_end;
}

static bool test_writer_independent_state(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 15; scenario++) {
		RCore *core = writer_core ();
		mu_assert_notnull (core, "read-only original for independent state");
		BorlandProfileContext ctx;
		mu_assert_true (writer_context (core, &ctx), "independent-state original identity");
		mu_assert_true (writer_apply (&ctx), "initial typed writer");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, WRITER_ADDR);
		RAnalBlock *bb = r_list_first (fcn->bbs);
		switch (scenario) {
		case 0: r_anal_function_rename (fcn, "manual_writer"); break;
		case 1: fcn->meta.stack_pop = 2; break;
		case 2: bb->size--; break;
		case 3: bb->jump = WRITER_ADDR + 1; break;
		case 4: sdb_set (core->anal->sdb_types, "func."WRITER_NAME".arg.3", "uint16_t,manual_ds", 0); break;
		case 5: sdb_set (core->anal->sdb_types, "func."WRITER_NAME".ret", "uint16_t", 0); break;
		case 6: r_anal_function_store_callconv (core->anal, fcn, "manual_writer_cc"); break;
		case 7: sdb_set (core->anal->sdb_types, "func."WRITER_NAME".cc", "manual_prototype_cc", 0); break;
		case 8: r_anal_function_set_var (fcn, -2, R_ANAL_VAR_KIND_BPV, "uint16_t", 2, false, "manual_local"); break;
		case 9: fcn->is_noreturn = true; break;
		case 10: {
			ut8 byte = r_buf_read8_at (ctx.file->buf, 0x3458) ^ 1;
			core->anal->iob.overlay_write_at (core->io, WRITER_ADDR, &byte, 1);
			break;
		}
		case 11: r_anal_hint_set_bits (core->anal, WRITER_ADDR + 1, 32); r_anal_hint_set_bits (core->anal, WRITER_ADDR + 2, 16); break;
		case 12: sdb_set (core->anal->sdb_types, "func."WRITER_NAME".prototype", "unspecified", 0); break;
		case 13: sdb_unset (core->anal->sdb_types, "func."WRITER_NAME".prototype", 0); break;
		case 14: sdb_set (core->anal->sdb_types, "func."WRITER_NAME".prototype", "invalid", 0); break;
		}
		char *types = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
		char *name = strdup (fcn->name), *cc = strdup (fcn->callconv);
		ut64 size = bb->size, jump = bb->jump;
		int pop = fcn->meta.stack_pop;
		size_t vars = RVecAnalVarPtr_length (&fcn->vars);
		bool noreturn = fcn->is_noreturn;
		const char *refused_comment = "dependent annotation must not be added";
		RAnalFunctionSignature signature = writer_signature ();
		mu_assert_false (profile_function_ranges_contract (&ctx, &writer_range, 1, WRITER_NAME, 0, refused_comment, &signature), "independent contract/body/current context refuses dependent application");
		r_list_free (signature.params);
		mu_assert_ptreq (r_anal_get_function_at (core->anal, WRITER_ADDR), fcn, "conflicted function preserved");
		mu_assert_streq (fcn->name, name, "independent name retained");
		mu_assert_streq (fcn->callconv, cc, "independent convention retained");
		mu_assert_eq (bb->size, size, "body extent retained");
		mu_assert_eq (bb->jump, jump, "edge retained");
		mu_assert_eq (fcn->meta.stack_pop, pop, "purge retained");
		mu_assert_eq (RVecAnalVarPtr_length (&fcn->vars), vars, "independent variables retained");
		mu_assert_eq (fcn->is_noreturn, noreturn, "noreturn retained");
		mu_assert_null (strstr (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, WRITER_ADDR), refused_comment), "no dependent annotation after refusal");
		char *after = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
		mu_assert_streq (after, types, "independent signature and type storage untouched");
		free (types);
		free (after);
		free (name);
		free (cc);
		r_core_free (core);
	}
	mu_end;
}

static bool test_writer_existing_storage(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 10; scenario++) {
		RCore *core = writer_core ();
		mu_assert_notnull (core, "read-only original for type storage");
		BorlandProfileContext ctx;
		mu_assert_true (writer_context (core, &ctx), "type-storage original identity");
		Sdb *types = core->anal->sdb_types;
		if (scenario == 0) {
			mu_assert_true (r_type_set_link (types, "uint16_t", WRITER_ADDR), "independent nonfunction link");
		} else if (scenario == 1 || scenario == 2 || scenario == 6) {
			sdb_set (types, "independent_writer", "func", 0);
			sdb_set (types, "func.independent_writer.ret", "uint16_t", 0);
			sdb_num_set (types, "func.independent_writer.args", 0, 0);
			if (scenario == 2) {
				sdb_set (types, "fcnlink.00003058", "independent_writer", 0);
			} else {
				mu_assert_true (r_type_set_link (types, "independent_writer", WRITER_ADDR), "independent address prototype");
			}
		} else if (scenario >= 7) {
			const char *states[] = { "unknown", "unspecified", "fixed" };
			sdb_set (types, "func."WRITER_NAME".prototype", states[scenario - 7], 0);
		} else {
			sdb_set (types, WRITER_NAME, scenario == 3? "type": "func", 0);
			if (scenario == 4) {
				sdb_set (types, "func."WRITER_NAME".ret", "uint16_t", 0);
				sdb_num_set (types, "func."WRITER_NAME".args", 0, 0);
			}
		}
		if (scenario == 6) {
			// A matching name prototype must not mask the address-selected incompatible one.
			RAnalFunction named = { .anal = core->anal, .name = WRITER_NAME, .addr = WRITER_ADDR + 0x1000 };
			RAnalFunctionSignature signature = writer_signature ();
			mu_assert_true (r_anal_function_set_signature (core->anal, &named, &signature), "matching name prototype fixture");
			r_list_free (signature.params);
		}
		char *before = sdb_querys (types, NULL, 0, "*");
		mu_assert_false (writer_apply (&ctx), "occupied incompatible type/prototype storage refuses before creation");
		mu_assert_null (r_anal_get_function_at (core->anal, WRITER_ADDR), "no dependent function");
		mu_assert_null (r_flag_get (core->flags, WRITER_NAME), "no dependent label");
		char *after = sdb_querys (types, NULL, 0, "*");
		mu_assert_streq (after, before, "existing prototype/link keys preserved");
		free (before);
		free (after);
		r_core_free (core);
	}
	mu_end;
}

static bool test_writer_equivalent_address_storage(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		mu_end;
	}
	RCore *core = writer_core ();
	mu_assert_notnull (core, "normally loaded original for equivalent linked contract");
	BorlandProfileContext ctx;
	mu_assert_true (writer_context (core, &ctx), "linked-contract original identity");
	mu_assert_true (profile_function (&ctx, 0x3458, 150, WRITER_NAME, 0, "existing qualified body"), "qualified ordinary function");
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, WRITER_ADDR);
	sdb_set (core->anal->sdb_types, "existing_writer_contract", "func", 0);
	mu_assert_true (r_type_set_link (core->anal->sdb_types, "existing_writer_contract", WRITER_ADDR), "address-selected prototype storage");
	RAnalFunctionSignature signature = writer_signature ();
	mu_assert_true (r_anal_function_set_signature (core->anal, fcn, &signature), "existing equivalent native prototype");
	r_list_free (signature.params);
	mu_assert_true (r_anal_function_store_callconv (core->anal, fcn, WRITER_CC), "opaque native convention");
	char *before = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
	ut64 epoch = r_anal_types_dirty_epoch (core->anal);
	mu_assert_true (writer_apply (&ctx), "equivalent address-selected signature admitted");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "equivalent linked prototype not rewritten");
	mu_assert_null (sdb_const_get (core->anal->sdb_types, WRITER_NAME, NULL), "no competing name prototype");
	char *link = r_type_link_at (core->anal->sdb_types, WRITER_ADDR);
	mu_assert_streq (link, "existing_writer_contract", "same address type owner");
	char *after = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
	mu_assert_streq (after, before, "no alternate type keys");
	free (link);
	free (before);
	free (after);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_writer_install_and_reapply);
	mu_run_test (test_writer_independent_state);
	mu_run_test (test_writer_existing_storage);
	mu_run_test (test_writer_equivalent_address_storage);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
