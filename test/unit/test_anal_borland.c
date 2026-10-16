#include <r_core.h>
#include "minunit.h"

#define MOVE_ADDR 0x110e8
static const char family_hex[] =
	"45558bec56571e8b4e0c8b5e0a8b56088b46063bd1770c72043bc37306fdb80100eb03fc33c0c57606c47e0a8b4e0e0bc0740603f14e03f94ff7c701007404e311a4492bf02bf8d1e9f3a5730503f003f8a4fc1f5f5e5d4dcb"
	"45558bec5657ff760eff7608ff7606ff760cff760a0ee88eff83c40a8b56088b46065f5e5d4dcb";

static RCore *move_core(void) {
	RCore *core = r_core_new ();
	core->io->va = true;
	r_io_open_at (core->io, "malloc://128", R_PERM_RWX, 0, MOVE_ADDR);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	r_anal_types_prepare (core->anal);
	core->anal->opt.vars = false;
	ut8 bytes[128];
	r_hex_str2bin (family_hex, bytes);
	r_io_write_at (core->io, MOVE_ADDR, bytes, sizeof (bytes));
	RBinFile *bf = R_NEW0 (RBinFile);
	bf->bo = R_NEW0 (RBinObject);
	bf->rbin = core->bin;
	core->bin->cur = bf;
	RVecRBinSection_init (&bf->bo->sections_vec);
	RBinSection *section = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
	section->name = strdup ("code");
	section->vaddr = MOVE_ADDR;
	section->size = section->vsize = 128;
	section->perm = R_PERM_RWX;
	return core;
}

static void move_core_free(RCore *core) {
	RBinFile *bf = core->bin->cur;
	core->bin->cur = NULL;
	RVecRBinSection_fini (&bf->bo->sections_vec);
	free (bf->bo);
	free (bf);
	r_core_free (core);
}

static bool move_run(RCore *core, int expected) {
	char *output = r_anal_cmd (core->anal, "borland");
	char *prefix = r_str_newf ("Borland: %d function contracts qualified", expected);
	bool result = output && r_str_startswith (output, prefix);
	if (!result) {
		eprintf ("unexpected Borland result: %s\n", r_str_get (output));
	}
	free (output);
	free (prefix);
	return result;
}

static bool test_move_family(void) {
	RCore *core = move_core ();
	char *help = r_anal_cmd (core->anal, "borland?");
	mu_assert_notnull (help, "registered command help");
	mu_assert_notnull (strstr (help, "a:borland"), "truthful command");
	free (help);
	r_config_set (core->config, "anal.plugins.pre", "borland");
	core->anal->opt.vars = true;
	r_anal_plugin_action (core->anal, R_ANAL_PLUGIN_ACTION_PRE_ANALYSIS, NULL);
	mu_assert_true (core->anal->opt.vars, "normal variable recovery option restored");
	int i;
	for (i = 0; i < 2; i++) {
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, MOVE_ADDR + (i? 89: 0));
		mu_assert_notnull (fcn, "automatic native function");
		mu_assert_eq (r_anal_function_min_addr (fcn), fcn->addr, "body entry");
		mu_assert_eq (r_anal_function_max_addr (fcn), fcn->addr + (i? 39: 89), "exact body end");
		mu_assert_eq (r_anal_function_realsize (fcn), i? 39: 89, "complete body extent");
		mu_assert_streq (fcn->callconv, i? "borland_fmemmove_16far": "borland_fmovmem_16far", "distinct native model");
		RAnalFunctionSignature *sig = r_anal_function_get_signature (fcn);
		mu_assert_notnull (sig, "typed signature");
		mu_assert_streq (sig->ret_type, i? "FarAddress16": "void", "distinct analysis return");
		mu_assert_eq (r_list_length (sig->params), 3, "three arguments");
		RAnalFunctionParam *first = r_list_get_n (sig->params, 0);
		RAnalFunctionParam *second = r_list_get_n (sig->params, 1);
		RAnalFunctionParam *count = r_list_get_n (sig->params, 2);
		mu_assert_streq (first->name, i? "destination": "source", "first record");
		mu_assert_streq (second->name, i? "source": "destination", "second record");
		mu_assert_streq (first->type, "FarAddress16", "record, not pointer");
		mu_assert_streq (count->type, "uint16_t", "WORD count");
		ut64 epoch = fcn->dirty_epoch;
		mu_assert_true (move_run (core, 2), "equivalent rerun");
		mu_assert_eq (fcn->dirty_epoch, epoch, "rerun does not reapply signature");
		r_anal_function_signature_free (sig);
	}
	RAnalBaseType *type = r_anal_get_base_type (core->anal, "FarAddress16");
	mu_assert_notnull (type, "native record type");
	mu_assert_eq (type->size, 32, "four-byte record");
	RAnalTypeMember *member = RVecAnalTypeMember_at (&type->struct_data.members, 1);
	mu_assert_streq (member->name, "selector", "selector field");
	mu_assert_eq (member->offset, 2, "selector byte offset");
	mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, "FarAddress16"), 32, "native measured record");
	r_anal_base_type_free (type);
	move_core_free (core);
	mu_end;
}

static bool test_move_current_qualification(void) {
	RCore *core = move_core ();
	ut8 patch = 0x90;
	r_io_write_at (core->io, MOVE_ADDR + 127, &patch, 1);
	mu_assert_true (move_run (core, 0), "patched wrapper refuses both contracts");
	mu_assert_eq (r_list_length (core->anal->fcns), 0, "no partial core recognition");
	patch = 0xcb;
	r_io_write_at (core->io, MOVE_ADDR + 127, &patch, 1);
	r_anal_hint_set_bits (core->anal, MOVE_ADDR + 36, 32);
	mu_assert_true (move_run (core, 0), "internal context override refuses both contracts");
	r_anal_hint_unset_bits (core->anal, MOVE_ADDR + 36);
	r_anal_hint_set_jump (core->anal, MOVE_ADDR + 111, 0x12345);
	mu_assert_true (move_run (core, 0), "wrapper CALL override refuses both contracts");
	RAnalHint *hint = r_anal_hint_get (core->anal, MOVE_ADDR + 111);
	mu_assert_eq (hint->jump, 0x12345, "flow override preserved");
	r_anal_hint_free (hint);
	r_anal_hint_unset_jump (core->anal, MOVE_ADDR + 111);
	RIOMap *map = r_io_map_get_at (core->io, MOVE_ADDR);
	map->perm = R_PERM_RW;
	mu_assert_true (move_run (core, 0), "actual nonexecutable mapping refuses both contracts");
	map->perm = R_PERM_RWX;
	mu_assert_true (move_run (core, 2), "restored current family qualifies");
	move_core_free (core);
	mu_end;
}

static bool test_move_preserve_independent_state(void) {
	RCore *core = move_core ();
	RAnal *anal = core->anal;
	RAnalFunction *fcn = r_anal_create_function (anal, NULL, MOVE_ADDR, R_ANAL_FCN_TYPE_FCN, NULL);
	r_anal_function (anal, fcn, fcn->addr, R_ANAL_REF_TYPE_CALL);
	fcn->stack = 42;
	fcn->bp_off = 8;
	r_meta_set_string (anal, R_META_TYPE_COMMENT, fcn->addr, "manual comment");
	mu_assert_true (r_anal_xrefs_set (anal, fcn->addr + 1, MOVE_ADDR + 120, R_ANAL_REF_TYPE_DATA), "create independent reference to a mapped target");
	mu_assert_true (move_run (core, 2), "independent frame and references are not replaced");
	mu_assert_true (r_str_startswith (fcn->name, "fcn"), "existing generic name retained");
	mu_assert_eq (fcn->stack, 42, "manual frame retained");
	mu_assert_eq (fcn->bp_off, 8, "manual BP offset retained");
	mu_assert_streq (r_meta_get_string (anal, R_META_TYPE_COMMENT, fcn->addr), "manual comment", "comment retained");
	RVecAnalRef *refs = r_anal_xrefs_get_from (anal, fcn->addr + 1);
	mu_assert_eq (RVecAnalRef_length (refs), 1, "independent reference retained");
	mu_assert_eq (RVecAnalRef_at (refs, 0)->addr, MOVE_ADDR + 120, "reference destination retained");
	RVecAnalRef_free (refs);
	RAnalBlock *bb = r_list_first (fcn->bbs);
	ut64 previous_jump = bb->jump;
	bb->jump = 0x87654;
	mu_assert_true (move_run (core, 1), "body-flow-only edit preserves core without a name protector");
	mu_assert_eq (bb->jump, 0x87654, "manual body flow retained");
	bb->jump = previous_jump;
	RAnalFunctionSignature changed = { .ret_type = "int", .callconv = "cdecl", .params = r_list_new () };
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &changed), "manual signature setup");
	r_list_free (changed.params);
	mu_assert_true (move_run (core, 1), "manual signature preserved");
	RAnalFunctionSignature *sig = r_anal_function_get_signature (fcn);
	mu_assert_streq (sig->ret_type, "int", "manual return retained");
	r_anal_function_signature_free (sig);
	move_core_free (core);

	core = move_core ();
	anal = core->anal;
	fcn = r_anal_create_function (anal, NULL, MOVE_ADDR, R_ANAL_FCN_TYPE_FCN, NULL);
	r_anal_function (anal, fcn, fcn->addr, R_ANAL_REF_TYPE_CALL);
	RAnalVar *var = r_anal_function_set_var (fcn, 6, R_ANAL_VAR_KIND_BPV, "uint16_t", 2, true, "manual_argument");
	mu_assert_notnull (var, "manual variable setup with no signature/name protector");
	mu_assert_true (move_run (core, 1), "variable-only edit preserves core");
	mu_assert_streq (var->name, "manual_argument", "manual variable name");
	mu_assert_streq (var->type, "uint16_t", "manual variable type");
	move_core_free (core);
	mu_end;
}

static bool test_move_preserve_body_and_convention(void) {
	RCore *core = move_core ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, NULL, MOVE_ADDR, R_ANAL_FCN_TYPE_FCN, NULL);
	r_anal_function (core->anal, fcn, fcn->addr, R_ANAL_REF_TYPE_CALL);
	const char *previous_cc = fcn->callconv;
	r_anal_function_rename (fcn, "manual_move");
	mu_assert_true (move_run (core, 1), "rename-only edit preserves the operational contract");
	mu_assert_streq (fcn->name, "manual_move", "manual name retained");
	mu_assert_eq (fcn->callconv, previous_cc, "rename does not authorize a different convention");
	mu_assert_null (r_type_link_at (core->anal->sdb_types, fcn->addr), "rename does not authorize a prototype");
	r_anal_function_rename (fcn, "fcn.000110e8");
	RAnalBlock *bb = r_list_first (fcn->bbs);
	ut64 size = bb->size;
	r_anal_block_set_size (bb, size - 1);
	mu_assert_true (move_run (core, 1), "body-extent-only edit preserves core");
	mu_assert_eq (bb->size, size - 1, "manual extent retained");
	r_anal_block_set_size (bb, size);
	fcn->meta.stack_pop = 6;
	mu_assert_true (move_run (core, 1), "independent native callee-pop conflict preserves core");
	mu_assert_eq (fcn->meta.stack_pop, 6, "inferred callee-pop not overwritten");
	fcn->meta.stack_pop = 0;
	r_anal_function_store_callconv (core->anal, fcn, "selected_convention");
	mu_assert_true (move_run (core, 1), "independent selected convention preserves core");
	mu_assert_streq (fcn->callconv, "selected_convention", "selected convention retained");
	move_core_free (core);
	mu_end;
}

static bool test_move_preserve_type(void) {
	RCore *core = move_core ();
	sdb_set (core->anal->sdb_types, "FarAddress16", "struct", 0);
	sdb_set (core->anal->sdb_types, "struct.FarAddress16", "changed", 0);
	sdb_set (core->anal->sdb_types, "struct.FarAddress16.changed", "uint32_t,0,0", 0);
	mu_assert_true (move_run (core, 0), "independent record definition prevents application");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "struct.FarAddress16", NULL), "changed", "type not overwritten");
	move_core_free (core);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_move_family);
	mu_run_test (test_move_current_qualification);
	mu_run_test (test_move_preserve_independent_state);
	mu_run_test (test_move_preserve_body_and_convention);
	mu_run_test (test_move_preserve_type);
	return tests_passed != tests_run;
}
