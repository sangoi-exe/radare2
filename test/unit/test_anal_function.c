#include <r_anal.h>
#include <r_core.h>
#include <r_anal_priv.h>
#include "minunit.h"
#include <string.h>

#include "test_anal_block_invars.inl"

bool ht_up_count(void *user, const ut64 k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

bool ht_pp_count(void *user, const void *k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

typedef struct {
	int count;
	ut64 block_addr;
	ut64 switch_addr;
	ut64 default_addr;
	ut64 first_case_addr;
	ut64 first_case_value;
} SwitchForeachCtx;

static bool count_switches_cb(RAnalFunction *fcn, RAnalBlock *block, RAnalSwitchOp *op, void *user) {
	SwitchForeachCtx *ctx = user;
	mu_assert_notnull (fcn, "switch callback function");
	mu_assert_notnull (block, "switch callback block");
	mu_assert_notnull (op, "switch callback switch");
	ctx->count++;
	ctx->block_addr = block->addr;
	ctx->switch_addr = op->addr;
	ctx->default_addr = op->def_val;
	RAnalCaseOp *caseop = r_list_first (op->cases);
	mu_assert_notnull (caseop, "switch callback first case");
	ctx->first_case_addr = caseop->jump;
	ctx->first_case_value = caseop->value;
	return true;
}

static bool function_check_invariants(RAnal *anal) {
	if (!block_check_invariants (anal)) {
		return false;
	}

	RListIter *it;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, it, fcn) {
		mu_assert_ptreq (ht_up_find (anal->ht_addr_fun, fcn->addr, NULL), fcn, "function in addr ht");
		mu_assert_ptreq (ht_pp_find (anal->ht_name_fun, fcn->name, NULL), fcn, "function in name ht");
	}

	size_t addr_count = 0;
	ht_up_foreach (anal->ht_addr_fun, ht_up_count, &addr_count);
	mu_assert_eq (addr_count, r_list_length (anal->fcns), "function addr ht count");

	size_t name_count = 0;
	ht_pp_foreach (anal->ht_name_fun, ht_pp_count, &name_count);
	mu_assert_eq (name_count, r_list_length (anal->fcns), "function name ht count");

	return true;
}

#define check_invariants function_check_invariants
#define check_leaks block_check_leaks

#define assert_invariants(anal) do { if (!check_invariants (anal)) { return false; } } while (0)
#define assert_leaks(anal) do { if (!check_leaks (anal)) { return false; } } while (0)

bool test_r_anal_function_relocate(void) {
	RAnal *anal = r_anal_new ();
	assert_invariants (anal);

	RAnalFunction *fa = r_anal_create_function (anal, "do_something", 0x1337, 0, NULL);
	assert_invariants (anal);
	RAnalFunction *fb = r_anal_create_function (anal, "do_something_else", 0xdeadbeef, 0, NULL);
	assert_invariants (anal);
	r_anal_create_function (anal, "do_something_different", 0xc0ffee, 0, NULL);
	assert_invariants (anal);

	bool success = r_anal_function_relocate (fa, fb->addr);
	assert_invariants (anal);
	mu_assert_false (success, "failed relocate");
	mu_assert_eq (fa->addr, 0x1337, "failed relocate addr");
	ut64 revision_epoch = r_anal_function_dirty_epoch (fa);

	success = r_anal_function_relocate (fa, 0x1234);
	assert_invariants (anal);
	mu_assert_true (success, "successful relocate");
	mu_assert_eq (fa->addr, 0x1234, "successful relocate addr");
	mu_assert_neq (r_anal_function_dirty_epoch (fa), revision_epoch,
		"relocation bumps the function revision epoch");
	revision_epoch = r_anal_function_dirty_epoch (fa);
	mu_assert_true (r_anal_function_rename (fa, "relocated_function"),
		"rename relocated function");
	mu_assert_neq (r_anal_function_dirty_epoch (fa), revision_epoch,
		"rename bumps the function revision epoch");

	assert_leaks (anal);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_labels(void) {
	RAnal *anal = r_anal_new ();

	RAnalFunction *f = r_anal_create_function (anal, "do_something", 0x1337, 0, NULL);

	bool s = r_anal_function_set_label (f, "smartfriend", 0x1339);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "stray", 0x133c);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "the", 0x1340);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "stray", 0x1234);
	mu_assert_false (s, "set label (existing name)");
	s = r_anal_function_set_label (f, "henlo", 0x133c);
	mu_assert_false (s, "set label (existing addr)");

	ut64 addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label");
	addr = r_anal_function_get_label (f, "stray");
	mu_assert_eq (addr, 0x133c, "get label");
	addr = r_anal_function_get_label (f, "skies");
	mu_assert_eq (addr, UT64_MAX, "get label (unknown)");

	const char *name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at");
	name = r_anal_function_get_label_at (f, 0x133c);
	mu_assert_streq (name, "stray", "get label at");
	name = r_anal_function_get_label_at (f, 0x1234);
	mu_assert_null (name, "get label at (unknown)");

	r_anal_function_delete_label (f, "stray");
	addr = r_anal_function_get_label (f, "stray");
	mu_assert_eq (addr, UT64_MAX, "get label (deleted)");
	name = r_anal_function_get_label_at (f, 0x133c);
	mu_assert_null (name, "get label at (deleted)");
	addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label (unaffected by delete)");
	name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at (unaffected by delete)");

	r_anal_function_delete_label_at (f, 0x1340);
	addr = r_anal_function_get_label (f, "the");
	mu_assert_eq (addr, UT64_MAX, "get label (deleted)");
	name = r_anal_function_get_label_at (f, 0x340);
	mu_assert_null (name, "get label at (deleted)");
	addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label (unaffected by delete)");
	name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at (unaffected by delete)");

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_str_to_fcn_returns_status(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *f = r_anal_create_function (anal, "sigtest", 0x1000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for signature test");

	bool ok = r_anal_str_to_fcn (anal, f, "int sigtest (int arg0);");
	mu_assert_true (ok, "valid signature must return success");

	char *typed_name = r_type_func_name (anal->sdb_types, f->name);
	mu_assert_notnull (typed_name, "valid signature must create a type entry");

	const char *ret = r_type_func_ret (anal->sdb_types, typed_name);
	int argc;
	mu_assert_true (r_type_func_args_count (anal->sdb_types, typed_name, &argc), "valid prototype count");
	char *arg0 = r_type_func_args_type (anal->sdb_types, typed_name, 0);
	mu_assert_true (ret && (!strcmp (ret, "int") || !strcmp (ret, "int32_t")),
		"valid signature should set integer return type");
	mu_assert_eq (argc, 1, "valid signature should set one argument");
	mu_assert_true (arg0 && (!strcmp (arg0, "int") || !strcmp (arg0, "int32_t")),
		"valid signature should keep first argument type");
	free (arg0);

	ok = r_anal_str_to_fcn (anal, f, "int sigtest (");
	mu_assert_false (ok, "invalid signature must return failure");

	ret = r_type_func_ret (anal->sdb_types, typed_name);
	mu_assert_true (r_type_func_args_count (anal->sdb_types, typed_name, &argc), "existing prototype count");
	arg0 = r_type_func_args_type (anal->sdb_types, typed_name, 0);
	mu_assert_true (ret && (!strcmp (ret, "int") || !strcmp (ret, "int32_t")),
		"invalid signature must not clobber existing return type");
	mu_assert_eq (argc, 1, "invalid signature must not clobber existing argc");
	mu_assert_true (arg0 && (!strcmp (arg0, "int") || !strcmp (arg0, "int32_t")),
		"invalid signature must not clobber existing argument type");
	free (arg0);
	free (typed_name);
	r_anal_free (anal);
	mu_end;
}

bool test_r_core_anal_fcn_prefers_exact_start_match(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");
	RAnal *anal = core->anal;
	r_config_set_b (core->config, "anal.esil", false);

	RAnalFunction *outer = r_anal_create_function (anal, "outer", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *target = r_anal_create_function (anal, "target", 0x120, R_ANAL_FCN_TYPE_LOC, NULL);
	mu_assert_notnull (outer, "Couldn't create outer function");
	mu_assert_notnull (target, "Couldn't create target function");

	RAnalBlock *outer_bb = r_anal_create_block (anal, 0x100, 0x30);
	RAnalBlock *target_bb = r_anal_create_block (anal, 0x120, 0x10);
	mu_assert_notnull (outer_bb, "Couldn't create outer block");
	mu_assert_notnull (target_bb, "Couldn't create target block");
	r_anal_function_add_block (outer, outer_bb);
	r_anal_function_add_block (target, target_bb);
	r_unref (outer_bb);
	r_unref (target_bb);

	bool ret = r_core_anal_fcn (core, 0x120, 0x104, R_ANAL_REF_TYPE_CALL, 1);
	mu_assert_false (ret, "Exact-start function should short-circuit analysis");
	mu_assert_eq (r_anal_xrefs_count (anal), 0, "Exact-start match should not synthesize a new xref");

	r_core_free (core);
	mu_end;
}

bool test_r_core_anal_fcn_variadic_marker_requires_unclobbered_al(void) {
	const ut64 addr = 0x1000;
	const ut8 bytes[] = {
		0x0f, 0xb6, 0x07, // movzx eax, byte [rdi]
		0x84, 0xc0, // test al, al
		0xc3, // ret
		0x84, 0xc0, // test al, al
		0x74, 0x01, // je +1
		0xc3, // ret
		0xc3, // ret
	};
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");
	core->io->va = true;
	mu_assert_notnull (r_io_open_at (core->io, "malloc://12",
		R_PERM_RWX, 0, addr), "open variadic marker test map");
	mu_assert_true (r_io_write_at (core->io, addr, bytes, sizeof (bytes)),
		"write variadic marker test bytes");
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 64);
	r_config_set_b (core->config, "anal.esil", false);

	mu_assert_true (r_anal_cc_set (core->anal, "void amd64 (rdi, rsi, rdx, rcx, r8, r9, stack)"),
		"must seed amd64 calling convention");
	r_anal_set_cc_default (core->anal, "amd64");

	mu_assert_true (r_core_anal_fcn (core, addr, UT64_MAX,
		R_ANAL_REF_TYPE_NULL, 1), "analyze clobbered marker function");
	RAnalFunction *clobbered = r_anal_get_function_at (core->anal, addr);
	mu_assert_notnull (clobbered, "analysis creates clobbered marker function");
	mu_assert_streq (clobbered->callconv, "amd64", "clobbered marker uses amd64 calling convention");
	mu_assert_false (clobbered->is_variadic,
		"writing eax invalidates the incoming al variadic marker");

	const ut64 preserved_addr = addr + 6;
	mu_assert_true (r_core_anal_fcn (core, preserved_addr, UT64_MAX,
		R_ANAL_REF_TYPE_NULL, 1), "analyze preserved marker function");
	RAnalFunction *preserved = r_anal_get_function_at (core->anal, preserved_addr);
	mu_assert_notnull (preserved, "analysis creates preserved marker function");
	mu_assert_streq (preserved->callconv, "amd64", "preserved marker uses amd64 calling convention");
	mu_assert_true (preserved->is_variadic,
		"an unclobbered test of al remains a variadic marker");

	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_get_signature(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_true (r_anal_cc_set (anal, "void amd64 (rdi, rsi, rdx, rcx, r8, r9, stack)"),
		"must seed amd64 calling convention");
	RAnalFunction *f = r_anal_create_function (anal, "sigread", 0x2000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for typed cache test");
	bool ok = r_anal_str_to_fcn (anal, f, "int sigread (int arg0, char *arg1);");
	mu_assert_true (ok, "valid signature must apply before cache refresh");

	char *typed_name = r_type_func_name (anal->sdb_types, f->name);
	mu_assert_notnull (typed_name, "typed function name");
	char *typed_cc = r_str_newf ("func.%s.cc=amd64\n", typed_name);
	mu_assert_notnull (typed_cc, "persisted callconv key");
	r_anal_save_parsed_type (anal, typed_cc);

	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed signature must be readable");
	mu_assert_streq (f->name, "sigread", "typed function name");
	mu_assert_nullable_streq (signature->type_name, typed_name, "snapshot identifies the selected canonical record");
	mu_assert_streq (signature->ret_type, "int", "typed return type");
	mu_assert_streq (signature->callconv, "amd64", "typed callconv");
	mu_assert_eq ((int)r_list_length (signature->params), 2, "typed param count");
	RAnalFunctionParam *arg0 = r_list_get_n (signature->params, 0);
	RAnalFunctionParam *arg1 = r_list_get_n (signature->params, 1);
	mu_assert_notnull (arg0, "first typed param");
	mu_assert_notnull (arg1, "second typed param");
	mu_assert_streq (arg0->type, "int", "first typed param type");
	mu_assert_streq (arg1->type, "char *", "second typed param type");
	mu_assert_notnull (signature->signature, "typed signature string");

	free (typed_cc);
	free (typed_name);
	r_anal_function_signature_free (signature);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_get_signature_prefers_exact_type_link(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	bool ok = r_anal_import_c_decls (anal,
		"int fallback_signature (int fallback);"
		"char linked_signature (char linked);"
		"void renamed_signature (void);", NULL);
	mu_assert_true (ok, "seed linked and fallback signatures");

	RAnalFunction *f = r_anal_create_function (anal, "fallback_signature", 0x2800, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for exact type link test");
	mu_assert_true (r_type_set_link (anal->sdb_types, "linked_signature", f->addr),
		"exact function type link must be set");

	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "exact linked signature must be readable");
	mu_assert_nullable_streq (signature->type_name, "linked_signature", "snapshot identifies the address-selected record");
	mu_assert_streq (signature->ret_type, "char", "exact link must take precedence over function name");
	mu_assert_eq ((int)r_list_length (signature->params), 1, "exact linked signature param count");
	r_anal_function_signature_free (signature);
	RAnalFunctionParam updated_param = { .name = "changed", .type = "short" };
	RList *updated_params = r_list_new ();
	mu_assert_notnull (updated_params, "Couldn't create updated linked param list");
	r_list_append (updated_params, &updated_param);
	RAnalFunctionSignature updated = {
		.ret_type = "short",
		.params = updated_params,
	};
	mu_assert_true (r_anal_function_set_signature (anal, f, &updated),
		"updating a linked signature must succeed");
	r_list_free (updated_params);
	mu_assert_streq (r_type_func_ret (anal->sdb_types, "linked_signature"), "short",
		"updating a linked function must update the linked type");

	mu_assert_true (r_anal_function_rename (f, "renamed_signature"), "function rename must succeed");
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "exact linked signature must survive function rename");
	mu_assert_nullable_streq (signature->type_name, "linked_signature", "the selected record identity survives function rename");
	mu_assert_streq (signature->ret_type, "short", "renaming must not change exact linked signature");
	r_anal_function_signature_free (signature);

	mu_assert_true (r_type_unlink (anal->sdb_types, f->addr), "exact function type link must be removed");
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "name-based signature must remain available after unlink");
	mu_assert_nullable_streq (signature->type_name, "renamed_signature", "unlink exposes the name-selected record identity");
	mu_assert_streq (signature->ret_type, "void", "unlink must restore name-based lookup");
	r_anal_function_signature_free (signature);

	sdb_set (anal->sdb_types, "not_a_function", "type", 0);
	mu_assert_true (r_type_set_link (anal->sdb_types, "not_a_function", f->addr),
		"non-function type link must be set for rejection test");
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "non-function link must fall back to name-based signature");
	mu_assert_streq (signature->ret_type, "void", "non-function address link must be ignored");
	r_anal_function_signature_free (signature);

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_set_signature_uses_canonical_type_name(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	bool ok = r_anal_import_c_decls (anal, "int scanf (const char *fmt);", NULL);
	mu_assert_true (ok, "seed canonical scanf signature");

	RAnalFunction *f = r_anal_create_function (anal, "sym.imp.__isoc99_scanf", 0x3000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for typed apply test");
	RAnalFunction *alias = r_anal_create_function (anal, "scanf", 0x3001, 0, NULL);
	mu_assert_notnull (alias, "Couldn't create alias function for typed apply test");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (alias);
	mu_assert_notnull (signature, "alias typed signature must warm");
	r_anal_function_signature_free (signature);

	RAnalFunctionParam params_data[] = {
		{ .name = "format", .type = "const char *" },
		{ .name = "value", .type = "int *" },
	};
	RList *params = r_list_new ();
	mu_assert_notnull (params, "Couldn't create typed apply param list");
	r_list_append (params, &params_data[0]);
	r_list_append (params, &params_data[1]);

	RAnalFunctionSignature input = {
		.ret_type = "int",
		.callconv = "amd64",
		.params = params,
		.noreturn = false,
	};
	ok = r_anal_function_set_signature (anal, f, &input);
	mu_assert_true (ok, "typed signature apply must succeed");
	r_list_free (params);

	char *typed_name = r_type_func_name (anal->sdb_types, f->name);
	mu_assert_notnull (typed_name, "canonical typed name");
	mu_assert_streq (typed_name, "scanf", "apply must reuse canonical type name");
	int argc;
	mu_assert_true (r_type_func_args_count (anal->sdb_types, typed_name, &argc), "typed apply count succeeds");
	mu_assert_eq (argc, 2, "typed apply param count");
	mu_assert_null (sdb_const_get (anal->sdb_types, f->name, 0), "apply must not create duplicate import-scoped signature");

	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed signature read");
	mu_assert_nullable_streq (signature->type_name, "scanf", "snapshot identifies the fuzzy-selected canonical record");
	mu_assert_streq (signature->ret_type, "int", "typed apply return type");
	mu_assert_streq (signature->callconv, "amd64", "typed apply callconv");
	mu_assert_eq ((int)r_list_length (signature->params), 2, "typed apply context param count");
	RAnalFunctionParam *arg0 = r_list_get_n (signature->params, 0);
	RAnalFunctionParam *arg1 = r_list_get_n (signature->params, 1);
	mu_assert_notnull (arg0, "first typed param");
	mu_assert_notnull (arg1, "second typed param");
	mu_assert_streq (arg0->name, "format", "first typed param name");
	mu_assert_streq (arg0->type, "const char *", "first typed param type");
	mu_assert_streq (arg1->name, "value", "second typed param name");
	mu_assert_streq (arg1->type, "int *", "second typed param type");
	mu_assert_streq (signature->signature, "int sym.imp.__isoc99_scanf (const char *format, int *value);",
		"declaration must carry the function's own name, not the type db key");
	r_anal_function_signature_free (signature);
	mu_assert_streq (f->callconv, "amd64", "typed apply must sync live callconv");

	input.ret_type = "void";
	input.callconv = "cdecl";
	input.params = NULL;
	input.noreturn = true;
	ok = r_anal_function_set_signature (anal, f, &input);
	mu_assert_true (ok, "typed signature overwrite must succeed");
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed overwrite signature read");
	mu_assert_streq (signature->ret_type, "void", "typed overwrite return type");
	mu_assert_streq (signature->callconv, "cdecl", "typed overwrite callconv");
	mu_assert_true (f->is_noreturn, "typed overwrite noreturn");
	mu_assert_eq ((int)r_list_length (signature->params), 0, "typed overwrite clears params");
	r_anal_function_signature_free (signature);

	mu_assert_true (r_type_func_args_count (anal->sdb_types, typed_name, &argc), "typed overwrite count succeeds");
	mu_assert_eq (argc, 0, "typed overwrite argc");
	signature = r_anal_function_get_signature (alias);
	mu_assert_notnull (signature, "alias signature must refresh after overwrite");
	mu_assert_streq (signature->ret_type, "void", "alias return type must refresh after overwrite");
	mu_assert_streq (signature->callconv, "cdecl", "alias callconv must refresh after overwrite");
	mu_assert_eq ((int)r_list_length (signature->params), 0, "alias params must refresh after overwrite");
	r_anal_function_signature_free (signature);
	free (typed_name);

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_signature_preserves_declarator_shapes(void) {
	const struct {
		const char *ret_type;
		const char *param_type;
		const char *param_name;
		const char *stored_name;
		const char *signature;
	} cases[] = {
		{ "void", "int (*)(int)", "callback", "callback", "void shaped (int (*callback)(int));" },
		{ "void", "int (far * const )(char near *, int)", "callback", "callback", "void shaped (int (far * const callback)(char near *, int));" },
		{ "void", "const int (far * const )[3]", "matrix", "matrix", "void shaped (const int (far * const matrix)[3]);" },
		{ "int (near *)[3]", "int", "count", "count", "int (near *shaped (int count))[3];" },
		{ "int (far *)(char near *, int)", "int", "count", "count", "int (far *shaped (int count))(char near *, int);" },
		{ "int far * near *", "int near * far *", "value", "value", "int far * near *shaped (int near * far *value);" },
		{ "void", "int (*)[3]", NULL, "arg0", "void shaped (int (*arg0)[3]);" },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RAnal *anal = r_anal_new ();
		mu_assert_notnull (anal, "create analysis for structured signature");
		anal->opt.tparser = strdup ("tcc");
		mu_assert_true (r_anal_cc_set (anal, "void shapecc (stack)"), "seed independent calling convention");
		RAnalFunction *fcn = r_anal_create_function (anal, "shaped", 0x3000, 0, NULL);
		mu_assert_notnull (fcn, "create function for structured signature");
		RAnalFunctionParam param = { .name = (char *)cases[i].param_name, .type = (char *)cases[i].param_type };
		RList *params = r_list_new ();
		r_list_append (params, &param);
		RAnalFunctionSignature input = {
			.ret_type = (char *)cases[i].ret_type,
			.callconv = "shapecc",
			.params = params,
			.noreturn = true,
		};
		ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
		ut64 types_epoch = r_anal_types_dirty_epoch (anal);
		mu_assert_true (r_anal_function_set_signature (anal, fcn, &input), "apply abstract declarator types");
		r_list_free (params);
		mu_assert_neq (r_anal_function_dirty_epoch (fcn), function_epoch, "signature write dirties the function");
		mu_assert_neq (r_anal_types_dirty_epoch (anal), types_epoch, "signature write dirties types");
		mu_assert_streq (r_anal_function_cc (fcn), "shapecc", "pointer qualifiers do not choose calling convention");
		mu_assert_true (fcn->is_noreturn, "signature write retains explicit noreturn");
		function_epoch = r_anal_function_dirty_epoch (fcn);
		types_epoch = r_anal_types_dirty_epoch (anal);
		RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
		mu_assert_notnull (signature, "read structured signature");
		mu_assert_eq (signature->origin, R_ANAL_FUNCTION_SIGNATURE_ORIGIN_NAME, "read producer-owned prototype");
		mu_assert_streq (signature->signature, cases[i].signature, "declaration places names at the correct layer");
		mu_assert_streq (signature->ret_type, cases[i].ret_type, "stored return retains ordered shape");
		mu_assert_eq (r_list_length (signature->params), 1, "nested callback arguments are not outer arguments");
		RAnalFunctionParam *stored = r_list_first (signature->params);
		mu_assert_notnull (stored, "read stored parameter");
		mu_assert_streq (stored->name, cases[i].stored_name, "stored parameter retains its name");
		mu_assert_streq (stored->type, cases[i].param_type, "stored parameter retains qualifiers and ordered shape");
		char *row = r_str_newf ("%s,%s", cases[i].param_type, cases[i].stored_name);
		mu_assert_streq (sdb_const_get (anal->sdb_types, "func.shaped.arg.0", 0), row, "c2 remains the argument metadata producer");
		free (row);
		mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "structured signature read leaves function clean");
		mu_assert_eq (r_anal_types_dirty_epoch (anal), types_epoch, "structured signature read leaves types clean");
		mu_assert_true (r_anal_function_set_signature (anal, fcn, signature), "write back the getter's structured result");
		RAnalFunctionSignature *again = r_anal_function_get_signature (fcn);
		mu_assert_notnull (again, "read structured signature after writeback");
		mu_assert_streq (again->signature, signature->signature, "writeback preserves the whole declaration");
		mu_assert_streq (again->callconv, "shapecc", "writeback retains calling convention");
		mu_assert_true (again->noreturn, "writeback retains noreturn");
		r_anal_function_signature_free (again);

		RAnal *reparsed = r_anal_new ();
		RAnalFunction *copy = r_anal_create_function (reparsed, "shaped", 0x3000, 0, NULL);
		mu_assert_true (r_anal_str_to_fcn (reparsed, copy, signature->signature), "reparse rendered declaration through c2");
		again = r_anal_function_get_signature (copy);
		mu_assert_notnull (again, "read reparsed declaration");
		mu_assert_streq (again->signature, signature->signature, "render and reparse retain declaration shape");
		mu_assert_streq (again->ret_type, signature->ret_type, "reparse retains return type");
		stored = r_list_first (again->params);
		mu_assert_notnull (stored, "read reparsed parameter");
		mu_assert_streq (stored->name, cases[i].stored_name, "reparse retains parameter name");
		mu_assert_streq (stored->type, cases[i].param_type, "reparse retains parameter shape");
		r_anal_function_signature_free (again);
		r_anal_free (reparsed);
		r_anal_function_signature_free (signature);
		r_anal_free (anal);
	}
	mu_end;
}

bool test_r_anal_function_set_signature_rejects_invalid_declarators(void) {
	RAnal *anal = r_anal_new ();
	RAnalFunction *fcn = r_anal_create_function (anal, "shaped", 0x3000, 0, NULL);
	mu_assert_true (r_anal_str_to_fcn (anal, fcn, "int shaped (int original);"), "seed signature before invalid write");
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 types_epoch = r_anal_types_dirty_epoch (anal);
	RAnalFunctionParam param = { .name = "callback", .type = "int (*)(" };
	RList *params = r_list_new ();
	r_list_append (params, &param);
	RAnalFunctionSignature input = { .ret_type = "void", .params = params };
	mu_assert_false (r_anal_function_set_signature (anal, fcn, &input), "refuse malformed callback without textual fallback");
	input.ret_type = "int (*)[";
	param.type = "int";
	mu_assert_false (r_anal_function_set_signature (anal, fcn, &input), "refuse malformed return declarator");
	r_list_free (params);
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	mu_assert_notnull (signature, "existing signature survives refused write");
	mu_assert_streq (signature->signature, "int shaped (int original);", "invalid declaration does not overwrite metadata");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "refused signature leaves function epoch unchanged");
	mu_assert_eq (r_anal_types_dirty_epoch (anal), types_epoch, "refused signature leaves type epoch unchanged");
	r_anal_function_signature_free (signature);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_str_to_fcn_defaults_omitted_return_type(void) {
	const struct {
		const char *name;
		const char *input;
		const char *signature;
		int argc;
	} cases[] = {
		{ "no_type", "no_type(int a, char **b);", "void no_type (int a, char **b);", 2 },
		{ "foo.bar", "foo.bar();;", "void foo.bar ();", 0 },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RAnal *anal = r_anal_new ();
		RAnalFunction *fcn = r_anal_create_function (anal, cases[i].name, 0x3000, 0, NULL);
		mu_assert_true (r_anal_str_to_fcn (anal, fcn, cases[i].input), "signature command accepts an omitted return type");
		RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
		mu_assert_notnull (signature, "read signature with defaulted return type");
		mu_assert_streq (signature->signature, cases[i].signature, "default return preserves function and parameter declarators");
		mu_assert_streq (signature->ret_type, "void", "omitted result defaults to void");
		mu_assert_eq (r_list_length (signature->params), cases[i].argc, "default return preserves parameter count");
		mu_assert_streq (r_type_func_ret (anal->sdb_types, cases[i].name), "void", "c2 owns the defaulted prototype metadata");
		r_anal_function_signature_free (signature);
		r_anal_free (anal);
	}
	mu_end;
}

bool test_r_anal_function_signature_parse_requires_a_named_function(void) {
	const char *inputs[] = { "uint16_t far *(near *returns_table(void))[3]", "foo.bar();;" };
	const char *names[] = { "returns_table", "foo.bar" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (inputs); i++) {
		char *error = NULL;
		RTypeDecl *decl = r_anal_function_signature_parse (inputs[i], NULL, &error);
		mu_assert_notnull (decl, "prepare a named normalized signature");
		mu_assert_null (error, "valid named signature has no diagnostic");
		mu_assert_streq (decl->name, names[i], "normalization exposes the actual function name");
		mu_assert_eq (decl->type->kind, R_TYPE_DECL_FUNCTION, "prepared signature starts at its function");
		r_type_decl_free (decl);
	}
	const char *invalid[] = { "int (*)(int)", "int object", "int (object)", "Result (object)", "int()", "void()", "const()", "struct()", "if()", "int malformed(" };
	for (i = 0; i < R_ARRAY_SIZE (invalid); i++) {
		char *error = NULL;
		RTypeDecl *decl = r_anal_function_signature_parse (invalid[i], NULL, &error);
		mu_assert_null (decl, "signature preparation does not invent a function name");
		mu_assert_notnull (error, "invalid named signature reports its failure");
		free (error);
	}
	mu_end;
}

bool test_r_anal_function_signature_prepared_tag_namespace(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	anal->opt.tparser = strdup ("tcc");
	RAnalFunction *fcn = r_anal_create_function (anal, "tagged", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	char *error = NULL;
	RAnalFunctionSignaturePrepared *prepared = r_anal_function_signature_prepare (anal, "int tagged(struct Fresh *value)", &error);
	mu_assert_notnull (prepared, "the selected TCC frontend prepares the actual tagged reference");
	mu_assert_null (error, "the prepared tag declaration is admitted");
	mu_assert_eq (r_type_kind (anal->sdb_types, "struct Fresh"), R_TYPE_INVALID, "preparation does not mutate the analysis tag namespace");
	mu_assert_true (r_anal_function_signature_prepare_target (anal, prepared, fcn, fcn->addr, fcn->name, R_ANAL_SIGNATURE_APPLY_SHARED, &error), "settle the final target and native records before application");
	mu_assert_true (r_anal_function_signature_apply (anal, fcn, prepared), "application retains the prepared child-namespace records");
	mu_assert_eq (r_type_kind (anal->sdb_types, "struct Fresh"), R_TYPE_STRUCT, "the applied signature carries its introduced tag identity");
	mu_assert_eq (r_type_kind (anal->sdb_types, "Fresh"), R_TYPE_INVALID, "application does not fabricate an ordinary tag alias");
	char *param = r_type_func_args_type (anal->sdb_types, "tagged", 0);
	mu_assert_streq (param, "struct Fresh *", "the applied parameter references the actual tag");
	free (param);
	r_anal_function_signature_prepared_free (prepared);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_signature_visible_typedef(void) {
	RAnal *anal = r_anal_new ();
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal, "typedef int T;", &error), "make the analysis typedef visible to signature admission");
	const char *inputs[] = { "int f(int (T))", "int h(int (T,T))", "int g(int (*)(T))", "int control(int (value))" };
	const char *names[] = { "f", "h", "g", "control" };
	const char *types[] = { "int (*)(T)", "int (*)(T, T)", "int (*)(T)", "int" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (inputs); i++) {
		RAnalFunction *fcn = r_anal_create_function (anal, names[i], 0x1000 + i * 0x10, R_ANAL_FCN_TYPE_FCN, NULL);
		RAnalFunctionSignaturePrepared *prepared = r_anal_function_signature_prepare (anal, inputs[i], &error);
		mu_assert_notnull (prepared, "prepare the signature using visible analysis bindings before normalization");
		mu_assert_null (error, "contextual signature admission has no diagnostic");
		mu_assert_true (r_anal_function_signature_prepare_target (anal, prepared, fcn, fcn->addr, fcn->name, R_ANAL_SIGNATURE_APPLY_SHARED, &error), "settle the contextual signature target before application");
		mu_assert_true (r_anal_function_signature_apply (anal, fcn, prepared), "apply the admitted callback signature");
		r_anal_function_signature_prepared_free (prepared);
		RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
		mu_assert_notnull (signature, "read back the real applied signature");
		RAnalFunctionParam *param = r_list_first (signature->params);
		mu_assert_notnull (param, "applied signature retains its parameter");
		mu_assert_streq (param->type, types[i], "normalization and application preserve the contextual parameter category");
		if (i == 3) {
			mu_assert_streq (param->name, "value", "grouped ordinary parameter keeps its name");
		}
		r_anal_function_signature_free (signature);
	}
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_signature_tagged_returns(void) {
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 64);
	mu_assert_true (r_anal_import_c_decls (core->anal,
		"struct Big {uint64_t words[3];}; union Choice {uint64_t word;};"
		"enum State {READY=1}; struct Forward;", NULL), "seed genuine tag definitions and a forward declaration");
	const char *returns[] = { "struct Big", "union Choice", "enum State", "struct Forward *" };
	const char *names[] = { "large", "choice", "state", "forward_pointer" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (returns); i++) {
		char *original = r_str_newf ("original%zu", i);
		RAnalFunction *fcn = r_anal_create_function (core->anal, original, i * 0x10, R_ANAL_FCN_TYPE_FCN, NULL);
		free (original);
		RAnalBlock *block = r_anal_create_block (core->anal, fcn->addr, 1);
		r_anal_function_add_block (fcn, block);
		r_unref (block);
		char *input = r_str_newf ("%s %s(void)", returns[i], names[i]);
		char *error = NULL;
		mu_assert_true (r_core_anal_function_set_signature (core, fcn->addr, input, &error), "the selected c2 frontend admits a function with an explicitly tagged return");
		mu_assert_null (error, "tagged return classification does not enter aggregate-body parsing");
		RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
		mu_assert_notnull (signature, "read the actual tagged-return contract");
		mu_assert_streq (signature->ret_type, returns[i], "the function retains the explicit tag namespace and return shape");
		mu_assert_eq (signature->prototype, R_TYPE_FUNC_PROTOTYPE_FIXED, "tagged return admission retains the fixed-empty formal list");
		mu_assert_true (r_list_empty (signature->params), "no hidden-return parameter is fabricated by host admission");
		r_anal_function_signature_free (signature);
		free (input);
	}
	mu_assert_eq (r_anal_type_bitsize (core->anal, "struct Big"), 192, "the direct aggregate-return type retains its genuine three-word layout");
	mu_assert_eq (r_type_kind (core->anal->sdb_types, "struct Forward"), R_TYPE_STRUCT, "forward-tag identity survives function classification");
	mu_assert_eq (r_type_kind (core->anal->sdb_types, "Big"), R_TYPE_INVALID, "tagged return admission does not fabricate a typedef alias");
	RAnalFunction *large = r_anal_get_function_at (core->anal, 0);
	RAnalFunctionSignature input = { .ret_type = "struct Big", .prototype = R_TYPE_FUNC_PROTOTYPE_FIXED };
	r_config_set (core->config, "types.plugin", "tcc");
	mu_assert_true (r_anal_function_set_signature (core->anal, large, &input), "the same actual aggregate return is admitted through trusted structured construction under selected TCC");
	mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "large"), "struct Big", "structured normalization also retains genuine tag identity");
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_signature_prototype_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	RAnalFunction *fcn = r_anal_create_function (anal, "roundtrip", 0x1000, 0, NULL);
	mu_assert_true (r_type_func_set_prototype (anal->sdb_types, "roundtrip", R_TYPE_FUNC_PROTOTYPE_FIXED), "parameter-list knowledge can exist without a declaration or count");
	mu_assert_false (r_type_func_prototype_exist (anal->sdb_types, "roundtrip"), "the specificity fact does not declare a prototype record");
	int unavailable_count = 99;
	mu_assert_false (r_type_func_args_count (anal->sdb_types, "roundtrip", &unavailable_count), "known specificity does not fabricate argument count zero");
	mu_assert_eq (unavailable_count, 99, "unavailable count remains unavailable");
	RAnalFunctionSignature *partial = r_anal_function_get_signature (fcn);
	mu_assert_notnull (partial, "read available knowledge from a partial signature");
	mu_assert_null (partial->type_name, "parameter-list metadata alone does not invent a function record");
	mu_assert_eq (partial->prototype, R_TYPE_FUNC_PROTOTYPE_FIXED, "missing count does not erase known specificity");
	mu_assert_streq (partial->signature, "void roundtrip ();", "the C projection cannot invent fixed-empty inputs from an unavailable count");
	r_anal_function_signature_free (partial);
	RAnalFunctionSignature input = { .signature = "int not_the_authority(void);", .ret_type = "int", .params = r_list_new () };
	RTypeFunctionPrototype states[] = { R_TYPE_FUNC_PROTOTYPE_UNKNOWN, R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED, R_TYPE_FUNC_PROTOTYPE_FIXED };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (states); i++) {
		input.prototype = states[i];
		mu_assert_true (r_anal_function_set_signature (anal, fcn, &input), "set the structured parameter-list fact");
		RAnalFunctionSignature *actual = r_anal_function_get_signature (fcn);
		mu_assert_notnull (actual, "read normalized structured signature");
		mu_assert_eq (actual->prototype, states[i], "temporary C normalization cannot overwrite supplied knowledge");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "func.roundtrip.prototype", NULL), r_type_func_prototype_name (states[i]), "the canonical metadata stores the explicit state");
		mu_assert_streq (actual->signature, states[i] == R_TYPE_FUNC_PROTOTYPE_FIXED? "int roundtrip (void);": "int roundtrip ();", "C text is a projection, with void only for known fixed-empty");
		mu_assert_null (sdb_const_get (anal->sdb_types, "not_the_authority", NULL), "the setter never treats a derived string as its source");
		r_anal_function_signature_free (actual);
	}
	mu_assert_true (r_type_func_set_prototype (anal->sdb_types, "__roundtrip", R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED), "the shared setter follows the existing canonical function-name lookup");
	RTypeFunctionPrototype canonical;
	mu_assert_true (r_type_func_get_prototype (anal->sdb_types, "__roundtrip", &canonical), "the shared getter selects the same function owner");
	mu_assert_eq (canonical, R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED, "canonical lookup preserves the written state");
	mu_assert_null (sdb_const_get (anal->sdb_types, "func.__roundtrip.prototype", NULL), "the setter does not create a shadow metadata owner");
	RAnalFunctionParam value = { .name = "value", .type = "int" };
	r_list_append (input.params, &value);
	input.prototype = R_TYPE_FUNC_PROTOTYPE_UNKNOWN;
	mu_assert_true (r_anal_function_set_signature (anal, fcn, &input), "unknown knowledge does not discard known parameter types");
	RAnalFunctionSignature *actual = r_anal_function_get_signature (fcn);
	mu_assert_notnull (actual, "read known parameters with unknown completeness");
	mu_assert_eq (actual->prototype, R_TYPE_FUNC_PROTOTYPE_UNKNOWN, "typed presentation is not evidence of a fixed contract");
	mu_assert_eq (r_list_length (actual->params), 1, "known parameters survive normalization");
	r_anal_function_signature_free (actual);
	sdb_unset (anal->sdb_types, "func.roundtrip.prototype", 0);
	actual = r_anal_function_get_signature (fcn);
	mu_assert_notnull (actual, "missing source knowledge still permits a signature snapshot");
	mu_assert_eq (actual->prototype, R_TYPE_FUNC_PROTOTYPE_UNKNOWN, "missing metadata is not inferred from argument count");
	r_anal_function_signature_free (actual);
	RTypeFunctionPrototype unchanged = R_TYPE_FUNC_PROTOTYPE_FIXED;
	sdb_set (anal->sdb_types, "func.roundtrip.prototype", "invalid", 0);
	mu_assert_false (r_type_func_get_prototype (anal->sdb_types, "roundtrip", &unchanged), "invalid metadata fails visibly");
	mu_assert_eq (unchanged, R_TYPE_FUNC_PROTOTYPE_FIXED, "failed reads do not normalize invalid metadata");
	mu_assert_null (r_anal_function_get_signature (fcn), "invalid knowledge cannot become an invented signature state");
	ut64 epoch = r_anal_types_dirty_epoch (anal);
	input.prototype = (RTypeFunctionPrototype)99;
	mu_assert_false (r_anal_function_set_signature (anal, fcn, &input), "the structured setter refuses invalid enum values");
	mu_assert_eq (r_anal_types_dirty_epoch (anal), epoch, "invalid structured input cannot mutate metadata");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "func.roundtrip.prototype", NULL), "invalid", "invalid source metadata is preserved for correction");
	mu_assert_true (r_anal_function_del_signature (anal, "roundtrip"), "remove a named signature");
	mu_assert_null (sdb_const_get (anal->sdb_types, "func.roundtrip.prototype", NULL), "signature deletion removes specificity metadata");
	mu_assert_true (r_anal_import_c_decls (anal, "int roundtrip(void);", NULL), "reimport a declared signature");
	r_type_del (anal->sdb_types, "roundtrip");
	mu_assert_null (sdb_const_get (anal->sdb_types, "func.roundtrip.prototype", NULL), "type deletion also removes specificity metadata");
	r_list_free (input.params);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_set_signature_refuses_incomplete_fixed_snapshot(void) {
	size_t count;
	for (count = 0; count < 2; count++) {
		RAnal *anal = r_anal_new ();
		r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
		RAnalFunction *fcn = r_anal_create_function (anal, "partial", 0x1000, 0, NULL);
		sdb_set (anal->sdb_types, "partial", "func", 0);
		sdb_set (anal->sdb_types, "func.partial.ret", "int", 0);
		sdb_set (anal->sdb_types, "func.partial.noreturn", "true", 0);
		sdb_set (anal->sdb_types, "func.partial.prototype", "fixed", 0);
		sdb_set (anal->sdb_types, "func.partial.arg.2", "short,known", 0);
		RAnalVar *hint = count? r_anal_function_set_var (fcn, 8, R_ANAL_VAR_KIND_BPV, "int32_t", 4, true, "hint"): NULL;
		RAnalFunctionSignature *snapshot = r_anal_function_get_signature (fcn);
		mu_assert_notnull (snapshot, "read fixed knowledge with an unavailable formal count");
		mu_assert_eq (snapshot->origin, R_ANAL_FUNCTION_SIGNATURE_ORIGIN_VARIABLES, "available presentation comes from variables, not complete formals");
		mu_assert_eq (r_list_length (snapshot->params), count, "retain available inferred parameter presentation");
		ut64 types_epoch = r_anal_types_dirty_epoch (anal);
		ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
		mu_assert_false (r_anal_function_set_signature (anal, fcn, snapshot), "unchanged partial fixed snapshots cannot publish a complete list");
		mu_assert_null (sdb_const_get (anal->sdb_types, "func.partial.args", NULL), "refusal cannot fabricate a complete zero or shortened count");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "func.partial.arg.2", NULL), "short,known", "independent known parameter facts survive refusal");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "func.partial.noreturn", NULL), "true", "independent return behavior survives refusal");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "func.partial.prototype", NULL), "fixed", "refusal does not erase source specificity");
		mu_assert_eq (r_anal_types_dirty_epoch (anal), types_epoch, "refusal does not mutate the type database");
		mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "refusal does not mutate the function");
		mu_assert_false (fcn->is_noreturn, "refusal does not synchronize independent function state");
		if (count) {
			mu_assert_notnull (hint, "seed the inferred variable");
			mu_assert_streq (hint->name, "hint", "refusal preserves inferred variable identity");
			mu_assert_streq (hint->type, "int32_t", "refusal preserves inferred variable type");
		}
		r_anal_function_signature_free (snapshot);
		r_anal_free (anal);
	}
	mu_end;
}

bool test_r_anal_function_signature_empty_list_specificity(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_true (r_anal_import_c_decls (anal, "int unspecified();int fixed(void);", NULL), "import both empty parameter-list forms");
	RAnalFunction *unspecified = r_anal_create_function (anal, "unspecified", 0x1000, 0, NULL);
	RAnalFunction *fixed = r_anal_create_function (anal, "fixed", 0x2000, 0, NULL);
	RAnalFunctionSignature *first = r_anal_function_get_signature (unspecified);
	RAnalFunctionSignature *second = r_anal_function_get_signature (fixed);
	mu_assert_notnull (first, "read unspecified signature");
	mu_assert_notnull (second, "read fixed signature");
	mu_assert_streq (first->signature, "int unspecified ();", "unspecified empty list retains parentheses");
	mu_assert_streq (second->signature, "int fixed (void);", "fixed zero-input signature retains void");
	mu_assert_eq (first->prototype, R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED, "unspecified is an explicit structured fact");
	mu_assert_eq (second->prototype, R_TYPE_FUNC_PROTOTYPE_FIXED, "fixed is independent of the zero count");
	r_anal_function_signature_free (first);
	r_anal_function_signature_free (second);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_signature_grouped_name(void) {
	char *error = NULL;
	RTypeDecl *decl = r_anal_function_signature_parse ("int (grouped)(int)", NULL, &error);
	mu_assert_notnull (decl, "grouped function identifier is a named signature");
	mu_assert_null (error, "grouped function name has no diagnostic");
	mu_assert_streq (decl->name, "grouped", "signature preparation retains the actual grouped function name");
	mu_assert_eq (decl->type->kind, R_TYPE_DECL_FUNCTION, "the named declaration is a function");
	mu_assert_streq (decl->type->child->base.name, "int", "the return type is not promoted to the function name");
	RTypeDecl *param = r_list_first (decl->type->function.parameters);
	mu_assert_notnull (param, "the grouped function retains its argument");
	mu_assert_null (param->name, "an unnamed int parameter remains unnamed");
	mu_assert_streq (param->type->base.name, "int", "the parameter retains its type");
	r_type_decl_free (decl);
	decl = r_anal_function_signature_parse ("int (object)", NULL, &error);
	mu_assert_null (decl, "a grouped object declaration must not become a signature named int");
	mu_assert_notnull (error, "a grouped object reports signature rejection");
	free (error);
	mu_end;
}

bool test_r_core_anal_function_set_signature(void) {
	const struct {
		const char *declaration;
		const char *parameter_type;
		const char *parameter_name;
		RTypeFunctionPrototype prototype;
	} cases[] = {
		{ "int grid(uint16_t (*values)[2+3])", "uint16_t (*)[2+3]", "values", R_TYPE_FUNC_PROTOTYPE_FIXED },
		{ "int grid(uint16_t (*values)[1|2+3])", "uint16_t (*)[1|2+3]", "values", R_TYPE_FUNC_PROTOTYPE_FIXED },
		{ "int grid(uint16_t (*values)[16>>1])", "uint16_t (*)[16>>1]", "values", R_TYPE_FUNC_PROTOTYPE_FIXED },
		{ "int grid(int (*callback)(int (*nested)(char)))", "int (*)(int (*nested)(char))", "callback", R_TYPE_FUNC_PROTOTYPE_FIXED },
		{ "int grid()", NULL, NULL, R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED },
		{ "int grid(void)", NULL, NULL, R_TYPE_FUNC_PROTOTYPE_FIXED }
	};
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "original", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0x1000, 8);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	RFlagItem *flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "original", 0x1000, 8);
	r_core_seek (core, 0x2000, false);
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		char *error = NULL;
		mu_assert_true (r_core_anal_function_set_signature (core, 0x1002, cases[i].declaration, &error), "apply direct signature at a containing address");
		mu_assert_null (error, "successful direct signature has no error");
		mu_assert_eq (core->addr, 0x2000, "direct signature application does not seek");
		mu_assert_streq (fcn->name, "grid", "direct signature renames the actual containing function");
		mu_assert_ptreq (r_flag_get (core->flags, "grid"), flag, "direct signature renames the function-owned flag");
		RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
		mu_assert_notnull (signature, "read the effective direct signature");
		mu_assert_eq (signature->prototype, cases[i].prototype, "direct signature preserves parameter-list specificity");
		mu_assert_eq (r_list_length (signature->params), cases[i].parameter_type? 1: 0, "direct signature preserves parameter count");
		if (cases[i].parameter_type) {
			RAnalFunctionParam *param = r_list_first (signature->params);
			mu_assert_streq (param->type, cases[i].parameter_type, "array expressions and nested callbacks retain their declarator graphs");
			mu_assert_streq (param->name, cases[i].parameter_name, "the parameter keeps its own name");
		}
		r_anal_function_signature_free (signature);
	}
	r_core_free (core);
	mu_end;
}

bool test_r_core_anal_function_set_signature_errors(void) {
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *other = r_anal_create_function (core->anal, "taken", 16, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 8);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	mu_assert_true (r_anal_import_c_decls (core->anal, "int keep(int value);long taken(char saved);", NULL), "seed both contracts");
	RFlagItem *flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "keep", 0, 8);
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
	const char *declarations[] = { "int (object)", "char taken(void)", "int absent(void)" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (declarations); i++) {
		char *error = NULL;
		mu_assert_false (r_core_anal_function_set_signature (core, i == 2? 0x1000: 2, declarations[i], &error), "invalid declaration, duplicate name and absent function fail");
		mu_assert_notnull (error, "direct signature failure has a diagnostic");
		mu_assert_true (*error, "direct signature diagnostic is not empty");
		if (i == 1) {
			mu_assert_notnull (strstr (error, "taken"), "name-conflict diagnostic identifies the rejected name");
		} else if (i == 2) {
			mu_assert_notnull (strstr (error, "No function defined"), "missing-function diagnostic identifies the failure");
		}
		free (error);
		mu_assert_streq (fcn->name, "keep", "failure preserves function identity");
		mu_assert_streq (other->name, "taken", "failure preserves the conflicting function");
		mu_assert_ptreq (r_flag_get (core->flags, "keep"), flag, "failure preserves the function-owned flag");
		mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "keep"), "int", "failure preserves the prior return type");
		mu_assert_streq (sdb_const_get (core->anal->sdb_types, "func.keep.arg.0", NULL), "int,value", "failure preserves the prior parameter");
		mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "taken"), "long", "failure preserves the conflicting contract");
		mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "failure leaves function metadata unchanged");
		mu_assert_eq (r_anal_types_dirty_epoch (core->anal), types_epoch, "failure leaves type metadata unchanged");
	}
	mu_assert_false (r_core_anal_function_set_signature (core, 2, "int (object)", NULL), "diagnostic output is optional");
	core->rc = R_CMD_RC_SUCCESS;
	r_core_cmd0 (core, "afs char taken(void)");
	mu_assert_eq (core->rc, R_CMD_RC_FAILURE, "CLI signature dispatch reports the same name-conflict failure");
	r_core_seek (core, 0x1000, false);
	core->rc = R_CMD_RC_SUCCESS;
	r_core_cmd0 (core, "afs int absent(void)");
	mu_assert_eq (core->rc, R_CMD_RC_FAILURE, "CLI signature dispatch reports the missing-function failure");
	mu_assert_streq (fcn->name, "keep", "CLI failures preserve the prior identity");
	mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "keep"), "int", "CLI failures preserve the prior contract");
	r_core_free (core);
	mu_end;
}

bool test_r_core_afs_rejects_grouped_object_without_mutation(void) {
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	mu_assert_true (r_anal_str_to_fcn (core->anal, fcn, "int keep(int value);"), "seed the existing function contract");
	RFlagItem *flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "keep", 0, 1);
	mu_assert_notnull (flag, "seed the function-owned flag");
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
	r_core_cmd0 (core, "afs int (object)");
	mu_assert_streq (fcn->name, "keep", "a rejected grouped object cannot rename the function");
	mu_assert_ptreq (r_flag_get (core->flags, "keep"), flag, "a rejected grouped object cannot rename the function flag");
	mu_assert_null (r_flag_get (core->flags, "int"), "the return keyword must not become a function flag");
	mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "keep"), "int", "the original prototype return type survives rejection");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "func.keep.arg.0", NULL), "int,value", "the original prototype argument survives rejection");
	mu_assert_null (sdb_const_get (core->anal->sdb_types, "func.int.ret", NULL), "rejection does not install a keyword-named prototype");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "rejection leaves function metadata unchanged");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), types_epoch, "rejection leaves type metadata unchanged");
	char *json_text = r_core_cmd_str (core, "afsj");
	RJson *json = r_json_parsedup (json_text);
	mu_assert_notnull (json, "signature JSON is valid");
	mu_assert_streq (r_json_get_str (json, "prototype"), "fixed", "signature JSON carries the structured specificity");
	r_json_free (json);
	free (json_text);
	json_text = r_core_cmd_str (core, "afij");
	json = r_json_parsedup (json_text);
	mu_assert_notnull (json, "function-info JSON is valid");
	mu_assert_streq (r_json_get_str (r_json_item (json, 0), "prototype"), "fixed", "function-info JSON carries the same specificity");
	r_json_free (json);
	free (json_text);
	r_core_cmd0 (core, "afn renamed");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "func.renamed.prototype", NULL), "fixed", "rename transfers the specificity owner");
	mu_assert_null (sdb_const_get (core->anal->sdb_types, "func.keep.prototype", NULL), "rename leaves no stale specificity owner");
	r_core_free (core);
	mu_end;
}

bool test_r_anal_str_to_fcn_does_not_retry_rejected_header(void) {
	RAnal *anal = r_anal_new ();
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	RAnalFunction *fcn = r_anal_create_function (anal, "keep", 0x3000, 0, NULL);
	mu_assert_true (r_anal_str_to_fcn (anal, fcn, "int keep(int value);"), "seed the existing signature");
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 types_epoch = r_anal_types_dirty_epoch (anal);
	mu_assert_false (r_anal_str_to_fcn (anal, fcn, "struct Unexpected {int member;};"), "a rejected signature must not retry as an unrelated header");
	mu_assert_null (sdb_const_get (anal->sdb_types, "Unexpected", NULL), "rejected signature input cannot import an unrelated aggregate");
	mu_assert_streq (r_type_func_ret (anal->sdb_types, "keep"), "int", "rejection preserves the original function contract");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "refused header leaves the function unchanged");
	mu_assert_eq (r_anal_types_dirty_epoch (anal), types_epoch, "refused header leaves the type database unchanged");
	r_anal_free (anal);
	mu_end;
}

bool test_r_core_afs_preserves_compound_return_name_and_flags(void) {
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	RAnalFunction *fcn = r_anal_create_function (core->anal, "original", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	mu_assert_notnull (r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "original", 0, 1), "seed function-owned flag");
	RFlagItem *symbol = r_flag_set_inspace (core->flags, R_FLAGS_FS_SYMBOLS, "sym.original", 0, 1);
	mu_assert_notnull (symbol, "seed independent symbol flag");
	mu_assert_true (r_anal_import_c_decls (core->anal, "int returns_table(int old);", NULL), "seed an occupied shared name before the compound local edit");
	mu_assert_eq (r_core_cmd0 (core, "afs uint16_t far *(near *returns_table(void))[3]"), 0, "apply manual compound signature");
	mu_assert_streq (fcn->name, "returns_table", "manual afs uses the function's declarator name");
	RFlagItem *flag = r_flag_get (core->flags, "returns_table");
	mu_assert_notnull (flag, "manual afs renames the function-owned flag");
	mu_assert_streq (flag->space->name, R_FLAGS_FS_FUNCTIONS, "renamed flag stays in functions space");
	mu_assert_null (r_flag_get (core->flags, "original"), "old function-owned flag is removed");
	mu_assert_ptreq (r_flag_get (core->flags, "sym.original"), symbol, "manual afs preserves independent symbol flags");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	mu_assert_notnull (signature, "read manual compound signature");
	mu_assert_streq (signature->ret_type, "uint16_t far *(near *)[3]", "manual afs preserves the return graph");
	mu_assert_streq (signature->signature, "uint16_t far *(near *returns_table (void))[3];", "render the named compound declaration");
	mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "returns_table"), "int", "local compound application does not replace the occupied shared type");
	r_anal_function_signature_free (signature);
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
	r_core_cmd0 (core, "afs int (*)(int)");
	mu_assert_streq (fcn->name, "returns_table", "unnamed declaration cannot rename the function");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "refused unnamed declaration leaves function unchanged");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), types_epoch, "refused unnamed declaration leaves types unchanged");
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_structured_signature_preserves_raw_callconv(void) {
	RAnal *anal = r_anal_new ();
	r_anal_cc_reset (anal);
	mu_assert_true (r_anal_cc_set (anal, "void configured (stack)"), "seed the effective default");
	r_anal_set_cc_default (anal, "configured");
	mu_assert_true (r_anal_import_c_decls (anal, "int scanf(const char *format);", NULL), "seed the canonical shared record");
	RAnalFunction *fcn = r_anal_create_function (anal, "sym.imp.__isoc99_scanf", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	anal->opt.tparser = strdup ("tcc");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	mu_assert_notnull (signature, "read the effective signature");
	mu_assert_nullable_streq (signature->type_name, "scanf", "raw facts belong to the canonical selected record");
	mu_assert_streq (signature->callconv, "configured", "effective configuration remains available");
	free (signature->callconv);
	signature->callconv = NULL;
	mu_assert_true (r_anal_function_set_signature (anal, fcn, signature), "structured writeback accepts an omitted source convention under TCC");
	mu_assert_null (sdb_const_get (anal->sdb_types, "func.scanf.cc", NULL), "omission does not fabricate an explicit effective-default fact");
	mu_assert_streq (r_anal_function_cc (fcn), "configured", "the effective default remains independent of source omission");
	sdb_set (anal->sdb_types, "func.scanf.cc", "native_only", 0);
	mu_assert_true (r_anal_function_set_signature (anal, fcn, signature), "omitted update retains an existing raw native-only convention");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "func.scanf.cc", NULL), "native_only", "the raw source fact is not replaced by a host-supported fallback");
	mu_assert_streq (r_anal_function_cc (fcn), "configured", "existing effective-callconv policy remains unchanged");
	signature->callconv = strdup ("replacement_native");
	mu_assert_true (r_anal_function_set_signature (anal, fcn, signature), "explicit structured input updates the raw fact");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "func.scanf.cc", NULL), "replacement_native", "explicit input is retained without imposing host support");
	signature->noreturn = true;
	mu_assert_true (r_anal_function_set_signature (anal, fcn, signature), "structured noreturn is supplied independently of the declaration node");
	mu_assert_true (fcn->is_noreturn, "the supplied noreturn fact reaches the function");
	signature->noreturn = false;
	mu_assert_true (r_anal_function_set_signature (anal, fcn, signature), "a structured update can clear noreturn");
	mu_assert_false (fcn->is_noreturn, "false is not replaced by stale effective noreturn");
	r_anal_function_signature_free (signature);
	r_anal_free (anal);
	mu_end;
}

bool test_r_core_signature_long_isolation_admission(void) {
	int occupied;
	for (occupied = 0; occupied < 2; occupied++) {
		RCore *core = r_core_new ();
		RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
		RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
		r_anal_function_add_block (fcn, block);
		r_unref (block);
		mu_assert_true (r_anal_import_c_decls (core->anal, "int keep(int value);", NULL), "seed the existing contract");
		RFlagItem *flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "keep", 0, 1);
		char name[240];
		memset (name, 'a', sizeof (name) - 1);
		name[sizeof (name) - 1] = 0;
		if (occupied) {
			char *header = r_str_newf ("long %s(void);", name);
			mu_assert_true (r_anal_import_c_decls (core->anal, header, NULL), "the unsuffixed 239-character record is representable");
			free (header);
		}
		char *before = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
		ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
		ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
		char *input = r_str_newf ("char %s(void)", name);
		char *error = NULL;
		bool applied = r_core_anal_function_set_signature (core, 0, input, &error);
		if (occupied) {
			mu_assert_false (applied, "an unrepresentable final isolation key refuses before mutation");
			mu_assert_notnull (error, "final-key refusal is reported");
			mu_assert_streq (fcn->name, "keep", "isolation failure does not rename the function");
			mu_assert_ptreq (r_flag_get (core->flags, "keep"), flag, "isolation failure preserves the function flag");
			mu_assert_null (r_flag_get (core->flags, name), "isolation failure does not publish a destination flag");
			mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "isolation failure preserves the function epoch");
			mu_assert_eq (r_anal_types_dirty_epoch (core->anal), types_epoch, "isolation failure preserves the type epoch");
			char *after = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
			mu_assert_streq (after, before, "isolation failure preserves every existing native record and link");
			free (after);
		} else {
			mu_assert_true (applied, "a complete representable final key remains supported");
			mu_assert_null (error, "representable long key has no refusal");
			mu_assert_streq (fcn->name, name, "the long function name is not truncated or remapped");
			RAnalFunctionSignature *actual = r_anal_function_get_signature (fcn);
			mu_assert_notnull (actual, "the complete applied long-name contract is readable");
			mu_assert_nullable_streq (actual->type_name, name, "the exact long key owns the admitted contract");
			mu_assert_streq (actual->ret_type, "char", "long-name admission retains the return record");
			mu_assert_eq (actual->prototype, R_TYPE_FUNC_PROTOTYPE_FIXED, "long-name admission retains parameter-list knowledge");
			mu_assert_true (r_list_empty (actual->params), "the long-name fixed-empty list remains complete");
			r_anal_function_signature_free (actual);
		}
		free (error);
		free (input);
		free (before);
		r_core_free (core);
	}
	mu_end;
}

bool test_r_core_signature_preserves_independent_flags(void) {
	int normalized;
	for (normalized = 0; normalized < 2; normalized++) {
		RCore *core = r_core_new ();
		r_config_set (core->config, "asm.arch", "x86");
		r_config_set_i (core->config, "asm.bits", 64);
		RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
		RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
		r_anal_function_add_block (fcn, block);
		r_unref (block);
		mu_assert_true (r_anal_import_c_decls (core->anal, "int keep(int value);", NULL), "seed the original signature");
		RFlagItem *flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "keep", 0, 1);
		const char *destination = normalized? "fcn.00000000": "edited";
		if (normalized) {
			mu_assert_notnull (r_reg_get (core->anal->reg, "rax", -1), "the register-name witness exercises Core's established normalization");
		}
		RFlagItem *independent = r_flag_set_inspace (core->flags, R_FLAGS_FS_SYMBOLS, destination, 16, 8);
		char *before = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
		ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
		ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
		char *error = NULL;
		mu_assert_false (r_core_anal_function_set_signature (core, 0, normalized? "char rax(void)": "char edited(void)", &error), "independent final flag ownership refuses before application");
		mu_assert_notnull (error, "the independent flag conflict is reported");
		mu_assert_streq (fcn->name, "keep", "flag refusal preserves function identity");
		mu_assert_ptreq (r_flag_get (core->flags, "keep"), flag, "flag refusal preserves the function-owned flag");
		mu_assert_ptreq (r_flag_get (core->flags, destination), independent, "the independent destination flag is not replaced");
		mu_assert_eq (independent->addr, 16, "the independent flag is not moved");
		mu_assert_eq (independent->size, 8, "the independent flag extent is unchanged");
		mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "flag refusal preserves the function epoch");
		mu_assert_eq (r_anal_types_dirty_epoch (core->anal), types_epoch, "flag refusal preserves the type epoch");
		char *after = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
		mu_assert_streq (after, before, "flag refusal preserves native records and address links");
		free (after);
		free (before);
		free (error);
		r_core_free (core);
	}
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	RFlagItem *independent = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "keep", 16, 8);
	mu_assert_true (r_core_anal_function_set_signature (core, 0, "char edited(void)", NULL), "an unrelated old same-name flag does not own the addressed function");
	mu_assert_ptreq (r_flag_get (core->flags, "keep"), independent, "an independent old same-name flag is not renamed");
	mu_assert_eq (independent->addr, 16, "the independent old flag retains its address");
	mu_assert_streq (fcn->name, "edited", "the addressed function still receives its admitted name");
	RFlagItem *edited = r_flag_get (core->flags, "edited");
	mu_assert_notnull (edited, "the addressed function receives its own new flag");
	mu_assert_eq (edited->addr, 0, "the new function flag names the addressed owner");
	r_core_free (core);
	mu_end;
}

static int signature_parser_calls;
static bool signature_parser_saw_original;
static RAnalFunction *signature_parser_function;

static char *signature_parser_refuse(RAnal *anal, const char *text) {
	signature_parser_calls++;
	signature_parser_saw_original = !strcmp (signature_parser_function->name, "keep")
		&& !strcmp (r_type_func_ret (anal->sdb_types, "keep"), "int");
	return NULL;
}

static char *signature_parser_admit(RAnal *anal, const char *text) {
	signature_parser_calls++;
	signature_parser_saw_original = !strcmp (signature_parser_function->name, "keep");
	char *parser = anal->opt.tparser;
	anal->opt.tparser = NULL;
	char *result = r_anal_cparse (anal, text, NULL);
	anal->opt.tparser = parser;
	return result;
}

static char *signature_parser_wrong_function(RAnal *anal, const char *text) {
	signature_parser_refuse (anal, text);
	return strdup ("other=func\nfunc.other.args=0\nfunc.other.ret=char\nfunc.other.prototype=fixed\n");
}

bool test_r_core_afs_requires_the_requested_function(void) {
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	mu_assert_true (r_anal_str_to_fcn (core->anal, fcn, "int keep(int value);"), "seed the original contract");
	RAnalPlugin parser = { .meta = { .name = "wrong_function" }, .tparse_text = signature_parser_wrong_function };
	r_anal_plugin_add (core->anal, &parser);
	r_config_set (core->config, "types.plugin", parser.meta.name);
	signature_parser_calls = 0;
	signature_parser_function = fcn;
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
	char *error = NULL;
	mu_assert_false (r_core_anal_function_set_signature (core, 0, "char requested(void)", &error), "arbitrary parser output cannot substitute its first function for the requested declaration");
	mu_assert_notnull (error, "missing requested function is an admission refusal");
	mu_assert_eq (signature_parser_calls, 1, "the selected parser is consulted exactly once");
	mu_assert_true (signature_parser_saw_original, "parser output is admitted before changing identity");
	mu_assert_streq (fcn->name, "keep", "wrong-function output cannot rename the target");
	mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "wrong-function refusal preserves the function epoch");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), types_epoch, "wrong-function refusal preserves the type epoch");
	mu_assert_null (sdb_const_get (core->anal->sdb_types, "other", NULL), "unselected parser records are not published");
	free (error);
	r_core_free (core);
	mu_end;
}

bool test_r_core_afs_selected_parser_refuses_before_mutation(void) {
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	mu_assert_true (r_anal_str_to_fcn (core->anal, fcn, "int keep(int value);"), "seed the admitted contract");
	RFlagItem *flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "keep", 0, 1);
	RAnalPlugin parser = { .meta = { .name = "signature_refusal" }, .tparse_text = signature_parser_refuse };
	r_anal_plugin_add (core->anal, &parser);
	r_config_set (core->config, "types.plugin", parser.meta.name);
	signature_parser_calls = 0;
	signature_parser_function = fcn;
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
	r_core_cmd0 (core, "afs char denied(void)");
	bool identity_unchanged = !strcmp (fcn->name, "keep") && r_flag_get (core->flags, "keep") == flag
		&& !r_flag_get (core->flags, "denied");
	const char *ret = r_type_func_ret (core->anal->sdb_types, "keep");
	bool contract_unchanged = ret && !strcmp (ret, "int")
		&& !sdb_const_get (core->anal->sdb_types, "denied", NULL);
	bool epochs_unchanged = r_anal_function_dirty_epoch (fcn) == function_epoch
		&& r_anal_types_dirty_epoch (core->anal) == types_epoch;
	r_core_free (core);
	mu_assert_eq (signature_parser_calls, 1, "the selected parser admits exactly once");
	mu_assert_true (signature_parser_saw_original, "local rejecting callback runs before identity mutation");
	mu_assert_true (identity_unchanged, "selected-parser rejection preserves function and flag identity");
	mu_assert_true (contract_unchanged, "selected-parser rejection preserves the contract");
	mu_assert_true (epochs_unchanged, "selected-parser rejection leaves both epochs unchanged");
	mu_end;
}

bool test_r_core_afs_reuses_selected_parser_admission(void) {
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	RAnalPlugin parser = { .meta = { .name = "signature_admission" }, .tparse_text = signature_parser_admit };
	r_anal_plugin_add (core->anal, &parser);
	r_config_set (core->config, "types.plugin", parser.meta.name);
	signature_parser_calls = 0;
	signature_parser_function = fcn;
	r_core_cmd0 (core, "afs admitted.name();;");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	bool accepted = signature && !strcmp (fcn->name, "admitted.name") && !strcmp (signature->ret_type, "void")
		&& signature->prototype == R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED
		&& !sdb_const_get (core->anal->sdb_types, "link.00000000", NULL);
	r_anal_function_signature_free (signature);
	r_core_free (core);
	mu_assert_eq (signature_parser_calls, 1, "the selected parser's admitted result is not reparsed after rename");
	mu_assert_true (signature_parser_saw_original, "local admitting callback observes the original function identity");
	mu_assert_true (accepted, "normalization preserves dotted omitted-return syntax and specificity");
	mu_end;
}

bool test_r_core_afs_name_collision_preserves_state(void) {
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "keep", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *other = r_anal_create_function (core->anal, "taken", 16, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	mu_assert_true (r_anal_import_c_decls (core->anal, "int keep(int value);long taken(char saved);", NULL), "seed both contracts");
	RFlagItem *flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "keep", 0, 1);
	RFlagItem *other_flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "taken", 16, 1);
	ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
	r_core_cmd0 (core, "afs char taken(void)");
	bool identity_unchanged = !strcmp (fcn->name, "keep") && !strcmp (other->name, "taken")
		&& r_flag_get (core->flags, "keep") == flag && r_flag_get (core->flags, "taken") == other_flag;
	const char *ret = r_type_func_ret (core->anal->sdb_types, "keep");
	bool contract_unchanged = ret && !strcmp (ret, "int")
		&& !strcmp (r_type_func_ret (core->anal->sdb_types, "taken"), "long");
	bool epochs_unchanged = r_anal_function_dirty_epoch (fcn) == function_epoch
		&& r_anal_types_dirty_epoch (core->anal) == types_epoch;
	r_core_free (core);
	mu_assert_true (identity_unchanged, "duplicate function name preserves both function-owned flags");
	mu_assert_true (contract_unchanged, "duplicate function name preserves both prototypes");
	mu_assert_true (epochs_unchanged, "ordinary name collision leaves metadata epochs unchanged");
	mu_end;
}

bool test_r_core_afs_updates_effective_binding(void) {
	const struct {
		const char *link;
		const char *source;
		const char *input;
		RTypeFunctionPrototype prototype;
		bool destination;
	} cases[] = {
		{ NULL, "original", "afs char target(void)", R_TYPE_FUNC_PROTOTYPE_FIXED, true },
		{ "link", "linked", "afs char target()", R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED, false },
		{ "link", "original", "afs char target(void)", R_TYPE_FUNC_PROTOTYPE_FIXED, false },
		{ "fcnlink", "original", "afs char target()", R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED, false },
		{ "fcnlink", "linked", "afs char target(void)", R_TYPE_FUNC_PROTOTYPE_FIXED, false },
		{ "fcnlink", "linked", "afs char target(void)", R_TYPE_FUNC_PROTOTYPE_FIXED, true }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RCore *core = r_core_new ();
		RAnalFunction *fcn = r_anal_create_function (core->anal, "original", 0, R_ANAL_FCN_TYPE_FCN, NULL);
		RAnalFunction *other = r_anal_create_function (core->anal, cases[i].link? "other": "dbg.original", 16, R_ANAL_FCN_TYPE_FCN, NULL);
		RAnalBlock *block = r_anal_create_block (core->anal, 0, 8);
		r_anal_function_add_block (fcn, block);
		r_unref (block);
		mu_assert_true (r_anal_import_c_decls (core->anal, "int original(int old);short linked(char saved);", NULL), "seed the source and linked contracts");
		mu_assert_true (r_anal_cc_set (core->anal, "void sharedcc (stack)"), "seed the shared source convention");
		sdb_set (core->anal->sdb_types, "func.original.cc", "sharedcc", 0);
		sdb_set (core->anal->sdb_types, "func.linked.cc", "sharedcc", 0);
		sdb_set (core->anal->sdb_types, "func.original.noreturn", "true", 0);
		sdb_set (core->anal->sdb_types, "func.linked.noreturn", "true", 0);
		if (cases[i].destination) {
			mu_assert_true (r_anal_import_c_decls (core->anal, "long target(void);", NULL), "seed an occupied destination prototype");
		}
		if (cases[i].link) {
			sdb_setf (core->anal->sdb_types, cases[i].source, 0, "%s.%08" PFMT64x, cases[i].link, fcn->addr);
			sdb_setf (core->anal->sdb_types, cases[i].source, 0, "%s.%08" PFMT64x, cases[i].link, other->addr);
		}
		RAnalFunctionSignature *before = r_anal_function_get_signature (other);
		mu_assert_notnull (before, "read the other function's shared contract before the edit");
		RFlagItem *flag = r_flag_set_inspace (core->flags, R_FLAGS_FS_FUNCTIONS, "original", 0, 8);
		RFlagItem *symbol = r_flag_set_inspace (core->flags, R_FLAGS_FS_SYMBOLS, "sym.original", 0, 8);
		r_core_seek (core, 4, true);
		r_core_cmd0 (core, cases[i].input);
		RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
		bool identity_updated = !strcmp (fcn->name, "target") && r_flag_get (core->flags, "target") == flag
			&& r_flag_get (core->flags, "sym.original") == symbol;
		bool contract_updated = signature && signature->ret_type && !strcmp (signature->ret_type, "char") && r_list_empty (signature->params)
			&& signature->prototype == cases[i].prototype;
		RAnalFunctionSignature *after = r_anal_function_get_signature (other);
		bool other_unchanged = after && !strcmp (before->signature, after->signature) && before->prototype == after->prototype
			&& before->noreturn == after->noreturn && !strcmp (before->callconv, after->callconv);
		const char *source_ret = r_type_func_ret (core->anal->sdb_types, cases[i].source);
		bool source_unchanged = source_ret && !strcmp (source_ret, !strcmp (cases[i].source, "linked")? "short": "int")
			&& sdb_num_getf (core->anal->sdb_types, NULL, "func.%s.args", cases[i].source) == 1;
		const char *other_link = cases[i].link? sdb_const_getf (core->anal->sdb_types, NULL, "%s.%08" PFMT64x, cases[i].link, other->addr): NULL;
		bool links_preserved = !cases[i].link || (other_link && !strcmp (other_link, cases[i].source));
		const char *destination = r_type_func_ret (core->anal->sdb_types, "target");
		bool destination_preserved = !cases[i].destination || (destination && !strcmp (destination, "long"));
		char *private_type = r_type_link_at (core->anal->sdb_types, fcn->addr);
		bool isolated = private_type && strcmp (private_type, cases[i].source);
		bool selected_identity = signature && signature->type_name && private_type && !strcmp (signature->type_name, private_type);
		ut64 types_epoch = r_anal_types_dirty_epoch (core->anal);
		r_core_cmd0 (core, cases[i].input);
		char *repeated_type = r_type_link_at (core->anal->sdb_types, fcn->addr);
		bool repeated_unchanged = private_type && repeated_type && !strcmp (private_type, repeated_type)
			&& r_anal_types_dirty_epoch (core->anal) == types_epoch;
		free (private_type);
		free (repeated_type);
		r_anal_function_signature_free (before);
		r_anal_function_signature_free (after);
		r_anal_function_signature_free (signature);
		r_core_free (core);
		mu_assert_true (identity_updated, "afs at a contained address renames the owning function and flag, not its symbol");
		mu_assert_true (contract_updated, "afs applies the admitted result to the selected effective contract");
		mu_assert_true (isolated, "a command edit selects its own ordinary function record through the addressed link");
		mu_assert_true (selected_identity, "the signature snapshot identifies the isolated return and parameter record");
		mu_assert_true (other_unchanged, "explicit and name-derived shared lookup cannot change the other function");
		mu_assert_true (source_unchanged, "command rename and application preserve the shared source type");
		mu_assert_true (links_preserved, "other explicit address and DWARF links keep their source owner");
		mu_assert_true (destination_preserved, "an occupied destination keeps its unrelated contract");
		mu_assert_true (repeated_unchanged, "an unchanged repeated command does not create another ordinary type record");
	}
	mu_end;
}

bool test_r_core_signature_isolation_avoids_other_name_matches(void) {
	RCore *core = r_core_new ();
	mu_assert_true (r_anal_import_c_decls (core->anal, "int edited(int old);", NULL), "seed the source type that must remain shared");
	RAnalFunction *fcn = r_anal_create_function (core->anal, "original", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *other = r_anal_create_function (core->anal, "dbg.edited_0", 16, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	r_type_set_link (core->anal->sdb_types, "edited", fcn->addr);
	RAnalFunctionSignature *before = r_anal_function_get_signature (other);
	mu_assert_notnull (before, "read the other function's original name-based presentation");
	mu_assert_true (r_core_anal_function_set_signature (core, 0, "char edited(void)", NULL), "apply a function-local edit through the direct Core facade");
	RAnalFunctionSignature *after = r_anal_function_get_signature (other);
	mu_assert_notnull (after, "read the other function after candidate selection");
	mu_assert_streq (before->signature, after->signature, "the new ordinary key cannot become another function's name-based match");
	mu_assert_null (sdb_const_get (core->anal->sdb_types, "edited_0", NULL), "an unused but shadowing ordinary name is not selected");
	mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "edited"), "int", "the shared source is not overwritten");
	r_anal_function_signature_free (before);
	r_anal_function_signature_free (after);
	r_core_free (core);
	mu_end;
}

bool test_r_core_signature_isolation_preserves_dormant_peer_bindings(void) {
	const char *bindings[] = { "link", "fcnlink" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bindings); i++) {
		RCore *core = r_core_new ();
		r_config_set (core->config, "asm.arch", "x86");
		r_config_set_i (core->config, "asm.bits", 64);
		mu_assert_notnull (r_core_file_open (core, "malloc://64", R_PERM_RW, 0), "open the actual function bytes");
		mu_assert_true (r_core_bin_load (core, NULL, UT64_MAX), "map the raw function buffer through Core loading");
		r_core_cmd0 (core, "wx c3 @ 0;wx c3 @ 0x10;af+ 0 original;af+ 0x10 peer;td int future(void)");
		ut8 ret;
		mu_assert_true (r_io_read_at (core->io, 0, &ret, 1), "read the addressed function's actual body");
		mu_assert_eq (ret, 0xc3, "the addressed function contains a real return instruction");
		mu_assert_true (r_io_read_at (core->io, 0x10, &ret, 1), "read the peer function's actual body");
		mu_assert_eq (ret, 0xc3, "the peer function contains a real return instruction");
		RAnalFunction *original = r_anal_get_function_at (core->anal, 0);
		RAnalFunction *peer = r_anal_get_function_at (core->anal, 0x10);
		mu_assert_notnull (original, "create the addressed function");
		mu_assert_notnull (peer, "create the peer function");
		RAnalBlock *block = r_anal_create_block (core->anal, original->addr, 1);
		r_anal_function_add_block (original, block);
		r_unref (block);
		block = r_anal_create_block (core->anal, peer->addr, 1);
		r_anal_function_add_block (peer, block);
		r_unref (block);
		char *binding = r_str_newf ("%s.%08" PFMT64x, bindings[i], peer->addr);
		char *command = r_str_newf ("tk %s=future", binding);
		r_core_cmd0 (core, command);
		free (command);
		r_core_cmd0 (core, "t- future");
		mu_assert_null (sdb_const_get (core->anal->sdb_types, "future", NULL), "normal deletion removes the fixed-empty producer's type owner");
		mu_assert_null (sdb_const_get (core->anal->sdb_types, "func.future", NULL), "no typed-argument name row masks the dormant-binding witness");
		mu_assert_streq (sdb_const_get (core->anal->sdb_types, binding, NULL), "future", "normal deletion retains the demonstrated dormant binding");
		RAnalFunctionSignature *before = r_anal_function_get_signature (peer);
		mu_assert_notnull (before, "read the peer after deleting its target type");
		mu_assert_streq (before->signature, "void peer ();", "the dormant peer has no known return or formal-list declaration");
		mu_assert_eq (before->prototype, R_TYPE_FUNC_PROTOTYPE_UNKNOWN, "the dormant peer has unknown source specificity");
		ut64 peer_epoch = r_anal_function_dirty_epoch (peer);
		r_core_seek (core, original->addr, false);
		r_core_cmd0 (core, "afs char future(void)");
		RAnalFunctionSignature *after = r_anal_function_get_signature (peer);
		RAnalFunctionSignature *edited = r_anal_function_get_signature (original);
		bool peer_unchanged = after && !strcmp (before->signature, after->signature)
			&& after->prototype == R_TYPE_FUNC_PROTOTYPE_UNKNOWN && r_list_empty (after->params)
			&& r_anal_function_dirty_epoch (peer) == peer_epoch;
		bool edit_applied = edited && edited->ret_type && !strcmp (edited->ret_type, "char")
			&& edited->prototype == R_TYPE_FUNC_PROTOTYPE_FIXED && r_list_empty (edited->params);
		const char *retained = sdb_const_get (core->anal->sdb_types, binding, NULL);
		bool binding_unchanged = retained && !strcmp (retained, "future");
		free (binding);
		r_anal_function_signature_free (before);
		r_anal_function_signature_free (after);
		r_anal_function_signature_free (edited);
		r_core_free (core);
		mu_assert_true (peer_unchanged, "creating an isolated signature cannot activate another function's dormant link or fcnlink");
		mu_assert_true (binding_unchanged, "the peer's dormant binding is not deleted or rewritten");
		mu_assert_true (edit_applied, "the addressed fixed-empty declaration still applies successfully");
	}
	mu_end;
}

bool test_r_core_afs_overrides_import_for_only_the_current_function(void) {
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "original", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0, 1);
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	mu_assert_true (r_anal_import_c_decls (core->anal, "long library(char saved);", NULL), "seed a shared library signature");
	RFlagItem *import = r_flag_set_inspace (core->flags, R_FLAGS_FS_IMPORTS, "sym.imp.library", 0, 1);
	r_core_cmd0 (core, "afs int edited(void)");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	mu_assert_notnull (signature, "the current function has its edited contract");
	mu_assert_streq (fcn->name, "edited", "the explicit declaration supplies the function name");
	mu_assert_streq (signature->ret_type, "int", "the import flag does not shadow the supplied contract");
	mu_assert_eq (signature->prototype, R_TYPE_FUNC_PROTOTYPE_FIXED, "the admitted fixed-empty contract is retained");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.00000000", NULL), "edited", "existing address association selects the function-owned declaration");
	mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "library"), "long", "the shared library return remains unchanged");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "func.library.arg.0", NULL), "char,saved", "the shared library parameters remain unchanged");
	mu_assert_ptreq (r_flag_get (core->flags, "sym.imp.library"), import, "the independent import flag remains unchanged");
	r_anal_function_signature_free (signature);
	r_core_free (core);
	mu_end;
}

bool test_r_core_afn_migrates_explicit_prototype_links(void) {
	RCore *core = r_core_new ();
	RAnalFunction *fcn = r_anal_create_function (core->anal, "original", 0, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_true (r_anal_import_c_decls (core->anal, "int original();", NULL), "seed a renameable prototype");
	sdb_set (core->anal->sdb_types, "link.00000000", "original", 0);
	sdb_set (core->anal->sdb_types, "fcnlink.00000020", "original", 0);
	r_core_cmd0 (core, "afn migrated");
	mu_assert_streq (fcn->name, "migrated", "ordinary afn retains its rename behavior");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.00000000", NULL), "migrated", "ordinary rename retains the explicit address association");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "fcnlink.00000020", NULL), "migrated", "other explicit references to the moved prototype do not dangle");
	mu_assert_null (sdb_const_get (core->anal->sdb_types, "original", NULL), "the original owner is actually moved");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	mu_assert_notnull (signature, "the moved prototype remains readable");
	mu_assert_eq (signature->prototype, R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED, "ordinary rename retains parameter-list knowledge");
	r_anal_function_signature_free (signature);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_get_signature_string_resolves_import_flag_prototype(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Couldn't create new RCore");
	RAnal *anal = core->anal;
	bool ok = r_anal_import_c_decls (anal, "int scanf (const char *fmt);", NULL);
	mu_assert_true (ok, "seed canonical scanf signature");

	RAnalFunction *f = r_anal_create_function (anal, "fcn.00003000", 0x3000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for import flag test");
	mu_assert_notnull (
		r_flag_set_inspace (core->flags, R_FLAGS_FS_IMPORTS, "sym.imp.__isoc99_scanf", f->addr, 0),
		"Couldn't create import flag for function"
	);

	char *sig = r_anal_function_get_signature_string (f);
	mu_assert_notnull (sig, "import flag signature");
	// the prototype is resolved through the import flag, but the declaration
	// names the function so that an unedited afs! cannot rename it
	mu_assert_streq (sig, "int fcn.00003000 (const char *fmt);", "import flag must resolve canonical prototype");
	free (sig);
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_get_signature_uses_basename_for_dbg_prefixed_function(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	bool ok = r_anal_import_c_decls (anal, "char * alloc_and_copy (char *src, size_t len);", NULL);
	mu_assert_true (ok, "seed canonical alloc_and_copy signature");

	RAnalFunction *f = r_anal_create_function (anal, "dbg.alloc_and_copy", 0x3100, 0, NULL);
	mu_assert_notnull (f, "Couldn't create dbg-prefixed function");

	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "dbg-prefixed function must resolve canonical basename signature");
	mu_assert_nullable_streq (signature->type_name, "alloc_and_copy", "snapshot identifies the basename-selected record");
	mu_assert_streq (signature->ret_type, "char *", "dbg-prefixed return type");
	mu_assert_eq ((int)r_list_length (signature->params), 2, "dbg-prefixed param count");
	RAnalFunctionParam *arg0 = r_list_get_n (signature->params, 0);
	RAnalFunctionParam *arg1 = r_list_get_n (signature->params, 1);
	mu_assert_notnull (arg0, "first dbg-prefixed param");
	mu_assert_notnull (arg1, "second dbg-prefixed param");
	mu_assert_streq (arg0->name, "src", "first dbg-prefixed param name");
	mu_assert_streq (arg0->type, "char *", "first dbg-prefixed param type");
	mu_assert_streq (arg1->name, "len", "second dbg-prefixed param name");
	mu_assert_streq (arg1->type, "size_t", "second dbg-prefixed param type");
	r_anal_function_signature_free (signature);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_get_signature_string_falls_back_to_vars(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *f = r_anal_create_function (anal, "foo", 0x4000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for var fallback test");
	mu_assert_notnull (
		r_anal_function_set_var (f, 8, R_ANAL_VAR_KIND_BPV, "int32_t", 4, true, "arg_ch"),
		"Couldn't add second arg var");
	mu_assert_notnull (
		r_anal_function_set_var (f, 4, R_ANAL_VAR_KIND_BPV, "int32_t", 4, true, "arg_8h"),
		"Couldn't add first arg var");

	char *sig = r_anal_function_get_signature_string (f);
	mu_assert_notnull (sig, "var fallback signature");
	mu_assert_streq (sig, "void foo (int32_t arg_8h, int32_t arg_ch);", "signature must fall back to sorted arg vars");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "var fallback signature read");
	mu_assert_eq ((int)r_list_length (signature->params), 2, "var fallback param count");
	r_anal_function_signature_free (signature);
	free (sig);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_get_signature_string_hides_variadic_placeholder(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *f = r_anal_create_function (anal, "foo.bar", 0x5000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for variadic signature test");

	bool ok = r_anal_str_to_fcn (anal, f, "char foo.bar (int a, ...);");
	mu_assert_true (ok, "variadic signature must parse");

	char *sig = r_anal_function_get_signature_string (f);
	mu_assert_notnull (sig, "variadic signature string");
	mu_assert_streq (sig, "char foo.bar (int a, ...);", "variadic placeholder name must stay hidden");
	free (sig);
	r_anal_free (anal);
	mu_end;
}

bool test_r_core_function_json_uses_typed_signature(void) {
	const struct {
		const char *name;
		const char *prototype;
		const char *signature;
		int nvars;
		int nargs;
	} cases[] = {
		{ "record_copy", "copy_proto", "void record_copy (FarAddress16 src, FarAddress16 dst, uint16_t count);", 5, 3 },
		{ "no_args", NULL, "int no_args (void);", 1, 0 },
		{ "from_vars", NULL, "void from_vars (int32_t word0, int32_t word1);", 2, 2 },
		{ "fcn.00003000", NULL, "int fcn.00003000 (const char *fmt);", 2, 1 },
		{ "dbg.by_name", NULL, "char dbg.by_name (char value);", 2, 1 },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RCore *core = r_core_new ();
		mu_assert_notnull (core, "create core for function JSON commands");
		RAnal *anal = core->anal;
		RAnalBaseType *record = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
		record->name = strdup ("FarAddress16");
		record->size = 32;
		RAnalTypeMember offset = { .name = strdup ("offset"), .type = strdup ("uint16_t") };
		RAnalTypeMember selector = { .name = strdup ("selector"), .type = strdup ("uint16_t"), .offset = 2 };
		RVecAnalTypeMember_push_back (&record->struct_data.members, &offset);
		RVecAnalTypeMember_push_back (&record->struct_data.members, &selector);
		r_anal_save_base_type (anal, record);
		r_anal_base_type_free (record);
		mu_assert_true (r_anal_import_c_decls (anal,
			"void copy_proto (FarAddress16 src, FarAddress16 dst, uint16_t count);"
			"int no_args (void);"
			"int scanf (const char *fmt);"
			"char by_name (char value);", NULL), "seed canonical JSON prototypes");
		mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "FarAddress16"), 32, "record contains exactly two packed WORDs");
		RAnalFunction *fcn = r_anal_create_function (anal, cases[i].name, 0x3000, R_ANAL_FCN_TYPE_FCN, NULL);
		mu_assert_notnull (fcn, "create function for JSON commands");
		RAnalBlock *bb = r_anal_create_block (anal, fcn->addr, 1);
		mu_assert_notnull (bb, "create function range for command lookup");
		r_anal_function_add_block (fcn, bb);
		r_unref (bb);
		mu_assert_true (r_anal_function_store_callconv (anal, fcn, "cdecl"), "seed function calling convention");
		if (cases[i].prototype) {
			mu_assert_true (r_type_set_link (anal->sdb_types, cases[i].prototype, fcn->addr), "link record prototype by address");
		}
		if (!strcmp (cases[i].name, "fcn.00003000")) {
			mu_assert_notnull (r_flag_set_inspace (core->flags, R_FLAGS_FS_IMPORTS, "sym.imp.__isoc99_scanf", fcn->addr, 0), "seed import prototype resolution");
		}
		int j;
		for (j = cases[i].nvars - 1; j >= 0; j--) {
			char *name = r_str_newf ("word%d", j);
			RAnalVar *var = r_anal_function_set_var (fcn, 4 + j * 4, R_ANAL_VAR_KIND_BPV, "int32_t", 4, true, name);
			free (name);
			mu_assert_notnull (var, "seed inferred argument storage");
		}
		ut64 function_epoch = r_anal_function_dirty_epoch (fcn);
		ut64 types_epoch = r_anal_types_dirty_epoch (anal);
		char *callconv = strdup (r_anal_function_cc (fcn));
		bool noreturn = fcn->is_noreturn;
		const char *commands[] = { "afij @ 0x3000", "aflj" };
		size_t k;
		for (k = 0; k < R_ARRAY_SIZE (commands); k++) {
			char *output = r_core_cmd_str (core, commands[k]);
			mu_assert_notnull (output, "function JSON command output");
			RJson *json = r_json_parsedup (output);
			free (output);
			mu_assert_notnull (json, "parse function JSON command output");
			mu_assert_eq (json->type, R_JSON_ARRAY, "function JSON is an array");
			mu_assert_eq (json->children.count, 1, "one function in JSON output");
			const RJson *entry = r_json_item (json, 0);
			mu_assert_streq (r_json_get_str (entry, "signature"), cases[i].signature, "JSON uses canonical signature, not inferred storage");
			mu_assert_streq (r_json_get_str (entry, "prototype"), !strcmp (cases[i].name, "from_vars")? "unknown": "fixed", "JSON preserves source knowledge independently of lookup origin and recovered variables");
			const RJson *nargs = r_json_get (entry, "nargs");
			mu_assert_notnull (nargs, "JSON retains argument count field");
			mu_assert_eq (nargs->num.u_value, cases[i].nargs, "JSON counts logical parameters");
			r_json_free (json);
		}
		char *signature = r_anal_function_get_signature_string (fcn);
		mu_assert_streq (signature, cases[i].signature, "JSON and typed API agree");
		free (signature);
		mu_assert_eq (r_anal_function_dirty_epoch (fcn), function_epoch, "JSON observation leaves function epoch unchanged");
		mu_assert_eq (r_anal_types_dirty_epoch (anal), types_epoch, "JSON observation leaves type epoch unchanged");
		mu_assert_eq (r_list_length (anal->fcns), 1, "JSON observation does not create functions");
		mu_assert_eq (r_anal_var_count_args (fcn), cases[i].nvars, "JSON observation retains inferred storage");
		mu_assert_streq (fcn->name, cases[i].name, "JSON observation retains function name");
		mu_assert_streq (r_anal_function_cc (fcn), callconv, "JSON observation retains calling convention");
		mu_assert_eq (fcn->is_noreturn, noreturn, "JSON observation retains noreturn");
		free (callconv);
		r_core_free (core);
	}
	mu_end;
}

bool test_r_anal_function_get_signature_falls_back_to_valid_callconv(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_anal_cc_reset (anal);
	mu_assert_true (r_anal_cc_set (anal, "void amd64 (rdi, rsi, rdx, rcx, r8, r9, stack)"),
		"must seed amd64 calling convention");
	r_anal_set_cc_default (anal, "amd64");
	char *parsed = r_anal_cparse (anal, "void sigcc (size_t sz);", NULL);
	mu_assert_notnull (parsed, "declaration with no supplied convention parses");
	r_anal_save_parsed_type (anal, parsed);
	free (parsed);
	mu_assert_null (sdb_const_get (anal->sdb_types, "func.sigcc.cc", NULL), "header producer leaves the convention absent");

	RAnalFunction *f = r_anal_create_function (anal, "sigcc", 0x6000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for callconv fallback test");
	bool ok = r_anal_str_to_fcn (anal, f, "void sigcc (size_t sz);");
	mu_assert_true (ok, "signature must parse");

	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed signature must be readable");
	mu_assert_streq (signature->callconv, "amd64", "absent source convention follows the active analysis configuration");
	mu_assert_notnull (signature->type_name, "an absent convention does not erase record identity");
	mu_assert_null (sdb_const_getf (anal->sdb_types, NULL, "func.%s.cc", signature->type_name), "record identity preserves the distinction between absent source and effective convention");
	r_anal_function_signature_free (signature);
	sdb_set (anal->sdb_types, "func.sigcc.cc", "cdecl", 0);
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "typed signature with an unavailable stored convention remains readable");
	mu_assert_streq (signature->callconv, "amd64", "an unavailable persisted convention retains the existing valid-live fallback");
	mu_assert_notnull (signature->type_name, "a native-only convention does not erase record identity");
	mu_assert_streq (sdb_const_getf (anal->sdb_types, NULL, "func.%s.cc", signature->type_name), "cdecl", "the selected record independently exposes its explicit unavailable convention");
	r_anal_function_signature_free (signature);
	r_anal_free (anal);
	mu_end;
}

static const char *test_bin_get_cc(RBin *bin, ut64 vaddr) {
	return vaddr == 0x2000? "amd64": NULL;
}

bool test_r_anal_function_callconv_resolves_when_assigned(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_true (r_anal_cc_set (anal, "void amd64 (rdi, rsi, rdx, rcx, r8, r9, stack)"),
		"must seed amd64 calling convention");
	mu_assert_true (r_anal_cc_set (anal, "void reg (rdi)"), "must seed the reg fallback");
	r_anal_set_cc_default (anal, "dyncc");
	anal->binb.get_cc = test_bin_get_cc;

	RAnalFunction *known = r_anal_create_function (anal, "known", 0x2000, 0, NULL);
	mu_assert_notnull (known, "Couldn't create function with a per-function convention");
	mu_assert_streq (r_anal_function_cc (known), "amd64",
		"a dyncc default resolves when the function is created");
	ut64 epoch = r_anal_function_dirty_epoch (known);
	mu_assert_streq (r_anal_function_cc (known), "amd64", "reading the convention again returns the same");
	mu_assert_eq (r_anal_function_dirty_epoch (known), epoch, "reading the convention changes nothing");

	RAnalFunction *unknown = r_anal_create_function (anal, "unknown", 0x3000, 0, NULL);
	mu_assert_notnull (unknown, "Couldn't create function without a per-function convention");
	mu_assert_streq (r_anal_function_cc (unknown), "reg", "no per-function convention falls back to reg");

	mu_assert_true (r_anal_function_set_callconv (anal, unknown, "amd64"), "an explicit convention is accepted");
	mu_assert_streq (r_anal_function_cc (unknown), "amd64", "an explicit convention is kept");
	mu_assert_true (r_anal_function_set_callconv (anal, known, "dyncc"), "reassigning dyncc is accepted");
	mu_assert_streq (r_anal_function_cc (known), "amd64", "reassigning dyncc resolves it again");

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_get_signature_reports_origin_and_only_reads(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	bool ok = r_anal_import_c_decls (anal,
		"int by_name (int a);"
		"char by_link (char c);", NULL);
	mu_assert_true (ok, "seed name and link prototypes");

	RAnalFunction *f = r_anal_create_function (anal, "by_name", 0x2800, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for origin test");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "name-based signature must be readable");
	mu_assert_eq (signature->origin, R_ANAL_FUNCTION_SIGNATURE_ORIGIN_NAME, "a prototype found by name");
	mu_assert_nullable_streq (signature->type_name, "by_name", "name origin identifies its actual record");
	r_anal_function_signature_free (signature);

	mu_assert_true (r_type_set_link (anal->sdb_types, "by_link", f->addr), "link a prototype to the address");
	ut64 function_epoch = r_anal_function_dirty_epoch (f);
	ut64 types_epoch = r_anal_types_dirty_epoch (anal);
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "address-linked signature must be readable");
	mu_assert_eq (signature->origin, R_ANAL_FUNCTION_SIGNATURE_ORIGIN_ADDRESS, "a prototype linked to the address");
	mu_assert_nullable_streq (signature->type_name, "by_link", "address origin identifies its actual record");
	mu_assert_streq (signature->ret_type, "char", "the linked prototype wins");
	r_anal_function_signature_free (signature);
	signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "the signature reads again");
	r_anal_function_signature_free (signature);
	mu_assert_eq (r_anal_function_dirty_epoch (f), function_epoch, "reading a signature leaves the function epoch alone");
	mu_assert_eq (r_anal_types_dirty_epoch (anal), types_epoch, "reading a signature leaves the type epoch alone");

	RAnalFunction *vars = r_anal_create_function (anal, "from_vars", 0x4000, 0, NULL);
	mu_assert_notnull (vars, "Couldn't create function for variable origin");
	mu_assert_notnull (
		r_anal_function_set_var (vars, 8, R_ANAL_VAR_KIND_BPV, "int32_t", 4, true, "arg_8h"),
		"Couldn't add arg var");
	signature = r_anal_function_get_signature (vars);
	mu_assert_notnull (signature, "variable-built signature must be readable");
	mu_assert_eq (signature->origin, R_ANAL_FUNCTION_SIGNATURE_ORIGIN_VARIABLES, "no prototype; built from variables");
	mu_assert_null (signature->type_name, "variable-only presentation has no invented record identity");
	r_anal_function_signature_free (signature);

	mu_assert_true (r_type_set_link (anal->sdb_types, "by_link", vars->addr), "bind the variable-bearing function to a real record");
	sdb_unset (anal->sdb_types, "func.by_link.args", 0);
	sdb_unset (anal->sdb_types, "func.by_link.prototype", 0);
	signature = r_anal_function_get_signature (vars);
	mu_assert_notnull (signature, "a selected record with unavailable formal-list knowledge remains readable");
	mu_assert_eq (signature->origin, R_ANAL_FUNCTION_SIGNATURE_ORIGIN_VARIABLES, "unavailable formal count retains variable fallback");
	mu_assert_eq (signature->prototype, R_TYPE_FUNC_PROTOTYPE_UNKNOWN, "record identity does not invent parameter-list knowledge");
	mu_assert_nullable_streq (signature->type_name, "by_link", "variable fallback does not erase an actual selected record");
	mu_assert_streq (signature->ret_type, "char", "the selected record still supplies the return type");
	mu_assert_eq (r_list_length (signature->params), 1, "variable fallback still supplies the parameter");
	RAnalFunctionParam *param = r_list_first (signature->params);
	mu_assert_streq (param->type, "int32_t", "the parameter remains inferred from the function's variable");
	r_anal_free (anal);
	mu_assert_nullable_streq (signature->type_name, "by_link", "snapshot owns its record identity beyond the analysis database lifetime");
	r_anal_function_signature_free (signature);
	mu_end;
}

bool test_r_anal_function_get_signature_origin_of_a_zero_argument_prototype(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	// The ordinary prototype and same-spelling tag have separate owners.
	char *error = NULL;
	bool ok = r_anal_import_c_decls (anal,
		"int foo (void);"
		"struct foo { int x; };", &error);
	mu_assert_true (ok, error? error: "seed a prototype whose name a struct also uses");
	free (error);
	mu_assert_eq (r_type_kind (anal->sdb_types, "foo"), R_TYPE_FUNCTION, "the tag does not replace the ordinary function root");
	mu_assert_eq (r_type_kind (anal->sdb_types, "struct foo"), R_TYPE_STRUCT, "the same-spelling struct retains tag identity");

	RAnalFunction *f = r_anal_create_function (anal, "foo", 0x5000, 0, NULL);
	mu_assert_notnull (f, "Couldn't create function for the zero-argument test");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (f);
	mu_assert_notnull (signature, "zero-argument signature must be readable");
	mu_assert_eq (signature->origin, R_ANAL_FUNCTION_SIGNATURE_ORIGIN_NAME,
		"no arguments does not mean no prototype");
	mu_assert_streq (signature->ret_type, "int", "the prototype's return type is read");
	r_anal_function_signature_free (signature);

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_callconv_store_keeps_an_undefined_name(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *fcn = r_anal_create_function (anal, "restored", 0x6000, 0, NULL);
	mu_assert_notnull (fcn, "Couldn't create function for the store test");

	// a project restores a name whose definition it did not save
	mu_assert_true (r_anal_function_store_callconv (anal, fcn, "savedcc"),
		"storing a convention the target does not define succeeds");
	mu_assert_streq (r_anal_function_cc (fcn), "savedcc", "the stored name is kept");
	mu_assert_false (r_anal_function_set_callconv (anal, fcn, "savedcc"),
		"the validating setter still refuses an undefined convention");
	mu_assert_streq (r_anal_function_cc (fcn), "savedcc", "a refused assignment changes nothing");
	mu_assert_true (r_anal_function_store_callconv (anal, fcn, NULL), "an empty name clears the convention");
	mu_assert_null (r_anal_function_cc (fcn), "the convention is cleared");

	r_anal_free (anal);
	mu_end;
}

typedef struct {
	size_t count;
	ut64 owner_addr;
	ut64 switch_addr;
} SwitchOwnershipProbe;

static bool switch_ownership_probe(RAnalFunction *fcn, RAnalBlock *block,
		RAnalSwitchOp *switch_op, void *user) {
	(void)fcn;
	SwitchOwnershipProbe *probe = user;
	probe->count++;
	probe->owner_addr = block->addr;
	probe->switch_addr = switch_op->jump_addr;
	return true;
}

// the walk reaches the indirect jump twice; the second arrival must not publish the switch on the start block
bool test_r_anal_function_overlapped_walk_keeps_one_switch_owner(void) {
	const ut64 addr = 0x1000;
	const char *hex =
		"554889e54883fe040f82990000004889f148c1e9024883f901750431c0eb644883e1fe31c066662e0f1f8400000000004469"
		"0407512d9ecc41c1c00f4569c09335871b4131d041c1c00d438d148081c2646b54e64469440704512d9ecc41c1c00f4569c0"
		"9335871b4131d041c1c00d438d148081c2646b54e64883c0084883c1fe75ad40f6c604741e690407512d9eccc1c00f69c093"
		"35871b31d0c1c00d8d148081c2646b54e64889f04883e0fc4189f04183e00331c94c8d0d5e0000004f6304814d01c841ffe0"
		"0fb64c0702c1e110440fb644070141c1e0084409c10fb6040731c869c0512d9eccc1c00f69c09335871b31c231d689f0c1e8"
		"1031f069c06bcaeb8589c1c1e90d31c169c935aeb2c289c8c1e81031c85dc30f1f00d8ffffffc1ffffffb4ffffffacffffff";
	size_t bytes_size = 0;
	ut8 *bytes = r_hex_str2bin_dup (hex, &bytes_size);
	mu_assert_notnull (bytes, "decode overlapping-switch fixture");
	mu_assert_eq (bytes_size, 300, "fixture contains function and jump table");
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "create overlapping-switch analysis core");
	core->io->va = true;
	mu_assert_notnull (r_io_open_at (core->io, "malloc://300",
		R_PERM_RWX, 0, addr), "open overlapping-switch analysis map");
	mu_assert_true (r_io_write_at (core->io, addr, bytes, bytes_size),
		"write overlapping-switch fixture");
	free (bytes);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 64);
	r_config_set_b (core->config, "anal.jmptbl", true);
	r_config_set_b (core->config, "anal.esil", false);
	(void)r_core_anal_fcn (core, addr, UT64_MAX, R_ANAL_REF_TYPE_NULL, 256);
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
	mu_assert_notnull (fcn, "analysis creates overlapping-switch function");
	SwitchOwnershipProbe ownership = {0};
	mu_assert_true (r_anal_function_switches_foreach (
		fcn, switch_ownership_probe, &ownership), "enumerate switch owners");
	mu_assert_eq (ownership.count, 1, "one block owns the discovered switch");
	mu_assert_eq (ownership.owner_addr, addr + 167,
		"the indirect-jump block owns the discovered switch");
	mu_assert_eq (ownership.switch_addr, addr + 197,
		"switch ownership names the indirect jump");
	r_core_free (core);
	mu_end;
}

bool test_r_anal_function_switches_foreach(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	RAnalFunction *fcn = r_anal_create_function (anal, "switchy", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "Couldn't create function for switch iteration test");
	RAnalBlock *switch_bb = r_anal_create_block (anal, 0x1000, 0x10);
	RAnalBlock *fallthrough_bb = r_anal_create_block (anal, 0x1010, 0x10);
	mu_assert_notnull (switch_bb, "Couldn't create switch block");
	mu_assert_notnull (fallthrough_bb, "Couldn't create fallthrough block");
	r_anal_function_add_block (fcn, switch_bb);
	r_anal_function_add_block (fcn, fallthrough_bb);
	r_anal_block_add_switch_case (switch_bb, 0x1008, 0, 0x1020);
	r_anal_block_add_switch_case (switch_bb, 0x1008, 1, 0x1030);
	switch_bb->switch_op->def_val = 0x1040;
	switch_bb->switch_op->amount = 2;
	SwitchForeachCtx ctx = {0};
	mu_assert_true (r_anal_function_switches_foreach (fcn, count_switches_cb, &ctx), "switch iteration must succeed");
	mu_assert_eq (ctx.count, 1, "switch iteration count");
	mu_assert_eq (ctx.block_addr, 0x1000, "switch iteration block addr");
	mu_assert_eq (ctx.switch_addr, 0x1008, "switch iteration switch addr");
	mu_assert_eq (ctx.default_addr, 0x1040, "switch iteration default addr");
	mu_assert_eq (ctx.first_case_addr, 0x1020, "switch iteration first case addr");
	mu_assert_eq (ctx.first_case_value, 0, "switch iteration first case value");
	r_unref (switch_bb);
	r_unref (fallthrough_bb);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_getter_preserves_purge_ownership(void) {
	RAnal *anal = r_anal_new ();
	RAnalFunction *fcn = r_anal_create_function (anal, "owned_function", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create owned function");
	RAnalBlock *bb = r_anal_create_block (anal, 0x1000, 4);
	mu_assert_notnull (bb, "create externally retained block");
	r_anal_function_add_block (fcn, bb);
	RListFree destructor = anal->fcns->free;
	mu_assert_notnull (destructor, "analysis owns function destruction");
	mu_assert_ptreq (r_anal_get_fcns (anal), anal->fcns, "getter borrows the owned list");
	mu_assert_true (anal->fcns->free == destructor, "getter must preserve function destruction");
	r_anal_purge (anal);
	mu_assert_eq (r_list_length (anal->fcns), 0, "purge empties the owned collection");
	mu_assert_null (r_anal_get_function_at (anal, 0x1000), "purge removes address registration");
	mu_assert_null (ht_pp_find (anal->ht_name_fun, "owned_function", NULL), "purge removes name registration");
	mu_assert_eq (r_list_length (bb->fcns), 0, "purge removes reciprocal block membership");
	assert_invariants (anal);
	fcn = r_anal_create_function (anal, "owned_function", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "same name and address can be registered after purge");
	r_anal_function_add_block (fcn, bb);
	r_unref (bb);
	assert_invariants (anal);
	(void)r_anal_get_fcns (anal);
	r_anal_purge (anal);
	mu_assert_null (r_anal_get_function_at (anal, 0x1000), "repeated purge removes recreated function");
	mu_assert_null (r_anal_get_block_at (anal, 0x1000), "function's final block reference is released");
	assert_invariants (anal);
	r_anal_free (anal);
	mu_end;
}

bool test_r_core_project_preserves_instruction_positions_and_stack_pop(void) {
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "scr.interactive", false);
	const int stack_pop[] = { R_ANAL_CC_STACK_POP_UNKNOWN, 0, 6 };
	const int ninstr[] = { 3, 2, 0 };
	const ut16 offsets[][2] = { { 2, 5 }, { 4, 0 }, { 0, 0 } };
	int i, j;
	for (i = 0; i < 3; i++) {
		const ut64 addr = 0x1000 + i * 0x100;
		char *name = r_str_newf ("codec.fields.%d", i);
		RAnalFunction *fcn = r_anal_create_function (core->anal, name, addr, R_ANAL_FCN_TYPE_FCN, NULL);
		free (name);
		mu_assert_notnull (fcn, "create function with independent contract metadata");
		fcn->maxstack = 32;
		fcn->meta.stack_pop = stack_pop[i];
		RAnalBlock *bb = r_anal_create_block (core->anal, addr, 8);
		mu_assert_notnull (bb, "create body with explicit instruction positions");
		bb->ninstr = ninstr[i];
		for (j = 1; j < ninstr[i]; j++) {
			mu_assert_true (r_anal_bb_set_offset (bb, j, offsets[i][j - 1]), "set independently selected instruction position");
		}
		r_anal_function_add_block (fcn, bb);
		r_unref (bb);
	}
	char *path = r_file_temp ("newprj-native-fields");
	mu_assert_notnull (path, "project artifact path");
	mu_assert_eq (r_core_cmdf (core, "prj save \"%s\"", path), 0, "save native body and contract metadata");
	r_core_cmd0 (core, "af-*");
	mu_assert_null (r_anal_get_block_at (core->anal, 0x1000), "source block is not retained as an implicit codec fallback");
	mu_assert_eq (r_core_cmdf (core, "prj load \"%s\"", path), 0, "load native body and contract metadata");
	for (i = 0; i < 3; i++) {
		const ut64 addr = 0x1000 + i * 0x100;
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
		mu_assert_notnull (fcn, "restored function is registered");
		mu_assert_eq (fcn->maxstack, 32, "frame size remains independent of callee cleanup");
		mu_assert_eq (fcn->meta.stack_pop, stack_pop[i], "unknown zero and nonzero cleanup remain distinct");
		RAnalBlock *bb = r_anal_get_block_at (core->anal, addr);
		mu_assert_notnull (bb, "restored block");
		mu_assert_ptreq (r_list_first (fcn->bbs), bb, "restored function owns its block");
		mu_assert_eq (bb->ninstr, ninstr[i], "instruction counts retain independent body edits");
		for (j = 0; j < ninstr[i]; j++) {
			mu_assert_eq (r_anal_bb_opaddr_i (bb, j), addr + (j? offsets[i][j - 1]: 0), "instruction addresses retain selected offsets");
		}
	}
	mu_assert_true (r_file_rm (path), "remove owned project artifact");
	free (path);
	r_core_free (core);
	mu_end;
}

bool test_r_core_calling_conventions_reinitialize_after_purge(void) {
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	r_core_anal_cc_init (core);
	const char *default_cc = r_anal_cc_default (core->anal);
	mu_assert_notnull (default_cc, "normal initialization provides a default convention");
	char *expected = strdup (default_cc);
	mu_assert_true (r_anal_cc_exist (core->anal, expected), "normal default has its definition");
	mu_assert_true (r_anal_cc_set (core->anal, "ax selected_cc (ax)"), "install independently selected convention");
	r_anal_set_cc_default (core->anal, "selected_cc");
	r_core_anal_cc_init (core);
	mu_assert_streq (r_anal_cc_default (core->anal), "selected_cc", "same-config initialization preserves an initialized manual selection");
	mu_assert_true (r_anal_cc_exist (core->anal, "selected_cc"), "same-config initialization preserves its definition");
	r_anal_purge (core->anal);
	mu_assert_null (r_anal_cc_default (core->anal), "purge clears convention payload without replacing the core");
	mu_assert_false (r_anal_cc_exist (core->anal, expected), "purge clears the previous default definition");
	r_core_anal_cc_init (core);
	mu_assert_streq (r_anal_cc_default (core->anal), expected, "same-config initialization rebuilds the reset baseline");
	mu_assert_true (r_anal_cc_exist (core->anal, expected), "baseline definition is rebuilt despite the retained path cache");
	mu_assert_false (r_anal_cc_exist (core->anal, "selected_cc"), "purged manual definitions are not replayed");
	free (expected);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_core_calling_conventions_reinitialize_after_purge);
	mu_run_test (test_r_core_project_preserves_instruction_positions_and_stack_pop);
	mu_run_test (test_r_anal_function_getter_preserves_purge_ownership);
	mu_run_test (test_r_anal_function_relocate);
	mu_run_test (test_r_anal_function_labels);
	mu_run_test (test_r_anal_str_to_fcn_returns_status);
	mu_run_test (test_r_core_anal_fcn_prefers_exact_start_match);
	mu_run_test (test_r_core_anal_fcn_variadic_marker_requires_unclobbered_al);
	mu_run_test (test_r_anal_function_get_signature);
	mu_run_test (test_r_anal_function_get_signature_prefers_exact_type_link);
	mu_run_test (test_r_anal_function_set_signature_uses_canonical_type_name);
	mu_run_test (test_r_anal_function_signature_preserves_declarator_shapes);
	mu_run_test (test_r_anal_function_set_signature_rejects_invalid_declarators);
	mu_run_test (test_r_anal_str_to_fcn_defaults_omitted_return_type);
	mu_run_test (test_r_anal_function_signature_parse_requires_a_named_function);
	mu_run_test (test_r_anal_function_signature_visible_typedef);
	mu_run_test (test_r_anal_function_signature_tagged_returns);
	mu_run_test (test_r_anal_function_signature_prepared_tag_namespace);
	mu_run_test (test_r_anal_function_signature_prototype_roundtrip);
	mu_run_test (test_r_anal_function_set_signature_refuses_incomplete_fixed_snapshot);
	mu_run_test (test_r_anal_function_signature_empty_list_specificity);
	mu_run_test (test_r_anal_function_signature_grouped_name);
	mu_run_test (test_r_core_anal_function_set_signature);
	mu_run_test (test_r_core_anal_function_set_signature_errors);
	mu_run_test (test_r_core_afs_rejects_grouped_object_without_mutation);
	mu_run_test (test_r_anal_str_to_fcn_does_not_retry_rejected_header);
	mu_run_test (test_r_core_afs_preserves_compound_return_name_and_flags);
	mu_run_test (test_r_core_afs_selected_parser_refuses_before_mutation);
	mu_run_test (test_r_core_afs_requires_the_requested_function);
	mu_run_test (test_r_core_afs_reuses_selected_parser_admission);
	mu_run_test (test_r_core_afs_name_collision_preserves_state);
	mu_run_test (test_r_anal_function_structured_signature_preserves_raw_callconv);
	mu_run_test (test_r_core_signature_long_isolation_admission);
	mu_run_test (test_r_core_signature_preserves_independent_flags);
	mu_run_test (test_r_core_afs_updates_effective_binding);
	mu_run_test (test_r_core_signature_isolation_avoids_other_name_matches);
	mu_run_test (test_r_core_signature_isolation_preserves_dormant_peer_bindings);
	mu_run_test (test_r_core_afs_overrides_import_for_only_the_current_function);
	mu_run_test (test_r_core_afn_migrates_explicit_prototype_links);
	mu_run_test (test_r_anal_function_get_signature_string_resolves_import_flag_prototype);
	mu_run_test (test_r_anal_function_get_signature_uses_basename_for_dbg_prefixed_function);
	mu_run_test (test_r_anal_function_get_signature_string_falls_back_to_vars);
	mu_run_test (test_r_anal_function_get_signature_string_hides_variadic_placeholder);
	mu_run_test (test_r_core_function_json_uses_typed_signature);
	mu_run_test (test_r_anal_function_get_signature_falls_back_to_valid_callconv);
	mu_run_test (test_r_anal_function_callconv_resolves_when_assigned);
	mu_run_test (test_r_anal_function_get_signature_reports_origin_and_only_reads);
	mu_run_test (test_r_anal_function_get_signature_origin_of_a_zero_argument_prototype);
	mu_run_test (test_r_anal_function_callconv_store_keeps_an_undefined_name);
	mu_run_test (test_r_anal_function_switches_foreach);
	mu_run_test (test_r_anal_function_overlapped_walk_keeps_one_switch_owner);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
