#include <r_core.h>
#include "minunit.h"

#define MOVE_ADDR 0x110e8
static const char family_hex[] =
	"45558bec56571e8b4e0c8b5e0a8b56088b46063bd1770c72043bc37306fdb80100eb03fc33c0c57606c47e0a8b4e0e0bc0740603f14e03f94ff7c701007404e311a4492bf02bf8d1e9f3a5730503f003f8a4fc1f5f5e5d4dcb"
	"45558bec5657ff760eff7608ff7606ff760cff760a0ee88eff83c40a8b56088b46065f5e5d4dcb";

static RCore *helper_core(const char *hex) {
	RCore *core = r_core_new ();
	core->io->va = true;
	r_io_open_at (core->io, "malloc://128", R_PERM_RWX, 0, MOVE_ADDR);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	r_anal_types_prepare (core->anal);
	core->anal->opt.vars = false;
	ut8 bytes[128] = {0};
	int size = r_hex_str2bin (hex, bytes);
	r_io_write_at (core->io, MOVE_ADDR, bytes, sizeof (bytes));
	RBinFile *bf = R_NEW0 (RBinFile);
	bf->bo = R_NEW0 (RBinObject);
	bf->rbin = core->bin;
	core->bin->cur = bf;
	RVecRBinSection_init (&bf->bo->sections_vec);
	RBinSection *section = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
	section->name = strdup ("code");
	section->vaddr = MOVE_ADDR;
	section->size = section->vsize = size;
	section->perm = R_PERM_RWX;
	return core;
}

static RCore *move_core(void) {
	return helper_core (family_hex);
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
	RAnalBaseType *type = r_anal_get_base_type (core->anal, "FarAddress16", R_TYPE_NAMESPACE_ORDINARY);
	mu_assert_notnull (type, "native record type");
	mu_assert_eq (type->space, R_TYPE_NAMESPACE_ORDINARY, "FarAddress16 remains an ordinary named analysis view");
	mu_assert_null (r_anal_get_base_type (core->anal, "FarAddress16", R_TYPE_NAMESPACE_TAG), "the profile does not fabricate a historical C tag");
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

static bool test_move_preserve_prototype_metadata(void) {
	const struct {
		const char *prototype;
		RTypeFunctionPrototype specificity;
		const char *binding;
	} cases[] = {
		{ "unknown", R_TYPE_FUNC_PROTOTYPE_UNKNOWN, NULL },
		{ "unspecified", R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED, NULL },
		{ "fixed", R_TYPE_FUNC_PROTOTYPE_FIXED, NULL },
		{ "invalid", R_TYPE_FUNC_PROTOTYPE_UNKNOWN, NULL },
		{ "unknown", R_TYPE_FUNC_PROTOTYPE_UNKNOWN, "link" },
		{ "unknown", R_TYPE_FUNC_PROTOTYPE_UNKNOWN, "fcnlink" },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RCore *core = move_core ();
		RAnal *anal = core->anal;
		RAnalFunction *fcn = r_anal_create_function (anal, NULL, MOVE_ADDR, R_ANAL_FCN_TYPE_FCN, NULL);
		r_anal_function (anal, fcn, fcn->addr, R_ANAL_REF_TYPE_CALL);
		const char *type_name = cases[i].binding? "manual_move_prototype": fcn->name;
		char *prototype_key = r_str_newf ("func.%s.prototype", type_name);
		sdb_set (anal->sdb_types, prototype_key, cases[i].prototype, 0);
		if (cases[i].binding) {
			sdb_set (anal->sdb_types, type_name, "func", 0);
			sdb_setf (anal->sdb_types, type_name, 0, "%s.%08"PFMT64x, cases[i].binding, fcn->addr);
		}
		char *name = strdup (fcn->name);
		const char *cc = fcn->callconv;
		RAnalBlock *bb = r_list_first (fcn->bbs);
		ut64 epoch = fcn->dirty_epoch;
		mu_assert_true (move_run (core, 1), "prototype-only or unreadable metadata refuses the generic move helper");
		mu_assert_ptreq (r_anal_get_function_at (anal, MOVE_ADDR), fcn, "existing function identity retained");
		mu_assert_streq (fcn->name, name, "generic name retained");
		mu_assert_ptreq (fcn->callconv, cc, "existing convention retained");
		mu_assert_ptreq (r_list_first (fcn->bbs), bb, "existing body retained");
		mu_assert_eq (fcn->dirty_epoch, epoch, "refused signature is not applied");
		mu_assert_streq (sdb_const_get (anal->sdb_types, prototype_key, NULL), cases[i].prototype, "independent specificity retained");
		mu_assert_null (sdb_const_getf (anal->sdb_types, NULL, "func.%s.ret", type_name), "no helper return installed");
		mu_assert_null (sdb_const_getf (anal->sdb_types, NULL, "func.%s.args", type_name), "no helper parameters installed");
		mu_assert_null (sdb_const_get (anal->sdb_types, "borland_fmovmem_000110e8", NULL), "no helper prototype created");
		char *linked = r_type_link_at (anal->sdb_types, MOVE_ADDR);
		if (cases[i].binding && !strcmp (cases[i].binding, "link")) {
			mu_assert_streq (linked, type_name, "explicit effective binding retained");
		} else {
			mu_assert_null (linked, "no new helper link");
		}
		free (linked);
		const char *dwarf = sdb_const_getf (anal->sdb_types, NULL, "fcnlink.%08"PFMT64x, MOVE_ADDR);
		if (cases[i].binding && !strcmp (cases[i].binding, "fcnlink")) {
			mu_assert_streq (dwarf, type_name, "DWARF effective binding retained");
		} else {
			mu_assert_null (dwarf, "no new DWARF binding");
		}
		RAnalFunctionSignature *sig = r_anal_function_get_signature (fcn);
		if (!strcmp (cases[i].prototype, "invalid")) {
			mu_assert_null (sig, "invalid metadata remains unreadable instead of becoming a helper");
		} else {
			mu_assert_notnull (sig, "independent signature remains readable");
			mu_assert_eq (sig->prototype, cases[i].specificity, "effective specificity retained");
			mu_assert_null (sig->ret_type, "effective return remains absent");
			mu_assert_true (r_list_empty (sig->params), "effective parameters remain absent");
		}
		r_anal_function_signature_free (sig);
		mu_assert_notnull (r_anal_get_function_at (anal, MOVE_ADDR + 89), "unrelated qualified wrapper remains available");
		free (prototype_key);
		free (name);
		move_core_free (core);
	}
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

static bool test_move_metadata_spaces(void) {
	int installed, other;
	for (installed = 0; installed < 2; installed++) {
		for (other = 0; other < 2; other++) {
			RCore *core = move_core ();
			RAnal *anal = core->anal;
			if (installed) {
				mu_assert_true (move_run (core, 2), "valid helper baseline before independent DATA");
			}
			RAnalFunction *fcn = r_anal_get_function_at (anal, MOVE_ADDR);
			char *signature = fcn? r_anal_function_get_signature_string (fcn): NULL;
			ut64 epoch = fcn? fcn->dirty_epoch: 0;
			RSpace *manual = r_spaces_set (&anal->meta_spaces, "manual");
			mu_assert_notnull (manual, "independent metadata space");
			mu_assert_true (r_meta_set (anal, R_META_TYPE_DATA, MOVE_ADDR + 1, 2, "manual definition"), "independent DATA within current helper");
			r_meta_set_string (anal, R_META_TYPE_COMMENT, MOVE_ADDR, "manual comment");
			RIntervalNode *data = r_meta_get_in (anal, MOVE_ADDR + 1, R_META_TYPE_DATA);
			RIntervalNode *comment = r_meta_get_in (anal, MOVE_ADDR, R_META_TYPE_COMMENT);
			mu_assert_notnull (data, "native DATA node");
			mu_assert_notnull (comment, "native comment node");
			RSpace *selected = r_spaces_set (&anal->meta_spaces, other? "selected": "manual");
			mu_assert_true (move_run (core, 1), "DATA blocks helper creation and equivalent-helper early return in every space");
			mu_assert_ptreq (r_spaces_current (&anal->meta_spaces), selected, "helper admission never switches current metadata space");
			mu_assert_ptreq (r_anal_get_function_at (anal, MOVE_ADDR), fcn, "no conflicting function creation or replacement");
			if (fcn) {
				char *after = r_anal_function_get_signature_string (fcn);
				mu_assert_streq (after, signature, "equivalent helper prototype preserved without reapplication");
				mu_assert_eq (fcn->dirty_epoch, epoch, "refused helper contract not rewritten");
				free (after);
			} else {
				mu_assert_null (r_type_link_at (anal->sdb_types, MOVE_ADDR), "no dependent helper prototype");
			}
			mu_assert_notnull (r_anal_get_function_at (anal, MOVE_ADDR + 89), "unrelated qualified wrapper remains available");
			RAnalMetaItem *item = data->data;
			mu_assert_ptreq (item->space, manual, "DATA ownership preserved");
			mu_assert_eq (item->type, R_META_TYPE_DATA, "DATA kind preserved");
			mu_assert_eq (item->subtype, 0, "DATA subtype preserved");
			mu_assert_eq (data->start, MOVE_ADDR + 1, "DATA start preserved");
			mu_assert_eq (data->end, MOVE_ADDR + 2, "DATA extent preserved");
			mu_assert_streq (item->str, "manual definition", "DATA content preserved");
			mu_assert_streq (((RAnalMetaItem *)comment->data)->str, "manual comment", "refusal adds no dependent helper comment");
			if (other) {
				mu_assert_null (r_meta_get_string (anal, R_META_TYPE_COMMENT, MOVE_ADDR), "no dependent comment in selected space");
			}
			free (signature);
			move_core_free (core);
		}
	}
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

static const char scopy_hex[] = "558bec56571ec57606c47e0afcd1e9f3a513c9f3a41f5f5e5dca0800";
static const char forward_hex[] = "45558bec56578cdac47e06c5760a8b4e0ed1e9fcf3a57301a48eda8b56088b46065f5e5d4dcb";
static const char compare_hex[] = "518ae8b104d3e803d08ac58ae3d3eb5903cb8adc250f0083e30f3bd175023bc3cb";
static const char fill_hex[] = "45558bec571e078b7e068b4e088a460a8ae0fcf7c701007404e309aa49d1e9f3ab7301aa5f5d4dcb45558bec568b76068a460850ff760a560ee8c4ff83c4068bc65e5d4dcb";
static const char shifts_hex[] = "5b0e5380f91073108bd8d3e0d3e2f6d980c110d3eb0bd3cb80e9109233c0d3e2cb5b0e5380f91073108bdad3e8d3faf6d980c110d3e30bc3cb80e9109299d3f8cb5b0e5380f91073108bdad3e8d3eaf6d980c110d3e30bc3cb80e9109233d2d3e8cb";

static bool test_remaining_helper_contracts(void) {
	const struct {
		const char *hex;
		int count;
		int start;
		int size;
		const char *cc;
		const char *ret;
		const char *first_name;
		const char *first_type;
	} cases[] = {
		{ scopy_hex, 1, 0, 28, "borland_f_scopy_16far", "void", "byte_count", "uint16_t" },
		{ forward_hex, 1, 0, 38, "borland_far_copy_16far", "FarAddress16", "destination", "FarAddress16" },
		{ compare_hex, 1, 0, 33, "borland_far_pointer_compare_16far", "FarPointerCompareAnalysisState9", "entry_dx_ax", "FarAddress16" },
		{ fill_hex, 2, 0, 40, "borland_setmem_16far", "uint16_t", "destination_offset", "uint16_t" },
		{ shifts_hex, 3, 3, 30, "borland_word_shift_16far", "uint32_t", "value", "uint32_t" },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RCore *core = helper_core (cases[i].hex);
		mu_assert_true (move_run (core, cases[i].count), "native helper application");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, MOVE_ADDR + cases[i].start);
		mu_assert_notnull (fcn, "qualified native helper");
		mu_assert_eq (r_anal_function_realsize (fcn), cases[i].size, "complete body");
		mu_assert_streq (fcn->callconv, cases[i].cc, "exact native convention name");
		RAnalFunctionSignature *sig = r_anal_function_get_signature (fcn);
		mu_assert_notnull (sig, "native signature");
		mu_assert_streq (sig->ret_type, cases[i].ret, "actual analysis return");
		RAnalFunctionParam *first = r_list_first (sig->params);
		mu_assert_streq (first->name, cases[i].first_name, "first parameter name");
		mu_assert_streq (first->type, cases[i].first_type, "first parameter type");
		r_anal_function_signature_free (sig);
		if (i == 0) {
			mu_assert_eq (fcn->meta.stack_pop, 8, "actual RETF8 callee pop");
		}
		if (i == 2) {
			RAnalBaseType *type = r_anal_get_base_type (core->anal, "FarPointerCompareAnalysisState9", R_TYPE_NAMESPACE_ORDINARY);
			mu_assert_notnull (type, "analysis tuple type");
			mu_assert_eq (type->size, 72, "exact nine-byte tuple");
			mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, "bool"), 8, "one-byte boolean storage");
			const char *names[] = { "equal_zf", "ax", "dx", "bx", "cx" };
			int j;
			for (j = 0; j < 5; j++) {
				RAnalTypeMember *member = RVecAnalTypeMember_at (&type->struct_data.members, j);
				mu_assert_streq (member->name, names[j], "native tuple field order");
				mu_assert_eq (member->offset, j? j * 2 - 1: 0, "packed tuple offset");
			}
			r_anal_base_type_free (type);
		}
		if (i == 3) {
			RAnalFunction *wrapper = r_anal_get_function_at (core->anal, MOVE_ADDR + 40);
			mu_assert_notnull (wrapper, "qualified memset wrapper");
			mu_assert_streq (wrapper->callconv, "borland_memset_16far", "distinct fill wrapper model");
			sig = r_anal_function_get_signature (wrapper);
			mu_assert_streq (((RAnalFunctionParam *)r_list_get_n (sig->params, 1))->name, "value_word_low_byte", "wrapper value before count");
			mu_assert_streq (((RAnalFunctionParam *)r_list_get_n (sig->params, 2))->name, "byte_count", "wrapper count last");
			r_anal_function_signature_free (sig);
		}
		if (i == 4) {
			const int starts[] = { 3, 36, 68 }, sizes[] = { 30, 29, 30 };
			int j;
			for (j = 0; j < 3; j++) {
				RAnalFunction *shift = r_anal_get_function_at (core->anal, MOVE_ADDR + starts[j]);
				mu_assert_notnull (shift, "far shift core");
				mu_assert_eq (r_anal_function_realsize (shift), sizes[j], "nonoverlapping exact core");
				mu_assert_eq (r_list_length (shift->bbs), 3, "three native blocks");
				mu_assert_eq (r_anal_function_instrcount (shift), 15, "fifteen native instructions");
				mu_assert_null (r_anal_get_function_at (core->anal, shift->addr - 3), "adapter is not a returning function");
				mu_assert_notnull (r_flag_get_by_spaces (core->flags, false, shift->addr - 3, NULL), "adapter label");
				sig = r_anal_function_get_signature (shift);
				mu_assert_streq (sig->ret_type, j == 1? "int32_t": "uint32_t", "only arithmetic shift is signed");
				mu_assert_streq (((RAnalFunctionParam *)r_list_get_n (sig->params, 1))->type, "uint8_t", "CL is BYTE, not CX");
				r_anal_function_signature_free (sig);
			}
		}
		ut64 epoch = fcn->dirty_epoch;
		mu_assert_true (move_run (core, cases[i].count), "all remaining helpers rerun idempotently");
		mu_assert_eq (fcn->dirty_epoch, epoch, "no signature rewrite on rerun");
		move_core_free (core);
	}
	mu_end;
}

static bool test_fill_qualification(void) {
	RCore *core = helper_core (fill_hex);
	ut8 patch = 0x90;
	r_io_write_at (core->io, MOVE_ADDR + 39, &patch, 1);
	mu_assert_true (move_run (core, 0), "unqualified actual setmem target blocks wrapper");
	move_core_free (core);
	core = helper_core (fill_hex + 80);
	mu_assert_true (move_run (core, 0), "isolated wrapper is not admitted");
	move_core_free (core);
	core = helper_core (fill_hex);
	r_anal_hint_set_jump (core->anal, MOVE_ADDR + 57, MOVE_ADDR + 1);
	mu_assert_true (move_run (core, 1), "wrapper CALL override blocks wrapper, not independent core");
	move_core_free (core);
	mu_end;
}

static bool test_shift_family_qualification(void) {
	RCore *core = helper_core (shifts_hex);
	ut8 patch = 0x90;
	r_io_write_at (core->io, MOVE_ADDR + 97, &patch, 1);
	mu_assert_true (move_run (core, 0), "partial shift family cannot create any core");
	move_core_free (core);
	core = helper_core (shifts_hex);
	r_anal_hint_set_bits (core->anal, MOVE_ADDR + 34, 32);
	mu_assert_true (move_run (core, 0), "internal adapter/core context refuses whole family");
	move_core_free (core);
	core = helper_core (shifts_hex);
	RAnalFunction *owner = r_anal_create_function (core->anal, NULL, MOVE_ADDR, R_ANAL_FCN_TYPE_FCN, NULL);
	r_anal_function (core->anal, owner, owner->addr, R_ANAL_REF_TYPE_CALL);
	mu_assert_true (move_run (core, 2), "different overlapping owner blocks first core only");
	mu_assert_null (r_anal_get_function_at (core->anal, MOVE_ADDR + 3), "do not delete/recreate adapter owner");
	mu_assert_eq (r_anal_function_realsize (owner), 33, "prior adapter body retained");
	move_core_free (core);
	mu_end;
}

static bool test_remaining_type_and_pop_preservation(void) {
	RCore *core = helper_core (compare_hex);
	sdb_set (core->anal->sdb_types, "FarPointerCompareAnalysisState9", "struct", 0);
	sdb_set (core->anal->sdb_types, "struct.FarPointerCompareAnalysisState9", "manual", 0);
	sdb_set (core->anal->sdb_types, "struct.FarPointerCompareAnalysisState9.manual", "uint8_t,0,0", 0);
	mu_assert_true (move_run (core, 0), "conflicting analysis record preserved");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "struct.FarPointerCompareAnalysisState9", NULL), "manual", "independent tuple not replaced");
	move_core_free (core);
	core = helper_core (compare_hex);
	sdb_set (core->anal->sdb_types, "bool", "struct", 0);
	sdb_set (core->anal->sdb_types, "struct.bool", "manual", 0);
	sdb_set (core->anal->sdb_types, "struct.bool.manual", "uint8_t,0,0", 0);
	sdb_num_set (core->anal->sdb_types, "type.bool.size", 8, 0);
	mu_assert_true (move_run (core, 0), "same-width nonboolean definition cannot authorize a boolean tuple");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "bool", NULL), "struct", "independent boolean-name conflict preserved");
	move_core_free (core);
	core = helper_core (scopy_hex);
	RAnalFunction *fcn = r_anal_create_function (core->anal, NULL, MOVE_ADDR, R_ANAL_FCN_TYPE_FCN, NULL);
	r_anal_function (core->anal, fcn, fcn->addr, R_ANAL_REF_TYPE_CALL);
	mu_assert_eq (fcn->meta.stack_pop, 8, "normal callee-popped body");
	fcn->meta.stack_pop = 0;
	mu_assert_true (move_run (core, 0), "independently conflicting zero pop is preserved for F_SCOPY");
	mu_assert_eq (fcn->meta.stack_pop, 0, "zero pop not silently replaced by eight");
	move_core_free (core);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_move_family);
	mu_run_test (test_move_current_qualification);
	mu_run_test (test_move_preserve_independent_state);
	mu_run_test (test_move_preserve_prototype_metadata);
	mu_run_test (test_move_preserve_body_and_convention);
	mu_run_test (test_move_metadata_spaces);
	mu_run_test (test_move_preserve_type);
	mu_run_test (test_remaining_helper_contracts);
	mu_run_test (test_fill_qualification);
	mu_run_test (test_shift_family_qualification);
	mu_run_test (test_remaining_type_and_pop_preservation);
	return tests_passed != tests_run;
}
