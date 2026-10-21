#include <r_anal.h>
#include "minunit.h"

static bool vec_contains(RVecAnalVarPtr *vec, RAnalVar *var) {
	if (!vec) {
		return false;
	}
	RAnalVar **it;
	R_VEC_FOREACH (vec, it) {
		if (*it == var) {
			return true;
		}
	}
	return false;
}

static bool sanitize_instr_acc(void *user, const ut64 k, const void *v) {
	RVecAnalVarPtr *vec = (RVecAnalVarPtr *)v;
	RAnalVar **it;
	R_VEC_FOREACH (vec, it) {
		RAnalVar *var = *it;
		RAnalVarAccess *acc;
		bool found = false;
		R_VEC_FOREACH (&var->accesses, acc) {
			if (acc->offset == (st64)k) {
				found = true;
				break;
			}
		}
		mu_assert ("instr refs var, but var does not ref instr", found);
	}
	return true;
}

static bool sanitize(RAnalFunction *fcn) {
	ht_up_foreach (fcn->inst_vars, sanitize_instr_acc, NULL);

	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		RAnalVarAccess *acc;
		R_VEC_FOREACH (&var->accesses, acc) {
			RVecAnalVarPtr *iaccs = ht_up_find (fcn->inst_vars, acc->offset, NULL);
			mu_assert ("var refs instr but instr does not ref var", vec_contains (iaccs, var));
		}
	}
	return true;
}

#define assert_sane(anal) do { RListIter *ass_it; RAnalFunction *ass_fcn; \
	r_list_foreach ((anal)->fcns, ass_it, ass_fcn) { \
		if (!sanitize (ass_fcn)) { \
			return false; \
		} \
	} \
} while (0);

bool test_r_anal_var(void) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);

	RAnalFunction *fcn = r_anal_create_function (anal, "fcn", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	assert_sane (anal);

	// creating variables and renaming

	RAnalVar *a = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "char *", 8, false, "random_name");
	mu_assert_notnull (a, "create a var");
	mu_assert_streq (a->name, "random_name", "var name");
	bool succ = r_anal_var_rename (anal, a, "var_a");
	mu_assert ("rename success", succ);
	mu_assert_streq (a->name, "var_a", "var name after rename");

	RAnalVar *b = r_anal_function_set_var (fcn, -0x10, R_ANAL_VAR_KIND_SPV, "char *", 8, false, "var_a");
	mu_assert_null (b, "create a var with the same name");
	b = r_anal_function_set_var (fcn, -0x10, R_ANAL_VAR_KIND_SPV, "char *", 8, false, "new_var");
	mu_assert_notnull (b, "create a var with another name");
	mu_assert_streq (b->name, "new_var", "var name");
	succ = r_anal_var_rename (anal, b, "random_name");
	mu_assert ("rename success", succ);
	mu_assert_streq (b->name, "random_name", "var name after rename");
	succ = r_anal_var_rename (anal, b, "var_a");
	mu_assert ("rename failed", !succ);
	mu_assert_streq (b->name, "random_name", "var name after failed rename");
	succ = r_anal_var_rename (anal, b, "var_b");
	mu_assert ("rename success", succ);
	mu_assert_streq (b->name, "var_b", "var name after rename");

	RAnalVar *c = r_anal_function_set_var (fcn, 0x30, R_ANAL_VAR_KIND_REG, "int64_t", 8, true, "arg42");
	mu_assert_notnull (c, "create a var");

	// querying variables

	RAnalVar *v = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, 0x41);
	mu_assert_null (v, "get no var");
	v = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, 0x30);
	mu_assert_ptreq (v, c, "get var (reg)");
	v = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_SPV, -0x10);
	mu_assert_ptreq (v, b, "get var (sp)");
	v = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_BPV, -8);
	mu_assert_ptreq (v, a, "get var (bp)");

	v = r_anal_function_get_var_byname (fcn, "random_name");
	mu_assert_null (v, "nonsense name");
	v = r_anal_function_get_var_byname (fcn, "var_a");
	mu_assert_ptreq (v, a, "get var by name");

	// accesses

	r_anal_var_set_access (anal, a, "rsp", 0x120, R_PERM_R, 42);
	r_anal_var_set_access (anal, a, "rbp", 0x130, R_PERM_W, 13);
	r_anal_var_set_access (anal, b, "rsp", 0x120, R_PERM_W, 123);
	r_anal_var_set_access (anal, b, "rbp", 0x10, R_PERM_W, -100);

	st64 stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x12345);
	mu_assert_eq (stackptr, ST64_MAX, "unset stackptr");

	RVecAnalVarPtr *used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x130);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x130);
	mu_assert_eq (stackptr, 13, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, 123123, 0x130);
	mu_assert_eq (stackptr, ST64_MAX, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x120);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 2, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	mu_assert ("used vars", vec_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x120);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x120);
	mu_assert_eq (stackptr, 42, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x10);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x10);
	mu_assert_eq (stackptr, -100, "stackptr");

	assert_sane (anal);

	// relocate function

	r_anal_function_relocate (fcn, 0xffffffffffff0100UL);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL); // addresses should stay the same
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	r_anal_var_set_access (anal, a, "rbp", 0xffffffffffff0130UL, R_PERM_R, 42);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	r_anal_var_set_access (anal, a, "rbp" , 0x123, R_PERM_R, 42);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0120);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 2, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	mu_assert ("used vars", vec_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0xffffffffffff0120);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0xffffffffffff0120);
	mu_assert_eq (stackptr, 42, "stackptr");
	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0010);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, b));

	r_anal_function_relocate (fcn, 0x8000000000000010);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000100);
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	r_anal_var_set_access (anal, a, "rbp", 0x8000000000000100, R_PERM_R, 987321);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000100);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x8000000000000100);
	mu_assert_eq (stackptr, 987321, "stackptr");

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x7ffffffffffffe00);
	mu_assert ("no used vars", !used_vars || RVecAnalVarPtr_length (used_vars));
	r_anal_var_set_access (anal, a, "rbp", 0x7ffffffffffffe00, R_PERM_R, 777);
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x7ffffffffffffe00);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x7ffffffffffffe00);
	mu_assert_eq (stackptr, 777, "stackptr");

	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000040UL);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000010033);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000040);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000030);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 2, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, a));
	mu_assert ("used vars", vec_contains (used_vars, b));
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -0x10, 0x8000000000000030);
	mu_assert_eq (stackptr, 123, "stackptr");
	stackptr = r_anal_function_get_var_stackptr_at (fcn, -8, 0x8000000000000030);
	mu_assert_eq (stackptr, 42, "stackptr");

	assert_sane (anal);

	r_anal_var_delete (anal, a);
	assert_sane (anal);

	used_vars = r_anal_function_get_vars_used_at (fcn, 0xffffffffffff0130UL);
	mu_assert ("used vars count", !used_vars || !RVecAnalVarPtr_length (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x123);
	mu_assert ("used vars count", !used_vars || !RVecAnalVarPtr_length (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x130);
	mu_assert ("used vars count", !used_vars || !RVecAnalVarPtr_length (used_vars));
	used_vars = r_anal_function_get_vars_used_at (fcn, 0x8000000000000030);
	mu_assert_eq (RVecAnalVarPtr_length (used_vars), 1, "used vars count");
	mu_assert ("used vars", vec_contains (used_vars, b));

	// serialization / RAnalVarProt
	RList *vps = r_anal_var_get_prots (fcn);
	mu_assert ("Failed r_anal_var_get_protos", vps && r_list_length (vps) == 2);

	char *serial = r_anal_var_prot_serialize (vps, true);
	mu_assert ("serial space", !strcmp (serial, "fs-16:var_b:char *, tr48:arg42:int64_t"));
	free (serial);

	serial = r_anal_var_prot_serialize (vps, false);
	mu_assert ("serial no space", !strcmp (serial, "fs-16:var_b:char *,tr48:arg42:int64_t"));
	free (serial);
	r_list_free (vps);

	vps = r_anal_var_deserialize ("ts-16:var_name:char **, tr48:var_name_b:size_t");
	mu_assert ("Failed r_anal_var_deserialize", vps && r_list_length (vps) == 2);

	RAnalVarProt *vp = (RAnalVarProt *)r_list_first (vps);
	mu_assert ("Deserialize name[0]", !strcmp (vp->name, "var_name") && !strcmp (vp->type, "char **"));
	vp = (RAnalVarProt *)r_list_last (vps);
	mu_assert ("Deserialize name[1]", !strcmp (vp->name, "var_name_b") && !strcmp (vp->type, "size_t"));

	mu_assert ("r_anal_function_set_var_prot", r_anal_function_set_var_prot (fcn, vps));
	mu_assert ("Setting first var from proto", !strcmp (b->name, "var_name") && !strcmp (b->type, "char **"));
	mu_assert ("Setting second var from proto", !strcmp (c->name, "var_name_b") && !strcmp (c->type, "size_t"));

	r_list_purge (vps);
	vp = R_NEW0 (RAnalVarProt);
	vp->name = strdup ("bad_name:`${}~|#@&<>,");
	vp->type = strdup ("bad_type:`${}~|#@&<>,");
	r_list_append (vps, vp);
	vp->kind = 'z';
	serial = r_anal_var_prot_serialize (vps, false);
	mu_assert ("Serializtion succeeded despite invalide kind", !serial);
	free (serial);

	vp->kind = R_ANAL_VAR_KIND_REG;
	serial = r_anal_var_prot_serialize (vps, false);
	mu_assert ("Serializtion filtered bad chars", serial && !strcmp ("fr0:bad_name_____________:bad_type:____________", serial));
	r_list_free (vps);
	free (serial);

	vps = r_anal_var_deserialize ("ts-16:v,r_name:char **");
	mu_assert ("No ',' in serialized name", !vps);

	r_anal_var_delete (anal, b);
	r_anal_var_delete (anal, c);

	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_var_rename_meta(void) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);

	RAnalFunction *fcn = r_anal_create_function (anal, "fcn", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create function");
	RAnalVar *var = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "int64_t", 8, true, "arg7");
	mu_assert_notnull (var, "create variable to rename");
	RAnalVar *collision = r_anal_function_set_var (fcn, -16, R_ANAL_VAR_KIND_BPV, "int64_t", 8, true, "arg1");
	mu_assert_notnull (collision, "create variable with conflicting name");

	r_anal_var_set_access (anal, var, "rbp", 0x110, R_PERM_R, 0);
	r_anal_var_set_access (anal, var, "rbp", 0x120, R_PERM_R, 0);
	r_anal_var_set_access (anal, var, "rbp", 0x130, R_PERM_R, 0);
	r_anal_var_set_access (anal, var, "rbp", 0x140, R_PERM_R, 0);
	r_meta_set_string (anal, R_META_TYPE_VARTYPE, 0x110, "arg7");
	r_meta_set_string (anal, R_META_TYPE_VARTYPE, 0x120, "arg7");
	r_meta_set_string (anal, R_META_TYPE_VARTYPE, 0x130, "custom");
	r_meta_set_string (anal, R_META_TYPE_VARTYPE, 0x150, "arg7");

	mu_assert_false (r_anal_var_rename (anal, var, "invalid name"), "reject invalid variable name");
	mu_assert_streq (var->name, "arg7", "invalid rename keeps variable name");
	mu_assert_streq (r_meta_get_string (anal, R_META_TYPE_VARTYPE, 0x110), "arg7", "invalid rename keeps matching meta");
	mu_assert_false (r_anal_var_rename (anal, var, "arg1"), "reject conflicting variable name");
	mu_assert_streq (var->name, "arg7", "failed rename keeps variable name");
	mu_assert_streq (r_meta_get_string (anal, R_META_TYPE_VARTYPE, 0x110), "arg7", "failed rename keeps matching meta");
	mu_assert_streq (r_meta_get_string (anal, R_META_TYPE_VARTYPE, 0x130), "custom", "failed rename keeps custom meta");

	mu_assert_true (r_anal_var_rename (anal, var, "arg2"), "rename variable");
	mu_assert_streq (var->name, "arg2", "rename updates variable name");
	mu_assert_streq (r_meta_get_string (anal, R_META_TYPE_VARTYPE, 0x110), "arg2", "rename updates first matching meta");
	mu_assert_streq (r_meta_get_string (anal, R_META_TYPE_VARTYPE, 0x120), "arg2", "rename updates second matching meta");
	mu_assert_streq (r_meta_get_string (anal, R_META_TYPE_VARTYPE, 0x130), "custom", "rename keeps custom meta");
	mu_assert_null (r_meta_get_string (anal, R_META_TYPE_VARTYPE, 0x140), "rename does not create missing meta");
	mu_assert_streq (r_meta_get_string (anal, R_META_TYPE_VARTYPE, 0x150), "arg7", "rename ignores meta outside variable accesses");

	r_anal_free (anal);
	mu_end;
}

static bool test_r_anal_var_array_layout(void) {
	const char *types[] = { "uint16_t[8]", "uint16_t[010]", "uint16_t[0x8]", "uint16_t[1|2+3]", "uint16_t[2][010]", "uint8_t *[8]", "uint8_t[256]", "uint8_t[257]" };
	const int counts[] = { 8, 8, 8, 5, 16, 8, 256, 257 };
	const int strides[] = { 2, 2, 2, 2, 2, 8, 1, 1 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (types); i++) {
		RAnal *anal = r_anal_new ();
		r_anal_use (anal, "x86");
		r_anal_set_bits (anal, 64);
		r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
		RAnalFunction *fcn = r_anal_create_function (anal, "arrays", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
		const int base = 16;
		const int size = counts[i] * strides[i];
		RAnalVar *before = r_anal_function_set_var (fcn, base - 1, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "before");
		RAnalVar *interior = r_anal_function_set_var (fcn, base + size - 1, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "interior");
		RAnalVar *after = r_anal_function_set_var (fcn, base + size, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "after");
		RAnalVar *array = r_anal_function_set_var (fcn, base, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "array");
		r_anal_var_set_access (anal, interior, "rbp", 0x120, R_PERM_R, base + size - 1);
		r_anal_var_set_type (anal, array, types[i]);
		mu_assert_streq (array->type, types[i], "array spelling is preserved while canonical layout determines its extent");
		mu_assert_null (r_anal_function_get_var_byname (fcn, "interior"), "the complete canonical array shadows an interior variable");
		mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "before"), before, "preceding variable is not shadowed");
		mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "after"), after, "the exact array endpoint is outside its extent");
		RVecAnalVarPtr *used = r_anal_function_get_vars_used_at (fcn, 0x120);
		mu_assert_true (!used || !RVecAnalVarPtr_length (used), "shadowing removes the old inverse access without transferring it");
		r_anal_var_set_access (anal, array, "rbp", 0x110, R_PERM_R, 32);
		mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, base + size - 1, 0x110), 32 + size - 1, "interior reference lookup uses canonical extent");
		mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, base + size, 0x110), ST64_MAX, "reference lookup excludes the array endpoint");
		RList *fields = r_anal_function_get_var_fields (fcn, R_ANAL_VAR_KIND_BPV);
		RListIter *iter;
		RAnalVarField *field;
		int displayed = 0;
		bool bounded = false;
		r_list_foreach (fields, iter, field) {
			if (!strcmp (field->name, "before") || !strcmp (field->name, "after")) {
				continue;
			}
			if (counts[i] <= 256) {
				char *expected = displayed? r_str_newf ("array[%d]", displayed): strdup ("array");
				mu_assert_streq (field->name, expected, "bounded display retains flattened array indices");
				mu_assert_eq (field->delta, base + displayed * strides[i], "field display uses the canonical element stride");
				mu_assert_true (field->field, "expanded array entries are fields");
				free (expected);
				displayed++;
			} else {
				mu_assert_streq (field->name, "array", "large arrays retain one bounded display entry");
				mu_assert_false (field->field, "large arrays are not partially expanded");
				bounded = true;
			}
		}
		mu_assert_eq (displayed, counts[i] <= 256? counts[i]: 0, "the existing 256-element display boundary is retained");
		mu_assert_eq (bounded, counts[i] > 256, "arrays above the display boundary remain visible");
		r_list_free (fields);
		assert_sane (anal);
		r_anal_free (anal);
	}
	mu_end;
}

static bool test_r_anal_var_large_array_extent(void) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	RAnalFunction *fcn = r_anal_create_function (anal, "large", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalVar *before = r_anal_function_set_var (fcn, -16, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "before");
	r_anal_function_set_var (fcn, 2147483632, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "interior");
	RAnalVar *after = r_anal_function_set_var (fcn, 2147483640, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "after");
	RAnalVar *unrelated = r_anal_function_set_var (fcn, ST32_MAX, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "unrelated");
	RAnalVar *other_kind = r_anal_function_set_var (fcn, 2147483632, R_ANAL_VAR_KIND_SPV, "uint8_t", 1, false, "other_kind");
	RAnalVar *array = r_anal_function_set_var (fcn, -8, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "local");
	r_anal_var_set_type (anal, array, "uint64_t[268435456]");
	mu_assert_streq (array->type, "uint64_t[268435456]", "the demonstrated large declared type is preserved without a host ceiling");
	mu_assert_null (r_anal_function_get_var_byname (fcn, "interior"), "the large array owns its actual two-GiB extent");
	mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "before"), before, "large extent keeps preceding variables");
	mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "after"), after, "large extent keeps its endpoint");
	mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "unrelated"), unrelated, "large extent does not wrap into unrelated offsets");
	mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "other_kind"), other_kind, "large extent does not shadow another location kind");
	r_anal_var_set_access (anal, array, "rbp", 0x110, R_PERM_R, 40);
	mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, 2147483639, 0x110), 2147483687LL, "large interior references retain a wide result");
	mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, 2147483640, 0x110), ST64_MAX, "large array endpoint is not an interior reference");
	mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, ST64_MAX, 0x110), ST64_MAX, "unrelated extreme offsets do not overflow the extent comparison");
	RList *fields = r_anal_function_get_var_fields (fcn, R_ANAL_VAR_KIND_BPV);
	mu_assert_eq (r_list_length (fields), 4, "large array display remains bounded to its base variable");
	r_list_free (fields);
	assert_sane (anal);
	r_anal_free (anal);
	mu_end;
}

static bool test_r_anal_var_large_array_stride(void) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal, "typedef uint64_t HugeRow[268435456];", &error), "import a real array alias with a two-GiB row stride");
	mu_assert_null (error, "large array alias imports without changing its meaning");
	RAnalFunction *fcn = r_anal_create_function (anal, "stride", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalVar *array = r_anal_function_set_var (fcn, 16, R_ANAL_VAR_KIND_BPV, "HugeRow[2]", 1, false, "rows");
	mu_assert_streq (array->type, "HugeRow[2]", "row alias spelling is retained");
	RList *fields = r_anal_function_get_var_fields (fcn, R_ANAL_VAR_KIND_BPV);
	mu_assert_eq (r_list_length (fields), 2, "two rows retain the ordinary bounded display behavior");
	RAnalVarField *field = r_list_first (fields);
	mu_assert_eq (field->delta, 16, "first row starts at the variable base");
	field = r_list_last (fields);
	mu_assert_streq (field->name, "rows[1]", "the second row has the established array field name");
	mu_assert_eq (field->delta, 2147483664LL, "row offsets wider than int are represented exactly");
	r_list_free (fields);
	r_anal_var_set_access (anal, array, "rbp", 0x110, R_PERM_R, 48);
	mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, 4294967311LL, 0x110), 4294967343LL, "lookup retains the full four-GiB aggregate extent");
	mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, 4294967312LL, 0x110), ST64_MAX, "lookup excludes the full aggregate endpoint");
	r_anal_var_set_access (anal, array, "rbp", 0x110, R_PERM_R, ST64_MAX - 32);
	mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, 40, 0x110), ST64_MAX - 8, "reference arithmetic subtracts the base before adding the displacement");
	mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, 56, 0x110), ST64_MAX, "unrepresentable reference results do not wrap");
	assert_sane (anal);
	r_anal_free (anal);
	mu_end;
}

static bool test_r_anal_var_struct_extent(void) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal, "struct Pair {uint64_t first;uint64_t second;};", &error), "import an ordinary sized aggregate");
	mu_assert_null (error, "ordinary aggregate layout succeeds");
	RAnalFunction *fcn = r_anal_create_function (anal, "record", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalVar *before = r_anal_function_set_var (fcn, -17, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "before");
	r_anal_function_set_var (fcn, -1, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "interior");
	RAnalVar *after = r_anal_function_set_var (fcn, 0, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "after");
	r_anal_function_set_var (fcn, -16, R_ANAL_VAR_KIND_BPV, "struct Pair", 1, false, "record");
	mu_assert_null (r_anal_function_get_var_byname (fcn, "interior"), "ordinary sized aggregates retain interior ownership");
	mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "before"), before, "ordinary aggregates keep preceding variables");
	mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "after"), after, "ordinary aggregates keep endpoint variables");
	RList *fields = r_anal_function_get_var_fields (fcn, R_ANAL_VAR_KIND_BPV);
	mu_assert_eq (r_list_length (fields), 4, "ordinary structure fields and unrelated variables remain visible");
	r_list_free (fields);
	assert_sane (anal);
	r_anal_free (anal);
	mu_end;
}

static bool test_r_anal_var_invalid_array_extent(void) {
	const char *types[] = { "uint8_t[2+BOGUS]", "uint8_t[8junk]", "uint8_t[0]", "uint8_t[]", "uint64_t[18446744073709551615ULL]", "uint8_t (*)[8]" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (types); i++) {
		RAnal *anal = r_anal_new ();
		r_anal_use (anal, "x86");
		r_anal_set_bits (anal, 64);
		r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
		RAnalFunction *fcn = r_anal_create_function (anal, "invalid", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
		RAnalVar *interior = r_anal_function_set_var (fcn, -15, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "interior");
		RAnalVar *array = r_anal_function_set_var (fcn, -16, R_ANAL_VAR_KIND_BPV, "uint8_t", 1, false, "array");
		r_anal_var_set_type (anal, array, types[i]);
		mu_assert_streq (array->type, types[i], "unsupported bounds and non-array declarations retain their exact type");
		mu_assert_ptreq (r_anal_function_get_var_byname (fcn, "interior"), interior, "an unknown or non-aggregate extent cannot delete another variable");
		r_anal_var_set_access (anal, array, "rbp", 0x110, R_PERM_R, -16);
		mu_assert_eq (r_anal_function_get_var_stackptr_at (fcn, -15, 0x110), ST64_MAX, "reference lookup does not guess an array extent");
		RList *fields = r_anal_function_get_var_fields (fcn, R_ANAL_VAR_KIND_BPV);
		mu_assert_eq (r_list_length (fields), 2, "unsupported arrays and pointers to arrays are not expanded as sized arrays");
		r_list_free (fields);
		assert_sane (anal);
		r_anal_free (anal);
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_anal_var);
	mu_run_test (test_r_anal_var_rename_meta);
	mu_run_test (test_r_anal_var_array_layout);
	mu_run_test (test_r_anal_var_large_array_extent);
	mu_run_test (test_r_anal_var_large_array_stride);
	mu_run_test (test_r_anal_var_struct_extent);
	mu_run_test (test_r_anal_var_invalid_array_extent);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
