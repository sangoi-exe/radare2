#include <r_asm.h>

#include "minunit.h"
#include "test_sdb.h"

static void setup_sdb_for_struct(Sdb *res) {
	// "td struct kappa {int bar;int cow;};"
	sdb_set (res, "kappa", "struct", 0);
	sdb_set (res, "struct.kappa", "bar,cow", 0);
	sdb_set (res, "struct.kappa.bar", "int32_t,0,0", 0);
	sdb_set (res, "struct.kappa.cow", "int32_t,4,0", 0);
}

static void setup_sdb_for_union(Sdb *res) {
	// "td union kappa {int bar;int cow;};"
	sdb_set (res, "kappa", "union", 0);
	sdb_set (res, "union.kappa", "bar,cow", 0);
	sdb_set (res, "union.kappa.bar", "int32_t,0,0", 0);
	sdb_set (res, "union.kappa.cow", "int32_t,0,0", 0);
}

static void setup_sdb_for_enum(Sdb *res) {
	// "td enum foo { firstCase=1, secondCase=2,};"
	sdb_set (res, "foo", "enum", 0);
	sdb_set (res, "enum.foo", "firstCase,secondCase", 0);
	sdb_set (res, "enum.foo.firstCase", "0x1", 0);
	sdb_set (res, "enum.foo.secondCase", "0x2", 0);
	sdb_set (res, "enum.foo.0x1", "firstCase", 0);
	sdb_set (res, "enum.foo.0x2", "secondCase", 0);
}

static void setup_sdb_for_typedef(Sdb *res) {
	// td typedef char *string;
	sdb_set (res, "string", "typedef", 0);
	sdb_set (res, "typedef.string", "char *", 0);
}

static void setup_sdb_for_atomic(Sdb *res) {
	sdb_set (res, "char", "type", 0);
	sdb_set (res, "type.char.size", "8", 0);
	sdb_set (res, "type.char", "c", 0);
}

static void setup_sdb_for_not_found(Sdb *res) {
	// malformed type states
	sdb_set (res, "foo", "enum", 0);
	sdb_set (res, "bar", "struct", 0);
	sdb_set (res, "quax", "union", 0);
	sdb_set (res, "enum.foo", "aa,bb", 0);
	sdb_set (res, "struct.bar", "cc,dd", 0);
	sdb_set (res, "union.quax", "ee,ff", 0);

	sdb_set (res, "omega", "struct", 0);
	sdb_set (res, "struct.omega", "ee,ff,gg", 0);
	sdb_set (res, "struct.omega.ee", "0,1", 0);
	sdb_set (res, "struct.omega.ff", "", 0);
}

static bool test_anal_get_base_type_struct(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_struct (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "kappa");
	mu_assert_notnull (base, "Couldn't create get base type of struct \"kappa\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_STRUCT, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "kappa", "type name");

	RAnalStructMember *member;

	member = RVecAnalTypeMember_at (&base->struct_data.members, 0);
	mu_assert_eq (member->offset, 0, "Incorrect offset for struct member");
	mu_assert_streq (member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq (member->name, "bar", "Incorrect name for struct member");

	member = RVecAnalTypeMember_at (&base->struct_data.members, 1);
	mu_assert_eq (member->offset, 4, "Incorrect offset for struct member");
	mu_assert_streq (member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq (member->name, "cow", "Incorrect name for struct member");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_struct(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kappa");

	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("bar")
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_struct (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save struct type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_struct_member_needing_sanitization_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	// A member name that sdb keys cannot hold verbatim. DWARF produces these
	// for C++ vtable pointers, e.g. "_vptr.Bird".
	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("Bird");

	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int (**)()"),
		.name = strdup ("_vptr.Bird")
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	// The member list has to name the member by the key that addresses it,
	// otherwise the reader looks up a key that was never written and the whole
	// type becomes unreadable.
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Bird", 0), "_vptr_Bird",
		"member list names the sanitized key");
	mu_assert_notnull (sdb_const_get (anal->sdb_types, "struct.Bird._vptr_Bird", 0),
		"member is stored under the sanitized key");

	RAnalBaseType *got = r_anal_get_base_type (anal, "Bird");
	mu_assert_notnull (got, "reload struct whose member name needed sanitization");
	mu_assert_eq (RVecAnalTypeMember_length (&got->struct_data.members), 1,
		"member survives the round trip");
	RAnalStructMember *m = RVecAnalTypeMember_at (&got->struct_data.members, 0);
	mu_assert_streq (m->name, "_vptr_Bird", "member is named by its key");
	mu_assert_streq (m->type, "int (**)()", "member type survives");
	r_anal_base_type_free (got);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_enum_case_needing_sanitization_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	base->name = strdup ("Mode");

	RAnalEnumCase cas = {
		.name = strdup ("Mode.One"),
		.val = 1
	};
	RVecAnalEnumCase_push_back (&base->enum_data.cases, &cas);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	mu_assert_streq (sdb_const_get (anal->sdb_types, "enum.Mode", 0), "Mode_One",
		"case list names the sanitized key");

	// get_enum_type treats a missing case key as fatal, so a single case name
	// needing sanitization made the whole enum unreadable.
	RAnalBaseType *got = r_anal_get_base_type (anal, "Mode");
	mu_assert_notnull (got, "reload enum whose case name needed sanitization");
	mu_assert_eq (RVecAnalEnumCase_length (&got->enum_data.cases), 1,
		"case survives the round trip");
	RAnalEnumCase *c = RVecAnalEnumCase_at (&got->enum_data.cases, 0);
	mu_assert_streq (c->name, "Mode_One", "case is named by its key");
	mu_assert_eq (c->val, 1, "case value survives");
	r_anal_base_type_free (got);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_union(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_union (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "kappa");
	mu_assert_notnull (base, "Couldn't create get base type of union \"kappa\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_UNION, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "kappa", "type name");

	RAnalUnionMember *member;

	member = RVecAnalTypeMember_at (&base->union_data.members, 0);
	mu_assert_streq (member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq (member->name, "bar", "Incorrect name for union member");

	member = RVecAnalTypeMember_at (&base->union_data.members, 1);
	mu_assert_streq (member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq (member->name, "cow", "Incorrect name for union member");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_union(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("kappa");

	RAnalUnionMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("bar")
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	member.offset = 0;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_union (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save union type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_enum(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_enum (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "foo");
	mu_assert_notnull (base, "Couldn't create get base type of enum \"foo\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_ENUM, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "foo", "type name");

	RAnalEnumCase *cas = RVecAnalEnumCase_at (&base->enum_data.cases, 0);
	mu_assert_eq (cas->val, 1, "Incorrect value for enum case");
	mu_assert_streq (cas->name, "firstCase", "Incorrect name for enum case");

	cas = RVecAnalEnumCase_at (&base->enum_data.cases, 1);
	mu_assert_eq (cas->val, 2, "Incorrect value for enum case");
	mu_assert_streq (cas->name, "secondCase", "Incorrect name for enum case");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_enum(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	base->name = strdup ("foo");

	RAnalEnumCase cas = {
		.name = strdup ("firstCase"),
		.val = 1
	};
	RVecAnalEnumCase_push_back (&base->enum_data.cases, &cas);

	cas.name = strdup ("secondCase");
	cas.val = 2;
	RVecAnalEnumCase_push_back (&base->enum_data.cases, &cas);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_enum (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save enum type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_typedef(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	setup_sdb_for_typedef (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "string");
	mu_assert_notnull (base, "Couldn't create get base type of typedef \"string\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_TYPEDEF, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "string", "type name");
	mu_assert_streq (base->type, "char *", "typedefd type");
	mu_assert_eq (r_anal_type_bitsize (anal, "string"), 64,
		"Pointer typedef uses the current architecture width");
	sdb_set (anal->sdb_types, "word", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.word", "unsigned long", 0);
	sdb_num_set (anal->sdb_types, "type.word.size", 64, 0);
	mu_assert_eq (r_anal_type_bitsize (anal, "word"), 64,
		"Scalar typedef uses its exact declared width");
	sdb_set (anal->sdb_types, "cycle_a", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.cycle_a", "cycle_b", 0);
	sdb_set (anal->sdb_types, "cycle_b", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.cycle_b", "cycle_a", 0);
	sdb_set (anal->sdb_types, "u64", "type", 0);
	sdb_num_set (anal->sdb_types, "type.u64.size", 64, 0);
	sdb_set (anal->sdb_types, "myword", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.myword", "u64", 0);
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "myword"), 64,
		"Typedef without a declared width measures what it aliases");
	mu_assert_eq (r_anal_type_bitsize (anal, "cycle_a"), 0,
		"Cyclic typedefs fail closed");

	sdb_set (anal->sdb_types, "word", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.word", "unsigned long", 0);
	sdb_num_set (anal->sdb_types, "type.word.size", 64, 0);
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "word"), 64,
		"Typedef with a declared width measures that width");

	sdb_set (anal->sdb_types, "u64", "type", 0);
	sdb_num_set (anal->sdb_types, "type.u64.size", 64, 0);
	sdb_set (anal->sdb_types, "myword", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.myword", "u64", 0);
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "myword"), 64,
		"Typedef without a declared width measures what it aliases");

	sdb_set (anal->sdb_types, "cycle_a", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.cycle_a", "cycle_b", 0);
	sdb_set (anal->sdb_types, "cycle_b", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.cycle_b", "cycle_a", 0);
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "cycle_a"), 0,
		"Cyclic typedefs fail closed");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_typedef(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	base->name = strdup ("string");
	base->type = strdup ("char *");

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_typedef (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save typedef type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_atomic(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_atomic (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "char");
	mu_assert_notnull (base, "Couldn't create get base type of atomic type \"char\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_ATOMIC, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "char", "type name");
	mu_assert_streq (base->type, "c", "atomic type type");
	mu_assert_eq (base->size, 8, "atomic type size");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_atomic(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	base->name = strdup ("char");
	base->type = strdup ("c");
	base->size = 8;

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_atomic (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save atomic type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_not_found(void) {
	RAnal *anal = r_anal_new ();
	setup_sdb_for_not_found (anal->sdb_types);

	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_get_base_type (anal, "non_existant23321312___");
	mu_assert_null (base, "Should find nothing");
	base = r_anal_get_base_type (anal, "foo");
	mu_assert_null (base, "Should find nothing");
	base = r_anal_get_base_type (anal, "bar");
	mu_assert_null (base, "Should find nothing");
	base = r_anal_get_base_type (anal, "quax");
	mu_assert_null (base, "Should find nothing");
	base = r_anal_get_base_type (anal, "omega");
	mu_assert_null (base, "Should find nothing");

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_struct_array_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("arr");

	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("scalar"),
		.count = 0
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup ("char");
	member.name = strdup ("buf");
	member.count = 16;
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	RAnalBaseType *got = r_anal_get_base_type (anal, "arr");
	mu_assert_notnull (got, "reload struct with array member");

	RAnalStructMember *m = RVecAnalTypeMember_at (&got->struct_data.members, 0);
	mu_assert_eq (m->count, 0, "scalar member count survives as 0");
	m = RVecAnalTypeMember_at (&got->struct_data.members, 1);
	mu_assert_eq (m->offset, 4, "array member offset survives");
	mu_assert_eq (m->count, 16, "array member count survives the roundtrip");

	r_anal_base_type_free (got);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_struct_redefine(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kappa");
	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("bar")
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	member.offset = 4;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	// a redefinition replaces the member list and drops the stale member keys
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kappa");
	member.offset = 0;
	member.type = strdup ("int64_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	sdb_set (reg, "kappa", "struct", 0);
	sdb_set (reg, "struct.kappa", "cow", 0);
	sdb_set (reg, "struct.kappa.cow", "int64_t,0,0", 0);
	assert_sdb_eq (anal->sdb_types, reg, "redefined struct type");

	// an empty declaration must not clobber the full definition
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kappa");
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	assert_sdb_eq (anal->sdb_types, reg, "empty declaration kept the definition");
	sdb_free (reg);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_struct_comma_type_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("tpl");

	RAnalStructMember member = {
		.offset = 8,
		.type = strdup ("pair<int, char>"),
		.name = strdup ("p"),
		.count = 0
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	RAnalBaseType *got = r_anal_get_base_type (anal, "tpl");
	mu_assert_notnull (got, "reload struct with comma in member type");

	RAnalStructMember *m = RVecAnalTypeMember_at (&got->struct_data.members, 0);
	mu_assert_streq (m->type, "pair<int, char>", "member type with comma survives the roundtrip");
	mu_assert_eq (m->offset, 8, "offset not shifted by the comma in the type");
	mu_assert_eq (m->count, 0, "no count fabricated from comma-shifted fields");

	r_anal_base_type_free (got);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_union_comma_type_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("utpl");

	RAnalUnionMember member = {
		.offset = 0,
		.type = strdup ("pair<int, char>"),
		.name = strdup ("p"),
		.count = 4
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	RAnalBaseType *got = r_anal_get_base_type (anal, "utpl");
	mu_assert_notnull (got, "reload union with comma in member type");

	RAnalUnionMember *m = RVecAnalTypeMember_at (&got->union_data.members, 0);
	mu_assert_streq (m->type, "pair<int, char>", "member type with comma survives the roundtrip");
	mu_assert_eq (m->count, 4, "count not shifted by the comma in the type");

	r_anal_base_type_free (got);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_union_array_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("uarr");

	RAnalUnionMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("scalar"),
		.count = 0
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	member.offset = 0;
	member.type = strdup ("char");
	member.name = strdup ("buf");
	member.count = 16;
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	RAnalBaseType *got = r_anal_get_base_type (anal, "uarr");
	mu_assert_notnull (got, "reload union with array member");

	RAnalUnionMember *m = RVecAnalTypeMember_at (&got->union_data.members, 0);
	mu_assert_eq (m->count, 0, "scalar member count survives as 0");
	m = RVecAnalTypeMember_at (&got->union_data.members, 1);
	mu_assert_eq (m->count, 16, "array member count survives the roundtrip");

	r_anal_base_type_free (got);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_union_redefine(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("omega");
	RAnalUnionMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("bar")
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);
	member.offset = 0;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	// a redefinition replaces the member list and drops the stale member keys
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("omega");
	member.offset = 0;
	member.type = strdup ("int64_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	sdb_set (reg, "omega", "union", 0);
	sdb_set (reg, "union.omega", "cow", 0);
	sdb_set (reg, "union.omega.cow", "int64_t,0,0", 0);
	assert_sdb_eq (anal->sdb_types, reg, "redefined union type");

	// an empty declaration must not clobber the full definition
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("omega");
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	assert_sdb_eq (anal->sdb_types, reg, "empty declaration kept the definition");
	sdb_free (reg);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_to_kv(void) {
	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kv");

	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("scalar"),
		.count = 0
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup ("char");
	member.name = strdup ("buf");
	member.count = 16;
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	char *kv = r_anal_base_type_to_kv (base);
	mu_assert_streq (kv,
		"kv=struct\n"
		"struct.kv.scalar=int32_t,0,0\n"
		"struct.kv.buf=char,4,16\n"
		"struct.kv=scalar,buf\n",
		"canonical struct kv serialization");
	free (kv);
	base->size = 256;
	kv = r_anal_base_type_to_kv (base);
	mu_assert_notnull (strstr (kv, "type.kv.size=256\n"), "canonical serialization retains the known aggregate extent in bits");
	free (kv);
	r_anal_base_type_free (base);

	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("ukv");
	RAnalUnionMember umember = {
		.offset = 0,
		.type = strdup ("char"),
		.name = strdup ("buf"),
		.count = 8
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &umember);

	kv = r_anal_base_type_to_kv (base);
	mu_assert_streq (kv,
		"ukv=union\n"
		"union.ukv.buf=char,0,8\n"
		"union.ukv=buf\n",
		"canonical union kv serialization");
	free (kv);
	r_anal_base_type_free (base);
	mu_end;
}

static bool test_anal_cparse_multiline_fnptr(void) {
	RAnal *anal = r_anal_new ();
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	char *kv = r_anal_cparse (anal, "void once(void (*cb)(\n\tint\n));", &error);
	mu_assert_null (error, "parse multiline function pointer parameter");
	mu_assert_notnull (kv, "serialize multiline function pointer parameter");
	mu_assert_notnull (strstr (kv, "func.once.arg.0=void (*)(int),cb\n"),
		"function pointer type stays within one SDB row");
	free (kv);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_attribute_capacity(void) {
	RAnal *anal = r_anal_new ();
	int form, count;
	for (form = 0; form < 2; form++) {
		for (count = 10; count <= 11; count++) {
			RStrBuf *header = r_strbuf_new ("int before(int value);\n");
			if (!form) {
				r_strbuf_append (header, "///");
			}
			int i;
			for (i = 0; i < count; i++) {
				r_strbuf_appendf (header, form? "__attribute__((a%d(%d))) ": " @a%d(%d)", i, i);
			}
			r_strbuf_append (header, "\nint annotated(int value);\nint after(int value);\n");
			char *error = NULL;
			char *kv = r_anal_cparse (anal, r_strbuf_get (header), &error);
			r_strbuf_free (header);
			mu_assert_null (error, "parse attributes at and above the former capacity");
			mu_assert_notnull (kv, "serialize all attributes without truncation");
			for (i = 0; i < count; i++) {
				char *expected = r_str_newf ("func.annotated.@.a%d=%d\n", i, i);
				mu_assert_notnull (strstr (kv, expected), "retain each attribute value and key");
				free (expected);
			}
			mu_assert_null (strstr (kv, "func.before.@."), "attributes do not affect the preceding declaration");
			mu_assert_null (strstr (kv, "func.after.@."), "applying attributes resets the collection");
			mu_assert_notnull (strstr (kv, "func.annotated.arg.0=int,value\n"), "attributes preserve the annotated signature");
			mu_assert_notnull (strstr (kv, "func.after.arg.0=int,value\n"), "the next ordinary signature is retained");
			free (kv);
		}
	}
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_attribute_duplicates(void) {
	RAnal *anal = r_anal_new ();
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	char *kv = r_anal_cparse (anal,
		"/// @a0(0) @a1(1) @a2(2) @a3(3) @a4(4) @a5(5) @a6(6) @value(first) @value(last) @flag\n"
		"__attribute__((value(gnu))) __attribute__((value(again))) int mixed(void);\n"
		"struct Mixed __attribute__((aligned(8))) {\n"
		"int member __attribute__((value(gnu))); /// @value(comment) @memberflag\n"
		"char tail;};\n"
		"int ordinary(void);", &error);
	mu_assert_null (error, "parse duplicate and mixed-form attributes");
	mu_assert_notnull (kv, "serialize duplicate and mixed-form attributes");
	mu_assert_notnull (strstr (kv, "func.mixed.@.a6=6\n"), "mixed-form accumulation retains earlier attributes beyond the former capacity");
	mu_assert_notnull (strstr (kv,
		"func.mixed.@.value=last\nfunc.mixed.@.flag=true\n"
		"func.mixed.@.value=gnu\nfunc.mixed.@.value=again\n"),
		"comment duplicates replace the first entry while GNU duplicates append in order");
	mu_assert_null (strstr (kv, "func.mixed.@.value=first\n"), "the replaced comment value is not applied");
	mu_assert_notnull (strstr (kv, "struct.Mixed.@.aligned=8\n"), "aggregate attributes retain their scope");
	mu_assert_notnull (strstr (kv, "struct.Mixed.member.@.value=comment\nstruct.Mixed.member.@.memberflag=true\n"),
		"trailing comment replaces a matching GNU attribute and retains a bare flag");
	mu_assert_null (strstr (kv, "struct.Mixed.member.@.value=gnu\n"), "mixed-form replacement does not append a duplicate");
	mu_assert_null (strstr (kv, "struct.Mixed.tail.@."), "member attributes reset before the next member");
	mu_assert_null (strstr (kv, "func.ordinary.@."), "attributes reset before the next function");
	r_anal_save_parsed_type (anal, kv);
	mu_assert_eq (r_anal_type_bitsize (anal, "Mixed"), 64, "attribute lookup retains aggregate alignment");
	free (kv);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_nested_layout(void) {
	int bits;
	for (bits = 32; bits <= 64; bits += 32) {
		RAnal *anal = r_anal_new ();
		anal->config->bits = bits;
		r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
		char *error = NULL;
		char *kv = r_anal_cparse (anal,
			"struct Window {const char *sunlight;};"
			"struct Bright {void *morning;struct Window window;int ambassador;};", &error);
		mu_assert_null (error, "parse nested pointer-sized record");
		mu_assert_notnull (kv, "serialize nested pointer-sized record");
		const char *ambassador = bits == 64? "struct.Bright.ambassador=int,16,0\n": "struct.Bright.ambassador=int,8,0\n";
		mu_assert_notnull (strstr (kv, ambassador), "the member after Window does not overlap it");
		mu_assert_null (sdb_const_get (anal->sdb_types, "Window", NULL), "parsing does not import its definitions into analysis");
		r_anal_save_parsed_type (anal, kv);
		free (kv);
		mu_assert_eq (r_anal_type_bitsize (anal, "Window"), bits, "Window retains its pointer-sized extent");
		mu_assert_eq (r_anal_type_bitsize (anal, "Bright"), bits == 64? 192: 96, "Bright retains aggregate tail padding");
		mu_assert_true (r_anal_import_c_decls (anal,
			"typedef struct Window WindowAlias;typedef WindowAlias WindowPair[2];"
			"typedef struct Group {char lead;WindowPair windows;char tail;} Group;"
			"typedef union Choice {char c;Group groups[2];} Choice;"
			"struct Outer {char lead;Choice choice;char tail;};", &error), "import aliases, arrays and definition-form aggregates");
		mu_assert_null (error, "measure previously imported definitions");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.WindowPair", NULL), "WindowAlias [2]", "array typedef retains its element type and extent");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Group.tail", NULL), bits == 64? "char,24,0": "char,12,0", "definition-form struct measures array alias elements");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Outer.tail", NULL), bits == 64? "char,72,0": "char,36,0", "definition-form union extent governs its consumer");
		mu_assert_eq (r_anal_type_bitsize (anal, "Group"), bits == 64? 256: 128, "definition-form struct has tail padding");
		mu_assert_eq (r_anal_type_bitsize (anal, "Choice"), bits == 64? 512: 256, "definition-form union measures its largest array");
		mu_assert_true (r_anal_import_c_decls (anal,
			"struct Packed __attribute__((packed)) {char c;void *p;};", &error), "import a packed pointer record");
		mu_assert_true (r_anal_import_c_decls (anal,
			"struct Envelope {char lead;struct Packed packed;char tail;};", &error), "reuse packing from a previous import");
		mu_assert_null (error, "packed nested definition layout succeeds");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Envelope.packed", NULL), "struct Packed,1,0", "nested packed alignment comes from its definition");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Envelope.tail", NULL), bits == 64? "char,10,0": "char,6,0", "nested packed extent includes its pointer");
		r_anal_free (anal);
	}
	mu_end;
}

static bool test_anal_cparse_callback_array_layout(void) {
	int bits;
	for (bits = 32; bits <= 64; bits += 32) {
		RAnal *anal = r_anal_new ();
		anal->config->bits = bits;
		r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
		char *error = NULL;
		mu_assert_true (r_anal_import_c_decls (anal,
			"typedef int (*CB)(int x[4]); struct S { CB callback; char tail; };", &error), "import callback with an array parameter and its consumer together");
		mu_assert_null (error, "callback parameter array does not prevent record layout");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.CB", NULL), "func.CB *", "callback typedef is imported");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.S.callback", NULL), "CB,0,0", "record retains its callback member");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.S.tail", NULL), bits == 64? "char,8,0": "char,4,0", "callback occupies one target pointer");
		mu_assert_eq (r_anal_type_bitsize (anal, "S"), bits * 2, "callback record retains pointer alignment and tail padding");
		mu_assert_true (r_anal_import_c_decls (anal,
			"typedef int (*ArrayCallback)(int x[4]);typedef ArrayCallback CallbackAlias;"
			"struct AliasRecord {CallbackAlias callback;char tail;};"
			"typedef int *Pointers[2];struct PointerArrays {int *direct[2];Pointers indirect;char tail;};", &error), "import transitive callback aliases and outer pointer arrays");
		mu_assert_null (error, "callback aliases and pointer arrays retain their distinct layout");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.CallbackAlias", NULL), "ArrayCallback", "transitive callback alias is imported");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.AliasRecord.tail", NULL), bits == 64? "char,8,0": "char,4,0", "transitive callback alias occupies one pointer");
		mu_assert_eq (r_anal_type_bitsize (anal, "AliasRecord"), bits * 2, "transitive callback record retains tail padding");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.PointerArrays.indirect", NULL), bits == 64? "Pointers,16,0": "Pointers,8,0", "direct pointer array retains both elements");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.PointerArrays.tail", NULL), bits == 64? "char,32,0": "char,16,0", "outer array typedef retains both pointer elements");
		mu_assert_eq (r_anal_type_bitsize (anal, "PointerArrays"), bits * 5, "pointer arrays retain their extent and alignment");
		r_anal_free (anal);
	}
	mu_end;
}

static bool test_anal_cparse_lazy_alias_layout(void) {
	RAnal *anal = r_anal_new ();
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal,
		"typedef int HostRow[4];typedef HostRow HostChain;typedef int HostFn(int);", &error), "establish host aliases without aggregate layout");
	mu_assert_null (error, "host signature-only aliases parse successfully");
	char *kv = r_anal_cparse (anal,
		"typedef HostChain Local;void before(Local values,HostFn callback);"
		"typedef char HostRow[2];void shadowed(HostChain values);"
		"struct LocalRecord {Local values;char tail;};void after(Local values);", &error);
	mu_assert_null (error, "resolve aliases across local and host records before and after first layout");
	mu_assert_notnull (kv, "serialize private alias and aggregate definitions");
	mu_assert_notnull (strstr (kv, "func.before.arg.0=int *,values\n"), "local alias reaches a transitive host array alias");
	mu_assert_notnull (strstr (kv, "func.before.arg.1=HostFn *,callback\n"), "host function typedef parameters retain adjustment");
	mu_assert_notnull (strstr (kv, "func.shadowed.arg.0=char *,values\n"), "local definition shadows the end of a host alias chain");
	mu_assert_notnull (strstr (kv, "struct.LocalRecord.tail=char,2,0\n"), "first layout replays all local definitions after host metadata");
	mu_assert_notnull (strstr (kv, "func.after.arg.0=char *,values\n"), "post-layout alias lookup retains the same local precedence");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.HostRow", NULL), "int [4]", "private shadowing does not change the host alias");
	mu_assert_null (sdb_const_get (anal->sdb_types, "Local", NULL), "successful parsing does not import local aliases");
	mu_assert_null (sdb_const_get (anal->sdb_types, "LocalRecord", NULL), "successful layout does not import local aggregates");
	free (kv);
	kv = r_anal_cparse (anal, "typedef char HostRow[2];struct Partial {HostRow row;};struct Broken {Unknown value;};", &error);
	mu_assert_null (kv, "failed aggregate parsing returns no partial definitions");
	mu_assert_notnull (error, "failed private layout reports the unmeasurable member");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.HostRow", NULL), "int [4]", "failed parsing does not overwrite host aliases");
	mu_assert_null (sdb_const_get (anal->sdb_types, "Partial", NULL), "failed parsing does not import an earlier complete aggregate");
	free (error);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_tcc_prototype_metadata(void) {
	RAnal *anal = r_anal_new ();
	anal->opt.tparser = strdup ("tcc");
	mu_assert_true (r_anal_import_c_decls (anal, "int old();int fixed(void);int typed(int value);int variadic(int value,...);", NULL), "the optional TCC producer emits parameter-list facts");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.old.prototype", NULL), "unspecified", "TCC FUNC_OLD retains unspecified inputs");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.fixed.prototype", NULL), "fixed", "TCC void retains fixed-empty inputs");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.typed.prototype", NULL), "fixed", "TCC typed arguments retain a fixed contract");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.variadic.prototype", NULL), "fixed", "TCC ellipsis does not turn the prototype unspecified");
	mu_assert_true (r_type_func_is_variadic (anal->sdb_types, "variadic", 2), "TCC preserves explicit ellipsis separately");
	mu_assert_false (r_type_func_is_variadic (anal->sdb_types, "old", 0), "TCC does not invent literal ellipsis for FUNC_OLD");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_prototype_metadata(void) {
	RAnal *anal = r_anal_new ();
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal,
		"int unspecified();int fixed(void);int typed(int value);int variadic(int value,...);"
		"typedef int (*UnspecifiedCallback)();typedef int (*FixedCallback)(void);", &error), "import declarations with actual parameter-list syntax");
	mu_assert_null (error, "parameter-list declarations parse successfully");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.unspecified.prototype", NULL), "unspecified", "empty parentheses preserve unspecified inputs");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.fixed.prototype", NULL), "fixed", "void preserves a fixed zero-input contract");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.typed.prototype", NULL), "fixed", "typed inputs preserve a fixed contract");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.variadic.prototype", NULL), "fixed", "explicit ellipsis is separate from unspecified inputs");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.UnspecifiedCallback.prototype", NULL), "unspecified", "callback metadata retains empty-parentheses syntax");
	mu_assert_nullable_streq (sdb_const_get (anal->sdb_types, "func.FixedCallback.prototype", NULL), "fixed", "callback metadata retains void syntax");
	mu_assert_true (r_type_func_is_variadic (anal->sdb_types, "variadic", 2), "ellipsis retains its separate argument marker");
	mu_assert_false (r_type_func_is_variadic (anal->sdb_types, "unspecified", 0), "unspecified input is not an explicit ellipsis");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_grouped_names(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal,
		"int (grouped)(int);typedef int (Number);"
		"struct Grouped {int (object);int (*callback)(int);};", &error), "the header producer uses named declaration context");
	mu_assert_null (error, "grouped function, typedef and member names are accepted");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "grouped", NULL), "func", "the real grouped identifier owns the function");
	mu_assert_streq (r_type_func_ret (anal->sdb_types, "grouped"), "int", "the grouped function keeps its return type");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.Number", NULL), "int", "a grouped typedef name still names an object type");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Grouped.object", NULL), "int,0,0", "a grouped scalar member is not an anonymous function");
	mu_assert_null (sdb_const_get (anal->sdb_types, "Grouped.object", NULL), "a grouped scalar member does not install a callback signature");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Grouped.callback", NULL), "func.Grouped.callback *,8,0", "the separate callback member retains its function-pointer shape");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_visible_typedef_callbacks(void) {
	int existing;
	for (existing = 0; existing < 2; existing++) {
		RAnal *anal = r_anal_new ();
		char *error = NULL;
		if (existing) {
			mu_assert_true (r_anal_import_c_decls (anal, "typedef int T;", &error), "seed the existing analysis typedef");
		}
		char *header = r_str_newf ("%sint f(int (T));int h(int (T,T));int g(int (*)(T));int control(int (value));"
			"int hide(int T, void (*cb)(int (T)));int scoped(void (*cb)(int T), int (T));",
			existing? "": "typedef int T;");
		mu_assert_true (r_anal_import_c_decls (anal, header, &error), "import contextual declarations from the same header or the analysis database");
		mu_assert_null (error, "contextual declarations import without errors");
		free (header);
		const char *names[] = { "f", "h", "g" };
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (names); i++) {
			char *type = r_type_func_args_type (anal->sdb_types, names[i], 0);
			mu_assert_streq (type, i == 1? "int (*)(T, T)": "int (*)(T)", "imported callback retains adjusted pointer and typedef parameters");
			RTypeDecl *decl = r_type_decl_parse (type, R_TYPE_DECL_CONTEXT_ABSTRACT, anal->sdb_types, NULL);
			mu_assert_notnull (decl, "imported callback is a shared declaration");
			mu_assert_eq (decl->type->kind, R_TYPE_DECL_POINTER, "import adjusts a function parameter to a pointer");
			mu_assert_eq (decl->type->child->kind, R_TYPE_DECL_FUNCTION, "callback category survives real import");
			mu_assert_true (decl->type->child->function.prototype, "callback prototype remains fixed");
			r_type_decl_free (decl);
			free (type);
		}
		char *type = r_type_func_args_type (anal->sdb_types, "control", 0);
		mu_assert_streq (type, "int", "ordinary grouped parameter remains scalar during import");
		mu_assert_streq (r_type_func_args_name (anal->sdb_types, "control", 0), "value", "ordinary grouped parameter retains its name");
		free (type);
		type = r_type_func_args_type (anal->sdb_types, "hide", 1);
		mu_assert_streq (type, "void (*)(int T)", "earlier parameter hides the typedef during import");
		free (type);
		type = r_type_func_args_type (anal->sdb_types, "scoped", 1);
		mu_assert_streq (type, "int (*)(T)", "nested prototype parameter does not leak into outer import");
		free (type);
		mu_assert_false (r_anal_import_c_decls (anal, "int invalid(int T, T value);", &error), "import refuses a hidden typedef used as a type");
		free (error);
		r_anal_free (anal);
	}
	mu_end;
}

static bool test_anal_cparse_forward_identity(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 16;
	r_anal_use (anal, "x86");
	r_anal_types_reload (anal, R2_PREFIX, "windows", "x86");
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal,
		"struct Opaque;union Choice;struct Opaque;union Choice;"
		"typedef struct Opaque near *OpaqueNear;typedef union Choice far *ChoiceFar;"
		"struct Handles {OpaqueNear first;ChoiceFar second;};struct Opaque;union Choice;", &error), "import real incomplete tags and pointer declarations");
	mu_assert_null (error, "opaque pointer headers do not need pointee layout");
	const char *names[] = { "Opaque", "Choice" };
	int i;
	for (i = 0; i < R_ARRAY_SIZE (names); i++) {
		RAnalBaseType *base = r_anal_get_base_type (anal, names[i]);
		mu_assert_notnull (base, "a forward declaration has a readable base identity");
		mu_assert_eq (base->kind, i? R_ANAL_BASE_TYPE_KIND_UNION: R_ANAL_BASE_TYPE_KIND_STRUCT, "the tag retains its aggregate kind");
		mu_assert_true (RVecAnalTypeMember_empty (r_anal_base_type_members (base)), "an incomplete tag has no invented members");
		mu_assert_eq (base->size, 0, "an incomplete identity has no recorded extent");
		r_anal_save_base_type (anal, base);
		char *serialized = r_anal_base_type_to_kv (base);
		r_anal_save_parsed_type (anal, serialized);
		free (serialized);
		r_anal_base_type_free (base);
		RTypeLayout layout;
		mu_assert_false (r_type_get_layout (anal->sdb_types, names[i], &layout), "save roundtrip must not make an incomplete tag a zero-byte object");
	}
	mu_assert_streq (sdb_const_get (anal->sdb_types, "Opaque", NULL), "struct", "save retains the struct identity");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "Choice", NULL), "union", "save retains the union identity");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.OpaqueNear", NULL), "struct Opaque near *", "near pointer retains its explicit opaque target");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.ChoiceFar", NULL), "union Choice far *", "far pointer retains its explicit opaque target");
	mu_assert_eq (r_anal_type_bitsize (anal, "OpaqueNear"), 16, "near opaque pointer has target width");
	mu_assert_eq (r_anal_type_bitsize (anal, "ChoiceFar"), 32, "far opaque pointer has target width");
	mu_assert_eq (r_anal_type_bitsize (anal, "Handles"), 48, "pointer members compose without completing either tag");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_forward_completion(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal, "struct Opaque;union Choice;", &error), "import incomplete identities");
	mu_assert_true (r_anal_import_c_decls (anal,
		"struct Opaque;struct Opaque {int value;};struct Opaque;"
		"union Choice;union Choice {int value;};union Choice;", &error), "complete each tag and then forward declare it in one input");
	mu_assert_true (r_anal_import_c_decls (anal, "struct Opaque;union Choice;struct Opaque;union Choice;", &error), "later imports may repeat forward declarations");
	mu_assert_null (error, "forward declarations do not invalidate complete definitions");
	const char *names[] = { "Opaque", "Choice" };
	int i;
	for (i = 0; i < R_ARRAY_SIZE (names); i++) {
		RAnalBaseType *base = r_anal_get_base_type (anal, names[i]);
		mu_assert_notnull (base, "complete definition remains retrievable");
		RAnalTypeMember *member = RVecAnalTypeMember_at (r_anal_base_type_members (base), 0);
		mu_assert_notnull (member, "a repeated forward does not remove existing members");
		mu_assert_streq (member->name, "value", "completed member identity survives");
		mu_assert_eq (r_anal_type_bitsize (anal, names[i]), 32, "completed extent survives repeated forwards");
		r_anal_base_type_free (base);
	}
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_forward_typedef(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal,
		"typedef struct Opaque Opaque;typedef union Choice Choice;"
		"typedef struct Distinct Alias;typedef union DistinctUnion UnionAlias;"
		"struct Links {Opaque *first;Choice *second;struct Distinct *third;Alias *fourth;};", &error), "typedef-only declarations retain the introduced tag");
	mu_assert_null (error, "same-name aliases do not create recursive typedefs");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "Opaque", NULL), "struct", "same-name struct typedef coalesces with the tag");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "Choice", NULL), "union", "same-name union typedef coalesces with the tag");
	mu_assert_null (sdb_const_get (anal->sdb_types, "typedef.Opaque", NULL), "coalesced identity has no self-referential alias");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "Distinct", NULL), "struct", "a distinct explicit tag owns its identity");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "Alias", NULL), "typedef", "a distinct alias is not mistaken for the explicit tag");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.Alias", NULL), "struct Distinct", "a distinct typedef retains its actual target");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "DistinctUnion", NULL), "union", "a distinct union tag owns its identity");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.UnionAlias", NULL), "union DistinctUnion", "a distinct union alias retains its actual target");
	mu_assert_true (r_anal_import_c_decls (anal, "struct Opaque {int value;};union Choice {int value;};", &error), "complete coalesced typedef tags");
	mu_assert_true (r_anal_import_c_decls (anal, "typedef struct Opaque Opaque;typedef union Choice Choice;", &error), "a later same-name typedef preserves completed layouts");
	mu_assert_eq (r_anal_type_bitsize (anal, "Opaque"), 32, "same-name struct typedef does not clobber a complete definition");
	mu_assert_eq (r_anal_type_bitsize (anal, "Choice"), 32, "same-name union typedef does not clobber a complete definition");
	mu_assert_true (r_anal_import_c_decls (anal, "struct Inline;typedef struct Inline Inline;struct Inline {int value;};typedef struct Inline Inline;", &error), "same-input forwards and same-name typedefs preserve completion");
	mu_assert_eq (r_anal_type_bitsize (anal, "Inline"), 32, "same-input coalescing retains completed extent");
	mu_assert_false (r_anal_import_c_decls (anal, "union Opaque;", &error), "a different aggregate kind still conflicts with an actual struct tag");
	mu_assert_notnull (error, "a real tag conflict reports a diagnostic");
	mu_assert_notnull (strstr (error, "Conflicting aggregate tag"), "only the actual tag namespace establishes this conflict");
	free (error);
	mu_assert_streq (sdb_const_get (anal->sdb_types, "Opaque", NULL), "struct", "rejected tag-kind changes preserve the completed owner");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_distinct_tag_and_typedef_names(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 16;
	r_anal_types_reload (anal, R2_PREFIX, "windows", "x86");
	char *error = NULL;
	bool imported = r_anal_import_c_decls (anal,
		"struct Window {const char *sunlight;};struct Bright {int member;};"
		"typedef struct Bright BrightTypedefd;typedef struct BrightTypedefd *BrightTypedefdPtr;"
		"typedef struct BrightTypedefd near *BrightNear;"
		"union Box {int member;};typedef union Box UnionAlias;typedef union UnionAlias far *UnionFar;"
		"struct Pointers {BrightTypedefdPtr first;BrightNear second;UnionFar third;};"
		"struct Ordinary {BrightTypedefd first;UnionAlias second;};"
		"struct BrightTypedefd;union UnionAlias;", &error);
	if (imported) {
		mu_assert_null (error, "ordinary typedef names are not evidence of a conflicting tag");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "Window", NULL), "struct", "later tag declarations retain earlier owners");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "BrightTypedefd", NULL), "typedef", "the ordinary typedef is not replaced with a tag owner");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.BrightTypedefd", NULL), "struct Bright", "the ordinary alias retains its actual aggregate");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.BrightTypedefdPtr", NULL), "struct BrightTypedefd *", "the distinct incomplete tag retains its explicit spelling");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "UnionAlias", NULL), "typedef", "a union tag does not replace an unrelated ordinary alias");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.UnionFar", NULL), "union UnionAlias far *", "a far pointer retains the distinct union tag");
		mu_assert_eq (r_anal_type_bitsize (anal, "Window"), 16, "earlier pointer-containing layouts survive admission");
		mu_assert_eq (r_anal_type_bitsize (anal, "Pointers"), 64, "ordinary, near and far pointers do not need incomplete pointee layouts");
		mu_assert_eq (r_anal_type_bitsize (anal, "Ordinary"), 32, "ordinary struct and union aliases remain usable by value");
	}
	free (error);
	r_anal_free (anal);
	mu_assert_true (imported, "the header admits a typedef and a distinct incomplete tag with the same spelling");
	mu_end;
}

static bool test_anal_cparse_tagged_member_does_not_resolve_typedef(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	mu_assert_true (r_anal_import_c_decls (anal,
		"struct Bright {int member;};typedef struct Bright Alias;"
		"union Box {int member;};typedef union Box UnionAlias;"
		"struct Ordinary {Alias value;};struct Pointer {struct Alias *value;};", NULL), "seed ordinary aliases and an opaque tagged pointer");
	mu_assert_eq (r_anal_type_bitsize (anal, "Ordinary"), 32, "ordinary Alias still names the completed struct");
	mu_assert_eq (r_anal_type_bitsize (anal, "Pointer"), 64, "an opaque tagged pointer still has target representation");
	RTypeLayout layout;
	bool struct_layout = r_type_get_layout (anal->sdb_types, "struct Alias", &layout);
	bool union_layout = r_type_get_layout (anal->sdb_types, "union UnionAlias", &layout);
	const char *headers[] = { "struct Consumer {struct Alias value;};", "union Consumer {union UnionAlias value;};" };
	bool refused = true;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (headers); i++) {
		char *error = NULL;
		bool imported = r_anal_import_c_decls (anal, headers[i], &error);
		refused = refused && !imported && error && strstr (error, "Cannot measure member type");
		free (error);
	}
	bool no_consumer = !sdb_const_get (anal->sdb_types, "Consumer", NULL);
	r_anal_free (anal);
	mu_assert_false (struct_layout, "struct Alias cannot use the unrelated ordinary typedef's layout");
	mu_assert_false (union_layout, "union UnionAlias cannot use the unrelated ordinary typedef's layout");
	mu_assert_true (refused, "incomplete tagged by-value members refuse with a layout diagnostic");
	mu_assert_true (no_consumer, "rejected member layouts do not install a fabricated containing aggregate");
	mu_end;
}

static bool test_anal_type_format_tagged_identity(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	mu_assert_true (r_anal_import_c_decls (anal,
		"struct Bright {int member;};typedef struct Bright Alias;struct Alias;"
		"union Box {int member;};typedef union Box UnionAlias;union UnionAlias;"
		"struct Opaque;", NULL), "seed complete aggregates, ordinary aliases and incomplete tags");
	char *format = r_type_format (anal->sdb_types, "struct Alias");
	mu_assert_null (format, "an incomplete struct tag cannot borrow an ordinary typedef's format");
	format = r_type_format (anal->sdb_types, "union UnionAlias");
	mu_assert_null (format, "an incomplete union tag cannot borrow an ordinary typedef's format");
	format = r_type_format (anal->sdb_types, "struct Opaque");
	mu_assert_null (format, "an incomplete tag without an alias has no by-value format");
	format = r_type_format (anal->sdb_types, "union Bright");
	mu_assert_null (format, "an explicit tag cannot borrow another tag kind's format");
	format = r_type_format (anal->sdb_types, "Alias");
	mu_assert_streq (format, "d member ", "ordinary struct aliases retain the complete format");
	free (format);
	format = r_type_format (anal->sdb_types, "struct Bright");
	mu_assert_streq (format, "d member ", "a complete struct retains its tagged format");
	free (format);
	format = r_type_format (anal->sdb_types, "UnionAlias");
	mu_assert_streq (format, "0d member ", "ordinary union aliases retain the complete format");
	free (format);
	format = r_type_format (anal->sdb_types, "union Box");
	mu_assert_streq (format, "0d member ", "a complete union retains its tagged format");
	free (format);
	format = r_type_format (anal->sdb_types, "struct Alias *");
	mu_assert_streq (format, "p", "an incomplete tagged pointee still has pointer representation");
	free (format);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_incomplete_member(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal, "struct Opaque;typedef struct Opaque Opaque;union Choice;", &error), "establish incomplete tags");
	const char *headers[] = {
		"struct Broken {struct Opaque value;};",
		"struct Broken {Opaque value;};",
		"union Broken {union Choice value;};",
		"struct Broken {struct Opaque values[2];};"
	};
	int i;
	for (i = 0; i < R_ARRAY_SIZE (headers); i++) {
		mu_assert_false (r_anal_import_c_decls (anal, headers[i], &error), "incomplete by-value members have no usable layout");
		mu_assert_notnull (error, "an incomplete member reports a diagnostic");
		mu_assert_notnull (strstr (error, "Cannot measure member type"), "failure identifies the missing member layout");
		free (error);
		error = NULL;
		mu_assert_null (sdb_const_get (anal->sdb_types, "Broken", NULL), "failed import must not invent a containing aggregate");
	}
	mu_assert_streq (sdb_const_get (anal->sdb_types, "Opaque", NULL), "struct", "failed by-value imports preserve the opaque identity");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_definition_alias(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal,
		"typedef struct Tag {int x;int y;} Alias;"
		"typedef union UnionTag {Alias value;int word;} UnionAlias;"
		"typedef struct Same {Alias value;} Same;"
		"typedef struct {UnionAlias value;} Anonymous;", &error), "import definition-form aliases");
	mu_assert_null (error, "definition-form aliases parse successfully");
	RAnalBaseType *base = r_anal_get_base_type (anal, "Alias");
	mu_assert_notnull (base, "the distinct struct alias has a native owner");
	mu_assert_eq (base->kind, R_ANAL_BASE_TYPE_KIND_TYPEDEF, "the distinct struct alias is a typedef");
	mu_assert_streq (base->type, "struct Tag", "the alias targets the named struct");
	r_anal_base_type_free (base);
	base = r_anal_get_base_type (anal, "Tag");
	mu_assert_notnull (base, "the named struct remains readable");
	mu_assert_eq (base->kind, R_ANAL_BASE_TYPE_KIND_STRUCT, "the tag owns the struct definition");
	RAnalTypeMember *member = RVecAnalTypeMember_at (r_anal_base_type_members (base), 1);
	mu_assert_notnull (member, "the tag retains the y field");
	mu_assert_streq (member->name, "y", "the named struct retains field identity");
	mu_assert_eq (member->offset, 4, "the named struct retains field layout");
	r_anal_base_type_free (base);
	base = r_anal_get_base_type (anal, "UnionAlias");
	mu_assert_notnull (base, "the distinct union alias has a native owner");
	mu_assert_eq (base->kind, R_ANAL_BASE_TYPE_KIND_TYPEDEF, "the distinct union alias is a typedef");
	mu_assert_streq (base->type, "union UnionTag", "the alias targets the named union");
	r_anal_base_type_free (base);
	base = r_anal_get_base_type (anal, "UnionTag");
	mu_assert_notnull (base, "the named union remains readable");
	mu_assert_eq (base->kind, R_ANAL_BASE_TYPE_KIND_UNION, "the tag owns the union definition");
	r_anal_base_type_free (base);
	mu_assert_eq (r_anal_type_bitsize (anal, "Alias"), 64, "native measurement follows the struct typedef");
	mu_assert_eq (r_anal_type_bitsize (anal, "UnionAlias"), 64, "native measurement follows the union typedef");
	const char *records[] = {"Same", "Anonymous"};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (records); i++) {
		base = r_anal_get_base_type (anal, records[i]);
		mu_assert_notnull (base, "same-name and anonymous definitions remain native records");
		mu_assert_eq (base->kind, R_ANAL_BASE_TYPE_KIND_STRUCT, "the definition owns its record kind");
		mu_assert_eq (base->size, 64, "record layout follows the distinct alias member");
		r_anal_base_type_free (base);
		mu_assert_null (sdb_const_getf (anal->sdb_types, NULL, "typedef.%s", records[i]), "a record does not declare itself as a typedef");
	}
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_type_bitsize_struct_recorded(void) {
	RAnal *anal = r_anal_new ();
	Sdb *TDB = anal->sdb_types;
	sdb_set (TDB, "int32_t", "type", 0);
	sdb_num_set (TDB, "type.int32_t.size", 32, 0);
	// an importer that knows the real width, padding included, saves it with the members
	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("padded");
	base->size = 128;
	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("a")
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	member.offset = 8;
	member.type = strdup ("int32_t");
	member.name = strdup ("b");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);
	mu_assert_eq (sdb_num_get (TDB, "type.padded.size", NULL), 128, "The struct width is saved beside its members");
	mu_assert_eq (r_type_get_bitsize (TDB, "padded"), 128, "A recorded width wins over the member sum");
	mu_assert_eq (r_type_get_bitsize (TDB, "struct padded"), 128, "The keyword spelling reads the same record");
	// a re-save of what was read back keeps the width
	base = r_anal_get_base_type (anal, "padded");
	mu_assert_notnull (base, "The saved struct reads back");
	mu_assert_eq (base->size, 128, "The width reads back with the members");
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);
	mu_assert_eq (r_type_get_bitsize (TDB, "padded"), 128, "A re-save keeps the recorded width");
	// a struct that names itself still measures when the importer recorded its width
	sdb_set (TDB, "self", "struct", 0);
	sdb_set (TDB, "struct.self", "inner", 0);
	sdb_set (TDB, "struct.self.inner", "self,0,0", 0);
	sdb_num_set (TDB, "type.self.size", 8, 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "self"), 8, "A recorded width answers for a self-naming struct");
	// a definition without a width drops a stale record and walks the members again
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("padded");
	member.offset = 0;
	member.type = strdup ("int32_t");
	member.name = strdup ("a");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);
	mu_assert_null (sdb_const_get (TDB, "type.padded.size", NULL), "A save without a width drops the stale record");
	mu_assert_eq (r_type_get_bitsize (TDB, "padded"), 32, "Without a record the members are measured");
	// deleting the type drops its width too
	sdb_num_set (TDB, "type.padded.size", 64, 0);
	r_type_del (TDB, "padded");
	mu_assert_null (sdb_const_get (TDB, "type.padded.size", NULL), "Deleting the struct drops its width");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_type_bitsize_struct_cycle(void) {
	RAnal *anal = r_anal_new ();
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	Sdb *TDB = anal->sdb_types;
	sdb_set (TDB, "int32_t", "type", 0);
	sdb_num_set (TDB, "type.int32_t.size", 32, 0);
	sdb_set (TDB, "self", "struct", 0);
	sdb_set (TDB, "struct.self", "n,inner", 0);
	sdb_set (TDB, "struct.self.n", "int32_t,0,0", 0);
	sdb_set (TDB, "struct.self.inner", "self,4,0", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "self"), 0, "A struct containing itself fails closed");
	sdb_set (TDB, "ping", "struct", 0);
	sdb_set (TDB, "struct.ping", "pong", 0);
	sdb_set (TDB, "struct.ping.pong", "pong_t,0,0", 0);
	sdb_set (TDB, "pong_t", "typedef", 0);
	sdb_set (TDB, "typedef.pong_t", "pong", 0);
	sdb_set (TDB, "pong", "struct", 0);
	sdb_set (TDB, "struct.pong", "ping", 0);
	sdb_set (TDB, "struct.pong.ping", "ping,0,0", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "ping"), 0, "A struct cycle through a typedef fails closed");
	sdb_set (TDB, "pair", "struct", 0);
	sdb_set (TDB, "struct.pair", "a,b", 0);
	sdb_set (TDB, "struct.pair.a", "int32_t,0,0", 0);
	sdb_set (TDB, "struct.pair.b", "int32_t,4,0", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "pair"), 64, "An acyclic struct still measures its members");
	sdb_set (TDB, "pair_t", "typedef", 0);
	sdb_set (TDB, "typedef.pair_t", "pair", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "pair_t"), 64, "A typedef measures its struct members");
	sdb_set (TDB, "pairs_t", "typedef", 0);
	sdb_set (TDB, "typedef.pairs_t", "pair_t[2]", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "pairs_t"), 128, "An array typedef measures its struct elements");
	sdb_set (TDB, "struct.pong.ping", "int32_t,0,0", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "ping"), 32, "An acyclic struct measures members through a typedef");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_type_bitsize_arrays(void) {
	RAnal *anal = r_anal_new ();
	anal->config->bits = 64;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	Sdb *types = anal->sdb_types;
	sdb_set (types, "word", "type", 0);
	sdb_num_set (types, "type.word.size", 16, 0);
	sdb_set (types, "Ptr", "typedef", 0);
	sdb_set (types, "typedef.Ptr", "word *", 0);
	sdb_set (types, "Row", "typedef", 0);
	sdb_set (types, "typedef.Row", "word[3]", 0);
	mu_assert_eq (r_anal_type_bitsize (anal, "word[2][3]"), 96, "Multidimensional arrays measure every element");
	mu_assert_eq (r_anal_type_bitsize (anal, "Row[2]"), 96, "Array typedef dimensions multiply");
	mu_assert_eq (r_anal_type_bitsize (anal, "Ptr[3]"), 192, "Pointer typedef arrays use the target width");
	mu_assert_eq (r_anal_type_bitsize (anal, "word (*)[3]"), 64, "A pointer to an array is one word");
	mu_assert_eq (r_anal_type_bitsize (anal, "word[2]junk"), 0, "Trailing array text is rejected");
	mu_assert_eq (r_anal_type_bitsize (anal, "word[18446744073709551615]"), 0, "Overflowing dimensions are rejected");
	RTypeLayout unsized;
	mu_assert_true (r_type_get_layout (types, "word[]", &unsized), "an unsized bound retains its separate layout representation");
	mu_assert_eq (unsized.bits, 0, "an unsized array is not one element or a positive bound");
	char *format = r_type_format (types, "char[]");
	mu_assert_null (format, "formatting cannot invent an element count for an unsized array");
	sdb_set (types, "Recursive", "typedef", 0);
	sdb_set (types, "typedef.Recursive", "Recursive[2]", 0);
	mu_assert_eq (r_anal_type_bitsize (anal, "Recursive"), 0, "Recursive array aliases are rejected");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_cparse_array_bounds(void) {
	const char *bounds[] = { "8", "010", "0x8", "1|2+3", "2+3", "(2+3)*2", "1<<3", "8/2", "7%3", "2|4", "010+1", "8U" };
	const int counts[] = { 8, 8, 8, 5, 5, 10, 8, 4, 1, 6, 9, 8 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bounds); i++) {
		RAnal *anal = r_anal_new ();
		r_arch_config_use (anal->config, "x86");
		anal->config->bits = 16;
		r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
		char *header = r_str_newf (
			"typedef char Row[%s];typedef Row Grid[2];typedef int near *NearRow[%s];typedef int far *FarRow[%s];"
			"struct Bounds {char direct[%s];char nested[2][%s];Row alias;NearRow nearptrs;FarRow farptrs;char tail;};",
			bounds[i], bounds[i], bounds[i], bounds[i], bounds[i]);
		char *error = NULL;
		mu_assert_true (r_anal_import_c_decls (anal, header, &error), bounds[i]);
		mu_assert_null (error, "supported bounds reach the real c2 importer");
		free (header);
		char *expected = r_str_newf ("char,0,%d", counts[i]);
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Bounds.direct", NULL), expected, "direct member count uses shared evaluation");
		free (expected);
		expected = r_str_newf ("char,%d,0", 10 * counts[i]);
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Bounds.tail", NULL), expected, "nested, alias, near and far arrays have the expected combined extent");
		free (expected);
		mu_assert_eq (r_anal_type_bitsize (anal, "Bounds"), (10 * counts[i] + 2) * 8, "record extent retains target two-byte pointer alignment");
		mu_assert_eq (r_anal_type_bitsize (anal, "Grid"), counts[i] * 16, "nested typedef arrays multiply both dimensions");
		mu_assert_eq (r_anal_type_bitsize (anal, "NearRow"), counts[i] * 16, "near pointer elements retain two-byte target width");
		mu_assert_eq (r_anal_type_bitsize (anal, "FarRow"), counts[i] * 32, "far pointer elements retain four-byte target width");
		char *format = r_type_format (anal->sdb_types, "Grid");
		expected = r_str_newf ("%dc", counts[i] * 2);
		mu_assert_streq (format, expected, "formatting uses the same count through nested aliases");
		free (expected);
		free (format);
		format = r_type_format (anal->sdb_types, "NearRow");
		expected = counts[i] == 1? strdup ("p"): r_str_newf ("%dp", counts[i]);
		mu_assert_streq (format, expected, "formatting retains near pointer element width and count");
		free (expected);
		free (format);
		format = r_type_format (anal->sdb_types, "FarRow");
		expected = counts[i] == 1? strdup ("p4"): r_str_newf ("%dp4", counts[i]);
		mu_assert_streq (format, expected, "formatting retains far pointer element width and count");
		free (expected);
		free (format);
		r_anal_free (anal);
	}
	mu_end;
}

static bool test_anal_array_bound_target_model(void) {
	int bits;
	for (bits = 16; bits <= 64; bits *= 4) {
		RAnal *anal = r_anal_new ();
		r_arch_config_use (anal->config, "x86");
		anal->config->bits = bits;
		r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
		ut64 count = 0;
		const char *diagnostic = NULL;
		mu_assert_eq (sdb_num_get (anal->sdb_types, "type.int.size", NULL), bits == 16? 16: 32, "selected target database provides int width");
		mu_assert_eq (sdb_num_get (anal->sdb_types, "type.long.size", NULL), bits == 16? 32: 64, "selected target database provides long width");
		mu_assert_true (r_type_array_bound_from_db (anal->sdb_types, "0xffff+2", &count, &diagnostic), "read the selected target model for literal typing");
		mu_assert_eq (count, bits == 16? 1: 65537, "hex literal type follows target int range, not host sizeof");
		char *error = NULL;
		mu_assert_true (r_anal_import_c_decls (anal, "struct TargetBound {char items[0xffff+2];char tail;};", &error), "c2 uses the actual selected integer model");
		mu_assert_null (error, "target-width expression imports successfully");
		mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.TargetBound.tail", NULL), bits == 16? "char,1,0": "char,65537,0", "target integer wrap governs the next field offset");
		char *format = r_type_format (anal->sdb_types, "char[0xffff+2]");
		mu_assert_streq (format, bits == 16? "c": "65537c", "formatting uses the same target-dependent count");
		free (format);
		char *kv = r_anal_cparse (anal, "struct SignedOverflow {char items[32767+1];};", &error);
		if (bits == 16) {
			mu_assert_null (kv, "signed 16-bit arithmetic overflow is rejected");
			mu_assert_notnull (error, "overflow produces a parser diagnostic");
		} else {
			mu_assert_notnull (kv, "the same addition fits a 32-bit int");
			mu_assert_null (error, "representable target arithmetic is valid");
		}
		free (kv);
		free (error);
		r_anal_free (anal);
	}
	mu_end;
}

static bool test_anal_cparse_invalid_bounds_and_builtins(void) {
	RAnal *anal = r_anal_new ();
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	const char *bounds[] = { "0", "-1", "2+BOGUS", "8junk", "1+8/0", "1+8%0" };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (bounds); i++) {
		char *type = r_str_newf ("char [%s]", bounds[i]);
		RTypeLayout layout;
		mu_assert_false (r_type_get_layout (anal->sdb_types, type, &layout), "layout refuses an invalid bound instead of inventing a count");
		char *format = r_type_format (anal->sdb_types, type);
		mu_assert_null (format, "formatting refuses the same invalid bound");
		free (type);
		char *header = r_str_newf ("struct InvalidBound {char items[%s];};", bounds[i]);
		char *error = NULL;
		char *kv = r_anal_cparse (anal, header, &error);
		mu_assert_null (kv, "real c2 rejects invalid array evaluation");
		mu_assert_notnull (error, "invalid evaluation reports a parser error");
		free (error);
		free (header);
	}
	const char *builtins[] = { "unsigned float", "signed unsigned int", "short double", "long long long" };
	for (i = 0; i < R_ARRAY_SIZE (builtins); i++) {
		char *header = r_str_newf ("%s invalid(void);", builtins[i]);
		char *error = NULL;
		char *kv = r_anal_cparse (anal, header, &error);
		mu_assert_null (kv, "real c2 rejects contradictory builtin tokens");
		mu_assert_notnull (error, "invalid builtin tokens report a parser error");
		free (error);
		free (header);
	}
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_x86_16_declaration_layout(void) {
	RAnal *anal = r_anal_new ();
	r_arch_config_use (anal->config, "x86");
	anal->config->bits = 16;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	const char *types[] = { "int", "short", "long", "float", "double", "long double", "long long", "void *", "void near *", "void far *", "uint64_t", "signed char" };
	const ut64 sizes[] = { 16, 16, 32, 32, 64, 80, 64, 16, 16, 32, 64, 8 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (types); i++) {
		mu_assert_eq (r_anal_type_bitsize (anal, types[i]), sizes[i], types[i]);
	}
	RTypeLayout long_doubles;
	mu_assert_true (r_type_get_layout (anal->sdb_types, "long double [2]", &long_doubles), "measure a contiguous long-double pair");
	mu_assert_eq (long_doubles.bits, 160, "two ten-byte elements occupy twenty bytes");
	mu_assert_eq (long_doubles.align, 2, "long-double alignment divides its representation");
	mu_assert_false (r_type_get_layout (anal->sdb_types, "int &", &long_doubles), "reference syntax does not infer a data-object ABI width");
	char *error = NULL;
	mu_assert_true (r_anal_import_c_decls (anal,
		"typedef unsigned char BYTE;typedef BYTE far * volatile near *MIX;"
		"typedef int (far *CB)(int x[4], void (*cb)(int, int));"
		"struct Mixed {char lead;MIX p;int far *farptr;CB cb;char tail;};"
		"void consume(int values[4], int callback(int));struct Wide {long double values[2];};"
		"struct WideTail {long double values[2];char tail;};"
		"typedef int FN(int);typedef int Row[4];void aliases(Row values, FN callback, CB qualified);", &error), "import mixed pointers and explicit far callback");
	mu_assert_null (error, "target declaration import succeeds");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.MIX", NULL), "BYTE far * volatile near *", "mixed pointer typedef retains ordered explicit layers");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "typedef.CB", NULL), "func.CB far *", "callback object has an explicit far pointer around its function reference");
	mu_assert_eq (r_anal_type_bitsize (anal, "func.CB"), 0, "function reference is not a sized object");
	mu_assert_eq (r_anal_type_bitsize (anal, "MIX"), 16, "outer near pointer determines object width");
	mu_assert_eq (r_anal_type_bitsize (anal, "CB"), 32, "far callback pointer width is independent from the convention");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Mixed.p", NULL), "MIX,2,0", "near pointer retains target alignment");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Mixed.farptr", NULL), "int far *,4,0", "far pointer has four-byte extent without imposing four-byte alignment");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Mixed.cb", NULL), "CB,8,0", "far callback follows the far data pointer");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Mixed.tail", NULL), "char,12,0", "callback occupies four bytes");
	mu_assert_eq (r_anal_type_bitsize (anal, "Mixed"), 112, "aggregate retains two-byte pointer alignment and tail padding");
	mu_assert_eq (r_anal_type_bitsize (anal, "Wide"), 160, "long-double array aggregate retains twenty-byte extent");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.WideTail.tail", NULL), "char,20,0", "tail follows twenty bytes of long-double elements");
	char *format = r_type_format (anal->sdb_types, "WideTail");
	mu_assert_streq (format, "[20]bc values tail ", "format composes primitive repetition with the member array extent");
	free (format);
	sdb_set (anal->sdb_types, "type.long double", "[18446744073709551615]b", 0);
	format = r_type_format (anal->sdb_types, "WideTail");
	mu_assert_null (format, "overflowing repeat composition is not serialized");
	sdb_set (anal->sdb_types, "type.long double", "[10]b", 0);
	char *argument = r_type_func_args_type (anal->sdb_types, "CB", 1);
	mu_assert_streq (argument, "void (*)(int, int)", "nested callback commas are not discarded");
	mu_assert_streq (r_type_func_args_name (anal->sdb_types, "CB", 1), "cb", "nested callback name uses the canonical final delimiter");
	free (argument);
	argument = r_type_func_args_type (anal->sdb_types, "consume", 0);
	mu_assert_streq (argument, "int *", "array adjustment is specific to the parameter producer");
	free (argument);
	argument = r_type_func_args_type (anal->sdb_types, "consume", 1);
	mu_assert_streq (argument, "int (*)(int)", "function adjustment is specific to the parameter producer");
	free (argument);
	argument = r_type_func_args_type (anal->sdb_types, "aliases", 0);
	mu_assert_streq (argument, "int *", "array typedef parameters decay to their element type");
	free (argument);
	argument = r_type_func_args_type (anal->sdb_types, "aliases", 1);
	mu_assert_streq (argument, "FN *", "function typedef parameters acquire one explicit pointer");
	free (argument);
	argument = r_type_func_args_type (anal->sdb_types, "aliases", 2);
	mu_assert_streq (argument, "CB", "a callback pointer typedef does not acquire another pointer");
	free (argument);
	mu_assert_eq (r_anal_type_bitsize (anal, "FN"), 0, "function typedef is not globally coerced to a pointer object");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "func.CB.cc", NULL), "cdecl", "pointer qualification does not rewrite the current convention");
	RAnalBaseType *record = r_anal_get_base_type (anal, "Mixed");
	char *serialized = r_anal_base_type_to_kv (record);
	mu_assert_notnull (serialized, "serialize the current explicit-layer record");
	r_anal_remove_parsed_type (anal, "Mixed");
	r_anal_save_parsed_type (anal, serialized);
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Mixed.farptr", NULL), "int far *,4,0", "saved-analysis representation retains the far pointer");
	mu_assert_eq (r_anal_type_bitsize (anal, "Mixed"), 112, "current-shape record retains its extent after storage roundtrip");
	free (serialized);
	r_anal_base_type_free (record);
	free (error);
	r_anal_free (anal);
	anal = r_anal_new ();
	r_arch_config_use (anal->config, "arm");
	anal->config->bits = 16;
	r_anal_types_reload (anal, R2_PREFIX, NULL, NULL);
	mu_assert_eq (r_anal_type_bitsize (anal, "int"), 32, "x86-16 data model does not redefine ARM Thumb int");
	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_anal_x86_16_declaration_layout);
	mu_run_test (test_anal_get_base_type_struct);
	mu_run_test (test_anal_save_base_type_struct);
	mu_run_test (test_anal_base_type_struct_array_roundtrip);
	mu_run_test (test_anal_base_type_struct_member_needing_sanitization_roundtrip);
	mu_run_test (test_anal_base_type_enum_case_needing_sanitization_roundtrip);
	mu_run_test (test_anal_save_base_type_struct_redefine);
	mu_run_test (test_anal_base_type_struct_comma_type_roundtrip);
	mu_run_test (test_anal_base_type_union_comma_type_roundtrip);
	mu_run_test (test_anal_base_type_union_array_roundtrip);
	mu_run_test (test_anal_save_base_type_union_redefine);
	mu_run_test (test_anal_base_type_to_kv);
	mu_run_test (test_anal_cparse_multiline_fnptr);
	mu_run_test (test_anal_cparse_attribute_capacity);
	mu_run_test (test_anal_cparse_attribute_duplicates);
	mu_run_test (test_anal_cparse_nested_layout);
	mu_run_test (test_anal_cparse_callback_array_layout);
	mu_run_test (test_anal_cparse_lazy_alias_layout);
	mu_run_test (test_anal_cparse_definition_alias);
	mu_run_test (test_anal_cparse_prototype_metadata);
	mu_run_test (test_anal_tcc_prototype_metadata);
	mu_run_test (test_anal_cparse_grouped_names);
	mu_run_test (test_anal_cparse_visible_typedef_callbacks);
	mu_run_test (test_anal_cparse_forward_identity);
	mu_run_test (test_anal_cparse_forward_completion);
	mu_run_test (test_anal_cparse_forward_typedef);
	mu_run_test (test_anal_cparse_distinct_tag_and_typedef_names);
	mu_run_test (test_anal_cparse_tagged_member_does_not_resolve_typedef);
	mu_run_test (test_anal_type_format_tagged_identity);
	mu_run_test (test_anal_cparse_incomplete_member);
	mu_run_test (test_anal_get_base_type_union);
	mu_run_test (test_anal_save_base_type_union);
	mu_run_test (test_anal_get_base_type_enum);
	mu_run_test (test_anal_save_base_type_enum);
	mu_run_test (test_anal_get_base_type_typedef);
	mu_run_test (test_anal_type_bitsize_struct_cycle);
	mu_run_test (test_anal_type_bitsize_struct_recorded);
	mu_run_test (test_anal_type_bitsize_arrays);
	mu_run_test (test_anal_cparse_array_bounds);
	mu_run_test (test_anal_array_bound_target_model);
	mu_run_test (test_anal_cparse_invalid_bounds_and_builtins);
	mu_run_test (test_anal_save_base_type_typedef);
	mu_run_test (test_anal_get_base_type_atomic);
	mu_run_test (test_anal_save_base_type_atomic);
	mu_run_test (test_anal_get_base_type_not_found);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
