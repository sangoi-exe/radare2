#include <r_anal.h>
#include <r_bin.h>
#include <r_core.h>
#include "minunit.h"

#define MODE 2

// Global test context to prevent leaks on early returns
static RBin *bin = NULL;
static RIO *io = NULL;
static RAnal *anal = NULL;

static bool setup(void) {
	bin = r_bin_new ();
	io = r_io_new ();
	anal = r_anal_new ();
	if (!bin || !io || !anal) {
		r_bin_free (bin);
		r_io_free (io);
		r_anal_free (anal);
		return false;
	}
	anal->binb.demangle = r_bin_demangle;

	r_io_bind (io, &bin->iob);
	return true;
}

static bool teardown(void) {
	r_anal_free (anal);
	r_bin_free (bin);
	r_io_free (io);
	anal = NULL;
	bin = NULL;
	io = NULL;
	return true;
}

#define check_kv(k, v) \
	do { \
		value = sdb_const_get (sdb, k, NULL); \
		mu_assert_nullable_streq (value, v, "Wrong key - value pair"); \
	} while (0)

static bool test_parse_dwarf_types(void) {
	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, UT64_MAX, 0, 0);
	bool res = r_bin_open (bin, "bins/pe/vista-glass.exe", &opt);
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 32;
	mu_assert ("pe/vista-glass.exe binary could not be opened", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf);
	if (!abbrevs) {
		mu_assert ("Couldn't parse Abbreviations", false);
		return MU_ERR;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs);
	if (!info) {
		RVecDwarfAbbrevDecl_free (abbrevs);
		mu_assert ("Couldn't parse debug_info section", false);
		return MU_ERR;
	}

	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bf, 4);
	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	const char *value = NULL;
	Sdb *sdb = sdb_ns (anal->sdb_types, "tags", false);
	check_kv ("_cairo_status", "enum");
	check_kv ("enum._cairo_status.0x0", "CAIRO_STATUS_SUCCESS");
	check_kv ("enum._cairo_status.CAIRO_STATUS_SUCCESS", "0x0");
	check_kv ("enum._cairo_status.0x9", "CAIRO_STATUS_INVALID_PATH_DATA");
	check_kv ("enum._cairo_status.CAIRO_STATUS_INVALID_PATH_DATA", "0x9");
	check_kv ("enum._cairo_status.0x1f", "CAIRO_STATUS_INVALID_WEIGHT");
	check_kv ("enum._cairo_status.CAIRO_STATUS_INVALID_WEIGHT", "0x1f");
	check_kv ("enum._cairo_status.0x20", NULL);
	check_kv ("enum._cairo_status", "CAIRO_STATUS_SUCCESS,CAIRO_STATUS_NO_MEMORY" 
	",CAIRO_STATUS_INVALID_RESTORE,CAIRO_STATUS_INVALID_POP_GROUP,CAIRO_STATUS_NO_CURRENT_POINT"
	",CAIRO_STATUS_INVALID_MATRIX,CAIRO_STATUS_INVALID_STATUS,CAIRO_STATUS_NULL_POINTER,"
	"CAIRO_STATUS_INVALID_STRING,CAIRO_STATUS_INVALID_PATH_DATA,CAIRO_STATUS_READ_ERROR,"
	"CAIRO_STATUS_WRITE_ERROR,CAIRO_STATUS_SURFACE_FINISHED,CAIRO_STATUS_SURFACE_TYPE_MISMATCH,"
	"CAIRO_STATUS_PATTERN_TYPE_MISMATCH,CAIRO_STATUS_INVALID_CONTENT,CAIRO_STATUS_INVALID_FORMAT,"
	"CAIRO_STATUS_INVALID_VISUAL,CAIRO_STATUS_FILE_NOT_FOUND,CAIRO_STATUS_INVALID_DASH,"
	"CAIRO_STATUS_INVALID_DSC_COMMENT,CAIRO_STATUS_INVALID_INDEX,CAIRO_STATUS_CLIP_NOT_REPRESENTABLE,"
	"CAIRO_STATUS_TEMP_FILE_ERROR,CAIRO_STATUS_INVALID_STRIDE,"
	"CAIRO_STATUS_FONT_TYPE_MISMATCH,CAIRO_STATUS_USER_FONT_IMMUTABLE,CAIRO_STATUS_USER_FONT_ERROR,"
	"CAIRO_STATUS_NEGATIVE_COUNT,CAIRO_STATUS_INVALID_CLUSTERS,"
	"CAIRO_STATUS_INVALID_SLANT,CAIRO_STATUS_INVALID_WEIGHT");

	check_kv ("_MARGINS", "struct");
	// TODO evaluate member_location operations in DWARF to get offset and test it
	check_kv ("struct._MARGINS", "cxLeftWidth,cxRightWidth,cyTopHeight,cyBottomHeight");

	check_kv ("unaligned", "union");
	check_kv ("union.unaligned", "ptr,u2,u4,u8,s2,s4,s8");
	check_kv ("union.unaligned.u2", "short unsigned int,0,0");
	check_kv ("union.unaligned.s8", "long long int,0,0");
	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_loc (loc_table);
	RVecDwarfAbbrevDecl_free (abbrevs);
	mu_end;
}

static bool test_dwarf_function_parsing_cpp(void) {
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;

	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, UT64_MAX, 0, 0);
	bool res = r_bin_open (bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert ("elf/dwarf4_many_comp_units.elf binary could not be opened", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf);
	if (!abbrevs) {
		mu_assert ("Couldn't parse Abbreviations", false);
		return MU_ERR;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs);
	if (!info) {
		RVecDwarfAbbrevDecl_free (abbrevs);
		mu_assert ("Couldn't parse debug_info section", false);
		return MU_ERR;
	}
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bf, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	const char *value = NULL;
	check_kv ("Mammal", "fcn");
	check_kv ("fcn.Mammal.addr", "0x401300");
	check_kv ("fcn.Mammal.sig", "void Mammal(struct Mammal * this);");
	check_kv ("fcn.Dog::walk__.addr", "0x401380");
	check_kv ("fcn.Dog::walk__.sig", "int Dog::walk()(struct Dog * this);");
	check_kv ("fcn.Dog::walk__.name", "Dog::walk()");
	check_kv ("fcn.Mammal::walk__.args", "this");
	check_kv ("fcn.Mammal::walk__.arg.0", "this,b,-8,struct Mammal *");
	check_kv ("fcn.Mammal::walk__.vars", NULL);

	check_kv ("main", "fcn");
	check_kv ("fcn.main.addr", "0x401160");
	check_kv ("fcn.main.sig", "int main();");
	check_kv ("fcn.main.vars", "b,m,output");
	check_kv ("fcn.main.var.output", "b,-40,int");
	const char *typed_main = sdb_const_get (sdb, "fcn.main.typed_name", NULL);
	mu_assert_notnull ("Missing typed name for main", typed_main);
	sdb = anal->sdb_types;
	char *typed_main_kind = strdup (typed_main);
	check_kv (typed_main_kind, "func");
	free (typed_main_kind);
	RTypeFunctionPrototype prototype;
	mu_assert_true (r_type_func_get_prototype (sdb, typed_main, &prototype), "read the real C++ fixture main parameter-list knowledge");
	mu_assert_eq (prototype, R_TYPE_FUNC_PROTOTYPE_UNKNOWN, "main has no explicit prototyped attribute; language/count do not supply erased knowledge");
	char *typed_main_ret = r_str_newf ("func.%s.ret", typed_main);
	check_kv (typed_main_ret, "int");
	free (typed_main_ret);

	Sdb *dwarf_sdb2 = sdb_ns (anal->sdb, "dwarf", 0);
	const char *typed_walk = sdb_const_get (dwarf_sdb2, "fcn.Dog::walk__.typed_name", NULL);
	mu_assert_notnull ("Missing typed name for Dog::walk()", typed_walk);
	char *typed_walk_kind = strdup (typed_walk);
	check_kv (typed_walk_kind, "func");
	free (typed_walk_kind);
	char *typed_walk_ret = r_str_newf ("func.%s.ret", typed_walk);
	check_kv (typed_walk_ret, "int");
	free (typed_walk_ret);
	char *typed_walk_args = r_str_newf ("func.%s.args", typed_walk);
	check_kv (typed_walk_args, "1");
	free (typed_walk_args);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	mu_end;
}

static bool test_dwarf_function_parsing_go(void) {
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;

	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, UT64_MAX, 0, 0);
	bool res = r_bin_open (bin, "bins/elf/dwarf_go_tree", &opt);
	mu_assert ("bins/elf/dwarf_go_tree", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf);
	if (!abbrevs) {
		mu_assert ("Couldn't parse Abbreviations", false);
		return MU_ERR;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs);
	if (!info) {
		RVecDwarfAbbrevDecl_free (abbrevs);
		mu_assert ("Couldn't parse debug_info section", false);
		return MU_ERR;
	}
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bf, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	if (!sdb) {
		r_bin_dwarf_free_debug_info (info);
		RVecDwarfAbbrevDecl_free (abbrevs);
		r_bin_dwarf_free_loc (loc_table);
		mu_assert ("No dwarf function information in db", false);
		return MU_ERR;
	}
	const char *value = NULL;

	check_kv ("main_main", "fcn");
	check_kv ("fcn.main_main.name", "main.main");
	check_kv ("fcn.main_main.addr", "0x491980");

	check_kv ("main_tree_iterInorder", "fcn");
	check_kv ("fcn.main_tree_iterInorder.name", "main.tree.iterInorder");
	check_kv ("fcn.main_tree_iterInorder.addr", "0x491d90");
	check_kv ("fcn.main_tree_iterInorder.sig", "void main.tree.iterInorder(main.tree t,func(int) visit);");

	/* We do not parse variable information from .debug_frame that is this Go binary using, so
	don't check variable information and add it in the future */

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	mu_end;
}

static bool test_dwarf_function_parsing_rust(void) {
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;

	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, UT64_MAX, 0, 0);
	bool res = r_bin_open (bin, "bins/elf/dwarf_rust_bubble", &opt);
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	free (anal->config->cpu);
	mu_assert ("bins/elf/dwarf_rust_bubble", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf);
	if (!abbrevs) {
		mu_assert ("Couldn't parse Abbreviations", false);
		return MU_ERR;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs);
	if (!info) {
		RVecDwarfAbbrevDecl_free (abbrevs);
		mu_assert ("Couldn't parse debug_info section", false);
		return MU_ERR;
	}
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bf, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	const char *value = NULL;

	check_kv ("fcn.main.addr", "0x5750");
	check_kv ("fcn.main.name", "main");
	check_kv ("fcn.main.var.numbers", "s,128,i32[10]");
	check_kv ("fcn.main.var.strings", "s,312,&str[5]");
	// check_kv ("fcn.main.vars", "numbers,arg0,arg0,strings,arg0,arg0"); Fix these collision by unique renaming in future
	check_kv ("fcn.lang_start_internal.sig", "isize lang_start_internal(&Fn<()> main,isize argc,u8 ** argv);");

	check_kv ("bubble_sort__str_", "fcn");
	check_kv ("bubble_sort_i32_", "fcn");
	check_kv ("fcn.bubble_sort_i32_.args", "values");
	check_kv ("fcn.bubble_sort_i32_.vars", "n,swapped,iter,__next,val,i");
	check_kv ("fcn.bubble_sort_i32_.var.iter", "s,112,Range<usize>");
	check_kv ("fcn.bubble_sort_i32_.var.i", "s,176,usize");
	check_kv ("fcn.bubble_sort_i32_.name", "bubble_sort<i32>");
	check_kv ("fcn.bubble_sort_i32_.addr", "0x5270");
	const char *typed_bubble = sdb_const_get (sdb, "fcn.bubble_sort_i32_.typed_name", NULL);
	mu_assert_notnull ("Missing typed name for bubble_sort_i32_", typed_bubble);
	sdb = anal->sdb_types;
	char *typed_bubble_kind = strdup (typed_bubble);
	check_kv (typed_bubble_kind, "func");
	free (typed_bubble_kind);
	char *typed_bubble_ret = r_str_newf ("func.%s.ret", typed_bubble);
	check_kv (typed_bubble_ret, "void");
	free (typed_bubble_ret);
	char *typed_bubble_args = r_str_newf ("func.%s.args", typed_bubble);
	check_kv (typed_bubble_args, "1");
	free (typed_bubble_args);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	mu_end;
}

#define run_test_with_setup(test_func) \
	do { \
		if (!setup ()) { \
			fprintf (stderr, "Setup failed for " #test_func "\n"); \
			return 1; \
		} \
		mu_run_test (test_func); \
		teardown (); \
	} while (0)

static void prototype_test_die(RBinDwarfCompUnit *unit, ut64 offset, ut16 tag, const RBinDwarfAttrValue *attrs, size_t count) {
	RBinDwarfDie die = { .offset = offset, .abbrev_code = tag? 1: 0, .tag = tag, .attr_idx = RVecDwarfAttrValue_length (unit->attrs), .attr_count = count };
	size_t i;
	for (i = 0; i < count; i++) {
		RVecDwarfAttrValue_push_back (unit->attrs, &attrs[i]);
	}
	RVecDwarfDie_push_back (unit->dies, &die);
}

static bool test_dwarf_prototype_attributes(void) {
	const struct {
		int local;
		ut16 reference;
		ut8 inherited;
		bool chain;
		RTypeFunctionPrototype expected;
	} cases[] = {
		{ -1, 0, 0, false, R_TYPE_FUNC_PROTOTYPE_UNKNOWN },
		{ 0, 0, 0, false, R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED },
		{ 1, 0, 0, false, R_TYPE_FUNC_PROTOTYPE_FIXED },
		{ -1, DW_AT_specification, 1, false, R_TYPE_FUNC_PROTOTYPE_FIXED },
		{ -1, DW_AT_abstract_origin, 0, false, R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED },
		{ 0, DW_AT_specification, 1, false, R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED },
		{ -1, DW_AT_specification, 1, true, R_TYPE_FUNC_PROTOTYPE_FIXED }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RAnal *scenario = r_anal_new ();
		RBinDwarfDebugInfo *info = R_NEW0 (RBinDwarfDebugInfo);
		info->comp_units = RVecDwarfCompUnit_new ();
		RBinDwarfCompUnit unit = { .dies = RVecDwarfDie_new (), .attrs = RVecDwarfAttrValue_new () };
		RBinDwarfAttrValue language[] = { { .attr_name = DW_AT_language, .kind = DW_AT_KIND_CONSTANT, .uconstant = DW_LANG_C_plus_plus_14 } };
		prototype_test_die (&unit, 1, DW_TAG_compile_unit, language, R_ARRAY_SIZE (language));
		RBinDwarfAttrValue source[] = {
			{ .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "dwarf_case" },
			{ .attr_name = DW_AT_declaration, .kind = DW_AT_KIND_FLAG, .flag = 1 },
			{ .attr_name = DW_AT_prototyped, .kind = DW_AT_KIND_FLAG, .flag = cases[i].inherited }
		};
		prototype_test_die (&unit, 10, DW_TAG_subprogram, source, R_ARRAY_SIZE (source));
		RBinDwarfAttrValue middle[] = {
			{ .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "dwarf_case" },
			{ .attr_name = DW_AT_declaration, .kind = DW_AT_KIND_FLAG, .flag = 1 },
			{ .attr_name = DW_AT_abstract_origin, .kind = DW_AT_KIND_REFERENCE, .reference = 10 }
		};
		prototype_test_die (&unit, 20, DW_TAG_subprogram, middle, R_ARRAY_SIZE (middle));
		RBinDwarfAttrValue actual[5] = {
			{ .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "dwarf_case" },
			{ .attr_name = DW_AT_low_pc, .kind = DW_AT_KIND_ADDRESS, .address = 0x1000 },
			{ .attr_name = DW_AT_high_pc, .kind = DW_AT_KIND_ADDRESS, .address = 0x1001 }
		};
		size_t count = 3;
		if (cases[i].local >= 0) {
			actual[count++] = (RBinDwarfAttrValue){ .attr_name = DW_AT_prototyped, .kind = DW_AT_KIND_FLAG, .flag = cases[i].local };
		}
		if (cases[i].reference) {
			actual[count++] = (RBinDwarfAttrValue){ .attr_name = cases[i].reference, .kind = DW_AT_KIND_REFERENCE, .reference = cases[i].chain? 20: 10 };
		}
		prototype_test_die (&unit, 30, DW_TAG_subprogram, actual, count);
		RVecDwarfCompUnit_push_back (info->comp_units, &unit);
		RAnalDwarfContext ctx = { .info = info };
		r_anal_dwarf_process_info (scenario, &ctx);
		RTypeFunctionPrototype prototype = R_TYPE_FUNC_PROTOTYPE_UNKNOWN;
		mu_assert_true (r_type_func_get_prototype (scenario->sdb_types, "dwarf_case", &prototype), "read actual-DIE importer specificity");
		mu_assert_eq (prototype, cases[i].expected, "direct flags override inherited flags; absence remains unknown even in a C++ unit");
		mu_assert_nullable_streq (sdb_const_get (scenario->sdb_types, "func.dwarf_case.prototype", NULL), r_type_func_prototype_name (cases[i].expected), "DWARF emits explicit known or unavailable knowledge");
		r_anal_dwarf_process_info (scenario, &ctx);
		mu_assert_nullable_streq (sdb_const_get (scenario->sdb_types, "fcnlink.00001000", NULL), "dwarf_case", "matching specificity preserves importer identity on repeat");
		if (!i) {
			r_type_func_set_prototype (scenario->sdb_types, "dwarf_case", R_TYPE_FUNC_PROTOTYPE_FIXED);
			r_anal_dwarf_process_info (scenario, &ctx);
			mu_assert_nullable_streq (sdb_const_get (scenario->sdb_types, "func.dwarf_case.prototype", NULL), "fixed", "DWARF does not overwrite conflicting manual parameter-list knowledge");
			mu_assert_nullable_streq (sdb_const_get (scenario->sdb_types, "func.dwarf_case_1000.prototype", NULL), "unknown", "conflicting source knowledge gets the existing distinct typed identity");
			mu_assert_nullable_streq (sdb_const_get (scenario->sdb_types, "fcnlink.00001000", NULL), "dwarf_case_1000", "address lookup selects the matching source fact");
		}
		r_bin_dwarf_free_debug_info (info);
		r_anal_free (scenario);
	}
	mu_end;
}

static bool test_dwarf_incomplete_formals(void) {
	const struct {
		bool missing;
		bool known;
		bool ranges;
		bool prototyped;
	} cases[] = {
		{ true, false, false, true },
		{ true, true, false, true },
		{ false, true, true, true },
		{ false, false, false, true },
		{ false, false, false, false }
	};
	const ut64 languages[] = { DW_LANG_C_plus_plus_14, DW_LANG_Rust };
	size_t language, i;
	for (language = 0; language < R_ARRAY_SIZE (languages); language++) {
		for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
			RAnal *scenario = r_anal_new ();
			r_str_ncpy (scenario->config->arch, "x86", sizeof (scenario->config->arch));
			scenario->config->bits = 64;
			RBinDwarfDebugInfo *info = R_NEW0 (RBinDwarfDebugInfo);
			info->comp_units = RVecDwarfCompUnit_new ();
			RBinDwarfCompUnit unit = { .dies = RVecDwarfDie_new (), .attrs = RVecDwarfAttrValue_new () };
			RBinDwarfAttrValue language_attr[] = { { .attr_name = DW_AT_language, .kind = DW_AT_KIND_CONSTANT, .uconstant = languages[language] } };
			prototype_test_die (&unit, 1, DW_TAG_compile_unit, language_attr, R_ARRAY_SIZE (language_attr));
			RBinDwarfAttrValue base[] = {
				{ .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "int" },
				{ .attr_name = DW_AT_byte_size, .kind = DW_AT_KIND_CONSTANT, .uconstant = 4 },
				{ .attr_name = DW_AT_encoding, .kind = DW_AT_KIND_CONSTANT, .uconstant = DW_ATE_signed }
			};
			prototype_test_die (&unit, 10, DW_TAG_base_type, base, R_ARRAY_SIZE (base));
			RBinDwarfAttrValue function[] = {
				{ .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "decoded_case" },
				{ .attr_name = DW_AT_low_pc, .kind = DW_AT_KIND_ADDRESS, .address = 0x1000 },
				{ .attr_name = DW_AT_high_pc, .kind = DW_AT_KIND_ADDRESS, .address = 0x1010 },
				{ .attr_name = DW_AT_type, .kind = DW_AT_KIND_REFERENCE, .reference = 10 },
				{ .attr_name = DW_AT_prototyped, .kind = DW_AT_KIND_FLAG, .flag = cases[i].prototyped },
				{ .attr_name = DW_AT_ranges, .kind = DW_AT_KIND_RANGELISTPTR, .uconstant = 0 }
			};
			prototype_test_die (&unit, 20, DW_TAG_subprogram, function, cases[i].ranges? 6: 5);
			RVecDwarfDie_at (unit.dies, RVecDwarfDie_length (unit.dies) - 1)->has_children = true;
			if (cases[i].missing) {
				RBinDwarfAttrValue missing[] = { { .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "lost" } };
				prototype_test_die (&unit, 30, DW_TAG_formal_parameter, missing, cases[i].known? 1: 0);
			}
			const ut8 arg_location[] = { DW_OP_reg5 };
			if (cases[i].known) {
				RBinDwarfAttrValue known[] = {
					{ .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "known" },
					{ .attr_name = DW_AT_type, .kind = DW_AT_KIND_REFERENCE, .reference = 10 },
					{ .attr_name = DW_AT_location, .kind = DW_AT_KIND_BLOCK, .block = { .length = sizeof (arg_location), .data = arg_location } }
				};
				prototype_test_die (&unit, 31, DW_TAG_formal_parameter, known, R_ARRAY_SIZE (known));
			}
			const ut8 local_location[] = { DW_OP_addr, 0x00, 0x20, 0, 0, 0, 0, 0, 0 };
			RBinDwarfAttrValue local[] = {
				{ .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "local" },
				{ .attr_name = DW_AT_type, .kind = DW_AT_KIND_REFERENCE, .reference = 10 },
				{ .attr_name = DW_AT_location, .kind = DW_AT_KIND_BLOCK, .block = { .length = sizeof (local_location), .data = local_location } }
			};
			prototype_test_die (&unit, 32, DW_TAG_variable, local, R_ARRAY_SIZE (local));
			prototype_test_die (&unit, 40, 0, NULL, 0);
			RVecDwarfCompUnit_push_back (info->comp_units, &unit);
			RAnalDwarfContext ctx = { .info = info };
			r_anal_dwarf_process_info (scenario, &ctx);
			int argc = 99;
			mu_assert_eq (r_type_func_args_count (scenario->sdb_types, "decoded_case", &argc), !cases[i].missing, "only complete formal lists publish a formal count through either producer");
			if (cases[i].missing) {
				mu_assert_eq (argc, 99, "missing formal types cannot become zero or a shortened count");
			} else {
				mu_assert_eq (argc, cases[i].known? 1: 0, "address ranges do not erase independently complete formals");
			}
			mu_assert_nullable_streq (sdb_const_get (scenario->sdb_types, "func.decoded_case.prototype", NULL), cases[i].prototyped? "fixed": "unspecified", "formal completeness does not replace source specificity");
			mu_assert_null (sdb_const_get (scenario->sdb_types, "func.decoded_case.cc", NULL), "neither DWARF producer invents a convention without source evidence");
			Sdb *dwarf = sdb_ns (scenario->sdb, "dwarf", 0);
			mu_assert_notnull (dwarf, "actual decoded DIEs reached the importer");
			mu_assert_nullable_streq (sdb_const_get (dwarf, "fcn.decoded_case.var.local", NULL), "g,8192,int", "independent local type and location facts survive incomplete formals");
			if (cases[i].known) {
				mu_assert_nullable_streq (sdb_const_getf (scenario->sdb_types, NULL, "func.decoded_case.arg.%d", cases[i].missing? 1: 0), "int,known", "available formals retain their actual DIE positions without asserting a full count");
				mu_assert_nullable_streq (sdb_const_get (dwarf, "fcn.decoded_case.arg.0", NULL), "known,r,rdi,int", "a formal's independently supplied location is retained");
			}
			if (cases[i].missing) {
				mu_assert_nullable_streq (sdb_const_get (dwarf, "fcn.decoded_case.csig", NULL), "int decoded_case();", "the C projection cannot publish a fixed-empty or shortened prototype");
				mu_assert_null (sdb_const_get (scenario->sdb_types, "fcnlink.00001000", NULL), "an incomplete formal list cannot acquire a complete address prototype");
				RAnalFunction *named = r_anal_create_function (scenario, "decoded_case", 0x3000, 0, NULL);
				RAnalFunctionSignature *snapshot = r_anal_function_get_signature (named);
				mu_assert_notnull (snapshot, "the name lookup still exposes the independent return and specificity facts");
				mu_assert_eq (snapshot->prototype, R_TYPE_FUNC_PROTOTYPE_FIXED, "name lookup preserves fixed knowledge without claiming its list is available");
				ut64 epoch = r_anal_types_dirty_epoch (scenario);
				mu_assert_false (r_anal_function_set_signature (scenario, named, snapshot), "an unchanged incomplete DWARF snapshot cannot harden on writeback");
				mu_assert_eq (r_anal_types_dirty_epoch (scenario), epoch, "incomplete snapshot refusal leaves imported facts unchanged");
				r_anal_function_signature_free (snapshot);
			} else if (cases[i].ranges) {
				mu_assert_null (sdb_const_get (scenario->sdb_types, "fcnlink.00001000", NULL), "range qualification is independent of the complete name-based signature");
			}
			r_anal_dwarf_process_info (scenario, &ctx);
			mu_assert_nullable_streq (sdb_const_get (dwarf, "fcn.decoded_case.typed_name", NULL), "decoded_case", "the same partial or complete facts remain idempotent");
			r_bin_dwarf_free_debug_info (info);
			r_anal_free (scenario);
		}
	}
	mu_end;
}

static bool test_dwarf_linked_functions_isolate_core_edit(void) {
	RCore *core = r_core_new ();
	RBinDwarfDebugInfo *info = R_NEW0 (RBinDwarfDebugInfo);
	info->comp_units = RVecDwarfCompUnit_new ();
	RBinDwarfCompUnit unit = { .dies = RVecDwarfDie_new (), .attrs = RVecDwarfAttrValue_new () };
	RBinDwarfAttrValue language[] = { { .attr_name = DW_AT_language, .kind = DW_AT_KIND_CONSTANT, .uconstant = DW_LANG_C_plus_plus_14 } };
	prototype_test_die (&unit, 1, DW_TAG_compile_unit, language, R_ARRAY_SIZE (language));
	RBinDwarfAttrValue function[] = {
		{ .attr_name = DW_AT_name, .kind = DW_AT_KIND_STRING, .string.content = "decoded_shared" },
		{ .attr_name = DW_AT_low_pc, .kind = DW_AT_KIND_ADDRESS, .address = 0x1000 },
		{ .attr_name = DW_AT_high_pc, .kind = DW_AT_KIND_ADDRESS, .address = 0x1001 },
		{ .attr_name = DW_AT_prototyped, .kind = DW_AT_KIND_FLAG, .flag = 1 }
	};
	prototype_test_die (&unit, 20, DW_TAG_subprogram, function, R_ARRAY_SIZE (function));
	function[1].address = 0x2000;
	function[2].address = 0x2001;
	prototype_test_die (&unit, 30, DW_TAG_subprogram, function, R_ARRAY_SIZE (function));
	RVecDwarfCompUnit_push_back (info->comp_units, &unit);
	RAnalDwarfContext ctx = { .info = info };
	r_anal_dwarf_process_info (core->anal, &ctx);
	mu_assert_nullable_streq (sdb_const_get (core->anal->sdb_types, "fcnlink.00001000", NULL), "decoded_shared", "first actual decoded function selects the shared type");
	mu_assert_nullable_streq (sdb_const_get (core->anal->sdb_types, "fcnlink.00002000", NULL), "decoded_shared", "second actual decoded function selects that same type");
	RAnalFunction *edited = r_anal_create_function (core->anal, "decoded_shared", 0x1000, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalFunction *other = r_anal_create_function (core->anal, "dbg.decoded_shared", 0x2000, R_ANAL_FCN_TYPE_FCN, NULL);
	RAnalBlock *block = r_anal_create_block (core->anal, 0x1000, 1);
	r_anal_function_add_block (edited, block);
	r_unref (block);
	RAnalFunctionSignature *before = r_anal_function_get_signature (other);
	mu_assert_notnull (before, "read the automatically linked peer before the edit");
	mu_assert_true (r_core_anal_function_set_signature (core, 0x1000, "int edited(int (*callback)(char))", NULL), "edit only one automatically linked function through the Core facade");
	mu_assert_streq (edited->name, "edited", "the local edit renames only its selected function");
	mu_assert_streq (r_type_func_ret (core->anal->sdb_types, "decoded_shared"), "void", "the imported shared source type is not rewritten");
	mu_assert_nullable_streq (sdb_const_get (core->anal->sdb_types, "fcnlink.00001000", NULL), "decoded_shared", "signature rename does not migrate the original automatic binding");
	r_anal_dwarf_process_info (core->anal, &ctx);
	RAnalFunctionSignature *after = r_anal_function_get_signature (other);
	mu_assert_notnull (after, "read the automatically linked peer after import refresh");
	mu_assert_streq (before->signature, after->signature, "the peer's shared signature is unchanged by the local edit and refresh");
	RAnalFunctionSignature *actual = r_anal_function_get_signature (edited);
	mu_assert_notnull (actual, "the selected function keeps its own address-linked signature");
	mu_assert_streq (actual->ret_type, "int", "automatic DWARF binding cannot override the isolated edit");
	mu_assert_eq (r_list_length (actual->params), 1, "callback parameters retain the outer function's arity");
	RAnalFunctionParam *param = r_list_first (actual->params);
	mu_assert_streq (param->type, "int (*)(char)", "the admitted nested function type remains inline after isolation");
	mu_assert_streq (param->name, "callback", "the callback keeps its declared name");
	r_anal_function_signature_free (before);
	r_anal_function_signature_free (after);
	r_anal_function_signature_free (actual);
	r_bin_dwarf_free_debug_info (info);
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_dwarf_prototype_attributes);
	mu_run_test (test_dwarf_incomplete_formals);
	mu_run_test (test_dwarf_linked_functions_isolate_core_edit);
	run_test_with_setup (test_parse_dwarf_types);
	run_test_with_setup (test_dwarf_function_parsing_cpp);
	run_test_with_setup (test_dwarf_function_parsing_rust);
	run_test_with_setup (test_dwarf_function_parsing_go);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
