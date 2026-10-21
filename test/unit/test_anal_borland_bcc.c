#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_bcc_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland

static RCore *bcc_original(const char *variable) {
	const char *path = getenv (variable);
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

static bool bcc_original_equal(BorlandProfileContext *ctx, const char *variable) {
	size_t size;
	char *expected = r_file_slurp (getenv (variable), &size);
	mu_assert_notnull (expected, "read-only named original");
	mu_assert_eq (r_buf_size (ctx->file->buf), size, "complete original file size");
	ut8 *original = malloc (size);
	mu_assert_notnull (original, "complete original comparison buffer");
	mu_assert_eq (r_buf_read_at (ctx->file->buf, 0, original, size), size, "entire native original buffer read");
	mu_assert_eq (memcmp (original, expected, size), 0, "native original literally equals the named source file");
	free (original);
	free (expected);
	return true;
}

static bool bcc31_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "ne", 672150, "87c6dfbad817eeca31c069043f08063f7122663e51932ad089e6d1c563450d3b");
}

static bool bcc45_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "ne", 768026, "6e58346640ca94e32b547c4df872d06905e58c5ef6d473d0b6a6a3903d640a46");
}

#include "borland_bcc_expected.h"

static bool bcc_check_functions(BorlandProfileContext *ctx, const BccExpectedFunction *expected, size_t count) {
	size_t i;
	for (i = 0; i < count; i++) {
		const BccExpectedFunction *fact = &expected[i];
		ut64 address = profile_mapped (ctx, fact->start, fact->end - fact->start, true);
		RAnalFunction *fcn = r_anal_get_function_at (ctx->anal, address);
		mu_assert_notnull (fcn, fact->name);
		mu_assert_streq (fcn->name, fact->name, "source function name");
		mu_assert_eq (r_anal_function_realsize (fcn), fact->end - fact->start, "complete source body");
		mu_assert_eq (r_anal_function_max_addr (fcn), address + fact->end - fact->start, "adjacent tables excluded");
		mu_assert_eq (fcn->meta.stack_pop, fact->purge, "source own cleanup");
		int instructions = 0;
		ut64 cursor = address;
		while (cursor < address + fact->end - fact->start) {
			RAnalBlock *block = r_anal_get_block_at (ctx->anal, cursor);
			mu_assert_notnull (block, "complete native instruction/block ownership");
			mu_assert_true (r_list_contains (fcn->bbs, block), "block belongs to this source function");
			instructions += block->ninstr;
			cursor += block->size;
		}
		mu_assert_eq (cursor, address + fact->end - fact->start, "exact terminal-inclusive body coverage");
		if (fact->instructions) {
			mu_assert_eq (instructions, fact->instructions, "owner-validated native instruction count");
		}
	}
	return true;
}

static int bcc_ref(RAnal *anal, ut64 source, ut64 target) {
	RVecAnalRef *refs = r_anal_refs_get (anal, source);
	int type = 0;
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			if (ref->addr == target) {
				type = R_ANAL_REF_TYPE_MASK (ref->type);
			}
		}
	}
	RVecAnalRef_free (refs);
	return type;
}

static bool bcc_check_data(BorlandProfileContext *ctx, ut64 physical, int size, const char *type, const char *name) {
	ut64 address = profile_mapped (ctx, physical, size, false);
	char key[48];
	snprintf (key, sizeof (key), "link.%08"PFMT64x, address);
	const char *link = sdb_const_get (ctx->anal->sdb_types, key, NULL);
	mu_assert_notnull (link, "source data has a native type link");
	mu_assert_streq (link, type, "source data type and array count");
	mu_assert_eq (r_type_get_bitsize (ctx->anal->sdb_types, type), size * 8, "exact data envelope");
	RList *blocks = r_anal_get_blocks_intersect (ctx->anal, address, size);
	mu_assert_true (r_list_empty (blocks), "source data must remain outside instruction bodies");
	r_list_free (blocks);
	if (name) {
		RFlagItem *flag = r_flag_get (ctx->anal->flb.f, name);
		mu_assert_notnull (flag, "dependent data label");
		mu_assert_eq (flag->addr, address, "label uses native FILE projection");
	}
	return true;
}

static bool bcc_check_data_facts(BorlandProfileContext *ctx, const BccExpectedData *facts, size_t count) {
	size_t i;
	for (i = 0; i < count; i++) {
		mu_assert_true (bcc_check_data (ctx, facts[i].physical, facts[i].size, facts[i].type, NULL), facts[i].type);
	}
	return true;
}

static bool bcc_check_refs(BorlandProfileContext *ctx, const BccExpectedReference *facts, size_t count) {
	size_t i;
	for (i = 0; i < count; i++) {
		ut64 source = profile_mapped (ctx, facts[i].source, 1, false);
		ut64 target = profile_mapped (ctx, facts[i].target, 1, false);
		if (bcc_ref (ctx->anal, source, target) != R_ANAL_REF_TYPE_DATA) {
			eprintf ("Missing source DATA relationship FILE 0x%"PFMT64x" -> 0x%"PFMT64x"\n", facts[i].source, facts[i].target);
		}
		mu_assert_eq (bcc_ref (ctx->anal, source, target), R_ANAL_REF_TYPE_DATA, "every source-established DATA relation");
	}
	return true;
}

static bool bcc_check_text(BorlandProfileContext *ctx, const BccExpectedText *facts, size_t count, bool labels) {
	size_t i;
	for (i = 0; i < count; i++) {
		ut64 address = profile_mapped (ctx, facts[i].physical, 1, false);
		if (labels) {
			RFlagItem *flag = r_flag_get (ctx->anal->flb.f, facts[i].text);
			mu_assert_notnull (flag, facts[i].text);
			mu_assert_eq (flag->addr, address, "source label uses native mapping");
		} else {
			const char *comment = r_meta_get_string (ctx->anal, R_META_TYPE_COMMENT, address);
			mu_assert_notnull (comment, facts[i].text);
			mu_assert_notnull (strstr (comment, facts[i].text), "source qualification and uncertainty retained verbatim");
		}
	}
	return true;
}

static bool bcc_check_types(RAnal *anal, const BccExpectedRecord *records, size_t record_count, const BccExpectedEnum *enums, size_t enum_count) {
	size_t i;
	for (i = 0; i < record_count; i++) {
		const BccExpectedRecord *fact = &records[i];
		RAnalBaseType *type = r_anal_get_base_type (anal, fact->name, R_TYPE_NAMESPACE_ORDINARY);
		mu_assert_notnull (type, fact->name);
		mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_STRUCT, "native named partial record");
		mu_assert_eq (type->size, fact->size * 8, "source partial envelope");
		mu_assert_eq (RVecAnalTypeMember_length (&type->struct_data.members), fact->count, "unknown bytes have no invented fields");
		int j;
		for (j = 0; j < fact->count; j++) {
			RAnalTypeMember *member = RVecAnalTypeMember_at (&type->struct_data.members, j);
			mu_assert_streq (member->name, fact->members[j].name, "source field role");
			mu_assert_streq (member->type, fact->members[j].type, "source field domain");
			mu_assert_eq (member->offset, fact->members[j].offset, "source field offset");
			mu_assert_eq (member->count, 0, "scalar field, not speculative extent");
			mu_assert_eq (member->bitsize, 0, "not an invented bitfield");
		}
		r_anal_base_type_free (type);
	}
	for (i = 0; i < enum_count; i++) {
		const BccExpectedEnum *fact = &enums[i];
		RAnalBaseType *type = r_anal_get_base_type (anal, fact->name, R_TYPE_NAMESPACE_ORDINARY);
		mu_assert_notnull (type, fact->name);
		mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_ENUM, "distinct native enum domain");
		mu_assert_eq (type->size, 16, "source WORD domain");
		mu_assert_eq (RVecAnalEnumCase_length (&type->enum_data.cases), fact->count, "only source-established enum values");
		int j;
		for (j = 0; j < fact->count; j++) {
			RAnalEnumCase *entry = RVecAnalEnumCase_at (&type->enum_data.cases, j);
			mu_assert_streq (entry->name, fact->cases[j].name, "enum value role");
			mu_assert_eq (entry->val, fact->cases[j].value, "enum numeric value");
		}
		r_anal_base_type_free (type);
	}
	return true;
}

static bool bcc_check_callback_metadata(BorlandProfileContext *ctx, const ut64 *tables, RIntervalNode **before) {
	int family, i;
	for (family = 0; family < 2; family++) {
		for (i = 0; i < 26; i++) {
			ut64 address = profile_mapped (ctx, tables[family] + 4 * i, 4, false);
			RIntervalNode *node = r_meta_get_in (ctx->anal, address, R_META_TYPE_DATA);
			mu_assert_notnull (node, "actual native loader DATA4 cell");
			mu_assert_eq (node->start, address, "cell start retained");
			mu_assert_eq (node->end, address + 3, "array did not resize native DATA4 cell");
			if (before[family * 26 + i]) {
				mu_assert_ptreq (node, before[family * 26 + i], "native cell node identity retained");
			} else {
				before[family * 26 + i] = node;
			}
		}
	}
	return true;
}

static bool test_bcc31_original(void) {
	if (!getenv ("R2_TEST_BCC31")) {
		eprintf ("BCC31 original proof not run: set R2_TEST_BCC31 to the qualified read-only original\n");
		mu_end;
	}
	RCore *core = bcc_original ("R2_TEST_BCC31");
	mu_assert_notnull (core, "native BCC31 load");
	BorlandProfileContext ctx;
	mu_assert_true (bcc31_context (core, &ctx), "exact original identity");
	mu_assert_true (bcc_original_equal (&ctx, "R2_TEST_BCC31"), "original byte equality");
	const ut64 tables[] = { 0x19574, 0x1965a };
	RIntervalNode *cells[52] = {0};
	mu_assert_true (bcc_check_callback_metadata (&ctx, tables, cells), "native callback metadata before apply");
	RIntervalNode *opcode_string = r_meta_get_in (core->anal, profile_mapped (&ctx, 0x194a2, 1, false), R_META_TYPE_STRING);
	RIntervalNode *inverse_string = r_meta_get_in (core->anal, profile_mapped (&ctx, 0x19560, 1, false), R_META_TYPE_STRING);
	mu_assert_notnull (opcode_string, "actual opcode-overlapping STRING");
	mu_assert_notnull (inverse_string, "actual inverse-overlapping STRING");
	ut64 opcode_start = opcode_string->start, opcode_end = opcode_string->end;
	ut64 inverse_start = inverse_string->start, inverse_end = inverse_string->end;
	RAnalMetaItem *opcode_item = opcode_string->data, *inverse_item = inverse_string->data;
	char *opcode_text = strdup (opcode_item->str), *inverse_text = strdup (inverse_item->str);
	mu_assert_eq (borland_bcc31_profile (core->anal), 28, "all BCC31 source function facts");
	mu_assert_true (bcc_check_functions (&ctx, expected_bcc31, R_ARRAY_SIZE (expected_bcc31)), "all complete BCC31 bodies");
	mu_assert_true (bcc_check_data_facts (&ctx, expected_bcc31_data, R_ARRAY_SIZE (expected_bcc31_data)), "all source data views");
	mu_assert_true (bcc_check_refs (&ctx, expected_bcc31_refs, R_ARRAY_SIZE (expected_bcc31_refs)), "all source DATA relations");
	mu_assert_true (bcc_check_text (&ctx, expected_bcc31_labels, R_ARRAY_SIZE (expected_bcc31_labels), true), "all source labels");
	mu_assert_true (bcc_check_text (&ctx, expected_bcc31_comments, R_ARRAY_SIZE (expected_bcc31_comments), false), "all source comments");
	mu_assert_true (bcc_check_types (core->anal, expected_bcc31_records, R_ARRAY_SIZE (expected_bcc31_records), expected_bcc31_enums, R_ARRAY_SIZE (expected_bcc31_enums)), "all source layouts and distinct enum domains");
	mu_assert_true (bcc_check_callback_metadata (&ctx, tables, cells), "array view preserves all 52 actual DATA4 cells");
	mu_assert_true (bcc_check_data (&ctx, 0x19574, 104, "bcc31_FarStorage16 [26]", "bcc31_object_source_callbacks26"), "object callbacks");
	mu_assert_true (bcc_check_data (&ctx, 0x1965a, 104, "bcc31_FarStorage16 [26]", "bcc31_asm_source_callbacks26"), "asm callbacks");
	mu_assert_true (bcc_check_data (&ctx, 0x1c736, 104, "bcc31_FarStorage16 [26]", "bcc31_mutable_callback_workspace26"), "mutable workspace is storage only");
	const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, profile_mapped (&ctx, 0x7eff2, 1, true));
	mu_assert_notnull (comment, "parent semantic qualification");
	mu_assert_notnull (strstr (comment, "PARTIAL semantic coverage"), "byte completeness is not complete semantics");
	char *before = strdup (comment);
	int flags = r_flag_count (core->flags, NULL);
	ut64 type_epoch = r_anal_types_dirty_epoch (core->anal);
	mu_assert_eq (borland_bcc31_profile (core->anal), 28, "equivalent rerun");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), type_epoch, "equivalent rerun creates no duplicate types or links");
	mu_assert_true (bcc_check_callback_metadata (&ctx, tables, cells), "rerun retains native callback metadata");
	mu_assert_true (bcc_check_data_facts (&ctx, expected_bcc31_data, R_ARRAY_SIZE (expected_bcc31_data)), "rerun retains all source data");
	mu_assert_true (bcc_check_refs (&ctx, expected_bcc31_refs, R_ARRAY_SIZE (expected_bcc31_refs)), "rerun retains every source DATA relation");
	mu_assert_ptreq (r_meta_get_in (core->anal, profile_mapped (&ctx, 0x194a2, 1, false), R_META_TYPE_STRING), opcode_string, "opcode STRING node retained");
	mu_assert_ptreq (r_meta_get_in (core->anal, profile_mapped (&ctx, 0x19560, 1, false), R_META_TYPE_STRING), inverse_string, "inverse STRING node retained");
	mu_assert_ptreq (opcode_string->data, opcode_item, "opcode STRING item retained");
	mu_assert_ptreq (inverse_string->data, inverse_item, "inverse STRING item retained");
	mu_assert_eq (opcode_string->start, opcode_start, "opcode STRING prefix retained");
	mu_assert_eq (opcode_string->end, opcode_end, "opcode STRING tail retained");
	mu_assert_eq (inverse_string->start, inverse_start, "inverse STRING start retained");
	mu_assert_eq (inverse_string->end, inverse_end, "inverse STRING tail retained");
	mu_assert_streq (opcode_item->str, opcode_text, "opcode STRING contents retained");
	mu_assert_streq (inverse_item->str, inverse_text, "inverse STRING contents retained");
	free (opcode_text);
	free (inverse_text);
	mu_assert_eq (r_flag_count (core->flags, NULL), flags, "no duplicate labels");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, profile_mapped (&ctx, 0x7eff2, 1, true)), before, "comments idempotent");
	free (before);
	r_core_free (core);
	mu_end;
}

static bool test_bcc45_original(void) {
	if (!getenv ("R2_TEST_BCC45")) {
		eprintf ("BCC45 original proof not run: set R2_TEST_BCC45 to the qualified read-only original\n");
		mu_end;
	}
	RCore *core = bcc_original ("R2_TEST_BCC45");
	mu_assert_notnull (core, "native BCC45 load");
	BorlandProfileContext ctx;
	mu_assert_true (bcc45_context (core, &ctx), "exact original identity");
	mu_assert_true (bcc_original_equal (&ctx, "R2_TEST_BCC45"), "original byte equality");
	const ut64 tables[] = { 0x16fb2, 0x1751c };
	RIntervalNode *cells[52] = {0};
	mu_assert_true (bcc_check_callback_metadata (&ctx, tables, cells), "native callback metadata before apply");
	mu_assert_eq (borland_bcc45_profile (core->anal), 36, "all BCC45 source function facts");
	mu_assert_true (bcc_check_functions (&ctx, expected_bcc45, R_ARRAY_SIZE (expected_bcc45)), "all complete BCC45 bodies");
	mu_assert_true (bcc_check_data_facts (&ctx, expected_bcc45_data, R_ARRAY_SIZE (expected_bcc45_data)), "all source data views");
	mu_assert_true (bcc_check_refs (&ctx, expected_bcc45_refs, R_ARRAY_SIZE (expected_bcc45_refs)), "all source DATA relations");
	mu_assert_true (bcc_check_text (&ctx, expected_bcc45_labels, R_ARRAY_SIZE (expected_bcc45_labels), true), "all source labels");
	mu_assert_true (bcc_check_text (&ctx, expected_bcc45_comments, R_ARRAY_SIZE (expected_bcc45_comments), false), "all source comments");
	mu_assert_true (bcc_check_types (core->anal, expected_bcc45_records, R_ARRAY_SIZE (expected_bcc45_records), expected_bcc45_enums, R_ARRAY_SIZE (expected_bcc45_enums)), "all source layouts and distinct enum domains");
	mu_assert_true (bcc_check_callback_metadata (&ctx, tables, cells), "array view preserves all 52 actual DATA4 cells");
	mu_assert_true (bcc_check_data (&ctx, 0x16fb2, 104, "bcc45_FarStorage16 [26]", "bcc45_asm_source_callbacks26"), "asm callbacks");
	mu_assert_true (bcc_check_data (&ctx, 0x1751c, 104, "bcc45_FarStorage16 [26]", "bcc45_obj_source_callbacks26"), "object callbacks");
	mu_assert_true (bcc_check_data (&ctx, 0xa7c50, 0x72, "uint16_t [57]", "bcc45_asm_callback_switch_words"), "separate callback switch data");
	mu_assert_eq (bcc_ref (core->anal, profile_mapped (&ctx, 0xa7c98, 2, false), profile_mapped (&ctx, 0xa7b6a, 1, true)), R_ANAL_REF_TYPE_DATA, "current tag0039 cell joins native literal branch");
	RAnalBaseType *pending = r_anal_get_base_type (core->anal, "bcc45_PendingEntry9", R_TYPE_NAMESPACE_ORDINARY);
	mu_assert_notnull (pending, "pending descriptive type only");
	mu_assert_eq (pending->size, 72, "nine-byte pending layout");
	r_anal_base_type_free (pending);
	char *before = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, profile_mapped (&ctx, 0x895f1, 1, true)));
	int flags = r_flag_count (core->flags, NULL);
	ut64 type_epoch = r_anal_types_dirty_epoch (core->anal);
	mu_assert_eq (borland_bcc45_profile (core->anal), 36, "equivalent rerun");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), type_epoch, "equivalent rerun creates no duplicate types or links");
	mu_assert_true (bcc_check_callback_metadata (&ctx, tables, cells), "rerun retains native callback metadata");
	mu_assert_true (bcc_check_data_facts (&ctx, expected_bcc45_data, R_ARRAY_SIZE (expected_bcc45_data)), "rerun retains all source data");
	mu_assert_true (bcc_check_refs (&ctx, expected_bcc45_refs, R_ARRAY_SIZE (expected_bcc45_refs)), "rerun retains every source DATA relation");
	mu_assert_eq (r_flag_count (core->flags, NULL), flags, "no duplicate labels");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, profile_mapped (&ctx, 0x895f1, 1, true)), before, "comments idempotent");
	free (before);
	r_core_free (core);
	mu_end;
}

static bool test_bcc_independent_functions(void) {
	int version, scenario;
	for (version = 0; version < 2; version++) {
		const char *variable = version? "R2_TEST_BCC45": "R2_TEST_BCC31";
		if (!getenv (variable)) {
			continue;
		}
		for (scenario = 0; scenario < 7; scenario++) {
			RCore *core = bcc_original (variable);
			mu_assert_notnull (core, "read-only original for independent function protection");
			BorlandProfileContext ctx;
			mu_assert_true (version? bcc45_context (core, &ctx): bcc31_context (core, &ctx), "original protection context");
			int count = version? 36: 28;
			mu_assert_eq (version? borland_bcc45_profile (core->anal): borland_bcc31_profile (core->anal), count, "initial production fact owner");
			ut64 physical = version? 0xa7845: 0x74826;
			ut64 address = profile_mapped (&ctx, physical, 1, true);
			ut64 annotation = profile_mapped (&ctx, version? 0xa7b6a: 0x748ad, 1, true);
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, address);
			mu_assert_notnull (fcn, "actual source function to protect");
			RAnalBlock *block = r_list_first (fcn->bbs);
			switch (scenario) {
			case 0: r_anal_function_rename (fcn, "user_owned_bcc_function"); break;
			case 1: block->size--; break;
			case 2: fcn->meta.stack_pop = 22; break;
			case 3: block->jump = address + 1; break;
			case 4: {
				RAnalFunctionSignature signature = { .ret_type = "uint32_t", .params = r_list_new () };
				mu_assert_true (r_anal_function_set_signature (core->anal, fcn, &signature), "independent signature");
				r_list_free (signature.params);
				break;
			}
			case 5: r_anal_hint_set_type (core->anal, address + 1, R_ANAL_OP_TYPE_CALL); break;
			case 6: {
				ut8 original;
				mu_assert_eq (core->anal->iob.read_at (core->io, address, &original, 1), 1, "current original instruction");
				ut8 patch = original ^ 1;
				mu_assert_eq (core->anal->iob.overlay_write_at (core->io, address, &patch, 1), 1, "disposable virtual patch");
				break;
			}
			}
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, address, "manual function comment");
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, annotation, "manual annotation");
			ut64 size = block->size, jump = block->jump;
			int pop = fcn->meta.stack_pop;
			char *name = strdup (fcn->name);
			mu_assert_true (version? bcc45_context (core, &ctx): bcc31_context (core, &ctx), "original identity is not current-byte qualification");
			mu_assert_eq (version? borland_bcc45_profile (core->anal): borland_bcc31_profile (core->anal), count - 1, "one independent/current function refuses without dropping other facts");
			mu_assert_ptreq (r_anal_get_function_at (core->anal, address), fcn, "independent function retained");
			mu_assert_streq (fcn->name, name, "independent name retained");
			mu_assert_eq (block->size, size, "independent body retained");
			mu_assert_eq (block->jump, jump, "independent flow retained");
			mu_assert_eq (fcn->meta.stack_pop, pop, "independent cleanup retained");
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, address), "manual function comment", "refused body adds no dependent function comment");
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, annotation), "manual annotation", "refused body adds no dependent inline annotation");
			if (scenario == 4) {
				RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
				mu_assert_streq (signature->ret_type, "uint32_t", "independent signature retained");
				r_anal_function_signature_free (signature);
			}
			free (name);
			r_core_free (core);
		}
	}
	mu_end;
}

static bool test_bcc_independent_data_and_bindings(void) {
	int version, scenario;
	for (version = 0; version < 2; version++) {
		const char *variable = version? "R2_TEST_BCC45": "R2_TEST_BCC31";
		if (!getenv (variable)) {
			continue;
		}
		for (scenario = 0; scenario < 6; scenario++) {
			RCore *core = bcc_original (variable);
			mu_assert_notnull (core, "read-only original for independent data protection");
			BorlandProfileContext ctx;
			mu_assert_true (version? bcc45_context (core, &ctx): bcc31_context (core, &ctx), "original data context");
			r_anal_types_prepare (core->anal);
			ut64 physical = version? 0x14306: 0x1581d;
			ut64 address = profile_mapped (&ctx, physical, 8, false);
			ut64 handler = profile_mapped (&ctx, version? 0x6d6b5: 0x55deb, 1, true);
			const char *name = version? "bcc45_W_wildcard_state_rows": "bcc31_option_B";
			const char *type_name = version? "bcc45_ByteStoreOptionRow8": "bcc31_NearOptionDescriptor8Partial";
			ut64 table = version? 0x16fb2: 0x19574;
			ut64 table_address = profile_mapped (&ctx, table, 104, false);
			ut64 dispatch = version? 0xa7c98: 0x8f984;
			ut64 dispatch_address = profile_mapped (&ctx, dispatch, 2, false);
			ut64 dispatch_target = profile_mapped (&ctx, version? 0xa7b6a: 0x8f6c0, 1, true);
			int previous_ref = bcc_ref (core->anal, dispatch_address, dispatch_target);
			switch (scenario) {
			case 0: {
				const HelperMember independent[] = { { "user_owned_field", "uint16_t", 0 } };
				mu_assert_true (borland_record (core->anal, type_name, 64, independent, 1), "independent named type");
				break;
			}
			case 1: mu_assert_true (r_anal_types_set_link (core->anal, "uint8_t [8]", address), "independent data type link"); break;
			case 2: r_meta_set (core->anal, R_META_TYPE_DATA, address + 2, 2, "manual data"); break;
			case 3: r_anal_xrefs_set (core->anal, address + 2, handler, R_ANAL_REF_TYPE_CODE); break;
			case 4: {
				ut8 original;
				mu_assert_eq (core->anal->iob.read_at (core->io, table_address + 103, &original, 1), 1, "actual callback array tail");
				ut8 patch = original ^ 1;
				mu_assert_eq (core->anal->iob.overlay_write_at (core->io, table_address + 103, &patch, 1), 1, "current callback tail patch");
				break;
			}
			case 5: {
				ut8 patch[2];
				r_write_le16 (patch, version? 0xf6b: 0x12c1);
				mu_assert_true (core->anal->iob.overlay_write_at (core->io, dispatch_address, patch, sizeof (patch)), "current near WORD dispatch patch");
				break;
			}
			}
			mu_assert_eq (version? borland_bcc45_profile (core->anal): borland_bcc31_profile (core->anal), version? 36: 28, "data/ref refusal does not discard independent source bodies");
			if (scenario < 3) {
				mu_assert_null (r_flag_get (core->flags, name), "refused type/link/data adds no dependent label");
				mu_assert_eq (bcc_ref (core->anal, address + 2, handler), 0, "refused type/link/data adds no dependent DATA join");
			}
			if (!scenario) {
				RAnalBaseType *type = r_anal_get_base_type (core->anal, type_name, R_TYPE_NAMESPACE_ORDINARY);
				mu_assert_eq (RVecAnalTypeMember_length (&type->struct_data.members), 1, "independent type members retained");
				mu_assert_streq (RVecAnalTypeMember_at (&type->struct_data.members, 0)->name, "user_owned_field", "independent type role retained");
				r_anal_base_type_free (type);
			} else if (scenario == 1) {
				char key[48];
				snprintf (key, sizeof (key), "link.%08"PFMT64x, address);
				mu_assert_streq (sdb_const_get (core->anal->sdb_types, key, NULL), "uint8_t [8]", "independent type link retained");
			} else if (scenario == 2) {
				mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_DATA, address + 2), "manual data", "independent data metadata retained");
			} else if (scenario == 3) {
				mu_assert_eq (bcc_ref (core->anal, address + 2, handler), R_ANAL_REF_TYPE_CODE, "independent same-pair reference type retained");
			} else if (scenario == 4) {
				mu_assert_null (r_flag_get (core->flags, version? "bcc45_asm_source_callbacks26": "bcc31_object_source_callbacks26"), "changed callback tail refuses entire array before its label");
				char key[48];
				snprintf (key, sizeof (key), "link.%08"PFMT64x, table_address);
				mu_assert_null (sdb_const_get (core->anal->sdb_types, key, NULL), "changed tail adds no array type link");
			} else {
				mu_assert_null (r_flag_get (core->flags, version? "bcc45_asm_tag0039_dispatch_cell": "bcc31_SUB_dispatch_fragment"), "changed near WORD refuses dependent join label");
				mu_assert_eq (bcc_ref (core->anal, dispatch_address, dispatch_target), previous_ref, "changed near WORD adds no source DATA join");
				mu_assert_null (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, dispatch_address), "changed near WORD adds no dependent join comment");
				mu_assert_eq (r_buf_read_le16_at (ctx.file->buf, dispatch), version? 0xf6a: 0x12c0, "immutable source WORD remains distinct from patched current memory");
			}
			r_core_free (core);
		}
	}
	mu_end;
}

static bool test_bcc_independent_enums(void) {
	int version;
	for (version = 0; version < 2; version++) {
		const char *variable = version? "R2_TEST_BCC45": "R2_TEST_BCC31";
		if (!getenv (variable)) {
			continue;
		}
		RCore *core = bcc_original (variable);
		mu_assert_notnull (core, "original for independent enum protection");
		BorlandProfileContext ctx;
		mu_assert_true (version? bcc45_context (core, &ctx): bcc31_context (core, &ctx), "original enum context");
		const char *name = version? "bcc45_NodeTag": "bcc31_EventBranchCode";
		const BorlandEnumCase independent[] = { { "user_owned_code", 0x1234 } };
		mu_assert_true (borland_enum (core->anal, name, 16, independent, R_ARRAY_SIZE (independent)), "independent enum setup");
		mu_assert_eq (version? borland_bcc45_profile (core->anal): borland_bcc31_profile (core->anal), version? 36: 28, "enum conflict is independent of whole-body facts");
		RAnalBaseType *type = r_anal_get_base_type (core->anal, name, R_TYPE_NAMESPACE_ORDINARY);
		mu_assert_notnull (type, "independent enum retained");
		mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_ENUM, "independent enum kind retained");
		mu_assert_eq (RVecAnalEnumCase_length (&type->enum_data.cases), 1, "independent enum not expanded or replaced");
		RAnalEnumCase *entry = RVecAnalEnumCase_at (&type->enum_data.cases, 0);
		mu_assert_streq (entry->name, "user_owned_code", "independent case retained");
		mu_assert_eq (entry->val, 0x1234, "independent value retained");
		r_anal_base_type_free (type);
		if (!version) {
			mu_assert_null (r_flag_get (core->flags, "bcc31_JE_JNE_inverse_codes"), "conflicted enum suppresses dependent data label");
			mu_assert_null (r_anal_get_base_type (core->anal, "bcc31_Event16Partial", R_TYPE_NAMESPACE_ORDINARY), "conflicted enum suppresses dependent record");
		}
		r_core_free (core);
	}
	mu_end;
}

static bool bcc_command(RCore *core, int *count) {
	char *output = r_core_cmd_str (core, "a:borland");
	mu_assert_notnull (output, "registered RCore a:borland output");
	mu_assert_eq (sscanf (output, "Borland: %d function contracts qualified", count), 1, "honest production command count");
	eprintf ("RCore a:borland: %s", output);
	free (output);
	return true;
}

static bool bcc_default_pre(RCore *core) {
	mu_assert_streq (r_config_get (core->config, "anal.plugins.pre"), "", "unchanged default PRE-hook selection");
	r_anal_plugin_action (core->anal, R_ANAL_PLUGIN_ACTION_PRE_ANALYSIS, NULL);
	return true;
}

static bool bcc_complete_normal_facts(BorlandProfileContext *ctx, bool version) {
	if (version) {
		mu_assert_true (bcc_check_functions (ctx, expected_bcc45, R_ARRAY_SIZE (expected_bcc45)), "normal path all 36 complete bodies");
		mu_assert_true (bcc_check_data_facts (ctx, expected_bcc45_data, R_ARRAY_SIZE (expected_bcc45_data)), "normal path all 22 data views");
		mu_assert_true (bcc_check_refs (ctx, expected_bcc45_refs, R_ARRAY_SIZE (expected_bcc45_refs)), "normal path all 68 source DATA relationships");
		mu_assert_true (bcc_check_text (ctx, expected_bcc45_labels, R_ARRAY_SIZE (expected_bcc45_labels), true), "normal path all 21 source labels");
		mu_assert_true (bcc_check_text (ctx, expected_bcc45_comments, R_ARRAY_SIZE (expected_bcc45_comments), false), "normal path all 15 source comments");
		mu_assert_true (bcc_check_types (ctx->anal, expected_bcc45_records, R_ARRAY_SIZE (expected_bcc45_records), expected_bcc45_enums, R_ARRAY_SIZE (expected_bcc45_enums)), "normal path all BCC45 record and enum domains");
	} else {
		mu_assert_true (bcc_check_functions (ctx, expected_bcc31, R_ARRAY_SIZE (expected_bcc31)), "normal path all 28 complete bodies");
		mu_assert_true (bcc_check_data_facts (ctx, expected_bcc31_data, R_ARRAY_SIZE (expected_bcc31_data)), "normal path all 36 data views");
		mu_assert_true (bcc_check_refs (ctx, expected_bcc31_refs, R_ARRAY_SIZE (expected_bcc31_refs)), "normal path all 151 source DATA relationships");
		mu_assert_true (bcc_check_text (ctx, expected_bcc31_labels, R_ARRAY_SIZE (expected_bcc31_labels), true), "normal path all 46 source labels");
		mu_assert_true (bcc_check_text (ctx, expected_bcc31_comments, R_ARRAY_SIZE (expected_bcc31_comments), false), "normal path all 33 source comments");
		mu_assert_true (bcc_check_types (ctx->anal, expected_bcc31_records, R_ARRAY_SIZE (expected_bcc31_records), expected_bcc31_enums, R_ARRAY_SIZE (expected_bcc31_enums)), "normal path all BCC31 record and enum domains");
	}
	return true;
}

static bool test_bcc_registered_command_and_default_pre(void) {
	int version, pre;
	for (version = 0; version < 2; version++) {
		const char *variable = version? "R2_TEST_BCC45": "R2_TEST_BCC31";
		if (!getenv (variable)) {
			continue;
		}
		for (pre = 0; pre < 2; pre++) {
			RCore *core = bcc_original (variable);
			mu_assert_notnull (core, "normal-path exact original");
			BorlandProfileContext ctx;
			mu_assert_true (version? bcc45_context (core, &ctx): bcc31_context (core, &ctx), "normal-path original identity");
			ut64 physical = version? 0xa7845: 0x74826;
			ut64 address = profile_mapped (&ctx, physical, 1, true);
			mu_assert_null (r_anal_get_function_at (core->anal, address), "no private apply before registered path");
			const ut64 tables[] = { version? 0x16fb2: 0x19574, version? 0x1751c: 0x1965a };
			RIntervalNode *cells[52] = {0};
			mu_assert_true (bcc_check_callback_metadata (&ctx, tables, cells), "native cells before normal path");
			int count = 0;
			if (pre) {
				mu_assert_true (bcc_default_pre (core), "default registered PRE hook");
			} else {
				mu_assert_true (bcc_command (core, &count), "actual registered RCore command");
			}
			mu_assert_true (bcc_complete_normal_facts (&ctx, version), "registered path installs complete finite result");
			mu_assert_true (bcc_check_callback_metadata (&ctx, tables, cells), "registered path preserves native cells");
			int flags = r_flag_count (core->flags, NULL);
			ut64 epoch = r_anal_types_dirty_epoch (core->anal);
			char *comment = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, address));
			if (pre) {
				mu_assert_true (bcc_default_pre (core), "default-hook equivalent reapply");
			}
			int repeated = 0;
			mu_assert_true (bcc_command (core, &repeated), "normal command equivalent reapply after either route");
			if (!pre) {
				mu_assert_eq (repeated, count, "production count is stable on equivalent reapply");
			}
			mu_assert_true (repeated >= (version? 36: 28), "production count includes complete exact profile");
			mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "registered rerun adds no duplicate type/link state");
			mu_assert_eq (r_flag_count (core->flags, NULL), flags, "registered rerun adds no duplicate labels");
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, address), comment, "registered rerun preserves comment identity");
			free (comment);
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, address);
			ut64 size = r_anal_function_realsize (fcn);
			r_anal_function_rename (fcn, "user_owned_normal_bcc");
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, address, "manual normal-path comment");
			if (pre) {
				mu_assert_true (bcc_default_pre (core), "default hook preserves manual function state");
			}
			int preserved = 0;
			mu_assert_true (bcc_command (core, &preserved), "normal command preserves manual function state");
			mu_assert_eq (preserved, repeated - 1, "production count reports one refused independent function");
			mu_assert_ptreq (r_anal_get_function_at (core->anal, address), fcn, "normal routes retain independent function identity");
			mu_assert_streq (fcn->name, "user_owned_normal_bcc", "normal routes retain independent name");
			mu_assert_eq (r_anal_function_realsize (fcn), size, "normal routes retain independent body");
			mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, address), "manual normal-path comment", "refused normal route adds no dependent comment");
			r_core_free (core);
		}
	}
	mu_end;
}

static bool test_bcc_registered_current_word_refusal(void) {
	int version, pre;
	for (version = 0; version < 2; version++) {
		const char *variable = version? "R2_TEST_BCC45": "R2_TEST_BCC31";
		if (!getenv (variable)) {
			continue;
		}
		for (pre = 0; pre < 2; pre++) {
			RCore *core = bcc_original (variable);
			mu_assert_notnull (core, "normal current-WORD input");
			BorlandProfileContext ctx;
			mu_assert_true (version? bcc45_context (core, &ctx): bcc31_context (core, &ctx), "normal current-WORD original identity");
			ut64 physical = version? 0xa7c98: 0x8f984;
			ut64 address = profile_mapped (&ctx, physical, 2, false);
			ut64 target = profile_mapped (&ctx, version? 0xa7b6a: 0x8f6c0, 1, true);
			const char *label = version? "bcc45_asm_tag0039_dispatch_cell": "bcc31_SUB_dispatch_fragment";
			int previous = bcc_ref (core->anal, address, target);
			ut8 patch[2];
			r_write_le16 (patch, version? 0xf6b: 0x12c1);
			mu_assert_true (core->anal->iob.overlay_write_at (core->io, address, patch, sizeof (patch)), "disposable current WORD differs from immutable original");
			int count = 0;
			if (pre) {
				mu_assert_true (bcc_default_pre (core), "default hook observes changed current WORD");
			} else {
				mu_assert_true (bcc_command (core, &count), "normal command observes changed current WORD");
			}
			mu_assert_null (r_flag_get (core->flags, label), "normal path refuses dependent join label");
			mu_assert_eq (bcc_ref (core->anal, address, target), previous, "normal path adds no DATA join for changed current WORD");
			mu_assert_null (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, address), "normal path adds no dependent join comment");
			mu_assert_true (bcc_check_functions (&ctx, version? expected_bcc45: expected_bcc31, version? R_ARRAY_SIZE (expected_bcc45): R_ARRAY_SIZE (expected_bcc31)), "current table refusal preserves every independent complete body");
			r_write_le16 (patch, version? 0xf6a: 0x12c0);
			mu_assert_true (core->anal->iob.overlay_write_at (core->io, address, patch, sizeof (patch)), "restore current WORD in disposable view only");
			if (pre) {
				mu_assert_true (bcc_default_pre (core), "default hook admits newly qualifying current WORD");
			} else {
				mu_assert_true (bcc_command (core, &count), "normal command admits newly qualifying current WORD");
			}
			mu_assert_true (bcc_complete_normal_facts (&ctx, version), "normal rerun after current correction installs the complete result");
			r_core_free (core);
		}
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_bcc31_original);
	mu_run_test (test_bcc45_original);
	mu_run_test (test_bcc_independent_functions);
	mu_run_test (test_bcc_independent_data_and_bindings);
	mu_run_test (test_bcc_independent_enums);
	mu_run_test (test_bcc_registered_command_and_default_pre);
	mu_run_test (test_bcc_registered_current_word_refusal);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
