#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_tlink51_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland
#include "borland_tlink51_expected.h"

static RCore *tlink51_core(void) {
	const char *path = getenv ("R2_TEST_TLINK51");
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "bin.relocs.apply", true);
	if (!path || !r_core_file_open (core, path, R_PERM_RX, 0) || !r_core_bin_load (core, path, UT64_MAX)) {
		r_core_free (core);
		return NULL;
	}
	r_config_set_b (core->config, "io.va", true);
	return core;
}

static bool tlink51_activate(RCore *core, bool pre) {
	if (pre) {
		mu_assert_streq (r_config_get (core->config, "anal.plugins.pre"), "", "unchanged default registered PRE selection");
		r_anal_plugin_action (core->anal, R_ANAL_PLUGIN_ACTION_PRE_ANALYSIS, NULL);
	} else {
		char *output = r_core_cmd_str (core, "a:borland");
		mu_assert_notnull (output, "registered command output");
		int count = 0;
		mu_assert_eq (sscanf (output, "Borland: %d function contracts qualified", &count), 1, "registered production count");
		eprintf ("Registered TLINK51: %s", output);
		free (output);
	}
	return true;
}

static char *tlink51_snapshot(RCore *core) {
	// aflj cost/purity and ablj call derivation decode bytes and are not readonly observers under bits hints.
	char *state = r_core_cmd_str (core, "fj;Cj;axj;ahj");
	char *types = sdb_querys (core->anal->sdb_types, NULL, 0, "*");
	RStrBuf *result = r_strbuf_new (state);
	r_strbuf_appendf (result, "\ntypes:%s\narch:%s bits:%d dirty:%d", types? types: "", core->anal->config->arch, core->anal->config->bits, core->anal->is_dirty);
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		char *signature = r_anal_function_get_signature_string (fcn);
		r_strbuf_appendf (result, "\nfcn:%p addr:%"PFMT64x" name:%s bits:%d purge:%d cc:%s noreturn:%d changed:%d pure:%d vars:%zu signature:%s", (void *)fcn, fcn->addr, fcn->name, fcn->bits, fcn->meta.stack_pop, fcn->callconv? fcn->callconv: "", fcn->is_noreturn, fcn->has_changed, fcn->is_pure, RVecAnalVarPtr_length (&fcn->vars), signature? signature: "");
		free (signature);
	}
	RBIter blocks;
	RAnalBlock *block;
	r_rbtree_foreach (core->anal->bb_tree, blocks, block, RAnalBlock, _rb) {
		r_strbuf_appendf (result, "\nbb:%p addr:%"PFMT64x" size:%"PFMT64u" jump:%"PFMT64x" fail:%"PFMT64x" instructions:%d", (void *)block, block->addr, block->size, block->jump, block->fail, block->ninstr);
		int i;
		for (i = 0; i < block->ninstr; i++) {
			r_strbuf_appendf (result, " op:%"PFMT64x, r_anal_bb_opaddr_i (block, i));
		}
		r_list_foreach (block->fcns, iter, fcn) {
			r_strbuf_appendf (result, " owner:%"PFMT64x, fcn->addr);
		}
	}
	free (state);
	free (types);
	return r_strbuf_drain (result);
}

static bool tlink51_query(RCore *core, bool recognized, bool qualified) {
	char *before = tlink51_snapshot (core);
	ut64 epoch = r_anal_types_dirty_epoch (core->anal);
	char *output = r_core_cmd_str (core, "a:borland:continuations");
	mu_assert_notnull (output, "registered readonly query output");
	RJson *json = r_json_parse (output);
	mu_assert_notnull (json, "native JSON transport");
	const RJson *match = r_json_get (json, "recognized"), *joins = r_json_get (json, "continuations");
	mu_assert_notnull (match, "recognition always present");
	mu_assert_eq (match->type, R_JSON_BOOLEAN, "boolean recognition");
	mu_assert_eq (match->num.u_value, recognized, "exact identity, not mutation authority");
	mu_assert_notnull (joins, "continuations always present");
	mu_assert_eq (joins->type, R_JSON_ARRAY, "native pair array");
	mu_assert_eq (joins->children.count, qualified? 7: 0, "all seven jointly qualified or none");
	int i;
	for (i = 0; qualified && i < 7; i++) {
		const RJson *join = r_json_item (joins, i), *call = r_json_get (join, "call"), *resume = r_json_get (join, "resume");
		mu_assert_notnull (call, "qualified native call");
		mu_assert_notnull (resume, "qualified native resume");
		mu_assert_eq (call->num.u_value, 0x10000 + expected_joins[i][0], "source-owned call offset at actual native NE1");
		mu_assert_eq (resume->num.u_value, 0x10000 + expected_joins[i][2], "source-owned conditional resume offset at actual native NE1");
	}
	r_json_free (json);
	free (output);
	char *after = tlink51_snapshot (core);
	mu_assert_streq (after, before, "query unchanged functions/blocks/signatures/flags/metadata/refs/hints/type DB");
	mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "query does not prepare or write types");
	free (before);
	free (after);
	return true;
}

static ut32 tlink51_ref(RAnal *anal, ut64 from, ut64 to) {
	RVecAnalRef *refs = r_anal_refs_get (anal, from);
	RAnalRef *ref;
	ut32 type = 0;
	if (refs) {
		R_VEC_FOREACH (refs, ref) {
			if (ref->addr == to) {
				type = R_ANAL_REF_TYPE_MASK (ref->type);
			}
		}
	}
	RVecAnalRef_free (refs);
	return type;
}

static bool tlink51_comment(RAnal *anal, ut64 address, const char *text) {
	const char *comment = r_meta_get_string (anal, R_META_TYPE_COMMENT, address);
	return comment && strstr (comment, text);
}

static bool tlink51_shared(RCore *core, BorlandProfileContext *ctx) {
	RAnalFunction *shared = r_anal_get_function_at (core->anal, 0x1ddf9);
	mu_assert_notnull (shared, "registered multi-entry shared function");
	mu_assert_streq (shared->name, "tlink51_argument_consuming_error_entries", "source shared name");
	mu_assert_eq (shared->meta.stack_pop, R_ANAL_CC_STACK_POP_UNKNOWN, "current count S+4+n is not fixed purge");
	mu_assert_false (shared->is_noreturn, "consumed return is not ordinary noreturn");
	mu_assert_eq (r_anal_function_realsize (shared), 286, "code-only total excludes all89 inline bytes");
	mu_assert_null (r_anal_get_function_at (core->anal, 0x1df70), "separate DF70 is not fabricated as part of this transfer");
	BorlandContinuation projection[7];
	int i;
	for (i = 0; i < 7; i++) {
		projection[i] = (BorlandContinuation){ 0x10000 + expected_joins[i][0], 0x10000 + expected_joins[i][2] };
	}
	ctx->continuations = projection;
	ctx->continuation_count = 7;
	BorlandCodeRange ranges[8] = {0};
	for (i = 0; i < 8; i++) {
		int size = expected_intervals[i][1] - expected_intervals[i][0];
		ranges[i] = (BorlandCodeRange){ 0x10000 + expected_intervals[i][0], size, calloc (size, sizeof (HelperOp)) };
		mu_assert_true (profile_code (ctx, 0x1200 + expected_intervals[i][0], size, ranges[i].address, ranges[i].ops), "all eight current code partitions");
		char name[48];
		snprintf (name, sizeof (name), "tlink51_error_code_%x", expected_intervals[i][0]);
		RFlagItem *label = r_flag_get (core->flags, name);
		mu_assert_notnull (label, "every code interval label");
		mu_assert_eq (label->addr, ranges[i].address, "original native code interval");
	}
	mu_assert_true (borland_body_ranges (shared, ranges, 8), "same current decoded leader/edge oracle decides exact noncontiguous body equivalence");
	for (i = 0; i < 8; i++) {
		free (ranges[i].ops);
	}
	ctx->continuations = NULL;
	ctx->continuation_count = 0;
	for (i = 0; i < 7; i++) {
		ut64 call = 0x10000 + expected_joins[i][0], prefix = 0x10000 + expected_joins[i][1], resume = 0x10000 + expected_joins[i][2];
		RAnalBlock *bb = r_anal_function_bbget_in (core->anal, shared, call);
		mu_assert_notnull (bb, "actual call basic block");
		mu_assert_eq (bb->addr + bb->size, prefix, "block ends at call, not inline DATA");
		mu_assert_eq (bb->jump, resume, "conditional continuation installed by decoded-flow oracle before block creation");
		mu_assert_eq (bb->fail, UT64_MAX, "not unconditional helper fallthrough into DATA");
		mu_assert_eq (tlink51_ref (core->anal, call, 0x1b4f0), R_ANAL_REF_TYPE_CALL, "actual consumed-return helper relation");
		mu_assert_eq (tlink51_ref (core->anal, call, prefix), R_ANAL_REF_TYPE_DATA, "inline prefix data relation");
		RList *blocks = r_anal_get_blocks_intersect (core->anal, prefix, resume - prefix);
		mu_assert_true (r_list_empty (blocks), "no blocks or instructions in inline DATA");
		r_list_free (blocks);
		ut64 size = 0;
		mu_assert_notnull (r_meta_get_at (core->anal, prefix, R_META_TYPE_DATA, &size), "length and text are native DATA");
		mu_assert_eq (size, resume - prefix, "complete current inline extent");
		ut8 length;
		mu_assert_true (r_io_read_at (core->io, prefix, &length, 1), "actual current prefix read");
		mu_assert_eq (length, size - 1, "actual prefix independently determines conditional resume");
		char name[48];
		snprintf (name, sizeof (name), "tlink51_InlineText%d", length);
		RAnalBaseType *text = r_anal_get_base_type (core->anal, name, R_TYPE_NAMESPACE_ORDINARY);
		mu_assert_notnull (text, "every source inline record layout");
		mu_assert_eq (text->size, size * 8, "prefix and non-NUL text exact record extent");
		mu_assert_eq (RVecAnalTypeMember_length (&text->struct_data.members), 2, "only length and text fields");
		RAnalTypeMember *prefix_field = RVecAnalTypeMember_at (&text->struct_data.members, 0), *text_field = RVecAnalTypeMember_at (&text->struct_data.members, 1);
		mu_assert_streq (prefix_field->name, "length", "source inline length field");
		mu_assert_streq (prefix_field->type, "uint8_t", "source byte prefix");
		mu_assert_eq (prefix_field->offset, 0, "prefix starts record");
		mu_assert_streq (text_field->name, "text", "source inline text field");
		mu_assert_streq (text_field->type, "char", "source character bytes");
		mu_assert_eq (text_field->offset, 1, "text follows prefix");
		mu_assert_eq (text_field->count, length, "not NUL-terminated or padded");
		r_anal_base_type_free (text);
	}
	mu_assert_true (tlink51_comment (core->anal, 0x1ddf9, "S+4+n"), "source conditional return semantics");
	mu_assert_true (tlink51_comment (core->anal, 0x1df5a, "count freshly reread"), "fresh count not historical constant");
	return true;
}

static bool test_tlink51_nonmatch(void) {
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	mu_assert_true (tlink51_query (core, false, false), "readonly nonmatch");
	char *help = r_core_cmd_str (core, "a:borland?");
	mu_assert_notnull (strstr (help, "borland:continuations"), "query documented at actual command owner");
	free (help);
	r_core_free (core);
	mu_end;
}

static bool test_tlink51_original_facts(void) {
	if (!getenv ("R2_TEST_TLINK51")) {
		eprintf ("TLINK51 original proof skipped: set R2_TEST_TLINK51; no native bridge/engine/decompilation integration claimed\n");
		mu_end;
	}
	int pre;
	for (pre = 0; pre < 2; pre++) {
		RCore *core = tlink51_core ();
		mu_assert_notnull (core, "normally loaded read-only actual original");
		BorlandProfileContext ctx;
		mu_assert_true (tlink51_identity (core->anal, &ctx), "actual exact native original");
		RIntervalNode *diagnostic_strings[] = { r_meta_get_in (core->anal, 0x400ab, R_META_TYPE_STRING), r_meta_get_in (core->anal, 0x400d2, R_META_TYPE_STRING) };
		const ut64 string_sizes[] = { 25, 19 };
		const char *string_contents[] = { "Write failed, disk full?", "DOS error, ax = %d" };
		size_t text;
		for (text = 0; text < R_ARRAY_SIZE (diagnostic_strings); text++) {
			mu_assert_notnull (diagnostic_strings[text], "normal native loader's independent diagnostic STRING view");
			mu_assert_eq (diagnostic_strings[text]->end - diagnostic_strings[text]->start + 1, string_sizes[text], "actual native STRING extent differs from source array width");
		}
		mu_assert_null (r_anal_get_function_at (core->anal, 0x13c0b), "no private profile application before production");
		mu_assert_true (tlink51_query (core, true, true), "first pure query qualifies without installing functions/types/data");
		mu_assert_true (tlink51_activate (core, pre), "normal command or unchanged registered default PRE");
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (expected_functions); i++) {
			ut64 address = profile_mapped (&ctx, expected_functions[i].file, expected_functions[i].size, true);
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, address);
			if (!fcn) {
				eprintf ("Missing expected FILE %08"PFMT64x" %s\n", expected_functions[i].file, expected_functions[i].name);
			}
			mu_assert_notnull (fcn, "every complete source function installed by registered path");
			mu_assert_streq (fcn->name, expected_functions[i].name, "complete source function name");
			mu_assert_eq (r_anal_function_realsize (fcn), expected_functions[i].size, "source complete extent");
			mu_assert_eq (fcn->meta.stack_pop, expected_functions[i].purge, "only source-accounted cleanup");
			mu_assert_false (fcn->is_noreturn, "opaque/numeric requests are not assigned noreturn");
			HelperOp *ops = calloc (expected_functions[i].size, sizeof (HelperOp));
			mu_assert_true (profile_code (&ctx, expected_functions[i].file, expected_functions[i].size, address, ops), "actual current byte/context/relocation qualification");
			BorlandCodeRange range = { address, expected_functions[i].size, ops };
			mu_assert_true (borland_body_ranges (fcn, &range, 1), "complete actual decoded boundaries and all block edges");
			int off = 0, instructions = 0;
			while (off < expected_functions[i].size) {
				instructions++;
				off += ops[off].size;
			}
			if (expected_functions[i].instructions) {
				mu_assert_eq (instructions, expected_functions[i].instructions, "source validator instruction count");
			}
			free (ops);
		}
		mu_assert_true (tlink51_shared (core, &ctx), "all current code-only/inline relations");
		for (i = 0; i < R_ARRAY_SIZE (expected_windows); i++) {
			ut64 address = 0x10000 + expected_windows[i].start;
			RFlagItem *label = r_flag_get (core->flags, expected_windows[i].name);
			mu_assert_notnull (label, "every source partial window");
			mu_assert_eq (label->addr, address, "actual native partial window");
			RList *blocks = r_anal_get_blocks_intersect (core->anal, address, expected_windows[i].end - expected_windows[i].start);
			mu_assert_true (r_list_empty (blocks), "partial/multi-entry windows never invent complete functions/blocks");
			r_list_free (blocks);
			mu_assert_true (tlink51_comment (core->anal, address, "partial/multi-entry partitions"), "source partial limitation");
		}
		for (i = 0; i < R_ARRAY_SIZE (expected_records); i++) {
			RAnalBaseType *type = r_anal_get_base_type (core->anal, expected_records[i].name, R_TYPE_NAMESPACE_ORDINARY);
			mu_assert_notnull (type, "all independent source dynamic/working/static type views");
			mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_STRUCT, "native record");
			mu_assert_eq (type->size, expected_records[i].size * 8, "complete nominal layout");
			mu_assert_eq (RVecAnalTypeMember_length (&type->struct_data.members), expected_records[i].count, "only established fields, gaps remain undefined");
			int field;
			for (field = 0; field < expected_records[i].count; field++) {
				RAnalTypeMember *member = RVecAnalTypeMember_at (&type->struct_data.members, field);
				const HelperMember *expected = &expected_records[i].members[field];
				mu_assert_streq (member->name, expected->name, "source field name");
				mu_assert_streq (member->type, expected->type, "source field type/domain");
				mu_assert_eq (member->offset, expected->offset, "source field offset");
				mu_assert_eq (member->count, expected->count, "source array extent");
			}
			r_anal_base_type_free (type);
		}
		RAnalFunctionSignature *writer = r_anal_function_get_signature (r_anal_get_function_at (core->anal, 0x13c0b));
		mu_assert_streq (writer->ret_type, "NearWriterAnalysisState7", "shared seven-byte writer tuple");
		mu_assert_streq (writer->callconv, "tlink_writer_state_16near", "existing native writer convention");
		mu_assert_eq (r_list_length (writer->params), 4, "all four WORD inputs without widening HelperContract");
		const char *names[] = { "entry_bx", "entry_cx", "entry_dx", "entry_ds" };
		for (i = 0; i < R_ARRAY_SIZE (names); i++) {
			RAnalFunctionParam *param = r_list_get_n (writer->params, i);
			mu_assert_streq (param->name, names[i], "actual ordered writer input");
			mu_assert_streq (param->type, "uint16_t", "actual input WORD");
		}
		r_anal_function_signature_free (writer);
		mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, "NearWriterAnalysisState7"), 56, "no tuple padding");
		RAnalBaseType *location = r_anal_get_base_type (core->anal, "tlink51_MaskedLocationClass", R_TYPE_NAMESPACE_ORDINARY);
		mu_assert_notnull (location, "source masked-location enum");
		mu_assert_eq (location->kind, R_ANAL_BASE_TYPE_KIND_ENUM, "independent native enum domain");
		mu_assert_eq (location->size, 8, "source byte enum");
		mu_assert_eq (RVecAnalEnumCase_length (&location->enum_data.cases), 3, "only three established numeric classes");
		const struct { const char *name; ut64 value; } classes[] = { { "word_offset", 4 }, { "far_candidate", 12 }, { "alternate_import_offset", 20 } };
		for (i = 0; i < R_ARRAY_SIZE (classes); i++) {
			RAnalEnumCase *value = RVecAnalEnumCase_at (&location->enum_data.cases, i);
			mu_assert_streq (value->name, classes[i].name, "source numeric class name");
			mu_assert_eq (value->val, classes[i].value, "source masked numeric class");
		}
		r_anal_base_type_free (location);
		const struct { ut64 address; const char *type; int size; } data[] = {
			{ 0x13d08, "uint16_t [8]", 16 }, { 0x109a1, "uint8_t [128]", 128 }, { 0x10a21, "char [10]", 10 }, { 0x400ab, "char [24]", 24 }, { 0x400d2, "char [18]", 18 }, { 0x40a7d, "uint16_t", 2 }, { 0x40a81, "uint16_t", 2 }
		};
		for (i = 0; i < R_ARRAY_SIZE (data); i++) {
			char *type = r_type_link_at (core->anal->sdb_types, data[i].address);
			if (!type) {
				eprintf ("Missing static data at native 0x%08"PFMT64x"; loader ne.reloc.4.count=%s\n", data[i].address, sdb_const_get (ctx.ne, "ne.reloc.4.count", NULL));
			}
			mu_assert_notnull (type, "source static data cannot be omitted when native relocation-empty qualification is unavailable");
			mu_assert_streq (type, data[i].type, "all source static arrays/scalars");
			mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, type), data[i].size * 8, "source data link has its own exact extent");
			free (type);
			ut64 size = 0;
			RAnalMetaItem *metadata = r_meta_get_at (core->anal, data[i].address, R_META_TYPE_DATA, &size);
			if (!metadata && !strncmp (data[i].type, "char [", 6)) {
				metadata = r_meta_get_at (core->anal, data[i].address, R_META_TYPE_STRING, &size);
			}
			mu_assert_notnull (metadata, "static DATA or preserved native STRING ownership with exact array link");
			if (metadata->type == R_META_TYPE_STRING) {
				mu_assert_true (i == 3 || i == 4, "only the two witnessed independent diagnostic STRING views");
				mu_assert_ptreq (r_meta_get_in (core->anal, data[i].address, R_META_TYPE_STRING), diagnostic_strings[i - 3], "native STRING node preserved rather than replaced with source array width");
				mu_assert_eq (size, string_sizes[i - 3], "native STRING extent preserved");
				mu_assert_streq (metadata->str, string_contents[i - 3], "native diagnostic content preserved");
			} else {
				mu_assert_eq (size, data[i].size, "static DATA exact size");
			}
		}
		int position, ea = 0, ff = 0, raw = 0;
		for (position = 0; position < 105; position++) {
			ut64 address = 0x30002 + 5 * position;
			ut8 first;
			mu_assert_true (r_io_read_at (core->io, address, &first, 1), "actual raw leading byte");
			ea += first == 0xea;
			ff += first == 0xff;
			bool executable = false;
			for (i = 0; i < R_ARRAY_SIZE (expected_code_slots); i++) {
				executable |= address == 0x30000 + expected_code_slots[i];
			}
			if (!executable) {
				raw++;
				char *type = r_type_link_at (core->anal->sdb_types, address);
				mu_assert_streq (type, "tlink51_StoredFarSlot5", "99 positions are stored DATA, not executable stubs");
				free (type);
			}
			if (first == 0xea) {
				mu_assert_eq (tlink51_ref (core->anal, address + 1, 0x30afc), R_ANAL_REF_TYPE_DATA, "all97 native relocated target fields join real common trap");
			}
		}
		mu_assert_eq (ea, 97, "97 EA cells");
		mu_assert_eq (ff, 8, "eight nonjump FF cells");
		mu_assert_eq (raw, 99, "only six caller-proved executable slots");
		const ut16 writer_calls[] = { 0x3d6e, 0x4302, 0x432c };
		for (i = 0; i < R_ARRAY_SIZE (writer_calls); i++) {
			mu_assert_eq (tlink51_ref (core->anal, 0x10000 + writer_calls[i], 0x13c0b), R_ANAL_REF_TYPE_CALL, "actual partial writer caller relations");
		}
		const struct { ut16 source; ut16 target; } near[] = { { 0xd8ce, 0xd8e7 }, { 0x8718, 0x9e96 }, { 0x8784, 0x9e96 }, { 0x87cf, 0x9e96 }, { 0xbedd, 0x9e96 }, { 0xc059, 0x9e96 }, { 0x4c81, 0x9e96 }, { 0xabc1, 0xddfe }, { 0xabe6, 0xddfe }, { 0xdf54, 0x9b20 } };
		for (i = 0; i < R_ARRAY_SIZE (near); i++) {
			mu_assert_eq (tlink51_ref (core->anal, 0x10000 + near[i].source, 0x10000 + near[i].target), R_ANAL_REF_TYPE_CALL, "source validator's actual near-call relations");
		}
		const struct { ut16 source; ut16 target; } far[] = { { 0x665c, 0xc }, { 0x9cf4, 0xe3 }, { 0x9d01, 0xed }, { 0x9d71, 0xbb }, { 0x9da4, 0xc }, { 0x9c23, 0xbb }, { 0x9c3e, 0xbb }, { 0x9c68, 0x1ce }, { 0x9c79, 0xbb }, { 0x9c95, 0x16 }, { 0x9ca9, 0x16 } };
		for (i = 0; i < R_ARRAY_SIZE (far); i++) {
			mu_assert_eq (tlink51_ref (core->anal, 0x10000 + far[i].source, 0x30000 + far[i].target), R_ANAL_REF_TYPE_DATA, "all source-accounted native relocated FAR-field bindings");
		}
		for (i = 0; i < 8; i++) {
			ut8 word[2];
			mu_assert_eq (r_buf_read_at (ctx.file->buf, 0x4f08 + 2 * i, word, 2), 2, "original source dispatch WORD");
			mu_assert_eq (tlink51_ref (core->anal, 0x13d08 + 2 * i, 0x10000 + r_read_le16 (word)), R_ANAL_REF_TYPE_DATA, "all eight CS-relative dispatch relations");
		}
		mu_assert_eq (tlink51_ref (core->anal, 0x1dde5, 0x40a6f), R_ANAL_REF_TYPE_DATA, "actual additive selector binding joins NE4 message table");
		mu_assert_eq (tlink51_ref (core->anal, 0x40a7d, 0x400ab), R_ANAL_REF_TYPE_DATA, "index7 diagnostic text relation");
		mu_assert_eq (tlink51_ref (core->anal, 0x40a81, 0x400d2), R_ANAL_REF_TYPE_DATA, "index9 diagnostic text relation");
		mu_assert_null (r_type_link_at (core->anal->sdb_types, 0x85f), "working DS085F not invented static header");
		mu_assert_null (r_type_link_at (core->anal->sdb_types, 0x8bb), "NB02 working view not linked to fabricated initialized DS");
		mu_assert_true (tlink51_comment (core->anal, 0x1ab57, "65536 SHL"), "finite count-zero alignment semantics retained");
		mu_assert_true (tlink51_comment (core->anal, 0x186bd, "not usable debug symbols"), "bounded NB02 claim");
		mu_assert_true (tlink51_query (core, true, true), "pure query after actual registered application");
		R_DIRTY_UNSET (core->anal);
		mu_assert_true (profile_reference (core->anal, 0x1de2c, 0x1de2f, R_ANAL_REF_TYPE_DATA), "equivalent shared reference owner accepts the real installed inline relation");
		mu_assert_false (core->anal->is_dirty, "preflight extraction preserves the original equivalent-reference no-setter path");
		char *before = tlink51_snapshot (core);
		ut64 epoch = r_anal_types_dirty_epoch (core->anal);
		RAnalFunction *shared = r_anal_get_function_at (core->anal, 0x1ddf9);
		RAnalBlock *block = r_list_first (shared->bbs);
		mu_assert_true (tlink51_activate (core, pre), "equivalent registered reapply");
		char *after = tlink51_snapshot (core);
		mu_assert_streq (after, before, "complete finite equivalent rerun stable");
		mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "no duplicate type/signature setters");
		mu_assert_ptreq (r_list_first (shared->bbs), block, "noncontiguous block identity retained");
		mu_assert_true (tlink51_shared (core, &ctx), "same decoded-flow oracle admits reapplication");
		free (before);
		free (after);
		r_core_free (core);
	}
	mu_end;
}

static bool test_tlink51_current_and_manual_refusal(void) {
	if (!getenv ("R2_TEST_TLINK51")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 19; scenario++) {
		RCore *core = tlink51_core ();
		mu_assert_notnull (core, "actual original adverse input");
		bool initial = scenario == 18;
		if (!initial) {
			mu_assert_true (tlink51_activate (core, false), "actual registered baseline, not private fallback");
		}
		RAnalFunction *copy = r_anal_get_function_at (core->anal, 0x1b49f), *consume = r_anal_get_function_at (core->anal, 0x1b4f0), *shared = r_anal_get_function_at (core->anal, 0x1ddf9);
		ut64 changed_at = 0;
		ut8 changed = 0;
		switch (scenario) {
		case 0: changed_at = 0x1de2f; changed = 6; break;
		case 1: changed_at = 0x1de30; changed = 'X'; break;
		case 2: changed_at = 0x1b49f; changed = 0x51; break;
		case 3: changed_at = 0x1b4f0; changed = 0x56; break;
		case 4: changed_at = 0x1de0d; changed = 0x58; break;
		case 5: r_anal_function_rename (copy, "manual_copy"); break;
		case 6: consume->meta.stack_pop = 26; break;
		case 7: shared->meta.stack_pop = 26; break;
		case 8: ((RAnalBlock *)r_list_first (shared->bbs))->jump = 0x12345; break;
		case 9: r_meta_set (core->anal, R_META_TYPE_CODE, 0x1de2f, 8, NULL); break;
		case 10: r_meta_set (core->anal, R_META_TYPE_DATA, 0x1b4a0, 1, NULL); break;
		case 11: r_anal_xrefs_set (core->anal, 0x1de2c, 0x1de2f, R_ANAL_REF_TYPE_CODE); break;
		case 12: r_anal_hint_set_bits (core->anal, 0x1de30, 32); break;
		case 13: r_flag_set (core->flags, "tlink51_inline_text_de2f", 0x12345, 1); break;
		case 14: sdb_set (core->anal->sdb_types, "func.tlink51_copy_length_text.ret", "uint16_t", 0); sdb_set (core->anal->sdb_types, "tlink51_copy_length_text", "func", 0); break;
		case 15: sdb_set (core->anal->sdb_types, "struct.tlink51_InlineText7.text", "char,2,7", 0); break;
		case 16: consume->is_noreturn = true; break;
		case 17: mu_assert_notnull (r_io_open_at (core->io, "malloc://8", R_PERM_RWX, 0, 0x1de2f), "independent active map shadows original inline bytes"); break;
		case 18: changed_at = 0x1de2f; changed = 6; break;
		}
		if (changed_at) {
			r_config_set_b (core->config, "io.cache", true);
			mu_assert_true (r_io_write_at (core->io, changed_at, &changed, 1), "selected current virtual edit only; original remains read-only");
		}
		BorlandProfileContext ctx;
		mu_assert_true (tlink51_identity (core->anal, &ctx), "same original identity survives current byte/manual state changes");
		mu_assert_true (tlink51_query (core, true, false), "current mismatch/manual prerequisites visibly refuse all seven, readonly");
		if (!initial) {
			r_meta_del (core->anal, R_META_TYPE_COMMENT, 0x1de2c, 1);
		}
		mu_assert_true (tlink51_activate (core, false), "registered refusal, never repairs current state");
		mu_assert_false (tlink51_comment (core->anal, 0x1de2c, "CALL B4F0"), "dependent inline annotations withheld on prerequisite refusal");
		mu_assert_true (tlink51_query (core, true, false), "registered rerun never falsely restores stale qualification");
		if (changed_at) {
			ut8 current;
			mu_assert_true (r_io_read_at (core->io, changed_at, &current, 1), "current byte retained");
			mu_assert_eq (current, changed, "profile never repairs edits, including FILEf02f7->6");
		}
		if (initial) {
			mu_assert_null (r_anal_get_function_at (core->anal, 0x1ddf9), "initial prefix refusal creates no stale caller body");
			mu_assert_null (r_anal_get_function_at (core->anal, 0x1b4f0), "initial refusal stops jointly dependent helpers");
		} else {
			mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x1ddf9), shared, "existing caller object preserved, not replaced");
		}
		eprintf ("TLINK51 current/manual refusal scenario %d preserved; readonly query []\n", scenario);
		r_core_free (core);
	}
	mu_end;
}

static bool test_tlink51_metadata_spaces(void) {
	if (!getenv ("R2_TEST_TLINK51")) {
		mu_end;
	}
	int installed, other;
	for (installed = 0; installed < 2; installed++) {
		for (other = 0; other < 2; other++) {
			RCore *core = tlink51_core ();
			mu_assert_notnull (core, "actual original metadata-space witness");
			if (installed) {
				mu_assert_true (tlink51_activate (core, false), "valid original profile baseline before independent DATA");
				mu_assert_true (r_flag_unset_name (core->flags, "tlink51_source_record_setup"), "remove only the fixture's previously installed partial label");
			}
			RAnal *anal = core->anal;
			RAnalFunction *consume = r_anal_get_function_at (anal, 0x1b4f0), *shared = r_anal_get_function_at (anal, 0x1ddf9);
			RSpace *manual = r_spaces_set (&anal->meta_spaces, "manual");
			mu_assert_true (r_meta_set (anal, R_META_TYPE_DATA, 0x1b4f0, 2, "manual helper"), "independent definition at actual consumed-return helper");
			mu_assert_true (r_meta_set (anal, R_META_TYPE_DATA, 0x14f33, 2, "manual window"), "independent definition at actual partial window");
			r_meta_set_string (anal, R_META_TYPE_COMMENT, 0x1de2c, "manual call comment");
			RIntervalNode *helper = r_meta_get_in (anal, 0x1b4f0, R_META_TYPE_DATA), *window = r_meta_get_in (anal, 0x14f33, R_META_TYPE_DATA), *comment = r_meta_get_in (anal, 0x1de2c, R_META_TYPE_COMMENT);
			mu_assert_notnull (helper, "native helper DATA node");
			mu_assert_notnull (window, "native partial-window DATA node");
			mu_assert_notnull (comment, "native independent comment node");
			RSpace *selected = r_spaces_set (&anal->meta_spaces, other? "selected": "manual");
			mu_assert_true (tlink51_query (core, true, false), "same production preflight refuses readonly pairs regardless selected metadata space");
			mu_assert_ptreq (r_spaces_current (&anal->meta_spaces), selected, "readonly query preserves current metadata space");
			mu_assert_true (tlink51_activate (core, false), "unrelated original facts still apply");
			mu_assert_ptreq (r_spaces_current (&anal->meta_spaces), selected, "profile and window application preserve current metadata space");
			mu_assert_ptreq (r_anal_get_function_at (anal, 0x1b4f0), consume, "conflicting helper is neither created nor replaced");
			mu_assert_ptreq (r_anal_get_function_at (anal, 0x1ddf9), shared, "dependent caller is neither created nor replaced");
			mu_assert_null (r_flag_get (core->flags, "tlink51_source_record_setup"), "no dependent partial-code label");
			mu_assert_null (r_meta_get_string (anal, R_META_TYPE_COMMENT, 0x14f33), "no dependent partial-code comment in working space");
			mu_assert_notnull (r_anal_get_function_at (anal, 0x13c0b), "unrelated qualified writer remains available");
			RAnalMetaItem *helper_item = helper->data, *window_item = window->data;
			mu_assert_ptreq (helper_item->space, manual, "helper DATA ownership preserved");
			mu_assert_ptreq (window_item->space, manual, "partial-window DATA ownership preserved");
			mu_assert_eq (helper_item->type, R_META_TYPE_DATA, "helper DATA kind preserved");
			mu_assert_eq (window_item->type, R_META_TYPE_DATA, "partial-window DATA kind preserved");
			mu_assert_eq (helper_item->subtype, 0, "helper DATA subtype preserved");
			mu_assert_eq (window_item->subtype, 0, "partial-window DATA subtype preserved");
			mu_assert_eq (helper->start, 0x1b4f0, "helper DATA start preserved");
			mu_assert_eq (helper->end, 0x1b4f1, "helper DATA extent preserved");
			mu_assert_eq (window->start, 0x14f33, "window DATA start preserved");
			mu_assert_eq (window->end, 0x14f34, "window DATA extent preserved");
			mu_assert_streq (helper_item->str, "manual helper", "helper DATA content preserved");
			mu_assert_streq (window_item->str, "manual window", "window DATA content preserved");
			mu_assert_streq (((RAnalMetaItem *)comment->data)->str, "manual call comment", "refusal adds no dependent call comment");
			if (other) {
				mu_assert_null (r_meta_get_string (anal, R_META_TYPE_COMMENT, 0x1de2c), "no dependent call comment in selected space");
			}
			mu_assert_true (tlink51_query (core, true, false), "pairs remain withheld after registered reapply, without mutation");
			r_core_free (core);
		}
	}
	mu_end;
}

static bool test_tlink51_partial_refusal(void) {
	if (!getenv ("R2_TEST_TLINK51")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 4; scenario++) {
		RCore *core = tlink51_core ();
		mu_assert_notnull (core, "actual partial code input");
		RAnalBlock *independent = NULL;
		switch (scenario) {
		case 0: {
			ut8 changed = 0x90;
			r_config_set_b (core->config, "io.cache", true);
			mu_assert_true (r_io_write_at (core->io, 0x14f33, &changed, 1), "changed actual partial partition");
			break;
		}
		case 1: r_meta_set (core->anal, R_META_TYPE_DATA, 0x14f34, 2, NULL); break;
		case 2: r_flag_set (core->flags, "tlink51_source_record_setup", 0x12345, 1); break;
		case 3: {
			independent = r_anal_create_block (core->anal, 0x14f32, 3);
			mu_assert_notnull (independent, "independent straddling partial code block");
			break;
		}
		}
		mu_assert_true (tlink51_activate (core, false), "production applies other independent facts");
		mu_assert_false (tlink51_comment (core->anal, 0x14f33, "selected setup partition"), "canonical partial owner preserves byte/metadata/label/straddling block conflict");
		if (independent) {
			mu_assert_ptreq (r_anal_get_block_at (core->anal, 0x14f32), independent, "independent block remains live through production refusal");
			mu_assert_eq (independent->size, 3, "independent straddling extent preserved");
			r_unref (independent);
		}
		r_core_free (core);
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_tlink51_nonmatch);
	mu_run_test (test_tlink51_original_facts);
	mu_run_test (test_tlink51_current_and_manual_refusal);
	mu_run_test (test_tlink51_metadata_spaces);
	mu_run_test (test_tlink51_partial_refusal);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
