#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_tlink401_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland

static RCore *tlink401_core(void) {
	const char *path = getenv ("R2_TEST_TLINK401");
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "bin.relocs.apply", true);
	if (!path || !r_core_file_open (core, path, R_PERM_RX, 0) || !r_core_bin_load (core, path, UT64_MAX)) {
		r_core_free (core);
		return NULL;
	}
	r_config_set_b (core->config, "io.va", true);
	return core;
}

static bool tlink401_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "mz", 73401, "df1be38b22d43cc912992f1fcca93a5b630197721744ef2eea399f22d1415f0c");
}

static bool tlink401_comment(RAnal *anal, ut64 address, const char *text) {
	const char *comment = r_meta_get_string (anal, R_META_TYPE_COMMENT, address);
	return comment && strstr (comment, text);
}

static ut32 tlink401_reference(RAnal *anal, ut64 from, ut64 to) {
	RVecAnalRef *refs = r_anal_refs_get (anal, from);
	RAnalRef *ref;
	ut32 type = 0;
	if (refs) {
		R_VEC_FOREACH (refs, ref) {
			if (ref->addr == to) {
				type = ref->type;
			}
		}
	}
	RVecAnalRef_free (refs);
	return R_ANAL_REF_TYPE_MASK (type);
}

static bool tlink401_activate(RCore *core, bool pre, int *count) {
	if (pre) {
		mu_assert_streq (r_config_get (core->config, "anal.plugins.pre"), "", "unchanged default registered PRE selection");
		r_anal_plugin_action (core->anal, R_ANAL_PLUGIN_ACTION_PRE_ANALYSIS, NULL);
		eprintf ("Default registered TLINK401 PRE boundary invoked; downstream aaa is not claimed\n");
	} else {
		char *output = r_core_cmd_str (core, "a:borland");
		mu_assert_notnull (output, "registered RCore command output");
		mu_assert_eq (sscanf (output, "Borland: %d function contracts qualified", count), 1, "registered production count");
		eprintf ("Registered TLINK401 path: %s", output);
		free (output);
	}
	return true;
}

static bool test_tlink401_boolean_owner(void) {
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	RAnal *anal = core->anal;
	r_anal_types_prepare (anal);
	mu_assert_true (borland_type (anal, "bool"), "production bool owner independently admits atomic byte format b");
	mu_assert_null (sdb_const_get (anal->sdb_types, "FarPointerCompareAnalysisState9", NULL), "writer need not create unrelated comparison state");
	mu_assert_true (borland_type (anal, "NearWriterAnalysisState7"), "production writer return type");
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "NearWriterAnalysisState7"), 56, "seven byte packed state");
	ut64 epoch = r_anal_types_dirty_epoch (anal);
	mu_assert_true (borland_type (anal, "NearWriterAnalysisState7"), "equivalent state requalification");
	mu_assert_eq (r_anal_types_dirty_epoch (anal), epoch, "equivalent types not recreated");
	sdb_set (anal->sdb_types, "type.bool.size", "16", 0);
	mu_assert_false (borland_type (anal, "bool"), "independent incompatible bool rejected");
	mu_assert_false (borland_type (anal, "NearWriterAnalysisState7"), "dependent writer type rejected");
	mu_assert_false (borland_type (anal, "FarPointerCompareAnalysisState9"), "shared comparison owner still preserves incompatible bool");
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "bool"), 16, "independent bool unchanged");
	r_core_free (core);
	mu_end;
}

static bool test_tlink401_production_facts(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		eprintf ("TLINK401 original production fact proof skipped: set R2_TEST_TLINK401; no unobserved original or native decompiler integration is claimed\n");
		mu_end;
	}
	int pre;
	for (pre = 0; pre < 2; pre++) {
		RCore *core = tlink401_core ();
		mu_assert_notnull (core, "normally loaded read-only original");
		BorlandProfileContext ctx;
		mu_assert_true (tlink401_context (core, &ctx), "native MZ original identity");
		mu_assert_null (r_anal_get_function_at (core->anal, 0x3058), "no private function application before registered path");
		int count = 0;
		mu_assert_true (tlink401_activate (core, pre, &count), "registered route installs complete finite facts before any private fallback");
		const struct { ut64 file; int size; int instructions; const char *name; } expected[] = {
			{ 0x3458, 150, 51, "tlink401_rewrite_far_window_cf" },
			{ 0x3556, 204, 75, "tlink401_location_dispatch" },
			{ 0x6e8f, 411, 158, "tlink401_produce_entry_family" },
			{ 0x70fb, 44, 22, "tlink401_allocate_descriptor20" },
			{ 0x716e, 1003, 353, "tlink401_construct_family_descriptor" }
		};
		int i;
		for (i = 0; i < R_ARRAY_SIZE (expected); i++) {
			ut64 address = expected[i].file - 0x400;
			mu_assert_eq (profile_mapped (&ctx, expected[i].file, expected[i].size, true), address, "native resident mapping FILE=400+CS0 offset");
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, address);
			mu_assert_notnull (fcn, "all five native complete functions");
			mu_assert_streq (fcn->name, expected[i].name, "selected descriptive function name");
			mu_assert_eq (r_anal_function_realsize (fcn), expected[i].size, "complete body size");
			mu_assert_eq (r_anal_function_max_addr (fcn), address + expected[i].size, "complete exclusive terminal boundary");
			mu_assert_eq (fcn->meta.stack_pop, 0, "own argument purge zero");
			HelperOp *ops = calloc (expected[i].size, sizeof (HelperOp));
			mu_assert_true (profile_code (&ctx, expected[i].file, expected[i].size, address, ops), "production current byte/relocation/context qualification");
			BorlandCodeRange range = { address, expected[i].size, ops };
			mu_assert_true (borland_body_ranges (fcn, &range, 1), "exact complete native instruction/block/edge ownership, not size alone");
			int off = 0, instructions = 0;
			while (off < expected[i].size) {
				instructions++;
				off += ops[off].size;
			}
			mu_assert_eq (instructions, expected[i].instructions, "source established instruction count");
			free (ops);
			mu_assert_true (tlink401_comment (core->anal, address, "[LegacyToolchains tlink401-qualified]"), "complete function qualification");
		}
		RAnalFunction *writer = r_anal_get_function_at (core->anal, 0x3058);
		RAnalFunctionSignature *signature = r_anal_function_get_signature (writer);
		mu_assert_streq (signature->ret_type, "NearWriterAnalysisState7", "production return tuple, not fixture type construction");
		mu_assert_streq (signature->callconv, "tlink_writer_state_16near", "source established native model name");
		mu_assert_eq (r_list_length (signature->params), 4, "all four input WORDs");
		const char *names[] = { "entry_bx", "entry_cx", "entry_dx", "entry_ds" };
		for (i = 0; i < R_ARRAY_SIZE (names); i++) {
			RAnalFunctionParam *param = r_list_get_n (signature->params, i);
			mu_assert_streq (param->name, names[i], "ordered native input");
			mu_assert_streq (param->type, "uint16_t", "native WORD input");
		}
		r_anal_function_signature_free (signature);
		const HelperMember result[] = { { "accepted_cf", "bool", 0 }, { "dx", "uint16_t", 1 }, { "cx", "uint16_t", 3 }, { "es", "uint16_t", 5 } };
		const HelperMember descriptor[] = { { "kind", "uint8_t", 1 }, { "representative_entry_offset", "uint16_t", 4 }, { "descriptor_number", "uint16_t", 6 } };
		const HelperMember entry[] = { { "descriptor_offset", "uint16_t", 0 }, { "family_entry_offset", "uint16_t", 2 } };
		mu_assert_true (borland_record (core->anal, "NearWriterAnalysisState7", 56, result, R_ARRAY_SIZE (result)), "all result fields and offsets");
		mu_assert_true (borland_record (core->anal, "tlink401_Descriptor20Partial", 160, descriptor, R_ARRAY_SIZE (descriptor)), "independent 4.01 descriptor fields only");
		mu_assert_true (borland_record (core->anal, "tlink401_AssociatedEntry10Partial", 80, entry, R_ARRAY_SIZE (entry)), "independent 4.01 association fields only");
		mu_assert_null (sdb_const_get (core->anal->sdb_types, "FarPointerCompareAnalysisState9", NULL), "no unrelated comparison type");
		const struct { ut64 address; int size; const char *name; const char *text; } windows[] = {
			{ 0x363a, 365, "tlink401_frame50_selected_callers", "resolver finalCF is not writerCF" },
			{ 0xea, 75, "tlink401_mode_current_stores", "Parser mode is not a lifetime guarantee" },
			{ 0x574, 226, "tlink401_raw_option_dispatch", "no cross-release CLI equivalence" },
			{ 0x6fc, 119, "tlink401_selected_mode_option", "not final current0017 or historical configuration" },
			{ 0x8a6, 67, "tlink401_selected_uppercase_p_option", "No global absence-of-suppression conclusion" }
		};
		for (i = 0; i < R_ARRAY_SIZE (windows); i++) {
			RFlagItem *label = r_flag_get (core->flags, windows[i].name);
			mu_assert_notnull (label, "each of five partial window labels");
			mu_assert_eq (label->addr, windows[i].address, "native partial window coordinate");
			mu_assert_true (tlink401_comment (core->anal, label->addr, windows[i].text), "each selected window's independent limitation");
			RList *blocks = r_anal_get_blocks_intersect (core->anal, label->addr, windows[i].size);
			mu_assert_true (r_list_empty (blocks), "partial window never fabricated a function or basic block");
			r_list_free (blocks);
		}
		mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.00003146", NULL), "uint16_t [8]", "eight raw WORD dispatch cells");
		ut64 size;
		mu_assert_notnull (r_meta_get_at (core->anal, 0x3146, R_META_TYPE_DATA, &size), "table DATA separate from functions");
		mu_assert_eq (size, 16, "entire eight WORD table");
		const ut16 targets[] = { 0x31b2, 0x3166, 0x31b6, 0x3198, 0x31b2, 0x31aa, 0x31b2, 0x31b2 };
		for (i = 0; i < R_ARRAY_SIZE (targets); i++) {
			mu_assert_eq (tlink401_reference (core->anal, 0x3146 + 2 * i, targets[i]), R_ANAL_REF_TYPE_DATA, "all eight literal CS-relative DATA relations, including duplicates");
		}
		mu_assert_eq (tlink401_reference (core->anal, 0x31a5, 0x3058), R_ANAL_REF_TYPE_CALL, "actual location dispatcher near CALL");
		mu_assert_eq (tlink401_reference (core->anal, 0x370f, 0x3058), R_ANAL_REF_TYPE_CALL, "actual partial caller near CALL");
		mu_assert_true (tlink401_comment (core->anal, 0x370f, "returnedCF later overwritten"), "selected caller qualification");
		mu_assert_true (tlink401_comment (core->anal, 0x6ed1, "no universal equal-name iff equal-descriptor"), "selected ordinary reuse annotation");
		mu_assert_true (tlink401_comment (core->anal, 0x1ed, "DS0017 is not an initialized"), "startup paragraph out of initialized image");
		mu_assert_true (tlink401_comment (core->anal, 0x3146, "not FAR pointers or unconditional calls"), "selected table qualification");
		mu_assert_true (tlink401_comment (core->anal, 0x3058, "alias-sensitive ordering"), "complete shared writer limitations");
		RBinReloc *reloc;
		bool startup_relocation = false;
		R_VEC_FOREACH (ctx.file->bo->relocs, reloc) {
			startup_relocation |= reloc->paddr == 0x5ed && reloc->vaddr == 0x1ed && reloc->type == R_BIN_RELOC_16;
		}
		mu_assert_true (startup_relocation, "actual native MZ paragraph relocation record");
		mu_assert_eq (profile_mapped (&ctx, 0x11f27, 1, false), UT64_MAX, "DS11B1:0017 lies beyond immutable initialized file extent");
		mu_assert_null (r_type_link_at (core->anal->sdb_types, 0x11b27), "no invented DS0017 initialized object");
		RAnalBlock *block = r_list_first (writer->bbs);
		ut64 epoch = r_anal_types_dirty_epoch (core->anal);
		char *comment = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x3058));
		int functions = r_list_length (core->anal->fcns), labels = r_flag_count (core->flags, NULL);
		ut64 references = r_anal_xrefs_count (core->anal);
		int initial_count = count;
		mu_assert_true (tlink401_activate (core, pre, &count), "registered equivalent reapply");
		int repeated = 0;
		mu_assert_true (tlink401_activate (core, false, &repeated), "equivalent registered command after either route");
		mu_assert_true (repeated >= 5, "registered count includes all five exact functions");
		if (!pre) {
			mu_assert_eq (repeated, initial_count, "unchanged registered count");
		}
		mu_assert_eq (r_list_length (core->anal->fcns), functions, "registered rerun adds no duplicate functions");
		mu_assert_eq (r_flag_count (core->flags, NULL), labels, "registered rerun adds no duplicate labels");
		mu_assert_eq (r_anal_xrefs_count (core->anal), references, "registered rerun adds no duplicate references");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x3058), writer, "writer identity retained");
		mu_assert_ptreq (r_list_first (writer->bbs), block, "writer block identity retained");
		mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "no duplicated type or signature setter");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x3058), comment, "shared and profile comments idempotent");
		free (comment);
		r_core_free (core);
	}
	mu_end;
}

static bool test_tlink401_production_preservation(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		mu_end;
	}
	RCore *core = tlink401_core ();
	mu_assert_notnull (core, "actual production preserved prerequisite input");
	BorlandProfileContext ctx;
	mu_assert_true (tlink401_context (core, &ctx), "native preservation identity");
	mu_assert_true (borland_tlink_writer (&ctx, 0x3458, "tlink401_rewrite_far_window_cf", NULL), "only shared writer fixture from actual original");
	RAnalFunction *writer = r_anal_get_function_at (core->anal, 0x3058);
	r_anal_function_rename (writer, "manual_writer");
	r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x3058, "manual writer comment");
	mu_assert_eq (borland_tlink401_profile (core->anal), 4, "production refuses independently named writer only");
	mu_assert_streq (writer->name, "manual_writer", "independent writer name retained");
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x3058), "manual writer comment", "no dependent writer contract comment");
	mu_assert_false (tlink401_comment (core->anal, 0x370f, "Actual selected near CALL"), "writer refusal stops dependent caller contract");
	mu_assert_eq (tlink401_reference (core->anal, 0x370f, 0x3058), 0, "writer refusal stops partial-window CALL relation");
	r_core_free (core);
	core = tlink401_core ();
	mu_assert_notnull (core, "real independent type and table input");
	r_anal_types_prepare (core->anal);
	mu_assert_true (borland_type (core->anal, "NearWriterAnalysisState7"), "real writer type before independent edit");
	sdb_set (core->anal->sdb_types, "struct.NearWriterAnalysisState7.dx", "uint16_t,2,0", 0);
	mu_assert_true (r_anal_types_set_link (core->anal, "uint16_t *", 0x3146), "independent pointer interpretation");
	r_meta_set (core->anal, R_META_TYPE_DATA, 0x3146, 2, NULL);
	RAnalMetaItem *data = r_meta_get_at (core->anal, 0x3146, R_META_TYPE_DATA, NULL);
	r_anal_xrefs_set (core->anal, 0x3146, 0x31b2, R_ANAL_REF_TYPE_CODE);
	mu_assert_eq (borland_tlink401_profile (core->anal), 4, "incompatible result record blocks writer creation");
	mu_assert_null (r_anal_get_function_at (core->anal, 0x3058), "no dependent writer function after type conflict");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "struct.NearWriterAnalysisState7.dx", NULL), "uint16_t,2,0", "independent field layout retained");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.00003146", NULL), "uint16_t *", "independent table type retained");
	mu_assert_ptreq (r_meta_get_at (core->anal, 0x3146, R_META_TYPE_DATA, NULL), data, "independent DATA cell retained");
	mu_assert_eq (tlink401_reference (core->anal, 0x3146, 0x31b2), R_ANAL_REF_TYPE_CODE, "independent relation not converted to DATA");
	mu_assert_null (r_flag_get (core->flags, "tlink401_location_dispatch_words8"), "table conflict stops dependent label");
	mu_assert_eq (tlink401_reference (core->anal, 0x3148, 0x3166), 0, "table conflict stops dependent cells");
	r_core_free (core);
	core = tlink401_core ();
	mu_assert_notnull (core, "real standalone cell-reference conflict");
	r_anal_xrefs_set (core->anal, 0x314c, 0x3198, R_ANAL_REF_TYPE_CODE);
	mu_assert_eq (borland_tlink401_profile (core->anal), 5, "independent unrelated functions survive reference conflict");
	mu_assert_eq (tlink401_reference (core->anal, 0x314c, 0x3198), R_ANAL_REF_TYPE_CODE, "conflicting cell relation retained");
	mu_assert_eq (tlink401_reference (core->anal, 0x314e, 0x31b2), R_ANAL_REF_TYPE_DATA, "independent valid cell still qualified");
	r_core_free (core);
	mu_end;
}

static bool test_tlink401_partial_window_preservation(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		mu_end;
	}
	// Current-byte, context, flow, DATA and label conflicts at the actual partial window boundary.
	int scenario;
	for (scenario = 0; scenario < 5; scenario++) {
		RCore *core = tlink401_core ();
		mu_assert_notnull (core, "normally loaded real partial-code input");
		BorlandProfileContext ctx;
		mu_assert_true (tlink401_context (core, &ctx), "partial-code original identity");
		ut8 original;
		r_io_read_at (core->io, 0x363a, &original, 1);
		RAnalBlock *bb = NULL;
		RAnalMetaItem *data = NULL;
		switch (scenario) {
		case 0: {
			ut8 changed = original ^ 1;
			core->anal->iob.overlay_write_at (core->io, 0x363a, &changed, 1);
			break;
		}
		case 1: r_anal_hint_set_bits (core->anal, 0x363b, 32); r_anal_hint_set_bits (core->anal, 0x363c, 16); break;
		case 2:
			bb = r_anal_create_block (core->anal, 0x363a, 1);
			bb->ninstr = 1;
			bb->jump = 0x363b;
			break;
		case 3:
			r_meta_set (core->anal, R_META_TYPE_DATA, 0x363a, 2, NULL);
			data = r_meta_get_at (core->anal, 0x363a, R_META_TYPE_DATA, NULL);
			break;
		case 4: r_flag_set (core->flags, "tlink401_frame50_selected_callers", 0x363b, 1); break;
		}
		mu_assert_eq (borland_tlink401_profile (core->anal), 5, "independent complete functions still qualify");
		mu_assert_false (tlink401_comment (core->anal, 0x363a, "[LegacyToolchains tlink401-qualified]"), "no dependent partial-code annotation after conflict");
		mu_assert_false (tlink401_comment (core->anal, 0x370f, "Actual selected near CALL"), "no dependent caller contract after partial refusal");
		mu_assert_eq (tlink401_reference (core->anal, 0x370f, 0x3058), 0, "no dependent partial caller relation");
		mu_assert_null (r_anal_get_function_at (core->anal, 0x363a), "no manufactured partial function");
		if (!scenario) {
			ut8 current;
			r_io_read_at (core->io, 0x363a, &current, 1);
			mu_assert_eq (current, original ^ 1, "current byte retained");
		} else if (scenario == 1) {
			mu_assert_eq (r_anal_hint_bits_at (core->anal, 0x363b, NULL), 32, "interior context retained");
		} else if (scenario == 2) {
			mu_assert_eq (bb->size, 1, "independent block body retained");
			mu_assert_eq (bb->jump, 0x363b, "independent flow retained");
			r_unref (bb);
		} else if (scenario == 3) {
			mu_assert_ptreq (r_meta_get_at (core->anal, 0x363a, R_META_TYPE_DATA, NULL), data, "independent partial DATA retained");
		} else {
			mu_assert_eq (r_flag_get (core->flags, "tlink401_frame50_selected_callers")->addr, 0x363b, "independent label retained");
		}
		r_core_free (core);
	}
	mu_end;
}

static bool test_tlink401_registered_refusal(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		mu_end;
	}
	int pre;
	for (pre = 0; pre < 2; pre++) {
		RCore *core = tlink401_core ();
		mu_assert_notnull (core, "registered preservation original");
		int count = 0;
		mu_assert_true (tlink401_activate (core, pre, &count), "actual initial registered application");
		RAnalFunction *writer = r_anal_get_function_at (core->anal, 0x3058);
		mu_assert_notnull (writer, "registered writer before manual state");
		RAnalBlock *block = r_list_first (writer->bbs);
		r_anal_function_rename (writer, "manual_registered_writer");
		writer->meta.stack_pop = 26;
		RAnalFunctionSignature signature = { .ret_type = "uint16_t", .params = r_list_new () };
		mu_assert_true (r_anal_function_set_signature (core->anal, writer, &signature), "independent canonical native prototype");
		r_list_free (signature.params);
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x3058, "manual registered writer");
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x370f, "manual registered caller");
		mu_assert_true (tlink401_activate (core, pre, &count), "registered route preserves manual state");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x3058), writer, "same independently edited writer");
		mu_assert_ptreq (r_list_first (writer->bbs), block, "same independent body");
		mu_assert_streq (writer->name, "manual_registered_writer", "independent registered name retained");
		mu_assert_eq (writer->meta.stack_pop, 26, "independent registered purge retained");
		RAnalFunctionSignature *actual = r_anal_function_get_signature (writer);
		mu_assert_streq (actual->ret_type, "uint16_t", "independent registered prototype retained");
		r_anal_function_signature_free (actual);
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x3058), "manual registered writer", "refused registered writer gets no dependent comment");
		mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x370f), "manual registered caller", "refused registered writer stops dependent caller annotation");
		r_core_free (core);
		core = tlink401_core ();
		mu_assert_notnull (core, "registered current-byte refusal original");
		ut8 original;
		mu_assert_true (r_io_read_at (core->io, 0x363a, &original, 1), "actual partial window byte");
		ut8 changed = original ^ 1;
		mu_assert_eq (core->anal->iob.overlay_write_at (core->io, 0x363a, &changed, 1), 1, "independent current partial-code edit");
		mu_assert_true (r_io_read_at (core->io, 0x3155, &original, 1), "actual table last byte");
		ut8 table_byte = original ^ 1;
		mu_assert_eq (core->anal->iob.overlay_write_at (core->io, 0x3155, &table_byte, 1), 1, "independent current table-tail edit");
		mu_assert_true (tlink401_activate (core, pre, &count), "registered route refuses edited current inputs");
		mu_assert_notnull (r_anal_get_function_at (core->anal, 0x3058), "independent writer remains qualified");
		mu_assert_null (r_flag_get (core->flags, "tlink401_frame50_selected_callers"), "current partial-code refusal stops label");
		mu_assert_false (tlink401_comment (core->anal, 0x370f, "Actual selected near CALL"), "current partial-code refusal stops dependent caller contract");
		mu_assert_eq (tlink401_reference (core->anal, 0x370f, 0x3058), 0, "current partial-code refusal stops CALL relation");
		mu_assert_null (r_flag_get (core->flags, "tlink401_location_dispatch_words8"), "current table refusal stops label");
		mu_assert_null (sdb_const_get (core->anal->sdb_types, "link.00003146", NULL), "current table refusal stops type link");
		mu_assert_eq (tlink401_reference (core->anal, 0x3146, 0x31b2), 0, "current table refusal stops dependent relation");
		ut8 current;
		mu_assert_true (r_io_read_at (core->io, 0x363a, &current, 1), "current partial-code byte remains readable");
		mu_assert_eq (current, changed, "registered route does not repair current code");
		mu_assert_true (r_io_read_at (core->io, 0x3155, &current, 1), "current table byte remains readable");
		mu_assert_eq (current, table_byte, "registered route does not repair current table");
		r_core_free (core);
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_tlink401_boolean_owner);
	mu_run_test (test_tlink401_production_facts);
	mu_run_test (test_tlink401_production_preservation);
	mu_run_test (test_tlink401_partial_window_preservation);
	mu_run_test (test_tlink401_registered_refusal);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
