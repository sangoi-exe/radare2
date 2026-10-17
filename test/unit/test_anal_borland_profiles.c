#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_profile_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland

#define PROFILE_ADDR 0x10000
#define PROFILE_NAME "qualified_test_profile"

static BorlandProfileContext local_profile(void) {
	RCore *core = r_core_new ();
	core->io->va = true;
	RIODesc *desc = r_io_open_at (core->io, "malloc://64", R_PERM_RWX, 0, PROFILE_ADDR);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	ut8 bytes[64] = { 0x55, 0x8b, 0xec, 0x74, 0x01, 0x90, 0x5d, 0xcb };
	r_io_write_at (core->io, PROFILE_ADDR, bytes, sizeof (bytes));
	desc->perm = R_PERM_R;
	static RBinPlugin plugin = { .meta = { .name = "ne" } };
	RBinFile *file = R_NEW0 (RBinFile);
	file->bo = R_NEW0 (RBinObject);
	file->bo->plugin = &plugin;
	file->bo->relocs = RVecRBinReloc_new ();
	file->buf = r_buf_new_with_bytes (bytes, sizeof (bytes));
	file->fd = desc->fd;
	file->sdb_info = sdb_new0 ();
	file->rbin = core->bin;
	core->bin->cur = file;
	RVecRBinSection_init (&file->bo->sections_vec);
	RBinSection *section = RVecRBinSection_emplace_back (&file->bo->sections_vec);
	section->name = strdup ("code");
	section->vaddr = PROFILE_ADDR;
	section->size = section->vsize = sizeof (bytes);
	section->perm = R_PERM_RX;
	sdb_num_set (file->sdb_info, "ne.reloc.1.count", 0, 0);
	return (BorlandProfileContext){ core->anal, file, file->sdb_info };
}

static void local_free(BorlandProfileContext *ctx) {
	RCore *core = ctx->anal->coreb.core;
	core->bin->cur = NULL;
	r_unref (ctx->file->buf);
	sdb_free (ctx->ne);
	RVecRBinReloc_free (ctx->file->bo->relocs);
	RVecRBinSection_fini (&ctx->file->bo->sections_vec);
	free (ctx->file->bo);
	free (ctx->file);
	r_core_free (core);
}

static bool local_apply(BorlandProfileContext *ctx, bool known_zero) {
	return profile_function (ctx, 0, 8, PROFILE_NAME, known_zero, "qualified local extent; no modern ABI");
}

static int reference_type(RAnal *anal, ut64 from, ut64 to) {
	RVecAnalRef *refs = r_anal_refs_get (anal, from);
	int type = 0;
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			if (ref->addr == to) {
				type = ref->type;
			}
		}
	}
	RVecAnalRef_free (refs);
	return type;
}

static bool test_profile_identity_and_current(void) {
	BorlandProfileContext ctx = local_profile ();
	ut8 original[64];
	r_buf_read_at (ctx.file->buf, 0, original, sizeof (original));
	int digest_size;
	ut8 *digest = ctx.anal->mb.hash (&ctx.anal->mb, "sha256", original, sizeof (original), &digest_size);
	mu_assert_eq (digest_size, 32, "native hash callback");
	char sha[65];
	r_hex_bin2str (digest, digest_size, sha);
	free (digest);
	BorlandProfileContext matched;
	mu_assert_true (profile_identity (ctx.anal, &matched, "ne", 64, sha), "local original identity");
	mu_assert_false (profile_identity (ctx.anal, &matched, "mz", 64, sha), "format gate");
	mu_assert_false (profile_identity (ctx.anal, &matched, "ne", 63, sha), "size gate");
	mu_assert_false (profile_identity (ctx.anal, &matched, "ne", 64, "wrong"), "full hash gate");
	ut8 patched = 0x90;
	ctx.anal->iob.overlay_write_at (ctx.anal->iob.io, PROFILE_ADDR, &patched, 1);
	mu_assert_true (profile_identity (ctx.anal, &matched, "ne", 64, sha), "virtual patch is not original identity");
	mu_assert_false (local_apply (&ctx, true), "current patch refuses body");
	mu_assert_null (r_anal_get_function_at (ctx.anal, PROFILE_ADDR), "refusal creates nothing");
	local_free (&ctx);
	mu_end;
}

static bool test_profile_body_and_additive_state(void) {
	BorlandProfileContext ctx = local_profile ();
	r_meta_set_string (ctx.anal, R_META_TYPE_COMMENT, PROFILE_ADDR, "manual comment");
	r_anal_xrefs_set (ctx.anal, PROFILE_ADDR + 3, PROFILE_ADDR + 6, R_ANAL_REF_TYPE_DATA);
	int previous_ref = reference_type (ctx.anal, PROFILE_ADDR + 3, PROFILE_ADDR + 6);
	mu_assert_true (local_apply (&ctx, true), "qualified local function");
	RAnalFunction *fcn = r_anal_get_function_at (ctx.anal, PROFILE_ADDR);
	mu_assert_notnull (fcn, "function created");
	mu_assert_eq (r_anal_function_realsize (fcn), 8, "complete body");
	mu_assert_eq (r_anal_function_max_addr (fcn), PROFILE_ADDR + 8, "exact end");
	mu_assert_eq (fcn->meta.stack_pop, 0, "qualified known own purge");
	mu_assert_eq (reference_type (ctx.anal, PROFILE_ADDR + 3, PROFILE_ADDR + 6), previous_ref, "different same-pair reference type and permissions preserved");
	char *comment = strdup (r_meta_get_string (ctx.anal, R_META_TYPE_COMMENT, PROFILE_ADDR));
	mu_assert_notnull (strstr (comment, "manual comment"), "manual text retained");
	mu_assert_true (local_apply (&ctx, true), "equivalent rerun");
	mu_assert_streq (r_meta_get_string (ctx.anal, R_META_TYPE_COMMENT, PROFILE_ADDR), comment, "comment idempotence");
	mu_assert_ptreq (r_anal_get_function_at (ctx.anal, PROFILE_ADDR), fcn, "function not recreated");
	free (comment);
	local_free (&ctx);
	mu_end;
}

static bool test_profile_independent_conflicts(void) {
	int scenario;
	for (scenario = 0; scenario < 11; scenario++) {
		BorlandProfileContext ctx = local_profile ();
		mu_assert_true (local_apply (&ctx, true), "initial local body");
		RAnalFunction *fcn = r_anal_get_function_at (ctx.anal, PROFILE_ADDR);
		RAnalBlock *bb = r_list_first (fcn->bbs);
		switch (scenario) {
		case 0: r_anal_function_rename (fcn, "manual_name"); break;
		case 1: bb->size--; break;
		case 2: fcn->meta.stack_pop = 8; break;
		case 3: bb->jump = PROFILE_ADDR + 7; break;
		case 4: r_anal_hint_set_size (ctx.anal, PROFILE_ADDR + 1, 1); break;
		case 5: r_anal_hint_set_bits (ctx.anal, PROFILE_ADDR + 2, 32); r_anal_hint_set_bits (ctx.anal, PROFILE_ADDR + 3, 16); break;
		case 6: r_anal_hint_set_arch (ctx.anal, PROFILE_ADDR + 2, "arm"); r_anal_hint_set_arch (ctx.anal, PROFILE_ADDR + 3, "x86"); break;
		case 7: r_meta_set (ctx.anal, R_META_TYPE_DATA, PROFILE_ADDR + 2, 2, "manual data"); break;
		case 8: r_anal_hint_set_pointer (ctx.anal, PROFILE_ADDR + 1, 0); break;
		case 9: {
			RAnalFunction *other = r_anal_create_function (ctx.anal, "independent_owner", PROFILE_ADDR + 32, R_ANAL_FCN_TYPE_FCN, NULL);
			r_anal_function_add_block (other, bb);
			break;
		}
		case 10: r_anal_bb_set_offset (bb, 1, 2); break;
		}
		ut64 block_size = bb->size, jump = bb->jump;
		int pop = fcn->meta.stack_pop;
		char *name = strdup (fcn->name);
		mu_assert_false (local_apply (&ctx, true), "independent conflict refused");
		mu_assert_streq (fcn->name, name, "name preserved");
		mu_assert_eq (bb->size, block_size, "block extent preserved");
		mu_assert_eq (bb->jump, jump, "flow preserved");
		mu_assert_eq (fcn->meta.stack_pop, pop, "cleanup preserved");
		free (name);
		local_free (&ctx);
	}
	mu_end;
}

static bool test_profile_relocation_limits(void) {
	int scenario;
	for (scenario = 0; scenario < 6; scenario++) {
		BorlandProfileContext ctx = local_profile ();
		if (scenario < 4) {
			RBinReloc *reloc = RVecRBinReloc_emplace_back (ctx.file->bo->relocs);
			reloc->type = R_BIN_RELOC_32;
			reloc->ntype = 3;
			reloc->paddr = scenario == 0? 5: 0;
			reloc->vaddr = PROFILE_ADDR + reloc->paddr;
			reloc->addend = r_buf_read_le32_at (ctx.file->buf, reloc->paddr);
			if (scenario == 1) {
				reloc->ntype = 13;
			} else if (scenario == 2) {
				RBinReloc duplicate = *reloc;
				RVecRBinReloc_push_back (ctx.file->bo->relocs, &duplicate);
			} else if (scenario == 3) {
				reloc->addend = UT64_MAX;
			}
		} else if (scenario == 4) {
			sdb_num_set (ctx.ne, "ne.reloc.1.count", 1, 0);
			sdb_num_set (ctx.ne, "ne.reloc.1.0.application_count", 0, 0);
		} else {
			RBinSection *section = RVecRBinSection_emplace_back (&ctx.file->bo->sections_vec);
			section->paddr = 2;
			section->vaddr = PROFILE_ADDR + 0x100;
			section->size = section->vsize = 2;
		}
		mu_assert_false (local_apply (&ctx, true), "partial, unsupported, overlapping, unresolved or ambiguous native fields refuse");
		mu_assert_null (r_anal_get_function_at (ctx.anal, PROFILE_ADDR), "field refusal has no function side effect");
		local_free (&ctx);
	}
	mu_end;
}

static bool test_profile_unknown_is_no_override(void) {
	BorlandProfileContext ctx = local_profile ();
	mu_assert_true (local_apply (&ctx, false), "unknown source supplies body only");
	RAnalFunction *fcn = r_anal_get_function_at (ctx.anal, PROFILE_ADDR);
	const char *cc = fcn->callconv;
	fcn->meta.stack_pop = 8;
	mu_assert_true (local_apply (&ctx, false), "no source cleanup override");
	mu_assert_eq (fcn->meta.stack_pop, 8, "independent inferred cleanup retained");
	mu_assert_ptreq (fcn->callconv, cc, "no fabricated convention");
	local_free (&ctx);
	mu_end;
}

static bool test_profile_mapping_preservation(void) {
	int scenario;
	for (scenario = 0; scenario < 4; scenario++) {
		BorlandProfileContext ctx = local_profile ();
		mu_assert_eq (profile_mapped (&ctx, 0, 8, true), PROFILE_ADDR, "canonical map");
		if (scenario == 0) {
			r_io_map_add (ctx.anal->iob.io, ctx.file->fd, R_PERM_RX, 0, PROFILE_ADDR + 0x100, 64);
		} else if (scenario == 1) {
			r_io_open_at (ctx.anal->iob.io, "malloc://1", R_PERM_RWX, 0, PROFILE_ADDR + 2);
		} else if (scenario == 2) {
			RBinSection *section = RVecRBinSection_emplace_back (&ctx.file->bo->sections_vec);
			section->vaddr = PROFILE_ADDR + 0x100;
			section->size = section->vsize = 64;
		} else {
			RAnalFunction *fcn = r_anal_create_function (ctx.anal, "manual_interior_entry", PROFILE_ADDR + 2, R_ANAL_FCN_TYPE_FCN, NULL);
			mu_assert_notnull (fcn, "independent empty entry");
		}
		mu_assert_false (local_apply (&ctx, true), "alias, descriptor, section or empty interior entry refuses");
		mu_assert_null (r_anal_get_function_at (ctx.anal, PROFILE_ADDR), "no partial function");
		local_free (&ctx);
	}
	mu_end;
}

static RCore *original_core(void) {
	const char *path = getenv ("R2_TEST_SCRANTIC");
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

static bool test_scrantic_production(void) {
	if (!getenv ("R2_TEST_SCRANTIC")) {
		eprintf ("SCRANTIC original proof not run: set R2_TEST_SCRANTIC to the read-only original\n");
		mu_end;
	}
	RCore *core = original_core ();
	mu_assert_notnull (core, "real native original load");
	r_config_set (core->config, "anal.plugins.pre", "borland");
	r_anal_plugin_action (core->anal, R_ANAL_PLUGIN_ACTION_PRE_ANALYSIS, NULL);
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (scrantic_functions); i++) {
		ut64 addr = 0x10000 + scrantic_functions[i].start - 0x800;
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, addr);
		mu_assert_notnull (fcn, "automatic profile function");
		mu_assert_streq (fcn->name, scrantic_functions[i].name, "qualified, nonhistorical name");
		mu_assert_eq (r_anal_function_realsize (fcn), scrantic_functions[i].end - scrantic_functions[i].start, "complete original extent");
		mu_assert_eq (r_anal_function_max_addr (fcn), addr + scrantic_functions[i].end - scrantic_functions[i].start, "exact exclusive end");
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
		mu_assert_notnull (comment, "qualified provenance");
		if (i >= 3) {
			mu_assert_notnull (strstr (comment, "no proved net-cleanup override"), "source uncertainty retained");
		}
	}
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x126e3, 0xd07e5)), R_ANAL_REF_TYPE_DATA, "first exact FAR DATA binding");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x12798, 0xd0962)), R_ANAL_REF_TYPE_DATA, "second exact FAR DATA binding");
	for (i = 0; i < R_ARRAY_SIZE (scrantic_annotations); i++) {
		BorlandProfileContext ctx = { core->anal, core->bin->cur, NULL };
		ut64 addr = profile_mapped (&ctx, scrantic_annotations[i].physical, 1, false);
		mu_assert_notnull (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr), "every selected annotation");
		if (scrantic_annotations[i].name) {
			RFlagItem *flag = r_flag_get (core->flags, scrantic_annotations[i].name);
			mu_assert_notnull (flag, "every selected label");
			mu_assert_eq (flag->addr, addr, "label coordinate");
		}
	}
	RAnalFunction *unknown = r_anal_get_function_at (core->anal, 0x1229c);
	unknown->meta.stack_pop = 8;
	const char *cc = unknown->callconv;
	r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x105e2, "manual original comment");
	char *output = r_anal_cmd (core->anal, "borland");
	mu_assert_notnull (output, "real explicit production entry");
	free (output);
	mu_assert_eq (unknown->meta.stack_pop, 8, "source UNKNOWN does not reset native inference");
	mu_assert_ptreq (unknown->callconv, cc, "no fake heap convention");
	mu_assert_notnull (strstr (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x105e2), "manual original comment"), "original manual comment appended, not replaced");
	char *comment = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x105e2));
	output = r_anal_cmd (core->anal, "borland");
	free (output);
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x105e2), comment, "original rerun idempotence");
	free (comment);
	r_core_free (core);
	mu_end;
}

static bool test_scrantic_production_preservation(void) {
	if (!getenv ("R2_TEST_SCRANTIC")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 7; scenario++) {
		RCore *core = original_core ();
		mu_assert_notnull (core, "real read-only preservation input");
		BorlandProfileContext ctx;
		mu_assert_true (profile_identity (core->anal, &ctx, "ne", 295952, "f0552c281a2a9b367ad5f41402a907a3c99e73ad0a221ba14d063e31cff594ac"), "literal original identity");
		mu_assert_true (profile_function (&ctx, 0x2eb8, 73, scrantic_functions[1].name, true, scrantic_functions[1].comment), "qualified initial FHEAP73 body");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x126b8);
		RAnalBlock *bb = r_list_first (fcn->bbs);
		switch (scenario) {
		case 0: r_anal_function_rename (fcn, "manual_fheap73"); break;
		case 1: bb->size--; break;
		case 2: fcn->meta.stack_pop = 8; break;
		case 3: r_anal_hint_set_bits (core->anal, 0x126bb, 32); r_anal_hint_set_bits (core->anal, 0x126bc, 16); break;
		case 4: {
			ut8 patched = 0x90;
			core->anal->iob.overlay_write_at (core->io, 0x126b8, &patched, 1);
			break;
		}
		case 5: bb->jump = 0x126b9; break;
		case 6: r_flag_set (core->flags, scrantic_functions[1].name, 0x126b9, 99); break;
		}
		ut64 size = bb->size, jump = bb->jump;
		int pop = fcn->meta.stack_pop;
		int original_ref = reference_type (core->anal, 0x126e3, 0xd07e5);
		char *name = strdup (fcn->name);
		char *output = r_anal_cmd (core->anal, "borland");
		mu_assert_notnull (output, "actual production refusal path");
		free (output);
		mu_assert_streq (fcn->name, name, "original manual name retained");
		mu_assert_eq (fcn->meta.stack_pop, pop, "original manual cleanup retained");
		mu_assert_eq (bb->size, size, "original body retained");
		mu_assert_eq (bb->jump, jump, "original flow retained");
		mu_assert_null (r_flag_get (core->flags, "scrantic_fheap_getmem_binding"), "refused prerequisite stops field label");
		mu_assert_null (r_flag_get (core->flags, "scrantic_fheap_subordinate_13_07e5"), "refused prerequisite stops target label");
		mu_assert_eq (reference_type (core->anal, 0x126e3, 0xd07e5), original_ref, "refusal preserves preexisting native loader reference");
		free (name);
		r_core_free (core);
	}
	RCore *core = original_core ();
	mu_assert_notnull (core, "real read-only independent reference input");
	r_anal_xrefs_set (core->anal, 0x126e3, 0xd07e5, R_ANAL_REF_TYPE_CODE);
	r_anal_xrefs_set (core->anal, 0x126e3, 0xd07e6, R_ANAL_REF_TYPE_DATA);
	int previous_code = reference_type (core->anal, 0x126e3, 0xd07e5);
	int previous_data = reference_type (core->anal, 0x126e3, 0xd07e6);
	char *output = r_anal_cmd (core->anal, "borland");
	free (output);
	mu_assert_eq (reference_type (core->anal, 0x126e3, 0xd07e5), previous_code, "same-pair independent reference not retyped");
	mu_assert_eq (reference_type (core->anal, 0x126e3, 0xd07e6), previous_data, "other independent reference retained");
	mu_assert_null (r_flag_get (core->flags, "scrantic_fheap_getmem_binding"), "preserved conflicting reference stops dependent binding label");
	mu_assert_null (r_flag_get (core->flags, "scrantic_fheap_subordinate_13_07e5"), "preserved conflicting reference stops dependent target label");
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_profile_identity_and_current);
	mu_run_test (test_profile_body_and_additive_state);
	mu_run_test (test_profile_independent_conflicts);
	mu_run_test (test_profile_unknown_is_no_override);
	mu_run_test (test_profile_mapping_preservation);
	mu_run_test (test_profile_relocation_limits);
	mu_run_test (test_scrantic_production);
	mu_run_test (test_scrantic_production_preservation);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
