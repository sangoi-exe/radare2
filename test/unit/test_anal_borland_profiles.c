#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_profile_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland

#define PROFILE_ADDR 0x100000000ULL
#define PROFILE_NAME "qualified_test_profile"

static BorlandProfileContext local_profile_bytes(const ut8 *bytes, int size) {
	RCore *core = r_core_new ();
	core->io->va = true;
	char *uri = r_str_newf ("malloc://%d", size);
	RIODesc *desc = r_io_open_at (core->io, uri, R_PERM_RWX, 0, PROFILE_ADDR);
	free (uri);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	r_config_set_i (core->config, "asm.addr.segment.bits", 32);
	r_io_write_at (core->io, PROFILE_ADDR, bytes, size);
	desc->perm = R_PERM_R;
	static RBinPlugin plugin = { .meta = { .name = "ne" } };
	RBinFile *file = R_NEW0 (RBinFile);
	file->bo = R_NEW0 (RBinObject);
	file->bo->plugin = &plugin;
	file->bo->relocs = RVecRBinReloc_new ();
	file->buf = r_buf_new_with_bytes (bytes, size);
	file->fd = desc->fd;
	file->sdb_info = sdb_new0 ();
	file->rbin = core->bin;
	core->bin->cur = file;
	RVecRBinSection_init (&file->bo->sections_vec);
	RBinSection *section = RVecRBinSection_emplace_back (&file->bo->sections_vec);
	section->name = strdup ("code");
	section->vaddr = PROFILE_ADDR;
	section->size = section->vsize = size;
	section->perm = R_PERM_RX;
	section->add = true;
	sdb_num_set (file->sdb_info, "ne.reloc.1.count", 0, 0);
	return (BorlandProfileContext){ core->anal, file, file->sdb_info };
}

static BorlandProfileContext local_profile(void) {
	ut8 bytes[64] = { 0x55, 0x8b, 0xec, 0x74, 0x01, 0x90, 0x5d, 0xcb };
	return local_profile_bytes (bytes, sizeof (bytes));
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
	return profile_function (ctx, 0, 8, PROFILE_NAME, known_zero? 0: R_ANAL_CC_STACK_POP_UNKNOWN, "qualified local extent; no modern ABI");
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
			section->add = true;
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
			section->add = true;
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

static bool test_profile_current_without_code(void) {
	BorlandProfileContext ctx = local_profile ();
	ut8 current[64];
	HelperOp ops[64];
	mu_assert_true (profile_current (&ctx, 0, 64, PROFILE_ADDR, current), "raw current bytes qualify without complete instruction coverage");
	mu_assert_false (profile_code (&ctx, 63, 1, PROFILE_ADDR + 63, ops), "one trailing opcode byte is not a complete instruction");
	mu_assert_true (profile_current (&ctx, 63, 1, PROFILE_ADDR + 63, current), "same partial observation qualifies as bytes only");
	mu_assert_null (r_anal_get_function_at (ctx.anal, PROFILE_ADDR), "byte/code qualification creates no function");
	r_anal_hint_set_bits (ctx.anal, PROFILE_ADDR + 63, 32);
	mu_assert_false (profile_current (&ctx, 0, 64, PROFILE_ADDR, current), "byte-only observations retain internal context checks");
	mu_assert_true (profile_code (&ctx, 0, 8, PROFILE_ADDR, ops), "context beyond the selected window is not its context");
	r_anal_hint_set_bits (ctx.anal, PROFILE_ADDR + 3, 32);
	mu_assert_false (profile_code (&ctx, 0, 8, PROFILE_ADDR, ops), "code uses the same interior context refusal");
	local_free (&ctx);
	mu_end;
}

static bool test_profile_long_body_and_integer_purge(void) {
	static const int purges[] = { 6, 10, 12 };
	int i;
	for (i = 0; i < R_ARRAY_SIZE (purges); i++) {
		ut8 bytes[256];
		memset (bytes, 0x90, sizeof (bytes));
		bytes[253] = 0xc2;
		bytes[254] = purges[i];
		bytes[255] = 0;
		BorlandProfileContext ctx = local_profile_bytes (bytes, sizeof (bytes));
		mu_assert_true (profile_function (&ctx, 0, sizeof (bytes), PROFILE_NAME, purges[i], NULL), "long complete body with exact integer purge");
		RAnalFunction *fcn = r_anal_get_function_at (ctx.anal, PROFILE_ADDR);
		mu_assert_eq (r_anal_function_realsize (fcn), sizeof (bytes), "body has no 128-byte ceiling");
		mu_assert_eq (fcn->meta.stack_pop, purges[i], "known nonzero purge");
		mu_assert_true (profile_function (&ctx, 0, sizeof (bytes), PROFILE_NAME, purges[i], NULL), "long body rerun retains instruction boundaries");
		fcn->meta.stack_pop = 0;
		mu_assert_false (profile_function (&ctx, 0, sizeof (bytes), PROFILE_NAME, purges[i], NULL), "independent known-zero conflicts with nonzero source purge");
		mu_assert_eq (fcn->meta.stack_pop, 0, "conflicting integer retained");
		mu_assert_true (profile_function (&ctx, 0, sizeof (bytes), PROFILE_NAME, R_ANAL_CC_STACK_POP_UNKNOWN, NULL), "UNKNOWN does not override zero");
		RAnalBlock *bb = r_list_first (fcn->bbs);
		r_anal_bb_set_offset (bb, 200, 201);
		mu_assert_false (profile_function (&ctx, 0, sizeof (bytes), PROFILE_NAME, R_ANAL_CC_STACK_POP_UNKNOWN, NULL), "long-body internal instruction edits preserved");
		local_free (&ctx);
	}
	mu_end;
}

static RCore *original_core_at(const char *path, ut64 base) {
	if (!path) {
		return NULL;
	}
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "bin.relocs.apply", true);
	if (!r_core_file_open (core, path, R_PERM_RX, 0) || !r_core_bin_load (core, path, base)) {
		r_core_free (core);
		return NULL;
	}
	r_config_set_b (core->config, "io.va", true);
	return core;
}

static RCore *original_core_path(const char *path) {
	return original_core_at (path, UT64_MAX);
}

static RCore *original_core(void) {
	return original_core_path (getenv ("R2_TEST_SCRANTIC"));
}

static bool test_scrantic_metadata_spaces(void) {
	if (!getenv ("R2_TEST_SCRANTIC")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 4; scenario++) {
		bool helper = scenario >= 2, other = scenario % 2;
		RCore *core = original_core ();
		mu_assert_notnull (core, "actual read-only SCRANTIC metadata witness");
		RAnal *anal = core->anal;
		ut64 entry = helper? 0x10000033aULL: 0x1000005e2ULL, at = helper? 0x10000033bULL: 0x1000005e4ULL;
		RSpace *manual = r_spaces_set (&anal->meta_spaces, "manual");
		mu_assert_true (r_meta_set (anal, R_META_TYPE_DATA, at, 2, "manual definition"), "actual LSEEK profile or F_SCOPY helper conflicts with independent DATA");
		RIntervalNode *data = r_meta_get_in (anal, at, R_META_TYPE_DATA);
		mu_assert_notnull (data, "native original-backed DATA node");
		RSpace *selected = r_spaces_set (&anal->meta_spaces, other? "selected": "manual");
		char *output = r_core_cmd_str (core, "a:borland");
		mu_assert_notnull (output, "actual registered profile application");
		mu_assert_notnull (strstr (output, "Borland: 14 function contracts qualified"), "same refusal count regardless selected metadata space");
		free (output);
		mu_assert_ptreq (r_spaces_current (&anal->meta_spaces), selected, "profile admission preserves current metadata space");
		mu_assert_null (r_anal_get_function_at (anal, entry), "no global profile/helper function over independent DATA");
		mu_assert_null (r_type_link_at (anal->sdb_types, entry), "no dependent original-backed prototype");
		mu_assert_null (r_flag_get (core->flags, helper? "qualified_borland_f_scopy.10000033a": "scrantic_cwm31_lseek_correspondence"), "no dependent profile/helper label");
		mu_assert_null (r_meta_get_string (anal, R_META_TYPE_COMMENT, entry), "no dependent profile/helper comment");
		mu_assert_notnull (r_anal_get_function_at (anal, helper? 0x1000005e2ULL: 0x10000033aULL), "unrelated original function remains qualified");
		RAnalMetaItem *item = data->data;
		mu_assert_ptreq (item->space, manual, "original-backed DATA space preserved");
		mu_assert_eq (item->type, R_META_TYPE_DATA, "original-backed DATA kind preserved");
		mu_assert_eq (item->subtype, 0, "original-backed DATA subtype preserved");
		mu_assert_eq (data->start, at, "original-backed DATA start preserved");
		mu_assert_eq (data->end, at + 1, "original-backed DATA extent preserved");
		mu_assert_streq (item->str, "manual definition", "original-backed DATA content preserved");
		r_core_free (core);
	}
	mu_end;
}

static bool tasm_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "mz", 129266, "80534cd6a1e2c2b4376ae3f21954c6dbfa77a6998d5e0bf8b8bee6153f3174ea");
}

static bool test_tasm_mz_current(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		eprintf ("TASM MZ original proof not run: set R2_TEST_TASM31 to the read-only original\n");
		mu_end;
	}
	RCore *core = original_core_path (getenv ("R2_TEST_TASM31"));
	mu_assert_notnull (core, "native TASM MZ load");
	BorlandProfileContext ctx;
	mu_assert_true (tasm_context (core, &ctx), "literal TASM original identity");
	mu_assert_eq (ctx.file->bo->baddr, UT64_MAX, "MZ without a baddr callback retains the unspecified-base sentinel");
	mu_assert_eq (ctx.file->bo->baddr_shift, 0, "native MZ has no base shift");
	mu_assert_eq (ctx.file->bo->loadaddr, 0, "native original load address");
	mu_assert_null (sdb_const_get (ctx.ne, "ne.reloc.1.count", NULL), "MZ has no NE provenance obligation");
	static const BorlandProfileRange ranges[] = { { 0x50cc, 22 }, { 0x50e2, 16 }, { 0x50f2, 40 }, { 0x1084b, 13 } };
	HelperOp ops[40];
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (ranges); i++) {
		ut64 address = ranges[i].physical - 0x800;
		mu_assert_eq (profile_mapped (&ctx, ranges[i].physical, ranges[i].size, true), address, "native mapped segments ignore nonmapping text metadata");
		mu_assert_true (profile_code (&ctx, ranges[i].physical, ranges[i].size, address, ops), "allocation union, independent clear and nonzero logical segment code qualify");
		mu_assert_null (r_anal_get_function_at (core->anal, address), "code qualification does not manufacture a function");
	}
	static const ut64 pairs[] = { 0x4dec, 0x4e05, 0x4ee4, 0xfe96, 0xfeb1, 0x11ce0 };
	static const ut64 targets[] = { 0x15fd2, 0x15fd2, 0x15fd2, 0x1004b, 0x1004b, 0x16def };
	for (i = 0; i < R_ARRAY_SIZE (pairs); i++) {
		int fields = 0;
		RBinReloc *reloc;
		R_VEC_FOREACH (ctx.file->bo->relocs, reloc) {
			if (reloc->paddr == pairs[i] + 2) {
				mu_assert_eq (reloc->type, R_BIN_RELOC_16, "actual MZ segment WORD record");
				mu_assert_eq (reloc->ntype, 0, "MZ ntype zero is not NE byte relocation");
				mu_assert_eq (reloc->vaddr, pairs[i] + 2 - 0x800, "actual zero-origin relocation coordinate");
				fields++;
			}
		}
		mu_assert_eq (fields, 1, "each selected FAR segment field has one native relocation");
		ut8 current[4];
		mu_assert_true (profile_current (&ctx, pairs[i], 4, pairs[i] - 0x800, current), "native unchanged FAR offset and paragraph qualify");
		mu_assert_eq (r_read_le16 (current + 2), r_buf_read_le16_at (ctx.file->buf, pairs[i] + 2), "no invented DOS relocation arithmetic");
		mu_assert_eq (((ut64)r_read_le16 (current + 2) << 4) + r_read_le16 (current), targets[i], "native zero-origin target differs from source FILE coordinate");
		mu_assert_eq (profile_mapped (&ctx, targets[i] + 0x800, 1, true), targets[i], "original target FILE maps to the actual resident image");
		mu_assert_false (profile_current (&ctx, pairs[i] + 2, 1, pairs[i] + 2 - 0x800, current), "partial relocation WORD does not qualify");
		ut8 original = r_buf_read8_at (ctx.file->buf, pairs[i] + 2);
		ut8 patch = original ^ 1;
		core->anal->iob.overlay_write_at (core->io, pairs[i] + 2 - 0x800, &patch, 1);
		mu_assert_false (profile_current (&ctx, pairs[i], 4, pairs[i] - 0x800, current), "edited relocation WORD is not normalized away");
		core->anal->iob.overlay_write_at (core->io, pairs[i] + 2 - 0x800, &original, 1);
	}
	r_core_free (core);
	core = original_core_at (getenv ("R2_TEST_TASM31"), 0);
	mu_assert_notnull (core, "native MZ explicitly zero-based load");
	mu_assert_true (tasm_context (core, &ctx), "zero-base original identity");
	mu_assert_eq (ctx.file->bo->baddr, 0, "explicit zero base is retained without a callback");
	mu_assert_eq (profile_mapped (&ctx, 0x50e2, 16, true), 0x48e2, "zero and unspecified bases share native resident coordinates");
	mu_assert_true (profile_code (&ctx, 0x50e2, 16, 0x48e2, ops), "explicit zero base qualifies without a relocation delta");
	r_core_free (core);
	mu_end;
}

static bool test_tlink_mz_current(void) {
	if (!getenv ("R2_TEST_TLINK401")) {
		eprintf ("TLINK MZ original proof not run: set R2_TEST_TLINK401 to the read-only original\n");
		mu_end;
	}
	RCore *core = original_core_path (getenv ("R2_TEST_TLINK401"));
	mu_assert_notnull (core, "native TLINK401 MZ load");
	BorlandProfileContext ctx;
	mu_assert_true (profile_identity (core->anal, &ctx, "mz", 73401, "df1be38b22d43cc912992f1fcca93a5b630197721744ef2eea399f22d1415f0c"), "literal TLINK401 original identity");
	static const BorlandProfileRange ranges[] = {
		{ 0x3458, 0x96 }, { 0x3556, 0xcc }, { 0x6e8f, 0x19b }, { 0x70fb, 0x2c }, { 0x716e, 0x3eb },
		{ 0x3a3a, 0x16d }, { 0x4ea, 0x4b }, { 0x974, 0xe2 }, { 0xafc, 0x77 }, { 0xca6, 0x43 }
	};
	HelperOp ops[0x3eb];
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (ranges); i++) {
		ut64 address = ranges[i].physical - 0x400;
		mu_assert_eq (profile_mapped (&ctx, ranges[i].physical, ranges[i].size, true), address, "TLINK selected native CS0 mapping");
		mu_assert_true (profile_code (&ctx, ranges[i].physical, ranges[i].size, address, ops), "five complete functions and five partial windows qualify as code only");
		mu_assert_null (r_anal_get_function_at (core->anal, address), "qualification does not promote a partial window to a function");
	}
	ut8 current[2];
	mu_assert_true (profile_current (&ctx, 0x5ed, 2, 0x1ed, current), "actual startup DS relocation WORD qualifies");
	mu_assert_eq (r_read_le16 (current), 0x11b1, "startup paragraph is unchanged by native MZ loader");
	mu_assert_null (r_io_map_get_at (core->io, 0x11b10 + 0x17), "DS0017 outside initialized load image is not invented");
	r_core_free (core);
	mu_end;
}

static bool test_mz_current_preservation(void) {
	if (!getenv ("R2_TEST_TASM31")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 5; scenario++) {
		RCore *core = original_core_path (getenv ("R2_TEST_TASM31"));
		mu_assert_notnull (core, "real native MZ preservation input");
		BorlandProfileContext ctx;
		mu_assert_true (tasm_context (core, &ctx), "MZ preservation original identity");
		mu_assert_true (profile_function (&ctx, 0x50e2, 16, PROFILE_NAME, 0, NULL), "independent clear function prerequisite");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x48e2);
		RAnalBlock *bb = r_list_first (fcn->bbs);
		RIOMap *map = NULL;
		if (scenario == 0) {
			ut8 patch = 0x90;
			core->anal->iob.overlay_write_at (core->io, 0x48e4, &patch, 1);
		} else if (scenario == 1) {
			r_anal_hint_set_bits (core->anal, 0x48e4, 32);
			r_anal_hint_set_bits (core->anal, 0x48e5, 16);
		} else if (scenario == 2) {
			map = r_io_map_add (core->io, ctx.file->fd, R_PERM_RX, 0x50e2, 0x30000, 16);
		} else if (scenario == 3) {
			mu_assert_notnull (r_io_open_at (core->io, "malloc://1", R_PERM_RWX, 0, 0x48e4), "competing active descriptor");
		} else {
			ctx.file->bo->baddr = 0x1000;
		}
		ut64 size = bb->size, jump = bb->jump;
		mu_assert_false (profile_function (&ctx, 0x50e2, 16, PROFILE_NAME, 0, NULL), "changed bytes, interior context, competing image/FD or unsupported base refuse");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x48e2), fcn, "refusal retains independent function");
		mu_assert_eq (bb->size, size, "refusal retains body");
		mu_assert_eq (bb->jump, jump, "refusal retains flow");
		mu_assert_eq (fcn->meta.stack_pop, 0, "refusal retains cleanup");
		if (scenario == 0) {
			ut8 current;
			r_io_read_at (core->io, 0x48e4, &current, 1);
			mu_assert_eq (current, 0x90, "independent byte edit retained");
		} else if (scenario == 1) {
			mu_assert_eq (r_anal_hint_bits_at (core->anal, 0x48e4, NULL), 32, "interior context edit retained");
		} else if (scenario == 2) {
			mu_assert_notnull (map, "competing image map exists");
			mu_assert_ptreq (r_io_map_get_at (core->io, 0x30000), map, "competing map retained");
		}
		r_core_free (core);
	}
	mu_end;
}

static const BorlandProfileRange simtower_main_ranges[] = { { 0x420a, 26 }, { 0x426e, 1069 } };

static bool simtower_main(BorlandProfileContext *ctx) {
	return profile_function_ranges (ctx, simtower_main_ranges, R_ARRAY_SIZE (simtower_main_ranges), "simtower_crt45_candidate_VPRINTER", 12, "Selected exact union; not full CRT semantics.");
}

static bool simtower_context(RCore *core, BorlandProfileContext *ctx) {
	return profile_identity (core->anal, ctx, "ne", 6566400, "2825a3c53f77945c63b6d72e26faa7dde5ddd56c31ca668e67a12576d7feca96");
}

static bool test_simtower_selected_code(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		eprintf ("SimTower selected-code original proof not run: set R2_TEST_SIMTOWER to the read-only original\n");
		mu_end;
	}
	RCore *core = original_core_path (getenv ("R2_TEST_SIMTOWER"));
	mu_assert_notnull (core, "real SimTower native load");
	BorlandProfileContext ctx;
	mu_assert_true (simtower_context (core, &ctx), "literal SimTower original identity");
	mu_assert_eq (profile_mapped (&ctx, 0x2200, 378, true), 0x100000000ULL, "canonical startup mapping");
	ut8 startup_bytes[378];
	mu_assert_true (profile_current (&ctx, 0x2200, 378, 0x100000000ULL, startup_bytes), "current relocated startup bytes and context");
	HelperOp startup[378];
	mu_assert_true (profile_code (&ctx, 0x2200, 378, 0x100000000ULL, startup), "complete startup observation beyond former ceiling");
	mu_assert_null (r_anal_get_function_at (core->anal, 0x100000000ULL), "observed startup is not an invented complete function");
	ut8 current[70];
	mu_assert_true (profile_current (&ctx, 0x65030, 70, 0x5200000030ULL, current), "data bytes use the same native original/current qualifier");
	mu_assert_true (profile_current (&ctx, 0x6029a, 5, 0x4f0000009aULL, current), "separate selector/offset current fields qualify without code coverage");
	mu_assert_true (profile_function (&ctx, 0x4224, 13, "simtower_vprinter_scan_entry", R_ANAL_CC_STACK_POP_UNKNOWN, NULL), "independent scanner");
	mu_assert_true (profile_function (&ctx, 0x423a, 52, "simtower_vprinter_flush_entry", R_ANAL_CC_STACK_POP_UNKNOWN, NULL), "independent flush and shared RET");
	mu_assert_true (profile_function (&ctx, 0x4231, 9, "simtower_vprinter_emit_entry", R_ANAL_CC_STACK_POP_UNKNOWN, NULL), "exclusive emitter has valid external edges");
	RAnalFunction *flush = r_anal_get_function_at (core->anal, 0x10000203aULL);
	RAnalFunction *emitter = r_anal_get_function_at (core->anal, 0x100002031ULL);
	RAnalBlock *emit = r_list_first (emitter->bbs);
	mu_assert_eq (emit->jump, 0x10000206dULL, "emitter conditional edge to shared RET");
	mu_assert_eq (emit->fail, 0x10000203aULL, "emitter falls through to separate flush");
	mu_assert_eq (r_anal_function_realsize (emitter), 9, "external edges do not absorb flush");
	mu_assert_true (simtower_main (&ctx), "complete VPRINTER exact union");
	RAnalFunction *main = r_anal_get_function_at (core->anal, 0x10000200aULL);
	mu_assert_eq (r_anal_function_realsize (main), 1095, "union byte count excludes74 independent bytes");
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (main->bbs, iter, bb) {
		mu_assert_true (bb->addr + bb->size <= 0x100002024ULL || bb->addr >= 0x10000206eULL, "no main block owns scanner/emitter/flush/shared RET");
	}
	RAnalBlock *entry = r_list_first (main->bbs);
	mu_assert_eq (entry->jump, 0x10000206eULL, "original EB4A remains a branch to the second range");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x100002022ULL, 0x10000206eULL)), R_ANAL_REF_TYPE_CODE, "union JMP is not rewritten as a call");
	mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x10000203aULL), flush, "flush owner retained");
	mu_assert_true (simtower_main (&ctx), "exact union rerun");
	mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x10000200aULL), main, "union not recreated");
	r_core_cmd0 (core, "afbt tbl=0x10000249b esz=2 n=24 base=0x100000000 @0x1000020db");
	RList *dispatch_blocks = r_anal_get_blocks_in (core->anal, 0x1000020dbULL);
	RAnalBlock *dispatch = r_list_first (dispatch_blocks);
	mu_assert_notnull (dispatch, "actual dispatch instruction block");
	RAnalSwitchOp *switch_op = dispatch->switch_op;
	mu_assert_notnull (switch_op, "native switch owner reads actual24-WORD table");
	mu_assert_eq (r_list_length (switch_op->cases), 24, "native switch retains24 cells including repeated targets");
	int switch_reference = reference_type (core->anal, 0x1000020dbULL, 0x1000020f9ULL);
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (switch_reference), R_ANAL_REF_TYPE_CODE, "native switch has a real case reference");
	mu_assert_true (simtower_main (&ctx), "independent native switch metadata does not alone reject the exact body");
	mu_assert_ptreq (dispatch->switch_op, switch_op, "switch metadata is not deleted/recreated");
	mu_assert_eq (r_list_length (switch_op->cases), 24, "independent switch cases retained");
	mu_assert_eq (reference_type (core->anal, 0x1000020dbULL, 0x1000020f9ULL), switch_reference, "native switch reference retained");
	r_list_free (dispatch_blocks);
	mu_assert_true (profile_function (&ctx, 0x5024, 69, "simtower_sprintf_copy_callback", 10, NULL), "actual known callback purge10");
	mu_assert_true (profile_function (&ctx, 0x606f, 124, "simtower_crt45_candidate_exit_local_helper", 6, NULL), "actual known EXIT local purge6");
	mu_assert_eq (main->meta.stack_pop, 12, "actual VPRINTER purge12");
	mu_assert_eq (r_anal_get_function_at (core->anal, 0x100002e24ULL)->meta.stack_pop, 10, "callback purge is distinct");
	mu_assert_eq (r_anal_get_function_at (core->anal, 0x100003e6fULL)->meta.stack_pop, 6, "EXIT purge is distinct");
	mu_assert_true (profile_number_is (&ctx, "ne.reloc.1.6", "flags", 7), "actual OS instruction-fixup record");
	mu_assert_true (profile_number_is (&ctx, "ne.reloc.1.6", "application_count", 0), "native loader intentionally does not address-relocate OS instructions");
	mu_assert_true (profile_current (&ctx, 0x23a9, 2, 0x1000001a9ULL, current), "unchanged OS instruction bytes qualify against original");
	ut8 patch = current[0] ^ 0xff;
	core->anal->iob.overlay_write_at (core->io, 0x1000001a9ULL, &patch, 1);
	mu_assert_false (profile_current (&ctx, 0x23a9, 2, 0x1000001a9ULL, current), "OS instruction patches are not normalized away");
	r_core_free (core);
	mu_end;
}

static bool test_simtower_code_preservation(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		mu_end;
	}
	int scenario;
	for (scenario = 0; scenario < 5; scenario++) {
		RCore *core = original_core_path (getenv ("R2_TEST_SIMTOWER"));
		mu_assert_notnull (core, "read-only original for preservation");
		BorlandProfileContext ctx;
		mu_assert_true (simtower_context (core, &ctx), "preservation original identity");
		ut8 entry_bytes[26];
		mu_assert_eq (profile_mapped (&ctx, 0x420a, 26, true), 0x10000200aULL, "canonical main entry mapping");
		mu_assert_true (profile_current (&ctx, 0x420a, 26, 0x10000200aULL, entry_bytes), "current main entry bytes and context");
		mu_assert_true (simtower_main (&ctx), "initial exact main body");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x10000200aULL);
		RAnalBlock *entry = r_list_first (fcn->bbs);
		switch (scenario) {
		case 0: r_anal_hint_set_type (core->anal, 0x100002022ULL, R_ANAL_OP_TYPE_CALL); break;
		case 1: entry->jump = 0x100002024ULL; break;
		case 2: fcn->meta.stack_pop = 0; break;
		case 3: r_anal_hint_set_bits (core->anal, 0x10000200bULL, 32); r_anal_hint_set_bits (core->anal, 0x10000200cULL, 16); break;
		case 4: {
			ut8 zero = 0;
			core->anal->iob.overlay_write_at (core->io, 0x100002499ULL, &zero, 1);
			break;
		}
		}
		ut64 jump = entry->jump;
		int pop = fcn->meta.stack_pop;
		mu_assert_false (simtower_main (&ctx), "override-only hint, flow, cleanup, context or RET12-to-RET0 patch refuses");
		mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x10000200aULL), fcn, "conflicted function retained");
		mu_assert_eq (entry->jump, jump, "independent flow retained");
		mu_assert_eq (fcn->meta.stack_pop, pop, "independent cleanup retained");
		mu_assert_eq (r_anal_function_realsize (fcn), 1095, "conflicted union remains intact");
		if (!scenario) {
			RAnalHint *hint = r_anal_hint_get (core->anal, 0x100002022ULL);
			mu_assert_notnull (hint, "override-only native hint retained");
			mu_assert_eq (hint->type, R_ANAL_OP_TYPE_CALL, "hint was not silently cleared");
			r_anal_hint_free (hint);
		}
		r_core_free (core);
	}
	RCore *core = original_core_path (getenv ("R2_TEST_SIMTOWER"));
	mu_assert_notnull (core, "ordinary selected native analysis input");
	BorlandProfileContext ctx;
	mu_assert_true (simtower_context (core, &ctx), "ordinary analysis original identity");
	r_core_cmd0 (core, "af @0x10000206e");
	RAnalFunction *continuation = r_anal_get_function_at (core->anal, 0x10000206eULL);
	mu_assert_notnull (continuation, "native independent continuation owner");
	ut64 size = r_anal_function_realsize (continuation);
	mu_assert_false (simtower_main (&ctx), "independent native continuation cannot be absorbed or deleted");
	mu_assert_ptreq (r_anal_get_function_at (core->anal, 0x10000206eULL), continuation, "ordinary continuation remains separately owned");
	mu_assert_eq (r_anal_function_realsize (continuation), size, "ordinary incomplete analysis is not repaired");
	mu_assert_null (r_anal_get_function_at (core->anal, 0x10000200aULL), "refused union does not create an entry");
	r_core_free (core);
	mu_end;
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
		ut64 addr = 0x100000000ULL + scrantic_functions[i].start - 0x800;
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
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x1000026e3ULL, 0xd000007e5ULL)), R_ANAL_REF_TYPE_DATA, "first exact FAR DATA binding");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x100002798ULL, 0xd00000962ULL)), R_ANAL_REF_TYPE_DATA, "second exact FAR DATA binding");
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
	RAnalFunction *unknown = r_anal_get_function_at (core->anal, 0x10000229cULL);
	unknown->meta.stack_pop = 8;
	const char *cc = unknown->callconv;
	r_meta_set_string (core->anal, R_META_TYPE_COMMENT, 0x1000005e2ULL, "manual original comment");
	char *output = r_anal_cmd (core->anal, "borland");
	mu_assert_notnull (output, "real explicit production entry");
	free (output);
	mu_assert_eq (unknown->meta.stack_pop, 8, "source UNKNOWN does not reset native inference");
	mu_assert_ptreq (unknown->callconv, cc, "no fake heap convention");
	mu_assert_notnull (strstr (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x1000005e2ULL), "manual original comment"), "original manual comment appended, not replaced");
	char *comment = strdup (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x1000005e2ULL));
	output = r_anal_cmd (core->anal, "borland");
	free (output);
	mu_assert_streq (r_meta_get_string (core->anal, R_META_TYPE_COMMENT, 0x1000005e2ULL), comment, "original rerun idempotence");
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
		mu_assert_true (profile_function (&ctx, 0x2eb8, 73, scrantic_functions[1].name, 0, scrantic_functions[1].comment), "qualified initial FHEAP73 body");
		RAnalFunction *fcn = r_anal_get_function_at (core->anal, 0x1000026b8ULL);
		RAnalBlock *bb = r_list_first (fcn->bbs);
		switch (scenario) {
		case 0: r_anal_function_rename (fcn, "manual_fheap73"); break;
		case 1: bb->size--; break;
		case 2: fcn->meta.stack_pop = 8; break;
		case 3: r_anal_hint_set_bits (core->anal, 0x1000026bbULL, 32); r_anal_hint_set_bits (core->anal, 0x1000026bcULL, 16); break;
		case 4: {
			ut8 patched = 0x90;
			core->anal->iob.overlay_write_at (core->io, 0x1000026b8ULL, &patched, 1);
			break;
		}
		case 5: bb->jump = 0x1000026b9ULL; break;
		case 6: r_flag_set (core->flags, scrantic_functions[1].name, 0x1000026b9ULL, 99); break;
		}
		ut64 size = bb->size, jump = bb->jump;
		int pop = fcn->meta.stack_pop;
		int original_ref = reference_type (core->anal, 0x1000026e3ULL, 0xd000007e5ULL);
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
		mu_assert_eq (reference_type (core->anal, 0x1000026e3ULL, 0xd000007e5ULL), original_ref, "refusal preserves preexisting native loader reference");
		free (name);
		r_core_free (core);
	}
	RCore *core = original_core ();
	mu_assert_notnull (core, "real read-only independent reference input");
	r_anal_xrefs_set (core->anal, 0x1000026e3ULL, 0xd000007e5ULL, R_ANAL_REF_TYPE_CODE);
	r_anal_xrefs_set (core->anal, 0x1000026e3ULL, 0xd000007e6ULL, R_ANAL_REF_TYPE_DATA);
	int previous_code = reference_type (core->anal, 0x1000026e3ULL, 0xd000007e5ULL);
	int previous_data = reference_type (core->anal, 0x1000026e3ULL, 0xd000007e6ULL);
	char *output = r_anal_cmd (core->anal, "borland");
	free (output);
	mu_assert_eq (reference_type (core->anal, 0x1000026e3ULL, 0xd000007e5ULL), previous_code, "same-pair independent reference not retyped");
	mu_assert_eq (reference_type (core->anal, 0x1000026e3ULL, 0xd000007e6ULL), previous_data, "other independent reference retained");
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
	mu_run_test (test_profile_current_without_code);
	mu_run_test (test_profile_long_body_and_integer_purge);
	mu_run_test (test_tasm_mz_current);
	mu_run_test (test_tlink_mz_current);
	mu_run_test (test_mz_current_preservation);
	mu_run_test (test_scrantic_production);
	mu_run_test (test_scrantic_production_preservation);
	mu_run_test (test_scrantic_metadata_spaces);
	mu_run_test (test_simtower_selected_code);
	mu_run_test (test_simtower_code_preservation);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
