#include <r_core.h>
#include "minunit.h"

#define R2_PLUGIN_INCORE
#define r_anal_plugin_borland unit_borland_data_plugin
#include "../../libr/anal/p/anal_borland.c"
#undef r_anal_plugin_borland

#define LOCAL_BASE 0x10000
#define LOCAL_DATA (LOCAL_BASE + 32)

static bool selected_types(RAnal *anal) {
	r_anal_types_prepare (anal);
	const HelperMember startup[] = {
		{ "protected_word", "uint16_t", 2 }, { "processor_word", "uint16_t", 4 },
		{ "coprocessor_word", "uint16_t", 6 }, { "psp_word", "uint16_t", 8 },
		{ "instance_word", "uint16_t", 10 }, { "previous_instance_word", "uint16_t", 12 },
		{ "command_offset_word", "uint16_t", 14 }, { "show_word", "uint16_t", 16 },
		{ "version_word", "uint16_t", 18 }, { "abend_test_word", "uint16_t", 25 },
		{ "copyright_bytes", "uint8_t", 27, 43 }
	};
	const HelperMember far[] = { { "offset", "uint16_t", 0 }, { "selector", "uint16_t", 2 } };
	const HelperMember exit[] = {
		{ "callback_storage_0", "FarStorage16", 0 }, { "callback_storage_1", "FarStorage16", 4 },
		{ "callback_storage_2", "FarStorage16", 8 }, { "guard_word", "uint16_t", 12 }
	};
	const HelperMember xxv[] = {
		{ "terminate_storage", "FarStorage16", 10 }, { "unexpected_storage", "FarStorage16", 14 },
		{ "terminate_ds_word", "uint16_t", 18 }, { "unexpected_ds_word", "uint16_t", 20 }
	};
	return borland_record (anal, "StartupData70Partial", 560, startup, R_ARRAY_SIZE (startup))
		&& borland_record (anal, "FarStorage16", 32, far, R_ARRAY_SIZE (far))
		&& borland_record (anal, "ExitData14Partial", 112, exit, R_ARRAY_SIZE (exit))
		&& borland_record (anal, "XxvInitialized296Partial", 2368, xxv, R_ARRAY_SIZE (xxv));
}

static BorlandProfileContext local_data(void) {
	RCore *core = r_core_new ();
	core->io->va = true;
	RIODesc *desc = r_io_open_at (core->io, "malloc://256", R_PERM_RWX, 0, LOCAL_BASE);
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	ut8 bytes[256] = {0};
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
	section->name = strdup ("local");
	section->vaddr = LOCAL_BASE;
	section->size = section->vsize = sizeof (bytes);
	section->perm = R_PERM_R;
	section->add = true;
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

static bool test_data_types_and_equivalent_state(void) {
	BorlandProfileContext ctx = local_data ();
	mu_assert_true (selected_types (ctx.anal), "selected exact native types");
	RAnalBaseType *startup = r_anal_get_base_type (ctx.anal, "StartupData70Partial");
	mu_assert_notnull (startup, "native startup record");
	mu_assert_eq (startup->size, 560, "complete byte extent stored as bits");
	mu_assert_eq (RVecAnalTypeMember_length (&startup->struct_data.members), 11, "only established members, no invented gap fields");
	RAnalTypeMember *member = RVecAnalTypeMember_at (&startup->struct_data.members, 10);
	mu_assert_eq (member->offset, 27, "unaligned BYTE array offset");
	mu_assert_eq (member->count, 43, "native array count");
	r_anal_base_type_free (startup);
	RAnalBaseType *xxv = r_anal_get_base_type (ctx.anal, "XxvInitialized296Partial");
	mu_assert_eq (xxv->size, 2368, "XXV full296-byte extent survives trailing gap");
	mu_assert_eq (RVecAnalTypeMember_length (&xxv->struct_data.members), 4, "public labels do not create fields or extents");
	r_anal_base_type_free (xxv);
	mu_assert_true (profile_data (&ctx, 32, 70, "StartupData70Partial"), "qualified data and link");
	RAnalMetaItem *meta = r_meta_get_at (ctx.anal, LOCAL_DATA, R_META_TYPE_DATA, NULL);
	mu_assert_notnull (meta, "data annotation");
	ut64 epoch = r_anal_types_dirty_epoch (ctx.anal);
	mu_assert_true (selected_types (ctx.anal), "equivalent structured definitions");
	mu_assert_true (profile_data (&ctx, 32, 70, "StartupData70Partial"), "equivalent region rerun");
	mu_assert_eq (r_anal_types_dirty_epoch (ctx.anal), epoch, "equivalent types/links are not saved again");
	mu_assert_ptreq (r_meta_get_at (ctx.anal, LOCAL_DATA, R_META_TYPE_DATA, NULL), meta, "equivalent metadata not recreated");
	mu_assert_false (profile_data_array (&ctx, 32, "uint8_t", 70), "different linked type preserved despite equal extent");
	const HelperMember conflict[] = { { "different", "uint8_t", 27, 42 } };
	mu_assert_false (borland_record (ctx.anal, "StartupData70Partial", 560, conflict, 1), "conflicting type never overwritten");
	mu_assert_eq (r_anal_types_dirty_epoch (ctx.anal), epoch, "conflict has no type mutation");
	local_free (&ctx);
	ctx = local_data ();
	r_anal_types_prepare (ctx.anal);
	mu_assert_true (profile_data_array (&ctx, 32, "uint16_t", 24), "native plain WORD array needs no wrapper record");
	epoch = r_anal_types_dirty_epoch (ctx.anal);
	mu_assert_true (profile_data_array (&ctx, 32, "uint16_t", 24), "equivalent plain array");
	mu_assert_eq (r_anal_types_dirty_epoch (ctx.anal), epoch, "array link not recreated");
	local_free (&ctx);
	mu_end;
}

static bool test_data_conflicting_extents_and_references(void) {
	int scenario;
	for (scenario = 0; scenario < 9; scenario++) {
		BorlandProfileContext ctx = local_data ();
		mu_assert_true (selected_types (ctx.anal), "local types");
		r_anal_xrefs_set (ctx.anal, LOCAL_DATA - 5, LOCAL_DATA + 69, R_ANAL_REF_TYPE_DATA);
		r_anal_xrefs_set (ctx.anal, LOCAL_DATA + 69, LOCAL_DATA + 100, R_ANAL_REF_TYPE_CODE);
		ut64 meta_start = LOCAL_DATA + 3, meta_size = 2;
		RAnalBlock *code = NULL;
		switch (scenario) {
		case 0: meta_start = LOCAL_DATA - 1; meta_size = 72; break;
		case 1: meta_start = LOCAL_DATA + 69; meta_size = 10; break;
		case 2: break;
		case 3: r_spaces_push (&ctx.anal->meta_spaces, "independent"); break;
		case 4: r_anal_types_set_link (ctx.anal, "uint8_t [72]", LOCAL_DATA - 1); break;
		case 5: r_anal_types_set_link (ctx.anal, "uint16_t", LOCAL_DATA + 2); break;
		case 6:
			sdb_set (ctx.anal->sdb_types, "unknown_object", "struct", 0);
			r_anal_types_set_link (ctx.anal, "unknown_object", LOCAL_BASE + 1);
			break;
		case 7: r_anal_create_function (ctx.anal, "independent_empty_entry", LOCAL_DATA + 69, R_ANAL_FCN_TYPE_FCN, NULL); break;
		case 8: {
			code = r_anal_create_block (ctx.anal, LOCAL_DATA - 1, 72);
			mu_assert_notnull (code, "independent crossing code block");
			break;
		}
		}
		RAnalMetaItem *meta = NULL;
		if (scenario < 4) {
			r_meta_set (ctx.anal, R_META_TYPE_DATA, meta_start, meta_size, NULL);
			meta = r_meta_get_at (ctx.anal, meta_start, R_META_TYPE_DATA, NULL);
		}
		if (scenario == 3) {
			r_spaces_pop (&ctx.anal->meta_spaces);
			r_spaces_push (&ctx.anal->meta_spaces, "selected");
		}
		ut64 epoch = r_anal_types_dirty_epoch (ctx.anal);
		mu_assert_false (profile_data (&ctx, 32, 70, "StartupData70Partial"), "conflicting full/interior/tail/unknown/link/other-space/code owner refuses");
		mu_assert_eq (r_anal_types_dirty_epoch (ctx.anal), epoch, "refusal adds no type link");
		mu_assert_null (sdb_const_get (ctx.anal->sdb_types, "link.00010020", NULL), "no requested link after refusal");
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (ctx.anal, LOCAL_DATA - 5, LOCAL_DATA + 69)), R_ANAL_REF_TYPE_DATA, "incoming tail reference retained");
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (ctx.anal, LOCAL_DATA + 69, LOCAL_DATA + 100)), R_ANAL_REF_TYPE_CODE, "outgoing tail reference retained");
		if (scenario < 4) {
			if (scenario == 3) {
				r_spaces_pop (&ctx.anal->meta_spaces);
				r_spaces_push (&ctx.anal->meta_spaces, "independent");
			}
			ut64 size;
			mu_assert_ptreq (r_meta_get_at (ctx.anal, meta_start, R_META_TYPE_DATA, &size), meta, "existing full metadata object retained");
			mu_assert_eq (size, meta_size, "full crossing/tail extent retained");
		}
		if (code) {
			r_unref (code);
		}
		local_free (&ctx);
	}
	mu_end;
}

static bool test_data_prototype_and_pointer_categories(void) {
	BorlandProfileContext ctx = local_data ();
	mu_assert_true (selected_types (ctx.anal), "local types");
	sdb_set (ctx.anal->sdb_types, "preceding_prototype", "func", 0);
	mu_assert_eq (r_type_kind (ctx.anal->sdb_types, "preceding_prototype"), R_TYPE_FUNCTION, "canonical native prototype category");
	mu_assert_true (r_anal_types_set_link (ctx.anal, "preceding_prototype", LOCAL_BASE + 1), "existing prototype link");
	mu_assert_true (profile_data (&ctx, 32, 70, "StartupData70Partial"), "preceding code prototype is not an unknown data extent");
	local_free (&ctx);
	ctx = local_data ();
	mu_assert_true (selected_types (ctx.anal), "local types for inside prototype");
	sdb_set (ctx.anal->sdb_types, "inside_prototype", "func", 0);
	r_anal_types_set_link (ctx.anal, "inside_prototype", LOCAL_DATA + 1);
	mu_assert_false (profile_data (&ctx, 32, 70, "StartupData70Partial"), "prototype at interior address remains an independent owner");
	local_free (&ctx);
	ctx = local_data ();
	mu_assert_true (selected_types (ctx.anal), "local types for pointer field");
	sdb_set (ctx.anal->sdb_types, "function_pointer", "func", 0);
	sdb_set (ctx.anal->sdb_types, "type.function_pointer", "func", 0);
	mu_assert_true (r_type_get_bitsize (ctx.anal->sdb_types, "function_pointer") > 8, "native function-pointer storage has object width");
	r_anal_types_set_link (ctx.anal, "function_pointer", LOCAL_DATA - 1);
	mu_assert_false (profile_data (&ctx, 32, 70, "StartupData70Partial"), "crossing function-pointer object is not exempted as a code prototype");
	local_free (&ctx);
	mu_end;
}

static bool test_data_declared_byte_array_string_views(void) {
	int scenario;
	for (scenario = 0; scenario < 6; scenario++) {
		BorlandProfileContext ctx = local_data ();
		mu_assert_true (selected_types (ctx.anal), "local declared field layouts");
		ut64 start = LOCAL_DATA + 27, size = 43;
		const char *type = "StartupData70Partial";
		bool compatible = !scenario || scenario == 4 || scenario == 5;
		switch (scenario) {
		case 1: start--; size++; break;
		case 2: start = LOCAL_DATA + 2; size = 2; break;
		case 3: start = LOCAL_DATA; size = 1; break;
		case 4: start = LOCAL_DATA + 1; size = 1; break;
		case 5: start++; size = 5; break;
		}
		r_meta_set_with_subtype (ctx.anal, R_META_TYPE_STRING, 1, start, size, "independent string view");
		RIntervalNode *node = r_meta_get_in (ctx.anal, start, R_META_TYPE_STRING);
		mu_assert_notnull (node, "existing native string node");
		RAnalMetaItem *item = node->data;
		bool applied = scenario == 4? profile_data_array (&ctx, 32, "uint8_t", 70): profile_data (&ctx, 32, 70, type);
		mu_assert_eq (applied, compatible, "only a wholly contained declared raw BYTE-array view coexists");
		mu_assert_ptreq (r_meta_get_in (ctx.anal, start, R_META_TYPE_STRING), node, "STRING node retained, not converted");
		mu_assert_ptreq (node->data, item, "STRING item not recreated");
		mu_assert_eq (item->type, R_META_TYPE_STRING, "STRING type retained");
		mu_assert_eq (item->subtype, 1, "STRING subtype retained");
		mu_assert_streq (item->str, "independent string view", "STRING content retained");
		mu_assert_eq (node->start, start, "STRING start retained");
		mu_assert_eq (node->end, start + size - 1, "STRING full extent retained");
		local_free (&ctx);
	}
	mu_end;
}

static bool test_data_array_element_views(void) {
	int scenario;
	for (scenario = 0; scenario < 10; scenario++) {
		BorlandProfileContext ctx = local_data ();
		r_anal_types_prepare (ctx.anal);
		ut64 start = LOCAL_DATA, size = 2;
		bool compatible = scenario < 3;
		switch (scenario) {
		case 1: start += 46; break;
		case 2: r_spaces_push (&ctx.anal->meta_spaces, "independent"); break;
		case 3: start++; break;
		case 4: size = 1; break;
		case 5: size = 4; break;
		case 6: start--; break;
		case 7: start += 46; size = 4; break;
		case 8: break;
		case 9: break;
		}
		const char *content = scenario == 9? "independent typed data": NULL;
		int subtype = scenario == 8? 1: 0;
		mu_assert_true (r_meta_set_with_subtype (ctx.anal, R_META_TYPE_DATA, subtype, start, size, content), "independent array-element candidate");
		RIntervalNode *node = r_meta_get_in (ctx.anal, start, R_META_TYPE_DATA);
		mu_assert_notnull (node, "existing DATA node");
		RAnalMetaItem *item = node->data;
		const RSpace *space = item->space;
		if (scenario == 2) {
			r_spaces_pop (&ctx.anal->meta_spaces);
			r_spaces_push (&ctx.anal->meta_spaces, "selected");
		}
		r_anal_xrefs_set (ctx.anal, LOCAL_DATA - 4, start, R_ANAL_REF_TYPE_DATA);
		r_anal_xrefs_set (ctx.anal, start, LOCAL_DATA + 80, R_ANAL_REF_TYPE_CODE);
		ut64 epoch = r_anal_types_dirty_epoch (ctx.anal);
		mu_assert_eq (profile_data_array (&ctx, 32, "uint16_t", 24), compatible, "only exact aligned plain element DATA coexists");
		if (compatible) {
			mu_assert_streq (sdb_const_get (ctx.anal->sdb_types, "link.00010020", NULL), "uint16_t [24]", "complete array linked natively");
			epoch = r_anal_types_dirty_epoch (ctx.anal);
			mu_assert_true (profile_data_array (&ctx, 32, "uint16_t", 24), "array element rerun");
		}
		mu_assert_eq (r_anal_types_dirty_epoch (ctx.anal), epoch, "refusal or equivalent rerun changes no links");
		if (scenario == 2) {
			r_spaces_pop (&ctx.anal->meta_spaces);
			r_spaces_push (&ctx.anal->meta_spaces, "independent");
		}
		mu_assert_ptreq (r_meta_get_in (ctx.anal, start, R_META_TYPE_DATA), node, "DATA node identity retained");
		mu_assert_ptreq (node->data, item, "DATA item identity retained");
		mu_assert_ptreq (item->space, space, "DATA space retained");
		mu_assert_eq (node->start, start, "DATA start retained");
		mu_assert_eq (node->end, start + size - 1, "first element not resized to aggregate extent");
		mu_assert_eq (item->subtype, subtype, "DATA subtype retained");
		if (content) {
			mu_assert_streq (item->str, content, "DATA content retained");
		} else {
			mu_assert_null (item->str, "plain DATA content retained");
		}
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (ctx.anal, LOCAL_DATA - 4, start)), R_ANAL_REF_TYPE_DATA, "element incoming reference retained");
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (ctx.anal, start, LOCAL_DATA + 80)), R_ANAL_REF_TYPE_CODE, "element outgoing reference retained");
		local_free (&ctx);
	}
	mu_end;
}

static bool test_data_array_string_and_guards(void) {
	int scenario;
	for (scenario = 0; scenario < 8; scenario++) {
		BorlandProfileContext ctx = local_data ();
		r_anal_types_prepare (ctx.anal);
		ut64 start = LOCAL_DATA - 3, size = 12;
		mu_assert_true (r_meta_set_with_subtype (ctx.anal, R_META_TYPE_STRING, 1, start, size, "independent overlapping string"), "complete independent STRING view");
		RIntervalNode *node = r_meta_get_in (ctx.anal, start, R_META_TYPE_STRING);
		RAnalMetaItem *item = node->data;
		const RSpace *space = item->space;
		RAnalBlock *code = NULL;
		switch (scenario) {
		case 1: r_anal_types_set_link (ctx.anal, "uint8_t [6]", LOCAL_DATA); break;
		case 2: r_anal_types_set_link (ctx.anal, "uint16_t", LOCAL_DATA + 2); break;
		case 3: r_meta_set (ctx.anal, R_META_TYPE_DATA, LOCAL_DATA + 1, 2, NULL); break;
		case 4: code = r_anal_create_block (ctx.anal, LOCAL_DATA + 2, 2); break;
		case 5: r_anal_create_function (ctx.anal, "independent_array_entry", LOCAL_DATA + 2, R_ANAL_FCN_TYPE_FCN, NULL); break;
		case 6: {
			ut8 patch = 1;
			ctx.anal->iob.overlay_write_at (ctx.anal->iob.io, LOCAL_DATA + 3, &patch, 1);
			break;
		}
		case 7: r_anal_hint_set_bits (ctx.anal, LOCAL_DATA + 3, 32); break;
		}
		ut64 epoch = r_anal_types_dirty_epoch (ctx.anal);
		mu_assert_eq (profile_data_array (&ctx, 32, "uint16_t", 2), !scenario, "independent STRING alone coexists; other owners/current bytes/hints still refuse");
		mu_assert_null (r_meta_get_at (ctx.anal, LOCAL_DATA, R_META_TYPE_DATA, NULL), "no overlapping aggregate DATA marker");
		if (scenario) {
			mu_assert_eq (r_anal_types_dirty_epoch (ctx.anal), epoch, "refusal changes no existing type link");
		} else {
			mu_assert_streq (sdb_const_get (ctx.anal->sdb_types, "link.00010020", NULL), "uint16_t [2]", "whole array represented by type link alone");
		}
		mu_assert_ptreq (r_meta_get_in (ctx.anal, start, R_META_TYPE_STRING), node, "whole STRING node retained");
		mu_assert_ptreq (node->data, item, "STRING item identity retained");
		mu_assert_ptreq (item->space, space, "STRING space retained");
		mu_assert_eq (node->start, start, "STRING prefix outside array retained");
		mu_assert_eq (node->end, start + size - 1, "STRING tail outside array retained");
		mu_assert_eq (item->subtype, 1, "STRING subtype retained");
		mu_assert_streq (item->str, "independent overlapping string", "STRING content retained");
		if (code) {
			r_unref (code);
		}
		local_free (&ctx);
	}
	BorlandProfileContext ctx = local_data ();
	r_anal_types_prepare (ctx.anal);
	mu_assert_false (profile_data_array (&ctx, 32, "uint16_t", 0), "empty array refuses");
	mu_assert_false (profile_data_array (&ctx, 32, "uint64_t", UT32_MAX), "oversized array refuses before allocation");
	mu_assert_false (profile_data_array (&ctx, 32, "unknown_element", 2), "unknown native element width refuses");
	local_free (&ctx);
	mu_end;
}

static bool test_local_native_chained_application(void) {
	// Local native NE producer scenario, not a claim that either supplied original contains a chain.
	ut8 bytes[0x240] = {0};
	memcpy (bytes, "MZ", 2);
	r_write_le32 (bytes + 0x3c, 0x40);
	memcpy (bytes + 0x40, "NE", 2);
	r_write_le16 (bytes + 0x44, 0x50);
	r_write_le16 (bytes + 0x46, 2);
	r_write_le16 (bytes + 0x56, 1);
	r_write_le16 (bytes + 0x5c, 2);
	r_write_le16 (bytes + 0x62, 0x40);
	r_write_le16 (bytes + 0x66, 0x70);
	bytes[0x76] = 2;
	const ut8 segments[] = { 0, 1, 0x40, 0, 0x10, 0x11, 0x40, 0, 0, 2, 0x20, 0, 1, 0x10, 0x20, 0 };
	memcpy (bytes + 0x80, segments, sizeof (segments));
	r_write_le16 (bytes + 0x101, 0x11);
	r_write_le16 (bytes + 0x111, UT16_MAX);
	r_write_le16 (bytes + 0x128, 5);
	const ut8 records[] = { 3, 0, 1, 0, 2, 0, 0, 0, 5, 4, 0x28, 0, 2, 0, 0x10, 0 };
	r_write_le16 (bytes + 0x140, 2);
	memcpy (bytes + 0x142, records, sizeof (records));
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 16);
	core->io->va = true;
	RIODesc *desc = r_io_open_at (core->io, "malloc://576", R_PERM_RWX, 0, 0);
	mu_assert_notnull (desc, "local producer descriptor");
	r_io_write_at (core->io, 0, bytes, sizeof (bytes));
	desc->perm = R_PERM_RX;
	RBuffer *buf = r_buf_new_with_bytes (bytes, sizeof (bytes));
	RBinFileOptions options = {0};
	r_bin_file_options_init (&options, desc->fd, 0, 0, 0);
	options.filename = "local-chain.ne";
	options.pluginname = "ne";
	mu_assert_true (r_bin_open_buf (core->bin, buf, &options), "production NE parser consumes local chain scenario");
	RBinFile *file = r_bin_cur (core->bin);
	RVecRBinSection *sections = r_bin_get_sections_vec (core->bin);
	RBinSection *section;
	R_VEC_FOREACH (sections, section) {
		r_io_map_add (core->io, desc->fd, section->perm, section->paddr, section->vaddr, section->size);
	}
	mu_assert_notnull (r_bin_patch_relocs (file), "production NE relocation expansion and current patching");
	BorlandProfileContext ctx = { core->anal, file, file->bo->plugin->get_sdb (file) };
	mu_assert_true (profile_number_is (&ctx, "ne.reloc.1.0", "application_count", 2), "native producer actually expanded two applications");
	mu_assert_true (profile_number_is (&ctx, "ne.reloc.1.0", "source_offset", 1), "raw head differs from selected application");
	mu_assert_notnull (file->bo->relocs, "native object relocation vector");
	mu_assert_eq (profile_mapped (&ctx, 0x111, 4, true), 0x10011, "local actual application mapping");
	ut8 qualified[4];
	mu_assert_true (profile_current (&ctx, 0x111, 4, 0x10011, qualified), "local actual application current bytes and context");
	BorlandProfileBinding chain = { 3, 0, 2, 0, 0x200, NULL, false, true, true };
	mu_assert_true (profile_binding (&ctx, 0x111, &chain), "select actual non-head application, not raw head");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x10011, 0x20000)), R_ANAL_REF_TYPE_DATA, "selected field receives exact DATA relation");
	chain.singleton = true;
	mu_assert_false (profile_binding (&ctx, 0x111, &chain), "stronger singleton fact cannot qualify a chain");
	BorlandProfileBinding additive = { 5, 4, 2, 0x10, 0x210, NULL, false, true, false };
	mu_assert_true (profile_binding (&ctx, 0x128, &additive), "native additive offset uses actual original5 plus target0010");
	ut8 value[2];
	r_io_read_at (core->io, 0x10028, value, 2);
	mu_assert_eq (r_read_le16 (value), 0x15, "nonzero native additive arithmetic");
	value[0] ^= 0xff;
	core->anal->iob.overlay_write_at (core->io, 0x10028, value, 1);
	mu_assert_false (profile_binding (&ctx, 0x128, &additive), "patched additive field refuses");
	r_unref (buf);
	r_core_free (core);
	mu_end;
}

static RCore *actual_core(BorlandProfileContext *ctx) {
	const char *path = getenv ("R2_TEST_SIMTOWER");
	if (!path) {
		return NULL;
	}
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "bin.relocs.apply", true);
	if (!r_core_file_open (core, path, R_PERM_RX, 0) || !r_core_bin_load (core, path, UT64_MAX)
			|| !profile_identity (core->anal, ctx, "ne", 6566400, "2825a3c53f77945c63b6d72e26faa7dde5ddd56c31ca668e67a12576d7feca96")) {
		r_core_free (core);
		return NULL;
	}
	r_config_set_b (core->config, "io.va", true);
	return core;
}

static bool test_actual_selected_data_shapes(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		eprintf ("SimTower actual data/binding proof not run: set R2_TEST_SIMTOWER to the read-only original; local scenarios do not establish original behavior\n");
		mu_end;
	}
	BorlandProfileContext ctx;
	RCore *core = actual_core (&ctx);
	mu_assert_notnull (core, "exact read-only actual SimTower");
	mu_assert_true (selected_types (core->anal), "exact selected partial types");
	RIntervalNode *copyright_node = r_meta_get_in (core->anal, 0x52004b, R_META_TYPE_STRING);
	mu_assert_notnull (copyright_node, "ordinary loading retains the original copyright STRING view");
	RAnalMetaItem *copyright_item = copyright_node->data;
	int subtype = copyright_item->subtype;
	char *content = strdup (copyright_item->str);
	ut64 string_start = copyright_node->start, string_end = copyright_node->end;
	r_anal_xrefs_set (core->anal, 0x10024, string_start, R_ANAL_REF_TYPE_DATA);
	r_anal_xrefs_set (core->anal, string_end, 0x520080, R_ANAL_REF_TYPE_DATA);
	const ut64 field_addresses[] = { 0x521036, 0x52103a, 0x52103e, 0x5207f6, 0x5207fa };
	const ut64 field_targets[] = { 0x13e6a, 0x13e6a, 0x13e6a, 0x4f0000, 0x4f0143 };
	RIntervalNode *field_nodes[5];
	RAnalMetaItem *field_items[5];
	const RSpace *field_spaces[5];
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (field_addresses); i++) {
		field_nodes[i] = r_meta_get_in (core->anal, field_addresses[i], R_META_TYPE_DATA);
		mu_assert_notnull (field_nodes[i], "ordinary loader's actual FAR-field node");
		field_items[i] = field_nodes[i]->data;
		field_spaces[i] = field_items[i]->space;
		mu_assert_eq (field_nodes[i]->start, field_addresses[i], "actual field start");
		mu_assert_eq (field_nodes[i]->end, field_addresses[i] + 3, "actual field extent4");
		mu_assert_eq (field_items[i]->subtype, 0, "actual field is plain untyped DATA");
		mu_assert_null (field_items[i]->str, "actual field has no content to replace");
		r_anal_xrefs_set (core->anal, 0x10030 + i, field_addresses[i], R_ANAL_REF_TYPE_DATA);
		r_anal_xrefs_set (core->anal, field_addresses[i], field_targets[i], R_ANAL_REF_TYPE_CODE);
	}
	const struct { ut64 physical; int size; const char *type; ut32 count; } regions[] = {
		{ 0x65030, 70, "StartupData70Partial" }, { 0x469b, 48, "uint16_t", 24 },
		{ 0x65b5c, 7, "uint8_t", 7 }, { 0x65b63, 96, "uint8_t", 96 },
		{ 0x66036, 14, "ExitData14Partial" }, { 0x60266, 42, "uint8_t", 42 },
		{ 0x657ec, 296, "XxvInitialized296Partial" }
	};
	for (i = 0; i < R_ARRAY_SIZE (regions); i++) {
		bool applied = regions[i].count? profile_data_array (&ctx, regions[i].physical, regions[i].type, regions[i].count): profile_data (&ctx, regions[i].physical, regions[i].size, regions[i].type);
		mu_assert_true (applied, "actual selected data shape without functions or BSS placement");
		ut64 epoch = r_anal_types_dirty_epoch (core->anal);
		applied = regions[i].count? profile_data_array (&ctx, regions[i].physical, regions[i].type, regions[i].count): profile_data (&ctx, regions[i].physical, regions[i].size, regions[i].type);
		mu_assert_true (applied, "actual equivalent region");
		mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "actual equivalent link not rewritten");
	}
	mu_assert_true (r_list_empty (core->anal->fcns), "data observations never create functions");
	mu_assert_ptreq (r_meta_get_in (core->anal, 0x52004b, R_META_TYPE_STRING), copyright_node, "actual STRING node not deleted or recreated");
	mu_assert_ptreq (copyright_node->data, copyright_item, "actual STRING item retained");
	mu_assert_eq (copyright_item->type, R_META_TYPE_STRING, "actual STRING remains a STRING");
	mu_assert_eq (copyright_item->subtype, subtype, "actual STRING subtype retained");
	mu_assert_eq (copyright_node->start, string_start, "actual STRING start retained");
	mu_assert_eq (copyright_node->end, string_end, "actual STRING extent retained");
	mu_assert_streq (copyright_item->str, content, "actual STRING content retained");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x10024, string_start)), R_ANAL_REF_TYPE_DATA, "actual STRING incoming reference unchanged");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, string_end, 0x520080)), R_ANAL_REF_TYPE_DATA, "actual STRING tail reference unchanged");
	free (content);
	for (i = 0; i < R_ARRAY_SIZE (field_addresses); i++) {
		RVecIntervalNodePtr *nodes = r_meta_get_all_at (core->anal, field_addresses[i]);
		RIntervalNode **node;
		bool retained = false;
		R_VEC_FOREACH (nodes, node) {
			retained |= *node == field_nodes[i];
		}
		RVecIntervalNodePtr_free (nodes);
		mu_assert_true (retained, "actual field node retained in the native metadata tree");
		mu_assert_ptreq (field_nodes[i]->data, field_items[i], "actual field item not recreated");
		mu_assert_ptreq (field_items[i]->space, field_spaces[i], "actual field metadata space retained");
		mu_assert_eq (field_items[i]->type, R_META_TYPE_DATA, "actual field remains DATA");
		mu_assert_eq (field_items[i]->subtype, 0, "actual field subtype retained");
		mu_assert_null (field_items[i]->str, "actual field content retained");
		mu_assert_eq (field_nodes[i]->start, field_addresses[i], "actual field start unchanged");
		mu_assert_eq (field_nodes[i]->end, field_addresses[i] + 3, "actual field not resized to aggregate");
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x10030 + i, field_addresses[i])), R_ANAL_REF_TYPE_DATA, "actual field incoming reference unchanged");
		mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, field_addresses[i], field_targets[i])), R_ANAL_REF_TYPE_CODE, "actual field outgoing independent reference unchanged");
	}
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.00521036", NULL), "ExitData14Partial", "EXIT aggregate layout is available through its native type link");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.005207ec", NULL), "XxvInitialized296Partial", "XXV aggregate layout is available through its native type link");
	ut64 meta_size;
	r_meta_get_at (core->anal, 0x521036, R_META_TYPE_DATA, &meta_size);
	mu_assert_eq (meta_size, 4, "first EXIT field retained instead of a destructive DATA14 resize");
	r_core_free (core);
	mu_end;
}

static bool test_actual_bcc_array_views(void) {
	const struct { const char *env; int size; const char *sha256; } images[] = {
		{ "R2_TEST_BCC31", 672150, "87c6dfbad817eeca31c069043f08063f7122663e51932ad089e6d1c563450d3b" },
		{ "R2_TEST_BCC45", 768026, "6e58346640ca94e32b547c4df872d06905e58c5ef6d473d0b6a6a3903d640a46" }
	};
	const ut64 callbacks[][2] = { { 0x19574, 0x1965a }, { 0x16fb2, 0x1751c } };
	size_t image;
	for (image = 0; image < R_ARRAY_SIZE (images); image++) {
		const char *path = getenv (images[image].env);
		if (!path) {
			eprintf ("Actual BCC array proof not run: set %s to the read-only original; local scenarios do not establish original behavior\n", images[image].env);
			continue;
		}
		RCore *core = r_core_new ();
		r_config_set_b (core->config, "bin.relocs.apply", true);
		mu_assert_notnull (r_core_file_open (core, path, R_PERM_RX, 0), "read-only actual BCC original");
		mu_assert_true (r_core_bin_load (core, path, UT64_MAX), "ordinary native BCC loading");
		r_config_set_b (core->config, "io.va", true);
		BorlandProfileContext ctx;
		mu_assert_true (profile_identity (core->anal, &ctx, "ne", images[image].size, images[image].sha256), "exact BCC original identity");
		r_anal_types_prepare (core->anal);
		const HelperMember far[] = { { "offset", "uint16_t", 0 }, { "selector", "uint16_t", 2 } };
		mu_assert_true (borland_record (core->anal, "FarStorage16", 32, far, R_ARRAY_SIZE (far)), "source-established native FAR storage element");
		mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, "FarStorage16"), 32, "native element width4");
		size_t family;
		for (family = 0; family < 2; family++) {
			ut64 physical = callbacks[image][family];
			ut64 address = profile_mapped (&ctx, physical, 104, false);
			mu_assert_neq (address, UT64_MAX, "actual complete104-byte source-array mapping");
			RVecIntervalNodePtr *nodes = r_meta_get_all_intersect (core->anal, address, 104, R_META_TYPE_DATA);
			mu_assert_notnull (nodes, "ordinary native callback DATA views");
			mu_assert_eq (RVecIntervalNodePtr_length (nodes), 26, "ordinary loader's26 per-element DATA nodes");
			RIntervalNode *field_nodes[26];
			RAnalMetaItem *field_items[26];
			const RSpace *field_spaces[26];
			ut64 starts[26];
			size_t i;
			for (i = 0; i < 26; i++) {
				RIntervalNode *node = *RVecIntervalNodePtr_at (nodes, i);
				field_nodes[i] = node;
				field_items[i] = node->data;
				field_spaces[i] = field_items[i]->space;
				starts[i] = node->start;
				mu_assert_eq ((node->start - address) % 4, 0, "native DATA is at a declared element boundary");
				mu_assert_eq (node->end, node->start + 3, "native DATA is exactly one FAR element");
				mu_assert_eq (field_items[i]->subtype, 0, "native DATA is untyped");
				mu_assert_null (field_items[i]->str, "native DATA has no content to overwrite");
				r_anal_xrefs_set (core->anal, address - 10 - i, starts[i], R_ANAL_REF_TYPE_DATA);
				r_anal_xrefs_set (core->anal, starts[i], address + 200 + i, R_ANAL_REF_TYPE_CODE);
			}
			RVecIntervalNodePtr_free (nodes);
			mu_assert_true (profile_data_array (&ctx, physical, "FarStorage16", 26), "actual26-element FAR array coexists with native per-element views");
			ut64 epoch = r_anal_types_dirty_epoch (core->anal);
			mu_assert_true (profile_data_array (&ctx, physical, "FarStorage16", 26), "actual array equivalent rerun");
			mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "actual array link not rewritten");
			char *linked = r_type_link_at (core->anal->sdb_types, address);
			mu_assert_streq (linked, "FarStorage16 [26]", "native linked element type and count26");
			mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, linked), 832, "native aggregate width104");
			free (linked);
			nodes = r_meta_get_all_intersect (core->anal, address, 104, R_META_TYPE_DATA);
			mu_assert_eq (RVecIntervalNodePtr_length (nodes), 26, "link-only aggregate adds no DATA104 marker");
			for (i = 0; i < 26; i++) {
				RIntervalNode **node;
				bool retained = false;
				R_VEC_FOREACH (nodes, node) {
					retained |= *node == field_nodes[i];
				}
				mu_assert_true (retained, "actual element node remains in native tree");
				mu_assert_ptreq (field_nodes[i]->data, field_items[i], "actual element item retained");
				mu_assert_ptreq (field_items[i]->space, field_spaces[i], "actual element space retained");
				mu_assert_eq (field_nodes[i]->start, starts[i], "actual element start retained");
				mu_assert_eq (field_nodes[i]->end, starts[i] + 3, "actual element extent not resized");
				mu_assert_eq (field_items[i]->type, R_META_TYPE_DATA, "actual element DATA type retained");
				mu_assert_eq (field_items[i]->subtype, 0, "actual element subtype retained");
				mu_assert_null (field_items[i]->str, "actual element content retained");
				mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, address - 10 - i, starts[i])), R_ANAL_REF_TYPE_DATA, "actual element incoming independent reference retained");
				mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, starts[i], address + 200 + i)), R_ANAL_REF_TYPE_CODE, "actual element outgoing independent reference retained");
			}
			RVecIntervalNodePtr_free (nodes);
			ut8 patch;
			r_io_read_at (core->io, address + 103, &patch, 1);
			patch ^= 0xff;
			core->anal->iob.overlay_write_at (core->io, address + 103, &patch, 1);
			mu_assert_false (profile_data_array (&ctx, physical, "FarStorage16", 26), "actual array refuses changed current tail byte");
			mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "actual patched rerun does not rewrite existing link");
		}
		if (!image) {
			RAnalBaseType *code = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
			code->name = strdup ("bcc31_EventBranchCode");
			code->size = 16;
			RAnalEnumCase je = { strdup ("JE"), 0xa }, jne = { strdup ("JNE"), 0xb };
			RVecAnalEnumCase_push_back (&code->enum_data.cases, &je);
			RVecAnalEnumCase_push_back (&code->enum_data.cases, &jne);
			r_anal_save_base_type (core->anal, code);
			r_anal_base_type_free (code);
			const struct { ut64 physical; const char *element; int size; ut64 start; ut64 end; } strings[] = {
				{ 0x194a2, "uint8_t", 2, 0x9589c, 0x958ac },
				{ 0x19560, "bcc31_EventBranchCode", 4, 0x95960, 0x95969 }
			};
			size_t i;
			for (i = 0; i < R_ARRAY_SIZE (strings); i++) {
				ut64 address = profile_mapped (&ctx, strings[i].physical, strings[i].size, false);
				RIntervalNode *node = r_meta_get_in (core->anal, address, R_META_TYPE_STRING);
				mu_assert_notnull (node, "ordinary loading's actual overlapping STRING view");
				RAnalMetaItem *item = node->data;
				int subtype = item->subtype;
				const RSpace *space = item->space;
				char *content = strdup (item->str);
				mu_assert_eq (node->start, strings[i].start, "actual STRING begins outside or at source array");
				mu_assert_eq (node->end, strings[i].end, "actual STRING extends beyond source array");
				ut8 bytes[4];
				mu_assert_true (profile_current (&ctx, strings[i].physical, strings[i].size, address, bytes), "source-established table current bytes");
				if (i) {
					mu_assert_eq (r_read_le16 (bytes), 0xb, "source-established JNE inverse code");
					mu_assert_eq (r_read_le16 (bytes + 2), 0xa, "source-established JE inverse code");
				} else {
					mu_assert_eq (bytes[0], 0x74, "source-established JE opcode");
					mu_assert_eq (bytes[1], 0x75, "source-established JNE opcode");
				}
				r_anal_xrefs_set (core->anal, 0x10024 + i, node->start, R_ANAL_REF_TYPE_DATA);
				r_anal_xrefs_set (core->anal, node->end, 0x10030 + i, R_ANAL_REF_TYPE_CODE);
				mu_assert_true (profile_data_array (&ctx, strings[i].physical, strings[i].element, 2), "actual BYTE/enum-WORD array link coexists with complete STRING view");
				ut64 epoch = r_anal_types_dirty_epoch (core->anal);
				mu_assert_true (profile_data_array (&ctx, strings[i].physical, strings[i].element, 2), "actual overlapping STRING array equivalent rerun");
				mu_assert_eq (r_anal_types_dirty_epoch (core->anal), epoch, "actual STRING array link not rewritten");
				char *expected = r_str_newf ("%s [2]", strings[i].element);
				char *linked = r_type_link_at (core->anal->sdb_types, address);
				mu_assert_streq (linked, expected, "native linked table element type/count2");
				mu_assert_eq (r_type_get_bitsize (core->anal->sdb_types, linked), strings[i].size * 8, "native table aggregate width");
				free (linked);
				free (expected);
				mu_assert_null (r_meta_get_at (core->anal, address, R_META_TYPE_DATA, NULL), "no DATA aggregate over actual STRING");
				mu_assert_ptreq (r_meta_get_in (core->anal, address, R_META_TYPE_STRING), node, "actual complete STRING node retained");
				mu_assert_ptreq (node->data, item, "actual STRING item retained");
				mu_assert_ptreq (item->space, space, "actual STRING metadata space retained");
				mu_assert_eq (item->type, R_META_TYPE_STRING, "actual STRING remains STRING");
				mu_assert_eq (item->subtype, subtype, "actual STRING subtype retained");
				mu_assert_eq (node->start, strings[i].start, "actual STRING prefix retained");
				mu_assert_eq (node->end, strings[i].end, "actual STRING tail retained");
				mu_assert_streq (item->str, content, "actual complete STRING content retained");
				mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x10024 + i, node->start)), R_ANAL_REF_TYPE_DATA, "actual STRING incoming independent reference retained");
				mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, node->end, 0x10030 + i)), R_ANAL_REF_TYPE_CODE, "actual STRING tail outgoing independent reference retained");
				free (content);
			}
		}
		mu_assert_true (r_list_empty (core->anal->fcns), "array observations do not create functions");
		r_core_free (core);
	}
	mu_end;
}

static bool test_actual_native_fields_and_patches(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		mu_end;
	}
	const struct { ut64 physical; BorlandProfileBinding fact; } fields[] = {
		{ 0x66036, { 3, 0, 1, 0x3e6a, 0x606a, NULL, false, false, true } },
		{ 0x2252, { 3, 1, 7, 5, UT64_MAX, "USER", false, true, false } },
		{ 0x6029a, { 2, 0, 79, 0, 0x60200, NULL, false, true, false } },
		{ 0x6029d, { 5, 0, 79, 0x7e, 0x6027e, NULL, false, true, false } },
		{ 0x3cb3, { 2, 4, 79, 0x143, 0x60343, NULL, false, true, false } },
		{ 0x6087, { 3, 1, 5, 48, UT64_MAX, "KERNEL", false, true, false } }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (fields); i++) {
		BorlandProfileContext ctx;
		RCore *core = actual_core (&ctx);
		mu_assert_notnull (core, "actual native field input");
		mu_assert_true (profile_binding (&ctx, fields[i].physical, &fields[i].fact), "actual data-source/import/selector/offset/additive native field");
		int size = fields[i].fact.type == 3? 4: 2;
		ut64 address = profile_mapped (&ctx, fields[i].physical, size, false);
		ut8 current[4];
		r_io_read_at (core->io, address, current, size);
		current[0] ^= 0xff;
		core->anal->iob.overlay_write_at (core->io, address, current, 1);
		mu_assert_false (profile_binding (&ctx, fields[i].physical, &fields[i].fact), "actual current-field patch refuses");
		r_core_free (core);
	}
	BorlandProfileContext ctx;
	RCore *core = actual_core (&ctx);
	mu_assert_notnull (core, "actual module discrimination input");
	BorlandProfileBinding wrong_module = fields[1].fact;
	wrong_module.module = "KERNEL";
	mu_assert_false (profile_binding (&ctx, fields[1].physical, &wrong_module), "USER ordinal is not a same-number KERNEL import");
	mu_assert_true (profile_binding (&ctx, fields[1].physical, &fields[1].fact), "correct USER module still qualifies");
	r_core_free (core);
	mu_end;
}

static bool test_actual_stored_near_and_converted_relations(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		mu_end;
	}
	BorlandProfileContext ctx;
	RCore *core = actual_core (&ctx);
	mu_assert_notnull (core, "actual stored/near window input");
	mu_assert_true (profile_word (&ctx, 0x2224, 0x38), "actual original/current stored startup WORD");
	mu_assert_false (profile_word (&ctx, 0x2224, 0x39), "contradictory stored WORD refuses");
	mu_assert_true (profile_offset (&ctx, 0x469b, 0x20f9, 0x42f9), "actual dispatch stored offset DATA relation");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x1249b, 0x120f9)), R_ANAL_REF_TYPE_DATA, "stored offset is DATA, not CALL");
	mu_assert_true (profile_near (&ctx, 0x5088, 0x420a, false), "actual direct near displacement");
	mu_assert_true (profile_near (&ctx, 0x22bf, 0x60eb, true), "complete converted NOP/PUSH-CS/CALL window");
	ut8 patch = 0x91;
	core->anal->iob.overlay_write_at (core->io, 0x100bf, &patch, 1);
	mu_assert_false (profile_near (&ctx, 0x22bf, 0x60eb, true), "converted prefix patch refuses despite intact displacement");
	r_anal_xrefs_set (core->anal, 0x12e88, 0x1200a, R_ANAL_REF_TYPE_DATA);
	mu_assert_false (profile_near (&ctx, 0x5088, 0x420a, false), "conflicting same-pair native reference is not retyped");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x12e88, 0x1200a)), R_ANAL_REF_TYPE_DATA, "conflicting reference retained");
	mu_assert_true (r_list_empty (core->anal->fcns), "field/window observations never create functions");
	r_core_free (core);
	mu_end;
}

static bool test_actual_pointer_valued_dispatch_conflict(void) {
	if (!getenv ("R2_TEST_SIMTOWER")) {
		mu_end;
	}
	BorlandProfileContext ctx;
	RCore *core = actual_core (&ctx);
	mu_assert_notnull (core, "actual dispatch table cell input");
	r_anal_types_prepare (core->anal);
	mu_assert_true (profile_word (&ctx, 0x469b, 0x20f9), "real first dispatch cell is a stored code offset");
	mu_assert_true (r_anal_types_set_link (core->anal, "uint16_t *", 0x1249b), "independent pointer-valued cell interpretation");
	ut64 pointer_size = r_type_get_bitsize (core->anal->sdb_types, "uint16_t *") / 8;
	mu_assert_true (r_meta_set (core->anal, R_META_TYPE_DATA, 0x1249b, pointer_size, NULL), "existing pointer definition");
	RAnalMetaItem *meta = r_meta_get_at (core->anal, 0x1249b, R_META_TYPE_DATA, NULL);
	r_anal_xrefs_set (core->anal, 0x120db, 0x1249b, R_ANAL_REF_TYPE_DATA);
	r_anal_xrefs_set (core->anal, 0x1249b, 0x120f9, R_ANAL_REF_TYPE_CODE);
	mu_assert_false (profile_data_array (&ctx, 0x469b, "uint16_t", 24), "real pointer-valued cell blocks whole-array replacement");
	mu_assert_streq (sdb_const_get (core->anal->sdb_types, "link.0001249b", NULL), "uint16_t *", "pointer link preserved");
	ut64 size;
	mu_assert_ptreq (r_meta_get_at (core->anal, 0x1249b, R_META_TYPE_DATA, &size), meta, "pointer metadata not recreated");
	mu_assert_eq (size, pointer_size, "full pointer extent retained");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x120db, 0x1249b)), R_ANAL_REF_TYPE_DATA, "incoming native reference unchanged");
	mu_assert_eq (R_ANAL_REF_TYPE_MASK (reference_type (core->anal, 0x1249b, 0x120f9)), R_ANAL_REF_TYPE_CODE, "outgoing independent interpretation unchanged");
	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_data_types_and_equivalent_state);
	mu_run_test (test_data_conflicting_extents_and_references);
	mu_run_test (test_data_prototype_and_pointer_categories);
	mu_run_test (test_data_declared_byte_array_string_views);
	mu_run_test (test_data_array_element_views);
	mu_run_test (test_data_array_string_and_guards);
	mu_run_test (test_local_native_chained_application);
	mu_run_test (test_actual_selected_data_shapes);
	mu_run_test (test_actual_bcc_array_views);
	mu_run_test (test_actual_native_fields_and_patches);
	mu_run_test (test_actual_stored_near_and_converted_relations);
	mu_run_test (test_actual_pointer_valued_dispatch_conflict);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
