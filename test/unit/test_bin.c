#include <r_util.h>
#include <r_userconf.h>
#include "minunit.h"
#include <r_bin.h>

//TODO test r_str_chop_path

bool test_r_bin(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinFileOptions opt = {0};
	bool res = r_bin_open (bin, "bins/elf/ioli/crackme0x00", &opt);
	mu_assert ("crackme0x00 binary could not be opened", res);

	RVecRBinSection *sections = r_bin_get_sections_vec (bin);
	// XXX this is wrong, because its returning the sections and the segments, we need another api here
	mu_assert_eq (RVecRBinSection_length (sections), 39, "r_bin_get_sections_vec");

	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

bool test_r_bin_plan9_symbol_names(void) {
	const ut8 symbols[] =
		"\x00\x00\x00\x01" "f" "old.c\0"
		"\x00\x00\x00\x01" "f" "test.c\0"
		"\x00\x00\x00\x00" "f" "ignored\0"
		"\x00\x00\x00\x01" "z" "\0\x00\x01\x00\x00"
		"\x00\x00\x00\x00" "z" "\0\x00\x00"
		"\x00\x00\x00\x07" "a" "skipped\0"
		"\x00\x00\x10\x20" "T" "text\0"
		"\x00\x00\x20\x00" "D" "data\0";
	ut8 bytes[32 + sizeof (symbols) - 1] = {0};
	r_write_be32 (bytes, 0x1eb);
	r_write_be32 (bytes + 20, 0x1020);
	memcpy (bytes + 32, symbols, sizeof (symbols) - 1);
	int i;
	for (i = 0; i < 3; i++) {
		size_t size = sizeof (bytes) - (i == 2? 1: 0);
		r_write_be32 (bytes + 16, size - 32);
		r_write_be32 (bytes + 28, i == 1? 1: 0);
		RBuffer *buf = r_buf_new_with_bytes (bytes, size);
		mu_assert_notnull (buf, "Plan 9 symbol buffer");
		RBin *bin = r_bin_new ();
		RIO *io = r_io_new ();
		r_io_bind (io, &bin->iob);
		RBinFileOptions opt = {0};
		r_bin_file_options_init (&opt, -1, 0, 0, 0);
		opt.filename = "symbols.p9";
		opt.pluginname = "p9";
		mu_assert_true (r_bin_open_buf (bin, buf, &opt), "Plan 9 symbols could not be opened");
		RVecRBinSymbol *bin_symbols = r_bin_get_symbols_vec (bin);
		mu_assert_notnull (bin_symbols, "Plan 9 symbols");
		mu_assert_eq (RVecRBinSymbol_length (bin_symbols), i == 2? 1: 2, "Plan 9 symbol count");
		RBinSymbol *symbol = RVecRBinSymbol_at (bin_symbols, 0);
		mu_assert_streq (symbol->name->oname, "text", "Plan 9 text symbol name survives cleanup");
		mu_assert_eq (symbol->vaddr, 0x1020, "Plan 9 text symbol address");
		if (i != 2) {
			symbol = RVecRBinSymbol_at (bin_symbols, 1);
			mu_assert_streq (symbol->name->oname, "data", "Plan 9 data symbol name survives cleanup");
			mu_assert_eq (symbol->vaddr, 0x2000, "Plan 9 data symbol address");
		}
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

bool test_r_bin_ne_segmented_relocations(void) {
	ut8 bytes[0x240] = {0};
	memcpy (bytes, "MZ", 2);
	r_write_le32 (bytes + 0x3c, 0x40);
	memcpy (bytes + 0x40, "NE", 2);
	r_write_le16 (bytes + 0x44, 0x50);
	r_write_le16 (bytes + 0x46, 16);
	r_write_le16 (bytes + 0x56, 1);
	r_write_le16 (bytes + 0x5c, 2);
	r_write_le16 (bytes + 0x5e, 2);
	r_write_le16 (bytes + 0x62, 0x40);
	r_write_le16 (bytes + 0x66, 0x70);
	r_write_le16 (bytes + 0x68, 0x80);
	r_write_le16 (bytes + 0x6a, 0x90);
	bytes[0x76] = 2;
	const ut8 segments[] = { 0, 1, 0x40, 0, 0x10, 0x11, 0x60, 0, 0, 2, 0x20, 0, 0, 0x10, 0x20, 0 };
	memcpy (bytes + 0x80, segments, sizeof (segments));
	// Unused ordinals 1 and 2 precede a movable entry in the final segment.
	const ut8 entries[] = { 2, 0, 1, 0xff, 0, 0x3f, 0xcd, 2, 0x10, 0, 1, 2, 0, 0x12, 0, 0 };
	memcpy (bytes + 0x90, entries, sizeof (entries));
	const ut8 names[] = { 3, 'M', 'O', 'D', 0, 0, 6, 'T', 'a', 'r', 'g', 'e', 't', 3, 0, 0 };
	memcpy (bytes + 0xb0, names, sizeof (names));
	r_write_le16 (bytes + 0xc2, 7);
	memcpy (bytes + 0xd0, "\x06" "KERNEL" "\x04" "USER", 12);
	const ut16 sites[] = { 1, 6, 0xb, 0x11, 0x16, 0x1b, 0x21, 0x2c, 0x2e };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sites); i++) {
		r_write_le16 (bytes + 0x100 + sites[i], UT16_MAX);
	}
	r_write_le16 (bytes + 0x101, 0x11);
	r_write_le16 (bytes + 0x128, 5);
	const ut8 records[] = {
		3, 0, 1, 0, 2, 0, 0, 0,
		3, 0, 0x21, 0, 0xff, 0, 3, 0,
		3, 1, 6, 0, 1, 0, 91, 0,
		3, 1, 0xb, 0, 1, 0, 23, 0,
		3, 1, 0x16, 0, 2, 0, 91, 0,
		3, 1, 0x1b, 0, 1, 0, 91, 0,
		5, 4, 0x28, 0, 2, 0, 0x10, 0,
		2, 0, 0x2c, 0, 2, 0, 0, 0,
		5, 0, 0x2e, 0, 0xff, 0, 2, 0,
		3, 7, 0x31, 0, 1, 0, 0, 0,
	};
	r_write_le16 (bytes + 0x140, sizeof (records) / 8);
	memcpy (bytes + 0x142, records, sizeof (records));
	RBuffer *buf = r_buf_new_with_bytes (bytes, sizeof (bytes));
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);
	io->va = true;
	RIODesc *desc = r_io_open_at (io, "malloc://576", R_PERM_RWX, 0, 0);
	mu_assert_notnull (desc, "NE I/O buffer");
	mu_assert_true (r_io_write_at (io, 0, bytes, sizeof (bytes)), "write original NE image");
	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, desc->fd, 0, 0, 0);
	opt.filename = "segmented.ne";
	opt.pluginname = "ne";
	mu_assert_true (r_bin_open_buf (bin, buf, &opt), "open NE image");
	mu_assert_true (r_bin_get_info (bin)->has_va, "NE has virtual coordinates");
	mu_assert_true (r_bin_get_info (bin)->has_lit, "NE publishes artificial import addresses");
	mu_assert_streq (r_bin_get_info (bin)->rclass, "ne", "NE format identity");
	RVecRBinSection *sections = r_bin_get_sections_vec (bin);
	mu_assert_eq (RVecRBinSection_length (sections), 2, "NE segment count");
	RBinSection *section = RVecRBinSection_at (sections, 0);
	mu_assert_eq (section->paddr, 0x100, "NE preserves file coordinates");
	mu_assert_eq (section->vaddr, 0x10000, "NE segment coordinate");
	mu_assert_eq (section->vsize, 0x60, "NE allocation size");
	mu_assert_true (section->add, "NE segments request host maps");
	mu_assert_eq (section->perm, R_PERM_RX, "discardable NE code remains readable in analysis maps");
	R_VEC_FOREACH (sections, section) {
		mu_assert_notnull (r_io_map_add (io, desc->fd, section->perm, section->paddr, section->vaddr, section->size), "map NE segment");
	}
	const RList *entrypoints = r_bin_get_entries (bin);
	mu_assert_eq (r_list_length (entrypoints), 3, "unused entry ordinals are not entrypoints");
	RBinAddr *entry = r_list_get_n (entrypoints, 0);
	mu_assert_eq (entry->paddr, 0x100, "startup file coordinate");
	mu_assert_eq (entry->vaddr, 0x10000, "startup virtual coordinate");
	entry = r_list_get_n (entrypoints, 1);
	mu_assert_eq (entry->paddr, 0x210, "final-segment entry file coordinate");
	mu_assert_eq (entry->vaddr, 0x20010, "final-segment entry virtual coordinate");
	entry = r_list_get_n (entrypoints, 2);
	mu_assert_eq (entry->paddr, 0x212, "fixed final-segment entry file coordinate");
	mu_assert_eq (entry->vaddr, 0x20012, "fixed final-segment entry virtual coordinate");
	RVecRBinSymbol *symbols = r_bin_get_symbols_vec (bin);
	RBinSymbol *symbol = RVecRBinSymbol_at (symbols, 0);
	mu_assert_streq (symbol->name->oname, "Target", "export name");
	mu_assert_eq (symbol->ordinal, 3, "export retains skipped ordinal progression");
	mu_assert_eq (symbol->vaddr, 0x20010, "export resolves its actual ordinal, not startup/list index");
	RVecRBinImport *imports = r_bin_get_imports_vec (bin);
	mu_assert_eq (RVecRBinImport_length (imports), 3, "imports deduplicate module plus ordinal, excluding OS fixups");
	mu_assert_eq (RVecRBinImport_at (imports, 0)->ordinal, 91, "first import ordinal");
	mu_assert_eq (RVecRBinImport_at (imports, 1)->ordinal, 23, "second import ordinal");
	mu_assert_eq (RVecRBinImport_at (imports, 2)->ordinal, 91, "same ordinal in another module");
	symbol = RVecRBinSymbol_at (symbols, RVecRBinSymbol_length (symbols) - 3);
	mu_assert_true (symbol->is_imported, "artificial target is an imported host symbol");
	mu_assert_eq (symbol->vaddr, 0x30000, "import symbol agrees with relocated call target");
	mu_assert_streq (symbol->name->oname, RVecRBinImport_at (imports, 0)->name->oname, "import and target retain the same identity");
	RVecRBinReloc *relocs = r_bin_patch_relocs (r_bin_cur (bin));
	mu_assert_notnull (relocs, "patch NE relocations");
	mu_assert_eq (RVecRBinReloc_length (relocs), 9, "expanded relocation chain, no undefined ordinal or OS import");
	ut8 patched[0x40];
	mu_assert_true (r_io_read_at (io, 0x10000, patched, sizeof (patched)), "read relocated analysis view");
	mu_assert_eq (r_read_le32 (patched + 1), 0x20000, "movable source uses direct target discriminator");
	mu_assert_eq (r_read_le32 (patched + 0x11), 0x20000, "chain source receives the same target");
	mu_assert_eq (r_read_le32 (patched + 0x21), 0x20010, "ordinal target uses private entry identity");
	mu_assert_eq (r_read_le32 (patched + 6), 0x30000, "first artificial import coordinate");
	mu_assert_eq (r_read_le32 (patched + 0xb), 0x30004, "different ordinals are distinct");
	mu_assert_eq (r_read_le32 (patched + 0x16), 0x30008, "different modules are distinct");
	mu_assert_eq (r_read_le32 (patched + 0x1b), 0x30000, "repeated import retains its identity");
	mu_assert_eq (r_read_le16 (patched + 0x28), 0x15, "additive offset uses original operand");
	mu_assert_eq (r_read_le16 (patched + 0x2c), 2, "selector operand is a synthetic segment ID");
	mu_assert_eq (r_read_le16 (patched + 0x2e), UT16_MAX, "undefined ordinal remains unresolved");
	mu_assert_notnull (r_io_map_get_at (io, 0x30000), "artificial imports use host map");
	RBinReloc *reloc = RVecRBinReloc_at (relocs, 0);
	mu_assert_eq (reloc->paddr, 0x101, "relocation preserves physical source");
	mu_assert_eq (reloc->vaddr, 0x10001, "relocation exposes virtual source");
	ut8 original[0x240];
	mu_assert_eq (r_buf_read_at (buf, 0, original, sizeof (original)), sizeof (original), "read original buffer after patches");
	mu_assert_memeq (original, bytes, sizeof (bytes), "NE relocation preserves original buffer bytes");
	mu_assert_true (r_io_read_at (io, 0x100, original, 0x40), "read physical backing view");
	mu_assert_memeq (original, bytes + 0x100, 0x40, "NE relocation does not write backing descriptor");
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	mu_end;
}

bool test_r_bin_mach0_chained_fixups(void) {
	const char *path = "bins/mach0/hello-macos-arm64-chained";
	int i;
	for (i = 0; i < 2; i++) {
		RBin *bin = r_bin_new ();
		RIO *io = r_io_new ();
		r_io_bind (io, &bin->iob);
		mu_assert_null (io->desc, "Mach-O load starts without a selected I/O descriptor");
		RBinFileOptions opt = {0};
		r_bin_file_options_init (&opt, -1, 0, 0, 0);
		opt.filename = path;
		RBuffer *buf = NULL;
		bool opened;
		if (i) {
			buf = r_buf_new_file (path, O_RDONLY, 0);
			mu_assert_notnull (buf, "Mach-O input buffer");
			opened = r_bin_open_buf (bin, buf, &opt);
		} else {
			opened = r_bin_open (bin, path, &opt);
		}
		mu_assert_true (opened, "Mach-O with chained fixups could not be opened");
		RBinFile *bf = r_bin_cur (bin);
		mu_assert_notnull (bf, "Mach-O binfile");
		mu_assert_notnull (bf->buf, "Mach-O load retains its buffer");
		ut8 bytes[8];
		mu_assert_eq (r_buf_read_at (bf->buf, 0, bytes, 4), 4, "Read Mach-O header");
		mu_assert_eq (r_read_le32 (bytes), 0xfeedfacf, "Mach-O header is intact");
		mu_assert_eq (r_buf_read_at (bf->buf, 0x8158, bytes, sizeof (bytes)), sizeof (bytes), "Read chained rebase");
		mu_assert_eq (r_read_le64 (bytes), 0x100003bfcULL, "Chained rebase resolves its target");
		mu_assert_eq (r_buf_read_at (bf->buf, 0x80f8, bytes, sizeof (bytes)), sizeof (bytes), "Read chained bind");
		mu_assert_eq (r_read_le64 (bytes), 0, "Chained bind is cleared in the rebased buffer");
		if (buf) {
			mu_assert_eq (r_buf_read_at (buf, 0x8158, bytes, sizeof (bytes)), sizeof (bytes), "Read original chained pointer");
			mu_assert_eq (r_read_le64 (bytes), 0x0010000000003bfcULL, "Rebasing preserves the input buffer");
		}
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

static bool bin_is_jni(const char *path) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);
	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	bool is_jni = r_bin_open (bin, path, &opt)
		&& bin->cur && bin->cur->bo && bin->cur->bo->info
		&& R_VPACK_HAS (bin->cur->bo->langs, R_BIN_LANG_JNI)
		&& bin->cur->bo->info->lang
		&& !strcmp (bin->cur->bo->info->lang, "jni");
	r_bin_free (bin);
	r_io_free (io);
	return is_jni;
}

bool test_r_bin_jni_language(void) {
	mu_assert_true (bin_is_jni ("bins/elf/analysis/libsimplejni.so"),
		"JNI_OnLoad identifies a JNI binary");
	mu_assert_true (bin_is_jni ("bins/elf/jni/jniO2-arm64"),
		"Java_ exports identify a JNI binary");
	mu_end;
}

bool test_r_bin_languages(void) {
	RBinInfo info = { .rclass = "mach0" };
	RBinObject bo = { .info = &info };
	RBinFile bf = { .bo = &bo };
	RVecRBinImport_init (&bo.imports_vec);
	RBinSymbol c_symbol = { .attr.lang = R_BIN_LANG_C };
	RBinSymbol rust_symbol = { .attr.lang = R_BIN_LANG_RUST };
	r_bin_file_add_language (&bf, c_symbol.attr.lang);
	char *demangled = r_bin_demangle (&bf, NULL, "_RNvNtCs1234_7mycrate3foo3bar", 0, false);
	mu_assert_notnull (demangled, "valid Rust symbol is demangled");
	free (demangled);

	mu_assert_true (R_VPACK_HAS (bo.langs, R_BIN_LANG_C), "binary contains C");
	mu_assert_true (R_VPACK_HAS (bo.langs, R_BIN_LANG_RUST), "binary contains Rust");
	mu_assert_eq (c_symbol.attr.lang, R_BIN_LANG_C, "C symbol has one language");
	mu_assert_eq (rust_symbol.attr.lang, R_BIN_LANG_RUST, "Rust symbol has one language");
	bo.langs = r_bin_load_languages (&bf);
	mu_assert_streq (info.lang, "rust", "primary language is independent of pack order");

	RBinImport objc_import = { .name = r_bin_name_new ("objc_msgSend") };
	RVecRBinImport_push_back (&bo.imports_vec, &objc_import);
	bo.langs = r_bin_load_languages (&bf);
	mu_assert_streq (info.lang, "objc", "Objective-C is the primary binary language");
	mu_assert_true (R_VPACK_HAS (bo.langs, R_BIN_LANG_OBJC), "binary contains Objective-C");
	mu_assert_true (R_VPACK_HAS (bo.langs, R_BIN_LANG_C), "binary retains C symbol language");
	mu_assert_true (R_VPACK_HAS (bo.langs, R_BIN_LANG_RUST), "binary retains Rust symbol language");

	info.lang = "swift";
	r_bin_file_add_language (&bf, R_BIN_LANG_SWIFT);
	bo.langs = r_bin_load_languages (&bf);
	mu_assert_streq (info.lang, "swift", "Objective-C membership does not override Swift primary");
	mu_assert_true (R_VPACK_HAS (bo.langs, R_BIN_LANG_OBJC), "mixed Swift binary retains Objective-C");

	RVecRBinImport_fini (&bo.imports_vec);
	mu_end;
}

bool test_r_bin_function_kind_attributes(void) {
	char *attrs = r_bin_attr_tostring (R_BIN_ATTR_ASYNC | R_BIN_ATTR_GENERATOR | R_BIN_ATTR_DESTRUCTOR, false);
	mu_assert_streq (attrs, "async generator destructor", "function kind attributes");
	free (attrs);
	mu_end;
}

static RBuffer *pebble_resource_pack(ut32 table_size) {
	size_t content_start = 12 + table_size * 16;
	const ut8 content[] = "ICONfont-data";
	size_t size = content_start + sizeof (content) - 1;
	ut8 *bytes = calloc (1, size);
	if (!bytes) {
		return NULL;
	}
	r_write_le32 (bytes, 2);
	r_write_le32 (bytes + 4, 0x11223344);
	r_write_le32 (bytes + 8, 0);
	r_write_le32 (bytes + 12, 1);
	r_write_le32 (bytes + 16, 0);
	r_write_le32 (bytes + 20, 4);
	r_write_le32 (bytes + 24, 0xaabbccdd);
	r_write_le32 (bytes + 28, 2);
	r_write_le32 (bytes + 32, 4);
	r_write_le32 (bytes + 36, sizeof (content) - 5);
	r_write_le32 (bytes + 40, 0x55667788);
	memcpy (bytes + content_start, content, sizeof (content) - 1);
	RBuffer *buf = r_buf_new_with_bytes (bytes, size);
	free (bytes);
	return buf;
}

bool test_r_bin_pebble_resources(void) {
	RBuffer *buf = pebble_resource_pack (256);
	mu_assert_notnull (buf, "Pebble resource pack allocation");
	RBin *bin = r_bin_new ();
	RBinFile probe = {0};
	probe.file = "app_resources.pbpack";
	RBinPlugin *plugin = r_bin_get_binplugin_by_buffer (bin, &probe, buf);
	mu_assert_true (plugin && !strcmp (plugin->meta.name, "pebble"), "Pebble application resource pack detection");
	RBuffer *system_buf = pebble_resource_pack (512);
	mu_assert_notnull (system_buf, "Pebble system resource pack allocation");
	probe.file = "system_resources.pbpack";
	plugin = r_bin_get_binplugin_by_buffer (bin, &probe, system_buf);
	mu_assert_true (plugin && !strcmp (plugin->meta.name, "pebble"), "Pebble system resource pack detection");
	r_unref (system_buf);
	RBuffer *invalid_buf = pebble_resource_pack (256);
	mu_assert_notnull (invalid_buf, "Invalid Pebble resource pack allocation");
	ut8 invalid_offset[4];
	r_write_le32 (invalid_offset, UT32_MAX);
	r_buf_write_at (invalid_buf, 16, invalid_offset, sizeof (invalid_offset));
	probe.file = "invalid.pbpack";
	plugin = r_bin_get_binplugin_by_buffer (bin, &probe, invalid_buf);
	mu_assert_false (plugin && !strcmp (plugin->meta.name, "pebble"), "Reject out-of-bounds Pebble resource");
	r_unref (invalid_buf);
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "app_resources.pbpack";
	bool opened = r_bin_open_buf (bin, buf, &opt);
	mu_assert_true (opened, "Pebble resource pack could not be opened");

	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Pebble resource pack binfile");
	RVecRBinResource *resources = r_bin_file_get_resources (bf);
	mu_assert_notnull (resources, "Pebble resources");
	mu_assert_eq (RVecRBinResource_length (resources), 2, "Pebble resource count");
	RBinResource *resource = RVecRBinResource_at (resources, 0);
	mu_assert_streq (resource->name, "1", "Pebble resource id name");
	mu_assert_streq (resource->type, "RESOURCE", "Pebble resource type");
	mu_assert_eq (resource->paddr, 4108, "Pebble resource physical address");
	mu_assert_eq (resource->size, 4, "Pebble resource size");

	RBuffer *data = r_bin_file_get_resource_data (bf, resource, false);
	mu_assert_notnull (data, "Pebble resource data");
	ut8 bytes[4];
	mu_assert_eq (r_buf_read_at (data, 0, bytes, sizeof (bytes)), sizeof (bytes), "Read Pebble resource data");
	mu_assert_memeq (bytes, (const ut8 *)"ICON", sizeof (bytes), "Pebble resource contents");
	r_unref (data);

	RVecRBinSection *sections = r_bin_get_sections_vec (bin);
	mu_assert_eq (RVecRBinSection_length (sections), 3, "Pebble resource pack sections");
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	mu_end;
}

static RBuffer *le_resource_binary(bool is_le) {
	const ut32 object_table = 0xb0;
	const ut32 page_table = object_table + 48;
	const ut32 resource_table = page_table + (is_le? 8: 16);
	const ut32 resident_table = resource_table + 28;
	const ut32 data_pages = 0x200;
	ut8 *bytes = calloc (1, 0x300);
	if (!bytes) {
		return NULL;
	}
	memcpy (bytes, is_le? "LE": "LX", 2);
	r_write_le16 (bytes + 8, 2);
	r_write_le16 (bytes + 10, 1);
	r_write_le32 (bytes + 0x14, 1);
	r_write_le32 (bytes + 0x28, 0x100);
	r_write_le32 (bytes + 0x2c, is_le? 0x100: 0);
	r_write_le32 (bytes + 0x40, object_table);
	r_write_le32 (bytes + 0x44, 2);
	r_write_le32 (bytes + 0x48, page_table);
	r_write_le32 (bytes + 0x50, resource_table);
	r_write_le32 (bytes + 0x54, 2);
	r_write_le32 (bytes + 0x58, resident_table);
	r_write_le32 (bytes + 0x80, data_pages);
	r_write_le32 (bytes + object_table, 0x100);
	r_write_le32 (bytes + object_table + 8, 1);
	r_write_le32 (bytes + object_table + 12, 1);
	r_write_le32 (bytes + object_table + 16, 1);
	r_write_le32 (bytes + object_table + 24, 0x100);
	r_write_le32 (bytes + object_table + 28, 0x1000);
	r_write_le32 (bytes + object_table + 32, 9);
	r_write_le32 (bytes + object_table + 36, 2);
	r_write_le32 (bytes + object_table + 40, 1);
	if (is_le) {
		bytes[page_table + 3] = 3;
		bytes[page_table + 6] = 1;
	} else {
		r_write_le16 (bytes + page_table + 6, 3);
		r_write_le16 (bytes + page_table + 12, 0x100);
	}
	r_write_le16 (bytes + resource_table, 2);
	r_write_le16 (bytes + resource_table + 2, 7);
	r_write_le32 (bytes + resource_table + 4, 4);
	r_write_le16 (bytes + resource_table + 8, 2);
	r_write_le32 (bytes + resource_table + 10, 0x20);
	r_write_le16 (bytes + resource_table + 14, 5);
	r_write_le16 (bytes + resource_table + 16, 3);
	r_write_le32 (bytes + resource_table + 18, 6);
	r_write_le16 (bytes + resource_table + 22, 2);
	r_write_le32 (bytes + resource_table + 24, 0x30);
	memcpy (bytes + data_pages + 0x20, "ICON", 4);
	memcpy (bytes + data_pages + 0x30, "hello", 6);
	RBuffer *buf = r_buf_new_with_bytes (bytes, 0x300);
	free (bytes);
	return buf;
}

bool test_r_bin_le_resources(void) {
	int i;
	for (i = 0; i < 2; i++) {
		RBuffer *buf = le_resource_binary (i == 0);
		mu_assert_notnull (buf, "LE/LX allocation");
		RBin *bin = r_bin_new ();
		RIO *io = r_io_new ();
		r_io_bind (io, &bin->iob);
		RBinFileOptions opt = {0};
		r_bin_file_options_init (&opt, -1, 0, 0, 0);
		opt.filename = i == 0? "resources.le": "resources.lx";
		mu_assert_true (r_bin_open_buf (bin, buf, &opt), "LE/LX resource binary open");
		RBinFile *bf = r_bin_cur (bin);
		mu_assert_notnull (bf, "LE/LX resource binfile");
		RVecRBinResource *resources = r_bin_file_get_resources (bf);
		mu_assert_notnull (resources, "LE/LX resources");
		mu_assert_eq (RVecRBinResource_length (resources), 2, "LE/LX resource count");
		RBinResource *resource = RVecRBinResource_at (resources, 0);
		mu_assert_streq (resource->name, "7", "LE/LX resource name ID");
		mu_assert_streq (resource->type, "BITMAP", "LE/LX resource type");
		mu_assert_eq (resource->id, 7, "LE/LX resource ID");
		mu_assert_eq (resource->type_id, 2, "LE/LX resource type ID");
		mu_assert_eq (resource->paddr, 0x220, "LE/LX resource physical address");
		mu_assert_eq (resource->vaddr, 0x1020, "LE/LX resource virtual address");
		mu_assert_eq (resource->size, 4, "LE/LX resource size");
		RBuffer *data = r_bin_file_get_resource_data (bf, resource, false);
		mu_assert_notnull (data, "LE/LX resource data");
		ut8 bytes[4];
		mu_assert_eq (r_buf_read_at (data, 0, bytes, sizeof (bytes)), sizeof (bytes), "Read LE/LX resource data");
		mu_assert_memeq (bytes, (const ut8 *)"ICON", sizeof (bytes), "LE/LX resource contents");
		r_unref (data);
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

static RBuffer *decode_resource(const ut8 *data, size_t size, const char *encoding, bool decode) {
	RBinFile bf = { .buf = r_buf_new_with_bytes (data, size) };
	if (!bf.buf) {
		return NULL;
	}
	RBinResource resource = { .encoding = (char *)encoding, .size = size };
	RBuffer *decoded = r_bin_file_get_resource_data (&bf, &resource, decode);
	r_unref (bf.buf);
	return decoded;
}

static RBuffer *external_resource_data(RBinFile *bf, const RBinResource *resource) {
	(void)bf;
	return resource->index? NULL
		: r_buf_new_with_bytes ((const ut8 *)"SIDE", 4);
}

bool test_r_bin_external_resource_data(void) {
	RBinPlugin plugin = {
		.get_resource_data = external_resource_data,
	};
	RBinObject bo = {
		.plugin = &plugin,
	};
	RBinFile bf = {
		.bo = &bo,
		.buf = r_buf_new_with_bytes ((const ut8 *)"MAIN", 4),
	};
	RBinResource resource = {
		.size = 4,
	};
	RBuffer *data = r_bin_file_get_resource_data (&bf, &resource, false);
	mu_assert_notnull (data, "External resource data");
	ut8 bytes[4];
	mu_assert_eq (r_buf_read_at (data, 0, bytes, sizeof (bytes)),
		sizeof (bytes), "Read external resource data");
	mu_assert_memeq (bytes, (const ut8 *)"SIDE", sizeof (bytes),
		"External resolver must override the main file");
	r_unref (data);
	resource.index = 1;
	data = r_bin_file_get_resource_data (&bf, &resource, false);
	mu_assert_null (data, "External resolver failure must not fall back");
	r_unref (bf.buf);
	mu_end;
}

bool test_r_bin_resource_decoding(void) {
	const char base64[] = "aGVsbG8";
	const char data_uri[] = "data:image/png;charset=utf-8;base64,iVBORw0KGgo=";
	const char plain_uri[] = "data:text/plain,hello";
	const char escaped_uri[] = "data:text/plain,hello%20world%00x";
	const ut8 hello[] = "hello";
	const ut8 png[] = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };
	const ut8 escaped[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0, 'x' };
	const ut8 lz4[] = { 0x50, 'h', 'e', 'l', 'l', 'o' };
#if WANT_ZIP
	const ut8 gzip[] = {
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
		0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00,
		0x00
	};
#endif
	const ut8 utf16[][10] = {
		{ 0xff, 0xfe, 'r', 0, '2', 0, 0x3c, 0xd8, 0xb8, 0xdf },
		{ 0xfe, 0xff, 0, 'r', 0, '2', 0xd8, 0x3c, 0xdf, 0xb8 }
	};
	const ut8 utf8[] = "r2\xf0\x9f\x8e\xb8";
	typedef struct {
		const ut8 *data;
		size_t size;
		const char *encoding;
		bool decode;
		const ut8 *expected;
		size_t expected_size;
	} ResourceDecodeTest;
	const ResourceDecodeTest tests[] = {
		{ (const ut8 *)base64, sizeof (base64) - 1, "base64", false, (const ut8 *)base64, sizeof (base64) - 1 },
		{ (const ut8 *)base64, sizeof (base64) - 1, "base64", true, hello, sizeof (hello) - 1 },
		{ (const ut8 *)data_uri, sizeof (data_uri) - 1, "data-uri", true, png, sizeof (png) },
		{ (const ut8 *)plain_uri, sizeof (plain_uri) - 1, "data-uri", true, hello, sizeof (hello) - 1 },
		{ (const ut8 *)escaped_uri, sizeof (escaped_uri) - 1, "data-uri", true, escaped, sizeof (escaped) },
		{ lz4, sizeof (lz4), "lz4", true, hello, sizeof (hello) - 1 },
#if WANT_ZIP
		{ gzip, sizeof (gzip), "gzip", true, hello, sizeof (hello) - 1 },
#endif
		{ utf16[0], sizeof (utf16[0]), "utf16le", true, utf8, sizeof (utf8) - 1 },
		{ utf16[1], sizeof (utf16[1]), "utf16", true, utf8, sizeof (utf8) - 1 },
	};
	ut8 bytes[16];
	int i;
	for (i = 0; i < R_ARRAY_SIZE (tests); i++) {
		const ResourceDecodeTest *test = &tests[i];
		RBuffer *data = decode_resource (test->data, test->size, test->encoding, test->decode);
		mu_assert_notnull (data, "Resource decoding");
		mu_assert_eq (r_buf_size (data), test->expected_size, "Decoded resource size");
		mu_assert_eq (r_buf_read_at (data, 0, bytes, test->expected_size), test->expected_size, "Read decoded resource");
		mu_assert_memeq (bytes, test->expected, test->expected_size, "Decoded resource contents");
		r_unref (data);
	}
	mu_end;
}

static ut8 *extract_test_resource(bool raw, size_t *size) {
	const char encoded[] = "aGVsbG8";
	RBin bin = { 0 };
	bin.options.resraw = raw;
	RBinObject bo = { .resources_loaded = true };
	RVecRBinResource_init (&bo.resources_vec);
	RBinFile bf = {
		.rbin = &bin,
		.bo = &bo,
		.buf = r_buf_new_with_bytes ((const ut8 *)encoded, sizeof (encoded) - 1),
	};
	RBinResource *resource = RVecRBinResource_emplace_back (&bo.resources_vec);
	resource->name = strdup ("test");
	resource->type = strdup ("DATA");
	resource->encoding = strdup ("base64");
	resource->size = sizeof (encoded) - 1;
	resource->id = UT64_MAX;
	resource->type_id = UT32_MAX;
	resource->named = true;
	char *dir = r_file_temp (raw? "r2-bin-resource-raw": "r2-bin-resource-decoded");
	ut8 *result = NULL;
	if (dir && r_bin_file_extract_resources (&bf, dir)) {
		char *file = r_str_newf ("%s%sresource_DATA_named_0.bin", dir, R_SYS_DIR);
		result = (ut8 *)r_file_slurp (file, size);
		free (file);
	}
	if (dir) {
		r_file_rm_rf (dir);
	}
	free (dir);
	r_unref (bf.buf);
	RVecRBinResource_fini (&bo.resources_vec);
	return result;
}

bool test_r_bin_resource_raw_extraction(void) {
	size_t size = 0;
	ut8 *data = extract_test_resource (false, &size);
	mu_assert_notnull (data, "Decoded resource extraction");
	mu_assert_eq (size, 5, "Decoded resource extraction size");
	mu_assert_memeq (data, (const ut8 *)"hello", size, "Decoded resource extraction contents");
	free (data);

	data = extract_test_resource (true, &size);
	mu_assert_notnull (data, "Raw resource extraction");
	mu_assert_eq (size, 7, "Raw resource extraction size");
	mu_assert_memeq (data, (const ut8 *)"aGVsbG8", size, "Raw resource extraction contents");
	free (data);
	mu_end;
}

bool test_r_bin_cmd(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);
	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	mu_assert_true (r_bin_open (bin, "bins/pcap/udp6.pcap", &opt), "PCAP could not be opened");

	char *res = r_bin_cmd (bin, "s");
	mu_assert_notnull (res, "PCAP stream command was not handled");
	mu_assert ("PCAP stream command output is missing", strstr (res, "pkts=3") && strstr (res, "pkts=4"));
	free (res);
	res = r_bin_cmd (bin, "sa");
	mu_assert_notnull (res, "PCAP stream payload command was not handled");
	mu_assert_streq (res, "query?again", "PCAP stream payload output is missing");
	free (res);
	res = r_bin_cmd (bin, "s 1");
	mu_assert_notnull (res, "PCAP stream selection was not handled");
	mu_assert ("PCAP stream selection output is missing", strstr (res, "* 1 tcp"));
	free (res);
	mu_assert_null (r_bin_cmd (bin, "invalid"), "Invalid PCAP command was handled");

	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

// ELF32 ET_DYN using PN_XNUM: e_phnum is 0xffff and the real program header
// count is taken from shdr[0].sh_info, so phdr[] holds a single entry
static RBuffer *elf_pn_xnum_shared_object(void) {
	const ut32 phoff = 0x34;
	const ut32 stroff = phoff + 32;
	const ut32 shoff = 0x68;
	const ut32 textoff = 0x1000;
	const ut32 textsize = 0x10;
	const char shstrtab[] = "\0.text\0.shstrtab";
	const size_t size = textoff + textsize;
	ut8 *bytes = calloc (1, size);
	if (!bytes) {
		return NULL;
	}
	memcpy (bytes, "\x7f" "ELF\x01\x01\x01", 7);
	r_write_le16 (bytes + 16, 3); // ET_DYN
	r_write_le16 (bytes + 18, 40); // EM_ARM
	r_write_le32 (bytes + 20, 1);
	r_write_le32 (bytes + 28, phoff);
	r_write_le32 (bytes + 32, shoff);
	r_write_le16 (bytes + 40, 52);
	r_write_le16 (bytes + 42, 32);
	r_write_le16 (bytes + 44, 0xffff); // PN_XNUM
	r_write_le16 (bytes + 46, 40);
	r_write_le16 (bytes + 48, 3);
	r_write_le16 (bytes + 50, 2);

	r_write_le32 (bytes + phoff, 1); // PT_LOAD
	r_write_le32 (bytes + phoff + 4, textoff);
	r_write_le32 (bytes + phoff + 8, textoff);
	r_write_le32 (bytes + phoff + 12, textoff);
	r_write_le32 (bytes + phoff + 16, textsize);
	r_write_le32 (bytes + phoff + 20, textsize);
	r_write_le32 (bytes + phoff + 24, 5);
	r_write_le32 (bytes + phoff + 28, 0x1000);

	memcpy (bytes + stroff, shstrtab, sizeof (shstrtab));

	r_write_le32 (bytes + shoff + 28, 1); // shdr[0].sh_info holds the phdr count
	r_write_le32 (bytes + shoff + 40, 1); // .text, resolves the entrypoint
	r_write_le32 (bytes + shoff + 44, 1);
	r_write_le32 (bytes + shoff + 48, 6);
	r_write_le32 (bytes + shoff + 52, textoff);
	r_write_le32 (bytes + shoff + 56, textoff);
	r_write_le32 (bytes + shoff + 60, textsize);
	r_write_le32 (bytes + shoff + 80, 7); // .shstrtab
	r_write_le32 (bytes + shoff + 84, 3);
	r_write_le32 (bytes + shoff + 96, stroff);
	r_write_le32 (bytes + shoff + 100, sizeof (shstrtab));

	RBuffer *buf = r_buf_new_with_bytes (bytes, size);
	free (bytes);
	return buf;
}

bool test_r_bin_elf_pn_xnum_phdr(void) {
	RBuffer *buf = elf_pn_xnum_shared_object ();
	mu_assert_notnull (buf, "PN_XNUM ELF allocation");
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "pn_xnum.so";
	mu_assert_true (r_bin_open_buf (bin, buf, &opt), "PN_XNUM ELF could not be opened");

	// looking up the entrypoint scans the program headers for PT_INTERP, which
	// must stay inside the array sized from shdr[0].sh_info and not e_phnum
	const RList *entries = r_bin_get_entries (bin);
	mu_assert_notnull (entries, "PN_XNUM ELF entries");
	mu_assert_eq (r_list_length (entries), 1, "PN_XNUM ELF entry count");

	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	mu_end;
}


bool all_tests(void) {
	mu_run_test(test_r_bin);
	mu_run_test(test_r_bin_plan9_symbol_names);
	mu_run_test(test_r_bin_ne_segmented_relocations);
	mu_run_test(test_r_bin_mach0_chained_fixups);
	mu_run_test(test_r_bin_jni_language);
	mu_run_test(test_r_bin_languages);
	mu_run_test(test_r_bin_function_kind_attributes);
	mu_run_test(test_r_bin_pebble_resources);
	mu_run_test(test_r_bin_le_resources);
	mu_run_test(test_r_bin_external_resource_data);
	mu_run_test(test_r_bin_resource_decoding);
	mu_run_test(test_r_bin_resource_raw_extraction);
	mu_run_test(test_r_bin_cmd);
	mu_run_test(test_r_bin_elf_pn_xnum_phdr);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
