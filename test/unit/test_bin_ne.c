#include <r_core.h>
#include "../../libr/bin/format/ne/ne.h"
#include "minunit.h"

// Protect the established native NE loader behavior and its evidence-status boundary.
static void ne_image(ut8 *bytes) {
	memset (bytes, 0, 0x140);
	memcpy (bytes, "MZ", 2);
	r_write_le32 (bytes + 0x3c, 0x40);
	memcpy (bytes + 0x40, "NE", 2);
	r_write_le16 (bytes + 0x44, 0x50);
	r_write_le16 (bytes + 0x5c, 1);
	r_write_le16 (bytes + 0x62, 0x40);
	r_write_le16 (bytes + 0x64, 0x60);
	bytes[0x76] = 2;
	r_write_le16 (bytes + 0x80, 0x100);
	r_write_le16 (bytes + 0x82, 0x10);
	r_write_le16 (bytes + 0x84, 0x100);
	r_write_le16 (bytes + 0x86, 0x10);
	r_write_le16 (bytes + 0x100, UT16_MAX);
	r_write_le16 (bytes + 0x104, UT16_MAX);
	r_write_le16 (bytes + 0x108, UT16_MAX);
	r_write_le16 (bytes + 0x110, 4);
	const ut8 records[] = {
		5, 0, 0, 0, 1, 0, 4, 0,
		5, 0, 4, 0, 0xff, 0, 1, 0,
		0x7f, 0, 8, 0, 1, 0, 0, 0,
		5, 3, 12, 0, 1, 0, 0, 0,
	};
	memcpy (bytes + 0x112, records, sizeof (records));
}

static RBin *open_ne(RBuffer *buf, RIO **io) {
	RBin *bin = r_bin_new ();
	*io = r_io_new ();
	r_io_bind (*io, &bin->iob);
	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "status.ne";
	opt.pluginname = "ne";
	if (!r_bin_open_buf (bin, buf, &opt)) {
		r_bin_free (bin);
		return NULL;
	}
	return bin;
}

static bool test_ne_resolution_status(void) {
	ut8 bytes[0x140];
	ne_image (bytes);
	RIO *io;
	RBuffer *buf = r_buf_new_with_bytes (bytes, sizeof (bytes));
	RBin *bin = open_ne (buf, &io);
	mu_assert_notnull (bin, "open NE status fixture");
	Sdb *db = r_bin_cur (bin)->sdb_info;
	mu_assert_streq (sdb_const_get (db, "ne.relocs.status", NULL), "complete", "complete source-record enumeration");
	mu_assert_eq (sdb_num_get (db, "ne.relocs.count", NULL), 4, "unresolved and unsupported records are retained");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.status", NULL), "complete", "complete segment table");
	mu_assert_eq (sdb_num_get (db, "ne.reloc.1.observed_count", NULL), 4, "native observed table count");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.0.resolution", NULL), "resolved", "internal target resolved in analysis coordinates");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.0.target_address_domain", NULL), "segment_offset", "not a loaded runtime address");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.0.record_address_domain", NULL), "file", "record coordinates are physical");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.0.application_status", NULL), "complete", "terminated source chain");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.0.application.0.original", NULL), "ffff", "original source bytes");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.1.resolution", NULL), "unresolved", "missing entry ordinal is not resolved");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.1.reason", NULL), "unresolved_target", "zero applications has a native reason");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.1.application_status", NULL), "not_enumerated", "unresolved is not complete empty");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.2.resolution", NULL), "unsupported", "unsupported source encoding remains distinct");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.2.reason", NULL), "unsupported_type", "unsupported type reason");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.3.reason", NULL), "os_fixup", "OS instruction fixup is not an address target");
	ut8 unchanged[sizeof (bytes)];
	mu_assert_eq (r_buf_read_at (buf, 0, unchanged, sizeof (unchanged)), sizeof (unchanged), "read original NE image");
	mu_assert_memeq (unchanged, bytes, sizeof (bytes), "evidence reporting leaves input unchanged");
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	mu_end;
}

static bool test_ne_incomplete_and_empty(void) {
	int scenario;
	for (scenario = 0; scenario < 6; scenario++) {
		ut8 bytes[0x140];
		ne_image (bytes);
		size_t size = sizeof (bytes);
		switch (scenario) {
		case 0: r_write_le16 (bytes + 0x80, 0); break;
		case 1: size = 0x111; break;
		case 2: size = 0x120; break;
		case 3: r_write_le16 (bytes + 0x84, 0); break;
		case 4: r_write_le16 (bytes + 0x110, 0); break;
		case 5: r_write_le16 (bytes + 0x100, 0); break;
		}
		RIO *io;
		RBuffer *buf = r_buf_new_with_bytes (bytes, size);
		RBin *bin = open_ne (buf, &io);
		mu_assert_notnull (bin, "open bounded NE table scenario");
		Sdb *db = r_bin_cur (bin)->sdb_info;
		if (scenario < 3) {
			mu_assert_streq (sdb_const_get (db, "ne.relocs.status", NULL), "incomplete", "missing or truncated table is not complete empty");
			mu_assert_streq (sdb_const_get (db, "ne.reloc.1.status", NULL), "incomplete", "explicit table completeness");
			mu_assert_null (sdb_const_get (db, "ne.reloc.1.count", NULL), "no fabricated complete count");
		} else if (scenario < 5) {
			mu_assert_streq (sdb_const_get (db, "ne.relocs.status", NULL), "complete", "owner-known complete empty set");
			mu_assert_streq (sdb_const_get (db, "ne.reloc.1.count", NULL), "0", "explicit empty count");
		} else {
			mu_assert_streq (sdb_const_get (db, "ne.relocs.status", NULL), "complete", "a cycle does not erase raw records");
			mu_assert_streq (sdb_const_get (db, "ne.reloc.1.0.application_status", NULL), "incomplete", "cyclic chain expansion is incomplete");
			mu_assert_streq (sdb_const_get (db, "ne.reloc.1.0.reason", NULL), "source_cycle", "cycle reason belongs to native owner");
		}
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

static bool test_ne_coordinates_and_relocation_bytes(void) {
	ut8 bytes[0x200] = {0};
	ne_image (bytes);
	r_write_le16 (bytes + 0x46, 6);
	r_write_le16 (bytes + 0x54, 2);
	r_write_le16 (bytes + 0x56, 1);
	r_write_le16 (bytes + 0x5e, 1);
	r_write_le16 (bytes + 0x68, 0x58);
	r_write_le16 (bytes + 0x6a, 0x5a);
	r_write_le16 (bytes + 0x82, 0x40);
	r_write_le16 (bytes + 0x86, 0x40);
	const ut8 entry[] = { 1, 1, 1, 0x20, 0, 0 };
	memcpy (bytes + 0x90, entry, sizeof (entry));
	memcpy (bytes + 0x9a, "\x03" "DLL", 4);
	memset (bytes + 0x100, 0, 0x40);
	r_write_le32 (bytes + 0x100, UT16_MAX);
	r_write_le16 (bytes + 0x104, UT16_MAX);
	r_write_le16 (bytes + 0x106, UT16_MAX);
	r_write_le32 (bytes + 0x108, UT16_MAX);
	r_write_le16 (bytes + 0x10c, 2);
	r_write_le16 (bytes + 0x10e, 0xfff0);
	bytes[0x110] = 0x11;
	r_write_le32 (bytes + 0x114, UT16_MAX);
	const ut8 records[] = {
		3, 0, 0, 0, 1, 0, 0x20, 0,
		2, 0, 4, 0, 1, 0, 0x20, 0,
		5, 0, 6, 0, 1, 0, 0x20, 0,
		3, 4, 8, 0, 1, 0, 0x20, 0,
		2, 4, 12, 0, 1, 0, 0x20, 0,
		5, 4, 14, 0, 1, 0, 0x20, 0,
		0, 4, 16, 0, 1, 0, 0x20, 0,
		3, 1, 20, 0, 1, 0, 7, 0,
	};
	r_write_le16 (bytes + 0x140, 8);
	memcpy (bytes + 0x142, records, sizeof (records));
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "bin.relocs.apply", true);
	mu_assert_notnull (r_core_file_open (core, "malloc://512", R_PERM_RWX, 0), "in-memory original NE input");
	mu_assert_eq (r_io_fd_write_at (core->io, core->io->desc->fd, 0, bytes, sizeof (bytes)), sizeof (bytes), "write original physical input before loading");
	mu_assert_true (r_core_bin_load (core, NULL, UT64_MAX), "actual Core NE load and relocation overlay");
	RBinFile *file = r_bin_cur (core->bin);
	mu_assert_streq (file->bo->plugin->meta.name, "ne", "actual NE loader selected");
	mu_assert_eq (core->anal->config->seggrn, 32, "NE selects C48 without widening machine operands");
	mu_assert_eq (core->anal->config->bits, 16, "machine mode remains sixteen bits");
	RBinSection *section = RVecRBinSection_at (&file->bo->sections_vec, 0);
	mu_assert_eq (section->vaddr, 0x100000000ULL, "selector starts at bit32");
	mu_assert_eq (section->paddr, 0x100, "physical section location unchanged");
	mu_assert_eq (section->size, 0x40, "machine segment size unchanged");
	RBinAddr *startup = r_list_first (file->bo->entries);
	mu_assert_eq (startup->vaddr, 0x100000002ULL, "startup entry uses C48");
	mu_assert_eq (startup->paddr, 0x102, "startup physical location unchanged");
	RBinAddr *entrypoint = r_list_get_n (file->bo->entries, 1);
	mu_assert_notnull (entrypoint, "fixed entry-table ordinal retained");
	mu_assert_eq (entrypoint->vaddr, 0x100000020ULL, "entry-table ordinal uses C48");
	mu_assert_eq (entrypoint->paddr, 0x120, "entry-table physical location unchanged");
	Sdb *db = file->sdb_info;
	mu_assert_eq (sdb_num_get (db, "ne.reloc.1.0.target_vaddr", NULL), 0x100000020ULL, "resolved analysis target uses C48");
	mu_assert_eq (sdb_num_get (db, "ne.reloc.1.0.application.0.vaddr", NULL), 0x100000000ULL, "relocation source uses C48");
	mu_assert_eq (sdb_num_get (db, "ne.reloc.1.7.target_vaddr", NULL), 0x200000000ULL, "synthetic import selector uses C48");
	mu_assert_streq (sdb_const_get (db, "ne.reloc.1.0.application.0.original", NULL), "ffff0000", "retained original raw pointer");
	ut8 current[24];
	mu_assert_true (r_io_read_at (core->io, 0x100000000ULL, current, sizeof (current)), "read actual mapped overlay");
	mu_assert_eq (r_read_le32 (current), 0x00010020, "far pointer remains offset16 plus selector16");
	mu_assert_eq (r_read_le16 (current + 4), 1, "selector field is a raw WORD");
	mu_assert_eq (r_read_le16 (current + 6), 0x20, "offset field is a raw WORD");
	mu_assert_eq (r_read_le32 (current + 8), 0x0002001f, "additive raw pointer preserves carry semantics");
	mu_assert_eq (r_read_le16 (current + 12), 3, "additive selector WORD");
	mu_assert_eq (r_read_le16 (current + 14), 0x10, "additive offset WORD wraps independently");
	mu_assert_eq (current[16], 0x31, "additive low byte unchanged");
	mu_assert_eq (r_read_le32 (current + 20), 0x00020000, "import target encoded as raw far pointer");
	ut8 original[sizeof (bytes)];
	mu_assert_eq (r_buf_read_at (file->buf, 0, original, sizeof (original)), sizeof (original), "read original input after patching");
	mu_assert_memeq (original, bytes, sizeof (bytes), "analysis overlay never mutates original NE bytes");
	r_core_free (core);
	mu_end;
}

static int failed_import_fd;

static RIOMap *ne_fail_spill_map(RIO *io, int fd, int flags, ut64 delta, ut64 address, ut64 size) {
	if (address == 0x300000000ULL) {
		failed_import_fd = fd;
		return NULL;
	}
	return r_io_map_add (io, fd, flags, delta, address, size);
}

static bool test_ne_import_selector_spill(void) {
	const size_t unique_count = 0x4002, record_count = unique_count + 2;
	const size_t size = 0x142 + record_count * 8;
	ut8 *bytes = calloc (1, size);
	mu_assert_notnull (bytes, "bounded import-boundary input allocation");
	ne_image (bytes);
	r_write_le16 (bytes + 0x5e, 1);
	r_write_le16 (bytes + 0x68, 0x58);
	r_write_le16 (bytes + 0x6a, 0x5a);
	r_write_le16 (bytes + 0x82, 0x40);
	r_write_le16 (bytes + 0x86, 0x40);
	memcpy (bytes + 0x9a, "\x03" "DLL", 4);
	memset (bytes + 0x100, 0, 0x40);
	size_t i;
	for (i = 0; i < 28; i += 4) {
		r_write_le16 (bytes + 0x100 + i, UT16_MAX);
	}
	r_write_le16 (bytes + 0x140, record_count);
	for (i = 0; i < record_count; i++) {
		size_t slot = i;
		if (i == unique_count) {
			slot = 0;
		} else if (i > unique_count) {
			slot = 0x4000;
		}
		ut16 source = i < 0x3ffe? 0: 4 * (i - 0x3ffe + 1);
		ut8 *record = bytes + 0x142 + 8 * i;
		record[0] = 3;
		record[1] = 1;
		r_write_le16 (record + 2, source);
		r_write_le16 (record + 4, 1);
		r_write_le16 (record + 6, slot + 1);
	}
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "bin.relocs.apply", true);
	char *uri = r_str_newf ("malloc://%zu", size);
	mu_assert_notnull (r_core_file_open (core, uri, R_PERM_RWX, 0), "real in-memory NE import-boundary input");
	free (uri);
	mu_assert_eq (r_io_fd_write_at (core->io, core->io->desc->fd, 0, bytes, size), size, "physical original input");
	mu_assert_true (r_core_bin_load (core, NULL, UT64_MAX), "actual Core import-boundary load and patching");
	RBinFile *file = r_bin_cur (core->bin);
	mu_assert_streq (file->bo->plugin->meta.name, "ne", "native NE loader selected");
	mu_assert_eq (RVecRBinImport_length (&file->bo->imports_vec), unique_count, "cross-selector imports retain all distinct identities");
	mu_assert_eq (RVecRBinReloc_length (file->bo->relocs), record_count, "repeated identities retain their source applications");
	const struct { size_t record; ut16 ordinal; ut16 source; ut64 target; ut32 pointer; } cases[] = {
		{ 0x3ffe, 0x3fff, 4, 0x20000fff8ULL, 0x0002fff8 },
		{ 0x3fff, 0x4000, 8, 0x20000fffcULL, 0x0002fffc },
		{ 0x4000, 0x4001, 12, 0x300000000ULL, 0x00030000 },
		{ 0x4001, 0x4002, 16, 0x300000004ULL, 0x00030004 },
		{ 0x4002, 1, 20, 0x200000000ULL, 0x00020000 },
		{ 0x4003, 0x4001, 24, 0x300000000ULL, 0x00030000 },
	};
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		char key[96];
		snprintf (key, sizeof (key), "ne.reloc.1.%zu.target_vaddr", cases[i].record);
		mu_assert_eq (sdb_num_get (file->sdb_info, key, NULL), cases[i].target, "resolved import target preserves selector and offset16");
		snprintf (key, sizeof (key), "ne.reloc.1.%zu.application.0.target_vaddr", cases[i].record);
		mu_assert_eq (sdb_num_get (file->sdb_info, key, NULL), cases[i].target, "source observation uses the same target");
		RBinSymbol *symbol;
		int symbols = 0;
		R_VEC_FOREACH (&file->bo->symbols_vec, symbol) {
			if (symbol->is_imported && symbol->ordinal == cases[i].ordinal) {
				mu_assert_eq (symbol->vaddr, cases[i].target, "imported symbol agrees with resolved identity");
				symbols++;
			}
		}
		mu_assert_eq (symbols, 1, "one symbol for each deduplicated identity");
		RBinReloc *reloc;
		int applications = 0;
		R_VEC_FOREACH (file->bo->relocs, reloc) {
			if (reloc->paddr == 0x100 + cases[i].source) {
				mu_assert_notnull (reloc->import, "returned relocation retains its import");
				mu_assert_eq (reloc->laddr, cases[i].target, "returned import target agrees");
				applications++;
			}
		}
		mu_assert_eq (applications, 1, "one returned relocation at each selected source");
		ut8 current[4];
		mu_assert_true (r_io_read_at (core->io, 0x100000000ULL + cases[i].source, current, sizeof (current)), "read actual relocation overlay");
		mu_assert_eq (r_read_le32 (current), cases[i].pointer, "far bytes preserve all import identity bits");
		mu_assert_eq (((ut64)r_read_le16 (current + 2) << 32) | r_read_le16 (current), cases[i].target, "raw far pointer resolves to the allocated coordinate");
	}
	RIOMap *first = r_io_map_get_at (core->io, 0x200000000ULL);
	RIOMap *second = r_io_map_get_at (core->io, 0x300000000ULL);
	mu_assert_notnull (first, "first import selector map");
	mu_assert_notnull (second, "spill selector map");
	mu_assert_true (first != second, "selector-spaced windows remain distinct");
	mu_assert_eq (first->fd, second->fd, "one backing descriptor");
	RList *maps = r_io_map_get_by_fd (core->io, first->fd);
	mu_assert_eq (r_list_length (maps), 2, "only the two selector-spaced windows are mapped");
	r_list_free (maps);
	mu_assert_eq (first->delta, 0, "first backing window begins at zero");
	mu_assert_eq (first->itv.size, 0x10000, "first window covers offset16");
	mu_assert_eq (second->delta, 0x10000, "spill map advances the backing offset");
	mu_assert_eq (second->itv.size, 8, "spill map contains the remaining slots");
	mu_assert_streq (first->name, "ne.imports", "first map name retained");
	mu_assert_streq (second->name, "ne.imports", "spill map name retained");
	mu_assert_eq (first->perm, R_PERM_R, "import map permission retained");
	mu_assert_eq (core->io->desc->fd, file->fd, "original descriptor selection retained");
	RIOMapAdd map_add = core->bin->iob.map_add;
	core->bin->iob.map_add = ne_fail_spill_map;
	failed_import_fd = -1;
	RVecRBinReloc *failed = file->bo->plugin->patch_relocs (file);
	core->bin->iob.map_add = map_add;
	mu_assert_null (failed, "required spill-map failure refuses relocation patching");
	mu_assert_true (failed_import_fd >= 0, "failure injected after allocating the owned backing descriptor");
	mu_assert_null (r_io_desc_get (core->io, failed_import_fd), "failed backing descriptor is closed");
	maps = r_io_map_get_by_fd (core->io, failed_import_fd);
	mu_assert_eq (r_list_length (maps), 0, "all maps owned by the failed descriptor are removed");
	r_list_free (maps);
	mu_assert_ptreq (r_io_map_get_at (core->io, 0x200000000ULL), first, "failed attempt removes only its own first window");
	mu_assert_ptreq (r_io_map_get_at (core->io, 0x300000000ULL), second, "existing spill mapping retained");
	mu_assert_eq (core->io->desc->fd, file->fd, "mapping failure restores original descriptor selection");
	ut8 *original = malloc (size);
	mu_assert_notnull (original, "bounded original-byte comparison allocation");
	mu_assert_eq (r_buf_read_at (file->buf, 0, original, size), size, "read actual original input after patching");
	mu_assert_memeq (original, bytes, size, "selector spill never changes original NE input");
	free (original);
	free (bytes);
	r_core_free (core);
	mu_end;
}

static bool test_ne_import_capacity(void) {
	r_bin_ne_obj_t bin = { .imports_base = 0x200000000ULL };
	ut64 address;
	const size_t old_capacity = (UT32_MAX - (2ULL << 16) - 3) / 4 + 1;
	mu_assert_eq (old_capacity, 65534ULL * 16384, "previous packed selector-limited capacity");
	mu_assert_true (r_bin_ne_import_address (&bin, old_capacity - 1, &address), "last previously representable import remains admitted");
	mu_assert_eq (address, 0xffff0000fffcULL, "last slot uses selectorffff and offsetfffc");
	mu_assert_false (r_bin_ne_import_address (&bin, old_capacity, &address), "selector exhaustion refuses without wrap");
	bin.imports_base = 0xffff00000000ULL;
	mu_assert_true (r_bin_ne_import_address (&bin, 16383, &address), "last available selector retains every four-byte slot");
	mu_assert_eq (address, 0xffff0000fffcULL, "last selector boundary");
	mu_assert_false (r_bin_ne_import_address (&bin, 16384, &address), "no selector remains afterffff");
	bin.imports_base = 0x1000000000000ULL;
	mu_assert_false (r_bin_ne_import_address (&bin, 0, &address), "no import selector remains after maximum NE segment count");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_ne_resolution_status);
	mu_run_test (test_ne_incomplete_and_empty);
	mu_run_test (test_ne_coordinates_and_relocation_bytes);
	mu_run_test (test_ne_import_selector_spill);
	mu_run_test (test_ne_import_capacity);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
