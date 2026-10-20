#include <r_bin.h>
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

int all_tests(void) {
	mu_run_test (test_ne_resolution_status);
	mu_run_test (test_ne_incomplete_and_empty);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
