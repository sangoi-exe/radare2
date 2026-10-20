#include <r_bin.h>
#include "minunit.h"

// Open Watcom ORL omfload.c establishes the record, index and FIXUPP grammar.
static const ut8 omf_prefix[] = {
	0x80, 3, 0, 1, 't', 0,
	0x96, 14, 0, 0, 4, 'C', 'O', 'D', 'E', 6, 'D', 'G', 'R', 'O', 'U', 'P', 0,
	0x98, 7, 0, 0x48, 8, 0, 2, 0, 0, 0,
	0x9a, 4, 0, 3, 0xff, 1, 0,
	0x8c, 12, 0, 9, '_', '_', 'A', 'H', 'S', 'H', 'I', 'F', 'T', 0, 0,
	0x90, 13, 0, 0, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0, 0, 0,
	0xa0, 12, 0, 1, 0, 0, 0x11, 0x22, 0, 0, 0, 0, 0, 0, 0,
};

static RBin *open_omf(const ut8 *records, size_t size, RIO **io, RBuffer **buffer) {
	RBuffer *buf = r_buf_new_with_bytes (omf_prefix, sizeof (omf_prefix));
	r_buf_append_bytes (buf, records, size);
	const ut8 end[] = { 0x8a, 2, 0, 0, 0 };
	r_buf_append_bytes (buf, end, sizeof (end));
	RBin *bin = r_bin_new ();
	*io = r_io_new ();
	r_io_bind (*io, &bin->iob);
	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "fixups.obj";
	opt.pluginname = "omf";
	*buffer = buf;
	if (!r_bin_open_buf (bin, buf, &opt)) {
		r_bin_free (bin);
		return NULL;
	}
	return bin;
}

static bool test_omf_fixupp_provenance(void) {
	// Real TASM3.1 paired objects differ at c4/d4; their companion FIXDAT is 56.
	int loader;
	for (loader = 0; loader < 2; loader++) {
		ut8 records[] = { 0x9c, 10, 0, 0xc4, 2, 0x56, 1, 0xc4, 4, 0x16, 1, 1, 0 };
		records[3] = loader? 0xd4: 0xc4;
		RIO *io;
		RBuffer *buf;
		RBin *bin = open_omf (records, sizeof (records), &io, &buf);
		mu_assert_notnull (bin, "open standard OMF through RBin");
		RBinFile *bf = r_bin_cur (bin);
		Sdb *db = bf->sdb_info;
		mu_assert ("OMF metadata uses the native plugin boundary", db == bf->bo->plugin->get_sdb (bf));
		mu_assert_streq (sdb_const_get (db, "omf.externals.status", NULL), "complete", "complete external index namespace");
		mu_assert_eq (sdb_num_get (db, "omf.externals.count", NULL), 1, "external survives temporary record destruction");
		mu_assert_streq (sdb_const_get (db, "omf.external.1.name", NULL), "__AHSHIFT", "external identity");
		mu_assert_streq (sdb_const_get (db, "omf.group.1.name", NULL), "DGROUP", "group name resolves LNAMES");
		mu_assert_eq (sdb_num_get (db, "omf.group.1.member.0.segment", NULL), 1, "group member index");
		mu_assert_eq (RVecRBinImport_length (r_bin_get_imports_vec (bin)), 1, "native imports expose external names without target addresses");
		mu_assert_streq (RVecRBinImport_at (r_bin_get_imports_vec (bin), 0)->name->oname, "__AHSHIFT", "native import identity");
		mu_assert_eq (sdb_num_get (db, "omf.relocs.count", NULL), 1, "one source FIXUPP record, not two flattened sites");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.paddr", NULL), sizeof (omf_prefix), "FIXUPP file coordinate");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.subrecord_count", NULL), 2, "two fixup subrecords");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.subrecord.0.location", NULL), loader? 5: 1, "distinct LOCAT types");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.location_name", NULL), loader? "OFF16L": "OFF16", "loader-resolved semantics are not a width alias");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.subrecord.0.width", NULL), 2, "both standard encodings have width16");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.subrecord.0.frame.method", NULL), 5, "same-target frame remains explicit");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.target.name", NULL), "__AHSHIFT", "external target identity");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.1.frame.name", NULL), "DGROUP", "group frame identity");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.resolution", NULL), "unresolved", "not linked");
		mu_assert_null (sdb_const_get (db, "omf.reloc.0.target_vaddr", NULL), "no invented final target");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application_count", NULL), 2, "associated source sites");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.subrecord_index", NULL), 0, "application retains subrecord parent");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.vaddr", NULL), 0x1002, "unchanged synthetic source placement");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.application.0.source_address_domain", NULL), "synthetic_section", "not a runtime address");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.application.0.original", NULL), "0000", "original source bytes");
		mu_assert_eq (RVecRBinSection_at (r_bin_get_sections_vec (bin), 0)->vaddr, 0x1000, "section placement unchanged");
		mu_assert_eq (RVecRBinSymbol_at (r_bin_get_symbols_vec (bin), 0)->vaddr, 0x1000, "symbol placement unchanged");
		ut8 unchanged[sizeof (records)];
		mu_assert_eq (r_buf_read_at (buf, sizeof (omf_prefix), unchanged, sizeof (unchanged)), sizeof (unchanged), "read source records after reporting");
		mu_assert_memeq (unchanged, records, sizeof (records), "reporting does not patch original records");
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

static bool test_omf_threads_and_partial_records(void) {
	const ut8 records[] = {
		0x9c, 5, 0, 0x45, 1, 0x0a, 1, 0,
		0x9c, 4, 0, 0xc4, 2, 0x9e, 0,
		0x9d, 9, 0, 0xc4, 4, 0x52, 1, 0x78, 0x56, 0x34, 0x12, 0,
		0x9c, 8, 0, 0xc4, 0, 0x37, 0x34, 0x12, 0x78, 0x56, 0,
		0x9c, 2, 0, 0xc4, 0,
		0x9c, 4, 0, 0xc4, 2, 0x9e, 0,
	};
	RIO *io;
	RBuffer *buf;
	RBin *bin = open_omf (records, sizeof (records), &io, &buf);
	mu_assert_notnull (bin, "open OMF thread and partial fixup records");
	Sdb *db = r_bin_cur (bin)->sdb_info;
	mu_assert_eq (sdb_num_get (db, "omf.relocs.count", NULL), 6, "thread-only and malformed records remain in source count");
	mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application_count", NULL), 0, "thread-only record does not invent a site");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.kind", NULL), "thread", "thread definition survives");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.1.subrecord.0.frame.name", NULL), "DGROUP", "frame thread persists across FIXUPP records");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.1.subrecord.0.target.name", NULL), "__AHSHIFT", "target thread persists across FIXUPP records");
	mu_assert_eq (sdb_num_get (db, "omf.reloc.1.subrecord.0.frame.thread_paddr", NULL), sizeof (omf_prefix) + 3, "thread provenance identifies actual defining bytes");
	mu_assert_eq (sdb_num_get (db, "omf.reloc.2.subrecord.0.displacement_width", NULL), 4, "FIXUPP32 displacement width");
	mu_assert_eq (sdb_num_get (db, "omf.reloc.2.subrecord.0.displacement", NULL), 0x12345678, "raw displacement retained independently of linking");
	mu_assert_eq (sdb_num_get (db, "omf.reloc.3.subrecord.0.frame.datum", NULL), 0x1234, "absolute frame consumes LE16, not an OMF index");
	mu_assert_eq (sdb_num_get (db, "omf.reloc.3.subrecord.0.target.datum", NULL), 0x5678, "absolute target consumes LE16 after frame");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.4.status", NULL), "incomplete", "truncated FIXUPP does not become a complete empty set");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.5.subrecord.0.frame.status", NULL), "undefined_thread", "truncated unknown thread state is not fabricated");
	mu_assert_null (sdb_const_get (db, "omf.reloc.5.subrecord.0.frame.method", NULL), "undefined thread is not silently method0");
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_omf_fixupp_provenance);
	mu_run_test (test_omf_threads_and_partial_records);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
