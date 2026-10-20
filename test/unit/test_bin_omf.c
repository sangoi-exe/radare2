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

static RBin *open_omf_buffer(RBuffer *buf, RIO **io) {
	const ut8 end[] = { 0x8a, 2, 0, 0, 0 };
	r_buf_append_bytes (buf, end, sizeof (end));
	RBin *bin = r_bin_new ();
	*io = r_io_new ();
	r_io_bind (*io, &bin->iob);
	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = "fixups.obj";
	opt.pluginname = "omf";
	if (!r_bin_open_buf (bin, buf, &opt)) {
		r_bin_free (bin);
		return NULL;
	}
	return bin;
}

static RBin *open_omf(const ut8 *records, size_t size, RIO **io, RBuffer **buffer) {
	*buffer = r_buf_new_with_bytes (omf_prefix, sizeof (omf_prefix));
	r_buf_append_bytes (*buffer, records, size);
	return open_omf_buffer (*buffer, io);
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

static bool test_omf_source_headers(void) {
	// ORL doFirstTHEADR/procRecord admit additional source headers before MODEND.
	const ut8 header_types[] = { 0x80, 0x82 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (header_types); i++) {
		ut8 records[] = {
			0x80, 3, 0, 1, 's', 0,
			0x8c, 4, 0, 1, 'e', 0, 0,
			0x9a, 4, 0, 3, 0xff, 1, 0,
			0x9c, 6, 0, 0xc4, 2, 0x16, 2, 2, 0,
		};
		records[0] = header_types[i];
		RIO *io;
		RBuffer *buf;
		RBin *bin = open_omf (records, sizeof (records), &io, &buf);
		mu_assert_notnull (bin, "open OMF with an additional source header");
		Sdb *db = r_bin_cur (bin)->sdb_info;
		mu_assert_eq (sdb_num_get (db, "omf.externals.count", NULL), 2, "source header does not end external namespace");
		mu_assert_streq (sdb_const_get (db, "omf.externals.status", NULL), "complete", "single module retains complete external namespace");
		mu_assert_streq (sdb_const_get (db, "omf.groups.status", NULL), "complete", "single module retains complete group namespace");
		mu_assert_eq (RVecRBinImport_length (r_bin_get_imports_vec (bin)), 2, "imports after source header survive");
		mu_assert_streq (RVecRBinImport_at (r_bin_get_imports_vec (bin), 1)->name->oname, "e", "later import identity");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.status", NULL), "complete", "source header does not suppress FIXUPP");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.frame.name", NULL), "DGROUP", "later group frame identity");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.target.name", NULL), "e", "later external target identity");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application_count", NULL), 1, "source header retains data context");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.vaddr", NULL), 0x1002, "source header preserves synthetic source placement");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.application.0.original", NULL), "0000", "source bytes remain unchanged");
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

static bool test_omf_multiple_modules(void) {
	const ut8 end_types[] = { 0x8a, 0x8b };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (end_types); i++) {
		ut8 records[] = {
			0x8a, 2, 0, 0, 0,
			0x80, 3, 0, 1, 's', 0,
			0x9c, 5, 0, 0xc4, 2, 0x56, 1, 0,
		};
		records[0] = end_types[i];
		RIO *io;
		RBuffer *buf;
		RBin *bin = open_omf (records, sizeof (records), &io, &buf);
		mu_assert_notnull (bin, "open OMF containing two actual modules");
		Sdb *db = r_bin_cur (bin)->sdb_info;
		mu_assert_streq (sdb_const_get (db, "omf.externals.status", NULL), "incomplete", "multiple module namespace remains excluded");
		mu_assert_streq (sdb_const_get (db, "omf.groups.status", NULL), "incomplete", "multiple module groups remain excluded");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.status", NULL), "unsupported", "actual second module remains unsupported");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.reason", NULL), "multiple_modules", "MODEND followed by header is a module boundary");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application_count", NULL), 0, "no invented cross-module applications");
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

static bool test_omf_shared_names(void) {
	// ORL doLNAMES sends both LNAMES and LLNAMES to the same OmfAddLName table.
	const ut8 records[] = {
		0x80, 3, 0, 1, 't', 0,
		0xca, 3, 0, 1, 'L', 0,
		0x96, 9, 0, 1, 'G', 5, 'O', 'T', 'H', 'E', 'R', 0,
		0x98, 7, 0, 0x48, 8, 0, 1, 0, 0, 0,
		0x9a, 4, 0, 2, 0xff, 1, 0,
		0xa0, 8, 0, 1, 0, 0, 0x11, 0x22, 0x33, 0x44, 0,
		0x9c, 6, 0, 0xc4, 0, 0x14, 1, 1, 0,
	};
	RBuffer *buf = r_buf_new_with_bytes (records, sizeof (records));
	RIO *io;
	RBin *bin = open_omf_buffer (buf, &io);
	mu_assert_notnull (bin, "open OMF with interleaved local and global names");
	Sdb *db = r_bin_cur (bin)->sdb_info;
	mu_assert_streq (sdb_const_get (db, "omf.group.1.name", NULL), "G", "group index includes preceding LLNAMES entry");
	mu_assert_streq (RVecRBinSection_at (r_bin_get_sections_vec (bin), 0)->name, "L_1", "native section resolves local name in shared table");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.frame.name", NULL), "G", "frame identity uses canonical shared names");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.target.name", NULL), "L", "segment target resolves LLNAMES");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.target.identity_status", NULL), "known", "known identity is the source-defined name");
	mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application_count", NULL), 1, "shared names retain source application");
	mu_assert_streq (sdb_const_get (db, "omf.reloc.0.application.0.original", NULL), "1122", "shared names do not alter source bytes");
	r_bin_free (bin);
	r_io_free (io);
	r_unref (buf);
	mu_end;
}

static bool test_omf_segdef_alignment(void) {
	// ORL doSEGDEF and pcobj.h place alignment in ACBP bits 7:5.
	int bits;
	for (bits = 16; bits <= 32; bits += 16) {
		const ut8 prefix[] = {
			0x80, 3, 0, 1, 't', 0,
			0x96, 11, 0, 4, 'C', 'O', 'D', 'E', 4, 'N', 'E', 'X', 'T', 0,
		};
		const ut8 seg16[] = { 0x98, 7, 0, 0x60, 8, 0, 1, 0, 0, 0 };
		const ut8 seg32[] = { 0x99, 9, 0, 0x61, 8, 0, 0, 0, 1, 0, 0, 0 };
		const ut8 records[] = {
			0x98, 7, 0, 0x48, 8, 0, 2, 0, 0, 0,
			0xa0, 8, 0, 1, 0, 0, 0x11, 0x22, 0x33, 0x44, 0,
			0x9c, 5, 0, 0xc4, 2, 0x54, 1, 0,
			0xa0, 8, 0, 2, 0, 0, 0x55, 0x66, 0x77, 0x88, 0,
		};
		RBuffer *buf = r_buf_new_with_bytes (prefix, sizeof (prefix));
		r_buf_append_bytes (buf, bits == 16? seg16: seg32, bits == 16? sizeof (seg16): sizeof (seg32));
		r_buf_append_bytes (buf, records, sizeof (records));
		RIO *io;
		RBin *bin = open_omf_buffer (buf, &io);
		mu_assert_notnull (bin, "open paragraph-aligned private segment");
		Sdb *db = r_bin_cur (bin)->sdb_info;
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application_count", NULL), 1, "ACBP60 segment size admits in-bounds source fixup");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.application_status", NULL), "complete", "segment source bounds match decoded size");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.subrecord.0.target.name", NULL), "CODE", "ACBP60 segment name uses correct cursor");
		mu_assert_eq (RVecRBinSection_length (r_bin_get_sections_vec (bin)), 2, "both initialized source sections survive");
		RBinSection *section = RVecRBinSection_at (r_bin_get_sections_vec (bin), 0);
		mu_assert_streq (section->name, "CODE_1", "native section shares corrected SEGDEF name");
		mu_assert_eq (section->vaddr, 0x1000, "first section synthetic base unchanged");
		mu_assert_eq (section->size, 4, "initialized source byte count unchanged");
		mu_assert_eq (RVecRBinSection_at (r_bin_get_sections_vec (bin), 1)->vaddr, 0x1008, "next section follows actual eight-byte segment size");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.vaddr", NULL), section->vaddr + 2, "provenance agrees with native source mapping");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.paddr", NULL), section->paddr + 2, "source file coordinate agrees with native section");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.application.0.original", NULL), "3344", "corrected segment retains original fixup bytes");
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

static bool test_omf_ledata_index(void) {
	// ORL loadIndex consumes two bytes when the encoded first byte has bit 7 set.
	const ut16 indices[] = { 127, 128, 255, 256 };
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (indices); i++) {
		const ut8 prefix[] = {
			0x80, 3, 0, 1, 't', 0,
			0x96, 6, 0, 4, 'C', 'O', 'D', 'E', 0,
		};
		const ut8 segment[] = { 0x98, 7, 0, 0x48, 8, 0, 1, 0, 0, 0 };
		RBuffer *buf = r_buf_new_with_bytes (prefix, sizeof (prefix));
		ut16 j;
		for (j = 0; j < indices[i]; j++) {
			r_buf_append_bytes (buf, segment, sizeof (segment));
		}
		ut64 data_paddr = r_buf_size (buf) + (indices[i] < 128? 6: 7);
		const ut8 data_header[] = { 0xa0, indices[i] < 128? 8: 9, 0 };
		r_buf_append_bytes (buf, data_header, sizeof (data_header));
		if (indices[i] >= 128) {
			r_buf_append_ut8 (buf, 0x80 | (indices[i] >> 8));
		}
		r_buf_append_ut8 (buf, indices[i] & 0xff);
		const ut8 data_and_fixup[] = {
			2, 0, 0x11, 0x22, 0x33, 0x44, 0,
			0x9c, 5, 0, 0xc4, 1, 0x54, 1, 0,
		};
		r_buf_append_bytes (buf, data_and_fixup, sizeof (data_and_fixup));
		RIO *io;
		RBin *bin = open_omf_buffer (buf, &io);
		mu_assert_notnull (bin, "open OMF at encoded segment index boundaries");
		mu_assert_eq (RVecRBinSection_length (r_bin_get_sections_vec (bin)), 1, "one initialized segment at selected index");
		RBinSection *section = RVecRBinSection_at (r_bin_get_sections_vec (bin), 0);
		mu_assert_eq (section->paddr, data_paddr, "LEDATA source starts after full encoded index");
		mu_assert_eq (section->vaddr, 0x1000 + (indices[i] - 1) * 8 + 2, "LEDATA offset follows full encoded index");
		mu_assert_eq (section->size, 4, "encoded index is not exposed as source data");
		mu_assert_streq (section->name, "CODE_1", "indexed segment identity");
		Sdb *db = r_bin_cur (bin)->sdb_info;
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.application_status", NULL), "complete", "indexed source bounds retain fixup");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.source_segment", NULL), indices[i], "provenance retains decoded segment index");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.source_offset", NULL), 3, "source offset includes LEDATA offset and LOCAT");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.paddr", NULL), section->paddr + 1, "provenance and native section use identical source bytes");
		mu_assert_eq (sdb_num_get (db, "omf.reloc.0.application.0.vaddr", NULL), section->vaddr + 1, "provenance and native section use identical virtual mapping");
		mu_assert_streq (sdb_const_get (db, "omf.reloc.0.application.0.original", NULL), "2233", "encoded index never becomes original source bytes");
		ut8 original[4];
		const ut8 expected[] = { 0x11, 0x22, 0x33, 0x44 };
		mu_assert_eq (r_buf_read_at (buf, section->paddr, original, sizeof (original)), sizeof (original), "read native source section");
		mu_assert_memeq (original, expected, sizeof (expected), "native section bytes remain unmodified");
		r_bin_free (bin);
		r_io_free (io);
		r_unref (buf);
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_omf_fixupp_provenance);
	mu_run_test (test_omf_threads_and_partial_records);
	mu_run_test (test_omf_source_headers);
	mu_run_test (test_omf_multiple_modules);
	mu_run_test (test_omf_shared_names);
	mu_run_test (test_omf_segdef_alignment);
	mu_run_test (test_omf_ledata_index);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
