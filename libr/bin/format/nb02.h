#ifndef R_BIN_FORMAT_NB02_H
#define R_BIN_FORMAT_NB02_H

#include <r_util.h>
#include <sdb/sdb.h>

static bool bin_nb02_observe(RBuffer *buf, Sdb *db) {
	static const ut8 initial[16] = { 'N', 'B', '0', '2', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	ut64 size = r_buf_size (buf);
	ut8 footer[8];
	bool terminal = false;
	ut64 distance = 0, target = 0;
	bool target_in_range = false;
	if (size >= sizeof (footer)) {
		if (r_buf_read_at (buf, size - sizeof (footer), footer, sizeof (footer)) != sizeof (footer)) {
			R_LOG_ERROR ("Incomplete NB02 original-input footer read");
			return false;
		}
		terminal = !memcmp (footer, "NB02", 4);
		if (terminal) {
			distance = r_read_le32 (footer + 4);
			if (distance <= size) {
				target = size - distance;
				target_in_range = size >= sizeof (footer) + sizeof (initial) && target <= size - sizeof (footer) - sizeof (initial);
			}
		}
	}
	ut8 window[65536];
	ut64 start = 0, count = 0;
	bool linked = false;
	r_strf_buffer (96);
	while (size - start >= sizeof (initial)) {
		size_t length = R_MIN (sizeof (window), size - start);
		if (r_buf_read_at (buf, start, window, length) != length) {
			R_LOG_ERROR ("Incomplete NB02 original-input window read at 0x%" PFMT64x, start);
			return false;
		}
		size_t i;
		for (i = 0; i <= length - sizeof (initial); i++) {
			if (!memcmp (window + i, initial, sizeof (initial))) {
				ut64 offset = start + i;
				sdb_num_set (db, r_strf ("nb02.initial.%" PFMT64u ".offset", count), offset, 0);
				sdb_num_set (db, r_strf ("nb02.initial.%" PFMT64u ".end", count), offset + sizeof (initial), 0);
				count++;
				if (target_in_range && offset == target) {
					linked = true;
				}
			}
		}
		start += length - sizeof (initial) + 1;
	}
	sdb_set (db, "nb02.scope", "Offsets are relative to the retained original input buffer; its end is not a reconstructed historical file boundary.", 0);
	sdb_set (db, "nb02.limit", "Structural byte/arithmetic compatibility only; no symbol/type import, complete debug-directory claim, historical producer attribution, or conclusion about removed/truncated/absent debug information.", 0);
	sdb_num_set (db, "nb02.retained_size", size, 0);
	sdb_num_set (db, "nb02.initial.count", count, 0);
	sdb_bool_set (db, "nb02.footer.present", terminal, 0);
	if (terminal) {
		sdb_num_set (db, "nb02.footer.offset", size - sizeof (footer), 0);
		sdb_num_set (db, "nb02.footer.distance", distance, 0);
		if (distance > size) {
			sdb_set (db, "nb02.footer.target", r_strf ("-0x%" PFMT64x, distance - size), 0);
		} else {
			sdb_num_set (db, "nb02.footer.target", target, 0);
		}
		sdb_bool_set (db, "nb02.footer.relation_qualified", linked, 0);
	}
	return true;
}

#endif
