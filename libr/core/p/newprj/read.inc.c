/* radare - MIT - Copyright 2024-2026 - pancake */

#include "newprj.h"

static const char *rprj_entry_type_tostring(int a) {
	switch (a) {
	case RPRJ_INFO: return "Info";
	case RPRJ_MAPS: return "Maps";
	case RPRJ_CMDS: return "Cmds";
	case RPRJ_FLAG: return "Flags";
	case RPRJ_CMNT: return "Comments";
	case RPRJ_MODS: return "Mods";
	case RPRJ_BLOB: return "Blob";
	case RPRJ_STRS: return "Strings";
	case RPRJ_THEM: return "Theme";
	case RPRJ_HINT: return "Hints";
	case RPRJ_EVAL: return "Evals";
	case RPRJ_XREF: return "Xrefs";
	case RPRJ_FUNC: return "Functions";
	case RPRJ_VART: return "VarTypes";
	case RPRJ_BRKP: return "Breakpoints";
	case RPRJ_SIGS: return "Signals";
	case RPRJ_TYPE: return "Types";
	case RPRJ_TLNK: return "TypeLinks";
	case RPRJ_FMT: return "Formats";
	case RPRJ_GLOB: return "Globals";
	case RPRJ_STATE: return "State";
	}
	return "UNKNOWN";
}

static const char *rprj_st_get(R2ProjectStringTable *st, ut32 idx) {
	if (!st || !st->data || idx >= st->size) {
		return NULL;
	}
	const ut8 *s = st->data + idx;
	return memchr (s, 0, st->size - idx)? (const char *)s: NULL;
}

static bool rprj_st_is_valid(R2ProjectStringTable *st) {
	return st && st->data && st->size > 0 && st->data[st->size - 1] == 0 && rprj_st_get (st, 0);
}

static bool rprj_read_exact(RBuffer *b, ut8 *buf, size_t len) {
	return r_buf_read (b, buf, len) == (st64)len;
}

static bool rprj_header_read(RBuffer *b, R2ProjectHeader *hdr) {
	ut8 buf[RPRJ_HEADER_SIZE];
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	hdr->magic = r_read_le32 (buf + r_offsetof (R2ProjectHeader, magic));
	hdr->version = r_read_le32 (buf + r_offsetof (R2ProjectHeader, version));
	return hdr->magic == RPRJ_MAGIC;
}

static bool rprj_entry_read(RBuffer *b, R2ProjectEntry *entry) {
	ut8 buf[RPRJ_ENTRY_SIZE];
	R_LOG_DEBUG ("reading entry at 0x%08"PFMT64x, r_buf_at (b));
	if (!rprj_read_exact (b, buf, sizeof (buf))) {
		return false;
	}
	entry->size = r_read_le32 (buf + r_offsetof (R2ProjectEntry, size));
	entry->type = r_read_le32 (buf + r_offsetof (R2ProjectEntry, type));
	R_LOG_DEBUG ("entry at 0x%08"PFMT64x" with type=%d(%s) and size=%d",
			r_buf_at (b), entry->type, rprj_entry_type_tostring (entry->type), entry->size);
	return true;
}

static ut8 *rprj_find(RBuffer *b, ut32 type, ut32 *size) {
	r_buf_seek (b, RPRJ_HEADER_SIZE, SEEK_SET);
	const ut64 last = r_buf_size (b);
	ut64 at = r_buf_at (b);
	*size = 0;
	while (r_buf_at (b) < last) {
		R2ProjectEntry entry = {0};
		if (!rprj_entry_read (b, &entry)) {
			R_LOG_ERROR ("find: Cannot read entry");
			break;
		}
		if (entry.size < RPRJ_ENTRY_SIZE || entry.size > last - at) {
			R_LOG_ERROR ("invalid size");
			break;
		}
		if (entry.type == type) {
			const ut32 data_size = entry.size - RPRJ_ENTRY_SIZE;
			ut8 *buf = data_size? malloc (data_size): R_NEWS0 (ut8, 1);
			if (buf) {
				if (data_size && r_buf_read_at (b, at + RPRJ_ENTRY_SIZE, buf, data_size) != (st64)data_size) {
					free (buf);
					return NULL;
				}
				*size = data_size;
				return buf;
			}
			return NULL;
		}
		at += entry.size;
		r_buf_seek (b, at, SEEK_SET); // entry.size, SEEK_CUR);
	}
	return NULL;
}

static RBuffer *rprj_read_open(const char *file, R2ProjectHeader *hdr, R2ProjectStringTable *st) {
	RBuffer *b = r_buf_new_from_file (file);
	if (!b) {
		R_LOG_ERROR ("Cannot open file");
		return NULL;
	}
	if (!rprj_header_read (b, hdr)) {
		R_LOG_ERROR ("Invalid file type");
		goto fail;
	}
	if (hdr->version != RPRJ_VERSION) {
		R_LOG_ERROR ("Unsupported project version %d (this build understands version %d)", hdr->version, RPRJ_VERSION);
		goto fail;
	}
	st->data = rprj_find (b, RPRJ_STRS, &st->size);
	if (!st->data) {
		R_LOG_ERROR ("Missing string table (RPRJ_STRS) in project file");
		goto fail;
	}
	if (!rprj_st_is_valid (st)) {
		R_LOG_ERROR ("Invalid string table (RPRJ_STRS) in project file");
		R_FREE (st->data);
		goto fail;
	}
	return b;
fail:
	r_unref (b);
	return NULL;
}

static bool rprj_is_old_ne(RBuffer *b, R2ProjectStringTable *st) {
	ut32 size;
	ut8 *state = rprj_find (b, RPRJ_STATE, &size);
	const char *loader = state && size >= 16? rprj_st_get (st, r_read_le32 (state + 12)): NULL;
	const bool ne = loader && !strcmp (loader, "ne") && r_read_le32 (state) == 1;
	free (state);
	if (!ne) {
		return false;
	}
	ut8 *eval = rprj_find (b, RPRJ_EVAL, &size);
	bool old = false;
	if (eval && size >= 4) {
		const ut32 count = r_read_le32 (eval);
		ut32 i;
		for (i = 0; i < count && i < (size - 4) / 8; i++) {
			const char *key = rprj_st_get (st, r_read_le32 (eval + 4 + i * 8));
			const char *value = rprj_st_get (st, r_read_le32 (eval + 8 + i * 8));
			if (key && value && !strcmp (key, "asm.addr.segment.bits")) {
				old = r_num_math (NULL, value) == 16;
				break;
			}
		}
	}
	free (eval);
	return old;
}
