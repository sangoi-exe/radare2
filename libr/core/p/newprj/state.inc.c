/* radare - MIT - Copyright 2026 - pancake */

#define RPRJ_STATE_HEADER_SIZE 80

typedef struct {
	ut32 kind;
	ut32 cache_mode;
	ut32 va;
	ut32 loader;
	ut64 size;
	ut64 baddr;
	ut64 loadaddr;
	ut8 digest[R_HASH_SIZE_SHA256];
	ut32 relocs;
} RPrjState;

static bool rprj_state_current(RPrjCursor *cur, RPrjState *state, const char **loader) {
	RCore *core = cur->core;
	RBinFile *bf = r_bin_cur (core->bin);
	RIODesc *desc = bf? r_io_desc_get (core->io, bf->fd): core->io->desc;
	if (r_config_get_b (core->config, "cfg.debug") || !desc || !desc->plugin
			|| strcmp (desc->plugin->meta.name, "default") || !(desc->perm & R_PERM_R)
			|| (desc->perm & R_PERM_W) || core->io->p_cache) {
		return false;
	}
	RBinPlugin *plugin = bf? r_bin_file_cur_plugin (bf): NULL;
	if (bf && (!bf->bo || !plugin)) {
		return false;
	}
	state->kind = bf? 1: 2;
	state->cache_mode = core->io->cache.mode;
	state->va = core->io->va;
	state->size = r_io_desc_size (desc);
	state->baddr = bf? bf->bo->baddr: 0;
	state->loadaddr = bf? bf->bo->loadaddr: 0;
	state->relocs = r_config_get_b (core->config, "bin.relocs.apply");
	*loader = bf? plugin->meta.name: "";
	if (!state->size || state->size == UT64_MAX) {
		return false;
	}
	const ut64 position = r_io_desc_seek (desc, 0, R_IO_SEEK_CUR);
	RHash *hash = r_hash_new (false, R_HASH_SHA256);
	ut8 buf[65536];
	ut64 at = 0;
	bool ok = true;
	while (at < state->size) {
		const int len = R_MIN ((ut64)sizeof (buf), state->size - at);
		// Physical plugin reads exclude virtual edits, loader overlays and descriptor caches.
		if (r_io_plugin_read_at (desc, at, buf, len) != len) {
			ok = false;
			break;
		}
		r_hash_do_sha256 (hash, buf, len);
		at += len;
	}
	r_hash_do_end (hash, R_HASH_SHA256);
	memcpy (state->digest, hash->digest, sizeof (state->digest));
	r_hash_free (hash);
	r_io_desc_seek (desc, position, R_IO_SEEK_SET);
	return ok;
}

static bool rprj_state_write(RPrjCursor *cur, bool snapshot) {
	RPrjState state = {0};
	const char *loader = "";
	if (!rprj_state_current (cur, &state, &loader)) {
		if (snapshot) {
			return false;
		}
		state = (RPrjState) {0};
	}
	state.loader = rprj_st_append (cur->st, loader);
	if (state.loader == UT32_MAX) {
		return false;
	}
	RBuffer *b = cur->b;
	const ut64 start = r_buf_at (b);
	rprj_write_le32 (b, state.kind);
	rprj_write_le32 (b, state.cache_mode);
	rprj_write_le32 (b, state.va);
	rprj_write_le32 (b, state.loader);
	rprj_write_le64 (b, state.size);
	rprj_write_le64 (b, state.baddr);
	rprj_write_le64 (b, state.loadaddr);
	r_buf_write (b, state.digest, sizeof (state.digest));
	rprj_write_le32 (b, state.relocs);
	const ut64 count_at = r_buf_at (b);
	rprj_write_le32 (b, 0);
	ut32 count = 0;
	RListIter *iter;
	RIOCacheLayer *layer;
	r_list_foreach (cur->core->io->cache.layers, iter, layer) {
		RIOCacheItem **item;
		R_VEC_FOREACH (layer->vec, item) {
			const RInterval *span = (*item)->tree_itv;
			if (!span || !span->size) {
				continue;
			}
			if (span->size > INT_MAX || span->addr > UT64_MAX - span->size || count == UT32_MAX
					|| r_buf_at (b) - start > UT32_MAX - RPRJ_ENTRY_SIZE - 12 - span->size) {
				return false;
			}
			ut8 *data = malloc (span->size);
			if (!data) {
				return false;
			}
			// Save effective bytes only, not cache layer or undo history.
			const bool ok = r_io_cache_read_at (cur->core->io, span->addr, data, span->size);
			if (ok) {
				rprj_write_le64 (b, span->addr);
				rprj_write_le32 (b, span->size);
				r_buf_write (b, data, span->size);
				count++;
			}
			free (data);
			if (!ok) {
				return false;
			}
		}
	}
	ut8 encoded[4];
	r_write_le32 (encoded, count);
	r_buf_write_at (b, count_at, encoded, sizeof (encoded));
	return true;
}

static bool rprj_state_maps_match(RPrjCursor *cur) {
	ut32 size;
	ut8 *data = rprj_find (cur->b, RPRJ_MAPS, &size);
	RVecPrjMap *maps = rprj_maps_current (cur);
	bool ok = data && maps && size % RPRJ_MAP_SIZE == 0
		&& size / RPRJ_MAP_SIZE == RVecPrjMap_length (maps);
	RBuffer *b = data? r_buf_new_with_bytes (data, size): NULL;
	ok &= b != NULL;
	RPrjMap *map;
	if (ok) {
		R_VEC_FOREACH (maps, map) {
			R2ProjectMap saved;
			if (!rprj_map_read (b, &saved) || saved.pmin != map->pmin || saved.pmax != map->pmax
					|| saved.vmin != map->vmin || saved.vmax != map->vmax) {
				ok = false;
				break;
			}
		}
	}
	r_unref (b);
	RVecPrjMap_free (maps);
	free (data);
	return ok;
}

static bool rprj_state_validate(RPrjCursor *cur, const ut8 *data, ut32 size) {
	if (size < RPRJ_STATE_HEADER_SIZE) {
		return false;
	}
	RPrjState current = {0};
	const char *loader;
	const char *saved_loader = rprj_st_get (cur->st, r_read_le32 (data + 12));
	if (!saved_loader || !rprj_state_current (cur, &current, &loader)
			|| r_read_le32 (data) != current.kind || r_read_le32 (data + 8) != current.va
			|| strcmp (saved_loader, loader) || r_read_le64 (data + 16) != current.size
			|| r_read_le64 (data + 24) != current.baddr || r_read_le64 (data + 32) != current.loadaddr
			|| memcmp (data + 40, current.digest, sizeof (current.digest))
			|| r_read_le32 (data + 72) != current.relocs
			|| (r_read_le32 (data + 4) & ~R_PERM_RWX) || !rprj_state_maps_match (cur)) {
		return false;
	}
	ut32 count = r_read_le32 (data + 76);
	ut64 at = RPRJ_STATE_HEADER_SIZE;
	while (count--) {
		if (size - at < 12) {
			return false;
		}
		const ut64 addr = r_read_le64 (data + at);
		const ut32 len = r_read_le32 (data + at + 8);
		at += 12;
		if (!len || len > INT_MAX || len > size - at || addr > UT64_MAX - len) {
			return false;
		}
		at += len;
	}
	return at == size;
}

static bool rprj_state_restore(RPrjCursor *cur, const ut8 *data) {
	RIO *io = cur->core->io;
	ut32 count = r_read_le32 (data + 76);
	ut64 at = RPRJ_STATE_HEADER_SIZE;
	// Retain the normally loaded original's relocation cache beneath the selected edits.
	while (count--) {
		const ut64 addr = r_read_le64 (data + at);
		const ut32 len = r_read_le32 (data + at + 8);
		at += 12;
		if (!r_io_cache_write_at (io, addr, data + at, len)) {
			R_LOG_ERROR ("Cannot restore virtual edit at 0x%" PFMT64x, addr);
			return false;
		}
		at += len;
	}
	const ut32 mode = r_read_le32 (data + 4);
	r_config_set_b (cur->core->config, "io.cache", !!(mode & R_PERM_X));
	r_config_set_b (cur->core->config, "io.cache.read", !!(mode & R_PERM_R));
	r_config_set_b (cur->core->config, "io.cache.write", !!(mode & R_PERM_W));
	r_core_block_read (cur->core);
	return true;
}
