#ifndef R_BIN_PRIVATE_H_
#define R_BIN_PRIVATE_H_

#include <r_bin.h>
#include <r_util.h>
#include <r_types.h>

typedef struct r_bin_trycatch_store_t RBinTrycatchStore;

typedef struct {
	RBuffer *bytes;
	RBuffer *input;
	RIO *io;
	RIODesc *desc;
	RBinPlugin *plugin;
	RIOOverlayWriteAt writer;
	ut64 baddr;
	st64 baddr_shift;
	ut64 loadaddr;
	ut64 offset;
	ut64 map_generation;
	ut32 bank;
	int fd;
	int va;
	bool relocs;
	bool pending;
	bool failed;
	bool qualified;
} RBinLoaderBaseline;

typedef struct {
	RBinTrycatchStore *trycatch;
	RBinLoaderBaseline *loader;
} RBinObjectPrivate;

static inline RBinObjectPrivate *r_bin_object_private_get(RBinObject *bo, bool create) {
	if (!bo->trycatch && create) {
		bo->trycatch = R_NEW0 (RBinObjectPrivate);
	}
	return bo->trycatch;
}

static inline RBinLoaderBaseline *r_bin_loader_baseline_begin(RBinFile *bf, bool relocs) {
	RBinObject *bo = bf->bo;
	RBinObjectPrivate *priv = r_bin_object_private_get (bo, true);
	if (priv->loader) {
		return priv->loader;
	}
	RBinLoaderBaseline *baseline = R_NEW0 (RBinLoaderBaseline);
	priv->loader = baseline;
	RIO *io = bf->rbin->iob.io;
	baseline->bytes = r_buf_new_sparse (0);
	baseline->input = bf->buf;
	baseline->io = io;
	baseline->fd = bf->fd;
	baseline->desc = io? r_io_desc_get (io, bf->fd): NULL;
	baseline->plugin = bo->plugin;
	baseline->baddr = bo->baddr;
	baseline->baddr_shift = bo->baddr_shift;
	baseline->loadaddr = bo->loadaddr;
	baseline->offset = bf->offset;
	baseline->relocs = relocs;
	baseline->pending = true;
	baseline->failed = !baseline->bytes || !baseline->desc || bo->is_reloc_patched;
	return baseline;
}

static inline void r_bin_loader_baseline_record(RBinLoaderBaseline *baseline, ut64 addr, const ut8 *bytes, int len) {
	if (baseline->failed) {
		return;
	}
	if (!baseline->pending || len < 1 || addr > UT64_MAX - len) {
		baseline->failed = true;
		return;
	}
	RList *ranges = r_buf_nonempty_list (baseline->bytes);
	if (!ranges) {
		baseline->failed = true;
		return;
	}
	RListIter *iter;
	RBufferSparseItem *range;
	r_list_foreach (ranges, iter, range) {
		const ut64 start = R_MAX (addr, range->from);
		const ut64 end = R_MIN (addr + len, range->to);
		if (start < end) {
			// Sparse ranges can overlap; keep every retained copy current before filling gaps.
			memcpy (range->data + start - range->from, bytes + start - addr, end - start);
		}
	}
	r_list_free (ranges);
	if (r_buf_write_at (baseline->bytes, addr, bytes, len) != len) {
		baseline->failed = true;
	}
}

static inline bool loader_baseline_object_matches(RBinLoaderBaseline *baseline, RBinFile *bf, bool relocs) {
	RBinObject *bo = bf->bo;
	RIO *io = bf->rbin->iob.io;
	return bf == bf->rbin->cur && baseline->io == io && baseline->fd == bf->fd
		&& baseline->desc == r_io_desc_get (io, bf->fd) && baseline->input == bf->buf
		&& baseline->plugin == bo->plugin && baseline->baddr == bo->baddr
		&& baseline->baddr_shift == bo->baddr_shift && baseline->loadaddr == bo->loadaddr
		&& baseline->offset == bf->offset && baseline->relocs == relocs;
}

static inline void r_bin_loader_baseline_finish(RBinFile *bf, bool relocs) {
	RBinObjectPrivate *priv = r_bin_object_private_get (bf->bo, false);
	RBinLoaderBaseline *baseline = priv? priv->loader: NULL;
	if (!baseline || !baseline->pending) {
		return;
	}
	baseline->pending = false;
	baseline->qualified = !baseline->failed && loader_baseline_object_matches (baseline, bf, relocs);
	baseline->map_generation = baseline->io? baseline->io->mts: 0;
	baseline->bank = baseline->io? baseline->io->bank: 0;
	baseline->va = baseline->io? baseline->io->va: 0;
}

static inline const RBinLoaderBaseline *r_bin_loader_baseline_get(RBinFile *bf, bool relocs) {
	RBinObjectPrivate *priv = r_bin_object_private_get (bf->bo, false);
	RBinLoaderBaseline *baseline = priv? priv->loader: NULL;
	if (!baseline || !baseline->qualified || baseline->failed || baseline->pending) {
		return NULL;
	}
	if (!loader_baseline_object_matches (baseline, bf, relocs)
			|| baseline->map_generation != baseline->io->mts || baseline->bank != baseline->io->bank
			|| baseline->va != baseline->io->va) {
		baseline->qualified = false;
		return NULL;
	}
	return baseline;
}

static inline void r_bin_loader_baseline_invalidate(RBinObject *bo) {
	RBinObjectPrivate *priv = r_bin_object_private_get (bo, false);
	if (priv && priv->loader) {
		priv->loader->failed = true;
		priv->loader->qualified = false;
	}
}

R_IPI RBinFile *r_bin_file_new(RBin *bin, const char *file, ut64 file_sz, RBinFileOptions *opt, Sdb *sdb, bool steal_ptr);
R_IPI RBinObject *r_bin_file_object_find_by_id(RBinFile *binfile, ut32 binobj_id);
R_IPI RVecRBinString *r_bin_file_get_strings(RBinFile *a, int min, int raw, RStrBuf *output);
R_IPI RBinFile *r_bin_file_find_by_object_id(RBin *bin, ut32 binobj_id);
R_IPI RBinFile *r_bin_file_find_by_id(RBin *bin, ut32 binfile_id);
R_IPI bool r_bin_file_set_obj(RBin *bin, RBinFile *bf, RBinObject *obj);
R_IPI RBinFile *r_bin_file_xtr_load_bytes(RBin *bin, RBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
R_IPI bool r_bin_file_set_bytes(RBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr);

static inline ut64 r_bin_file_get_buffer_offset(RBinFile *bf, ut64 paddr) {
	RBinObject *bo = bf->bo;
	if (bo && (r_sub_overflow (paddr, bo->loadaddr, &paddr)
			|| r_sub_overflow (paddr, bo->boffset, &paddr))) {
		return UT64_MAX;
	}
	return paddr;
}

R_IPI RBinPlugin *r_bin_get_binplugin_any(RBin *bin);

static inline Sdb *open_ordinalsdb(const char *sdbdir, const char *mod) {
	char *sfn = r_str_newf ("%s%s%s.sdb",
			r_str_get_fail (sdbdir, "."), R_SYS_DIR, mod);
	Sdb *db = r_file_exists (sfn)? sdb_new (NULL, sfn, 0): NULL;
	free (sfn);
	return db;
}

static inline bool limit_reached(const RList *list, int limit) {
	return limit > 0 && r_list_length (list) >= limit;
}

static inline bool limit_reached_vec(const RVecRBinSymbol *vec, int limit) {
	return limit > 0 && RVecRBinSymbol_length (vec) >= (size_t)limit;
}

static inline bool limit_reached_vec_imports(const RVecRBinImport *vec, int limit) {
	return limit > 0 && RVecRBinImport_length (vec) >= (size_t)limit;
}

R_IPI void r_bin_object_free(void /*RBinObject*/ *o_);
R_IPI void r_bin_trycatch_free(void *store);
R_IPI ut64 r_bin_object_get_baddr(RBinObject *o);
R_IPI RBinSymbol *r_bin_object_get_symbol_at(RBinObject *o, ut64 addr);
R_IPI void r_bin_object_filter_strings(RBinObject *bo);

static inline void r_bin_strings_index_insert(HtUP *index, ut64 vaddr, size_t string_index) {
	if (index) {
		ht_up_insert (index, vaddr, (void *)(size_t)(string_index + 1));
	}
}

static inline HtUP *r_bin_strings_build_index(RVecRBinString *strings) {
	if (!strings) {
		return NULL;
	}
	HtUP *index = ht_up_new0 ();
	if (!index) {
		return NULL;
	}
	RBinString *string;
	size_t i = 0;
	R_VEC_FOREACH (strings, string) {
		r_bin_strings_index_insert (index, string->vaddr, i);
		i++;
	}
	return index;
}

static inline HtUP *r_bin_object_ensure_strings_db(RBinObject *bo) {
	if (!bo) {
		return NULL;
	}
	if (!bo->strings_db) {
		bo->strings_db = r_bin_strings_build_index (&bo->strings);
	}
	return bo->strings_db;
}

static inline RBinString *r_bin_strings_index_get(RVecRBinString *strings, HtUP *index, ut64 addr) {
	if (!strings || !index || addr == 0 || addr == UT64_MAX) {
		return NULL;
	}
	void *value = ht_up_find (index, addr, NULL);
	if (!value) {
		return NULL;
	}
	RBinString *string = RVecRBinString_at (strings, (size_t)value - 1);
	return string && string->vaddr == addr? string: NULL;
}

static inline void r_bin_strings_index_update_after_remove(RVecRBinString *strings, HtUP *index, ut64 vaddr, size_t string_index) {
	if (!strings || !index) {
		return;
	}
	ht_up_delete (index, vaddr);
	bool found = false;
	size_t i;
	for (i = string_index; i < RVecRBinString_length (strings); i++) {
		RBinString *string = RVecRBinString_at (strings, i);
		if (string) {
			if (string->vaddr == vaddr) {
				found = true;
			}
			r_bin_strings_index_insert (index, string->vaddr, i);
		}
	}
	if (!found) {
		for (i = string_index; i > 0; i--) {
			RBinString *string = RVecRBinString_at (strings, i - 1);
			if (string && string->vaddr == vaddr) {
				r_bin_strings_index_insert (index, string->vaddr, i - 1);
				break;
			}
		}
	}
}

static inline void r_bin_take_strings(RVecRBinString *dst, RVecRBinString *src) {
	if (src) {
		RVecRBinString_swap (dst, src);
		RVecRBinString_free (src);
	}
}

static inline void r_bin_object_drop_strings_db(RBinObject *bo) {
	if (bo) {
		ht_up_free (bo->strings_db);
		bo->strings_db = NULL;
	}
}

R_IPI RBinObject *r_bin_object_new(RBinFile *binfile, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz);
R_IPI RBinObject *r_bin_object_get_cur(RBin *bin);
R_IPI RBinObject *r_bin_object_find_by_arch_bits(RBinFile *binfile, const char *arch, int bits, const char *name);
R_IPI RVecRBinReloc *r_bin_object_patch_relocs(RBinFile *binfile, RBinObject *o);

R_IPI bool r_bin_name_is_unnamed(const char *name);

R_IPI const char *r_bin_lang_tostring(RBinLanguage lang);
R_IPI RBinLanguage r_bin_lang_type(RBinFile *binfile, const char *def, const char *sym);
R_IPI RBinLanguage r_bin_lang_from_symbol_name(const char *sym);
R_IPI void r_bin_register_symbol_language(RBinFile *binfile, RBinSymbol *symbol);
R_IPI bool r_bin_lang_rustv0(const char *sym);
R_IPI bool r_bin_lang_swift(RBinFile *binfile);

R_IPI void r_bin_class_free(RBinClass *c);
R_IPI RBinSymbol *r_bin_class_add_method(RBinFile *binfile, const char *classname, const char *name, int nargs);
R_IPI void r_bin_class_add_field(RBinFile *binfile, const char *classname, const char *name);

R_IPI RBinFile *r_bin_file_xtr_load(RBin *bin, RBinXtrPlugin *xtr, const char *filename, RBuffer *buf, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
R_IPI RBinFile *r_bin_file_new_from_buffer(RBin *bin, const char *file, RBuffer *buf, RBinFileOptions *opt);

// parse the Itanium C++ ABI LSDA at lsda_addr filling result with RBinTrycatch entries
R_IPI void r_bin_dwarf_parse_lsda(RBinFile *bf, RVecRBinTrycatch *result, ut64 fcn_addr, ut64 lsda_addr);
// walk the FDEs in the eh_frame section parsing the LSDA referenced by each one
R_IPI void r_bin_dwarf_parse_eh_frame(RBinFile *bf, RVecRBinTrycatch *result);

#endif
