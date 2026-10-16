/* radare - LGPL - Copyright 2019-2025 - GustavoLCR */

#include "ne.h"
#include <sdb/ht_uu.h>

static bool ne_header_at(RBuffer *buf, ut64 offset) {
	ut64 bufsz = r_buf_size (buf);
	if (offset > bufsz || bufsz - offset <= 26) {
		return false;
	}
	ut8 magic[2];
	return r_buf_read_at (buf, offset, magic, sizeof (magic)) == sizeof (magic)
		&& !memcmp (magic, "NE", sizeof (magic));
}

bool r_bin_ne_get_header_offset(RBuffer *buf, R_OUT ut32 *offset) {
	if (!buf || !offset || r_buf_size (buf) < 0x40) {
		return false;
	}
	ut32 candidate = r_buf_read_le32_at (buf, 0x3c);
	if (ne_header_at (buf, candidate)) {
		*offset = candidate;
		return true;
	}
	ut16 legacy = candidate;
	if (legacy != candidate && ne_header_at (buf, legacy)) {
		*offset = legacy;
		return true;
	}
	return false;
}

static char *__get_target_os(r_bin_ne_obj_t *bin) {
	const int targetOS = (bin->ne_header) ? bin->ne_header->targOS: 0;
	switch (targetOS) {
	case 1:
		return "OS/2";
	case 2:
		return "Windows";
	case 3:
		return "European MS-DOS 4.x";
	case 4:
		return "Windows 386";
	case 5:
		return "BOSS (Borland Operating System Services)";
	default:
		return "Unknown";
	}
}

static int __translate_perms(int flags) {
	// Analysis must read code even when the NE segment is execute-only.
	int perms = R_PERM_R;
	if (flags & IS_DATA) {
		if (!(flags & 0x80)) { // NE data read-only flag, not the discardable bit.
			perms |= R_PERM_W;
		}
	} else {
		perms |= R_PERM_X;
	}
	return perms;
}

static char *pascalstr_at(RBuffer *buf, ut64 offset, ut64 end, R_OUT ut8 * R_NULLABLE size_out) {
	if (offset >= end) {
		return NULL;
	}
	ut8 size = r_buf_read8_at (buf, offset);
	if (!size || size > end - offset - 1) {
		return NULL;
	}
	char *str = malloc ((ut64)size + 1);
	if (!str) {
		return NULL;
	}
	if (r_buf_read_at (buf, offset + 1, (ut8 *)str, size) != size) {
		free (str);
		return NULL;
	}
	str[size] = 0;
	if (size_out) {
		*size_out = size;
	}
	return str;
}

static char *__func_name_from_ord(const char *module, ut16 ordinal) {
	if (!module) {
		return NULL;
	}
	char *lower_module = strdup (module);
	r_str_case (lower_module, false);
	char *pfx = r_sys_prefix (NULL);
	char *path = r_str_newf (R_JOIN_4_PATHS ("%s", R2_SDB_FORMAT, "dll", "%s.sdb"), pfx, lower_module);
	free (pfx);
	free (lower_module);
	char *name = NULL;
	if (r_file_exists (path)) {
		Sdb *sdb = sdb_new (NULL, path, 0);
		const char *value = sdb_const_getf (sdb, NULL, "%d", ordinal);
		name = value? strdup (value): NULL;
		sdb_free (sdb);
	}
	if (!name) {
		name = r_str_newf ("%d", ordinal);
	}
	free (path);
	return name;
}

bool r_bin_ne_load_segments(r_bin_ne_obj_t *bin, RVecRBinSection *segments) {
	int i;
	if (!bin || !bin->segment_entries || !bin->ne_header || !segments) {
		return false;
	}
	RVecRBinSection_clear (segments);
	for (i = 0; i < bin->ne_header->SegCount; i++) {
		RBinSection *bs = RVecRBinSection_emplace_back (segments);
		if (!bs) {
			return false;
		}
		NE_image_segment_entry *se = &bin->segment_entries[i];
		bs->size = se->offset? (se->length? se->length: 0x10000): 0;
		bs->vsize = R_MAX (bs->size, se->minAllocSz? se->minAllocSz: 0x10000);
		// Synthetic analysis segment IDs, not Windows runtime selectors.
		bs->vaddr = (ut64)(i + 1) << 16;
		bs->add = true;
		bs->bits = R_SYS_BITS_PACK (16);
		bs->is_data = se->flags & IS_DATA;
		bs->perm = __translate_perms (se->flags);
		bs->paddr = (ut64)se->offset * bin->alignment;
		bs->name = r_str_newf ("%s.%" PFMT64d, se->flags & IS_MOVEABLE ? "MOVEABLE" : "FIXED", bs->paddr);
		bs->is_segment = true;
	}
	return true;
}

static bool ne_has_symbol_at(RVecRBinSymbol *vec, ut64 vaddr) {
	RBinSymbol *s;
	R_VEC_FOREACH (vec, s) {
		if (s->vaddr == vaddr) {
			return true;
		}
	}
	return false;
}

void r_bin_ne_load_symbols(r_bin_ne_obj_t *bin, RVecRBinSymbol *symbols) {
	if (!bin->ne_header) {
		return;
	}
	ut64 bufsz = r_buf_size (bin->buf);
	ut64 off = (ut64)bin->ne_header->ResidNamTable + bin->header_offset;
	bool resident = true, first = true;
	while (true) {
		if (off >= bufsz) {
			break;
		}
		ut8 sz = r_buf_read8_at (bin->buf, off);
		if (!sz) {
			first = true;
			if (resident) {
				resident = false;
				off = bin->ne_header->OffStartNonResTab;
				if (off >= bufsz || !r_buf_read8_at (bin->buf, off)) {
					break;
				}
			} else {
				break;
			}
		}
		char *name = pascalstr_at (bin->buf, off, bufsz, &sz);
		if (!name) {
			break;
		}
		off += (ut64)sz + 1;
		if (bufsz - off < sizeof (ut16)) {
			free (name);
			break;
		}
		ut16 entry_off = r_buf_read_le16_at (bin->buf, off);
		off += sizeof (ut16);
		if (!entry_off) {
			free (name);
			first = false;
			continue;
		}
		RBinSymbol *sym = RVecRBinSymbol_emplace_back (symbols);
		if (!sym) {
			free (name);
			return;
		}
		sym->name = r_bin_name_new_from (name);
		if (!first) {
			sym->bind = R_BIN_BIND_GLOBAL_STR;
		}
		RBinAddr *entry = RVecNEEntry_at (&bin->entries, entry_off - 1);
		sym->paddr = entry && entry->vaddr? entry->paddr: UT64_MAX;
		sym->vaddr = entry && entry->vaddr? entry->vaddr: UT64_MAX;
		sym->ordinal = entry_off;
		first = false;
	}
	RBinAddr *entry;
	size_t ordinal = 1;
	R_VEC_FOREACH (&bin->entries, entry) {
		if (entry->vaddr && !ne_has_symbol_at (symbols, entry->vaddr)) {
			RBinSymbol *sym = RVecRBinSymbol_emplace_back (symbols);
			if (!sym) {
				return;
			}
			sym->name = r_bin_name_new_from (r_str_newf ("entry%zu", ordinal));
			sym->paddr = entry->paddr;
			sym->vaddr = entry->vaddr;
			sym->bind = R_BIN_BIND_GLOBAL_STR;
			sym->ordinal = ordinal;
		}
		ordinal++;
	}
	RBinImport *imp;
	size_t index = 0;
	R_VEC_FOREACH (&bin->imports, imp) {
		RBinSymbol *sym = RVecRBinSymbol_emplace_back (symbols);
		if (!sym) {
			return;
		}
		sym->name = r_bin_name_clone (imp->name);
		sym->paddr = UT64_MAX;
		sym->vaddr = bin->imports_base + index++ * 4;
		sym->ordinal = imp->ordinal;
		sym->is_imported = true;
		sym->type = R_BIN_TYPE_FUNC_STR;
		sym->attr.size = 4;
	}
}

static char *__resource_type_str(int type) {
	static const char *names[] = {
		/*  0 */ NULL,
		/*  1 */ "CURSOR",
		/*  2 */ "BITMAP",
		/*  3 */ "ICON",
		/*  4 */ "MENU",
		/*  5 */ "DIALOG",
		/*  6 */ "STRING",
		/*  7 */ "FONTDIR",
		/*  8 */ "FONT",
		/*  9 */ "ACCELERATOR",
		/* 10 */ "RCDATA",
		/* 11 */ "MESSAGETABLE",
		/* 12 */ "GROUP_CURSOR",
		/* 13 */ NULL,
		/* 14 */ "GROUP_ICON",
		/* 15 */ "NAMETABLE",
		/* 16 */ "VERSION",
		/* 17 */ "DLGINCLUDE",
		/* 18 */ NULL,
		/* 19 */ "PLUGPLAY",
		/* 20 */ "VXD",
		/* 21 */ "ANICURSOR",
		/* 22 */ "ANIICON",
		/* 23 */ "HTML",
		/* 24 */ "MANIFEST"
	};
	if ((unsigned)type < (sizeof names / sizeof names[0]) && names[type]) {
		return strdup (names[type]);
	}
	return r_str_newf("UNKNOWN (%d)", type);
}

static void __free_resource_entry(void *entry) {
	r_ne_resource_entry *en = (r_ne_resource_entry *)entry;
	free (en->name);
	free (en);
}

static void __free_resource(void *resource) {
	r_ne_resource *res = (r_ne_resource *)resource;
	free (res->name);
	r_list_free (res->entry);
	free (res);
}

static bool __ne_get_resources(r_bin_ne_obj_t *bin) {
	if (!bin || !bin->ne_header) {
		return false;
	}
	if (!bin->resources) {
		bin->resources = r_list_newf (__free_resource);
		if (!bin->resources) {
			return false;
		}
	}
	ut64 bufsz = r_buf_size (bin->buf);
	ut64 resoff = (ut64)bin->ne_header->ResTableOffset + bin->header_offset;
	ut64 resend = (ut64)bin->ne_header->ResidNamTable + bin->header_offset;
	if (!bin->ne_header->ResTableOffset || !bin->ne_header->ResidNamTable
		|| resoff >= resend || resend > bufsz || resend - resoff < sizeof (ut16)) {
		return true;
	}
	ut16 alignment = r_buf_read_le16_at (bin->buf, resoff);
	if (alignment >= sizeof (ut64) * 8) {
		return false;
	}
	ut64 shift_limit = bufsz >> alignment;
	ut64 off = resoff + 2;
	while (off <= resend && resend - off >= sizeof (NE_image_typeinfo_entry)) {
		NE_image_typeinfo_entry ti = {0};
		if (r_buf_fread_at (bin->buf, off, (ut8 *)&ti, "2si", 1) != sizeof (ti)) {
			return false;
		}
		if (!ti.rtTypeID) {
			return true;
		}
		off += sizeof (NE_image_typeinfo_entry);
		if (ti.rtResourceCount > (resend - off) / sizeof (NE_image_nameinfo_entry)) {
			return false;
		}
		r_ne_resource *res = R_NEW0 (r_ne_resource);
		res->entry = r_list_newf (__free_resource_entry);
		if (!res->entry) {
			free (res);
			return false;
		}
		if (ti.rtTypeID & 0x8000) {
			res->type_id = ti.rtTypeID & ~0x8000;
			res->name = __resource_type_str (res->type_id);
		} else if (ti.rtTypeID < resend - resoff) {
			res->named = true;
			res->name = pascalstr_at (bin->buf, resoff + ti.rtTypeID, resend, NULL);
		} else {
			__free_resource (res);
			return false;
		}
		if (!res->name) {
			__free_resource (res);
			return false;
		}
		int i;
		for (i = 0; i < ti.rtResourceCount; i++) {
			NE_image_nameinfo_entry ni = {0};
			if (r_buf_fread_at (bin->buf, off, (ut8 *)&ni, "6s", 1) != sizeof (ni)) {
				__free_resource (res);
				return false;
			}
			off += sizeof (NE_image_nameinfo_entry);
			if (ni.rnOffset > shift_limit || ni.rnLength > shift_limit) {
				continue;
			}
			r_ne_resource_entry *ren = R_NEW0 (r_ne_resource_entry);
			ren->offset = (ut64)ni.rnOffset << alignment;
			ren->size = (ut64)ni.rnLength << alignment;
			ren->flags = ni.rnFlags;
			if (ni.rnID & 0x8000) {
				ren->id = ni.rnID & ~0x8000;
				ren->name = r_str_newf ("%d", ren->id);
			} else {
				// Offset to resident name table
				ren->named = true;
				if (ni.rnID >= resend - resoff) {
					free (ren);
					continue;
				}
				ren->name = pascalstr_at (bin->buf, resoff + ni.rnID, resend, NULL);
			}
			if (ren->offset > bufsz || ren->size > bufsz - ren->offset || !ren->name) {
				__free_resource_entry (ren);
				continue;
			}
			r_list_append (res->entry, ren);
		}
		if (r_list_empty (res->entry)) {
			__free_resource (res);
		} else {
			r_list_append (bin->resources, res);
		}
	}
	return true;
}

void r_bin_ne_load_imports(r_bin_ne_obj_t *bin, RVecRBinImport *vec) {
	RBinImport *imp;
	R_VEC_FOREACH (&bin->imports, imp) {
		RBinImport *copy = RVecRBinImport_emplace_back (vec);
		if (!copy) {
			return;
		}
		*copy = *imp;
		copy->name = r_bin_name_clone (imp->name);
	}
}

static bool ne_segment_address(r_bin_ne_obj_t *bin, ut16 segment, ut16 offset, RBinAddr *addr) {
	if (!bin->segment_entries || !segment || segment > bin->ne_header->SegCount) {
		return false;
	}
	NE_image_segment_entry *se = &bin->segment_entries[segment - 1];
	ut32 size = se->offset? (se->length? se->length: 0x10000): 0;
	ut32 vsize = R_MAX (size, se->minAllocSz? se->minAllocSz: 0x10000);
	if (offset >= vsize) {
		return false;
	}
	addr->bits = 16;
	addr->vaddr = ((ut64)segment << 16) | offset;
	addr->paddr = offset < size? (ut64)se->offset * bin->alignment + offset: UT64_MAX;
	return true;
}

static void ne_load_entries(r_bin_ne_obj_t *bin) {
	size_t off = 0;
	ut64 tableat = (ut64)bin->header_offset + bin->ne_header->EntryTableOffset;
	ut64 bufsz = r_buf_size (bin->buf);
	size_t length = tableat < bufsz? R_MIN (bin->ne_header->EntryTableLength, bufsz - tableat): 0;
	while (off < length) {
		ut8 count = bin->entry_table[off++];
		if (!count || off == length) {
			break;
		}
		ut8 type = bin->entry_table[off++];
		if (count > UT16_MAX - RVecNEEntry_length (&bin->entries)) {
			R_LOG_WARN ("NE entry ordinals exceed 16 bits");
			break;
		}
		int i;
		for (i = 0; i < count; i++) {
			size_t size = type == 0xff? 6: type? 3: 0;
			if (size > length - off) {
				return;
			}
			RBinAddr *entry = RVecNEEntry_emplace_back (&bin->entries);
			if (!entry) {
				return;
			}
			if (type) {
				ut8 segment = type == 0xff? bin->entry_table[off + 3]: type;
				ut16 offset = r_read_le16 (bin->entry_table + off + size - 2);
				ne_segment_address (bin, segment, offset, entry);
			}
			off += size;
		}
	}
}

RList *r_bin_ne_get_entrypoints(r_bin_ne_obj_t *bin) {
	if (!bin->ne_header) {
		return NULL;
	}
	RList *entries = r_list_newf (free);
	RBinAddr startup = {0};
	if (ne_segment_address (bin, bin->ne_header->csEntryPoint, bin->ne_header->ipEntryPoint, &startup)) {
		r_list_append (entries, r_mem_dup (&startup, sizeof (startup)));
	}
	RBinAddr *entry;
	R_VEC_FOREACH (&bin->entries, entry) {
		if (entry->vaddr) {
			r_list_append (entries, r_mem_dup (entry, sizeof (*entry)));
		}
	}
	return entries;
}

static RBinImport *ne_reloc_import(r_bin_ne_obj_t *bin, NE_image_reloc_item *rel, HtUU *imports_by_key, ut64 *target) {
	ut16 kind = rel->flags & 3;
	ut64 key = ((ut64)kind << 32) | ((ut32)rel->index << 16) | rel->func_ord;
	bool found;
	size_t index = ht_uu_find (imports_by_key, key, &found);
	if (found) {
		*target = bin->imports_base + index * 4;
		return RVecRBinImport_at (&bin->imports, index);
	}
	if (!rel->index || rel->index > bin->ne_header->ModRefs) {
		return NULL;
	}
	ut64 bufsz = r_buf_size (bin->buf);
	ut64 modref = (ut64)bin->header_offset + bin->ne_header->ModRefTable + (rel->index - 1) * 2;
	ut64 names = (ut64)bin->header_offset + bin->ne_header->ImportNameTable;
	char *module = pascalstr_at (bin->buf, names + r_buf_read_le16_at (bin->buf, modref), bufsz, NULL);
	if (!module) {
		return NULL;
	}
	char *func = kind == IMPORTED_ORD? __func_name_from_ord (module, rel->func_ord): pascalstr_at (bin->buf, names + rel->name_off, bufsz, NULL);
	if (!func) {
		free (module);
		return NULL;
	}
	index = RVecRBinImport_length (&bin->imports);
	*target = bin->imports_base + index * 4;
	if (*target > UT32_MAX - 3) {
		free (module);
		free (func);
		return NULL;
	}
	RBinImport *imp = RVecRBinImport_emplace_back (&bin->imports);
	if (imp) {
		imp->name = r_bin_name_new_from (r_str_newf ("%s.%s", module, func));
		imp->ordinal = kind == IMPORTED_ORD? rel->func_ord: 0;
		imp->type = R_BIN_TYPE_FUNC_STR;
		ht_uu_insert (imports_by_key, key, index);
	}
	free (module);
	free (func);
	return imp;
}

static void ne_reloc_record(r_bin_ne_obj_t *bin, const char *key, const NE_image_reloc_item *rel, ut64 paddr, size_t segment, int index) {
	r_strf_buffer (128);
	sdb_num_set (bin->kv, r_strf ("%s.paddr", key), paddr, 0);
	sdb_num_set (bin->kv, r_strf ("%s.source_segment", key), segment, 0);
	sdb_num_set (bin->kv, r_strf ("%s.record_index", key), index, 0);
	sdb_num_set (bin->kv, r_strf ("%s.type", key), rel->type, 0);
	sdb_num_set (bin->kv, r_strf ("%s.flags", key), rel->flags, 0);
	sdb_num_set (bin->kv, r_strf ("%s.source_offset", key), rel->offset, 0);
	sdb_num_set (bin->kv, r_strf ("%s.target_word0", key), rel->index, 0);
	sdb_num_set (bin->kv, r_strf ("%s.target_word1", key), rel->func_ord, 0);
	sdb_num_set (bin->kv, r_strf ("%s.additive", key), !!(rel->flags & ADDITIVE), 0);
	sdb_num_set (bin->kv, r_strf ("%s.application_count", key), 0, 0);
}

static void ne_reloc_application(r_bin_ne_obj_t *bin, const char *record_key, size_t index, const RBinReloc *reloc, ut64 target) {
	r_strf_buffer (128);
	r_strf_var (key, 96, "%s.application.%zu", record_key, index);
	sdb_num_set (bin->kv, r_strf ("%s.paddr", key), reloc->paddr, 0);
	sdb_num_set (bin->kv, r_strf ("%s.vaddr", key), reloc->vaddr, 0);
	sdb_num_set (bin->kv, r_strf ("%s.target_vaddr", key), target, 0);
	int width = reloc->type / 8;
	sdb_num_set (bin->kv, r_strf ("%s.width", key), width, 0);
	ut8 original[6];
	if (r_buf_read_at (bin->buf, reloc->paddr, original, width) == width) {
		char hex[13];
		r_hex_bin2str (original, width, hex);
		sdb_set (bin->kv, r_strf ("%s.original", key), hex, 0);
	}
	sdb_num_set (bin->kv, r_strf ("%s.application_count", record_key), index + 1, 0);
}

static void ne_load_relocs(r_bin_ne_obj_t *bin) {
	r_strf_buffer (128);
	size_t record_count = 0;
	sdb_num_set (bin->kv, "ne.relocs.count", 0, 0);
	ut64 bufsz = r_buf_size (bin->buf);
	HtUU *imports_by_key = ht_uu_new0 ();
	if (!imports_by_key) {
		return;
	}
	bin->relocs = RVecRBinReloc_new ();
	if (!bin->relocs) {
		ht_uu_free (imports_by_key);
		return;
	}
	size_t index;
	for (index = 0; index < bin->ne_header->SegCount; index++) {
		NE_image_segment_entry *seg = &bin->segment_entries[index];
		if (!(seg->flags & RELOCINFO) || !seg->offset) {
			continue;
		}
		ut64 paddr = (ut64)seg->offset * bin->alignment;
		ut32 size = seg->length? seg->length: 0x10000;
		ut64 off = paddr + size;
		if (off > bufsz || bufsz - off < 2) {
			R_LOG_WARN ("Truncated NE relocation table for segment %zu", index + 1);
			continue;
		}
		ut16 count = r_buf_read_le16_at (bin->buf, off);
		off += 2;
		if (count > (bufsz - off) / sizeof (NE_image_reloc_item)) {
			R_LOG_WARN ("Truncated NE relocation records for segment %zu", index + 1);
			continue;
		}
		sdb_num_set (bin->kv, r_strf ("ne.reloc.%zu.count", index + 1), 0, 0);
		int i;
		for (i = 0; i < count; i++, off += sizeof (NE_image_reloc_item)) {
			NE_image_reloc_item rel = {0};
			if (r_buf_fread_at (bin->buf, off, (ut8 *)&rel, "2c3s", 1) != sizeof (rel)) {
				break;
			}
			r_strf_var (record_key, 64, "ne.reloc.%zu.%d", index + 1, i);
			ne_reloc_record (bin, record_key, &rel, off, index + 1, i);
			record_count++;
			sdb_num_set (bin->kv, r_strf ("ne.reloc.%zu.count", index + 1), i + 1, 0);
			RBinReloc reloc = {0};
			reloc.ntype = rel.type;
			switch (rel.type) {
			case LOBYTE:
				reloc.type = R_BIN_RELOC_8;
				break;
			case SEL_16:
			case OFF_16:
				reloc.type = R_BIN_RELOC_16;
				break;
			case POI_32:
			case OFF_32:
				reloc.type = R_BIN_RELOC_32;
				break;
			case POI_48:
				reloc.type = R_BIN_RELOC_48;
				break;
			default:
				R_LOG_WARN ("Unsupported NE relocation type %u at 0x%" PFMT64x, rel.type, off);
				continue;
			}
			ut64 target = UT64_MAX;
			switch (rel.flags & 3) {
			case INTERNAL_REF:
				if (!rel.zero && rel.segnum == 0xff) {
					RBinAddr *entry = rel.entry_ordinal? RVecNEEntry_at (&bin->entries, rel.entry_ordinal - 1): NULL;
					if (entry && entry->vaddr) {
						target = entry->vaddr;
					}
				} else {
					RBinAddr addr = {0};
					if (!rel.zero && ne_segment_address (bin, rel.segnum, rel.segoff, &addr)) {
						target = addr.vaddr;
					}
				}
				reloc.addend = target;
				break;
			case IMPORTED_ORD:
			case IMPORTED_NAME:
				reloc.import = ne_reloc_import (bin, &rel, imports_by_key, &target);
				reloc.laddr = target;
				break;
			case OSFIXUP:
				// OS instruction fixups are not address relocations.
				continue;
			}
			if (target == UT64_MAX || ((rel.flags & 3) != INTERNAL_REF && !reloc.import)) {
				R_LOG_WARN ("Unresolved NE relocation target at 0x%" PFMT64x, off);
				continue;
			}
			sdb_num_set (bin->kv, r_strf ("%s.target_vaddr", record_key), target, 0);
			if (reloc.import) {
				sdb_set (bin->kv, r_strf ("%s.import_name", record_key), r_bin_name_tostring (reloc.import->name), 0);
				if ((rel.flags & 3) == IMPORTED_ORD) {
					sdb_num_set (bin->kv, r_strf ("%s.import_ordinal", record_key), rel.func_ord, 0);
				}
			}
			reloc.additive = !!(rel.flags & ADDITIVE);
			size_t application_count = 0;
			ut32 source = rel.offset;
			RBitset *visited = r_bitset_new ();
			while (source < size && r_bitset_set (visited, source)) {
				ut32 width = reloc.type / 8;
				if (width > size - source || paddr + source > bufsz || width > bufsz - paddr - source) {
					break;
				}
				reloc.paddr = paddr + source;
				reloc.vaddr = ((ut64)(index + 1) << 16) | source;
				RBinReloc *copy = RVecRBinReloc_emplace_back (bin->relocs);
				if (!copy) {
					break;
				}
				*copy = reloc;
				ne_reloc_application (bin, record_key, application_count++, &reloc, target);
				if (reloc.import) {
					copy->import = r_bin_import_clone (reloc.import);
				}
				if (reloc.additive || size - source < 2 || bufsz - paddr - source < 2) {
					break;
				}
				source = r_buf_read_le16_at (bin->buf, reloc.paddr);
				if (source == UT16_MAX) {
					break;
				}
			}
			r_bitset_free (visited);
		}
	}
	sdb_num_set (bin->kv, "ne.relocs.count", record_count, 0);
	ht_uu_free (imports_by_key);
}

RVecRBinReloc *r_bin_ne_get_relocs(r_bin_ne_obj_t *bin, RVecRBinSymbol *symbols) {
	if (!bin->relocs) {
		return NULL;
	}
	RVecRBinReloc *relocs = RVecRBinReloc_new ();
	if (!relocs) {
		return NULL;
	}
	HtUP *symbols_by_addr = ht_up_new0 ();
	if (!symbols_by_addr) {
		RVecRBinReloc_free (relocs);
		return NULL;
	}
	RBinSymbol *sym;
	R_VEC_FOREACH (symbols, sym) {
		ht_up_insert (symbols_by_addr, sym->vaddr, sym);
	}
	RBinReloc *reloc;
	R_VEC_FOREACH (bin->relocs, reloc) {
		RBinReloc *copy = RVecRBinReloc_emplace_back (relocs);
		if (!copy) {
			ht_up_free (symbols_by_addr);
			RVecRBinReloc_free (relocs);
			return NULL;
		}
		*copy = *reloc;
		if (reloc->import) {
			copy->import = r_bin_import_clone (reloc->import);
		} else {
			copy->symbol = ht_up_find (symbols_by_addr, reloc->addend, NULL);
		}
	}
	ht_up_free (symbols_by_addr);
	return relocs;
}

void __init(RBuffer *buf, r_bin_ne_obj_t *bin) {
	bin->buf = buf;
	if (!r_bin_ne_get_header_offset (buf, &bin->header_offset)) {
		return;
	}
	bin->ne_header = R_NEW0 (NE_image_header);
	if (r_buf_fread_at (buf, bin->header_offset, (ut8 *)bin->ne_header, "4c2si4c4si8si3s2c3s2c", 1) < 1) {
		R_FREE (bin->ne_header);
		return;
	}
	if (bin->ne_header->FileAlnSzShftCnt > 15) {
		bin->ne_header->FileAlnSzShftCnt = 15;
	}
	ut64 from = (ut64)bin->ne_header->ModRefTable + bin->header_offset;
	ut64 bufsz = r_buf_size (bin->buf);
	if (from >= bufsz) {
		bin->ne_header->ModRefs = 0;
	} else {
		ut64 left = bufsz - from;
		if (bin->ne_header->ModRefs * sizeof (ut16) > left) {
			bin->ne_header->ModRefs = left / sizeof (ut16);
		}
	}
	bin->alignment = 1 << bin->ne_header->FileAlnSzShftCnt;
	if (!bin->alignment) {
		bin->alignment = 1 << 9;
	}
	bin->os = __get_target_os (bin);

	ut64 offset = (ut64)bin->ne_header->SegTableOffset + bin->header_offset;
	size_t size = bin->ne_header->SegCount * sizeof (NE_image_segment_entry);
	if (offset >= r_buf_size (bin->buf)) {
		return;
	}
	ut64 remaining = r_buf_size (bin->buf) - offset;
	size = R_MIN (remaining, size);
	bin->ne_header->SegCount = size / sizeof (NE_image_segment_entry); // * sizeof (NE_image_segment_entry);
	bin->segment_entries = calloc (1, size);
	if (size >= remaining) {
		bin->ne_header->SegCount = size / sizeof (NE_image_segment_entry);
	}
	if (!bin->segment_entries) {
		return;
	}
	r_buf_fread_at (buf, offset, (ut8 *)bin->segment_entries, "4s", bin->ne_header->SegCount);
	bin->entry_table = calloc (1, R_MAX (1, bin->ne_header->EntryTableLength));
	if (!bin->entry_table) {
		R_FREE (bin->segment_entries);
		return;
	}
	r_buf_read_at (buf, (ut64)bin->header_offset + bin->ne_header->EntryTableOffset, bin->entry_table, bin->ne_header->EntryTableLength);
	ne_load_entries (bin);
	bin->imports_base = (ut64)(bin->ne_header->SegCount + 1) << 16;
	ne_load_relocs (bin);
	__ne_get_resources (bin);
}

void r_bin_ne_free(r_bin_ne_obj_t *bin) {
	r_list_free (bin->resources);
	sdb_free (bin->kv);
	RVecNEEntry_fini (&bin->entries);
	RVecRBinImport_fini (&bin->imports);
	RVecRBinReloc_free (bin->relocs);
	free (bin->entry_table);
	free (bin->ne_header);
	free (bin->resident_name_table);
	free (bin->segment_entries);
	free (bin);
}

r_bin_ne_obj_t *r_bin_ne_new_buf(RBuffer *buf, bool verbose) {
	r_bin_ne_obj_t *bin = R_NEW0 (r_bin_ne_obj_t);
	bin->kv = sdb_new0 ();
	RVecNEEntry_init (&bin->entries);
	RVecRBinImport_init (&bin->imports);
	__init (buf, bin);
	return bin;
}
