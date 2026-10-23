/* radare - LGPL - Copyright 2009-2019 - GustavoLCR, nibble, pancake, alvarofe */

#include <r_bin.h>
#include "../i/private.h"
#include "../format/ne/ne.h"

static Sdb *get_sdb(RBinFile *bf) {
	r_bin_ne_obj_t *ne = bf && bf->bo? bf->bo->bin_obj: NULL;
	return ne? ne->kv: NULL;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length < 0x40) {
		return false;
	}
	ut8 magic[2];
	ut32 offset;
	return r_buf_read_at (b, 0, magic, sizeof (magic)) == sizeof (magic)
		&& !memcmp (magic, "MZ", sizeof (magic))
		&& r_bin_ne_get_header_offset (b, &offset);
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && buf, false);
	r_bin_ne_obj_t *res = r_bin_ne_new_buf (buf, bf->rbin->options.verbose);
	if (res) {
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static void destroy(RBinFile *bf) {
	r_bin_ne_free (bf->bo->bin_obj);
}

static char *header(RBinFile *bf, int mode) {
	r_bin_ne_obj_t *ne = bf->bo->bin_obj;
	if (!ne || !ne->ne_header) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
#define p(f,...) r_strbuf_appendf (sb, f, ##__VA_ARGS__)
	p ("Signature: NE\n");
	p ("MajLinkerVersion: %d\n", ne->ne_header->MajLinkerVersion);
	p ("MinLinkerVersion: %d\n", ne->ne_header->MinLinkerVersion);
	p ("EntryTableOffset: 0x%04x\n", ne->ne_header->EntryTableOffset);
	p ("EntryTableLength: %d\n", ne->ne_header->EntryTableLength);
	p ("FileLoadCRC: %08x\n", ne->ne_header->FileLoadCRC);
	p ("ProgFlags: %d\n", ne->ne_header->ProgFlags);
	p ("ApplFlags: %d\n", ne->ne_header->ApplFlags);
	p ("AutoDataSegIndex: %d\n", ne->ne_header->AutoDataSegIndex);
	p ("InitHeapSize: %d\n", ne->ne_header->InitHeapSize);
	p ("InitStackSize: %d\n", ne->ne_header->InitStackSize);
	p ("EntryPointCSIndex: %d\n", ne->ne_header->csEntryPoint);
	p ("EntryPointIPOff: 0x%04x\n", ne->ne_header->ipEntryPoint);
	p ("InitStack: %d\n", ne->ne_header->InitStack);
	p ("SegCount: %d\n", ne->ne_header->SegCount);
	p ("ModuleRefsCount: %d\n", ne->ne_header->ModRefs);
	p ("NonResNamesTblSiz: 0x%x\n", ne->ne_header->NoResNamesTabSiz);
	p ("SegTableOffset: 0x%x\n", ne->ne_header->SegTableOffset);
	p ("ResourceTblOff: 0x%x\n", ne->ne_header->ResTableOffset);
	p ("ResidentNameTblOff: 0x%x\n", ne->ne_header->ResidNamTable);
	p ("ModuleRefTblOff: 0x%x\n", ne->ne_header->ModRefTable);
	p ("ImportNameTblOff: 0x%x\n", ne->ne_header->ImportNameTable);
	p ("OffStartNonResTab: %d\n", ne->ne_header->OffStartNonResTab);
	p ("MovEntryCount: %d\n", ne->ne_header->MovEntryCount);
	p ("FileAlnSzShftCnt: %d\n", ne->ne_header->FileAlnSzShftCnt);
	p ("nResTabEntries: %d\n", ne->ne_header->nResTabEntries);
	p ("OS: %s\n", ne->os);
	p ("OS2EXEFlags: %x\n", ne->ne_header->OS2EXEFlags);
	p ("retThunkOffset: %d\n", ne->ne_header->retThunkOffset);
	p ("segRefThunksOff: %d\n", ne->ne_header->segrefthunksoff);
	p ("mincodeswap: %d\n", ne->ne_header->mincodeswap);
	p ("winver: %d.%d\n", ne->ne_header->expctwinver[1], ne->ne_header->expctwinver[0]);
#undef p
	return r_strbuf_drain (sb);
}

static RBinInfo *info(RBinFile *bf) {
	r_bin_ne_obj_t *ne = bf->bo->bin_obj;
	RBinInfo *i = R_NEW0 (RBinInfo);
	i->bits = 16;
	i->rclass = strdup ("ne");
	i->has_va = true;
	i->has_lit = true;
	i->arch = strdup ("x86");
	i->os = strdup (ne->os? ne->os: "os2");
	if (ne->ne_header) {
		i->claimed_checksum = r_str_newf ("%08x", ne->ne_header->FileLoadCRC);
	}
	return i;
}

static RList *entries(RBinFile *bf) {
	return r_bin_ne_get_entrypoints (bf->bo->bin_obj);
}

static bool symbols_vec(RBinFile *bf) {
	r_bin_ne_load_symbols (bf->bo->bin_obj, &bf->bo->symbols_vec);
	return true;
}

static bool imports_vec(RBinFile *bf) {
	r_bin_ne_load_imports (bf->bo->bin_obj, &bf->bo->imports_vec);
	return true;
}

static RVecRBinReloc *relocs(RBinFile *bf) {
	return r_bin_ne_get_relocs (bf->bo->bin_obj, &bf->bo->symbols_vec);
}

static RVecRBinReloc *patch_relocs(RBinFile *bf) {
	RBin *b = bf->rbin;
	r_bin_ne_obj_t *ne = bf->bo->bin_obj;
	if (!b->iob.io || !b->iob.overlay_write_at) {
		return NULL;
	}
	RVecRBinReloc *all_relocs = relocs (bf);
	if (!all_relocs) {
		return NULL;
	}
	size_t imports_size = RVecRBinImport_length (&ne->imports) * 4;
	if (imports_size) {
		char *uri = r_str_newf ("malloc://%zu", imports_size);
		RIODesc *desc = b->iob.open_at (b->iob.io, uri, R_PERM_R, 0664, ne->imports_base);
		free (uri);
		if (!desc) {
			R_LOG_ERROR ("Cannot map NE artificial import targets");
			RVecRBinReloc_free (all_relocs);
			return NULL;
		}
		RIOMap *map = b->iob.map_get_at (b->iob.io, ne->imports_base);
		if (map) {
			free (map->name);
			map->name = strdup ("ne.imports");
		}
		b->iob.desc_use (b->iob.io, bf->fd);
	}
	RBinReloc *reloc;
	R_VEC_FOREACH (all_relocs, reloc) {
		ut64 target = reloc->import? reloc->laddr: reloc->addend;
		ut8 bytes[4] = {0};
		int size = 0;
		switch (reloc->ntype) {
		case LOBYTE:
			size = 1;
			bytes[0] = target;
			if (reloc->additive) {
				bytes[0] += r_buf_read8_at (ne->buf, reloc->paddr);
			}
			break;
		case SEL_16:
		case OFF_16:
			size = 2;
			ut16 value = reloc->ntype == SEL_16? target >> 32: target;
			if (reloc->additive) {
				value += r_buf_read_le16_at (ne->buf, reloc->paddr);
			}
			r_write_le16 (bytes, value);
			break;
		case POI_32:
			size = 4;
			ut32 pointer = ((ut32)(target >> 32) << 16) | (target & UT16_MAX);
			if (reloc->additive) {
				pointer += r_buf_read_le32_at (ne->buf, reloc->paddr);
			}
			r_write_le32 (bytes, pointer);
			break;
		default:
			R_LOG_WARN ("Unsupported NE relocation patch type %" PFMT64u, reloc->ntype);
			break;
		}
		if (size && !b->iob.overlay_write_at (b->iob.io, reloc->vaddr, bytes, size)) {
			R_LOG_ERROR ("Cannot patch NE relocation at 0x%" PFMT64x, reloc->vaddr);
		}
	}
	return all_relocs;
}

static bool sections_vec(RBinFile *bf) {
	return r_bin_ne_load_segments (bf->bo->bin_obj, &bf->bo->sections_vec);
}

static bool load_resources(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, false);
	r_bin_ne_obj_t *ne = bf->bo->bin_obj;
	if (!ne) {
		return false;
	}
	ut32 index = 0;
	RListIter *iter;
	r_ne_resource *res;
	r_list_foreach (ne->resources, iter, res) {
		RListIter *entry_iter;
		r_ne_resource_entry *entry;
		r_list_foreach (res->entry, entry_iter, entry) {
			RBinResource *resource = RVecRBinResource_emplace_back (&bf->bo->resources_vec);
			if (!resource) {
				return false;
			}
			resource->name = entry->name? strdup (entry->name): NULL;
			resource->type = res->name? strdup (res->name): NULL;
			if ((entry->name && !resource->name) || (res->name && !resource->type)) {
				return false;
			}
			resource->paddr = entry->offset + bf->bo->loadaddr;
			resource->vaddr = resource->paddr;
			resource->size = entry->size;
			resource->id = entry->named? UT64_MAX: entry->id;
			resource->index = index++;
			resource->type_id = res->named? UT32_MAX: res->type_id;
			resource->named = entry->named;
		}
	}
	return true;
}

RBinPlugin r_bin_plugin_ne = {
	.meta = {
		.name = "ne",
		.desc = "New Executables for 16bit Windows",
		.author = "GustavoLCR",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb,
	.check = &check,
	.load = &load,
	.destroy = &destroy,
	.header = &header,
	.info = &info,
	.entries = &entries,
	.sections_vec = &sections_vec,
	.symbols_vec = &symbols_vec,
	.imports_vec = &imports_vec,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.minstrlen = 4,
	.load_resources = &load_resources
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ne,
	.version = R2_VERSION
};
#endif
