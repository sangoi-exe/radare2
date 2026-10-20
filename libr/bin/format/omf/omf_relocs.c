/* radare - LGPL - Copyright 2026 */

#include "omf_relocs.h"

// Grammar: Open Watcom ORL omfload.c, GetFrame/GetTarget and process*Fixup.
typedef struct {
	const ut8 *bytes;
	size_t size;
	size_t offset;
} OmfCursor;

typedef struct {
	bool defined;
	ut8 method;
	ut16 datum;
	ut64 paddr;
} OmfThread;

typedef struct {
	ut8 type;
	ut64 paddr;
	ut64 record_paddr;
	ut16 segment;
	ut32 offset;
	const ut8 *bytes;
	size_t size;
	bool valid;
} OmfDataContext;

static void omf_num(Sdb *db, const char *key, const char *field, ut64 value) {
	r_strf_buffer (192);
	sdb_num_set (db, r_strf ("%s.%s", key, field), value, 0);
}

static void omf_str(Sdb *db, const char *key, const char *field, const char *value) {
	r_strf_buffer (192);
	sdb_set (db, r_strf ("%s.%s", key, field), value, 0);
}

static bool omf_index(OmfCursor *c, ut16 *value) {
	if (c->offset == c->size) {
		return false;
	}
	ut8 first = c->bytes[c->offset++];
	*value = first;
	if (first & 0x80) {
		if (c->offset == c->size) {
			return false;
		}
		*value = ((first & 0x7f) << 8) | c->bytes[c->offset++];
	}
	return true;
}

static bool omf_word(OmfCursor *c, size_t width, ut32 *value) {
	if (width > c->size - c->offset) {
		return false;
	}
	*value = width == 4? r_read_le32 (c->bytes + c->offset): r_read_le16 (c->bytes + c->offset);
	c->offset += width;
	return true;
}

static const char *omf_name(r_bin_omf_obj *obj, ut16 index) {
	return index && index <= obj->nb_name? obj->names[index - 1]: NULL;
}

static bool omf_externals(r_bin_omf_obj *obj, OmfCursor *c, OMF_record_handler *record, size_t *count, bool indices_known) {
	while (c->offset < c->size) {
		size_t start = c->offset;
		ut8 length = c->bytes[c->offset++];
		if (length > c->size - c->offset) {
			return false;
		}
		const ut8 *name = c->bytes + c->offset;
		c->offset += length;
		ut16 type;
		if (!omf_index (c, &type)) {
			return false;
		}
		char *text = r_str_ndup ((const char *)name, length);
		if (!text) {
			return false;
		}
		r_strf_var (key, 64, "omf.external.%zu", ++*count);
		omf_str (obj->kv, key, "name", text);
		omf_num (obj->kv, key, "type_index", type);
		omf_num (obj->kv, key, "record_paddr", record->paddr);
		omf_num (obj->kv, key, "paddr", record->paddr + 3 + start);
		omf_num (obj->kv, key, "local", record->type == OMF_LEXTDEF);
		omf_str (obj->kv, key, "index_status", indices_known? "known": "unknown");
		if (indices_known) {
			omf_num (obj->kv, key, "index", *count);
		}
		free (text);
	}
	return true;
}

static bool omf_group(r_bin_omf_obj *obj, OmfCursor *c, OMF_record_handler *record, size_t index) {
	r_strf_buffer (192);
	r_strf_var (key, 64, "omf.group.%zu", index);
	omf_num (obj->kv, key, "index", index);
	omf_num (obj->kv, key, "paddr", record->paddr);
	omf_str (obj->kv, key, "status", "incomplete");
	omf_num (obj->kv, key, "member_count", 0);
	ut16 name_index;
	if (!omf_index (c, &name_index)) {
		return false;
	}
	omf_num (obj->kv, key, "name_index", name_index);
	const char *name = omf_name (obj, name_index);
	if (name) {
		omf_str (obj->kv, key, "name", name);
	}
	size_t count = 0;
	while (c->offset < c->size) {
		ut16 segment;
		if (c->bytes[c->offset++] != 0xff || !omf_index (c, &segment)) {
			return false;
		}
		omf_num (obj->kv, key, r_strf ("member.%zu.segment", count++), segment);
		omf_num (obj->kv, key, "member_count", count);
	}
	omf_str (obj->kv, key, "status", "complete");
	return true;
}

static bool omf_method(OmfCursor *c, ut8 method, OmfThread *thread) {
	thread->method = method;
	if (method < 3) {
		return omf_index (c, &thread->datum);
	}
	if (method == 3) {
		ut32 frame;
		if (!omf_word (c, 2, &frame)) {
			return false;
		}
		thread->datum = frame;
	}
	return true;
}

static void omf_reference(r_bin_omf_obj *obj, const char *key, const char *which, const OmfThread *ref) {
	r_strf_buffer (192);
	r_strf_var (base, 128, "%s.%s", key, which);
	omf_str (obj->kv, base, "status", ref->defined? "decoded": "undefined_thread");
	if (!ref->defined) {
		return;
	}
	omf_num (obj->kv, base, "method", ref->method);
	if (ref->method < 4) {
		omf_num (obj->kv, base, "datum", ref->datum);
	}
	const char *kind = NULL;
	const char *name = NULL;
	switch (ref->method) {
	case 0:
		kind = "segment";
		if (ref->datum && ref->datum <= obj->nb_section) {
			name = omf_name (obj, obj->sections[ref->datum - 1]->name_idx);
		}
		break;
	case 1:
		kind = "group";
		name = sdb_const_get (obj->kv, r_strf ("omf.group.%u.name", ref->datum), NULL);
		break;
	case 2:
		kind = "external";
		if (!strcmp (sdb_const_get (obj->kv, "omf.externals.status", NULL), "complete")) {
			name = sdb_const_get (obj->kv, r_strf ("omf.external.%u.name", ref->datum), NULL);
		}
		break;
	case 3:
		kind = "absolute_frame";
		break;
	case 4:
		kind = "location";
		break;
	case 5:
		kind = "target";
		break;
	}
	if (kind) {
		omf_str (obj->kv, base, "kind", kind);
	}
	if (ref->method < 3) {
		omf_str (obj->kv, base, "identity_status", name? "known": "unresolved");
	}
	if (name) {
		omf_str (obj->kv, base, "name", name);
	}
}

static size_t omf_location(Sdb *db, const char *key, ut8 location) {
	const char *name = NULL;
	size_t width = 0;
	switch (location) {
	case 0: name = "LOW8"; width = 1; break;
	case 1: name = "OFF16"; width = 2; break;
	case 2: name = "BASE16"; width = 2; break;
	case 3: name = "PTR16:16"; width = 4; break;
	case 4: name = "HIGH8"; width = 1; break;
	case 5: name = "OFF16L"; width = 2; break;
	case 9: name = "OFF32"; width = 4; break;
	case 11: name = "PTR16:32"; width = 6; break;
	case 13: name = "OFF32L"; width = 4; break;
	}
	if (name) {
		omf_str (db, key, "location_name", name);
		omf_num (db, key, "width", width);
	}
	return width;
}

static bool omf_application(r_bin_omf_obj *obj, const char *record_key, const char *key, const OmfDataContext *data, size_t subrecord, size_t *count, ut16 offset, size_t width) {
	const char *reason = NULL;
	if (!data->valid) {
		reason = "missing_data_record";
	} else if (data->type != OMF_LEDATA && data->type != OMF_LEDATA32) {
		reason = "unsupported_data_record";
	} else if (!width) {
		reason = "unsupported_location";
	} else if (offset > data->size || width > data->size - offset) {
		reason = "source_out_of_bounds";
	} else if (!data->segment || data->segment > obj->nb_section) {
		reason = "invalid_source_segment";
	} else {
		OMF_segment *segment = obj->sections[data->segment - 1];
		ut64 source = (ut64)data->offset + offset;
		if (source > segment->size || width > segment->size - source) {
			reason = "source_out_of_bounds";
		}
	}
	omf_str (obj->kv, key, "application_status", reason? "not_enumerated": "complete");
	if (reason) {
		omf_str (obj->kv, key, "reason", reason);
		return false;
	}
	r_strf_var (application, 128, "%s.application.%zu", record_key, (*count)++);
	omf_num (obj->kv, application, "subrecord_index", subrecord);
	omf_num (obj->kv, application, "paddr", data->paddr + offset);
	omf_num (obj->kv, application, "vaddr", OMF_BASE_ADDR + obj->sections[data->segment - 1]->vaddr + data->offset + offset);
	omf_num (obj->kv, application, "source_segment", data->segment);
	omf_num (obj->kv, application, "source_offset", (ut64)data->offset + offset);
	omf_num (obj->kv, application, "width", width);
	omf_str (obj->kv, application, "source_address_domain", "synthetic_section");
	char original[13];
	r_hex_bin2str (data->bytes + offset, width, original);
	omf_str (obj->kv, application, "original", original);
	return true;
}

static bool omf_fixup(r_bin_omf_obj *obj, OmfCursor *c, const char *record_key, const char *key, OmfThread *frames, OmfThread *targets, const OmfDataContext *data, size_t subrecord, size_t *applications, bool *sites_complete, size_t displacement_width) {
	if (c->size - c->offset < 3) {
		return false;
	}
	ut8 first = c->bytes[c->offset++];
	ut16 offset = ((first & 3) << 8) | c->bytes[c->offset++];
	ut8 fixdat = c->bytes[c->offset++];
	ut8 location = (first >> 2) & 15;
	omf_str (obj->kv, key, "kind", "fixup");
	omf_num (obj->kv, key, "locat", (first << 8) | (offset & 0xff));
	omf_num (obj->kv, key, "fixdat", fixdat);
	omf_num (obj->kv, key, "location", location);
	omf_num (obj->kv, key, "segment_relative", !!(first & 0x40));
	omf_num (obj->kv, key, "data_record_offset", offset);
	omf_str (obj->kv, key, "resolution", "unresolved");
	omf_str (obj->kv, key, "target_address_domain", "link_unresolved");
	OmfThread frame = { .defined = true };
	OmfThread target = { .defined = true };
	bool frame_thread = !!(fixdat & 0x80);
	bool target_thread = !!(fixdat & 8);
	omf_num (obj->kv, key, "frame.thread", frame_thread);
	omf_num (obj->kv, key, "target.thread", target_thread);
	if (frame_thread) {
		ut8 slot = (fixdat >> 4) & 3;
		omf_num (obj->kv, key, "frame.thread_index", slot);
		frame = frames[slot];
		if (frame.defined) {
			omf_num (obj->kv, key, "frame.thread_paddr", frame.paddr);
		}
	} else if (!omf_method (c, (fixdat >> 4) & 7, &frame)) {
		return false;
	}
	if (target_thread) {
		ut8 slot = fixdat & 3;
		omf_num (obj->kv, key, "target.thread_index", slot);
		target = targets[slot];
		if (target.defined) {
			omf_num (obj->kv, key, "target.thread_paddr", target.paddr);
		}
	} else if (!omf_method (c, fixdat & 3, &target)) {
		return false;
	}
	omf_reference (obj, key, "frame", &frame);
	omf_reference (obj, key, "target", &target);
	bool displacement_present = !(fixdat & 4);
	omf_num (obj->kv, key, "displacement_present", displacement_present);
	if (displacement_present) {
		ut32 displacement;
		if (!omf_word (c, displacement_width, &displacement)) {
			return false;
		}
		omf_num (obj->kv, key, "displacement_width", displacement_width);
		omf_num (obj->kv, key, "displacement", displacement);
	}
	size_t width = omf_location (obj->kv, key, location);
	omf_str (obj->kv, key, "status", width && frame.method < 6? "complete": "unsupported");
	if (frame.defined && frame.method >= 6) {
		omf_str (obj->kv, key, "reason", "unsupported_frame_method");
	}
	if (!omf_application (obj, record_key, key, data, subrecord, applications, offset, width)) {
		*sites_complete = false;
	}
	return true;
}

static bool omf_fixupp(r_bin_omf_obj *obj, OmfCursor *c, OMF_record_handler *record, size_t index, OmfThread *frames, OmfThread *targets, const OmfDataContext *data, const char *unsupported) {
	r_strf_var (key, 64, "omf.reloc.%zu", index);
	omf_num (obj->kv, key, "paddr", record->paddr);
	omf_num (obj->kv, key, "type", record->type);
	omf_num (obj->kv, key, "size", record->record.size + 3);
	omf_str (obj->kv, key, "record_address_domain", "file");
	omf_str (obj->kv, key, "source_address_domain", "synthetic_section");
	omf_str (obj->kv, key, "target_address_domain", "link_unresolved");
	omf_str (obj->kv, key, "resolution", "unresolved");
	omf_num (obj->kv, key, "application_count", 0);
	omf_num (obj->kv, key, "subrecord_count", 0);
	char *raw = malloc (c->size * 2 + 1);
	if (!raw) {
		return false;
	}
	r_hex_bin2str (c->bytes, c->size, raw);
	omf_str (obj->kv, key, "raw", raw);
	free (raw);
	if (unsupported) {
		omf_str (obj->kv, key, "status", "unsupported");
		omf_str (obj->kv, key, "reason", unsupported);
		omf_str (obj->kv, key, "application_status", "not_enumerated");
		return true;
	}
	if (data->valid) {
		omf_num (obj->kv, key, "data_record_paddr", data->record_paddr);
		omf_num (obj->kv, key, "data_record_type", data->type);
		omf_num (obj->kv, key, "data_paddr", data->paddr);
		omf_num (obj->kv, key, "source_segment", data->segment);
		omf_num (obj->kv, key, "data_offset", data->offset);
	}

	size_t count = 0;
	size_t fixups = 0;
	size_t applications = 0;
	bool complete = true;
	bool sites_complete = true;
	while (c->offset < c->size) {
		size_t start = c->offset;
		r_strf_var (subkey, 128, "%s.subrecord.%zu", key, count);
		ut64 paddr = record->paddr + 3 + start;
		omf_num (obj->kv, subkey, "paddr", paddr);
		omf_str (obj->kv, subkey, "status", "incomplete");
		ut8 first = c->bytes[start];
		omf_str (obj->kv, subkey, "kind", first & 0x80? "fixup": "thread");
		bool parsed;
		if (first & 0x80) {
			fixups++;
			parsed = omf_fixup (obj, c, key, subkey, frames, targets, data, count, &applications, &sites_complete, record->type == OMF_FIXUPP32? 4: 2);
		} else {
			c->offset++;
			bool is_frame = !!(first & 0x40);
			ut8 slot = first & 3;
			OmfThread thread = { .defined = true, .paddr = paddr };
			parsed = omf_method (c, (first >> 2) & (is_frame? 7: 3), &thread);
			omf_str (obj->kv, subkey, "kind", "thread");
			omf_num (obj->kv, subkey, "raw", first);
			omf_num (obj->kv, subkey, "frame", is_frame);
			omf_num (obj->kv, subkey, "thread_index", slot);
			if (parsed) {
				omf_reference (obj, subkey, "reference", &thread);
				omf_str (obj->kv, subkey, "status", thread.method < 6? "complete": "unsupported");
				(is_frame? frames: targets)[slot] = thread;
			}
		}
		omf_num (obj->kv, key, "subrecord_count", ++count);
		if (!parsed) {
			omf_str (obj->kv, subkey, "reason", "truncated_subrecord");
			complete = false;
			sites_complete = false;
			break;
		}
		omf_num (obj->kv, subkey, "size", c->offset - start);
	}
	omf_num (obj->kv, key, "fixup_count", fixups);
	if (!fixups) {
		omf_str (obj->kv, key, "resolution", "not_applicable");
	}
	omf_num (obj->kv, key, "application_count", applications);
	omf_str (obj->kv, key, "status", complete? "complete": "incomplete");
	omf_str (obj->kv, key, "application_status", sites_complete? "complete": "incomplete");
	if (!complete) {
		memset (frames, 0, sizeof (OmfThread) * 4);
		memset (targets, 0, sizeof (OmfThread) * 4);
	}
	return true;
}

bool r_bin_omf_load_provenance(r_bin_omf_obj *obj, const ut8 *buf) {
	size_t externals = 0;
	size_t groups = 0;
	bool external_indices = true;
	bool groups_complete = true;
	bool easy = false;
	size_t modules = 0;
	bool module_ended = false;
	OMF_record_handler *record;
	for (record = obj->records; record; record = record->next) {
		if (record->type == OMF_THEADR || record->type == OMF_LHEADR) {
			if (!modules || module_ended) {
				modules++;
			}
			module_ended = false;
		} else if (record->type == OMF_MODEND || record->type == OMF_MODEND32) {
			module_ended = true;
		}
		if (modules > 1) {
			external_indices = false;
			groups_complete = false;
			continue;
		}
		OmfCursor c = { buf + record->paddr + 3, record->record.size - 1, 0 };
		switch (record->type) {
		case OMF_EXTDEF:
		case OMF_LEXTDEF:
			if (!omf_externals (obj, &c, record, &externals, external_indices)) {
				external_indices = false;
			}
			break;
		case OMF_COMDEF:
		case OMF_LCOMDEF:
		case OMF_CEXTDEF:
			external_indices = false;
			break;
		case OMF_GRPDEF:
			if (!omf_group (obj, &c, record, ++groups)) {
				groups_complete = false;
			}
			break;
		case OMF_COMENT:
			if (c.size >= 7 && c.bytes[0] == 0x80 && c.bytes[1] == 0xaa && !memcmp (c.bytes + 2, "80386", 5)) {
				easy = true;
			}
			break;
		}
	}
	omf_num (obj->kv, "omf.externals", "count", externals);
	omf_str (obj->kv, "omf.externals", "status", external_indices? "complete": "incomplete");
	omf_num (obj->kv, "omf.groups", "count", groups);
	omf_str (obj->kv, "omf.groups", "status", groups_complete? "complete": "incomplete");
	omf_str (obj->kv, "omf", "dialect", easy? "easy_omf_unsupported": "standard");
	const char *unsupported = NULL;
	if (modules > 1) {
		unsupported = "multiple_modules";
	} else if (easy) {
		unsupported = "easy_omf";
	}
	OmfThread frames[4] = {0};
	OmfThread targets[4] = {0};
	OmfDataContext data = {0};
	size_t count = 0;
	for (record = obj->records; record; record = record->next) {
		OmfCursor c = { buf + record->paddr + 3, record->record.size - 1, 0 };
		switch (record->type) {
		case OMF_LEDATA:
		case OMF_LEDATA32:
		case OMF_LIDATA:
		case OMF_LIDATA32:
			data = (OmfDataContext){ .type = record->type, .record_paddr = record->paddr };
			if (omf_index (&c, &data.segment) && omf_word (&c, record->type & 1? 4: 2, &data.offset)) {
				data.valid = true;
				data.paddr = record->paddr + 3 + c.offset;
				data.bytes = c.bytes + c.offset;
				data.size = c.size - c.offset;
			}
			break;
		case OMF_COMDAT:
		case OMF_COMDAT32:
			data = (OmfDataContext){0};
			break;
		case OMF_FIXUPP:
		case OMF_FIXUPP32:
			if (!omf_fixupp (obj, &c, record, count++, frames, targets, &data, unsupported)) {
				return false;
			}
			break;
		case OMF_MODEND:
		case OMF_MODEND32:
			data = (OmfDataContext){0};
			memset (frames, 0, sizeof (frames));
			memset (targets, 0, sizeof (targets));
			break;
		}
	}
	omf_num (obj->kv, "omf.relocs", "count", count);
	omf_str (obj->kv, "omf.relocs", "status", "complete");
	return true;
}
