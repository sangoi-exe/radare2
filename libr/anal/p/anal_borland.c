/* radare - LGPL - Copyright 2026 */

#include <r_anal.h>
#include <r_anal_priv.h>

typedef struct {
	const char *name;
	const char *type;
} HelperParam;

typedef struct {
	const char *name;
	const char *cc;
	const char *ret;
	int start;
	int size;
	int purge;
	int argc;
	HelperParam args[3];
	const char *comment;
} HelperContract;

typedef struct {
	const char *hex;
	const ut8 *lengths;
	size_t ninstr;
	const HelperContract *helpers;
	size_t nhelpers;
	int call;
	bool adapters;
} HelperFamily;

typedef struct {
	int size;
	ut32 type;
	ut64 jump;
	ut64 fail;
} HelperOp;

#include "borland_helpers.inc.c"

static int borland_eligible(RAnal *anal) {
	return !strcmp (anal->config->arch, "x86")
		&& anal->config->bits == 16 && !R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config)? 0: -1;
}

static bool borland_qualify(RAnal *anal, ut64 addr, const HelperFamily *family, const ut8 *expected, int family_size, HelperOp *ops) {
	ut8 bytes[128];
	if (addr > UT64_MAX - family_size || !anal->iob.read_at || !anal->iob.get_region_at
			|| anal->iob.read_at (anal->iob.io, addr, bytes, family_size) != family_size) {
		return false;
	}
	if (memcmp (bytes, expected, family_size)) {
		return false;
	}
	int i, off = 0;
	for (i = 0; i < family_size; i++) {
		RIORegion region;
		if (!anal->iob.get_region_at (anal->iob.io, &region, addr + i) || !(region.perm & R_PERM_X)) {
			return false;
		}
	}
	for (i = 0; i < family->ninstr; i++) {
		const ut64 at = addr + off;
		const int bits = r_anal_hint_bits_at (anal, at, NULL);
		const char *arch = r_anal_hint_arch_at (anal, at, NULL);
		if ((bits && bits != 16) || (arch && strcmp (arch, "x86"))) {
			return false;
		}
		// An independent semantic override is not permission to reinterpret the bytes.
		RAnalHint *hint = r_anal_hint_get (anal, at);
		bool override = hint && (hint->jump != UT64_MAX || hint->fail != UT64_MAX
			|| hint->type || hint->size || hint->opcode || hint->esil || hint->new_bits
			|| hint->ret != UT64_MAX || hint->stackframe != UT64_MAX);
		r_anal_hint_free (hint);
		if (override) {
			return false;
		}
		RAnalOp op = {0};
		int size = r_anal_op (anal, &op, at, bytes + off, family_size - off, R_ARCH_OP_MASK_BASIC);
		bool valid = size == family->lengths[i] && anal->config->bits == 16;
		if (family->call && off == family->call - 1) {
			valid &= op.type == R_ANAL_OP_TYPE_RPUSH;
		}
		if (family->call && off == family->call) {
			valid &= (op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_CALL && op.jump == addr;
		}
		ops[off] = (HelperOp){ size, op.type & R_ANAL_OP_TYPE_MASK, op.jump, op.fail };
		r_anal_op_fini (&op);
		if (!valid) {
			return false;
		}
		off += size;
	}
	return off == family_size;
}

typedef struct {
	const char *name;
	const char *type;
	int offset;
	size_t count;
} HelperMember;

static bool borland_record(RAnal *anal, const char *name, int bits, const HelperMember *members, int count) {
	int i;
	for (i = 0; i < count; i++) {
		ut64 width = r_type_get_bitsize (anal->sdb_types, members[i].type);
		if (!width || members[i].offset < 0 || (members[i].count && r_mul_overflow (width, (ut64)members[i].count, &width))
				|| bits < 1 || (ut64)members[i].offset * 8 > bits || width > bits - (ut64)members[i].offset * 8) {
			return false;
		}
	}
	RAnalBaseType *type = r_anal_get_base_type (anal, name);
	if (type) {
		bool valid = type->kind == R_ANAL_BASE_TYPE_KIND_STRUCT && type->size == bits
			&& RVecAnalTypeMember_length (&type->struct_data.members) == count;
		for (i = 0; valid && i < count; i++) {
			RAnalTypeMember *member = RVecAnalTypeMember_at (&type->struct_data.members, i);
			valid = !strcmp (member->name, members[i].name) && !strcmp (member->type, members[i].type)
				&& member->offset == members[i].offset && member->count == members[i].count && !member->bitsize;
		}
		r_anal_base_type_free (type);
		return valid;
	}
	if (sdb_const_get (anal->sdb_types, name, NULL)) {
		return false;
	}
	type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	type->name = strdup (name);
	type->size = bits;
	for (i = 0; i < count; i++) {
		RAnalTypeMember member = { .name = strdup (members[i].name), .type = strdup (members[i].type), .offset = members[i].offset, .count = members[i].count };
		RVecAnalTypeMember_push_back (&type->struct_data.members, &member);
	}
	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);
	return true;
}

static bool borland_type(RAnal *anal, const char *name) {
	if (!strcmp (name, "void")) {
		return true;
	}
	if (!strcmp (name, "FarAddress16")) {
		const HelperMember members[] = { { "offset", "uint16_t", 0 }, { "selector", "uint16_t", 2 } };
		return r_type_get_bitsize (anal->sdb_types, "uint16_t") == 16
			&& borland_record (anal, name, 32, members, R_ARRAY_SIZE (members));
	}
	if (!strcmp (name, "FarPointerCompareAnalysisState9")) {
		RAnalBaseType *boolean = r_anal_get_base_type (anal, "bool");
		if (boolean) {
			bool valid = boolean->kind == R_ANAL_BASE_TYPE_KIND_ATOMIC && boolean->size == 8
				&& boolean->type && !strcmp (boolean->type, "b");
			r_anal_base_type_free (boolean);
			if (!valid) {
				return false;
			}
		} else {
			if (sdb_const_get (anal->sdb_types, "bool", NULL)) {
				return false;
			}
			boolean = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
			boolean->name = strdup ("bool");
			boolean->type = strdup ("b");
			boolean->size = 8;
			r_anal_save_base_type (anal, boolean);
			r_anal_base_type_free (boolean);
		}
		const HelperMember members[] = { { "equal_zf", "bool", 0 }, { "ax", "uint16_t", 1 }, { "dx", "uint16_t", 3 }, { "bx", "uint16_t", 5 }, { "cx", "uint16_t", 7 } };
		return r_type_get_bitsize (anal->sdb_types, "bool") == 8
			&& r_type_get_bitsize (anal->sdb_types, "uint16_t") == 16
			&& borland_record (anal, name, 72, members, R_ARRAY_SIZE (members));
	}
	int bits = !strcmp (name, "uint8_t")? 8: 16;
	if (!strcmp (name, "int32_t") || !strcmp (name, "uint32_t")) {
		bits = 32;
	}
	return r_type_get_bitsize (anal->sdb_types, name) == bits;
}

static bool borland_types(RAnal *anal, const HelperContract *helper) {
	r_anal_types_prepare (anal);
	if (!borland_type (anal, helper->ret)) {
		return false;
	}
	int i;
	for (i = 0; i < helper->argc; i++) {
		if (!borland_type (anal, helper->args[i].type)) {
			return false;
		}
	}
	return true;
}

static void borland_comment(RAnal *anal, ut64 addr, const char *text) {
	if (!text) {
		return;
	}
	const char *previous = r_meta_get_string (anal, R_META_TYPE_COMMENT, addr);
	if (previous && strstr (previous, text)) {
		return;
	}
	char *comment = previous? r_str_newf ("%s\n\n%s", previous, text): strdup (text);
	r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, comment);
	free (comment);
}

typedef struct {
	ut64 address;
	int size;
	HelperOp *ops;
} BorlandCodeRange;

static bool borland_ends_block(const HelperOp *op) {
	return op->type == R_ANAL_OP_TYPE_JMP || op->type == R_ANAL_OP_TYPE_CJMP
		|| op->type == R_ANAL_OP_TYPE_UJMP || op->type == R_ANAL_OP_TYPE_UCJMP || op->type == R_ANAL_OP_TYPE_RET;
}

static void borland_edges(const HelperOp *op, ut64 end, ut64 *jump, ut64 *fail) {
	*jump = UT64_MAX;
	*fail = UT64_MAX;
	if (op->type == R_ANAL_OP_TYPE_JMP || op->type == R_ANAL_OP_TYPE_CJMP
			|| op->type == R_ANAL_OP_TYPE_UJMP || op->type == R_ANAL_OP_TYPE_UCJMP) {
		*jump = op->jump;
		*fail = op->fail;
	} else if (op->type != R_ANAL_OP_TYPE_RET) {
		*jump = end;
	}
}

static bool borland_body_ranges(RAnalFunction *fcn, const BorlandCodeRange *ranges, int count) {
	size_t total = 0;
	int i, j;
	for (i = 0; i < count; i++) {
		if (ranges[i].size < 1 || ranges[i].address > UT64_MAX - ranges[i].size
				|| r_add_overflow (total, (size_t)ranges[i].size, &total)) {
			return false;
		}
		for (j = 0; j < i; j++) {
			if (ranges[i].address < ranges[j].address + ranges[j].size && ranges[j].address < ranges[i].address + ranges[i].size) {
				return false;
			}
		}
	}
	if (!total) {
		return false;
	}
	bool *covered = calloc (total, sizeof (bool));
	if (!covered) {
		return false;
	}
	bool valid = false;
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		size_t index = 0;
		for (i = 0; i < count; i++) {
			if (bb->addr >= ranges[i].address && bb->addr - ranges[i].address < ranges[i].size) {
				break;
			}
			index += ranges[i].size;
		}
		if (i == count || !bb->size || bb->size > ranges[i].size - (bb->addr - ranges[i].address)) {
			goto beach;
		}
		const BorlandCodeRange *range = &ranges[i];
		int off = bb->addr - range->address, end = off + bb->size, n = 0;
		const HelperOp *last = NULL;
		while (off < end) {
			last = &range->ops[off];
			if (last->size < 1 || last->size > end - off || r_anal_bb_opaddr_i (bb, n++) != range->address + off) {
				goto beach;
			}
			for (j = off; j < off + last->size; j++) {
				if (covered[index + j]) {
					goto beach;
				}
				covered[index + j] = true;
			}
			off += last->size;
			if (off < end && borland_ends_block (last)) {
				goto beach;
			}
		}
		ut64 jump, fail;
		borland_edges (last, range->address + end, &jump, &fail);
		if (bb->jump != jump || bb->fail != fail || bb->ninstr != n) {
			goto beach;
		}
	}
	size_t k;
	for (k = 0; k < total; k++) {
		if (!covered[k]) {
			goto beach;
		}
	}
	valid = true;
beach:
	free (covered);
	return valid;
}

static bool borland_body(RAnalFunction *fcn, ut64 family, int start, int size, const HelperOp *ops) {
	BorlandCodeRange range = { family + start, size, (HelperOp *)ops + start };
	return borland_body_ranges (fcn, &range, 1);
}

static bool borland_generic_name(const char *name) {
	return r_str_startswith (name, "fcn.") || r_str_startswith (name, "fcn_")
		|| r_str_startswith (name, "loc.") || r_str_startswith (name, "loc_")
		|| r_str_startswith (name, "sub.") || r_str_startswith (name, "sub_");
}

static bool borland_signature_equal(RAnalFunctionSignature *sig, const HelperContract *helper) {
	if (!sig || !sig->ret_type || strcmp (sig->ret_type, helper->ret) || !sig->callconv
			|| strcmp (sig->callconv, helper->cc) || sig->noreturn || r_list_length (sig->params) != helper->argc) {
		return false;
	}
	int i;
	for (i = 0; i < helper->argc; i++) {
		RAnalFunctionParam *param = r_list_get_n (sig->params, i);
		if (!param->name || strcmp (param->name, helper->args[i].name) || strcmp (param->type, helper->args[i].type)) {
			return false;
		}
	}
	return true;
}

static bool borland_apply(RAnal *anal, ut64 family, const HelperContract *helper, const HelperOp *ops) {
	const int start = helper->start, size = helper->size;
	const ut64 addr = family + start;
	RAnalFunction *fcn = r_anal_get_function_at (anal, addr);
	RList *blocks = r_anal_get_blocks_intersect (anal, addr, size);
	RListIter *iter;
	RAnalBlock *bb;
	bool overlap = false;
	r_list_foreach (blocks, iter, bb) {
		if (!fcn || !r_list_contains (fcn->bbs, bb) || r_list_length (bb->fcns) != 1) {
			overlap = true;
		}
	}
	r_list_free (blocks);
	if (overlap || (fcn && (!borland_body (fcn, family, start, size, ops) || fcn->bits != 16))) {
		R_LOG_WARN ("Borland: preserving body at 0x%08"PFMT64x, addr);
		return false;
	}
	if (fcn) {
		RAnalFunctionSignature *sig = r_anal_function_get_signature (fcn);
		bool same = borland_signature_equal (sig, helper) && fcn->callconv && !strcmp (fcn->callconv, helper->cc);
		bool conflict = sig && (sig->ret_type || !r_list_empty (sig->params));
		r_anal_function_signature_free (sig);
		if (same && RVecAnalVarPtr_empty (&fcn->vars) && !fcn->is_noreturn
				&& (fcn->meta.stack_pop == R_ANAL_CC_STACK_POP_UNKNOWN || fcn->meta.stack_pop == helper->purge)) {
			borland_comment (anal, addr, helper->comment);
			return true;
		}
		const char *default_cc = r_anal_cc_default (anal);
		if (!borland_generic_name (fcn->name) || conflict || !RVecAnalVarPtr_empty (&fcn->vars) || fcn->is_noreturn
				|| (fcn->meta.stack_pop != R_ANAL_CC_STACK_POP_UNKNOWN && fcn->meta.stack_pop != helper->purge)
				|| (fcn->callconv && (!default_cc || strcmp (fcn->callconv, default_cc)))) {
			R_LOG_WARN ("Borland: preserving prototype/variables/convention at 0x%08"PFMT64x, addr);
			return false;
		}
	}
	char *linked = r_type_link_at (anal->sdb_types, addr);
	if (linked) {
		R_LOG_WARN ("Borland: preserving existing type link at 0x%08"PFMT64x, addr);
		free (linked);
		return false;
	}
	if (!fcn) {
		char *name = r_str_newf ("qualified_borland_%s.%08"PFMT64x, helper->name, addr);
		fcn = r_anal_create_function (anal, name, addr, R_ANAL_FCN_TYPE_FCN, NULL);
		free (name);
		if (!fcn) {
			return false;
		}
		bool recover_vars = anal->opt.vars;
		anal->opt.vars = false;
		r_anal_function (anal, fcn, addr, R_ANAL_REF_TYPE_CALL);
		anal->opt.vars = recover_vars;
		if (!borland_body (fcn, family, start, size, ops)) {
			R_LOG_WARN ("Borland: native analysis did not produce the qualified body at 0x%08"PFMT64x, addr);
			return false;
		}
	}
	char *type_name = r_str_newf ("borland_%s_%08"PFMT64x, helper->name, addr);
	if (sdb_const_get (anal->sdb_types, type_name, NULL)) {
		R_LOG_WARN ("Borland: preserving existing prototype key %s", type_name);
		free (type_name);
		return false;
	}
	sdb_set (anal->sdb_types, type_name, "func", 0);
	r_type_set_link (anal->sdb_types, type_name, addr);
	free (type_name);
	RList *params = r_list_new ();
	RAnalFunctionParam values[3];
	int i;
	for (i = 0; i < helper->argc; i++) {
		values[i] = (RAnalFunctionParam){ .name = (char *)helper->args[i].name, .type = (char *)helper->args[i].type };
		r_list_append (params, &values[i]);
	}
	RAnalFunctionSignature signature = { .ret_type = (char *)helper->ret, .callconv = (char *)helper->cc, .params = params };
	bool result = r_anal_function_set_signature (anal, fcn, &signature);
	r_list_free (params);
	if (result) {
		result = r_anal_function_store_callconv (anal, fcn, helper->cc);
	}
	RAnalFunctionSignature *actual = r_anal_function_get_signature (fcn);
	result = result && borland_signature_equal (actual, helper);
	r_anal_function_signature_free (actual);
	if (!result) {
		R_LOG_WARN ("Borland: native signature application failed at 0x%08"PFMT64x, addr);
	} else {
		borland_comment (anal, addr, helper->comment);
	}
	return result;
}

static void borland_adapters(RAnal *anal, ut64 addr, const HelperFamily *family) {
	if (!family->adapters) {
		return;
	}
	size_t i;
	for (i = 0; i < family->nhelpers; i++) {
		ut64 adapter = addr + family->helpers[i].start - 3;
		char *name = r_str_newf ("qualified_borland_%s_near_adapter.%08"PFMT64x, family->helpers[i].name, adapter);
		if (anal->flb.f && !r_flag_get (anal->flb.f, name)) {
			r_flag_set (anal->flb.f, name, adapter, 3);
		}
		free (name);
		borland_comment (anal, adapter, "Qualified word-shift near adapter: POP BX; PUSH CS; PUSH BX constructs the four-byte far return frame and falls through to the core. Label/code only, not a three-byte returning function; no near caller is inferred.");
	}
}

static int borland_scan(RAnal *anal) {
	if (borland_eligible (anal) < 0 || !anal->iob.read_at || !anal->binb.get_sections_vec) {
		return 0;
	}
	RVecRBinSection *sections = anal->binb.get_sections_vec (anal->binb.bin);
	if (!sections) {
		return 0;
	}
	int applied = 0;
	size_t f;
	for (f = 0; f < R_ARRAY_SIZE (helper_families); f++) {
		const HelperFamily *family = &helper_families[f];
		ut8 bytes[4096], expected[128];
		const int family_size = r_hex_str2bin (family->hex, expected);
		RBinSection *section;
		R_VEC_FOREACH (sections, section) {
			ut64 size = R_MIN (section->size, section->vsize);
			if (!(section->perm & R_PERM_X) || size < family_size || section->vaddr > UT64_MAX - size) {
				continue;
			}
			ut64 off = 0;
			while (off <= size - family_size) {
				const int len = R_MIN (sizeof (bytes), size - off);
				if (anal->iob.read_at (anal->iob.io, section->vaddr + off, bytes, len) != len) {
					R_LOG_WARN ("Borland: unreadable executable section at 0x%08"PFMT64x, section->vaddr + off);
					break;
				}
				int i;
				for (i = 0; i <= len - family_size; i++) {
					if (memcmp (bytes + i, expected, 10)) {
						continue;
					}
					const ut64 addr = section->vaddr + off + i;
					HelperOp ops[128] = {0};
					if (!borland_qualify (anal, addr, family, expected, family_size, ops)) {
						R_LOG_WARN ("Borland: refused current bytes/context/flow at 0x%08"PFMT64x, addr);
						continue;
					}
					borland_adapters (anal, addr, family);
					size_t h;
					for (h = 0; h < family->nhelpers; h++) {
						if (!borland_types (anal, &family->helpers[h])) {
							R_LOG_WARN ("Borland: preserving conflicting native type for %s", family->helpers[h].name);
							continue;
						}
						applied += borland_apply (anal, addr, &family->helpers[h], ops);
					}
				}
				off += len - family_size + 1;
			}
		}
	}
	return applied;
}

#include "borland_profile_context.inc.c"
#include "borland_profile_data.inc.c"
#include "borland_profile_bindings.inc.c"
#include "borland_profiles.inc.c"

static bool borland_pre_analysis(RAnal *anal) {
	int count = borland_profiles (anal);
	return borland_scan (anal) + count > 0;
}

static char *borland_command(RAnal *anal, const char *input) {
	if (strcmp (input, "borland") && strcmp (input, "borland?")) {
		return NULL;
	}
	if (input[7] == '?') {
		return strdup ("| a:borland    qualify exact executable 16-bit Borland helper families and exact-original profiles; preserve conflicting analysis\n| a:borland?   show this help; rerun a:borland after changing bytes/context\n");
	}
	int count = borland_profiles (anal);
	return r_str_newf ("Borland: %d function contracts qualified (including unchanged); refusals are logged\n", borland_scan (anal) + count);
}

RAnalPlugin r_anal_plugin_borland = {
	.meta = {
		.name = "borland",
		.desc = "Whole-family-qualified Borland 16-bit runtime helpers",
		.license = "LGPL-3.0-only",
	},
	.eligible = borland_eligible,
	.pre_analysis = borland_pre_analysis,
	.cmd = borland_command,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_borland,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
