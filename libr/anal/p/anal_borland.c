/* radare - LGPL - Copyright 2026 */

#include <r_anal.h>
#include <r_anal_priv.h>

static const char move_hex[] =
	"45558bec56571e8b4e0c8b5e0a8b56088b46063bd1770c72043bc37306fdb80100eb03fc33c0c57606c47e0a8b4e0e0bc0740603f14e03f94ff7c701007404e311a4492bf02bf8d1e9f3a5730503f003f8a4fc1f5f5e5d4dcb"
	"45558bec5657ff760eff7608ff7606ff760cff760a0ee88eff83c40a8b56088b46065f5e5d4dcb";
static const ut8 move_lengths[] = {
	1, 1, 2, 1, 1, 1, 3, 3, 3, 3, 2, 2, 2, 2, 2, 1, 3, 2, 1, 2, 3, 3, 3, 2, 2, 2, 1, 2, 1, 4, 2, 2, 1, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 2, 1, 1, 3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 1, 1, 1, 1, 1
};

typedef struct {
	int size;
	ut32 type;
	ut64 jump;
	ut64 fail;
} MoveOp;

static int borland_eligible(RAnal *anal) {
	return !strcmp (anal->config->arch, "x86")
		&& anal->config->bits == 16 && !R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config)? 0: -1;
}

static bool move_qualify(RAnal *anal, ut64 addr, MoveOp *ops) {
	ut8 expected[128], bytes[128];
	if (addr > UT64_MAX - sizeof (bytes) || !anal->iob.read_at || !anal->iob.get_region_at
			|| anal->iob.read_at (anal->iob.io, addr, bytes, sizeof (bytes)) != sizeof (bytes)) {
		return false;
	}
	r_hex_str2bin (move_hex, expected);
	if (memcmp (bytes, expected, sizeof (bytes))) {
		return false;
	}
	int i, off = 0;
	for (i = 0; i < sizeof (bytes); i++) {
		RIORegion region;
		if (!anal->iob.get_region_at (anal->iob.io, &region, addr + i) || !(region.perm & R_PERM_X)) {
			return false;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (move_lengths); i++) {
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
		int size = r_anal_op (anal, &op, at, bytes + off, sizeof (bytes) - off, R_ARCH_OP_MASK_BASIC);
		bool valid = size == move_lengths[i] && anal->config->bits == 16;
		if (off == 110) {
			valid &= op.type == R_ANAL_OP_TYPE_RPUSH;
		}
		if (off == 111) {
			valid &= (op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_CALL && op.jump == addr;
		}
		ops[off] = (MoveOp){ size, op.type & R_ANAL_OP_TYPE_MASK, op.jump, op.fail };
		r_anal_op_fini (&op);
		if (!valid) {
			return false;
		}
		off += size;
	}
	return off == sizeof (bytes);
}

static bool move_type(RAnal *anal) {
	r_anal_types_prepare (anal);
	if (r_type_get_bitsize (anal->sdb_types, "uint16_t") != 16) {
		return false;
	}
	RAnalBaseType *type = r_anal_get_base_type (anal, "FarAddress16");
	if (type) {
		bool valid = type->kind == R_ANAL_BASE_TYPE_KIND_STRUCT && type->size == 32
			&& RVecAnalTypeMember_length (&type->struct_data.members) == 2;
		if (valid) {
			RAnalTypeMember *offset = RVecAnalTypeMember_at (&type->struct_data.members, 0);
			RAnalTypeMember *selector = RVecAnalTypeMember_at (&type->struct_data.members, 1);
			valid = !strcmp (offset->name, "offset") && !strcmp (selector->name, "selector")
				&& !strcmp (offset->type, "uint16_t") && !strcmp (selector->type, "uint16_t")
				&& !offset->offset && selector->offset == 2 && !offset->count && !selector->count
				&& !offset->bitsize && !selector->bitsize;
		}
		r_anal_base_type_free (type);
		return valid;
	}
	if (sdb_const_get (anal->sdb_types, "FarAddress16", NULL)) {
		return false;
	}
	type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	type->name = strdup ("FarAddress16");
	type->size = 32;
	RAnalTypeMember offset = { .name = strdup ("offset"), .type = strdup ("uint16_t") };
	RAnalTypeMember selector = { .name = strdup ("selector"), .type = strdup ("uint16_t"), .offset = 2 };
	RVecAnalTypeMember_push_back (&type->struct_data.members, &offset);
	RVecAnalTypeMember_push_back (&type->struct_data.members, &selector);
	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);
	return true;
}

static bool move_body(RAnalFunction *fcn, ut64 family, int start, int size, const MoveOp *ops) {
	bool covered[128] = {0};
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr < family + start || bb->addr >= family + start + size
				|| !bb->size || bb->size > family + start + size - bb->addr || bb->switch_op) {
			return false;
		}
		int off = bb->addr - family, end = off + bb->size, n = 0;
		const MoveOp *last = NULL;
		while (off < end) {
			last = &ops[off];
			if (!last->size || off + last->size > end || r_anal_bb_opaddr_i (bb, n++) != family + off) {
				return false;
			}
			int j;
			for (j = off; j < off + last->size; j++) {
				if (covered[j]) {
					return false;
				}
				covered[j] = true;
			}
			off += last->size;
			if (off < end && (last->type == R_ANAL_OP_TYPE_JMP || last->type == R_ANAL_OP_TYPE_CJMP || last->type == R_ANAL_OP_TYPE_RET)) {
				return false;
			}
		}
		ut64 jump = UT64_MAX, fail = UT64_MAX;
		if (last->type == R_ANAL_OP_TYPE_JMP || last->type == R_ANAL_OP_TYPE_CJMP) {
			jump = last->jump;
			fail = last->fail;
		} else if (last->type != R_ANAL_OP_TYPE_RET) {
			jump = family + end;
		}
		if (bb->jump != jump || bb->fail != fail || bb->ninstr != n) {
			return false;
		}
	}
	int i;
	for (i = start; i < start + size; i++) {
		if (!covered[i]) {
			return false;
		}
	}
	return true;
}

static bool move_generic_name(const char *name) {
	return r_str_startswith (name, "fcn.") || r_str_startswith (name, "fcn_")
		|| r_str_startswith (name, "loc.") || r_str_startswith (name, "loc_")
		|| r_str_startswith (name, "sub.") || r_str_startswith (name, "sub_");
}

static bool move_signature_equal(RAnalFunctionSignature *sig, const char *ret, const char **names, const char *cc) {
	if (!sig || !sig->ret_type || strcmp (sig->ret_type, ret) || !sig->callconv
			|| strcmp (sig->callconv, cc) || sig->noreturn || r_list_length (sig->params) != 3) {
		return false;
	}
	int i;
	for (i = 0; i < 3; i++) {
		RAnalFunctionParam *param = r_list_get_n (sig->params, i);
		if (!param->name || strcmp (param->name, names[i]) || strcmp (param->type, i == 2? "uint16_t": "FarAddress16")) {
			return false;
		}
	}
	return true;
}

static bool move_apply(RAnal *anal, ut64 family, bool wrapper, const MoveOp *ops) {
	const int start = wrapper? 89: 0, size = wrapper? 39: 89;
	const ut64 addr = family + start;
	const char *cc = wrapper? "borland_fmemmove_16far": "borland_fmovmem_16far";
	const char *ret = wrapper? "FarAddress16": "void";
	const char *names[] = { wrapper? "destination": "source", wrapper? "source": "destination", "byte_count" };
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
	if (overlap || (fcn && (!move_body (fcn, family, start, size, ops) || fcn->bits != 16))) {
		R_LOG_WARN ("Borland: preserving body at 0x%08"PFMT64x, addr);
		return false;
	}
	if (fcn) {
		RAnalFunctionSignature *sig = r_anal_function_get_signature (fcn);
		bool same = move_signature_equal (sig, ret, names, cc) && fcn->callconv && !strcmp (fcn->callconv, cc);
		bool conflict = sig && (sig->ret_type || !r_list_empty (sig->params));
		r_anal_function_signature_free (sig);
		if (same && RVecAnalVarPtr_empty (&fcn->vars) && !fcn->is_noreturn
				&& (fcn->meta.stack_pop == R_ANAL_CC_STACK_POP_UNKNOWN || fcn->meta.stack_pop == 0)) {
			return true;
		}
		const char *default_cc = r_anal_cc_default (anal);
		if (!move_generic_name (fcn->name) || conflict || !RVecAnalVarPtr_empty (&fcn->vars) || fcn->is_noreturn
				|| (fcn->meta.stack_pop != R_ANAL_CC_STACK_POP_UNKNOWN && fcn->meta.stack_pop != 0)
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
		char *name = r_str_newf ("qualified_borland_%s.%08"PFMT64x, wrapper? "fmemmove": "fmovmem", addr);
		fcn = r_anal_create_function (anal, name, addr, R_ANAL_FCN_TYPE_FCN, NULL);
		free (name);
		if (!fcn) {
			return false;
		}
		bool recover_vars = anal->opt.vars;
		anal->opt.vars = false;
		r_anal_function (anal, fcn, addr, R_ANAL_REF_TYPE_CALL);
		anal->opt.vars = recover_vars;
		if (!move_body (fcn, family, start, size, ops)) {
			R_LOG_WARN ("Borland: native analysis did not produce the qualified body at 0x%08"PFMT64x, addr);
			return false;
		}
	}
	char *type_name = r_str_newf ("borland_%s_%08"PFMT64x, wrapper? "fmemmove": "fmovmem", addr);
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
	for (i = 0; i < 3; i++) {
		values[i] = (RAnalFunctionParam){ .name = (char *)names[i], .type = i == 2? "uint16_t": "FarAddress16" };
		r_list_append (params, &values[i]);
	}
	RAnalFunctionSignature signature = { .ret_type = (char *)ret, .callconv = (char *)cc, .params = params };
	bool result = r_anal_function_set_signature (anal, fcn, &signature);
	r_list_free (params);
	if (result) {
		result = r_anal_function_store_callconv (anal, fcn, cc);
	}
	RAnalFunctionSignature *actual = r_anal_function_get_signature (fcn);
	result = result && move_signature_equal (actual, ret, names, cc);
	r_anal_function_signature_free (actual);
	if (!result) {
		R_LOG_WARN ("Borland: native signature application failed at 0x%08"PFMT64x, addr);
	}
	return result;
}

static int borland_scan(RAnal *anal) {
	if (borland_eligible (anal) < 0 || !anal->iob.read_at || !anal->binb.get_sections_vec) {
		return 0;
	}
	ut8 bytes[4096], expected[128];
	r_hex_str2bin (move_hex, expected);
	int applied = 0;
	RVecRBinSection *sections = anal->binb.get_sections_vec (anal->binb.bin);
	if (!sections) {
		return 0;
	}
	RBinSection *section;
	R_VEC_FOREACH (sections, section) {
		ut64 size = R_MIN (section->size, section->vsize);
		if (!(section->perm & R_PERM_X) || size < 128 || section->vaddr > UT64_MAX - size) {
			continue;
		}
		ut64 off = 0;
		while (off <= size - 128) {
			const int len = R_MIN (sizeof (bytes), size - off);
			if (anal->iob.read_at (anal->iob.io, section->vaddr + off, bytes, len) != len) {
				R_LOG_WARN ("Borland: unreadable executable section at 0x%08"PFMT64x, section->vaddr + off);
				break;
			}
			int i;
			for (i = 0; i <= len - 128; i++) {
				if (memcmp (bytes + i, expected, 10)) {
					continue;
				}
				const ut64 addr = section->vaddr + off + i;
				MoveOp ops[128] = {0};
				if (!move_qualify (anal, addr, ops)) {
					R_LOG_WARN ("Borland: refused current bytes/context/flow at 0x%08"PFMT64x, addr);
					continue;
				}
				if (!move_type (anal)) {
					R_LOG_WARN ("Borland: preserving conflicting FarAddress16/WORD type");
					continue;
				}
				applied += move_apply (anal, addr, false, ops);
				applied += move_apply (anal, addr, true, ops);
			}
			off += len - 127;
		}
	}
	return applied;
}

static bool borland_pre_analysis(RAnal *anal) {
	return borland_scan (anal) > 0;
}

static char *borland_command(RAnal *anal, const char *input) {
	if (strcmp (input, "borland") && strcmp (input, "borland?")) {
		return NULL;
	}
	if (input[7] == '?') {
		return strdup ("| a:borland    qualify current executable 16-bit move families; preserve conflicting analysis\n| a:borland?   show this help; rerun a:borland after changing bytes/context\n");
	}
	return r_str_newf ("Borland: %d function contracts qualified (including unchanged); refusals are logged\n", borland_scan (anal));
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
