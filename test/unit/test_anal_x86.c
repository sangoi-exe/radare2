#include <r_anal.h>
#include <r_core.h>
#include "minunit.h"

bool test_x86_stack_access(void) {
	const struct {
		int bits;
		const char *hex;
		const char *pc;
		const char *sp;
		int width;
	} cases[] = {
		{ 16, "e80000", "ip", "sp", 2 },
		{ 16, "66e800000000", "ip", "sp", 4 },
		{ 16, "50", "ip", "sp", 2 },
		{ 16, "6650", "ip", "sp", 4 },
		{ 16, "9a00000000", "ip", "sp", 4 },
		{ 16, "669a000000000000", "ip", "sp", 8 },
		{ 32, "e800000000", "eip", "esp", 4 },
		{ 32, "66e80000", "eip", "esp", 2 },
		{ 32, "9a000000000000", "eip", "esp", 8 },
		{ 32, "669a00000000", "eip", "esp", 4 },
		{ 32, "50", "eip", "esp", 4 },
		{ 32, "6650", "eip", "esp", 2 },
		{ 64, "e800000000", "rip", "rsp", 8 },
		{ 64, "66e800000000", "rip", "rsp", 8 },
		{ 64, "50", "rip", "rsp", 8 },
		{ 64, "6650", "rip", "rsp", 2 },
		{ 16, "b80000", "ip", "sp", 0 },
		{ 32, "b800000000", "eip", "esp", 0 },
		{ 64, "4889c3", "rip", "rsp", 0 },
	};
	RAnal *anal = r_anal_new ();
	mu_assert_true (r_anal_use (anal, "x86"), "select x86");
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		mu_assert_true (r_anal_set_bits (anal, cases[i].bits), "set bits");
		ut8 buf[16];
		int len = r_hex_str2bin (cases[i].hex, buf);
		RAnalOp op = {0};
		mu_assert_eq (r_anal_op (anal, &op, 0x100, buf, len, R_ARCH_OP_MASK_VAL), len, "decode");
		RAnalValue *pc = r_list_get_n (op.access, 0);
		mu_assert_notnull (pc, "PC access");
		mu_assert_streq (pc->reg, cases[i].pc, "PC register matches mode");
		bool found = false;
		RListIter *iter;
		RAnalValue *value;
		r_list_foreach (op.access, iter, value) {
			if (value->type == R_ANAL_VAL_MEM && (value->access & R_PERM_W)) {
				mu_assert_streq (value->reg, cases[i].sp, "stack register matches mode");
				mu_assert_eq (value->memref, cases[i].width, "stack write width");
				mu_assert_eq (value->delta, -cases[i].width, "stack write displacement");
				found = true;
			}
		}
		mu_assert_eq (found, cases[i].width != 0, "only stack-writing instructions store through SP");
		r_anal_op_fini (&op);
	}
	r_anal_free (anal);
	mu_end;
}

bool test_x86_cs_frame_pointer(void) {
	const struct {
		const char *name;
		const char *hex[3];
		bool bp_frame;
	} cases[] = {
		{ "mov bp, sp", { "89e5", "89e5", "4889e5" }, true },
		{ "mov bp, ax", { "89c5", "89c5", "4889c5" }, false },
		{ "lea bp, [other]", { "8d2f", "8d28", "488d28" }, false },
		{ "add bp, 1", { "83c501", "83c501", "4883c501" }, false },
		{ "sub bp, 1", { "83ed01", "83ed01", "4883ed01" }, false },
		{ "and bp, -16", { "83e5f0", "83e5f0", "4883e5f0" }, false },
		{ "or bp, 1", { "83cd01", "83cd01", "4883cd01" }, false },
		{ "xor bp, ax", { "31c5", "31c5", "4831c5" }, false },
		{ "not bp", { "f7d5", "f7d5", "48f7d5" }, false },
		{ "shl bp, 1", { "d1e5", "d1e5", "48d1e5" }, false },
		{ "shr bp, 1", { "d1ed", "d1ed", "48d1ed" }, false },
		{ "sar bp, 1", { "d1fd", "d1fd", "48d1fd" }, false },
		{ "rol bp, 1", { "d1c5", "d1c5", "48d1c5" }, false },
		{ "ror bp, 1", { "d1cd", "d1cd", "48d1cd" }, false },
		{ "cmovz bp, ax", { "0f44e8", "0f44e8", "480f44e8" }, false },
		{ "mov ax, bp", { "89e8", "89e8", "4889e8" }, true },
		{ "cmovz ax, bp", { "0f44c5", "0f44c5", "480f44c5" }, true },
		{ "cmp bp, ax", { "39c5", "39c5", "4839c5" }, true },
		{ "push bp", { "55", "55", "55" }, true },
		{ "pop bp", { "5d", "5d", "5d" }, true },
		{ "mov [bp-8], ax", { "8946f8", "8945f8", "488945f8" }, true },
		{ "mov ax, [bp-8]", { "8b46f8", "8b45f8", "488b45f8" }, true },
		{ "lea ax, [bp-8]", { "8d46f8", "8d45f8", "488d45f8" }, true },
		{ "add [bp-8], 1", { "8346f801", "8345f801", "488345f801" }, true },
		{ "not [bp-8]", { "f756f8", "f755f8", "48f755f8" }, true },
		{ "shl [bp-8], 1", { "d166f8", "d165f8", "48d165f8" }, true },
	};
	const int bits[] = { 16, 32, 64 };
	RCore *core = r_core_new ();
	RAnal *anal = core->anal;
	mu_assert_true (r_anal_use (anal, "x86"), "select Capstone x86");
	core->io->va = true;
	mu_assert_notnull (r_io_open_at (core->io, "malloc://16", R_PERM_RWX, 0, 0), "open instruction buffer");
	RAnalFunction *fcn = r_anal_create_function (anal, "frame", 0, 0, NULL);
	mu_assert_notnull (fcn, "create function");
	RAnalBlock *bb = r_anal_create_block (anal, 0, 16);
	mu_assert_notnull (bb, "create block");
	r_anal_function_add_block (fcn, bb);
	r_unref (bb);
	size_t mode, i;
	for (mode = 0; mode < R_ARRAY_SIZE (bits); mode++) {
		mu_assert_true (r_anal_set_bits (anal, bits[mode]), "set bits");
		for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
			ut8 buf[16];
			int len = r_hex_str2bin (cases[i].hex[mode], buf);
			mu_assert_true (r_io_write_at (core->io, 0, buf, len), "write instruction");
			r_anal_block_set_size (bb, len);
			fcn->bp_frame = true;
			r_anal_function_check_bp_use (fcn);
			char message[128];
			snprintf (message, sizeof (message), "%d-bit %s", bits[mode], cases[i].name);
			mu_assert_eq (fcn->bp_frame, cases[i].bp_frame, message);
		}
	}
	r_core_free (core);
	mu_end;
}

bool test_x86_segmented_targets(void) {
	const struct {
		const char *hex;
		ut64 addr;
		int segment_bits;
		ut64 target;
	} cases[] = {
		{ "e8e9ff", 0x4f02fa, 16, 0x4f02e6 },
		{ "e9c300", 0xfffaa, 4, 0xf0070 },
		{ "e97ae7", 0xf1911, 4, 0xf008e },
		{ "e8faff", 0x20000, 16, 0x2fffd },
		{ "9ad7024f00", 0x10006, 16, 0x4f02d7 },
		{ "ea551a0100", 0x4f02ee, 16, 0x11a55 },
		{ "9a34002001", 0x100, 4, 0x1234 },
	};
	const int syntax[] = { R_ARCH_SYNTAX_INTEL, R_ARCH_SYNTAX_ATT };
	RAnal *anal = r_anal_new ();
	mu_assert_true (r_anal_use (anal, "x86"), "select bundled Capstone x86");
	mu_assert_true (r_anal_set_bits (anal, 16), "select 16-bit mode");
	size_t i, j;
	for (j = 0; j < R_ARRAY_SIZE (syntax); j++) {
		anal->config->syntax = syntax[j];
		for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
			anal->config->seggrn = cases[i].segment_bits;
			ut8 bytes[8];
			int size = r_hex_str2bin (cases[i].hex, bytes);
			RAnalOp op = {0};
			mu_assert_eq (r_anal_op (anal, &op, cases[i].addr, bytes, size, R_ARCH_OP_MASK_DISASM), size, "decode segmented control flow");
			mu_assert_eq (op.jump, cases[i].target, "near wrap and far operand use the selected coordinates");
			if (i < 4) {
				char *target = r_str_newf ("0x%" PFMT64x, cases[i].target);
				mu_assert_notnull (strstr (op.mnemonic, target), "printed near target agrees with analysis detail");
				free (target);
			}
			r_anal_op_fini (&op);
		}
	}
	r_anal_free (anal);
	mu_end;
}

bool test_x86_return_cleanup(void) {
	const struct {
		int bits;
		const char *hex;
		int width;
		bool far;
		int cleanup;
	} cases[] = {
		{ 16, "ca0800", 2, true, 8 }, // Original SimTower F_SCOPY at 0x13de2.
		{ 16, "cb", 2, true, 0 },
		{ 16, "ca0000", 2, true, 0 },
		{ 16, "c3", 2, false, 0 },
		{ 16, "c20800", 2, false, 8 },
		{ 16, "c2ffff", 2, false, UT16_MAX },
		{ 16, "66c3", 4, false, 0 },
		{ 16, "66c20800", 4, false, 8 },
		{ 16, "66cb", 4, true, 0 },
		{ 16, "66ca0800", 4, true, 8 },
		{ 32, "c3", 4, false, 0 },
		{ 32, "c20800", 4, false, 8 },
		{ 32, "cb", 4, true, 0 },
		{ 32, "ca0800", 4, true, 8 },
		{ 32, "66c3", 2, false, 0 },
		{ 32, "66c20800", 2, false, 8 },
		{ 32, "66cb", 2, true, 0 },
		{ 32, "66ca0800", 2, true, 8 },
		{ 64, "c3", 8, false, 0 },
		{ 64, "c20800", 8, false, 8 },
		{ 64, "66c3", 8, false, 0 },
		{ 64, "66c20800", 8, false, 8 },
		{ 64, "cb", 4, true, 0 },
		{ 64, "ca0800", 4, true, 8 },
		{ 64, "66cb", 2, true, 0 },
		{ 64, "66ca0800", 2, true, 8 },
		{ 64, "48cb", 8, true, 0 },
		{ 64, "48ca0800", 8, true, 8 },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		RCore *core = r_core_new ();
		RAnal *anal = core->anal;
		r_config_set (core->config, "asm.arch", "x86");
		r_config_set_i (core->config, "asm.bits", cases[i].bits);
		r_config_set_b (core->config, "anal.esil", false);
		core->io->va = true;
		mu_assert_notnull (r_io_open_at (core->io, "malloc://512", R_PERM_RWX, 0, 0x1000), "open return and stack buffer");
		ut8 bytes[8];
		int len = r_hex_str2bin (cases[i].hex, bytes);
		mu_assert_true (r_io_write_at (core->io, 0x1000, bytes, len), "write return instruction");
		RAnalOp op = {0};
		mu_assert_eq (r_anal_op (anal, &op, 0x1000, bytes, len, R_ARCH_OP_MASK_ESIL), len, "decode return");
		mu_assert_eq (op.type, R_ANAL_OP_TYPE_RET, "normal return type");
		mu_assert_eq (op.stackop, R_ANAL_STACK_INC, "return changes stack");
		int consumed = cases[i].width * (cases[i].far? 2: 1) + cases[i].cleanup;
		mu_assert_eq (op.stackptr, -consumed, "return frame plus argument purge");
		mu_assert_eq (op.val, cases[i].cleanup, "decoded unsigned argument purge");
		const char *sp = cases[i].bits == 16? "sp": cases[i].bits == 32? "esp": "rsp";
		const char *pc = cases[i].bits == 16? "ip": cases[i].bits == 32? "eip": "rip";
		ut8 stack[16] = {0};
		ut64 target = cases[i].width == 8? 0x123456789abc: cases[i].width == 4? 0x12345678: 0x5678;
		r_write_le64 (stack, target);
		if (cases[i].far) {
			r_write_le16 (stack + cases[i].width, 0x55aa);
		}
		mu_assert_true (r_io_write_at (core->io, 0x1100, stack, sizeof (stack)), "write return frame");
		mu_assert_true (r_esil_setup (anal->esil, anal, false, false, false), "initialize native ESIL");
		r_reg_setv (anal->reg, sp, 0x1100);
		r_reg_setv (anal->reg, pc, cases[i].bits == 64? 0x1234abcd9876: 0xabcd9876);
		r_reg_setv (anal->reg, "cs", 0x44);
		mu_assert_true (r_esil_parse (anal->esil, r_strbuf_get (&op.esil)), "execute decoded return ESIL");
		ut64 expected_sp = 0x1100 + consumed;
		if (cases[i].bits == 16) {
			expected_sp &= UT16_MAX;
		}
		mu_assert_eq (r_reg_getv (anal->reg, sp), expected_sp, "ESIL consumes complete return and purge");
		mu_assert_eq (r_reg_getv (anal->reg, pc), cases[i].bits == 16? target & UT16_MAX: target, "ESIL restores mode-selected PC from operand-sized return offset");
		mu_assert_eq (r_reg_getv (anal->reg, "cs"), cases[i].far? 0x55aa: 0x44, "only far returns restore selector");
		r_anal_op_fini (&op);
		mu_assert_true (r_core_anal_fcn (core, 0x1000, UT64_MAX, R_ANAL_REF_TYPE_NULL, 1), "analyze native return function");
		RAnalFunction *fcn = r_anal_get_function_at (anal, 0x1000);
		mu_assert_notnull (fcn, "return function exists");
		mu_assert_eq (fcn->meta.stack_pop, cases[i].cleanup, "inferred purge excludes near or far return frame");
		r_core_free (core);
	}
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_x86_stack_access);
	mu_run_test (test_x86_cs_frame_pointer);
	mu_run_test (test_x86_segmented_targets);
	mu_run_test (test_x86_return_cleanup);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
