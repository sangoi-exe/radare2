/* radare - LGPL - Copyright 2026 */

static const char move_hex[] =
	"45558bec56571e8b4e0c8b5e0a8b56088b46063bd1770c72043bc37306fdb80100eb03fc33c0c57606c47e0a8b4e0e0bc0740603f14e03f94ff7c701007404e311a4492bf02bf8d1e9f3a5730503f003f8a4fc1f5f5e5d4dcb"
	"45558bec5657ff760eff7608ff7606ff760cff760a0ee88eff83c40a8b56088b46065f5e5d4dcb";
static const ut8 move_lengths[] = {
	1, 1, 2, 1, 1, 1, 3, 3, 3, 3, 2, 2, 2, 2, 2, 1, 3, 2, 1, 2, 3, 3, 3, 2, 2, 2, 1, 2, 1, 4, 2, 2, 1, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 2, 1, 1, 3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 1, 1, 1, 1, 1
};

static const HelperContract move_helpers[] = {
	{ "fmovmem", "borland_fmovmem_16far", "void", 0, 89, 0, 3, { { "source", "FarAddress16" }, { "destination", "FarAddress16" }, { "byte_count", "uint16_t" } }, NULL },
	{ "fmemmove", "borland_fmemmove_16far", "FarAddress16", 89, 39, 0, 3, { { "destination", "FarAddress16" }, { "source", "FarAddress16" }, { "byte_count", "uint16_t" } }, NULL },
};
static const ut8 scopy_lengths[] = { 1, 2, 1, 1, 1, 3, 3, 1, 2, 2, 2, 2, 1, 1, 1, 1, 3 };
static const HelperContract scopy_helpers[] = {
	{ "f_scopy", "borland_f_scopy_16far", "void", 0, 28, 8, 3, { { "byte_count", "uint16_t" }, { "source", "FarAddress16" }, { "destination", "FarAddress16" } },
		"Qualified Borland F_SCOPY: CX is the unsigned WORD byte count; source/destination FarAddress16 records at entry SP+4/+8. RETF 8 purges eight argument bytes plus the four-byte far return (total12). Analysis void, not a historical declaration. Forward WORD copies then odd BYTE, not memmove. Ordinary intact-frame/non-disruptive completion preserves low16 BP/SI/DI/DS, leaves AX/BX/DX untouched and SS unwritten; ES/CX/DF and arithmetic flags are conservatively clobbered by the native model. Storage is not a flat pointer or selector mapping; prototype does not compute post-call values, copy effects, faults or arbitrary aliases." },
};
static const ut8 forward_lengths[] = { 1, 1, 2, 1, 1, 2, 3, 3, 3, 2, 1, 2, 2, 1, 2, 3, 3, 1, 1, 1, 1, 1 };
static const HelperContract forward_helpers[] = {
	{ "far_copy", "borland_far_copy_16far", "FarAddress16", 0, 38, 0, 3, { { "destination", "FarAddress16" }, { "source", "FarAddress16" }, { "byte_count", "uint16_t" } },
		"Qualified Borland forward far copy: destination/source records at entry SP+4/+8, unsigned WORD count at+12; no incoming GPR argument. Plain RETF, far return4, purge0. DX:AX freshly rereads current destination after copying, not unconditional identity with initial LES destination under aliases. Forward WORD/optional BYTE, not memmove. Ordinary intact-frame/non-disruptive completion preserves low16 BP/SI/DI/DS, leaves BX untouched and SS unwritten. Native clobbers do not compute register/flag values or memory effects; no flat pointer, selector mapping, historical spelling or exclusive release is inferred." },
};
static const ut8 compare_lengths[] = { 1, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 3, 3, 2, 2, 2, 1 };
static const HelperContract compare_helpers[] = {
	{ "far_pointer_compare", "borland_far_pointer_compare_16far", "FarPointerCompareAnalysisState9", 0, 33, 0, 2, { { "entry_dx_ax", "FarAddress16" }, { "entry_cx_bx", "FarAddress16" } },
		"Qualified Borland F_PCMP: entry DX:AX and CX:BX records. AX=entryAX&15; DX=u16(entryDX+(entryAX>>4)); BX=entryBX&15; CX=u16(entryCX+(entryBX>>4)), using logical shifts. Returned ZF means normalized high AND low words agree, not raw-pair equality/nullness; AX is not boolean. FarPointerCompareAnalysisState9 is the packed analysis-only ZF/AX/DX/BX/CX tuple, native join most-significant first CX/BX/DX/AX/ZF, not a historical C ABI. Plain RETF, return4/purge0. Ordinary intact-stack completion leaves BP/SI/DI/DS/ES/SS/DF unwritten; other arithmetic flags are clobbered. No selector mapping or downstream effects are inferred." },
};
static const ut8 setmem_lengths[] = { 1, 1, 2, 1, 1, 1, 3, 3, 3, 2, 1, 4, 2, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1 };
static const HelperContract setmem_helpers[] = {
	{ "setmem", "borland_setmem_16far", "uint16_t", 0, 40, 0, 3, { { "destination_offset", "uint16_t" }, { "byte_count", "uint16_t" }, { "fill_word_low_byte", "uint16_t" } },
		"Qualified Borland setmem: DS-selected destination offset/count/fill WORDs at entry SP+4/+6/+8; only the fill low byte is read. No incoming GPR or host pointer. Plain RETF, return4/purge0. AX is the duplicated fill byte (fill_low_byte*0101h), an analysis WORD result, not historical return attribution. Forward odd-destination byte, WORD fill and optional carry tail. Ordinary intact-frame/non-disruptive accesses restore BP/DI, leave BX/DX/SI/DS untouched and SS unwritten. Native clobbers do not compute AX/CX/ES/DF/flags or memory effects; faults, selector validity and arbitrary aliases remain unresolved." },
};
static const ut8 fill_lengths[] = {
	1, 1, 2, 1, 1, 1, 3, 3, 3, 2, 1, 4, 2, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1,
	1, 1, 2, 1, 3, 3, 1, 3, 1, 1, 3, 3, 2, 1, 1, 1, 1
};
static const HelperContract memset_helpers[] = {
	{ "memset", "borland_memset_16far", "uint16_t", 40, 29, 0, 3, { { "destination_offset", "uint16_t" }, { "value_word_low_byte", "uint16_t" }, { "byte_count", "uint16_t" } },
		"Qualified Borland memset: destination offset/value WORD/count at entry SP+4/+6/+8; DS-selected offset, not a flat pointer. Complete preceding setmem and actual PUSH CS/near CALL binding are qualified. Inner arguments are caller-cleaned by ADD SP,6; outer plain RETF has return4/purge0. MOV AX,SI returns current SI before POP SI, not unrestricted identity with the initial destination or a historical C return guarantee. Ordinary intact-frame/non-disruptive accesses preserve low16 BP/SI/DI/BX/DX/DS; SS is unwritten. Native clobbers do not compute output/flag values or fill effects, alias/fault safety or selector validity." },
};
static const ut8 shift_lengths[] = {
	1, 1, 1, 3, 2, 2, 2, 2, 2, 3, 2, 2, 1, 3, 1, 2, 2, 1,
	1, 1, 1, 3, 2, 2, 2, 2, 2, 3, 2, 2, 1, 3, 1, 1, 2, 1,
	1, 1, 1, 3, 2, 2, 2, 2, 2, 3, 2, 2, 1, 3, 1, 2, 2, 1
};
#define SHIFT_DOMAIN "Qualified whole 98-byte Borland shift family; far core only: 15 instructions, three blocks, two plain RETF exits, return4/purge0. DX:AX value/result and unsigned BYTE CL count, not CX. Mathematical domain CL=0..31 only: for n<16 final CL=16-n; otherwise final CL=n-16. Outside that domain only original instruction mechanics are retained; no clamp, replacement semantics or host-C undefined-shift claim. BX is scratch; low16 BP/SI/DI/DS/ES and CH are unwritten; arithmetic flags are conservatively clobbered. Adapter is separate labeled code, not an overlapping returning function. No historical name or exclusive release is inferred. "
static const HelperContract shift_helpers[] = {
	{ "word_shift_left_far_core", "borland_word_shift_16far", "uint32_t", 3, 30, 0, 2, { { "value", "uint32_t" }, { "count", "uint8_t" } }, SHIFT_DOMAIN "Operation: finite 32-bit left shift modulo2^32." },
	{ "word_shift_arithmetic_right_far_core", "borland_word_shift_16far", "int32_t", 36, 29, 0, 2, { { "value", "int32_t" }, { "count", "uint8_t" } }, SHIFT_DOMAIN "Operation: finite signed32 arithmetic right shift with sign fill." },
	{ "word_shift_logical_right_far_core", "borland_word_shift_16far", "uint32_t", 68, 30, 0, 2, { { "value", "uint32_t" }, { "count", "uint8_t" } }, SHIFT_DOMAIN "Operation: finite unsigned32 logical right shift with zero fill." },
};
#undef SHIFT_DOMAIN
static const HelperFamily helper_families[] = {
	{ move_hex, move_lengths, R_ARRAY_SIZE (move_lengths), move_helpers, R_ARRAY_SIZE (move_helpers), 111, false },
	{ "558bec56571ec57606c47e0afcd1e9f3a513c9f3a41f5f5e5dca0800", scopy_lengths, R_ARRAY_SIZE (scopy_lengths), scopy_helpers, R_ARRAY_SIZE (scopy_helpers), 0, false },
	{ "45558bec56578cdac47e06c5760a8b4e0ed1e9fcf3a57301a48eda8b56088b46065f5e5d4dcb", forward_lengths, R_ARRAY_SIZE (forward_lengths), forward_helpers, R_ARRAY_SIZE (forward_helpers), 0, false },
	{ "518ae8b104d3e803d08ac58ae3d3eb5903cb8adc250f0083e30f3bd175023bc3cb", compare_lengths, R_ARRAY_SIZE (compare_lengths), compare_helpers, R_ARRAY_SIZE (compare_helpers), 0, false },
	{ "45558bec571e078b7e068b4e088a460a8ae0fcf7c701007404e309aa49d1e9f3ab7301aa5f5d4dcb", setmem_lengths, R_ARRAY_SIZE (setmem_lengths), setmem_helpers, R_ARRAY_SIZE (setmem_helpers), 0, false },
	{ "45558bec571e078b7e068b4e088a460a8ae0fcf7c701007404e309aa49d1e9f3ab7301aa5f5d4dcb45558bec568b76068a460850ff760a560ee8c4ff83c4068bc65e5d4dcb", fill_lengths, R_ARRAY_SIZE (fill_lengths), memset_helpers, R_ARRAY_SIZE (memset_helpers), 57, false },
	{ "5b0e5380f91073108bd8d3e0d3e2f6d980c110d3eb0bd3cb80e9109233c0d3e2cb5b0e5380f91073108bdad3e8d3faf6d980c110d3e30bc3cb80e9109299d3f8cb5b0e5380f91073108bdad3e8d3eaf6d980c110d3e30bc3cb80e9109233d2d3e8cb", shift_lengths, R_ARRAY_SIZE (shift_lengths), shift_helpers, R_ARRAY_SIZE (shift_helpers), 0, true },
};
