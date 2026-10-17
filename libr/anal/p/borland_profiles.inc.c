/* radare - LGPL - Copyright 2026 */

#define SCRANTIC_MARKER "[LegacyToolchains scrantic-runtime-qualified] "

static const struct {
	ut64 start;
	ut64 end;
	const char *name;
	bool known_zero;
	const char *comment;
} scrantic_functions[] = {
	{ 0xde2, 0xe0d, "scrantic_cwm31_lseek_correspondence", true, SCRANTIC_MARKER "NE1:[05e2,060d), complete43-byte/20-instruction correspondence to the bound Borland3.1 CWM LSEEK member/public _lseek. This is qualified tool-member provenance, not a historical Johnny name or modern lseek ABI. The indexed DS displacement is2af8; the near call at0606 reaches04e8. INT21 effects/meaning, DS-selected memory meanings and vendor-callee equivalence remain unproved. Proved own argument purge is zero, not a complete subordinate or whole-function effects contract. Complete original-file extent [de2,e0d)." },
	{ 0x2eb8, 0x2f01, "scrantic_cwm31_fheap_farmallocf_correspondence", true, SCRANTIC_MARKER "NE1:[26b8,2701), complete73-byte/33-instruction bound correspondence to FHEAP public __farmallocf. Three DS-relative WORD operands bind0027; the FAR field26e3 binds actual NE13:07e5. Vendor __WinAllocFlag/__GETMEM are laboratory binding roles, not historical names or a proved allocation ABI. BP-based SP restoration and terminal plain RETF establish zero own argument purge; subordinate register/memory/allocator semantics remain unproved. Proved own argument purge is zero, not a complete subordinate or whole-function effects contract. Complete original-file extent [2eb8,2f01)." },
	{ 0x2f76, 0x2faa, "scrantic_cwm31_fheap_farfreef_correspondence", true, SCRANTIC_MARKER "NE1:[2776,27aa), complete52-byte/25-instruction bound correspondence to FHEAP public __farfreef. Three DS-relative WORD operands bind0027; FAR field2798 binds actual NE13:0962. Vendor __WinAllocFlag/__RLSMEM are laboratory binding roles, not original names or proved release semantics. BP-based SP restoration and terminal plain RETF establish zero own argument purge; subordinate effects and ABI remain unproved. Proved own argument purge is zero, not a complete subordinate or whole-function effects contract. Complete original-file extent [2f76,2faa)." },
	{ 0x2a9c, 0x2aae, "scrantic_cwm31_heap_malloc_correspondence", false, SCRANTIC_MARKER "NE1:[229c,22ae), complete18-byte bound HEAP member/public _malloc correspondence. Pushes literal zero and incoming BP+6, then imported KERNEL ordinal5. Terminal RETF has no immediate; imported cleanup/effects and net cleanup are unproved, so source net cleanup remains UNKNOWN. No modern malloc prototype, pointer or allocation semantics. UNKNOWN supplies no proved net-cleanup override; native own-return purge remains independent inference, not a proved whole-function net-zero contract. Complete original-file extent [2a9c,2aae)." },
	{ 0x2aae, 0x2ae1, "scrantic_cwm31_heap_realloc_correspondence", false, SCRANTIC_MARKER "NE1:[22ae,22e1), complete51-byte/29-instruction bound HEAP member/public _realloc correspondence, original raw-caller-qualified rather than newly proved executable ingress. Actual near calls22be->229c and22cb->22f8 are retained. The latter reaches original15, NOT matching vendor FREE20; full/transitive HEAP equivalence is false. Other arm forwards AX/DX/literal2 to KERNEL ordinal6. Import cleanup/effects, unrestricted C/source and modern realloc ABI remain unproved; terminal plain RETF is not a net-cleanup proof. UNKNOWN supplies no proved net-cleanup override; native own-return purge remains independent inference, not a proved whole-function net-zero contract. Complete original-file extent [2aae,2ae1)." },
	{ 0x2ae1, 0x2af8, "scrantic_cwm31_heap_calloc_correspondence", false, SCRANTIC_MARKER "NE1:[22e1,22f8), complete23-byte/12-instruction bound HEAP member/public _calloc correspondence. Pushes0040, computes signed DX:AX product of two incoming WORDs, forwards current low AX to KERNEL ordinal5. No unrestricted product, pointer, allocation or modern calloc ABI interpretation; imported cleanup/effects and net cleanup remain UNKNOWN despite terminal plain RETF. UNKNOWN supplies no proved net-cleanup override; native own-return purge remains independent inference, not a proved whole-function net-zero contract. Complete original-file extent [2ae1,2af8)." },
	{ 0x2af8, 0x2b07, "scrantic_original_22f8_not_heap_free20", false, SCRANTIC_MARKER "NEGATIVE vendor qualification: original NE1:[22f8,2307) is15 bytes/eight instructions, not genuine HEAP _free20. Original pushes BP+6 directly and unconditionally calls22ff; vendor20 adds a zero test and has different call/return positions. Same KERNEL ordinal7 does not repair correspondence. This original extent ends at terminal2306 RETF; raw00 at2307 and next prefix2308 are excluded. Import effects/cleanup and modern free semantics remain unproved. UNKNOWN supplies no proved net-cleanup override; native own-return purge remains independent inference, not a proved whole-function net-zero contract. Complete original-file extent [2af8,2b07)." },
};

static const struct {
	ut64 physical;
	const char *name;
	const char *comment;
	unsigned prerequisites;
} scrantic_annotations[] = {
	{ 0xded, "scrantic_lseek_dgroup_displacement_binding", SCRANTIC_MARKER "NE1:05ed, member field+0b: original bound WORD2af8 in the indexed DS operand. Vendor __openfd is a binding role, not an admitted original data name or complete table layout. No runtime DS/selector or indexed extent guarantee.", 1 },
	{ 0xe06, "scrantic_lseek_near_error_binding", SCRANTIC_MARKER "Original E8 dffe at NE1:0606 reaches actual NE1:04e8 (FILE0ce8). The member's __IOERROR binding does not prove this subordinate is the vendor implementation. Its effects and a modern error/I/O API remain unproved.", 1 },
	{ 0xce8, "scrantic_lseek_subordinate_04e8", SCRANTIC_MARKER "Actual near target of the qualified LSEEK member. This profile marks the binding only, not a complete subordinate function or vendor __IOERROR equivalence.", 1 },
	{ 0x2ee3, "scrantic_fheap_getmem_binding", SCRANTIC_MARKER "Original NE1:26e3 singleton/nonadditive type3 width4 flags0 relocation -> NE13:07e5; native relocated pair is required, not raw FFFF:0000. Member __GETMEM binding does not establish allocator equivalence; the surrounding original provider differs from the inspected vendor allocator.", 130 },
	{ 0x2f98, "scrantic_fheap_rlsmem_binding", SCRANTIC_MARKER "Original NE1:2798 singleton/nonadditive type3 width4 flags0 relocation -> NE13:0962. Member __RLSMEM binding is established; release semantics, preservation and complete provider equivalence are not.", 260 },
	{ 0x179e5, "scrantic_fheap_subordinate_13_07e5", SCRANTIC_MARKER "Actual original target of the FHEAP73 binding; label only. Whole allocator/vendor equivalence is not established, and the known vendor predicate difference must not be normalized away. No transitive allocation contract is installed.", 130 },
	{ 0x17b62, "scrantic_fheap_subordinate_13_0962", SCRANTIC_MARKER "Actual original target of the FHEAP52 binding; label only, not a complete release-function or imported ABI claim.", 260 },
	{ 0x17e27, "scrantic_fheap_dgroup_0027_binding", SCRANTIC_MARKER "Original NE14/DGROUP offset0027 supplies the six WORD displacement bindings in the selected FHEAP bodies. Vendor __WinAllocFlag is a binding role only; runtime DS identity, selector validity, lifetime and global meaning remain unproved.", 6 },
	{ 0x2abe, NULL, SCRANTIC_MARKER "Original NE1:22be near CALL229c, real selected HEAP18 supplier; no relocation overlay or unresolved placeholder.", 24 },
	{ 0x2acb, NULL, SCRANTIC_MARKER "Original NE1:22cb near CALL22f8 after NOP/PUSH CS. This actual target is the15-byte original, not vendor FREE20: matching51-byte wrapper does not prove transitive supplier equivalence.", 80 },
	{ 0x2aa7, "scrantic_heap_malloc_kernel5_binding", SCRANTIC_MARKER "Original singleton/nonadditive NE type3 width4 flags1 imported operand; module index3 KERNEL ordinal5. Original FFFF0000 is the source-chain terminator plus placeholder, NOT a callee address. Native loader import binding is analysis indirection, not the loaded imported implementation or runtime selector. This profile annotates the established ordinal but does not fabricate imported effects, cleanup or API prototype.", 520 },
	{ 0x2ada, "scrantic_heap_realloc_kernel6_binding", SCRANTIC_MARKER "Original singleton/nonadditive NE type3 width4 flags1 imported operand; module index3 KERNEL ordinal6. Original FFFF0000 is the source-chain terminator plus placeholder, NOT a callee address. Native loader import binding is analysis indirection, not the loaded imported implementation or runtime selector. This profile annotates the established ordinal but does not fabricate imported effects, cleanup or API prototype.", 1040 },
	{ 0x2af1, "scrantic_heap_calloc_kernel5_binding", SCRANTIC_MARKER "Original singleton/nonadditive NE type3 width4 flags1 imported operand; module index3 KERNEL ordinal5. Original FFFF0000 is the source-chain terminator plus placeholder, NOT a callee address. Native loader import binding is analysis indirection, not the loaded imported implementation or runtime selector. This profile annotates the established ordinal but does not fabricate imported effects, cleanup or API prototype.", 2080 },
	{ 0x2b00, "scrantic_original_22f8_kernel7_binding", SCRANTIC_MARKER "Original singleton/nonadditive NE type3 width4 flags1 imported operand; module index3 KERNEL ordinal7. Original FFFF0000 is the source-chain terminator plus placeholder, NOT a callee address. Native loader import binding is analysis indirection, not the loaded imported implementation or runtime selector. This profile annotates the established ordinal but does not fabricate imported effects, cleanup or API prototype.", 4160 },
};

static int borland_scrantic_profile(RAnal *anal) {
	BorlandProfileContext ctx;
	if (borland_eligible (anal) < 0 || !profile_identity (anal, &ctx, "ne", 295952, "f0552c281a2a9b367ad5f41402a907a3c99e73ad0a221ba14d063e31cff594ac")) {
		return 0;
	}
	unsigned accepted = 0;
	int count = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (scrantic_functions); i++) {
		bool applied = profile_function (&ctx, scrantic_functions[i].start, scrantic_functions[i].end - scrantic_functions[i].start, scrantic_functions[i].name, scrantic_functions[i].known_zero? 0: R_ANAL_CC_STACK_POP_UNKNOWN, scrantic_functions[i].comment);
		if (applied) {
			accepted |= 1u << i;
			count++;
		}
		R_LOG_INFO ("Borland scrantic-runtime-qualified: FILE 0x%08"PFMT64x" %s", scrantic_functions[i].start, applied? "qualified (including unchanged)": "preserved/refused; dependent facts skipped");
	}
	const BorlandProfileBinding getmem = { 3, 0, 13, 0x7e5, 0x179e5, NULL, true, true, true };
	const BorlandProfileBinding rlsmem = { 3, 0, 13, 0x962, 0x17b62, NULL, true, true, true };
	if ((accepted & 2) && profile_binding (&ctx, 0x2ee3, &getmem)) {
		accepted |= 128;
	}
	if ((accepted & 4) && profile_binding (&ctx, 0x2f98, &rlsmem)) {
		accepted |= 256;
	}
	static const struct { ut64 physical; int ordinal; unsigned owner; unsigned binding; } imports[] = {
		{ 0x2aa7, 5, 8, 512 }, { 0x2ada, 6, 16, 1024 }, { 0x2af1, 5, 32, 2048 }, { 0x2b00, 7, 64, 4096 }
	};
	for (i = 0; i < R_ARRAY_SIZE (imports); i++) {
		BorlandProfileBinding fact = { 3, 1, 3, imports[i].ordinal, UT64_MAX, "KERNEL", true, true, false };
		if ((accepted & imports[i].owner) && profile_binding (&ctx, imports[i].physical, &fact)) {
			accepted |= imports[i].binding;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (scrantic_annotations); i++) {
		if ((accepted & scrantic_annotations[i].prerequisites) != scrantic_annotations[i].prerequisites) {
			continue;
		}
		ut64 at = profile_mapped (&ctx, scrantic_annotations[i].physical, 1, false);
		if (at != UT64_MAX && (!scrantic_annotations[i].name || profile_label (&ctx, at, scrantic_annotations[i].name))) {
			borland_comment (anal, at, scrantic_annotations[i].comment);
		}
	}
	return count;
}

#undef SCRANTIC_MARKER

#include "borland_profile_simtower.inc.c"

static int borland_profiles(RAnal *anal) {
	return borland_scrantic_profile (anal) + borland_simtower_profile (anal);
}
