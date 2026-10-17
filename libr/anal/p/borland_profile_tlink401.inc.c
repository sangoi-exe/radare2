/* radare - LGPL - Copyright 2026 */

#define TLINK401_MARKER "[LegacyToolchains tlink401-qualified] "

static const struct {
	ut64 start;
	ut64 end;
	const char *name;
	const char *comment;
} tlink401_functions[] = {
	{ 0x3458, 0x34ee, "tlink401_rewrite_far_window_cf", TLINK401_MARKER "R118/R144: CS0 load-image[3058,30EE), original FILE=0400+load offset. Descriptor kind1/3 and representative word4==BX plus opcode/buffer guards are required; not final physical-segment equality. DS03E6/03E8 are current entry/record coordinates;077E/079E select distinct arrays. For j=DX&03FF, old operand is read before opcode rejection.9A→90 0E E8, EA→90 90 E9; j0 additionally checks0210/0212 and uses saved opcode0214, setting carry-back0C4C. Success adds F802 to fullDX, subtracts j/4/current03E8 fromCX, writes marker021C=FFFF and setsCF; rejectionCF0. Saved AX/SI/DI restored; finalES is descriptor view." },
	{ 0x3556, 0x3622, "tlink401_location_dispatch", TLINK401_MARKER "R144: complete3156..3222 including diagnostic backedge3220→31B2.3198 compares currentDS0450 against I[BX]+2; equality bypasses writer.31A5 calls3058 only on inequality; returnedCF1 skips30EE. No immediate5.1-style disable guard in this partition; upstream controls remain open." },
	{ 0x6e8f, 0x702a, "tlink401_produce_entry_family", TLINK401_MARKER "R144: current07BE list; combinable same-name entries retain remembered entry offset in R+2. Nonzero alignmentE0/combine1C and list/order/state conditions apply; producer does not itself compare class handles. OrdinaryRET6BF2, diagnostic tail through6C28 included." },
	{ 0x70fb, 0x7127, "tlink401_allocate_descriptor20", TLINK401_MARKER "R144: request14h via079A; successful usable allocation clears20 bytes, stores currentSI at descriptor+4, independently increments06B9 and stores number at+6. Growth/error effects unresolved; representative is not descriptor number/finalCS." },
	{ 0x716e, 0x7559, "tlink401_construct_family_descriptor", TLINK401_MARKER "R144: ordinary nonempty reuse requires equal name/class, nonzero combine and flag02 clear; publish existing descriptor in R+0 without replacing+4. Empty/special/packing branches differ. OrdinaryRET7100 and diagnostic tail7156→708A included; helper effects remain conditional." },
};

static const struct {
	ut64 start;
	ut64 end;
	const char *name;
	const char *comment;
} tlink401_windows[] = {
	{ 0x3a3a, 0x3ba7, "tlink401_frame50_selected_callers", TLINK401_MARKER "R144: explicitly partial363A..37A7. Selected frame50 setsBX=DI; ordinary0215 flags clear and current0017 nonzero select lowCX/high0420 SUB/SBB of021E/0220. RestoredDX class0C calls3058 at370F;37A0 recomputesDI then clearsCF, so resolver finalCF is not writerCF. No immediate rewrite-disable test, not global suppression absence. Exact FILE=0400+CS0 load-image offset; no complete containing function or stronger ABI inferred." },
	{ 0x4ea, 0x535, "tlink401_mode_current_stores", TLINK401_MARKER "R151: partial startup suffix, not whole function. First0100 store0017=(current0128!=1); call9487/017F/BC2B; second0122 store0017=(current0128>=2). Intervening BC2B→A63F can change0128. Parser mode is not a lifetime guarantee. Exact FILE=0400+CS0 load-image offset; no complete containing function or stronger ABI inferred." },
	{ 0x974, 0xa56, "tlink401_raw_option_dispatch", TLINK401_MARKER "R151: complete selected raw-letter dispatch partition, not complete parser. Generic savedCH has no f comparison; ordinary/f reaches0653→07A6, not5.1 disable setter. BF71 effects unresolved; no cross-release CLI equivalence. Exact FILE=0400+CS0 load-image offset; no complete containing function or stronger ABI inferred." },
	{ 0xafc, 0xb73, "tlink401_selected_mode_option", TLINK401_MARKER "R151: raw uppercaseT selects handler; ordinary next folded d/w/o/b stores0128=1/2/3/4. Further modifiers and961B are conditional, not final current0017 or historical configuration. Exact FILE=0400+CS0 load-image offset; no complete containing function or stronger ABI inferred." },
	{ 0xca6, 0xce9, "tlink401_selected_uppercase_p_option", TLINK401_MARKER "R151: selected/P- clears0126 at08BE; chosen caller/writer do not read that separate byte. No global absence-of-suppression conclusion. Exact FILE=0400+CS0 load-image offset; no complete containing function or stronger ABI inferred." },
};

// Partial code is qualified through the same current mapping/relocation/context owner; never fabricate a function.
static bool tlink401_window(BorlandProfileContext *ctx, ut64 physical, int size, const char *name, const char *comment) {
	ut64 address = profile_mapped (ctx, physical, size, true);
	HelperOp *ops = calloc (size, sizeof (HelperOp));
	bool valid = ops && address != UT64_MAX && profile_code (ctx, physical, size, address, ops);
	if (valid) {
		RVecIntervalNodePtr *metadata = r_meta_get_all_intersect (ctx->anal, address, size, R_META_TYPE_ANY);
		RIntervalNode **node;
		if (metadata) {
			R_VEC_FOREACH (metadata, node) {
				RAnalMetaItem *item = (*node)->data;
				valid &= item->type == R_META_TYPE_COMMENT || item->type == R_META_TYPE_HIGHLIGHT;
			}
		}
		RVecIntervalNodePtr_free (metadata);
		RList *blocks = r_anal_get_blocks_intersect (ctx->anal, address, size);
		RListIter *iter;
		RAnalBlock *bb;
		r_list_foreach (blocks, iter, bb) {
			if (bb->addr < address || bb->addr - address >= size || bb->size > size - (bb->addr - address)) {
				valid = false;
				break;
			}
			BorlandCodeRange range = { bb->addr, bb->size, ops + (bb->addr - address) };
			RAnalFunction view = { .bbs = r_list_new () };
			r_list_append (view.bbs, bb);
			valid &= borland_body_ranges (&view, &range, 1);
			r_list_free (view.bbs);
		}
		r_list_free (blocks);
	}
	free (ops);
	if (!valid || (name && !profile_label (ctx, address, name))) {
		R_LOG_WARN ("Borland tlink401-qualified: preserving partial code at FILE 0x%08"PFMT64x, physical);
		return false;
	}
	borland_comment (ctx->anal, address, comment);
	return true;
}

static void tlink401_types(RAnal *anal) {
	if (!borland_type (anal, "uint8_t") || !borland_type (anal, "uint16_t")) {
		return;
	}
	const HelperMember descriptor[] = {
		{ "kind", "uint8_t", 1 }, { "representative_entry_offset", "uint16_t", 4 }, { "descriptor_number", "uint16_t", 6 }
	};
	const HelperMember entry[] = {
		{ "descriptor_offset", "uint16_t", 0 }, { "family_entry_offset", "uint16_t", 2 }
	};
	// Independent dynamic views only: never link these to an invented initialized DS object.
	borland_record (anal, "tlink401_Descriptor20Partial", 160, descriptor, R_ARRAY_SIZE (descriptor));
	borland_record (anal, "tlink401_AssociatedEntry10Partial", 80, entry, R_ARRAY_SIZE (entry));
}

static int borland_tlink401_profile(RAnal *anal) {
	BorlandProfileContext ctx;
	if (borland_eligible (anal) < 0 || !profile_identity (anal, &ctx, "mz", 73401, "df1be38b22d43cc912992f1fcca93a5b630197721744ef2eea399f22d1415f0c")) {
		return 0;
	}
	r_anal_types_prepare (anal);
	tlink401_types (anal);
	bool accepted[R_ARRAY_SIZE (tlink401_functions)] = {0};
	int count = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tlink401_functions); i++) {
		accepted[i] = i? profile_function (&ctx, tlink401_functions[i].start, tlink401_functions[i].end - tlink401_functions[i].start, tlink401_functions[i].name, 0, tlink401_functions[i].comment)
			: borland_tlink_writer (&ctx, tlink401_functions[i].start, tlink401_functions[i].name, tlink401_functions[i].comment);
		count += accepted[i];
		R_LOG_INFO ("Borland tlink401-qualified: FILE 0x%08"PFMT64x" %s", tlink401_functions[i].start, accepted[i]? "qualified (including unchanged)": "preserved/refused; dependent facts skipped");
	}
	bool windows[R_ARRAY_SIZE (tlink401_windows)] = {0};
	for (i = 0; i < R_ARRAY_SIZE (tlink401_windows); i++) {
		windows[i] = tlink401_window (&ctx, tlink401_windows[i].start, tlink401_windows[i].end - tlink401_windows[i].start, tlink401_windows[i].name, tlink401_windows[i].comment);
	}
	if (profile_data_array (&ctx, 0x3546, "uint16_t", 8)
			&& profile_label (&ctx, profile_mapped (&ctx, 0x3546, 16, false), "tlink401_location_dispatch_words8")) {
		borland_comment (anal, profile_mapped (&ctx, 0x3546, 16, false), TLINK401_MARKER "R144: eight raw CS-relative word targets, not FAR pointers or unconditional calls. Slot3/location0C selects3198. Native loaded source addresses come from original FILE mappings, never an NE ordinal.");
		const ut16 targets[] = { 0x31b2, 0x3166, 0x31b6, 0x3198, 0x31b2, 0x31aa, 0x31b2, 0x31b2 };
		for (i = 0; i < R_ARRAY_SIZE (targets); i++) {
			profile_offset (&ctx, 0x3546 + 2 * i, targets[i], 0x400 + targets[i]);
		}
	}
	if (accepted[4]) {
		borland_comment (anal, profile_mapped (&ctx, 0x72d1, 1, true), TLINK401_MARKER "R144: selected ordinary reuse branch6ED1..6F1F; no universal equal-name iff equal-descriptor rule. I uses current0776, R current077E, D current079E.");
	}
	if (tlink401_window (&ctx, 0x5ec, 3, NULL, NULL)) {
		borland_comment (anal, profile_mapped (&ctx, 0x5ed, 2, true), TLINK401_MARKER "R151: actual native MZ relocation selects startup DS11B1 relative paragraph;11B10 is beyond initialized load-image end11AB9. DS0017 is not an initialized original-file object. Native relocated pointers, not FILE+inventedDS, own the loaded view; startup/helper/service/lifetime remain unproved.");
	}
	if (accepted[0] && accepted[1]) {
		profile_near (&ctx, 0x35a5, 0x3458, false);
	}
	if (accepted[0] && windows[0] && profile_near (&ctx, 0x3b0f, 0x3458, false)) {
		borland_comment (anal, profile_mapped (&ctx, 0x3b0f, 3, true), TLINK401_MARKER "Actual selected near CALL370F->3058 (writer); returnedCF later overwritten by resolver37A0. See independently qualified descriptor views; no5.1 fields or option latch imported.");
	}
	return count;
}

#undef TLINK401_MARKER
