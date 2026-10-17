/* radare - LGPL - Copyright 2026 */

#define SIMTOWER_MARKER "[LegacyToolchains simtower-runtime-qualified] "
#define SIMTOWER_SOURCE "Source: SimTower windows-toolchain-fingerprints.md at e90bb42; retained C0WL45/same-model CWL45 members. Vendor correspondence candidates and descriptive analysis names, not original debug symbols, historical producer attribution, integral linkage or observed runtime effects. "
#define SIMTOWER_UNKNOWN R_ANAL_CC_STACK_POP_UNKNOWN

static const struct {
	BorlandProfileRange ranges[2];
	int count;
	const char *name;
	int purge;
	const char *comment;
} simtower_functions[] = {
	{ {{0x22c9,18}}, 1, "simtower_crt45_candidate_cleanup", 0, "SF02 complete cleanup FAR-return body; conditional dispatcher effects remain unproved." },
	{ {{0x22db,1}}, 1, "simtower_crt45_candidate_checknull", 0, "SF02 one-byte RETF public, not a noreturn assertion." },
	{ {{0x22dc,1}}, 1, "simtower_crt45_candidate_restorezero", 0, "SF02 one-byte RETF public." },
	{ {{0x22f2,3}}, 1, "simtower_crt45_candidate_GetDGROUP", 0, "SF02 supplier __GetDGROUP; MOV AX,SS; RETF. No invented return type." },
	{ {{0x22f5,68}}, 1, "simtower_startup_init_dispatch", 0, "SF02 complete near dispatcher; analysis name, not another vendor public. Six-byte record traversal and conditional near/FAR calls do not prove actual table population." },
	{ {{0x2339,65}}, 1, "simtower_startup_exit_dispatch", 0, "SF02 complete near dispatcher; analysis name. Shared136-byte suffix is not release-discriminating." },
	{ {{0x5024,69}}, 1, "simtower_sprintf_copy_callback", 10, "SPRF01 near callback69; mutable destination-pair context and reread count, not a modern callback prototype. Same-library memcpy38 correspondence is separately owned by far-copy analysis." },
	{ {{0x5069,39}}, 1, "simtower_crt45_candidate_sprintf", 0, "SPRF01 FAR wrapper39; constructs SS-relative trailing argument cursor, initializes destination before later argument reads. No va_list, signed-return or pointer-validity assertion." },
	{ {{0x5090,38}}, 1, "simtower_crt45_candidate_vsprintf", 0, "SPRF01 FAR wrapper38 reads supplied cursor WORD; not proof of modern va_list or complete formatting semantics." },
	{ {{0x420a,26},{0x426e,1069}}, 2, "simtower_crt45_candidate_VPRINTER", 12, "SPRF02 [200a,249b)1169 is regional correspondence coverage, not exclusive function ownership. Main native body joins entry[200a,2024) and continuation[206e,249b),1095 bytes; JMP2022 skips independent helpers[2024,206e). Terminal LEAVE; RET0c precedes data. Complete engine effects/servicing remain unreviewed." },
	{ {{0x4224,13}}, 1, "simtower_vprinter_scan_entry", SIMTOWER_UNKNOWN, "SPRF02 native scanner13; real near CALLs22db/233b/236d and RET2030. No register-result prototype or stronger cleanup inferred." },
	{ {{0x4231,9}}, 1, "simtower_vprinter_emit_entry", SIMTOWER_UNKNOWN, "SPRF02 native exclusive emitter entry9, not a standalone returning nine-byte helper. SS:[DI] store/increment, parent-frame BYTE[BP-14] decrement; conditional2038 reaches shared RET206d, otherwise falls through to flush entry203a. Shared tail[203a,206e) remains owned by the native flush function; no overlapping function, synthetic callee or net cleanup/prototype inferred." },
	{ {{0x423a,52}}, 1, "simtower_vprinter_flush_entry", SIMTOWER_UNKNOWN, "SPRF02 native flush52 shares RET206d with emitter entry2031. Parent BP/current-frame callback[BP+e] at2051 has unknown callee contract. Native exclusive partition does not make the emitter's shared suffix disjoint code or establish standalone C parameters, callback effects or net cleanup." },
	{ {{0x606a,5}}, 1, "simtower_crt45_candidate_exit_dummy", 0, "CRT03 exit.c member; five wrappers/dummy literal, helper124 has all41 raw CODE differences. Fifteen CODE sites/25 rows. Matching wrapper bytes do not prove noreturn or complete subordinate effects." },
	{ {{0x606f,124}}, 1, "simtower_crt45_candidate_exit_local_helper", 6, "CRT03 exit.c member; five wrappers/dummy literal, helper124 has all41 raw CODE differences. Fifteen CODE sites/25 rows. Matching wrapper bytes do not prove noreturn or complete subordinate effects." },
	{ {{0x60eb,21}}, 1, "simtower_crt45_candidate_exit", 0, "CRT03 exit.c member; five wrappers/dummy literal, helper124 has all41 raw CODE differences. Fifteen CODE sites/25 rows. Matching wrapper bytes do not prove noreturn or complete subordinate effects." },
	{ {{0x6100,21}}, 1, "simtower_crt45_candidate__exit", 0, "CRT03 exit.c member; five wrappers/dummy literal, helper124 has all41 raw CODE differences. Fifteen CODE sites/25 rows. Matching wrapper bytes do not prove noreturn or complete subordinate effects." },
	{ {{0x6115,14}}, 1, "simtower_crt45_candidate__cexit", 0, "CRT03 exit.c member; five wrappers/dummy literal, helper124 has all41 raw CODE differences. Fifteen CODE sites/25 rows. Matching wrapper bytes do not prove noreturn or complete subordinate effects. Original incoming coverage for this name candidate unproved." },
	{ {{0x6123,14}}, 1, "simtower_crt45_candidate__c_exit", 0, "CRT03 exit.c member; five wrappers/dummy literal, helper124 has all41 raw CODE differences. Fifteen CODE sites/25 rows. Matching wrapper bytes do not prove noreturn or complete subordinate effects. Original incoming coverage for this name candidate unproved." },
	{ {{0x60200,10}}, 1, "simtower_crt45_candidate_terminate", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public @terminate$qv. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." },
	{ {{0x6020a,92}}, 1, "simtower_crt45_candidate_set_terminate", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public @set_terminate$qnqv$v. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." },
	{ {{0x60290,179}}, 1, "simtower_crt45_candidate_call_terminate", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public ___call_terminate. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." },
	{ {{0x60343,9}}, 1, "simtower_crt45_candidate_unexpected", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public @unexpected$qv. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." },
	{ {{0x6034c,92}}, 1, "simtower_crt45_candidate_set_unexpected", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public @set_unexpected$qnqv$v. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." },
	{ {{0x603a8,131}}, 1, "simtower_crt45_candidate_call_unexpected", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public ___call_unexpected. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." },
	{ {{0x6042b,84}}, 1, "simtower_crt45_candidate_GetPolymorphicDTC", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public @__GetPolymorphicDTC$qnvui. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." },
	{ {{0x6047f,88}}, 1, "simtower_crt45_candidate_GetPolymorphicDTCfar", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public @__GetPolymorphicDTCfar$qnvui. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." },
	{ {{0x604d7,122}}, 1, "simtower_crt45_candidate_ExceptInit", SIMTOWER_UNKNOWN, "CRT03 original NE79 complete selected code-entry region; exact supplier public __ExceptInit. Whole849-byte CODE differs83 field/window bytes. unexpected9 and the two DTC bodies84/88 are literal. No pointer/return prototype or noreturn inferred; cleanup left native UNKNOWN." }
};

static bool simtower_fact(BorlandProfileContext *ctx, ut64 physical, bool qualified, const char *name, const char *comment) {
	ut64 address = qualified? profile_mapped (ctx, physical, 1, false): UT64_MAX;
	if (address == UT64_MAX || (name && !profile_label (ctx, address, name))) {
		R_LOG_WARN ("Borland simtower-runtime-qualified: FILE 0x%08"PFMT64x" preserved/refused; dependent annotation skipped", physical);
		return false;
	}
	if (comment) {
		char *text = r_str_newf (SIMTOWER_MARKER "%s", comment);
		borland_comment (ctx->anal, address, text);
		free (text);
	}
	return true;
}

static bool simtower_owner(ut64 physical, const bool *accepted) {
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (simtower_functions); i++) {
		int part;
		for (part = 0; part < simtower_functions[i].count; part++) {
			const BorlandProfileRange *range = &simtower_functions[i].ranges[part];
			if (physical >= range->physical && physical - range->physical < range->size) {
				return accepted[i];
			}
		}
	}
	return false;
}

static bool simtower_far(BorlandProfileContext *ctx, ut64 physical, bool qualified, bool executable, int segment, int offset, ut64 target, const char *name, const char *comment) {
	BorlandProfileBinding fact = { 3, 0, segment, offset, target, NULL, true, executable, true };
	return simtower_fact (ctx, physical, qualified && profile_binding (ctx, physical, &fact), name, comment);
}

static void simtower_word(BorlandProfileContext *ctx, ut64 physical, bool qualified, int expected, const char *comment) {
	simtower_fact (ctx, physical, qualified && profile_word (ctx, physical, expected), NULL, comment);
}

static void simtower_call(BorlandProfileContext *ctx, ut64 physical, bool qualified, ut64 target, bool converted, const char *comment) {
	char *text = converted? r_str_newf ("%s; complete five-byte NOP/PUSH CS/near CALL window, not raw FAR-call equality or proof of actual candidate link. Caller effects beyond this stored relation unproved.", comment): r_str_newf ("%s; original near CALL target FILE %"PFMT64x". No stronger callee effects inferred.", comment, target);
	simtower_fact (ctx, physical, qualified && profile_near (ctx, physical, target, converted), NULL, text);
	free (text);
}

static void simtower_offset(BorlandProfileContext *ctx, ut64 physical, bool qualified, int expected, ut64 target, const char *comment) {
	char *text = r_str_newf ("%s; stored WORD %x, qualified original FILE target %"PFMT64x".", comment, expected, target);
	simtower_fact (ctx, physical, qualified && profile_offset (ctx, physical, expected, target), NULL, text);
	free (text);
}

static bool simtower_startup_type(RAnal *anal) {
	const HelperMember fields[] = {
		{ "protected_word", "uint16_t", 2 }, { "processor_word", "uint16_t", 4 }, { "coprocessor_word", "uint16_t", 6 },
		{ "psp_word", "uint16_t", 8 }, { "instance_word", "uint16_t", 10 }, { "previous_instance_word", "uint16_t", 12 },
		{ "command_offset_word", "uint16_t", 14 }, { "show_word", "uint16_t", 16 }, { "version_word", "uint16_t", 18 },
		{ "abend_test_word", "uint16_t", 25 }, { "copyright_bytes", "uint8_t", 27, 43 }
	};
	return borland_record (anal, "StartupData70Partial", 560, fields, R_ARRAY_SIZE (fields));
}

static void simtower_data(BorlandProfileContext *ctx, bool *accepted) {
	r_anal_types_prepare (ctx->anal);
	const HelperMember far[] = { { "offset", "uint16_t", 0 }, { "selector", "uint16_t", 2 } };
	const HelperMember exit[] = { { "callback_storage_0", "FarStorage16", 0 }, { "callback_storage_1", "FarStorage16", 4 }, { "callback_storage_2", "FarStorage16", 8 }, { "guard_word", "uint16_t", 12 } };
	const HelperMember xxv[] = { { "terminate_storage", "FarStorage16", 10 }, { "unexpected_storage", "FarStorage16", 14 }, { "terminate_ds_word", "uint16_t", 18 }, { "unexpected_ds_word", "uint16_t", 20 } };
	bool far_type = borland_record (ctx->anal, "FarStorage16", 32, far, R_ARRAY_SIZE (far));
	bool word_type = borland_type (ctx->anal, "uint16_t"), byte_type = borland_type (ctx->anal, "uint8_t");
	bool types[] = { simtower_startup_type (ctx->anal), word_type, byte_type, byte_type, far_type && borland_record (ctx->anal, "ExitData14Partial", 112, exit, R_ARRAY_SIZE (exit)), byte_type, far_type && borland_record (ctx->anal, "XxvInitialized296Partial", 2368, xxv, R_ARRAY_SIZE (xxv)) };
	static const struct { ut64 physical; int size; const char *type; ut32 count; const char *name; const char *comment; } regions[] = {
		{ 0x65030,70,"StartupData70Partial",0,"simtower_c0wl45_initialized_data70", "SF02 complete initialized C0WL45 DATA70 literally equals NE82[0030,0076). Stored placement bias0030, not observed live DS. WORD fields are stored operand/public correspondence only; literal vendor copyright DATA correspondence is not producer identity. Descriptive partial analysis layout, not a recovered C type; unestablished fields remain undefined." },
		{ 0x469b,0,"uint16_t",24,"simtower_vprinter_dispatch_words24", "SPRF02 adjacent48-byte data, not functions. All24 original targets equal supplier offsets+1ff2. Whole CODE1241 differs58 bytes: five WORD sites plus24 target WORDs; no normalized equality, final candidate link or complete formatting semantics." },
		{ 0x65b5c,0,"uint8_t",7,"simtower_vprinter_null_text7", "SPRF02 complete DATA103 literally equals both inspected same-model members: (null)/NUL7 then96 dispatch-index bytes. Shared bytes do not identify a release. Stored operands qualify placement, not loaded DS or candidate linkage." },
		{ 0x65b63,0,"uint8_t",96,"simtower_vprinter_dispatch_indices96", NULL },
		{ 0x66036,14,"ExitData14Partial",0,NULL, "CRT03 complete initialized member contribution candidate NE82[1036,1044); six differing raw FAR-chain bytes, not whole DATA equality. Three native offset/selector storage fields and guard WORD; no function prototype or live selector resolution." },
		{ 0x60266,0,"uint8_t",42,"simtower_xxv_raw_table42", "CRT03 xxv.cpp [0066,0090) raw table-like contribution, execution ownership unresolved; not a tenth function. Twenty-five member publics = nine code entries + fifteen DATA + one unplaced BSS, not25 code functions." },
		{ 0x657ec,296,"XxvInitialized296Partial",0,NULL, "CRT03 full initialized DATA placement candidate NE82[07ec,0914), four raw differing FAR-chain bytes. Public labels do not establish public field extents/types. Descriptive partial analysis layout, not a recovered C type; unestablished fields remain undefined." }
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (regions); i++) {
		accepted[i] = types[i] && (regions[i].count? profile_data_array (ctx, regions[i].physical, regions[i].type, regions[i].count): profile_data (ctx, regions[i].physical, regions[i].size, regions[i].type));
		R_LOG_INFO ("Borland simtower-runtime-qualified: data FILE 0x%08"PFMT64x" %s", regions[i].physical, accepted[i]? "qualified (including unchanged)": "preserved/refused; dependent facts skipped");
		simtower_fact (ctx, regions[i].physical, accepted[i], regions[i].name, regions[i].comment);
	}
}

static int borland_simtower_profile(RAnal *anal) {
	BorlandProfileContext ctx;
	if (borland_eligible (anal) < 0 || !profile_identity (anal, &ctx, "ne", 6566400, "2825a3c53f77945c63b6d72e26faa7dde5ddd56c31ca668e67a12576d7feca96")) {
		return 0;
	}
	bool functions[R_ARRAY_SIZE (simtower_functions)] = {0}, data[7] = {0};
	int count = 0, data_count = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (simtower_functions); i++) {
		char *comment = simtower_functions[i].count == 1? r_str_newf (SIMTOWER_MARKER SIMTOWER_SOURCE "%s Complete original-file extent [%"PFMT64x",%"PFMT64x").", simtower_functions[i].comment, simtower_functions[i].ranges[0].physical, simtower_functions[i].ranges[0].physical + simtower_functions[i].ranges[0].size): r_str_newf (SIMTOWER_MARKER SIMTOWER_SOURCE "%s", simtower_functions[i].comment);
		functions[i] = profile_function_ranges (&ctx, simtower_functions[i].ranges, simtower_functions[i].count, simtower_functions[i].name, simtower_functions[i].purge, comment);
		free (comment);
		count += functions[i];
		R_LOG_INFO ("Borland simtower-runtime-qualified: function FILE 0x%08"PFMT64x" %s", simtower_functions[i].ranges[0].physical, functions[i]? "qualified (including unchanged)": "preserved/refused; dependent facts skipped");
	}
	simtower_data (&ctx, data);
	for (i = 0; i < R_ARRAY_SIZE (data); i++) {
		data_count += data[i];
	}
	HelperOp startup_ops[378], cluster_ops[24];
	bool startup = profile_code (&ctx, 0x2200, 378, profile_mapped (&ctx, 0x2200, 378, true), startup_ops);
	simtower_fact (&ctx, 0x2200, startup, "simtower_c0wl45_startup_correspondence", SIMTOWER_SOURCE "SF02/C0FP01 complete CODE378 has55 unequal bytes, all22 WORD operands, six FAR offsets and three complete converted-call windows. Not literal equality or a release-exclusive signature. Startup entry/shared termination flow is not assigned an invented complete function extent. Stable suffix [00f2,017a) is136 literal bytes shared with inspected3.1/4.5 releases.");
	simtower_fact (&ctx, 0x2256, startup, "simtower_c0wl45_public_candidate_56", "Supplier public __INITAPPCALLED; an internal startup point, not an additional proved whole function.");
	simtower_fact (&ctx, 0x22b2, startup, "simtower_c0wl45_public_candidate_b2", "Supplier public __WINMAINCALL; internal startup point. Native FAR binding at00b3 targets NE78:0013; WINMAIN is a vendor candidate, not a retained original name.");
	simtower_fact (&ctx, 0x22dd, startup, "simtower_c0wl45_public_candidate_dd", "Supplier __terminate candidate; original DOS-interrupt/converted-call sequence [00dd,00f2). No noreturn or complete C prototype inferred.");
	static const int startup_words[][2] = { {0x24,0x38},{0x28,0x3e},{0x2c,0x3c},{0x30,0x3a},{0x34,0x40},{0x3b,0x1266},{0x3e,0xe748},{0x4f,0x3a},{0x62,0x42},{0x70,0x32},{0x7b,0x36},{0x8f,0x34},{0x96,0x1242},{0x99,0x125a},{0xa0,0x3a},{0xa4,0x3c},{0xa8,0x38},{0xac,0x3e},{0xb0,0x40},{0xba,0x49},{0xd0,0x125a},{0xd3,0x1266} };
	for (i = 0; i < R_ARRAY_SIZE (startup_words); i++) {
		char *comment = r_str_newf ("SF02 stored startup binding WORD -> NE82:%x; operand/boundary correspondence, not a resolved live DS reference or complete linker map.", startup_words[i][1]);
		simtower_word (&ctx, 0x2200 + startup_words[i][0], startup && data[0], startup_words[i][1], comment);
		free (comment);
	}
	simtower_far (&ctx, 0x2207, startup && functions[27], true, 79, 0x2d7, 0x604d7, NULL, "SF02 native FAR binding NE79:02d7; __ExceptInit correspondence, not a complete exception contract.");
	simtower_far (&ctx, 0x22b3, startup, true, 78, 0x13, 0x5f813, NULL, "SF02 native FAR binding NE78:0013; WINMAIN candidate, not a retained original name or complete callee contract.");
	static const struct { ut64 physical; int module; int ordinal; const char *library; const char *comment; } imports[] = {
		{0x2210,5,91,"KERNEL","SF02 INITTASK candidate / KERNEL91"}, {0x2249,5,30,"KERNEL","SF02 WAITEVENT candidate / KERNEL30"},
		{0x2252,7,5,"USER","SF02 INITAPP candidate / USER5"}, {0x2265,5,132,"KERNEL","SF02 GETWINFLAGS candidate / KERNEL132"},
		{0x6087,5,48,"KERNEL","CRT03 GETMODULEUSAGE candidate / KERNEL48; transitive servicing unproved"}
	};
	for (i = 0; i < R_ARRAY_SIZE (imports); i++) {
		BorlandProfileBinding fact = { 3, 1, imports[i].module, imports[i].ordinal, UT64_MAX, imports[i].library, false, true, false };
		char *comment = r_str_newf ("%s; actual native NE import module%d ordinal%d. Name is correspondence-qualified; no imported ABI, return value or servicing inferred.", imports[i].comment, imports[i].module, imports[i].ordinal);
		simtower_fact (&ctx, imports[i].physical, (i < 4? startup: functions[14]) && profile_binding (&ctx, imports[i].physical, &fact), NULL, comment);
		free (comment);
	}
	static const int startup_calls[][2] = { {0xbf,0x3eeb},{0xc4,0x3f00},{0xe9,0x3eeb} };
	for (i = 0; i < R_ARRAY_SIZE (startup_calls); i++) {
		simtower_call (&ctx, 0x2200 + startup_calls[i][0], startup, 0x2200 + startup_calls[i][1], true, "SF02 startup FAR-to-near conversion");
	}
	simtower_fact (&ctx, 0x5024, functions[6], NULL, "SPRF01 whole146-byte correspondence is not literal:13 differing bytes belong to five native supplier owners: one five-byte converted memcpy call, two callback offsets and two relative engine fields. No NE load-time relocation source intersects this region; actual candidate linkage unperformed.");
	simtower_call (&ctx, 0x503c, functions[6], 0x3422, true, "SPRF01 supplier _memcpy; same-library CWL31/CWL45 bodies literally equal original38 bytes, not exclusive release attribution");
	simtower_offset (&ctx, 0x5077, functions[7] && functions[6], 0x2e24, 0x5024, "SPRF01 callback offset, no selector/prototype inferred");
	simtower_offset (&ctx, 0x509e, functions[8] && functions[6], 0x2e24, 0x5024, "SPRF01 second callback offset");
	simtower_call (&ctx, 0x5088, functions[7] && functions[9], 0x420a, false, "SPRF01 supplier __VPRINTER dependency");
	simtower_call (&ctx, 0x50ae, functions[8] && functions[9], 0x420a, false, "SPRF01 second __VPRINTER call");
	bool cluster = profile_code (&ctx, 0x41f2, 24, profile_mapped (&ctx, 0x41f2, 24, true), cluster_ops);
	simtower_fact (&ctx, 0x41f2, cluster, "simtower_vprinter_conversion_cluster24", "SPRF02 literal conversion cluster24, shared across inspected releases; multiple near entries share a suffix, not24 bytes of separately proved public functions.");
	simtower_fact (&ctx, 0x426d, functions[11] && functions[12], "simtower_vprinter_emit_flush_shared_ret", "SPRF02 one physical RET, native owner flush203a; emitter2038 branches here. A shared tail relation, not duplicate code or a separate callee address.");
	simtower_word (&ctx, 0x4222, functions[9], 0x4aeb, "SPRF02 original EB4A JMP ->206e joins the main continuation. Native branch/body ownership is qualified; independent flow/hints are preserved, never cleared as a Java CALL_RETURN override.");
	static const int targets[] = {0x20f9,0x20e3,0x212e,0x20ee,0x215c,0x2169,0x21a7,0x21ae,0x21b3,0x2117,0x21dc,0x21ba,0x21be,0x21c2,0x223c,0x22e9,0x228c,0x22ac,0x242d,0x2469,0x2469,0x2469,0x2109,0x210f};
	for (i = 0; i < R_ARRAY_SIZE (targets); i++) {
		simtower_offset (&ctx, 0x469b + 2 * i, data[1], targets[i], 0x2200 + targets[i], "SPRF02 CS-relative dispatch WORD, not an unconditional call");
	}
	simtower_offset (&ctx, 0x42de, functions[9] && data[1], 0x249b, 0x469b, "SPRF02 stored CS-indexed table operand");
	simtower_word (&ctx, 0x42cf, functions[9] && data[3], 0xb63, "SPRF02 stored DATA0b63 = base0b5c+7; does not establish live DS loading.");
	simtower_word (&ctx, 0x44d9, functions[9] && data[2], 0xb5c, "SPRF02 stored NULL-fallback DATA0b5c; no live DS/valid-pointer claim.");
	simtower_call (&ctx, 0x442a, functions[9], 0x5476, false, "SPRF02 supplier __LONGTOA candidate; subordinate body/effects unrecovered");
	simtower_call (&ctx, 0x4525, functions[9], 0x5617, false, "SPRF02 supplier __REALCVT candidate; subordinate body/effects unrecovered");
	static const char *exit_names[] = { "simtower_crt45_candidate___exitbuf", "simtower_crt45_candidate___exitfopen", "simtower_crt45_candidate___exitopen" };
	for (i = 0; i < R_ARRAY_SIZE (exit_names); i++) {
		simtower_far (&ctx, 0x66036 + 4 * i, data[4] && functions[13], false, 1, 0x3e6a, 0x606a, exit_names[i], "CRT03 native FAR callback storage NE1:3e6a, not a function prototype or complete callback effects.");
	}
	static const int exit_words[][2] = { {0x1a,0x3a},{0x28,0x1042},{0x2f,0x1042},{0x37,0x1034},{0x3b,0x1034},{0x42,0xe6c8},{0x46,0x1034},{0x52,0x1036},{0x6c,0x103a},{0x70,0x103e} };
	for (i = 0; i < R_ARRAY_SIZE (exit_words); i++) {
		char *comment = r_str_newf ("CRT03 EXIT supplier binding; stored NE82 offset%x. Stored placement correspondence only, not observed DS loading or a live resolved pointer.", exit_words[i][1]);
		simtower_word (&ctx, 0x606a + exit_words[i][0], functions[14] && data[4], exit_words[i][1], comment);
		free (comment);
	}
	static const int exit_calls[][2] = { {0x3eb5,0xc9},{0x3ebe,0xdc},{0x3ec3,0xdb},{0x3edf,0xdd} };
	for (i = 0; i < R_ARRAY_SIZE (exit_calls); i++) {
		simtower_call (&ctx, 0x2200 + exit_calls[i][0], functions[14], 0x2200 + exit_calls[i][1], true, "CRT03 EXIT converted supplier call");
	}
	simtower_fact (&ctx, 0x604d7, functions[27], NULL, "CRT03 initializer122 has28 raw unequal field bytes. Genuine startup source NE1:0007 binds here. Complete exception semantics, imported/transitive servicing and integral member linkage remain unproved.");
	bool terminate_storage = simtower_far (&ctx, 0x657f6, data[6] && functions[19], false, 79, 0, 0x60200, NULL, "CRT03 terminate FAR storage binding; no pointer prototype or runtime selector claim.");
	bool unexpected_storage = simtower_far (&ctx, 0x657fa, data[6] && functions[22], false, 79, 0x143, 0x60343, NULL, "CRT03 unexpected FAR storage binding; no pointer prototype or runtime selector claim.");
	static const int public_offsets[] = {0,4,6,8,0xa,0xe,0x12,0x14,0x16,0x1a,0x1c,0x20,0x24,0x28,0xa8};
	static const char *public_names[] = {"CPPexceptionList","exceptFlags","savedDS","savedSI","terminatePTR","unexpectdPTR","terminate_DS","unexpectd_DS","throwFileName","throwLineNumber","throwExceptionName","exceptStaticBuffP","exceptMemAllocVars","exceptionNameBuff","ExceptStaticXbuff"};
	bool publics = data[6];
	for (i = 0; i < R_ARRAY_SIZE (public_offsets); i++) {
		char *name = r_str_newf ("simtower_crt45_candidate_%s", public_names[i]);
		bool binding = (i != 4 || terminate_storage) && (i != 5 || unexpected_storage);
		bool applied = simtower_fact (&ctx, 0x657ec + public_offsets[i], data[6] && binding, name, NULL);
		publics &= applied;
		free (name);
	}
	simtower_fact (&ctx, 0x657ec, publics, NULL, "CRT03 all15 DATA publics and intermediate bytes accounted; labels are supplier correspondence candidates, not field-size/prototype recovery. Four-byte BSS public __DestructorCountPtr has no selected-member fixup/reference and no established original placement; deliberately no arbitrary zero-slot label/data.");
	simtower_far (&ctx, 0x6026a, data[5] && functions[21], false, 79, 0x129, 0x60329, NULL, "CRT03 raw-table FAR storage binding NE79:0129; raw contribution is not another function.");
	simtower_far (&ctx, 0x60288, data[5], false, 79, 0x66, 0x60266, NULL, "CRT03 raw-table FAR storage binding NE79:0066, not a code-entry declaration.");
	static const int client_fields[] = {0x15,0x3d,0xae,0xd3,0xec,0x102,0x157,0x17f,0x1b3,0x1d3,0x1ec,0x202,0x2fc,0x311,0x32c};
	for (i = 0; i < R_ARRAY_SIZE (client_fields); i++) {
		ut64 physical = 0x60200 + client_fields[i];
		simtower_far (&ctx, physical, simtower_owner (physical, functions), true, 1, 0x1d4c, 0x3f4c, NULL, "CRT03 supplier @__EH_GetClientData$qui candidate; native FAR binding NE1:1d4c, not its prototype or transitive effects.");
	}
	static const int dependencies[][2] = { {3,0x3e26},{0x132,0x3e26},{0x222,0x3e26},{0xa8,0x259e},{0x2ef,0x1a55},{0x304,0x1e47} };
	for (i = 0; i < R_ARRAY_SIZE (dependencies); i++) {
		ut64 physical = 0x60200 + dependencies[i][0];
		char *comment = r_str_newf ("CRT03 native supplier dependency binding NE1:%x; abort/flushall/EH helper name candidates do not establish full effects or noreturn.", dependencies[i][1]);
		simtower_far (&ctx, physical, simtower_owner (physical, functions), true, 1, dependencies[i][1], 0x2200 + dependencies[i][1], NULL, comment);
		free (comment);
	}
	static const int xxv_words[][2] = { {0x2db,0x940},{0x2e6,0xe6bc},{0x2ea,0xe6be},{0x2f5,0xe6be},{0x2f8,0xe6bc},{0x30a,0x944},{0x30d,0x942},{0x349,0x800},{0x34c,0x7fe} };
	for (i = 0; i < R_ARRAY_SIZE (xxv_words); i++) {
		ut64 physical = 0x60200 + xxv_words[i][0];
		char *comment;
		if (xxv_words[i][0] == 0x349) {
			comment = strdup ("CRT03 stored DATA0800 corresponds to supplier0014; stored NE82 offset800, placement evidence, not live DS resolution.");
		} else if (xxv_words[i][0] == 0x34c) {
			comment = strdup ("CRT03 stored DATA07fe corresponds to supplier0012; stored NE82 offset7fe, placement evidence, not live DS resolution.");
		} else {
			comment = r_str_newf ("CRT03 cachedSS/cachedVarPtr/EH_TablePtr supplier binding; stored NE82 offset%x. Stored placement correspondence only, not observed DS loading or a live resolved pointer.", xxv_words[i][1]);
		}
		simtower_word (&ctx, physical, data[6] && simtower_owner (physical, functions), xxv_words[i][1], comment);
		free (comment);
	}
	const BorlandProfileBinding selector = { 2, 0, 79, 0, 0x60200, NULL, false, true, false };
	const BorlandProfileBinding offset = { 5, 0, 79, 0x7e, 0x6027e, NULL, false, true, false };
	simtower_fact (&ctx, 0x6029a, functions[21] && profile_binding (&ctx, 0x6029a, &selector), NULL, "CRT03 native SEG relocation to NE79; separately retained from OFF16L009d. Not an invented flat pointer.");
	simtower_fact (&ctx, 0x6029d, functions[21] && data[5] && profile_binding (&ctx, 0x6029d, &offset), NULL, "CRT03 native OFF16L relocation to NE79:007e, within raw table contribution; not a code-entry declaration.");
	static const int xxv_calls[][2] = { {0x9f,0x3649},{0x12c,0x1a58},{0x139,0x36ba} };
	for (i = 0; i < R_ARRAY_SIZE (xxv_calls); i++) {
		ut64 physical = 0x60200 + xxv_calls[i][0];
		simtower_call (&ctx, physical, simtower_owner (physical, functions), 0x60200 + xxv_calls[i][1], true, "CRT03 XXV converted supplier call; transitive body/effects unproved");
	}
	R_LOG_INFO ("Borland simtower-runtime-qualified: %d/28 function facts, %d/7 data regions qualified (including unchanged); preserved/refused prerequisites stop dependent facts. No complete CRT binding, historical attribution, modern prototypes, noreturn or BSS placement inferred.", count, data_count);
	return count;
}

#undef SIMTOWER_MARKER
#undef SIMTOWER_SOURCE
#undef SIMTOWER_UNKNOWN
