/* radare - LGPL - Copyright 2026 */

#define TLINK51_MARKER "[LegacyToolchains tlink51-qualified] "
#define TLINK51_CODE 0x1200
#define TLINK51_SLOTS 0x11800

typedef struct {
	ut16 start;
	ut16 end;
	const char *name;
	int purge;
	const char *comment;
} Tlink51CodeFact;

static const Tlink51CodeFact tlink51_functions[] = {
	{ 0x3c0b, 0x3ca1, "tlink51_rewrite_far_window_cf", 0, TLINK51_MARKER "R118/K2: complete150-byte/51-instruction writer. Current09C0 array at058C selects descriptor in09D8; kind1/3 and word4==BX required. j=DX&03FF; old operand read before opcode rejection.9A->90 0E E8, EA->90 90 E9; j0 checks saved0282/0284 before0286 opcode and sets0CD6. Success addsF802 to fullDX, subtracts j/4/fresh058E fromCX and writes028E=FFFF/CF1; rejectionCF0. AX/SI/DI restored, finalES descriptor selector. Representative equality is not a universal physical-segment rule." },
	{ 0x3b87, 0x3c0b, "tlink51_flush_rewrite_buffer", 0, TLINK51_MARKER "R118: saves last opcode/current record boundary in0286/0284/0282. Carry-back0CD6 conditionally extends source/position backward1.9E96 is a buffer-copy request, not physical-I/O success." },
	{ 0x7cb3, 0x7e58, "tlink51_produce_entry_family", 0, TLINK51_MARKER "K2: ordered combinable same-name family stores currentSI or rememberedCX into R+2. Sorting/list order/helper/current-state prerequisites remain; not descriptor number or packed selector." },
	{ 0x7f29, 0x7f55, "tlink51_allocate_descriptor20", 0, TLINK51_MARKER "K2: request14h via09D4; zero20 on usable return, storeSI at+4; separately increment087B and store at+6. Allocation/growth effects conditional." },
	{ 0x7f9c, 0x8391, "tlink51_construct_family_descriptor", 0, TLINK51_MARKER "K2: ordinary PUBLIC nonempty reuse requires equal name/class and combine controls, retains representative+4 while publishing R+0. New/empty/special packing branches differ; descriptor sharing is not final physical-segment equivalence." },
	{ 0xa901, 0xa97d, "tlink51_classify_descriptor_kind", 0, TLINK51_MARKER "K2: current attributes/special handles first; trailing literalCODE test can return1, other category3 also writer-accepted. Not universal CODE classification or historical identity." },
	{ 0x03c0, 0x043f, "tlink51_read_option_character", 0, TLINK51_MARKER "R126: pending byte returns both halves unchanged; ordinary return AH raw/AL ASCII-folded, BX/CX/DX restored. Numeric INT21 state/results are unresolved, ES/flags not preserved." },
	{ 0x0baa, 0x0c64, "tlink51_initialize_options", 0, TLINK51_MARKER "R126: ES=DS clear42 bytes0180..01AA only with clearDF, including01A9/0186; then input composer/config attempt. No localCLD or historical defaults guaranteed. Relocated immediate0BD1 targetsNE1:0010, not literal16." },
	{ 0x0a2b, 0x0baa, "tlink51_compose_option_input", 0, TLINK51_MARKER "R126: conditional config/name and response input composition, parser calls0AE0/0B46. Service/helper returns, exact chosen config, BX/SI/DI preservation and historical controls are not inferred." },
	{ 0x00c4, 0x0119, "tlink51_reset_working_controls", 0, TLINK51_MARKER "R192: clears0019/001A, not0186. Complete body excludes subsequent inline-text startup path." },
	{ 0xa046, 0xa06f, "tlink51_traverse_record_controls", 0, TLINK51_MARKER "R192: matching current record bytesFF/03 set0019 independently of option setter. Intact ordinary termination AND SI,SI givesCF0/ZF1, restoresBX/ES and leavesSI0; no allocator/record/API identity." },
	{ 0xa06f, 0xa089, "tlink51_selected_control_traversals", 0, TLINK51_MARKER "R192: actual A082 conditional0019=1 store exists but is not selected by either intact ordinary A046 clearCF return. No blanket syntactic unreachable or exclusive supplier claim." },
	{ 0xd84a, 0xd8e7, "tlink51_supply_association_and_call", 0, TLINK51_MARKER "R206: current chain/A4CE values supply089F/08A1/08A3/08A7; optionalzeroSI leaves089F untouched; clears08A5 and directly callsD8E7 atD8CE. Subsequent chain read reloadsES; no historical name or helper preservation inferred." },
	{ 0xd8e7, 0xd976, "tlink51_construct_name_association", 0, TLINK51_MARKER "R206: request12 then six-word currentDF copy from089F. Name bank08D8 and record bank0938 differ; full offsets retained around low3-bit bank selection. New record writes0/+2/+0C/flags20 before name binding; existing current10 permits+2 replacement and20-set/10-clear, otherwise copied association discarded. Allocation/error/helper state and extents remain conditional." },
	{ 0x6649, 0x6663, "tlink51_allocate_vector_descriptor", 0, TLINK51_MARKER "R212: capacity80/cursor0 then FAR3:000C boundary; localDI/CX saves do not prove external cleanup/selector write/allocation success." },
	{ 0x6663, 0x6673, "tlink51_allocate_vector_pair", 0, TLINK51_MARKER "R212: allocate/fill descriptor then DI+=8 and repeat. Paired layout is not successful allocation proof." },
	{ 0x6673, 0x6684, "tlink51_fill_vector_descriptor", 0, TLINK51_MARKER "R212: currentES descriptor+4, capacity/2 wordsFFFF with currentDF, noCLD; restoresDI, not AX/CX/ES." },
	{ 0x64ef, 0x654d, "tlink51_advance_vector_bank_cf", 0, TLINK51_MARKER "R212: preservesSI only under ordinary stack premises; finite remaining-space/request, compares descriptor+6+8, can publish0A6A=0A6C. Direct success returns currentES/DI, not preserved incoming pointer; clearDF/even extents are premises for word-slot projection." },
	{ 0xbcdd, 0xbeaf, "tlink51_construct_output_header", 0, TLINK51_MARKER "R162: workingDS085F, NOT inputFILE10C0. StoresNE05/0A fields;+22=40 then finite count/table shifts and selected carry checks. Optional count replacement/decrement occurs after initial<=FE check; equal+24/+26 does not prove resource absence/ownership. Helpers and diagnostic-return fallthrough remain conditional." },
	{ 0xab57, 0xab98, "tlink51_produce_alignment_state", 0, TLINK51_MARKER "R162: current001E0 gives exponent4/maskF; otherwise01A6 nonzero produces floor-log2. Input1 exponent0 executes65536 SHL iterations and maskFFFF, NOT mask0. Zero diagnostic and unsupported inputs/lifetime unresolved." },
	{ 0xbeaf, 0xbee1, "tlink51_request_current_header_copy", 0, TLINK51_MARKER "R162/R181: BC75, then86BD, THEN reloadCX40/SI085F/AX=currentB7A2/DX0 forBEDD->9E96. Prior record copies can reach external preparation first; not immutable header or physical output." },
	{ 0xbee1, 0xc02f, "tlink51_produce_segment_record8", 0, TLINK51_MARKER "R169: ordered zero/full/clipped length/allocation/sector stores to08AB/08AD/08B1; finite bytecarry/shift geometry, count0 executes65536 shifts. Current signed-kind and+13 bit tests store08AF flags last. Ordinary helper-free epilogue restores incomingAX/BX/CX/DX/DI; ES descriptor view, flags clobbered. Diagnostic tails not proved returning/preserving." },
	{ 0xc02f, 0xc062, "tlink51_request_segment_table_records", 0, TLINK51_MARKER "R162/R169: current header+22/0881+B7A2 position; descriptors advance14. Nonempty+0D OR+0F callsBEE1 thenCX8/SI08AB/DX0->9E96. BEE1 ordinary return restores inputAX; later position is actual post9E96 value. Not full count/loop/file validity." },
	{ 0x86bd, 0x87d8, "tlink51_produce_nb02_working_records", 0, TLINK51_MARKER "R181/R187: conditional clearDF initial16 NB02+12FF at08BB; saveQ from ACTUAL post-first-copyDX:AX. Selected middle0686 stores52FB/0310-or0209/current0182 and adjustedQ fields; fresh state then final08CB NB02+u32(W-Q+18). Requests9E96 at8718/8784/87CF; zero-count middle request is not a no-op. FinalDX0, actualAX; no localCLD or direct seed of0ABC/0CBD/0631/0633. Shapes are not usable debug symbols, removed-debug proof or witnessed physicalEOF." },
	{ 0xab98, 0xabb0, "tlink51_divide_position_0200", 0, TLINK51_MARKER "R181: ordinaryDIV domainDX<0200, remainder064A and wrapped rounded quotient064C; AX/BX/DX saved/restored, flags not. Overflow before stores andFFFF+carry wrap forbid unrestricted ceiling arithmetic." },
	{ 0x4c31, 0x4c8b, "tlink51_request_current_working_record", 0, TLINK51_MARKER "R198/R220: old descriptor+11 read BEFORE increment;6D01 uses old count. Fresh descriptor+8/+0A then05A4; ADC CL,CH discards byteoverflow; fresh05A6/05A8 selects source/count for4C81->9E96. Ordinary six saved registers restored, ES not preserved, CF not deliberate success." },
	{ 0x6d01, 0x6d19, "tlink51_adjust_quantity", 0, TLINK51_MARKER "R220: finiteoldDX<<1; if current001E nonzero shift twice more+2; AX addition's CF alone becomesDX0/1 via MOV/ADC. No source/count stores, helpers or external output." },
	{ 0x9e96, 0x9edf, "tlink51_copy_mapped_buffer", 0, TLINK51_MARKER "R162/R175/R220: map via9D26 before each chunk; capacity8000-DI. Actual ADD AX,count / ADC DL,DH, not ADC DX,0. SHR/REP MOVSW/RCL/REP MOVSB words then oddbyte with currentDF, noCLD. Conditional0633 high-water update; ordinary savedBX/CX restored andES=CS, not preserved inputES. No successful preparation/physical I/O implied." },
	{ 0x9ce2, 0x9d07, "tlink51_prepare_table_entry_boundary", 0, TLINK51_MARKER "R175: forwards words through FAR3:00E3/00ED. LocalBX saves require actual external argument disposal. DI/SI/DS/DF not locally preserved; no allocator success or identity inferred." },
	{ 0x9bd6, 0x9c15, "tlink51_submit_current_mapped_source_count", 0, TLINK51_MARKER "R256: finiteSI shift/exchanges form first4200 numeric request viaABB0. THEN fresh002A handle, currentSI/0631/0633 count, restoredAX and current0ABC+SI selector supplyABD3 sourceDS:0. No countclamp; savedDS/DX/CX restored only on intact ordinary completion, BX requires currentSI preserved; AX/ES/flags not restored." },
	{ 0xdd30, 0xdddc, "tlink51_consumed_near_frame_formatter", R_ANAL_CC_STACK_POP_UNKNOWN, TLINK51_MARKER "R276: POP nearreturn offset and precedingCS beforeBP frame; reconstructs FAR return. Initial argument cursorBP+10; selected%d consumes2, literal disk-full string consumesnone. String termination/views/DF/numeric helper effects remain conditional, not general formatting or historicalC ABI." },
	{ 0xdddc, 0xddf9, "tlink51_select_message_word", 2, TLINK51_MARKER "R276: finite doubled index, additive selector relocationDDE2 associates currentES withNE4:0A6F; table index7/9 select tool diagnostic strings, not service contracts." },
	{ 0x9b20, 0x9b3d, "tlink51_conditional_error_request_chain", 0, TLINK51_MARKER "R276: B496/B3D0/A9A3 then forwards frameword toA9B4. These can reach/reenter numeric wrapper; actual return/termination and physical effects remain unresolved." },
	{ 0xa9a3, 0xa9b4, "tlink51_request_current_handles", 0, TLINK51_MARKER "R276: current0028/002A handles call existingABC4 continuation, NOT ABB0 interrupt entry. Actual currentBX guards/recursive returns remain conditional." },
	{ 0xa9b4, 0xa9db, "tlink51_forward_error_request_word", 0, TLINK51_MARKER "R276: current0194/019A pointer conditionalA9DB then frameword forwardedA9ED; no guaranteed external effects." },
	{ 0xa9db, 0xa9ed, "tlink51_numeric_request_41", 4, TLINK51_MARKER "R276: numericINT21 AH41 andRET4, not assigned API identity or external success." },
	{ 0xa9ed, 0xaa1d, "tlink51_numeric_request_4c", 2, TLINK51_MARKER "R276: calls01F9/009A and FARNE10:0037, then reloads framewordAX, setsAH4C andINT21. Selectedkind4 can submitAL2 under stated returning-frame premises; finalPOP BP/RET2 only IF interruptreturns. Not ordinarynoreturn/termination/exit-status proof." }
};

static const Tlink51CodeFact tlink51_windows[] = {
	{ 0x4f33, 0x4f97, "tlink51_source_record_setup", 0, TLINK51_MARKER "R118: selected setup partition, stores currentBX at058C, adjusted low/high record offset058E/0590, copied count058A and DS0CD8 buffer. Not a complete containing function or finalNE segment identity." },
	{ 0x3d18, 0x3d9c, "tlink51_location_dispatch", 0, TLINK51_MARKER "R118/R198 partial dispatcher, not entire function: (DH&1C)>>1 indexes table.0C->3D5A requires current01A9!=1 and special-class comparison inequality, calls3C0B at3D6E; acceptedCF skips3CA1.04->3D28 and14->3D73 are separate; imported-symbol40E5 return bypasses this dispatcher." },
	{ 0x42bf, 0x43b1, "tlink51_selected_target_frame_writer_callers", 0, TLINK51_MARKER "R118/K2: selected partial resolver with direct4302/432C writer calls; both require class0C/current01A9!=1. Frame50 carries target family key intoBX; other frame/import/thread paths differ.43AA derivesDI from updatedDX and clearsCF, so final resolverCF is not writerCF." },
	{ 0x0493, 0x09a1, "tlink51_option_parser_partition", 0, TLINK51_MARKER "R126/R192: decoded parser partition only, selected f/v semantics, not all handlers. Normal reader AH raw/AL selectively folded; savedCH==lowercasef reaches0726->01A9=1.UppercaseF differs; trailing+/- is pushed back, not a latch toggle. Rawv has separate sign path; no historical config/current-value inference." },
	{ 0x0177, 0x01f9, "tlink51_publish_current_working_controls", 0, TLINK51_MARKER "R192 partial startup path;018B suppression can clear0186 and callDE08, then0197 freshly reads0186 before0019/001A stores. No preservation across diagnostic/helper or initializer-to-record lifetime implied." },
	{ 0x1b22, 0x1b59, "tlink51_record_allocator_partition", 0, TLINK51_MARKER "R206: current063C size, not producer's literal12. Local no-growth zero/fill/decrement fields withCLD and returned oldDI; growth/error boundaries open. LastCALL6450 is not aRET or proved nonreturn; no closed function ABI." },
	{ 0x1b59, 0x1bba, "tlink51_publish_record_vector_partition", 0, TLINK51_MARKER "R206/R212: bound name saves full record offset then current control0A6A/LES+2, finite cursor+2, fullAX store1BA7 before localDI>>1 at01FA. Ends after errorCALL, not a complete returning function. Bank-local slot is not proved equal to resolverBX-1+06DA." },
	{ 0x401e, 0x4064, "tlink51_select_vector_record", 0, TLINK51_MARKER "R206/R212 partial resolver: finiteBX-1+current06DA; below7FC0 uses0A68, else one subtract/current0A70 then doubled offset. Full record handle selects0938 bank; current fields/guards remain. No append-slot/module identity or universal bounds." },
	{ 0x40b8, 0x40ef, "tlink51_association_consumer", 0, TLINK51_MARKER "R198: current record flags20 selects word2->CX/BX=FFFD and jumps43AA without ordinary dispatcher/FAR rewrite. Consumer NameBoundRecord15Partial/Association12Partial domains are distinct." },
	{ 0x67ba, 0x67d2, "tlink51_initialize_vector_pair_fields", 0, TLINK51_MARKER "R212 partial initializer:0A66/0A6E=0,0A6A/0A72=0A64; selectors at descriptor+4 are consumer0A68/0A70. Lifetime/slot identity remains open." },
	{ 0x97af, 0x97d3, "tlink51_select_working_source_count", 0, TLINK51_MARKER "R220 partial initializer: current001E nonzero stores05A6=8/05A8=08B3 thencallsBAEF; zero selects2/0822. This is not a proved lifetime to later4C79/4C7D." },
	{ 0xb8f4, 0xb9e7, "tlink51_working_fixup_partition", 0, TLINK51_MARKER "R198 complete containing partition, selected IMPORTED branch semantics only. DH04/14->source_type5;04 alone sets08B4 bit04 and skips localFFFF source-word replacement. Ordered current08B7/08B9/058E/08B5 reads/stores then4C31; other contained bytes only boundaries, not nonimport closure." },
	{ 0x9d26, 0x9dbe, "tlink51_map_buffer_partition", 0, TLINK51_MARKER "R175: complete selected partition, not sole routine entry. SUB/SBB current0CBD; DI=lo&7FFF; BX=ROL16(hi|(lo&8000),2), not arbitrary division. No-borrow/below0200/no-diagnostic/no-preparation valid-LAR-bit path selectsES/current0ABC table and restoresAX/CX/DX, givespositive capacity. Other paths/selector validity/arguments/services unresolved." },
	{ 0x9c15, 0x9cae, "tlink51_output_loop_slice", 0, TLINK51_MARKER "R256 partial loop: branches outside9CAE. Slot tests and currentreturnedAX gates distinguish9BD6 submissions; fresh0631 loop comparison, finite wrap/control mutations remain. No physical-output or universal bounded-loop claim." },
	{ 0xabb0, 0xabea, "tlink51_numeric_wrapper_entries", 0, TLINK51_MARKER "R256/R276 multi-entry partition, not one ordinary function. ABB1 INT21; savesBX/CLD; errorDDFE consumes index9/count2/savedAX and conditionally resumesABC4. ABD3 AH40 path compares actualreturnedAX with actualcurrentCX; mismatch index7/count0 conditionally resumesABE9. No numeric-service API identity, success, nonreturn or bounded-recursion guarantee." }
};

static const ut16 tlink51_code_slots[] = { 0xc, 0x16, 0xbb, 0xe3, 0xed, 0x1ce };
static const ut16 tlink51_joins[][3] = { { 0xde2c, 0xde2f, 0xde37 }, { 0xde3f, 0xde42, 0xde4c }, { 0xde4e, 0xde51, 0xde59 }, { 0xdeb2, 0xdeb5, 0xdec7 }, { 0xded1, 0xded4, 0xdee0 }, { 0xdee9, 0xdeec, 0xdef1 }, { 0xdefd, 0xdf00, 0xdf1c } };
static const BorlandProfileRange tlink51_error_ranges[] = {
	{ 0xeff9, 0x36 }, { 0xf037, 0xb }, { 0xf04c, 5 }, { 0xf059, 0x5c }, { 0xf0c7, 0xd }, { 0xf0e0, 0xc }, { 0xf0f1, 0xf }, { 0xf11c, 0x54 }
};
static const Tlink51CodeFact tlink51_inline_functions[] = {
	{ 0xb49f, 0xb4c5, "tlink51_copy_length_text", 0, TLINK51_MARKER "R276: savesAX/CX, swapsDS/ES, LODS length, zeroextends and copies bytes. No localCLD; cancallB3D0. ForwardSI/resume requiresDF0/valid extents/intactviews/returning non-destructive helpers; no generic string/ABI guarantee." },
	{ 0xb4f0, 0xb4f8, "tlink51_consume_return_inline_text", 0, TLINK51_MARKER "R276: POP SI consumes nearreturn, ES=CS, CALL B49F thenJMP SI. Does NOT RET into adjacent inline text. Conditional inline-text fallthroughs require accepted current helper/shared-body facts; no ordinary noreturn." }
};
static const char *tlink51_error_name = "tlink51_argument_consuming_error_entries";
static const char *tlink51_error_comment = TLINK51_MARKER "R276 shared alternative entriesDDF9/DDFE/DE03/DE08 selectAX2/4/1/0, POP returnDX beforeBP frame: indexBP+2/countBP+4/bytesBP+6. Code-only NONCONTIGUOUS body excludes all89 inline-data bytes and separateDF70 entry. If DF5A reached with intact saves, restoreDI/SI/BX/DS; savedreturn->DX; SP/AX=u16(BP+6+CURRENT count); restoreBP;PUSH DX/RET. For preCALLSP=S, finalSP=u16(S+4+n). AX/DX are not preserved interrupt results; CX/ES/flags not promised. Kind4 requests further opaque/numeric operations; actual return/termination/recursion remains unresolved. Unknown stack purge, NOT an ordinary noreturn or historical C prototype.";

static bool tlink51_identity(RAnal *anal, BorlandProfileContext *ctx) {
	if (!profile_identity (anal, ctx, "ne", 150569, "ab8b8b96c1bde5ff6f56c8be2c3b928d21ead7430e72b01e3b22f1fa179ad006")) {
		return false;
	}
	ctx->tlink51_relations = true;
	return true;
}

static bool tlink51_types(RAnal *anal) {
	const HelperMember info[] = { { "name_handle", "uint16_t", 0 }, { "class_handle", "uint16_t", 2 }, { "length_low", "uint16_t", 6 }, { "length_extension", "uint8_t", 8 }, { "attributes", "uint8_t", 9 } };
	const HelperMember associated[] = { { "descriptor_offset", "uint16_t", 0 }, { "family_entry_offset", "uint16_t", 2 } };
	const HelperMember descriptor[] = { { "kind", "uint8_t", 1 }, { "association", "uint16_t", 2 }, { "representative_entry_offset", "uint16_t", 4 }, { "descriptor_number", "uint16_t", 6 }, { "coordinate_low", "uint16_t", 8 }, { "coordinate_extension", "uint8_t", 10 }, { "length_word", "uint16_t", 13 }, { "auxiliary_length_word", "uint16_t", 15 }, { "working_count", "uint16_t", 17 }, { "output_control_bits", "uint8_t", 19 } };
	const HelperMember association[] = { { "word0", "uint16_t", 0 }, { "word2", "uint16_t", 2 }, { "word4", "uint16_t", 4 }, { "word6", "uint16_t", 6 }, { "name_handle", "uint16_t", 8 }, { "worda", "uint16_t", 10 } };
	const HelperMember record[] = { { "link_or_unresolved", "uint16_t", 0 }, { "association_offset", "uint16_t", 2 }, { "word08", "uint16_t", 8 }, { "word0a", "uint16_t", 10 }, { "name_handle", "uint16_t", 12 }, { "flags", "uint8_t", 14 } };
	const HelperMember vector[] = { { "capacity_bytes", "uint16_t", 0 }, { "cursor_offset", "uint16_t", 2 }, { "selector", "uint16_t", 4 }, { "current_or_boundary_descriptor", "uint16_t", 6 } };
	const HelperMember fixup[] = { { "source_type", "uint8_t", 0 }, { "flags", "uint8_t", 1 }, { "adjusted_coordinate", "uint16_t", 2 }, { "target_word", "uint16_t", 4 }, { "target_quantity", "uint16_t", 6 } };
	const HelperMember header[] = { { "signature_ne", "uint16_t", 0 }, { "field02", "uint8_t", 2 }, { "field03", "uint8_t", 3 }, { "word4", "uint16_t", 4 }, { "word6", "uint16_t", 6 }, { "word14", "uint16_t", 20 }, { "word16", "uint16_t", 22 }, { "word1c", "uint16_t", 28 }, { "word22", "uint16_t", 34 }, { "word24", "uint16_t", 36 }, { "word26", "uint16_t", 38 }, { "word28", "uint16_t", 40 }, { "word2a", "uint16_t", 42 }, { "word2c", "uint16_t", 44 }, { "word2e", "uint16_t", 46 }, { "word32", "uint16_t", 50 }, { "word34", "uint16_t", 52 }, { "field36", "uint8_t", 54 } };
	const HelperMember segment[] = { { "sector_word", "uint16_t", 0 }, { "raw_length", "uint16_t", 2 }, { "flags", "uint16_t", 4 }, { "raw_allocation", "uint16_t", 6 } };
	const HelperMember initial[] = { { "signature_nb02", "uint8_t", 0, 4 }, { "ffff_words", "uint16_t", 4, 6 } };
	const HelperMember footer[] = { { "signature_nb02", "uint8_t", 0, 4 }, { "finite_distance", "uint32_t", 4 } };
	const HelperMember middle[] = { { "word52fb", "uint16_t", 0 }, { "version_word", "uint16_t", 2 }, { "position_low", "uint16_t", 32 }, { "position_high", "uint16_t", 34 }, { "control0182", "uint8_t", 40 } };
	const HelperMember slot[] = { { "leading_byte", "uint8_t", 0 }, { "target_offset", "uint16_t", 1 }, { "target_selector", "uint16_t", 3 } };
	const struct { const char *name; int size; const HelperMember *members; int count; } records[] = {
		{ "tlink51_SegmentInfo10Partial", 10, info, R_ARRAY_SIZE (info) }, { "tlink51_AssociatedEntry10Partial", 10, associated, R_ARRAY_SIZE (associated) }, { "tlink51_Descriptor20Partial", 20, descriptor, R_ARRAY_SIZE (descriptor) }, { "tlink51_Association12Partial", 12, association, R_ARRAY_SIZE (association) }, { "tlink51_NameBoundRecord15Partial", 15, record, R_ARRAY_SIZE (record) }, { "tlink51_VectorDescriptor8Partial", 8, vector, R_ARRAY_SIZE (vector) }, { "tlink51_FixupWorking8", 8, fixup, R_ARRAY_SIZE (fixup) }, { "tlink51_OutputHeader64Partial", 64, header, R_ARRAY_SIZE (header) }, { "tlink51_OutputSegmentRecord8", 8, segment, R_ARRAY_SIZE (segment) }, { "tlink51_Nb02InitialWorking16", 16, initial, R_ARRAY_SIZE (initial) }, { "tlink51_Nb02TerminalWorking8", 8, footer, R_ARRAY_SIZE (footer) }, { "tlink51_MiddleWorkingRecordPartial", 48, middle, R_ARRAY_SIZE (middle) }, { "tlink51_StoredFarSlot5", 5, slot, R_ARRAY_SIZE (slot) }
	};
	bool valid = true;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (records); i++) {
		if (!borland_record (anal, records[i].name, 8 * records[i].size, records[i].members, records[i].count)) {
			R_LOG_WARN ("Borland tlink51-qualified: preserving type %s", records[i].name);
			valid = false;
		}
	}
	const BorlandEnumCase location[] = { { "word_offset", 4 }, { "far_candidate", 12 }, { "alternate_import_offset", 20 } };
	return borland_enum (anal, "tlink51_MaskedLocationClass", 8, location, R_ARRAY_SIZE (location)) && valid;
}

static bool tlink51_label_admit(BorlandProfileContext *ctx, ut64 physical, const char *name) {
	RFlagItem *flag = ctx->anal->flb.f? r_flag_get (ctx->anal->flb.f, name): NULL;
	ut64 address = profile_mapped (ctx, physical, 1, false);
	return ctx->anal->flb.f && address != UT64_MAX && (!flag || flag->addr == address);
}

// The first query need not install types. An occupied inline type must still have precisely the canonical fields.
static bool tlink51_inline_type_admit(RAnal *anal, const char *name, int length) {
	RAnalBaseType *type = r_anal_get_base_type (anal, name);
	if (!type) {
		return !sdb_const_get (anal->sdb_types, name, NULL);
	}
	bool valid = type->kind == R_ANAL_BASE_TYPE_KIND_STRUCT && type->size == 8 * (length + 1) && RVecAnalTypeMember_length (&type->struct_data.members) == 2;
	if (valid) {
		RAnalTypeMember *prefix = RVecAnalTypeMember_at (&type->struct_data.members, 0), *text = RVecAnalTypeMember_at (&type->struct_data.members, 1);
		valid = !strcmp (prefix->name, "length") && !strcmp (prefix->type, "uint8_t") && !prefix->offset && !prefix->count && !prefix->bitsize
			&& !strcmp (text->name, "text") && !strcmp (text->type, "char") && text->offset == 1 && text->count == length && !text->bitsize;
	}
	r_anal_base_type_free (type);
	return valid;
}

static bool tlink51_inline_preflight(BorlandProfileContext *ctx, BorlandContinuation *joins, BorlandFunctionCheck *checks) {
	size_t i;
	memset (checks, 0, 3 * sizeof (*checks));
	for (i = 0; i < R_ARRAY_SIZE (tlink51_joins); i++) {
		const ut16 *join = tlink51_joins[i];
		int size = join[2] - join[1];
		ut64 physical = TLINK51_CODE + join[1], address = profile_mapped (ctx, physical, size, false);
		ut8 current[28];
		char type[48], label[48];
		snprintf (type, sizeof (type), "tlink51_InlineText%d", size - 1);
		snprintf (label, sizeof (label), "tlink51_inline_text_%x", join[1]);
		BorlandDataCheck data;
		if (size > sizeof (current) || !profile_current (ctx, physical, size, address, current) || current[0] != size - 1
				|| !tlink51_inline_type_admit (ctx->anal, type, size - 1) || !tlink51_label_admit (ctx, physical, label)
				|| !profile_data_preflight (ctx, physical, size, type, 0, &data)) {
			R_LOG_WARN ("Borland tlink51-qualified: refused current inline prefix/extent/data at FILE 0x%08"PFMT64x"; seven continuations withheld", physical);
			goto refuse;
		}
		ut64 call = profile_mapped (ctx, TLINK51_CODE + join[0], 3, true), resume = profile_mapped (ctx, TLINK51_CODE + join[2], 1, true);
		if (call == UT64_MAX || resume == UT64_MAX || !profile_reference_admit (ctx->anal, call, address, R_ANAL_REF_TYPE_DATA, NULL)) {
			goto refuse;
		}
		joins[i] = (BorlandContinuation){ call, resume };
	}
	ctx->continuations = joins;
	ctx->continuation_count = R_ARRAY_SIZE (tlink51_joins);
	for (i = 0; i < R_ARRAY_SIZE (tlink51_inline_functions); i++) {
		const Tlink51CodeFact *fact = &tlink51_inline_functions[i];
		BorlandProfileRange range = { TLINK51_CODE + fact->start, fact->end - fact->start };
		if (!profile_function_preflight (ctx, &range, 1, fact->name, fact->purge, NULL, &checks[i])) {
			goto refuse;
		}
	}
	if (!profile_function_preflight (ctx, tlink51_error_ranges, R_ARRAY_SIZE (tlink51_error_ranges), tlink51_error_name, R_ANAL_CC_STACK_POP_UNKNOWN, NULL, &checks[2])) {
		goto refuse;
	}
	if (checks[2].function && checks[2].function->meta.stack_pop != R_ANAL_CC_STACK_POP_UNKNOWN) {
		goto refuse;
	}
	for (i = 0; i < R_ARRAY_SIZE (tlink51_joins); i++) {
		BorlandCodeRange *range = &checks[2].ranges[i];
		int offset = joins[i].call - range->address;
		if (offset < 0 || offset >= range->size || range->ops[offset].size != 3 || range->ops[offset].type != R_ANAL_OP_TYPE_CALL
				|| range->ops[offset].jump != checks[1].ranges[0].address || range->ops[offset].fail != joins[i].resume) {
			goto refuse;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (tlink51_error_ranges); i++) {
		char name[48];
		snprintf (name, sizeof (name), "tlink51_error_code_%x", (unsigned)(tlink51_error_ranges[i].physical - TLINK51_CODE));
		if (!tlink51_label_admit (ctx, tlink51_error_ranges[i].physical, name)) {
			goto refuse;
		}
	}
	const ut16 entries[] = { 0xddfe, 0xde03, 0xde08 };
	for (i = 0; i < R_ARRAY_SIZE (entries); i++) {
		char name[48];
		snprintf (name, sizeof (name), "tlink51_error_entry_%x", entries[i]);
		if (!tlink51_label_admit (ctx, TLINK51_CODE + entries[i], name)) {
			goto refuse;
		}
	}
	return true;
refuse:
	ctx->continuations = NULL;
	ctx->continuation_count = 0;
	for (i = 0; i < 3; i++) {
		profile_function_check_fini (&checks[i]);
	}
	R_LOG_WARN ("Borland tlink51-qualified: preserving inline prerequisites; seven conditional continuations refused");
	return false;
}

static char *borland_tlink51_continuations(RAnal *anal) {
	BorlandProfileContext ctx;
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}
	bool recognized = tlink51_identity (anal, &ctx);
	pj_o (pj);
	pj_kb (pj, "recognized", recognized);
	pj_ka (pj, "continuations");
	BorlandContinuation joins[R_ARRAY_SIZE (tlink51_joins)];
	BorlandFunctionCheck checks[3];
	if (recognized && tlink51_inline_preflight (&ctx, joins, checks)) {
		size_t i;
		for (i = 0; i < R_ARRAY_SIZE (joins); i++) {
			pj_o (pj);
			pj_kn (pj, "call", joins[i].call);
			pj_kn (pj, "resume", joins[i].resume);
			pj_end (pj);
		}
		for (i = 0; i < R_ARRAY_SIZE (checks); i++) {
			profile_function_check_fini (&checks[i]);
		}
	}
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

static int tlink51_inline_apply(BorlandProfileContext *ctx) {
	BorlandContinuation joins[R_ARRAY_SIZE (tlink51_joins)];
	BorlandFunctionCheck checks[3];
	if (!tlink51_inline_preflight (ctx, joins, checks)) {
		return 0;
	}
	bool applied = true;
	size_t i;
	for (i = 0; i < 2; i++) {
		const Tlink51CodeFact *fact = &tlink51_inline_functions[i];
		applied &= profile_function_apply (ctx, &checks[i], fact->name, fact->purge, fact->comment, NULL);
	}
	applied &= profile_function_apply (ctx, &checks[2], tlink51_error_name, R_ANAL_CC_STACK_POP_UNKNOWN, tlink51_error_comment, NULL);
	for (i = 0; i < 3; i++) {
		profile_function_check_fini (&checks[i]);
	}
	if (applied) {
		for (i = 0; i < R_ARRAY_SIZE (tlink51_joins); i++) {
			int size = tlink51_joins[i][2] - tlink51_joins[i][1];
			char type[48], label[48];
			snprintf (type, sizeof (type), "tlink51_InlineText%d", size - 1);
			snprintf (label, sizeof (label), "tlink51_inline_text_%x", tlink51_joins[i][1]);
			const HelperMember members[] = { { "length", "uint8_t", 0 }, { "text", "char", 1, size - 1 } };
			if (borland_record (ctx->anal, type, size * 8, members, R_ARRAY_SIZE (members))
					&& profile_data (ctx, TLINK51_CODE + tlink51_joins[i][1], size, type)) {
				profile_label (ctx, joins[i].call + 3, label);
				profile_reference (ctx->anal, joins[i].call, joins[i].call + 3, R_ANAL_REF_TYPE_DATA);
				borland_comment (ctx->anal, joins[i].call, TLINK51_MARKER "R276 CALL B4F0 consumes its return into inline length-prefixed DATA, no terminatingNUL. Conditional clearDF/intactviews/returninghelpers resume follows exactly the current consumed bytes. SetDF/helper mutation/nonreturn invalidates this path; not an unconditional return guarantee.");
			}
		}
		for (i = 0; i < R_ARRAY_SIZE (tlink51_error_ranges); i++) {
			char name[48];
			snprintf (name, sizeof (name), "tlink51_error_code_%x", (unsigned)(tlink51_error_ranges[i].physical - TLINK51_CODE));
			ut64 at = profile_mapped (ctx, tlink51_error_ranges[i].physical, 1, true);
			profile_label (ctx, at, name);
			borland_comment (ctx->anal, at, TLINK51_MARKER "R276 exact code-only partition; neighboring length-prefixed text is DATA. Multipleentry, consumed-return frame and conditional helper/request effects; no ordinary noreturn. Original NE1 offsets, FILE=1200+offset; partial/multi-entry partitions do not imply a containing function or stronger ABI.");
		}
		const ut16 entries[] = { 0xddfe, 0xde03, 0xde08 };
		for (i = 0; i < R_ARRAY_SIZE (entries); i++) {
			char name[48];
			snprintf (name, sizeof (name), "tlink51_error_entry_%x", entries[i]);
			profile_label (ctx, profile_mapped (ctx, TLINK51_CODE + entries[i], 1, true), name);
		}
		borland_comment (ctx->anal, profile_mapped (ctx, 0xf15a, 1, true), TLINK51_MARKER "R276 conditional rebuilt return; count freshly reread atBP+4, SP/AX=u16(BP+6+count), DX savedreturn. Kind4/helper/INT effects remain unresolved; not conventional argument cleanup or error-result preservation.");
	}
	ctx->continuations = NULL;
	ctx->continuation_count = 0;
	return applied? 3: 0;
}

static bool tlink51_far(BorlandProfileContext *ctx, ut64 physical, ut16 offset) {
	const BorlandProfileBinding fact = { 3, 0, 3, offset, TLINK51_SLOTS + offset, NULL, false, true, true };
	return profile_binding (ctx, physical, &fact);
}

static int tlink51_slots(BorlandProfileContext *ctx, bool types) {
	bool code[R_ARRAY_SIZE (tlink51_code_slots)] = {0};
	int count = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tlink51_code_slots); i++) {
		char name[48];
		snprintf (name, sizeof (name), "tlink51_stored_far_jump_%x", tlink51_code_slots[i]);
		ut64 physical = TLINK51_SLOTS + tlink51_code_slots[i];
		code[i] = profile_function (ctx, physical, 5, name, R_ANAL_CC_STACK_POP_UNKNOWN, TLINK51_MARKER "R175/R236/R256 actual selected caller target; complete storedEA+relocated4-byte target, initially commontrap3:0AFC. Conditional startup patch may change words, not leadingbyte; runtime callee/cleanup/preservation/service/selectorcodealias remain unknown.");
		count += code[i];
		if (code[i]) {
			tlink51_far (ctx, physical + 1, 0xafc);
		}
	}
	count += profile_function (ctx, TLINK51_SLOTS + 0xafc, 30, "tlink51_common_numeric_trap", R_ANAL_CC_STACK_POP_UNKNOWN, TLINK51_MARKER "R175/R236: complete30-byte/18-instruction trap with selector fixupsNE12/13, numericINT21 thenINT3/INT00 and possible plainLRET. NO six-byte argument cleanup or proved returning descriptor constructor/API/physical service.");
	if (profile_function (ctx, TLINK51_SLOTS + 0x469, 126, "tlink51_conditional_far_target_writer", R_ANAL_CC_STACK_POP_UNKNOWN, TLINK51_MARKER "R236: numericINT2F FB42 requests. Stores current returnedBX->ES:[DI+1], thenAX->[DI+3] only on returnedDX0. InitialCX from current0019 loaded once;04DE backedge04C3 does NOT reloadCX/ES/DI. Iteration savesAX/BX/DX only. Suitable unchanged progression covers105 positions, not105 returning calls; request3 hits000C only IF selectedES aliasescode. Final localLRET doesn't prove external service/argument contract.")) {
		count++;
		borland_comment (ctx->anal, profile_mapped (ctx, TLINK51_SLOTS + 0x4de, 1, true), TLINK51_MARKER "R236 actual04DE->04C3; noCXreload. Selected companion IRET restoresflags from interrupt frame, not necessarily localCF/CLD. Unknown callback/currentrecord/selector validity/codealias and failed-ordinal lookup may still reportDX0; service success/callable target is not established.");
	}
	int ea = 0, ff = 0, position;
	bool raw = types;
	for (position = 0; position < 105; position++) {
		ut64 physical = TLINK51_SLOTS + 2 + 5 * position;
		ut8 original;
		if (r_buf_read_at (ctx->file->buf, physical, &original, 1) != 1) {
			raw = false;
			continue;
		}
		ea += original == 0xea;
		ff += original == 0xff;
		bool executable = false;
		for (i = 0; i < R_ARRAY_SIZE (tlink51_code_slots); i++) {
			if (2 + 5 * position == tlink51_code_slots[i]) {
				executable = true;
				raw &= code[i];
			}
		}
		if (!executable) {
			bool data = types && profile_data (ctx, physical, 5, "tlink51_StoredFarSlot5");
			raw &= data;
			if (data && original == 0xea) {
				raw &= tlink51_far (ctx, physical + 1, 0xafc);
			}
		}
	}
	if (raw && ea == 97 && ff == 8 && profile_label (ctx, profile_mapped (ctx, TLINK51_SLOTS + 2, 525, false), "tlink51_stored_far_slots105")) {
		borland_comment (ctx->anal, profile_mapped (ctx, TLINK51_SLOTS + 2, 525, false), TLINK51_MARKER "R236:525 raw bytes/105 five-byte positions,97 EA stored FAR jumps and8 FF-leading nonjump positions; NOT105 executable stubs. Original applied relocations join97 target words to common3:0AFC trap. Conditional runtime writer changes target words only IF returnedES aliases code and services/currentregisters/saves qualify; native static relocation is not witnessed loadedpatch/service resolution.");
	}
	return count;
}

static int borland_tlink51_profile(RAnal *anal) {
	BorlandProfileContext ctx;
	if (borland_eligible (anal) < 0 || !tlink51_identity (anal, &ctx)) {
		return 0;
	}
	r_anal_types_prepare (anal);
	bool types = tlink51_types (anal);
	bool functions[R_ARRAY_SIZE (tlink51_functions)] = {0}, windows[R_ARRAY_SIZE (tlink51_windows)] = {0};
	int count = 0;
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (tlink51_functions); i++) {
		const Tlink51CodeFact *fact = &tlink51_functions[i];
		functions[i] = i? profile_function (&ctx, TLINK51_CODE + fact->start, fact->end - fact->start, fact->name, fact->purge, fact->comment)
			: borland_tlink_writer (&ctx, TLINK51_CODE + fact->start, fact->name, fact->comment);
		count += functions[i];
		R_LOG_INFO ("Borland tlink51-qualified: FILE 0x%08x %s", TLINK51_CODE + fact->start, functions[i]? "qualified (including unchanged)": "preserved/refused; dependent facts skipped");
	}
	for (i = 0; i < R_ARRAY_SIZE (tlink51_windows); i++) {
		const Tlink51CodeFact *fact = &tlink51_windows[i];
		windows[i] = profile_window (&ctx, TLINK51_CODE + fact->start, fact->end - fact->start, fact->name, fact->comment);
		if (windows[i]) {
			borland_comment (anal, profile_mapped (&ctx, TLINK51_CODE + fact->start, 1, true), "Original NE1 offsets, FILE=1200+offset; partial/multi-entry partitions do not imply a containing function or stronger ABI.");
		}
	}
	const struct { ut16 call; unsigned window; } writer_calls[] = { { 0x3d6e, 1 }, { 0x4302, 2 }, { 0x432c, 2 } };
	for (i = 0; i < R_ARRAY_SIZE (writer_calls); i++) {
		if (functions[0] && windows[writer_calls[i].window]) {
			profile_near (&ctx, TLINK51_CODE + writer_calls[i].call, 0x4e0b, false);
		}
	}
	int inline_count = tlink51_inline_apply (&ctx);
	count += inline_count;
	if (inline_count && windows[14]) {
		profile_near (&ctx, 0xbdc1, 0xeffe, false);
		profile_near (&ctx, 0xbde6, 0xeffe, false);
	}
	count += tlink51_slots (&ctx, types);
	const struct { ut16 at; unsigned owner; const char *comment; } annotations[] = {
		{ 0x3c2b, 0, "Descriptor20Partial representative+4 comparison uses currentBX, not descriptor_number+6. Dynamic arrays are not assigned static FileBytes storage." },
		{ 0x7f43, 3, "Descriptor20Partial+4=currentSI; separate7F4E word+6 receives incremented087B." },
		{ 0xd927, 13, "NameBoundRecord15Partial+2 receives saved Association12Partial offset; D92F then ASSIGNS flags20. Existing-record D961 replaces+2 only after currentflags10 test, then OR20/AND EF; separate name/record bank domains." },
		{ 0xbee7, 21, "R169 saves incomingAX, ordinaryC012..C01A restores it BEFORE consumerC051/C059. Diagnostic routes do not establish this preservation." },
		{ 0x4c46, 25, "Descriptor20Partial+0D read, then OLD+11 read at4C4A BEFORE increment4C4E. Fresh coordinate+08/+0A follows6D01; source/count05A8/05A6 freshly read later. Field views are not an immutable descriptor snapshot." },
		{ 0xbf4a, 21, "OutputSegmentRecord8: allocation+6 store08B1 precedes length+2 store08AD on this full-length branch. Other branches differ; sector+0 and current flags+4 are stored later. These are native working-buffer stores, not witnessed file bytes." },
		{ 0x871b, 23, "R181 post-first-copy currentDX:AX isQ; not the computed pre-copy position. Nb02InitialWorking16 and Nb02TerminalWorking8 are distinct views." }
	};
	for (i = 0; i < R_ARRAY_SIZE (annotations); i++) {
		if (types && functions[annotations[i].owner]) {
			borland_comment (anal, profile_mapped (&ctx, TLINK51_CODE + annotations[i].at, 1, true), annotations[i].comment);
		}
	}
	if (functions[0] && types) {
		borland_comment (anal, profile_mapped (&ctx, 0x4e0b, 1, true), "TLINK51 partial descriptive type views: unknown bytes remain undefined; current DS/ES/SS views, valid extents, lifetime and non-destructive aliases are prerequisites, not inferred file mappings or historical C. SegmentInfo10Partial I is current09B8-selected, distinct from R09C0 and D09D8; module coordinate06D8+10*(index-1), interned full length/name comparison (not hash alone), class05F6/@OVYDATA, SEGDEF length_low plus separate extension8/attributes9 alignmentE0/combine1C, not unrestricted32-bit length. R offsets match I, not descriptor numbers; descriptor_offset is first writer read, group/absolute alternatives differ; family_entry_offset=7D2D currentSI or7D62 rememberedCX, read40DF. Descriptor20Partial association+2 constructor81E0; kind1/3 writer versus4/signed<=0 output tests; representative+4 distinct from counter+6 and physicalCS. coordinate_extension ADC CL/DL discards byte overflow; length+0D is not paired with+0F as a high length;+13 output bits0..5 read separately. Association12Partial six-word source089F is currentDF, not atomic/overlap-safe; name_handle+8 current08A7 uses bank08D8 low3 bits while retaining full offset. NameBoundRecord15Partial bank0938: new link0, consumer rejectsFFFF; allocator decrements words08/0a; name+0C currentBX later028A; flags10/20 independent, not exclusive tags. VectorDescriptor8Partial paired0A64/0A6C capacity finiteFF80, consumer7FC0 words; LES+2 cursor/selector, external allocation/write/extent unresolved; boundary+6 initially0A64 and advancement can store0A6C in0A6A, not append-slot/module identity. FixupWorking8 currentDS08B3: adjusted_coordinate=u16(DI+fresh058E), target_word currentBX atB9AB, target_quantity currentCX atB9AF; no initializer/copier lifetime. OutputHeader64Partial workingDS085F notFILE10C0, not all initialized; signature454E, fields02=05/03=0A, +22=0040 thenC02F addsB7A2, field36=D976 returnedAL; equal+24/+26 not resource ownership/absence. OutputSegmentRecord8 nominal geometry only: sector canzero, raw_length zero/full/clipped not65536 processed-byte proof, flags current signed-kind/bit tests, raw_allocation saved+0D. Nb02InitialWorking16 DS08BB signature424E/3230 and sixFFFF words conditionalclearDF, not debug importer. Distinct terminalDS08CB copy8 atW not physicalEOF; finite_distance=u32(W-Q+18h), Q saved after optionalfirstcopy. MiddleWorkingRecordPartial DS0686 fixedview30, actual count=u16(30+current06B4); word52FB, version0310 or018F1->0209, position actualsavedpostcopyQ+selectedadjustment, freshcontrol0182. MaskedLocationClass=DH&1C:04/14 share source_type5, only04 setsflag04; not exclusive descriptor/record tags or formalOMF identity.");
	}
	if (profile_data_array (&ctx, 0x4f08, "uint16_t", 8) && profile_label (&ctx, profile_mapped (&ctx, 0x4f08, 16, false), "tlink51_location_dispatch_words8")) {
		for (i = 0; i < 8; i++) {
			ut8 word[2];
			if (r_buf_read_at (ctx.file->buf, 0x4f08 + 2 * i, word, 2) == 2) {
				ut16 target = r_read_le16 (word);
				profile_offset (&ctx, 0x4f08 + 2 * i, target, TLINK51_CODE + target);
			}
		}
	}
	if (profile_data_array (&ctx, 0x1ba1, "uint8_t", 128) && profile_label (&ctx, profile_mapped (&ctx, 0x1ba1, 128, false), "tlink51_ascii_option_classes128")) {
		borland_comment (anal, profile_mapped (&ctx, 0x1ba1, 128, false), "R126 ASCII table128, no high-bit index guard. f/F class2, +/-class1; table classification is distinct from raw-letter dispatch. Adjacent0A21..0A2B literal tlink.cfg includesNUL.");
	}
	if (profile_data_array (&ctx, 0x1c21, "char", 10)) {
		profile_label (&ctx, profile_mapped (&ctx, 0x1c21, 10, false), "tlink51_config_candidate_name");
	}
	if (windows[14]) {
		profile_label (&ctx, profile_mapped (&ctx, 0xbdd3, 1, true), "tlink51_numeric_count_checked_entry");
	}
	const struct { ut16 at; ut16 target; unsigned owner; bool window; } far_calls[] = {
		{ 0x665b, 0xc, 14, false }, { 0x9cf3, 0xe3, 28, false }, { 0x9d00, 0xed, 28, false }, { 0x9d70, 0xbb, 12, true }, { 0x9da3, 0xc, 12, true }, { 0x9c22, 0xbb, 13, true }, { 0x9c3d, 0xbb, 13, true }, { 0x9c67, 0x1ce, 13, true }, { 0x9c78, 0xbb, 13, true }, { 0x9c94, 0x16, 13, true }, { 0x9ca8, 0x16, 13, true }
	};
	for (i = 0; i < R_ARRAY_SIZE (far_calls); i++) {
		if (far_calls[i].window? windows[far_calls[i].owner]: functions[far_calls[i].owner]) {
			tlink51_far (&ctx, TLINK51_CODE + far_calls[i].at + 1, far_calls[i].target);
		}
	}
	if (functions[31]) {
		BorlandProfileBinding message = { 2, 4, 4, 0xa6f, 0x1326f, NULL, false, true, false };
		ut64 table = profile_mapped (&ctx, 0x1326f, 1, false);
		if (profile_binding (&ctx, 0xefe2, &message) && table != UT64_MAX) {
			profile_reference (anal, profile_mapped (&ctx, 0xefe5, 1, true), table, R_ANAL_REF_TYPE_DATA);
		}
	}
	if (profile_data_array (&ctx, 0x128ab, "char", 24) && profile_data (&ctx, 0x1327d, 2, "uint16_t")) {
		profile_offset (&ctx, 0x1327d, 0xab, 0x128ab);
	}
	if (profile_data_array (&ctx, 0x128d2, "char", 18) && profile_data (&ctx, 0x13281, 2, "uint16_t")) {
		profile_offset (&ctx, 0x13281, 0xd2, 0x128d2);
	}
	return count;
}

#undef TLINK51_MARKER
#undef TLINK51_CODE
#undef TLINK51_SLOTS
