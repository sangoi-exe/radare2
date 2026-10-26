# Native fixed-input byte slices: causal record

## Authority and baseline

The [Intent Contract](../planning/2026-10-26-native-fixed-input-slices.md) owns the correction. User confirmation is current-thread source29582, turn01a17938-2faa-7ee2-9057-905432a6fa6f, 2026-10-26T14:18:07.991-03:00 (America/Sao_Paulo), following paraphrase29575. The later source29635 acceptance at14:25:09.355-03:00 authorizes a separate read-only model-hole investigation, not model-hole implementation. Source29614 asked about parallel work. The exact rollout locator is in the plan.

Native12f04ca6d23c4bb7e8f180ab4cf0ca913676e244, bridgebe7b512342baa9b7748fe3be93abbb78fe730098 and host2159ca64a968fcb26c225a2332329d6b769c2802 are the intake baselines. The preceding push verified all three remote master tips. Tracked trees were clean; pre-existing .refs/ remains excluded.

P=/home/lucas/.cache/codex/radare2/native-fixed-input-slices-2026-10-26. P/sources/review-inputs retains the corrected Sol/Astra TXT files and the R4 ZIP, compared byte-for-byte with the supplied Downloads files. The initial TXT files were identical; the user corrected them before substantive triage concluded. Current Sol is10842 bytes, Astra13434 bytes; both were read completely. The32-member ZIP was inventoried and the relevant metadata, source excerpts, fixtures, proposed regressions and result records were inspected in memory. No supplied executable or reproduce script was run.

## S1 — interior fixed parameter receives the low bytes again

### Observed and expected behavior

The exact136-byte packed32 fixtures have caller31/direct CALL1016 or caller33/indirect CALL101b, callee1040/body12 and eight bytes at1080 containing DWORDs1 and7. The supplied variadic prototype has two fixed unsigned-int parameters. The direct path uses separate four-byte LOADs for the fixed argument locations. The normal indirect path prints packed_target(Var1,Var1); its native XML CALL101b→ram1040 uses the same four-byte Varnode0xa0 twice. That Varnode is defined by SUBPIECE(source8,0), with source8 copied from ram1080. Expected: the second parameter consumes the distinct interior four-byte source range, not the first parameter's bytes again.

The older qualified a449642 runtime produces the same wrong indirect C/XML. The current indirect retained-code path instead reanalyzes to separate four-byte LOADs. No CPU execution or observed107 return is claimed;107/101 in the supplied report are arithmetic predictions from fixture bytes, not our runtime oracle.

P/evidence/intake/production-observations.json retains all16 admitted actual C/XML process records, exact commands, zero statuses and empty stderr. The first four records retain full stdout; the remaining twelve retain C or the complete relevant argument-definition graph parsed from the full XML in memory. The frozen current launcher is /home/lucas/.cache/codex/radare2/native-late-variadic-state-2026-10-26/runtime/integration/r2-exact; the exact older launcher is /home/lucas/.cache/codex/radare2/native-variadic-mapping-2026-10-26/runtime/integration/r2-exact. Both select their matching plugin/languages and the frozen W35 SDK.

### Diagnosis and selected correction

Root and /root/r4_packed_slice_investigation inspected the actual composed source, N=/home/lucas/.cache/codex/radare2/native-late-variadic-state-2026-10-26/build/integration/source/subprojects/ghidra-native. transferLockedInputParam atfspec.cc5350–5363 accepts contained storage but returns only a slot. transferLockedInput at5419–5422 carries only its Varnode. commitNewInputs clears trials at5481 before buildParam at5327–5336 uses SUBPIECE offset0 for every smaller parameter. The three relevant helper bodies match the imported a449642 baseline; the supplied transcriptions match the prepared methods after ignoring comments/spacing. The actual wrong endpoint is reproduced, while the precise pre-/post-deindirection trial and restart state is not yet directly observed.

Selected direction: materialize the fixed inputs against their still-live selected source trials, compute the justified byte displacement through the existing Address::justifiedContain helper (address.cc131–141), and then perform the existing fixed-trial/placeholder/tail reconstruction. This keeps the public restriction facade and avoids new persistent/parallel transfer state. Private helper details remain local implementation choices under that operation order. Do not derive source storage from the representative's constant, unique or memory-value address. The first native regression must observe the internal causal premise rather than merely repeat the C endpoint.

Falsifier: an internal trace showing another producer created the wrong shared slice would change the execution's causal attribution, but would not erase the independently observed wrong CALL inputs. No correction is implemented yet and no new suite has run for this lot.

### Actual validation state and failed attempts

Read-only intake produced16 admitted successful C/XML observations: current direct and indirect two-fixed normal, current indirect two-fixed retained, older indirect two-fixed normal, and current one-fixed direct/indirect in both modes, each through C and native XML. These are actual plugin executions, not the package's synthetic probes or a new native test build.

One extra retained-mode capture exceeded the command output limit. The subsequent JSON envelope parse failed before a usable result record was retained; that attempt is not admitted as proof. The bounded retry parsed complete XML in memory and emitted only the relevant CALL/definition graph. No source or EXPECT changed. The plugin has debug information, but gdb was not found by current command lookup; no debugger was installed. Existing native action breakpoints will supply the first-slice observation.

## Associated partial-overlap observation

With only the first parameter fixed, both direct and indirect paths in normal and retained modes emit only that first argument and no incomplete-recovery warning. That endpoint is not exclusive to the changed retention loop. Source confirms commitNewInputs discards the whole old trial on fixed-prefix overlap; recoverCallRelativeInputs also skips the same full-width STORE before its uncertainty branch when any trial overlaps. This does not independently prove what residual argument evidence the product must recover.

Disposition: separately qualified observation, not an admitted second correction. Do not restore a whole overlapping trial or infer every remaining byte as a variadic argument. A future correction needs established residual storage/position evidence and a current-user Scope decision.

## Model-hole status and parallel investigation

The earlier fabricated-argument/erased-warning allegation is refuted for the stated standard x86-32 subcall case, and Sol now formally withdraws it. The exact saved-frame witness still has no CALL argument inputs and retains the stack[0x4:4] warning. Positive later stack+8 use is not associated with the CALL; the STORE of7 remains visible in C/XML. That omission has not been corrected or globally qualified.

The user accepted investigating that omission in parallel while the fixed-slice implementation proceeds. /root/r4_model_hole_investigation reads only the frozen12f04ca/be7b512 source and existing actual captures. It must distinguish value storage, argument position and source-signature knowledge; printing callee(7) is not accepted automatically if that moves the value into the first ABI slot. The lane returns diagnosis and material options, not edits. Its findings will be retained here without silently widening the slicing contract.

### Completed M1 diagnosis and verified limits

The investigator completed the five-question source/representation investigation with full declared coverage and no writes or new execution. Root independently decoded the retained XML: a live STORE at0x1010 contains constant7:4 (ref0x92), while CALL1018→1040 has only its destination input. The C still contains the STORE of7. The lost information is the explicit CALL-input association, not removal of that value from the entire output.

The frozen source explains the omission: recoverCallRelativeInputs admits the non-competing stack+8 STORE as active/checked. The callee snapshot lookup occurs only inside the competing-read branch and therefore decides the ambiguous stack+4 cell; no distinct positive-callee-use constraint reaches forceInactiveChain. The standard subcall model fills a missing first stack resource with an unref hole, deactivates the hole and later trial, and finalization skips both before replacing the CALL inputs. The earlier false-argument/erased-warning claim remains refuted. This source chain agrees with the real endpoint; it is not a newly executed intermediate trace.

Root verified the direct positional consumers in N: ParamActive::deleteUnusedTrials (fspec.cc2012–2029) renumbers surviving CALL inputs densely; PrintC::opCall (printc.cc661–702) prints those operands consecutively; TypeOpCall::getInputLocal (typeop.cc742–772) consults getParam(slot-1). fixedPosition only orders supplied fixed arguments. An unref trial, if selected, creates a real input/load and resolves covered uncertainty; it is not a marker that the source-argument role is unknown. A four-byte storage slot atstack+8 does not itself establish source parameter index1 because one source parameter may consume multiple model resource slots.

Disposition: a real, unresolved recovery limitation, not a demonstrated violation of a current sparse-input contract. No such carrier/guarantee was found in the inspected owner chain. That classification does not qualify the output for global byte-identical reconstruction or make the omission acceptable as a universal result. Retaining only7 as formal operand0 or manufacturing an ordinary first argument would substitute a different unsupported claim for the missing association.

Full recovery requires an explicit native representation for known storage/value atstack+8, unresolved role atstack+4 and unknown source arity, consumed consistently by C/XML/type paths. The investigator found no inherent need for a new host-persisted signature or global knowledge owner, but no existing representation selects that outcome automatically. A separately evidenced weaker option is a more specific warning through existing native disclosure; it would not restore the CALL dataflow association and is not selected as the fix. Root has not selected a representation or authorized either implementation.

There is no functional dependency on the fixed-slice path for this open-signature witness. Any later implementation still must serialize with slicing because patch0400, testsegmented.cc, tests/README.md and the single bridge engine pin are shared physical owners. The frozen-source investigation therefore ran safely in parallel; two moving patch writers would not. Reopening requires the user's selected recovery/disclosure result and representation, then the same72-byte witness with storage position, unresolved-role and C/XML checks. M1 is complete; model-hole remediation remains a separate future decision, not a blocker or hidden addition to S1.

## Review-claim disposition

Sol maintains PROCEED_WITH_NITS for the preceding delta and recommends a future explicit re-registration operation; this does not establish the R4 slice correction. The current upstream Ghidra source inspected on2026-10-26 has reregisterTrial/reset derived metadata but still uses zero-offset buildParam slicing. The official SUBPIECE reference defines its least-significant-byte truncation. These sources support interpretation, not a wholesale-upgrade route: https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Features/Decompiler/src/decompile/cpp/fspec.cc ; https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Features/Decompiler/src/decompile/cpp/fspec.hh ; https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html . Master references are dated observations, not immutable snapshots.

Astra's slicing claim is now supported by actual production output, beyond its explicit synthetic-method proof. Its conditional partial-overlap observation remains separate. Neither report reopens the closed mixed-order or non-overlapping-tail correction; no rollback or speculative derived-metadata cleanup is selected.

## Current execution state

The user confirmed the fixed-slice correction and separate read-only model-hole investigation. Root established the current owner, existing endian-aware helper, prior runtime comparison and directly observable acceptance. /root/r4_plan returned PROCEED after complete primary-path Intent Contract coverage and direct source, authority and16-record evidence checks. Root applied the registered transition to active Implementation, published the execution locator and dispatched S1 to /root/r4_slice_worker. The classifier remains Doctrine; no material user decision blocks the correction. M1's read-only investigation is complete and integrated above as a separate observation, not a changed implementation Scope.
