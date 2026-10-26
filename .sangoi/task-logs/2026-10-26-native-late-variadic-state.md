# Late variadic input-state correction and review-claim evidence

## Authority and baseline

The [Intent Contract](../planning/2026-10-26-native-late-variadic-state.md) owns this lot. Current-user correction confirmation is source28368, turn01a17868-d66b-75e1-80f1-2e57b5a3f131, 2026-10-26T10:31:39.588-03:00 (America/Sao_Paulo), after paraphrase28361. Source28230 separately requests detailed refutation records that later Pro reviewers can discover. Source references are in thread01a16717-0b9b-7e10-9f98-d4203ccbfde6.

Initial native/bridge/host heads are a4496420247fcd192cf65272825bf46564f04734,6cf63f2ad62c1f32a47f64cb3ac79c63886be6c8 and959730398f9f8065597e5353880180dd2c8092c2. The preceding requested push verified all three remote master tips. At this new intake all tracked states are clean and pre-existing `.refs/` is excluded.

Supplied reports are `/mnt/c/Users/lucas/Downloads/sol56pro-new-audit-261026-093730.txt`, `astra6pro-new-audit-261026-094452.txt` and `native-adversarial-review-2026-10-26-r3.zip`. The ZIP has39 members. Root read the reports completely and the relevant metadata, fixture, proposed test and result members in memory; no supplied script or executable was run. The probes use explicit collaborators and do not execute the full native pipeline. The report's separate Linux fixture result1143 is its reported observation, not our decompiler or CPU replay.

## Actual production reproduction

The commands below use the already-qualified runtime at nativea449642, not a new build. `R2` names `/home/lucas/.cache/codex/radare2/native-variadic-mapping-2026-10-26/runtime/integration/r2-exact`. That launcher explicitly selects the frozen W35 host SDK, current plugin and matching languages. `N` below names its matching composed native source at `/home/lucas/.cache/codex/radare2/native-variadic-mapping-2026-10-26/build/integration/source/subprojects/ghidra-native`. The canonical change owner remains the native patch stack, not N.

The direct fixture is the exact79-byte ZIP member `native-review-2026-10-26-r3/mixed_prefix64.bin`, directly compared with its .hex member:

```text
554889e54883ec10bf0b000000be2100000048b8000000000000f43f66480f6ec0b801000000e815000000c9c3000000000000000000000000000000000000006bc764f20f2cd06bd20a01d001f0c3
```

The indirect variant preserves the register assignments, AL value and callee bytes/address. At original offset0x26, it replaces the five-byte direct call plus LEAVE/RET with `mov r11d,0x1040; call r11; leave; ret`, consumes four padding bytes and keeps the total79 bytes. The caller becomes49 bytes; CALL moves to0x102c, while the15-byte callee stays at0x1040:

```text
554889e54883ec10bf0b000000be2100000048b8000000000000f43f66480f6ec0b80100000041bb4010000041ffd3c9c30000000000000000000000000000006bc764f20f2cd06bd20a01d001f0c3
```

For the command below, set DIRECT_HEX to the complete direct literal above and R2 to the qualified launcher path given in this section. Exact command form for the direct control:

```sh
"$R2" -q -a x86 -b 64 -m 0x1000 -e scr.color=0 -e log.level=0 -c 'af+ 0x1000 mixed_caller;afb+ 0x1000 0x1000 45;af+ 0x1040 mixed_target;afb+ 0x1040 0x1040 15;e r2ghidra.lang=x86:LE:64:default:gcc;e r2ghidra.deadcode=false;td int mixed_target(int tag, double amount, ...);pdg @ 0x1000' "hex://$DIRECT_HEX"
```

For the indirect variant, use the exact indirect hex above and change only the caller size to49. To inspect the native CALL, replace `pdg` with `pdgx`. The retained comparison changes only `e r2ghidra.deadcode=false` to `true`. No `aaa`, exact-PC calllink or explicit host-xref insertion was supplied. Empty `axj` output was not used as independent absence proof.

| Actual input/mode | CALL PC | Ordered native argument identities and widths | Actual C call |
| --- | --- | --- | --- |
| Direct, normal | 0x1026 | 11:4,0x3ff4000000000000:8,33:8 | `mixed_target(0xb,1.25,0x21)` |
| Indirect, normal | 0x102c | 0x3ff4000000000000:8,11:4; no33 | `mixed_target(0x3ff4000000000000,0xb)` |
| Indirect, retained | 0x102c | 11:4,0x3ff4000000000000:8,33:8 | `mixed_target(0xb,1.25,0x21)` |

Every final native CALL targets ram0x1040. The floating value is identified by its eight-byte bits, not by reinterpreting the incorrect C expression as a valid argument. Both C and XML were executed independently for each row; all processes exited0 with empty stderr. There was no incomplete-input warning on the wrong indirect result.

Root repeated the indirect normal C/XML commands with the older qualified `/home/lucas/.cache/codex/radare2/native-pro-followup-consumers-2026-10-24/runtime/w52-map-bridge/r2-exact` at native7a5505b. Both returned the same wrong two arguments, exit0 and empty stderr. The observed defect is inherited; the preceding guard/placeholder/capacity fixes are not rolled back.

## L1 — declared fixed-prefix order lost

Observed: the indirect late result reverses the fixed integer and floating-point inputs while the explicit prototype keeps tag before amount. Expected: the declared fixed prefix remains11 then1.25 regardless of the point at which the compatible prototype becomes known.

Confirmed cause: late commitNewInputs clears activeinput and reconstructs fixed trials without setFixedPosition. Early ActionFuncLink sets the position for each fixed variadic trial. The actual x86-64 GCC model allocates XMM before GPR resource groups; actual ParamListStandard selection preserves both active/checked fixed trials, then fixedPositionCompare falls back to that resource order when both positions are-1. Materialization consumes that wrong order while positional type/printing consumers still use the declared prototype.

Relevant current composed anchors: N/src/decompiler/fspec.cc5462–5508,1921–1933,850–937,1286–1313,6028–6055; coreaction.cc1632–1637 and1923–1929. The initial constant-register CALLIND can reach ActionDeindirect before input recovery finalizes; compatibility admits unknown-to-variadic in-place specialization. This causal path was inspected, not single-stepped; the final product error was actually executed above.

Selected direction: restore fixed-position metadata in declaration order at the same late producer. No comparator, cspec or global mode change. R1 implemented this correction in canonical patch0400. Root integrated source/test commit b519ae3ea6c66e806a215cec7559d22aad2645d2 and documentation commit 12f04ca6d23c4bb7e8f180ab4cf0ca913676e244 after native validation. Matching bridge be7b512 is qualified below; Code review remains pending.

R1's fresh baseline-plus-tests now executes the natural indirect path through native action breakpoints. Before deindirect, the call is CALLIND at 0x102c with unknown entry, active recovery and no override. Immediately after deindirect, the same call specification and operation are a direct CALL with the supplied locked variadic prototype and active recovery; `hasRestartPending` is false. The order regression then fails on the first fixed value: 4608308318706860032 (0x3ff4000000000000) instead of 11. The early control passes. Root read the test and raw `evidence/native/red-focused.log` under the current task cache. This is actual in-place late-path evidence, not merely the earlier causal source inspection.

The first selected correction passes all three focused tests in the fresh green build (`evidence/native/green-focused.log`, exit 0). Root inspected the full canonical patch delta, the resulting commitNewInputs owner, whichTrial semantics and the new test assertions. Fixed positions now preserve the declared 11:4 then double-bits:8 prefix without changing the comparator or restarting the late path. At this focused checkpoint, full native/preparation qualification and bridge observation had not yet run; later results are recorded below.

## L2 — existing register tail discarded

Observed:33 exists in the direct control and after retained clear/reanalysis, but is absent from the normal late CALL. Expected: a variadic prefix does not close or silently discard the already-discovered non-fixed input state.

Confirmed source mechanism: transferLockedInput gathers only the fixed inputs; commitNewInputs clears all existing trials and replaces the CALL operand vector with the new prefix plus any dedicated placeholder. Ordinary register heritage need not revisit those ranges, and0400's additional recovery is stack-relative, not a reconstruction of discarded register trials. Current anchors are N/src/decompiler/fspec.cc5412–5431,5462–5508 and heritage.cc1263–1268,2707,2786–2797.

Selected direction: before destructive reconstruction, preserve existing candidate trials by value; rebuild fixed inputs with their positions; retain only non-overlapping non-fixed candidates with original values and facts; reindex through existing slot/placeholder APIs before replacing the CALL inputs. Keep the current pass/final-check lifecycle and ordinary model selection. Do not promote every saved candidate to active or invent new tail values. Completed API recon and root direct reads establish value-copy semantics, stable borrowed model-entry ownership, fresh entry binding during normal derivation, and slot/placeholder accounting. The Microtask Program froze registration/copy/setSlot reconstruction, existing overlap semantics and preservation of the current pass policy before dispatch. No generic transfer helper or new state owner is selected. Canonical patch0400 implements this sequence, restricting exclusion to overlaps with authoritative fixed trials. Root integrated the same source/documentation commits as L1 after native validation; matching bridge be7b512 is qualified below and Code review remains pending.

The independent late-tail regression reaches the same verified in-place path and fails because no constant 33 with size 8 remains among the CALL inputs. It checks presence before the fixed-order assertions, so the order failure cannot mask this separate consequence. Together with the early control, the selected red result is 1/3, driver exit 2, at `evidence/native/red-focused.log`. This valid red preceded the producer correction.

The first green retains 33:8 after the fixed prefix and after explicit clear/reanalysis. Additional transition assertions observe that the original candidates have CALL representatives, a wider original tag-register trial is consumed by the narrower fixed parameter without duplication, and retained non-prefix values and exposed trial facts survive reconstruction. The green test includes those extra assertions; its test bytes are not identical to the earlier red test. These assertions do not inject or select trials. Root verified the production delta uses value copies, restricts exclusion to fixed-prefix overlaps and reconnects original values before replacing CALL inputs. The existing pass, placeholder and nonvariadic policies remain unchanged. This focused checkpoint did not itself establish broader suite/integration results; later results are recorded below.

## Corrected test premise

The supplied `native_order_regression.cc.txt` was not compiled or run. Its fixture bytes and independent internal prototype premise are valid, but its exact tail-width4 assertion is not established: the actual direct production control yields an eight-byte constant33. That is an analysis representation observation, not a claim that the source variadic argument has an eight-byte C type.

The isolated order probe manually re-adds and selects tail trials after commitNewInputs. The real producer does not do that. Therefore its8/8 candidate result after adding setFixedPosition proves the isolated ordering correction, not preservation of the real register tail. A native regression must expose the fixed identities and missing tail separately rather than treating an unsupported count/width premise as the ordering proof.

## Refuted model-hole claim

**Disposition: the supplied standard-stack counterexample's claimed fabricated-argument/erased-warning chain is refuted, not merely deferred by Scope.** The narrower inability to recover a later argument after a hole is a different, explicitly excluded limitation.

### Allegation and missing causal step

Sol repeats that a caller's unresolved stack+4 is filled as an unref trial, materialized as a concrete argument and removed from unresolvedInputStorages when only stack+8 was observed in the callee. That description omits the subcall selection step between hole creation and final materialization.

FuncCallSpecs constructs `activeinput(true)` (N/src/decompiler/fspec.cc5236). Function-input recovery uses `ParamActive(false)` (coreaction.cc5006). These are not interchangeable uses of the model. During subcall recovery, forceInactiveChain recognizes an unref stack trial as an inactive-chain boundary (fspec.cc1112–1151). The hole and following trial become inactive; fillinMap marks only remaining active trials used (1303–1313). buildInputFromTrials skips unused trials before either materialization or resolveInputStorage (6034–6036). A producer-only function-input model-hole test cannot establish that the caller reaches the later unconditional resolution call.

Root compared the complete prepared fspec.cc files from the earlier7a5505b runtime and the currenta449642 runtime. The only differences are the admitted recovery guard and dedicated-placeholder condition. This subcall hole-selection chain is unchanged.

### Exact counterexample and actual output

The following72 bytes implement the claimed roles: the caller stores its saved frame value at pre-CALL ESP, stores7 at pre-CALL ESP+4, calls a callee that reads entry-stack+8, then reloads the saved frame cell. With the ordinary four-byte near return address, those caller cells are call-relative stack+4 and stack+8. The bytes derive from the previous supplied72-byte fixture by replacing offsets9..15 with `89 2c 24 90 90 90 90` and offsets29..32 with `8b 6c 24 00`; caller/callee addresses and total length remain unchanged.

```text
5589e583e4f083ec10892c2490909090c744240407000000e8230000008b6c240089ec5dc30000000000000000000000000000000000000000000000000000008b44240883c003c3
```

Set MODEL_HOLE_HEX to the complete72-byte literal above and keep R2 at the qualified current launcher. Exact current-runtime command:

```sh
"$R2" -q -a x86 -b 32 -m 0x1000 -e scr.color=0 -e log.level=0 -c 'af+ 0x1000 saved_frame_caller;afb+ 0x1000 0x1000 37;af+ 0x1040 stack_argument_consumer;afb+ 0x1040 0x1040 8;e r2ghidra.lang=x86:LE:32:default:gcc;e r2ghidra.deadcode=false;pdg @ 0x1000' "hex://$MODEL_HOLE_HEX"
```

Actual relevant C:

```c
//WARNING: Incomplete call input recovery: unresolved call-relative storage stack[0x4:4]
stack_argument_consumer();
```

A separate `pdgx` run confirms CALL0x1018→ram0x1040 with no argument inputs and warning tokens naming stack[0x4:4] at the call. Both processes exit0 with empty stderr. This directly contradicts the alleged concrete saved-frame argument and erased warning. The later7 is also omitted; this observation does not claim complete argument recovery.

### Limits and reopening condition

This refutation covers the stated standard x86-32 GCC subcall scenario, not every possible model or unref materialization. Reopen it only with new evidence of an actual subcall path where the relevant unref trial remains selected/used, reaches materialization/resolution and removes that unresolved cell without an authoritative supplied contract. A differently configured model or caller needs its own complete path and actual output. Repeating the skipped-step argument or quoting the Scope exclusion is not such evidence.

The earlier short disposition is in [the preceding task log](2026-10-26-native-variadic-mapping.md#disposition-of-the-other-supplied-claims). The current record adds the explicit mode distinction, source steps, bytes, command, observed C/XML and falsifier requested by the user.

The corrected native 12f04ca / bridge be7b512 candidate repeats the same exact 72-byte C/XML commands through its own qualified launcher at the current task cache's runtime/integration/r2-exact. Raw `evidence/integration/17-model-hole-{pdg,pdgx}.*` contains the same no-argument CALL1018→1040 and CALL-PC stack[0x4:4] warning. Root independently verified both exact fixtures/commands, exit0, empty stderr, the XML input list and warning tokens. The later7 remains omitted. The refutation therefore applies to this integrated candidate as well as the preceding runtime, within the unchanged stated limits.

## R2 integration observations

The fresh private bridge selects native 12f04ca6d23c4bb7e8f180ab4cf0ca913676e244 with the frozen W35 host SDK. Its first twelve actual C/JSON/XML captures reproduce both exact 79-byte inputs in normal and retained modes. Root inspected every command, input, exit status and stderr, confirmed that JSON code equals C, and dereferenced the actual native CALL operands. All four CALL graphs have target ram0x1040 and ordered inputs 11:4, 0x3ff4000000000000:8 and 33:8; the direct PC is0x1026 and indirect PC is0x102c. No incomplete-input warning appears. Every process exits0 with empty stderr. Raw captures are `evidence/integration/05-mixed-{direct,indirect}-{false,true}-{pdg,pdgj,pdgx}.*`; root's result is `evidence/integration/root-primary-inspection.txt` under the current task cache. This is inspection of actual new captures, not a claim of twelve root re-executions.

Root's first XML extraction mistakenly counted a non-void operation output as a CALL input in retained mode. It failed before writing a success record. Reading actual XML and PcodeOp::encode established the existing order: seqnum, output/void, then inputs. The corrected bounded extraction passed all four graphs. A guessed encodeRaw symbol lookup returned no match before the actual encode owner was read. These are proof-extraction errors, not product defects or changes to expected arguments.

Combined Meson3/3, native161/161, preparation10/10 and pcode XML pass, with matching extra-language build/reuse complete. Root read the new combined-suite results. An exploratory r2 XML grep containing literal `>` was interpreted as command redirection/filter syntax and emitted full XML; that output is not admitted as a filtered-test result. R2 retained the attempt and used ordinary token text for the direct regression without changing semantic expectations. The admitted observations and new tests preserve the supplied host prototype fields and show no calllink before or after normal/retained queries.

The first r2r runner invocations exited127 before any tests because the runner itself lacked the private SDK LD_LIBRARY_PATH; both stderr streams identify missing libr_cons.so. The child r2 launcher already selected that SDK, but its environment does not configure the parent runner. R2 retained those attempts and repeated the same suites with the runner's library path explicitly set. This is an infrastructure failure, not a semantic regression or an EXPECT correction. The corrected runs pass pcode17/17, types80/80 and resolution41/41. The established formatter frontier is10/12: the PPC global-name difference and varargs-off missing-call difference each match the preceding integrated baseline after ANSI removal. Neither historical failure is a pass or an edited EXPECT. Root read all runner result records: no skipped case or timeout, with only those two semantic failures.

Fresh retained comparisons preserve exact-PC2/2/5/refusal, F11 CALL1/1/2/1 and effective AND, the six prior variadic available/absent/bodyless mode graphs and C/JSON, and both streams of the NE refusal/continuation control. Their actual commands/results and bounded comparison are retained in `evidence/integration/13-*` through `18-semantic-and-historical-comparisons.txt`. The compared referenced AST/CFG does not normalize semantic values; unreferenced serialized Varnodes are outside that comparison. Native F12 and fixed/model-only/placeholder/mapping controls also pass in the combined suite. This is not new Windows/CPU execution.

Root read `19-source-runtime-correspondence.txt` and the complete Worker handoff at `21-handoff.md`. The compared canonical/private bridge files, all 48 applied patches, 87 non-imported native inputs, prepared-source identities, built/runtime plugin and 163 selected runtime language files (26 SLA) agree; explicit SDK linkage has no missing dependencies. An initial Worker correspondence command included the empty terminator of a NUL-separated Git list and failed before producing its report; the corrected enumeration excluded that terminator. Root initially looked for the wrong correspondence filename and incorrectly treated multi-command status files as one scalar status; the corrected reads account for 65 status files and 74 command statuses. The only nonzero command statuses are the two pre-test runner failures and the disclosed historical formatter run. These errors did not alter source, expectations or semantic results.

Root inspected the complete final bridge diff and staged patch, confirmed unchanged existing test bodies and expectations, and committed only the pin and two direct regressions as be7b512342baa9b7748fe3be93abbb78fe730098. R1/R2 are complete. The candidate remains fixed for the selected local Code review; implementation is not yet Gate-approved.

## Selected Code review procedure

The registered route is Senior Code Reviewer / Task change-set review, Doctrine, Implementation, amendment transition not-applicable. Root selected narrow crossed review: one Senior/Claude pair reviews the complete candidate, then exchanges actual findings before root analysis and the Senior's final cumulative disposition. The substantive complexity is one native in-place trial/operand reconstruction owner; the bridge has only its exact pin and direct test followers, and host changes are task evidence. No independent bridge algorithm or second architecture domain changed. This supports one pair with no separate source/integration tier, while the nontrivial trial/placeholder/pass semantics justify independent crossed assessment rather than a single reviewer.

The pair's required surfaces are the complete native patch delta and direct trial/placeholder consumers, its test documentation, bridge pin/production tests and matching runtime seam, and the four host task records including the detailed refutation. Root assigns all of these to /root/r3_code_senior and /root/r3_code_claude; no required surface is assigned elsewhere or excluded by file count. Review has not started at this checkpoint. Both initial reports receive equivalent evidence without the partner's opinion; every Claude invocation remains serialized. No source remediation is authorized while the fixed review is open.

## Current execution state

The user confirmed the new correction lot and the documentation requirement. Root completed read-only production/source triage, including the old-runtime comparison and current model-hole replay. Ten C/XML processes exited0; no supplied scripts, new native build, guest or repository edits were part of that triage. /root/r3_plan returned PROCEED with complete Intent Contract coverage, including direct source and rollout evidence checks. Root applied the registered transition into Implementation; the edit-bearing classifier remains Doctrine. After publishing the execution locator, root dispatched R1 to /root/r3_native_worker with the exact reconstruction mechanism, canonical footprint, fresh-build roots and targeted proof obligations. Root committed the admitted contract and evidence as 31f33a1acc0ff388058f4f79994e67c15b9cacc0. R2 waited for the native handoff and commits; no material user decision remains open.

The fresh test-only source and driver compiled. The first three selected executions could not find the matching `.sla` files because the language fixtures are non-default build targets. This was an infrastructure failure before a behavioral result, not a failed semantic correction or a valid red. Compiling the existing x86-test-sla, x86-64-test-sla and x86-protected-test-sla targets resolved that prerequisite. Root read `red-missing-fixtures.log`, `red-languages.log` and the valid `red-focused.log` in the current task's evidence/native directory. The final red is 1/3 as described in L1/L2. Root's initial source lookup used an absent generic test filename; the failure log identified the actual patch-supplied owner, src/unittests/testsegmented.cc, which root then inspected. That failed lookup supplied no evidence.

R1 completed with focused 3/3, native 161/161, real-compiler preparation 10/10, registered Meson 2/2 and matching post-language build reuse passing. Root inspected the complete source/test and documentation deltas, relevant production APIs, raw focused/suite/reuse logs and the native/preparation result entries in green-testlog.txt. Native cmp confirms the canonical patch equals the evaluated green-source patch. Root reviewed each staged diff and committed source/tests separately from the independently coherent documentation. R2 then completed on final native 12f04ca6d23c4bb7e8f180ab4cf0ca913676e244 and was integrated as bridge be7b512342baa9b7748fe3be93abbb78fe730098 after the production inspection described above. The remaining frontier is fixed-candidate local Code review and closeout. No global installation or publication has occurred in this lot.
