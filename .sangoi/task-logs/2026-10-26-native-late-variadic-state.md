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

Selected direction: restore fixed-position metadata in declaration order at the same late producer. No comparator, cspec or global mode change. Implementation: not started. Correction validation: pending.

## L2 — existing register tail discarded

Observed:33 exists in the direct control and after retained clear/reanalysis, but is absent from the normal late CALL. Expected: a variadic prefix does not close or silently discard the already-discovered non-fixed input state.

Confirmed source mechanism: transferLockedInput gathers only the fixed inputs; commitNewInputs clears all existing trials and replaces the CALL operand vector with the new prefix plus any dedicated placeholder. Ordinary register heritage need not revisit those ranges, and0400's additional recovery is stack-relative, not a reconstruction of discarded register trials. Current anchors are N/src/decompiler/fspec.cc5412–5431,5462–5508 and heritage.cc1263–1268,2707,2786–2797.

Selected direction: before destructive reconstruction, preserve existing candidate trials by value; rebuild fixed inputs with their positions; retain only non-overlapping non-fixed candidates with original values and facts; reindex through existing slot/placeholder APIs before replacing the CALL inputs. Keep the current pass/final-check lifecycle and ordinary model selection. Do not promote every saved candidate to active or invent new tail values. Completed API recon and root direct reads establish value-copy semantics, stable borrowed model-entry ownership, fresh entry binding during model derivation, and slot/placeholder accounting. The Microtask Program freezes registration/copy/setSlot reconstruction, existing overlap semantics and preservation of the current pass policy before dispatch. No generic transfer helper or new state owner is selected. Implementation: not started. Correction validation: pending.

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

## Current execution state

The user confirmed the new correction lot and the documentation requirement. Root completed read-only production/source triage, including the old-runtime comparison and current model-hole replay. Ten C/XML processes exited0; no supplied scripts, new native build, guest or repository edits were part of that triage. /root/r3_plan returned PROCEED with complete Intent Contract coverage, including direct source and rollout evidence checks. Root applied the registered transition into Implementation; the edit-bearing classifier remains Doctrine. After publishing the execution locator, root dispatched R1 to /root/r3_native_worker with the exact reconstruction mechanism, canonical footprint, fresh-build roots and targeted proof obligations. R2 waits for the native handoff and commits. Implementation and correction validation remain pending; no material user decision remains open.
