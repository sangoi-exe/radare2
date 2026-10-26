# Intent Contract: preserve native fixed-input byte slices

Status: active
Task mode: Doctrine
Lifecycle phase: Implementation
Strategy epoch: 1
Plan kind: Bugfix / Regression Plan
Plan kind rationale: Correct a reproduced inherited wrong-byte selection in late fixed-parameter reconstruction. Preserve the selected native owner and already-qualified order/tail behavior.

## Confirmed intent and authority

The required result is to preserve the selected source-storage range until each fixed parameter is materialized, so distinct contained parameters use their own bytes. Add a regression through the actual native action pipeline, qualify the matching bridge, and record diagnosis, validation and review decisions. Preserve the preceding correction; do not replace the normal path with retained mode or a global restart.

The user confirmed root's complete paraphrase at current-thread source29582, turn01a17938-2faa-7ee2-9057-905432a6fa6f, 2026-10-26T14:18:07.991-03:00 (America/Sao_Paulo): “ok, confirmo, mas uma dúvida, aquele esquema do model hole, que fim teve?”. The preceding paraphrase is source29575. Exact source is /home/lucas/.codex/sessions/2026/10/23/rollout-2026-10-23T01-48-46-01a16717-0b9b-7e10-9f98-d4203ccbfde6.jsonl. Source order and the explicit confirmation establish this new lot; the preceding completed plan is historical.

After asking about parallel model-hole work at source29614, the user accepted root's separate read-only investigation proposal at source29635, 2026-10-26T14:25:09.355-03:00, with “ok, pode ser”. That lane examines a fixed pre-correction snapshot and does not authorize model-hole edits, a new representation, or a change to this correction's acceptance. Model-hole remediation needs a separate current-user decision after evidence. No human decision blocks the fixed-slice correction.

## Observed wrong behavior and expected result

Baselines are native 12f04ca6d23c4bb7e8f180ab4cf0ca913676e244, bridge be7b512342baa9b7748fe3be93abbb78fe730098 and host2159ca64a968fcb26c225a2332329d6b769c2802. These exact refs were published and remotely verified in the preceding user-authorized push. Tracked trees are clean at intake; pre-existing untracked .refs/ is excluded.

The supplied R4 136-byte x86-32 fixture stores one eight-byte value containing DWORDs1 and7. Two supplied fixed parameters occupy stack[4:4] and stack[8:4]. The actual normal indirect CALL at0x101b targets0x1040 and passes the same four-byte Varnode twice. Its sole definition is SUBPIECE(source8,0); rendered C shows packed_target(Var1,Var1). The prior qualified a449642 runtime produces the same wrong endpoint. This is an inherited defect, not a regression introduced by the last tail-preservation change.

The same direct fixture, and the indirect fixture in retained mode, use distinct four-byte LOADs for the two argument locations. Those are behavioral controls, not a selected workaround. The native helper bodies are unchanged against the older baseline; no known-good earlier in-place late implementation is established. Expected correction is byte provenance: the second parameter uses the selected source's interior four-byte range, not a second copy of the low range. Literal107 is a fixture-derived arithmetic result, not an observed CPU or decompiler return value and not the decisive oracle.

## Selected route and Technical rationale

Canonical ownership remains the native patch stack at patches/0400-call-relative-stack-inputs.patch and its fixed-input transfer/reconstruction consumers. transferLockedInputParam accepts contained parameter storage but returns only the CALL slot; transferLockedInput preserves only its value. commitNewInputs clears the source trial state before buildParam, which unconditionally truncates oversized values at offset0. Thus the source range needed to distinguish the interior parameter is lost before slicing.

Materialize the fixed inputs while their original selected trials remain available. Reuse the current containment-selection owner to obtain the correct source range and Address::justifiedContain to express the endian-aware least-significant-byte displacement. Then clear/reconstruct fixed-trial metadata and retain non-overlapping tail candidates using the already-qualified sequence. Preserve the relationship between a trial's storage and its actual representative; do not derive source storage from the address of a constant, unique or loaded-value Varnode. Keep the existing public lateRestriction interface, placeholder lifecycle, pass/model policy and refusal/restart ownership; no new persistent field, public API or generic transfer layer is selected.

This two-phase materialization avoids transporting a new parallel state owner through the public restriction API. Equivalent private helper signatures and local organization remain implementation details. The first native observation must confirm the exact selected trial/representative relationship and whether the actual transition is in place. If that observation contradicts the diagnosis, revise the causal episode before dispatching another correction; do not force a test to the proposed explanation.

Retained-mode reanalysis currently avoids the endpoint, but using it globally would bypass the requested normal-path correction. A wholesale upstream upgrade or the separate reregisterTrial metadata idea does not establish a fix for source-range displacement. No such route, model-hole repair or speculative metadata cleanup is selected.

## Primary acceptance and first verifiable slice

- The real native indirect fixture exposes the selected eight-byte source trial, fixed parameter locations, generated slice offsets and restart state at the existing ActionDeindirect boundary. Establish a focused red for the wrong second slice, then show corrected nonduplicated four-byte provenance.

- The real bridge's normal indirect result uses both specified argument ranges and agrees with the direct/retained controls on those live arguments. Inspect CALL inputs and their definitions, not merely C spelling, token presence, count or the unexecuted107 oracle.

- Explicit clear/reanalysis and the preceding mixed GPR/XMM order, non-overlapping variadic tail, fixed/model-only, stack-prefix/warning, placeholder, F11/F12 and exact-PC controls remain valid. Tests exercise the actual native pipeline and matching plugin, not the supplied synthetic methods.

- The bridge pins the final committed native candidate and uses matching languages/SDK/plugin. Required targeted native/preparation/bridge checks and the default local Code review decide the result; unchanged historical formatter failures remain individually disclosed, not rewritten as passes.

The first runnable slice is the exact136-byte direct/indirect pair with the two-fixed variadic prototype in the current native harness, using existing action breakpoints before/after deindirection. This supplies the missing internal trace without installing a debugger or adding production instrumentation. No exhaustive model, endian or restart matrix is required before that execution.

## Scope and exclusions

In Scope: fixed-input selection/materialization at the existing native owner, direct private declarations/callers, focused native tests and coverage documentation, bridge pin and direct production regressions, canonical plan/log/changelog and retained evidence. The primary workspace is /home/lucas/work/radare2; its independent nested native/bridge repositories own their source changes.

Out of implementation Scope: model-hole recovery, partial-overlap residual argument recovery, global model/comparator policy, derived-metadata cleanup, C48/NE/selector/Windows behavior, host production changes, a Ghidra upgrade, public API/persistence/compatibility changes, global installation, new worktrees, downloads, cleanup and push. A new material owner/contract/risk/behavior choice returns to the user. The admitted parallel model-hole investigation remains read-only and cannot silently turn its recommendation into remediation.

Use fresh task-scoped build/runtime/evidence roots under /home/lucas/.cache/codex/radare2/native-fixed-input-slices-2026-10-26. Preserve previous evaluated trees, SDKs, media and lab inputs. Generic x86-32 decompiler tests do not establish new Windows/16-bit CPU behavior.

## Work and continuity

1. Audit this confirmed contract and finalize the bounded native execution entry.
2. Establish the internal trace, implement the selected two-phase slicing correction and run targeted native proof.
3. Integrate the committed native pin and qualify production bridge consumers.
4. Obtain the registered local Code review, finish records, commit and inspect final Git state.
5. In parallel, collect a separate read-only model-hole diagnosis and surface any actual material correction choice without changing this implementation Scope.

Root owns strategy, the [Microtask Program](2026-10-26-native-fixed-input-slices-microtasks.md), [task log](../task-logs/2026-10-26-native-fixed-input-slices.md), integration, validation and Git. Workers own admitted source implementation. This runtime exposes no update_plan tool; the one subordinate annex retains execution continuity without owning Scope or lifecycle. /root/r4_plan returned PROCEED with complete Intent Contract coverage and no material finding. Root applied the registered publish-plan-locator-and-enter-implementation transition. S1 is implemented, natively validated and committed at37cd3df63a96b4b16669b2131ccb6ca6102a6b8d. No human decision blocks this correction. Next action: complete S2's matching bridge qualification, then obtain the fixed-candidate local Code review. The completed separate model-hole diagnosis does not expand implementation Scope.
