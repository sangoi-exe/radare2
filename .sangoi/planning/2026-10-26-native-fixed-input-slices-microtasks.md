# Microtask Program: native fixed-input byte slices

Subordinate to [the Intent Contract](2026-10-26-native-fixed-input-slices.md), epoch1. Root owns scheduling and technical direction. P=/home/lucas/.cache/codex/radare2/native-fixed-input-slices-2026-10-26.

## S1 — native fixed-input materialization

- Objective: preserve the selected byte range for each fixed input while maintaining the qualified trial/tail lifecycle.
- Status/executor: /root/r4_slice_worker dispatched after Plan PROCEED and execution-locator publication. Internal observation and native implementation are in progress.
- Canonical write footprint: r2ghidra/ghidra-native/patches/0400-call-relative-stack-inputs.patch and tests/README.md. Private header/caller followers are represented inside that canonical patch, not edited imported source. Generated/disposable footprint: P/build/native/ and P/evidence/native/.
- Read dependencies: exact native12f04ca baseline, frozen prepared source and current native action/test harness, exact R4 fixture archive and the16 admitted actual production observations. /root/r4_packed_slice_investigation provides source/endpoint reconciliation. A separate model-hole lane reads the immutable baseline only; it is not a concurrent source writer.
- Selected mechanism: build fixed input values while the original trials are still available; obtain source storage through the existing containment selector; compute the endian-aware byte offset with Address::justifiedContain; pass that displacement/range to the private materializer rather than inferring it from a Varnode address. Only after fixed materialization clear/reconstruct active trials and restore the already-qualified placeholder/tail sequence. Keep the public lateRestriction interface unchanged. No new persistent field or parallel transfer owner.
- Fixed decisions: preserve fixed positions, non-overlapping tail values/facts, nonvariadic semantics, dedicated placeholder and pass/final-check/model policy. No change to recoverCallRelativeInputs, inactive-chain model policy, residual-tail obligations or warning policy. Do not treat retained-mode success as the correction.
- Local discretion: equivalent private helper contracts, local temporary value representation and loop organization preserving the selected order; concise comments explaining source storage versus Varnode identity. Stop for public API or owner expansion.
- First validation: use the actual native pipeline and current fixture with before/after ActionDeindirect observation of source range/width/slot/value, fixed parameter locations, slice offsets and restart. Establish the causal red before correcting. Inspect the final CALL argument definitions and explicit reanalysis, then retained controls.
- Build boundary: fresh local exact-baseline source copies under the declared build root; supported offline Meson, existing compiler/tools and scoped TMPDIR, matching non-default language fixture targets built before execution. Never remove patch.done or modify prior prepared sources.
- Stop: contradicted mechanism, new material contract, footprint expansion or repeated same-behavior failed correction. Report defects and failed attempts promptly to root. Remaining frontier: trace, implementation, native proof and root commits.

## S2 — exact native pin and bridge qualification

- Status/executor: not dispatched; depends on S1 and root's native commits.
- Canonical footprint to freeze at dispatch: r2ghidra/subprojects/ghidra-native.wrap and test/db/extras/r2ghidra_pcode. Generated work: P/build/integration/, P/runtime/integration/ and P/evidence/integration/. No bridge algorithm change is selected.
- Mechanism: use the exact committed native input with the frozen W35 SDK, current plugin and matching language producers. Add direct production controls from the corrected observed result, preserving existing EXPECT values.
- Acceptance: direct/indirect, normal/retained CALL provenance and the existing affected native/bridge controls; exact source/runtime correspondence and individually qualified historical failures. Root retains final output inspection, Git and Code review.
- Stop: a new bridge correction, changed expectation premise or material owner/contract boundary. Remaining frontier: exact dispatch after S1.

## M1 — separate read-only model-hole investigation

- Executor: /root/r4_model_hole_investigation, Senior Bug Hunter. Status: complete and integrated into the task log; no writes or new runtime execution. Root verified the retained STORE/CALL and dense positional consumers. The result identifies real omitted CALL association and a sparse-storage/source-arity representation decision, not authority for a flag-only repair. No model-hole implementation is dispatched.
- Write footprint: none. Read source fixed at native12f04ca and bridgebe7b512 in the preceding task's evaluated source; no moving S1 candidate or concurrent validation input.
- Question: trace known stack+8 use through hole selection/materialization and identify a faithful storage/argument-position result without inventing stack+4 evidence or shifting the later value.
- Output: evidence-backed diagnosis, supported route/representation choices, exact source/test overlap and next decisive validation. No implementation, model change, new artifact owner or material decision authority.
- Fan-in: root classifies findings and any user decision separately; M1 does not block or expand the fixed-slice acceptance merely because the source file is shared.
