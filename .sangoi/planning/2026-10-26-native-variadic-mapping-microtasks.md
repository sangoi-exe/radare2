# Microtask Program: native variadic tail and mapping capacity

Subordinate execution projection of [the Intent Contract](2026-10-26-native-variadic-mapping.md), epoch1. The contract alone owns Scope, route, acceptance and lifecycle. Root owns this mutable projection. Initial source baselines are native7a5505b and bridgef77db63; full refs are in the contract. P is `/home/lucas/.cache/codex/radare2/native-variadic-mapping-2026-10-26`.

## T1 — variadic tail and SP-reference lifetime

- Objective: preserve the open variadic tail through fresh, late-contract and clear/reanalysis states.
- Executor: /root/tail26_native_worker, worker. Status: dispatched and active; no implementation result yet.
- Exact canonical write footprint: `r2ghidra/ghidra-native/patches/0400-call-relative-stack-inputs.patch`. Generated disposable source/build/evidence footprint: P/build/tail/, P/evidence/tail/. Native documentation is deferred to T3 to prevent shared-file writes.
- Read dependencies: native baseline patch stack, supplied72-byte ZIP member and proposed independent-prototype regression as untrusted evidence, existing native test driver/specifications, and the retained W52 source/runtime as read-only baseline. Local clones at the exact baseline freeze inputs; overlay only T1's declared patch in those copies. Do not incorporate concurrent T2 bytes or edit prior evaluated trees.
- Recon basis: /root/tail26_sp_reference_recon and root direct inspection of recovery, create/get/abort placeholder, commitNewInputs, transferLockedInput, ActionFuncLink/ActionActiveParam and clear/reanalysis.
- Selected mechanism: preserve existing fixed-input forwarding; admit active variadic recovery despite the fixed-prefix lock, while a locked nonvariadic list still stops. In commitNewInputs, retain an existing dedicated call-SP placeholder for a variadic prefix rather than replacing it with the first fixed stack parameter; reattach it through the existing slot bookkeeping. Continue current reaching-store, competing-use and positive-snapshot admission. Use the ordinary reconstruction path after clear; do not copy stale unresolved vectors, infer entry alignment, reverse-engineer a pointer from an already-forwarded constant, add a parallel SP field or change bridge scheduling. Preserve fixed-prefix identity/order and existing canonical-offset and selector-qualified behavior.
- Local discretion: equivalent local C++ structure, concise comments and test arrangement within the existing patch/test owner. A missing required placeholder in an actual admitted state, contradicted mechanism or footprint expansion returns to root before an alternative mechanism.
- Targeted validation: real native decoded fresh-prefix witness with available/withheld callee facts; independently constructed late variadic prefix and explicit clear/reanalysis; existing fixed/model-only and ordinary reused7/F12 controls. Inspect actual CALL operands, unresolved storage and CALL-PC warnings. First show the relevant new regression fails against the baseline where practical, then passes with the selected correction. Use supported fresh preparation/Meson and matching native language fixtures, not copied probe algorithms.
- Parallelism: canonical writes are disjoint from T2; isolated baseline-derived build copies permit concurrent targeted validation. Shared final validation waits for both handoffs.
- Stop: material route/behavior drift, missing technical mechanism, second same-behavior failed correction, unsafe state or a footprint expansion. Report new defects and failed attempts promptly. Remaining frontier: implementation and targeted proof.

## T2 — unwrapped native mapping-capacity admission

- Objective: reject the demonstrated over-capacity extent before publication and preserve valid mapping lifecycle.
- Executor: /root/tail26_mapping_worker, worker. Status: dispatched and active; no implementation result yet.
- Exact canonical write footprint: `r2ghidra/ghidra-native/patches/ghidra-native.patch` and `r2ghidra/ghidra-native/patches/0360-wide-address-regressions.patch`. Generated disposable source/build/evidence footprint: P/build/mapping/, P/evidence/mapping/. Native documentation is deferred to T3.
- Read dependencies: native baseline patch stack, Scope/MapEntry/Address/TypeArray owners and current WideEnvironment/native mapping tests. Freeze the exact baseline in local build copies and overlay only T2's declared patch files; do not ingest concurrent T1 bytes.
- Recon basis: /root/audit26_mapping_frontier plus root direct admission/arithmetic/producer inspection. The prior ownership fix and existing invalid-start regression remain binding controls.
- Selected mechanism: at ScopeInternal::addMapInternal, reject a starting coordinate above the space limit or a non-fitting unwrapped extent, using existing native Address range semantics only after establishing the valid-start precondition. Compute the modular last address only after admission. Preserve the existing delete-entry/throw path before symbol ownership and normal rangemap insertion afterward. No new helper/type/map representation, compatibility behavior, unrelated zero-size policy or stack/CPU model.
- Local discretion: equivalent local predicate form and focused test organization. Use a real two-byte native stack space and TypeArray size65537 through the existing scope/type admission boundary; test valid insertion/query/removal after refusal. Retain the existing C48-in-RAM4 refusal/cleanup control.
- Targeted validation: demonstrate the new capacity regression on the baseline native owner, then test corrected refusal/cleanup and valid mapping controls through the actual registered native executable. Supported fresh preparation/Meson only; do not use simulated Address/Scope doubles. This tests host data structures, not16-bit machine behavior.
- Parallelism: disjoint canonical files and isolated source/build roots from T1; no final combined validation until T1 is stable.
- Stop: contradicted producer/admission premise, material policy change, canonical footprint expansion, unsafe cleanup or second same-behavior failed correction. Report actual diagnosis and validation promptly. Remaining frontier: native reproduction, correction and targeted proof.

## T3 — combined native/bridge qualification and active docs

- Objective: integrate the committed corrected native candidate and verify matching production consumers and directly affected regression suites.
- Executor: not dispatched. Status: blocked on T1/T2 handoffs and root integration/native commit.
- Canonical footprint to freeze at dispatch: bridge `subprojects/ghidra-native.wrap`, the existing direct pcode regression owner and native `tests/README.md`; no bridge production change is currently required. Root must declare exact effective files and fresh build/runtime/evidence roots before dispatch.
- Fixed decisions: use the current per-command native/callee scheduling and error policy, matching frozen host SDK and new candidate plugin/languages. Qualify actual CALL values and C/JSON/XML disclosure, explicit caller clear/reanalysis and retained fixed-calllink/ordinary controls. Preserve historical fixture expectations unless a demonstrated admitted behavior changes them.
- Dependencies: both native patch entries stable; no source writers while combined validation reads them. No parallel writes to documentation or shared build sources.
- Remaining frontier: exact dispatch after native fan-in; then root final validation, committed Code review and bookkeeping under the canonical contract.
