# Microtask Program: incomplete native call inputs

Subordinate to [the Intent Contract](2026-10-26-native-incomplete-call-inputs.md), epoch1. This file owns no Scope, acceptance or lifecycle. Root owns scheduling and technical direction. P=/home/lucas/.cache/codex/radare2/native-incomplete-call-inputs-2026-10-26.

## H1 — observe native model-hole finalization

- Objective/status: Plan Gate PROCEED; ready for /root/hole_trace_worker. Measure the exact 72-byte witness at the current native owner before implementing the correction.
- Canonical implementation footprint: none for this observation. One bounded Worker may prepare disposable exact-baseline source and observation-only native test changes under P/build/native-trace/ and retain P/evidence/native-trace/. No repository source, prior tree or installation changes.
- Read dependencies: native37cd3df, the matching P0 fixed-slice prepared source/runtime, the exact existing witness/captures, current native action harness and the completed storage/consumer Recon. No concurrent source writer or validation-input mutation is legal.
- Fixed direction: use the actual native decoder/action pipeline and existing action breakpoints. Observe the admitted reaching STORE value, matching completed callee input-use storage, trials before/after model selection, final CALL operands and unresolved storage. Do not synthesize the model result or assert source parameter index from stack offset.
- Acceptance: show where positive stack[0x8:4] value7 association is lost while stack[0x4:4] stays unresolved; one focused assertion for the requested retained dependency must fail on the baseline. Existing STORE/warning and callee-use premises must be checked independently of that expected failure.
- Local discretion: exact observation hook/test organization under the existing harness. Existing action breakpoints are preferred; if the required state changes inside one action, temporary diagnostic-only statements at the actual admission/selection/finalization boundaries are allowed only in this disposable source. Such instrumentation must not change control flow or values. Preserve every evaluated source/log and show the production-byte difference is diagnostic only; no production correction in this entry.
- Stop: contradictory cause, missing real callee observation, source footprint expansion or unestablished machine/ABI premise. Report actual evidence to root before the next entry.

## Remaining admitted work

After H1, root will size the smallest implementation entry for the confirmed native storage-qualified input mechanism and its direct semantic/rendering followers. Implementation must retain real CALL value edges and explicit storage/unknown-source-role semantics without an auxiliary pseudo-effect owner. The matching bridge/pdgx integration follows a committed native result. These work packages are not dispatchable entries until their exact write/read dependencies, footprint and decisive acceptance are stated. Root keeps source updates sequential across shared patch owners and later serializes all Claude review invocations.
