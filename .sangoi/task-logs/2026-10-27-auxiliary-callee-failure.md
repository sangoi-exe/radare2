# Auxiliary callee decode failure

Date: 2026-10-27. Workspace: /home/lucas/work/radare2. Current intent: [canonical contract](../planning/2026-10-27-auxiliary-callee-failure.md).

## Intake and authority

The user resumed historical session01a16717-0b9b-7e10-9f98-d4203ccbfde6. Recovery found completed R5 work followed by a newer unfinished P1 investigation, not an unclosed R5 implementation. The supplied Sol report alleges that optional callee failure removes caller output. Astra's21-file archive executes transcribed finalization and queue predicates, not the real auxiliary preparation/action/reanalysis path. Its lack of an integrated error is a proof boundary, not a refutation. Neither external report selects a correction.

Current-user Scope confirmation and the subsequent disclosed clean-reconstruction route and proceed messages are retained in the canonical contract. The private host/plugin/language inputs are the previously qualified native workspace inputs; no global installation, authentication change, download, worktree or push was authorized or performed.

## Defect episode AF1: optional failure suppresses available caller output

Observed: With the same90-byte x86-32 caller/invalid-callee input, the retained pre-R5 plugin renders caller C. The current plugin renders no C and reports Bad instruction count exceeded at0x1050. Direct current analysis of the invalid callee produces the same diagnostic. Current pdgj normal and retained modes return only an errors object. Every subprocess exits0; the exit code does not establish successful decompilation.

Expected under the confirmed result: optional decode failure leaves a conservative caller result and explicit unresolved input storage. It does not invent a CALL operand or erase unavailable evidence. Caller/final-analysis errors and unclassified failures remain errors.

Comparison controls: the current plugin with the same invalid bytes but a registered bodyless callee renders the caller and unresolved stack[0x8:4]. Restoring the original valid eight-byte callee produces __call_incomplete(stack_argument_consumer,__input_storage("stack",0x8,4,7)). A subsequent command in the same process after the error also renders the bodyless conservative caller; observed asm.arch, asm.bits, anal.arch and configured language remain x86/32/x86/x86:LE:32:default:gcc in this witness.

Evidence basis: current-thread real-plugin tool outputs include the completed three-case baseline/current comparison, four focused current controls and one same-process experiment. The payload was recovered exactly from historical source34469, call_id call_3vL8TQbC9RIzq0nOEHLkcUAO, after validating its90-byte length. It is a local production-plugin witness, not Windows or machine-execution evidence. The old process session78054 was unavailable. Two initial diagnostic-script attempts stopped before invoking radare2: a transcribed byte-count assertion failed, then a JSON type assumption failed. The corrected extraction used the observed native list shape and completed; no source correction attempts occurred.

Confirmed cause: native R5 correctly retains rejected-input uncertainty, causing this caller to enter the already-existing bridge queue. In r2ghidra/src/core_ghidra.cpp:427-471, the caller finishes before the optional callee action. That action's BadDataError escapes before final caller rendering/harvest. The source scheduler is unchanged across the R5 bridge range. This is reachability expansion of an unisolated optional-evidence failure, not evidence that uncertainty retention is wrong.

## Route assessment and selected correction

Root directly inspected the bridge sequencing, rendering/harvest consumers, positive snapshot producer/consumer and relevant native cleanup. A bounded Recon mapped the BadDataError producer, negative-action semantics and existing sleep/timeout boundaries. A read-only Senior Bug Hunter pressure-tested cleanup and disposal; its conclusions are advisory and no Gate was substituted.

The initial same-architecture cleanup idea was not implemented. Copied call prototypes retain scope aliases; clearing a Funcdata preserves overrides and completion/model state. Restart and inlining can alter a larger native footprint than the queued function. An exception subtype does not prove that clearing only that function rolls back the attempt. Clearing the caller earlier would also remove positive observations that an auxiliary can consult. These facts reject both naive catch-and-render and early-clear simplifications without requiring a failed patch.

Selected direction: discard the failed command-local native architecture and reconstruct the caller once without auxiliary scheduling. Preserve existing wakeup, locking, translator-reset, mode-specific output and harvest ownership. Re-establish selected caller interpretation before new import/analysis. The native engine's existing static translator reuse is not a failed-analysis-object transfer. No native API or snapshot-import path is added. Earlier successful auxiliary enrichment is deliberately lost on that recovery path, as disclosed before the user's proceed instructions. Do not claim certainty that decode trouble originates in intrinsically invalid bytes rather than their selected interpretation.

Exterior-state qualification: actual source preparation can reach Core address-specific architecture/bitness callbacks. A new architecture therefore is not a rollback of every Core side effect. The observed fixed-language case showed no context drift, and reconstruction must preserve the selected caller inputs rather than blindly consume the last callee's configuration. Existing configuration facilities own that bounded handling. No broad Core rollback or new host support is selected.

Implementation state: proposed and selected, not implemented. Correction validation: not run. The pre-correction witness and controls are complete for the claimed failure. Next proof: small bridge slice produces conservative code where the current candidate yields only errors, with unchanged valid-callee output and a bounded failure-path reconstruction.

## Current execution state

Canonical contract created for Initial audit. The root-owned Microtask Program records the exact bounded Worker footprint. No code edits, patch application, builds, global installation or external mutation have occurred in this task. Tracked repository state at intake is clean in all four repositories; host .refs/ is pre-existing untracked material and remains excluded.

Build-input Recon located matching R5 prepared native source, the W35 SDK and the matching flat language/data inputs. The canonical bridge managed-engine path and .wraplock are absent. The program admits only a no-clobber task symlink and Meson's task-created lock at those exact ignored paths, plus fresh output files. The proposed setup/symlink route has not run; marker validation must succeed without source mutation. Default Sleigh targets can write the old prepared source, and meson install can target the old SDK despite a private prefix, so neither is admitted. Explicit plugin loading from the new output is the runtime route.

## Initial Plan decision

The local /root/af1_plan_audit returned PROCEED with complete Intent Contract coverage and no material finding. The auditor directly verified the current-user Scope/route anchors and source boundary. Its nonblocking wording note distinguishes auxiliary negative/incomplete actions, which currently throw, from caller/final negative results, which currently warn and can render output. Root clarified that both retain their current handling and neither requests reconstruction. This is clarify_existing, not a runtime change or new Plan decision. The task enters Implementation with no additional human checkpoint.
