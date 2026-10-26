# Intent Contract: close the two retained formatter failures

Status: active
Task mode: Doctrine
Lifecycle phase: Implementation
Strategy epoch: 1
Plan kind: Bugfix / Regression Plan
Plan kind rationale: Correct one reproduced declaration-data propagation defect and one stale test expectation. No new inference feature, prototype schema or rendering architecture is needed.

## Confirmed intent and authority

Correct the two retained formatter failures without disguising a runtime defect as an EXPECT update. Root's diagnosis and exact recommendation at current-thread source31942 distinguish the missing printf prototype knowledge from PPC's obsolete four-name expectation. The user explicitly accepted that recommendation at source31978: “ok, pode seguir tua recomendação então”, 2026-10-26T19:31:26.814-03:00, America/Sao_Paulo. Root's execution clarification at source31989 preserves the ellipsis, the varargs-off EXPECT and the engine. The user investigation request is source31794. All anchors are in turn01a179c7-79ce-7d91-97d5-e5818107b438 of /home/lucas/.codex/sessions/2026/10/23/rollout-2026-10-23T01-48-46-01a16717-0b9b-7e10-9f98-d4203ccbfde6.jsonl. The exact two-owner correction is selected; no material decision remains open.

This task starts after the separate incomplete-input task closed PROCEED_WITH_NITS. Its baselines are host3a482dc28c2a9b6686fa62674fecff600dba07ef, bridge3fbfdd4568965c8bbc838e01720971d9e09172bf and read-only native2ab32524c109737b0956b56f80ff2f249688d552. Native/bridge are clean and host has only pre-existing untracked .refs/. The earlier review does not approve these new corrections.

## Wrong behavior, required result and acceptance

With r2ghidra.varargs=false, the actual printf CALL survives with the expected three tail expressions, but its first input prints as 0x2000 rather than the format string. The host's supplied printf record has the format parameter and ellipsis but omits prototype knowledge. Current consumers correctly treat absence as unknown. A fresh-process change of only func.printf.prototype to fixed restores the original EXPECT without altering the tail, masks, return or ellipsis. Final acceptance must load corrected generated data normally, without this diagnostic in-memory setter.

The PPC test expects four _obj.g_* spellings. Current host analysis supplies correctly sized typed global.g_* objects, and the bridge intentionally prefers them. Actual ELF objects, CALL source ranges and double argument at f1 agree; only the four names differ. The native leading underscore means a size mismatch, not a required namespace. Update only these four EXPECT names, leaving the format, argument order, indentation and other bytes intact.

- A fresh production process loads printf prototype=fixed from generated canonical data while preserving const char *format and the existing variadic ellipsis. Recovery-off produces the original expected call and four actual value operands; the neighboring recovery-on control retains its distinct specialization behavior.
- The PPC regression passes with its four current global names and unchanged argument geometry/FP-register evidence. No host naming or native printing behavior changes.
- The two reported failures close, and affected existing formatter/type/resolution controls are checked with the matching private host/bridge/engine/languages. Classify any observed new failure against the old dataset before changing additional expectations or expanding Scope.

No old passing executable baseline was established. The current exact reproduction, successful single-field counterfactual and PPC graph/ELF comparison supply falsifiable correction anchors. Source history identifies the explicit-knowledge transition and earlier automatic-global change, but is not a historical runtime pass.

## Selected route and Technical rationale

Add func.printf.prototype=fixed at its canonical host declaration record in libr/anal/d/types.sdb.txt. This expresses known supplied parameter-list structure, including its existing ellipsis; it does not turn printf into a non-variadic function or a fixed call-site arity. Keep the conservative utype and R2Scope consumers unchanged. Restoring count/name-based inference, forcing format specialization or accepting numeric 0x2000 would obscure the demonstrated producer defect. Update only the PPC names in the existing bridge test/db/extras/r2ghidra_output. Recreating undersized generic-symbol rendering would contradict current host global ownership.

The selected private W35 runtime loads disk SDB data rather than compiled-in gperf data. Use the canonical native SDB generator with a fresh task-scoped output, then select a task-scoped data prefix through the existing dir.prefix option before binary loading. Keep the other qualified databases and executable/libraries/plugin/languages unchanged. This directly exercises generated-data loading and its real bridge consumer without a host C rebuild, source clone or global installation. An ephemeral runner entry may add that native option where r2r accepts only an executable path; it is task-specific transport, not a maintained proof helper or new loader.

## Scope and boundaries

Canonical edits are the one printf source record and four PPC EXPECT names. Direct generated SDB/C output and private validation runtime/evidence belong under /home/lucas/.cache/codex/radare2/formatter-regressions-2026-10-26/. Root owns plan/log/changelog, integration, validation, exact commits and review; an admitted Worker owns the two implementation files and targeted execution. The [Microtask Program](2026-10-26-formatter-regressions-microtasks.md) is the single subordinate execution projection because update_plan is unavailable; the [task log](../task-logs/2026-10-26-formatter-regressions.md) owns causal episodes and actual results.

Non-goals: audit or rewrite other supplied signatures, change generic knowledge defaults, source arity, varargs inference, host global naming, bridge/native source, the model-hole XML nit, fixture bytes, global installation, guest/Windows execution, worktrees, downloads, cleanup or push. Native schema and persisted data do not change. Existing unrelated task artifacts remain intact. A required additional owner or changed behavior returns to the user.

## Execution and continuity

First directly verifiable slice: the two exact canonical edits, generated base type data loaded by the unchanged private production consumer, and the original recovery-off plus PPC commands. Then run the affected regression frontier, integrate honest commits and obtain the default local Code Gate. This small data/test delta warrants a single Senior review unless execution reveals new complexity. /root/formatter_plan returned PROCEED with complete field coverage and no material finding. Root read the matching transition, published the existing locator and entered active Implementation. No current blocker or material user decision remains. Next action: dispatch F1 to its bounded Worker, then integrate its actual results.
