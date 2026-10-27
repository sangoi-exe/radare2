# Microtask Program: auxiliary callee decode failure

This root-owned execution annex follows [the Intent Contract](2026-10-27-auxiliary-callee-failure.md). The contract alone owns objective, Scope, route, authority, lifecycle and acceptance. Retain this one annex for continuity; no update_plan tool is exposed in this session.

## B1 — bridge reconstruction and direct qualification

- Objective: Preserve conservative caller output after the demonstrated optional callee decode failure, using one clean caller-only reconstruction.
- Status: ready after Initial Plan PROCEED; not dispatched.
- Dependencies: Initial Plan PROCEED; exact qualified SDK/native/language read inputs established by bounded Recon. No parallel source writer or validation against changing inputs is legal.
- Effective write footprint: r2ghidra/src/core_ghidra.cpp; r2ghidra/test/db/extras/r2ghidra_pcode; r2ghidra/doc/incomplete-call-inputs.md; r2ghidra/AGENTS.md; fresh task-scoped build/runtime/evidence outputs; and only the task-created ignored build entries r2ghidra/subprojects/ghidra-native (a no-clobber symlink to the matching prepared engine) and r2ghidra/subprojects/.wraplock. Both entries were absent at root preflight. Do not replace an existing entry. Existing caches, native/host/MCP source, manifests/pins, root .sangoi artifacts and Git state are forbidden writes.
- Recon basis: Existing sequencing/cleanup, error taxonomy, result ownership and qualified build-input reports; root's eight production subprocesses, including same-process failure followed by a conservative next command.
- Selected mechanism: Signal a BadDataError specifically from optional callee action to the command-local analysis owner; complete sleep cleanup and destroy that architecture; re-establish selected caller interpretation; run the same full path once with auxiliary scheduling disabled. Keep successful flow unchanged and retain no failed native analysis objects. Keep supplied contracts and mode-specific rendering/harvest behavior.
- Fixed decisions: No generic error swallowing, same-architecture rollback, native snapshot import, persistent failure state, new process, retry queue, source-arity inference, patch/pin change, global installation or push. A failed reconstruction does not request another attempt. On recovery, all prior auxiliary enrichment is intentionally discarded and the reason is explicit.
- Local discretion: Equivalent local C++ structure, names, existing configuration/ownership helper use, test arrangement and diagnostic wording within the selected mechanism and repository conventions.
- Acceptance: Demonstrated invalid callee returns conservative code plus uncertainty in normal/retained output; valid-callee behavior and supplied contracts remain correct; mixed success/failure is conservatively explicit; caller/init/unclassified exceptions retain their current error path, while caller/final negative action returns retain their existing warning/output handling and never request reconstruction; same-process reuse and caller interpretation are checked.
- Targeted validation: Matching bridge Meson build, pcode-xml, affected p-code regressions and existing types/resolution/formatter followers; bounded real-plugin failure/control observations. Keep actual commands/results and input identity factual. Do not run an unneeded native/Windows suite or mutate old qualified build roots.
- Build constraints: Reuse the R5 prepared native3accd421 source and matching language bundle read-only; setup must validate the existing marker and stop on refusal. Build explicit core_r2ghidra and pcode-xml-test targets into the new output only. Do not run default sleigh targets or meson install, which can write old source languages or the old SDK. Keep the two task-owned dependency entries until dependent builds/tests finish; root owns their final cleanup.
- Result: none yet. Remaining frontier: implementation and actual correction proof.
- Stop: Missing/stale qualification, required write-footprint expansion, mechanism contradiction, material boundary, or a new unsupported failure. Report defects promptly to root; do not write task records or stage/commit.

## Root integration and completion

- After B1: inspect complete task diffs and decisive production output, preserve unrelated files, and checkpoint coherent code and documentation in their owning repositories with exact staging and the required Codex trailer.
- Review: one fixed committed candidate, narrow crossed local Senior/Claude procedure, equivalent evidence, serial Claude invocations, reciprocal examination and final cumulative Senior disposition. No source mutation while that object is under review.
- Closeout: actual review/validation records, changelog, exact final status/diff and retained-runtime disclosure. Root owns these writes and commits.
