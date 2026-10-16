# Nested native workspace — Intent Contract

Status: complete
Task mode: Doctrine
Lifecycle phase: Closeout
Strategy epoch: native-layout-1
Plan kind: Operations / Tooling Plan
Secondary kind: Instruction / Policy Plan
Active annexes: none

## Confirmed objective and required result

Make `/home/lucas/work/radare2` the native RE workspace and the current user's normal Codex entry point. Relocate the three existing independent repositories into this exact hierarchy: radare2 at the workspace root, r2ghidra at `r2ghidra/`, and the editable native engine at `r2ghidra/ghidra-native/`. Preserve each repository's Git history, branch, remotes and task commits. Do not create a fourth repository, submodules or replacement clones.

Add the two root-anchored parent ignore rules so nested repositories are not accidentally tracked by their parents. Extend the existing radare2 `AGENTS.md` into the principal workspace map while preserving its useful repo guidance. Create one `AGENTS.md` in each child repository, with explicit local ownership, conventions, navigation and validation boundaries. Keep compiler/RE knowledge implemented at its current code owners rather than duplicating it in instruction prose. Correct the active product-document source paths affected by nesting.

The primary kind is Operations / Tooling because the result changes the operator's workspace location and navigation, not runtime behavior. The instruction secondary aspect is material because three independent code owners will have a root/child instruction topology. It does not import a separate workflow or plan.

## Current-user decisions and authority

- Naming/layout preference: turn `01a14662-67b9-74f0-944b-7433ef520227`, `2026-10-16T17:23:37.754-03:00` (America/Sao_Paulo). The user rejected a Win16-specific workspace name and proposed radare2 containing r2ghidra containing the native engine.
- Selected layout and added instruction/ignore scope: turn `01a14666-80d7-7b83-92c2-2b006a2b6a1e`, `2026-10-16T17:28:05.499-03:00`: “vamos fazer como eu sugeri”, with parent `.gitignore` protection and an `AGENTS.md` in each repository; radare2 is the primary Codex entry point.
- Confirmed paraphrase delta: turn `01a1466b-10eb-7142-80a9-dee6491946f3`, `2026-10-16T17:33:04.410-03:00`: “sim, confirmo”. The preceding paraphrase names the exact two ignore rules, the preserved/extended root instructions, scoped child instructions, active path correction, preserved historical records, and no functional change or push.
- No material route decision remains open. Confirmation authorizes the Plan Gate. After a normal `PROCEED`, obtain later unambiguous current-user implementation authorization; no checkpoint exception from the completed Win16 task carries into this task.
- Implementation and exact local Code Gate authority: turn `01a14679-0d44-7481-9548-2bcff2156b79`, `2026-10-16T17:48:22.949-03:00` (America/Sao_Paulo): “sim, pode executar, e ir local no code gate”. This later instruction activates the approved task and selects the first local Code Gate for its committed candidate.
- No external writes, push, PR, deletion, global installation, runtime-setting change or Codex-global instruction edit is authorized.

## Current owner evidence and selected route

Inspected intake sources were `/home/lucas/work/ghidra/.refs/radare2` at `1c46397457f4913a877015416772103199875d79`, `.refs/r2ghidra` at `cf1ca86cd8df32bf4feb44a8da26150e01e80a94`, and `.refs/ghidra-native` at `8c0a00933c9d19d493c3858799bb3f8d0388f2fa`. All three were clean on branch `win16-fmovmem`, with `origin` at the user's `sangoi-exe` fork and `upstream` at `radareorg`. Each has a normal `.git` directory, no `core.worktree` override or Git object alternates, and the same filesystem device as the target parent. The exact destination and nested names were absent. Administrative plan commits may follow these intake baselines before implementation.

Move these existing checkouts, preserving metadata, rather than recloning or converting them into submodules. The physical parent is the radare2 repository; the runtime host/bridge/engine ownership remains unchanged. Root owns checkout relocation and Git lifecycle as workspace integration; an admitted Worker owns the bounded content changes. No new builder, symlink or compatibility path is needed.

The editable engine's selected location is directly inside r2ghidra, not `subprojects/ghidra-native`. Existing Make/Meson integration continues to consume its build-managed copy in the latter location. Product guidance at `r2ghidra/doc/win16-fmovmem.md` must use the new direct-child source instead of `../ghidra-native`. Preserve its managed build destination and existing task-scoped private build approach. The wrap remains the sole engine URL/revision pin; no pin update or runtime source change is needed for a directory move and instruction edits.

## Canonical instruction and Git boundaries

- radare2 `AGENTS.md`: primary macro workspace map and navigation index. Retain useful radare2 guidance for `libr/`, `binr/`, host APIs and tests. Scope radare2-specific style/build rules to its own source, and point to the child instruction owners before child edits. Keep the map concise and stable, with local ownership and review/staleness context.
- r2ghidra `AGENTS.md`: bridge source, type/prototype transfer, native dependency integration, plugin tests and the distinction between editable engine and disposable build input. Follow existing bridge conventions rather than inheriting unrelated host C rules.
- ghidra-native `AGENTS.md`: canonical sorted patch stack, imported/generated followers, processor specifications, shared source manifest, focused native tests, and concrete local build/cleanup hazards. Keep operational detail at its current owners and do not copy global Codex rules.
- radare2 `.gitignore` adds `/r2ghidra/`; r2ghidra `.gitignore` adds `/ghidra-native/`. Preserve existing managed-subproject ignores. The engine needs no new nested-repository ignore rule.
- The default resident/shared instruction corpus continues to own execution, roles, approvals and lifecycle. Local `AGENTS.md` files do not redefine those contracts. Only workspace-local instruction owners change.

## Acceptance and immediate proof

The user can start from `/home/lucas/work/radare2` and find the complete native workspace map. All three expected roots resolve as independent Git repositories at the exact selected paths. Existing histories and metadata are preserved; new commits contain only this task's instruction, ignore, active documentation and required lead-owned records.

Git's native ignore checks must show that each parent excludes its nested checkout, while each child can still track its own files. Parent tracked-path inventories must contain no nested repository contents or mode-160000 entries for the selected children. Inspect the complete instruction and documentation changes, resolve their local pointers, and verify that host-specific conventions do not become accidental child rules.

The first directly verifiable slice is the physical root/child arrangement with preserved Git identity, its parent ignore boundaries, and the three readable scoped instruction owners. Native path/type/status/ref checks and semantic document review decide this result. No maintained checker, duplicate inventory, hashes, native rebuild or whole-game rerun is required because runtime code and build pins do not change. Check affected product shell syntax and active path followers directly.

## Propagation and preservation disposition

Live roots are the three selected repositories and the confirmed product-document consumer. Remove old live checkout pointers inside this causal frontier and update current instruction/navigation followers. The old checkout paths intentionally stop working after relocation; do not leave aliases or symlinks. If a new active consumer is observed, classify its causal link before changing it.

The completed first-slice plan and task log, prior reviewer ranges, rollout references and private build/evidence exports are historical records. Keep their old paths as `historical mention only`; they are not current navigation or new-task authority. Do not rewrite those records to pretend the past build or review ran from the new workspace. Keep the original Ghidra repository, its extensions, the game repositories/binaries and all other reference clones untouched.

## Scope, constraints and failure boundary

Scope contains the three checkout relocations, the two parent ignore owners, three root/child `AGENTS.md` owners, the direct product-document path corrections, and this task's plan/log/changelog. The destination must remain unoccupied at the operation boundary. Preserve any newly observed unrelated work; do not overwrite a destination, discard Git state, delete data, or add a fallback layout. If a move stops partway, preserve completed moves and report the exact remaining source/destination state rather than repeating an ambiguous operation.

Non-goals are functional code changes, new architecture support, extension/MCP migration, changing the engine pin, rebuilding/installing, pushing, changing Codex-global instructions or runtime settings, broad README/documentation migration, unrelated cleanup, and a fourth repository. Existing test/build READMEs remain product procedures at their existing owners, not replacement agent instruction owners. The reviewer-enumerated XPS source-path correction does not migrate or replace that product document.

After relocation, this same plan moves with the primary radare2 repository. Its final path is `/home/lucas/work/radare2/.sangoi/planning/2026-10-16-native-workspace-layout.md`; publish the updated continuity locator when that path changes. New instruction discovery in a fresh Codex session at the new root is not proven by static file review; validate it when available or disclose the new-session requirement explicitly.

## High-level work packages and lifecycle continuity

1. Close the local Intent Contract audit and obtain later current-user implementation authority.
2. Integrate the exact checkout relocation, then apply the admitted Worker content changes in the final owner paths.
3. Verify Git preservation/ignore boundaries, local instruction semantics, active product paths and unchanged runtime/pin surfaces; commit coherent owner changes.
4. Obtain the current-user-selected Code Gate, then finish factual closeout records and final Git/path inspection.

Plan Gate: `PROCEED` from `/root/native_layout_plan_audit`, local `Senior Plan Auditor / Intent contract audit`, Doctrine / Initial. The reviewer covered every required Intent field, verified the user anchors and decisive owner/path premises, and found no material findings or evidence-blocked required field. The sole matching transition places the plan on-hold in Initial, without authorizing implementation.
Implementation authority: active under the later current-user instruction above, after the actual Plan Gate `PROCEED`.
Relocation result: the three existing checkouts now occupy `/home/lucas/work/radare2`, `r2ghidra/`, and `r2ghidra/ghidra-native/` beneath it. Same-filesystem renames preserved every repository's exact pre-move HEAD, branch, all Git references, remotes, and root/`.git` inode identity. The three old paths are absent; the eight other reference-directory names are unchanged. The canonical plan locator was republished for the new workspace root.
Code Gate: `PROCEED_AFTER_FIXES` from `/root/native_layout_code_review`, local `Senior Code Reviewer / Task change-set review`, selected in turn `01a14679-0d44-7481-9548-2bcff2156b79`. The reviewer completed all four partitions and nine changed files plus direct followers, identifying one mechanically unequivocal correction in the newly linked bridge `r2plugin/README.md`. The Worker applied that exact one-line XPS target correction; the root verified its exact diff, resolved target and existing bridge Makefile, four console-block syntax checks, and whitespace. The sole transition's local-fix/mechanical-verification obligations are satisfied; it enters Closeout without another semantic review. The underlying verdict remains `PROCEED_AFTER_FIXES`, not `PROCEED`.
Blocker: none for the completed layout task.
Implementation result: all three scoped instruction owners and both parent ignore rules are in place. The active product document uses the editable direct-child engine source while retaining the managed build destination and unchanged pin. Native Git checks verified independent roots, preserved ancestry/branches/remotes, parent ignore behavior, and no selected nested tracked contents or gitlinks. Original host guidance is unchanged below the new map; local instruction links resolve and all three product shell blocks pass syntax checks. Runtime/build sources and pin are unchanged; no build or game replay was run.
Next high-level action: no further mutation is authorized by this completed task. Use `/home/lucas/work/radare2` for the next user session; fresh-session automatic instruction discovery remains unverified. Publishing commits or changing runtime behavior requires separate authority.
Review status: Plan Gate complete; local Code Gate semantically complete; its enumerated local fix is applied and mechanically verified. Only factual closeout bookkeeping follows the reviewed object and exact correction.
