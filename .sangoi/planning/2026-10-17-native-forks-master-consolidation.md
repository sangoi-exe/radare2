# Native fork master consolidation — Intent Contract

Status: active
Task mode: Doctrine
Lifecycle phase: Implementation
Strategy epoch: native-master-1
Plan kind: Operations / Tooling Plan
Secondary kinds: none
Active annexes: none

## Confirmed objective and required result

Keep only `master` as the local working branch and GitHub default/principal branch in each of the four selected native-workspace forks. Put the complete reviewed native-transfer work on those masters without squashing or rebasing away its commits. Preserve the history already on each principal branch. Create `master` for the MCP fork, whose current principal is `main`. Publish the resulting masters and delete the other fork/local working branches only after a recoverable native backup exists.

“All commits” means our current native-transfer work plus the existing principal history. It does not mean merging the inherited experimental branches into the selected code. Their branch references will be deleted; a local recoverable backup will retain their prior targets. This is branch/publication consolidation, not a new feature, experimental-upstream integration, global installation or another transfer task.

The primary kind is Operations / Tooling because Git refs, publication and the fork default branches are the primary inputs and outputs. The existing runtime architecture, engine pin and native analysis contracts remain unchanged. The two already-existing remote host-master commits are retained through ordinary integration, not a forced replacement or a fabricated ancestry-only merge.

## Current-user decisions and authority

- Request: turn `01a14ae8-e8e3-7dd3-8464-b8452167934a`, message `msg_01a14ae8-e99d-7d01-b2f3-13aa13e52268`, `2026-10-17T14:29:00.573-03:00` (America/Sao_Paulo), current rollout line21414: keep only master in each fork, create it where missing, and put all commits there.
- Explicit paraphrase confirmation and route selection: turn `01a14aef-831e-7652-83f3-9ab1c69840b3`, message `msg_01a14aef-83b0-7210-b763-7351a9978d37`, `2026-10-17T14:36:13.233-03:00` (America/Sao_Paulo), current rollout line21538: “sim, confirmo, só nosso trabalho”. The preceding proposal states one master locally/on GitHub, all our work plus current principal history, the host's two remote commits retained by normal merge, recoverable backup before deleting169 extra remote branches, and exclusion of inherited experiments, tags and upstream repositories.
- This is explicit authority for the named fork publications, default-branch change and branch deletions within this envelope. It is not permission to lose unique history without the selected backup, force-rewrite master, change tags, mutate upstream, alter global configuration or expand runtime behavior.
- The confirmation authorized the local Initial Intent Contract audit. After its `PROCEED`, turn `01a14af8-3ed0-7f41-9832-419c92e3f0de`, message `msg_01a14af8-3f6b-7191-9169-38ea44e5ab89`, `2026-10-17T14:45:45.580-03:00` (America/Sao_Paulo), raw rollout21670, says “pode executar” in response to the exact backup/consolidation/publication/cleanup and local Code Gate proposal at21663. This is the later implementation authorization and this task's local Code Gate selection. The previous transfer's expired selection is not reused.

## Canonical owners and observed inputs

The active workspace is `/home/lucas/work/radare2`. Its four nested repositories are independent Git roots, not submodules. Git owns refs, commits, merges, bundles, local tracking and push; GitHub owns each fork's default branch. Preserve the existing `upstream` remotes and all tags. Do not modify another clone, worktree, fork, original Ghidra repository or game worktree.

| Local repository | Authorized GitHub fork | Reviewed work tip | Existing principal |
| --- | --- | --- | --- |
| `.` | `sangoi-exe/radare2` | `ec1e1f5b3c9d0e9bc9858b84eb2839f3f26c941e` | Local master `2edc13b6f72854bd846c4dcab14acd06381dc71a`; remote/default master `cde84d8bb8c7886a575220b429ddccecee678a69` |
| `r2ghidra/` | `sangoi-exe/r2ghidra` | `296dd569c119805951dc596d5478c7bce57ea978` | Local/remote/default master `9b7969e190eda2e05023808a045fd1aa9627dbb7` |
| `r2ghidra/ghidra-native/` | `sangoi-exe/ghidra-native` | `cd9a067b7ec14bed6f6faaa5192343742bc1953e` | Local/remote/default master `c958826f04a63f76c1e2eb517c3a1bbca9045656` |
| `r2mcp/` | `sangoi-exe/radare2-mcp` | `e8fb3ac34e98d633661127d9b13e1b0174b8f2d8` | Local/remote/default main `562c0cf23c42b65b3052f0b294d8778c20facbde`; master absent |

Bounded Recon on `/root/branch_consolidation_host_recon` and `/root/branch_consolidation_components_recon` found all four tracked/untracked worktrees clean, one worktree per repository and no shallow history. Authenticated GitHub identity is `sangoi-exe`; origin push URLs name exactly these forks. Complete live remote head counts are155/12/4/1. One master per fork therefore removes169 old remote names and creates the MCP master. These are observed input counts, not an instruction to ignore subsequent drift.

The bridge, engine and MCP principals are ancestors of their work tips, with10/5/8 work-only commits. The local host principal is also an ancestor of its work tip, with45 work-only commits. The actual remote host master is missing locally; a read-only GitHub comparison proves it is two commits ahead of the local baseline, with no baseline-only commits and merge base exactly2edc13b6. Those commits are02b69cc2 (`sys/install.sh`) andcde84d8 (`libr/core/core.c`, `libr/include/r_util/r_str.h`, `libr/util/markdown.c`, `test/unit/test_str.c`). Their integration requires actual object acquisition and ordinary merge validation after activation; no fast-forward or mergeability claim is made for that pair yet.

The host has149 exact live upstream branch-name/tip matches. Four other nonprincipal branches outside our work ancestry are not proven disposable by name or author; they are included in the explicitly selected reference deletion with recoverable backup, not silently classified as merged. The bridge's10 experimental heads and engine's2 match live upstream and contain17/3 commits outside our selected work tips. They will not enter master. No open fork PR or repository ruleset was observed; existing principal branches are unprotected. Actual permissions/state remain preconditions for the later external operations, not a guarantee that writes will succeed.

## Selected route and propagation disposition

Use the existing repositories and native Git/GitHub operations. After activation, acquire missing origin objects without changing user files, retain the exact before-state and create verified standalone Git bundles for the local/origin branch targets before deleting or replacing any branch reference. Keep these operational backups in a fresh task-scoped destination under `/home/lucas/.cache/codex/`; no new worktree, clone, backup service, retained validator or remote archive branch is needed.

Preserve existing principal ancestry. Fast-forward the three straightforward principals to the selected work tips. Integrate the host's current remote master with its selected work through a normal merge, preserving both histories and actual changes. Do not rebase/squash the reviewed train, use an `ours` ancestry-only merge, discard a principal commit, merge the experimental branches, or force-rewrite master. If a conflict needs content edits, the root establishes the bounded resolution and dispatches it to an admitted Worker; Git lifecycle and commits remain root-owned.

Publish the exact qualified engine commit before publishing a bridge that depends on it. Make `master` the MCP fork default before deleting its current default `main`. Delete only the explicitly enumerated nonmaster fork heads, with exact expected remote targets; preserve tags and all upstream state. Complete local consolidation so each actual checkout is on master tracking its fork's origin/master and only that local branch remains. Upstream remote-tracking refs are not fork branches and are not a deletion target.

The sole engine wrap stays pinned tocd9a067b7ec14bed6f6faaa5192343742bc1953e. `r2ghidra/doc/win16-fmovmem.md` currently calls that pin unpublished; publishing it makes that active status claim stale. Correct the existing product guide without inventing a branch pin, changing its local-copy procedure or claiming a fresh network-only build. Completed transfer plans/logs and old branch names used as historical evidence are historical mention only; no rewrite of their then-current commits or results is selected.

No other evidenced route is needed for the confirmed result. Merging every experimental branch violates the clarified Scope. Force-replacing master would discard the principal history that the user confirmed must remain. Existing histories can converge through native fast-forwards and one ordinary integration; no new owner or compatibility branch is justified.

## Primary-path acceptance and first slice

The first directly verifiable slice is a recoverable, ancestry-preserving engine master prepared from the selected exact engine work tip. Native Git decides whether the before-state bundle contains every required target and whether both former principal/work tips remain reachable. This sizes execution; it does not select another architecture or authorize remote mutation before the required checkpoints.

Final acceptance:

- Each of the four forks exposes exactly `refs/heads/master`, GitHub identifies master as default, and its exact tip equals the intended local master. Each actual checkout is on master tracking origin/master and has no other local branch.
- Every selected work tip and prior principal tip remains reachable from its resulting master. The experimental histories are not merged; their original branch references are recoverable from the verified native backup. Do not call them integrated merely because their backup exists.
- Original runtime changes remain the reviewed native system. Validate the actual host integration against its changed native/core/string surface, and reuse other proofs only within unchanged source/component/input frontiers. A Git ref rename alone does not require rebuilding unchanged engine/MCP code. Unexpected substantive integration requirements return to the applicable current-user boundary rather than producing a workaround stack.
- The exact engine pin resolves on the published fork. Correct active publication guidance, retain explicit limits on fresh remote builds and global installation, and leave original executables/Ghidra/game worktrees untouched.
- Native status/diff/ref-set checks, required Code Gate, task log/changelog and exact commits account for the result. Report the backup locator, publication/default-branch/deletion outcome and any unverified surface. Clean source status does not erase the already-disclosed ignored principal configure artifacts; they remain outside this task and no principal-tree build is admitted.

## External/destructive execution boundary

Before writes, the root records the selected current-user action, exact repository/ref targets and expected values, authenticated identity, current local source, the narrow mutation, verification, no-ambiguous-retry rule and recovery affordance in the existing task record. A fresh native before-state/bundle is operational evidence, not a new maintained manifest or authority.

The destructive frontier is precisely all nonmaster local branch references and all nonmaster fork heads in the four named repositories after their targets have been captured. Only the old MCP default changes from main to master. Do not delete before backup validation, delete an unenumerated new remote head, or guess after a failed/ambiguous external operation. Preserve safe state, distinguish known/ambiguous completion, verify the actual remote and request a current-user decision if the documented native route cannot continue. Do not perform broad restore/reset/clean, remove operational backups or alter another workspace's branches.

## High-level work and continuity

1. Close the local Intent audit and obtain later implementation authorization; keep this new task separate from the completed native-transfer plan.
2. Capture exact before-state, acquire missing objects and verify native recovery backups; prepare ancestry-preserving local masters and the directly affected product guide through the admitted root/Worker owners.
3. Validate the host integration and consolidated committed candidates; obtain the newly selected Code Gate, then execute authorized publication/default/deletion in safe dependency order and verify exact post-state.
4. Complete factual task log/changelog, checkpoint all lead-owned artifacts and report remaining operational limits.

The root retains Git lifecycle, external/destructive actions, integration, final validation and documentary meaning. Workers may change only their admitted source/documentary footprints; they do not fetch, switch branches, stage, commit, push, change defaults or delete refs. The Microtask Program remains root-owned and proportional; no execution annex is needed for this bounded task.

Plan Gate: `/root/native_master_plan_audit` returned `PROCEED` for the local Doctrine / Initial / Intent contract audit at host `a14824fa4809ec1070506f776a6b29133d42e1b6`, with complete required-field coverage and no material findings or required correction. The reviewer verified the exact request/paraphrase/confirmation source sequence and current principal/work ancestry. The sole matching resident transition places the plan on-hold, retains Initial and requires later current-user implementation authorization; no rerun is required.
Implementation authority: active under the later current-user message at `2026-10-17T14:45:45.580-03:00`, raw21670. The plan enters Implementation before the first consolidation mutation.
Code Gate: local `Senior Code Reviewer / Task change-set review` selected for this task's next committed-candidate review by the same message in response to the exact local/Extra High/Pro proposal. No override or review waiver is supplied.
Blocker: none. Missing remote host-master object remains a known execution input, not established mergeability. No source, remote publication, default or deletion result is claimed before observation.
Next high-level action: capture fresh exact refs and identity, acquire required origin objects and verify standalone recovery bundles, then prepare ancestry-preserving local masters and the bounded guide/host-integration proof. Preserve the selected Scope and closed interpretation.
