# Nested native workspace implementation checkpoint

Date: 2026-10-16 (America/Sao_Paulo).
Canonical contract: `.sangoi/planning/2026-10-16-native-workspace-layout.md`.

## Authority and selected result

The user selected the nested radare2 → r2ghidra → ghidra-native layout and confirmed the instruction/ignore Scope. Local Plan Gate `/root/native_layout_plan_audit` returned `PROCEED` with complete Intent-field coverage and no material finding. Later user turn `01a14679-0d44-7481-9548-2bcff2156b79`, `2026-10-16T17:48:22.949-03:00`, authorized implementation and selected the local Code Gate. No previous task's authorization or review result was reused.

## Relocation observations

The root moved the existing checkouts with same-filesystem renames, without clones, submodules, symlinks, overwrites or deletion. Exact pre-move HEADs, branches, all Git references, remotes, and directory/`.git` inode identities matched after each move, before content changes.

| Previous source | Current independent root | HEAD at the move boundary |
| --- | --- | --- |
| `/home/lucas/work/ghidra/.refs/radare2` | `/home/lucas/work/radare2` | `805adda11a102a80bdcfc37ad05b316e4b01f280` |
| `/home/lucas/work/ghidra/.refs/r2ghidra` | `/home/lucas/work/radare2/r2ghidra` | `cf1ca86cd8df32bf4feb44a8da26150e01e80a94` |
| `/home/lucas/work/ghidra/.refs/ghidra-native` | `/home/lucas/work/radare2/r2ghidra/ghidra-native` | `8c0a00933c9d19d493c3858799bb3f8d0388f2fa` |

All branches remain `win16-fmovmem`. Each `origin` remains the corresponding `sangoi-exe` fork, and each `upstream` remains the corresponding `radareorg` repository. Later task commits add only configuration/documentation. The old three checkout paths are absent and intentionally have no alias. The canonical plan moved with the host, and its continuity locator was republished for the new root.

The other eight reference-directory names remain in the Ghidra `.refs`: cutter, ghidra-mcp, libghidra, retdec, revng, rizin, rizin-ghidra and rz-ghidra. The original Ghidra repository remains at `9ba90c3b53870d33f6b36023a6237a4e30cc81f7`, without tracked or index changes. No original binary or existing analysis project was used as a mutable input.

## Content owners and implementation

One bounded Worker, `/root/native_layout_instructions`, changed exactly six files: host `.gitignore` and `AGENTS.md`; bridge `.gitignore`, `AGENTS.md` and `doc/win16-fmovmem.md`; engine `AGENTS.md`. The root retained relocation, the plan/log/changelog, integration, Git lifecycle and validation accounting.

- Host `AGENTS.md` now owns the macro workspace map, child instruction pointers and host-specific guide scope. Its original guidance from `## Work and references` through EOF is byte-identical to the intake version.
- Child guides own the bridge and engine's local source/build/test/patch navigation. They distinguish the editable direct-child engine from the build-managed `subprojects/ghidra-native` copy. They do not redefine the global resident workflow or dump compiler knowledge into prose.
- Host `/r2ghidra/` and bridge `/ghidra-native/` ignores prevent parent tracking. Existing managed-subproject ignores remain intact. No native ignore edit was needed.
- Product guidance now reads its local engine source from `./ghidra-native`, not the former sibling path. The managed destination, compiler/engine URL-revision wrap, runtime language path and post-setup procedure remain unchanged.

Ignore configuration and instruction/product documentation were checkpointed separately. Each repository's changes remain owned by its own Git history; no embedded Git entry was staged.

## Verification and frontier

- Native `rev-parse --show-toplevel`, branch, ancestry and remote checks passed for all three exact roots.
- `git check-ignore -v` selected host `.gitignore:2:/r2ghidra/` and bridge `.gitignore:1:/ghidra-native/`. Each child guide remained trackable from its own root; the existing managed engine ignore also remained effective.
- Parent `git ls-files --stage -- <selected-child>` inventories were empty. No selected child contents or mode-160000 entry was tracked.
- Complete changed-file sets stayed inside the declared six-file footprint plus root-owned records. Runtime/build/test source and the engine wrap did not change.
- Root read all three resulting guides through EOF, inspected the full content diff and resolved every local Markdown link. The original host guide body was compared directly to its intake Git object.
- All three product shell blocks passed bounded in-memory `bash -n`. Clone, build, install, cleanup and patch-application commands were not executed.
- The unchanged wrap still resolves native commit `8c0a00933c9d19d493c3858799bb3f8d0388f2fa` in the editable child. No managed engine copy was created by this task.
- `git diff --check` passed in each owner, including direct whitespace checks of new untracked guides before staging.

Live stale-scan roots were the three `AGENTS.md` files and the active product procedure. They contain no old selected absolute checkout paths or sibling source dependency. The active relocation plan and this log record source-to-destination dispositions and absence proof; those are not live checkout dependencies. The completed native-feature plan/log, previous review evidence, rollouts and private cache exports retain their historical paths and were not rewritten. Broader Ghidra/global/cache inventories remain outside the claim.

The Worker corrected one rejected patch hunk after rereading current bytes, and corrected expected `git diff --no-index` exit handling during a validation batch. Neither event changed runtime behavior or created a new proof mechanism. The complete targeted checks passed afterward.

## Review and operational consequence

The committed candidate is ready for the current-user-selected local Code Gate; no Code verdict exists for this layout task yet. The root retains host integration/evidence and scoped host guidance, bridge instructions/product path, and engine instructions as separate review partitions for one final reviewer synthesis.

Fresh-session automatic instruction loading was not executed. The user should open the next session at `/home/lucas/work/radare2` for the new principal workspace context; the current session started at the old Ghidra workspace. No runtime source, engine pin, Codex-global instruction, model/runtime setting, external repository, PR or installation was changed. No push was performed.
