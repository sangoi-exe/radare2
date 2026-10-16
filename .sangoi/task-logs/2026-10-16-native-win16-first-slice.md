# Native Win16 first-slice implementation checkpoint

Date: 2026-10-16 (America/Sao_Paulo).
Canonical Intent Contract: `.sangoi/planning/2026-10-16-native-win16-first-slice.md`.

## Authority and external result

The user selected radare2 + r2ghidra + ghidra-native in turn `01a145e8-2ded-7810-a5d4-e81c08ba394a` and confirmed the first-slice paraphrase and conditional execution after Plan Gate `PROCEED` in turn `01a145ea-0c5c-7891-86ae-7255c77ae054`. `/root/native_win16_plan_audit` returned `PROCEED` with complete Intent-field coverage and no material finding. The user-authorized checkpoint exception activated implementation; neither Gate was waived.

The authenticated GitHub actor was `sangoi-exe`, user ID 125471877. Before creation, all three source repositories were readable and the three destination names returned HTTP 404. The root created `sangoi-exe/radare2`, `sangoi-exe/r2ghidra`, and `sangoi-exe/ghidra-native` with `gh repo fork --clone=false --remote=false`. Post-write API reads verified each exact owner, `fork=true`, matching `radareorg` parent and push permission. No creation was retried, no upstream source was written, and no implementation commit was pushed.

Local selected checkouts remain under `/home/lucas/work/ghidra/.refs/`. Their branches are `win16-fmovmem`, `origin` is the corresponding user fork, and `upstream` is the original repository. No additional worktree or global installation was created. Recovery does not require deleting a fork; deletion is not authorized.

## Implemented owner changes

- ghidra-native `c958826f04a63f76c1e2eb517c3a1bbca9045656..8c0a00933c9d19d493c3858799bb3f8d0388f2fa`: durable selector-preserving native engine patch, exact `borland_fmovmem_16far` compiler prototype, and three focused owner tests registered in the current Meson test target. Imported source/spec/test followers remain baseline bytes in Git; the existing patch runner generates them once in private build exports. The call-only selector metadata family was not copied.
- r2ghidra `9b7969e190eda2e05023808a045fd1aa9627dbb7..cf1ca86cd8df32bf4feb44a8da26150e01e80a94`: exact loaded-native prototype selection before generic host CC conversion, two production-path regressions, and the existing shared Make/Meson engine wrap pinned to the user's native commit. `R2Scope.cpp` needed no change. Implementation is `47f249fa9386e4ce4f37093e3b22f1cdcb5d4f0e`; product procedure is a separate documentation commit.
- radare2 runtime remains at the inspected `2edc13b6f72854bd846c4dcab14acd06381dc71a` source behavior. Its existing type/function commands were sufficient for the explicit contract. Plan checkpoint `bc621d3c358ba9af77b926fb856e381e7154da21` and this factual documentary batch are the only host-repository changes.

The type record is `{ WORD offset; WORD selector; }`, not a flattened native pointer. The existing host parser placed the second WORD at offset 4; explicit `tk` member offsets produce the required native size 4 and offsets 0/2. This first slice supplies that known layout through the current type database rather than repairing the general parser. `afs` resets the host CC, so `afc` follows it. The procedure states these facts and requires a fresh disposable analysis session.

## Actual validation

Private baseline host: radare2 6.2.5 / ABI 156 from the inspected source pin. Tools: Meson 1.12.1, Ninja 1.13.2, GCC 13.3, system zlib 1.3. Builds used at most two jobs. Original executables were read and analyzed, not executed or opened for writing. Existing projects were not used as mutable inputs.

Evidence root: `/home/lucas/.cache/codex/native-win16-first-slice/run-JjzubK/`.

| Surface | Observed result | Evidence |
| --- | --- | --- |
| Native canonical patch replay | Full stack reapplies in a fresh export; replayed source equals tested source | `engine/logs/reapply.log` and Worker handoff |
| Native release build and suite | 9/9 tests passed, including three new segmented cases | `engine/build/meson-logs/testlog.txt` |
| Native negative control | All three new tests fail against pre-task libraries | `engine/logs/negative-baseline.log` |
| Compiler prototype | Semantic XML equals the qualified Ghidra reference | Engine Worker validation |
| Integrated private build | Plugin, DATA/x86 Sleigh targets and p-code XML executable build successfully | `integration/logs/{setup,build}.log` |
| Real SimTower production path | Process exit 0, empty stderr, full debug/function XML and C | `integration/results/qualified-v3/` |
| SimTower byte/instruction oracle | Complete 128-byte family; exact 89-byte/49-instruction core and 39-byte/20-instruction wrapper; native PUSH CS, near CALL to core, and terminal RETF | `qualified-v3/{acceptance,wrapper-acceptance}.json`, raw instruction/Sleigh outputs |
| SimTower effective ABI | Void; exactly three arguments; stack offsets 4/8/12, sizes 4/4/2; exact native model, far return 4 and no argument purge | `qualified-v3/simtower-{debug,function}.xml` |
| SimTower effective memory | All 17 retained LOAD/STORE addresses preserve two-byte selector/offset dependencies. Each of the three copy sites loads DS/source and stores the same value through ES/destination; selectors originate in the high WORD of the correct SS-relative records | `qualified-v3/acceptance.json` and full native function XML |
| Added bridge regressions | Native r2r: 2 OK, 0 failed, 0 skipped; both cases also fail against the unchanged baseline at intended boundaries | `integration/results/r2r-new-fixtures-v2.json`; `bridge/*-baseline.*` |
| Existing p-code fixture file | Native r2r: all 9 current cases passed, no failures or skips | `integration/results/r2r-full-pcode.json` |
| Existing native p-code XML test | 1/1 passed | `integration/logs/pcode-xml.stdout` |
| Johnny original entry | Real and Protected modes each exit 0 with empty stderr and nonempty C/native XML; five unresolved `func_0x0000ffff` calls remain | `integration/results/johnny/` |
| Dependency pin | Actual Make and Meson wrap consumers resolve the same user-fork URL and exact native commit; local Git resolves that commit | Bridge Worker N16-3P validation and `subprojects/ghidra-native.wrap` |

The retained raw native XML, not C snapshots or opcode counts alone, decided the helper acceptance. Two typed member-zero PTRSUB operations wrap SEGMENTOP rather than using it as the immediate memory pointer definition. Direct graph inspection confirmed that both still retain the selector; an initial immediate-op-only verification assumption was corrected without changing runtime code.

## Diagnostic and evidence boundaries

The first two integrated invocations had incorrect `SLEIGHHOME` paths and produced no native C/XML. The root inspected `SleighArchitecture::scanForSleighDirectories`: it accepts the Ghidra directory structure or a flat language directory, not arbitrary recursive processor roots. `qualified-v3` uses the verified flat x86 directory and is the valid replay; the earlier outputs are not passes.

The native r2r tool was built privately. Enabling its Meson option required explicit build regeneration before the named target became visible. The first fixture transport incorrectly put a quoted, space-containing load command in ARGS; the runner splits ARGS on spaces, so those attempts timed out without exercising the candidate. The corrected operational copies preserve `extras` path classification and unchanged canonical CMDS/EXPECT, except for an explicit plugin-load preamble and automatic-plugin suppression that select the exact private artifact. No wrapper or replacement fixture parser was introduced. Those corrected native runs passed.

Default staged `git diff --check` reports unified-diff context markers inside the new `.patch` file as trailing-space/space-before-tab issues. Those are patch-format context, not added C++ whitespace. The root checked actual added target-source lines and the Meson delta, and ran the staged check with those two patch-context classes disabled. The full canonical patch application and source tests passed. No Git attributes or whitespace policy were changed to hide the distinction.

No full `r2ghidra_types` fixture suite, all-processor suite, sanitizer build, whole-game analysis, existing-project round trip, selector-table reconstruction, complete NE/import/fixup parity, automatic family recognizer, GUI or MCP port was claimed. The known Ghidra preservation findings remain outside this slice and were not repaired.

The engine and bridge candidate commits are local only. The shared wrap correctly points to the selected fork, but a fresh network-only fetch of its new engine commit is not established before an authorized push. The product procedure uses the existing supported local subproject mechanism and discloses that publication gap. Publication, PR creation and global installation are not authorized by this task.

## Review handoff

This is an implementation checkpoint, not a Code Gate verdict or completed migration. The user selected the local Code Gate in turn `01a14642-d89c-78e3-bfc9-0ae04863cdd2` at `2026-10-16T16:49:11.041-03:00` (America/Sao_Paulo). The review object is the committed native/bridge change set plus the host's plan/evidence documentation and their direct causal followers. The root retained host integration and original-input verification; the two Workers owned disjoint native-engine and bridge footprints. The reviewer receives separate native-engine, compiler-prototype, bridge/dependency, and documentation/evidence partitions; the reviewer owns final semantic accounting and synthesis.
