# Native baseline remediation: implementation checkpoint

The current intent, authority, Scope, lifecycle, blocker and next action belong to [the canonical Intent Contract](../planning/2026-10-17-native-baseline-remediation.md). This log records execution evidence; it is not a completion verdict.

## Decision and review history

The first local Code Gate reviewed host `86f3a061549b728b35f39daef79823674f11e3b9`, bridge `cc51cbdbbb9d2067e103e67300d46bb578a13fd8`, engine `ac2f4fed9184b453f235f6250c14c0e2c23b35a5`, and MCP `a1e2fae58547132d155cb1312fd4fa22b1b6aa91`. Its final cumulative result was `DO_NOT_PROCEED`, with eight functional findings after reciprocal Senior/Claude examination, four complete source partitions and root analysis. That negative verdict remains accurate for that candidate.

The current user selected the three-owner correction at `2026-10-17T21:34:02.851-03:00`, America/Sao_Paulo, turn `01a14c6e-0b64-78b0-b4e8-ca0726dbe9d3`: `perfeito, vamos executar então`. The epoch-4 Strategy-reset Plan Gate returned `PROCEED`. Plan checkpoint `0d1e227e83728ab46a74a9ea9ae042ad1b03f772` recorded the selected route and bounded execution before implementation.

## Implemented checkpoints

| Owner | Commit | Change |
| --- | --- | --- |
| Host | `4ed4c93b43fbb62365149420629cf1bc45544dbd` | Qualify effective selected-bank maps, loader and saved byte alternatives, and replay prerequisites before analysis mutation. Strict snapshot uses the same effective-state owner; generic save retains its map inventory. Permission/bank/priority mutations advance the existing generation without changing map-reference timestamps. |
| Bridge | `820f5af38191e5a836f426cf14eafcd05d6fc2a9` | Preserve recursive identities until ordinary destruction, but retain the first union-construction failure and refuse subsequent factory resolutions before native or bridge cache lookup. |
| MCP | `333e07cf36304c8e9c8f0424b9479e9f7c0624cf` | Move endpoint/mode to selected `RadareState`; probe reconnect before publication; free only the selected endpoint on close/fini/eviction. Prepare raw initial mapping before normal-load completion. |

The engine and bridge pin remain `ac2f4fed9184b453f235f6250c14c0e2c23b35a5`. No public host ABI, project format, protocol, second parser, independent cache, target manager or compatibility layer was added. MCP product documentation is in its implementation commit because it describes that same target-lifecycle and raw-opening change. Other documentary bookkeeping is separate. Every new commit has the required Codex co-author trailer; no push or global installation was performed.

The retained large test files remain at their existing canonical test owners. New cases protect the demonstrated owner interactions and reuse their current fixtures/dispatch helpers; extracting another transport/test owner would add registration and setup without reducing the admitted complexity.

## Validation evidence

### Host

Private source/build/install: `/home/lucas/.cache/codex/radare2/m12-host-WFS7Cw`.

- Root Make build and install exited 0: `build-final.log`, `install-final.log`.
- Final private-fixture offline command suite passed 73/73: `newprj-private-fixtures-final.log`.
- Trycatch passed 8/8: `trycatch-final.log`.
- Eight active IO follower checks passed: `io-final.log`. The existing disabled `test_r_io_cache` body is not substantive cache coverage.
- New production cases observe relocation-overlap success, pre-mutation empty-cache refusal, removed loader-byte refusal, unreadable/inactive-map refusal, strict mapless-save retention, and restored-read-mode qualification.

The first expanded suite passed 71/72; exact RWX equality incorrectly rejected the established readable `r-x` to `r--` reopen. Qualification now requires readable effective state rather than identical execute bits. A later production witness found that restoring a saved disabled-cache-read mode could hide required loader bytes. The final preflight covers that same effective-state frontier; the final suite passes 73/73. No fully correct historical strict-restore baseline existed; reviewed source and explicit current contract anchored these corrections.

### Bridge combined with final host

Private tree: `/home/lucas/.cache/codex/radare2/M14-union-DKh75l`.

- Root reconfiguration explicitly set Meson's cached `pkg_config_path` to the final host's `install/lib/pkgconfig`; the dependency introspection contains the final host path. Merely replacing the environment initially retained the old cached dependency, which was detected before compilation.
- Root rebuild and pcode test exited 0: `root-new-host-build.log`, `root-new-host-pcode.log` (1/1).
- Root type suite passed 64/64: `root-new-host-types-corrected.log`. It ran from the bridge private `source/test` fixture owner with final host `R2R_RADARE2`/`R2R_RASM2` and offline mode. The first root run incorrectly used host test fixtures and failed on missing bridge-specific inputs; no expectations changed.
- The real-factory probe catches the initial invalid-union error and observes ten later resolutions refuse with the same error: `factory-probe.log`. It covers cached, qualified, typedef, dependent-struct and array resolution without deleting native graph objects.
- The original invalid case reproduces on the baseline; two valid controls pass and two new invalid-publication cases fail there. Valid recursive union identity and prior recursive-struct cases pass on the corrected implementation.

The private plugin uses unchanged all-language inputs from the previous M11 stage matching the exact engine pin. An initial x86-only run had missing-language failures; the matched-language run closed that environment gap.

### MCP combined with final host

Private source/build: `/home/lucas/.cache/codex/radare2/m13-mcp-target/build-Y2YCM0`.

- Root clean/configure/build exited 0 against the final host: `root-new-host-clean.log`, `root-new-host-configure.log`, `root-new-host-build.log`.
- Final root `make test` exited 0: `root-new-host-tests-final.log`. It includes `test.sh`, `test2.sh`, HTTP remote/framing tests and the JSON number/log Python suites.
- Actual HTTP tests cover two `X-Session-ID` targets, failed connection/reconnect, remote catalog isolation, selected close, LRU eviction, default `-u`/plugin proxy and new-session noninheritance. Controlled Frida metadata establishes local routing, not real attachment.
- The raw explicit-base case saves a comment and virtual edit, closes, reopens with identical parameters, restores, and observes recovered mapped bytes/comment.
- Direct controls preserve ELF virtual entry behavior across two bases and WAD physical behavior. Idle-timeout-specific eviction and sanitizers were not separately executed.

The default path checker rejects lexical hidden paths without an explicit root. Therefore tests physically stored under `.cache` need a visible pathname, without weakening production checks or moving artifacts outside task cache. The passing Worker and root invocations alias both the private build cwd and temporary root through open directory descriptors, using logical `/proc/<parent-shell-pid>/fd/8` and `/proc/<parent-shell-pid>/fd/9` paths. All bytes remain physically task-cached. The root final run used shell PID `3668492`; descriptors closed on command completion. The initial root run had only a physical cache TMPDIR and failed at fixture admission; aliasing only TMPDIR then exposed the same issue in `TEST_OBJECT="$PWD/src/r2mcp.o"`. The exact prior passing invocation established the missing logical cwd. No source/test expectation or path policy was changed to obtain the final pass.

Native comparisons matched all 22 live changed implementation/test/product-doc files with their private validation sources (9 host, 10 MCP, 3 bridge). Exact stale scans of MCP `src` found no remaining `ss->http_mode`, `ss.http_mode`, `ss->baseurl` or `ss.baseurl` target ownership. Server supervisor/listener/configuration fields remain at their selected owners. All staged patches were inspected and passed `git diff --cached --check` before their exact commits.

## Operational incident and deferred observations

An initial host test fixture copy preserved a symlink into `/home/lucas/.cache/codex/native-transfer/fixtures-projects-pLNxIK/bins`. The first r2r invocation attempted its default Git pull and failed for missing tracking. The fixture owner's `.git/FETCH_HEAD` has matching invocation-time mtime `2026-10-17T21:49:38.003936266-03:00`; a bounded timestamp scan found no other newly modified Git metadata, but no preimage exists and no complete unchanged-metadata claim is made. The file was not restored. The binary fixture remained byte-identical. Only the new task-owned symlink was replaced by a dereferenced private fixture copy, and final tests ran offline.

Deferred observation: unchanged MCP `src/dsltest.c:63-67` empties an unquoted value before scanning it. The same unquoted `/bin/ls` DSL request fails with both prior and final hosts; `test.sh` prints that result without asserting successful opening. This is outside the current correction. The final `make test` exit does not establish unquoted DSL correctness. A bounded follow-up belongs to the DSL parser and its existing test owner.

The source-backed quadratic recording/comparison concern has no measured admitted-workload failure; no performance subsystem or benchmark framework was added. Existing publication-failure evidence remains at the M05 production observation; no duplicate proof owner was added.

Native Windows, hosted CI, network-only pin fetching, real Frida, and fresh epoch-4 game-specific smokes remain unobserved. Earlier engine 17/17 and M11 game observations remain historical evidence for unchanged inputs, not newly executed claims. Original game data was excluded from epoch-4 validation. The unexpected earlier Claude plan `/home/lucas/.claude/plans/independently-review-the-following-fluttering-octopus.md` remains outside the reviewed object and was not used as evidence.

## Review transport boundary

At the implementation checkpoint, no new Code Gate had launched. At `2026-10-17T21:26:23.891791575-03:00`, after this session started, the default resident contract and Senior role changed from the injected source-partition procedure to Senior/Claude source pairs plus integration. The lead template changed at `2026-10-17T21:27:07.874911920-03:00`. The reload requirement was accurately reported as an instruction-content boundary, not a runtime-setting warning.

The current user then requested using the new Gate without reload at `2026-10-17T22:09:51.031-03:00`, source rollout line 1442: `se tu conseguir usar o novo gate sem o reload seria melhor`. The canonical plan records this narrowly scoped operational override. Fresh reviewer instances can receive the current registered role contracts; the lead does not claim its configuration was retroactively reloaded. The new Gate retains all source/integration pairs, reciprocal review and final cumulative authority. No Gate verdict or final-review obligation is overridden. Task completion and Closeout remain unclaimed pending that review.
