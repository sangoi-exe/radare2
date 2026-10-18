# Native baseline remediation: implementation and review

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
- The original invalid case reproduces on the baseline; two valid controls pass and two new invalid-publication cases fail there. The direct self-pointer union identity control and prior recursive-struct cases pass. Those controls do not cover the valid mutual recursion later identified as B1.

The private plugin uses unchanged all-language inputs from the previous M11 stage matching the exact engine pin. An initial x86-only run had missing-language failures; the matched-language run closed that environment gap.

### MCP combined with final host

Private source/build: `/home/lucas/.cache/codex/radare2/m13-mcp-target/build-Y2YCM0`.

- Root clean/configure/build exited 0 against the final host: `root-new-host-clean.log`, `root-new-host-configure.log`, `root-new-host-build.log`.
- Final root `make test` exited 0: `root-new-host-tests-final.log`. It includes `test.sh`, `test2.sh`, HTTP remote/framing tests and the JSON number/log Python suites.
- The optional real MCP→bridge native-decompile-status witness was explicitly skipped at log line 304 because its plugin, language and SCRANTIC inputs were unset. The observed combined checks are host↔bridge and host↔MCP, not fresh execution of that MCP→bridge witness.
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

The current user then requested using the new Gate without reload at `2026-10-17T22:09:51.031-03:00`, source rollout line 1442: `se tu conseguir usar o novo gate sem o reload seria melhor`. The canonical plan records this narrowly scoped operational override. The root launched fresh matching reviewer instances and retained all source/integration pairs, reciprocal review and final cumulative authority. No retroactive configuration reload, Gate-verdict override or final-review override is claimed. The outcome below records the completed review.

## Epoch-4 paired Code Gate

The authorized same-session Gate completed at `2026-10-17T22:55:28.163-03:00`, America/Sao_Paulo. The integration Senior `/root/gate_integration_senior` issued the single final `DO_NOT_PROCEED`, route condition `user-decision`, for host `40e24b6cfc2fa46dbbcb918349046c59fed232ce`, bridge `820f5af38191e5a836f426cf14eafcd05d6fc2a9`, MCP `333e07cf36304c8e9c8f0424b9479e9f7c0624cf`, and unchanged engine/pin `ac2f4fed9184b453f235f6250c14c0e2c23b35a5`. Source ranges start at the epoch-3 candidates above. Current-session rollout `01a14c49-9c6e-7df2-a1eb-2c29aaec3480` line 2030 retains the actual final report. No runtime bytes changed during review.

| Required responsibility | Actual Senior / Claude pair | Coverage |
| --- | --- | --- |
| Host source and direct followers | `/root/gate_host_senior` / `/root/gate_host_claude` | Nine changed source/test files; independent initial and reciprocal examination complete; no material delta finding. |
| MCP source and direct followers | `/root/gate_mcp_senior` / `/root/gate_mcp_claude` | Ten changed source/test/product-documentation files; independent initial and reciprocal examination complete; no material delta finding. |
| Bridge source, producers and native consumers | `/root/gate_bridge_senior` / `/root/gate_bridge_claude` | Three changed files; independent initial and reciprocal examination complete. One bounded continuation closed Claude's host-producer read gap. B1 retained. |
| Integration, task documents and seams | `/root/gate_integration_senior` / `/root/gate_integration_claude` | Four changed task documents, source-pair adequacy and cross-component seams; both initial and reciprocal reports complete before root analysis and formal Senior synthesis. |

All required semantic surfaces were reviewed. The closure examined 17 actual source/integration reports and replies plus root analysis. All source assignments were registered siblings with overlapping initial work. Native launch records prove roles, identities and timing, but their message fields are opaque transport tokens. Root corrected its initial assertion that those fields exposed plaintext briefs. Actual reports and root attestation support equivalent responsibilities/evidence; no concrete mismatch was found. No decryption, replay ledger or new proof owner was added.

All successful Claude assessments reported CLI `2.1.302`, observed `claude-opus-5-5`, exit 0 and no permission denials. The integration initial invocation first hit an OS argument-length rejection before Claude started, then a stdin timeout before prompt ingestion; the complete same-model read-only invocation subsequently succeeded. These transport failures were disclosed and were not treated as review results. No reviewer created a plan file, source change, build, test or probe in this Gate.

### Root analysis and finding disposition

B1 is a `verified_defect` established by a direct source path at `r2ghidra/src/R2TypeFactory.cpp:491–494`, not an executed reproduction. The valid finite graph `union B; union A { union B *p; }; union B { union A a; uint64_t value; };` has eight-byte unions on the qualified x86-64 target. Resolving `A *` eagerly constructs `B`, finds incomplete `A` for `B.a`, rejects that member and latches the error. Resolving `B` first can complete both. The host preserves the type spellings/extents, and existing `tk` dispatch provides ingestion without a C-parser assumption. Root independently checked current and baseline factory code, the producer, native interning/field completion and that write route. The new rejection violates preservation of legitimate recursion. Successful exact-candidate resolution with both completed identities would falsify the finding; no such run occurred.

The recommended closure is `modify_existing_owner`: correct construction ordering or incomplete-state classification in the existing factory, retaining failed-construction refusal and native lifetime ownership. Wholesale guard removal reopens the invalid self-by-value case. The current user has not selected the substantive correction or accepted its risk. No automatic correction was applied.

The source-confirmed post-`aaa` limitation is separate. Non-debug analysis that reaches successful `aaft`/`aeim` stack-map creation advances `io->mts`, invalidating the load-time baseline even when `io.va` is restored. Restore invalidation is inherited; strict publication now fails earlier for that unqualified state, consistent with refusing unrestorable snapshots. Not every `aaa` or `list_functions` call takes that path. The practical workflow was not executed. The unobserved workflow is a `proof_gap`; supporting snapshots through analysis-created mappings remains a current-user product/route decision, not an authorized recertification or special case.

The validation-wording qualification is a `bundle/proof correction`: distinguish pairwise component validation from the skipped MCP→bridge witness and limit the recursive-control claim. Recording the actual negative Gate result is `bookkeeping memorialization`. No pass count or runtime evidence changed. Default-proxy ordinary-log asymmetry and inherited native→remote→close local-core retention remain nonblocking observations; native failure status and JSON2's separate diagnostic owner remain intact. Inherited struct/typedef concerns and unobserved post-catch serialization are not additional verified defects. The corrected native source has typedef-completion callers in struct, union and code decode paths, not only struct decoding.

Regression recovery boundary: the original R1 left a failed interned union usable; M14 added the failure latch and incomplete-member guard; the Gate then found B1, where that guard breaks valid recursion. This is a fix-breaks-another-surface stop. The comparison baseline is bridge `cc51cbdbbb9d2067e103e67300d46bb578a13fd8`; its exact B1 behavior is source-backed, not executed. Retained learning is that the latch closes post-failure reuse, while temporary incompleteness alone does not identify an invalid value cycle. The closure frontier is this factory's construction order and its direct union tests, not general struct/type-graph validation. No next correction is authorized. The first recommended verification, after the current-user decision, is the exact mutual-recursion graph against candidate and baseline with completed sizes and identities observed before another patch.

The matched transition requests the current user's decision and retains Implementation. The canonical plan is on hold. Task completion, Closeout, residual-risk acceptance, further source changes and another Gate remain unclaimed. The local runtime candidates are unchanged; the later documentation checkpoint only memorializes this result.

## Current-user remediation decision and pre-correction proof

The current user confirmed the recommended bounded route with `confirmo` at `2026-10-17T23:09:44.797-03:00`, America/Sao_Paulo, turn `01a14cc5-a8cd-7dc0-afbb-936e7cf5409b`, current-session rollout line 2108. The selected remediation keeps the current factory owner, native lifetime ownership and terminal failed-construction refusal. It corrects B1 only after comparison with the known baseline. The same decision authorizes observation of `aaa` followed by strict snapshot, but not a change to loader-baseline qualification.

Root executed the exact B1 metadata through the real bridge plugin and matching host/language inputs in four fresh processes. Current bridge `820f5af38191e5a836f426cf14eafcd05d6fc2a9` returns `{"errors":["Ghidra Decompiler Error: Failed to construct complete union B"]}` when `A *` is resolved first. Resolving `B *` first succeeds. Baseline bridge `cc51cbdbbb9d2067e103e67300d46bb578a13fd8` succeeds in both orders. Each successful run exports `A` as ID `0xc000000000007b41` and `B` as ID `0xc0000000feab85e9`; both are size-8 unions and retain fields `p` and `a`. This production-path execution closes the source-only uncertainty and anchors the correction to the known baseline.

The host observation used final private host `/home/lucas/.cache/codex/radare2/m12-host-WFS7Cw/install` and private `anim8.exe`. The control strict snapshot succeeded and wrote a 131955-byte artifact. In a fresh process, `aaa` added map `mem.0x100000_0xf0000`; `prj snapshot` then reported `Cannot save snapshot: requires a restorable read-only original and valid virtual edits`, returned through the command's refusal branch and created no artifact. Evidence is retained under `/home/lucas/.cache/codex/radare2/remediation-b1-aaa-0zx0igpp/`. This observation confirms the disclosed Route A limitation. It does not classify the refusal as a new defect or authorize baseline recertification.

Lifecycle is now `Remediation review`. The next correction frontier is only the existing bridge factory and its direct type regression file. The first verification is the exact mutual-recursion graph in both root orders together with the invalid-union and post-failure-latch controls. The host, engine, MCP, project codec and baseline qualification remain outside this correction.

## B1 remediation checkpoint

Worker `/root/remediate_bridge_union` changed only `r2ghidra/src/R2TypeFactory.cpp`, `src/R2TypeFactory.h`, and `test/db/extras/r2ghidra_types`. The bridge commit is `a718a85e4a7a51969a5980b0acb2a268e8e147e2`, with the required Codex trailer. The other three repositories remained unchanged during source implementation.

The existing CString parser now allows a union pointer member to reference a native forward union identity without eagerly completing the pointee. The containing union establishes its fields and extent first. The factory then completes deferred pointees that are not already under construction. Native lookup completes an inactive forward union before returning it. The change retains the incomplete/zero-size guard for by-value members, factory-owned native identities and the terminal first-error latch. It adds no persistent pending registry, graph validator, fallback, public API, engine change or new owner.

Fresh validation root: `/home/lucas/.cache/codex/radare2/remediate-b1/M17-20Xr4v`.

- The exact mutual-recursion regression passes 1/1 and proves both root orders export size-8 `A` and `B`, stable IDs, `A.p` as `B *`, `B.a` as `A`, and scalar `B.value`. The same test fails on the pre-fix candidate and passes on the baseline.
- Four directly affected existing union controls pass 4/4. The full qualified bridge type suite passes 65/65. P-code XML passes 1/1.
- Zero-size and overflowing-count production controls still refuse.
- The original same-factory failure probe refuses all ten later resolutions. A second probe proves an invalid deferred pointee preserves its first error and also refuses all ten later resolutions, even after the outer union completed.
- Meson used the final private host through explicit `pkg_config_path`; all three live changed files matched the validated private source. Root inspected the complete diff, `git diff --check` passed, and root independently reran both B1 root orders against the built plugin with the expected size-8 identities and fields.

The implementation closes the exact two-union witness. Gate acceptance remained pending at this checkpoint. General struct/typedef-cycle repair, post-`aaa` qualification, engine changes, fresh MCP→bridge execution, Windows, hosted CI, real Frida and game runs remain outside or unverified as previously classified. The next completion authority was the default local `Remediation delta review` on the committed candidate.

## B1 Remediation delta review

The paired `Remediation delta review` completed at `2026-10-18T00:07:19.455-03:00`, America/Sao_Paulo, current-session rollout line 2745. Integration Senior `/root/gate_integration_senior` issued `DO_NOT_PROCEED`, route condition `user-decision`, for host `edfb4a701b287515c7d715805c1bff6422803cac`, bridge `a718a85e4a7a51969a5980b0acb2a268e8e147e2`, unchanged MCP `333e07cf36304c8e9c8f0424b9479e9f7c0624cf`, and unchanged engine/pin `ac2f4fed9184b453f235f6250c14c0e2c23b35a5`.

The source pair `/root/gate_bridge_senior` and `/root/gate_bridge_claude` completed independent initials, both reciprocal replies and one bounded Claude follower continuation. The integration pair completed independent initials and both reciprocal replies. All required three bridge files, four task documents and direct lookup/caller/lifetime seams were reviewed. Broader native recovery/output behavior remains unobserved; no universal claim is made. No reviewer changed files or ran builds, tests or probes.

The exact original B1 graph is closed by execution. The review found B1-R, a remaining `verified_defect` established by direct source rather than runtime execution. For `union C; union B { union C *p; }; union A { union B b; }; union C { union A a; uint64_t value; };` with all extents 64 bits, root `A *` completes `B` and immediately drains deferred `C` while enclosing `A` remains incomplete. `C.a` retrieves incomplete `A`, the by-value guard rejects it and the factory latches `Failed to construct complete union C`. Root `C *` instead permits completion. This uses only direct union names and the new deferral/drain path. The failure already exists at `820f5af`, remains a regression against `cc51cbdb`, and violates preservation of legitimate recursive types.

The falsifier is an unchanged-candidate root-`A *` run that exports complete size-8 `A`, `B` and `C` with the stated fields, or evidence that the host metadata/lookup path cannot reach the source sequence. Neither exists. The recommended closure is another `modify_existing_owner` correction that defers work until required enclosing by-value layouts complete, while retaining the guard, native ownership and terminal latch. No graph owner, engine change or guard removal is justified. The current user has not selected this correction or accepted the limitation.

This is a repeated same-surface remediation stop. M14 closed failed-type reuse but exposed B1; M17 closes the exact two-union witness but leaves B1-R in the same construction-order class. Retained learning is that immediate-container completion is insufficient when a by-value outer union is still active. No further patching is authorized. If the user selects correction, the next verification is the exact B1-R graph against `a718a85` and `cc51cbdb` before another edit.

The review classified document changes as nonblocking `bundle/proof correction` and `bookkeeping memorialization`: limit closure claims to the executed two-union witness, record B1-R, historicalize superseded M14/M15 state, describe the containing union as immediate, avoid blanket baseline claims for valid struct/typedef hypotheses, and describe each probe as ten subsequent refusals. The current plan is on hold in `Remediation review`; Closeout, risk acceptance, further execution and another Gate remain unclaimed.

## Confirmed resolution-class revision

The current user asked whether another local correction was the best route. Root kept the task read-only and compared the candidate and known baseline through the real plugin, using the same final private host and matching x86-64 language. B1-R now executes: candidate `a718a85` rejects root `A *` with `Failed to construct complete union C`, while root `C *` and both baseline `cc51cbdb` orders return complete size-8 graphs. The demonstrated typedef-pointer variant `BP = B *`, used as `A.p`, also rejects root `A *` on the candidate while the other current order and both baseline orders succeed. The original invalid extent has the opposite discriminator: the candidate refuses and the baseline exports `U` as a size-zero union. These observations were returned in tool stdout in the current session; no new helper, fixture or cached report was created for the reassessment.

Retained causal learning: the local drain solves only immediate-container ordering. The private `deferredUnion` output is not carried by `queryR2Typedef`, which invokes the ordinary CString path. A rollback would recover valid recursion but discard failed-publication protection. Another drain-only patch would leave the executed typedef case outside its mechanism. The selected closure must replace this local mechanism inside the existing owner, not add singular exceptions or a separate graph manager. Current native APIs already provide forward identities, pointer construction and field completion.

The root presented this revised result and boundary. The current user selected it with `perfeito, pode executar assim então` at `2026-10-18T00:19:55.091-03:00`, America/Sao_Paulo, turn `01a14d05-e6a3-7cf2-90cb-f7a15cff45b3`, current-session rollout line 2922. The canonical plan records a bounded Scope revision to include the demonstrated typedef follower while all six strategy boundaries and epoch 4 remain unchanged. The next action is the required Intent Contract audit, followed by one Worker construction-resolution replacement and direct proof. There is no user pause, unresolved material choice, risk acceptance, host qualification change or Gate override.

The Scope-revision audit on `/root/native_baseline_plan_audit` returned `PROCEED`, with complete Intent Contract coverage and no material findings. The root resolved the registered `publish-plan-locator-and-enter-implementation` transition and published the existing locator before source dispatch. The root also replaced the stale earlier three-owner execution list, as the auditor's nonblocking documentary note requested. This is active Implementation for the selected M18 result, not Code approval or acceptance of the earlier failures.
