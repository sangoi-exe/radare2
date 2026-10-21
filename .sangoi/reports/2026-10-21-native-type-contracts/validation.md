# Native type-contract validation

This report records the native type-contract qualification and the subsequent focused SIGNATURE-F4 correction. The final [local review](review.md) returns PROCEED for the admitted correction and closes F4. It is not a whole-decompiler correctness claim or rebuild-ready game source. The original executables were opened for analysis without execution, write mode or saved-project mutation.

## Focused SIGNATURE-F4 correction

Host runtime `4b8fc8f5f67b9571117e721d2fac5f74dd2f45cb` changes only prospective-name selection in `libr/anal/fcn.c` and its direct function/Core regression test. Peer `link`/`fcnlink` references reserve a name even when the referenced type is absent. Deletion, SHARED updates, standalone `afn`, public APIs and ABI157 remain unchanged. The source/test bytes match the fresh canonical Make build at `/home/lucas/.cache/codex/radare2/native-type-contract-2026-10-21/r-f4-dormant-lzUGvC/`; `install/` is its private SDK.

| Surface | Current observed result | Evidence under that directory |
| --- | --- | --- |
| Baseline | Both old-runtime CLI witnesses reproduce activation; qualified unit run has43 retained passes and the new dormant-binding failure | `baseline/`, `baseline-unit-qualified.log` |
| Host function/Core units | 44/44, including both binding variants and all43 retained controls | `unit.log`, canonical build/install logs |
| Exact CLI witnesses | Both exit0 with empty stderr; peer remains void/unknown and its binding stays intact | `current/` |
| Primary host CLI | 54/54 | `integration/host-primary.json` |
| Bridge type files | One complete94/94 run using the unchanged bridge/plugin languages with the new ABI157 SDK; no compositional-count claim is needed for this run | `integration/bridge-types.json`, `bridge-linkage.log` |
| Native MCP signatures | 54 requests across five sessions: retained22, valid-link eight, valid-fcnlink eight, dormant-link eight, dormant-fcnlink eight; unique response IDs, no notification responses and all processes exit0 | `mcp/proof/results.json`, complete requests/streams/status/linkage |

The MCP source is unchanged at `51df6714dc5b40822ab421ac685caa4d3da2a0ae` and was rebuilt against the corrected SDK. The bridge/engine source and processor inputs are unchanged at the versions below; the existing plugin was dynamically linked to the new private host libraries for the current94-case run. The new unit's initial `afb+` fixture setup was invalid in the unit harness and was corrected to canonical Analysis blocks with mapped real return bytes before applying the runtime fix. No production failure was hidden by that setup correction. Other earlier host units, native preparation/algorithm tests and original-game captures below remain retained evidence of their named inputs; they were not all rerun for this private selector change.

## Broader remediation baseline and runtime

| Component | Committed runtime input |
| --- | --- |
| Host | `f1d71fc9c86777113c2565f7de8b815b53698505` |
| Bridge | `82d150dcbfffc0f03a91a3e4c3debde8dfd803a5` (runtime `40dbd80`) |
| Native engine | `6f7438da7a942c7a1dd728e2dda08faabe8644b4` (runtime `6a4d8bf`) |
| MCP | `51df6714dc5b40822ab421ac685caa4d3da2a0ae` |

Later host commits containing only these records do not change the tested runtime. The bridge wrap selects the listed engine exactly. ABI157 requires rebuilt matching callers; no compatibility adapter, global installation or push is part of this validation.

The private runtime is `/home/lucas/.cache/codex/radare2/native-type-contract-2026-10-21/remediation-runtime-t4sm1del/`. `install/` contains the host SDK, `bridge/build/libcore_r2ghidra.so` is the plugin, `bridge/languages/` selects matching DATA/x86/AARCH64/PowerPC specifications, and `mcp/source/src/r2mcp` is the server. Linkage logs show the private host libraries without sanitizer libraries. Builds used canonical host Make and bridge Meson targets, not isolated copied production fragments. QJS and ZIP were excluded from this private host build, as in the earlier qualified SDKs. The host archive began at `e73b35b4`; all16 changed runtime/test files were compared byte-for-byte with the committed `f1d71fc9` candidate. `host-base.txt` retains the archive base, while `host-ref.txt` records the validated equivalent runtime commit. The initial candidate and its evidence remain in `final-runtime-2p16mosx/` and Git history.

## Broader baseline proof

| Surface | Observed result | Evidence under the private runtime |
| --- | --- | --- |
| Host units | 190 passed across15 suites: declarations15, types44, functions43, variables7, JNI2, DWARF7, generic Borland11, BCC20 eight, SimTower four, BCC seven, TASM12, contract four, TLINK401 five, TLINK51 five, profiles16 | `host/root-unit-results.json`, `host/unit-*.log`, `rsig-validation-6VRVlO/`; sibling `r-fmt-validation-jiIw9sjt/` and `r-borland-validation-eYcNUG1k/` |
| Host CLI | 54 primary controls and42 follower controls passed; these sets overlap and are not96 unique tests | `host/primary-cli-final.json`; sibling `r-follow-proof/` |
| Bridge type files | Compositional94/94: full run93/94, then the sole corrected callback oracle1/1; all other93 inputs and runtime bytes remain unchanged. Includes all original91 controls; no timeouts. | `bridge/suite.json`, `callback-corrected*`, `combined-accounting.tsv`, equality records |
| Bridge test followers | 12/12: complete ten-case `ghidra_types` plus the exact PPC fixture and synthetic fmovmem controls | Sibling `R-BEX-FTKO9m/final.*` and full-C/XML premise probes |
| Native | 54/54 native controls, ten preparation controls and p-code XML test passed in the matching combined build | `bridge/registered-tests.log`, `bridge/build/meson-logs/testlog.txt` |
| Preparation reuse | Matching bounded build passed after language generation | `bridge/reuse.log` |
| Typed native MCP signature boundary | 38 requests across three sessions: retained22 plus two eight-request shared-link isolation cases; unique responses and no notification responses | `mcp/signature-proof/` |
| Original-game MCP tools | SimTower 18 and Johnny 10 requests, unique responses, no tool errors, both processes exit0 | Retained `mcp-*` files in each game directory |

Earlier instrumented slice builds cover the actual host/bridge corrections. B4's full instrumented run passed 89/91; one selector-only assertion correction passed its separate rerun. Combined unique coverage was90 passing cases plus the known pre-bridge PowerPC signed-shift UB. The later normal91/91 run closes functional coverage, not that UB. Native engine objects were uninstrumented in combined sanitizer runs; do not claim whole-engine sanitizer cleanliness. Detailed slice results and failing attempts remain in the [execution projection](../../planning/2026-10-21-native-type-contract-corrections-microtasks.md).

Operational setup failures remain recorded: configure removed an older-timestamp plugins.cfg; unit paths and the DWARF working directory were initially wrong; an initial r2r help lookup lacked the private library path; an unnecessary fixture symlink was refused because the archive already contained the tracked fixtures. Corrected canonical commands passed. No fixture or original was overwritten to fix those setup errors.

The remediation's first native full-action test exposed an earlier unlocked-symbol cleanup path; the existing-owner correction passes the same full-action test and retained controls without new native representation. The bridge callback probe first used a selector parsed as redirection, then an incidental XML-list count that included both the callback and call-site override. The final test checks the actual open callback owner, call and retained metadata. Root's first primary CLI invocation used the wrong fixture directory and missed the deeper Swift case; the corrected54-case run exposed only two stale shared-edit assertions. R-BEX retained its unique custom-global test by removing the pre-existing inferred flag before installing the intended explicit record, and corrected its ordinary-alias pointer premise without changing the valid incomplete-tag header. These are recorded test/setup corrections, not silent runtime fixes or waived failures.

## Original-backed observations

The game directories retain direct CLI C, complete architecture/function XML, instruction JSON, raw instruction p-code, loaded binary information, language selection, profile output, exact invocation arguments, diagnostics and exit status. The MCP directories' streams are copied byte-for-byte from the actual server runs, with original requests and invocations. These are generated evidence, not maintained source or golden expectations.

Source and hand-maintained documentation pass whitespace checks. The unmodified generated C/p-code/profile output retains its emitted trailing spaces and blank final lines; the full staged whitespace check reports those artifacts. The evidence was not reformatted to hide that distinction.

Both originals load as x86/16 NE (`ij.bin.bintype == "ne"`). The explicit language setting is empty; automatic matching reports `x86:LE:16:Protected Mode:`. Context XML records `protectedMode=1`. Current invocations set `LD_LIBRARY_PATH` to the private `install/lib` and `SLEIGHHOME` to `bridge/languages` before loading the plugin; the earlier absent-global-Sleigh startup diagnostic is no longer present. No global installation is needed. An initial remediation checker incorrectly expected `ij.bin.class == "NE"`; the actual `class` is empty. That checker was corrected to the actual loader field and reused the already completed SimTower capture, without repeating an original-file action.

SimTower's current128 mapped bytes at `0x110e8` equal the qualified move-core/wrapper bytes in the product procedure. The captured core uses `borland_fmovmem_16far`; its source/destination records occupy stack offsets 4/8 and its two-byte count offset 12. The wrapper uses `borland_fmemmove_16far`, returns `FarAddress16`, and the complete function XML passes the source/destination/count operands to the core in the correct order before returning the destination. The four-byte record retains independent two-byte offset/selector fields. Raw p-code retains symbolic SS for stack accesses, the PUSH CS at `0x11156`, near CALL at `0x11157` to `0x110e8`, and RETF at `0x11140`. Other captured targets are `0x10006→0x4f02d7`, `0x4f02ee→0x11a55` and `0x4f00a1→0x4f3649`.

Johnny's qualified F_SCOPY at `0x1033a` retains its explicit `borland_f_scopy_16far` model, FarAddress16 arguments and extrapop 12. The captured far CALL at `0x100b0` targets `0x20000` and preserves selector-bearing stack operations. These are analysis-coordinate observations, not Windows runtime selector values.

MCP returns complete C pages and parseable complete native XML for those three functions. All nonblank C lines match direct CLI output after removing per-line surrounding whitespace; the MCP response removes indentation, so the responses are not byte-identical raw C. The direct CLI files preserve raw formatting. An initial exact-text comparison failed for that formatting difference; it is not reported as a passing byte-equality check. Raw p-code text can contain process-dependent address-space handles, which are not game addresses.

The three current direct C files, all three context XML files, signatures and SimTower helper bytes are byte-identical to the initial candidate's captures. Two full-function XML files differ only in the observed process-dependent address-space constants; the wrapper XML is byte-identical. Current raw captures and both MCP streams (28 requests total) were copied without reformatting into the existing56-file durable capture set. Each original executable was byte-compared before and after its read-only observations.

Profile messages count qualified facts, including unchanged facts, not a claim that every possible contract applied. The SimTower refusal at `0x131af` remains visible in CLI and MCP diagnostics; no signature or profile override was used to hide it.

## Unresolved observed rendering limitation

The Johnny F_SCOPY odd-byte loop prints dereferences through `uint far *`, like the word loop, without narrowing casts. Actual live native XML keeps the MOVSW transfer at `0x10349` as two-byte LOAD/STORE and the MOVSB transfer at `0x1034d` as one-byte LOAD/STORE (`1033a.function.xml`, byte value reference `0xf1`, LOAD/STORE unique IDs `0x53`/`0x55`). Address operands are four bytes; address width is not transfer width. Thus native operations retain the distinction, but the printed dereference does not faithfully express it.

Bounded read-only comparison with the retained matching `B1-resume` plugin, its language bundle and its earlier host SDK reproduces the same C and both access widths. This proves pre-B4 existence, not pre-task origin or correctness. No further correction or full-game C approval is claimed. This observation must remain visible in review and handoff rather than being hidden by successful transport or test counts.

## Proof limits

The result does not qualify global installation, remote acquisition of unpublished pins, whole-project persistence/file switching, complete game decompilation, historical Borland source compatibility, byte-identical recompilation, every processor, full host Meson/XPS linkage, or the alternate imported Make test link. That alternate Make route still reaches the separately observed duplicate pcodeinject object link failure; preparation reuse after its actual outputs passed. The [task log](../../task-logs/2026-10-21-native-type-contract-corrections.md) records other retained baseline observations and their exact frontier.
