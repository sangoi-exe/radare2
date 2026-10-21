# Native type-contract validation

This report records the candidate and observed coverage. It is not a Code Gate verdict, a whole-decompiler correctness claim or rebuild-ready game source. The subsequent [local Code Gate](review.md) returned DO_NOT_PROCEED for residual defects despite these bounded passes. The original executables were opened for analysis without execution, write mode or saved-project mutation.

## Candidate and runtime

| Component | Committed runtime input |
| --- | --- |
| Host | `6fba81631ce4b84f70ed6d6d68b2ff2aef3b96a0` |
| Bridge | `0294500175f30613c526580484c66d7160bb882a` |
| Native engine | `fce4b2c2019da4588d9b51765a2649321c07cb43` |
| MCP | `51df6714dc5b40822ab421ac685caa4d3da2a0ae` |

Later host commits containing only these records do not change the tested runtime. The bridge wrap selects the listed engine exactly. ABI157 requires rebuilt matching callers; no compatibility adapter, global installation or push is part of this validation.

The private runtime is `/home/lucas/.cache/codex/radare2/native-type-contract-2026-10-21/final-runtime-2p16mosx/`. `install/` contains the host SDK, `bridge/build/libcore_r2ghidra.so` is the plugin, `bridge/languages/` selects matching DATA/x86/AARCH64/PowerPC specifications, and `mcp/source/src/r2mcp` is the server. Linkage logs show the private host libraries without sanitizer libraries. Builds used canonical host Make and bridge Meson targets, not isolated copied production fragments. QJS and ZIP were excluded from this private host build, as in the earlier qualified SDKs.

## Executed proof

| Surface | Observed result | Evidence under the private runtime |
| --- | --- | --- |
| Host units | 184 passed across 15 suites: declarations (15), types (43), functions (41), variables (7), JNI (2), DWARF (5), Borland (10), BCC20 (8), SimTower (4), BCC (7), TASM (12), contract (4), TLINK401 (5), TLINK51 (5), profiles (16) | `host/unit-*.log`; DWARF final result is `unit-dwarf-corrected.log` |
| Host CLI | 43 type controls and 11 signature controls passed | `host/cli.log`, `host/cli-vars.log` and status files |
| Bridge | One complete run of `r2ghidra_types` and `r2ghidra_type_resolution` passed 91/91, including their PowerPC controls; no timeouts. This is not all of `test/db/extras`. | `bridge/suite.json`, stdout/stderr and status |
| Native | 51/51 native controls, ten preparation controls and p-code XML test passed | `bridge/registered-tests.log`, `bridge/build/meson-logs/testlog.txt` |
| Preparation reuse | Matching bounded build passed after language generation | `bridge/reuse.log` |
| Typed native MCP signature boundary | 22 requests, exactly one response per ID, none for initialization notification; expected success/refusal and unchanged seek observations passed | `mcp/signature.*` |
| Original-game MCP tools | SimTower 18 and Johnny 10 requests, unique responses, no tool errors, both processes exit0 | Retained `mcp-*` files in each game directory |

Earlier instrumented slice builds cover the actual host/bridge corrections. B4's full instrumented run passed 89/91; one selector-only assertion correction passed its separate rerun. Combined unique coverage was90 passing cases plus the known pre-bridge PowerPC signed-shift UB. The later normal91/91 run closes functional coverage, not that UB. Native engine objects were uninstrumented in combined sanitizer runs; do not claim whole-engine sanitizer cleanliness. Detailed slice results and failing attempts remain in the [execution projection](../../planning/2026-10-21-native-type-contract-corrections-microtasks.md).

Operational setup failures remain recorded: configure removed an older-timestamp plugins.cfg; unit paths and the DWARF working directory were initially wrong; an initial r2r help lookup lacked the private library path; an unnecessary fixture symlink was refused because the archive already contained the tracked fixtures. Corrected canonical commands passed. No fixture or original was overwritten to fix those setup errors.

## Original-backed observations

The game directories retain direct CLI C, complete architecture/function XML, instruction JSON, raw instruction p-code, loaded binary information, language selection, profile output, exact invocation arguments, diagnostics and exit status. The MCP directories' streams are copied byte-for-byte from the actual server runs, with original requests and invocations. These are generated evidence, not maintained source or golden expectations.

Source and hand-maintained documentation pass whitespace checks. The unmodified generated C/p-code/profile output retains its emitted trailing spaces and blank final lines; the full staged whitespace check reports those artifacts. The evidence was not reformatted to hide that distinction.

Both originals load as x86/16 NE. The explicit language setting is empty; automatic matching reports `x86:LE:16:Protected Mode:`. Context XML records `protectedMode=1`. Direct CLI plugin initialization first reported the absent globally installed Sleigh directory; the following explicit private path selected the correct bundle before observation. A separate bounded startup check with `SLEIGHHOME` set before plugin loading exits0 without that diagnostic (`bridge/startup-env/`). For replay, set `LD_LIBRARY_PATH` to the private `install/lib` and `SLEIGHHOME` to the private `bridge/languages` before loading the plugin. No global installation is needed.

SimTower's current128 mapped bytes at `0x110e8` equal the qualified move-core/wrapper bytes in the product procedure. The captured core uses `borland_fmovmem_16far`; its source/destination records occupy stack offsets 4/8 and its two-byte count offset 12. The wrapper uses `borland_fmemmove_16far`, returns `FarAddress16`, and the complete function XML passes the source/destination/count operands to the core in the correct order before returning the destination. The four-byte record retains independent two-byte offset/selector fields. Raw p-code retains symbolic SS for stack accesses, the PUSH CS at `0x11156`, near CALL at `0x11157` to `0x110e8`, and RETF at `0x11140`. Other captured targets are `0x10006→0x4f02d7`, `0x4f02ee→0x11a55` and `0x4f00a1→0x4f3649`.

Johnny's qualified F_SCOPY at `0x1033a` retains its explicit `borland_f_scopy_16far` model, FarAddress16 arguments and extrapop 12. The captured far CALL at `0x100b0` targets `0x20000` and preserves selector-bearing stack operations. These are analysis-coordinate observations, not Windows runtime selector values.

MCP returns complete C pages and parseable complete native XML for those three functions. All nonblank C lines match direct CLI output after removing per-line surrounding whitespace; the MCP response removes indentation, so the responses are not byte-identical raw C. The direct CLI files preserve raw formatting. An initial exact-text comparison failed for that formatting difference; it is not reported as a passing byte-equality check. Raw p-code text can contain process-dependent address-space handles, which are not game addresses.

Profile messages count qualified facts, including unchanged facts, not a claim that every possible contract applied. The SimTower refusal at `0x131af` remains visible in CLI and MCP diagnostics; no signature or profile override was used to hide it.

## Unresolved observed rendering limitation

The Johnny F_SCOPY odd-byte loop prints dereferences through `uint far *`, like the word loop, without narrowing casts. Actual live native XML keeps the MOVSW transfer at `0x10349` as two-byte LOAD/STORE and the MOVSB transfer at `0x1034d` as one-byte LOAD/STORE (`1033a.function.xml`, byte value reference `0xf1`, LOAD/STORE unique IDs `0x53`/`0x55`). Address operands are four bytes; address width is not transfer width. Thus native operations retain the distinction, but the printed dereference does not faithfully express it.

Bounded read-only comparison with the retained matching `B1-resume` plugin, its language bundle and its earlier host SDK reproduces the same C and both access widths. This proves pre-B4 existence, not pre-task origin or correctness. No further correction or full-game C approval is claimed. This observation must remain visible in review and handoff rather than being hidden by successful transport or test counts.

## Proof limits

The result does not qualify global installation, remote acquisition of unpublished pins, whole-project persistence/file switching, complete game decompilation, historical Borland source compatibility, byte-identical recompilation, every processor, full host Meson/XPS linkage, or the alternate imported Make test link. That alternate Make route still reaches the separately observed duplicate pcodeinject object link failure; preparation reuse after its actual outputs passed. The [task log](../../task-logs/2026-10-21-native-type-contract-corrections.md) records other retained baseline observations and their exact frontier.
