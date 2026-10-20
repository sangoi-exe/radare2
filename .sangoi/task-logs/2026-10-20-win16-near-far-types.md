# Win16 target types and explicit pointer layers

Status: implementation and matching-component validation complete; final Code Gate pending.

The [Intent Contract](../planning/2026-10-20-win16-near-far-types.md) owns Scope, decisions and lifecycle. Its [execution projection](../planning/2026-10-20-win16-near-far-types-microtasks.md) records bounded Worker responsibilities. This log records established execution evidence, not a second acceptance authority.

## Implemented result

The host has one structured declaration parser/renderer and target-Sdb-backed layout owner. Default `c2`, signatures, direct CLI consumers and bridge translation use that structure. Explicit pointer layers replace implicit callback-object handles; function metadata remains independent. The bridge reads fundamental/default widths from the native target and preserves near/far through import, C output and harvest/writeback. Native patches expose existing target metadata, correct the selected x86/16 scalar model and retain anonymous callback arity through the canonical datatype codec.

The current user selected this route and later admitted the observed whole-function compound-return printing and manual `afs` name failures. Both owner corrections and final matching bridge/MCP integration are qualified. The OMF LEDATA16/BIG16 findings remain outside this task. No byte-identical game reconstruction, full C++ frontend, optional TinyCC correction, universal Borland ABI, global installation or push is claimed.

## Checkpoints

The original task baselines are host `983911bf6fde95a4f2e71f7ba1b4530d94e816c2`, bridge `0405ec5e39bc95d797d9e74c3fc4d671baff7592`, native `3ee06068bc8e5c483bbb35a45a23b9f4eafadfa6` and unchanged MCP `95bc806fbfc1b0de0813744299fa71756aaddec9`.

- Host `18778d42c2cea4413e5be99f3c751ee35405cbf8` introduced the shared declaration boundary. `fc06d07fe9303c245bf11798dda2ac94bc1ff39d` propagated established dotted names. `70e28a9cb1f63a93a5d12bb20da71d7fc70f7cfe` integrated default-producer, target layout, signature and direct-follower changes. `2d8c835e334c02c9e9635b3b9ef65abb76803739` uses shared named signature preparation for manual `afs`, preserving Core rename/flag ownership and existing configured-parser delegation.
- Native `ad1574c931dc9b68be58bc3ed25bf3352b298bc7` introduced metadata getters and the pointer-print hook. `e8221d7d2a3d9f604eefdc6f9469c3ba4b4a4456` selected eight-byte long long under the user's explicit local-model decision. `cd2677f333deea532a94e89173dc0e9a3dbe6138` corrected ten-byte long-double array stride. `1e671ba96c051c974d9d971a60b5a641390d334c` updated the native navigation map. `bbab9042a2603792f5f94ec0a9862a2fd8ede315` corrected input-only internal prototype serialization. `3f46b7c7e70599d394a08a6a71b252c0cbb4fa9f` integrates contextual whole-function declaration printing into the existing RPN/type traversal.
- Bridge `7bb2af5ecabc8805f978849630b5d882b62e198d` commits the implementation, final engine pin, regressions, product documentation and owner map. These belong together because code/pin/matching-build instructions must remain coherent. Root reviewed the full change set and compared all14 implementation/test/doc inputs with the qualified source; the staged15-file set additionally contains the reviewed owner map. MCP source remains unchanged.

All new checkpoints include the required Codex co-author trailer. Existing unrelated `.refs/` remains untouched.

## Evidence and observation limits

All paths below are relative to `/home/lucas/.cache/codex/radare2/win16-near-far-2026-10-20/`.

| Object | Evidence | Observed result |
| --- | --- | --- |
| Host70e28 matching source/install | `host-selection-2fkApu/`; `host-dot-validation-xVDDIR/` build, install, unit, r2r and input-comparison records | Declaration9/9, analysis-types28/28, analysis-function26/26 and304/304 type/callback/prototype regressions. All23 changed implementation/test inputs matched the qualified source. |
| Host2d8c835 matching source/install | `host-afs-AMIXVh/` final build/install, unit, paired-witness and r2r logs | Compound-`afs`/unchanged-`CF` witnesses2/2; declaration9/9, analysis-types28/28, analysis-function28/28 and305/305 type/callback/prototype regressions. Root compared all five delta inputs with the qualified source. |
| Architecture-specific type selection | `host-dot-validation-xVDDIR/model-transition.*`, `same-selection.*` | x86/16→ARM/16→x86/16 selects int sizes2→4→2. Rejected `x68` retains its diagnostic; reselecting x86 preserves the user marker. |
| Nativebbab904 codec | `native-prototype-kh71eW/red-tests.log`, `focused-tests.log`, `final-tests.log`, `final-reuse.log` | Baseline callback gained a false second input; corrected codec retains one input. Native39/39, preparation8/8 and matching reuse passed. |
| Native3f46b7c contextual declaration | `native-function-decl-BjMsDa/red-tests2.log`, `qualified-{focused-tests,tests,reuse}.log` and qualified build test log | Baseline detached return reproduced; corrected exact plain/XML declaration, real function/parameter/return associations and balanced scope/RPN/formatting pass. Focused1/1, native40/40, preparation8/8 and reuse with CPUI_DEBUG/PRETTY_DEBUG. |
| Stable bridge primary paths | `bridge-8Dflio/` source, build, native checks, `types-final.*`, probes and linkage record |72/72 maintained type cases, native39/39, preparation8/8, pcode XML and matching reuse passed. Original matching components passed67/67. |
| Native MCP integration | `mcp-validation-1HVFGs/native-mcp-results.json`, stdio capture, linkage record and three context XML files |20 successful JSON-RPC responses used the matching host, plugin and languages. Default/mixed pointer layers, locked convention and ordered stack storage4/6/8 survived writeback. |
| Final bridge7bb2af5 | `b3-nZrrzL/` matching source/build, `native-tests.log`, `types-final.*`, `reuse.log`, `ldd.log`, compound probes |73/73, native40/40, preparation8/8, pcode XML and reuse pass against host2d8c835/native3f46. The previous72 expectations remain unchanged. |
| Final rebuilt MCP95bc | `mcp-final-jhkembmg/` configure/build/linkage, `native-mcp-results.json`, stdio and context/annotation captures |35 successful JSON-RPC responses and exit0. Default/mixed layers and stack4/6/8 pass. Compound near2→array3/size12→far4 survives `pdgw`; complete C and exact function/parameter token associations pass. |

The bridge observations include two-byte int/default pointers, mixed near2→far4, pointer-to-array precedence, exact anonymous callback arity, PPC64 dotted-name writeback and a twenty-byte long-double aggregate. Type XML references core scalar types rather than re-emitting their definitions; storage, type references and pointer nodes are the observed production evidence. Do not claim that each scalar width was independently encoded in those context XML files.

The final MCP run explicitly loaded the qualified plugin and flat x86 languages, with all22 radare2 library bindings resolving to the H5 private SDK. Its `pdgw` calls reported no changes for the already-canonical manual signatures; this proves preservation/idempotence, not a new write in those calls. The maintained bridge default-pointer control separately observes signature writeback followed by a no-change second call. No original input file was opened for writing.

Builds use private matching sources and installations. The host configuration excludes unavailable optional ZIP/QuickJS components. Fixture inputs come from the exact official radare2-testbins revision `221fc02993747ed1ceb82aa1f22eb8f12e29ff51`. The bridge regression file uses matching DATA/x86/AARCH64/PowerPC languages. Full bridge Make, packaged-distribution, XPS linkage and other processors are not qualified by the bounded Meson results. This task has not repeated saved-analysis/file-switch integration or compared original and recompiled game binaries.

## Corrections to earlier evidence

- The default host header producer is `c2`, not optional TinyCC. Current callback tests and documentation use that admitted producer; TinyCC still produces obsolete implicit callback handles and is excluded.
- An early architecture-invalidation correction fixed same-bitness changes but broke failed-selection recovery. The final correction extends the existing private loaded-type cache key with architecture and removes the failed session heuristic. Its recovery and direct witnesses are recorded in the execution projection.
- A copied private build reused dependency files with absolute paths and mixed old/new private header layouts. Its109 failures are not evidence for a coherent binary. A canonical clean build replaced that invalid observation; no source correction was inferred from those results.
- Anonymous callback import first exposed incomplete handwritten bridge serialization, then a native producer that redundantly encoded the return among inputs. The bridge now uses the existing native encoder/tree handler. Native patch0200 removes the redundant return at its producer; it does not add a decoder filter or compatibility path.
- A first MCP proof assertion expected core scalar definitions in native context XML. The native encoder deliberately omits those definitions. The proof assertion was corrected to inspect actual references, storage and pointer layers; runtime source and the successful captured operation did not change.
- The initial manual-`afs` correction made its shared facade too strict for the existing `CF` configured-parser caller. The canonical baseline established that raw producer delegation belongs to that facade, whereas Core needs strict name preparation. Restoring that separation passed both direct witnesses and the complete305-test frontier without changing old expectations or optional TinyCC source. The new CLI fixture separately needed a real return instruction before block creation.
- The native contextual-print test first used an extra document group and then discarded XML syntax whitespace through the ordinary TreeHandler. Production-style function grouping and the existing SAX whitespace extension corrected the fixture without weakening its exact plain/XML text or metadata expectations. The separate sccache socket-path failure was resolved with a shorter task TMPDIR. Product bytes remained stable during the XML-fixture correction.

## Foundations and compatibility dispositions

The Borland C++3.1 Programmer's Guide (1992), verified on2026-10-20, establishes the relevant int/short/near/far/long-double widths and contiguous arrays. It does not establish Borland long-long support or one universal aggregate-packing setting. The selected eight-byte long-long value is the user's local analysis-model decision. Native prototype ownership is grounded in the revision-matched upstream `FunctionPrototype.java` at `a14dad67f369affeffc1cd4d584b6b717cd9c3f5`, not a synthetic double repeating the patch's assumption. Exact references are in the Intent Contract.

Old implicit callback-object handles and removed context-free layout APIs intentionally break; current declarations must be re-imported or callers updated. No migration, alias, dual interpretation or preservation exception was authorized. Function metadata remains live. Erroneous old native dumps containing the redundant return are not supported as an alternate shape.

A bounded stale scan covered host `libr`, `binr`, `test`, `doc`, `man`, `AGENTS.md` and bridge `src`, `r2plugin`, `ghidra`, `doc`, `test`, `AGENTS.md`, `meson.build`. It found no removed layout APIs/helpers or live manual bridge declaration paths. Its sole bridge scratch-prefix hit explains removal in the active product document; it is not runtime handling. The scan excluded README files, historical `.sangoi` records, `.refs/`, independent nested repositories and managed/generated engine copies. Its absence claim is limited to those roots and terms.

## Remaining work

Obtain the required local broad crossed Code Gate on the fixed host/bridge/native candidates, then finalize bookkeeping. Host, bridge and native owner partitions require independent Senior/Claude assessments and reciprocal examination, followed by the integration pair's seam/evidence synthesis and the integration Senior's final cumulative disposition. The public type boundary, multiple native/bridge consumers and annotated printer integration justify the broad procedure. No Code Gate verdict or final success is recorded here.
