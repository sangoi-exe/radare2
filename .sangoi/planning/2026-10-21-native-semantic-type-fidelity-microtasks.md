# Native semantic type fidelity: execution projection

The [Intent Contract](2026-10-21-native-semantic-type-fidelity.md) owns Scope, route, acceptance and lifecycle. This projection owns only current execution footprints, dependencies and results. Root retains all documentary and Git writes. Workers share the worktree; none may stage, commit, push or modify another entry's footprint.

## N1 — Qualified native datatype representation

- Objective: Extend existing concrete datatype classes with meaningful const/volatile layers, distinct canonical identity, completion, codecs and C declarator rendering. This is the representation portion of the first slice; it does not by itself close volatile access preservation.
- Effective write footprint: editable engine `patches/0280-qualified-native-types.patch` and `tests/meson.build`; generated source/test changes exist only through that canonical patch and in fresh task-scoped disposable copies. The patch may change native `type.hh`, `type.cc`, `printc.hh`, `printc.cc`, `marshal.hh`, `marshal.cc`, and supply `src/unittests/testqualifiers.cc`. No direct imported-source edits in the editable repository.
- Validation-read dependencies: native base `6f7438da7a942c7a1dd728e2dda08faabe8644b4`, current patch stack, native build/test owners and compiled x86 languages. No host or bridge dependency.
- Parallel legality: may run with H1; its canonical writes and validation inputs are disjoint. No other native patch-stack writer runs concurrently.
- Recon basis: `/root/semantic_qualifier_recon` mapped class-preserving clones, incomplete-typedef completion, named/structural interning, codec and concrete declarator seams. Flags alone do not preserve identity; wrapper metatypes violate concrete casts.
- Local acceptance: qualified/unqualified variants remain distinct and concrete-class-correct; canonical unqualified types are unchanged; meaningful layers survive native codec/printing and incomplete named completion. Preserve current native controls. Access effects are N2, not a claimed N1 result.
- Targeted validation: canonical fresh native build and focused native qualification/roundtrip tests, plus directly affected retained native tests. No copied implementation double or global installation.
- Status: running on `/root/semantic_native_types_worker`.
- Result / remaining frontier: implementation uses class-preserving qualifier variants within the existing TypeFactory lifecycle; N2 consumes the established representation before bridge import. No result is qualified yet.
- Stop condition: material route contradiction, required source family outside the declared generated footprint, inability to preserve concrete/native identity, or entry too large for one Worker context.

## H1 — Contextual declaration binding

- Objective: Supply visible typedef/ordinary-name context to the shared declaration parser, including same-header declarations and current prototype-local hiding/lifetime; propagate its API through direct live callers without a compatibility wrapper.
- Effective write footprint: host `libr/include/r_util/r_type.h`, `libr/include/r_anal.h`, `libr/include/r_lib.h`, `libr/util/type_decl.c`, `libr/util/type_layout.c`, `libr/util/utype.c`, `libr/anal/c2/kv.c`, `libr/anal/c2/layout.inc.c`, `libr/anal/fcn.c`, `libr/anal/var.c`, `libr/core/cmd_type.inc.c`, `test/unit/test_type_decl.c`, `test/unit/test_anal_types.c`, `test/unit/test_anal_function.c`; bridge `src/R2TypeFactory.cpp` and `src/r2harvest.cpp` only for direct parser-context API propagation. No other bridge behavior in this entry.
- Validation-read dependencies: current host declarations/c2/type database, canonical host Make and unit targets. Bridge compilation waits for the matching new SDK and later semantic integration; H1 must report that frontier honestly.
- Parallel legality: may run with N1. Other host header/c2/signature writers and bridge type writers wait for H1 handoff.
- Recon basis: prior host audit and sufficiency continuation established the exact grouping regression, existing incremental c2 environment, prototype-local hiding requirement, and direct parser API callers. Root enumerated current callers with native Git search.
- Local acceptance: visible `T` remains a callback in the supplied forms; same-header and analysis-database visibility agree; ordinary grouped names remain scalar; nested prototype names do not leak. Named/abstract, near/far, existing qualifier and declarator controls remain truthful. Do not claim the final signature application/namespace work complete.
- Targeted validation: canonical host build and existing declaration/type/function units with focused binding witnesses and retained controls. No isolated production-fragment compilation. Preserve failed output and use a fresh private build when needed.
- Status: running on `/root/semantic_host_binding_worker`.
- Result / remaining frontier: the shared parse API is receiving the actual SDB environment plus parser-local prototype bindings; ABI158 is the reported target. Canonical external admission/structured application, tag identity and flexible-array semantics remain dependent packages. No validation result is qualified yet.
- Stop condition: need for a general C scope/compiler subsystem, material change to selected frontend semantics, required files outside the footprint, or entry too large. API changes must update declared direct callers; report additional diagnostic followers before expansion.

## D1 — Data-directory guidance owner

- Objective: Move the encountered tracked data-directory navigation from `libr/anal/d/README.md` to the local instruction owner, preserving its useful factual content and dlang example without changing database behavior.
- Effective write footprint: `libr/anal/d/README.md` (remove) and `libr/anal/d/AGENTS.md` (new). This durable subtree owns source databases and their generators; root workspace guidance remains macro-sized.
- Dependencies / parallel legality: source inputs and Make/Meson definitions are read-only; no overlap with N1/H1 writes or validation inputs. Pause further data-input edits until this owner correction is integrated.
- Recon basis: fixed source README is a directory overview and file-navigation owner; the shared instruction corpus requires the scoped AGENTS owner. No existing data-directory AGENTS exists.
- Acceptance / validation: preserve useful nonredundant content, use truthful current source/generator pointers and one physical prose line per paragraph, remove the obsolete navigation README, check references/diff. No build is needed for this documentary relocation.
- Status: complete; `/root/semantic_data_guide_worker` returned and root inspected both changed files.
- Result / remaining frontier: local navigation moved to AGENTS, obsolete README removed, dlang example preserved byte-for-byte, references and whitespace checked. No build or behavior change; data-input work may proceed after H1 dependencies settle.
- Stop condition: material content reinterpretation, unproven source fact, or footprint expansion.

## Dependent frontier

N2 completes early native volatile access semantics using N1's actual interface and the existing full-action harness. The first slice remains incomplete until N1 and N2 both pass. Subsequent entries will close host tag/completeness and structured/target-bound application, bridge qualifier/tag/callback import/export, dependency requirements, matching runtime qualification and the committed-candidate Code Gate. Exact footprints are admitted when their predecessor interfaces are stable; this list is not an independent plan or speculative failure inventory.
