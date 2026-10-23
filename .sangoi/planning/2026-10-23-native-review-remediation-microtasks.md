# Native review remediation: execution projection

Owner: [Intent Contract](2026-10-23-native-review-remediation.md). This annex records execution only; it supplies no additional Scope or authority.

## N1 — real native volatile witnesses

- Objective: Establish the STORE-dependency failure and the single-member union failure with current native implementations, and distinguish direct native-method proof from normal-pipeline reachability.
- Status: complete on `/root/native_volatile_witness`. Five controls pass; five defect witnesses fail individually. Real scheduled typed-stack/register cases return3 after conversion; union loses its first read. Source and logs remain in the declared footprint.
- Dependencies: confirmed intent; Plan Gate PROCEED; fresh source snapshot from native `168c8b6fb5154219456ed63b6440cae58112c137`; root owns snapshot/Git lifecycle. Validation reads current native source and matching x86 language fixtures.
- Effective write footprint: only `/home/lucas/.cache/codex/radare2/native-review-remediation-2026-10-23/native-witness/`, including the copied patch0290 test hunks, prepared source, native build, output and logs. No production-repository write is authorized by this entry.
- Parallel execution: legal with independent H1 private proofs and read-only CALLF investigation. No other writer may share this footprint. Preserve prior N7 artifacts.
- Recon basis: native source check and retained-build discovery by `/root/native_review_source_check`; bounded causal analysis by `/root/volatile_mechanism_investigation`. Root revalidated the three existing native controls, 3/3.
- Mechanism and fixed decisions: extend the existing native test owner in the fresh snapshot, not copied implementation methods. Reuse decoded conditional stack-store inputs and real guards. Compare ordinary versus actual volatile conversion with actual RuleIndirectCollapse, asserting dependencies of returned values. Then exercise qualified input through the normal native pipeline. Union uses the real factory, helpers and action pipeline with the ordinary control. Production behavior and representation remain unchanged.
- Local discretion: exact test names, equivalent assertion structure, native type-injection API usage and bounded diagnostics. Do not replace or stub engine methods. Do not claim schedule reachability from manual conversion alone.
- Validation: canonical Meson target and matching language files; execute named tests and verify executed counts. Record actual failures and controls. A failure is expected evidence, not permission to fix production code.
- Remaining frontier: production corrections and full candidate qualification.
- Stop: stale or ambiguous preparation; missing required API; footprint expansion; inability to establish actual type input; or a material mechanism change. Report evidence promptly, do not improvise another representation or modify retained proof.

## H1 — real host enum and convention witnesses

- Objective: Observe target-default enum read/save and explicit convention application through the retained matching host SDK and bridge, without changing production code.
- Status: complete on `/root/host_enum_cc_witness`. Actual enum default/bridge-width and new-CC substitution failures observed; explicit-width, registered-CC and later-afc controls pass. Raw output is retained in the declared footprint.
- Dependencies: Initial Plan Gate PROCEED; retained H3 SDK and B5 bridge/source anchors verified by Recon. Validation reads these stable retained components, not N1's changing source/build.
- Effective write footprint: only `/home/lucas/.cache/codex/radare2/native-review-remediation-2026-10-23/host-witness/` for a generated SDK-consumer executable and raw output/logs. No production source or retained build input changes.
- Parallel execution: legal with N1 because both effective writes and validation inputs are disjoint.
- Mechanism and fixed decisions: compile a bounded SDK consumer from the already supplied enum probe through stdin, calling actual public APIs against in-memory state; do not compile host implementation files separately or copy their methods. Exercise actual Core signature application and bridge model selection in fresh processes with known/unknown/native-only conventions. Compare recorded CC, operational CC, status/diagnostic and native model; preserve a deliberate later afc control. Read current expected tests as fallible contract evidence.
- Local discretion: equivalent command/argument construction and diagnostic output, exact independent witness names and source facts needed to observe explicit enum sizes in native output. No persistent analysis or original inputs.
- Validation: confirm actual private library/plugin paths, run target-int16 enum read/save and explicit8/32 controls; run concrete new-application, known-convention and intentional-afc controls. No production correction is authorized by this entry.
- Stop: unmatched component identity, unsupported actual API, required footprint expansion, materially different precedence policy, or a failed setup that cannot be bounded to existing tools. Report exact observed state rather than masking it.

## Pending packages

Volatile correction, union correction, enum coherence, explicit convention application and CALLF correction remain high-level Intent Contract packages. Root will admit concrete correction entries only after the decisive evidence and mechanism are established. These entries are not speculative implementation instructions.

## N2 — preserve native volatile memory effects and single-member qualifiers

- Objective: Correct V1/V2 while retaining existing CALLOTHER representation and native owners.
- Status: complete on `/root/native_volatile_witness`, promoted and committed at nativee6145a1. Candidate2 passes14/14 focused,94/94 native and10/10 preparation tests; matching reuse and root3/3 decisive checks pass. Candidate1's invalid Cover premise and correction remain in the task log.
- Effective write footprint: canonical `r2ghidra/ghidra-native/patches/0290-qualified-volatile-accesses.patch`; generated proof/source/build/log outputs only below `/home/lucas/.cache/codex/radare2/native-review-remediation-2026-10-23/native-fix/`. No imported canonical src edits or other patch owners.
- Dependencies: completed N1; diagnosis and direction recorded in task-log V1/V2. Validation reads the stable rest of the native patch stack. No concurrent native patch/specification writer is legal during its preparation/build.
- Mechanism: derive memory read/write classification and memory-space interpretation at the existing TypeOp/PcodeOp boundary, with qualified CALLOTHER identity/encoding interpreted in its existing type-operation/userop context. Ordinary LOAD/STORE and qualified indirect volatile accesses must feed existing discovery, guard validity/creation, collapse, merge and load-crossing decisions consistently. Retain normal opcode gates in rewrites that would remove volatile accesses. Use existing opcode lists and guards rather than new persistent indexes or effect registries.
- Union mechanism: descend through one unambiguous union member when its extent covers the access; retain STRUCT/ARRAY behavior. Do not resolve arbitrary multi-member unions.
- Local discretion: exact internal query names and equivalent organization in existing source owners; no representation, serialized shape, source/operational convention or external bridge API change. A contradiction returns to root before another mechanism.
- Tests: promote concise N1 regressions into the existing patch-supplied test owner. Retain returned-value dependency assertions, real ordinary controls and union read-survival assertions. Add only directly necessary coverage of the proven guard/merge/crossing consumers; no speculative matrix or full raw-IR logging in maintained tests.
- Validation: demonstrate retained baseline failures and corrected native controls/witnesses, then complete native/preparation suites with matching languages and build reuse. Keep current source inputs fixed while validating; use fresh snapshots for changed preparation inputs.
- Stop: footprint expansion, material API/representation requirement, second failed same-behavior correction, fix-breaks-another-surface, stale preparation, or unsupported proof machinery. Report failed attempts and diagnosis changes promptly. Root owns final integration and commits.

## H2 — host enum width and supplied convention application

- Objective: Correct the reproduced host enum read/save disagreement and new explicit convention substitution while preserving persisted getter fallback and intentional afc/harvest behavior.
- Status: complete on `/root/host_enum_cc_witness`; committed at host86f689fecd and213b26aa22. Full private Make/install,53+54 units,9 CLI controls and SDK probes pass. Root independently observed corrected native-only model selection, explicit unknown refusal and later-afc priority with the retained bridge.
- Effective write footprint: canonical `libr/anal/type.c`, `libr/anal/fcn.c`, `test/unit/test_anal_types.c`, `test/unit/test_anal_function.c`; fresh source/build/private SDK/log outputs only under `/home/lucas/.cache/codex/radare2/native-review-remediation-2026-10-23/host-fix/`.
- Dependencies: completed H1 and recorded E1/C1 diagnosis. No concurrent host runtime/test writer or consumer build may use changing H2 source/SDK. Parallel native N2 validation is independent.
- Enum mechanism: pass the root type environment and explicit namespace into the existing enum reader; construct the existing BASE declaration representation with the exact ordinary/tag spelling and consume `r_type_decl_layout` rather than reparse trusted metadata or invent a default. Preserve explicit width and ordinary/tag lookup; no public API/schema change or duplicated enum-default owner.
- Convention mechanism: during non-unchanged application, use an explicitly supplied convention from the original prepared input records rather than interpreting it through the persisted-record effective selector. Omission continues existing resolution; preserve-operational updates remain untouched; unchanged function-scoped reapplication retains its existing behavior. Keep the public getter's fallback and the native consumer's model validation. No new precedence metadata or host-only admission policy.
- Tests: extend existing units with H1 real target16 read/save plus explicit-width controls and fresh-function supported/native-only/unknown convention application. Retain existing persisted getter, source omission, later-afc and preserving-harvest controls.
- Validation: canonical full root Make build at a fresh private prefix, existing unit targets, actual H1 SDK/Core probes against that prefix, and directly affected CLI type/signature controls. No individual product C/object compilation, global installation, original inputs or fixture checkout updates. Bridge integration follows after stable SDK/native candidates.
- Stop: source/ABI/schema footprint expansion, changed precedence policy, unavailable shared layout semantics, build inputs that cannot be matched, or regression-loop trigger. Root owns integration, docs and Git.

## Current execution boundary

N1/H1/N2/H2 are complete. No implementation lane is running. Remaining bridge enum/CALLF/pin/integration/review work is blocked on the Intent Contract's current-user decisions E and F. Do not infer a new task or dispatch from the completed entries.
