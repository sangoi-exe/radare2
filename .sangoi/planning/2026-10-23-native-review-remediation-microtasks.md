# Native review remediation: execution projection

Owner: [Intent Contract](2026-10-23-native-review-remediation.md). This annex records execution only; it supplies no additional Scope or authority.

## N1 — real native volatile witnesses

- Objective: Establish the STORE-dependency failure and the single-member union failure with current native implementations, and distinguish direct native-method proof from normal-pipeline reachability.
- Status: admitted; Initial Plan Gate PROCEED. Root prepares the fresh source snapshot, then dispatches the Worker.
- Dependencies: confirmed intent; Plan Gate PROCEED; fresh source snapshot from native `168c8b6fb5154219456ed63b6440cae58112c137`; root owns snapshot/Git lifecycle. Validation reads current native source and matching x86 language fixtures.
- Effective write footprint: only `/home/lucas/.cache/codex/radare2/native-review-remediation-2026-10-23/native-witness/`, including the copied patch0290 test hunks, prepared source, native build, output and logs. No production-repository write is authorized by this entry.
- Parallel execution: legal with read-only host/bridge/CALLF investigation. No other writer may share this footprint. Preserve prior N7 artifacts.
- Recon basis: native source check and retained-build discovery by `/root/native_review_source_check`; bounded causal analysis by `/root/volatile_mechanism_investigation`. Root revalidated the three existing native controls, 3/3.
- Mechanism and fixed decisions: extend the existing native test owner in the fresh snapshot, not copied implementation methods. Reuse decoded conditional stack-store inputs and real guards. Compare ordinary versus actual volatile conversion with actual RuleIndirectCollapse, asserting dependencies of returned values. Then exercise qualified input through the normal native pipeline. Union uses the real factory, helpers and action pipeline with the ordinary control. Production behavior and representation remain unchanged.
- Local discretion: exact test names, equivalent assertion structure, native type-injection API usage and bounded diagnostics. Do not replace or stub engine methods. Do not claim schedule reachability from manual conversion alone.
- Validation: canonical Meson target and matching language files; execute named tests and verify executed counts. Record actual failures and controls. A failure is expected evidence, not permission to fix production code.
- Remaining frontier: all new witnesses and all corrections remain unexecuted.
- Stop: stale or ambiguous preparation; missing required API; footprint expansion; inability to establish actual type input; or a material mechanism change. Report evidence promptly, do not improvise another representation or modify retained proof.

## Pending packages

Volatile correction, union correction, enum coherence, explicit convention application and CALLF correction remain high-level Intent Contract packages. Root will admit concrete correction entries only after the decisive evidence and mechanism are established. These entries are not speculative implementation instructions.
