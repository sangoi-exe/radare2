# Intent Contract: preserve incomplete native call-input evidence

Status: complete
Task mode: Doctrine
Lifecycle phase: Closeout
Strategy epoch: 1
Plan kind: Feature / PRD Plan
Plan kind rationale: Add an explicit representation for a demonstrated recovery limitation. The current native contract has dense source arguments and storage-only uncertainty, but no supported value/storage association with unknown source-parameter position. This is not a claim that an existing sparse representation regressed.

## Confirmed objective and authority

Preserve the native association between a call, a known value and its storage when the source parameter position or arity remains unknown. Render the call explicitly incomplete in C and JSON code, export the storage/value association structurally in pdgx XML, and verify the actual 72-byte model-hole case without inventing a missing argument. Preserve ordinary calls, supplied prototypes and the completed fixed-input slicing correction.

The user requested this lot at current-thread source30537, turn01a179b2-244b-7b21-b28d-9db1407b9637, 2026-10-26T16:31:20.700-03:00. Root's complete paraphrase is source30604. The user confirmed it with “confirmo” at source30611, turn01a179c7-79ce-7d91-97d5-e5818107b438, 2026-10-26T16:54:38.906-03:00 (America/Sao_Paulo). Source: /home/lucas/.codex/sessions/2026/10/23/rollout-2026-10-23T01-48-46-01a16717-0b9b-7e10-9f98-d4203ccbfde6.jsonl. The confirmed route retains FuncCallSpecs responsibility and changes its direct consumers; an additional warning alone is insufficient. Exact presentation spelling is an implementation detail within explicit analysis notation, not a normal source signature.

The completed R4 plan remains historical. Baselines for this lot are host1bb23d47afe1f9af0d1059102b77cb60f7cf130e, bridge86a0b12e30c97abeead4013a293ddd6c05ef0501 and native37cd3df63a96b4b16669b2131ccb6ca6102a6b8d. Tracked trees are clean; pre-existing untracked .refs/ is excluded. No push is authorized.

## Primary behavior and acceptance

The retained saved-frame caller writes7 to call-relative stack[0x8:4]; the existing callee body reads that storage. Current output preserves the STORE and unresolved stack[0x4:4] warning, but CALL1018 to1040 has no argument operands. Source confirms that the standard model's missing first resource deactivates the later trial; dense finalization drops the value-to-call association. A model resource is not necessarily one source parameter, so printing callee(7) or inventing a first formal argument would not satisfy the result.

- The exact 72-byte native pipeline witness retains a real dataflow use of7 at the call and its call-relative stack[0x8:4] storage. No operand or source-parameter index is invented for the unresolved stack[0x4:4] cell. Unknown parameter placement and arity remain explicit.
- Normal C and matching JSON code render an analysis-only incomplete call, not an ordinary dense call that implies7 is the first parameter. pdgx exports the actual CALL identity, retained value reference and storage coordinate/width, together with incomplete mapping and unresolved-storage facts.
- Ordinary direct/indirect calls, explicit complete and fixed-prefix contracts, the prior fixed-input slices, and established input-use/warning controls remain valid. Existing clear/reanalysis and cloning boundaries do not reuse stale value pointers or discard the new association.
- Qualify the committed engine through the matching bridge, native/preparation/XML tests and affected production regressions. Retain individually established historical failures as failures; do not change EXPECT merely to fit output.

No known-good implementation of the requested sparse association exists in the inspected owner chain. Existing STORE preservation and warnings are baseline controls, not a solution. The first slice observes the actual trial/value/storage transition around native finalization before implementing the new result; source-based intermediate claims remain distinct from measured ones until that execution.

## Selected route and Technical rationale

Keep value ownership in real CALL/CALLIND operands, with FuncCallSpecs owning the distinction between ordinary source-parameter inputs and storage-qualified inputs whose source mapping is incomplete. Storage descriptors contain coordinates, widths and operand correspondence, not independently owned Varnode pointers. The CALL operand edge retains SSA liveness; a warning string or metadata pointer alone would not. Existing unresolvedInputStorages continues to describe unresolved cells, not fabricated values.

Carry positive callee storage-use evidence independently of the standard model's formal-parameter selection. When an admitted reaching value has matching positive callee use but the model-hole selection would discard it, retain that value/storage association under the explicit incomplete-input state rather than forcing the model to invent a preceding parameter. Construct the final operand/storage correspondence before rejected-trial disposal. Ordinary mapping stays unchanged when this condition is absent. A later supplied complete contract uses the existing storage-based restriction/restart owner rather than preserving competing inferred authority.

Update direct consumers that interpret or transform source parameters. Incomplete storage inputs must not receive prototype types or hidden-this/constructor interpretation from a guessed slot, or lose storage correspondence through a source-parameter join/narrowing operation. Reuse the existing generic SSA operand and printer machinery; do not add an auxiliary effect operation, parallel value owner or global knowledge service. Reanalysis reconstructs facts from current code and callee evidence. Clone metadata refers to the cloned CALL's operands, not old SSA objects.

Use the native printer's existing functional analysis notation for the incomplete call and storage-qualified value expressions. The notation names its target and known storage/value pairs without presenting them as source arguments. It must preserve the real operation/value annotations where the current markup supports them. JSON code follows the existing C-markup path; no new structured JSON API is required by this lot.

The bridge's pdgx result wrapper owns the new structured export, consuming native callspec facts and existing Varnode identities. Do not add new children or numeric IDs to shared Funcdata::encode: that method also produces packed decompiler responses and serves a persistence boundary. Existing raw native AST remains its existing format; this lot does not qualify an external packed receiver or change host persistence. The new pdgx association is an analysis-output contract, not a guessed source prototype or a versioned persistence schema.

These mechanisms address the observed loss at its native owner while keeping ordinary formal inputs and confirmed contracts distinct. Warning-only disclosure cannot preserve the required dependency. Adding a separate pseudo-effect operation would duplicate value/call ownership when CALL already supplies the required SSA edge; that route is not selected. No current-user material decision remains open within this selected route. A discovered requirement to change external packed transport, host persistence or another owner returns to the user.

## Scope, owners and constraints

The primary workspace is /home/lucas/work/radare2. Native source changes belong to its independent r2ghidra/ghidra-native patch stack, including FuncCallSpecs, its trial/finalization and direct type/transform/printer followers. Focused native tests and active coverage documentation follow that owner. Bridge pdgx export, exact native pin and direct regressions are in Scope. Root owns plan, task log, changelog, integration, final validation and Git; bounded Workers own source implementation.

Out of Scope: partial-overlap residual recovery; a universal ABI, source-arity, alias, model or endian guarantee; global model-policy changes; speculative derived-metadata cleanup; host signature/persistence changes; native packed-protocol expansion; new opcodes or parallel value carriers; a Ghidra upgrade; lab/media/Windows changes or new guest execution; global installation; new worktrees; downloads; cleanup; push. The generic x86-32 decompiler case makes no new 16-bit machine or Windows-owned behavior claim.

Use fresh task-scoped source/build/runtime/evidence categories only as needed under /home/lucas/.cache/codex/radare2/native-incomplete-call-inputs-2026-10-26. Keep prior evaluated trees and reusable lab inputs intact. No compatibility aliases or dual runtime paths are selected; any changed live native query/export contract propagates to its direct consumers. Existing complete-call behavior is an explicitly preserved requirement, not an inferred legacy exception.

## Work and continuity

1. Audit the confirmed contract and establish the actual primary trial-finalization trace.
2. Implement storage-qualified native call inputs and direct semantic/rendering followers; prove the native result and preserved controls.
3. Integrate the exact engine and structured pdgx export through the matching private bridge; inspect actual C/JSON/XML.
4. Commit the fixed candidate, obtain the registered local Code review, and finish durable records and final Git inspection.

The root-owned [Microtask Program](2026-10-26-native-incomplete-call-inputs-microtasks.md) records completed execution; the [task log](../task-logs/2026-10-26-native-incomplete-call-inputs.md) owns causal episodes, proof and review resolutions. H1 measured the baseline loss; H2 is qualified at native2ab32524c109737b0956b56f80ff2f249688d552; H3 is qualified at bridge3fbfdd4568965c8bbc838e01720971d9e09172bf. Native164/164, preparation10/10, XML1/1, pcode21/21, types80/80 and resolution41/41 pass. Formatter10/12 retains two individually unchanged historical failures. The local crossed Gate on hostc806a1e424959750f6a5789aa6c558c58ee972f4 and those component candidates concluded PROCEED_WITH_NITS after complete independent and reciprocal coverage and root analysis. Root read and applied record-nits-enter-closeout. The optional XML-fragment specificity nit remains recorded and unapplied; no required source correction or semantic rerun remains. Three Claude invocations completed serially without failure or dispensation. No push, global installation or new guest run occurred. The subsequently authorized formatter corrections are a separate task and do not broaden this approval.
