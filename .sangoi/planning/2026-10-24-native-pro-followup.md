# Intent Contract: native call-input evidence and overlap correction

Status: on-hold
Task mode: Doctrine
Lifecycle phase: Implementation
Strategy epoch: 11
Plan kind: Bugfix / Regression Plan
Secondary kinds: Architecture / RFC Plan
Plan kind rationale: Correct the demonstrated lost-argument and interval-overlap defects. The user selected a change to the native/bridge knowledge-processing flow and surviving uncertainty, rather than another caller-side exclusion heuristic. This architectural aspect serves the concrete regression; it is not a general interprocedural-analysis feature.

## Confirmed objective and required result

Correct whichTrial's missed containment and the legitimate reused argument lost by0400. Preserve F11's aligned-stack recovery and the observable F12 result that real frame saves are not invented as outgoing arguments. Produce and consume native evidence from the available called function without converting inferred inputs into a fixed source signature. When input evidence is insufficient, retain the unresolved state through finalization and output instead of silently turning it into definite non-use or an apparently complete empty call.

Retain0390's correct PHI/AND/unknown-cleanup behavior, C48 and existing exact-PC calllink precedence. No new selector-value inference, invented alignment, source-complete arity claim, persistent knowledge store or analysis backend is selected. The prior epoch10 review and publication remain actual historical results; they do not qualify the newly reproduced counterexample.

The user confirmed this objective at source23974 and the material route/paraphrase delta at source24266. The latter authorizes the native/bridge processing and unresolved-input boundary, not a new global memory model or unrelated program-wide analyzer.

## Current-user authority and retained decisions

Source anchors refer to thread01a16717-0b9b-7e10-9f98-d4203ccbfde6. Human timestamps use America/Sao_Paulo. The [task log](../task-logs/2026-10-24-native-pro-followup.md) owns causal episodes, earlier decisions and actual historical results; it does not replace this current contract.

| Decision | Current-user anchor | Consequence |
| --- | --- | --- |
| Reopen the demonstrated correction lot | source23974, message msg_01a17517-2aea-7773-ae08-777c2b5c6082, turn01a17517-2820-7c10-9a0d-4849ca11289c, 2026-10-25T19:03:35.018-03:00 | Correct whichTrial and reassess0400 while retaining F11, observable F12,0390,C48 and calllink. Do not add another unsupported exception. |
| Callee evidence and explicit unresolved inputs | displayed paraphrase/source24259; explicit `sim, confirmo` at source24266, message msg_01a17535-a952-7da3-92be-2c580530fe6d, turn01a17535-a788-75c3-be92-52c2c9a56936, 2026-10-25T19:36:53.460-03:00 | Produce/consume native callee evidence, keep inferred inputs distinct from a fixed signature, and preserve insufficient knowledge through output. Expand the intervention to the native/bridge flow and unresolved-input treatment. |
| Correct F11 rather than accept lost arguments | source19892, turn01a172bd-093b-74d2-8f2c-9fc588e6791e, 2026-10-25T08:05:54.119-03:00 | Retain actual aligned-stack argument recovery without restoring false alignment or stack equations. |
| Retain observable F12 frame-save exclusion | sources21601,22581,22932; latest turn01a17463-fcac-72c0-8656-b74618582362, 2026-10-25T15:47:52.758-03:00 | Preserve the requested one-argument results in the demonstrated frame cases. Source24266 replaces the unsupported caller-only proof policy; internal NoUse assertions are not immutable acceptance. |
| Exact-PC contract precedes optional format inference | sources18524/18599; continuation19128 | Keep the current host association and bridge override priority. Callee inference must not replace an explicit call-site contract. |
| Target-backed16-bit claims and durable lab | source9346, turn01a16c95-ef86-7d50-88da-70f0b58d8e79, 2026-10-24T03:25:28.270-03:00 | Required lab inputs remain under .refs/labs/dos622-win311; real Microsoft/target observations ground relevant machine claims. Native32-bit analysis tests are not a Windows oracle. |
| Publish qualified checkpoints when possible | source14242, 2026-10-24T17:24:24.177-03:00 | Ordinary exact origin/master publication after required validation/review; no force push or unreviewed implementation publication. |

Root verified both new intact messages and their preceding paraphrases. The selected high-level route remains confirmed, and no residual loss or risk is accepted. W50 subsequently exposes a pre-existing invalid-mapping cleanup defect while correcting a stale direct test premise; admitting its native mapping owner and changing the incompatible-mode test contract require the pending current-user decision below. The change to processing/knowledge architecture starts epoch11; the admitted correction result remains bounded. Older closed decisions on NE, LEAVE, FAR/selector separation, storage preservation, cleanup and C48 remain preserved constraints, with exact historical anchors in the completed task-log episodes and epoch10 Git record.

## Observed failures and baseline

Current production baselines are native13b16c2d70d3c9665ac629faa47913ba810df654 and bridgee7c903a05072bac5becd9a044d61a162cdc3a56b. Host812f6ea027fd16ce7e49681633f9b9c3fb12e521 is the unchanged production baseline; hostb78e8883069e2eb503071f6114c388eb55239438 adds only the renewed diagnostic record. Only pre-existing untracked .refs/ is outside tracked clean state.

The actual72-byte reused-argument witness writes7, calls at1010, then rereads the same cell. Its callee at1040 consumes entry-stack+4. Root's matching-plugin comparison shows ea40 preserving argument7 and eecc/13 omitting it from both CALL SSA and C. The caller's later read is not proof that the callee does not consume the value.0400 promotes that read to checked definite non-use; final model selection/materialization then removes the argument.

No complete known-good joint baseline exists: ea40 preserves reused7/F11 but overadmits F12 frame saves; eecc and13 improve the demonstrated frame cases but lose reused7. Returning to false pre0390 stack/alignment facts is not admissible. Existing F12 tests contain callee bytes but analyze only the caller, and their internal NoUse assertions encode the faulty implication.

Separately, whichTrial checks query endpoints against a stored trial and misses strict containment: trial[8,10), query[4,12). The defect is inherited, not introduced by0400. Production Address::overlap and the composed function establish this source defect; a final duplicate CALL argument from it has not been observed. Zero-length queries are established point lookups, not mathematical empty intervals. The existing first-overlap test also fails to exercise simultaneous overlap and needs its premise corrected.

## Selected route and Technical rationale

### Input knowledge at the existing native/bridge boundary

Separate three facts: a reaching STORE establishes available contents; caller reuse establishes another use; callee analysis or an exact supplied contract establishes input consumption. Remove the implication from caller reuse to exclusive non-argument ownership.

Use the existing native analysis producer and FuncProto/input-storage facilities for available callee facts. Root separately executed the actual reused7 and F12 callees with the current plugin, without signatures or harvesting: both yield a four-byte entry-stack+4 input reaching EAX/RETURN, with ADD3 in reused7. Parameters remain unlocked. This proves a useful positive producer; it does not prove completeness of unlisted inputs.

The selected flow makes those facts available to call-input recovery within the existing native/bridge analysis lifetime, without persisting inferred signatures or locking their arity. Existing explicit call-site and fixed source contracts retain precedence. Root will freeze the concrete sequencing and consumer mechanism from current Action/Funcdata/bridge APIs before implementation dispatch; no Worker may invent a different analysis owner.

At call-relative candidate admission and finalization, distinguish proven inputs from unresolved candidates. Do not replace NoUse with a transient inactive flag and claim success: unused candidates are currently discarded, and the printer sees only the surviving CALL slots. Retain the admitted unresolved knowledge through the native callspec/finalization boundary and its output consumer so the observed lack of knowledge is explicit. Recovered count or processing completion alone must not supply negative completeness. No separate memory SSA, persisted protocol or parallel inference framework is selected.

The appropriate mechanism combines an already-observed positive producer, existing native analysis/parameter owners, and preservation of the uncertainty that current finalization erases. Native implementation and the decisive bridge production slice now pass; final integration and Code review remain incomplete. This direction addresses the actual missing information instead of adding another prologue, value, restore or later-read veto.

### whichTrial at its current owner

Correct the existing overlap predicate using the production address-space overlap semantics and the missing containment direction. Retain first-vector-match, one-byte scan and zero-length point lookup behavior. Update the canonical patch hunk and direct tests; do not add a second interval helper or speculative stored-trial guards.

### Evidenced alternatives and disposition

Another caller-role veto lacks exclusive-use evidence. Merely weakening NoUse can still discard reused7; all-active restores F12. Both fail the retained joint result. A new global memory model would improve identity machinery without itself proving target consumption, so it is not selected. Preserving uncertainty alone does not replace the requested recovery of the demonstrated real argument; the user selected callee evidence together with explicit uncertainty.

Obsolete hard exclusion from caller reuse and test assertions that mandate that inference are `delete/update now`. Their replacement is qualified native input evidence plus retained unresolved knowledge. No compatibility branch, persisted-data migration or preservation exception is selected. Historical tests/reports retain their actual outcomes but do not define current acceptance.

## Primary-path acceptance and first runnable slice

- The exact reused7 caller/callee bytes recover the real argument7 through native production analysis without a supplied fixed callee signature. Verify the applied CALL operand and returned SSA, not only rendered text.
- The demonstrated single-call/two-call/interblock F12 cases do not invent frame saves as arguments. Their available callee bodies may now supply real input evidence; remove internal assertions that require the refuted NoUse policy. Preserve the nonlinear AND and unknown entry-relative alignment.
- With the demonstrated callee-input evidence withheld or unavailable, the relevant unresolved candidate remains explicit through finalization/output, not silently represented as definite non-use or a complete empty argument list. No universal input recovery or source-complete arity is claimed.
- Retain actual F11 operands/values,0390's seven SSA controls, exact-calllink2/2/5/refusal behavior and the already-qualified C48/raw16-bit boundaries.
- whichTrial finds the containment witness and preserves its existing point lookup, first-match and scan behavior.

The first runnable correction slice uses the existing native decoded-function harness on the exact reused7 bytes: establish the failing caller result, produce the existing callee's positive input fact in the same analysis context, and verify consumption at the real caller boundary without fixing its input signature. The existing F12 body supplies the direct contrasting case. The unavailable-knowledge observation exercises the same demonstrated ambiguity, not a speculative case. whichTrial's independent direct unit regression can run as a separate bounded entry while those read dependencies remain stable.

Use supported native/bridge preparation and private builds. Qualify the committed engine pin against the matching frozen host SDK/plugin/languages, then run the affected native/preparation/bridge and retained production controls. Existing historical bridge expectation failures remain individually disclosed; passing counts are not whole-tree approval. No new guest run is implied by these native-analysis tests.

## Scope, owners and constraints

Primary workspace: /home/lucas/work/radare2. Canonical implementation owners: the independent native repository's patch stack, existing FuncCallSpecs/ParamActive/Action/Funcdata/prototype/finalization/printing chain, and the bridge's existing Decompile/type-import integration. Native test/doc and bridge pin/test/doc followers are in Scope. Existing upstream/imported sources remain baselines; evaluated prepared trees remain frozen.

Host source, generic numeric parser, C48 layout, NE relocations, actual selector-bit semantics, raw CALLF/RETF/LEAVE behavior, host calllink persistence and MCP behavior are retained read dependencies, not new edit frontiers. No ir*/overlay repair, global install, unrelated refactor, new external dependency, extra worktree, persistent knowledge database or general whole-program/recursive analysis feature is admitted.

Root owns the canonical plan, [execution projection](2026-10-24-native-pro-followup-microtasks.md), causal task log, integration, rendered/guest evidence when applicable, Git and review. Worker-family executors own only declared implementation entries and their targeted validation. Current Recon establishes concrete lifecycle seams without selecting strategy. All Claude invocations remain serial.

Keep required lab inputs under .refs/labs/dos622-win311 and preserve all evaluated disks/media. Other private sources/build/runtime/evidence use the existing task-scoped cache owner /home/lucas/.cache/codex/radare2/native-pro-followup-consumers-2026-10-24 with fresh entry-specific destinations. No cleanup, baseline overwrite, download or global install is authorized.

## High-level work and continuity

1. Audit this confirmed epoch11 Intent Contract and finish bounded API/processing-seam discovery.
2. Implement and validate whichTrial at its owner; implement the native positive-input/uncertainty path and its exact regression slice with fixed root technical direction.
3. Integrate the bridge's selected analysis lifetime and matching engine pin; qualify production consumers with stable private inputs.
4. Commit a coherent candidate and obtain the registered local Code Gate, using proportional crossed review for the changed inference/lifecycle contract. Apply material findings only after the current-user decision.
5. Complete task-log/changelog/Git bookkeeping and publish only qualified checkpoints under retained authority.

Current Plan disposition: PROCEED from /root/followup_epoch11_plan, Senior Plan Auditor / Intent contract audit, after complete inline-contract coverage and direct authority/source checks. The resident publish-plan-locator-and-enter-implementation transition was applied. That result remains valid for the admitted route; it does not authorize the newly exposed mapping correction. Concrete microtask mechanisms remain root-owned execution preparation, not another generic permission checkpoint. A materially different owner, persistent state, external contract or broader analysis route returns to the user.

Current next action: obtain the current user's disposition of F14, the pre-existing invalid native mapping cleanup exposed by W50's C48 test-input correction. Recommend admitting a bounded mapping-lifecycle correction and truthful incompatible-mode test behavior, without C48 truncation, Real Mode remapping or wider machine support. This recommendation is not selected Scope. Keep source mutation and Gate launch stopped until the decision; lifecycle remains Implementation and this contract remains the current intent owner.

Retained state: native701f2f6 includes W48/W49, with focused8/8, native152/152 and preparation10/10. W50's exact reused7 CALL/RETURN SSA and available/unavailable C/JSON/XML warnings are independently inspected by root; combined native/preparation/XML pass and types/resolution/formatter is131/133 with the two known baseline failures. The affected pcode file was11/13 before the bounded old-test corrections. The corrected fmovmem premise passes on W46; the corrected NE premise crashes W46 before any W50 rerun. Source establishes unsafe partial-mapping cleanup, but no runtime stack trace identifies the exact faulting instruction. W50 production remains uncommitted pending integration; root records are checkpointed separately. No current Code Gate, publication or global installation has occurred. The previous epoch10 PROCEED_WITH_NITS remains the actual result for its older object, not approval of this new correction.
