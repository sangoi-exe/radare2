# Local Code Gate: PROCEED

The final focused Remediation delta review returns PROCEED and closes SIGNATURE-F4, with complete required coverage and no findings. The earlier seven defects were closed by the preceding broad review. Earlier negative verdicts remain historical evidence for their candidates; none was relabeled as an approval.

## Initial Task change-set review

The final cumulative `Senior Code Reviewer / Task change-set review` returned **DO_NOT_PROCEED**, with route condition **user-decision**. The integration owner was `/root/type_gate_integration_senior`. Semantic coverage of the admitted object is complete; the result is not an approval, a review override or authorization to apply material remediation.

## Fixed reviewed object

| Repository | Base | Candidate |
| --- | --- | --- |
| Host | `fc4d7e7aded2f06644714bb98a2e0b0b8b334686` | `d2728414f3549a1c1ab18812d29626507fa0909e` |
| Bridge | `27c3caaebb23926853b2143ff72d8dc303c086f2` | `0294500175f30613c526580484c66d7160bb882a` |
| Native | `3f46b7c7e70599d394a08a6a71b252c0cbb4fa9f` | `fce4b2c2019da4588d9b51765a2649321c07cb43` |
| MCP | `95bc806fbfc1b0de0813744299fa71756aaddec9` | `51df6714dc5b40822ab421ac685caa4d3da2a0ae` |

No implementation changed during review. Subsequent bookkeeping does not replace this reviewed object. ABI157, the exact engine pin and the matching runtime are coherent; passing validation does not close the failures below.

## Confirmed material defects

All seven items are classified as `verified_defect`. The recommendations are `modify_existing_owner`, not selected implementations. Each correction and its causal proof remain pending the current user's decision.

| Finding | Fact, required property and impact | Recommended correction and falsifier |
| --- | --- | --- |
| TYPES-F1: `libr/util/utype.c:759–762` | Explicit `struct Alias` loses its tag and borrows unrelated `Bright` fields through the ordinary typedef. Shared layout already refuses that incomplete tag, so memory formatting violates the same identity contract. Root reproduced the failure. | Enforce matching tagged identity and available by-value layout at the formatter. The witness must refuse while ordinary `Alias` and `struct Alias *` retain their valid formats. |
| SIGNATURE-F1: `libr/anal/fcn.c:3293–3327,3384–3388` | A FIXED fact with unavailable count reads as a partial snapshot, but reapplying that snapshot makes inferred arguments complete; an empty list becomes `(void)`. Root reproduced the real-library get/set roundtrip. | Refuse or preserve unavailable-list snapshots at the canonical setter. Reapplication must not invent a count or fixed-empty meaning. |
| SIGNATURE-F2: `libr/anal/p/anal_borland.c:419–432` | Generic helper admission ignores prototype-only independent facts and unreadable signatures. Both unspecified and invalid SimTower cases acquire the helper's fixed address-linked contract. Root reproduced both. | Correct this existing preflight while retaining clean application and exact-match idempotence. The conflicting variants must preserve their original effective contracts. |
| SIGNATURE-F3: `libr/anal/dwarf_process.c:1592–1594,1839–1856,2163–2188` | Formal-type recovery detects incompleteness, but rendering/import publishes `(void)` and a complete count. Name lookup consumes the wrong record even without an address link. The witness is local decoded-DIE input through the real importer, not an observed external compiler artifact. | Carry formal completeness independently through both serialization paths. Preserve FIXED knowledge without claiming a complete list; coordinate with F1 so later snapshot writes remain safe. |
| BR-1: `r2ghidra/src/R2Scope.cpp:721–741` | A known 24-byte aggregate return loses its ABI-hidden input constraint with unknown/unspecified real source inputs. Root reproduced fixed typed field stores versus scalar offset stores under the same model/body. ABI-lowered pointer return spelling alone is not the defect. | Preserve return-derived hidden storage without closing real source inputs. All three states must retain that constraint. A genuinely necessary new native representation requires a further user decision. |
| BR-2: `src/r2harvest.cpp:WriteSignature`, `src/R2TypeFactory.cpp:603–604` | Writeback keeps UNSPECIFIED while adding inferred parameter records; the named callback consumer rejects the resulting nonzero count. A producer emits a state its direct consumer rejects. | Reconcile the existing consumer with open source meaning and separately retained analysis records. The writeback-to-callback sequence must remain representable. Deleting useful inferred records, freezing UNKNOWN hints or adding provenance state is not mandatory. |
| BR-3: `r2ghidra/src/R2Scope.cpp:183–185` | An explicit `uint8_t[]` local reaches warning/null handling and disappears rather than refusing an incomplete object. | Refuse unusable explicit objects at this import boundary. Complete-prefix flexible aggregates and pointers to unsized arrays must continue working; do not invent an extent. |

## Bounded producer and test followers

The demonstrated Linux `strlen` metadata omission is a `follower_gap`. The shipped record at `libr/anal/d/types.sdb.txt:2000–2003` lacks the fixed fact, while `/usr/include/string.h:407–408` independently declares the exact one-parameter API. The retained runtime witness loses its string literal until that fact is supplied. Qualify applicable evidenced producer facts at the host owner; do not bulk-convert old records or infer fixedness from counts.

Required directly affected followers remain:

- Route the two TCC preprocessor/crash controls through the existing header parser. Strict signature admission now prevents `CF #define` reaching TCC. Only the second test's preprocessor portion is ineffective; its overall expected output is not empty.
- Update justified snapshots in `types_prototypes`, `r2pipe2`, `cmd_iw` and relevant bridge extras. The `cmd_iw` mismatch is source-confirmed, not runtime-executed; obtain fixture-backed output before choosing its full replacement.
- Preserve `ghidra_types`' unique global-variable control while correcting its live stale cases. It uses the same command surface and is included by `test/Makefile`; deletion as an assumed duplicate is not justified.
- Correct the invalid `signed int64_t` fixture premise or explicitly test refusal. This does not require a new `afvt` validation API.
- Propagate invalid-specificity refusal from `tfj` at its existing command boundary. `afsj` fails correctly; `afij`/`aflj` omit unreadable data without setting failure, contrary to an initial peer comparison.
- Correct the fmovmem filtered golden: the exact full-C witness retains direction predicates and selector-bearing copies, but `~segmentop` excludes the now-direct field comparisons. No loss of direction logic was demonstrated.
- Name the two declared bridge type files in the 91-case proof claim. The broader 145-case exploratory run contained missing languages/fixtures and does not justify an all-processor requirement.

Runtime/status and producer corrections are `substantive runtime/contract fix` follow-ups. Test-route/snapshot updates are `bundle/proof correction` follow-ups to execute with the selected remediation, not permission to bless every changed output. The 91-case coverage wording is an already-established proof correction and is recorded now.

## Current-user decision: shared-link edit policy

This item is classified as `current_user_decision`, not an automatically authorized clone/repoint repair. The new prepared `afs`/MCP path writes through a shared `link` or `fcnlink` prototype. Root's two-address witnesses confirm that editing the first function changes the second function's signature. A reported real DWARF `_Bird` pair exhibits the same effect. The structured setter already has intentional, tested shared-type semantics; that old behavior is not itself a regression.

The lead and final reviewer recommend isolating `afs`/MCP edits to the addressed function while retaining the explicit structured setter's shared-type behavior. This keeps a per-function command from changing another function's effective contract. The alternative is to keep collective command edits through shared links, which means an address-specific edit can affect other functions and requires explicit acceptance of that behavior. Neither policy was selected by the review. No new database, compatibility layer or generic transaction is recommended.

## Review accounting and resolved disagreements

Five actual Senior/Claude source pairs covered TYPES, SIGNATURE, BRIDGE, NATIVE and PREPARATION. Every source Senior completed independent and reciprocal semantic coverage. The integration Senior validated partition adequacy, direct followers, API/ABI/pin seams, evidence truth and active task records. No required source surface remains semantically unreviewed.

No production finding remains against native patches0220–0260 or the preparation correction. The claimed ineffective `SLEIGHHOME` advice is contradicted by the patch-supplied fixture's `startDecompilerLibrary(getenv("SLEIGHHOME"))` call. Parser regeneration is an expressly disclosed canonical-input refusal. The unsanitized union regression baseline was not observed; sanitizer-only detection remains an inference, not a fact.

The old flexible-tail memory format invented an extent. Prefix-only `pf` output, broader namespaces, member-attribute policy changes, typedef-aware syntax and unqualified global target database repairs were not promoted into this task. Raw TypeCode restore and F_SCOPY printed byte-width limitations remain real disclosed observations, not whole-game approval.

The root applied only three contribution-specific dispensations after reading actual Claude API429 `usage_limit_reached` errors: BRIDGE reciprocal; PREPARATION's missing-fixture follow-up; INTEGRATION initial assessment and its unavailable dependent exchange. Received findings remain considered. No missing answer is agreement, retraction or approval; this is not a task-level review override.

Native Claude plan files are allowed auxiliary artifacts. Separate scratch writes under `/tmp/rv-probe/`, `/tmp/r2review/`, `/tmp/claude_types_diff.txt` and `/home/lucas/.claude/plans/.r2r-unrun.log` exceeded the supplied boundary. Those files were preserved and disclosed. The candidate remained unchanged; no cleanup or harness rewrite is authorized here.

Actual native responses and root analysis remain under `/home/lucas/.cache/codex/radare2/native-type-contract-2026-10-21/local-code-gate/`. The final disposition and this record are `bookkeeping memorialization`. Rejected optional/broader proposals remain `deferred observation`.

## Post-review current-user selection

The user confirmed the recommended correction batch and per-function `afs`/MCP isolation in message `msg_01a15e6f-791f-7d33-b9a7-45a6538715c2` at `2026-10-21T09:28:46.248-03:00` (`America/Sao_Paulo`). The structured setter keeps its intentional shared-type behavior. That decision activated Remediation review in epoch2, with bounded Worker corrections in the existing execution annex. It superseded the earlier pending-decision state without changing that candidate's DO_NOT_PROCEED disposition. The resulting candidate received the separate Remediation delta review below.

## Remediation delta review — current

Final authority: `/root/type_gate_integration_senior`, Senior Code Reviewer / Remediation delta review. Verdict: **DO_NOT_PROCEED**. Route condition: **user-decision**. Required semantic coverage is complete; no required source partition is unread or evidence-blocked.

The fixed candidate is host `1c062e75897c31596aae0115e72846e229e42cf3`, bridge `82d150dcbfffc0f03a91a3e4c3debde8dfd803a5`, native `6f7438da7a942c7a1dd728e2dda08faabe8644b4`, and unchanged MCP `51df6714dc5b40822ab421ac685caa4d3da2a0ae`. No candidate files changed during review. The four Senior source partitions (TYPES, SIGNATURE, BRIDGE, NATIVE), independent integration and final root synthesis close all seven prior findings and their bounded followers. Normal validation remains190 units,54 primary CLI plus42 overlapping followers,94 compositionally covered bridge type controls,12 bridge followers,native54/preparation10/XML/reuse,38 typed/isolation and28 original-game MCP requests. Those passes do not falsify the new witness.

### SIGNATURE-F4: dormant peer bindings defeat function-local edits

- Class and priority: `verified_defect`, P2; follow-up class `substantive runtime/contract fix`.
- Location: `libr/anal/fcn.c:3540–3598`, `function_signature_unused_type_name`, particularly the candidate-only probe at lines3542,3572 and3584.
- Observed fact: normal `t- future` can leave a peer's `link` or `fcnlink` row dormant. Prospective-key selection checks name/prefix records and peers against a probe without those rows. Creating `future` for an edit to another function activates the peer's old reference.
- Required property: the already-selected `afs`/MCP operation changes only the addressed function's effective contract. This policy is closed; the finding does not request a new policy or broader deletion semantics.
- Impact: both actual private-runtime witnesses change the peer from return void / specificity unknown to char / fixed after `afs char future(void)` edits `original`. Each run exits0 with empty stderr, and the peer's binding row remains unchanged. The unchanged MCP setter reaches the same Core owner.
- Recommended closure: `modify_existing_owner`. Account for peer `link`/`fcnlink` references in prospective-key occupancy and retain the existing suffix-selection path. Extend the existing isolation controls for both demonstrated binding kinds. Preserve `t-`, intentional SHARED updates and standalone `afn`; no registry, reference graph or transaction framework is justified.
- Falsifier: both witnesses leave the peer's void/unknown contract and binding intact while applying the addressed declaration.
- Current-user decision needed: select this correction, another evidenced closure or an explicit residual-risk disposition. No selection or risk acceptance has occurred after this new finding.

Exact commands and full observations are retained under `/home/lucas/.cache/codex/radare2/native-type-contract-2026-10-21/remediation-code-gate/dormant-link/{link,fcnlink}.{invocation.json,stdout,stderr,status}`. Root, SIGNATURE and integration reviewed the live causal chain and retained results. The material finding is not eligible for automatic non-substantive correction.

### Review availability and remaining limits

Two fresh native Claude calls, TYPES and SIGNATURE, actually failed with exit1/HTTP429 `usage_limit_reached`, empty modelUsage and no semantic assessment. Both reported quota reset at `2026-10-21T13:20:00-03:00` (`America/Sao_Paulo`). Root directly checked these envelopes and applied the current-Gate failure exception to affected Claude contributions and dependent exchanges. BRIDGE, NATIVE and integration were uncalled while the same observed account outage still applied; they are not described as failed calls or completed reviews. No absent Claude opinion is approval or agreement. This is not a task-level override or a standing exception for later Gates.

All required Senior source and integration coverage is complete, and no semantic disagreement remains among those assessments. No new proof matrix is required. Previously disclosed F_SCOPY rendering, sanitizer, alternate Make, full TypeCode restoration, all-processor, global activation, remote pin and persistence/whole-game limits remain unchanged. Root synthesis and actual error envelopes are in the task cache's `remediation-code-gate/` directory.

The registered transition returns the material correction to the current user and keeps lifecycle Remediation review. The canonical plan is on hold. This disposition and its documentation are bookkeeping only; no correction, new Gate or source mutation is authorized by them.

## Final SIGNATURE-F4 review — PROCEED

The current user confirmed the proposed bounded correction in message `msg_01a15efc-a298-7dd1-8d71-1577497f4199` at `2026-10-21T12:02:57.433-03:00` (`America/Sao_Paulo`). The canonical plan resumed active Remediation review without changing Scope or epoch. This is remediation selection, not an override or approval of the preceding candidate.

Host runtime `4b8fc8f5f67b9571117e721d2fac5f74dd2f45cb` changes only `libr/anal/fcn.c` and `test/unit/test_anal_function.c`. Literal peer `link`/`fcnlink` targets now reserve a prospective name before the existing name probe. The current suffix path, deletion, SHARED setter, standalone `afn`, public API and ABI157 remain unchanged. Both exact witnesses retain the peer's unknown/void signature and binding while applying the addressed edit. The new unit fails on the qualified previous runtime and passes with all43 retained controls in the corrected44-test run.

Root's current proof adds primary CLI54/54, a full unchanged-bridge type run94/94 with corrected-host linkage, and54 actual MCP requests across retained/normal-sharing/dormant-sharing sessions. Evidence is `/home/lucas/.cache/codex/radare2/native-type-contract-2026-10-21/r-f4-dormant-lzUGvC/`. No original executable, saved analysis, global installation or remote was changed.

The new Gate uses the resident's proportional single-Senior procedure: this is a small cohesive private selector correction, one direct test boundary and factual documentary followers, with no new architecture/API/state or independent source owner. The previously completed broad partitions are unchanged. This is a new committed-candidate review, not a downgrade of the old crossed Gate or reuse of its Claude quota dispensation.

`/root/type_gate_integration_senior` reviewed host `1c062e75897c31596aae0115e72846e229e42cf3..5eca6c4577e0fdf0aad08b0425e519a3baf8d686` and issued the final **PROCEED** disposition. Route condition: `not-applicable`; registered transition: enter Closeout. No reportable finding, required local correction or indispensable proof gap remains in the admitted object.

The reviewer inspected the complete two-source-file delta, selector/canonical lookup/FUNCTION-SHARED/Core seams, adjacent isolation/rename controls, all six factual documentary followers, exact baseline/current witnesses and private linkage. It confirmed44/44 function/Core units,54/54 primary CLI, one complete94/94 bridge type run and54 MCP requests across five sessions with unique replies within each session and none for notifications. The source/test candidate matches the qualified snapshot; scoped whitespace checks pass. No source was changed during review, and only excluded host `.refs/` remained untracked.

SIGNATURE-F4 is closed: the peer's literal link/fcnlink references reserve prospective names before the existing probe, conflicts follow the existing suffix path, and both observed peers remain unknown/void with unchanged bindings. Deletion, SHARED updates, standalone `afn`, parser admission and ABI157 remain intact. No unchanged broad review was restarted and no Claude participation was required by this small-delta procedure. Previously disclosed F_SCOPY, sanitizer, alternate-Make, TypeCode, persistence, processor and whole-game limits remain excluded rather than silently approved. Post-verdict changes only memorialize this result.
