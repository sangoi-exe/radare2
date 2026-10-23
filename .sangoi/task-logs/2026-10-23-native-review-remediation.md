# Native review reproduction and remediation

Date: 2026-10-23
Owner: [Intent Contract](../planning/2026-10-23-native-review-remediation.md).
State: Implementation; Plan Gate PROCEED; no production mutation or correction attempted.

## Intake and baseline

The current user confirmed the five-group reproduction/correction Scope in thread `01a16717-0b9b-7e10-9f98-d4203ccbfde6`, turn `01a16733-ed99-7330-a2a2-fe76b18a70ce`, at `2026-10-23T02:20:19.001-03:00` (`America/Sao_Paulo`), source line152. The previous session ended at report intake, not authorized remediation. Its completed plan remains historical.

Read the full supplied `report-23-10-2026.txt` and selected evidence/test members of both supplied ZIPs without extraction or execution. The recorded probes use transcribed methods with doubles; they are not integrated product execution. Local heads match host c0416b53bc, native168c8b6fb5, bridgeff776a846f and MCP856845ccf9. Host `.refs/` is pre-existing and remains untouched. The first two passes use 30/10/6/5 commit ranges; the isolated pass uses 31/10/6/4, with different host/MCP bases.

Native N7 source/build evidence was recovered through existing task references, not directory recency. Source is `/home/lucas/.cache/codex/radare2/native-semantic-type-fidelity-2026-10-21/n7-display/run-4Q7dF8/source`; matching build is its sibling `build`. Recon compared every currently tracked non-src canonical file and checked the existing preparation fingerprint against its inputs. Root executed the retained binary with matching SLEIGHHOME and exact tests `flat_conditional_stack_store_negative`, `flat_conditional_stack_store_positive`, `qualified_volatile_equal_sized_member`: 3/3 passed, exit0. This proves retained controls only. Observed free space was about13GiB; no cleanup is authorized or performed.

The Initial Intent Contract audit on `/root/review_remediation_plan_audit` returned PROCEED with complete contract coverage and no material finding. Its result admits the first real-native witness slice and preserves the user decision boundary for a required material contract change. Root recorded the transition to active Implementation; no extra execution permission is required.

## V1 — converted volatile STORE loses memory classification

- Observed versus expected: canonical patch0290 converts STORE to CALLOTHER without clearing the spacebase mark. RuleIndirectCollapse can bypass the STORE-only guard and replace an alias-possible returned value with its pre-write input. Expected: qualifying a write preserves its memory dependency as well as observability.
- Evidence: patch0290:161–177; imported ruleaction.cc:3175–3244 combined with patch0170's mayAlias change; opcode-list changes at op.cc:912–949; heritage guardStores:1538–1556; StackAffectingOps::populate at merge.cc:63–75; ActionMarkImplied::checkImpliedCover at coreaction.cc:3529–3558. Root inspected the conversion, collapse, guard enumeration, merge and crossing paths. The Bug Hunter accounted for direct producer/consumer coverage.
- Cause: source-proven conditional classification loss after representation conversion. The collapse premises include a live effect, retained spacebase_ptr and an INDIRECT output without no-local-alias. Heritage reprocessing can remove those premises in some paths. Normal-schedule reachability and an incorrect native return remain unobserved.
- Selected direction: preserve CALLOTHER representation and repair memory-effect equivalence through existing owners/direct consumers after real witnesses. Reuse builtin identity, existing operand encoding and conservative guards. Do not merely clear the flag. Retaining LOAD/STORE is unselected because it changes the encoded operation contract and requires a different observability mechanism.
- Implementation: none. First admitted work is real native-method and normal-pipeline reproduction in a fresh private snapshot, not a production correction.
- Validation: existing ordinary/struct controls 3/3; new witness not run. No correction success claimed.

## V2 — single-member volatile union

- Observed versus expected: patch0290:295–333 descends through STRUCT/ARRAY but not UNION. An equal-sized unqualified union with one volatile scalar returns no member qualifier. Expected: the unambiguous member access remains observable.
- Cause: helper branch omission is source-supported; actual native helper/pipeline results remain to be executed.
- Selected direction: reproduce using real TypeFactory and QualifiedAccessEnvironment; retain current representation. Exact correction unselected until the native witness establishes the boundary. No arbitrary first-member rule for ambiguous unions.
- Implementation/validation: none; external copied-helper failure is not local native evidence.

## E1 — enum width disagreement and bridge default

- Observed versus expected: host get_enum_type defaults to32 at libr/anal/type.c:358–359; layout defaults to root type.int.size at libr/util/type_layout.c:125–127; save_enum persists a nonzero exposed width at type.c:722–729. Bridge queryR2Enum at src/R2TypeFactory.cpp:591–623 uses a native global-width constructor. Expected: effective width is consistent across layout, read/save and native import.
- Cause: separate default selection and missing width propagation, present in the supplied baselines. The source predicts16/32/32 for target-int16 without an explicit enum size; this is not yet a local executed result.
- Selected direction: establish actual host read/save and bridge construction witnesses, then consume the same effective target width at existing owners. No MCP JSON compensation or mutation of a native global default. Any required material API choice remains unselected.
- Implementation/validation: none.

## C1 — explicit convention and operational fallback

- Observed versus expected: libr/anal/fcn.c:3037–3054 can return a recognized existing operational CC when the recorded CC is unrecognized; apply preserves the original Sdb record and synchronizes the operational field. R2Scope consumes the operational CC. Expected: faithful admitted explicit behavior without defeating the user's intentional afc selection.
- Cause: conditional inherited selector behavior is source-supported. A concrete wrong result under the selected operational/source contract still requires production-path observation; the original declaration is not erased.
- Selected direction: test apply, stored metadata, operational field and native diagnosis together, including deliberate afc priority. Exact correction unselected. Blanket host-only CC rejection and indiscriminate unchanged-path resynchronization are not selected.
- Implementation/validation: none.

## F1 — inherited prefix-related CALLF constructors

- Observed versus expected: imported ia.sinc:2991,2997–2998 uses addr16/addr32 directly as target; these constructors provide effective addresses, not loaded FAR pointers. Patch0320 fixes only the16/16 constructor. Expected: the target depends on the pointer contents with corresponding address/operand widths and return behavior.
- Cause: source-supported omission inherited from base6f7438da7a; the imported ia.sinc blob is unchanged across those refs. Neither Sleigh execution nor original-game reachability was observed.
- Selected direction: verify the instruction contract against an owner-controlled source and exercise matching real Sleigh translation before correcting the existing specification/patch. No host workaround.
- Implementation/validation: none.

## Deferred observations

- First-pass identity-prefix and sanitizing-writer issues are outside the confirmed five-group correction Scope. Root confirmed the literal key encoder and read/write asymmetry only; persistence/native-collision consequences remain unvalidated.
- The first report's blanket CI-absence claim was withdrawn by its successor. No CI inventory was performed here.
- Historical plan-locator recovery returned no valid marker even though historical marker-shaped messages exist. No helper diagnosis or repair belongs to this task.
- Historical closeout prose says no push occurred; later source messages authorized and reported a push. Preserve chronology rather than rewriting that completed plan during this task.
