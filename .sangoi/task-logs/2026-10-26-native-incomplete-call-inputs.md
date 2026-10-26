# Incomplete native call inputs: causal record

## Authority and baseline

The [Intent Contract](../planning/2026-10-26-native-incomplete-call-inputs.md) owns this new lot. User request source30537 and paraphrase confirmation source30611 are in current thread01a16717-0b9b-7e10-9f98-d4203ccbfde6; source30604 contains the confirmed scope. The exact rollout, turn IDs and America/Sao_Paulo timestamps are in the contract. The earlier read-only M1 authorization did not authorize implementation; this newer confirmation does.

Baselines: host1bb23d47afe1f9af0d1059102b77cb60f7cf130e, bridge86a0b12e30c97abeead4013a293ddd6c05ef0501, native37cd3df63a96b4b16669b2131ccb6ca6102a6b8d. Root observed clean tracked trees and only the pre-existing excluded host .refs/. P0=/home/lucas/.cache/codex/radare2/native-fixed-input-slices-2026-10-26 supplies the unchanged evaluated baseline, matching private runtime and actual captures. P=/home/lucas/.cache/codex/radare2/native-incomplete-call-inputs-2026-10-26 is this lot's fresh operational owner.

## H1 — known later storage loses its call association

### Observed versus requested behavior

The exact 72-byte x86-32 saved-frame case is retained in P0/evidence/integration/17-model-hole-{pdg,pdgx}.command.txt and their stdout/stderr/status siblings. Both processes exited0 with empty stderr. Root reread the full C output and exact command: STORE7 at1010 remains, the CALL1018 to1040 has no input arguments, and the warning still names unresolved stack[0x4:4]. The existing callee body reads stack[0x8:4]. The missing result is the value/storage association with the call, not the value disappearing from the whole function or the warning being erased.

Requested result: retain the known storage/value as actual call dataflow while explicitly withholding source parameter position and arity. A plain callee(7) would falsely assign the first source position; a manufactured first argument would assert another unproved fact. The completed R4 log's model-hole investigation is historical diagnosis evidence, not a current implementation approval or a passing sparse-input test.

### Established cause and selected direction

Native recoverCallRelativeInputs links an admitted reaching STORE value to a trial and a real CALL input. The positive callee snapshot is currently consulted only in the competing-read branch. Standard model selection can deactivate the later trial after a missing first resource; buildInputFromTrials keeps only used formal trials, replaces the CALL input vector and deletes/reindexes unused trials. ParamTrial holds storage and a slot, not independent value ownership. Existing unresolvedInputStorages holds only VarnodeData locations. Ordinary operand ownership updates Varnode descendants; a metadata-only Varnode pointer would not protect liveness.

Selected direction: preserve positive observed call-storage evidence independently of dense formal selection, retain the actual value edge in CALL operands, and have FuncCallSpecs expose an explicit incomplete storage mapping to direct consumers. Source parameters and storage observations remain distinct. The first native run must measure the exact active-trial/model/finalization transition for this witness; the intermediate chain is currently source-established, not a fresh runtime trace in this lot. A contradictory trace changes the diagnosis before a correction is dispatched.

### Direct consumer and codec constraints

/root/hole_storage_recon and /root/hole_consumers_recon read the current owner and two bounded continuations. Root directly verified current fspec.hh/cc storage and finalization, Funcdata operand linking, native ActionActiveParam ordering, the admission branch, SubvariableFlow narrowing, the printer's functional notation, bridge pdgx entry point and Funcdata::encode boundary.

Material native followers include slot-based TypeOpCall typing and hidden-this printing, locked-call type/naming inference, union scoring, constructor recognition, input consumption, and active/post-recovery input joining or narrowing. Existing generic SSA traversal does not establish source-parameter knowledge. There is no inspected central slot-to-formal-role accessor; propagation must use the new explicit callspec semantics rather than sprinkle unrelated fallback behavior. The exact implementation footprint will follow these direct owners and diagnostics, not a speculative repo-wide matrix.

Funcdata::encode(saveTree=true) also serves PackedEncode in DecompileAt. Its persistence decoder does not consume arbitrary analysis-tree children, and FunctionSymbol persistence uses saveTree=false. A new shared codec child would introduce an unnecessary external receiver frontier. The selected pdgx wrapper export avoids that schema expansion; source facts remain native-owned. Native functional printer tokens already support real op/Varnode references. Raw pdgx preserves those markup references; JSON code retains its current selected annotations and is not promised a new structured argument API.

### Actual implementation and validation state

No files implementing the correction have changed, and no new build or target execution has run. Prior R4 observations are reused only for unchanged baseline facts. A native-only first trace and focused failing assertion are the next decisive proof. There is no known-good sparse implementation to restore. /root/hole_plan returned PROCEED with full planning coverage; the unmeasured internal transition is the explicitly acknowledged H1 proof gap, not a blocker for observing it. Root read the exact transition, entered Implementation and published the existing locator before dispatch. No current-user material decision remains pending within the confirmed native-owner route; a new owner, host persistence or packed-protocol requirement stops its affected frontier.
