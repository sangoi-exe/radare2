# Variadic tail and mapping-capacity correction log

## Authority and baseline

The [Intent Contract](../planning/2026-10-26-native-variadic-mapping.md) owns the new lot. User confirmation is thread01a16717-0b9b-7e10-9f98-d4203ccbfde6 source26961, turn01a1775c-2ee8-7dc2-9f96-9e6f2e5f11bc, 2026-10-26T05:38:12.840-03:00 (America/Sao_Paulo), responding to the complete source26954 paraphrase. Native7a5505bea1ffa74f001c2547e77ad9634e5c7c7f, bridgef77db6387398140600c903bf14fe6b05240dcde5 and host1bfb3eedfbc2c423b97f62f1fdba99119b3ff62f are the initial baselines. Tracked worktrees were clean; `.refs/` was pre-existing and excluded.

The preceding completed lot and its PROCEED_WITH_NITS remain historical results for their exact object and qualified cases. The new reports do not retroactively replace that verdict. This record starts the newly confirmed correction, not another claim of universal input or mapping coverage.

## V1 — locked variadic prefix suppresses tail recovery

### Observed and expected behavior

Input: `/mnt/c/Users/lucas/Downloads/native-adversarial-review-2026-10-26.zip`, member `native-review-2026-10-26/variadic_reused32.bin`. Root compared the72-byte binary with the supplied hex in memory. CALL1018 targets1040; the callee reads entry-stack+8; the caller stores1 and7 and later rereads7 after nonlinear stack alignment.

Actual qualification used `/home/lucas/.cache/codex/radare2/native-pro-followup-consumers-2026-10-24/runtime/w52-map-bridge/r2-exact`, with x86-32, base1000, caller body37 bytes, callee body8 bytes and `x86:LE:32:default:gcc`. With no calllink, production C and native XML contain CALL arguments1,7. With `td unsigned int audited_varargs(unsigned int first, ...);tk calllink.00001018=audited_varargs`, they contain only1 and no incomplete-input warning. All processes exited0 with empty stderr. Inputs were memory-only; no supplied script, guest or rebuilt candidate ran.

Expected: a supplied variadic prefix constrains the fixed parameters, not the open tail. Proven tail input7 must survive, or insufficient knowledge must be disclosed until evidence is available. Clearing/reanalysis must reconstruct the current uncertainty rather than silently making the call appear complete.

### Diagnosis and selected direction

Canonical patch0400:283 returns for every input lock before collecting candidates or consulting positive callee evidence. ActionFuncLink deliberately makes locked variadic calls input-active and supplies an initial placeholder. Late commitNewInputs can instead attach the reference to the first fixed stack parameter, so removing the guard alone is insufficient. Empty unresolved storage then suppresses the existing bridge evidence request at `r2ghidra/src/core_ghidra.cpp:405`.

The inherited guard exists before701f2f6; that commit introduced the uncertainty producer without closing this boundary. No older jointly correct recovery baseline exists. The selected direction is correction at the existing native input/placeholder lifecycle, with fresh dataflow-derived knowledge and unchanged fixed-list/calllink authority. Completed bounded Recon and root inspection distinguish dedicated opaque call-SP tracking from fixed-parameter entry-offset normalization. Before dispatch, root selected two cohesive existing-owner changes: admit active variadic recovery despite the prefix lock, and retain the existing dedicated placeholder across late variadic commitNewInputs rather than replacing it with a fixed parameter. Existing heritage/abort/normalization still own temporary-reference retirement. No parallel SP field, reverse reconstruction from forwarded constants or copied stale uncertainty vector is selected. Actual absence of the required reference at an admitted state returns to root, not an invented fallback.

### Actual validation state

The fresh-prefix product defect is reproduced in C and CALL XML. The explicit late-override/clear/reanalysis test in the ZIP was inspected but not compiled or run. Its independent setInternal→setPieces prototype premise avoids the previous shared-store test defect. The report's transcribed methods and doubles are not native execution. Implementation: not started. Correction validation: pending.

An initial root XML query looked for mnemonic CALL, but this encoder uses numeric opcode7; its zero matches were not absence evidence. Root checked the actual opcode enum and extracted the real CALL/varnode graph. Comments are split across XML tokens; concatenated substring misses were not warning absence. The actual token sequence and C establish the model-hole warning described below.

## M1 — modular end-address check accepts an over-capacity extent

### Observed and expected behavior

Source-proven witness: a65537-byte array at offset0 in a65536-byte native address space. Address addition wraps the last byte to0, so `last < start` is false. ScopeInternal inserts range[0,0] while the MapEntry retains size65537. TypeFactory::getTypeArray, Scope::addSymbol/addMapPoint/addMap and addSymbolInternal impose no capacity comparison on this inspected path. A real two-byte native stack space exists. Runtime admission and bridge reachability were not executed during triage.

Expected: mapping storage must fit the actual address space before publication. Oversized rejection must preserve the ownership/cleanup correction and leave ordinary mappings usable.

### Diagnosis and selected direction

The predicate in `r2ghidra/ghidra-native/patches/ghidra-native.patch:27` compares addresses after modular arithmetic. This predicate is inherited; the previous fix moved validation before ownership and disposed the rejected entry. The selected direction is to validate the starting coordinate and unwrapped extent at the same owner before modular end calculation/publication, preserving existing rejection transport and disposal. A standalone isValidRange call is insufficient for an out-of-range start because unsigned subtraction can underflow. No broader map or coordinate redesign is selected.

### Actual validation state

Root verified production arithmetic and admission anchors and the65537/65536 calculation. Read-only Recon traced the datatype producer and space-width construction. Native execution of this precise extent remains pending. The old C48-in-RAM4 cleanup/refusal control is an existing retained regression, not proof of this new case. Implementation: not started. Correction validation: pending.

## Disposition of the other supplied claims

- Sol's claimed model-hole promotion/uncertainty erasure is refuted for its standard-stack path. forceInactiveChain deactivates the unref hole and later trials during subcall recovery; buildInputFromTrials skips unused trials before materialization/resolution. Root's displaced-reread variant and saved-frame/restore variant both retained the CALL-PC unresolved stack[0x4:4] warning and produced no fabricated argument. The later7 is also omitted; recovery after such holes is a separate, explicitly excluded limitation, not an accepted claim of completeness.
- Continuing after an attempted callee analysis fails would change the current bridge error policy. No such change is selected. Missing/bodyless evidence and attempted incomplete analysis remain distinct existing paths.
- Supplied reports are local advisory evidence, not a new formal Gate. The native restart proposal and isolated probes remain unexecuted by this task. No new CPU/Windows claim follows from the32-bit host-consumer observations or native mapping arithmetic.

## Current execution state

The user confirmed the new lot. `/root/tail26_plan` returned PROCEED after complete Initial Intent Contract coverage and direct authority/source checks. Root applied the registered transition into Implementation. `/root/tail26_sp_reference_recon` completed its bounded lifecycle question with no mutation. The subordinate Microtask Program recorded exact independent T1/T2 canonical and disposable footprints, selected mechanisms, validation dependencies and stop conditions before dispatch. Root dispatched /root/tail26_native_worker and /root/tail26_mapping_worker with isolated baseline-derived validation inputs. Their results are pending; no correction is yet validated. Root retains documentary meaning, integration and Git. No installation, publication or cleanup is selected.
