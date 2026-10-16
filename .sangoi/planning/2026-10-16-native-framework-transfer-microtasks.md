# Native framework transfer — Microtask Program

Canonical Intent Contract: [2026-10-16-native-framework-transfer.md](2026-10-16-native-framework-transfer.md). This subordinate document records execution only. The canonical plan owns Scope, route, architecture, acceptance, lifecycle, strategy epoch and task status. The root updates this projection when dispatch evidence or results change; no Worker owns this file.

## NATIVE-01 — Coherent native NE loading

- Objective: realize the selected synthetic segment coordinates and applied NE internal/import fixups through the existing host loader, preserving original file bytes and ordinal identity.
- Write footprint: host `libr/bin/format/ne/ne.c`, its private `ne.h`, `libr/bin/p/bin_ne.c`, `libr/core/cbin.c`, `subprojects/packagefiles/capstone-v5/capstone-patches/fix-x86-16.patch`, `test/unit/test_bin.c`, `test/unit/test_anal_x86.c`, `test/db/formats/ne` and `test/db/anal/x86_16`. No public metadata field, other decoder, bridge, engine, instructions or lead-owned records are assigned.
- Dependencies and parallelism: host-only implementation can run in parallel with NATIVE-02 and MCP checkout preparation. Validation uses a fresh task-private source/build export, not live source files while another Worker edits their dependencies. Cumulative bridge/MCP proof waits for integration.
- Recon basis: `/root/native_transfer_ne_recon` established target-discriminator and ordinal-list defects, missing overlay callback, existing section/RIO/setup APIs, and the canonical Capstone16 patch's already-broken wrap case. The selected correction remains at these owners, not a new mapper/protocol.
- Acceptance/targeted validation: coherent file↔segment coordinates, applied operands and distinct imports; the three confirmed game edges and five Johnny startup imports; nonfirst-segment near/far targets and the established wrap witness; skipped entry bundles retain ordinal identity. Use existing focused unit owners and available original-file observations. Report unavailable separate testbins fixtures; do not invent passing expectations.
- Status: ready for Worker dispatch.
- Result: none yet.
- Remaining frontier: implementation, private host build, focused tests and original-input observations.
- Stop: owner/API/architecture expansion or missing original/target evidence; no fabricated selectors, new public field, broad dependency reset or source-worktree build spill.

## NATIVE-02 — Real CALL argument SS dependencies

- Objective: supply the current declared SS register to real synthesized CALL stack reads while keeping abstract stack placeholders offset-only, including late heritage/prototype reconstruction.
- Write footprint: one new canonical engine patch `patches/0130-win16-call-stack-segment.patch`, applied after 0110/0120; its generated delta may cover `architecture.cc`, `architecture.hh`, `marshal.cc`, `funcdata.hh`, `funcdata_op.cc`, `coreaction.cc`, `fspec.cc`, x86 `x86-16.cspec` and the existing patch-supplied `src/unittests/testsegmented.cc`. No applied imported-source copies, bridge pin or bridge source are assigned.
- Dependencies and parallelism: independent of NATIVE-01 source changes. Fresh cache-only patch replay/build with matching x86 specifications; previous proof builds remain untouched. Root integrates the engine commit/pin and matching bridge afterward.
- Recon basis: `/root/native_transfer_stack_recon`, final Ghidra commits `b2314ae0710bace02cd110858a1a5459ae1a04c5` and `45dbf35174fc1ef00ab4ba9c9ace64559792c6ef`, current native call/placeholder owners and existing 0110 test driver. Port final metadata semantics, not the deleted CALL-local STORE search.
- Acceptance/targeted validation: known SS binds through actual heritage; unknown SS stays unknown; near addition wraps before segmentation; real arguments remain separate from offset-only placeholder; late `forceSet` reconstruction retains selector dependence. Extend the registered native test owner and exercise the retained fill-wrapper/CALL_RETURN bytes through actual native analysis before claiming full decompilation success. XML copied into the tree is not an executed data test.
- Status: ready for Worker dispatch.
- Result: none yet.
- Remaining frontier: canonical patch, fresh replay, native tests and real-byte native decompilation witness.
- Stop: new framework/bridge-side guessed state or general store forwarding; incompatible metadata allocation without native registry evidence; source footprint expansion.

## NATIVE-03 — Native MCP checkout and workspace integration

- Objective: establish the selected user's fork as independent `r2mcp/`, then integrate parent ignore/navigation and component guidance without changing runtime semantics in that documentary slice.
- Write footprint: root owns GitHub fork, native Git checkout/remotes/branch and pre/post verification. Subsequent Worker content footprint is host `.gitignore`, host `AGENTS.md`, and MCP root `AGENTS.md`; the Worker cannot change Git lifecycle or runtime source. Exact native MCP baseline is inspected upstream `562c0cf23c42b65b3052f0b294d8778c20facbde`.
- Dependencies and parallelism: root preflight must establish the exact local/remote target first. Documentary Worker files are disjoint from NATIVE-01/02. No MCP runtime validation until a separate admitted entry with stable host/plugin dependencies.
- Recon basis: `/root/native_transfer_mcp_recon` traced canonical r2pm package to `radareorg/radare2-mcp`, inspected C/RCore/stdio/decompiler/tool lifecycle and root AGENTS; root verified the local pinned cache source. Existing native server replaces the unnecessary new Python transport proposal.
- Acceptance/targeted validation: owned fork/parent identity, independent exact local root/remotes, root-anchored parent ignore without gitlink/tracked child contents, truthful local navigation. Runtime/tool parity is not claimed by checkout/docs.
- Status: awaiting root read-before-write fork/checkout preflight.
- Result: none yet.
- Remaining frontier: external mutation receipt and fork/checkout, then bounded documentary Worker.
- Stop: authentication/target ambiguity, occupied local destination, incompatible existing user fork or ambiguous external result. Preserve safe state; no reset, deletion, force push or replacement target.

## Not yet dispatched

Qualified helper/profile application and native MCP runtime/persistence remain high-level admitted work packages in the Intent Contract. The root will add bounded entries after current native-owner evidence supplies their concrete direction and footprints. This statement is not a deferral or narrowing of the required result.
