# Intent Contract: native toolchain observations and agent usage

Status: active
Task mode: Doctrine
Lifecycle phase: Remediation review
Strategy epoch: 1
Plan kind: Feature / PRD Plan
Secondary kinds: Instruction / Policy Plan
Plan kind rationale: The requested result adds native binary-format observations, qualified analysis contracts and an MCP query. The existing agent skill is a directly requested instructional follower, not a separate research or harness redesign.

## Confirmed intent and authority

The user wants the three recommendations from the Johnny Castaway and SimTower toolchain scratchpads implemented in the current native tools, plus an agent-facing radare2 skill covering MCP use and startup. The result must preserve evidence provenance, distinguish analysis coordinates from runtime addresses and avoid presenting unproved compiler behavior as a universal ABI.

Current-user decision anchors belong to session `01a15772-6cb8-7670-9ce2-e367137f77b0`. The user selected the three fronts in turn `01a15942-8c6b-7e31-a713-d8f9a97d4dbc` at `2026-10-20T09:21:38.154-03:00`. The user confirmed the complete three-front paraphrase and requested the skill extra in turn `01a1594d-c800-7a82-a86a-ed17106b374f` at `2026-10-20T09:33:52.421-03:00`. The user confirmed the extra-only paraphrase with “sim” in turn `01a1596c-1f63-75c1-9ed6-8a788c992b87` at `2026-10-20T10:07:01.050-03:00`. The applicable timezone is `America/Sao_Paulo`.

The confirmed extra reuses `r2mcp/dist/codex-plugin/skills/reverse-engineering/SKILL.md`; it does not create a competing global copy. It explains CLI and native MCP operation, stdio startup, qualified local components, actual readiness, provenance queries, errors and analysis-preserving lifecycle. Package installation and client configuration changes are excluded.

The current user selected the recommended remediation in turn `01a15a44-5e8b-7c41-9814-c6bf053a65d4` at `2026-10-20T14:03:13.070-03:00`, after the five-finding decision package and the bounded correction recommendation. This decision authorizes canonical OMF corrections F1–F4, current-byte/context dependency qualification P2, focused real-owner counterexamples and the nonblocking skill/documentation clarifications. It explicitly permits correcting affected SEGDEF/LEDATA sizes and mappings. The user reports no Johnny Castaway or SimTower project mappings in use that need preservation. Earlier private synthetic-coordinate observations remain validation evidence, not a migration obligation. No compatibility path, data migration, broader architecture change, residual-risk acceptance or external publication was selected.

## User goal and required result

1. RBin retains and reports OMF `EXTDEF`, `GRPDEF` and `FIXUPP` semantics, including OFF16 versus OFF16L and the source/frame/target evidence needed to interpret unresolved references. Reporting does not become linking or relocation application.
2. The existing exact-image TASM 3.1 profile supplies explicit CF/ZF analysis contracts for the source-qualified helpers. Native conventions preserve the admitted flag outputs and represent demonstrated register effects without inventing register preservation, memory purity or a historical C ABI.
3. MCP exposes a structured, paginated, read-only NE/OMF relocation-provenance query. Source records remain associated with their application sites, including records with no applications. Native owners report incomplete, unresolved or unsupported information explicitly; the MCP consumer does not infer missing semantics or reparse binary records.
4. The existing packaged skill explains how agents use these tools and start/check the native MCP server, without claiming that catalog discovery establishes target or decompiler readiness.

## Scope and non-goals

The scope includes canonical host OMF/NE parsers and their direct plugin/test followers; the existing TASM profile, native x86 convention/test patch owners and necessary bridge integration/pin followers; the native MCP query/registration/tests/product documentation; and the packaged skill with directly necessary references. Lead-owned plan, task log, changelog and workspace-map updates belong to this one task.

Retain existing ownership: RBin interprets file formats, host analysis qualifies exact images, native specifications model decompiler storage, the bridge imports those contracts, and MCP presents native results. Prefer existing private format state, plugin callbacks and Sdb metadata. No public `RBinReloc` layout expansion is selected.

Non-goals: an OMF linker; final external/group address resolution; gratuitous changes to correctly decoded OMF synthetic placement merely to support reporting; a universal Borland ABI or compiler-identification heuristic; a full CPU/helper-effect emulator; resolving opaque TASM descendants outside the established helper/caller windows; support for every executable format; an MCP-side binary parser; a new transport, service, persistence layer or proof framework; automatic package installation or agent/client configuration; unrelated cleanup; external publication or a new external Pro Gate. Correcting the demonstrated SEGDEF/LEDATA decoding errors and their affected geometry/mappings is explicitly in Scope under the current-user decision above; preserving those incorrect results is not a compatibility goal.

The pre-existing host `.refs/` directory is outside the task. Preserve all unrelated work. Existing original compiler/platform evidence is admissible; game ports, rewrites and emulator implementation code are not foundations for recovered game behavior.

## Selected route and evidence

Initial discovery selected extension of the existing owner chain rather than another backend. At that baseline, OMF loaded unrecognized record families into zeroed generic payloads and discarded temporary records after object construction (`libr/bin/format/omf/omf.c`, `libr/bin/p/bin_omf.c`). The real retained TASM 3.1 paired objects differ at the FIXUPP LOCAT type, with the same source bytes and target/frame data; they provide the initial OFF16/OFF16L observation. Complete FIXUPP/THREAD decoding uses the admitted owner-controlled implementation as its foundation, not assumptions copied between implementation and tests.

The exact-image TASM profile already owns helper bounds and qualification. CF at logical `8c61` and ZF at `f687`/`f606` are established helper outputs. Finite caller inspection proves flag consumption but does not prove all changed register values dead; in particular, AH/DX reach opaque boundaries and the ZF continuation consumes current DS/ES. The established native retained-state convention style is available in `patches/0140-borland-qualified-prototypes.patch`. The new contracts must not use a flag-only declaration to manufacture preservation or erase current selector state.

NE already publishes raw-record/application provenance in format-owned Sdb, but missing applications and a zero count do not establish a particular resolution/completeness state. Add the necessary status/address-domain facts at that producer. The MCP query must read native cached/format-owned data directly: `irj` can call `r_bin_patch_relocs()` and change caches, so wrapping that command does not satisfy the selected read-only contract.

At initial discovery, the packaged skill covered a short analysis workflow but not startup/readiness. The implemented candidate now includes that guidance; remediation clarifies the observed distinction between instruction translation and selected native C decompilation. The server defaults to in-process RCore with stdio. `-t` exits before RCore initialization, `-T` is local DSL execution rather than MCP transport, `-H` selects HTTP server transport and `-u` selects a remote r2pipe backend. Preserve these distinctions instead of introducing a launcher or copying an exhaustive manual.

No competing material route remains selected or pending. Linking/applying OMF references and a second skill/backend would produce different results or duplicate ownership and are outside the confirmed scope.

The selected remediation repairs the existing format producers instead of adding downstream reconciliation guards or marking erroneous output unsupported through prose. F1 distinguishes actual module boundaries from additional source headers. F2 retains the shared LNAMES/LLNAMES namespace. F3/F4 repair canonical SEGDEF/LEDATA interpretation so host sections and provenance agree. P2 checks the current known callee ranges before installing contracts whose preservation depends on those ranges; manual-metadata rejection is not treated as changed code. Existing current-byte/context checks own qualification. No general dependency graph, effect engine, opaque-callee analysis or MCP decoder is admitted. The existing metadata/status contract remains unchanged; documentation clarifies subrecord parsing/support, reference definition and application enumeration rather than adding a new aggregate-status requirement.

## Acceptance and primary-path activation

- The real OFF16/OFF16L pair yields distinct, source-bound native OMF fixup semantics; external and group references survive object loading. Unresolved targets remain unresolved. Correctly decoded existing section/symbol placement remains intact; the admitted SEGDEF/LEDATA counterexamples receive corrected geometry and consistent native application coordinates. Additional source headers and shared LLNAMES indices retain the demonstrated single-module provenance and identities.
- Qualified TASM helper signatures reach the matching native models. Focused storage/contract checks and actual native caller/decompiler observations verify the admitted CF/ZF behavior and relevant current-register state. Changed known-callee bytes/context prevent installing dependent preservation contracts on a fresh qualified input, while unrelated functions and manual metadata remain intact. A storage-layout-only test is not reported as flag computation or caller-flow proof.
- A real MCP stdio client can initialize, discover and invoke the new query on matching host inputs. Results preserve record-to-application relationships and explicit evidence status for NE and OMF. The query does not apply relocations, change input bytes or implicitly run analysis; pagination accounts for source records.
- The revised skill's commands agree with live help/source and a bounded startup/target-read observation. Native decompiler readiness requires an actual matching plugin/language observation. Existing analysis is not silently discarded for a close/file-switch example.
- Focused existing tests and directly justified regressions pass; required build or runtime gaps are disclosed rather than replaced by source-only claims. The final change set receives the registered local Code Gate and honest task-owned commits.

The first directly verifiable slice is native reporting of the retained paired OMF objects through the canonical RBin loader, distinguishing location types without applying references. A bounded original-format fixture can protect that same behavior once its independent foundation is established. The other fronts proceed at their existing direct boundaries rather than waiting for an exhaustive future inventory.

The first remediation slice adds focused counterexamples at the existing RBin OMF and exact-image TASM test owners, observes the reported failures against the current candidate, then verifies the selected corrections and unchanged controls. Integration observes the corrected host through the existing native MCP/decompiler chain. The two source domains can execute independently in isolated validation copies; shared host validation waits until its inputs are stable.

## High-level work packages and owners

1. Native format producers: retain OMF fixup/external/group semantics and add the NE/OMF provenance/status needed by the query; focused parser/host checks.
2. Qualified analysis: implement the TASM host/native contract chain, validate native storage and caller observations, then propagate the committed native revision through the bridge's canonical pin and qualification documentation.
3. Native query: consume the stable host evidence, register the read-only MCP operation and validate real stdio responses and pagination.
4. Agent usage: extend the existing packaged skill after the query/startup behavior is stable, and verify its operational recipe without installing/configuring clients.
5. Integration and closeout: inspect cumulative owner/follower changes, run proportionate final validation, commit coherent candidates, obtain the default paired local review, record task log/changelog and inspect final Git state.

The root owns technical direction, the mutable Microtask Program, integration, final runtime observations, documentation semantics, Git lifecycle and commits. Registered Workers implement bounded source/instruction entries and targeted validation. Separate write footprints permit parallel implementation only while validation read dependencies are stable. No implementation starts before the Plan Gate.

## Continuity

Baseline host: `5981cfc8d1504759949f167209beea4ef2977184`.
Baseline bridge: `da5b916d329a33da2356f4aea20103c8395a1b7f`.
Baseline native engine: `56624b8f25b497dce4c1c2afcbf9d9c812ebff77`.
Baseline MCP: `5b91b9c05d412b9b1663381e34f628df0cce27e4`.

The preceding dependency/preparation task is complete and published; it is not reopened by this plan. Initial recon was read-only. The OMF grammar foundation is the official Open Watcom implementation at `979e202f1aec744940a8aa57c21dcd0f4dd47fd4`. The fresh private host Make/install, OMF2/NE2/RBin15/TASM9 unit cases and real NE r2r case pass. Official test fixtures were fetched at `radare2-testbins@221fc02993747ed1ceb82aa1f22eb8f12e29ff51`; native comparison established the retained NE sample's byte identity. The existing checkout's Make fails at its missing optional `subprojects/otezip`; the independent private build excludes optional ZIP plugins without modifying product source or checkout configuration.

Integration evidence exposed a proof-preparation error: copying the TASM delta with its old timestamps made Make retain the baseline analysis object. The registered path therefore had no new return types, while the source-including unit expected them. ASan localized the resulting null comparison; the timestamp/source overlay is corrected before claiming a current compiled TASM result. Do not count the first Make status as proof that the TASM delta was compiled.

Actual native F687 inspection exposed its fully known 074B leaf using an inferred near convention that fabricated an AL result. The finite correction now supplies the qualified void/DS far-leaf model through the existing host/native chain. Native original-body tests verify its four-byte frame, absent call result and established preservation. Matching production MCP observations import all four models and retain the original CF result, fresh F687 predicate and padding caller's ZF/current DS/ES. Six opaque work descendants remain excluded. Owner, architecture, requested behavior and Scope remain unchanged.

The matching bridge/plugin/languages build and all three registered checks pass: native units34/34, preparation and p-code XML. Full MCP `make test` passes with the NE/OMF original witnesses enabled. Initial full-suite/number-test failures also reproduced at the MCP baseline; actual native replay traced them to hidden task-cache fixtures opened without an explicit `-s` scope. The existing test producers now admit only their owned fixture directory and assert opening success; runtime policy, test oracles and explicit refusal cases are unchanged. The packaged skill includes the exercised startup/provenance path and the existing cast-display option needed for semantic C inspection.

Current-user decisions open: none. Turn `01a15a44-5e8b-7c41-9814-c6bf053a65d4` selects correction at the existing OMF and TASM owners, including affected existing geometry/mapping changes. The source counterexamples and the directly affected skill/documentation follow the selected two-domain remediation; no source finding is accepted as residual risk.
Residual-risk acceptance: none supplied.
Plan audit: `/root/toolchain_plan_audit` returned `PROCEED` for the complete initial Intent Contract. All required fields were reviewed; no material finding or current-user decision remained. The sole matching resident transition publishes the same plan locator and enters Implementation without another authorization checkpoint.
Previous Code Gate: `/root/toolchain_integration_senior` issued the final cumulative `DO_NOT_PROCEED` for host `a1e9fc93025ab77f2a22fd62aaafab797ac6dbed`, bridge `0405ec5e39bc95d797d9e74c3fc4d671baff7592`, native `3ee06068bc8e5c483bbb35a45a23b9f4eafadfa6` and MCP `ea78625ee962fdd352cb222e115e2e9dd4ce7857`. Required semantic coverage was complete for all 28 paths. Its recorded actual-call-error exception covered only the missing formats-Claude completion/reciprocal, not initial findings or required Senior coverage. That exception is not a standing dispensation for a new review. The task log records evidence, disagreements, proof limits and the decision package.
Remediation baseline: host `18b8656ea56cc31cb335c9b6d775eacada1ab29c` records the blocked review without changing runtime sources; other repository candidates remain as recorded above. The original negative Gate remains historical evidence and is not relabelled as approval.
Amendment audit: `/root/toolchain_plan_audit` returned `PROCEED` after complete current-user authority, mapping-acceptance and primary-path coverage. The matching transition publishes the existing plan locator and enters Implementation without another human checkpoint. Selected substantive corrections then execute in Remediation review under the existing owner chain.
Remediation implementation: source commit `5f3f694a3a1d8e3301a76cef29c8b323fed9da6b` implements F1–F4/P2 with actual failing-before/passing-after regressions. MCP documentation commit `95bc806fbfc1b0de0813744299fa71756aaddec9` clarifies native readiness and provenance semantics without changing runtime behavior. A fresh combined host build/install passes OMF 7/7, NE 2/2, RBin 15/15 and TASM 12/12; the freshly linked MCP full suite and original-input native provenance/decompiler observations also pass. Bridge/native source and pin remain unchanged. These are implementation/proof results, not a final review verdict.
Blocker: none.
Next action: submit the committed consolidated candidate to registered local Remediation delta review. Use crossed review because the OMF interpretation/mapping and TASM qualification domains are independent and materially affect analysis; assign source pairs to those two domains and the integration pair to documentation, seams and cumulative closure. Keep source fixed during review. Strategy epoch 1 and the canonical owner chain remain unchanged.
