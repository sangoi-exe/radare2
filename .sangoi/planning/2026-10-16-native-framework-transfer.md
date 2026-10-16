# Native RE framework transfer — Intent Contract

Status: on-hold
Task mode: Doctrine
Lifecycle phase: Implementation
Strategy epoch: native-transfer-1
Plan kind: Feature / PRD Plan
Secondary kinds: none
Active annexes: `.sangoi/planning/2026-10-16-native-framework-transfer-microtasks.md` — root-owned mutable execution projection; current dispatch/dependency state only. This Intent Contract retains all intent, Scope, architecture, acceptance and lifecycle authority.

## Confirmed objective and required result

Make the selected radare2 + r2ghidra + ghidra-native framework usable for Johnny Castaway and SimTower without a JVM analysis backend. Complete the relevant transfer of the existing Ghidra extension's implemented compiler/toolchain knowledge, segmented decompiler corrections and MCP workflows. This is the complete transfer task, not another isolated fmovmem demonstration. Continue in the current session where tools permit; elapsed time does not narrow the requested result.

The current user confirmed this paraphrase and route: correct NE loading, relocations, imports and Protected Mode selection; distinguish synthetic analysis coordinates from unknown runtime selectors; port the relevant qualified Borland helpers, profiles and segmented-C corrections; preserve manual analysis and refuse invalidated contracts; reuse and fork the existing native `radareorg/radare2-mcp` server at `/home/lucas/work/radare2/r2mcp`; and validate original inputs through loading, analysis, decompilation/p-code, MCP and saved-analysis reopening. Do not modify the originals, remove Ghidra, automatically migrate its databases or promise every old MCP endpoint.

The primary kind is Feature / PRD because the deliverable is an integrated user workflow with executable native capabilities. Loader corrections, repository setup and validation support that result; they are not separate research or migration deliverables.

## Current-user decisions and authority

- Continuation and publication request: turn `01a1469d-6434-7382-a855-06a01e3a3550`, `2026-10-16T18:28:05.545-03:00` (America/Sao_Paulo), “pode dar push, vamos seguir nessa session até terminarmos toda a transferência e ajustes pra poder usar o novo framework no johnny e no simtower”. Publishing the three existing reviewed branches has completed and is not pending implementation.
- Explicit confirmation of the full paraphrase, native MCP route, fork and fourth checkout: turn `01a146b0-1cdf-7462-be60-b121142d87f1`, `2026-10-16T18:48:29.513-03:00`, “perfeito, confirmo”. The preceding assistant proposal names all of the required result and non-goals above. This confirmation authorizes the local Intent Contract audit, not a silent implementation start after its normal result.
- Selected workspace remains `/home/lucas/work/radare2`, with independent nested Git repositories. Add only the selected `r2mcp/` sibling of `r2ghidra/`; do not turn the layout into submodules or a fourth umbrella repository.
- Fork `radareorg/radare2-mcp` into the current user's `sangoi-exe` account and establish the corresponding local checkout through the existing Git/GitHub owners after implementation activation. Verify identity and existing remote/local targets first. Preserve any existing repository or branch; no force push, branch deletion, master replacement, PR or unrelated external write is authorized.
- No material route decision remains open. Later current-user message at `2026-10-16T18:53:57.443-03:00`, turn `01a146b0-1cdf-7462-be60-b121142d87f1`, source rollout line 12449, explicitly says “pode seguir pra implementação em caso de proceed, e no code gate vá de local”. This authorizes entry to Implementation on the actual Plan Gate `PROCEED` without another human confirmation and selects this task's first local Code Gate. It does not override the Gate's semantic result or represent an absent verdict as a pass.

## Current owner evidence and baseline

The existing clean, published `win16-fmovmem` heads are host `9ab8dc62e0cf395b293d010a856f4512f6503a65`, bridge `a68b0f0749f7cc7fec3648a648efa7af86e1c28c`, and engine `5c546bd90538359374da167c0aefcfd4d3f5715f`. The bridge wrap remains the sole engine dependency pin, currently `8c0a00933c9d19d493c3858799bb3f8d0388f2fa`. A fresh depth-one network fetch of that exact published object succeeded. This proves pin availability, not a fresh network-only build.

The completed first-slice plan and log retain the qualified native fmovmem evidence and focused test results. They establish a useful known-good baseline for that behavior, not full migration approval. Its engine patches already preserve selected segmented address dependencies and provide the exact `borland_fmovmem_16far` model; its bridge selects exact native convention names. Automatic recognition, the other helper contracts, call-only SS metadata, coherent NE loading and native MCP integration remain unfinished. Preserve reusable evidence only while its causal inputs remain unchanged.

The source extension is `/home/lucas/work/ghidra/extensions/ghidra-legacy-toolchains` at Ghidra commit `9ba90c3b53870d33f6b36023a6237a4e30cc81f7`. Its `docs/usage.md` identifies eight exact-image profiles, complete helper families, relocation provenance and bounded NB02 observations. Source and original-byte evidence own the facts; documentation is navigation, not permission to reproduce an unsafe mutation.

Bounded Recon verified actual loader defects. Host `libr/bin/format/ne/ne.c` selects direct versus ordinal internal relocation targets from the source segment's mobility rather than the relocation's target discriminator. The NE plugin has no `patch_relocs` callback, while the bridge reads current host I/O bytes. The selected originals contain unresolved relocation-chain placeholders, and retained Johnny C has five `func_0x0000ffff()` calls. The bridge's ordinary x86/16 mapper selects Real Mode. Existing RBin/RIO mapping, overlay relocation writes, host segment granularity and native tracked-register APIs can carry the selected solution; no replacement loader or context framework is evidenced as necessary.

The canonical r2pm package resolves to `radareorg/radare2-mcp`; its historical `dnakov` URL redirects there. Inspected commit `562c0cf23c42b65b3052f0b294d8778c20facbde` implements C/RCore stdio MCP and selects r2ghidra through its existing decompiler tool. A task-cache checkout supports local inspection. No build or game integration of this server has yet run. Its current file switch closes the prior analysis, and its exposed tools do not establish project-save/reopen or static-context/p-code parity.

The finite post-ledger game ranges were screened at fixed tips: Johnny `7841f14702410ea427d373fcc4908efa3e29d225..5d261bdc73421855ac5ca81e8e37f9ce74181b3d` (33 commits), and SimTower `c7daad1f9df2ecde55021612fabe4a0c9bf261e5..a7457b229de428c15b71eafd1122aeb61f8a24ce` (22 commits). Selected technical diffs add BCC3.1 mode/selection/publication and BCC4.5 cleanup/cache/expression-lowering facts, not a new proven generic helper ABI or decompiler failure. Do not chase moving game HEADs or promote scratchpad indexes, unresolved joins or reconstruction results into generic analyzer contracts.

## Selected system and canonical ownership

Use the existing native owners as one connected system:

- **radare2 host:** binary-format loading, original file/segment coordinates, relocated analysis-memory views, import identities, analysis functions/types/references and native project persistence. Qualified compiler/toolchain facts enter these existing analysis owners; their recognition must not depend on Ghidra Java scheduling or ProgramDB semantics.
- **r2ghidra bridge:** native language selection, coherent host-to-engine addresses, qualified register/context input, types, prototypes and decompilation/p-code export. Compose tracked values through the existing context database without erasing required existing/default values such as DF. Do not invent DS/SS values for every function from startup metadata.
- **ghidra-native:** canonical patch/specification owners for segmented address semantics, call/stack corrections and evidenced ABI models, with their existing native tests. Keep imported source followers generated from the patch stack; update the single bridge pin when the selected engine changes.
- **r2mcp:** the existing C server owns MCP tools, stdio transport and its RCore lifecycle. Extend its actual tools only where the demonstrated workflow needs a missing operation. Do not copy Ghidra's Python HTTP discovery/schema/backend protocol or build another MCP server.

NE uses deterministic synthetic analysis segment coordinates compatible with the protected specification's `(segment_id << 16) | offset`. File offsets remain distinct and recoverable. These identifiers are not claims about Windows runtime selector values. Sections, entries, symbols, relocation sites/targets, near/far control flow and bridge lookups must agree. Preserve ordinary MZ/other x86-16 mode behavior; an NE correction is not permission to select Protected Mode globally.

The existing native MCP owner removes the need for the previously considered Python SDK/pipe adaptation. That adaptation would add backend/tool lifecycle ownership without an established missing capability that requires a replacement server. The current user selected existing-native-server reuse. Keep upstream-facing changes at their canonical owners and avoid parallel fallback paths, aliases or duplicate pins.

## Transfer boundary

Transfer the extension's current qualified helper contracts: F_SCOPY, forward far copy, the distinct fmovmem core/fmemmove wrapper family, F_PCMP, setmem/memset and the three word-pair shifts. Preserve each contract's actual record layout, finite domain, register effects and near/far frame limits; do not replace them with modern flat-pointer library prototypes or infer compiler-release exclusivity from shared bytes.

Transfer the eight existing exact-image profiles: BCC2.0, BCC3.1, BCC4.5, TASM3.1, TLINK4.01, TLINK5.1, SCRANTIC and SimTower, including their admitted static mappings and selected facts. Tool-image profiles support compiler-assisted RE; they are not universal compiler recognition or prerequisites for every game function. Incorporate the screened new technical facts only where retained original bodies and qualified current state support the exact assertion. Preserve explicit unknowns, incomplete semantic coverage and nonterminating/conditional domains. Transfer relocation provenance and bounded NB02 structural observations without manufacturing a debug-symbol/type importer.

Port the remaining evidenced segmented decompiler corrections, including the call-only SS/argument case, through the native owners. Reproduce their requested effect at the current extracted-engine interfaces rather than copying incompatible marshal IDs or Java machinery. Printed segmented C remains analysis notation, not a promise of historical or host-compilable source.

Native mutation must qualify the state it changes and any inputs on which dependent edits rely. Original-image identity alone does not authorize replacing current analysis. Conflicting definitions, references, function bodies/contracts and flow state remain independent preservation boundaries; preserving a prerequisite also stops its dependent edits. Do not reproduce destructive Java clear/recreate paths or add a generic provenance/mutation subsystem merely to imitate their repair proposals.

The six admitted audit classes remain concrete acceptance witnesses where a corresponding native operation exists: changed TLINK inline length; independent manual references in data-conversion ranges; override-only VPRINTER edits; references associated with preserved switch cells containing real pointer values; helper rename/body/purge-only edits; and patched or context-incompatible partial windows. Exercise the actual native production owner, or establish why the removed Java-only operation has no native mutation counterpart. Do not fabricate a counterpart or claim an unrun regression passed.

## Primary-path acceptance and immediate oracle

Use the supplied original SCRANTIC and SIMTOWER images read-only, with the matching rebuilt host, plugin and language specifications. Both must load as NE with usable segmented analysis maps, resolved internal calls and distinct module-plus-ordinal imports. The demonstrated connected edge witnesses are Johnny `1:00b1 → 2:0000`, SimTower `1:0007 → 79:02d7` and `79:02ef → 1:1a55`; Johnny's five entry imports are KERNEL ordinals 91, 23, 30 and 132, and USER ordinal 5. Establish original-record → mapped/patched operand → host reference → native reference/identity, including a near edge in a nonfirst segment. The first directly verifiable slice is this loader/address chain, not another manually flattened helper setup.

Relevant qualified helpers and profile facts must be available through native analysis rather than only copied prose. The already-proved fmovmem contract must remain correct, and the unported call-only SS case must expose the correct selector-qualified argument dependency. Inspect actual p-code operands and current bytes alongside C; nonempty output or opcode counts alone do not decide these properties. Unknown segment state must stay unknown.

The selected native MCP must start with these exact components and expose target identity plus the needed function/prototype, byte/map, disassembly, reference, decompilation/p-code and static context observations. Validate its real stdio path with both inputs, not just isolated command-handler doubles. Use the existing tool/command boundaries where adequate; no old Ghidra endpoint-name compatibility or all-tool parity is required.

Native saved analysis must reopen with the selected manual names, types/comments, boundaries/references and other actually changed state intact. Reapplying qualified facts must preserve demonstrated manual edits and refuse invalidated inputs. Use the host's existing persistence owner; MCP process exit/file switching is not permission to silently discard analysis. Original executables and existing Ghidra analysis projects remain untouched. The validation uses task-owned native projects, not an automatic Ghidra data migration.

Successful same-session MCP protocol validation does not mean the running Codex session hot-loaded new tools. Provide the verified launch/setup procedure and disclose any client registration/reload still needed; do not invent a runtime injection mechanism or disturb other active RE services. No global installation or Codex-global instruction rewrite is included.

## Scope, propagation and non-goals

Scope includes the host/bridge/engine owners and their direct callers, generated followers, tests and active documentation; the selected r2mcp fork/checkout and needed integration; the parent ignore and root/child workspace navigation updates; and this task's plan, log and changelog. Follow each independent repository's AGENTS and build conventions. Keep the original Ghidra repository and game worktrees read-only evidence sources. Use fresh task-scoped cache outputs and bounded build parallelism rather than mutating the previous proof trees or performing unbounded whole-image analysis before a selected-path result.

Native routes and names are canonical. Old Ghidra runtime paths/endpoints are not retained as aliases: their disposition for this native workflow is intentionally unsupported, while the separate existing Ghidra implementation remains untouched. Completed plans/logs and retained old build paths are historical mention only. Correct active setup/documentation claims that the now-published engine pin is unavailable. Do not rewrite historical evidence to imply it ran under the new layout or native server.

Non-goals include rewriting the decompiler, replacing RCore/project storage, reproducing Ghidra GUI/ProgramDB/transactions, automatic annotation migration, runtime Windows execution or selector recovery, full-game source recovery, unrestricted modern C/ABI equivalence, unrelated platform/security hardening, full old-MCP parity, new daemons/protocols, broad cleanup, global installation, removal of old services or force-publishing. A discovered need to change these boundaries returns to the current user rather than becoming silent implementation scope.

## High-level work packages and continuity

1. Record the completed local Intent Contract audit and activate the current user's conditional implementation authorization.
2. Establish the selected r2mcp fork/checkout and scoped workspace integration, then prove the NE loader/address first slice through the existing host and bridge.
3. Transfer qualified helper/profile facts and remaining segmented engine corrections at their native owners, with focused production-path preservation/current-state evidence.
4. Integrate native MCP observation and saved-analysis reopening; verify representative complete workflows on both original inputs with matching components.
5. Reconcile the cumulative committed candidates across the independent repositories, obtain the current-user-selected Code Gate, and finish factual bookkeeping and operational guidance.

The root-owned Microtask Program sizes implementation after activation. The runtime does not expose `update_plan`, so the one subordinate execution annex retains the current bounded footprints, dependencies, results and remaining frontier across this multi-repository task. It is not another intent or proof owner. Independent source footprints can proceed in parallel; validation waits for stable dependencies. The root retains integration, Git lifecycle and final proof.

Plan Gate: `PROCEED` from `/root/native_transfer_plan_audit`, local `Senior Plan Auditor / Intent contract audit`, Doctrine / Initial; complete required Intent-field coverage, no blocking findings. The sole transition places the plan on hold in Initial; the current user's explicit conditional authorization then activates Implementation. The review's sole continuity note is resolved by recording that later authority and Code Gate choice here.
Implementation authority: obtained and initially activated on the actual `PROCEED`, under the current-user message at `2026-10-16T18:53:57.443-03:00` above; further source mutation is currently suspended by the pending decision and on-hold status.
Code Gate: first task change-set review selected as local `Senior Code Reviewer` by that same message; no terminal result yet.
Blocker: current-user decision on the native MCP's path policy. The real stdio open of the supplied SimTower original is refused because `src/path.inc.c:108` unconditionally rejects hidden path components such as `.cache`; its tool response incorrectly reports `isError:false`. The root has not changed that policy or aliased/copied the input. Existing validated checkpoints and the in-flight helper validation remain preserved; no further source mutation is authorized while this decision is pending.
Next high-level action: ask whether explicit canonical sandbox roots supplied with existing `-s` may admit hidden descendants, while retaining default hidden-path refusal and outside-root/traversal rejection. Record the user's decision before assigning the MCP correction at its existing owner; false-success reporting must be corrected with that admitted operation.

## Pending current-user decision — native MCP input access

Classification: `current_user_decision`, with a separately verified error-reporting defect. Required property: read both supplied original inputs through native MCP without changing or relocating the originals. Observed fact: the private native server builds and serves Johnny successfully, but rejects the exact SimTower `.cache` path before opening a descriptor. This is an actual integration conflict with an existing intentional access policy, not a claim that every hidden-path restriction is defective.

Protected property and deployment: local stdio file-access scope for the current user's RE client, with originals opened read-only. The client can request a filesystem path through `open_file`. The present hidden-component rule prevents reads of hidden assets but also excludes this admitted executable; existing `-s` separately enforces a canonical root boundary. Permitting hidden descendants of an explicitly selected root changes access to those assets, so the root does not silently delete the restriction. No internet-facing or multi-tenant deployment is assumed.

Recommended closure: `modify_existing_owner` at MCP `src/path.inc.c` and its direct response/test followers. Retain the default hidden-path denial when no explicit sandbox root is configured. When the operator supplies `-s`, use the existing canonical containment check to admit paths inside that selected root, including hidden components; keep absolute-path, traversal and outside-root rejection. Select a task-owned root rather than a broad home directory. Report refused/failed opens as errors, not successful tool results. This reuses the existing owner and CLI option; it adds no server, protocol, parser, fallback, path alias or global exemption.

Impact if deferred: SimTower's MCP read observations and later combined workflow remain incomplete. Falsifier: successful real stdio `open_file` on that exact supplied path under the existing unmodified policy. Evidence: `/home/lucas/.cache/codex/native-transfer/mcp-baseline-1xOMuQHf`, verified source `r2mcp/src/path.inc.c:101–115`, `src/r2api.inc.c:144–238`, and `src/tools.c:1450–1515`. Current-user decision: pending; no new Gate has started and the selected first local Code Gate remains pending.
