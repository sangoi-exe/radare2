# Native Win16 first slice — Intent Contract

Status: active
Task mode: Doctrine
Lifecycle phase: Implementation
Strategy epoch: native-win16-1
Plan kind: Feature / PRD Plan
Secondary kinds: none
Active annexes: none

## Confirmed objective and required result

Establish radare2 + r2ghidra + ghidra-native as the selected native candidate for Johnny Castaway and SimTower. The larger objective is to reuse the relevant qualified toolchain knowledge and later the MCP integration without requiring a JVM. This task delivers the first substantive Win16 proof, not the complete migration.

Create the three upstream forks in the current user's GitHub account and implement a production-path proof for SimTower's qualified Borland fmovmem core. Preserve its established three-argument ABI and effective segmented accesses. Keep changes at their canonical owners and use the extracted engine's existing patch mechanism so upstream refreshes do not silently discard the changes.

The first slice is feature work because the chosen native host does not yet provide this qualified contract and segmented output. It is not a Ghidra repair task, a whole-workbench rewrite, or a project-data migration.

## Current-user decisions and authority

- Route selection: user message in turn `01a145e8-2ded-7810-a5d4-e81c08ba394a`, `2026-10-16T15:10:08.379-03:00` (America/Sao_Paulo): “ok, vamos com tua recomendação de radare2 + r2ghidra + ghidra-native”.
- Scope and paraphrase confirmation: user message in turn `01a145ea-0c5c-7891-86ae-7255c77ae054`, `2026-10-16T15:12:09.192-03:00`: “confirmo e pode executar quando sair o proceed do plan gate”. The confirmed paraphrase names the native stack, three forks in the user's account, the SimTower helper proof, untouched originals, Ghidra as read-only reference, and deferred GUI/full extension/MCP port/project migration.
- Conditional implementation authority: the same message explicitly authorizes execution after the Plan Gate returns `PROCEED`. For this task, the user replaces the separate post-Gate authorization prompt with this exact conditional instruction. The Plan Gate and Code Gate are not waived. A non-PROCEED disposition does not activate implementation.
- External authority covers creating `sangoi-exe/radare2`, `sangoi-exe/r2ghidra`, and `sangoi-exe/ghidra-native` from the corresponding `radareorg` repositories. The authenticated account was read as `sangoi-exe`. Each target returned HTTP 404 before creation; each source repository is readable. Re-read and verify the exact target/parent before and after each mutation. Do not push implementation commits, open PRs, delete repositories, or change remote policy under this authority.
- No material route decision remains open. A new owner, external contract, data migration, scope expansion, or residual-risk acceptance returns to the current user.

## Selected route and evidence

Use the existing local checkouts at `/home/lucas/work/ghidra/.refs/radare2`, `/home/lucas/work/ghidra/.refs/r2ghidra`, and `/home/lucas/work/ghidra/.refs/ghidra-native`. radare2 owns the primary host result and this canonical plan. No additional worktree or wrapper repository is needed.

The inspected baselines are radare2 `2edc13b6f72854bd846c4dcab14acd06381dc71a`, r2ghidra `9b7969e190eda2e05023808a045fd1aa9627dbb7`, and ghidra-native `c958826f04a63f76c1e2eb517c3a1bbca9045656` (0.7.2). Retain these validated local starting points even if newly created forks have newer remote default-branch tips. Keep upstream remotes distinct from the user's fork remotes.

The unmodified native baseline was built in `/home/lucas/.cache/codex/native-workbench-probe-C1iVz7`. It produced C for one actual function from each original executable in both automatic and explicitly selected Protected Mode. The override `r2ghidra.lang=x86:LE:16:Protected Mode` works without changing the bridge. This establishes feasibility, not faithful NE loading or segmented semantics.

SimTower FILE `0x32e8` matches the qualified 89-byte/49-instruction core; its adjacent 39-byte wrapper is the existing family qualification prerequisite. Baseline native inference produced four parameters and selector-erasing pointer expressions. The existing qualified Ghidra contract uses two `FarAddress16` storage records and a WORD, not flattened host pointers. The original-byte contract, instruction stream and native XML provide the oracle; Ghidra's current automatic mutation behavior is not an unquestioned reference.

Keeping and coherently repairing Ghidra has a smaller immediate correctness frontier but does not achieve the selected native direction. Cutter/Rizin was not selected after the bounded NE/bridge inspection. Those alternatives are closed for this slice; new factual evidence can reopen the decision, not a preference alone.

## Canonical owners and scope

- radare2 owns binary loading, host addresses, types, functions and calling-convention metadata. Use its current APIs and commands where sufficient. Modify native NE/analysis owners only if the admitted helper path demonstrates that they prevent the required result; do not rewrite the complete NE loader speculatively.
- r2ghidra owns translation of host prototypes/storage into the native engine, named native convention selection, and production decompile/XML export. The current bridge can import structures but does not faithfully select an arbitrary existing native prototype through its generic CC conversion.
- ghidra-native owns the extracted C++ engine and x86 compiler specifications. `patches/*.patch` and the existing patch runner own durable adjustments; imported source is a generated follower. Selector-preserving print, normalization, heritage and stack-reference behavior is relevant to the call-free core. Call-only selector metadata is not automatically part of this slice.
- Ghidra `/home/lucas/work/ghidra` at `9ba90c3b53870d33f6b36023a6237a4e30cc81f7`, the Johnny/SimTower source workspaces, original executables and existing analysis projects remain read-only reference inputs.

## Primary-path acceptance

- A private, JVM-free build runs the production radare2/r2ghidra path against the original SimTower executable without modifying that executable or an existing project.
- Qualification checks the actual complete move family and the core's 16-bit instruction context. The admitted core remains the exact 89-byte/49-instruction body terminating in plain RETF.
- The effective native prototype is `void` with exactly three explicit parameters: `source` as a four-byte offset/selector record at entry SP+4, `destination` as the same record at entry SP+8, and unsigned WORD `byte_count` at entry SP+12. The far return consumes four bytes; purge is zero; no incoming GPR argument is invented. Preserve the established low-16-bit preservation/clobber contract, not a generic stock ABI with stronger claims.
- Native parameter storage and post-analysis LOAD/STORE operands retain the appropriate selector and 16-bit offset dependencies. Abstract stack bookkeeping still identifies the entry-stack parameters. Printed C must not imply a selector-free host-pointer mapping. Unknown selectors remain unknown; this task does not invent a runtime selector table.
- Use the production native XML export to inspect operands and storage, original instruction boundaries for coverage, and focused existing owner tests for changed semantics. Nonempty C, a parameter count alone, or opcode names without operands do not establish acceptance.
- Recheck the already-observed Johnny entry path and directly affected existing native test surfaces after shared changes. Report remaining unresolved imports/NE semantics explicitly; this slice does not require whole-game decompilation parity.
- Changes and relevant validation are committed in their owning repositories. A current-user-selected Code Gate reviews the consolidated candidate and its direct causal followers before closeout. The Code Gate choice remains pending until that operation.

## Constraints and non-goals

Keep originals and existing projects unchanged. Use task-scoped private cache directories for build, installation, diagnostics and disposable imports. Use two build jobs initially to avoid repeating the earlier workstation saturation. Do not install globally or execute either original game.

Do not create a GUI, port the whole extension/MCP, migrate Ghidra projects, repair the six outstanding Ghidra preservation findings, promise complete NE/fixup/import fidelity, or impose generic mutation/validation machinery in this slice. Full extension and MCP work remains part of the larger objective, not this task's acceptance.

No compatibility layer, duplicate runtime, alias scheme, schema version or parallel semantic owner is authorized. A change to a live native boundary propagates to its current direct consumers, affected tests and active documentation. Reuse native APIs and existing test/patch/build owners.

## First directly verifiable slice and work packages

1. Establish and verify the authorized forks without changing upstream repositories or discarding the validated local baselines.
2. Transport the qualified helper's explicit record types and exact native convention through the existing host/bridge path; adapt the relevant selector-preserving engine behavior at its current owners.
3. Run the real helper through the production bridge, inspect complete storage and segmented operands, and validate the immediate native/Johnny followers. Use the first replay to decide further local work inside this fixed contract; do not prebuild hypothetical support.
4. Integrate and commit the coherent candidate in each changed owner, obtain the selected Code Gate, and finish task-log/changelog bookkeeping and exact Git verification.

## Lifecycle continuity

Plan Gate: `PROCEED` from `/root/native_win16_plan_audit`, local `Senior Plan Auditor / Intent contract audit`, Doctrine / Initial. The reviewer accounted for every required Intent field, with no material findings and no evidence-blocked fields. Future implementation correctness was excluded.
Transition record: the normal `PROCEED` transition placed the contract on-hold in Initial. The explicit current-user instruction in turn `01a145ea-0c5c-7891-86ae-7255c77ae054` then activated Implementation under its confirmed checkpoint exception. No Gate was overridden or relabeled.
Implementation authorization: active after the actual `PROCEED`, under the exact current-user conditional instruction above.
Code Gate: not selected or launched for this task.
Blocker: none at implementation start.
Next high-level action: verify and create the three authorized forks, then execute the bounded native-engine and bridge entries.
Review status: Plan Gate complete; implementation and Code Gate pending.
