# Agentic Coding Guidelines for radare2

## Native workspace map

Start this workspace at `/home/lucas/work/radare2`. It contains four independent Git repositories, not submodules; run Git commands from the repository that owns the change. Parent ignores exclude the nested checkouts, so a search or status at the workspace root does not cover their contents.

| Repository | Ownership | Local guidance |
| --- | --- | --- |
| `.` | radare2 host: `libr/` APIs, analysis, binary loading and plugins; `binr/` command-line tools | Host guide below |
| `r2ghidra/` | Native decompiler bridge: host types/prototypes, plugin commands, engine integration and language installation | [r2ghidra/AGENTS.md](r2ghidra/AGENTS.md) |
| `r2ghidra/ghidra-native/` | Editable native engine: decompiler patches, processor specifications, Sleigh compiler and native tests | [ghidra-native/AGENTS.md](r2ghidra/ghidra-native/AGENTS.md) |
| `r2mcp/` | Native MCP server: stdio transport, tools and RCore lifecycle | [r2mcp/AGENTS.md](r2mcp/AGENTS.md) |

Runtime flow is native r2mcp tools → linked radare2 RCore analysis and commands → r2ghidra translation → native decompiler and matching processor specifications; the host CLI also uses the same host/bridge/engine owners directly. No Java or Python analysis backend is required for this native path. Build integration consumes `r2ghidra/subprojects/ghidra-native/`, not the editable direct-child engine; `r2ghidra/subprojects/ghidra-native.wrap` owns the engine URL/revision pin. Read the child guidance before editing any child or changing this dependency boundary. Keep RE behavior in its source/specification/patch owners, not in this map.

Shared declaration binding/rendering belongs to `libr/util/type_decl.c` and its public API in `libr/include/r_util/r_type.h`; the parser consumes explicit named/abstract context and visible type bindings. Each FUNCTION node owns optional supplied `function.callconv` metadata; NULL does not assert a default. Canonical rendering uses `__attribute__((r2_cc("model")))` analysis syntax, with `cdecl`/`stdcall` attributes also accepted as input, not a claim of historical Borland C acceptance. The default header producer in `libr/anal/c2/` keeps anonymous/member callbacks intrinsic instead of manufacturing global `func.SCOPE` records; genuinely named function/callback-typedef records and real aliases retain their identity. Target integer constant-expression evaluation belongs to `libr/util/type_expr.c`. Target-Sdb-backed layout and effective incomplete-array facts belong to `libr/util/type_layout.c`; the C header producer enforces flexible-member placement using those facts. Signature composition in `libr/anal/fcn.c`, direct CLI and bridge translation consume these shared owners; signature serialization reads the supplied outer convention from the constructed FUNCTION node.

Signature record normalization, selected-text-frontend admission, target binding and application belong to `libr/anal/fcn.c`. Trusted structured facts do not pass through the configured text frontend. Preparation settles final keys/links before mutation; Core admits the function and function-owned flag action, and Borland profiles prepare before body creation. `afs` and the native MCP setter isolate edits to the addressed function; the structured setter retains its shared-type assignment, and standalone `afn` retains prototype migration. Prepared structured updates can preserve the separate operational calling convention for native harvest without inventing source metadata. Function parameter-list knowledge remains `func.NAME.prototype=unknown|unspecified|fixed`, independent of argument count or lookup origin; DWARF formal availability remains a separate fact. The child guides identify the bridge/native followers.

Host type identity belongs to `libr/util/utype.c` and `libr/anal/type.c`. Ordinary types and the shared C tag namespace are distinct: exact base-type lookup takes a raw name plus `RTypeNamespace`, while declaration and Core type commands use explicit `struct NAME`, `union NAME` or `enum NAME` spelling for tags. Existing ordinary analysis records remain ordinary. [The data guide](libr/anal/d/AGENTS.md) describes the serialized namespace boundary. An incomplete tag can be the target of a pointer, but an unmeasurable empty aggregate has no supported object layout. Rebuild direct API consumers after these host-interface changes; source checkout nesting does not supply a compatible SDK.

Declaration producers record supplied calling-convention facts without inventing `cdecl` for an omitted convention. Current Analysis consumers retain effective-default selection from the active configuration. A generic parser annotation is not a supplied C calling convention; pointer representation does not select a near/far call model.

NE analysis uses `((ut64)selector << 32) | offset32`; the selector is a synthetic segment ordinal, not an observed Windows runtime selector. NE loading and raw relocation encoding belong to `libr/bin/format/ne/ne.c` and `libr/bin/p/bin_ne.c`; raw far-pointer bytes and physical file offsets remain distinct from analysis coordinates. The bridge and isolated native Protected Mode specification consume the same coordinate while retaining ordinary near2/far4 pointers and a 16-bit stack. MZ/OMF and Real Mode retain their existing address models.

Project admission belongs to `libr/core/project.c` and `libr/core/p/newprj/`, with shared binary reading in `read.inc.c`. Identifiable old NE projects refuse before reset or state application. Old NE analysis requires fresh analysis, without migration; partial projects or arbitrary scripts without sufficient identity have no guaranteed automatic detection. A successful load is not evidence of old-coordinate compatibility.

Validation entry points are the host Make build and `r2r`/unit tests below, bridge Meson and `test/db/extras/`, engine `make test`, and the MCP root Make build/test targets; child guidance narrows the component procedures. [The qualified local-component procedure](r2ghidra/doc/win16-fmovmem.md) describes the existing private host/bridge/engine build and matching runtime inputs. Directory nesting or an MCP checkout alone does not select matching linked host libraries, plugins or language files, or establish runtime readiness. File-switch preservation and saved-analysis roundtrips require production-path observation, not source inspection alone; persistence belongs to the host, while the server owns its RCore lifecycle.

Native preparation and Meson build reuse validate matching patches/source inputs through the engine's shared runner. Stale or ambiguous preparation refuses without changing source bytes; preserve changes and prepare a new matching checkout or distribution rather than removing `patch.done` and retrying. Matching prepared distributions remain buildable without Git. The child guides own the preparation details and combined native/bridge test procedure.

Last reviewed: 2026-10-23 on `master`. Maintainers changing topology, ownership, build/test entry points or dependency integration must refresh this map and the affected child guidance against live files; branch names and installed components are not proof that this map is current.

## Historical native task archives

Completed-task archives are stored at `I:\.wsl\archives\radare2\2026-10-23\` on Windows, accessible at `/mnt/i/.wsl/archives/radare2/2026-10-23/` in WSL. The [archive inventory and restoration record](.sangoi/task-logs/2026-10-23-native-review-remediation.md#authorized-historical-cache-archival-and-disk-recovery) maps each archive to its original path under `/home/lucas/.cache/codex`. The archives retain their original relative paths; external symlink targets are not bundled. These historical archives are not the current task's runtime inputs.

## Shared prospective commit attribution

Commits materially authored by Codex in any of the four native repositories must include the exact trailer `Co-authored-by: Codex <codex@openai.com>` unless the current user explicitly says otherwise. Apply this prospectively without rewriting existing history or changing Git author/committer configuration.

## radare2 host guide

The remaining guidance applies to radare2-owned files, not the independent r2ghidra, ghidra-native or r2mcp repositories. Their local instructions own source style, builds and tests.

## Work and references

Make the smallest coherent fix. Reuse existing helpers; avoid unrelated cleanup,
speculative abstractions and repeated scans in hot paths. Extract helpers when
they simplify logic.

Search symbols and paths first; read only relevant sections:

- APIs: `libr/include/` declarations, corresponding `libr/` implementations and callers. Verify signatures and ownership against current code.
- Layout: libraries in `libr/`, CLI tools in `binr/`, plugins in `libr/*/p/`.
- Style/build details: `DEVELOPERS.md` and `doc/indent-example.c`; public API/ABI changes: `doc/abi.md`.
- Commands: `man/`, `r2 -h` and `<command>?`; test formats: `test/README.md` and nearby `test/db/` cases.

## Style

- Use descriptive function and variable names so code is readable without comments in most cases. Do not add multiline comments; use short single-line comments only for non-obvious intent.
- Match nearby code: tabs, no trailing whitespace, braces even for single statements, and `case` labels aligned with `switch`.
- Space before calls/control parentheses: `foo ()`, `if (x)`, `sizeof (int)`. Keep function signatures on one line without a space before `(`.
- Initialize variables near first use; declare loop variables before `for`, not inside it.
- Use `<r_types.h>` integer types (`ut8`, `ut32`, etc.), `PFMT64` formatting and `R_PACKED` for packed structures.
- Do not run `clang-format-radare2` unless requested. `sys/lint.sh` provides style diagnostics for the whole tree; distinguish pre-existing findings.

## Memory and APIs

- Project convention omits NULL checks for small constant `R_NEW`/`R_NEW0` allocations.
- Check runtime-sized allocations for failure; guard size arithmetic with `r_mul_overflow_*`/`r_add_overflow_*` before allocating. Check bounds before buffer access; endian helpers do not.
- Never use `alloca` or variable-length stack arrays. Avoid NULL guards around `free` and destructors that accept NULL.
- Use `R_RETURN_*` for public API preconditions; ordinary `if` for runtime/input errors. Use `r_util/r_assert.h` instead of `<assert.h>`.
- Prefer `!strcmp ()`, `r_str_newf`, `r_str_pad` and endian helpers such as `r_read_le32`. Use `r_strbuf_*` for concatenation in loops to avoid repeated copying.
- Use annotations from `libr/include/r_types.h` and `libr/include/r_types_null.h`; ownership macros are `R_OWNED`/`R_UNOWNED`.
- Prefer `r_json_parsedup`; when borrowing buffers, follow the lifetime rules in `libr/include/r_util/r_json.h`.
- New commands need `?` help. Use `R_LOG_*` for diagnostics and the existing console APIs for command output; remove debugging `eprintf` calls.

## Build

- For code changes, run `./configure` if needed, then `make -j2` from the root (adjust jobs to available resources). Keep failure output. Do not compile individual `.c`/`.o` files directly.
- Run `sys/install.sh --without-pull` for a full clean rebuild and symlink installation.
- `.d` files are compiler generated. If one causes a build failure, remove it and rebuild; do not edit it.
- Edit `configure.acr` and regenerate `configure` with `acr`; do not edit generated `configure` directly.
- Update both Make and Meson for library dependencies. Register new plugins in `dist/plugins-cfg/plugins.def.cfg`, `dist/plugins-cfg/plugins.static.cfg` and the relevant `libr/*/meson.build`.

## Verify

- Use `r2r` tests in `test/db/` for `r2` behavior and C unit tests in `test/unit/` for direct API behavior. Reuse test files and fixtures when suitable. Cover the reported behavior and edge cases; check expected output before changing it.
- When writing r2r tests, avoid the need to create temporal files or execute system programs like '!!' or '| grep'
- Build before running `r2r -u -C test db/...` from the root. The `-u` flag prevents the runner from pulling or cloning the independent `test/bins` repository; use `R2R_OFFLINE=1` when another native test entry point invokes r2r internally. Update fixture checkouts only as a separately selected action. Existing `symstall` symlinks use rebuilt files without reinstalling. Otherwise, install this checkout or set its executable, library and plugin paths. See [Regression testing](DEVELOPERS.md#regression-testing).
- Keep the filename last in `r2` invocations. Use `-n` only for raw input: it skips binary loading. `io.va=false` changes addressing, not binary loading.
- Binary fixtures belong in `radare2-testbins` (`test/bins/`), not this repository. `// R2R` comments can link source files to tests.
- For memory debugging, see `DEVELOPERS.md` (Error diagnosis): `R2_DEBUG=1` and `sys/sanitize.sh`.
- Run `git diff --check`; report what was tested and any blockers. Documentation-only changes need reference checks, not a full build.
- Before reporting completion, inspect `git status --short` and the diff. Verify every requested deliverable exists and contains the required content; remove temporary artifacts you created.

## Commits

Commit only when requested or needed for a requested PR; otherwise suggest a one-line message.
Write a one-line subject starting with a capital letter. If a body is needed,
separate it with a blank line and use only short bullet points.
For user-visible changes, append one existing `##tag` as the final word of the
subject; security fixes use `##crash`. See [Commit messages](DEVELOPERS.md#commit-messages)
for details, issue references and the tag list.
