# Workspace changelog

## 2026-10-16

- Relocated the three native checkouts into `/home/lucas/work/radare2/r2ghidra/ghidra-native`, preserving independent Git histories, branches and remotes. Added parent ignores, a principal host workspace map and scoped child guides, and corrected the active editable-engine source path. Runtime code and the engine pin are unchanged; the local layout Code Gate is pending.
- Implemented and locally validated the first qualified native Win16 fmovmem slice using the selected radare2, r2ghidra and ghidra-native forks. The helper retains the explicit three-parameter record/WORD ABI and selector-bearing accesses. Native engine and bridge changes are committed in their owning repositories; radare2 runtime source is unchanged.
- Recorded the actual-input SimTower/Johnny evidence, native regression results and local-only publication limitation. The local Code Gate returned `PROCEED` with complete coverage of all 11 changed files and direct followers, without required corrections or nits. The accepted first slice is complete; complete NE fidelity, publication and a full extension/MCP migration remain outside this result.
