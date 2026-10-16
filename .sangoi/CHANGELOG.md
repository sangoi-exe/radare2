# Workspace changelog

## 2026-10-16

- Implemented and locally validated the first qualified native Win16 fmovmem slice using the selected radare2, r2ghidra and ghidra-native forks. The helper retains the explicit three-parameter record/WORD ABI and selector-bearing accesses. Native engine and bridge changes are committed in their owning repositories; radare2 runtime source is unchanged.
- Recorded the actual-input SimTower/Johnny evidence, native regression results and local-only publication limitation. The local Code Gate returned `PROCEED` with complete coverage of all 11 changed files and direct followers, without required corrections or nits. The accepted first slice is complete; complete NE fidelity, publication and a full extension/MCP migration remain outside this result.
