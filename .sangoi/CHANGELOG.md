# Workspace changelog

## 2026-10-16

- Implemented and locally validated the first qualified native Win16 fmovmem slice using the selected radare2, r2ghidra and ghidra-native forks. The helper retains the explicit three-parameter record/WORD ABI and selector-bearing accesses. Native engine and bridge changes are committed in their owning repositories; radare2 runtime source is unchanged.
- Recorded the actual-input SimTower/Johnny evidence, native regression results, local-only publication limitation, and the pending Code Gate in `.sangoi/planning/2026-10-16-native-win16-first-slice.md` and its task log. This entry does not claim final review approval, complete NE fidelity, or a full extension/MCP migration.
