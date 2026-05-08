# Ghidra Script Resources

This directory contains bundled Ghidra helper scripts used by Ghidra-backed tools and exposed through MCP resources.

## Scripts

| Resource URI | File | Purpose |
| --- | --- | --- |
| `script://ghidra/AnalyzeCrossReferences` | `AnalyzeCrossReferences.java` | Extract cross-reference data |
| `script://ghidra/DecompileFunction` | `DecompileFunction.java` | Decompile a function from Java headless script |
| `script://ghidra/ExtractCFG` | `ExtractCFG.java` | Extract control-flow graph data |
| `script://ghidra/ExtractFunctions` | `ExtractFunctions.java` | List functions from a Ghidra project |
| `script://ghidra/SearchFunctionReferences` | `SearchFunctionReferences.java` | Search function references |
| `script://ghidra/DecompileFunction_py` | `DecompileFunction.py` | Python variant for function decompile |
| `script://ghidra/ExtractCFG_py` | `ExtractCFG.py` | Python variant for CFG extraction |
| `script://ghidra/ExtractFunctions_py` | `ExtractFunctions.py` | Python variant for function listing |

## Resolution

Resource paths are resolved by `src/core/tool-registry/script-resource-manifest.ts`.

The resolver checks:

1. `RIKUNE_RESOURCE_ROOT` when set.
2. The package or repository root discovered from the entry point.
3. Source paths such as `src/plugins/ghidra/scripts/*.java`.
4. Built package paths such as `dist/resources/scripts/ghidra/*.java`.

Ghidra execution configuration is handled by `src/ghidra/ghidra-config.ts` and related Ghidra worker code.

## Runtime Requirements

Ghidra-backed tools generally require:

- Ghidra installed and discoverable;
- Java 21+ for modern Ghidra releases;
- readable sample workspace;
- writable Ghidra project/cache directories;
- no stale exclusive lock on the target Ghidra project.

Use these checks:

- `system.health`;
- `system.setup.guide`;
- `ghidra.health` when the plugin is loaded;
- `tool.readiness` for specific Ghidra tools.

## Adding Scripts

1. Add the script in this directory.
2. Register it in `script-resource-manifest.ts`.
3. Ensure build asset copying includes it.
4. Add tests where resource or execution behavior changes.
5. Update this README with the URI.

## Troubleshooting

Script not found:

- run `npm run build`;
- check `RIKUNE_RESOURCE_ROOT`;
- verify source and built resource paths;
- check global package layout.

Script execution errors:

- check Java and Ghidra versions;
- inspect Ghidra command and runtime logs;
- remove stale project locks if an earlier run was interrupted;
- confirm the sample workspace still contains the immutable original sample.
