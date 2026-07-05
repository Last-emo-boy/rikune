# Maestro Context: Compiler Codegen Fingerprint

Date: 2026-06-26
Branch: `feat/compiler-codegen-fingerprint`
Base: `beta`

## Objective

Add a passive/static compiler code-generation provenance fingerprint capability to Rikune.
The first version should improve breadth across PE, ELF, Mach-O, COFF, native objects, and
language runtime markers while keeping the default MCP gateway small.

## Direction

Implement a standalone `compiler-codegen` plugin with tool `compiler.codegen.fingerprint`.
It inventories bounded static evidence for compiler, linker, language runtime, debug
provenance, section layout, and optimization/LTO/PGO hints. It must not execute samples,
load native binaries, invoke compilers/linkers/external tools, contact symbol/source servers,
use network, or mutate artifacts.

## Research Notes

- Read-only agents agreed that this direction fills a gap between `compiler.packer.detect`,
  `native-debug-types`, `windows-debug-symbols`, `cpp-abi-layout`, and `llvm-bitcode`.
- The plugin is standalone rather than part of `static-triage` because it produces a dedicated
  provenance artifact and workflow recipe and can later grow into model-assisted scoring.
- External literature/data-set direction: modern binary provenance work treats compiler family,
  version, optimization level, and architecture/toolchain combinations as first-class labels.

## Safety Boundary

- Passive bounded byte reads only.
- No sample execution.
- No native load, debugger, compiler, linker, disassembler, demangler, external tool, symbol
  server, source fetch, network, or mutation.
- No tool-level runtime policy; runtime handoff is explanatory only.

## Expected Deliverables

- `src/plugins/compiler-codegen/index.ts`
- `src/plugins/compiler-codegen/tools/compiler-codegen-fingerprint.ts`
- `tests/unit/compiler-codegen-fingerprint.test.ts`
- Updates to SDK tags, workflow search, plugin matrix tests, README/docs/tool catalog/Docker profile generation.
- Commit, PR to `beta`, CI check, merge if clean, server deploy and smoke.
