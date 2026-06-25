# Maestro Session: CUDA Fatbin Inventory Iteration

Date: 2026-06-26
Branch: `feat/cuda-fatbin-inventory`
Base: `beta-minimize-tool-surface`

## Goal

Continue the mainline Rikune tool iteration toward a versatile binary analysis platform by adding a passive CUDA/GPU binary artifact inventory layer.

## External Research Inputs

- NVIDIA CUDA Binary Utilities documentation: CUDA binaries / CUBIN are ELF-formatted and may be embedded in host executables; `cuobjdump` / `nvdisasm` are external tooling paths, not default discovery behavior.
- NVIDIA PTX overview: CUDA compilation can embed PTX and CUBIN variants in fatbins for multiple architectures.
- CuLifter / NVLift 2026 research: GPU binary lifting is an active frontier; Rikune needs a static GPU artifact inventory before bounded lift planning.
- ELF `EM_CUDA = 190` is used for NVIDIA CUDA device ELF / CUBIN identification.

## Subagent Inputs

### Newton

- Confirmed directory plugins under `src/plugins/<id>/index.ts` are auto-discovered.
- Recommended following existing static inventory shape: Zod schemas, `build*FromBuffer()`, handler with bounded preview, best-effort artifact persistence.
- Identified required sync points: `src/sample/sample-finalization.ts`, `SURFACE_FILE_TYPE_TAGS`, Docker `PLUGINS`, README/docs counts, and format matrix tests.
- Confirmed there is no `src/plugins/ebpf*`; `culifter` currently provides GPU planning and fixture-safe worker metadata, not a real CUDA byte parser.

### Boyle

- Proposed PE-focused backlog: `pe.security.profile`, Windows manifest/resource policy, DLL side-loading risk profile.
- Recommended `pe.security.profile` as the next depth-oriented iteration after this breadth iteration.

## Current Iteration Scope

- Add `cuda-binary` plugin with `cuda.binary.inventory`.
- Keep behavior passive and static:
  - no CUDA driver access;
  - no GPU access;
  - no `cuobjdump`;
  - no `nvdisasm`;
  - no profiler/emulator/lifter start;
  - no sample execution;
  - no mutation or network.
- Parse bounded previews for:
  - PTX `.version`, `.target`, `.address_size`, `.entry`, `.func`;
  - ELF CUBIN `e_machine = 190`;
  - CUDA section strings such as `.nv.info`, `.nv.constant*`, `.text.<kernel>`;
  - fatbin and host registration markers such as `__cudaRegisterFatBinary`;
  - SASS mnemonic hints.
- Route results to `culifter.gpu.plan`, `culifter.gpu.artifact.inventory`, `native.object.inventory`, `linux.binary.inventory`, strings, SBOM provenance, and evidence graph.

## Backlog

1. Add `pe.security.profile` for PE hardening / exploitability posture.
2. Add Windows manifest/resource security policy interpretation.
3. Enhance DLL side-loading / dependency risk scoring.
