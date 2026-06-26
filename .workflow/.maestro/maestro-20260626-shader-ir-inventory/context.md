# Shader IR Inventory Iteration

Date: 2026-06-26
Branch: `feat/shader-ir-inventory`
Base: `beta`

## Goal

Expand Rikune's frontier binary-analysis coverage with a passive GPU shader IR inventory plugin.
The first implementation targets broad static routing rather than external tool execution.

## Research Inputs

- Khronos SPIR-V specification and SPIRV-Headers confirm the module magic/header and machine-readable grammar ecosystem.
- LLVM DirectX Container documentation and Microsoft DirectXShaderCompiler document DXContainer / DXIL usage.
- W3C WGSL and WebGPU specifications establish WGSL as the WebGPU shader language.
- Read-only subagent `019f016c-84ae-7e31-812c-80c7a9f9e394` confirmed the repository had CUDA and LLVM bitcode adjacency but no SPIR-V, DXIL/DXBC, WGSL, or Metal library plugin.

## Scope

- Add `shader-ir` plugin and `shader.ir.inventory` tool.
- Support passive bounded parsing for:
  - SPIR-V module header, capabilities, entry points, execution modes, decorations.
  - DirectX `DXBC` container parts, including DXIL/DXBC/signature/debug part hints.
  - WGSL source entry points and resource bindings.
  - Metal library best-effort magic/extension/string hints.
- Add sample file-type detection and SDK surface aliases for `.spv`, `.spirv`, `.dxil`, `.dxbc`, `.cso`, `.wgsl`, `.metallib`.
- Keep default gateway limited to `workflow.search`, `workflow.run`, and `artifact.read`.

## Non-Goals

- No `spirv-val`, `spirv-dis`, `dxc`, `fxc`, `glslangValidator`, `spirv-cross`, `tint`, `naga`, `metal`, `metallib`, `xcrun`, or LLVM tool invocation.
- No GPU driver, GPU device, shader compilation, validation, disassembly, WebGPU adapter, pipeline creation, sample execution, mutation, or network.
- No full proprietary Metal library parser in the MVP.

## Validation Plan

- Focused Jest coverage for `shader.ir.inventory`.
- Format matrix, SDK surface tag, and `workflow.search` routing tests.
- `npx tsc --noEmit --pretty false`.
- `git diff --check`.
- PR, merge to `beta` if checks pass, then server pull/build/container health verification.
