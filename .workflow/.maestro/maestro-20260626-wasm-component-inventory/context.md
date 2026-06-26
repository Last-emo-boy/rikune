# Wasm Component Inventory Iteration

Date: 2026-06-26
Branch: `feat/wasm-component-inventory`
Base: `beta`

## Goal

Expand Rikune's frontier WebAssembly coverage with a passive WebAssembly Component Model
inventory plugin. The MVP targets routing, structural evidence, WIT/WASI Preview 2 hints,
and runtime handoff planning without running a component runtime or external decoders.

## Research Inputs

- Bytecode Alliance Component Model documentation describes components as a binary format
  distinct from core WebAssembly modules, using WIT and the Canonical ABI.
- WebAssembly/component-model `design/mvp/Binary.md` documents the component preamble,
  layer discriminator, and component section IDs.
- The WebAssembly core spec documents core module magic, section framing, and custom
  section behavior reused by component binaries.
- Read-only subagent `019f01ab-909e-7092-9a29-f1e125ba4ca1` recommended Apple
  ObjC/Swift runtime metadata as the next high-value plugin. This is recorded for
  the following iteration; the current Wasm Component iteration continues because
  its implementation branch and parser are already underway.

## Scope

- Add `wasm-component` plugin and `wasm.component.inventory` tool.
- Passively identify Component Model binaries by preamble/layer and parse bounded section
  framing, custom section names, core module/component nesting counts, imports, exports,
  canonical ABI hints, start/value sections, and text/WIT/WASI package hints.
- Add routing tags and sample file-type detection for component-model artifacts.
- Keep default gateway limited to `workflow.search`, `workflow.run`, and `artifact.read`.

## Non-Goals

- No `wasm-tools`, `wit-component`, `wasmtime`, `jco`, `wkg`, WABT execution, validation,
  instantiation, WASI grants, OCI fetch, network, mutation, or runtime startup.
- No full formal Component Model validator in the MVP.

## Validation Plan

- Focused Jest coverage for `wasm.component.inventory`.
- Format matrix, SDK surface tag, and `workflow.search` routing tests.
- `npx tsc --noEmit --pretty false`.
- `git diff --check`.
- PR, merge to `beta` if checks pass, then server pull/build/container health and MCP checks.
