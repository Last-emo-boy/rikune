# Rust Binary Inventory Iteration

Date: 2026-06-26
Branch: feat/rust-binary-inventory
Base: beta

## Objective

Add a passive Rust binary inventory capability without widening the default MCP
surface. The tool should improve language/runtime coverage for Rust malware and
native artifacts while preserving the existing `rust_binary.analyze`
compatibility surface in `static-triage`.

## Design

- New plugin: `rust-binary`
- New tool: `rust.binary.inventory`
- Artifact type: `rust_binary_inventory`
- Static/passive only; no runtime policy, no loader, no execution, no rustc,
  no cargo, no external demangler, no network, no mutation.
- Hidden activation through `workflow.search`; default MCP gateway remains
  `artifact_read`, `workflow_run`, `workflow_search`.

## Scope

- Detect Rust v0 and legacy mangled symbol candidates from bounded bytes.
- Detect rustc, Cargo registry/package/source-path, crate, target triple,
  runtime allocator, panic/unwind, and ecosystem markers.
- Support PE, ELF, Mach-O, object/archive, `.rlib`, and `.rmeta` routing.
- Keep Rust plugin activation scoped to Rust-specific tags/findings rather than
  generic `pe`, `elf`, or `macho`.

## External References

- rustc symbol mangling overview:
  https://doc.rust-lang.org/rustc/symbol-mangling/index.html
- rustc v0 symbol format:
  https://doc.rust-lang.org/rustc/symbol-mangling/v0.html

## Verification Plan

- Rust inventory unit tests.
- SDK file-type tag tests.
- workflow.search hidden activation tests.
- plugin format matrix subset and full matrix.
- TypeScript build check, lint, docs/tool catalog generation, Docker generation.
- PR CI, then beta merge and server Docker/MCP smoke if checks pass.
