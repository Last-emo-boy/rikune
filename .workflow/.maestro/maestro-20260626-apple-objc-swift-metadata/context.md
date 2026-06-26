# Apple ObjC / Swift Metadata Iteration

Date: 2026-06-26
Branch: `feat/apple-objc-swift-metadata`
Base: `beta`

## Goal

Expand Rikune's Apple native binary coverage with a passive Objective-C and Swift
metadata inventory plugin. The MVP targets Mach-O sections, Objective-C runtime
metadata hints, Swift ABI/reflection sections, and standalone Swift metadata files
without launching apps, attaching debuggers, mounting images, or invoking Apple
tooling.

## Research Inputs

- Apple's Mach-O documentation describes segments and sections as the container model
  used by macOS and iOS native binaries.
- Swift ABI `TypeMetadata.rst` documents runtime metadata as a first-class ABI surface.
- Swift ABI `Mangling.rst` documents Swift symbol encodings that can be recognized
  passively from symbol/string evidence.
- Swift runtime documentation describes runtime reflection and metadata concepts that
  are useful for static triage and follow-up planning.
- Read-only subagent `019f01e0-ec3d-72e0-b1c3-0e5e68373096` recommended a passive
  `apple-objc-swift` plugin and `apple.objc_swift.metadata.inspect` tool, with runtime
  work limited to opt-in handoff plans.

## Scope

- Add `apple-objc-swift` plugin and `apple.objc_swift.metadata.inspect` tool.
- Parse bounded Mach-O bytes for headers, slices, section records, Objective-C metadata
  section counts, pointer-reference counts, class/protocol/selector hints, Swift section
  hints, Swift mangled symbol hints, reflection strings, and concurrency/ABI hints.
- Support standalone Swift metadata artifacts such as `.swiftmodule`, `.swiftinterface`,
  `.swiftdoc`, and `.abi.json`.
- Add SDK surface tags, sample finalization detection, workflow search routing, focused
  Jest tests, format-matrix coverage, docs, and Docker profile generation.
- Keep default MCP gateway limited to `workflow.search`, `workflow.run`, and
  `artifact.read`.

## Non-Goals

- No app launch, LLDB/debug attach, Frida attach, device connection, simulator start,
  DMG mount, IPA install, runtime start, network, mutation, or external Apple tools.
- No `otool`, `nm`, `lipo`, `class-dump`, `swift-demangle`, `codesign`, or kernel/user
  runtime introspection in the MVP.
- No full Swift ABI validator or Objective-C runtime emulator.

## Validation Plan

- Focused Jest coverage for `apple.objc_swift.metadata.inspect`.
- Plugin SDK, workflow search, sample finalization, and plugin format matrix tests.
- `npx tsc --noEmit --pretty false`.
- `npm run lint`.
- `git diff --check`.
- `npm run docs:tool-catalog` and `npm run docker:generate:all`.
- PR against `beta`, merge if checks pass, then server pull/build/container health and
  MCP smoke checks.
