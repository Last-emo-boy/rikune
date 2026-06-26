# C++ ABI Layout Inventory Iteration

## Intent

Add a passive static analysis plugin for C++ ABI class/object model evidence so Rikune can inventory Itanium and MSVC vtables, RTTI/typeinfo, C++ EH personality hints, virtual dispatch, and class-layout seeds without loading or executing native code.

## Direction

- Plugin id: `cpp-abi-layout`
- Tool id: `cpp.abi.layout.inventory`
- Artifact type: `cpp_abi_layout_inventory`
- Workflow recipe: `cpp.abi-layout-static-inventory`
- Branch: `feat/cpp-abi-layout-inventory`
- Base branch: `beta`

## Research Inputs

- Zeno recommended `cpp-abi-layout` as the best next deep native-analysis gap after native debug types because the current system lacks Itanium `_ZTV/_ZTI/_ZTS` and MSVC `??_7/??_R*` ABI inventory.
- Ptolemy recommended `kernel-driver-surface` as the next breadth candidate for Windows/Linux/Apple/eBPF driver surface inventory.
- Beauvoir recommended `compiler-provenance` as a later cross-format toolchain provenance inventory.
- Primary ABI reference: `https://itanium-cxx-abi.github.io/cxx-abi/abi.html`
- MSVC-side implementation reference: LLVM/Clang Microsoft C++ ABI sources and Microsoft PE exception/unwind documentation.

## Safety Boundary

- Passive bounded preview only.
- No sample execution, native load, dynamic link, debugger attach, emulator, runtime start, or backend process.
- No external demangler such as `c++filt`, `llvm-cxxfilt`, `undname`, `dumpbin`, `nm`, `objdump`, `readelf`, Ghidra, Rizin, or RetDec.
- No symbol server download, source fetch, network, mutation, strip, sign, patch, or rewrite.

## Implementation Notes

- Added a bounded parser for printable ABI evidence, ELF/PE section summaries, Itanium `_ZTV/_ZTI/_ZTS/_ZTh/_ZTv` hints, and MSVC `??_7/??_8/??_R0/??_R3/??_R4` hints.
- Output is intentionally candidate-only: class hints, vtable hints, RTTI hints, exception profile, layout seeds, quality gates, and workflow handoff. It does not claim concrete field offset recovery.
- Added `workflow.search` routing for C++ ABI terms while preserving default gateway visibility: only `workflow.search`, `workflow.run`, and `artifact.read` remain gateway tools.
