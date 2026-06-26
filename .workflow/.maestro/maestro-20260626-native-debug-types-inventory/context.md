# Native Debug Types Inventory Iteration

## Intent

Add a passive static analysis plugin for native debug/type metadata so Rikune can inventory DWARF, split-DWARF, and Compact CTF evidence without starting debuggers, loading native code, invoking external dumpers, downloading symbols, fetching source, mutating samples, or using the network.

## Direction

- Plugin id: `native-debug-types`
- Tool id: `native.debug.types.inventory`
- Artifact type: `native_debug_type_inventory`
- Workflow recipe: `native.debug-types-static-inventory`
- Branch: `feat/dwarf-debug-inventory`
- Base branch: `beta`

## Research Inputs

- Huygens subagent recommended Native Debug Type Graph as the highest-value next capability after Objective-C/Swift and eBPF/BTF coverage.
- Avicenna subagent confirmed DWARF/split-DWARF/CTF is not currently parsed structurally; closest existing pattern is the passive `btf.type.inventory` parser.
- Darwin subagent confirmed Rust has existing `rust_binary.analyze` and local demangle helpers, making Rust inventory a later follow-up rather than the best next gap.
- DWARF v5 official specification page: `https://dwarfstd.org/dwarf5std.html`
- Sourceware Compact CTF specification: `https://sourceware.org/binutils/docs/ctf-spec.html`

## Safety Boundary

- Passive bounded preview only.
- No sample execution, native load, debugger attach, ptrace, or emulator.
- No external tools such as `readelf`, `dwarfdump`, `llvm-dwarfdump`, `objdump`, `pahole`, `ctfdump`, or libctf.
- No symbol server download, build-id lookup, source fetch, network, mutation, strip, sign, link, or rewrite.

## Implementation Notes

- Added ELF section header parsing for debug metadata sections, `.gnu_debuglink`, `.note.gnu.build-id`, `.ctf`, and `.BTF`.
- Added best-effort DWARF `.debug_info` unit header parsing, `.debug_abbrev` declaration summaries, `.debug_names` header summary, split-DWARF sidecar/index hints, and source path/language/compiler hints from `.debug_str` and `.debug_line_str`.
- Added bounded CTF dictionary/archive header detection.
- Added SDK surface tags and sample finalization for `.dwo`, `.dwp`, `.debug`, `.ctf`, raw CTF dictionary, and CTF archive magic.
