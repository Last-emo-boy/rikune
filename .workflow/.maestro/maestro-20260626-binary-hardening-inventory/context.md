# Maestro Context: Binary Hardening Inventory

- Branch: `feat/binary-hardening-inventory`
- Base: `beta`
- Started: `2026-06-26T20:20:04+08:00`
- Objective: add a passive cross-platform binary hardening and exploit-mitigation inventory capability without expanding the default MCP tool surface.
- Candidate plugin: `binary-hardening`
- Candidate tool: `binary.hardening.inventory`
- Safety boundary: no sample execution, no loader invocation, no exploit test, no debugger/emulator, no external tool, no network, and no mutation.

## Rationale

Recent iterations added low-level metadata, compiler provenance, syscall/kernel/UEFI/TEE surfaces, and platform-specific security profiles. A remaining gap is a unified hardening posture view across ELF, PE, Mach-O, and hardware-assisted mitigations such as CET, PAC/BTI, MTE, and CHERI hints. This complements `pe.security.profile`, `linux.binary.inventory`, `compiler.codegen.fingerprint`, and evidence graph workflows.

## Execution Notes

- Keep implementation passive and bounded.
- Prefer header, load-command, note, section, import/string, and manifest evidence.
- Treat mitigation signals as static candidates unless a format parser provides definitive metadata.
- Runtime validation and exploitability testing must remain opt-in follow-up workflows.

## Subagent Findings

- Hooke identified PDF object analysis, protocol schema inventory, firmware tables, hypervisor surface, and fuzz harness planning as future breadth candidates.
- Godel ranked cross-format mitigation posture first for this iteration: CET/IBT/SHSTK, PAC/BTI, MTE, CHERI, and unified checksec-style hardening evidence are missing and can be implemented passively.
- Linnaeus recommended reusing `pe.security.profile`, `linux.binary.inventory`, and `apple.security.profile` patterns, and warned to guard workflow.search/default MCP surface behavior.
