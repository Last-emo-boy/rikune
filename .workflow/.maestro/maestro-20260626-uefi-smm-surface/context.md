# Maestro Iteration: UEFI/SMM Surface Inventory

- Date: 2026-06-26
- Branch: `feat/uefi-smm-surface`
- Base: `beta`
- Goal: Extend Rikune with a passive/static UEFI and SMM firmware trust-boundary inventory plugin.

## Scope

Add `uefi-smm-surface` with tool `uefi.smm.surface.inventory`.

The first version is a bounded, offline triage tool. It reads sample bytes and inventories:

- UEFI firmware volume, capsule, PE, and TE hints.
- SMI handler and SMM dispatch evidence.
- SMM communication protocol and `CommBuffer` hints.
- Boot Services and Runtime Services references.
- NVRAM and Secure Boot variable surface.
- Flash, capsule update, MMIO/I/O, PCI, MSR, and S3 boot script primitive hints.
- Static workflow handoff to firmware, PE, strings, xref, vulnerability, evidence graph, report, and gateway tools.

## Safety Boundary

The plugin must not:

- Boot firmware or start emulation.
- Trigger SMI or execute SMM code.
- Write EFI variables or mutate NVRAM.
- Apply capsules or write SPI/firmware flash.
- Touch MMIO, I/O ports, PCI config space, or MSRs.
- Invoke external firmware tools.
- Access network or mutate samples.

Runtime-like follow-up stays out of top-level recommended tools. The default MCP gateway remains `workflow.search`, `workflow.run`, and `artifact.read`.

## Research Signals

Read-only subagents and public research converged on UEFI/SMM as the highest-value next gap after kernel driver and eBPF/BTF coverage. Existing `firmware` is binwalk/extraction oriented, while `pe-analysis` treats `.efi` as PE and does not model SMM trust boundaries. This plugin fills ring -2 static triage without introducing hardware or runtime behavior.

