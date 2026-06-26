# Syscall ABI Surface Iteration

Date: 2026-06-26
Branch: feat/syscall-abi-surface
Base: beta

## Intent

Continue Rikune frontier tool-surface expansion with a passive/static syscall ABI and user-kernel boundary inventory. The target is a cross-platform inventory for Windows direct/indirect syscall stubs, Linux syscall instructions, macOS Mach trap hints, ARM/ARM64 SVC patterns, and static risk/workflow handoff.

## External Signals

- B-Side research frames binary-level static system call identification as a current analysis problem.
- Burnyard research uses system-call/API events as lightweight malware analysis evidence.
- SysWhispers3 and Hell's Gate / Halo's Gate style projects keep direct syscall discovery relevant for modern evasion triage.

## Safety Boundary

The first version is passive/static bounded-read only. It must not execute the sample, invoke syscalls, start tracing, attach a debugger, use ptrace/strace/ltrace/Frida/Qiling, open devices, load drivers, contact the network, or mutate samples.

## Selected Direction

Tool: syscall.abi.surface.inventory
Plugin: syscall-abi-surface
Artifact: syscall_abi_surface_inventory

## Implementation Summary

- Added a passive static plugin for syscall ABI and user-kernel boundary inventory.
- Covered Windows x64 direct syscall stubs, SysWhispers/Hell's Gate-style resolver strings, Linux syscall/seccomp/ptrace hints, Mach trap strings, ARM/ARM64 SVC, and RISC-V ecall opcode evidence.
- Kept runtime handoff as opt-in planning only; default `workflow.search`, `workflow.run`, and `artifact.read` gateway behavior remains unchanged.
- Updated plugin SDK surface tags, sample finalization, workflow search routing, plugin format matrix, docs, generated tool catalog, and static/hybrid Docker plugin profiles.

## Local Verification

- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/syscall-abi-surface-inventory.test.ts tests/unit/packages/plugin-sdk.test.ts tests/unit/workflow-search.test.ts tests/unit/plugin-format-matrix.test.ts tests/unit/core/plugin-system/builtin-contract.test.ts tests/unit/mcp-tool-safety.test.ts`
- `npx tsc --noEmit --pretty false`
- `npm run lint`
- `npm run build`
- `npm run docs:tool-catalog`
- `npm run docker:generate:all`
- `git diff --check`
