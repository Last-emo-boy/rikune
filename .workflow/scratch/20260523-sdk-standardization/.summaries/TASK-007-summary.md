# TASK-007 Summary

Status: completed

Migrated format, package, firmware, disassembly/decompile adapter, PCAP, and memory-forensics plugins with standard aspects, output schemas, surface rules, dependencies, and evidence metadata.

Verification:

- `npm test -- --runTestsByPath tests/unit/plugin-format-matrix.test.ts tests/unit/tool-readiness.test.ts`
- `npm test -- --runTestsByPath tests/unit/apk-structure-analyze.test.ts tests/unit/elf-structure-analyze.test.ts tests/unit/firmware-scan.test.ts tests/unit/capstone-disasm.test.ts`
