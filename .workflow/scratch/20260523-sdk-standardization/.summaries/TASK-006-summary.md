# TASK-006 Summary

Status: completed

Migrated core static analysis plugins to the standard metadata shape while preserving existing tool names and behavior. Static representative tests and the plugin matrix passed.

Verification:

- `npm test -- --runTestsByPath tests/unit/plugin-contracts.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm test -- --runTestsByPath tests/unit/pe-structure-analyze.test.ts tests/unit/strings-extract.test.ts tests/unit/yara-scan.test.ts tests/unit/report-generate.test.ts`
