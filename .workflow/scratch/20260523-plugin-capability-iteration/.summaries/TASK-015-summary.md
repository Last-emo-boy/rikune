# TASK-015 Summary

Status: completed

Implemented `malware.intel.loop` as a local malware intelligence feedback workflow from config, C2, behavior, strings, and classification evidence into IOC export, ATT&CK hints, Sigma/YARA generation, YARA/YARA-X validation, and local vuln-pattern scan handoffs. Default operation is offline and backend-optional.

Verification:
- `npm test -- --runTestsByPath tests/unit/office-behavior-profile.test.ts tests/unit/unpack-workflow-plan.test.ts tests/unit/sample-family-cluster.test.ts tests/unit/malware-intel-loop.test.ts`
- `npm test -- --runTestsByPath tests/unit/unpack-auto.test.ts ... tests/unit/binary-diff.test.ts`
- `npm test -- --runTestsByPath tests/unit/tool-readiness.test.ts tests/unit/tool-help.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`
- `npm run lint`
