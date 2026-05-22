# TASK-012 Summary

Status: completed

Implemented `office.behavior.profile` as a passive Office macro behavior workflow over OLE/OOXML hints, VBA/XLM-like text, macro detector flags, static strings, IOC candidates, and YARA/Sigma handoffs. It does not automate Office, preview documents, execute macros, or perform network lookup.

Verification:
- `npm test -- --runTestsByPath tests/unit/office-behavior-profile.test.ts tests/unit/unpack-workflow-plan.test.ts tests/unit/sample-family-cluster.test.ts tests/unit/malware-intel-loop.test.ts`
- `npm test -- --runTestsByPath tests/unit/unpack-auto.test.ts ... tests/unit/binary-diff.test.ts`
- `npm test -- --runTestsByPath tests/unit/tool-readiness.test.ts tests/unit/tool-help.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`
- `npm run lint`
