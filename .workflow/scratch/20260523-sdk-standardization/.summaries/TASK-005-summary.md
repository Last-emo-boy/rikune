# TASK-005 Summary

Status: completed

Updated discovery, help, readiness, plugin list, and sample profile surfaces so users can see standard metadata, readiness reasons, quality warnings, artifact/evidence hints, and runtime policy context.

Verification:

- `npm test -- --runTestsByPath tests/unit/tools-discover.test.ts tests/unit/tool-help.test.ts tests/unit/tool-readiness.test.ts tests/unit/plugin-list.test.ts tests/unit/sample-profile-get.test.ts`
