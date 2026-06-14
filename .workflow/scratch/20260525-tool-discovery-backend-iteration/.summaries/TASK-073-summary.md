# TASK-073 Summary

Status: completed

Hardened MCP activation and backend execution safety:

- Hidden registered tools remain blocked by `ToolExecutor` until discovery exposes them.
- `tools.discover action=activate` returns `activation_audit`.
- Backend worker requests enforce `maxInputBytes` before readiness/execution.
- Builtin worker artifact `output_path` respects `allowedRoots`.
- External backend command strings reject shell launchers and shell control tokens.
- External backend diagnostics redact host paths and env-like secrets.
- External RE bridge endpoints are restricted to localhost/loopback HTTP/WS URLs.

Primary files:

- `src/worker/backend-worker-client.ts`
- `src/tools/tools-discover.ts`
- `tests/unit/backend-worker-contract.test.ts`
- `tests/unit/tools-discover.test.ts`
- `tests/unit/mcp-tool-safety.test.ts`
- `tests/fixtures/workers/fixture-worker.mjs`

Verification:

- `npm test -- --runTestsByPath tests/unit/mcp-tool-safety.test.ts tests/unit/core/tool-executor.test.ts tests/unit/backend-worker-contract.test.ts tests/unit/tools-discover.test.ts`
- `npm run lint`
- `npm run typecheck`
