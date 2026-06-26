# Gateway upload routing fix

## Intent

Fix issues discovered while exercising Rikune through the stable remote gateway against a crackme sample:

- Hidden analyzer subtools discovered by `workflow_search` could not be invoked through `rikune_tool_call` when the upstream analyzer kept a minimal `tools/list`.
- The gateway-exposed `workflow_run` schema had stale `backend_policy` and stage values.
- Upload sessions from remote analyzer deployments could return client-unreachable `localhost` URLs.
- `workflow.search action=activate result_id=...` depended too heavily on the current search window and could not directly activate stable `plugin:*` or `tool:*` result IDs.

## Scope

- Preserve the fixed MCP surface: `workflow_search`, `workflow_run`, `artifact_read`, `rikune_tool_call`, and connection controls.
- Do not expand upstream `tools/list` visibility.
- Keep upload handling passive; request_upload only creates a durable upload session and does not run analysis.
- Add focused unit tests for gateway routing, upload URL normalization, config loading, and direct result ID activation.

## Verification

- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/rikune-agent-gateway.test.ts tests/unit/sample-request-upload.test.ts tests/unit/config.test.ts tests/unit/workflow-run.test.ts tests/unit/workflow-search.test.ts`
- `npx tsc --noEmit --pretty false`

