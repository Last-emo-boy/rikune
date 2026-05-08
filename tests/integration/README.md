# Integration Tests

Integration tests exercise MCP tools, upload/session flows, file server behavior, plugin workflows, and end-to-end analysis paths.

Use Node.js 22+ for repository tests.

## Test Files

| File | Focus |
| --- | --- |
| `workflow.test.ts` | Workflow behavior |
| `triage-workflow.test.ts` | Compatibility triage workflow |
| `full-pipeline.test.ts` | Ingest-to-analysis path |
| `mcp-tools.test.ts` | MCP tool exposure and calls |
| `file-server-api.test.ts` | HTTP upload/artifact API |
| `upload-session-workflow.test.ts` | Durable upload sessions |
| `frida-workflow.test.ts` | Frida-related workflow behavior |
| `frida-script-generator.test.ts` | Frida script generation |
| `visualization.test.ts` | Visualization/report artifacts |
| `kb-integration.test.ts` | Knowledge-base integration |
| `beta2-tools.test.ts`, `v02-tools.test.ts`, `v0.1-acceptance.test.ts` | Regression coverage for older public surfaces |

## Setup

```bash
npm install
npm run build
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

If native modules fail after changing Node versions:

```bash
npm rebuild better-sqlite3
```

## Running Tests

All integration tests:

```bash
npm run test:integration
```

One file:

```bash
npx jest tests/integration/file-server-api.test.ts
```

Verbose:

```bash
npx jest tests/integration --verbose
```

Extended timeout:

```bash
npx jest tests/integration --testTimeout=60000
```

## Docker And E2E

Some e2e tests expect Docker. The e2e setup skips when Docker is unavailable.

```bash
npm run test:e2e
```

For Docker profile validation:

```bash
npm run build
npm run docker:generate:all
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
```

## Test Data

Tests use small synthetic fixtures and generated minimal binaries where possible. Do not commit live malware samples. If a real sample is needed, keep it outside the repository and document how to obtain or generate a safe equivalent.

## Troubleshooting

### better-sqlite3 Errors

Use Node.js 22+ and rebuild native modules:

```bash
npm rebuild better-sqlite3
```

### Worker Errors

Check Python dependency installation and run:

```bash
python -m pytest workers
```

### Timeouts

Prefer staged workflow polling:

- `workflow.analyze.start`
- `workflow.analyze.status`
- `workflow.analyze.promote`
- `task.status`

Increase Jest timeout only when the backend work is expected to take longer.

### Runtime Failures

Static integration tests should not require live Windows runtime. For hybrid/runtime tests, collect:

- `dynamic.runtime.status`;
- `/api/v1/ready`;
- Host Agent logs;
- Runtime Node logs;
- relevant environment variables without secrets.

## CI Notes

CI should run:

```bash
npm run typecheck
npm run test:unit
npm run test:integration
npm run build
```

Docker and live runtime tests should be separated from fast unit/integration checks unless the runner has the required environment.
