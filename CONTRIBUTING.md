# Contributing

This repository is a TypeScript monorepo with a Node.js MCP Analyzer, plugin packages, a Runtime Node, a Windows Host Agent, Python workers, Docker profiles, and tests.

Use Node.js 22+ for repository development.

## Development Setup

### Docker Development

Docker gives the most repeatable environment.

```bash
npm install
npm run build
npm run docker:generate:all
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
```

Useful commands:

```bash
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml ps
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml logs -f analyzer
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml down
```

### Native Development

```bash
npm install
npm run build
npm test
node dist/index.js
```

Python worker dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

Ghidra-backed analysis requires Java 21+ for modern Ghidra releases and a valid Ghidra install path.

## Validation

Run the narrowest useful check while working, then a broader check before handing off.

```bash
npm run typecheck
npm run test:unit
npm run test:integration
npm run test:e2e
npm test
npm run validate
```

Docker generation check:

```bash
npm run build
npm run docker:generate:all
```

If you changed runtime contracts, Runtime Node, or Host Agent behavior, also run:

```bash
npm run build:runtime
```

## Repository Layout

| Path | Purpose |
| --- | --- |
| `src/index.ts` | Analyzer entry point |
| `src/core/` | MCP server, registry, executor, plugin orchestration |
| `src/core/tool-registry/` | Core tool/prompt/resource registration slices |
| `src/tools/` | Core tool implementations |
| `src/workflows/` | Analysis workflows |
| `src/plugins/` | Built-in plugins |
| `packages/plugin-sdk/` | Public plugin SDK |
| `packages/shared/` | Shared runtime/tool contracts |
| `packages/runtime-node/` | Isolated runtime executor |
| `packages/windows-host-agent/` | Windows Sandbox / Hyper-V host agent |
| `workers/` | Python worker code and YARA rules |
| `docs/` | Architecture, plugin, runtime docs |

Root files such as `src/tool-registry.ts`, `src/server.ts`, and `src/plugins.ts` are compatibility forwarders. New implementation work should target `src/core/*`.

## Adding Core Tools

Prefer plugins for specialist capabilities. Add a core tool only when it is part of the baseline Analyzer contract, such as sample intake, artifacts, workflow orchestration, tasks, health, diagnostics, or utility discovery.

Core tool steps:

1. Add the implementation under `src/tools/` or `src/workflows/`.
2. Define a `ToolDefinition` with Zod input schema and output schema when useful.
3. Register it in the correct `src/core/tool-registry/*.ts` slice.
4. Add tests for validation, success, and important error behavior.
5. Update user-facing docs if the workflow changes.

## Adding Or Updating Plugins

Built-in plugins live under `src/plugins/<id>/`.

Plugin steps:

1. Create or update `src/plugins/<id>/index.ts`.
2. Use the public contract from `src/plugins/sdk.ts` or `@rikune/plugin-sdk`.
3. Register tools from `src/plugins/<id>/tools/`.
4. Declare `executionDomain`, `surfaceRules`, dependencies, and system dependencies.
5. Use injected services from `PluginToolDeps`; avoid importing Analyzer internals from plugins.
6. Add Docker metadata for external tools when required.
7. Add unit or integration tests.
8. Update [docs/PLUGINS.md](docs/PLUGINS.md) when plugin inventory or behavior changes.

External plugin scaffold:

```bash
node scripts/create-plugin.js my-feature --name "My Feature"
```

## Runtime Work

Runtime-sensitive changes require extra care.

Touch points:

- runtime contracts in `packages/shared`;
- analyzer client in `src/runtime-client`;
- runtime executor/router in `packages/runtime-node`;
- Host Agent lifecycle in `packages/windows-host-agent`;
- dynamic plugin runtime contracts;
- `tool.readiness` and readiness diagnostics.

Live execution must remain explicit and policy-gated. Docker/WSL Analyzer profiles should use `remote-sandbox`; Windows-native Analyzer can use `auto-sandbox`.

## Docker Guidelines

Docker files are generated from templates and plugin metadata.

Do:

- update plugin `systemDeps` and Docker metadata with plugin changes;
- regenerate Docker files after dependency changes;
- test the affected profile.

Do not:

- hand-edit generated Docker/Compose output without planning how regeneration will preserve the change;
- assume full and static profiles have the same dependency set;
- enable live runtime execution in static profiles.

Commands:

```bash
npm run build
npm run docker:generate:all
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
```

## Documentation Guidelines

Update docs in the same change when behavior changes.

Current authoritative docs:

- `README.md` and `README_zh.md` for user overview.
- `INSTALL.md` for Chinese Docker installation.
- `DEPLOYMENT.md` for deployment profiles.
- `docs/ARCHITECTURE.md` for code architecture.
- `docs/PLUGINS.md` for plugin inventory and SDK concepts.
- `packages/plugin-sdk/README.md` for plugin authors.
- `TROUBLESHOOTING.md` for operational errors.

Historical changelog entries should stay historical. Add new notes under `Unreleased`.

## Release Flow

Before release:

```bash
npm run validate
npm run build
npm run docker:generate:all
npm test
```

NPM release:

```bash
npm version prerelease --preid beta
npm publish
```

Docker release should build and tag generated profiles from the same commit that produced the package.
