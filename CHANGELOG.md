# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning where practical.

## [Unreleased]

### Plugin Matrix and SDK

- Expanded the plugin SDK contract with manifest v2 authoring helpers, aspect taxonomy, artifact/evidence helpers, dynamic runtime policy metadata, and fixture-backed harness coverage.
- Added passive static plugin coverage for common binary families including Windows installers/debug symbols, Linux packages/binaries, macOS/iOS containers/signing, Android packages, JVM, .NET/Unity, firmware filesystems, containers, WASM, and script bytecode.
- Added plan-only dynamic runtime plugins for Windows, Linux, macOS, iOS, Android, and WASM with opt-in isolation policy and no live runtime startup by default.
- Updated plugin matrix documentation and release quality gates for `qualityWarnings`, aspect metadata, output schemas, and runtime policy compatibility.

### Runtime Stability

- Fixed oversized `workflow.analyze.status` responses so response pruning keeps schema-valid structured content and reports pruning through top-level warnings.
- Fixed static Python worker envelope handling so tools such as `entropy.analyze` return flat schema-valid data instead of nested `data.data` payloads.
- Preserved staged-analysis `job_id` values across queued/running/completed updates so recovery logic no longer misclassifies active stages as lost worker context.
- Added automatic idle eviction for persistent runtime workers so idle `static_worker.py` processes are terminated after their configured TTL without waiting for another tool call.
- Added `task.status` visibility for external analyzer subprocesses through `external_active_rss_mb`, `external_active_process_count`, and `external_active_processes`.
- Materialized PE `.pdata` runtime function entries into the function index from `pe.pdata.extract`, making them immediately visible through `code.functions.list`.

### Tests

- Added regression coverage for response pruning, staged run `job_id` preservation, `.pdata` function materialization, and runtime worker idle eviction.

### Documentation

- Reworked active documentation to match the current `src/core/*` architecture, staged `workflow.analyze.start/status/promote` pipeline, 56 built-in plugin inventory, Docker profile model, and Analyzer/Runtime split.
- Updated installation, deployment, plugin, architecture, troubleshooting, SDK, worker, script-resource, and MCP client setup docs.

## [1.0.0-beta.3] - 2025-07-14

### Security Hardening (P0)

- **Security headers**: All responses now include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and a strict `Content-Security-Policy`.
- **CORS lockdown**: Changed `Access-Control-Allow-Origin` from wildcard `*` to localhost-only origin reflection (127.0.0.1 / localhost).
- **Dashboard authentication**: Dashboard HTML and API routes now require API key when `API_KEY` is set. Supports `X-API-Key` header or `?key=` query parameter for browser access.
- **Docker health check**: Replaced fake `console.log('healthy')` with real HTTP GET to `/api/v1/health`.

### Dashboard UX (P2)

- **Toast notifications**: Error, warning, info, and success toasts with auto-dismiss. API errors now show visual feedback.
- **Global search (Ctrl+K)**: Modal search across tools, samples, and artifacts. Debounced input with result categories and click-to-navigate.
- **Export CSV/JSON**: Samples, Analyses, and Artifacts tabs now have export buttons to download data as CSV or JSON files.
- **Plugin detail drawer**: Click any plugin row to open a detail panel showing config schema, tool list, error details, and status.
- **Auto-refresh toggle**: Header toggle to auto-refresh the active tab every 10 seconds.
- **Page jump & per-page**: All paginated tabs now support direct page jump input and configurable rows per page (30/50/100).

### CI/CD (P3)

- **Lint step**: Added `npm run lint` to CI pipeline (continue-on-error).
- **Coverage reporting**: Added coverage generation step with artifact upload.
- **Fixed CI flags**: Replaced deprecated `--testPathPattern` with `--testPathPatterns`.

### API Performance (P4)

- **Response caching**: Dashboard API endpoints for tools, plugins, config, and system now include `Cache-Control`, `ETag` headers. Supports `If-None-Match` -> 304 Not Modified.
- **Dashboard API documentation**: Added complete Dashboard API section to `docs/API-REFERENCE.md` documenting all 13 endpoints with parameters and response examples.

### Developer Experience (P5)

- **Dashboard hot-reload**: New `npm run dev:dashboard` script watches `src/api/dashboard/` and copies changes to dist on save.
- **Docker dev compose**: New `docker-compose.dev.yml` overlay mounts source code for live editing with dashboard hot-reload.

### Dashboard Iteration

- **Samples display fix**: Fixed `handleSamples` SQL query that selected non-existent columns (`original_name`, `file_size`), causing samples table to show blank rows. Now queries actual schema columns (`sha256`, `size`, `file_type`, `source`).
- **Sample detail drawer**: Clickable sample rows open a slide-in detail panel showing metadata grid, related analyses (with status badges and duration), artifacts (with inline view buttons), and top 20 functions ranked by score.
- **Analyses tab**: New dashboard tab with paginated analysis history table. Supports status filter dropdown (All / Done / Running / Queued / Failed) and clickable sample links.
- **Reports tab**: New dashboard tab for browsing and viewing artifacts inline.
  - Artifact list with type filter (auto-populated from backend) and path search.
  - **Markdown renderer**: Zero-dependency renderer supporting headers, bold/italic, code blocks, fenced code, tables, lists, blockquotes, links, horizontal rules.
  - **JSON syntax highlighter**: Recursive renderer with color-coded keys, strings, numbers, booleans, null.
  - **HTML viewer**: Sandboxed iframe rendering.
  - **SVG viewer**: DOMParser-based sanitized rendering.
  - **Code / text viewer**: Pre-formatted monospace display.
- **Dashboard API expansion**: 4 new endpoints - sample detail (`/samples/:id`), analyses listing, artifacts listing with type aggregation, artifact content reader with format detection.
- **Dashboard tab count**: 6 -> 8 tabs (Overview, Tools, Plugins, Samples, Analyses, Reports, Config, System).

### Bug Fixes & Quality

- **Async error handling**: Fixed fire-and-forget `void handleArtifactContent(...)` in dashboard API. Unhandled promise rejections now caught and logged with 500 response.
- **npm packaging**: Added `dist/**/*.html` and `data/*.json` to package.json `files` array. Dashboard HTML and vuln-patterns data were missing from published npm package.
- **Structured logging**: Replaced `console.error` in `src/workflows/triage.ts` with project logger.
- **Code hygiene**: Moved `error-handler.example.ts` from `src/` to `examples/` to avoid shipping example code in production build.
- **npm scripts**: Added `test:coverage` and `validate`.

### Plugin System Deep Refactoring

- **Plugin directory convention**: All plugin tool handlers migrated from flat `src/tools/` into `src/plugins/<id>/tools/` directories. Each plugin is now fully self-contained.
- **6 new plugins**: Expanded from 9 -> 15 built-in plugins:
  - `vuln-scanner` - Vulnerability pattern scanning and summary (2 tools)
  - `pe-analysis` - PE structure, imports, exports, fingerprint, pdata, symbol recovery (6 tools)
  - `threat-intel` - ATT&CK mapping and IOC export (2 tools)
  - `debug-session` - GDB/LLDB debug session management (6 tools)
  - `memory-forensics` - Memory dump analysis, volatility integration (6 tools)
  - `observability` - Tool call hook tracing (1 tool)
- **Plugin SDK**: Added `ToolArgs` type to `src/plugins/sdk.ts`; unified handler signature to `(deps: PluginToolDeps)` pattern across all plugins.
- **Tool count**: 160 MCP tools total (109 registry + 51 plugin-managed).
- **Test coverage**: 207 test files (194 unit + 13 integration).

### Web Dashboard

- **Web Dashboard** (`src/api/dashboard/index.html`): Dark-themed single-page monitoring dashboard served at `http://localhost:18080/dashboard`. 6 tabs: Overview, Tools, Plugins, Samples, Config, System.
- **Dashboard API** (`src/api/routes/dashboard-api.ts`): 7 JSON REST endpoints (`/api/v1/dashboard/*`) - overview, tools (categorized), plugins, samples (paginated), workers, config validation, system info.
- **Real-time SSE integration**: Dashboard subscribes to `/api/v1/events` for live analysis event streaming.
- **Auto-refresh**: Overview tab auto-polls every 15 seconds; tool search and sample pagination are fully client-side.
- **Docker integration**: Dashboard HTML is copied to dist during build; Dockerfile includes static asset copy; `docker-compose.yml` port comment updated.

### Production Hardening (P0-P3)

- **CI test coverage** (P0): `.github/workflows/ci.yml` runs full test suite.
- **TODO stub completion** (P0): Implemented `keygen-synthesizer`, `worker-pool`, `context-manager`, `decompiler-worker`, `DatabaseManager.getDb()`, `WorkerPool.registerHandler()`.
- **Config validation** (P0): `src/config-validator.ts` with `validateConfig()` returning `ValidationReport`; `config.validate` MCP tool.
- **Rate limiting** (P1): `src/api/rate-limiter.ts` integrated into HTTP File Server.
- **Pagination** (P1): `src/pagination.ts` cursor-based pagination utility.
- **Retry** (P1): `src/retry.ts` exponential backoff helper for transient failures.
- **Plugin SDK package** (P2): `packages/plugin-sdk/` standalone npm package for third-party plugin authors.
- **Plugin scaffolding** (P2): `scripts/create-plugin.js` interactive plugin generator.
- **Plugin tests** (P2): `tests/unit/plugins.test.ts` - 17 tests covering lifecycle, hooks, hot-load, and dependency resolution.
- **Plugin registry** (P2): `src/plugin-registry.ts` centralized plugin discovery and management.
- **LLM multi-model routing** (P3): `src/llm/model-router.ts` supports routing to multiple LLM backends.
- **Memory forensics** (P3): `src/plugins/memory-forensics.ts` plugin for memory analysis.
- **SBOM generation** (P3): `src/tools/sbom-generate.ts` Software Bill of Materials export.
- **Batch analysis** (P3): `src/tools/batch-analysis.ts` multi-sample batch analysis orchestration.
- **SSE events** (P3): `src/api/sse-events.ts` Server-Sent Events infrastructure for real-time streaming.

### Plugin SDK (Open Extensibility)

- **Plugin SDK** (`src/plugins.ts`): Complete rewrite - enhanced `Plugin` interface with `description`, `version`, `dependencies`, `configSchema`, `hooks`, and `teardown` fields. Third-party plugin authors implement this interface for full extensibility.
- **PluginManager**: Singleton class managing plugin lifecycle - `loadAll()`, `loadOne()`, `hotLoad()`, `unload()`, `fireHook()`, topological dependency sorting, `resolveEnabledPlugins()`.
- **9 built-in plugins**: Expanded from 4 -> 9 plugins. Added `frida` (runtime instrumentation), `ghidra` (headless analysis), `cross-module` (cross-binary comparison), `visualization` (HTML reports, timelines, data-flow maps), `kb-collaboration` (function matching, analysis templates).
- **Prerequisite checks**: `android` checks jadx binary access, `frida` checks `frida --version`, `ghidra` checks `GHIDRA_INSTALL_DIR` env var. Plugins that fail checks are gracefully skipped.
- **Plugin auto-discovery**: `plugins/` directory at project root is scanned for `.js`/`.mjs` files that default-export a `Plugin` object.
- **Declarative config schema**: Each plugin declares `configSchema: PluginConfigField[]`.
- **Dependency resolution**: Plugins declare `dependencies: string[]`.
- **Lifecycle hooks**: `PluginHooks` interface (`onBeforeToolCall`, `onAfterToolCall`, `onToolError`).
- **Hot-load / unload**: `plugin.enable` hot-loads a plugin at runtime, `plugin.disable` calls `teardown()` and unregisters all plugin tools.
- **Plugin introspection tools**: `plugin.list`, `plugin.enable`, `plugin.disable`.
- **`MCPServer.unregisterTool()`**: New method to remove tools at runtime.
- **`MCPServer.setPluginManager()`**: Wires PluginManager into server for lifecycle hook dispatch.
- **Docs**: Comprehensive `docs/PLUGINS.md` rewrite.

### Architecture & Infrastructure

- **Tool Registry** (`src/tool-registry.ts`): Centralised registration of all 148 tools, 3 prompts, and 16 resources. `src/index.ts` reduced from ~1,450 lines to ~90 lines.
- **Plugin Architecture** (`src/plugins.ts`): Four built-in plugins (android, malware, crackme, dynamic) controlled via `PLUGINS` env var.
- **MCP Resources**: 16 helper scripts (8 Frida + 8 Ghidra) exposed as MCP resources.
- **Streaming Progress** (`src/streaming-progress.ts`): `ProgressReporter` interface for long-running tools.
- **Architecture docs** (`docs/ARCHITECTURE.md`): Comprehensive guide covering tool registry, plugin system, resources, streaming, safe commands, process pool, structured logging, and CI/CD security.

### Security Hardening

- **Command injection prevention** (`src/safe-command.ts`): Whitelist regex validation, `execFileSync`/`spawnSync` with argument arrays, `safeCommandExists()`, `safeGetCommandVersion()`, `validateGraphvizFormat()`.
- **env-validator.ts**: Replaced `execSync` shell calls with safe wrappers.
- **cfg-visual-exports.ts**: Added `validateGraphvizFormat()` whitelist validation.
- **CI/CD security scanning**: Added `security` job to `.github/workflows/ci.yml`.

### Observability

- **Structured logging**: Migrated 7 files from `console.log`/`console.error` to Pino structured JSON logging.
- **Python Process Pool** (`src/python-process-pool.ts`): Queue-based concurrency limiter with `MAX_PYTHON_WORKERS` env var.

### Testing

- **68 new test files** generated for previously untested tools (193 total unit tests, up from 125).
- **Integration tests**: `tests/integration/full-pipeline.test.ts` and `tests/integration/beta2-tools.test.ts`.

### Documentation

- **API docs generation**: `scripts/generate-api-docs.js` + `npm run docs:api` script.
- New: `docs/ARCHITECTURE.md`, `docs/PLUGINS.md`.
- Updated: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/API-REFERENCE.md`, `CHANGELOG.md`.

## [1.0.0-beta.2] - 2026-03-30

### Android / APK Analysis

- Added `apk.structure.analyze` - APK manifest, permissions, and component extraction via Python worker.
- Added `apk.packer.detect` - APK packer/obfuscator detection.
- Added `dex.decompile` - DEX-to-Java decompilation via jadx.
- Added `dex.classes.list` - DEX class/method enumeration.
- Added `workers/apk_dex_worker.py`.
- Docker: Added jadx v1.5.1 installation.

### Symbolic Execution & CrackMe

- Added `symbolic.explore`.
- Added `keygen.verify`.
- Added `constraint.solve`.
- Added symbolic/keygen/constraint Python workers.

### Dynamic Analysis

- Added `dynamic.auto_hook`.
- Added `dynamic.memory_dump`.

### Malware Analysis

- Added `malware.config.extract`.
- Added `malware.classify`.
- Added `c2.extract`.
- Added `workers/malware_config_worker.py`.

### Cross-Platform & Visualization

- Added `elf.macho.parse`.
- Added `rizin.diff`.
- Added `cfg.visualize`.
- Added `timeline.correlate`.
- Added `cross_module.xref`.
- Added `kb.search`.
- Added ELF/Mach-O and Rizin diff workers.

### Quality & Infrastructure

- Unified Python path resolution via `config.workers.static.pythonPath`.
- Applied PolicyGuard to high-risk dynamic/symbolic tools.
- Applied CacheManager to malware analysis tools.
- Added worker input validation.
- `workflow.triage` routes APK/DEX samples to APK-specific tools.
- Replaced several `any` annotations.
- Added missing worker files to package metadata.
- Added unit tests for malware, APK, symbolic, and patch generation tools.

## [1.0.0-beta.1] - 2026-03-29

### Frida Dynamic Instrumentation

- Added Frida runtime instrumentation with spawn and attach modes.
- Added Frida script injection with pre-built script library.
- Added Frida trace capture with canonical MCP trace schema.
- Implemented trace filtering, aggregation, artifact persistence, and provenance tracking.
- Integrated Frida traces into dynamic import and report flows.
- Added async job support for long-running Frida traces.
- Added evidence scope selection and compare/baseline support.
- Added Frida documentation and tests.

### Static Analysis Foundation

- Added static triage foundation: `static.capability.triage`, `pe.structure.analyze`, and `compiler.packer.detect`.
- Added worker/config/setup support for `flare-capa`, `pefile`, `lief`, `CAPA_RULES_PATH`, and `DIE_PATH`.
- Integrated static capability, PE structure, and compiler/packer attribution into workflows and reports.
- Added static artifact persistence, provenance, scope selection, and compare/baseline support.

### HTTP File Server

- Added embedded HTTP file server on port 18080.
- Implemented sample upload, sample metadata, artifact list/read/delete, health, and upload session endpoints.
- Added API key authentication.
- Added MCP tools for file access.
- Added PowerShell upload/download helpers.
- Implemented storage management and audit logging.
- Added API documentation, Docker configuration, and tests.

### MCP Server Optimization (Phase 1-8)

- Implemented smart cache key generation.
- Implemented tiered response system.
- Enhanced JobQueue progress and cancellation.
- Implemented artifact lifecycle management.
- Added error recovery classification.
- Implemented MCP resources protocol.
- Added token usage persistence.
- Added performance benchmarking.

## [0.1.4] - 2026-03-14

- Added safer Ghidra defaults for `GHIDRA_PROJECT_ROOT` / `GHIDRA_LOG_ROOT`.
- Fixed bundled Ghidra script resolution.
- Added richer Ghidra diagnostics.
- Surfaced structured `ghidra_execution` summaries through workflows and reports.
- Added Java runtime detection and Java 21+ setup guidance.
- Extended module reconstruction review refresh.
- Stabilized unit coverage for Ghidra failure handling.

## [0.1.3] - 2026-03-14

- Added DLL- and COM-oriented profiling with `dll.export.profile` and `com.role.profile`.
- Added module-level LLM review primitives.
- Extended `workflow.reconstruct` with role-aware export strategy.
- Improved runtime memory ingestion.
- Added structured setup guidance.
- Refined README, installation docs, and release packaging.

## [0.1.2] - 2026-03-12

- Upgraded `workflow.reconstruct` with universal preflight orchestration.
- Aligned semantic review workflows with reconstruct refresh preflight.
- Added `.pdata`-driven PE recovery tooling.
- Added `workflow.function_index_recover` and `rust_binary.analyze`.
- Hardened sample/original and Ghidra project fallback handling.
- Stabilized runtime state defaults.

## [0.1.1] - 2026-03-11

- Added `binary.role.profile`.
- Added quality scaffolding.
- Added async job mode for high-level workflows.
- Wired queued workflow execution into the background analysis task runner.
- Integrated binary role profile output into report tools.
- Added report coverage for runtime and semantic provenance.
- Continued repository and packaging cleanup.

## [0.1.0] - 2026-03-11

- Initial public packaging baseline.
- MCP server with static PE analysis, Ghidra integration hooks, runtime evidence tools, and reconstruction workflows.
