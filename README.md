# Rikune

Rikune is an MCP server for reverse engineering Windows executables and related binary formats. It combines sample intake, static triage, Ghidra-assisted function recovery, plugin-driven specialist tooling, artifact management, and optional isolated Windows runtime execution behind a Model Context Protocol interface.

The current AI-facing server workflow is organized around a minimal gateway surface:

1. Use `workflow.search` to rank matching profiles, workflows, and specialist capabilities for the file type and user goal.
2. Use `workflow.run action=request_upload` for host-file upload, or let `workflow.search` point legacy clients to hidden sample-intake compatibility tools.
3. Use `workflow.run action=start` with the returned `sample_id`.
4. Use `workflow.run action=status` and `workflow.run action=promote` to monitor and deepen the staged run.
5. Use `artifact.read` for full persisted artifacts when compact workflow output is not enough.

`sample.*`, `workflow.analyze.*`, `workflow.triage`, `tools.discover`, and `task.status` remain registered for compatibility or low-level inspection, but new clients should prefer `workflow.search`, `workflow.run`, and `artifact.read`.

## What Rikune Provides

- MCP stdio server for AI clients and agent runtimes.
- Optional HTTP API and dashboard for uploads, downloads, health checks, SSE events, and artifact access.
- SHA-256 based sample workspaces with durable original files, cache directories, analysis artifacts, and upload sessions.
- SQLite-backed persistence for samples, analyses, jobs, evidence, artifacts, batches, debug sessions, and scheduler telemetry.
- Plugin architecture with 94 built-in plugins and external plugin discovery.
- Progressive tool surface: the default AI-facing gateway is intentionally small; `workflow.search` uses sample type, findings, and profile metadata to route toward specialist capabilities without exposing every tool up front.
- Static analysis and enrichment for PE, ELF, Mach-O, APK/DEX, Office, firmware, CUDA PTX/CUBIN/fatbin, strings, YARA, SBOM, signatures, packers, .NET, Go, Rust, and more.
- Ghidra, Rizin, RetDec, angr, Capstone, Graphviz, Qiling, PANDA, Speakeasy, Wine, Frida, and dynamic-runtime integration where available.
- Plugin-driven Docker backend installation with default, optional, research, runtime, GPU, BYO, and sidecar tiers for worker-backed reverse-engineering tools.
- Optional Analyzer/Runtime split for live Windows execution through a Windows Host Agent, Windows Sandbox, or Hyper-V VM.
- Policy gates for live execution, network access, external upload, and bulk decompilation.

## Quick Start

### Static Docker Analyzer

Static Docker is the safest default. It does not execute samples.

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

```bash
./rikune.sh install --profile static --data-root "$HOME/.rikune"
```

Manual equivalent:

```bash
npm install
npm run build
npm run docker:generate:all
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
```

### Hybrid Docker + Windows Runtime

Hybrid mode runs the Analyzer in Docker and delegates live Windows work to a Windows Host Agent. The Host Agent can start Windows Sandbox on demand or control a configured Hyper-V VM.

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime
```

From Linux/macOS with a remote Windows runtime host:

```bash
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
```

Connecting an MCP client does not start Windows Sandbox or run a sample. Live runtime work only starts when a tool explicitly requests it, such as `runtime.debug.session.start`, `runtime.debug.command`, `sandbox.execute`, or a promoted dynamic execution stage.

### Native Development

```bash
npm install
npm run build
npm test
node dist/index.js
```

The root package requires Node.js 22 or newer. Some runtime subpackages can run on older Node versions, but repository development and the published root CLI should use Node 22+.

## Primary Gateway Flow

### Search And Upload

Start with `workflow.search` whenever the requested workflow, file type, or backend is unclear. It ranks matching profiles and returns compact readiness/routing hints without activating hidden specialist tools.

For host files, call `workflow.run action=request_upload`, POST raw bytes to the returned upload URL, then read `sample_id` from the HTTP response. `sample.request_upload` and `sample.ingest` are compatibility helpers rather than the normal AI-facing path.

If the HTTP API is enabled, `POST /api/v1/samples` is still available for non-MCP integrations. Successful intake returns a `sample_id`; analysis should use `sample_id`, not a local path, after import.

### Start Analysis

Call `workflow.run action=start` with the `sample_id`. The first stage performs a fast profile and creates or reuses an analysis run. The returned `plan_id` maps to the persisted analysis run.

### Promote Stages

Use `workflow.run action=promote` to request deeper stages. The pipeline currently models these stages:

- `fast_profile`
- `enrich_static`
- `function_map`
- `reconstruct`
- `semantic_reviews`
- `dynamic_plan`
- `dynamic_execute`
- `summarize`

Long-running work is queued through the job system. Poll compact staged state with `workflow.run action=status`.

`workflow.run action=status` is the primary staged-run view. Large historical stage payloads may be pruned with a top-level warning; use `artifact.read` for full artifacts. `task.status` is a raw queue/process compatibility view and includes `external_active_*` memory telemetry for analyzer subprocesses.

### Review Results

Useful follow-up surfaces:

- `workflow.search`
- `workflow.run`
- `analysis.context.get`
- `artifact.read`, plus compatibility artifact helpers such as `artifact.list`, `artifact.diff`, and `artifact.download`
- `report.summarize`, `report.generate`, `workflow.summarize`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`
- `workflow.module_reconstruction_review`
- `tool.help`, `tool.readiness`, and `tools.discover` for compatibility/debug inspection

## Architecture

The current code path is:

```text
src/index.ts
  -> loadConfig()
  -> WorkspaceManager / DatabaseManager / PolicyGuard / CacheManager / StorageManager / JobQueue
  -> optional RuntimeClient or Windows sandbox bootstrap
  -> registerAllTools()
  -> MCP stdio server
```

Core server modules live under `src/core/`:

| Area | Current file |
| --- | --- |
| MCP server wrapper | `src/core/server.ts` |
| MCP tool/prompt/resource registry | `src/core/mcp-registry.ts` |
| Tool execution, validation, hooks | `src/core/tool-executor.ts` |
| Registry orchestration | `src/core/tool-registry.ts` |
| Built-in registry slices | `src/core/tool-registry/*.ts` |
| Plugin manager facade | `src/core/plugins.ts` |
| Plugin discovery/loading | `src/core/plugin-orchestrator.ts` |
| Progressive tool exposure | `src/core/tool-surface-manager.ts` |

Some root-level files such as `src/server.ts`, `src/tool-registry.ts`, and `src/plugins.ts` remain compatibility forwarders. New code should target `src/core/*`.

## Deployment Planes

| Plane | Purpose | Key code |
| --- | --- | --- |
| Analyzer | MCP stdio server, HTTP API, storage, jobs, static tools, plugin orchestration | `src/index.ts`, `src/core/*` |
| Runtime Node | Isolated task executor inside sandbox or VM | `packages/runtime-node/*` |
| Windows Host Agent | Starts/stops Windows Sandbox or Hyper-V runtime and exposes runtime control endpoints | `packages/windows-host-agent/*` |
| Agent Gateway | MCP gateway/proxy for analyzer/runtime connection management | `src/rikune-agent-gateway.ts` |

Runtime modes are configured through `runtime.mode` or environment variables:

- `disabled`: no runtime delegation.
- `manual`: connect to a supplied runtime endpoint.
- `remote-sandbox`: delegate to a Windows Host Agent.
- `auto-sandbox`: Windows-native analyzer launches Windows Sandbox locally.

Docker/WSL analyzers should use `remote-sandbox`, not `auto-sandbox`.

## Plugin System

Rikune currently includes 94 built-in plugins under `src/plugins/<id>/`. Plugins can register tools, declare dependencies, expose configuration schema, participate in lifecycle hooks, provide Docker metadata, and declare bounded Worker-backed tools through `workerBackend` metadata.

The frontier Worker suite keeps plan-only tools as triage and handoff surfaces, then adds explicit execution tools beside them. `restringer.deobfuscation.run`, `jsimplifier.pipeline.run`, `jsir.cascade.normalize`, `gtirb.ir.generate`, `remill.lift.run`, `manifold.fact.extract`, `qbdi.trace.run`, and `culifter.gpu.artifact.inventory` expose Worker contracts through `workflow.search`, `plugin.list`, `tool.help`, and `tool.readiness`; `tools.discover` remains a low-level compatibility portal. Discovery and readiness remain passive: they report backend metadata and setup guidance without starting REstringer, JSIMPLIFIER, JSIR/CASCADE, GTIRB, Remill, Manifold, QBDI, GPU drivers, Node/V8, browsers, or runtime instrumentation.

Docker generation reads plugin `systemDeps` and Worker packaging metadata directly. Default images install low-risk static wrappers such as REstringer, JSIMPLIFIER, Manifold, WABT, and LIEF validation; optional profiles can enable JSIR/CASCADE, JSVMP, GTIRB, radare2, and Triton-style static routes; heavy/runtime/GPU/license-sensitive backends remain profile-gated, BYO, or sidecar.

```bash
node scripts/generate-docker.mjs --dry-run
node scripts/generate-docker.mjs --profile=full --backend-profile=optional
node scripts/generate-docker.mjs --all-profiles --dry-run
```

Plugin loading is controlled by `PLUGINS`:

```bash
PLUGINS=*                 # all built-ins
PLUGINS=pe-analysis,yara  # selected plugins
PLUGINS=-dynamic          # all except dynamic
```

Use these MCP tools at runtime:

- `workflow.search`
- `workflow.run`
- `plugin.list`
- `plugin.enable`
- `plugin.disable`
- `tools.discover` and `tool.readiness` for low-level compatibility/debug inspection

See [docs/PLUGINS.md](docs/PLUGINS.md) and [packages/plugin-sdk/README.md](packages/plugin-sdk/README.md).

## HTTP API

When `api.enabled` is true, the embedded file server exposes:

| Endpoint | Purpose |
| --- | --- |
| `/dashboard` and `/` | Dashboard UI |
| `/api/v1/health` | Liveness |
| `/api/v1/ready` | Readiness across database, queue, runtime, and plugin backends |
| `/api/v1/events` | SSE events |
| `/api/v1/samples` | Direct sample upload |
| `/api/v1/samples/:id` | Sample metadata |
| `/api/v1/samples/:id/download` | Original sample download |
| `/api/v1/artifacts` | Artifact listing |
| `/api/v1/artifacts/:id` | Artifact read/delete |
| `/api/v1/uploads/:token` | Durable upload session POST/status |

API key auth, rate limiting, security headers, and limited CORS are handled by the HTTP layer.

## Prerequisites

Minimum development baseline:

- Node.js 22+
- npm
- Python 3.11+ recommended for workers and analysis scripts
- Docker 20.10+ and Docker Compose v2 for Docker profiles
- Java 21+ for modern Ghidra releases
- Ghidra for decompiler-backed function analysis
- Windows 10/11 Pro, Enterprise, or equivalent VM support for Windows Sandbox and Hyper-V runtime paths

Optional tools are plugin-specific. Run `system.health`, `system.setup.guide`, `tool.readiness`, and `plugin.list` to see what is missing in a given environment.

## Project Layout

```text
src/
  index.ts                    main server entry
  core/                       MCP server, registry, executor, plugin orchestration
  core/tool-registry/         built-in tool/prompt/resource registration slices
  tools/                      core tool implementations
  workflows/                  staged analysis, triage, reconstruction, review workflows
  analysis/                   run state and background task runner
  plugins/                    94 built-in plugins
  persistence/                SQLite and workspace persistence
  sample/                     sample finalization and workspace inspection
  storage/                    artifacts, uploads, retention
  runtime-client/             analyzer-side runtime delegation client
  worker/                     Ghidra and Python worker orchestration
packages/
  plugin-sdk/                 public plugin SDK
  shared/                     runtime and tool contract types
  runtime-node/               isolated runtime executor
  windows-host-agent/         Windows Sandbox / Hyper-V host agent
workers/                      Python worker scripts and YARA rules
docker/                       generated Dockerfile templates and profile files
docs/                         architecture, plugin, runtime, deployment docs
tests/                        unit, integration, and e2e tests
```

## Development Commands

```bash
npm install
npm run build
npm test
npm run typecheck
npm run validate
npm run docker:generate:all
```

Useful focused checks:

```bash
npm run test:unit
npm run test:integration
npm run test:e2e
npm run build:runtime
```

## MCP Client Configuration

Local build:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "node",
      "args": ["D:/Playground/windows-exe-decompiler-mcp-server/dist/index.js"],
      "env": {
        "API_ENABLED": "true",
        "API_PORT": "18080",
        "PLUGINS": "*"
      }
    }
  }
}
```

Docker stdio:

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": ["exec", "-i", "rikune-analyzer", "node", "dist/index.js"]
    }
  }
}
```

Published package:

```bash
npm install -g rikune
rikune
rikune docker-stdio
rikune agent
```

## Storage

By default Rikune stores persistent data under the user-level Rikune root. Docker installers usually map that root to a host directory such as `D:\Docker\rikune`.

Common subdirectories:

- `samples/`
- `artifacts/`
- `uploads/`
- `cache/`
- `logs/`
- SQLite database file
- audit log JSONL

Sample workspaces are bucketed by SHA-256 to avoid path collisions and preserve immutable originals.

## Security Boundaries

Rikune is designed for malware and untrusted binary analysis, but it is not a magic safety boundary by itself.

- Static Docker mode should be the default for routine analysis.
- Live Windows execution must happen inside Windows Sandbox or an isolated VM.
- Runtime Node refuses unsafe startup unless explicitly overridden.
- Dangerous actions are guarded by `PolicyGuard`.
- Command execution uses structured process APIs and allowlisted command validation.
- Do not run unknown samples on a host workstation outside the runtime isolation model.

See [SECURITY.md](SECURITY.md) and [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Documentation Map

- [INSTALL.md](INSTALL.md): Docker installer guide in Chinese.
- [DEPLOYMENT.md](DEPLOYMENT.md): deployment profiles and runtime topology.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): current code architecture.
- [docs/PLUGINS.md](docs/PLUGINS.md): plugin list, SDK concepts, lifecycle, discovery.
- [docs/ANALYSIS-RUNTIME.md](docs/ANALYSIS-RUNTIME.md): staged runtime and analysis execution model.
- [docs/ASYNC-JOB-PATTERN.md](docs/ASYNC-JOB-PATTERN.md): async job and polling pattern.
- [docs/MIGRATION-ASYNC.md](docs/MIGRATION-ASYNC.md): migration notes for staged async workflows.
- [docs/DYNAMIC-RUNTIME-ROADMAP.md](docs/DYNAMIC-RUNTIME-ROADMAP.md): runtime roadmap and status.
- [CONTRIBUTING.md](CONTRIBUTING.md): development and contribution flow.
- [packages/plugin-sdk/README.md](packages/plugin-sdk/README.md): plugin authoring package.
- [workers/README.md](workers/README.md): Python worker contract.

## License

MIT
