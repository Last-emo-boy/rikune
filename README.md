# Rikune

Rikune is an MCP server for reverse engineering Windows executables and related binary formats. It combines sample intake, static triage, Ghidra-assisted function recovery, plugin-driven specialist tooling, artifact management, and optional isolated Windows runtime execution behind a Model Context Protocol interface.

The current AI-facing server workflow is organized around a minimal gateway surface:

1. Use `workflow.search` to rank matching profiles, workflows, and specialist capabilities for the file type and user goal.
2. Use `workflow.run action=request_upload` for host-file upload, or let `workflow.search` point legacy clients to hidden sample-intake compatibility tools.
3. Use `workflow.run action=start` with the returned `sample_id`.
4. Use `workflow.run action=status` and `workflow.run action=promote` to monitor and deepen the staged run.
5. Use `artifact.read` for full persisted artifacts when compact workflow output is not enough.

`sample.*`, `workflow.analyze.*`, `workflow.triage`, `tools.discover`, and `task.status` remain registered for compatibility or low-level inspection, but new clients should prefer `workflow.search`, `workflow.run`, and `artifact.read`.

When connecting through the remote `rikune-agent` gateway, MCP clients see stable transport names:
`workflow_search`, `workflow_run`, `artifact_read`, `rikune_tool_call`, and the
`rikune_connection_*` controls. `rikune_connection_refresh` updates the internal upstream
capability cache only; it does not expand the MCP tool list. Use `rikune_tool_call` only after
`workflow_search` identifies a specific internal analyzer subtool that is not covered by the
primary workflow or artifact gateways.

## What Rikune Provides

- MCP stdio server for AI clients and agent runtimes.
- Optional HTTP API and dashboard for uploads, downloads, health checks, SSE events, and artifact access.
- SHA-256 based sample workspaces with durable original files, cache directories, analysis artifacts, and upload sessions.
- SQLite-backed persistence for samples, analyses, jobs, evidence, artifacts, batches, debug sessions, and scheduler telemetry.
- Plugin architecture with 117 built-in plugins and external plugin discovery.
- Progressive tool surface: the default AI-facing gateway is intentionally small; `workflow.search` uses sample type, findings, and profile metadata to route toward specialist capabilities without exposing every tool up front.
- Static analysis and enrichment for PE, ELF, Mach-O, APK/DEX, Office, firmware, UEFI/SMM, CUDA PTX/CUBIN/fatbin, strings, YARA, SBOM, signatures, packers, .NET, Go, Rust, and more.
- Ghidra, Rizin, RetDec, angr, Capstone, Graphviz, Qiling, PANDA, Speakeasy, Wine, Frida, and dynamic-runtime integration where available.
- Plugin-driven Docker backend installation with default, optional, research, runtime, GPU, BYO, and sidecar tiers for worker-backed reverse-engineering tools.
- Optional Analyzer/Runtime split for live Windows execution through a Windows Host Agent, Windows Sandbox, or Hyper-V VM.
- Policy gates for live execution, network access, external upload, and bulk decompilation.

## Platform Support in v1.4.0

The Analyzer and sample-custody data plane require a Linux kernel: native Linux, a Linux
container, or WSL2. Windows and macOS can host the supported Linux-container/control plane;
Windows can additionally host the Windows Host Agent, Windows Sandbox, or Hyper-V runtime for
explicit live execution. A native Windows or macOS Node Analyzer, including the
`auto-sandbox` topology, is not supported in v1.4.0. This boundary preserves the fail-closed
Linux secure-filesystem contract instead of treating unsupported filesystems as equivalent.
Under WSL2, keep `RIKUNE_DATA_ROOT` and every workspace/sample/storage path on the WSL Linux
filesystem (for example `~/.rikune` in the distribution's ext4.vhdx). `/mnt/c` and other
`/mnt/<drive>` DrvFS paths are not supported for sample custody.
The generated Analyzer images are currently `linux/amd64`. Every generated Compose service pins
that platform explicitly; Apple Silicon Docker Desktop hosts run it through amd64 emulation. Do
not remove or override the generated platform pin.

## Quick Start

### Static Docker Analyzer

Static Docker is the safest default. It does not execute samples.

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

```bash
./rikune.sh install --profile static --data-root "$HOME/.rikune"
```

The wrapper is the supported installation transaction. It snapshots and removes the protected
Compose env before dependency lifecycle commands, restores it if pre-commit work fails, and commits
the rotated credentials only after the new file verifies. Do not reproduce that sequence with the
lower-level env writer and `npm ci` commands.

The env writer rotates to a new 32-byte analyzer API key from the operating system CSPRNG unless a key is explicitly supplied for that invocation, and sets file mode `0600` on POSIX systems. Compose binds the API to `127.0.0.1` by default. The local Dashboard is `http://127.0.0.1:18080/?key=<RIKUNE_API_KEY>`; do not share that URL or commit `.docker-runtime.env`.

### Hybrid Docker + Windows Runtime

Hybrid mode runs the Analyzer in Docker and delegates live Windows work to a Windows Host Agent. The Host Agent can start Windows Sandbox on demand or control a configured Hyper-V VM.

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime
```

From Linux/macOS with a remote Windows runtime host:

```bash
# Bootstrap only inside an isolated trusted network/VPN; sandbox runtime ports use HTTP.
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user> \
  --host-agent-endpoint https://runtime.example.internal \
  --allow-insecure-runtime-http
```

The HTTPS endpoint should terminate at a trusted reverse proxy/VPN path. Remote bootstrap still uses plaintext Host Agent/Sandbox runtime ports inside that isolated network, so it requires the explicit `--allow-insecure-runtime-http` opt-in shown above. With a separately secured, pre-provisioned runtime, use `--skip-windows-setup` instead and omit the insecure opt-in. Runtime keys are accepted through a protected environment or hidden prompt, never as CLI arguments.

Connecting an MCP client does not start Windows Sandbox or run a sample. Live runtime work only starts when a tool explicitly requests it, such as `runtime.debug.session.start`, `runtime.debug.command`, `sandbox.execute`, or a promoted dynamic execution stage.

### Native Linux Development

Run the root Analyzer directly only on a Linux kernel. On Windows, use WSL2 or a Linux container;
on macOS, use a Linux container/VM. Windows runtime packages can still be developed and tested on
their native Windows host.

```bash
npm ci --include=dev
npm run build
npm test
node --env-file-if-exists=.env dist/index.js
```

The root package requires Node.js 22.9 or newer. Some runtime subpackages can run on older Node versions, but repository development and the published root CLI should use Node 22.9+.

## Primary Gateway Flow

### Search And Upload

Start with `workflow.search` whenever the requested workflow, file type, or backend is unclear. It ranks matching profiles and returns compact readiness/routing hints without activating hidden specialist tools.

For host files, call `workflow.run action=request_upload`, POST raw bytes to the returned upload URL, then read `sample_id` from the HTTP response. `sample.request_upload` and `sample.ingest` are compatibility helpers rather than the normal AI-facing path.

For remote analyzer or `rikune-agent` deployments, set `API_PUBLIC_BASE_URL`, `RIKUNE_API_PUBLIC_BASE_URL`, or `RIKUNE_ANALYZER_PUBLIC_URL` to a client-reachable HTTPS base such as `https://analyzer.example.com`. Upload sessions then return public `upload_url` / `status_url` values instead of container-local `localhost` URLs. Terminate TLS at a trusted reverse proxy on the same private Docker network; if the proxy also enforces SSO, strip any user-supplied `X-API-Key` and inject the internal analyzer secret only after authentication. Never expose the key-bearing API over plaintext HTTP. The remote gateway also normalizes localhost upload URLs from older analyzers to its configured analyzer endpoint.

If the HTTP API is enabled, `POST /api/v1/samples` is still available for non-MCP integrations. Successful intake returns a `sample_id`; analysis should use `sample_id`, not a local path, after import.

### Start Analysis

Call `workflow.run action=start` with the `sample_id`. The first stage performs a fast profile and creates or reuses an analysis run. The returned `plan_id` maps to the persisted analysis run.

### Promote Stages

Use `workflow.run action=promote` to request deeper stages. The pipeline currently models these stages:

- `fast_profile`
- `enrich_static`
- `function_map`
- `reconstruct`
- `semantic_name_review`
- `semantic_explain_review`
- `semantic_module_review`
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
- `artifact.read`, plus compatibility artifact helpers such as `artifacts.list`, `artifacts.diff`, and `artifact.download`
- `report.summarize`, `report.generate`, `workflow.summarize`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`
- `workflow.module_reconstruction_review`
- `tool.help`, `tool.readiness`, and `tools.discover` for compatibility/debug inspection

`analysis.claims.apply` records evidence-backed AI or imported findings as append-only `inferred` Claim Ledger revisions. Natural-language discovery can return the precise hidden result `tool:analysis.claims.apply` without activating sibling plugin tools. Analyst revisions are intentionally fail-closed: there is no MCP or HTTP path that can self-assign a reviewer or terminal status. A future operator boundary must use signed review intents before trusted decisions are enabled.

### Agent Case Workspace

Rikune keeps deterministic Analyzer Artifacts separate from Agent-authored investigation context:

```text
Analyzer Artifact (eligible Evidence)
  -> analysis.claims.apply (inferred Claim Ledger)
  -> analysis.case.checkpoint / analysis.case.snapshot (immutable Case state)
  -> analysis.context.pack (deterministic, token-bounded context)
  -> workflow.summarize (final digest with separate Evidence and Context)
```

`analysis_claim_set`, `analysis_case_state`, summary, and report Artifacts are context-only. They cannot become Claim evidence or enter summary `source_artifact_refs`. AI and imported producers can write only `inferred` Claims; trusted analyst review remains fail-closed.

Each Case is isolated by `case_id`. `analysis.context.pack` and `workflow.summarize` auto-select a sole Case, but fail closed when multiple Cases exist without an explicit selector. Once selected, Claim context is restricted to that Case's `active_claim_ids`; if Case state exists but cannot be trusted, Claims are withheld instead of falling back to the sample-wide Ledger. Active IDs are resolved newest-to-oldest through an integrity-checked scan capped at 512 Claim Set Artifacts and 128 MiB; a missing ID, broken chain, or exhausted budget withholds the entire Case Claim view. Incremental Context markers are also bound to `case_id` and cannot be reused across Cases.

Persisted summary reuse is guarded by a versioned fingerprint over the resolved synthesis mode, every scope/session selector, non-context source Artifact metadata, persisted Evidence/Function/Analysis/Run/RunStage state, selected Claim/Case markers, and integrity-review state. Source Artifact files are streamed through SHA-256 validation before reuse. Legacy digests without a compatible fingerprint are rebuilt instead of being reused.

Claim and Case writers serialize through a heartbeat-backed SQLite CAS lease before taking their owner-identified filesystem locks. Stale takeover is conditional on the observed owner and heartbeat, while malformed/foreign-host filesystem locks use identity-checked recovery. Writers reassert lease ownership before the final rename, then atomically fence the Artifact row insert on the current owner token. Before creating locks or JSON artifacts, workspace writes validate the configured canonical root and reject symlink-replaced shard or sample directories.

The reproducible benign CrackMe acceptance script runs passive ELF, hardening, strings, Claim, Case, Context, and deterministic summary steps by default. `--deep` additionally enables Ghidra:

```bash
npm run test:agent-case:e2e -- \
  --container <running-rikune-container> \
  --binary /fixtures/complex_crackme
```

See `tests/fixtures/crackmes/README.md` for fixture build and isolated-execution rules.

## Architecture

The current code path is:

```text
src/index.ts
  -> loadConfig()
  -> WorkspaceManager / DatabaseManager / PolicyGuard / CacheManager / StorageManager / JobQueue
  -> optional RuntimeClient or Windows Host Agent-backed runtime delegation
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
- `auto-sandbox`: compatibility configuration value; no supported v1.4.0 deployment topology.

Linux-kernel analyzers should use `remote-sandbox` to delegate to a Windows Host Agent. Native
Windows/macOS Node Analyzer and `auto-sandbox` topologies are unsupported in v1.4.0.

## Plugin System

Rikune currently includes 117 built-in plugins under `src/plugins/<id>/`. Plugins can register tools, declare dependencies, expose configuration schema, participate in lifecycle hooks, provide Docker metadata, and declare bounded Worker-backed tools through `workerBackend` metadata.

The frontier Worker suite keeps plan-only tools as triage and handoff surfaces, then adds explicit execution tools beside them. `restringer.deobfuscation.run`, `jsimplifier.pipeline.run`, `jsir.cascade.normalize`, `jsvmp.bytecode.recover`, `gtirb.ir.generate`, `remill.lift.run`, `manifold.fact.extract`, `qbdi.trace.run`, and `culifter.gpu.artifact.inventory` expose Worker contracts through `workflow.search`, `plugin.list`, `tool.help`, and `tool.readiness`; `tools.discover` remains a low-level compatibility portal. Discovery and readiness remain passive: they report backend metadata and setup guidance without starting REstringer, JSIMPLIFIER, JSIR/CASCADE, JSVMP, GTIRB, Remill, Manifold, QBDI, GPU drivers, Node/V8, browsers, or runtime instrumentation.

The `pdf-analysis` plugin exposes `pdf.analyze` for bounded, passive PDF structure, embedded JavaScript text, URI, action, and embedded-file inspection. It uses a bundled Python standard-library worker and does not open the document or execute embedded content.

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

- Node.js 22.9+
- npm
- CPython 3.12 x86_64 for native workers and the repository's hash-locked Python environments
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
  plugins/                    117 built-in plugins
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
npm ci --include=dev
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
npm run test:agent-case:e2e -- --help
npm run build:runtime
```

## MCP Client Configuration

Linux-native local build (including WSL2 with the repository and data on its Linux filesystem):

```json
{
  "mcpServers": {
    "rikune": {
      "command": "node",
      "args": ["/home/user/rikune/dist/index.js"],
      "env": {
        "API_ENABLED": "false",
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
      "args": [
        "exec",
        "-i",
        "-e",
        "API_ENABLED=false",
        "-e",
        "NODE_ENV=production",
        "-e",
        "PYTHONUNBUFFERED=1",
        "rikune-analyzer",
        "node",
        "dist/index.js"
      ]
    }
  }
}
```

Published package:

```bash
npm install -g rikune
# Linux-native Analyzer (or inside WSL2)
rikune
# Linux-container Analyzer on any supported Docker host
rikune docker-stdio
# Agent/control-plane entry point
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
- [docs/DYNAMIC-RUNTIME-ROADMAP.md](docs/DYNAMIC-RUNTIME-ROADMAP.md): runtime roadmap and status.
- [CONTRIBUTING.md](CONTRIBUTING.md): development and contribution flow.
- [packages/plugin-sdk/README.md](packages/plugin-sdk/README.md): plugin authoring package.
- [workers/README.md](workers/README.md): Python worker contract.

## License

MIT
