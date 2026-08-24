# Rikune Troubleshooting Guide

This guide covers the current Analyzer/Runtime split architecture, Docker profiles, MCP stdio, and common plugin dependency failures.

## First Checks

Run these before deeper debugging:

```bash
npm run build
npm run typecheck
npm test
```

If the HTTP API is enabled:

```bash
curl http://localhost:18080/api/v1/health
curl http://localhost:18080/api/v1/ready
```

From MCP:

- `system.health`
- `system.setup.guide`
- `system.config.validate`
- `plugin.list`
- `tool.readiness`
- `dynamic.runtime.status`

## Error Code Index

| Code | Topic | Common cause |
| --- | --- | --- |
| `E1001` | Windows Sandbox unavailable | Windows edition, feature disabled, or non-interactive session |
| `E1002` | Host Agent unreachable | Firewall, wrong endpoint, wrong bind address, Host Agent not running |
| `E1003` | Portproxy conflict | Stale Windows portproxy or multiple runtime sessions |
| `E1004` | Runtime isolation failed | Runtime Node started outside sandbox/VM without override |
| `E2001` | Python worker missing | Dependencies not installed or worker path missing |
| `E2002` | Sample upload failed | HTTP API disabled, wrong token, size limit, auth failure |
| `E3001` | Analyzer cannot reach runtime | Runtime mode or endpoint mismatch |
| `E3002` | Sandbox crashed / runtime 502 | Sandbox process exited, low memory, Host Agent lost session |
| `E4001` | MCP tool timeout | Client timeout shorter than queued/long-running analysis |
| `E5001` | Plugin tool missing | Progressive surface, `PLUGINS` filter, or dependency failure |

## E1001: Windows Sandbox Not Available

Symptoms:

- Host Agent reports Windows Sandbox unavailable.
- `runtime.debug.session.start` fails before Runtime Node starts.

Fix:

1. Use Windows 10/11 Pro, Enterprise, or another edition with Windows Sandbox support.
2. Enable the Windows Sandbox feature.
3. Reboot after enabling.
4. Run Host Agent in the logged-on user session.
5. Rikune v1.4.0 does not support a native Windows Analyzer. Use the Linux `hybrid` Analyzer with `RUNTIME_MODE=remote-sandbox`; do not use `auto-sandbox`.

## E1002: Host Agent Port Unreachable

Symptoms:

- Analyzer readiness shows runtime degraded.
- `dynamic.runtime.status` cannot reach Host Agent.
- Hybrid Docker reports connection refused or timeout.

Fix:

1. Confirm Host Agent is running on Windows.
2. Check endpoint, usually `http://host.docker.internal:18082` from Docker Desktop.
3. Confirm `RUNTIME_HOST_AGENT_API_KEY` matches.
4. Check firewall rules for Host Agent and portproxy ports.
5. From the Analyzer container, test connectivity to the Host Agent endpoint.

## E1003: Portproxy Conflict

Symptoms:

- First runtime session works, later sessions fail.
- Sandbox starts but Runtime Node endpoint is unreachable.
- Windows reports a portproxy conflict.

Fix:

1. Stop active runtime sessions.
2. Stop and restart Host Agent.
3. Remove stale Windows portproxy entries if necessary.
4. Avoid concurrent live Sandbox sessions unless the Host Agent/runtime profile supports them.

## E1004: Runtime Isolation Check Failed

Symptoms:

- Runtime Node refuses to start.
- Logs mention unverified isolation.

Reason:

Runtime Node is designed to run inside Windows Sandbox or an isolated VM. It intentionally refuses unsafe startup unless explicitly overridden for development.

Fix:

1. Start Runtime Node through Host Agent.
2. Confirm Sandbox or VM isolation is available.
3. For development only, use the explicit unsafe override documented in runtime configuration.
4. Do not run unknown samples on the host workstation.

## E2001: Python Worker Not Found

Symptoms:

- Static analysis tools fail immediately.
- Worker process cannot start.
- Missing Python modules are reported.

Fix:

```bash
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

Then check:

- Python version, preferably 3.11+.
- Worker files under `workers/`.
- Analyzer can read the repository root or installed package root.
- Docker image was regenerated after plugin dependency changes.

## E2002: Sample Upload Failed

Symptoms:

- `sample.request_upload` returns a URL but POST fails.
- HTTP upload returns 401, 404, 413, or 500.

Fix:

1. Confirm `API_ENABLED=true`.
2. Use the exact upload token returned by `sample.request_upload`.
3. Include API key when configured.
4. Check max sample size. The ingest path guards large samples.
5. Use `sample.ingest` with a server-readable path when local to the Analyzer.
6. Check `uploads/` and API logs.

## E3001: Analyzer Cannot Reach Runtime

Symptoms:

- `dynamic.runtime.status` returns disconnected.
- `tool.readiness` reports missing runtime backend.
- Runtime-delegated tools fail before dispatch.

Fix:

1. Check `RUNTIME_MODE`.
2. For manual mode, set `RUNTIME_ENDPOINT` and `RUNTIME_API_KEY`.
3. For hybrid mode, set `RUNTIME_HOST_AGENT_ENDPOINT` and `RUNTIME_HOST_AGENT_API_KEY`.
4. Confirm Host Agent can start Runtime Node.
5. Call `/api/v1/ready` and inspect runtime readiness.
6. Confirm the Runtime Node advertises the required contract capability.

## E3002: Sandbox Crashed / Runtime 502

Symptoms:

- Host Agent returns 502.
- Runtime session disappears.
- Sandbox window closes unexpectedly.

Fix:

1. Check Windows Event Viewer.
2. Check Host Agent logs.
3. Ensure the host has enough free memory.
4. Restart Host Agent.
5. Start a fresh runtime session.
6. For Hyper-V, restore the clean checkpoint if configured.

The Analyzer has limited recovery behavior, but repeated crashes usually require fixing host resources, sandbox configuration, or the sample execution plan.

## E4001: MCP Tool Timeout

Symptoms:

- MCP client times out while backend work continues.
- Long Ghidra or reconstruction work appears stalled.

Fix:

1. Prefer staged tools: `workflow.analyze.start`, `workflow.analyze.promote`, `workflow.analyze.status`.
2. Poll `task.status` for queued jobs.
3. Increase client-side MCP timeout for heavy operations.
4. Use `artifact.list` and `analysis.context.get` after jobs complete.
5. Cancel with `task.cancel` if needed.

## E4002: High Memory or Stale Worker Processes

Symptoms:

- Container RSS stays high after an analysis stage completes.
- `task.status` shows no queued jobs, but analyzer subprocesses still appear in process listings.
- `workflow.analyze.status` reports a recoverable or interrupted stage after a restart.

Fix:

1. Check `task.status`; recent builds include `external_active_rss_mb`, `external_active_process_count`, and a bounded `external_active_processes` list for analyzer subprocess visibility.
2. Wait for persistent worker idle TTL to expire. Idle static workers are evicted automatically after the configured runtime worker TTL.
3. If a stage was interrupted by restart or memory pressure, inspect `workflow.analyze.status` and re-promote only the recoverable stages you still need.
4. For large packed samples, promote stages incrementally instead of launching several heavy analyzers in parallel.
5. If memory remains high after all active subprocesses are gone, restart the analyzer container and preserve the mounted data/workspace volumes.

Notes:

- `static_worker.py` is a persistent worker and can stay resident briefly after successful static tools such as `entropy.analyze` or `strings.extract`; this is expected until the idle TTL fires.
- `workflow.analyze.status` may prune large historical stage results and place a warning in top-level `warnings`. Use `artifact.read` or a stage-specific tool for full payloads.

## E5001: Plugin Tool Missing

Symptoms:

- A known plugin tool is absent from `tools/list`.
- A client cannot find a specialist tool.

Fix:

1. Run `plugin.list`.
2. Check `PLUGINS`.
3. Check plugin dependency and system dependency errors.
4. Use `tools.discover` for tier 1-3 tools.
5. Run `tool.readiness` for the desired tool.
6. Rebuild if plugin code changed.

## Ghidra Problems

Common causes:

- Java version too old.
- `GHIDRA_INSTALL_DIR` points to the wrong directory.
- Ghidra project lock from an interrupted run.
- Headless analyzer not on PATH and not discoverable.
- Script resources not copied into the built package.

Fix:

```bash
npm run build
npm run build:runtime
```

Then run:

- `system.health`
- `system.setup.guide`
- Ghidra-related `tool.readiness`

Modern Ghidra releases generally require Java 21+.

## Docker Build Problems

If generated Docker files drift:

```bash
npm run build
npm run docker:generate:all
```

Then rebuild the selected profile.

If proxy settings fail inside Docker, use installer proxy parameters instead of raw `127.0.0.1` proxy URLs. The scripts translate host-local proxy addresses to container-reachable addresses where possible.

## Diagnostics Checklist

Collect:

- `git status --short`
- `node --version`
- `npm --version`
- `docker version`
- `docker compose version`
- selected compose file and `.docker-runtime.env` without secrets
- `/api/v1/health`
- `/api/v1/ready`
- `system.health`
- `plugin.list`
- `dynamic.runtime.status` for hybrid/runtime issues
- Host Agent logs for runtime issues
- Ghidra command/runtime logs for decompiler issues
