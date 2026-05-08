# Python Workers

The `workers/` directory contains Python-side analysis helpers used by the Analyzer and selected plugins. The main worker is `static_worker.py`, which communicates over stdin/stdout using newline-delimited JSON.

## Role

Workers handle analysis tasks that are more natural in Python or depend on Python libraries, for example:

- PE fingerprinting;
- imports and exports extraction;
- PE structure analysis;
- strings extraction;
- FLOSS decoding when available;
- YARA scanning;
- runtime/packer detection;
- entropy and obfuscation checks;
- .NET metadata extraction;
- selected dynamic dependency probes;
- compatibility shims for emulation-oriented tooling.

The TypeScript Analyzer owns orchestration, persistence, caching, policy checks, and MCP result shaping. Python workers return structured worker responses and artifact references.

## Files

| Path | Purpose |
| --- | --- |
| `static_worker.py` | Main stdin/stdout JSON worker |
| `frida_worker.py` | Frida helper worker |
| `rizin_preview_worker.py` | Rizin preview helper |
| `speakeasy_compat.py` | Speakeasy compatibility helpers |
| `requirements.txt` | Baseline worker dependencies |
| `requirements-dynamic.txt` | Dynamic-analysis Python dependencies |
| `requirements-qiling.txt` | Qiling-related dependencies |
| `yara_rules/` | Bundled YARA rules |
| `test_*.py` | Worker unit and integration tests |

## Protocol

Request shape:

```json
{
  "job_id": "job-123",
  "tool": "strings.extract",
  "sample": {
    "sample_id": "sample-123",
    "path": "/workspace/sample.exe"
  },
  "args": {},
  "context": {
    "request_time_utc": "2026-05-08T00:00:00Z",
    "policy": {
      "allow_dynamic": false,
      "allow_network": false
    },
    "versions": {}
  }
}
```

Response shape:

```json
{
  "job_id": "job-123",
  "ok": true,
  "warnings": [],
  "errors": [],
  "data": {},
  "artifacts": [],
  "metrics": {}
}
```

Workers must write protocol responses to stdout. Logs and diagnostics should go to stderr to avoid corrupting the protocol stream.

Some handlers internally return a worker-response envelope with `ok`, `data`, `warnings`, `errors`, and `metrics`. `static_worker.py` normalizes those envelopes instead of wrapping them again, so TypeScript tools receive the actual payload as `data` rather than a nested `data.data` object.

## Lifecycle

The TypeScript runtime worker pool keeps compatible Python workers warm between requests. A warm worker can reduce startup cost for repeated static tools, but it must not stay resident forever after work completes.

Current behavior:

- compatible idle workers can be reused while healthy;
- busy workers are not reused by another request;
- timed-out or unhealthy workers are terminated as a process tree;
- idle workers are evicted automatically after the configured runtime worker TTL;
- scheduler and `task.status` telemetry expose active external analyzer subprocess pressure separately from queue length.

If `task.status` reports `queue_length: 0` but `external_active_process_count` is non-zero, an analyzer subprocess such as FLOSS, capa, Ghidra, or Rizin is still running outside the in-memory queue view. If both queue and external process counts are zero, remaining idle static workers should disappear when the idle TTL fires.

## Supported Static Worker Tools

Current `static_worker.py` handler keys include:

- `pe.fingerprint`
- `pe.imports.extract`
- `pe.exports.extract`
- `pe.structure.analyze`
- `static.capability.triage`
- `strings.extract`
- `strings.floss.decode`
- `yara.scan`
- `runtime.detect`
- `packer.detect`
- `entrypoint.disasm`
- `system.health`
- `dynamic.dependencies`
- `sandbox.execute`
- `dotnet.metadata.extract`
- `entropy.analyze`
- `obfuscation.detect`
- `taint.track`
- `unpack.emulate`
- `sample.cluster`
- `dotnet.il.decompile`
- `java.decompile`
- `bytecode.taint`

Some handlers are compatibility surfaces or safe simulations. Live runtime evidence should come through Runtime Node and runtime contracts.

## Installation

Use Python 3.11+ where possible.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m pip install -r workers\requirements.txt
python -m pip install -r workers\requirements-dynamic.txt
```

Optional dependency availability is reported by worker health checks and plugin readiness.

## Testing

Run worker tests:

```bash
python -m pytest workers
```

Run a specific test:

```bash
python -m pytest workers/test_static_worker.py
```

Repository-level checks:

```bash
npm test
npm run test:integration
```

## Development Guidelines

When adding a worker handler:

1. Keep the request/response protocol stable.
2. Avoid shell execution unless absolutely necessary.
3. Validate file paths and never trust original sample names.
4. Return structured errors for missing optional dependencies.
5. Include metrics when useful.
6. Add tests under `workers/test_*.py`.
7. Register the TypeScript-side tool through the appropriate plugin or core registry.
8. Update docs if the tool becomes user-facing.

## Related Docs

- [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
- [../docs/PLUGINS.md](../docs/PLUGINS.md)
- [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md)
