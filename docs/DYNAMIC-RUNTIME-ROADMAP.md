# Dynamic Runtime Roadmap

This roadmap tracks the next iterations for Rikune dynamic execution, runtime
debugging, Windows Sandbox, Hyper-V VM, and runtime evidence workflows. The goal
is to make runtime work explicit, diagnosable, resumable, and reusable by
staged analysis workflows.

## Design Principles

- Runtime execution is explicit. Connecting an MCP client must not execute a
  sample or open Windows Sandbox by itself.
- The analyzer owns orchestration and persistence. The Windows runtime owns
  sample execution, debugging, tracing, dumps, and isolated artifacts.
- Every dynamic action should have a readiness check, a capability check, a
  bounded execution budget, and a structured artifact result.
- Windows Sandbox is the quick isolation backend. Hyper-V VM is the repeatable
  debugging backend with checkpoint rollback.
- Dynamic evidence must feed back into `workflow.analyze.*`,
  `workflow.reconstruct`, `workflow.summarize`, and reports.

## Iteration Phases

### Phase 1: Runtime Control Plane Hardening

Focus: make the current runtime session layer stable and recoverable.

| ID | Item | Scope | Acceptance Criteria |
|----|------|-------|---------------------|
| DR-01 | Persist runtime sessions | Store `runtime.debug.session.*` state in SQLite instead of process memory only. | Implemented for sample-bound `runtime.debug.session.*`: sessions persist endpoint, backend, sandbox id, timestamps, health, capabilities, task refs, and artifact refs in `debug_sessions`. |
| DR-02 | Capability-driven dispatch | Query Runtime Node `/capabilities` before execution. | Implemented in `runtime.debug.command`: unsupported backend hints fail before upload/execute with setup guidance and advertised runtime backends. |
| DR-03 | Runtime artifact auto-import | Download Runtime Node artifacts after `runtime.debug.command`. | Implemented for Runtime Node `artifactRefs`: downloaded files are copied into `reports/runtime_debug/<session>/` and registered as `runtime_debug_artifact`. |
| DR-04 | Sandbox and Host Agent diagnostics | Return high-signal startup diagnostics for Windows Sandbox failures. | Implemented for Host Agent start failures: responses include `.wsb` path, mapped folders, LogonCommand summary, WindowsSandbox.exe state, runtime ready file, startup/stdout/stderr log previews, and missing runtime paths. |

### Phase 2: Real Debugging Runtime

Focus: move from one-shot CDB commands to reusable debugging sessions.

| ID | Item | Scope | Acceptance Criteria |
|----|------|-------|---------------------|
| DR-05 | Long-lived Windows debug sessions | Keep CDB/DbgEng state alive across `start`, `breakpoint`, `continue`, `step`, `inspect`, `snapshot`, and `end`. | Breakpoints and process state persist across commands inside one runtime session. |
| DR-06 | Debug session transcript | Persist debugger commands, hits, registers, stack snapshots, module list, and errors. | Partially implemented: Runtime Node `executeDebugSession` writes `debug_session_trace.json` artifact refs for every command, including missing-debugger failures and CDB stdout/stderr previews. |
| DR-07 | Debug safety budgets | Add timeout, max breakpoint hits, max stdout/stderr, and max memory capture limits. | Partially implemented: Runtime Node debug commands now record timeout/stdout/stderr budgets in transcripts and cap returned CDB output. Breakpoint hit and memory capture budgets remain pending. |

### Phase 3: Hyper-V VM as a First-Class Backend

Focus: make Hyper-V the preferred repeatable runtime backend for deep debugging.

| ID | Item | Scope | Acceptance Criteria |
|----|------|-------|---------------------|
| DR-08 | Hyper-V VM lifecycle tools | Add status/list/checkpoint/restore helpers through Host Agent. | Implemented for status, list, create checkpoint, restore checkpoint, and stop: Host Agent exposes `/hyperv/status`, GET/POST `/hyperv/checkpoints`, `/hyperv/restore`, and `/hyperv/stop`, and MCP clients can use `runtime.hyperv.control`. |
| DR-09 | Runtime VM bootstrap guide | Document and script Runtime Node setup inside the VM. | A clean Windows VM can be prepared with Node, runtime package, firewall rule, startup command, and health endpoint. |
| DR-10 | Dirty checkpoint retention | Optionally preserve post-execution VM state for manual review. | Implemented: `runtime.debug.session.start` accepts `hyperv_retention_policy` with `clean_rollback`, `stop_only`, and `preserve_dirty`, plus low-level Hyper-V lifecycle overrides. Host Agent can restore the configured checkpoint, stop the VM, or leave the dirty VM state available on release. |

### Phase 4: Runtime Evidence Capture

Focus: broaden the runtime evidence surface beyond debugger output.

| ID | Item | Scope | Acceptance Criteria |
|----|------|-------|---------------------|
| DR-11 | Frida Runtime Node execution | Run generated Frida scripts inside Sandbox/VM rather than only generating plans. | Runtime can spawn/attach, capture API calls, decrypted strings, dynamic API resolution, allocation/write/execute events, and JSONL traces. |
| DR-12 | ETW/ProcMon/Sysmon-style behavior capture | Add coarse process/file/registry/network/module-load capture. | Partially implemented: `dynamic.behavior.capture` runs inside Windows Runtime Node, captures process/module/file/TCP/module/stdout/stderr observations, writes `behavior_capture.json`, and exposes an embedded normalized trace. Registry, DNS, ETW, and ProcMon-grade capture remain pending. |
| DR-13 | Memory dump workflow | Promote `dynamic.memory_dump` into a full dump/analyze/re-ingest path. | Runtime enumerates process/modules/regions, captures selected dumps, scans for PE/shellcode/URLs/config/keys, and can ingest derived unpacked samples. |

### Phase 5: Workflow and Product Integration

Focus: make dynamic work easy for AI clients and visible to users.

| ID | Item | Scope | Acceptance Criteria |
|----|------|-------|---------------------|
| DR-14 | Staged workflow integration | Wire runtime sessions, task refs, and dynamic artifacts into `dynamic_plan` and `dynamic_execute`. | Partially implemented: `workflow.analyze.start/status/promote` now include `runtime_sessions` and `runtime_readiness` with session refs, endpoints, artifact counts, capabilities, and next-step guidance. `dynamic_plan` now runs static behavior classification, embeds an evidence-aware `dynamic.deep_plan`, recommends `dynamic.runtime.status`, and keeps live behavior capture gated behind explicit runtime calls. |
| DR-15 | Dashboard runtime page | Add a Runtime tab to the dashboard. | Users can see Host Agent health, selected backend, active sessions, capabilities, VM/Sandbox status, recent tasks, startup logs, and stop/release controls. |
| DR-16 | AI-facing runtime guidance | Improve `tool.help`, `dynamic.runtime.status`, and failure guidance. | Partially implemented: `dynamic.runtime.status` is available and aggregates Runtime Node health, capabilities, Host Agent health, Hyper-V/Sandbox diagnostics, persisted sessions, backend-interface flags, and next actions. |
| DR-17 | Unified runtime backend interface | Normalize Sandbox, Hyper-V VM, manual runtime, Wine-local, and future remote backends. | Partially implemented: `dynamic.runtime.status` reports normalized `start`, `health`, `capabilities`, `upload`, `execute`, `download`, `stop`, and backend-support booleans across configured Runtime Node and Host Agent surfaces. |

### Phase 6: Deep Dynamic Plugin Expansion

Focus: turn advanced runtime debugging ideas into capability-driven plugins.

| ID | Item | Scope | Acceptance Criteria |
|----|------|-------|---------------------|
| DR-18 | Runtime tool inventory | Detect CDB/WinDbg, ProcDump, ProcMon, Sysmon, TTD helpers, x64dbg, dnSpyEx, Frida, dotnet, and FakeNet-style helpers inside Runtime Node/tool-cache paths. | Implemented: Runtime Node exposes read-only `/toolkit` plus `executeRuntimeToolProbe`; MCP clients use `dynamic.toolkit.status`. The probe searches `RUNTIME_TOOL_DIRS`, `RUNTIME_TOOL_CACHE_DIR`, `RIKUNE_RUNTIME_TOOLS`, `RIKUNE_TOOL_CACHE_DIR`, default `C:\rikune-tools`, PATH, and common Windows SDK locations. |
| DR-19 | Deep dynamic plan surface | Convert behavior/debugger/memory/telemetry/network/.NET/anti-evasion/TTD/manual-GUI directions into explicit MCP tool sequences. | Implemented: `dynamic.deep_plan` returns planning-only profiles, recommended tools, artifact expectations, and safety flags without launching or executing anything. |
| DR-20 | CDB automation pack | Add higher-level CDB actions for API breakpoints, exception tracing, dump-on-break, module breakpoints, and script templates. | Implemented: `debug.cdb.plan` creates planning-only CDB command batches and `runtime.debug.command` templates, and Runtime Node accepts bounded `debug.session.command_batch` / `debug.session.cdb_script` batches through the existing transcript and artifact path. |
| DR-21 | ProcDump integration | Capture crash, timeout, and trigger-based dumps with ProcDump, then import and scan them as runtime artifacts. | Implemented: `debug.procdump.plan` creates planning-only crash, first-chance, timeout, and PID-snapshot templates, and Runtime Node exposes `debug.procdump.capture` through `executeProcDumpCapture` with metadata, dump artifact discovery, setup guidance, and timeout/stdout/stderr budgets. |
| DR-22 | ProcMon/Sysmon/ETW telemetry plugins | Capture file, registry, process, network, image-load, and DNS telemetry beyond coarse snapshots. | Implemented: `debug.telemetry.plan` creates planning-only ProcMon, Sysmon, ETW process/DNS, and PowerShell event-log profiles with backend fit, cleanup/rollback requirements, static behavior hints, and correlation guidance. Runtime Node exposes `debug.telemetry.capture` through `executeTelemetryCapture`, with ProcMon/Sysmon setup detection, ETW process/DNS capture, PowerShell event-log snapshot fallback, artifact discovery, cleanup, setup guidance, and timeout/stdout/stderr budgets. |
| DR-23 | Fake network lab | Add FakeNet/INetSim-style service emulation, DNS/HTTP sinkholing, and future PCAP import. | Implemented as an explicit planning surface: `debug.network.plan` builds proxy sinkhole, DNS/HTTP sinkhole, FakeNet-style, and ETW DNS profiles, reads `static.config.carver` network indicators, emits safe runtime command templates for behavior capture and telemetry capture, and keeps DNS/hosts/service mutation gated behind explicit runtime setup. |
| DR-24 | Managed runtime debug profile | Add CLRMD/dotnet-dump/SOS-style managed object, stack, module, and resource inspection; keep dnSpyEx as a manual profile. | Implemented as a managed debug planner: `debug.managed.plan` builds managed safe-run, SOS/CDB, ProcDump, resource review, and dnSpyEx handoff profiles, can merge persisted `.NET` metadata context, and emits runtime command templates for `managed.safe_run`, `debug.session.command_batch`, and `debug.procdump.capture`. |
| DR-25 | Manual GUI debug handoff | Launch or prepare x64dbg/WinDbg/dnSpy sessions in visible Sandbox or preserved Hyper-V VMs. | Implemented as artifact-backed preparation: `debug.gui.handoff` creates x64dbg, WinDbg, and dnSpyEx handoff profiles, recommends Hyper-V `preserve_dirty` retention, records user-session constraints, and points manual outputs back into `dynamic.memory.import`, `unpack.child.handoff`, and evidence graph workflows. |

### Phase 7: Purpose-Built Static and Dynamic Plugins

Focus: add small, specialist plugins that are useful before, during, and after
runtime execution instead of relying only on broad decompilers or generic
sandbox output.

| ID | Item | Scope | Acceptance Criteria |
|----|------|-------|---------------------|
| DR-26 | Runtime persona planning | Build user-profile, RecentDocs, Office, locale, network, and interaction-timing plans for Sandbox/Hyper-V without mutating the runtime. | Implemented: `dynamic.persona.plan` returns a planning-only persona checklist and can persist `dynamic_persona_plan` artifacts. |
| DR-27 | Static resource graph | Extract PE resource leaves, payload magic, entropy, hashes, sizes, and string previews before live execution. | Implemented: `static.resource.graph` persists `static_resource_graph` artifacts and recommends config, entropy, strings, .NET, and dynamic follow-up tools. |
| DR-28 | Static config carver | Family-agnostic carving of URLs, domains, IP/port pairs, registry paths, mutex-like strings, HTTP clients, config keywords, and encoded blobs. | Implemented: `static.config.carver` persists `static_config_carver` artifacts and feeds dynamic planning. |
| DR-29 | Evidence graph | Correlate static strings/imports/resources, runtime traces, memory dumps, and report findings into one explainable graph. | Implemented: `analysis.evidence.graph` links specialist static artifacts, runtime observations, expectation nodes, observation nodes, and corroboration edges into `analysis_evidence_graph` artifacts. |
| DR-30 | Behavior contract and diff | Compare expected static behaviors against runtime observations to show what executed, what stayed dormant, and what requires a different persona/backend. | Implemented: `dynamic.behavior.diff` consumes `static.config.carver`, `static.resource.graph`, and dynamic trace artifacts to report confirmed behavior, missing expectations, unexpected observations, hypotheses, and next tools. |
| DR-31 | API hash and dynamic resolver deepening | Strengthen API hash detection, resolver-loop localization, and runtime breakpoint recommendations. | Implemented: `hash.resolver.plan` scans sample prefixes for resolver strings, PEB/module-walk hints, hex/hash-like constants, algorithm-family hints, and direct handoff to `hash.identify`, `hash.resolve`, `breakpoint.smart`, and `trace.condition`. |
| DR-32 | Crypto/key lifecycle graph | Track candidate keys, IVs, S-boxes, decrypt buffers, and call sites across static and runtime evidence. | Implemented: `crypto.lifecycle.graph` merges `crypto.identify` artifacts with imported dynamic traces to graph algorithms, functions, APIs, constants, runtime stages, memory-region hints, and corroborated crypto APIs. |
| DR-33 | Persistence and injection classifiers | Add dedicated classifiers for autostart, service install, scheduled task, WMI, process injection, and hollowing patterns. | Implemented: `static.behavior.classify` combines strings, `static.config.carver` artifacts, and optional dynamic trace imports to classify Run key, service, scheduled task, WMI, startup folder, IFEO, remote-thread injection, hollowing, APC, DLL injection, thread hijack, and anti-debug probes with runtime follow-up tools. |
| DR-34 | Unpack and child-sample handoff | Turn unpacked resource/memory payload candidates into staged child samples with provenance. | Implemented: `unpack.child.handoff` carves payload candidates from `static.resource.graph`, raw sample bytes, and `raw_dump` artifacts, persists payload artifacts, and registers bounded child samples with parent/source/offset provenance. |

## Proposed Milestones

| Milestone | Target Items | Outcome |
|-----------|--------------|---------|
| M1 Runtime Control | DR-01 to DR-04 | Runtime sessions become recoverable, capability-aware, and diagnosable. |
| M2 Debugger Core | DR-05 to DR-07 | Windows debugging becomes a real multi-command session. |
| M3 Hyper-V Runtime | DR-08 to DR-10 | Hyper-V VM becomes the repeatable debug backend. |
| M4 Evidence Capture | DR-11 to DR-13 | Runtime traces, behavior, and memory dumps become normalized evidence. |
| M5 Product Integration | DR-14 to DR-17 | Dynamic execution is visible in workflow status, dashboard, and AI guidance. |
| M6 Deep Dynamic Plugins | DR-18 to DR-25 | Advanced runtime tools become discoverable, profile-driven, and explicitly gated. |
| M7 Specialist Plugin Pack | DR-26 to DR-34 | Static and dynamic specialist tools produce small, composable evidence artifacts for deeper workflows. |

## Recommended Build Order

1. DR-01 session persistence.
2. DR-02 capability-driven dispatch.
3. DR-03 runtime artifact auto-import.
4. DR-04 Sandbox/Host Agent diagnostics.
5. DR-14 workflow integration for the stable control-plane fields.
6. DR-05 long-lived debug sessions.
7. DR-08 Hyper-V lifecycle tools.
8. DR-11 Frida Runtime Node execution.
9. DR-13 memory dump workflow.
10. DR-15 dashboard runtime page.
11. DR-18 runtime tool inventory.
12. DR-19 deep dynamic planning.
13. DR-20 CDB automation pack.
14. DR-21 to DR-24 deep capture plugins.
15. DR-25 manual GUI handoff.
16. DR-26 to DR-28 first specialist plugin pack.
17. DR-29 to DR-34 graph, diff, resolver, crypto, classifier, and unpack handoff tools.

This order keeps early work low-risk while producing immediate improvements for
the current Docker + Windows Host Agent + Sandbox/Hyper-V chain.
