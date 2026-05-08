# Dynamic Runtime Roadmap

This document tracks the dynamic-runtime direction after the Analyzer/Runtime split. It is a product and engineering roadmap, not a guarantee that every item is fully implemented in every profile.

## Current Baseline

Implemented baseline:

- Analyzer-side runtime client.
- Runtime Node HTTP API with health, capabilities, upload, execute, task status, download, cancel, logs, and SSE routes.
- Windows Host Agent with Windows Sandbox and Hyper-V control paths.
- Runtime contracts in `packages/shared`.
- Dynamic plugin surfaces for planning, sandbox execution, runtime debug sessions, toolkit status, Hyper-V control, behavior capture, behavior diff, Frida support, Wine, Qiling, PANDA, Speakeasy, managed sandbox, and runtime deobfuscation.
- Staged workflow integration through `dynamic_plan` and `dynamic_execute`.
- Policy gates for live execution and network-sensitive behavior.
- Readiness checks through `dynamic.runtime.status`, `dynamic.toolkit.status`, `tool.readiness`, `/api/v1/ready`, and `plugin.list`.

## Design Principles

1. Live execution must be explicit.
2. Runtime evidence must identify its execution semantics.
3. Safe simulation and emulation are useful, but they are not live Windows evidence.
4. Analyzer and Runtime Node must exchange structured contracts, not ad hoc commands.
5. Runtime artifacts should be importable into static evidence graphs.
6. Host Agent control must remain authenticated and operationally visible.
7. Hyper-V dirty-state handling must be intentional.

## Execution Semantics

Runtime-facing tools should describe one of:

| Mode | Meaning |
| --- | --- |
| `plan_only` | No sample execution, only a plan |
| `safe_simulation` | Safe synthetic or static approximation |
| `emulation` | Emulator-backed behavior |
| `live_sandbox` | Real execution inside Windows Sandbox |
| `live_hyperv` | Real execution inside a Hyper-V VM |
| `manual_runtime` | Human-operated runtime or attached external runtime |

Clients should not merge safe simulation with live runtime evidence without preserving provenance.

## Roadmap Phases

### Phase 1: Runtime Control Plane Hardening

Goal: make Runtime Node and Host Agent easier to diagnose and safer to operate.

Tasks:

- richer Host Agent health payloads;
- endpoint/API-key mismatch diagnostics;
- stale portproxy cleanup guidance;
- runtime task cancellation visibility;
- runtime log download through Analyzer artifacts;
- dashboard runtime status page.

### Phase 2: Evidence Import

Goal: make runtime artifacts first-class evidence.

Tasks:

- normalize runtime behavior traces;
- import memory dumps, module lists, process trees, registry/file/network events;
- connect runtime observations to static function, string, import, and config evidence;
- expose provenance in `analysis.context.get` and report tools.

### Phase 3: Debug Session Maturity

Goal: support longer, auditable debug sessions.

Tasks:

- persistent debug session records;
- explicit attach/spawn semantics;
- command audit trail;
- debugger inventory and readiness checks;
- manual GUI handoff metadata;
- controlled artifact extraction.

### Phase 4: Hyper-V First-Class Backend

Goal: make Hyper-V behavior equivalent to Sandbox where practical.

Tasks:

- checkpoint validation;
- configurable release policy;
- VM capability inventory;
- dirty-state warnings;
- restore failure diagnostics;
- per-session resource accounting.

### Phase 5: Workflow Productization

Goal: make staged workflows choose dynamic depth safely.

Tasks:

- richer `dynamic_plan` recommendations from static findings;
- explicit policy prompts before `dynamic_execute`;
- cost and time estimates;
- sample-family reuse of runtime hypotheses;
- failure-tolerant fallback from live runtime to emulation or plan-only results.

### Phase 6: Deep Dynamic Plugins

Goal: expand specialist runtime tools without bloating the default surface.

Candidates:

- debugger breakpoint planning;
- ProcDump and memory capture playbooks;
- ETW or equivalent telemetry plans;
- network experiment plans;
- managed runtime inspection;
- runtime string and config extraction;
- anti-debug and anti-VM behavior correlation.

### Phase 7: Cross-Evidence Graphs

Goal: unify static, emulated, and live observations.

Tasks:

- behavior-first summary graph;
- crypto/key lifecycle graph;
- persistence and injection classifiers;
- unpacking before/after diffs;
- function-to-runtime-event correlation;
- report-level confidence and provenance.

## Recommended Build Order

1. Stabilize runtime health and Host Agent diagnostics.
2. Improve runtime artifact import.
3. Strengthen debug session persistence.
4. Expand Hyper-V parity.
5. Add workflow-level policy/cost guidance.
6. Add specialist dynamic plugins behind tier 2 and tier 3 discovery.
7. Build evidence graphs that make runtime provenance visible in summaries and reviews.
