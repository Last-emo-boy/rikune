# Tool Discovery Backend Iteration Detailed Plan

## Goal

Keep the MCP startup surface small, but make the discovery portal powerful enough for an AI agent to find, rank, activate, and safely run the right tools based on sample type, analysis goal, backend readiness, and safety policy.

## Waves

### Wave 1 — Portal And Metadata Foundation

- `TASK-065`: Add ranked `tools.discover` recommendations.
- `TASK-066`: Complete plugin `aspects` for sample-type routing.
- `TASK-067`: Expose backend install/profile recommendation metadata.

### Wave 2 — Real Worker Backends And JS Suite

- `TASK-068`: Promote selected plan-only tools to bounded `backend-worker.v1` workers.
- `TASK-069`: Compose JavaScript/JSVMP static analysis pipeline.

### Wave 3 — Cross Backend Reverse Suite

- `TASK-070`: Add cross-decompiler/IR consensus workflow.
- `TASK-071`: Add BYO external RE MCP bridge contracts.

### Wave 4 — Quality And Safety Guards

- `TASK-072`: Create reverse-engineering benchmark guard suite.
- `TASK-073`: Harden MCP activation and backend safety.

### Wave 5 — Release Guard

- `TASK-074`: Refresh docs/catalog/results and run full verification.

## Execution Rules

- Do not widen the initial MCP tool list.
- Do not start backends from discovery, help, readiness, plugin list, catalog generation, or Docker dry-run.
- Use `backend-worker.v1` for external execution with timeout, output-size guard, and policy gates.
- Keep commercial, GPL/AGPL, DBI, GPU, runtime, and heavy toolchains BYO or profile-gated.
- Default CI uses fixtures and metadata-only tests.
