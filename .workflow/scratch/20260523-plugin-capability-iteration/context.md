# Plugin Capability Iteration Maestro Task

## Summary

Created a plan-only Maestro task set for the next plugin capability iteration after Plugin Standard v2.

- Session: `.workflow/.maestro/maestro-20260523-005419-plugin-capability-iteration/status.json`
- Plan: `.workflow/scratch/20260523-plugin-capability-iteration/plan.json`
- Tasks: `.workflow/scratch/20260523-plugin-capability-iteration/.task/TASK-*.json`
- CSV index: `.workflow/scratch/20260523-plugin-capability-iteration/tasks.csv`

## Direction

The next iteration should focus on vertical workflows:

1. Memory forensics to behavior / IOC / reporting.
2. VM-analysis and symbolic workflows.
3. KB collaboration as long-term analysis memory.
4. Runtime readiness and opt-in session templates.
5. Supply-chain SBOM provenance graph.
6. Platform ecosystems: Android, Apple/iOS/macOS, WASM, firmware/IoT.
7. Malware workflow closure: Office, unpacking, similarity, malware intel, YARA/Sigma feedback.

## Definition of Done

- Every selected vertical has a discoverable workflow recipe.
- `tool.readiness` explains backend/dependency/runtime status without live execution.
- Artifacts and evidence use Plugin Standard v2 declarations.
- Focused unit tests cover each vertical chain.
- Global matrix, help, readiness, typecheck, lint, and docs pass at release guard.
