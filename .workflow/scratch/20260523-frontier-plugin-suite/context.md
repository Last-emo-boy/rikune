# Frontier Plugin Suite

## Outcome

This Maestro iteration extends the plugin suite from 84 to 92 built-in plugins and keeps the new surfaces plan-only by default. The new plugins broaden the roadmap across JavaScript deobfuscation, JSVMP preprocessing, LLVM lifting, binary IR, DBI handoff, declarative decompilation, and GPU binary lifting.

## Implemented Plugins

- `jsimplifier`: staged JavaScript deobfuscation pipeline planning.
- `jsir-cascade`: JavaScript IR normalization and JSVMP preprocessing planning.
- `restringer`: string-array and expression deobfuscation planning.
- `remill`: LLVM bitcode lifting and instruction semantics planning.
- `gtirb`: binary IR, CFG/symbol, and rewrite-boundary planning.
- `qbdi`: DBI trace and instrumentation opt-in planning.
- `manifold`: declarative fact extraction and superset decompilation planning.
- `culifter`: GPU/SASS lifting planning without GPU or driver access.

## Safety Boundary

All new handlers reuse `createBackendPlanHandler()`. They generate metadata, workflow recipes, future worker contracts, handoff requirements, and safety notes only. They do not start external backends, execute samples, evaluate JavaScript, run Node/V8, inject instrumentation, attach debuggers, run solvers, mutate binaries, invoke Datalog engines, load GPU drivers, mount filesystems, or use network access.

## Verification

- `npm test -- --runTestsByPath tests/unit/backend-plan-plugins.test.ts tests/unit/javascript-obfuscation-profile.test.ts tests/unit/plugin-format-matrix.test.ts`
- `npm run typecheck`

Additional final checks are tracked in the root task plan for this turn.
