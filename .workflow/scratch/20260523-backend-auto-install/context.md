# Backend Auto Install

Date: 2026-05-23

This Maestro task set follows the completed `frontier-worker-integration` plan. The next goal is to move Worker-backed plugins from "discoverable and fixture-safe" to "real backend installable in Docker/Compose, readiness-visible, and executable only through the Worker policy gates."

Current state:

- Docker generation is plugin-driven through `systemDeps`, `aptPackages`, env vars, Docker fragments, validation commands, plugin worker copies, and generated Compose env/volumes.
- `dockerInstall` is descriptive today. A backend is truly installed only when it has an `aptPackages` route, a `workers/requirements*.txt` route, an in-repo worker copy route, or a `src/plugins/<id>/docker/<feature>.dockerfile` fragment.
- Worker tools now expose `workerBackend` metadata, but `runBackendWorker()` still defaults to builtin fixture-safe execution and does not yet run external wrappers as a real JSON worker protocol.
- Several plugins declare `dockerFeature` without a real install fragment: `restringer`, `jsimplifier`, `jsir-cascade`, `jsvmp-analysis`, `remill`, `manifold`, `qbdi`, `culifter`, `revng`, `wabt`, `radare2`.

Backend installation policy:

- Default full image may install static, read-only, non-runtime backends with version/help validation only.
- Heavy, GPL/AGPL, DBI, GPU, emulator, or sidecar backends must be profile-gated and opt-in.
- Build-time validation may call `--version`, `--help`, import checks, or wrapper self-tests. It must not execute user samples, attach debuggers, run instrumentation, instantiate WASM, evaluate JavaScript, load GPU drivers, or call network services.
- Readiness/help/discovery/plugin list paths must never start backend processes.
- Runtime execution must still go through `backend-worker.v1`, timeout/output limits, no-mutation guarantees, and explicit opt-in where required.

Research/source anchors observed on 2026-05-23:

- HumanSecurity/restringer: https://github.com/HumanSecurity/restringer, pushed 2025-12-07, MIT.
- google/jsir: https://github.com/google/jsir, pushed 2026-05-20, Apache-2.0.
- GrammaTech/gtirb: https://github.com/GrammaTech/gtirb, pushed 2026-04-28, license not asserted by GitHub API.
- GrammaTech/ddisasm: https://github.com/GrammaTech/ddisasm, pushed 2026-04-17, AGPL-3.0.
- lifting-bits/remill: https://github.com/lifting-bits/remill, pushed 2026-05-22, Apache-2.0.
- QBDI/QBDI: https://github.com/QBDI/QBDI, pushed 2026-04-03, license not asserted by GitHub API.
- WebAssembly/wabt: https://github.com/WebAssembly/wabt, pushed 2026-05-07, Apache-2.0.
- revng/revng: https://github.com/revng/revng, pushed 2026-05-22, GPL-2.0.
- radareorg/radare2: https://github.com/radareorg/radare2, pushed 2026-05-23, license not asserted by GitHub API.
- cea-sec/miasm: https://github.com/cea-sec/miasm, pushed 2026-03-26, GPL-2.0.
- lief-project/LIEF: https://github.com/lief-project/LIEF, pushed 2026-05-19, Apache-2.0.
- JonathanSalwan/Triton: https://github.com/JonathanSalwan/Triton, pushed 2026-05-20, Apache-2.0.

Execution intent:

1. First freeze the packaging contract and generator validation.
2. Then add real external Worker execution support.
3. Then install safe/light backends by default or near-default.
4. Then add heavy/native/runtime/GPU backends behind explicit profiles.
5. Finally prove the whole stack with Docker generation tests, readiness tests, docs, and smoke builds.

Conflict policy:

- Do not modify or stage the older untracked `20260521` workflow directories.
- Read owned files before editing.
- Use `apply_patch` for routine edits.
- Use `git add <specific-files>` only if a commit is requested.

Execution result:

- TASK-051 through TASK-064 are completed as of 2026-05-23T13:40:00+08:00.
- `backend-worker.v1` now supports gated external JSON workers with timeout, output-size guard, malformed output handling, stderr capture, and path/command parsing.
- Docker backend packaging metadata is enforceable through SDK types, runtime schema, generator classification, and backend install contract tests.
- Docker metadata loading now falls back from broken partial `dist` plugin imports to `src/plugins/<id>/index.ts`, so build-then-generate keeps complete systemDeps coverage.
- Default install routes cover safe/static backends such as REstringer, JSIMPLIFIER, Manifold, WABT, and LIEF validation.
- Optional/profile-gated routes cover JSIR/CASCADE, JSVMP, GTIRB, radare2, and Triton.
- License, heavy, runtime, sidecar, and GPU sensitive routes remain explicit opt-in or BYO: Miasm, ddisasm/GTIRB full toolchain, Remill, rev.ng, QBDI, and CuLifter.
- Generated Docker/Compose artifacts were refreshed with `npm run docker:generate:all` after `npm run build`, so generator output reflects current `dist` metadata.

Verification:

- Passed: `npm run lint`
- Passed: `npm test -- --runTestsByPath tests/unit/backend-worker-contract.test.ts tests/unit/backend-install-contract.test.ts tests/unit/docker-generator-backends.test.ts tests/unit/frontier-worker-plugins.test.ts tests/unit/tool-readiness.test.ts tests/unit/plugin-format-matrix.test.ts`
- Passed: `npm test -- --runTestsByPath tests/unit/core/plugin-system/builtin-contract.test.ts tests/unit/javascript-obfuscation-profile.test.ts`
- Passed: `npm run typecheck`
- Passed: `npm run build`
- Passed: `npm run docker:generate:all -- --dry-run`
- Passed: `npm run docker:generate:all`
- Passed: generator dry-run after build scans 92 plugins and 55 systemDep-bearing plugins without `Metadata load warnings`.
- Skipped: `docker compose -f docker-compose.analyzer.yml build --no-cache analyzer`; local environment has no `docker` executable.
