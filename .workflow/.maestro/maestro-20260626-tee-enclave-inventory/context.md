# Maestro Context: TEE Enclave Inventory

- Branch: `feat/tee-enclave-inventory`
- Base: `beta`
- Started: `2026-06-26T19:17:57+08:00`
- Objective: add a passive confidential computing / TEE enclave static inventory capability without expanding the default MCP tool surface.
- Candidate plugin: `tee-enclave`
- Candidate tool: `tee.enclave.inventory`
- Safety boundary: no sample execution, no enclave load, no attestation request, no debugger, no emulator, no kernel/TEE driver calls, no network, no mutation.
- Current status: local implementation verified; publish, GitHub CI, merge, and server smoke remain.

## Rationale

Recent iterations covered low-level firmware, kernel/syscall, object/debug metadata, eBPF/BTF, CUDA, WASM component, Apple metadata, and compiler provenance. TEE/confidential-computing enclave artifacts are a remaining platform frontier spanning SGX, TrustZone/OP-TEE, TDX/SEV evidence, and RISC-V enclave ecosystems.

## External Context

Use official/vendor or primary sources when documenting marker rationale. Keep the implementation passive and heuristic: marker discovery and workflow routing only, not trust or attestation validation.

## Execution Summary

- Added `tee-enclave` as a tier-1 static plugin with artifact type `tee_enclave_inventory`.
- Added SDK file-type tags and sample finalization hints for SGX enclave, SGX SIGSTRUCT, and OP-TEE TA artifacts.
- Added workflow search coverage to keep the default MCP gateway limited to `artifact.read`, `workflow.run`, and `workflow.search`.
- Updated plugin docs, generated tool catalog, and Docker analyzer/hybrid plugin lists.

## Verification

- `npm run lint`
- `npx tsc --noEmit --pretty false`
- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/tee-enclave-inventory.test.ts tests/unit/packages/plugin-sdk.test.ts tests/unit/workflow-search.test.ts`
- `npm test -- --runInBand --forceExit --runTestsByPath tests/unit/plugin-format-matrix.test.ts`
- `npm run build`
- `npm run docs:tool-catalog`
- `npm run docker:generate:all`
