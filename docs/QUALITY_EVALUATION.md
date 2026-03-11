# Quality Evaluation

This repository should be evaluated as a reverse-engineering MCP platform, not
only as a collection of independent tools.

## Target sample buckets

- native executable
- native DLL
- .NET executable
- .NET library
- packed executable
- driver-like image
- dual-use operator utility
- malware-like payload

## Core evaluation dimensions

### 1. Static coverage

- import/export extraction succeeded
- runtime detection succeeded
- strings extraction produced useful high-value clusters
- packer detection produced actionable output

### 2. Native analysis coverage

- Ghidra analysis completed
- function index usable
- decompile usable
- CFG usable
- function search usable

### 3. Semantic reconstruction quality

- high-value functions reconstructed
- parameter roles inferred
- state roles inferred
- struct inference produced reusable typed contexts
- suggested names moved unresolved functions into rule/hybrid/llm-resolved states

### 4. Role/profile quality

- binary role identified correctly
- DLL/export surface summarized
- COM/service/plugin indicators explained
- analysis priorities matched observed binary behavior

### 5. Runtime correlation quality

- runtime evidence scope selection reproducible
- runtime-to-function mapping contains corroborated APIs
- memory import or trace import improves prioritization

### 6. Export quality

- reconstruct export produced stable artifacts
- rewrite output remained readable
- build validation passed when compiler was available
- harness validation passed when run

## Suggested scorecard

For each sample, record:

- sample kind
- expected role
- expected entry model
- expected notable APIs
- expected exports
- expected runtime stages
- current binary.role.profile result
- current workflow.reconstruct result
- current report.summarize result
- regressions or missing capabilities

## Minimum regression set

Before significant releases, validate at least:

- one EXE with no exports
- one DLL with COM exports
- one DLL with plugin-style exports
- one .NET assembly
- one packed sample
- one sample with imported runtime evidence
