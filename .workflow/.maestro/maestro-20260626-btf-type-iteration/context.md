# Maestro BTF Type Iteration

Session: `maestro-20260626-btf-type-iteration`

Branch: `feat/btf-type-inventory`

Objective: add a passive BPF Type Format inventory capability for eBPF portability, kernel type metadata, and CO-RE relocation triage without invoking libbpf, bpftool, bpf(), the kernel verifier, or runtime loading.

## Inputs

- User direction: continue broad and deep binary-analysis capability iteration with branch, commit, PR, beta merge when possible, and remote container validation.
- Subagent A recommended container image security profile for broad platform coverage.
- Subagent B produced the remote static Docker validation path for `root@159.195.136.226`.
- Network research confirmed BTF and CO-RE are central to modern portable eBPF workflows and are specified by Linux kernel BPF documentation.

## Decision

This iteration chooses BTF/CO-RE over container image profile because it directly deepens the just-merged eBPF and LLVM bitcode toolchain. It is also a good fit for hand-written bounded parsing: raw BTF headers, type records, string tables, ELF `.BTF`, and `.BTF.ext` CO-RE relocation groups.

## Scope

- Add `src/plugins/btf` with `btf.type.inventory`.
- Support raw BTF buffers and ELF `.BTF` / `.BTF.ext` sections.
- Summarize BTF kind counts, named types, structs, functions, DATASEC records, string table previews, and CO-RE relocation groups.
- Keep default gateway limited to `workflow.search`, `workflow.run`, and `artifact.read`.

## Verification Plan

- Targeted Jest for raw BTF and ELF `.BTF/.BTF.ext` fixtures.
- Plugin SDK file-type tag coverage.
- Workflow search routing without gateway expansion.
- Plugin format matrix discovery, metadata, workflow recipe, and sample finalization checks.
- `npx tsc --noEmit --pretty false`, `git diff --check`, `npm run build`, and `npm run lint`.
