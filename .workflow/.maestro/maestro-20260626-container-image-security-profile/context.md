# Container Image Security Profile Iteration

Session: `maestro-20260626-container-image-security-profile`
Branch: `feat/container-image-security-profile`
Base: `beta`
Date: `2026-06-26`

## Intent

Expand Rikune's static supply-chain and container-analysis surface with a passive Docker/OCI image security profile. The tool should deepen container coverage without changing the default MCP gateway surface and without starting Docker, contacting registries, mounting layers, extracting files, installing packages, or running image entrypoints.

## Research Inputs

- OCI Image Manifest Specification: `https://github.com/opencontainers/image-spec/blob/master/manifest.md`
- OCI Image Configuration Specification: `https://specs.opencontainers.org/image-spec/config/`
- Open Container Initiative overview: `https://opencontainers.org/about/overview/`

## Subagent Inputs

- `019f0112-7144-71f1-8421-48b6805630e5` recommended AI/ML model artifact inventory as a high-value next frontier after this iteration.
- `019f0112-917f-74e2-975e-13d761d588cc` recommended deepening `container-analysis` with a passive Docker/OCI image security profile and avoiding CVE-scanner claims, registry access, Docker daemon usage, image load, mount, extraction, install scripts, and entrypoint execution.

## Decision

Implement `container.image.security.profile` under the existing `container-analysis` plugin, not as a new plugin. This keeps generic container inventory and Docker/OCI image risk profiling in one surface while allowing `workflow.search` to recommend the hidden static tool on `docker-image` and `oci-image` inputs.

## Safety Boundary

- Passive/static only.
- No registry network.
- No Docker daemon.
- No image load.
- No filesystem mount.
- No layer extraction to disk.
- No package install.
- No script or entrypoint execution.
- No mutation.
- No CVE lookup claim.
