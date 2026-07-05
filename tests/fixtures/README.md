# Safe Golden Fixture Strategy

This directory documents the regression corpus used by default tests. The
default corpus is manifest-first: it records safe synthetic sample classes and
expected analysis signals without committing live malware or requiring live
runtime execution.

## Safety Rules

- Do not commit live malware samples.
- Do not commit samples that require host execution to validate.
- Default CI fixtures must be synthetic, static-only, and reproducible.
- Optional real-tool or live-runtime validation belongs outside the repository
  and must be documented as an opt-in environment.
- Fixture metadata should describe expected routing signals, not guarantee a
  complete malware verdict.

## Manifest

`golden-samples.manifest.json` defines representative classes:

- minimal PE fast profile;
- suspected packed PE routing;
- .NET metadata routing;
- DLL/export routing;
- ELF and Mach-O structural routing;
- APK static routing;
- missing optional backend degradation.

Tests may generate tiny synthetic binaries at runtime from the manifest. When a
binary fixture is added later, keep it benign and include generation steps plus
expected SHA-256.
