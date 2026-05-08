# YARA Rules

This directory contains bundled YARA rules used by the Python worker and YARA-related plugins. The rules are intended for triage and enrichment, not for final attribution by themselves.

## Files

| File | Purpose |
| --- | --- |
| `default.yar` | Baseline suspicious strings and simple static indicators |
| `packers.yar` | Packer and protector indicators |
| `malware_families.yar` | Family-oriented signatures used for coarse triage |

## Usage

YARA scanning is exposed through MCP plugin tools and the Python worker. Typical user-facing paths are:

- staged analysis through `workflow.analyze.start` and `workflow.analyze.promote`;
- YARA plugin tools when visible;
- worker-level tests during development.

Run local tests:

```bash
python -m pytest workers/test_yara_scan.py workers/test_yara_scan_unit.py
```

## Adding Rules

When adding or changing rules:

1. Keep rule names stable and descriptive.
2. Add metadata such as `description`, `author`, `date`, and `reference` where useful.
3. Prefer high-signal strings and conditions.
4. Avoid overly broad rules that match benign compiler/runtime boilerplate.
5. Test rules against benign and malicious fixtures when available.
6. Update worker or plugin tests if result shape changes.

## Safety Notes

YARA hits are evidence, not proof. Reports should preserve rule name, namespace/file, matched strings when allowed, and confidence. Avoid exposing large matched byte ranges from proprietary or sensitive samples.

## References

- https://yara.readthedocs.io/
- Project worker docs: [../README.md](../README.md)
