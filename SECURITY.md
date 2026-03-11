# Security Policy

## Scope

This repository provides an MCP server for reverse-engineering and malware
analysis workflows. It is intended for controlled analysis environments.

## Reporting a vulnerability

Do not open a public GitHub issue for a security-sensitive report.

Instead, report:

- the affected version or commit
- the impacted MCP tool or workflow
- reproduction steps
- whether the issue can expose local files, execute unintended commands, or
  corrupt analysis results

If you plan to publish the repository, add your preferred private disclosure
channel before accepting public contributions.

## What is considered security-sensitive here

- unintended command execution
- path traversal or arbitrary file overwrite
- unsafe sample handling outside the intended analysis boundary
- privilege boundary bypass in packaging, install scripts, or worker launchers
- exposure of secrets through logs, reports, or generated artifacts

## Operational guidance

- Run the server in a dedicated analysis environment.
- Do not analyze untrusted samples on a production workstation.
- Review install scripts before using them in shared environments.
- Keep Ghidra, Python packages, and Node dependencies current.
