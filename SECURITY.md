# Security Policy

Rikune is a reverse-engineering and malware-analysis tool. Treat every input sample as hostile.

## Scope

Security-sensitive areas include:

- MCP tool execution and argument validation;
- sample upload, artifact download, and HTTP API auth;
- workspace path handling;
- command execution helpers;
- Python/Ghidra worker launchers;
- Docker images and install scripts;
- runtime delegation;
- Windows Host Agent control endpoints;
- sandbox or VM lifecycle;
- plugin loading and external plugin discovery.

## Reporting A Vulnerability

Open a private security advisory or contact the maintainers through the repository's configured security channel. Do not attach live malware samples to public issues.

Include:

- affected version or commit;
- deployment mode;
- reproduction steps;
- whether runtime execution, external plugins, or HTTP API were enabled;
- logs with secrets removed.

## Security Boundaries

Static Docker mode is the safest default. It should not execute samples.

Live execution must be isolated:

- Windows Sandbox;
- dedicated Hyper-V VM;
- another intentionally isolated runtime backend.

Runtime Node performs isolation checks and should not be started directly on a workstation for unknown samples. Any unsafe override is for controlled development only.

## Dangerous Actions

`PolicyGuard` gates operations such as:

- dynamic execution;
- network access;
- external upload;
- bulk decompilation.

Approvals are intentionally explicit and time-bounded. Do not treat an approval as a general trust decision for the sample.

## Command Injection Prevention

The project uses structured process APIs and safe command helpers instead of shell-built command strings where possible. Command names, output formats, and tool-specific arguments should remain validated and allowlisted.

When adding tools:

1. Avoid `shell: true`.
2. Use `execFile` or `spawn` with argument arrays.
3. Validate file paths stay inside the expected workspace or storage root.
4. Do not pass user-controlled strings through a shell.
5. Keep external tool output parsing defensive.

## Upload And Storage Safety

Sample uploads are stored under managed upload and sample roots. Imported samples are finalized by hash and should be treated as immutable originals.

Do not:

- mount unknown sample directories over the source tree;
- expose artifact directories without API auth;
- trust original filenames for paths;
- copy live samples into shared or synchronized folders.

## Plugin Safety

External plugins are executable code. Only load plugins from trusted sources.

Before enabling external plugins:

- review `plugin.json` and `index.js`;
- inspect declared `systemDeps`;
- check runtime contracts;
- check whether the plugin requests live execution or network access;
- prefer running in static Docker or an isolated development environment first.

## HTTP API

When exposed beyond localhost:

- configure `API_KEY`;
- place the service behind a trusted network boundary;
- keep rate limiting enabled;
- avoid permissive CORS;
- do not expose upload endpoints publicly without additional controls.

## Operational Guidance

- Prefer `static` Docker for routine triage.
- Use `hybrid` only when live runtime evidence is required.
- Keep Windows Sandbox or Hyper-V runtime disposable.
- Revert Hyper-V VMs to clean checkpoints after live analysis.
- Do not reuse dirty runtime state across unrelated samples unless that is an intentional investigation.
- Keep Node.js, Docker, Java, Ghidra, and Python dependencies patched.

## CI/CD Security

CI should continue to check:

- TypeScript build and type checks;
- tests;
- Docker generation;
- dependency vulnerability scanning where available;
- no committed secrets;
- install script behavior on supported platforms.
