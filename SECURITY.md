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

## Outbound Endpoint Trust

Configured Analyzer, Runtime Node, and Host Agent endpoints are trust inputs. Current control-plane clients use the shared endpoint policy and trusted fetch path where wired in. That path:

- accepts only `http` or `https` service endpoints and rejects URL credentials, query strings, and fragments in configured base endpoints;
- can bind credentials to the configured origin or an explicitly trusted parent endpoint;
- validates the complete DNS answer before the HTTP socket is opened and rejects metadata, link-local, unspecified, and related special-use targets, including covered IPv4-mapped IPv6 forms;
- uses the validated resolver in the HTTP dispatcher and forces `redirect: 'error'` so a redirect cannot silently move credentials or requests to another origin.

These controls reduce SSRF and DNS-rebinding paths to the protected address classes; they do not make every private, public, or allowlisted endpoint trustworthy. Operators must control endpoint configuration and DNS, authenticate control-plane services, and restrict network reachability. New credentialed outbound clients should reuse the shared endpoint and trusted-fetch helpers rather than use a separate redirect-following `fetch` path.

## Sidecars And Worker Provenance

Runtime sidecars are hostile sample-adjacent inputs, not trusted configuration. Sidecar staging confines explicit paths lexically and by resolved real path to the sample directory, accepts regular files only, and applies extension, file-count, and total-byte budgets. Keep those limits enabled. Containment prevents path escape; it does not make sidecar contents safe, so parsers and live runtimes still require the same isolation as the primary sample.

Worker-backed results expose execution metadata such as requested and actual mode, backend, adapter, contract version, and whether data came from a deterministic builtin fixture or an external analysis worker. Preserve this metadata when promoting artifacts or evidence. It is audit provenance, not cryptographic attestation: an operator-supplied worker path, binary, container, or sidecar can still be malicious or compromised. Pin and review external backends, verify distributable hashes or signatures where available, and do not treat a successful readiness check or `data_provenance` label as proof of integrity.

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
