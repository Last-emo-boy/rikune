# Plugin SDK For Rikune

`@rikune/plugin-sdk` is the canonical contract for Rikune plugins. Plugins should import SDK types and helpers from this contract instead of importing Analyzer internals.

## Installation

Inside this monorepo the package is available through npm workspaces:

```ts
import { definePlugin, defineTool, ok } from '@rikune/plugin-sdk'
```

The scoped package is bundled into the public `rikune` tarball rather than published independently. External plugins should install `rikune` and use its stable bridge:

```bash
npm install rikune zod
```

```ts
import { definePlugin, defineTool, ok } from 'rikune/plugin-sdk.js'
```

## Core Concepts

| Concept | Purpose |
| --- | --- |
| `Plugin` | The object exported by a plugin |
| `ToolDefinition` | MCP tool metadata, input schema, optional output schema, optional runtime contract |
| `PluginToolDeps` | Services injected by the Analyzer during registration |
| `PluginServerInterface` | Minimal server facade exposed to plugins |
| `ToolRuntimeContract` | Runtime Node delegation contract |
| `PluginAspects` | Routing taxonomy for formats, platforms, execution mode, runtime backends, safety, and evidence |
| `DynamicRuntimePolicy` | Policy metadata for dynamic or runtime-backed tools |
| `BackendWorkerContract` | Bounded optional backend Worker contract for tool-local external adapters |
| `ToolArtifactSpec`, `ToolEvidenceSpec` | Declarations for artifacts and evidence produced by a tool |
| `definePlugin`, `defineTool`, `defineManifestPlugin` | Helpers for code-first or manifest-backed plugins |
| `ok`, `fail`, `toolText` | Result helpers |

## Recommended Plugin Shape

```ts
import { z } from 'zod'
import { definePlugin, defineTool, ok } from 'rikune/plugin-sdk.js'

const inspectTool = defineTool({
  name: 'example.inspect',
  description: 'Inspect a sample with the example plugin',
  inputSchema: z.object({
    sample_id: z.string(),
  }),
  aspects: {
    formats: ['pe', 'elf', 'macho'],
    platforms: ['windows', 'linux', 'macos'],
    execution: ['static', 'triage'],
    safety: ['passive'],
    evidence: ['structure', 'provenance'],
  },
  artifacts: [{ type: 'example_inventory', mime: 'application/json' }],
  evidence: [{ category: 'structure', artifactTypes: ['example_inventory'] }],
  handler: async (args, deps) => {
    const workspace = deps.services?.workspace
    return ok({
      sample_id: args.sample_id,
      has_workspace_service: Boolean(workspace?.manager),
    })
  },
})

export default definePlugin({
  id: 'example',
  name: 'Example',
  description: 'Example Rikune plugin',
  version: '1.0.0',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho'],
    platforms: ['windows', 'linux', 'macos'],
    execution: ['static'],
    safety: ['passive'],
    capabilities: ['inventory'],
    evidence: ['structure', 'provenance'],
  },
  surfaceRules: { tier: 3, category: 'example' },
  tools: [inspectTool],
})
```

## Plugin Object

Important fields:

```ts
interface Plugin {
  id: string
  name: string
  description?: string
  version?: string
  executionDomain?: 'static' | 'dynamic' | 'both'
  dependencies?: string[]
  configSchema?: PluginConfigField[]
  systemDeps?: PluginSystemDependency[]
  aspects?: PluginAspects
  runtimePolicy?: DynamicRuntimePolicy
  surfaceRules?: PluginSurfaceRules
  tools?: DefinedTool[]
  register(server: PluginServerInterface, deps: PluginToolDeps, ctx?: PluginContext): string[] | void | Promise<string[] | void>
  check?(deps: PluginToolDeps, ctx?: PluginContext): boolean | Promise<boolean>
  teardown?(deps: PluginToolDeps, ctx?: PluginContext): void | Promise<void>
  hooks?: PluginHooks
}
```

## Dependency Injection

Plugins receive services through `PluginToolDeps`.

Common services:

- `workspaceManager`
- `database`
- `cacheManager`
- `jobQueue`
- `storageManager`
- `policyGuard`
- `runtimeClient`
- `services.workspace`
- `services.platform`
- `services.runtime`
- `services.ghidra`

Prefer service helpers such as `requireWorkspaceManager`, `requireDatabase`, and `getRuntimeServices` where available. Avoid importing from `src/core`, `src/persistence`, or other Analyzer internals directly.

## Plugin Standard v2

Plugin Standard v2 is additive and warning-first. The SDK accepts older plugin shapes, but
`auditPluginQuality(plugin)` reports metadata gaps so authors can migrate without breaking
runtime loading.

Plugin-level metadata should include:

- `id`, `name`, `description`, `version`
- `executionDomain`
- `aspects`
- `surfaceRules`
- `tools` or `register()`

Tool-level metadata should include:

- `name`, `description`, `inputSchema`, and `outputSchema`
- `aspects` when the tool is narrower than the plugin
- `artifacts` or `evidence` when the tool emits analysis output
- `runtimePolicy` and either `runtime` or plan-only semantics for dynamic tools
- `workerBackend` when a tool delegates to a bounded optional backend Worker

Quality warning codes include `missing-output-schema`, `missing-surface-rules`,
`missing-aspects`, `missing-evidence`, `missing-runtime-policy`,
`dynamic-runtime-contract-missing`, `missing-system-deps`, `missing-readiness-check`, and
`missing-tools`. Treat `warning` severity as work needed before strict gates; treat `info`
severity as migration guidance unless your project opts into stricter policy.

## Aspect Taxonomy

`aspects` is the main discovery contract. It lets `plugin.list`, `tools.discover`, `tool.help`, `tool.readiness`, `tool.aspect.matrix`, and sample profiling route from a file type to the right plugin.

| Group | Typical values | Meaning |
| --- | --- | --- |
| `formats` | `pe`, `elf`, `macho`, `apk`, `aab`, `ipa`, `dmg`, `deb`, `rpm`, `msi`, `wasm`, `pcap`, `memory-dump` | File, package, container, or artifact family |
| `platforms` | `windows`, `linux`, `macos`, `ios`, `android`, `jvm`, `dotnet`, `wasm`, `embedded`, `cross-platform` | Target platform or ecosystem |
| `architectures` | `x86`, `x64`, `arm`, `arm64`, `mips`, `riscv`, `wasm` | CPU or VM architecture |
| `execution` | `static`, `dynamic`, `emulation`, `decompilation`, `triage`, `correlation` | How the tool reasons about the sample |
| `runtimes` | `windows-sandbox`, `hyperv`, `wine`, `speakeasy`, `qiling`, `gdb`, `lldb`, `adb`, `android-emulator`, `frida`, `idevice-tools`, `wasmtime` | Runtime backend candidates |
| `safety` | `passive`, `opt_in_dynamic`, `requires_isolation`, `no_live_sample_by_default`, `no_installer_execution`, `no_auto_mount`, `no_network_by_default` | Safety boundary for discovery/readiness |
| `capabilities` | `inventory`, `structure`, `symbols`, `imports`, `decompile`, `behavior-plan`, `evidence-correlation` | Free-form capability tags |
| `evidence` | `structure`, `symbols`, `imports`, `exports`, `strings`, `signatures`, `behavior`, `network`, `filesystem`, `registry`, `memory`, `timeline`, `manifest`, `certificates`, `package-metadata`, `nested-binaries`, `sbom`, `vulnerabilities`, `provenance` | Evidence categories a tool can produce |

Declare broad plugin-level aspects, then narrower tool-level aspects when one tool only covers part of the plugin. Use lower-case kebab-case tags. Unknown tags are accepted so plugin authors can extend the matrix, but common tags should match the SDK vocabulary.

## Static And Dynamic Plugin Directions

Static plugins should be passive by default: inspect bytes, parse containers, build inventories, extract metadata, correlate existing artifacts, or generate reports. They must not install packages, mount images, launch samples, connect to devices, insert kernel modules, or start emulators.

Useful static plugin families:

| Family | Formats | Example tools |
| --- | --- | --- |
| Windows native | `pe`, `dll`, `sys`, `efi`, `pdb`, `msi`, `msix`, `appx`, `cab` | PE structure, signature, installer inventory, debug-symbol metadata |
| Linux native | `elf`, `elf-executable`, `so`, `elf-core`, `linux-kernel-module`, `deb`, `rpm`, `appimage` | ELF inventory, package inventory, core/module routing |
| Apple | `macho`, `dylib`, `framework`, `app-bundle`, `dmg`, `pkg`, `ipa`, `mobileprovision`, `dsym` | Apple container inventory, signing/entitlement inspection |
| Android | `apk`, `aab`, `apks`, `xapk`, `dex`, `oat`, `vdex`, `aar` | Package inventory, manifest parse, smali/resource decode, DEX listing |
| Managed and bytecode | `jar`, `class`, `war`, `jmod`, `dotnet`, `pe-clr`, `nupkg`, `unity-metadata`, `pyc`, `lua-bytecode`, `v8-cache` | JVM, .NET, Unity, script bytecode metadata |
| Containers and firmware | `zip`, `tar`, `docker-image`, `oci-image`, `cpio`, `squashfs`, `ubi`, `romfs` | Archive inventory, nested binary routing, firmware scan |
| WASM and network artifacts | `wasm`, `wasi`, `pcap`, `pcapng` | WASM section analysis, PCAP protocol/DNS/stream extraction |

Dynamic plugins should either be plan-only or runtime-backed:

- Plan-only tools, such as `android.runtime.plan` or `windows.runtime.plan`, produce readiness guidance and command templates locally. They declare `runtimePolicy`, but do not declare a `runtime` contract because they do not delegate execution.
- Runtime-backed tools declare both `runtimePolicy` and a `runtime` contract. They may delegate to Runtime Node only after explicit user opt-in, isolation readiness, backend readiness, and policy checks.

Dynamic plugin families currently worth expanding:

| Platform | Plan or backend direction |
| --- | --- |
| Windows | Windows Sandbox, Hyper-V, host-agent, Wine, Speakeasy, CDB/procdump/network telemetry plans |
| Linux | Qiling, GDB, strace/ltrace, eBPF planning, core-dump correlation |
| macOS | LLDB, DTrace, fs_usage, sandbox-exec planning |
| iOS | IPA/device readiness, Frida, idevice-tools, LLDB attach plans |
| Android | ADB/emulator readiness, Frida/frida-server, hook plans, APK install policy gates |
| WASM | wasmtime/WASI capability planning with explicit filesystem/network grants |

## Manifest-Backed Plugins

External plugins can declare manifest v2 metadata in `plugin.json` and export handlers from `index.js`.

```json
{
  "id": "example",
  "name": "Example",
  "version": "1.0.0",
  "description": "Example external plugin",
  "executionDomain": "static",
  "aspects": {
    "formats": ["apk", "dex"],
    "platforms": ["android"],
    "execution": ["static", "triage"],
    "safety": ["passive"],
    "evidence": ["manifest", "structure", "signatures"]
  },
  "surfaceRules": {
    "tier": 1,
    "category": "android-analysis",
    "activateOn": { "fileTypes": ["apk", "dex"] }
  },
  "tools": [
    {
      "name": "example.inspect",
      "description": "Inspect a sample",
      "handler": "example.inspect",
      "inputSchema": { "type": "object", "properties": {} },
      "aspects": {
        "formats": ["apk"],
        "platforms": ["android"],
        "execution": ["static"]
      },
      "artifacts": [{ "type": "example_inventory", "mime": "application/json" }],
      "evidence": [{ "category": "manifest", "artifactTypes": ["example_inventory"] }]
    }
  ]
}
```

The SDK includes manifest validation helpers used by the Analyzer loader.

Manifest v2 supports `aspects`, `runtimePolicy`, `resources`, `surfaceRules`, per-tool `artifacts`, per-tool `evidence`, per-tool `runtime` contracts, and per-tool `workerBackend` contracts. Existing manifest fields remain compatible; new fields are additive.

## Backend Worker Contracts

Use `workerBackend` for optional tool-local adapters such as deobfuscators, IR generators, lifters, fact extractors, or specialized inventory workers. This is distinct from `runtime`: a Worker contract describes a bounded backend adapter and readiness metadata, while `runtime` describes delegated live execution through Runtime Node.

Worker-backed tools should keep a separate explicit tool name such as `example.worker.run` instead of changing a plan-only tool into an execution tool. The contract should declare:

- `version: "backend-worker.v1"`
- `backendName`, `backendKind`, `adapter`, and optional `envVar` or `commandHint`
- `supportedModes` and `defaultMode`
- input and output artifact types
- `policy` fields such as `passiveByDefault`, `requiresUserOptIn`, `requiresIsolation`, `noNetwork`, `noMutation`, `noLiveExecution`, and size or timeout limits
- `readiness.doesNotStartBackend: true` plus setup actions
- `packaging` when the backend has Docker installation semantics

Discovery surfaces expose this metadata without executing the backend:

- `plugin.list` returns plugin-level `worker_backends` and per-tool `worker_backend`.
- `tools.discover` returns plugin `worker_backend` hints.
- `tool.help` returns per-tool `worker_backend`.
- `tool.readiness` returns `worker_backend_readiness`.

External backend execution should remain opt-in and fixture-tested. Static JavaScript workers must not evaluate JavaScript or start Node/V8/browser automation by default; native IR workers must be read-only and bounded by file/function/range; runtime-gated workers must require explicit approval and isolation.

### Backend Packaging Metadata

`PluginSystemDep` is also the Docker backend installation contract. When a dependency declares
`dockerFeature`, it must declare one of these routes:

| Route | Meaning |
| --- | --- |
| `installed` | The generator installs it through apt, a Docker fragment, a copied in-repo worker, or base-image dependency validation. |
| `profile-gated` | The generator installs it only when `--backend-profile` includes the declared `dockerInstallProfile`. |
| `validation-only` | The plugin is a planner/readiness surface; another plugin owns the executable backend. |
| `byo` | The user must provide the binary, wrapper, directory, or mounted path. |
| `sidecar` | The backend should be supplied as a separate service/container. |

Profiles are `default`, `optional`, `heavy`, `research`, `runtime`, `gpu`, and
`license-gated`. Default Docker images should only install static, low-risk backends. Heavy,
runtime, GPU, GPL/AGPL, or environment-sensitive tools must be profile-gated, BYO, or sidecar.

Example in-repo worker route:

```ts
systemDeps: [
  {
    type: 'file',
    name: 'example-worker',
    target: '$EXAMPLE_WORKER_PATH',
    envVar: 'EXAMPLE_WORKER_PATH',
    dockerDefault: '/opt/rikune-backends/example/bin/example-worker.js',
    dockerFeature: 'example',
    dockerValidation: ['node /opt/rikune-backends/example/bin/example-worker.js --self-test'],
    dockerInstallRoute: 'installed',
    dockerInstallProfile: 'default',
  },
]
```

The matching `workerBackend.packaging` should echo the route, profile, feature, env var, and
Docker default so `tool.readiness`, `plugin.list`, tests, and Docker dry-run agree on the same
backend state.

## Runtime Contracts

Tools delegated to Runtime Node can attach a `runtime` contract to their `ToolDefinition`.

Contracts describe:

- supported execution modes;
- required backend capabilities;
- timeout;
- expected artifact inputs and outputs;
- fallback behavior;
- failure categories.

Execution modes include:

- `plan_only`
- `safe_simulation`
- `emulation`
- `live_sandbox`
- `live_hyperv`
- `manual_runtime`

Live execution should remain explicit and policy-gated.

## Runtime Policy

Use `runtimePolicy` on dynamic plugins and runtime-backed tools:

```ts
runtimePolicy: {
  passiveByDefault: true,
  requiresUserOptIn: true,
  requiresIsolation: true,
  allowedBackends: ['android-emulator', 'frida'],
  networkPolicy: 'disabled',
}
```

For plan-only dynamic tools, declare `runtimePolicy` but omit `runtime`. For delegated tools, also declare `runtime` with supported modes, backend capabilities, timeout, isolation requirements, and fallback behavior.

`tool.readiness` surfaces this as `runtime_policy_status`, `opt_in_required`, `policy_denied`, `isolation_missing`, and `backend_missing`.

## Artifact And Evidence Metadata

Tools should declare what they may write and what evidence categories they support:

```ts
artifacts: [
  { type: 'android_package_inventory', mime: 'application/json' },
],
evidence: [
  { category: 'manifest', artifactTypes: ['android_package_inventory'] },
  { category: 'nested-binaries', artifactTypes: ['android_package_inventory'] },
]
```

This metadata powers report generation, evidence graphs, correlation tools, and client-side tool selection.

## Results

Use result helpers for consistent MCP output:

```ts
return ok({
  summary: 'analysis complete',
  findings: [],
})
```

Return errors as structured tool results when the failure is expected and user-actionable. Throw only for unexpected implementation failures.

## Surface Rules

`surfaceRules` controls when plugin tools are visible.

| Tier | Meaning |
| --- | --- |
| 0 | Visible gateway tools |
| 1 | File-type activated |
| 2 | Finding/signal activated |
| 3 | Expert/manual discovery |

Use `tools.discover` and `tool.readiness` to help clients find tier 1-3 tools.

## External Plugin Placement

Compiled external plugins can be placed in:

```text
plugins/<id>/index.js
plugins/<id>/plugin.json
```

or as a direct `.js` / `.mjs` module under `plugins/`.

The repository scaffold helper is:

```bash
node scripts/create-plugin.js my-feature --name "My Feature"
node scripts/create-plugin.js apk-inventory --template format-adapter
node scripts/create-plugin.js android-runtime-plan --template dynamic
node scripts/create-plugin.js sandbox-tool --template runtime-gated
node scripts/create-plugin.js external-shell --template manifest-only
```

## Testing Plugins

Recommended checks:

```bash
npm run build
npm run test:unit
npm run typecheck
```

Then validate runtime behavior with:

- `plugin.list`
- `tools.discover`
- `tool.readiness`
- the plugin's own tools
