# Plugin SDK And Built-In Plugins

Rikune uses plugins for most optional and specialist analysis surfaces. Core intake, workflow, artifact, task, and system tools are registered by `src/core/tool-registry.ts`; specialist tools are registered by plugins under `src/plugins/<id>/`.

The public plugin contract lives in `packages/plugin-sdk/src/index.ts`. Compatibility re-exports are available through `src/plugins/sdk.ts`.

## Plugin Responsibilities

A plugin can:

- register one or more MCP tools;
- declare static, dynamic, or both-domain execution;
- declare dependencies on other plugins;
- declare external system dependencies;
- expose configuration schema for `plugin.list`;
- provide lifecycle hooks;
- provide Docker generation metadata;
- define progressive tool surface rules;
- delegate execution to Runtime Node through a runtime contract.

## Built-In Plugins

The repository currently contains 76 built-in plugins.

| ID | Name | Domain | Surface tier |
| --- | --- | --- | --- |
| `android` | Android / APK Analysis | static | 1 |
| `android-package` | Android Package Inventory | static | 1 |
| `android-runtime` | Android Runtime Plan | dynamic | 2 |
| `angr` | angr | static | 3 |
| `api-hash` | API Hash Resolution | static | 2 |
| `apk-smali` | APK Smali Analysis | static | 1 |
| `apple-container` | Apple Container Inventory | static | 1 |
| `apple-signing` | Apple Signing Inventory | static | 1 |
| `batch` | Batch Analysis | both | 0 |
| `behavior-first` | Behavior-First Analysis | dynamic | 2 |
| `binary-diff` | Binary Diff | static | 2 |
| `bytecode` | Script Bytecode Inventory | static | 1 |
| `capstone` | Capstone Disassembly | static | 2 |
| `code-analysis` | Code Analysis | static | 0 |
| `container-analysis` | Container / Archive Inventory | static | 1 |
| `crackme` | CrackMe Automation | static | 3 |
| `cross-module` | Cross-Module Analysis | static | 2 |
| `debug-session` | Debug Session | dynamic | 3 |
| `deep-unpack` | Deep Unpack | static | 2 |
| `die` | Detect It Easy | static | 0 |
| `dotnet-decompile` | .NET Decompile | static | 2 |
| `dotnet-managed` | .NET Managed Inventory | static | 1 |
| `dotnet-reactor` | .NET Reactor Deobfuscation | static | 2 |
| `dynamic` | Dynamic Analysis Automation | dynamic | 3 |
| `elf-macho` | ELF / Mach-O | static | 1 |
| `firmware` | Firmware Analysis | static | 1 |
| `frida` | Frida Instrumentation | dynamic | 3 |
| `ghidra` | Ghidra Integration | static | 3 |
| `go-analysis` | Go Analysis | static | 2 |
| `graphviz` | Graphviz | static | 0 |
| `host-correlation` | Host Correlation | static | 2 |
| `ios-runtime` | iOS Runtime Plan | dynamic | 2 |
| `jvm` | JVM Bytecode Inventory | static | 1 |
| `kb-collaboration` | Knowledge Base & Collaboration | static | 0 |
| `linux-binary` | Linux Binary Inventory | static | 1 |
| `linux-package` | Linux Package Inventory | static | 1 |
| `linux-runtime` | Linux Runtime Plan | dynamic | 2 |
| `macos-runtime` | macOS Runtime Plan | dynamic | 2 |
| `malware` | Malware Analysis | static | 0 |
| `managed-fake-c2` | Managed Fake C2 | dynamic | 2 |
| `managed-il-xrefs` | Managed IL Cross-References | static | 2 |
| `managed-sandbox` | Managed Sandbox | dynamic | 2 |
| `memory-forensics` | Memory Forensics (Volatility 3) | static | 3 |
| `metadata` | File Metadata | static | 0 |
| `native-object` | Native Object Inventory | static | 1 |
| `observability` | observability.metrics | both | 0 |
| `office-analysis` | Office Analysis | static | 1 |
| `panda` | PANDA | dynamic | 3 |
| `pcap-analysis` | PCAP Analysis | static | 1 |
| `pe-analysis` | PE Analysis | static | 0 |
| `pe-signature` | PE Authenticode Signature | static | 2 |
| `qiling` | Qiling | dynamic | 3 |
| `reporting` | Reporting | both | 0 |
| `retdec` | RetDec | static | 3 |
| `rizin` | Rizin | static | 3 |
| `runtime-deobfuscate` | Runtime Deobfuscation | dynamic | 2 |
| `sbom` | SBOM | static | 2 |
| `similarity` | Sample Similarity | static | 2 |
| `speakeasy` | Speakeasy Emulator | dynamic | 2 |
| `static-triage` | Static Triage | static | 0 |
| `strings` | Strings Extraction | static | 0 |
| `threat-intel` | Threat Intelligence | static | 0 |
| `unity-managed` | Unity Managed Inventory | static | 1 |
| `unpacking` | Unpacking | static | 2 |
| `upx` | UPX | static | 2 |
| `visualization` | Visualization & Reporting | static | 0 |
| `vm-analysis` | VM Analysis & Symbolic | static | 3 |
| `vuln-scanner` | Vulnerability Scanner | static | 2 |
| `wasm` | WebAssembly Inventory | static | 1 |
| `wasm-runtime` | WASM Runtime Plan | dynamic | 2 |
| `windows-debug-symbols` | Windows Debug Symbols Inventory | static | 1 |
| `windows-installer` | Windows Installer Inventory | static | 1 |
| `windows-runtime` | Windows Runtime Plan | dynamic | 2 |
| `wine` | Wine | dynamic | 3 |
| `yara` | YARA | static | 0 |
| `yara-x` | YARA-X | static | 2 |

Surface tier meanings:

- `0`: visible gateway tools.
- `1`: file-type activated tools.
- `2`: finding/signal activated tools.
- `3`: expert tools, usually surfaced by `tools.discover` or explicit readiness checks.

## Plugin Standard v2

Plugin Standard v2 is the non-breaking contract for built-in and external plugins. During the
migration window, missing metadata is reported as `qualityWarnings`; it does not prevent plugin
loading unless the plugin shape itself is invalid.

Required plugin-level fields:

- `id`, `name`, `description`, `version`
- `executionDomain`: `static`, `dynamic`, or `both`
- `aspects`: at least one useful routing group, usually `formats`, `platforms`, `execution`,
  `safety`, `capabilities`, or `evidence`
- `surfaceRules`: tier and category, plus `activateOn` rules for tier 1 or tier 2 plugins
- `tools` or `register()`

Required tool-level fields:

- `definition.name`, `description`, `inputSchema`, and `outputSchema`
- `aspects` when the tool has narrower scope than the plugin
- `artifacts` or `evidence` when the tool emits analysis results
- `workflowRecipes` when the tool starts, advances, or completes a workflow/correlation chain
- `runtimePolicy` and either a `runtime` contract or explicit plan-only semantics for dynamic
  and runtime-backed tools

Quality warning severities are intentionally warning-first:

| Code | Meaning | Migration action |
| --- | --- | --- |
| `missing-output-schema` | Tool output is not machine-described | Add `outputSchema` or a shared worker-result schema |
| `missing-surface-rules` | Plugin defaults to always visible | Add tier/category and activation rules |
| `missing-aspects` | Plugin or tool cannot be routed by profile | Add aspect metadata |
| `missing-evidence` | Tool result provenance is unclear | Add artifact or evidence declarations |
| `missing-workflow-recipe` | Workflow/correlation-capable tool cannot explain follow-up flow | Add `workflowRecipes` with recipe id, inputs, outputs, next tools, and safety tags |
| `missing-runtime-policy` | Runtime behavior is not policy-described | Add `runtimePolicy` |
| `dynamic-runtime-contract-missing` | Dynamic tool has no delegation contract | Add `runtime` or make the tool clearly plan-only |
| `missing-system-deps` | Dependency readiness cannot be explained | Add `systemDeps` or a `check()` hook |
| `missing-readiness-check` | Dynamic plugin lacks readiness metadata | Add `systemDeps`, `check()`, or plan-only readiness semantics |
| `missing-tools` | Plugin has no tools or register handler | Add declarative tools or `register()` |

The canonical audit helper is `auditPluginQuality()` from `@rikune/plugin-sdk`. The core
orchestrator uses it to populate `plugin.list`, `tools.discover`, `tool.help`, and
`tool.readiness` quality metadata.

## Capability Workflows

Workflow recipes are additive metadata for cross-plugin analysis chains. They are exposed by
`plugin.list`, `tools.discover`, `tool.help`, `tool.readiness`, and `sample.profile.get`; they
must not start runtime backends or inspect samples by themselves.

Use `workflowRecipes` on each tool that acts as a workflow entry, bridge, or terminal evidence
collector. Supported fields:

- `id`: stable kebab/dot-case recipe id, such as `android.static.behavior`.
- `title` and optional `description`: short human-readable purpose.
- `startsWith`: tool names that can seed the recipe.
- `nextTools`: follow-up tools clients may choose after this tool succeeds.
- `requiredArtifacts`: artifact types or evidence bundles the tool expects.
- `producesArtifacts`: artifact types the tool emits or refines.
- `evidence`: evidence tags produced or consumed by the recipe.
- `safety`: passive and runtime-gate tags clients must preserve.
- `runtimeBackends`: backend names for plan-only or opt-in runtime handoff.

Shared artifact/evidence vocabulary for this iteration:

- `workflow_recipe`: workflow metadata envelope emitted by discovery/help/readiness surfaces.
- `finding_bundle`: grouped findings that can be routed into another plugin without parsing prose.
- `correlation_graph`: cross-tool relation graph for artifacts, processes, files, imports, IOCs, or packages.
- `provenance_graph`: source-to-derived-artifact lineage graph with tool and sample anchors.
- `runtime_plan`: plan-only runtime guidance that does not start a backend.
- `analysis_memory`: reusable analyst notes, rules, labels, or sample facts captured for future routing.
- `analysis_report`: generated report artifact consuming structured evidence.

Workflow-capable tools usually declare `execution: ["correlation"]`, `capabilities` containing
`workflow-*` or graph terms, or `evidence` containing `workflow`, `correlation-graph`, or
`provenance-graph`. When such a tool lacks `workflowRecipes`, `auditPluginQuality()` reports
`missing-workflow-recipe` with a `suggested_task_owner` pointing at the relevant Maestro task.

## Advanced Safety Categories

Advanced plugin iteration is grouped by risk so CI can audit contracts without invoking heavy or
unsafe backends:

| Category | Applies to | Required default |
| --- | --- | --- |
| `passive-static` | file inventory, parsing, strings, package metadata, signatures | May read existing sample/workspace files only |
| `external-binary` | Ghidra, RetDec, Rizin, Volatility, JADX, APKTool, binwalk, DIE, YARA-X | Must degrade through readiness/systemDeps and focused tests |
| `runtime-gated` | sandbox, emulator, debugger, Frida, Wine, Qiling, Speakeasy, PANDA, wasmtime | Must be passive by default, opt-in, isolated, and visible through `tool.readiness` |
| `network-sensitive` | threat intel, IOC export, malware config enrichment, package/vulnerability lookups | Must be offline in tests and declare `no_network_by_default` unless explicitly record-only |
| `corpus-dependent` | similarity, binary diff, family clustering, KB memory | Must handle empty corpus and never require private datasets in CI |
| `container-or-installer` | firmware extraction, container archive traversal, MSI/MSIX/PKG/DMG/APK/IPA | No mount, install, launch, entrypoint, package script, or custom action execution by default |

## Plugin Matrix

The current plugin matrix is organized by `formats`, `platforms`, `execution`, `runtimes`, `safety`, `capabilities`, and `evidence` aspects. `plugin.list`, `tools.discover`, `tool.help`, `tool.readiness`, and `sample.profile.get` expose these fields so clients can route from a file type to the right static inventory, dynamic plan, or runtime-gated tool.

| Coverage | Static plugins | Dynamic or runtime-plan plugins | Safety boundary |
| --- | --- | --- | --- |
| Windows PE, DLL, SYS, EFI, MSI/MSIX/APPX/CAB/PDB | `pe-analysis`, `pe-signature`, `windows-installer`, `windows-debug-symbols`, `dotnet-managed`, `retdec`, `rizin`, `ghidra` | `windows-runtime`, `debug-session`, `wine`, `speakeasy`, `behavior-first`, `frida` | Static inventory is passive. Dynamic tools require opt-in, isolation, and runtime readiness. |
| Linux ELF, SO, core, modules, packages | `linux-binary`, `linux-package`, `elf-macho`, `native-object`, `container-analysis` | `linux-runtime`, `qiling`, `debug-session`, `behavior-first` | No ELF execution, ptrace, kernel module loading, package install, or eBPF collection by default. |
| macOS Mach-O, app bundles, frameworks, DMG, PKG, dSYM | `apple-container`, `apple-signing`, `elf-macho`, `native-object` | `macos-runtime`, `debug-session`, `frida`, `behavior-first` | No DMG mount, app launch, LLDB attach, DTrace, or fs_usage capture by default. |
| iOS IPA, Mach-O, provisioning, entitlements | `apple-container`, `apple-signing`, `elf-macho` | `ios-runtime`, `frida`, `debug-session` | No IPA install, device connection, simulator start, Frida attach, or LLDB attach by default. |
| Android APK, AAB, APKS, XAPK, DEX/OAT/VDEX, AAR | `android-package`, `android`, `apk-smali`, `jvm`, `linux-binary` | `android-runtime`, `frida`, `behavior-first` | No emulator start, ADB install, APK launch, frida-server deployment, or device connection by default. |
| JVM, .NET, Unity, script bytecode | `jvm`, `dotnet-managed`, `dotnet-decompile`, `unity-managed`, `bytecode`, `strings` | `managed-sandbox`, `runtime-deobfuscate`, `behavior-first` | Runtime work is opt-in and delegated; metadata and bytecode inventory stay passive. |
| Firmware, containers, archives, native objects | `firmware`, `container-analysis`, `native-object`, `linux-package`, `windows-installer` | `qiling`, `linux-runtime`, `wasm-runtime` when applicable | No mount, extraction-to-execute path, package install, module insertion, or payload launch by default. |
| WASM/WASI | `wasm`, `strings`, `sbom` | `wasm-runtime` | No module instantiation, wasmtime start, filesystem preopen, or network grant by default. |
| Network, host, memory, reports | `pcap-analysis`, `host-correlation`, `memory-forensics`, `visualization`, `reporting` | `behavior-first`, `dynamic.behavior.diff`, `analysis.evidence.graph` | Correlation tools operate on existing artifacts and do not start live collection. |

## Aspect Authoring

Every new plugin should declare plugin-level aspects and tool-level metadata when a tool has a narrower scope:

- `formats`: file and container tags such as `pe`, `elf`, `macho`, `apk`, `ipa`, `wasm`, `deb`, `msi`, `firmware`.
- `platforms`: `windows`, `linux`, `macos`, `ios`, `android`, `wasm`, `jvm`, `dotnet`, `embedded`, or `cross-platform`.
- `execution`: `static`, `dynamic`, `emulation`, `decompilation`, `triage`, or `correlation`.
- `runtimes`: runtime backends such as `windows-sandbox`, `hyperv`, `wine`, `speakeasy`, `qiling`, `gdb`, `lldb`, `dtrace`, `adb`, `android-emulator`, `frida`, `idevice-tools`, `wasmtime`.
- `safety`: `passive`, `opt_in_dynamic`, `requires_isolation`, `no_live_sample_by_default`, `no_network_by_default`, `no_auto_mount`, `no_installer_execution`.
- `evidence`: `structure`, `imports`, `exports`, `strings`, `signatures`, `timeline`, `behavior`, `process`, `filesystem`, `registry`, `network`, `memory`, `method-calls`, `syscalls`, `provenance`, `workflow`, `analysis-memory`, `correlation-graph`, `provenance-graph`.

## Dynamic Policy

Dynamic plugins are passive by default. A dynamic plugin or tool should declare `runtimePolicy` with:

The dynamic policy contract is additive metadata: it is reported by discovery and readiness tools before any runtime backend is contacted.

- `passiveByDefault: true`
- `requiresUserOptIn: true`
- `requiresIsolation: true`
- `allowedBackends`: explicit backend list
- `networkPolicy: "disabled"` unless a tool is explicitly designed for record-only or restricted networking
- `notes`: backend and confidence caveats

`tool.readiness` reports `runtime_policy_status`, `opt_in_required`, `policy_denied`, `isolation_missing`, and `backend_missing` without executing the target tool. Plan-only dynamic tools such as `windows.runtime.plan`, `linux.runtime.plan`, `macos.runtime.plan`, `ios.runtime.plan`, `android.runtime.plan`, and `wasm.runtime.plan` are local planning tools: they generate runtime guidance and command templates, but they do not start backends.

## Runtime Management Tools

| Tool | Purpose |
| --- | --- |
| `plugin.list` | List known plugins, status, registered tools, dependencies, and optional config schema |
| `plugin.enable` | Hot-load a known plugin when supported |
| `plugin.disable` | Unload a plugin when supported |
| `tools.discover` | Reveal relevant specialist tools for a sample, finding, or goal |
| `tool.readiness` | Explain prerequisites, runtime contract, policy requirements, and backend availability for a tool |

## Loading Configuration

`PLUGINS` controls the startup plugin set.

```bash
PLUGINS=*                 # default: all built-ins
PLUGINS=pe-analysis,yara  # only selected plugin IDs
PLUGINS=-dynamic          # all except listed plugin IDs
```

Docker profile generation also uses plugin metadata. Regenerate Docker files after adding or removing plugin dependencies:

```bash
npm run build
npm run docker:generate:all
```

## Discovery And Lifecycle

Startup discovery:

1. Discover built-ins from `dist/plugins` in built packages or `src/plugins` in development.
2. Discover external compiled plugins under repository-level `plugins/`.
3. Apply `PLUGINS` filtering.
4. Sort by plugin dependency graph.
5. Validate plugin shape and dependencies.
6. Check system dependencies and plugin `check()` hooks when present.
7. Register plugin tools.
8. Record plugin status and tool ownership.
9. Register plugin introspection tools and diagnostics.

Runtime lifecycle hooks:

- `onBeforeToolCall`
- `onAfterToolCall`
- `onToolError`

The executor only fires plugin hooks for tools owned by that plugin.

## Recommended Plugin Shape

```ts
import { z } from 'zod'
import { definePlugin, defineTool, ok } from '@rikune/plugin-sdk'

const echoTool = defineTool({
  name: 'example.echo',
  description: 'Return a message from the example plugin',
  inputSchema: z.object({
    message: z.string(),
  }),
  handler: () => async (args) => ok({ message: args.message }),
})

export default definePlugin({
  id: 'example',
  name: 'Example Plugin',
  description: 'Small external plugin example',
  version: '1.0.0',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'example' },
  register(server) {
    server.registerTool(echoTool.definition, echoTool.handlerFactory({}))
    return ['example.echo']
  },
})
```

External plugins should compile to ESM JavaScript and be placed under `plugins/<id>/index.js` or as a direct `.js`/`.mjs` file under `plugins/`.

The repository also includes:

```bash
node scripts/create-plugin.js my-feature --name "My Feature"
```

## Manifest-Backed Plugins

Plugins can keep metadata in `plugin.json` and export handlers from `index.js`. Manifest validation is part of the SDK.

Minimal shape:

```json
{
  "id": "my-feature",
  "name": "My Feature",
  "version": "1.0.0",
  "description": "External feature plugin",
  "executionDomain": "static",
  "tools": [
    {
      "name": "my_feature.inspect",
      "description": "Inspect a sample"
    }
  ]
}
```

## Runtime Contracts

Dynamic or delegated tools can declare runtime contracts. Contracts describe execution mode, required capabilities, input/output artifacts, timeout, and backend needs. Analyzer-side `RuntimeClient` validates the contract before dispatching to Runtime Node.

Common execution modes:

- `plan_only`
- `safe_simulation`
- `emulation`
- `live_sandbox`
- `live_hyperv`
- `manual_runtime`

Live modes should require explicit policy approval and an isolated runtime backend.

## System Dependencies

Plugin `systemDeps` can describe binaries, Python modules, files, environment variables, Docker install snippets, and validation commands. These surface in:

- Docker generation;
- `plugin.list`;
- readiness checks;
- setup guidance;
- dashboard readiness.

## Troubleshooting

Plugin does not load:

1. Check `PLUGINS`.
2. Run `plugin.list` with config/status details.
3. Check system dependency messages.
4. Confirm the plugin exports a valid default plugin object.
5. Rebuild TypeScript if using built-in plugin changes.

Tool is missing:

1. Confirm the plugin loaded.
2. Check progressive surface behavior with `tools.discover`.
3. Use `tool.readiness`.
4. Check aliases if the client normalizes dotted names.

Runtime-delegated tool fails:

1. Check `dynamic.runtime.status`.
2. Check `/api/v1/ready`.
3. Confirm `RUNTIME_MODE`, Host Agent endpoint, and API keys.
4. Verify the Runtime Node advertises the required capability.
5. Confirm policy approval for live execution.
