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

The repository currently contains 84 built-in plugins.

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
| `jsvmp-analysis` | JSVMP Analysis Plan | static | 2 |
| `jvm` | JVM Bytecode Inventory | static | 1 |
| `javascript-deobfuscation` | JavaScript Deobfuscation | static | 2 |
| `kb-collaboration` | Knowledge Base & Collaboration | static | 0 |
| `lief` | LIEF Binary Plan | static | 3 |
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
| `miasm` | Miasm IR Plan | static | 3 |
| `native-object` | Native Object Inventory | static | 1 |
| `observability` | observability.metrics | both | 0 |
| `office-analysis` | Office Analysis | static | 1 |
| `panda` | PANDA | dynamic | 3 |
| `pcap-analysis` | PCAP Analysis | static | 1 |
| `pe-analysis` | PE Analysis | static | 0 |
| `pe-signature` | PE Authenticode Signature | static | 2 |
| `qiling` | Qiling | dynamic | 3 |
| `radare2` | radare2 Pipeline Plan | static | 3 |
| `reporting` | Reporting | both | 0 |
| `retdec` | RetDec | static | 3 |
| `revng` | rev.ng Pipeline Plan | static | 3 |
| `rizin` | Rizin | static | 3 |
| `runtime-deobfuscate` | Runtime Deobfuscation | dynamic | 2 |
| `sbom` | SBOM | static | 2 |
| `similarity` | Sample Similarity | static | 2 |
| `speakeasy` | Speakeasy Emulator | dynamic | 2 |
| `static-triage` | Static Triage | static | 0 |
| `strings` | Strings Extraction | static | 0 |
| `threat-intel` | Threat Intelligence | static | 0 |
| `triton` | Triton Symbolic Plan | static | 3 |
| `unity-managed` | Unity Managed Inventory | static | 1 |
| `unpacking` | Unpacking | static | 2 |
| `upx` | UPX | static | 2 |
| `visualization` | Visualization & Reporting | static | 0 |
| `vm-analysis` | VM Analysis & Symbolic | static | 3 |
| `vuln-scanner` | Vulnerability Scanner | static | 2 |
| `wabt` | WABT Toolchain Plan | static | 3 |
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

### Completed Capability Workflow Recipes

The current capability iteration fixed the following workflow recipes as release-guarded metadata.
These recipes are discoverable through `plugin.list`, `tools.discover`, `tool.help`,
`tool.readiness`, and the plugin aspect matrix. Default recipe paths are passive: they do not start
runtime backends, execute samples, perform network lookups, mount images, install packages, launch
emulators, or attach debuggers.

| Recipe | Plugin | Entry tool | Primary follow-up tools | Default safety boundary |
| --- | --- | --- | --- | --- |
| `memory-forensics.offline-correlation` | `memory-forensics` | `memory-forensics.correlate` | `analysis.evidence.graph`, `report.generate` | Existing Volatility rows only; no live memory, no network. |
| `vm.symbolic.workflow` | `vm-analysis` | `vm.workflow.plan` | `constraint.extract`, `smt.solve`, `keygen.synthesize` | Planner only; no solver or emulator is started. |
| `kb.analysis-memory.reuse` | `kb-collaboration` | `kb.context.suggest` | `kb.function.match`, `rule.library`, `kb.export` | Local analysis memory only; no network. |
| `windows.runtime.opt-in` | `windows-runtime` | `windows.runtime.plan` | `dynamic.runtime.status`, runtime-backed tools after approval | Plan-only, opt-in, isolated, network disabled. |
| `linux.runtime.opt-in` | `linux-runtime` | `linux.runtime.plan` | `dynamic.runtime.status`, `qiling`/debug tooling after approval | Plan-only, opt-in, isolated, network disabled. |
| `macos.runtime.opt-in` | `macos-runtime` | `macos.runtime.plan` | `dynamic.runtime.status`, LLDB/DTrace tooling after approval | Plan-only, opt-in, isolated, network disabled. |
| `ios.runtime.opt-in` | `ios-runtime` | `ios.runtime.plan` | `tool.readiness`, Frida/LLDB tooling after approval | Plan-only; no install, device attach, or simulator start. |
| `android.runtime.opt-in` | `android-runtime` | `android.runtime.plan` | `dynamic.toolkit.status`, ADB/emulator/Frida tooling after approval | Plan-only; no install, launch, device connection, or Frida attach. |
| `wasm.runtime.opt-in` | `wasm-runtime` | `wasm.runtime.plan` | `tool.readiness`, wasmtime tooling after approval | Plan-only; no module instantiation or WASI grant. |
| `supply-chain.sbom.provenance` | `sbom` | `sbom.provenance.graph` | `sbom.generate`, `vuln.pattern.summary`, `report.generate` | Local inventories only; no install, mount, execute, or network lookup. |
| `android.static.behavior-graph` | `android` | `android.behavior.graph` | `dex.classes.list`, `android.runtime.plan` | Static graph only; no APK launch, device connection, or runtime start. |
| `apple.security.runtime-profile` | `apple-signing` | `apple.security.profile` | `macho.structure.analyze`, `macos.runtime.plan`, `ios.runtime.plan` | Static profile only; no mount, install, keychain, codesign, or device action. |
| `firmware.iot.passive-workflow` | `firmware` | `firmware.workflow.plan` | `firmware.entropy`, `sbom.provenance.graph`, `qiling.inspect` | Passive workflow plan; no extraction-to-execute, mount, module load, or emulation. |
| `office.macro.static-profile` | `office-analysis` | `office.behavior.profile` | `ioc.export`, `yara.generate`, `sigma.rule.generate`, `report.generate` | Static macro profile only; no Office automation or macro execution. |
| `unpacking.detect-plan-retriage` | `unpacking` | `unpack.workflow.plan` | `unpack.auto`, `runtime.deobfuscate.plan`, `static.triage` | Passive plan with opt-in runtime gates; no live unpacking by default. |
| `similarity.family-cluster` | `similarity` | `sample.family.cluster` | `binary.diff.summary`, `kb.context.suggest`, `report.generate` | Corpus-local clustering; no private dataset or network requirement. |
| `malware.intel.feedback-loop` | `malware` | `malware.intel.loop` | `ioc.export`, `attack.map`, `sigma.rule.generate`, `yara.generate` | Offline evidence loop; no threat-intel network lookup by default. |
| `javascript.deobfuscation.jsvmp-triage` | `javascript-deobfuscation` | `javascript.obfuscation.profile` | `strings.extract`, `yara.generate`, `analysis.evidence.graph`, `report.generate` | Passive source/profile triage only; no JavaScript execution, Node/V8 start, network, or external deobfuscator invocation. |
| `jsvmp.bytecode.recovery-plan` | `jsvmp-analysis` | `jsvmp.bytecode.plan` | `strings.extract`, `yara.generate`, `analysis.evidence.graph`, `report.generate` | Plan-only bytecode/handler-map recovery; no JavaScript evaluation, interpreter-assisted normalization, Node/V8/browser start, or external backend invocation. |
| `revng.lift-decompile.plan` | `revng` | `revng.pipeline.plan` | `rizin.analyze`, `ghidra.analyze`, `retdec.decompile`, `analysis.evidence.graph` | Plan-only backend integration; no rev.ng process, lifting, decompile, execution, mount, or network. |
| `triton.symbolic.recovery-plan` | `triton` | `triton.symbolic.plan` | `constraint.extract`, `smt.solve`, `vm.workflow.plan`, `analysis.evidence.graph` | Plan-only symbolic workflow; no Triton/Unicorn emulation, solver run, live execution, or network. |
| `miasm.ir.deobfuscation-plan` | `miasm` | `miasm.ir.plan` | `code.function.cfg`, `constraint.extract`, `smt.solve`, `analysis.evidence.graph` | Plan-only IR/data-flow workflow; no Python backend start, IR lifting, symbolic execution, or network. |
| `lief.binary.structure-plan` | `lief` | `lief.binary.plan` | `pe.signature.verify`, `native.object.inventory`, `sbom.provenance.graph` | Plan-only LIEF integration; no binary modification, backend parsing, signing mutation, or network. |
| `radare2.cross-backend.plan` | `radare2` | `radare2.pipeline.plan` | `rizin.analyze`, `ghidra.analyze`, `retdec.decompile`, `analysis.evidence.graph` | Plan-only compatibility backend; no radare2 process, r2pipe command execution, debugger attach, or network. |
| `wabt.wasm.toolchain-plan` | `wabt` | `wabt.toolchain.plan` | `strings.extract`, `sbom.generate`, `wasm.runtime.plan`, `analysis.evidence.graph` | Plan-only WABT toolchain routing; no wasm2wat/wasm-objdump process, module instantiation, WASI grant, or network. |

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
| JavaScript, Node/browser bundles, source maps, JSVMP-like obfuscation | `javascript-deobfuscation`, `jsvmp-analysis`, `strings`, `yara`, `yara-x`, `bytecode` | Future JSIR/CASCADE, JSIMPLIFIER-style, REstringer, and handler-map workers must remain explicit opt-in backends | No JavaScript evaluation, Node/V8 start, browser automation, network lookup, or external deobfuscator invocation by default. |
| Advanced native lifting, symbolic execution, IR, and backend comparison workflows | `revng`, `triton`, `miasm`, `lief`, `radare2`, `vm-analysis`, `rizin`, `ghidra`, `retdec` | Future bounded workers only; runtime/emulation must be opt-in | Default tools emit backend plans and readiness metadata only; no heavy backend process, solver, emulator, binary mutation, or sample execution starts during discovery. |
| Firmware, containers, archives, native objects | `firmware`, `container-analysis`, `native-object`, `linux-package`, `windows-installer` | `qiling`, `linux-runtime`, `wasm-runtime` when applicable | No mount, extraction-to-execute path, package install, module insertion, or payload launch by default. |
| WASM/WASI | `wasm`, `wabt`, `strings`, `sbom` | `wasm-runtime` | No module instantiation, WABT process, wasmtime start, filesystem preopen, or network grant by default. |
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
