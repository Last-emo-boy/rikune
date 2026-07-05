# Rikune Plugin Catalog

Source: src/plugins, generated from current workspace.
Plugin count: 93
Tool count: 281

## android — Android / APK Analysis

- Domain: static
- Plugin function: APK manifest extraction, DEX decompilation, and packer detection
- Tools:
  - `apk.structure.analyze`: Analyze APK structure: manifest, DEX files, native libraries, signing info, and packer/hardening indicators.
  - `dex.decompile`: Decompile DEX/APK bytecode to Java source using JADX, optionally filtered by class name.
  - `dex.classes.list`: List class names defined in DEX bytecode from standalone DEX or embedded APK DEX files.
  - `apk.packer.detect`: Detect Android packer/hardening solutions such as 360, Bangbang, Legu, iJiaMi, Ali, and DexProtector.
  - `android.behavior.graph`: Build a passive static Android behavior graph from manifest/package/DEX/smali evidence and recommend hook/runtime-plan follow-ups.

## android-package — Android Package Inventory

- Domain: static
- Plugin function: Passive Android package and bytecode inventory with DEX, native library, signing, and split-package routing hints.
- Tools:
  - `android.package.inventory`: Passively inventory Android APK/AAB/APKS/XAPK/AAR and standalone DEX/OAT/VDEX/ODEX/ART files. Does not install, execute, connect to devices, or launch decompilers.

## android-runtime — Android Runtime Plan

- Domain: dynamic
- Plugin function: Passive Android runtime planning for ADB/emulator/Frida readiness, APK hook plans, and behavior evidence mapping.
- Tools:
  - `android.runtime.plan`: Build a passive Android dynamic-analysis plan for APK, AAB, split APKs, DEX/OAT/VDex, and native libraries across ADB, emulator, and Frida without installing, launching, or attaching.

## angr — angr

- Domain: static
- Plugin function: Symbolic execution and binary analysis via angr
- Tools:
  - `angr.analyze`: Run bounded angr static analysis against a sample. Use this when you explicitly want angr-backed CFG recovery or function discovery instead of the default Ghidra flow.

## api-hash — API Hash Resolution

- Domain: static
- Plugin function: Resolve shellcode API hashes (ROR13, CRC32, DJB2, etc.) against known hash databases.
- Tools:
  - `hash.resolve`: Resolve shellcode API hashes against known Windows API hash databases (ROR13, CRC32, DJB2, etc.).
  - `hash.identify`: Identify the hash algorithm used to produce shellcode API hashes by brute-force matching against known APIs.
  - `hash.resolver.plan`: Statically scan a sample for API resolver strings, PEB/module-walk hints, and hash-like constants, then produce a bounded resolver plan for hash.identify/hash.resolve and runtime breakpoint follow-up. Does not execute the sample.

## apk-smali — APK Smali Analysis

- Domain: static
- Plugin function: APK disassembly to Smali bytecode, resource decoding, and manifest parsing via apktool.
- Tools:
  - `apk.disassemble`: Disassemble an APK file into Smali bytecode via apktool. Lists Smali class files and provides previews.
  - `apk.manifest.parse`: Parse and decode AndroidManifest.xml from an APK, extracting permissions, components, and metadata.
  - `apk.resources.decode`: Decode and list resources from an APK (layouts, strings, drawables, etc.).

## apple-container — Apple Container Inventory

- Domain: static
- Plugin function: Passive Apple container inventory for IPA, DMG, PKG, app bundle, framework, and provisioning metadata without mount/install/device actions.
- Tools:
  - `apple.container.inventory`: Passively inventory Apple containers (IPA, DMG, PKG, app bundles) and route nested Mach-O candidates. Does not mount images, install packages, launch apps, or connect to devices.

## apple-signing — Apple Signing Inventory

- Domain: static
- Plugin function: Passive Apple signing, provisioning, entitlement, and bundle metadata inventory without codesign/keychain/device actions.
- Tools:
  - `apple.signing.inspect`: Passively inspect Apple code-signing, provisioning, entitlement, and bundle metadata hints without calling codesign, accessing keychains, mounting images, installing apps, or connecting devices.
  - `apple.security.profile`: Correlate Apple container, signing, entitlement, provisioning, and Mach-O hints into a passive macOS/iOS security profile. It recommends runtime plans without mounting DMG files, installing IPA/PKG payloads, calling codesign, or attaching to devices.

## batch — Batch Analysis

- Domain: both
- Plugin function: Multi-sample batch submission, monitoring, and result retrieval
- Tools:
  - `batch.submit`: Submit a batch of samples for parallel analysis through a tool pipeline. Returns a batch ID for tracking.
  - `batch.status`: Check the progress of a batch analysis job.
  - `batch.results`: Retrieve results of a completed batch analysis job.

## behavior-first — Behavior-First Analysis

- Domain: dynamic
- Plugin function: Behavioral-first analysis for opaque binaries: full behavioral capture (file/registry/network/process monitoring), IOC extraction, and network traffic analysis with C2 detection. Use when all other analysis approaches fail.
- Tools:
  - `behavior.capture`: Full behavioral capture: execute binary in Docker sandbox with comprehensive Frida instrumentation. Monitors file I/O, registry, network (DNS/HTTP/TCP), process creation, code injection, and API calls. Generates behavioral profile with risk classification and tags (persistence, process_injection, anti_debug, etc.). Use when static analysis is impossible due to heavy obfuscation/packing.
  - `behavior.ioc`: Extract IOCs (Indicators of Compromise) from behavioral capture data. Parses file operations, registry modifications, network traffic, and process creation events. Produces a structured IOC report with network indicators (IPs, domains, URLs), file indicators (dropped/deleted files), registry keys, and spawned processes. Feed behavior.capture output as behavior_data.
  - `behavior.network`: Deep network behavior analysis from behavioral capture data. Analyzes connection patterns, DNS resolution, HTTP requests, and applies C2 detection heuristics (single-IP beaconing, suspicious ports). Feed behavior.capture output as behavior_data.

## binary-diff — Binary Diff

- Domain: static
- Plugin function: Binary comparison and structural diff summaries
- Tools:
  - `binary.diff`: Compare two binary samples: function-level diff (via radiff2), structural delta (imports/exports/sections/strings), and ATT&CK technique delta. Produces a structured diff artifact.
  - `binary.diff.summary`: Produce a compact text digest (≤ 3000 chars) of a binary diff between two samples, focusing on the most significant changes. Requires binary.diff to have been run first.

## bytecode — Script Bytecode Inventory

- Domain: static
- Plugin function: Passive metadata inventory for Python PYC, Lua bytecode, and V8 cached data without interpreter execution.
- Tools:
  - `bytecode.metadata.inspect`: Passively inspect Python PYC, Lua bytecode, and V8 cached data metadata without starting an interpreter or decompiler.

## capstone — Capstone Disassembly

- Domain: static
- Plugin function: Lightweight multi-architecture disassembly for quick analysis of code snippets and shellcode
- Tools:
  - `disasm.quick`: Quickly disassemble bytes from a sample at a given offset. Uses Capstone — no Ghidra/Rizin needed. Ideal for entrypoints, shellcode snippets, and quick inspection.
  - `shellcode.disasm`: Disassemble raw shellcode from a sample using Capstone. Includes heuristic API call detection from call/jmp patterns.

## code-analysis — Code Analysis

- Domain: static
- Plugin function: Function listing, decompilation, disassembly, CFG, cross-references, reconstruction, renaming, explanation, and module review
- Tools:
  - `code.functions.list`: List all indexed functions for a binary sample. Supports Ghidra-extracted, PE metadata-recovered, or manually defined function indexes.
  - `code.functions.rank`: Rank indexed functions by interest score based on size, callers, sensitive API calls, and entry points. Works with Ghidra, recovered, or manually defined function indexes.
  - `code.functions.smart_recover`: Recover function candidates heuristically from PE runtime metadata such as .pdata / exception directory, exports, and entry point.
  - `code.functions.define`: Define or import function boundaries manually or from recovered metadata so code.functions.list/rank/reconstruct can use a non-Ghidra function index.
  - `code.functions.search`: Search functions by referenced API names or string literals. Uses Ghidra when available for string-to-function mapping and falls back to function-index API search otherwise. Use code.xrefs.analyze when you need bounded inbound/outbound relationship summaries instead of a simple function match list.
  - `code.xrefs.analyze`: Analyze bounded cross references for function, API, string, or data targets. Use this when you need indicator-to-function navigation before full reconstruction. Do not use it as a replacement for source-like export; continue with workflow.reconstruct or code.function.decompile after narrowing the target set.
  - `code.function.decompile`: Decompile a specific function to pseudocode. Requires prior Ghidra analysis. Provide either address or symbol name.
  - `code.function.disassemble`: Get assembly code for a function. Requires prior Ghidra analysis. Provide either address or symbol name.
  - `code.function.cfg`: Export a bounded function control-flow graph in json, dot, or mermaid format, with optional artifact-first SVG/PNG rendering. Mermaid and DOT are serializer choices over the same bounded graph semantics, not separate analysis goals. Use this after ghidra.analyze when you need graph structure or a report-friendly graph artifact before full reconstruction. Do not use it as a whole-program call graph; local caller/callee previews are bounded by depth and edge limit. Decision guide: - Use when: you need compact CFG structure, report-ready graph text, or artifact-first rendered SVG/PNG. - Do not use when: you need full source-like semantics; prefer code.function.decompile or workflow.reconstruct. - Typical next step: read the returned artifact_refs with artifact.read, or continue with code.function.decompile / workflow.reconstruct. - Common mistake: expecting render=svg/png to inline XML or binary output into the MCP response.
  - `code.functions.reconstruct`: Reconstruct function-level semantics by combining decompile, CFG, and assembly evidence with confidence and unresolved gaps.
  - `code.function.rename.prepare`: Prepare structured semantic-evidence bundles and a model-agnostic MCP prompt contract for external LLM function renaming review.
  - `code.function.explain.prepare`: Prepare a structured evidence bundle and MCP prompt contract so any tool-calling LLM can explain reconstructed functions and produce a universal output layer.
  - `code.function.explain.apply`: Persist structured function explanations returned by any external MCP client / LLM so export and report layers can consume them.
  - `code.module.review.prepare`: Prepare a structured module-level reconstruction bundle and MCP prompt contract so any tool-calling LLM can review grouped modules and refine rewrite guidance.
  - `code.module.review.apply`: Persist structured module review outputs returned by any external MCP client / LLM so export and workflow layers can consume them.
  - `code.function.rename.apply`: Persist structured semantic name suggestions returned by any external MCP client / LLM so reconstruct/export can reuse them.
  - `code.reconstruct.export`: Regroup recovered functions into source-like modules and export project skeleton with manifest and gaps.md.
  - `dotnet.reconstruct.export`: Export a maintainable C# reconstruction skeleton for .NET samples with confidence annotations and IL fallback guidance.
  - `code.reconstruct.plan`: Assess source-reconstruction feasibility and produce a phased reverse-engineering plan with confidence.
  - `code.cross_decompiler.consensus`: Compare fixture-safe outputs from multiple decompilers, disassemblers, and IR lifters to find stable facts, disagreements, backend coverage gaps, function evidence handoffs, and follow-up tools. Does not start external backends or execute samples.

## container-analysis — Container / Archive Inventory

- Domain: static
- Plugin function: Passive archive/container inventory with nested binary routing and extraction safety plan.
- Tools:
  - `container.structure.analyze`: Passively inventory archive/container files, detect nested binaries, flag extraction risks, and return an extraction plan without running payloads.

## crackme — CrackMe Automation

- Domain: static
- Plugin function: Validation routine location, symbolic execution, patching, and keygen verification
- Tools:
  - `crackme.locate.validation`: Automatically locate likely validation/serial-check functions in a CrackMe binary. Analyses string references ("Wrong"/"Correct"), dialog/input API imports, crypto API calls, and conditional branch patterns to rank candidate functions.
  - `symbolic.explore`: Run angr symbolic execution to find inputs reaching target addresses (CrackMe solving). Specify find_addresses (success path) and avoid_addresses (failure path). Returns concrete input values that satisfy path constraints.
  - `patch.generate`: Generate binary patches (NOP, JMP-always, invert-branch, custom bytes) for CrackMe bypass. Outputs IPS patch file and/or patched binary registered as a child sample.
  - `keygen.verify`: Verify a keygen-produced serial by emulating the target binary validation function. Feeds the serial (and optional username) into the binary via emulation and checks if the success path is taken.

## cross-module — Cross-Module Analysis

- Domain: static
- Plugin function: Cross-binary comparison, cross-module call graphs, and DLL dependency trees
- Tools:
  - `cross.binary.compare`: Compare two or more binaries to discover shared code (function hashes), common imported APIs, overlapping strings, and possible lineage/versioning relationships. Useful for malware family clustering and multi-component analysis.
  - `call.graph.cross.module`: Reconstruct a cross-module call graph by matching import entries in each binary to export entries in other binaries of the set. Produces a directed graph of inter-module dependencies with resolved function-level edges when available.
  - `dll.dependency.tree`: Build a dependency tree for a binary starting from its import table. Classifies each dependency as known-system, known-sample (in your collection), or unknown/suspicious. Flags potential DLL side-loading vectors.

## culifter — CuLifter GPU Plan

- Domain: static
- Plugin function: Passive CuLifter-style CUDA/SASS GPU binary lifting planning.
- Tools:
  - `culifter.gpu.plan`: Build a passive CuLifter-style GPU binary lifting plan for CUDA/SASS artifacts without running a lifter, GPU driver, profiler, or sample.
  - `culifter.gpu.artifact.inventory`: Inventory CUDA/SASS/PTX/fatbin candidates from local artifacts without requiring GPU drivers, profilers, or sample execution.

## debug-session — Debug Session

- Domain: dynamic
- Plugin function: Interactive debugging via GDB/LLDB — breakpoints, stepping, memory inspection
- Tools:
  - `debug.session.start`: Start an interactive GDB debug session for a sample. Supports ELF (direct GDB) and PE (via wine+GDB). Returns a session_id for subsequent debug commands.
  - `debug.session.breakpoint`: Manage breakpoints in a debug session: add (by address/symbol/condition), remove, or list all active breakpoints.
  - `debug.session.continue`: Continue execution in a debug session. Blocks until a breakpoint is hit, a signal is received, or timeout.
  - `debug.session.step`: Single-step execution in a debug session. Supports instruction-level stepping (into) and step-over mode.
  - `debug.session.inspect`: Inspect debug session state: registers, memory (up to 4096 bytes), stack frames (up to 20), or disassembly window.
  - `debug.session.end`: End a debug session: kill GDB, persist session trace as an artifact (breakpoint hits, register snapshots, history).
  - `debug.session.smart_breakpoint`: Automatically set intelligent breakpoints based on static analysis results. Strategies: crypto_intercept (break on CryptEncrypt/AES/RSA), network_monitor (break on connect/send/recv), unpack_oep (break at probable OEP), anti_debug (break on IsDebuggerPresent/NtQueryInformationProcess), string_decrypt (break at XOR/RC4 decryption loops), auto (all applicable).
  - `debug.session.snapshot`: Capture a structured snapshot of the debugger state: CPU registers, stack frames, memory map, loaded modules, and disassembly context around the instruction pointer. Designed for LLM consumption — all values are annotated with human-readable labels and semantic context.
  - `debug.session.watch`: Manage debug watchpoints: set hardware watchpoints on memory addresses, registers, or GDB expressions. Tracks value change history with timestamps. Actions: add (create watchpoint), remove (delete), list (show active), history (show value changes for a watch).

## deep-unpack — Deep Unpack

- Domain: static
- Plugin function: Multi-strategy deep unpacking for heavily packed/obfuscated binaries. Tries UPX → Speakeasy → Qiling → memory carve in sequence, supports up to 10 layers, with PE reconstruction and IAT fixing. Docker-priority.
- Tools:
  - `deep.unpack.pipeline`: Deep unpacking pipeline for heavily packed/obfuscated binaries. Tries multiple strategies in order (UPX �?Speakeasy emulation �?Qiling full emulation �?memory carve), supports up to 10 unpacking layers, auto-detects when unpacking is complete via entropy analysis. Best results in Docker environment with all backends available. Use when standard unpack.auto fails on custom/layered packers.
  - `deep.unpack.pe_reconstruct`: Reconstruct a valid PE from a memory dump or raw unpacked binary. Fixes section alignment, rebuilds PE headers, reconstructs IAT from API call traces, sets entry point and image base, recalculates checksum. Use after deep.unpack.pipeline or emulation-based unpacking.
  - `deep.unpack.dump_scan`: Scan a memory dump file for embedded PE images. Validates MZ/PE signatures, extracts each PE image, computes per-section entropy, and identifies PE type (PE32/PE32+). Useful for finding unpacked payloads in memory dumps from emulation or process hollowing detection.

## die — Detect It Easy

- Domain: static
- Plugin function: Deep signature-based identification of compilers, packers, linkers, and crypto using DIE
- Tools:
  - `die.scan`: Run a full Detect It Easy signature scan. Returns detailed compiler, packer, linker, and crypto detections with version info.
  - `die.identify`: Quick Detect It Easy identification — returns a compact list of detected signatures without full detail.

## dotnet-decompile — .NET Decompile

- Domain: static
- Plugin function: Full C# source code recovery from .NET assemblies using ILSpy CLI
- Tools:
  - `dotnet.decompile`: Decompile an entire .NET assembly to C# (or IL) source code using ILSpy CLI. Returns a preview and persists full output as artifact.
  - `dotnet.decompile.type`: Decompile a specific type (class) from a .NET assembly using ILSpy CLI. Use dotnet.types.list to discover type names first.

## dotnet-managed — .NET Managed Inventory

- Domain: static
- Plugin function: Passive .NET, Mono, NuGet, and WinMD metadata inventory without CLR execution or package restore.
- Tools:
  - `dotnet.assembly.inspect`: Passively inspect .NET PE-CLR, NuGet, Mono, and WinMD metadata without executing managed code or restoring packages.

## dotnet-reactor — .NET Reactor Deobfuscation

- Domain: static
- Plugin function: Analyze and deobfuscate .NET Reactor-protected assemblies — anti-tamper detection, string decryption, dynamic method recovery, and resource assembly export
- Tools:
  - `reactor.anti_tamper`: Detect .NET Reactor anti-tamper protection. Identifies cctor-based stubs, native code patches, integrity-check patterns, and module initializer hooks. Reports protection version estimate, stub offsets, and removal guidance.
  - `reactor.string_decrypt`: Track and decrypt .NET Reactor encrypted strings. Identifies delegate-based decryption proxies, resolves encrypted string tables, and decrypts via static pattern matching or dynamic sandbox execution. Returns original and decrypted string pairs with call-site locations.
  - `reactor.dynamic_methods`: Recover DynamicMethod and MethodBuilder bodies created by .NET Reactor at runtime. Combines static IL analysis with optional sandbox execution. Returns recovered method signatures, IL disassembly, and decompiled C# where possible.
  - `reactor.resource_export`: Extract and export embedded resource assemblies from .NET Reactor-protected binaries. Identifies encrypted/compressed satellite assemblies, payload DLLs, and packed dependencies. Attempts decryption and decompression, then saves recovered assemblies to the workspace for further analysis.

## dynamic — Dynamic Analysis Automation

- Domain: dynamic
- Plugin function: Automated Frida hooking, trace attribution, memory dumping, behavior capture, behavior diffing, dependency analysis, trace/memory import, sandbox execution, explicit runtime debug sessions, Hyper-V control, runtime toolkit inventory, runtime persona planning, CDB, ProcDump, telemetry, network lab, managed runtime, GUI handoff planning, deep dynamic planning, and dynamic runtime status aggregation
- Tools:
  - `dynamic.auto.hook`: Automatically generate Frida hook scripts based on static capability triage. Maps detected capabilities (file_manipulation, network_communication, etc.) to relevant API hooks with argument logging. Output can be directly used with frida.script.inject.
  - `dynamic.trace.attribute`: Attribute dynamic trace events (API calls, memory operations) to static analysis functions. Correlates return addresses in traces with Ghidra function boundaries to produce per-function behavior profiles.
  - `dynamic.memory.dump`: Smart memory dump during execution. Hooks VirtualAlloc/VirtualProtect to detect unpacking (RWX allocation, W→RX protection changes) and auto-dump memory regions at strategic moments. Useful for extracting unpacked code from packed/encrypted binaries.
  - `dynamic.dependencies`: Probe dynamic-analysis readiness across Speakeasy, Frida, Frida CLI, Qiling, angr, PANDA, Wine/winedbg, and related helper runtimes without executing the sample.
  - `dynamic.trace.import`: Import external runtime API traces or memory-snapshot summaries (Frida/Speakeasy/generic JSON) into the workspace and register them as MCP artifacts.
  - `dynamic.memory.import`: Import a minidump or raw process-memory snapshot, extract runtime-relevant strings/API evidence, and persist normalized memory-snapshot runtime artifacts.
  - `sandbox.execute`: Execute dynamic-analysis workflow in safe simulation mode (default), memory-guided mode, or Speakeasy user-mode emulation and return timeline/IOC/risk outputs.
  - `runtime.debug.session.start`: Start or attach to a runtime debug session. In remote-sandbox mode this asks the Windows Host Agent to start the selected backend (Windows Sandbox or Hyper-V VM) and returns a session id plus Runtime Node endpoint.
  - `runtime.debug.session.status`: Inspect runtime debug session health, tracked sessions, Host Agent backend state, and Runtime Node /health output.
  - `runtime.debug.session.stop`: Stop or release a runtime debug session through the Windows Host Agent. Hyper-V sessions honor Host Agent backend stop policy.
  - `runtime.debug.command`: Dispatch a Runtime Node command into an existing debug session. This reuses the Runtime Node /execute contract and supports debug.session.*, sandbox.execute, dynamic.behavior.capture, dynamic.memory_dump, managed.safe_run, and other advertised runtime handlers.
  - `dynamic.runtime.status`: Read-only dynamic runtime control-plane status. Aggregates configured Runtime Node health, Runtime Node capabilities, Windows Host Agent health, Hyper-V/Sandbox diagnostics, and persisted runtime debug sessions without launching a sandbox.
  - `dynamic.behavior.capture`: Execute a sample inside the configured Runtime Node and collect coarse behavior evidence: process observations, module loads, file snapshot deltas, stdout/stderr, and normalized runtime artifacts. Requires Sandbox, Hyper-V VM, or another Runtime Node backend.
  - `runtime.hyperv.control`: Control a configured Hyper-V Runtime VM through Windows Host Agent. Supports status, checkpoint listing, checkpoint creation, checkpoint restore, and VM stop without running a sample.
  - `dynamic.toolkit.status`: Read-only Runtime Node toolkit inventory for CDB/WinDbg, ProcDump, ProcMon, Sysmon, TTD, x64dbg, dnSpyEx, Frida, dotnet, and FakeNet-style tooling. Does not start Sandbox/Hyper-V or execute samples.
  - `dynamic.deep_plan`: Build a planning-only deep dynamic analysis profile covering behavior capture, CDB breakpoints, memory dumps, ProcMon/Sysmon/ETW-style telemetry, FakeNet-style network labs, .NET runtime debugging, anti-evasion hooks, TTD, x64dbg, and dnSpy. Does not launch or execute anything.
  - `debug.cdb.plan`: Build planning-only CDB automation command batches for API breakpoints, exception tracing, dump-on-break, module-load breakpoints, and injection watch profiles. Produces runtime.debug.command templates but does not start or execute a runtime.
  - `debug.procdump.plan`: Build planning-only Sysinternals ProcDump capture profiles for crash, first-chance exception, timeout, and PID snapshot dumps. Produces runtime.debug.command templates but does not start or execute a runtime.
  - `debug.telemetry.plan`: Build a planning-only telemetry capture plan for ProcMon, Sysmon, ETW process/DNS providers, and PowerShell event-log collection. Does not install services, start drivers, launch runtimes, or execute samples.
  - `debug.network.plan`: Build planning-only network lab profiles for proxy sinkholing, DNS/HTTP fake services, FakeNet-style tooling, and ETW DNS capture. Produces runtime.debug.command templates but does not start services or execute samples.
  - `debug.managed.plan`: Build planning-only .NET runtime debugging profiles for managed safe-run, SOS/CDB stack/object inspection, ProcDump follow-up, resource review, and dnSpyEx handoff. Produces runtime.debug.command templates but does not execute samples.
  - `debug.gui.handoff`: Build artifact-backed manual GUI debugging handoff notes for x64dbg, WinDbg, and dnSpyEx in visible Sandbox, Hyper-V VM, or manual runtime sessions. Does not launch GUI tools automatically.
  - `dynamic.persona.plan`: Build a planning-only runtime persona checklist for Windows Sandbox or Hyper-V: user profile files, RecentDocs, browser-like traces, timezone/locale hints, office artifacts, network persona, and interaction timing. Does not launch or modify any runtime.
  - `dynamic.behavior.diff`: Compare static behavior expectations from config/resource artifacts against runtime observations from dynamic traces. Produces confirmed behavior, dormant/missing expectations, unexpected runtime observations, and next runtime steps without executing the sample.

## elf-macho — ELF / Mach-O

- Domain: static
- Plugin function: Structure analysis and import/export extraction for Linux ELF and macOS Mach-O binaries
- Tools:
  - `elf.structure.analyze`: Analyze ELF binary structure: headers, sections, segments, symbols, dynamic entries.
  - `macho.structure.analyze`: Analyze Mach-O binary structure: load commands, sections, symbols. Handles fat (universal) binaries by listing all architectures.
  - `elf.imports.extract`: Extract ELF imports: DT_NEEDED shared libraries and imported symbols from .dynsym.
  - `elf.exports.extract`: Extract ELF exported symbols: globally visible symbols with non-zero addresses.

## external-re-bridge — External RE Bridge

- Domain: static
- Plugin function: Read-only BYO/sidecar bridge contract for IDA, Binary Ninja, Ghidra, and radare2 artifact exchange.
- Tools:
  - `external_re.bridge.sync`: Normalize read-only artifact manifests from local external RE MCP sidecars into cross-decompiler consensus inputs without contacting or starting the sidecar.

## firmware — Firmware Analysis

- Domain: static
- Plugin function: Firmware analysis, embedded file extraction, and entropy visualization using binwalk
- Tools:
  - `firmware.scan`: Scan a file with binwalk for embedded firmware signatures (file systems, kernels, compressed archives, etc.).
  - `firmware.extract`: Extract embedded files from a firmware image using binwalk. Returns a manifest of extracted files.
  - `firmware.entropy`: Compute block-level entropy of a firmware image using binwalk. Helps identify encrypted/compressed regions.
  - `firmware.workflow.plan`: Build a passive firmware/IoT workflow plan from firmware signatures, filesystem hints, package inventory, and architecture hints. It recommends SBOM and Qiling handoffs without extracting, mounting, or emulating firmware by default.

## frida — Frida Instrumentation

- Domain: dynamic
- Plugin function: Runtime instrumentation, script injection, and trace capture via Frida
- Tools:
  - `frida.runtime.instrument`: Instrument a Windows PE sample at runtime using Frida for dynamic API tracing and behavior analysis. Supports spawn and attach modes with pre-built or custom scripts.
  - `frida.script.inject`: Inject a custom or pre-built Frida JavaScript into a running process for dynamic analysis.
  - `frida.trace.capture`: Capture and normalize Frida traces with canonical schema, filtering, and aggregation.
  - `frida.script.generate`: Auto-generate Frida hook scripts from sample analysis evidence. Generates hooks for crypto APIs, network calls, file I/O, registry access, process manipulation, and anti-debug bypass. Uses import analysis and taint tracking results to target the most relevant APIs.

## ghidra — Ghidra Integration

- Domain: static
- Plugin function: Headless Ghidra analysis and health checks
- Tools:
  - `ghidra.analyze`: Start or reuse deep static analysis with Ghidra Headless to extract function indexes and unlock decompile/CFG workflows. Use this after a sample has been registered and you need code-level reverse engineering, not just quick profiling. Do not use this as the first host-file ingest step or as a health check. Decision guide: - Use when: you need function-level reverse engineering, decompilation, or reconstruction prerequisites. - Do not use when: the sample is not ingested yet or you only need a fast triage profile. - Typical next step: if status=queued, poll task.status(job_id); if completed/reused, continue with workflow.reconstruct, code.functions.list, or code.function.decompile. - Common mistake: assuming this tool is always synchronous and skipping task.status when a queue-backed client is active.
  - `ghidra.health`: Run a Ghidra environment health check plus optional end-to-end downstream probes using a real analyzed sample/project.

## go-analysis — Go Analysis

- Domain: static
- Plugin function: Go binary symbol and type recovery using Mandiant GoReSym
- Tools:
  - `go.symbols.recover`: Recover function symbols from a Go binary using GoReSym. Returns function names, addresses, and source file info.
  - `go.types.list`: List Go types (structs, interfaces) recovered from a Go binary using GoReSym.
  - `go.binary.analyze`: Comprehensive Go binary analysis: Go version, build info, packages, function & type recovery summary.

## graphviz — Graphviz

- Domain: static
- Plugin function: Graph rendering via Graphviz dot
- Tools:
  - `graphviz.render`: Render DOT graph text with Graphviz into SVG or PNG artifacts. This is a renderer/export helper over an existing graph, not the primary analysis or explanation surface. Use it when you explicitly want Graphviz output beyond code.function.cfg and need artifact-first graph rendering.

## gtirb — GTIRB IR Plan

- Domain: static
- Plugin function: Passive GTIRB binary IR and rewriting boundary planning.
- Tools:
  - `gtirb.ir.plan`: Build a passive GTIRB integration plan for binary IR, rewriting, and cross-backend comparison without invoking GTIRB tooling or mutating binaries.
  - `gtirb.ir.generate`: Generate or summarize read-only GTIRB-style IR artifacts from local binary artifacts through a bounded worker contract.

## host-correlation — Host Correlation

- Domain: static
- Plugin function: Auto-scan directory and system artifacts to correlate DLLs with host EXEs, scheduled tasks, services, startup entries, sideloading configs, and COM registration
- Tools:
  - `host.correlate`: Auto-scan directory and system artifacts to correlate a DLL/EXE with its host process, loader, and execution context. Checks co-located EXE import tables, scheduled tasks, services, startup entries, DLL sideloading configs, and COM registration to build a complete picture of how the sample is loaded and executed.

## ios-runtime — iOS Runtime Plan

- Domain: dynamic
- Plugin function: Passive iOS runtime planning for IPA hook plans, Frida/idevice readiness, provisioning gates, and method trace evidence.
- Tools:
  - `ios.runtime.plan`: Build a passive iOS dynamic-analysis plan for IPA, Mach-O, app bundles, provisioning profiles, and entitlements across Frida iOS and idevice tooling without installing or attaching to a device.

## javascript-deobfuscation — JavaScript Deobfuscation

- Domain: static
- Plugin function: Passive JavaScript, JSIR/CASCADE, REstringer, and JSVMP-oriented deobfuscation planning without script execution.
- Tools:
  - `javascript.obfuscation.profile`: Passively profile JavaScript obfuscation, VM-style dispatch, and JSVMP-like bytecode containers without evaluating the script or invoking Node/V8.

## jsimplifier — JSIMPLIFIER Pipeline Plan

- Domain: static
- Plugin function: Passive JSIMPLIFIER-style JavaScript deobfuscation pipeline planning.
- Tools:
  - `jsimplifier.pipeline.plan`: Build a passive JSIMPLIFIER-style JavaScript deobfuscation plan without dynamic tracing, LLM calls, network access, Node/V8 startup, or source evaluation.
  - `jsimplifier.pipeline.run`: Run a bounded JSIMPLIFIER-style static deobfuscation pipeline worker on local JavaScript artifacts without executing JavaScript.

## jsir-cascade — JSIR/CASCADE Plan

- Domain: static
- Plugin function: Passive JSIR/CASCADE-style JavaScript IR normalization and deobfuscation planning.
- Tools:
  - `jsir.cascade.plan`: Build a passive JSIR/CASCADE-style JavaScript normalization and deobfuscation plan without evaluating source, starting Node/V8, or invoking an external deobfuscator.
  - `jsir.cascade.normalize`: Normalize local JavaScript artifacts into a bounded JSIR/CASCADE-style static IR artifact without running Node, V8, or browser automation.

## jsvmp-analysis — JSVMP Analysis Plan

- Domain: static
- Plugin function: Passive JSVMP bytecode, dispatcher, handler-map, and semantics recovery planning for obfuscated JavaScript.
- Tools:
  - `jsvmp.bytecode.plan`: Build a passive JSVMP bytecode, dispatcher, handler-map, and semantics recovery plan without evaluating JavaScript or starting Node, V8, browser automation, or external deobfuscators.
  - `jsvmp.bytecode.recover`: Run a bounded static JSVMP bytecode recovery worker on local JavaScript artifacts. Builtin mode is fixture-safe; external mode requires JSVMP_WORKER_PATH.

## jvm — JVM Bytecode Inventory

- Domain: static
- Plugin function: Passive JVM bytecode and archive inventory for JAR, CLASS, WAR, AAR, JMOD, and Kotlin metadata.
- Tools:
  - `jvm.structure.analyze`: Passively inventory JVM artifacts (JAR, CLASS, WAR, AAR, JMOD, Kotlin metadata). Does not execute bytecode or launch a decompiler.

## kb-collaboration — Knowledge Base & Collaboration

- Domain: static
- Plugin function: Function signature matching, analysis templates, and knowledge base import/export/management
- Tools:
  - `kb.function.match`: Match function signatures from a sample against the knowledge base and other analyzed samples. Uses byte-pattern hashing and API-call fingerprinting to find reused code and propagate function names and annotations.
  - `analysis.template`: Get a recommended analysis plan from a pre-defined template. Returns an ordered list of tools to call for common workflows like malware triage, CrackMe solving, or APK analysis. Use with analyze.pipeline for automated execution.
  - `kb.import.bulk`: Bulk-import knowledge base entries from capa rules, MISP threat intel events, JSONL exports, or seed the built-in Windows API knowledge.
  - `kb.export`: Export knowledge base entries (function_kb and/or sample_kb) as JSONL for sharing or backup.
  - `kb.import`: Import a JSONL knowledge base file exported by kb.export, with configurable conflict resolution strategy.
  - `kb.stats`: Display knowledge base statistics: entry counts, source distribution, confidence histogram, and optional category breakdown.
  - `analysis.notes`: Analysis notebook system: add structured notes/findings to a sample, list all notes, search across notes, or export. Notes support categories (finding, hypothesis, IOC, technique, verdict), severity levels, tags, and cross-sample references. Findings are automatically indexed in the knowledge base for future reuse.
  - `rule.library`: Manage YARA and Sigma detection rule library: list rules across samples, get rule details, add tags/status labels, export in native formats, and view statistics. Integrates with yara.generate and sigma.rule.generate tools.
  - `kb.context.suggest`: Suggest local analysis-memory context for a sample: reusable function knowledge, notes, rule-library actions, and import/export follow-ups based on existing evidence tags. No network access is performed.

## lief — LIEF Binary Plan

- Domain: static
- Plugin function: Passive LIEF binary structure and transformation planning across PE, ELF, Mach-O, and object formats.
- Tools:
  - `lief.binary.plan`: Build a passive LIEF integration plan for binary structure, signatures, relocation, import/export, and safe transformation workflows without parsing or modifying the sample through LIEF.
  - `lief.binary.inspect`: Run a bounded read-only LIEF-style binary inspection worker for format, headers, imports, exports, relocations, and signature metadata. Mutation is excluded.

## linux-binary — Linux Binary Inventory

- Domain: static
- Plugin function: Passive Linux ELF/core/module/initramfs inventory with static routing hints and no execute/load/mount behavior.
- Tools:
  - `linux.binary.inventory`: Passively inventory Linux ELF executables, shared objects, core dumps, kernel modules, and initramfs/cpio images without executing, loading, mounting, or replaying content.

## linux-package — Linux Package Inventory

- Domain: static
- Plugin function: Passive Linux package inventory for deb, rpm, Alpine apk, snap, flatpak, and AppImage without executing installers or payloads.
- Tools:
  - `linux.package.inventory`: Passively inventory Linux package containers (deb, rpm, Alpine apk, snap, flatpak, AppImage). Does not install packages or execute maintainer scripts.

## linux-runtime — Linux Runtime Plan

- Domain: dynamic
- Plugin function: Passive Linux runtime planning for ELF emulation, debugger, syscall/library tracing, and optional kernel telemetry.
- Tools:
  - `linux.runtime.plan`: Build a passive Linux dynamic-analysis plan for ELF, shared objects, core dumps, and packages across Qiling, Unicorn, gdb, strace, ltrace, ptrace, seccomp, and eBPF without executing the sample.

## macos-runtime — macOS Runtime Plan

- Domain: dynamic
- Plugin function: Passive macOS runtime planning for Mach-O debugging, filesystem tracing, code-signing, and sandbox profile guidance.
- Tools:
  - `macos.runtime.plan`: Build a passive macOS dynamic-analysis plan for Mach-O, universal binaries, app bundles, frameworks, PKG, and DMG samples across LLDB, DTrace, fs_usage, codesign runtime checks, and sandbox-exec without executing the sample.

## malware — Malware Analysis

- Domain: static
- Plugin function: C2 extraction, config parsing, family classification, and sandbox report ingestion
- Tools:
  - `c2.extract`: Extract C2 (command & control) indicators from a binary: IP:port pairs, URLs, domains, and base64-encoded network addresses. Ranked by confidence.
  - `malware.config.extract`: Extract embedded malware configuration data. Supports known families: Cobalt Strike beacon, AsyncRAT, AgentTesla, Remcos, NjRAT, Emotet. Returns C2 addresses, ports, keys, mutexes, and family-specific settings.
  - `malware.classify`: Classify malware family using binary signature matching, string fingerprints, and behavioral pattern recognition. Returns ranked family matches with confidence scores.
  - `sandbox.report`: Generate a structured sandbox behavior report from dynamic execution evidence. Aggregates file, registry, network, process, and crypto operations into an analyst-facing behavior summary similar to commercial sandbox reports.
  - `malware.intel.loop`: Build a local malware intelligence feedback loop from config, C2, behavior, strings, and classification evidence. It normalizes IOC provenance, emits fusion and quality summaries, and prepares IOC, ATT&CK, Sigma/YARA, evidence graph, and report handoffs without online lookup.

## managed-fake-c2 — Managed Fake C2

- Domain: dynamic
- Plugin function: Configurable fake C2 server — set custom responses for endpoints like /plugin, /ping, /gate to drive malware samples into deeper operational logic during sandbox execution
- Tools:
  - `managed.fake_c2`: Start a configurable fake C2 server with custom endpoint responses. Configure responses for /plugin, /ping, /gate, /task, etc. to drive the sample into deeper operational logic. Captures all incoming requests for analysis. Supports TLS, response delays, and DNS redirection in sandbox.

## managed-il-xrefs — Managed IL Cross-References

- Domain: static
- Plugin function: IL-level cross-reference analysis — scan method bodies for stfld/ldfld/call sites, build bidirectional reference graphs, and resolve generic instantiation contexts
- Tools:
  - `managed.il_xrefs`: Scan all IL method bodies for cross-references to a given field, method, or type token. Reports stfld/stsfld/ldfld/ldsfld (fields), call/callvirt/newobj (methods), ldtoken/typeof (types). Handles generic context resolution.
  - `managed.token_xrefs`: Build a bidirectional cross-reference graph around a metadata token. Shows what references the token (incoming) and what the token references (outgoing). Supports transitive traversal up to 5 levels. Useful for call-chain analysis, field usage tracking, and type dependency mapping.

## managed-sandbox — Managed Sandbox

- Domain: dynamic
- Plugin function: Execute .NET assemblies in an isolated sandbox with network sinkholing, CLR hooks (Assembly.Load, CreateDecryptor, MethodInfo.Invoke), and dynamic-load capture
- Tools:
  - `managed.safe_run`: Execute a managed .NET assembly in an isolated sandbox with network sinkholing and CLR runtime hooks. Captures dynamically loaded assemblies, decryption calls, reflective invocations, and all outbound network requests. Supports configurable timeout, memory limit, and custom sinkhole responses.

## manifold — Manifold Decompilation Plan

- Domain: static
- Plugin function: Passive superset decompilation and fact-modeling planning.
- Tools:
  - `manifold.decompilation.plan`: Build a passive superset-decompilation and fact-modeling plan without running a decompiler, fact engine, lifter, or external backend.
  - `manifold.fact.extract`: Extract Manifold-style declarative reverse-engineering facts from local CFG/IR summaries through a bounded worker contract.

## memory-forensics — Memory Forensics (Volatility 3)

- Domain: static
- Plugin function: Memory dump analysis using Volatility 3 — process listing, DLL extraction, registry analysis, and memory-resident malware detection.
- Tools:
  - `memory-forensics.pslist`: List processes from a memory dump using Volatility 3.
  - `memory-forensics.dlllist`: List loaded DLLs from a memory dump.
  - `memory-forensics.malfind`: Detect injected code and suspicious memory regions in a memory dump.
  - `memory-forensics.netscan`: Scan for network connections in a memory dump.
  - `memory-forensics.hivelist`: List registry hives found in a memory dump.
  - `memory-forensics.cmdline`: Extract command-line arguments for all processes in a memory dump.
  - `memory-forensics.correlate`: Correlate existing Volatility JSON or fixture rows into an offline memory-forensics finding bundle with process, module, malfind, netscan, registry, command-line, IOC, timeline, and provenance views. This tool never invokes Volatility or touches live memory.

## metadata — File Metadata

- Domain: static
- Plugin function: Universal file metadata extraction using exiftool (works on PE, Office, PDF, images, and more)
- Tools:
  - `metadata.extract`: Extract universal file metadata using exiftool. Works on PE, ELF, Office docs, PDFs, images, archives, and more.

## miasm — Miasm IR Plan

- Domain: static
- Plugin function: Passive Miasm IR, data-flow, and symbolic workflow planning for obfuscated native code.
- Tools:
  - `miasm.ir.plan`: Build a passive Miasm integration plan for disassembly, IR lifting, data-flow, and symbolic execution without launching Python workers or executing the sample.
  - `miasm.ir.lift`: Run a bounded Miasm-style static IR lift worker for explicit functions, blocks, or shellcode windows. License-gated external mode requires MIASM_PYTHON.

## native-object — Native Object Inventory

- Domain: static
- Plugin function: Passive native object/static-library/debug-bundle inventory with safe routing hints for ELF, Mach-O, COFF, and kernel modules.
- Tools:
  - `native.object.inventory`: Passively inventory object files, static libraries, kernel modules, and debug bundles. Does not link, load, strip, sign, or execute content.

## observability — Observability

- Domain: both
- Plugin function: Tool invocation metrics and monitoring via lifecycle hooks
- Tools:
  - `observability.metrics`: Query tool invocation metrics — call counts, latencies, error rates. Powered by the plugin hook system.

## office-analysis — Office Analysis

- Domain: static
- Plugin function: VBA macro extraction, OLE structure analysis, and malicious Office document detection via oletools
- Tools:
  - `office.vba.extract`: Extract VBA macro source code from Office documents (.doc, .xls, .docm, .xlsm, etc.) using olevba.
  - `office.macro.detect`: Detect and classify malicious macros in Office documents. Returns risk level and specific threat indicators.
  - `office.ole.analyze`: Analyze OLE2 compound document structure: streams, embedded objects, ActiveX, and RTF objects.
  - `office.behavior.profile`: Build a passive Office document behavior profile from OLE/OOXML structure, VBA/XLM macro text, macro detector flags, static strings, and IOC-like evidence without automating Office or executing macros.

## panda — PANDA

- Domain: dynamic
- Plugin function: PANDA record/replay analysis for dynamic binary inspection
- Tools:
  - `panda.inspect`: Inspect PANDA/pandare runtime readiness and record/replay caveats. Use this when you explicitly request PANDA-oriented dynamic analysis support from the MCP server.

## pcap-analysis — PCAP Analysis

- Domain: static
- Plugin function: Network packet capture analysis and stream extraction using tshark
- Tools:
  - `pcap.analyze`: Analyze a PCAP file: protocol hierarchy, conversations, endpoints, packet count.
  - `pcap.dns.list`: Extract DNS queries and responses from a PCAP file.
  - `pcap.extract.streams`: Reassemble and extract TCP/UDP streams from a PCAP file.

## pe-analysis — PE Analysis

- Domain: static
- Plugin function: Windows PE structure analysis, import/export extraction, fingerprinting, and symbol recovery
- Tools:
  - `pe.structure.analyze`: Parse PE headers, sections, imports, exports, resources, and overlays through pefile and LIEF with a canonical MCP schema.
  - `pe.imports.extract`: 提取 PE 文件的导入表（DLL 和函数），支持按 DLL 分组
  - `pe.exports.extract`: Extract PE file export table (function names, ordinals, addresses, forwarders)
  - `pe.fingerprint`: 提取 PE 文件指纹信息（机器类型、子系统、时间戳、Imphash、节区熵值、签名）
  - `pe.pdata.extract`: Parse the PE exception directory / .pdata section and extract x64 RUNTIME_FUNCTION entries with unwind metadata.
  - `pe.symbols.recover`: Recover importable symbolic function names from PE runtime metadata such as .pdata / .xdata, exports, entry point, and language/runtime hints.

## pe-signature — PE Authenticode Signature

- Domain: static
- Plugin function: Verify PE Authenticode signatures and extract embedded certificates via osslsigncode.
- Tools:
  - `pe.signature.verify`: Verify PE Authenticode digital signature and show signer/issuer details.
  - `pe.certificate.extract`: Extract the Authenticode certificate chain from a signed PE file.

## qbdi — QBDI Instrumentation Plan

- Domain: static
- Plugin function: Passive QBDI dynamic binary instrumentation handoff planning.
- Tools:
  - `qbdi.instrumentation.plan`: Build a passive QBDI dynamic binary instrumentation handoff plan without loading a process, injecting instrumentation, or executing the sample.
  - `qbdi.trace.run`: Dispatch a QBDI trace request through an explicit opt-in delegated runtime worker contract. This local MCP server never starts QBDI directly.

## qiling — Qiling

- Domain: dynamic
- Plugin function: Qiling emulation framework for cross-platform binary emulation
- Tools:
  - `qiling.inspect`: Inspect Qiling readiness, configured rootfs state, and emulation prerequisites for a sample. Use this when you explicitly request Qiling-backed automation or need to verify rootfs prerequisites before emulation.

## radare2 — radare2 Pipeline Plan

- Domain: static
- Plugin function: Passive radare2 compatibility planning for cross-backend reverse-engineering comparison.
- Tools:
  - `radare2.pipeline.plan`: Build a passive radare2/r2pipe compatibility plan for cross-checking Rizin, Ghidra, and RetDec results without starting radare2 or analyzing the sample.
  - `radare2.pipeline.run`: Run a bounded radare2/r2pipe compatibility worker for read-only function, string, section, and xref summaries. Builtin mode is fixture-safe; external mode requires RADARE2_PATH.

## remill — Remill Lift Plan

- Domain: static
- Plugin function: Passive Remill LLVM bitcode lifting and instruction semantics planning.
- Tools:
  - `remill.lift.plan`: Build a passive Remill integration plan for lifting machine code to LLVM bitcode without running Remill, decoding a live target, or executing the sample.
  - `remill.lift.run`: Run a bounded Remill-style lift worker for explicit functions or address ranges; whole-program unbounded lifting is rejected by policy.

## reporting — Reporting

- Domain: both
- Plugin function: Report summarization, generation, and workflow summaries
- Tools:
  - `report.summarize`: Generate a bounded analyst-facing summary digest from triage/runtime/static context. Default detail_level=compact is the safe AI-facing mode and excludes heavyweight raw analysis trees. This is a compatibility summary surface, not the primary staged final-report workflow. Prefer workflow.summarize for staged final reporting, and use artifact.read / artifacts.list for deeper supporting detail. Read coverage_level, completion_state, known_findings, suspected_findings, unverified_areas, and upgrade_paths before treating the report as complete. Decision guide: - Use when: you want a deterministic compact report snapshot or compatibility with legacy report clients. - Best for: small/medium samples, quick analyst snapshots, or compact restatement of persisted fast/static evidence. - Large-sample pattern: keep detail_level=compact and prefer workflow.summarize for staged final output instead of requesting one large inline report. - Do not use when: you want the final multi-stage report synthesis path; prefer workflow.summarize. - Typical next step: call workflow.summarize for staged triage/static/deep/final digests, or artifact.read on returned artifact_refs for detail. - Common mistake: expecting compact mode to inline full static capability arrays, PE trees, or raw backend payloads.
  - `report.generate`: Export a comprehensive archival report artifact in Markdown, JSON, or HTML. This is an export-only surface over already persisted analysis state, not the primary AI-facing staged summary flow. Prefer workflow.summarize for staged analyst synthesis and report.summarize for deterministic compact compatibility snapshots.
  - `workflow.summarize`: Primary staged reporting workflow. Builds or reuses bounded triage/static/deep/final digest artifacts and returns compact final reporting output by stage. Prefer this over report.summarize when you need the final analyst-facing summary path without one monolithic payload. Read coverage_level, completion_state, known_findings, suspected_findings, unverified_areas, and upgrade_paths on the result before treating the summary as complete. Decision guide: - Use when: you want staged digest artifacts, resumable summary generation, or a final compact summary. - Best for: medium/large samples or any run that already progressed through queued analysis stages. - Do not use when: you only need a single deterministic digest snapshot; report.summarize is enough. - Typical next step: use artifact.read or artifacts.list on returned stage_artifacts for supporting detail. - Common mistake: expecting the workflow to inline raw backend payloads instead of returning digest artifacts.

## restringer — REstringer Plan

- Domain: static
- Plugin function: Passive REstringer JavaScript string-array and expression deobfuscation planning.
- Tools:
  - `restringer.deobfuscation.plan`: Build a passive REstringer integration plan for JavaScript string-array and expression deobfuscation without evaluating JavaScript or invoking the external tool.
  - `restringer.deobfuscation.run`: Run a bounded REstringer-style static JavaScript preprocessing worker on local artifacts. Builtin mode uses safe deterministic fixture logic; external mode requires RESTRINGER_PATH.

## retdec — RetDec

- Domain: static
- Plugin function: RetDec decompiler for binary-to-C decompilation
- Tools:
  - `retdec.decompile`: Decompile a sample with RetDec and persist the generated high-level output as an artifact. Use this when you explicitly want a RetDec alternative to the default Ghidra-oriented flow.

## revng — rev.ng Pipeline Plan

- Domain: static
- Plugin function: Passive rev.ng binary lifting and decompilation planning for cross-backend reverse engineering.
- Tools:
  - `revng.pipeline.plan`: Build a passive rev.ng integration plan for binary lifting, model recovery, CFG/export correlation, and decompilation without starting revng or processing the sample.

## rizin — Rizin

- Domain: static
- Plugin function: Rizin reverse engineering framework for binary analysis
- Tools:
  - `rizin.analyze`: Run bounded Rizin inspection on a sample for info, sections, imports, exports, entrypoints, functions, or strings. Use this when you explicitly want Rizin-backed inspection instead of the default workflow backends.

## runtime-deobfuscate — Runtime Deobfuscation

- Domain: dynamic
- Plugin function: Dynamic deobfuscation: runtime string decryption via Frida hooks, dynamic API resolution capture, CFG recovery from execution traces, and .NET deobfuscation via de4dot. Docker-priority.
- Tools:
  - `deobf.strings`: Runtime string decryption: hooks CryptDecrypt, XOR loops, VirtualAlloc, and custom decryption routines via Frida. Captures decrypted strings as the binary executes. Use when static FLOSS/string extraction returns only encrypted/obfuscated strings. Requires Frida + Wine (Docker recommended).
  - `deobf.api_resolve`: Capture dynamically resolved APIs: hooks GetProcAddress, LdrGetProcedureAddress, and LoadLibrary* via Frida. Builds a complete IAT map showing which DLLs are loaded and which APIs are resolved at runtime. Essential for understanding obfuscated import tables. Output can be fed into deep.unpack.pe_reconstruct for IAT fixing.
  - `deobf.cfg_trace`: CFG recovery from execution trace: uses Frida Stalker to instrument all branches, records every executed basic block, and reconstructs the actual control flow graph. Defeats control-flow flattening, opaque predicates, and bogus branches by showing only paths that were actually taken during execution.
  - `deobf.dotnet`: Deobfuscate .NET assemblies using de4dot. Performs string decryption, control flow deobfuscation, delegate restoration, and anti-tamper removal. Supports ConfuserEx, .NET Reactor, Dotfuscator, Babel, Crypto Obfuscator, DeepSea, Agile, Goliath, MaxtoCode, Eazfuscator, and SmartAssembly. Produces a clean deobfuscated assembly for further static analysis.

## sbom — SBOM

- Domain: static
- Plugin function: Software Bill of Materials (SBOM) generation from binary analysis
- Tools:
  - `sbom.generate`: Generate a Software Bill of Materials (SBOM) for a binary sample. Extracts component dependencies from PE imports, .NET assemblies, embedded resources, and static analysis results. Output in CycloneDX JSON or SPDX-lite format.
  - `sbom.provenance.graph`: Build a deterministic supply-chain provenance graph from local package, container, installer, Android, firmware, and SBOM inventory rows. It merges duplicate components and preserves evidence sources without installing, mounting, executing, or fetching vulnerability data.

## similarity — Sample Similarity

- Domain: static
- Plugin function: Fuzzy hashing (ssdeep, TLSH) for sample similarity analysis and malware family clustering
- Tools:
  - `sample.similarity`: Compute ssdeep and TLSH fuzzy hashes for a sample. Optionally compare against a second sample.
  - `sample.cluster.fuzzy`: Cluster multiple samples by ssdeep fuzzy hash similarity. Identifies malware families and variants.
  - `sample.family.cluster`: Build deterministic sample-family clusters from existing hash, fuzzy hash, import, string, function, and binary diff evidence. It is fixture-friendly and does not require ssdeep/TLSH native backends.

## speakeasy — Speakeasy Emulator

- Domain: dynamic
- Plugin function: Windows user-mode emulation for PE files and shellcode via Mandiant Speakeasy
- Tools:
  - `speakeasy.emulate`: Emulate a Windows PE file using Mandiant Speakeasy. Captures API calls, file/registry/network activity without native execution.
  - `speakeasy.shellcode`: Emulate raw shellcode bytes from a sample using Speakeasy. Specify architecture and optional offset.
  - `speakeasy.api_trace`: Run Speakeasy emulation and extract a focused API call trace with optional module/API name filtering.

## static-triage — Static Triage

- Domain: static
- Plugin function: First-pass static analysis including runtime detection, packer ID, capability triage, binary profiling, resource graphing, config carving, behavior classification, crypto detection, entropy analysis, and obfuscation detection
- Tools:
  - `analysis.context.link`: Build compact intermediate analyst context by merging strings.extract, strings.floss.decode, and bounded xref correlation. Use this after quick triage when you need indicator-to-function context before full reconstruction. Prefer mode=preview first; reserve mode=full for cases where FLOSS plus function-aware attribution is actually needed.
  - `runtime.detect`: 自动检测 PE 文件的运行时类型（.NET、C++、Go 等），解析 CLR 头部并返回置信度分数
  - `dotnet.metadata.extract`: Extract managed assembly metadata (assembly refs, types, methods, resources, DLL/EXE role) for .NET samples without executing them.
  - `dotnet.types.list`: List managed types from CLR metadata, with optional namespace filtering and per-method rows.
  - `packer.detect`: 自动检测 PE 文件是否加壳，使用 YARA 规则、节区熵值分析和入口点检查来识别常见加壳器（如 UPX、Themida、VMProtect）
  - `static.capability.triage`: Analyze executable behavior capabilities with a capa-style backend and return normalized capability groups, behavior/config/crypto/packer correlation bundles, evidence summaries, workflow handoffs, and setup guidance.
  - `compiler.packer.detect`: Identify likely compiler, packer, protector, and file-type signatures with a Detect It Easy-style backend, normalized MCP output, evidence handoff, and passive workflow routing.
  - `binary.role.profile`: Summarize Windows PE role, export surface, DLL/COM/service/plugin indicators, and analysis priorities for EXE/DLL-like samples. Start with mode=fast for normal or large samples, then escalate to mode=full only when export/import/string correlation must be complete.
  - `crypto.identify`: Correlate imports, enriched strings, bounded xrefs, capability hints, and optional runtime evidence into compact crypto findings with typed key/table summaries. Use this when a sample looks crypto-heavy and you need function-localized evidence before breakpoint planning. Prefer mode=preview first; use mode=full only when decoded-string and deeper context correlation are worth the extra cost.
  - `breakpoint.smart`: Rank crypto and sensitive-API breakpoint candidates from compact static and optional dynamic evidence without executing instrumentation. Use this after crypto.identify when you want a planning-first breakpoint shortlist before building a trace plan.
  - `trace.condition`: Compile a bounded conditional trace plan from a smart breakpoint candidate without executing instrumentation. Use this after breakpoint.smart to define capture scope, hit limits, and the recommended Frida-oriented runtime path.
  - `dll.export.profile`: Profile DLL-like export surfaces, dispatch models, DllMain lifecycle hints, and plugin/host callback patterns for PE samples.
  - `com.role.profile`: Profile COM-oriented PE samples, including class factory exports, CLSID/ProgID strings, registration hints, and likely activation flow.
  - `rust_binary.analyze`: Analyze Rust-oriented PE binaries by correlating runtime hints, crate/toolchain strings, smart function recovery, and recovered symbol names.
  - `entropy.analyze`: Compute byte-level and section-level Shannon entropy for a binary sample. Identifies packed regions, encrypted data, and high-entropy anomalies. Outputs per-section entropy, a block histogram, and packing/crypto likelihood classification.
  - `obfuscation.detect`: Detect obfuscation techniques applied to a binary: control flow flattening, opaque predicates, string encryption, import obfuscation (API hashing), junk code insertion, anti-disassembly tricks, and .NET-specific obfuscation (name mangling, ConfuserEx/.NET Reactor markers). Returns a scored assessment with per-technique confidence and remediation guidance.
  - `taint.track`: Perform static taint tracking: identify source APIs (network, file, registry, user_input), sink APIs (exec, write, send, crypto), and enumerate data-flow taint paths between them. Returns risk-scored paths to highlight critical data flows in the sample.
  - `static.resource.graph`: Build a compact PE resource and embedded-payload graph from sample bytes. Identifies resource leaf size, entropy, magic, hashes, strings, executable-like blobs, and recommended follow-up tools without executing the sample.
  - `static.config.carver`: Carve generic malware/configuration candidates from raw sample bytes: URLs, domains, IPs, ports, registry paths, mutex-like values, user agents, encoded blobs, and suspicious configuration strings. Does not execute the sample.
  - `static.behavior.classify`: Classify static persistence, service install, scheduled task, WMI, process injection, DLL injection, APC injection, and hollowing indicators from strings, config artifacts, and optional imported runtime evidence. Does not execute the sample.

## strings — Strings Extraction

- Domain: static
- Plugin function: Extract printable strings and decode obfuscated strings via FLOSS
- Tools:
  - `strings.extract`: Extract readable strings from a sample and return compact IOC-aware grouping plus enriched analyst labels. Use this for fast string triage; use analysis.context.link when you need merged FLOSS output and function-aware attribution before full reconstruction. On medium/large samples, prefer mode=preview first and only escalate to mode=full when the workflow explicitly needs complete extraction.
  - `strings.floss.decode`: Decode obfuscated strings with FLOSS and return compact enriched analyst labels for decoded output. Use this when you suspect stack/tight/decoded strings; use analysis.context.link to merge FLOSS output with raw strings and function attribution.

## threat-intel — Threat Intelligence

- Domain: static
- Plugin function: MITRE ATT&CK technique mapping, IOC export (JSON, CSV, STIX2), and Sigma rule generation
- Tools:
  - `attack.map`: Generate MITRE ATT&CK technique mapping from triage indicators with evidence-linked confidence scoring. Medium and larger samples may return a background job_id; use analysis.context.get before rerunning to discover prior ATT&CK maps, active jobs, and cached context.
  - `ioc.export`: Export normalized IOC data and optional ATT&CK mapping as JSON, CSV, or STIX 2.1 bundle.
  - `sigma.rule.generate`: Auto-generate Sigma detection rules from sample analysis evidence. Creates rules for process creation, file events, registry modifications, network connections, DNS queries, and DLL loads. Uses strings, imports, and behavioral evidence to build detection logic.

## triton — Triton Symbolic Plan

- Domain: static
- Plugin function: Passive Triton symbolic execution and taint-analysis planning for bounded reverse-engineering workflows.
- Tools:
  - `triton.symbolic.plan`: Build a passive Triton integration plan for instruction semantics, taint, symbolic execution, and path-constraint recovery without emulating or executing the sample.
  - `triton.symbolic.slice`: Run a bounded Triton-style symbolic slice worker for selected instructions or basic blocks. It refuses unbounded emulation and defaults to fixture-safe builtin mode.

## unity-managed — Unity Managed Inventory

- Domain: static
- Plugin function: Passive Unity metadata, Mono assembly, and IL2CPP bridge inventory without Unity runtime execution.
- Tools:
  - `unity.metadata.inspect`: Passively inspect Unity global-metadata.dat, IL2CPP, and managed assembly layout without starting Unity or loading native code.

## unpacking — Unpacking

- Domain: static
- Plugin function: Automated unpacking, child-sample handoff, and packer-specific unpacking guidance
- Tools:
  - `unpack.auto`: Automatically unpack a packed binary using the best available backend (UPX, Speakeasy memory dump, or Qiling OEP dump). Reads packer detection results from prior analysis, selects the optimal unpack strategy, executes it, and registers the unpacked binary as a child sample. Supports multi-layer unpacking up to 3 iterations.
  - `unpack.guide`: Provide step-by-step unpacking guidance for a packed binary. Uses packer detection results to identify the protector and generates tailored instructions, tool recommendations, and references. Covers UPX, Themida, VMProtect, .NET Reactor, ConfuserEx, ASPack, PECompact, and more.
  - `unpack.child.handoff`: Carve embedded payload candidates from static resource graph artifacts, raw sample bytes, and imported memory/raw dump artifacts, then optionally register bounded child samples with provenance. Does not execute the sample.
  - `unpack.workflow.plan`: Build a detect-to-plan-to-dump-to-reconstruct-to-retriage unpacking workflow from static packer/protector evidence. It adds packer confidence, evidence provenance, runtime opt-in gates, and re-triage handoffs without starting a debugger, emulator, or sample.

## upx — UPX

- Domain: static
- Plugin function: UPX packer/unpacker for executable compression analysis
- Tools:
  - `upx.inspect`: Inspect or decompress a sample with UPX. Use this when you explicitly want UPX-aware packed-sample checks rather than generic packer heuristics.

## visualization — Visualization & Reporting

- Domain: static
- Plugin function: HTML report generation, behavior timelines, data-flow maps, evidence graphs, and crypto lifecycle graphs
- Tools:
  - `report.html.generate`: Generate a self-contained HTML report for a sample analysis. Aggregates all available evidence into a professional report with overview, static analysis, dynamic behavior, strings, IoCs, and threat scoring sections.
  - `behavior.timeline`: Build a temporal timeline of behavioral events from dynamic analysis traces. Groups API calls by time intervals, highlights phase transitions (init → network → persistence → payload), and identifies behavioral bursts.
  - `data.flow.map`: Map data flow through a binary by correlating API call sequences from static imports and dynamic traces. Identifies data transformation chains (read → decrypt → decompress → execute) and data exfiltration paths.
  - `analysis.evidence.graph`: Build a compact evidence graph that links specialist static artifacts, plugin evidence handoffs, static expectations, dynamic trace observations, reporting handoffs, and corroboration edges. Does not execute the sample.
  - `crypto.lifecycle.graph`: Build a crypto lifecycle graph from crypto.identify artifacts and imported runtime evidence, linking algorithms, functions, APIs, constants, stages, and memory regions. Does not execute the sample.

## vm-analysis — VM Analysis & Symbolic

- Domain: static
- Plugin function: Virtual-machine protection analysis, constraint extraction, SMT solving, keygen synthesis, and MBA simplification
- Tools:
  - `vm.workflow.plan`: Build a passive VM-protection and symbolic-analysis workflow plan. It recommends the VM detection, opcode extraction, emulation, constraint extraction, SMT solving, keygen, and MBA simplification sequence without running solvers or emulators.
  - `vm.detect`: Detect virtual machine (VM) based protection in a binary. Scores functions for VM-like patterns (dispatch loops, bytecode fetches, handler tables) and classifies VM components.
  - `vm.pattern.analyze`: Deep analysis of VM protection patterns in specific functions. Provides per-heuristic scoring breakdown (loop-switch, bytecode fetch, PC increment, handler regularity, opcode range) and component role classification.
  - `vm.opcode.extract`: Extract the opcode table from a VM dispatch function. Parses switch/case handlers, classifies semantic categories (arithmetic, logic, memory, control flow), and detects instruction formats.
  - `vm.disasm.build`: Build a custom disassembler from a VM opcode table (extracted by vm.opcode.extract) and disassemble VM bytecode. Supports direct hex input or file offset.
  - `vm.emulate`: Emulate VM bytecode with concrete or symbolic execution. Requires a previously extracted opcode table. Produces an execution trace with register states per step and extracted constraints.
  - `vm.semantic.diff`: Compare opcode tables from two VM-protected samples to detect renamed opcodes, trap insertions (bit-width changes, operand swaps), and semantic differences.
  - `constraint.extract`: Extract mathematical constraints from a VM emulation trace. Produces constraints in IR form and a Z3 Python solver script.
  - `smt.solve`: Solve constraints using Z3 SMT solver. Uses previously extracted constraints or a custom Z3 script. Returns satisfiability result and variable solutions.
  - `keygen.synthesize`: Synthesize a forward keygen (Python script) from extracted VM constraints. Analyzes dependency chains, detects non-invertible operations, and generates sequential computation code.
  - `mba.simplify`: Simplify Mixed Boolean-Arithmetic (MBA) obfuscated expressions to their canonical forms. Applies algebraic identities like (a+b)-2*(a&b) → a^b, DeMorgan laws, constant folding, and more.

## vuln-scanner — Vulnerability Scanner

- Domain: static
- Plugin function: CWE-based vulnerability pattern scanning on decompiled code
- Tools:
  - `vuln.pattern.scan`: Scan decompiled functions for CWE vulnerability patterns (buffer overflow, format string, command injection, DLL hijacking, integer overflow, use-after-free).
  - `vuln.pattern.summary`: Summarize vulnerability scan findings: aggregate by CWE, rank most vulnerable functions, compute severity distribution.

## wabt — WABT Toolchain Plan

- Domain: static
- Plugin function: Passive WABT WebAssembly toolchain planning for wasm2wat, wasm-objdump, wasm-decompile, wasm2c, and WASI review.
- Tools:
  - `wabt.toolchain.plan`: Build a passive WABT integration plan for wasm2wat, wasm-objdump, wasm-decompile, wasm2c, and WASI capability review without instantiating or executing the module.
  - `wabt.toolchain.run`: Run a bounded WABT read-only toolchain worker for wasm section, WAT, objdump, validation, and wasm2c planning artifacts without instantiating the module.

## wasm — WebAssembly Inventory

- Domain: static
- Plugin function: Passive WebAssembly/WASI section, import/export, and capability inventory without module instantiation.
- Tools:
  - `wasm.structure.analyze`: Passively analyze WebAssembly module structure, sections, imports/exports hints, and WASI capability hints without executing the module.

## wasm-runtime — WASM Runtime Plan

- Domain: dynamic
- Plugin function: Passive WASM/WASI runtime planning for wasmtime readiness, capability review, and import/export behavior mapping.
- Tools:
  - `wasm.runtime.plan`: Build a passive WebAssembly/WASI runtime plan for wasmtime-backed capability review and import/export behavior mapping without instantiating the module.

## windows-debug-symbols — Windows Debug Symbols Inventory

- Domain: static
- Plugin function: Passive PDB, COFF object, and COFF library metadata inventory without symbol server download.
- Tools:
  - `windows.debug.metadata.inspect`: Passively inspect PDB, COFF object, and COFF library metadata without contacting symbol servers.

## windows-installer — Windows Installer Inventory

- Domain: static
- Plugin function: Passive Windows installer inventory for MSI, MSIX, APPX, CAB, NSIS, and Inno without installer execution.
- Tools:
  - `installer.inventory`: Passively inventory Windows installers (MSI, MSIX, APPX, CAB, NSIS, Inno) without installing packages or executing custom actions.

## windows-runtime — Windows Runtime Plan

- Domain: dynamic
- Plugin function: Passive Windows runtime planning for Sandbox, Hyper-V, host-agent, Wine, Speakeasy, debugging, and telemetry evidence.
- Tools:
  - `windows.runtime.plan`: Build a passive Windows dynamic-analysis plan for PE/.NET binaries across Windows Sandbox, Hyper-V, host-agent, Wine, and Speakeasy without executing the sample.

## wine — Wine

- Domain: dynamic
- Plugin function: Wine Windows compatibility layer — prefix management, DLL overrides, registry manipulation, and supervised execution of PE binaries
- Tools:
  - `wine.run`: Preflight or run a sample under Wine or winedbg. Use this only when you explicitly request Linux-hosted Wine debugging or execution; run/debug modes require approved=true.
  - `wine.env`: Manage Wine prefixes — create isolated environments, inspect existing ones, list all, or remove. Each prefix is a separate Windows filesystem for clean analysis.
  - `wine.dll_overrides`: Configure DLL load-order overrides in a Wine prefix. Set native/builtin/disabled per DLL — useful for hooking, anti-analysis bypass, or forcing specific API implementations.
  - `wine.reg`: Query, set, or export Wine registry keys in a prefix. Useful for pre-populating environment data (anti-VM bypass) or inspecting registry changes after execution.

## yara — YARA

- Domain: static
- Plugin function: YARA rule scanning and generation (single and batch)
- Tools:
  - `yara.scan`: 使用 YARA 规则扫描样本，识别已知的恶意软件家族和加壳器
  - `yara.generate`: Auto-generate YARA detection rules from sample analysis evidence (strings, imports, byte patterns). Supports tight/balanced/loose strictness levels.
  - `yara.generate.batch`: Generate YARA family detection rules by finding common unique features across multiple samples.

## yara-x — YARA-X

- Domain: static
- Plugin function: YARA-X next-gen pattern matching for malware detection
- Tools:
  - `yara_x.scan`: Scan a sample with YARA-X using inline rules or a rules file. Use this when you explicitly want the newer YARA-X engine instead of the legacy yara.scan path.
