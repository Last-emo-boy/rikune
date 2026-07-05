# Rikune 插件矩阵与 SDK 迭代详细方案

## 1. 目标边界

这轮迭代不再只做少量 SDK 和 manifest 任务，而是把插件体系扩成一个可持续增长的矩阵：

- SDK 层：提供稳定的 authoring API、manifest v2、aspect taxonomy、runtime contract、artifact/evidence facade、test harness 和 scaffold templates。
- 静态插件层：覆盖常用二进制、移动包、托管运行时、脚本字节码、固件、安装包和容器格式。
- 动态插件层：覆盖 Windows、Linux、macOS、Android/iOS 的 runtime 能力，但默认只做 passive readiness，不在 CI 或默认流程里执行 live sample。
- 发现与路由层：通过 aspect 把 `sample.profile`、`tools.discover`、`tool.help`、`tool.readiness`、`plugin.list` 串起来。
- 质量层：所有新增插件都有 fixtures、qualityWarnings、输出 schema、artifact provenance 和兼容性守卫。

## 2. SDK 需要包含的内容

### 2.1 Authoring API

- `definePlugin`：继续支持手写插件，适合内置插件和复杂 register 流程。
- `defineTool`：统一 tool definition、input/output schema、runtime contract、artifact/evidence metadata。
- `defineManifestPlugin`：支持 `plugin.json` 或 manifest-backed 插件，适合第三方插件和 scaffold 输出。
- `validatePlugin` / `validateTool`：用于测试、discovery 和 release guard。
- `src/plugins/sdk.ts`：继续作为内部兼容 re-export，不强迫已有插件改 import。

### 2.2 Manifest v2

Manifest v2 应包含但不强制已有插件一次性补齐：

- `id`、`name`、`version`、`description`
- `executionDomain`: `static`、`dynamic`、`both`
- `aspects`: 格式、平台、架构、runtime、安全策略、能力和证据形态
- `surfaceRules`: tier、category、activateOn、extractSignals
- `tools`: name、description、inputSchema、outputSchema、runtime、artifacts、evidence
- `systemDeps`: binary/file/docker/runtime 依赖
- `quality`: qualityWarnings、statusDetail、fixture coverage hints

缺字段先产生 `qualityWarnings`，不要直接让现有插件启动失败。

### 2.3 Aspect 模型

Aspect 是这轮插件扩展的核心。建议在 SDK 中做成可验证、可组合、可 passthrough 的对象：

| 维度 | 示例 | 用途 |
| --- | --- | --- |
| `format` | `pe`、`coff`、`pdb`、`elf`、`macho`、`ipa`、`apk`、`aab`、`apks`、`xapk`、`dex`、`oat`、`jar`、`class`、`dotnet`、`wasm`、`pyc`、`firmware`、`archive`、`container` | 决定工具是否匹配样本 |
| `platform` | `windows`、`linux`、`macos`、`ios`、`android`、`jvm`、`dotnet`、`wasm`、`embedded` | 决定 runtime、文档和 tool surface |
| `architecture` | `x86`、`x64`、`arm`、`arm64`、`mips`、`riscv`、`wasm` | 决定 disassembler、emulator、debugger |
| `execution` | `static`、`dynamic`、`emulation`、`decompilation`、`triage`、`correlation` | 区分静态和动态插件 |
| `runtime` | `local`、`docker`、`windows-sandbox`、`wine`、`qiling`、`frida`、`adb`、`lldb`、`gdb`、`strace`、`dtrace`、`wasmtime` | 对接 readiness 和 runtime-node |
| `safety` | `passive`、`opt_in_dynamic`、`requires_isolation`、`no_live_sample_by_default` | 避免默认执行不安全行为 |
| `capability` | `structure`、`imports`、`exports`、`symbols`、`strings`、`resources`、`behavior` | 给工具发现和推荐使用 |
| `evidence` | `artifact`、`timeline`、`ioc`、`network`、`filesystem`、`registry`、`memory` | 统一报告和关联输出 |

## 3. 插件扩展方向

### 3.1 静态插件 catalog

静态插件优先覆盖可离线解析、可 fixtures 验证、不会执行样本的能力。一个平台大类下面可以拆多个插件，避免 `android`、`elf-macho` 这类目录变成不可维护的巨型插件。

| 插件方向 | 主要格式 | 关键 tools | 产物/evidence | 任务落点 |
| --- | --- | --- | --- | --- |
| `windows-pe-core` | `pe`、`dll`、`sys`、`scr`、`efi` | `pe.structure.analyze`、`pe.imports.extract`、`pe.exports.extract`、`pe.resources.list` | sections、imports、exports、resources、TLS、overlay、rich header | `TASK-007` |
| `windows-debug-symbols` | `pdb`、CodeView、source link | `pdb.metadata.extract`、`pdb.source-map.plan` | GUID/age、streams、source refs、symbol coverage | `TASK-007` |
| `windows-installer` | `msi`、`msix`、`appx`、`cab`、NSIS、Inno | `installer.inventory`、`installer.extract.plan` | payload inventory、custom actions、registry/file intents | `TASK-007`、`TASK-014` |
| `linux-elf-core` | `elf`、`.so`、`.o`、core | `elf.structure.analyze`、`elf.imports.extract`、`elf.hardening.check`、`core.metadata.extract` | program headers、dynamic tags、GOT/PLT、RELRO/PIE/NX、core notes | `TASK-008` |
| `linux-package` | `deb`、`rpm`、`apk`(Alpine)、`snap`、`flatpak`、`appimage` | `linux.package.inventory`、`linux.package.scripts.review` | package metadata、maintainer scripts as text、nested ELF candidates | `TASK-008`、`TASK-014` |
| `macos-macho-core` | Mach-O、fat/universal、dylib、framework | `macho.structure.analyze`、`macho.imports.extract`、`macho.universal.slices` | load commands、segments、dylib imports、rpaths、arch slices | `TASK-009` |
| `macos-bundle-signature` | `.app`、`.framework`、`.dSYM`、entitlements | `macos.bundle.inspect`、`macos.codesign.inspect`、`macos.entitlements.extract` | Info.plist、code signature、team id、entitlements、dSYM link | `TASK-009` |
| `apple-container` | `dmg`、`pkg`、`ipa` | `apple.container.inventory`、`ipa.profile.extract`、`pkg.payload.plan` | nested Mach-O、mobile provisioning、installer payload plan | `TASK-009`、`TASK-014` |
| `android-apk-core` | `apk`、`aab`、`apks`、`xapk` | `apk.structure.analyze`、`apk.manifest.parse`、`apk.resources.decode` | manifest、permissions、components、resources、signing certs | `TASK-010` |
| `android-dex-oat` | `dex`、multi-dex、`oat`、`art`、`vdex` | `dex.classes.list`、`dex.decompile.plan`、`oat.inventory` | classes、methods、strings、annotations、unsupported OAT detail | `TASK-010` |
| `android-native-bridge` | APK `lib/*.so`、JNI、AAR native libs | `apk.native-libs.route`、`jni.symbols.link` | nested ELF candidates、ABI split、JNI method hints | `TASK-010`、`TASK-017` |
| `jvm-bytecode` | `jar`、`class`、`war`、`aar` | `jvm.structure.analyze`、`jvm.classes.list`、`jvm.deps.extract` | manifest、constant pool、packages、Kotlin metadata、deps | `TASK-011` |
| `dotnet-managed` | PE CLR、`.dll`、`.exe`、`.nupkg`、Mono | `dotnet.assembly.inspect`、`dotnet.il.xrefs`、`dotnet.decompile.plan` | assembly refs、MVID、target framework、IL tokens、resources | `TASK-012` |
| `unity-managed` | Unity `global-metadata.dat`、IL2CPP、Mono assemblies | `unity.metadata.inspect`、`unity.il2cpp.plan` | Unity version hints、metadata tables、managed/native bridge | `TASK-012` |
| `wasm-module` | `wasm`、WASI modules | `wasm.structure.analyze`、`wasm.imports.extract` | sections、imports/exports、WASI capabilities、function index | `TASK-015`、`TASK-016` |
| `script-bytecode` | Python `pyc`、Lua bytecode、Node V8 cache | `bytecode.metadata.inspect`、`bytecode.decompile.plan` | magic/version、constant table、decompile readiness | `TASK-016` |
| `firmware-image` | raw firmware、uImage、FIT、DTB、initramfs | `firmware.scan`、`firmware.entropy`、`firmware.extract.plan` | signatures、entropy windows、arch hints、filesystem candidates | `TASK-013` |
| `embedded-filesystem` | squashfs、cramfs、jffs2、ubifs、romfs | `filesystem.inventory`、`filesystem.nested.route` | files、configs、certs、scripts、nested ELF/package candidates | `TASK-013` |
| `container-archive` | zip、7z、rar、tar、gz、xz、docker/oci image | `container.structure.analyze`、`container.nested.list`、`container.extract.plan` | safe inventory、hashes、MIME guess、nested route plan | `TASK-014` |
| `native-re-adapters` | PE、ELF、Mach-O、shellcode | Ghidra、Rizin、RetDec、Capstone adapters | functions、basic blocks、xrefs、decompile units、disasm | `TASK-015` |
| `cross-format-intel` | all static formats | YARA/YARA-X、DIE、strings、metadata、SBOM、vuln scanner | rule hits、packer/language signals、IOC hints、SBOM、vulns | `TASK-016` |

### 3.2 动态插件

动态插件必须经过 runtime policy，默认只暴露 readiness 和 plan，不执行 live sample。

- Windows dynamic：Windows Sandbox/Hyper-V/host-agent、debug-session、ETW/Procmon-like trace、registry/file/process/network 行为、Wine/Speakeasy dry-run。
- Linux dynamic：Qiling/Unicorn emulation、gdb、strace/ltrace、ptrace、seccomp/eBPF optional trace、core dump correlation。
- macOS dynamic：LLDB、DTrace、fs_usage、codesign runtime checks、sandbox-exec plan；只能在 macOS host 或明确 runtime backend 可用时 ready。
- Android dynamic：ADB/emulator、Frida、root bypass、SSL pinning bypass、crypto trace、classloader/hook trace、network capture。
- iOS dynamic：Frida/LLDB readiness、IPA/Mach-O profile 关联、mobile provisioning 检查；默认只输出 plan，不能默认连接设备。
- Cross-runtime correlation：把动态行为和静态函数、imports、strings、resources、network、memory、host artifacts 关联成 evidence timeline。

### 3.3 动态插件拆分

| 插件方向 | runtime backend | 默认暴露 | 需要 opt-in 后才允许 | 任务落点 |
| --- | --- | --- | --- | --- |
| `windows-runtime-plan` | Windows Sandbox、Hyper-V、host-agent | readiness、isolation guidance、execution plan | sample launch、ETW/Procmon trace、memory snapshot | `TASK-019` |
| `wine-speakeasy-runtime` | Wine、Speakeasy | dependency check、API emulation plan | PE dry-run、registry/file/network trace | `TASK-019` |
| `linux-runtime-plan` | Qiling、Unicorn、gdb、strace/ltrace | readiness、syscall trace plan、limits | ELF emulation/debug/trace | `TASK-020` |
| `linux-ebpf-trace` | eBPF、seccomp、ptrace | capability check、permission explanation | live tracing on host/container | `TASK-020` |
| `macos-runtime-plan` | LLDB、DTrace、fs_usage、sandbox-exec | macOS host gating、trace plan | Mach-O launch/debug/trace | `TASK-021` |
| `android-runtime-plan` | ADB、emulator、Frida | device/backend readiness、script registry | install/run APK、attach Frida、MITM trace | `TASK-022` |
| `ios-runtime-plan` | Frida、LLDB、idevice tools | host/device readiness、IPA/Mach-O hook plan | install/attach/trace on device | `TASK-021`、`TASK-022` |
| `behavior-evidence-correlator` | all dynamic backends | timeline schema、mock correlation | large evidence ingest from live runs | `TASK-023` |

## 4. 执行顺序

1. Wave 1 做 SDK foundation：不先做这个，后面每个插件都会重复定义 format/platform/runtime metadata。
2. Wave 2 做静态插件矩阵：这些任务大多可并行，但 `TASK-017` 需要等格式插件落地后整合路由。
3. Wave 3 做动态插件矩阵：必须依赖 runtime readiness、policy 和静态 profile，默认 mock/fixture 验证。
4. Wave 4 收口：文档、compatibility、quality gates、release notes 和最终 test matrix。

## 5. 验证原则

- 每个格式插件都有至少 1 个 safe fixture，不需要真实恶意样本。
- 每个 dynamic 插件都有 readiness mock，不在默认测试中启动真实 runtime。
- 每个插件都能在 `tools.discover` 和 `tool.help` 中看到 aspect、适用格式、依赖和下一步建议。
- 每个 public output shape 改动都要补 `plugin-sdk`、`plugin-contracts`、`tool-readiness` 或对应格式测试。
- 最终验证包含 `npm run typecheck`，并确认 `package-lock.json` 没有意外变化。
