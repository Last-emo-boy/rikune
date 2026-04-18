# Rikune

英文版：[`README.md`](./README.md)

这是一个面向 Windows 逆向分析的 MCP Server。它把 PE 初筛、Ghidra 辅助分析、DLL/COM 画像、运行时证据导入、Rust/.NET 恢复、源码风格重建，以及 LLM 参与的语义 review，统一暴露成可复用的 MCP 工具，供任意支持 tool calling 的 LLM 调用。

## 功能亮点

- 通用 Windows PE 覆盖：对 EXE、DLL、COM 风格库、Rust native 样本和 .NET 程序都提供了专门的画像或恢复路径。
- 以恢复为中心：当 Ghidra 函数提取为空或退化时，系统仍可继续走 `.pdata` 解析、函数边界恢复、符号恢复和函数定义导入。
- 可观测的 Ghidra 执行：高层输出会直接返回命令日志、运行日志、阶段进度、项目/日志根路径，以及解析后的 Java 异常摘要。
- 运行时证据可回灌：静态证据、trace 导入、内存快照和语义 review 产物都能继续反灌到 reconstruct 和 report。
- LLM 可深度介入：函数命名、函数解释、模块级重建 review 都已经是结构化 MCP workflow，而不是零散 prompt。
- 适合长任务编排：长耗时 workflow 会返回 `job_id`、进度和 `polling_guidance`，方便客户端按建议 sleep/wait，而不是高频轮询浪费 token。
- **分阶段非阻塞流水线**：分析按显式阶段组织（`fast_profile`、`enrich_static`、`function_map`、`reconstruct`、`dynamic_plan`、`dynamic_execute`、`summarize`），支持预览优先的工具合约和持久化运行状态。
- **HTTP 文件服务**：内嵌 HTTP API（端口 18080），支持样本上传、产物下载、上传会话管理，API Key 认证。
- **Web 实时监控面板**：`http://localhost:18080/dashboard` — 暗色主题，8 个标签页，展示工具、插件、样本、分析历史、报告查看器、配置、系统资源和 SSE 事件流。支持实时日志流显示。
- **SSE 实时事件**：`/api/v1/events` 实时推送分析进度、样本导入、服务器状态变更。
- **插件 SDK**：56 个内置插件，热加载/卸载，第三方自动发现。
- **高级分析工具**：节区级熵值分析、行为分类、混淆检测（CFF、不透明谓词、字符串加密、.NET 混淆）、静态污点追踪、child sample handoff、智能脱壳指引、自动生成 Frida hook 脚本、Sigma 检测规则生成。

## 本轮新增的静态初筛能力

这一轮在深度逆向前补了一层更强的静态初筛能力：

- `static.capability.triage`：用 `capa` 风格的能力识别回答“样本可能具备什么行为能力”，而不只是展示字符串或导入表。
- `pe.structure.analyze`：把 `pefile` 和 `LIEF` 风格的 PE 结构解析合并成一个统一输出，同时保留后端细节块。
- `compiler.packer.detect`：补上编译器、保护器和壳归因，并在 Detect It Easy 缺失时优雅降级成 setup guidance。
- `static.resource.graph`、`static.config.carver`、`static.behavior.classify` 和 `unpack.child.handoff`：在真实运行前补齐 payload、配置、持久化/注入和 child sample handoff 证据。
- `workflow.triage`、`report.summarize` 和 `report.generate` 现在会直接消费这三类结果，并支持 static artifact 的 provenance、scope 和 compare/baseline。

## 典型使用路径

### 快速初筛

1. `sample.ingest`
2. `static.capability.triage`
3. `pe.structure.analyze`
4. `compiler.packer.detect`
5. `workflow.triage`
6. `report.summarize`

### 困难 native 恢复

1. `ghidra.analyze`
2. `workflow.function_index_recover`
3. `workflow.reconstruct`

### LLM 辅助精修

1. `workflow.reconstruct`
2. `workflow.semantic_name_review`
3. `workflow.function_explanation_review`
4. `workflow.module_reconstruction_review`

## 这个项目适合做什么

它不是一组一次性的本地脚本，而是一层可组合、可复盘、可扩展的逆向分析能力。

适合的典型场景：

- 快速初筛 Windows PE 样本
- 查看导入、导出、字符串、壳线索、运行时类型和二进制角色
- 在有 Ghidra 时做反编译、CFG、搜索和函数重建
- 在 Ghidra 函数提取失败时继续恢复可用的函数索引
- 在 Java、Python 依赖或 Ghidra 缺失时返回结构化安装/配置指引
- 在分析失败时返回更详细的 Ghidra 诊断、日志路径和 remediation hints
- 关联静态证据、运行时 trace、内存快照和语义 review 产物
- 导出带可选 build / harness 验证的源码风格重建结果

## 核心能力

### 样本与静态分析

- `sample.ingest`
- `sample.profile.get`
- `static.capability.triage`
- `static.resource.graph`
- `static.config.carver`
- `static.behavior.classify`
- `pe.structure.analyze`
- `compiler.packer.detect`
- `pe.fingerprint`
- `pe.imports.extract`
- `pe.exports.extract`
- `pe.pdata.extract`
- `dll.export.profile`
- `com.role.profile`
- `strings.extract`
- `strings.floss.decode`
- `yara.scan`
- `runtime.detect`
- `packer.detect`
- `binary.role.profile`
- `system.setup.guide`

### Ghidra 与函数分析

- `ghidra.health`
- `ghidra.analyze`
- `code.functions.list`
- `code.functions.rank`
- `code.functions.search`
- `code.function.decompile`
- `code.function.disassemble`
- `code.function.cfg`
- `code.functions.reconstruct`

### Rust 与困难 native 样本恢复

- `code.functions.smart_recover`
- `pe.symbols.recover`
- `code.functions.define`
- `rust_binary.analyze`
- `workflow.function_index_recover`

### .NET 与托管分析

- `dotnet.metadata.extract`
- `dotnet.types.list`
- `dotnet.reconstruct.export`

### 运行时证据与报告

- `dynamic.dependencies`
- `dynamic.runtime.status`
- `dynamic.toolkit.status` - 只读查询 Runtime Node 内的 CDB、ProcDump、ProcMon、Sysmon、TTD、x64dbg、dnSpyEx、Frida、dotnet、FakeNet 风格工具库存，不启动、不执行样本
- `dynamic.deep_plan` - 生成显式的深度动态分析计划，覆盖行为捕获、调试器、内存、遥测、网络、.NET、反逃逸、TTD 和手动 GUI 调试方案
- `debug.cdb.plan` - 生成只规划不执行的 CDB 命令批次，覆盖 API 断点、异常跟踪、模块加载停止和 dump-on-break 模板
- `debug.procdump.plan` - 生成只规划不执行的 ProcDump 捕获模板，覆盖崩溃、first-chance 异常、超时和 PID 快照 dump
- `debug.telemetry.plan` - 生成只规划不执行的 ProcMon、Sysmon、ETW 和事件日志采集方案，并包含清理/回滚要求
- `debug.network.plan` - 生成只规划不执行的 proxy sinkhole、ETW DNS 和 FakeNet 风格网络实验方案
- `debug.managed.plan` - 生成只规划不执行的 .NET safe-run、SOS/CDB、ProcDump、资源复核和 dnSpy handoff 方案
- `debug.gui.handoff` - 生成面向可见 Sandbox/Hyper-V runtime 的 x64dbg、WinDbg 和 dnSpyEx 手动交接记录
- `dynamic.persona.plan` - 生成只规划不启动的 Windows runtime persona 清单，用于 Sandbox/Hyper-V 用户态环境准备
- `dynamic.behavior.diff` - 对比静态预期和运行时观察，输出已确认、未触发和意外行为
- `analysis.evidence.graph` - 把静态 artifact、运行时观察和相互印证边组织成紧凑证据图
- `crypto.lifecycle.graph` - 把 crypto 发现、候选常量、运行时 API、阶段和内存区域线索串成生命周期图
- `runtime.hyperv.control`
- `sandbox.execute`
- `dynamic.behavior.capture`
- `dynamic.trace.import`
- `dynamic.memory.import`
- `dynamic.auto_hook` - 基于静态证据自动生成 Frida hook
- `dynamic.memory_dump` - 运行时内存转储与模式扫描
- `runtime.debug.session.start` / `runtime.debug.session.status` / `runtime.debug.session.stop` - 显式创建、查询和释放 Windows Sandbox 或 Hyper-V VM 运行时会话
- `runtime.debug.command` - 在已启动的运行时调试会话中分发受支持的 Runtime Node 命令
- `attack.map`
- `ioc.export`
- `report.summarize`
- `report.generate`
- `artifacts.list`
- `artifact.read`
- `artifacts.diff`
- `tool.help`

### Android / APK 分析

- `apk.structure.analyze` - APK 清单、权限、组件提取
- `apk.packer.detect` - APK 加壳/混淆检测
- `dex.decompile` - DEX 转 Java 反编译（jadx）
- `dex.classes.list` - DEX 类/方法枚举

### 符号执行与 CrackMe

- `symbolic.explore` - 基于 angr 的符号执行
- `keygen.verify` - 注册机/许可证验证（Qiling/angr）
- `constraint.solve` - Z3/angr 约束求解

### 恶意软件分析

- `malware.config.extract` - 恶意软件配置提取
- `malware.classify` - 家族分类（YARA + capa + 行为）
- `c2.extract` - C2 基础设施提取

### 跨平台与可视化

- `elf.macho.parse` - ELF/Mach-O 头部/段解析（Rizin）
- `rizin.diff` - 二进制差异比较（函数/基本块级别）
- `cfg.visualize` - 控制流图可视化（DOT/SVG/JSON）
- `timeline.correlate` - 多源事件时间线关联
- `analysis.evidence.graph` - 带相互印证边的静态/运行时证据图
- `crypto.lifecycle.graph` - 带静态/运行时相互印证的 crypto 生命周期图
- `cross_module.xref` - 跨模块交叉引用分析
- `kb.search` - 知识库语义搜索

### 高级分析

- `entropy.analyze` - 节区级 Shannon 熵值分析，加壳/加密分类
- `static.resource.graph` - PE 资源和嵌入 payload 图谱，包含熵值、magic、hash 和资源字符串预览
- `static.config.carver` - 通用配置候选提取：URL、域名、IP、注册表路径、mutex、HTTP client 字符串和编码 blob
- `static.behavior.classify` - 持久化、服务、计划任务、WMI、进程注入、DLL 注入、APC 和 hollowing 分类器
- `hash.resolver.plan` - 静态 API hash resolver 规划，给出 hash family 线索和断点 handoff 建议
- `obfuscation.detect` - 混淆检测：控制流平坦化、不透明谓词、字符串加密、导入混淆、反反汇编、.NET 混淆
- `taint.track` - 静态污点追踪：源/汇 API 映射、污点路径枚举、风险分级
- `unpack.guide` - 智能脱壳指引：UPX、Themida、VMProtect、.NET Reactor、ConfuserEx、ASPack、PECompact
- `unpack.child.handoff` - 提取嵌入 payload 候选，并以带 provenance 的 child sample 形式注册
- `frida.script.generate` - 基于分析证据自动生成 Frida hook 脚本（加密、网络、文件、注册表、进程、反调试、内存）
- `sigma.rule.generate` - 基于样本证据自动生成 Sigma 检测规则（进程创建、文件事件、注册表、网络、DNS、镜像加载）

### 语义 review 与重建

- `code.function.rename.prepare`（已废弃，使用 `llm.analyze`）
- `code.function.rename.review`（已废弃，使用 `llm.analyze`）
- `code.function.rename.apply`（已废弃，使用 `llm.analyze`）
- `code.function.explain.prepare`（已废弃，使用 `llm.analyze`）
- `code.function.explain.review`（已废弃，使用 `llm.analyze`）
- `code.function.explain.apply`（已废弃，使用 `llm.analyze`）
- `code.module.review.prepare`（已废弃，使用 `llm.analyze`）
- `code.module.review`（已废弃，使用 `llm.analyze`）
- `code.module.review.apply`（已废弃，使用 `llm.analyze`）
- `code.reconstruct.plan`
- `code.reconstruct.export`

### LLM 辅助分析

- `llm.analyze` - 统一 LLM 分析接口（替代已废弃的三步骤工具）
  - `task: 'summarize'` - 精简摘要
  - `task: 'explain'` - 清晰解释
  - `task: 'recommend'` - 可操作建议
  - `task: 'review'` - 代码审查

## 高层 Workflow

### `workflow.triage`

适合第一轮快速初筛，在深入恢复前先获得 PE 画像和分析方向。

### `workflow.deep_static`

长耗时静态分析流水线，适合更深入的函数排序和静态覆盖，支持异步 job 模式。

### `workflow.reconstruct`

这是当前最重要的高层重建入口。它可以：

- 执行 binary preflight
- 识别 Rust 倾向样本
- 识别 DLL 生命周期、导出分发、callback surface 和 COM activation 线索
- 在 Ghidra 函数索引缺失或退化时自动恢复函数索引
- 导出 native 或 .NET 的重建结果
- 可选执行 build 验证和 harness 验证
- 根据 DLL / COM / Rust 的角色画像自动调整导出策略
- 在环境不满足时返回结构化 setup guidance
- 在前台或后台 job 模式下返回阶段化进度信息
- 把 runtime / semantic provenance 和 diff 一起带到结果中
- 返回结构化 `ghidra_execution`，直接暴露项目路径、日志、阶段进度和 Java 异常摘要

### `workflow.function_index_recover`

困难 native 样本的高层恢复链：

1. `code.functions.smart_recover`
2. `pe.symbols.recover`
3. `code.functions.define`

当 Ghidra 已分析但函数提取为空或退化时，优先走这条链。

### `workflow.semantic_name_review`

供外部 LLM 执行函数命名 review 的高层 workflow。它可以准备证据、通过 MCP sampling 发起命名 review、应用结果，并可选刷新 `reconstruct/export`。当刷新 export 时，同样会返回 `ghidra_execution`。

### `workflow.function_explanation_review`

供外部 LLM 执行函数解释 review 的高层 workflow。它可以准备证据、请求结构化解释、应用结果，并可选重跑 `reconstruct/export`。当刷新 export 时，也会带上 `ghidra_execution`。

### `workflow.module_reconstruction_review`

供外部 LLM 执行模块级重建 review 的高层 workflow。它可以准备模块证据、请求结构化模块摘要和重写建议、应用结果，并可选刷新 `reconstruct/export`。当刷新 export 时，也会带上 `ghidra_execution`。

## 通用恢复模型

这个 Server 不假设 Ghidra 一定能正确提取函数。

对于 Rust、Go、重优化 native 或其他困难样本，推荐恢复链是：

1. `ghidra.analyze`
2. 如果 Ghidra post-script 提取失败，则走 `pe.pdata.extract`
3. 用 `code.functions.smart_recover` 恢复函数边界
4. 用 `pe.symbols.recover` 恢复命名线索
5. 用 `code.functions.define` 导入函数索引
6. 再继续使用 `code.functions.list`、`code.functions.rank`、`code.functions.reconstruct` 或 `workflow.reconstruct`

也就是说，系统会把：

- `function_index`
- `decompile`
- `cfg`

拆成不同的能力状态，而不是混成单一的“分析成功/失败”。

## Evidence Scope 与 Semantic Scope

多数高层工具支持显式作用域控制，避免历史证据污染当前结果。

运行时证据作用域：

- `evidence_scope=all`
- `evidence_scope=latest`
- `evidence_scope=session`，配合 `evidence_session_tag`

语义命名 / 函数解释 / 模块 review 作用域：

- `semantic_scope=all`
- `semantic_scope=latest`
- `semantic_scope=session`，配合 `semantic_session_tag`

也支持基线对比：

- `compare_evidence_scope`
- `compare_evidence_session_tag`
- `compare_semantic_scope`
- `compare_semantic_session_tag`

静态分析 artifact 也支持独立作用域：

- `static_scope=all`
- `static_scope=latest`
- `static_scope=session`，配合 `static_session_tag`

静态基线对比参数：

- `compare_static_scope`
- `compare_static_session_tag`

这样 MCP 客户端不只能够问“当前结果是什么”，还可以问“和上一轮证据或语义 review 相比变化了什么”。

## Ghidra 执行摘要

高层输出现在会显式返回 `ghidra_execution`，而不是把 Ghidra 行为隐藏在泛化的成功/失败状态后面。

它会告诉你：

- 当前使用的是哪一条分析记录
- 结果来自 `best_ready` 还是 `latest_attempt`
- project path、project root、log root
- command log 和 runtime log 路径
- function extraction 状态和所用脚本
- 阶段化 progress 信息
- 解析后的 Java exception 摘要

这层信息已经能在以下入口看到：

- `workflow.reconstruct`
- `workflow.semantic_name_review` 的 export refresh 结果
- `workflow.function_explanation_review` 的 export refresh 结果
- `workflow.module_reconstruction_review` 的 export refresh 结果
- `report.summarize`
- `report.generate`

## LLM 参与的 Review 层

当前已经支持三层结构化 review：

- 函数命名 review
- 函数解释 review
- 模块重建 review

统一流程是：

1. 准备结构化证据包
2. 在客户端支持 sampling 时发起受约束 review
3. 把接受的结果写回稳定 semantic artifact
4. 按显式 `semantic_scope` 重跑 `reconstruct/export/report`

## 异步 Job 模式

以下长任务支持排队执行和后台完成：

- `workflow.deep_static`
- `workflow.reconstruct`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`
- `workflow.module_reconstruction_review`

配套任务工具：

- `task.status`
- `task.cancel`
- `task.sweep`

排队后的 workflow 输出和 `task.status` 现在都会返回 `polling_guidance`。
当 Ghidra 或 reconstruct 这类长任务仍在排队或运行时，MCP 客户端应优先按
这个建议执行一次 sleep/wait，再查询下一次状态，而不是立即高频轮询。

## 环境 Bootstrap 与安装引导

如果用户一开始没有配好 Python 依赖、动态分析依赖或 Ghidra，可以使用：

- `system.health`
- `dynamic.dependencies`
- `ghidra.health`
- `system.setup.guide`

这些工具会返回结构化的：

- `setup_actions`
- `required_user_inputs`

方便 MCP 客户端显式要求用户执行：

- `python -m pip install ...`
- 设置 `JAVA_HOME`
- 提供 `GHIDRA_PATH` / `GHIDRA_INSTALL_DIR`
- 提供 `GHIDRA_PROJECT_ROOT` / `GHIDRA_LOG_ROOT`
- 提供 `CAPA_RULES_PATH`
- 提供 `DIE_PATH`
- 安装 Speakeasy / Frida 等可选动态分析依赖

### Frida 动态 Instrumentation（可选）

对于运行时 API 追踪和行为分析，安装 Frida：

```bash
pip install frida frida-tools
```

**环境变量**（可选 - 当 `frida` 在 PATH 中时自动检测）：

- `FRIDA_SERVER_PATH` - Frida server 二进制文件路径，用于 USB/远程设备分析
- `FRIDA_DEVICE` - 设备 ID 或 "usb" 用于 USB 设备选择（默认：本地 spawn）

**内置脚本** 位于 `src/plugins/frida/scripts/`：
- `api_trace.js` - Windows API 追踪与参数日志
- `string_decoder.js` - 运行时字符串解密
- `anti_debug_bypass.js` - 反调试检测中和
- `crypto_finder.js` - 加密 API 检测
- `file_registry_monitor.js` - 文件/注册表操作追踪

使用示例见 [`docs/EXAMPLES.md`](./docs/EXAMPLES.md#场景 -9-frida-运行时 instrumentation)。

## 当前开发进度

### 最新 Release: v1.0.0-beta.3

**稳定功能** (生产环境可用)：
- PE 初筛与静态分析 (`static.capability.triage`, `pe.structure.analyze`, `compiler.packer.detect`)
- Ghidra 辅助分析，完整执行可见性
- DLL/COM 画像 (`dll.export.profile`, `com.role.profile`)
- Rust 和 .NET 恢复路径
- 源码风格重建，支持 LLM 辅助 review 层
- 运行时证据导入与关联
- Android/APK 分析 (`apk.structure.analyze`, `dex.decompile`, `dex.classes.list`, `apk.packer.detect`)
- 符号执行与 CrackMe 工具 (`symbolic.explore`, `keygen.verify`, `constraint.solve`)
- 恶意软件分析 (`malware.config.extract`, `malware.classify`, `c2.extract`)
- 跨平台二进制解析 (`elf.macho.parse`, `rizin.diff`)
- 可视化与关联 (`cfg.visualize`, `timeline.correlate`, `cross_module.xref`, `kb.search`)
- Frida 动态 Instrumentation (`frida.runtime.instrument`, `frida.script.inject`, `frida.trace.capture`)
- HTTP 文件服务 REST API（端口 18080）— 样本上传、产物 CRUD、SSE 事件
- **Web 监控面板** (`http://localhost:18080/dashboard`) — 工具、插件、样本、分析历史、报告查看器（Markdown/JSON/HTML/SVG）、配置、系统实时监控，支持服务器日志流
- **插件 SDK**：56 个内置插件，热加载/卸载，第三方自动发现
- **生产基础设施**：限流、配置校验、分页、重试、批量分析、SBOM 生成
- **SSE 实时事件**：Server-Sent Events 实时推送分析进度

### 服务全景（Docker）

Docker 现在按 profile 部署：`static` 是默认纯静态 analyzer，`hybrid` 是 Linux analyzer + Windows Host Agent，`full` 是全量 Linux 工具链镜像。三种 profile 都暴露同一组服务入口：

| 服务 | 访问方式 | 说明 |
|------|----------|------|
| MCP Server | stdio (`docker exec -i`) | 241 个工具、3 个 prompt、16 个 resource |
| HTTP API | `http://localhost:18080/api/v1/*` | 样本/产物/上传/健康检查 REST API |
| Web 面板 | `http://localhost:18080/dashboard` | 实时监控 SPA（8 标签页，暗色主题） |
| SSE 事件 | `http://localhost:18080/api/v1/events` | 分析事件实时推送 |
| 面板 API | `http://localhost:18080/api/v1/dashboard/*` | 12 个 JSON 端点 |

### 内置插件（56 个）

| 插件 | ID | 工具数 | 说明 |
|------|----|--------|------|
| Android / APK | `android` | 4 | APK 清单、DEX 反编译、加壳检测 |
| angr | `angr` | 1 | 符号执行引擎 |
| API Hash | `api-hash` | 3 | Shellcode API 哈希解析与 resolver 规划 |
| APK Smali | `apk-smali` | 3 | APK Smali 反汇编与分析 |
| 批量分析 | `batch` | 3 | 批量样本处理 |
| 行为优先 | `behavior-first` | 3 | 行为分析优先级 |
| 二进制 Diff | `binary-diff` | 2 | 二进制比较与补丁 |
| Capstone | `capstone` | 2 | 反汇编引擎集成 |
| 代码分析 | `code-analysis` | 19 | CFG、反编译、交叉引用、代码模式 |
| CrackMe 自动化 | `crackme` | 4 | 验证定位、符号执行、补丁、注册机 |
| 跨模块分析 | `cross-module` | 3 | 跨二进制比较、调用图、DLL 依赖树 |
| 调试会话 | `debug-session` | 9 | GDB/LLDB 调试会话管理 |
| 深度脱壳 | `deep-unpack` | 3 | 多层脱壳与模拟 |
| Detect It Easy | `die` | 2 | 编译器、加壳器、保护器检测 |
| .NET 反编译 | `dotnet-decompile` | 2 | .NET 程序集反编译 |
| .NET Reactor | `dotnet-reactor` | 4 | .NET 混淆分析与去混淆 |
| 动态分析 | `dynamic` | 24 | 运行时状态、runtime 工具库存、深度动态计划、CDB、ProcDump、telemetry、网络实验、托管运行时和 GUI handoff 规划、runtime persona 规划、行为差异对比、Hyper-V 控制、行为捕获、自动 Frida hook、trace 归因、内存转储、运行时调试会话控制 |
| ELF/Mach-O | `elf-macho` | 4 | 跨平台二进制解析 |
| 固件分析 | `firmware` | 3 | 固件提取与分析 |
| Frida Instrumentation | `frida` | 4 | 运行时 instrumentation、脚本注入、trace 采集 |
| Ghidra 集成 | `ghidra` | 2 | 无头 Ghidra 分析与健康检查 |
| Go 分析 | `go-analysis` | 3 | Go 二进制分析与符号恢复 |
| Graphviz | `graphviz` | 1 | DOT 图形可视化 |
| 主机关联 | `host-correlation` | 1 | 主机级产物关联 |
| 知识库 | `kb-collaboration` | 8 | 函数签名匹配、分析模板 |
| 恶意软件分析 | `malware` | 4 | C2 提取、配置解析、家族分类 |
| 托管假 C2 | `managed-fake-c2` | 1 | 受控分析用假 C2 服务器 |
| 托管 IL 交叉引用 | `managed-il-xrefs` | 2 | .NET IL 交叉引用分析 |
| 托管沙箱 | `managed-sandbox` | 1 | 托管沙箱执行环境 |
| 内存取证 | `memory-forensics` | 6 | 内存转储分析、Volatility 集成 |
| 元数据 | `metadata` | 1 | 二进制元数据提取 |
| 可观测性 | `observability` | 1 | 工具调用 hook 追踪与指标 |
| Office 分析 | `office-analysis` | 3 | Office 文档宏与 OLE 分析 |
| PANDA | `panda` | 1 | PANDA 录制/重放分析 |
| PCAP 分析 | `pcap-analysis` | 3 | 网络抓包分析 |
| PE 分析 | `pe-analysis` | 6 | PE 结构、导入、导出、指纹、pdata、符号恢复 |
| PE 签名 | `pe-signature` | 2 | PE 数字签名验证 |
| Qiling | `qiling` | 1 | Qiling 二进制模拟 |
| 报告 | `reporting` | 3 | 报告生成与导出 |
| RetDec | `retdec` | 1 | RetDec 反编译后端 |
| Rizin | `rizin` | 1 | Rizin 反汇编后端 |
| 运行时去混淆 | `runtime-deobfuscate` | 4 | 运行时去混淆与模拟 |
| SBOM | `sbom` | 1 | 软件物料清单生成 |
| 相似度分析 | `similarity` | 2 | 二进制相似度匹配 |
| Speakeasy | `speakeasy` | 3 | Speakeasy 模拟分析 |
| 静态初筛 | `static-triage` | 20 | 能力初筛、资源图谱、配置提取、行为分类、编译器/壳检测 |
| 字符串 | `strings` | 2 | 高级字符串提取与分析 |
| 威胁情报 | `threat-intel` | 3 | ATT&CK 映射与 IOC 导出 |
| 脱壳 | `unpacking` | 3 | 加壳检测、脱壳与 child sample handoff |
| UPX | `upx` | 1 | UPX 脱壳后端 |
| 可视化 | `visualization` | 5 | HTML 报告、行为时间线、数据流图、证据图、crypto 生命周期图 |
| VM 分析 | `vm-analysis` | 10 | VM/模拟器检测与分析 |
| 漏洞扫描 | `vuln-scanner` | 2 | 漏洞模式扫描与摘要 |
| Wine | `wine` | 1 | 通过 Wine 执行 Windows PE |
| YARA | `yara` | 3 | YARA 规则扫描与生成 |
| YARA-X | `yara-x` | 1 | YARA-X 新一代规则引擎 |

插件通过 `PLUGINS` 环境变量控制（`*` = 全部, `android,malware` = 指定, `-dynamic` = 排除）。详见 [`docs/PLUGINS.md`](./docs/PLUGINS.md)。

### 开发中（beta 后续迭代）

完整动态运行时迭代计划记录在
[`docs/DYNAMIC-RUNTIME-ROADMAP.md`](./docs/DYNAMIC-RUNTIME-ROADMAP.md)。它覆盖
runtime session 持久化、能力驱动分发、运行时产物自动回收、Sandbox 诊断、长生命周期
Windows 调试会话、Hyper-V VM 调试后端、Frida 运行态执行、行为捕获、内存转储
workflow、分阶段 workflow 集成、Dashboard Runtime 页，以及统一 backend interface。

对于新的静态初筛能力，最常见的可选依赖是：

- `flare-capa`
- `pefile`
- `lief`
- 通过 `CAPA_RULES_PATH` 指向的 capa rules bundle
- 通过 `DIE_PATH` 指向的 Detect It Easy CLI

对于 Ghidra 12.0.4，当前默认要求 Java 21+。如果 Java 缺失或版本过低，`ghidra.health`、`system.health` 和 `system.setup.guide` 都会返回明确的兼容性提示。

当 Ghidra 命令失败时，Server 现在会保留：

- command log
- Ghidra runtime log（如果可用）
- 解析后的 Java exception 摘要
- 结构化 remediation hints

而不是只返回一个笼统的 `exit code 1`。

内置的 `src/plugins/ghidra/scripts/` 目录现在会按安装包根目录或仓库根目录解析，
而不是按当前工作目录解析。这样即使用户从别的目录启动 Server，也不会
再因为找不到 `ExtractFunctions.py` / `ExtractFunctions.java` 而失败。

## 项目结构

```text
bin/                         npm CLI 入口
dist/                        编译后的 TypeScript 输出
src/                         MCP Server 源码
  index.ts                   入口（~90 行）
  server.ts                  MCPServer 类
  tool-registry.ts           集中式工具/prompt/resource 注册
  plugins.ts                 插件框架（56 个内置 + 自动发现）
  safe-command.ts            命令注入防护
  config-validator.ts        运行时配置校验
  logger.ts                  Pino 结构化日志
  plugins/
    frida/scripts/           Frida instrumentation 脚本（同时作为 MCP resource）
    ghidra/scripts/          Ghidra 辅助脚本
    static-triage/helpers/   .NET 元数据辅助项目（DotNetMetadataProbe）
  analysis/                  分析编排模块
  artifacts/                 产物管理与存储
  constants/                 共享常量
  ghidra/                    Ghidra 集成辅助
  llm/                       LLM prompt 与 review 模块
  prompts/                   MCP prompt 定义
  sample/                    样本导入与管理
  storage/                   存储层抽象
  utils/                     共享工具模块
  worker/                    Python 进程池与 worker 管理
  tools/                     核心工具定义与处理器（31 个文件）
  plugins/                   插件目录（56 个内置插件）
  api/
    file-server.ts           HTTP API（端口 18080）
    rate-limiter.ts          请求限流
    sse-events.ts            Server-Sent Events
    dashboard/index.html     Web 监控面板
    routes/
      dashboard-api.ts       面板 JSON API（12 个端点）
tests/                       单元与集成测试（212 个测试文件）
workers/                     Python worker、YARA 规则、动态分析辅助
packages/plugin-sdk/         独立 Plugin SDK npm 包
docs/                        文档
```

## 环境要求

必须：

- Node.js 22+
- npm 10+
- Python 3.11+

强烈建议：

- Ghidra，用于 native 反编译与 CFG
- Java 21+，供 Ghidra 12.0.4 使用
- .NET SDK，用于 `dotnet.metadata.extract`
- Clang，用于 reconstruct export 编译验证
- [`requirements.txt`](./requirements.txt) 中的 Python 依赖
- [`workers/requirements.txt`](./workers/requirements.txt) 中的 worker 依赖

## 部署方式

当前部署代码已经统一到 profile 模型：

| 模式 | Dockerfile | Compose 文件 | 容器 | 运行时 |
|------|------------|--------------|------|--------|
| `static` | `docker/Dockerfile.analyzer` | `docker-compose.analyzer.yml` | `rikune-analyzer` | 禁用动态执行 |
| `hybrid` | `docker/Dockerfile.analyzer` | `docker-compose.hybrid.yml` | `rikune-analyzer` | 远程 Windows Host Agent / Windows Sandbox 或 Hyper-V VM |
| `full` | `Dockerfile` | `docker-compose.yml` | `rikune` | Linux 全量工具链，默认不接沙箱 |

推荐默认安装：

```powershell
.\rikune.ps1

# 自动化时也可以显式指定
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

如果是单台 Windows 机器同时跑 Docker Desktop、Windows Host Agent 和 Windows Sandbox：

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime
```

如果要用 Hyper-V VM 作为调试/动态执行运行时，先在 VM 内启动 Rikune Runtime Node，然后安装 hybrid 时指定 VM 后端：

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime `
  -RuntimeBackend hyperv-vm `
  -HyperVVmName "rikune-runtime" `
  -HyperVSnapshotName "clean-runtime" `
  -HyperVRuntimeEndpoint "http://192.168.1.50:18081" `
  -HyperVRestoreOnRelease
```

Linux/macOS 侧也有同级入口：

```bash
./rikune.sh

# Linux analyzer + 远程 Windows Host Agent
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
```

也可以手工生成全部 Docker 文件：

```bash
npm run build
npm run docker:generate:all
```

关键边界：

- `static` 和 `hybrid` 的 analyzer 镜像不再安装本地动态执行依赖，动态执行由 Windows 运行时面承担。
- 默认 `windows-sandbox` 后端要求 Host Agent 跑在已登录的 Windows 用户会话里，不能作为传统 Windows Service 运行。
- `hyperv-vm` 后端适合调试和无人值守风格实验：Host Agent 会启动 VM、可选恢复 checkpoint，然后等待 VM 内 Runtime Node 健康后把 endpoint 返回给 analyzer。
- Hyper-V 运行时会话可以选择释放策略：`runtime.debug.session.start` 里使用 `hyperv_retention_policy='clean_rollback'` 会在释放后恢复 checkpoint，`stop_only` 会关机并保留磁盘状态，`preserve_dirty` 会保留 VM 现场供人工检查。安装参数 `-HyperVRestoreOnRelease` 会设置 Host Agent 默认策略。
- 运行时会话是显式的：如果希望走 staged workflow，先用 `workflow.analyze.promote(dynamic_plan)` 自动运行 `static.behavior.classify`、生成证据感知的 `dynamic.deep_plan`，并保持 live execution 显式门控；也可以手动调用 `dynamic.runtime.status` 检查 Runtime Node 和 Host Agent 就绪状态，用 `dynamic.toolkit.status` 查看 runtime 内调试器、遥测、dump、手动 GUI 工具库存，用 `dynamic.deep_plan` 选择受限的动态分析方案，需要网络实验、.NET runtime 或 GUI 交接细节时再用 `debug.network.plan`、`debug.managed.plan`、`debug.gui.handoff`，用 `dynamic.persona.plan` 生成只规划不启动的 Sandbox/Hyper-V persona 清单；需要 Hyper-V 状态、checkpoint 创建/恢复或停止时调用 `runtime.hyperv.control`，再调用 `runtime.debug.session.start` 创建或附着 Windows runtime，然后用 `runtime.debug.command` 分发 `debug.session.*`、`sandbox.execute`、`dynamic.behavior.capture`、遥测、ProcDump、managed safe-run 或内存转储类任务，再用 `dynamic.behavior.diff`、`analysis.evidence.graph` 和 `crypto.lifecycle.graph` 把运行时观察关联回静态预期，最后用 `runtime.debug.session.stop` 释放。
- Runtime 工具缓存查询是只读的，可使用 `RUNTIME_TOOL_DIRS`、`RUNTIME_TOOL_CACHE_DIR`、`RIKUNE_RUNTIME_TOOLS` 或默认 `C:\rikune-tools` 挂载。需要更深动态方案时，把 Windows Debugging Tools 的 `cdb.exe`、Sysinternals ProcDump/ProcMon/Sysmon、TTD helper、x64dbg、dnSpyEx、Frida、dotnet 或 FakeNet 风格 harness 放到这里。
- Docker/WSL analyzer 不能使用 `auto-sandbox`；`auto-sandbox` 只适用于 Windows 原生 analyzer。
- `RUNTIME_HOST_AGENT_API_KEY` 用于 Analyzer -> Host Agent 控制面，`RUNTIME_API_KEY` 只在 Runtime Node 自身需要鉴权时使用。

## 本地开发

安装 JavaScript 依赖：

```bash
npm install
```

安装 Python worker 依赖：

```bash
python -m pip install -r requirements.txt
python -m pip install -r workers/requirements.txt
python -m pip install -r workers/requirements-dynamic.txt
```

构建：

```bash
npm run build
```

测试：

```bash
npm test
```

本地启动：

```bash
npm start
```

## MCP 客户端配置

### 通用 stdio 配置

```json
{
  "mcpServers": {
    "rikune": {
      "command": "node",
      "args": ["/absolute/path/to/repo/dist/index.js"],
      "cwd": "/absolute/path/to/repo",
      "env": {
        "GHIDRA_PATH": "C:/path/to/ghidra",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra"
      }
    }
  }
}
```

### 本地安装

- GitHub Copilot: [`COPILOT_INSTALLATION.md`](./COPILOT_INSTALLATION.md)

相关文档：

- [`COPILOT_INSTALLATION.md`](./COPILOT_INSTALLATION.md)

## 持久化存储

默认情况下，运行时状态会写到用户目录和稳定系统目录，而不是跟随当前工作目录漂移：

- Windows workspace root: `%USERPROFILE%/.rikune/workspaces`
- SQLite database: `%USERPROFILE%/.rikune/data/database.db`
- File cache: `%USERPROFILE%/.rikune/cache`
- Audit log: `%USERPROFILE%/.rikune/audit.log`
- Ghidra project root: `%ProgramData%/.rikune/ghidra-projects`
- Ghidra log root: `%ProgramData%/.rikune/ghidra-logs`
- Ghidra 内置脚本目录：自动从安装包根目录解析

可以通过环境变量或用户配置文件覆盖：

- `%USERPROFILE%/.rikune/config.json`
- `WORKSPACE_ROOT`
- `DB_PATH`
- `CACHE_ROOT`
- `AUDIT_LOG_PATH`
- `GHIDRA_PROJECT_ROOT`
- `GHIDRA_LOG_ROOT`
- `CAPA_RULES_PATH`
- `DIE_PATH`

## 样本导入说明

对于 VS Code、Copilot 这类本地 IDE 客户端，优先使用本地文件路径：

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "E:/absolute/path/to/sample.exe"
  }
}
```

只有当客户端无法访问与 Server 相同的文件系统时，才使用 `bytes_b64`。

## 发布到 npm

发布包包含：

- 编译后的 `dist/`
- `bin/` 中的 CLI 入口
- Python workers 和 YARA 规则
- Ghidra 辅助脚本
- .NET metadata helper 源码
- MCP 客户端安装脚本

不包含：

- tests
- 本地 workspaces
- caches
- 生成的 reports
- 临时草稿和内部进度文档

发布前检查：

1. 更新 [`package.json`](./package.json) 中的版本号
2. 运行 `npm run release:check`
3. 检查 `npm run pack:dry-run`
4. 执行 `npm login`
5. 执行 `npm publish --access public`

仓库内置的 GitHub 自动化：

- [`ci.yml`](./.github/workflows/ci.yml)
- [`publish-npm.yml`](./.github/workflows/publish-npm.yml)
- [`dependabot.yml`](./.github/dependabot.yml)

如果通过 GitHub Actions 发布，请配置仓库级 `NPM_TOKEN` secret。

## 安全边界

这个项目面向分析工作流，而不是实时恶意行为操作。

当前强项：

- PE 初筛与分类支持
- 逆向证据抽取
- IOC 与 ATT&CK 导出
- 运行时证据导入与关联
- 源码风格重建与 review

当前非目标：

- 对复杂 native 二进制恢复原始源码
- 仅靠静态证据就高置信完成恶意家族归因
- 对所有壳实现完全自动脱壳
- 对重优化代码中的每个函数都完成高置信语义恢复

## 贡献与发布流程

- 贡献指南：[`CONTRIBUTING.md`](./CONTRIBUTING.md)
- 质量评估说明：[`docs/QUALITY_EVALUATION.md`](./docs/QUALITY_EVALUATION.md)
- 示例 benchmark corpus：[`docs/examples/benchmark-corpus.example.json`](./docs/examples/benchmark-corpus.example.json)
- 安全策略：[`SECURITY.md`](./SECURITY.md)

## 使用已发布的 npm 包

先启动默认的 static Docker analyzer：

```powershell
npm run build
npm run docker:generate:static
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d analyzer
```

然后在 MCP 客户端中使用已发布的 npm launcher：

```json
{
  "mcpServers": {
    "rikune": {
      "command": "npx",
      "args": ["-y", "rikune", "docker-stdio"],
      "env": {
        "GHIDRA_PATH": "C:/path/to/ghidra",
        "GHIDRA_INSTALL_DIR": "C:/path/to/ghidra"
      }
    }
  }
}
```

发布态的职责划分是：

- `npm/npx` 只负责启动 MCP launcher
- Docker Compose 容器负责持久化 analyzer、HTTP API、上传存储和静态工具链

现有源码直跑方式和直接 `docker exec` 方式仍然可用。

## License

MIT 许可证，详见 [`LICENSE`](./LICENSE)。

感谢 [linuxdo (linux.do) ](https://linux.do/) 社区的交流、分享与反馈。
