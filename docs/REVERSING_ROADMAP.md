# Reversing Roadmap

## Goal

把 MCP 从“静态特征聚合器 + 可读重建器”继续推进成“一站式逆向平台”。目标不是宣称恢复原始作者源码，而是稳定产出：

- 可追溯的证据链
- 可读、可维护、可继续重写的等价语义代码
- 可执行的 C/C# skeleton
- 可复用的静态、Ghidra、动态、内存、.NET、DLL、脱壳协同工作流

## Current Baseline

当前已经具备：

- `ghidra.health` / `ghidra.analyze` 端到端检查与分析复用
- `code.functions.reconstruct` 函数级语义重建
- `code.reconstruct.export` 模块化 `pseudo.c` / `rewrite.c` / `reconstruct_support.h` / `reconstruct_harness.c` / `CMakeLists.txt`
- `dynamic.trace.import` / `dynamic.memory.import` / `sandbox.execute(mode=speakeasy|memory_guided|safe_simulation)`
- `.NET` 元数据提取与 C# skeleton 导出
- artifact/task/cache 持久化与 MCP 路由化

## Workstreams

### 1. 语义层

目标：把 `FUN_* / param_* / undefined8*` 继续压缩成人类语义。

已完成：
- 语义别名、行为标签、xref 摘要、caller/callee relationship hints
- runtime backfeed 到函数级 `runtime_context`
- `rewrite` 统一使用 `AkRuntimeContext / AkSemanticInputs / AkSemanticOutputs`

下一步：
- 参数名、返回值、局部变量重命名
- 原始伪代码签名解析与 `proposed_signature` 生成
- 指针/句柄/上下文对象的更细粒度类型恢复
- 大函数继续拆分成 capability / probe / dispatch / finalize 子函数

### 2. 行为层

目标：把“看起来像做了某事”推进到“明确恢复出行为路径”。

已完成：
- 动态 API 解析表、文件/注册表/进程能力表的显式 rewrite
- runtime trace / memory snapshot 反灌到 `runtime_context`
- 函数级 API/stage/memory region 关联

下一步：
- 更精确的函数级 trace 归属
- thunk / indirect-call / tail-jump 的 caller recovery 增强
- 根据真实 trace 自动补全 `rewrite` 的状态迁移与错误路径

### 3. 数据层

目标：恢复样本的配置、命令模型、上下文结构，而不只是 API 集合。

已完成：
- 字符串窗口化上下文
- help text / command banner / subcommand 候选提取
- 导出 `cli_model.json`，在 `reverse_notes.md` 里汇总 tool/banner/commands

下一步：
- 常量表 / 配置块 / 状态字段抽取
- 参数解析模型、子命令树、帮助页结构恢复
- 内存中的字符串窗口与函数 xref 双向联动

### 4. 可执行层

目标：让重建产物不只是“可读”，还要“可跑、可验证”。

已完成：
- `reconstruct_support.h`
- `reconstruct_harness.c`
- `CMakeLists.txt`
- C/C# skeleton artifact 注册

下一步：
- 可选 native compile validation
- trace-driven harness assertions
- 更明确的 stub/adapter 层，减少人工补胶水代码

### 5. 复杂样本层

目标：把单 EXE 扩展到壳、DLL、.NET、内存态、更多执行证据。

已完成：
- `.NET metadata extract`
- `.NET reconstruct export`
- DLL export surface baseline
- `dynamic.memory.import`
- `speakeasy` user-mode emulation

下一步：
- .NET method body / IL 级重建
- DLL public surface + cross-module call graph 恢复
- 壳识别之后的自动辅助解包链
- 更强的 minidump / process-memory 解析
- Frida / Speakeasy / imported trace 的统一证据融合

## Near-Term Milestones

### M1
- `runtime_context` 增加 memory region / suggested module / provenance
- `rewrite` 注释和 regrouping 消费这些新字段
- `cli_model.json` 持久化成 artifact

### M2
- 从 Ghidra 伪代码签名提取参数/返回值提示
- 生成更稳定的 header prototype
- 用 harness 做最小 compile smoke test

### M3
- minidump 中模块/段/地址级恢复
- 对接更强的动态证据源
- .NET method body / IL fallback 收敛

## Validation Expectations

每次迭代至少覆盖：

- 单元测试：schema、artifact、route、rewrite 生成、runtime correlation
- 真实样本回归：Akasha
- 至少一条 live MCP 路由验证
- 如环境允许，native 或 dotnet build validation
