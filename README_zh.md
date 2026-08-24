# Rikune

Rikune 是一个面向 Windows EXE 和多格式二进制逆向的 MCP Server。它把样本导入、静态初筛、Ghidra 辅助函数恢复、插件化专业工具、artifact 管理，以及可选的隔离 Windows 运行时执行统一暴露给 MCP 客户端。

当前面向 AI 客户端的主路径是最小 gateway surface：

1. 用 `workflow.search` 根据文件类型、样本画像和用户目标搜索并排序 workflow / specialist capabilities。
2. 宿主机文件上传用 `workflow.run action=request_upload`；旧客户端需要直接导入时，再由 `workflow.search` 指向隐藏的 sample-intake compatibility 工具。
3. 拿到 `sample_id` 后，用 `workflow.run action=start` 创建或复用 staged analysis run。
4. 用 `workflow.run action=status` 查询状态，用 `workflow.run action=promote` 推进更深阶段。
5. 紧凑输出不够时，用 `artifact.read` 读取完整持久化 artifact。

`sample.*`、`workflow.analyze.*`、`workflow.triage`、`tools.discover` 和 `task.status` 仍保留为兼容或低层检查入口；新客户端应优先使用 `workflow.search`、`workflow.run` 和 `artifact.read`。

通过远程 `rikune-agent` gateway 连接时，MCP 客户端看到的是固定 transport 名称：
`workflow_search`、`workflow_run`、`artifact_read`、`rikune_tool_call`，以及
`rikune_connection_*` 控制入口。`rikune_connection_refresh` 只更新内部上游能力缓存，
不会扩展 MCP tool list。只有当 `workflow_search` 明确识别到某个 primary workflow /
artifact gateway 覆盖不到的内部 analyzer subtool 时，才使用 `rikune_tool_call` 调用。

## 核心能力

- MCP stdio server，可直接接入支持 MCP 的 AI 客户端。
- 可选 HTTP API 和 dashboard，用于上传、下载、健康检查、SSE 事件和 artifact 访问。
- 按 SHA-256 分桶的样本工作区，保存原始样本、缓存、Ghidra/.NET 输出和报告。
- SQLite 持久化 samples、analysis runs、jobs、evidence、artifacts、batches、debug sessions 和 scheduler telemetry。
- 117 个内置插件，支持第三方插件自动发现。
- 渐进式工具暴露：默认面向 AI 的入口刻意保持很小；`workflow.search` 根据样本类型、发现结果和 profile metadata 路由到相关专业能力，而不是一次暴露所有工具。
- 覆盖 PE、ELF、Mach-O、APK/DEX、Office、firmware、UEFI/SMM、CUDA PTX/CUBIN/fatbin、strings、YARA、SBOM、签名、packer、.NET、Go、Rust 等静态分析。
- 可集成 Ghidra、Rizin、RetDec、angr、Capstone、Graphviz、Qiling、PANDA、Speakeasy、Wine、Frida 等后端。
- 插件驱动的 Docker backend 自动安装，支持 default、optional、research、runtime、GPU、BYO 和 sidecar 分层。
- 可选 Analyzer/Runtime 分离架构，通过 Windows Host Agent、Windows Sandbox 或 Hyper-V VM 执行真实 Windows 运行时任务。
- 对 live execution、网络访问、外部上传、批量反编译等危险能力做策略门控。

## v1.4.0 平台支持范围

Analyzer 与 sample-custody 数据面要求 Linux kernel：原生 Linux、Linux container 或 WSL2。
Windows 与 macOS 可作为受支持的 Linux container/control host；Windows 还可承载 Windows Host
Agent、Windows Sandbox 或 Hyper-V runtime，用于显式的 live execution。v1.4.0 不支持原生
Windows/macOS Node Analyzer，也不支持 `auto-sandbox` 拓扑。该边界保留 Linux secure-filesystem
的 fail-closed 契约，不会把不受支持的 filesystem 误当成等价实现。
在 WSL2 中，`RIKUNE_DATA_ROOT` 以及所有 workspace/sample/storage 路径必须位于 WSL Linux
filesystem（例如发行版 ext4.vhdx 内的 `~/.rikune`）。sample custody 不支持 `/mnt/c` 或其他
`/mnt/<drive>` DrvFS 路径。
当前生成的 Analyzer image 为 `linux/amd64`，所有生成的 Compose service 都会显式固定该
platform；Apple Silicon 上的 Docker Desktop 会通过 amd64 emulation 运行。不要删除或覆盖生成的
platform pin。

## 快速开始

### Static Docker Analyzer

默认推荐 static profile。它不会执行样本，适合日常静态分析。

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

```bash
./rikune.sh install --profile static --data-root "$HOME/.rikune"
```

wrapper 是唯一受支持的安装事务：它会在 dependency lifecycle command 前 snapshot 并移除受保护的
Compose env，在 pre-commit 工作失败时恢复原文件，并只在新文件完成安全验证后提交轮换后的
credential。不要用底层 env writer 与 `npm ci` 命令手工复刻该流程。

env writer 默认使用操作系统 CSPRNG 轮换新的 32-byte analyzer API key；仅当本次调用显式传入 key 时才保留指定值，并在 POSIX 系统上把文件权限设为 `0600`。Compose 默认只绑定 `127.0.0.1`。本地 Dashboard 地址为 `http://127.0.0.1:18080/?key=<RIKUNE_API_KEY>`；不要分享该 URL，也不要提交 `.docker-runtime.env`。

### Hybrid Docker + Windows Runtime

Hybrid profile 在 Docker 中运行 Analyzer，把真实 Windows 执行委托给 Windows Host Agent。Host Agent 可按需启动 Windows Sandbox，也可以控制预配置的 Hyper-V VM。

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime
```

Linux/macOS 宿主机上的 Linux-container analyzer + 远程 Windows runtime host：

```bash
# 仅在隔离的可信网络/VPN 内 bootstrap；Sandbox runtime ports 使用 HTTP。
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user> \
  --host-agent-endpoint https://runtime.example.internal \
  --allow-insecure-runtime-http
```

HTTPS endpoint 应通过可信 reverse proxy / VPN 路径提供。远程 bootstrap 在该隔离网络内部仍使用明文 Host Agent/Sandbox runtime ports，因此必须显式使用上方的 `--allow-insecure-runtime-http` opt-in。若 runtime 已单独加固并预先部署，请改用 `--skip-windows-setup`，并省略不安全 opt-in。Runtime key 只通过受保护环境或隐藏 prompt 提供，不接受 CLI 参数。

连接 MCP 客户端不会启动 Sandbox，也不会运行样本。只有 `runtime.debug.session.start`、`runtime.debug.command`、`sandbox.execute` 或 promoted dynamic execution stage 这类显式 live runtime 工具才会触发运行时。

### 原生 Linux 开发

根 Analyzer 仅可直接运行在 Linux kernel 上。Windows 请使用 WSL2 或 Linux container；macOS
请使用 Linux container/VM。Windows runtime package 仍可在原生 Windows host 上开发和测试。

```bash
npm ci --include=dev
npm run build
npm test
node --env-file-if-exists=.env dist/index.js
```

根包要求 Node.js 22.9 或更新版本。部分 runtime 子包仍能在较旧 Node 上运行，但仓库开发、根 CLI 和发布包以 Node 22.9+ 为基线。

## 主要 Gateway 流程

### 搜索与上传

不确定 workflow、文件类型或后端时，先调用 `workflow.search`。它会被动排序匹配的 profile / workflow / specialist tool，并返回紧凑的 readiness 与 routing hint，不会自动激活隐藏工具或启动后端。

宿主机文件上传调用 `workflow.run action=request_upload`，向返回的 upload URL POST 原始字节，然后从 HTTP 响应读取 `sample_id`。`sample.request_upload` 和 `sample.ingest` 是兼容 helper，不是普通 AI-facing 主路径。

远程 analyzer 或 `rikune-agent` 部署时，把 `API_PUBLIC_BASE_URL`、`RIKUNE_API_PUBLIC_BASE_URL` 或 `RIKUNE_ANALYZER_PUBLIC_URL` 设置为客户端可访问的 HTTPS base，例如 `https://analyzer.example.com`。应由同一私有 Docker network 上的可信 reverse proxy 终止 TLS；若 proxy 同时执行 SSO，必须移除用户传入的 `X-API-Key`，仅在认证成功后注入内部 analyzer secret。不要通过明文 HTTP 暴露携带 key 的 API。上传会话会返回公网/内网可访问的 `upload_url` / `status_url`，远程 gateway 也会把旧 analyzer 返回的 localhost 地址归一化到已配置 endpoint。

启用 HTTP API 时，非 MCP 集成仍可直接 `POST /api/v1/samples`。导入成功后会返回 `sample_id`；后续分析应使用 `sample_id`，不要继续依赖本地文件路径。

### 启动分析

用 `workflow.run action=start` 传入 `sample_id`。第一阶段会执行 fast profile，并创建或复用 analysis run。返回的 `plan_id` 映射到持久化 analysis run。

### 推进阶段

`workflow.run action=promote` 用于推进更深阶段。当前阶段模型包括：

- `fast_profile`
- `enrich_static`
- `function_map`
- `reconstruct`
- `semantic_name_review`
- `semantic_explain_review`
- `semantic_module_review`
- `dynamic_plan`
- `dynamic_execute`
- `summarize`

长任务会进入 JobQueue。用 `workflow.run action=status` 轮询紧凑 staged state。

`workflow.run action=status` 是主要 staged-run 视图。历史阶段结果过大时会裁剪，并在顶层 `warnings` 中说明；需要完整内容时用 `artifact.read` 读取持久化 artifact。`task.status` 是原始队列/进程兼容视图，并包含 analyzer 子进程的 `external_active_*` 内存遥测。

### 阅读结果

常用后续工具：

- `workflow.search`
- `workflow.run`
- `analysis.context.get`
- `artifact.read`，以及兼容 artifact helper：`artifacts.list`、`artifacts.diff`、`artifact.download`
- `report.summarize`、`report.generate`、`workflow.summarize`
- `workflow.semantic_name_review`
- `workflow.function_explanation_review`
- `workflow.module_reconstruction_review`
- `tool.help`、`tool.readiness` 和 `tools.discover` 用于兼容/调试检查

### Agent Case Workspace

Rikune 把确定性 Analyzer Artifact 与 Agent 生成的调查上下文分开：

```text
Analyzer Artifact（可作为 Evidence）
  -> analysis.claims.apply（inferred Claim Ledger）
  -> analysis.case.checkpoint / analysis.case.snapshot（不可变 Case 状态）
  -> analysis.context.pack（确定性、token-bounded 上下文）
  -> workflow.summarize（Evidence 与 Context 分栏的最终摘要）
```

`analysis_claim_set`、`analysis_case_state`、summary 和 report Artifact 都是 context-only，不能成为 Claim evidence，也不能进入 summary 的 `source_artifact_refs`。AI 或 imported producer 只能写入 `inferred` Claim；可信 analyst review 入口仍保持 fail-closed。

每个 Case 通过 `case_id` 隔离。样本只有一个 Case 时，`analysis.context.pack` 和 `workflow.summarize` 会自动选择；存在多个 Case 时必须显式传入 `case_id`，否则调用会 fail closed。选中 Case 后，Claim context 仅包含其 `active_claim_ids`；若 Case state 已存在但无法信任，则隐藏 Claims，不会回退到样本级全量 Ledger。active ID 会通过带完整性校验的 newest-to-oldest scan 解析，上限为 512 个 Claim Set Artifact 和 128 MiB；任何 ID 缺失、链断裂或预算耗尽都会隐藏整个 Case Claim view。增量 Context marker 同样绑定 `case_id`，不能跨 Case 重用。

持久化 summary 的复用由版本化 fingerprint 保护，绑定 resolved synthesis mode、全部 scope/session selector、非 context-only 来源 Artifact metadata、持久化 Evidence/Function/Analysis/Run/RunStage 状态、选中 Claim/Case marker，以及完整性 review 状态。复用前还会对来源 Artifact 文件执行流式 SHA-256 校验。缺少兼容 fingerprint 的旧 digest 会重建，不会直接复用。

Claim 和 Case writer 会先获取带 heartbeat 的 SQLite CAS lease，再获取带 owner identity 的 filesystem lock。stale takeover 同时绑定已观察到的 owner 与 heartbeat；malformed/foreign-host filesystem lock 通过 identity-checked 流程恢复。writer 会在最终 rename 前重新确认 lease ownership，并让 Artifact row insert 以当前 owner token 做原子 fencing。创建 lock 或 JSON Artifact 前，workspace 写路径会验证配置的 canonical root，并拒绝被 symlink 替换的 shard 或 sample 目录。

可复现的 benign CrackMe 验收脚本默认只执行被动 ELF、hardening、strings、Claim、Case、Context 和 deterministic summary 流程；`--deep` 才会启用 Ghidra：

```bash
npm run test:agent-case:e2e -- \
  --container <running-rikune-container> \
  --binary /fixtures/complex_crackme
```

Fixture 的构建与隔离执行规则见 `tests/fixtures/crackmes/README.md`。

## 架构概览

当前启动链路：

```text
src/index.ts
  -> loadConfig()
  -> WorkspaceManager / DatabaseManager / PolicyGuard / CacheManager / StorageManager / JobQueue
  -> 可选 RuntimeClient 或 Windows Host Agent-backed runtime delegation
  -> registerAllTools()
  -> MCP stdio server
```

核心 server 代码位于 `src/core/`：

| 模块 | 当前文件 |
| --- | --- |
| MCP server wrapper | `src/core/server.ts` |
| MCP tool/prompt/resource registry | `src/core/mcp-registry.ts` |
| 工具执行、校验、hooks | `src/core/tool-executor.ts` |
| 注册编排 | `src/core/tool-registry.ts` |
| 内置注册切片 | `src/core/tool-registry/*.ts` |
| PluginManager facade | `src/core/plugins.ts` |
| 插件发现和加载 | `src/core/plugin-orchestrator.ts` |
| 渐进式工具面 | `src/core/tool-surface-manager.ts` |

`src/server.ts`、`src/tool-registry.ts`、`src/plugins.ts` 等根级文件是兼容 forwarder。新代码应优先引用 `src/core/*`。

## 部署平面

| 平面 | 作用 | 关键代码 |
| --- | --- | --- |
| Analyzer | MCP stdio、HTTP API、存储、任务队列、静态工具、插件编排 | `src/index.ts`、`src/core/*` |
| Runtime Node | 隔离环境内的任务执行器 | `packages/runtime-node/*` |
| Windows Host Agent | 启停 Windows Sandbox 或 Hyper-V runtime | `packages/windows-host-agent/*` |
| Agent Gateway | Analyzer/runtime 连接管理和 MCP 代理 | `src/rikune-agent-gateway.ts` |

运行时模式：

- `disabled`：禁用 runtime delegation。
- `manual`：连接指定 runtime endpoint。
- `remote-sandbox`：委托给 Windows Host Agent。
- `auto-sandbox`：兼容配置值；v1.4.0 没有受支持的对应部署拓扑。

Linux-kernel analyzer 应通过 `remote-sandbox` 委托给 Windows Host Agent。v1.4.0 不支持原生
Windows/macOS Node Analyzer 与 `auto-sandbox` 拓扑。

## 插件系统

内置插件位于 `src/plugins/<id>/`，当前共 117 个。插件可以注册工具、声明依赖、暴露配置 schema、参与生命周期 hooks，并给 Docker 生成器提供安装元数据，也可以通过 `workerBackend` metadata 声明受限 Worker-backed 工具。

frontier Worker 套件保留 plan-only 工具作为 triage 和 handoff surface，再在旁边新增显式执行工具。`restringer.deobfuscation.run`、`jsimplifier.pipeline.run`、`jsir.cascade.normalize`、`jsvmp.bytecode.recover`、`gtirb.ir.generate`、`remill.lift.run`、`manifold.fact.extract`、`qbdi.trace.run` 和 `culifter.gpu.artifact.inventory` 会通过 `workflow.search`、`plugin.list`、`tool.help`、`tool.readiness` 暴露 Worker contract；`tools.discover` 保留为低层兼容入口。Discovery 和 readiness 保持 passive：只报告 backend metadata 和 setup guidance，不启动 REstringer、JSIMPLIFIER、JSIR/CASCADE、JSVMP、GTIRB、Remill、Manifold、QBDI、GPU driver、Node/V8、browser 或 runtime instrumentation。

`pdf-analysis` 插件通过 `pdf.analyze` 对 PDF 结构、内嵌 JavaScript 文本、URI、action 和 embedded-file marker 进行受限的被动检查。它使用仓库内置的 Python 标准库 worker，不打开文档，也不执行内嵌内容。

Docker 生成器直接读取插件 `systemDeps` 和 Worker packaging metadata。默认镜像安装低风险静态 wrapper，例如 REstringer、JSIMPLIFIER、Manifold、WABT 和 LIEF validation；optional profile 可启用 JSIR/CASCADE、JSVMP、GTIRB、radare2、Triton 等静态路线；heavy/runtime/GPU/license-sensitive backend 保持 profile-gated、BYO 或 sidecar。

```bash
node scripts/generate-docker.mjs --dry-run
node scripts/generate-docker.mjs --profile=full --backend-profile=optional
node scripts/generate-docker.mjs --all-profiles --dry-run
```

`PLUGINS` 控制启动时加载范围：

```bash
PLUGINS=*                 # 加载全部内置插件
PLUGINS=pe-analysis,yara  # 只加载指定插件
PLUGINS=-dynamic          # 加载除 dynamic 外的全部插件
```

运行时管理工具：

- `workflow.search`
- `workflow.run`
- `plugin.list`
- `plugin.enable`
- `plugin.disable`
- `tools.discover` 和 `tool.readiness` 用于低层兼容/调试检查

详见 [docs/PLUGINS.md](docs/PLUGINS.md) 和 [packages/plugin-sdk/README.md](packages/plugin-sdk/README.md)。

## HTTP API

启用 `api.enabled` 后，内嵌 file server 提供：

| Endpoint | 作用 |
| --- | --- |
| `/dashboard` 和 `/` | Dashboard UI |
| `/api/v1/health` | Liveness |
| `/api/v1/ready` | 数据库、队列、runtime、插件 backend readiness |
| `/api/v1/events` | SSE events |
| `/api/v1/samples` | 直接上传样本 |
| `/api/v1/samples/:id` | 样本元数据 |
| `/api/v1/samples/:id/download` | 原始样本下载 |
| `/api/v1/artifacts` | Artifact 列表 |
| `/api/v1/artifacts/:id` | Artifact 读取/删除 |
| `/api/v1/uploads/:token` | Durable upload session POST/status |

HTTP 层处理 API key 鉴权、rate limit、安全头和受限 CORS。

## 环境要求

开发基线：

- Node.js 22.9+
- npm
- CPython 3.12 x86_64，用于 native workers 与仓库中带 hash 的 Python 环境
- Docker 20.10+ 与 Docker Compose v2
- Java 21+，用于较新的 Ghidra
- Ghidra，用于反编译和函数分析
- Windows Sandbox / Hyper-V runtime 需要 Windows 10/11 Pro、Enterprise 或等价 VM 能力

可选依赖由插件决定。用 `system.health`、`system.setup.guide`、`tool.readiness` 和 `plugin.list` 检查当前环境缺什么。

## 项目结构

```text
src/
  index.ts                    主入口
  core/                       MCP server、registry、executor、插件编排
  core/tool-registry/         内置 tool/prompt/resource 注册切片
  tools/                      核心工具实现
  workflows/                  staged analysis、triage、reconstruction、review
  analysis/                   analysis run state 和后台任务 runner
  plugins/                    117 个内置插件
  persistence/                SQLite 和 workspace 持久化
  sample/                     样本 finalization 和 workspace 检查
  storage/                    artifacts、uploads、retention
  runtime-client/             Analyzer 侧 runtime delegation client
  worker/                     Ghidra 和 Python worker 编排
packages/
  plugin-sdk/                 公共插件 SDK
  shared/                     runtime 和 tool contract 类型
  runtime-node/               隔离 runtime executor
  windows-host-agent/         Windows Sandbox / Hyper-V host agent
workers/                      Python worker 脚本和 YARA 规则
docker/                       Docker 模板和 profile 产物
docs/                         架构、插件、runtime、部署文档
tests/                        单元、集成和 e2e 测试
```

## 开发命令

```bash
npm ci --include=dev
npm run build
npm test
npm run typecheck
npm run validate
npm run docker:generate:all
```

常用专项检查：

```bash
npm run test:unit
npm run test:integration
npm run test:e2e
npm run test:agent-case:e2e -- --help
npm run build:runtime
```

## MCP 客户端配置

Linux 原生本地构建（包括 repository 与数据均位于 Linux filesystem 的 WSL2）：

```json
{
  "mcpServers": {
    "rikune": {
      "command": "node",
      "args": ["/home/user/rikune/dist/index.js"],
      "env": {
        "API_ENABLED": "false",
        "PLUGINS": "*"
      }
    }
  }
}
```

Docker stdio：

```json
{
  "mcpServers": {
    "rikune": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "-e",
        "API_ENABLED=false",
        "-e",
        "NODE_ENV=production",
        "-e",
        "PYTHONUNBUFFERED=1",
        "rikune-analyzer",
        "node",
        "dist/index.js"
      ]
    }
  }
}
```

发布包：

```bash
npm install -g rikune
# Linux 原生 Analyzer（或在 WSL2 内运行）
rikune
# 在任一受支持 Docker host 上运行 Linux-container Analyzer
rikune docker-stdio
# Agent/control-plane 入口
rikune agent
```

## 持久化存储

默认数据存储在用户级 Rikune root 下。Docker 安装脚本通常把这个 root 映射到宿主目录，例如 `D:\Docker\rikune`。

常见子目录：

- `samples/`
- `artifacts/`
- `uploads/`
- `cache/`
- `logs/`
- SQLite 数据库
- audit log JSONL

样本工作区按 SHA-256 分桶，避免路径冲突并保持原始样本不可变。

## 安全边界

Rikune 面向恶意样本和不可信二进制分析，但它本身不是万能隔离边界。

- 日常分析优先使用 static Docker profile。
- 真实 Windows 执行必须放在 Windows Sandbox 或隔离 VM 中。
- Runtime Node 会拒绝未验证隔离环境，除非显式覆盖。
- 危险行为由 `PolicyGuard` 门控。
- 命令执行使用结构化 process API 和命令校验。
- 不要在宿主工作站上直接运行未知样本。

详见 [SECURITY.md](SECURITY.md) 和 [TROUBLESHOOTING.md](TROUBLESHOOTING.md)。

## 文档索引

- [INSTALL.md](INSTALL.md)：中文 Docker 安装指南。
- [DEPLOYMENT.md](DEPLOYMENT.md)：部署 profile 和 runtime topology。
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)：当前代码架构。
- [docs/PLUGINS.md](docs/PLUGINS.md)：插件列表、SDK、生命周期、发现机制。
- [docs/DYNAMIC-RUNTIME-ROADMAP.md](docs/DYNAMIC-RUNTIME-ROADMAP.md)：runtime roadmap 和状态。
- [CONTRIBUTING.md](CONTRIBUTING.md)：开发和贡献流程。
- [packages/plugin-sdk/README.md](packages/plugin-sdk/README.md)：插件作者 SDK。
- [workers/README.md](workers/README.md)：Python worker 协议。

## License

MIT
