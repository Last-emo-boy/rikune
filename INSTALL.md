# Docker 一键安装指南

本指南覆盖当前 Rikune Docker 安装路径。Docker 文件和 Compose 文件由 `scripts/generate-docker.mjs` 根据模板和插件元数据生成，安装脚本会自动完成构建、配置和启动。

## 推荐选择

| 需求 | 推荐 profile |
| --- | --- |
| 日常静态逆向、样本不执行 | `static` |
| Docker Analyzer + Windows Sandbox / Hyper-V live runtime | `hybrid` |
| 大而全的 Linux 工具链镜像 | `full` |
| Windows 本机 Analyzer + 本地 Sandbox | native + `auto-sandbox` |

不确定时先用 `static`。

## 快速安装

Windows static：

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

Windows 单机 hybrid，也就是同一台机器运行 Docker Desktop、Windows Host Agent 和 Windows Sandbox：

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime
```

Linux/macOS static：

```bash
./rikune.sh install --profile static --data-root "$HOME/.rikune"
```

Linux/macOS Analyzer + 远程 Windows runtime host：

```bash
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
```

## 安装脚本做什么

典型流程：

1. 检查 Docker、Docker Compose、Node.js、npm。
2. 安装 npm 依赖。
3. 构建 TypeScript 包。
4. 生成 Docker profile 文件。
5. 写入 `.docker-runtime.env`。
6. 根据 profile 构建镜像。
7. 启动 compose service。
8. 可选配置 MCP 客户端。
9. hybrid 时可安装或检查 Windows Host Agent。

## Profile 说明

| Profile | Compose | 容器 | Runtime mode | 说明 |
| --- | --- | --- | --- | --- |
| `static` | `docker-compose.analyzer.yml` | `rikune-analyzer` | `disabled` | 默认安全路径，不执行样本 |
| `hybrid` | `docker-compose.hybrid.yml` | `rikune-analyzer` | `remote-sandbox` | 通过 Windows Host Agent 委托 live runtime |
| `full` | `docker-compose.yml` | `rikune` | 默认 disabled | 全量 Linux 工具链，镜像更大 |

## Windows 参数示例

打开菜单：

```powershell
.\rikune.ps1
```

安装 static：

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

安装 hybrid 并安装 runtime：

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime
```

代理构建：

```powershell
.\rikune.ps1 install -Profile static -HttpProxy "http://127.0.0.1:7890" -HttpsProxy "http://127.0.0.1:7890"
.\rikune.ps1 install -Profile static -NoProxyAutoDetect
```

状态、日志、停止：

```powershell
.\rikune.ps1 status
.\rikune.ps1 logs
.\rikune.ps1 stop
```

底层脚本仍可直接使用：

```powershell
.\install-docker.ps1
.\install-docker.ps1 -Profile static -DataRoot "D:\Docker\rikune"
.\install-docker.ps1 -Profile full
.\install-docker.ps1 -Profile hybrid -RuntimeHostAgentEndpoint "http://host.docker.internal:18082"
.\install-docker.ps1 -Profile static -SkipStart
.\install-docker.ps1 -Profile static -SkipBuild
.\install-docker.ps1 -Profile static -ResetData
.\install-docker.ps1 -ConfigureClient Codex
```

## Linux/macOS 参数示例

```bash
./rikune.sh
./rikune.sh install --profile static --data-root "$HOME/.rikune"
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
./rikune.sh status
./rikune.sh logs
./rikune.sh stop
```

## 手工部署

Static：

```bash
npm install
npm run build
npm run docker:generate:all
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
```

Full：

```bash
npm install
npm run build
npm run docker:generate:all
docker compose --env-file .docker-runtime.env -f docker-compose.yml up -d --build mcp-server
```

Hybrid：

```bash
npm install
npm run build
npm run docker:generate:all
docker compose --env-file .docker-runtime.env -f docker-compose.hybrid.yml up -d --build analyzer
```

## `.docker-runtime.env`

安装脚本会写入 `.docker-runtime.env`。示例：

```env
RIKUNE_DATA_ROOT=D:/Docker/rikune
API_ENABLED=true
API_PORT=18080
PLUGINS=*
RUNTIME_MODE=disabled
```

Hybrid 示例：

```env
RIKUNE_DATA_ROOT=D:/Docker/rikune
API_ENABLED=true
API_PORT=18080
PLUGINS=*
RUNTIME_MODE=remote-sandbox
RUNTIME_HOST_AGENT_ENDPOINT=http://host.docker.internal:18082
RUNTIME_HOST_AGENT_API_KEY=<host-agent-key>
RUNTIME_API_KEY=<runtime-node-key>
```

## 数据目录

默认 Windows Docker 数据根：

```text
D:\Docker\rikune\
  samples\
  artifacts\
  uploads\
  cache\
  logs\
  rikune.db
  audit.jsonl
```

不要把未知样本目录挂载到应用源码目录。

## 常用命令

```powershell
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml ps
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml logs -f analyzer
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml down
curl http://localhost:18080/api/v1/health
curl http://localhost:18080/api/v1/ready
```

## Hybrid Runtime 说明

- Host Agent 默认端口通常是 `18082`。
- Runtime Node 默认端口通常是 `18081`，由 Host Agent 在 Sandbox/VM 内启动并转发。
- Windows Sandbox 后端要求 Host Agent 运行在已登录用户会话中。
- Docker/WSL Analyzer 不能使用 `auto-sandbox`，应使用 `remote-sandbox`。
- MCP 连接、`dynamic.runtime.status`、`dynamic.deep_plan`、`debug.*.plan` 不会启动 Sandbox。
- `runtime.debug.session.start`、`runtime.debug.command`、`sandbox.execute` 和 promoted `dynamic_execute` 才会请求 live runtime。
- `sandbox.execute` 返回的 `execution_semantics` 会说明本次是 live sandbox、live Hyper-V、safe simulation 还是 emulation。

## 验证

MCP 工具：

- `system.health`
- `system.setup.guide`
- `system.config.validate`
- `plugin.list`
- `tool.readiness`
- `dynamic.runtime.status`

HTTP：

```bash
curl http://localhost:18080/api/v1/health
curl http://localhost:18080/api/v1/ready
```

Docker：

```bash
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml ps
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml logs -f analyzer
```

## 故障排查

| 现象 | 处理 |
| --- | --- |
| `app/dist not found` | 重新执行 `npm run build` 和 `npm run docker:generate:all` 后再 build |
| Docker build 代理指向 `127.0.0.1` 失败 | 用安装脚本代理参数，脚本会转换到容器可访问地址 |
| MCP 一连接就以为 Sandbox 会启动 | 不会。只有 live runtime 工具会启动 Sandbox/VM |
| `/api/v1/ready` runtime degraded | 检查 `RUNTIME_MODE`、Host Agent endpoint、API key 和 Host Agent 日志 |
| Ghidra 不可用 | 检查 Java 21+、`GHIDRA_INSTALL_DIR`、`system.setup.guide` |
| 插件工具缺失 | 检查 `PLUGINS`、`plugin.list`、`tools.discover`、`tool.readiness` |

更多错误码见 [TROUBLESHOOTING.md](TROUBLESHOOTING.md)。
