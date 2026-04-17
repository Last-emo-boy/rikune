# Docker 一键安装指南

当前 Docker 部署已改为 profile 模型，所有 Dockerfile / Compose 文件都由
`scripts/generate-docker.mjs` 根据编译后的插件依赖生成。

## 推荐安装

普通用户优先使用顶层脚本。不加参数会进入菜单，菜单里可以安装、启动、停止、查看状态、看日志和运行诊断。

```powershell
# Windows
.\rikune.ps1
```

```bash
# Linux/macOS
./rikune.sh
```

Windows 单机 hybrid，也就是 Docker Desktop、Windows Host Agent 和 Windows Sandbox 都在同一台 Windows 上：

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime -Service
```

Linux analyzer + 远程 Windows Host Agent：

```bash
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
```

底层 `install-docker.ps1` 仍然保留，适合自动化或只想安装 Docker profile 的场景。它不加参数会进入 Docker profile 向导。

如果你要自动化部署，也可以显式传参数。默认安装纯静态 Docker analyzer，持久化数据放在 `D:\Docker\rikune`：

```powershell
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
```

这会执行：

1. 检查 Docker、Docker Compose、Node.js、npm
2. 创建持久化目录
3. 写入 `.docker-runtime.env`
4. `npm install`
5. `npm run build`
6. `node scripts/generate-docker.mjs --profile=static`
7. `docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer`
8. 检查 `http://localhost:18080/api/v1/health`

## 三种 Docker Profile

| Profile | 说明 | Compose 文件 | 容器 | 运行时 |
|---------|------|--------------|------|--------|
| `static` | 默认安全模式，只做静态/离线分析 | `docker-compose.analyzer.yml` | `rikune-analyzer` | `RUNTIME_MODE=disabled` |
| `hybrid` | Docker analyzer + Windows Host Agent / Windows Sandbox | `docker-compose.hybrid.yml` | `rikune-analyzer` | `RUNTIME_MODE=remote-sandbox` |
| `full` | 全量 Linux 工具链镜像 | `docker-compose.yml` | `rikune` | 默认禁用沙箱 |

## 安装脚本参数

顶层 Windows 入口：

```powershell
# 菜单
.\rikune.ps1

# 安装 / 启动 / 状态 / 日志 / 停止
.\rikune.ps1 install -Profile static -DataRoot "D:\Docker\rikune"
.\rikune.ps1 start -Profile static
.\rikune.ps1 status -Profile static
.\rikune.ps1 logs -Profile static -Follow
.\rikune.ps1 stop -Profile static

# 单机 hybrid
.\rikune.ps1 install -Profile hybrid -InstallRuntime -Service

# 代理：rikune.ps1 默认自动读取 Windows 系统代理；也可以显式指定或禁用
.\rikune.ps1 install -Profile static -HttpProxy "http://127.0.0.1:7890" -HttpsProxy "http://127.0.0.1:7890"
.\rikune.ps1 install -Profile static -NoProxyAutoDetect
```

顶层 Linux/macOS 入口：

```bash
./rikune.sh
./rikune.sh install --profile static --data-root "$HOME/.rikune"
./rikune.sh status --profile static
./rikune.sh logs --profile static --follow
./rikune.sh stop --profile static
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
```

底层 Docker profile 脚本仍可直接使用：

```powershell
# 默认 static profile
.\install-docker.ps1

# 指定数据根目录
.\install-docker.ps1 -Profile static -DataRoot "D:\Docker\rikune"

# 完整 Linux 工具链镜像
.\install-docker.ps1 -Profile full

# Hybrid，需要 Windows Host Agent
.\install-docker.ps1 -Profile hybrid `
  -HostAgentEndpoint http://192.168.1.10:18082 `
  -HostAgentApiKey <host-agent-key>

# 只生成/构建，不启动
.\install-docker.ps1 -Profile static -SkipStart

# 跳过构建，只启动已有镜像
.\install-docker.ps1 -Profile static -SkipBuild

# 明确删除并重建数据目录
.\install-docker.ps1 -Profile static -ResetData

# 代理构建
.\install-docker.ps1 -UseProxy
.\install-docker.ps1 -HttpProxy "http://127.0.0.1:7890" -HttpsProxy "http://127.0.0.1:7890"

# 生成 MCP 客户端配置
.\install-docker.ps1 -ConfigureClient Codex
```

参数说明：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-Profile` | `static` | `static` / `hybrid` / `full` |
| `-DataRoot` | `D:\Docker\rikune` | Docker 持久化数据目录 |
| `-ProjectRoot` | 脚本目录 | 项目根目录 |
| `-SkipBuild` | false | 跳过 Docker build |
| `-SkipStart` | false | 跳过 Compose up |
| `-ResetData` | false | 删除并重建 `DataRoot` |
| `-UseProxy` | false | 读取 Windows 系统代理 |
| `-HttpProxy` / `-HttpsProxy` | 空 | 手工指定构建代理 |
| `-HostAgentEndpoint` | 空 | Hybrid 模式下的 Windows Host Agent URL |
| `-HostAgentApiKey` | 空 | Analyzer -> Host Agent 控制面密钥 |
| `-RuntimeApiKey` | 同 Host Agent key | Analyzer -> Runtime Node 数据面密钥 |
| `-ConfigureClient` | `None` | `Claude` / `Copilot` / `Codex` / `Generic` |
| `-Interactive` | false | 即使传了部分参数，也强制进入向导模式 |

## 手工部署

```bash
npm install
npm run build
npm run docker:generate:all
```

启动 static：

```bash
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml up -d --build analyzer
```

启动 full：

```bash
docker compose --env-file .docker-runtime.env -f docker-compose.yml up -d --build mcp-server
```

启动 hybrid：

```bash
docker compose --env-file .docker-runtime.env -f docker-compose.hybrid.yml up -d --build analyzer
```

## `.docker-runtime.env`

安装脚本会写入 `.docker-runtime.env`。示例：

```env
RIKUNE_DATA_ROOT=D:/Docker/rikune
RIKUNE_BUILD_HTTP_PROXY=
RIKUNE_BUILD_HTTPS_PROXY=
RIKUNE_BUILD_NO_PROXY=localhost,127.0.0.1,deb.debian.org,security.debian.org,mirrors.aliyun.com,archive.ubuntu.com,security.ubuntu.com,aliyuncs.com
```

Hybrid 还需要：

```env
RUNTIME_HOST_AGENT_ENDPOINT=http://192.168.1.10:18082
RUNTIME_HOST_AGENT_API_KEY=<host-agent-key>
RUNTIME_API_KEY=<runtime-node-key-or-same-key>
```

## 数据目录结构

```text
D:\Docker\rikune\
  samples\
  workspaces\
  data\
  cache\
  logs\
  storage\
  ghidra-projects\
  ghidra-logs\
  qiling-rootfs\
  config\
```

## 常用命令

```powershell
# 查看容器
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml ps

# 查看日志
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml logs -f analyzer

# 停止 static analyzer
docker compose --env-file .docker-runtime.env -f docker-compose.analyzer.yml down

# 健康检查
Invoke-WebRequest http://localhost:18080/api/v1/health -UseBasicParsing
```

## Hybrid 快速说明

Windows 单机：

```powershell
.\rikune.ps1 install -Profile hybrid -InstallRuntime -Service
```

Windows 运行时侧手工安装：

```powershell
.\install-runtime-windows.ps1 -Headless -Service -ApiKey <host-agent-key>
```

Linux 侧：

```bash
./rikune.sh install --profile hybrid --windows-host <windows-host> --windows-user <windows-user>
./diagnose-hybrid.sh -w <windows-host> -u <windows-user>
```

关键边界：

- Docker/WSL analyzer 不能使用 `auto-sandbox`。
- `static` 默认不执行样本。
- `hybrid` 通过 Windows Host Agent 启动 Windows Sandbox。
- `RUNTIME_HOST_AGENT_API_KEY` 用于控制 Host Agent。
- `RUNTIME_API_KEY` 只在 Runtime Node 自身需要鉴权时使用。

## 故障排查

| 症状 | 处理 |
|------|------|
| `app/dist not found copy from builder` | 重新运行 `npm run docker:generate:all` 后再 build；新版 Dockerfile 会复制 monorepo `packages/` 并显式检查 `/app/dist/index.js` |
| Docker build 代理指向 `127.0.0.1` 失败 | 使用安装脚本传 `-UseProxy` 或 `-HttpProxy`，脚本会转换为 `host.docker.internal` |
| Hybrid 连接不上 Host Agent | 检查 Windows 防火墙、`RUNTIME_HOST_AGENT_ENDPOINT`、`RUNTIME_HOST_AGENT_API_KEY`，并运行 `diagnose-hybrid.sh` |
| 想清空持久化数据 | 显式传 `-ResetData`，不要手工删除不确定路径 |

更多部署细节见 [`DEPLOYMENT.md`](./DEPLOYMENT.md) 和 [`docs/docker.html`](./docs/docker.html)。
