import fs from 'fs'
import os from 'os'
import path from 'path'
import { setTimeout as sleep } from 'timers/promises'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  type CallToolResult,
  type Implementation,
  ListToolsRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js'
import {
  buildDockerLauncherCommand,
  formatCommand,
  maskDockerLauncherCommand,
} from './npm-docker-launcher.js'

type AgentTarget = 'analyzer' | 'vm' | 'runtime'
type McpTransportKind = 'docker-stdio' | 'docker-run' | 'stdio' | 'streamable-http'

interface UpstreamConfig {
  enabled?: boolean
  transport?: McpTransportKind
  command?: string
  args?: string[]
  cwd?: string
  endpoint?: string
  healthEndpoint?: string
  mcpEndpoint?: string
  apiKey?: string
  container?: string
  image?: string
  timeoutMs?: number
}

interface AgentConfig {
  analyzer: UpstreamConfig
  vm: UpstreamConfig
  runtime: UpstreamConfig
}

interface UpstreamState {
  client: Client | null
  tools: Tool[]
  connected: boolean
  serverVersion?: Implementation
  lastError?: string
  lastConnectedAt?: string
  lastRefreshAt?: string
  httpHealth?: unknown
  capabilities?: unknown
  toolkit?: unknown
}

interface ToolRoute {
  target: AgentTarget
  exposedName: string
  upstreamName: string
}

interface AgentOptions {
  env?: NodeJS.ProcessEnv
  configPath?: string
}

const VERSION = '1.0.0-beta.3'
const DEFAULT_CONNECT_TIMEOUT_MS = 30_000
const DEFAULT_TOOL_TIMEOUT_MS = 300_000
const DEFAULT_ANALYZER_HTTP_ENDPOINT = 'http://localhost:18080'

const CONTROL_TOOL_NAMES = new Set([
  'rikune_connection_status',
  'rikune_connection_configure',
  'rikune_connection_refresh',
])

const CONTROL_TOOLS: Tool[] = [
  {
    name: 'rikune_connection_status',
    description:
      'Query Rikune connector status, configured analyzer/VM/runtime endpoints, health, and upstream tool counts.',
    inputSchema: {
      type: 'object',
      properties: {
        refresh: {
          type: 'boolean',
          description: 'Refresh upstream health and tool lists before returning status.',
        },
        include_tools: {
          type: 'boolean',
          description: 'Include exposed upstream tool names in the response.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'rikune_connection_configure',
    description:
      'Configure analyzer, VM Host Agent, or Runtime Node connection settings used by the Rikune connector.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          enum: ['analyzer', 'vm', 'runtime'],
          description: 'Connection plane to configure.',
        },
        enabled: {
          type: 'boolean',
          description: 'Enable or disable this upstream connection.',
        },
        transport: {
          type: 'string',
          enum: ['docker-stdio', 'docker-run', 'stdio', 'streamable-http'],
          description:
            'MCP transport for tool discovery. VM/runtime can use HTTP health without an MCP transport.',
        },
        endpoint: {
          type: 'string',
          description:
            'HTTP base endpoint for health checks, such as analyzer API, Host Agent, or Runtime Node.',
        },
        health_endpoint: {
          type: 'string',
          description: 'Explicit health URL. Usually leave unset and provide endpoint instead.',
        },
        mcp_endpoint: {
          type: 'string',
          description:
            'Streamable HTTP MCP endpoint. When set, the connector pulls and proxies upstream tools.',
        },
        command: {
          type: 'string',
          description: 'Stdio MCP command for a custom upstream server.',
        },
        args: {
          type: 'array',
          items: { type: 'string' },
          description: 'Arguments for a custom stdio MCP command.',
        },
        cwd: {
          type: 'string',
          description: 'Working directory for a custom stdio MCP command.',
        },
        container: {
          type: 'string',
          description: 'Docker analyzer container name for docker-stdio.',
        },
        image: {
          type: 'string',
          description: 'Docker image name for docker-run.',
        },
        api_key: {
          type: 'string',
          description: 'API key for the selected endpoint. Status output only reports whether it is set.',
        },
        timeout_ms: {
          type: 'number',
          description: 'Connection/list-tools timeout in milliseconds.',
        },
        persist: {
          type: 'boolean',
          description: 'Persist the setting to the local Rikune agent config file. Defaults to true.',
        },
        refresh: {
          type: 'boolean',
          description: 'Refresh the selected upstream after applying the setting. Defaults to true.',
        },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'rikune_connection_refresh',
    description: 'Reconnect upstream services and refresh proxied tool lists.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          enum: ['all', 'analyzer', 'vm', 'runtime'],
          description: 'Connection plane to refresh. Defaults to all.',
        },
      },
      additionalProperties: false,
    },
  },
]

export class RikuneAgentGateway {
  private readonly env: NodeJS.ProcessEnv
  private readonly configPath: string
  private readonly server: Server
  private started = false
  private config: AgentConfig
  private states: Record<AgentTarget, UpstreamState>
  private toolRoutes = new Map<string, ToolRoute>()

  constructor(options: AgentOptions = {}) {
    this.env = loadEffectiveEnv(options.env ?? process.env)
    this.configPath = options.configPath || getAgentConfigPath(this.env)
    this.config = buildAgentConfig(this.env, loadPersistedConfig(this.configPath))
    this.states = {
      analyzer: createEmptyState(),
      vm: createEmptyState(),
      runtime: createEmptyState(),
    }

    this.server = new Server(
      {
        name: 'rikune-agent',
        version: VERSION,
      },
      {
        capabilities: {
          tools: {
            listChanged: true,
          },
        },
        instructions:
          'Rikune agent is a connector. Use rikune_connection_status, rikune_connection_configure, and rikune_connection_refresh to manage upstream analyzer and runtime links.',
      }
    )

    this.setupHandlers()
  }

  async start(): Promise<void> {
    const transport = new StdioServerTransport()
    await this.server.connect(transport)
    process.stdin.once('end', () => {
      this.stop().finally(() => process.exit(0))
    })
    this.started = true
  }

  async stop(): Promise<void> {
    await Promise.all(
      (['analyzer', 'vm', 'runtime'] as AgentTarget[]).map((target) =>
        withTimeout(this.closeTarget(target), 1_500).catch(() => {})
      )
    )
    await withTimeout(this.server.close(), 1_000).catch(() => {})
  }

  async refreshAll(options: { notify?: boolean } = {}): Promise<void> {
    await Promise.all([
      this.refreshTarget('analyzer'),
      this.refreshTarget('vm'),
      this.refreshTarget('runtime'),
    ])
    if (options.notify !== false) {
      this.notifyToolListChanged()
    }
  }

  async refreshTarget(target: AgentTarget): Promise<void> {
    const config = this.config[target]
    const state = this.states[target]
    state.lastRefreshAt = new Date().toISOString()
    state.lastError = undefined

    await this.closeTarget(target)
    state.tools = []
    state.connected = false
    state.serverVersion = undefined
    state.httpHealth = undefined
    state.capabilities = undefined
    state.toolkit = undefined

    if (config.enabled === false) {
      state.lastError = 'Connection is disabled.'
      return
    }

    await this.refreshHttpPlane(target, config, state)
    await this.refreshMcpPlane(target, config, state)
  }

  getStatus(includeTools = false): Record<string, unknown> {
    const tools = this.listExposedTools()
    return {
      ok: true,
      data: {
        config_path: this.configPath,
        exposed_tool_count: tools.length,
        control_tool_count: CONTROL_TOOLS.length,
        upstream_tool_count: tools.length - CONTROL_TOOLS.length,
        analyzer: this.describeTarget('analyzer'),
        vm: this.describeTarget('vm'),
        runtime: this.describeTarget('runtime'),
        ...(includeTools
          ? {
              tools: tools.map((tool) => tool.name),
            }
          : {}),
      },
    }
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.listExposedTools(),
    }))

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const name = request.params.name
      const args = (request.params.arguments || {}) as Record<string, unknown>

      if (name === 'rikune_connection_status') {
        return this.asToolResult(await this.handleStatus(args))
      }
      if (name === 'rikune_connection_configure') {
        return this.asToolResult(await this.handleConfigure(args))
      }
      if (name === 'rikune_connection_refresh') {
        return this.asToolResult(await this.handleRefresh(args))
      }

      return await this.proxyToolCall(name, args)
    })
  }

  private async handleStatus(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (args.refresh === true) {
      await this.refreshAll()
    }
    return this.getStatus(args.include_tools === true)
  }

  private async handleConfigure(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const target = parseTarget(args.target)
    const current = this.config[target]
    const next: UpstreamConfig = { ...current }

    assignBoolean(args, 'enabled', next, 'enabled')
    assignString(args, 'transport', next, 'transport')
    assignString(args, 'endpoint', next, 'endpoint')
    assignString(args, 'health_endpoint', next, 'healthEndpoint')
    assignString(args, 'mcp_endpoint', next, 'mcpEndpoint')
    assignString(args, 'command', next, 'command')
    assignString(args, 'cwd', next, 'cwd')
    assignString(args, 'container', next, 'container')
    assignString(args, 'image', next, 'image')
    assignString(args, 'api_key', next, 'apiKey')
    assignNumber(args, 'timeout_ms', next, 'timeoutMs')
    if (Array.isArray(args.args)) {
      next.args = args.args.filter((value): value is string => typeof value === 'string')
    }
    if (next.mcpEndpoint && !next.transport) {
      next.transport = 'streamable-http'
    }
    if ((next.command || next.args?.length) && !next.transport) {
      next.transport = 'stdio'
    }
    if (next.enabled === undefined) {
      next.enabled = true
    }

    this.config[target] = next
    if (args.persist !== false) {
      savePersistedConfig(this.configPath, this.config)
    }

    if (args.refresh !== false) {
      await this.refreshTarget(target)
      this.notifyToolListChanged()
    }

    return {
      ok: true,
      data: {
        target,
        persisted: args.persist !== false,
        refreshed: args.refresh !== false,
        status: this.describeTarget(target),
      },
    }
  }

  private async handleRefresh(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const target = typeof args.target === 'string' ? args.target : 'all'
    if (target === 'all') {
      await this.refreshAll()
    } else {
      await this.refreshTarget(parseTarget(target))
      this.notifyToolListChanged()
    }
    return this.getStatus(false)
  }

  private async proxyToolCall(
    exposedName: string,
    args: Record<string, unknown>
  ): Promise<CallToolResult> {
    const route = this.resolveRoute(exposedName)
    if (!route) {
      return this.errorToolResult(`Tool not found: ${exposedName}`)
    }

    const state = this.states[route.target]
    if (!state.client || !state.connected) {
      return this.errorToolResult(`Upstream ${route.target} is not connected.`)
    }

    try {
      const timeout = this.config[route.target].timeoutMs || getToolTimeoutMs(this.env)
      return (await state.client.callTool(
        {
          name: route.upstreamName,
          arguments: args,
        },
        undefined,
        {
          timeout,
          resetTimeoutOnProgress: true,
        }
      )) as CallToolResult
    } catch (error) {
      state.lastError = errorMessage(error)
      return this.errorToolResult(
        `Upstream ${route.target} tool call failed: ${errorMessage(error)}`
      )
    }
  }

  private listExposedTools(): Tool[] {
    const tools: Tool[] = [...CONTROL_TOOLS]
    const routes = new Map<string, ToolRoute>()
    const usedNames = new Set(CONTROL_TOOL_NAMES)

    for (const target of ['analyzer', 'vm', 'runtime'] as AgentTarget[]) {
      const state = this.states[target]
      if (!state.connected || state.tools.length === 0) {
        continue
      }

      for (const tool of state.tools) {
        let exposedName = tool.name
        if (usedNames.has(exposedName)) {
          exposedName = `${target}_${tool.name}`.replace(/[^A-Za-z0-9_-]/g, '_')
        }
        if (usedNames.has(exposedName)) {
          continue
        }
        usedNames.add(exposedName)
        routes.set(exposedName, {
          target,
          exposedName,
          upstreamName: tool.name,
        })
        tools.push({
          ...tool,
          name: exposedName,
          description:
            exposedName === tool.name
              ? tool.description
              : `[${target}] ${tool.description || tool.name}`,
        })
      }
    }

    this.toolRoutes = routes
    return tools
  }

  private resolveRoute(exposedName: string): ToolRoute | undefined {
    const existing = this.toolRoutes.get(exposedName)
    if (existing) {
      return existing
    }
    this.listExposedTools()
    return this.toolRoutes.get(exposedName)
  }

  private async refreshHttpPlane(
    target: AgentTarget,
    config: UpstreamConfig,
    state: UpstreamState
  ): Promise<void> {
    const healthUrls = getHealthUrls(target, config)
    if (healthUrls.length === 0) {
      return
    }

    try {
      state.httpHealth = await fetchFirstJson(healthUrls, getHttpHeaders(target, config), 8_000)
      if (target === 'runtime' && config.endpoint) {
        state.capabilities = await fetchJson(
          toHostReachableUrl(new URL('/capabilities', config.endpoint).toString()),
          getHttpHeaders(target, config),
          8_000
        ).catch((error) => ({ ok: false, error: errorMessage(error) }))
        state.toolkit = await fetchJson(
          toHostReachableUrl(new URL('/toolkit', config.endpoint).toString()),
          getHttpHeaders(target, config),
          8_000
        ).catch((error) => ({ ok: false, error: errorMessage(error) }))
      }
    } catch (error) {
      state.lastError = errorMessage(error)
      state.httpHealth = { ok: false, error: errorMessage(error) }
    }
  }

  private async refreshMcpPlane(
    target: AgentTarget,
    config: UpstreamConfig,
    state: UpstreamState
  ): Promise<void> {
    const transportConfig = buildTransportConfig(target, config, this.env)
    if (!transportConfig) {
      return
    }

    try {
      const client = new Client(
        {
          name: `rikune-agent-${target}`,
          version: VERSION,
        },
        {
          capabilities: {},
        }
      )
      await client.connect(transportConfig.transport, {
        timeout: config.timeoutMs || getConnectTimeoutMs(this.env),
      })
      const listed = await client.listTools(undefined, {
        timeout: config.timeoutMs || getConnectTimeoutMs(this.env),
      })
      state.client = client
      state.tools = listed.tools || []
      state.connected = true
      state.serverVersion = client.getServerVersion()
      state.lastConnectedAt = new Date().toISOString()
      state.lastError = undefined
    } catch (error) {
      state.lastError = errorMessage(error)
      state.connected = false
      state.tools = []
      try {
        await transportConfig.transport.close()
      } catch {}
    }
  }

  private async closeTarget(target: AgentTarget): Promise<void> {
    const client = this.states[target].client
    this.states[target].client = null
    if (!client) {
      return
    }
    await client.close().catch(() => {})
  }

  private describeTarget(target: AgentTarget): Record<string, unknown> {
    const config = this.config[target]
    const state = this.states[target]
    return {
      enabled: config.enabled !== false,
      transport: config.transport || null,
      endpoint: config.endpoint || null,
      health_endpoint: getHealthUrl(target, config),
      health_endpoint_candidates: getHealthUrls(target, config),
      mcp_endpoint: config.mcpEndpoint || null,
      command: config.command || null,
      args: config.args || [],
      cwd: config.cwd || null,
      container: config.container || null,
      image: config.image || null,
      api_key_configured: Boolean(config.apiKey),
      mcp_connected: state.connected,
      http_health: state.httpHealth || null,
      tool_count: state.tools.length,
      server: state.serverVersion || null,
      last_connected_at: state.lastConnectedAt || null,
      last_refresh_at: state.lastRefreshAt || null,
      last_error: state.lastError || null,
      ...(state.capabilities ? { capabilities: state.capabilities } : {}),
      ...(state.toolkit ? { toolkit: state.toolkit } : {}),
    }
  }

  private asToolResult(payload: Record<string, unknown>): CallToolResult {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(payload),
        },
      ],
      structuredContent: payload,
      isError: payload.ok === false,
    }
  }

  private errorToolResult(message: string): CallToolResult {
    return this.asToolResult({
      ok: false,
      errors: [message],
    })
  }

  private notifyToolListChanged(): void {
    if (!this.started) {
      return
    }
    this.server.sendToolListChanged().catch(() => {})
  }
}

export async function runRikuneAgentCli(
  args: string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env
): Promise<number> {
  const command = !args[0] || args[0].startsWith('-') ? 'stdio' : args[0]
  const rest = command === 'stdio' && args[0] === 'stdio' ? args.slice(1) : args

  if (command === '--help' || command === '-h' || rest.includes('--help') || rest.includes('-h')) {
    process.stdout.write(
      [
        'Usage:',
        '  rikune-agent stdio [--no-initial-refresh]',
        '  rikune-agent stdio --print-command',
        '',
        'Environment:',
        '  RIKUNE_DOCKER_CONTAINER   Docker analyzer container name',
        '  RIKUNE_ANALYZER_ENDPOINT  Analyzer HTTP endpoint for health checks',
        '  RUNTIME_HOST_AGENT_ENDPOINT / RUNTIME_HOST_AGENT_API_KEY',
        '  RUNTIME_ENDPOINT / RUNTIME_API_KEY',
        '',
      ].join('\n')
    )
    return 0
  }

  if (command !== 'stdio') {
    process.stderr.write(`Unknown rikune-agent command: ${command}\n`)
    return 1
  }

  const effectiveEnv = loadEffectiveEnv(env)
  if (rest.includes('--print-command')) {
    const cmd = buildDockerLauncherCommand('docker-stdio', [], effectiveEnv)
    process.stdout.write(formatCommand(cmd.command, maskDockerLauncherCommand(cmd.args)) + '\n')
    return 0
  }

  const gateway = new RikuneAgentGateway({ env: effectiveEnv })
  if (!rest.includes('--no-initial-refresh')) {
    await gateway.refreshAll({ notify: false })
  }
  await gateway.start()

  const shutdown = async () => {
    await gateway.stop().catch(() => {})
    process.exit(0)
  }
  process.once('SIGINT', shutdown)
  process.once('SIGTERM', shutdown)
  return await new Promise<number>(() => {})
}

function createEmptyState(): UpstreamState {
  return {
    client: null,
    tools: [],
    connected: false,
  }
}

function loadEffectiveEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const fileEnv = loadRuntimeEnvFiles(env)
  return {
    ...fileEnv,
    ...env,
  }
}

function loadRuntimeEnvFiles(env: NodeJS.ProcessEnv): Record<string, string> {
  if (env.RIKUNE_AGENT_NO_ENV_FILE === '1' || env.RIKUNE_AGENT_LOAD_ENV_FILE === 'false') {
    return {}
  }

  const candidates = [
    env.RIKUNE_AGENT_ENV_FILE,
    env.RIKUNE_DOCKER_ENV_FILE,
    path.join(process.cwd(), '.docker-runtime.env'),
  ].filter((value): value is string => Boolean(value))

  const result: Record<string, string> = {}
  for (const candidate of candidates) {
    Object.assign(result, parseEnvFile(candidate))
  }
  return result
}

function parseEnvFile(filePath: string): Record<string, string> {
  try {
    if (!fs.existsSync(filePath)) {
      return {}
    }
    const parsed: Record<string, string> = {}
    for (const rawLine of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
      const line = rawLine.trim()
      if (!line || line.startsWith('#')) {
        continue
      }
      const index = line.indexOf('=')
      if (index <= 0) {
        continue
      }
      const key = line.slice(0, index).trim()
      let value = line.slice(index + 1).trim()
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1)
      }
      parsed[key] = value
    }
    return parsed
  } catch {
    return {}
  }
}

function getAgentConfigPath(env: NodeJS.ProcessEnv): string {
  if (env.RIKUNE_AGENT_CONFIG) {
    return env.RIKUNE_AGENT_CONFIG
  }
  const home = env.RIKUNE_HOME || path.join(os.homedir(), '.rikune')
  return path.join(home, 'agent.json')
}

function loadPersistedConfig(configPath: string): Partial<AgentConfig> {
  try {
    if (!fs.existsSync(configPath)) {
      return {}
    }
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf8')) as Partial<AgentConfig>
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

function savePersistedConfig(configPath: string, config: AgentConfig): void {
  fs.mkdirSync(path.dirname(configPath), { recursive: true })
  fs.writeFileSync(
    configPath,
    JSON.stringify(
      {
        analyzer: config.analyzer,
        vm: config.vm,
        runtime: config.runtime,
        updated_at: new Date().toISOString(),
      },
      null,
      2
    ) + '\n',
    'utf8'
  )
}

function buildAgentConfig(env: NodeJS.ProcessEnv, persisted: Partial<AgentConfig>): AgentConfig {
  const analyzerEndpoint =
    env.RIKUNE_ANALYZER_ENDPOINT || env.ANALYZER_ENDPOINT || ''
  const vmEndpoint = env.RIKUNE_VM_ENDPOINT || env.RUNTIME_HOST_AGENT_ENDPOINT || ''
  const runtimeEndpoint = env.RIKUNE_RUNTIME_ENDPOINT || env.RUNTIME_ENDPOINT || ''

  const analyzer: UpstreamConfig = {
    enabled: persisted.analyzer?.enabled ?? true,
    transport: persisted.analyzer?.transport || 'docker-stdio',
    endpoint: persisted.analyzer?.endpoint || analyzerEndpoint || DEFAULT_ANALYZER_HTTP_ENDPOINT,
    ...persisted.analyzer,
  }
  const vm: UpstreamConfig = {
    enabled: Boolean(persisted.vm?.endpoint || persisted.vm?.mcpEndpoint),
    ...persisted.vm,
  }
  const runtime: UpstreamConfig = {
    enabled: Boolean(persisted.runtime?.endpoint || persisted.runtime?.mcpEndpoint),
    ...persisted.runtime,
  }

  if (env.RIKUNE_ANALYZER_TRANSPORT) {
    analyzer.transport = env.RIKUNE_ANALYZER_TRANSPORT as McpTransportKind
  }
  if (analyzerEndpoint) {
    analyzer.endpoint = analyzerEndpoint
  }
  if (env.RIKUNE_ANALYZER_API_KEY || env.ANALYZER_API_KEY || env.API_KEY) {
    analyzer.apiKey = env.RIKUNE_ANALYZER_API_KEY || env.ANALYZER_API_KEY || env.API_KEY
  }
  if (env.RIKUNE_DOCKER_CONTAINER || env.RIKUNE_ANALYZER_CONTAINER) {
    analyzer.container = env.RIKUNE_DOCKER_CONTAINER || env.RIKUNE_ANALYZER_CONTAINER
  }
  if (env.RIKUNE_DOCKER_IMAGE) {
    analyzer.image = env.RIKUNE_DOCKER_IMAGE
  }

  if (vmEndpoint) {
    vm.enabled = true
    vm.endpoint = vmEndpoint
  }
  if (env.RIKUNE_VM_API_KEY || env.RUNTIME_HOST_AGENT_API_KEY) {
    vm.apiKey = env.RIKUNE_VM_API_KEY || env.RUNTIME_HOST_AGENT_API_KEY
  }
  if (env.RIKUNE_VM_MCP_ENDPOINT) {
    vm.enabled = true
    vm.mcpEndpoint = env.RIKUNE_VM_MCP_ENDPOINT
    vm.transport = vm.transport || 'streamable-http'
  }
  if (vm.mcpEndpoint && !vm.transport) {
    vm.transport = 'streamable-http'
  }

  if (runtimeEndpoint) {
    runtime.enabled = true
    runtime.endpoint = runtimeEndpoint
  }
  if (env.RIKUNE_RUNTIME_MCP_ENDPOINT) {
    runtime.enabled = true
    runtime.mcpEndpoint = env.RIKUNE_RUNTIME_MCP_ENDPOINT
    runtime.transport = runtime.transport || 'streamable-http'
  }
  if (env.RIKUNE_RUNTIME_API_KEY || env.RUNTIME_API_KEY) {
    runtime.apiKey = env.RIKUNE_RUNTIME_API_KEY || env.RUNTIME_API_KEY
  }
  if (runtime.mcpEndpoint && !runtime.transport) {
    runtime.transport = 'streamable-http'
  }

  return { analyzer, vm, runtime }
}

function buildTransportConfig(
  target: AgentTarget,
  config: UpstreamConfig,
  env: NodeJS.ProcessEnv
):
  | {
      transport: StdioClientTransport | StreamableHTTPClientTransport
    }
  | null {
  const transport = config.transport || (target === 'analyzer' ? 'docker-stdio' : undefined)
  if (!transport) {
    return null
  }

  if (transport === 'docker-stdio' || transport === 'docker-run') {
    if (target !== 'analyzer') {
      return null
    }
    const mergedEnv: NodeJS.ProcessEnv = {
      ...env,
      ...(config.container ? { RIKUNE_DOCKER_CONTAINER: config.container } : {}),
      ...(config.image ? { RIKUNE_DOCKER_IMAGE: config.image } : {}),
    }
    const cmd = buildDockerLauncherCommand(transport, [], mergedEnv)
    return {
      transport: new StdioClientTransport({
        command: cmd.command,
        args: cmd.args,
        env: toSpawnEnv(env),
        stderr: 'inherit',
      }),
    }
  }

  if (transport === 'stdio') {
    if (!config.command) {
      return null
    }
    return {
      transport: new StdioClientTransport({
        command: config.command,
        args: config.args || [],
        cwd: config.cwd,
        env: toSpawnEnv(env),
        stderr: 'inherit',
      }),
    }
  }

  if (transport === 'streamable-http') {
    const endpoint = config.mcpEndpoint || config.endpoint
    if (!endpoint) {
      return null
    }
    return {
      transport: new StreamableHTTPClientTransport(new URL(endpoint), {
        requestInit: {
          headers: getHttpHeaders(target, config),
        },
      }),
    }
  }

  return null
}

function toSpawnEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => typeof entry[1] === 'string')
  )
}

function getHealthUrl(target: AgentTarget, config: UpstreamConfig): string | null {
  if (config.healthEndpoint) {
    return config.healthEndpoint
  }
  if (!config.endpoint) {
    return null
  }
  try {
    if (target === 'analyzer') {
      return new URL('/api/v1/health', config.endpoint).toString()
    }
    if (target === 'vm') {
      return new URL('/sandbox/health', config.endpoint).toString()
    }
    return new URL('/health', config.endpoint).toString()
  } catch {
    return config.endpoint
  }
}

function getHealthUrls(target: AgentTarget, config: UpstreamConfig): string[] {
  const healthUrl = getHealthUrl(target, config)
  if (!healthUrl) {
    return []
  }
  return uniqueStrings([healthUrl, toHostReachableUrl(healthUrl)])
}

function toHostReachableUrl(value: string): string {
  try {
    const url = new URL(value)
    if (url.hostname.toLowerCase() === 'host.docker.internal') {
      url.hostname = 'localhost'
      return url.toString()
    }
  } catch {}
  return value
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)))
}

function getHttpHeaders(target: AgentTarget, config: UpstreamConfig): Record<string, string> {
  if (!config.apiKey) {
    return {}
  }
  if (target === 'analyzer') {
    return { 'x-api-key': config.apiKey }
  }
  return { Authorization: `Bearer ${config.apiKey}` }
}

async function fetchFirstJson(
  urls: string[],
  headers: Record<string, string>,
  timeoutMs: number
): Promise<unknown> {
  let lastError: unknown
  for (const url of urls) {
    try {
      const body = await fetchJson(url, headers, timeoutMs)
      return {
        endpoint: url,
        body,
      }
    } catch (error) {
      lastError = error
    }
  }
  throw lastError ?? new Error('No health endpoint candidates were available.')
}

async function fetchJson(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number
): Promise<unknown> {
  const response = await fetch(url, {
    headers,
    signal: AbortSignal.timeout(timeoutMs),
  })
  const text = await response.text()
  let body: unknown = text
  try {
    body = text ? JSON.parse(text) : null
  } catch {}
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}${text ? ` ${text.slice(0, 500)}` : ''}`)
  }
  return body
}

function parseTarget(value: unknown): AgentTarget {
  if (value === 'analyzer' || value === 'vm' || value === 'runtime') {
    return value
  }
  throw new Error('target must be one of analyzer, vm, runtime')
}

function assignString<T extends object>(
  args: Record<string, unknown>,
  sourceKey: string,
  target: T,
  targetKey: keyof T
): void {
  const value = args[sourceKey]
  if (typeof value === 'string') {
    target[targetKey] = value.trim() as T[keyof T]
  }
}

function assignBoolean<T extends object>(
  args: Record<string, unknown>,
  sourceKey: string,
  target: T,
  targetKey: keyof T
): void {
  const value = args[sourceKey]
  if (typeof value === 'boolean') {
    target[targetKey] = value as T[keyof T]
  }
}

function assignNumber<T extends object>(
  args: Record<string, unknown>,
  sourceKey: string,
  target: T,
  targetKey: keyof T
): void {
  const value = args[sourceKey]
  if (typeof value === 'number' && Number.isFinite(value)) {
    target[targetKey] = value as T[keyof T]
  }
}

function getConnectTimeoutMs(env: NodeJS.ProcessEnv): number {
  return parsePositiveInt(env.RIKUNE_AGENT_CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS)
}

function getToolTimeoutMs(env: NodeJS.ProcessEnv): number {
  return parsePositiveInt(env.RIKUNE_AGENT_TOOL_TIMEOUT_MS, DEFAULT_TOOL_TIMEOUT_MS)
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value || '', 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T | undefined> {
  return await Promise.race([promise, sleep(timeoutMs, undefined, { ref: false })])
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
