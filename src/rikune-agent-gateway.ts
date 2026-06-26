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
const DIRECT_TOOL_CALL_NAME = 'rikune_tool_call'

const GATEWAY_INSTRUCTIONS = [
  'You are connected to Rikune through the Rikune Agent Gateway.',
  'This gateway intentionally exposes a small, stable MCP tool surface. Do not wait for, request, or expect specialist analyzer tools to appear in tools/list after refresh.',
  'Use workflow_search first for capability discovery, workflow selection, readiness checks, and explicit activation. workflow_search is passive unless action=activate is explicitly requested.',
  'Use workflow_run for the normal execution path: request_upload, start, status, and promote. Do not call low-level sample or workflow.analyze tools directly from the MCP surface.',
  'Use artifact_read for persisted evidence, summaries, reports, decompiler output, and other artifacts returned by workflow_run or workflow_search.',
  'Use rikune_tool_call only as an advanced subtool gateway when workflow_search identifies a specific internal analyzer tool that is not covered by workflow_run or artifact_read. Pass the internal tool name in the tool field and the tool arguments in arguments; the tool does not need to appear in upstream tools/list after activation.',
  'Connection tools manage upstream analyzer, VM, and runtime links. Refresh updates the internal capability cache only; it does not expand the MCP tool list.',
].join('\n')

const CONTROL_TOOL_NAMES = new Set([
  'rikune_connection_status',
  'rikune_connection_configure',
  'rikune_connection_refresh',
])

const STABLE_ANALYZER_TOOLS: Tool[] = [
  {
    name: 'workflow_search',
    description:
      'Primary Rikune analyzer planning and discovery gateway. Use this first to search, recommend, list, check status, or explicitly activate analysis capabilities. It is passive for status/search/recommend/list and does not require MCP tool-list refreshes.',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['status', 'search', 'recommend', 'list', 'activate'],
          description:
            'Search gateway action. Defaults to search. activate opens internal routes on the analyzer but does not change this MCP surface.',
        },
        query: {
          type: 'string',
          description: 'Natural-language user request or capability query.',
        },
        sample_id: {
          type: 'string',
          description: 'Optional sample ID used for file-type/profile routing.',
        },
        file_type: {
          type: 'string',
          description: 'Optional file type or extension hint, such as pe, .exe, elf, apk, wasm.',
        },
        goal: {
          type: 'string',
          enum: ['triage', 'static', 'reverse', 'dynamic', 'report'],
          description: 'Analyst goal used to enrich passive routing search.',
        },
        depth: {
          type: 'string',
          enum: ['safe', 'balanced', 'deep'],
          description: 'Requested analysis depth used to enrich passive routing search.',
        },
        category: { type: 'string', description: 'Optional capability category filter.' },
        plugin_id: { type: 'string', description: 'Optional plugin ID filter.' },
        tool_name: {
          type: 'string',
          description: 'Optional canonical or transport tool name filter.',
        },
        result_id: {
          type: 'string',
          description:
            'Stable result ID returned by a prior workflow.search result. Use with action=activate to expose only that result-scoped analyzer route internally.',
        },
        finding: {
          type: 'string',
          description: 'Optional finding/signal hint, such as packed, crypto, shellcode, c2.',
        },
        top_k: {
          oneOf: [
            { type: 'number', minimum: 1, maximum: 25 },
            { type: 'string', enum: ['auto'] },
          ],
          description: 'Maximum ranked recommendations to return. Defaults to auto upstream.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'workflow_run',
    description:
      'Primary Rikune analyzer execution gateway. Use request_upload for host-file upload, start with a sample_id, status with a plan_id, and promote for deeper staged analysis. Prefer this over low-level sample or workflow.analyze tools.',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['request_upload', 'start', 'status', 'promote'],
          description:
            'Whitelisted workflow action. Defaults to start upstream. request_upload creates an upload URL.',
        },
        filename: { type: 'string', description: 'Optional original filename for upload.' },
        ttl_seconds: {
          type: 'number',
          minimum: 30,
          maximum: 3600,
          description: 'Upload token TTL for action=request_upload.',
        },
        sample_id: { type: 'string', description: 'Required for action=start.' },
        plan_id: {
          type: 'string',
          description: 'Plan/run ID required for action=status and action=promote.',
        },
        goal: {
          type: 'string',
          enum: ['triage', 'static', 'reverse', 'dynamic', 'report'],
          description: 'Analysis goal for action=start.',
        },
        depth: {
          type: 'string',
          enum: ['safe', 'balanced', 'deep'],
          description: 'Analysis depth for action=start.',
        },
        backend_policy: {
          type: 'string',
          enum: ['auto', 'prefer_new', 'legacy_only', 'strict'],
          description: 'Backend routing policy for action=start.',
        },
        allow_transformations: {
          type: 'boolean',
          description: 'Allow transform-capable later stages when explicitly promoted.',
        },
        allow_live_execution: {
          type: 'boolean',
          description:
            'Allow live-execution-capable routing only when downstream policy permits it.',
        },
        stages: {
          type: 'array',
          items: {
            type: 'string',
            enum: [
              'fast_profile',
              'enrich_static',
              'function_map',
              'reconstruct',
              'semantic_name_review',
              'semantic_explain_review',
              'semantic_module_review',
              'dynamic_plan',
              'dynamic_execute',
              'summarize',
            ],
          },
          description: 'Optional promoted stages for action=promote.',
        },
        through_stage: {
          type: 'string',
          enum: [
            'fast_profile',
            'enrich_static',
            'function_map',
            'reconstruct',
            'semantic_name_review',
            'semantic_explain_review',
            'semantic_module_review',
            'dynamic_plan',
            'dynamic_execute',
            'summarize',
          ],
          description: 'Optional terminal stage for action=promote.',
        },
        force_refresh: { type: 'boolean', description: 'Bypass reusable run/stage results.' },
        include_raw_result: {
          type: 'boolean',
          description: 'Include wrapped workflow result for debugging.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'artifact_read',
    description:
      'Primary Rikune artifact reader. Use this to inspect metadata, summaries, bounded content, reports, decompiler output, and supporting evidence produced by workflow_run or internal analyzer subtools.',
    inputSchema: {
      type: 'object',
      properties: {
        sample_id: { type: 'string', description: 'Sample ID, usually sha256:<hex>.' },
        artifact_id: { type: 'string', description: 'Specific artifact UUID to fetch.' },
        artifact_type: { type: 'string', description: 'Artifact type to fetch latest match.' },
        path: { type: 'string', description: 'Artifact relative path to fetch.' },
        read_mode: {
          type: 'string',
          enum: ['profile', 'summary', 'content'],
          description:
            'profile returns selectors only, summary reads a bounded preview, content returns artifact content.',
        },
        include_untracked_files: {
          type: 'boolean',
          description: 'Allow synthetic inventory entries under scan roots.',
        },
        recursive: {
          type: 'boolean',
          description: 'Recursively scan export roots when include_untracked_files=true.',
        },
        scan_roots: {
          type: 'array',
          items: { type: 'string' },
          description: 'Workspace subdirectories to scan for untracked artifact files.',
        },
        select_latest: {
          type: 'boolean',
          description: 'When selector matches multiple artifacts, choose latest.',
        },
        include_content: { type: 'boolean', description: 'Return file content in response.' },
        max_bytes: {
          type: 'number',
          minimum: 256,
          maximum: 2097152,
          description: 'Maximum bytes to read from artifact file.',
        },
        encoding: {
          type: 'string',
          enum: ['auto', 'utf8', 'base64'],
          description: 'Content encoding mode when include_content=true.',
        },
        parse_json: {
          type: 'boolean',
          description: 'Parse JSON artifacts into structured object when content is UTF-8.',
        },
        ioc_highlights: {
          type: 'boolean',
          description: 'Extract IOC highlights from UTF-8 text content.',
        },
      },
      required: ['sample_id'],
      additionalProperties: false,
    },
  },
]

const CONTROL_TOOLS: Tool[] = [
  {
    name: 'rikune_connection_status',
    description:
      'Query Rikune connector status, configured analyzer/VM/runtime endpoints, health, stable exposed tools, and internally discovered upstream tool counts.',
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
          description:
            'API key for the selected endpoint. Status output only reports whether it is set.',
        },
        timeout_ms: {
          type: 'number',
          description: 'Connection/list-tools timeout in milliseconds.',
        },
        persist: {
          type: 'boolean',
          description:
            'Persist the setting to the local Rikune agent config file. Defaults to true.',
        },
        refresh: {
          type: 'boolean',
          description:
            'Refresh the selected upstream after applying the setting. Defaults to true.',
        },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'rikune_connection_refresh',
    description:
      'Reconnect upstream services and refresh the internal capability cache. This does not expand the stable MCP tool list.',
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

const DIRECT_TOOL_CALL_TOOL: Tool = {
  name: DIRECT_TOOL_CALL_NAME,
  description:
    'Advanced Rikune subtool gateway. Use workflow_search first to find or activate a specific internal analyzer capability, then call that internal tool here without requiring MCP clients to refresh their tool list; the internal tool does not need to appear in upstream tools/list after activation. Prefer workflow_run and artifact_read for normal analysis.',
  inputSchema: {
    type: 'object',
    properties: {
      target: {
        type: 'string',
        enum: ['analyzer', 'vm', 'runtime'],
        description: 'Upstream plane to call. Defaults to analyzer.',
      },
      tool: {
        type: 'string',
        description:
          'Internal upstream tool name, using either transport form like pe_fingerprint or canonical form like pe.fingerprint.',
      },
      arguments: {
        type: 'object',
        description: 'Arguments forwarded to the internal upstream tool.',
        additionalProperties: true,
      },
    },
    required: ['tool'],
    additionalProperties: false,
  },
}

const LOCAL_GATEWAY_TOOLS: Tool[] = [...CONTROL_TOOLS, DIRECT_TOOL_CALL_TOOL]
const LOCAL_GATEWAY_TOOL_NAMES = new Set([...CONTROL_TOOL_NAMES, DIRECT_TOOL_CALL_NAME])

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
        instructions: GATEWAY_INSTRUCTIONS,
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
    const discoveredToolCount = Object.values(this.states).reduce(
      (sum, state) => sum + state.tools.length,
      0
    )
    return {
      ok: true,
      data: {
        config_path: this.configPath,
        exposed_tool_count: tools.length,
        control_tool_count: CONTROL_TOOLS.length,
        local_gateway_tool_count: LOCAL_GATEWAY_TOOLS.length,
        stable_proxy_tool_count: tools.length - LOCAL_GATEWAY_TOOLS.length,
        upstream_tool_count: discoveredToolCount,
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
      const args = request.params.arguments || {}

      if (name === 'rikune_connection_status') {
        return this.asToolResult(await this.handleStatus(args))
      }
      if (name === 'rikune_connection_configure') {
        return this.asToolResult(await this.handleConfigure(args))
      }
      if (name === 'rikune_connection_refresh') {
        return this.asToolResult(await this.handleRefresh(args))
      }
      if (name === DIRECT_TOOL_CALL_NAME) {
        return await this.handleDirectToolCall(args)
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

  private async handleDirectToolCall(args: Record<string, unknown>): Promise<CallToolResult> {
    const target = args.target === undefined ? 'analyzer' : parseTarget(args.target)
    const requestedTool = typeof args.tool === 'string' ? args.tool.trim() : ''
    if (!requestedTool) {
      return this.errorToolResult('tool is required.')
    }
    if (LOCAL_GATEWAY_TOOL_NAMES.has(requestedTool)) {
      return this.errorToolResult(
        `Local gateway tool cannot be called through ${DIRECT_TOOL_CALL_NAME}.`
      )
    }

    const connected = await this.ensureTargetConnected(target)
    if (!connected) {
      return this.errorToolResult(`Upstream ${target} is not connected.`)
    }

    const state = this.states[target]
    const upstreamName =
      this.resolveUpstreamToolName(state, requestedTool) ??
      (target === 'analyzer' ? requestedTool : null)
    if (!upstreamName) {
      return this.errorToolResult(
        `Upstream ${target} tool not found: ${requestedTool}. Use workflow_search to discover available analyzer capabilities.`
      )
    }

    return await this.callUpstreamTool(target, upstreamName, asPlainObject(args.arguments))
  }

  private async proxyToolCall(
    exposedName: string,
    args: Record<string, unknown>
  ): Promise<CallToolResult> {
    const route = this.resolveRoute(exposedName)
    if (!route) {
      return this.errorToolResult(`Tool not found: ${exposedName}`)
    }

    const connected = await this.ensureTargetConnected(route.target)
    if (!connected) {
      return this.errorToolResult(`Upstream ${route.target} is not connected.`)
    }

    const state = this.states[route.target]
    const upstreamName =
      this.resolveUpstreamToolName(state, route.upstreamName) ?? route.upstreamName
    const result = await this.callUpstreamTool(route.target, upstreamName, args)
    return this.rewriteUploadUrlsForClient(route, args, result)
  }

  private rewriteUploadUrlsForClient(
    route: ToolRoute,
    args: Record<string, unknown>,
    result: CallToolResult
  ): CallToolResult {
    if (
      route.target !== 'analyzer' ||
      normalizeToolLookupName(route.upstreamName) !== 'workflow_run' ||
      args.action !== 'request_upload' ||
      !this.config.analyzer.endpoint
    ) {
      return result
    }

    const payload = structuredPayloadFromToolResult(result)
    if (!payload) {
      return result
    }

    const rewritten = rewriteUploadPayload(payload, this.config.analyzer.endpoint)
    if (!rewritten.changed) {
      return result
    }

    return {
      ...result,
      structuredContent: rewritten.payload,
      content: rewriteJsonTextContent(result.content, rewritten.payload),
    }
  }

  private async ensureTargetConnected(target: AgentTarget): Promise<boolean> {
    const state = this.states[target]
    if (state.client && state.connected) {
      return true
    }
    if (this.config[target].enabled === false) {
      return false
    }
    await this.refreshTarget(target)
    return Boolean(this.states[target].client && this.states[target].connected)
  }

  private async callUpstreamTool(
    target: AgentTarget,
    upstreamName: string,
    args: Record<string, unknown>
  ): Promise<CallToolResult> {
    const state = this.states[target]
    if (!state.client || !state.connected) {
      return this.errorToolResult(`Upstream ${target} is not connected.`)
    }

    try {
      const timeout = this.config[target].timeoutMs || getToolTimeoutMs(this.env)
      return (await state.client.callTool(
        {
          name: upstreamName,
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
      return this.errorToolResult(`Upstream ${target} tool call failed: ${errorMessage(error)}`)
    }
  }

  private listExposedTools(): Tool[] {
    const tools: Tool[] = [...LOCAL_GATEWAY_TOOLS]
    const routes = new Map<string, ToolRoute>()

    if (this.config.analyzer.enabled !== false) {
      for (const tool of STABLE_ANALYZER_TOOLS) {
        routes.set(tool.name, {
          target: 'analyzer',
          exposedName: tool.name,
          upstreamName: tool.name,
        })
        tools.push(tool)
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

  private resolveUpstreamToolName(state: UpstreamState, requestedTool: string): string | null {
    const normalizedRequested = normalizeToolLookupName(requestedTool)
    for (const tool of state.tools) {
      if (
        tool.name === requestedTool ||
        normalizeToolLookupName(tool.name) === normalizedRequested
      ) {
        return tool.name
      }
    }
    return null
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
  const analyzerEndpoint = env.RIKUNE_ANALYZER_ENDPOINT || env.ANALYZER_ENDPOINT || ''
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
): {
  transport: StdioClientTransport | StreamableHTTPClientTransport
} | null {
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

function structuredPayloadFromToolResult(result: CallToolResult): Record<string, unknown> | null {
  if (
    result.structuredContent &&
    typeof result.structuredContent === 'object' &&
    !Array.isArray(result.structuredContent)
  ) {
    return cloneRecord(result.structuredContent as Record<string, unknown>)
  }

  for (const item of result.content || []) {
    if (!('text' in item) || typeof item.text !== 'string') {
      continue
    }
    try {
      const parsed = JSON.parse(item.text) as unknown
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>
      }
    } catch {}
  }

  return null
}

function cloneRecord(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>
}

function rewriteJsonTextContent(
  content: CallToolResult['content'],
  payload: Record<string, unknown>
): CallToolResult['content'] {
  let replaced = false
  return (content || []).map((item) => {
    if (replaced || !('text' in item) || typeof item.text !== 'string') {
      return item
    }
    try {
      JSON.parse(item.text)
      replaced = true
      return {
        ...item,
        text: JSON.stringify(payload),
      }
    } catch {
      return item
    }
  })
}

function rewriteUploadPayload(
  payload: Record<string, unknown>,
  analyzerEndpoint: string
): { payload: Record<string, unknown>; changed: boolean } {
  const data = asPlainObject(payload.data)
  if (Object.keys(data).length === 0) {
    return { payload, changed: false }
  }

  const uploadUrl = typeof data.upload_url === 'string' ? data.upload_url : undefined
  const statusUrl = typeof data.status_url === 'string' ? data.status_url : undefined
  const rewrittenUploadUrl = uploadUrl
    ? rewriteLocalServiceUrl(uploadUrl, analyzerEndpoint)
    : undefined
  const rewrittenStatusUrl = statusUrl
    ? rewriteLocalServiceUrl(statusUrl, analyzerEndpoint)
    : undefined

  if (
    (!rewrittenUploadUrl || rewrittenUploadUrl === uploadUrl) &&
    (!rewrittenStatusUrl || rewrittenStatusUrl === statusUrl)
  ) {
    return { payload, changed: false }
  }

  const nextData: Record<string, unknown> = { ...data }
  if (rewrittenUploadUrl && uploadUrl && rewrittenUploadUrl !== uploadUrl) {
    nextData.upstream_upload_url = uploadUrl
    nextData.client_upload_url = rewrittenUploadUrl
    nextData.upload_url = rewrittenUploadUrl
  }
  if (rewrittenStatusUrl && statusUrl && rewrittenStatusUrl !== statusUrl) {
    nextData.upstream_status_url = statusUrl
    nextData.client_status_url = rewrittenStatusUrl
    nextData.status_url = rewrittenStatusUrl
  }

  const nextActions = Array.isArray(nextData.next_actions)
    ? nextData.next_actions.filter((item): item is string => typeof item === 'string')
    : []
  nextData.next_actions = uniqueStrings([
    'POST file bytes to upload_url; the gateway rewrote localhost upload URLs to the configured analyzer endpoint when needed.',
    ...nextActions,
  ])
  if (typeof nextData.message === 'string') {
    nextData.message = `${nextData.message} Gateway upload URLs were normalized for this client.`
  }

  const warnings = Array.isArray(payload.warnings)
    ? payload.warnings.filter((item): item is string => typeof item === 'string')
    : []
  return {
    payload: {
      ...payload,
      data: nextData,
      warnings: uniqueStrings([
        ...warnings,
        'Gateway rewrote localhost upload_url/status_url to the configured analyzer endpoint.',
      ]),
    },
    changed: true,
  }
}

function rewriteLocalServiceUrl(value: string, endpoint: string): string | null {
  try {
    const original = new URL(value)
    const host = original.hostname.toLowerCase()
    if (
      host !== 'localhost' &&
      host !== '127.0.0.1' &&
      host !== '0.0.0.0' &&
      host !== 'host.docker.internal'
    ) {
      return value
    }

    const base = new URL(endpoint)
    original.protocol = base.protocol
    original.hostname = base.hostname
    original.port = base.port
    original.username = ''
    original.password = ''
    return original.toString()
  } catch {
    return null
  }
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

function asPlainObject(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function normalizeToolLookupName(name: string): string {
  return name.trim().replace(/\./g, '_').toLowerCase()
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
