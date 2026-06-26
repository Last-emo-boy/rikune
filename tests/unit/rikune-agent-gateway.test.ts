import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import { RikuneAgentGateway } from '../../src/rikune-agent-gateway.js'

describe('RikuneAgentGateway stable tool surface', () => {
  let tempDir: string
  let configPath: string

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-agent-gateway-'))
    configPath = path.join(tempDir, 'agent.json')
  })

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  function createGateway(envOverrides: Record<string, string> = {}): RikuneAgentGateway {
    return new RikuneAgentGateway({
      configPath,
      env: {
        ...process.env,
        RIKUNE_AGENT_NO_ENV_FILE: '1',
        RIKUNE_ANALYZER_TRANSPORT: 'stdio',
        RIKUNE_ANALYZER_ENDPOINT: 'http://127.0.0.1:18080',
        ...envOverrides,
      },
    })
  }

  function toolNames(gateway: RikuneAgentGateway): string[] {
    const status = gateway.getStatus(true)
    const data = status.data as Record<string, unknown>
    return data.tools as string[]
  }

  test('exposes stable gateway tools before any upstream refresh', () => {
    const gateway = createGateway()
    const names = toolNames(gateway)
    const data = gateway.getStatus(true).data as Record<string, unknown>

    expect(names).toEqual([
      'rikune_connection_status',
      'rikune_connection_configure',
      'rikune_connection_refresh',
      'rikune_tool_call',
      'workflow_search',
      'workflow_run',
      'artifact_read',
    ])
    expect(data.exposed_tool_count).toBe(7)
    expect(data.control_tool_count).toBe(3)
    expect(data.local_gateway_tool_count).toBe(4)
    expect(data.stable_proxy_tool_count).toBe(3)
    expect(data.upstream_tool_count).toBe(0)
  })

  test('keeps analyzer proxy tools hidden when analyzer is disabled', async () => {
    await fs.writeFile(
      configPath,
      JSON.stringify({
        analyzer: { enabled: false },
        vm: { enabled: false },
        runtime: { enabled: false },
      }),
      'utf8'
    )

    const gateway = createGateway()
    const names = toolNames(gateway)
    const data = gateway.getStatus(true).data as Record<string, unknown>

    expect(names).toEqual([
      'rikune_connection_status',
      'rikune_connection_configure',
      'rikune_connection_refresh',
      'rikune_tool_call',
    ])
    expect(data.stable_proxy_tool_count).toBe(0)
  })

  test('does not expand discovered upstream tools into the MCP list', () => {
    const gateway = createGateway()
    ;(gateway as any).states.analyzer = {
      client: null,
      connected: true,
      tools: [
        { name: 'workflow_search', inputSchema: { type: 'object' } },
        { name: 'pe_fingerprint', inputSchema: { type: 'object' } },
      ],
    }

    const names = toolNames(gateway)
    const data = gateway.getStatus(true).data as Record<string, unknown>

    expect(names).toContain('workflow_search')
    expect(names).not.toContain('pe_fingerprint')
    expect(data.stable_proxy_tool_count).toBe(3)
    expect(data.upstream_tool_count).toBe(2)
  })

  test('documents the stable gateway contract in MCP tool descriptions', () => {
    const gateway = createGateway()
    const tools = (gateway as any).listExposedTools() as Array<{
      name: string
      description?: string
    }>
    const descriptions = new Map(tools.map((tool) => [tool.name, tool.description || '']))

    expect(descriptions.get('workflow_search')).toContain('Use this first')
    expect(descriptions.get('workflow_run')).toContain('Primary Rikune analyzer execution gateway')
    expect(descriptions.get('artifact_read')).toContain('Primary Rikune artifact reader')
    expect(descriptions.get('rikune_tool_call')).toContain('Advanced Rikune subtool gateway')
    expect(descriptions.get('rikune_connection_refresh')).toContain(
      'does not expand the stable MCP tool list'
    )
  })

  test('documents current workflow.run analyzer schema in the stable gateway surface', () => {
    const gateway = createGateway()
    const tools = (gateway as any).listExposedTools() as Array<{
      name: string
      inputSchema?: any
    }>
    const workflowRun = tools.find((tool) => tool.name === 'workflow_run')

    expect(workflowRun?.inputSchema.properties.backend_policy.enum).toEqual([
      'auto',
      'prefer_new',
      'legacy_only',
      'strict',
    ])
    expect(workflowRun?.inputSchema.properties.through_stage.enum).toContain('summarize')
    expect(workflowRun?.inputSchema.properties.through_stage.enum).toContain('function_map')
  })

  test('routes arbitrary subtool calls through the stable call gateway', async () => {
    const gateway = createGateway()
    const callTool = jest.fn(async () => ({
      content: [{ type: 'text', text: '{"ok":true}' }],
      structuredContent: { ok: true },
    }))
    ;(gateway as any).states.analyzer = {
      client: { callTool },
      connected: true,
      tools: [{ name: 'pe_fingerprint', inputSchema: { type: 'object' } }],
    }

    const result = await (gateway as any).handleDirectToolCall({
      tool: 'pe.fingerprint',
      arguments: { sample_id: 'sha256:test' },
    })

    expect(result.structuredContent).toEqual({ ok: true })
    expect(callTool).toHaveBeenCalledWith(
      {
        name: 'pe_fingerprint',
        arguments: { sample_id: 'sha256:test' },
      },
      undefined,
      expect.objectContaining({ resetTimeoutOnProgress: true })
    )
  })

  test('forwards activated analyzer subtools even when upstream tools/list stays minimal', async () => {
    const gateway = createGateway()
    const callTool = jest.fn(async () => ({
      content: [{ type: 'text', text: '{"ok":true}' }],
      structuredContent: { ok: true },
    }))
    ;(gateway as any).states.analyzer = {
      client: { callTool },
      connected: true,
      tools: [
        { name: 'workflow_search', inputSchema: { type: 'object' } },
        { name: 'workflow_run', inputSchema: { type: 'object' } },
        { name: 'artifact_read', inputSchema: { type: 'object' } },
      ],
    }

    const result = await (gateway as any).handleDirectToolCall({
      tool: 'code.function.decompile',
      arguments: { sample_id: 'sha256:test', address: '0x401000' },
    })

    expect(result.structuredContent).toEqual({ ok: true })
    expect(callTool).toHaveBeenCalledWith(
      {
        name: 'code.function.decompile',
        arguments: { sample_id: 'sha256:test', address: '0x401000' },
      },
      undefined,
      expect.objectContaining({ resetTimeoutOnProgress: true })
    )
  })

  test('rewrites localhost upload URLs to the configured analyzer endpoint', async () => {
    const gateway = createGateway({
      RIKUNE_ANALYZER_ENDPOINT: 'http://159.195.136.226:18080',
    })
    const upstreamPayload = {
      ok: true,
      data: {
        result_mode: 'workflow_run',
        action: 'request_upload',
        routed_tool: 'sample.request_upload',
        upload_url: 'http://localhost:18080/api/v1/uploads/token-1',
        status_url: 'http://localhost:18080/api/v1/uploads/token-1/status',
        token: 'token-1',
        recommended_workflow_tools: ['workflow.run'],
        next_actions: ['POST the file bytes to upload_url.'],
        message: 'request_upload routed through sample.request_upload; upload_url is ready.',
      },
    }
    const callTool = jest.fn(async () => ({
      content: [{ type: 'text', text: JSON.stringify(upstreamPayload) }],
      structuredContent: upstreamPayload,
    }))
    ;(gateway as any).states.analyzer = {
      client: { callTool },
      connected: true,
      tools: [{ name: 'workflow_run', inputSchema: { type: 'object' } }],
    }

    const result = await (gateway as any).proxyToolCall('workflow_run', {
      action: 'request_upload',
    })
    const payload = result.structuredContent as any
    const textPayload = JSON.parse((result.content[0] as any).text)

    expect(payload.data.upload_url).toBe(
      'http://159.195.136.226:18080/api/v1/uploads/token-1'
    )
    expect(payload.data.client_upload_url).toBe(payload.data.upload_url)
    expect(payload.data.upstream_upload_url).toBe(
      'http://localhost:18080/api/v1/uploads/token-1'
    )
    expect(payload.data.status_url).toBe(
      'http://159.195.136.226:18080/api/v1/uploads/token-1/status'
    )
    expect(payload.warnings).toContain(
      'Gateway rewrote localhost upload_url/status_url to the configured analyzer endpoint.'
    )
    expect(textPayload.data.upload_url).toBe(payload.data.upload_url)
  })
})
