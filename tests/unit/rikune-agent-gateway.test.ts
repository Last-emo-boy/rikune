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

  function createGateway(): RikuneAgentGateway {
    return new RikuneAgentGateway({
      configPath,
      env: {
        ...process.env,
        RIKUNE_AGENT_NO_ENV_FILE: '1',
        RIKUNE_ANALYZER_TRANSPORT: 'stdio',
        RIKUNE_ANALYZER_ENDPOINT: 'http://127.0.0.1:18080',
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
})
