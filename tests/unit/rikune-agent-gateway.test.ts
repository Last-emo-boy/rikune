import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import { RikuneAgentGateway } from '../../src/rikune-agent-gateway.js'

describe('RikuneAgentGateway stable tool surface', () => {
  let tempDir: string
  let configPath: string
  let originalFetch: typeof globalThis.fetch

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-agent-gateway-'))
    configPath = path.join(tempDir, 'agent.json')
    originalFetch = globalThis.fetch
  })

  afterEach(async () => {
    globalThis.fetch = originalFetch
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
    expect(descriptions.get('rikune_tool_call')).toContain(
      'does not need to appear in upstream tools/list'
    )
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

    expect(payload.data.upload_url).toBe('http://159.195.136.226:18080/api/v1/uploads/token-1')
    expect(payload.data.client_upload_url).toBe(payload.data.upload_url)
    expect(payload.data.upstream_upload_url).toBe('http://localhost:18080/api/v1/uploads/token-1')
    expect(payload.data.status_url).toBe(
      'http://159.195.136.226:18080/api/v1/uploads/token-1/status'
    )
    expect(payload.warnings).toContain(
      'Gateway rewrote localhost upload_url/status_url to the configured analyzer endpoint.'
    )
    expect(textPayload.data.upload_url).toBe(payload.data.upload_url)
  })

  test.each([
    ['endpoint', 'file:///tmp/runtime.sock'],
    ['health_endpoint', 'http://operator:secret@127.0.0.1:19001/health'],
    ['mcp_endpoint', 'ftp://127.0.0.1:19001/mcp'],
  ])('rejects an untrusted %s before persistence or refresh', async (field, value) => {
    const gateway = createGateway()
    const refreshTarget = jest.spyOn(gateway as any, 'refreshTarget')

    await expect(
      (gateway as any).handleConfigure({
        target: 'runtime',
        [field]: value,
      })
    ).rejects.toThrow()

    expect(refreshTarget).not.toHaveBeenCalled()
    await expect(fs.readFile(configPath, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test('does not inherit an API key when the endpoint origin changes', async () => {
    const gateway = createGateway({
      RIKUNE_RUNTIME_ENDPOINT: 'http://127.0.0.1:19001',
      RIKUNE_RUNTIME_API_KEY: 'configured-secret',
    })

    await expect(
      (gateway as any).handleConfigure({
        target: 'runtime',
        endpoint: 'http://127.0.0.1:19002',
        persist: false,
        refresh: false,
      })
    ).rejects.toThrow('cannot change while retaining its configured API key')

    const runtime = (gateway.getStatus().data as any).runtime
    expect(runtime.endpoint).toBe('http://127.0.0.1:19001')
    expect(runtime.api_key_configured).toBe(true)
  })

  test('accepts an endpoint origin change when a replacement API key is explicit', async () => {
    const gateway = createGateway({
      RIKUNE_RUNTIME_ENDPOINT: 'http://127.0.0.1:19001',
      RIKUNE_RUNTIME_API_KEY: 'configured-secret',
    })

    await (gateway as any).handleConfigure({
      target: 'runtime',
      endpoint: 'http://127.0.0.1:19002/runtime',
      api_key: 'replacement-secret',
      persist: false,
      refresh: false,
    })

    const runtime = (gateway.getStatus().data as any).runtime
    expect(runtime.endpoint).toBe('http://127.0.0.1:19002/runtime')
    expect(runtime.api_key_configured).toBe(true)
  })

  test.each([
    ['analyzer', 'RIKUNE_ANALYZER_ENDPOINT', 'RIKUNE_ANALYZER_API_KEY'],
    ['vm', 'RIKUNE_VM_ENDPOINT', 'RIKUNE_VM_API_KEY'],
    ['runtime', 'RIKUNE_RUNTIME_ENDPOINT', 'RIKUNE_RUNTIME_API_KEY'],
  ] as const)(
    'does not bind an environment API key to a persisted %s endpoint',
    async (target, endpointEnv, keyEnv) => {
      await fs.writeFile(
        configPath,
        JSON.stringify({
          [target]: {
            enabled: true,
            endpoint: 'http://attacker.invalid:19001',
          },
        }),
        'utf8'
      )
      const gateway = createGateway({
        [endpointEnv]: '',
        [keyEnv]: 'environment-secret',
      })

      expect((gateway as any).config[target].endpoint).toBe('http://attacker.invalid:19001')
      expect((gateway as any).config[target].apiKey).toBeUndefined()
    }
  )

  test.each([
    ['analyzer', 'RIKUNE_ANALYZER_ENDPOINT', 'RIKUNE_ANALYZER_API_KEY'],
    ['vm', 'RIKUNE_VM_ENDPOINT', 'RIKUNE_VM_API_KEY'],
    ['runtime', 'RIKUNE_RUNTIME_ENDPOINT', 'RIKUNE_RUNTIME_API_KEY'],
  ] as const)(
    'binds an environment %s endpoint and API key as one source',
    (target, endpointEnv, keyEnv) => {
      const gateway = createGateway({
        [endpointEnv]: 'http://environment.internal:19001',
        [keyEnv]: 'environment-secret',
      })

      expect((gateway as any).config[target].endpoint).toBe('http://environment.internal:19001')
      expect((gateway as any).config[target].apiKey).toBe('environment-secret')
    }
  )

  test.each([
    ['analyzer', 'RIKUNE_ANALYZER_ENDPOINT'],
    ['vm', 'RIKUNE_VM_ENDPOINT'],
    ['runtime', 'RIKUNE_RUNTIME_ENDPOINT'],
  ] as const)(
    'keeps a persisted %s endpoint and API key bound together',
    async (target, endpointEnv) => {
      await fs.writeFile(
        configPath,
        JSON.stringify({
          [target]: {
            enabled: true,
            endpoint: 'http://persisted.internal:19001',
            apiKey: 'persisted-secret',
          },
        }),
        'utf8'
      )
      const gateway = createGateway({ [endpointEnv]: '' })

      expect((gateway as any).config[target].endpoint).toBe('http://persisted.internal:19001')
      expect((gateway as any).config[target].apiKey).toBe('persisted-secret')
    }
  )

  test.each([
    ['analyzer', 'RIKUNE_ANALYZER_ENDPOINT', 'RIKUNE_ANALYZER_API_KEY'],
    ['vm', 'RIKUNE_VM_ENDPOINT', 'RIKUNE_VM_API_KEY'],
    ['runtime', 'RIKUNE_RUNTIME_ENDPOINT', 'RIKUNE_RUNTIME_API_KEY'],
  ] as const)(
    'does not carry a persisted %s API key to an environment endpoint',
    async (target, endpointEnv, keyEnv) => {
      await fs.writeFile(
        configPath,
        JSON.stringify({
          [target]: {
            enabled: true,
            endpoint: 'http://persisted.internal:19001',
            apiKey: 'persisted-secret',
          },
        }),
        'utf8'
      )
      const gateway = createGateway({
        [endpointEnv]: 'http://environment.internal:19001',
        [keyEnv]: '',
      })

      expect((gateway as any).config[target].endpoint).toBe('http://environment.internal:19001')
      expect((gateway as any).config[target].apiKey).toBeUndefined()
    }
  )

  test.each([
    ['analyzer', 'RIKUNE_ANALYZER_ENDPOINT', 'RIKUNE_ANALYZER_API_KEY'],
    ['vm', 'RIKUNE_VM_ENDPOINT', 'RIKUNE_VM_API_KEY'],
    ['runtime', 'RIKUNE_RUNTIME_ENDPOINT', 'RIKUNE_RUNTIME_API_KEY'],
  ] as const)(
    'preserves an explicitly empty persisted %s API key across restart',
    async (target, endpointEnv, keyEnv) => {
      await fs.writeFile(
        configPath,
        JSON.stringify({
          [target]: {
            enabled: true,
            endpoint: 'http://persisted.internal:19001',
            apiKey: '',
          },
        }),
        'utf8'
      )
      const gateway = createGateway({
        [endpointEnv]: '',
        [keyEnv]: 'environment-secret',
      })

      expect((gateway as any).config[target].apiKey).toBe('')
    }
  )

  test('does not bind a process API key to an env-file endpoint', async () => {
    const envPath = path.join(tempDir, 'runtime.env')
    await fs.writeFile(
      envPath,
      ['RUNTIME_ENDPOINT=http://env-file.internal:19001', 'RUNTIME_API_KEY=env-file-secret'].join(
        '\n'
      ),
      'utf8'
    )

    const gateway = new RikuneAgentGateway({
      configPath,
      env: {
        RIKUNE_AGENT_ENV_FILE: envPath,
        RUNTIME_API_KEY: 'process-secret',
      },
    })

    expect((gateway as any).config.runtime.endpoint).toBe('http://env-file.internal:19001')
    expect((gateway as any).config.runtime.apiKey).toBe('env-file-secret')
    expect((gateway as any).env.RUNTIME_API_KEY).toBe('env-file-secret')
  })

  test('does not carry an env-file API key to a process endpoint', async () => {
    const envPath = path.join(tempDir, 'runtime.env')
    await fs.writeFile(envPath, 'RUNTIME_API_KEY=env-file-secret\n', 'utf8')

    const gateway = new RikuneAgentGateway({
      configPath,
      env: {
        RIKUNE_AGENT_ENV_FILE: envPath,
        RUNTIME_ENDPOINT: 'http://process.internal:19001',
      },
    })

    expect((gateway as any).config.runtime.endpoint).toBe('http://process.internal:19001')
    expect((gateway as any).config.runtime.apiKey).toBeUndefined()
    expect((gateway as any).env.RUNTIME_API_KEY).toBeUndefined()
  })

  test('does not persist an environment API key and keeps it unbound after restart', async () => {
    const gateway = createGateway({
      RIKUNE_RUNTIME_ENDPOINT: 'http://environment.internal:19001',
      RIKUNE_RUNTIME_API_KEY: 'environment-secret',
    })

    await (gateway as any).handleConfigure({
      target: 'runtime',
      timeout_ms: 12_345,
      refresh: false,
    })

    const persisted = JSON.parse(await fs.readFile(configPath, 'utf8'))
    expect(persisted.runtime.endpoint).toBe('http://environment.internal:19001')
    expect(persisted.runtime.apiKey).toBeUndefined()
    if (process.platform !== 'win32') {
      expect((await fs.stat(configPath)).mode & 0o777).toBe(0o600)
    }

    const restarted = createGateway({
      RIKUNE_RUNTIME_ENDPOINT: '',
      RIKUNE_RUNTIME_API_KEY: 'environment-secret',
    })
    expect((restarted as any).config.runtime.endpoint).toBe('http://environment.internal:19001')
    expect((restarted as any).config.runtime.apiKey).toBeUndefined()
  })

  test('persists an explicitly configured API key', async () => {
    const gateway = createGateway()

    await (gateway as any).handleConfigure({
      target: 'runtime',
      endpoint: 'http://configured.internal:19001',
      api_key: 'configured-secret',
      refresh: false,
    })

    const persisted = JSON.parse(await fs.readFile(configPath, 'utf8'))
    expect(persisted.runtime.endpoint).toBe('http://configured.internal:19001')
    expect(persisted.runtime.apiKey).toBe('configured-secret')
  })

  test('rejects keyed health and MCP endpoints on another origin', async () => {
    const gateway = createGateway()

    await expect(
      (gateway as any).handleConfigure({
        target: 'runtime',
        endpoint: 'http://127.0.0.1:19001',
        health_endpoint: 'http://127.0.0.1:19002/health',
        mcp_endpoint: 'http://127.0.0.1:19003/mcp',
        api_key: 'explicit-secret',
        persist: false,
        refresh: false,
      })
    ).rejects.toThrow('must use one origin')
  })

  test('revalidates persisted endpoints before refresh', async () => {
    await fs.writeFile(
      configPath,
      JSON.stringify({
        runtime: {
          enabled: true,
          endpoint: 'http://operator:secret@127.0.0.1:19001',
          apiKey: 'persisted-secret',
        },
      }),
      'utf8'
    )
    const fetchMock = jest.fn(async () => new Response('{}', { status: 200 }))
    globalThis.fetch = fetchMock as typeof fetch
    const gateway = createGateway()

    await gateway.refreshTarget('runtime')

    expect(fetchMock).not.toHaveBeenCalled()
    const runtime = (gateway.getStatus().data as any).runtime
    expect(runtime.last_error).toContain('must not contain URL credentials')
  })

  test('revalidates the target before replaying through an existing client', async () => {
    const gateway = createGateway({
      RIKUNE_RUNTIME_ENDPOINT: 'http://127.0.0.1:19001',
    })
    const callTool = jest.fn(async () => ({
      content: [{ type: 'text', text: '{"ok":true}' }],
      structuredContent: { ok: true },
    }))
    const close = jest.fn(async () => {})
    ;(gateway as any).states.runtime = {
      client: { callTool, close },
      connected: true,
      tools: [{ name: 'runtime_status', inputSchema: { type: 'object' } }],
    }
    ;(gateway as any).config.runtime.endpoint = 'file:///tmp/runtime.sock'

    const result = await (gateway as any).handleDirectToolCall({
      target: 'runtime',
      tool: 'runtime_status',
    })

    expect(callTool).not.toHaveBeenCalled()
    expect(close).toHaveBeenCalled()
    expect(result.isError).toBe(true)
  })

  test('disables redirects for gateway HTTP refresh requests', async () => {
    const fetchMock = jest.fn(
      async () =>
        new Response(null, {
          status: 302,
          headers: { location: 'http://127.0.0.1:19002/redirected' },
        })
    )
    globalThis.fetch = fetchMock as typeof fetch
    const gateway = createGateway()
    await (gateway as any).handleConfigure({
      target: 'runtime',
      enabled: true,
      endpoint: 'http://127.0.0.1:19001',
      persist: false,
      refresh: false,
    })

    await gateway.refreshTarget('runtime')

    expect(fetchMock).toHaveBeenCalled()
    for (const call of fetchMock.mock.calls) {
      expect(call[1]).toEqual(expect.objectContaining({ redirect: 'error' }))
    }
  })

  test('does not send an API key to the host fallback origin', async () => {
    const fetchMock = jest.fn(async () => {
      throw new Error('configured endpoint is unavailable')
    })
    globalThis.fetch = fetchMock as typeof fetch
    const gateway = createGateway()
    await (gateway as any).handleConfigure({
      target: 'runtime',
      enabled: true,
      endpoint: 'http://host.docker.internal:19001',
      api_key: 'explicit-secret',
      persist: false,
      refresh: false,
    })

    await gateway.refreshTarget('runtime')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0].toString()).toContain('host.docker.internal:19001')
    expect(fetchMock.mock.calls[0][1]).toEqual(
      expect.objectContaining({
        headers: { Authorization: 'Bearer explicit-secret' },
        redirect: 'error',
      })
    )
  })

  test('uses the redirect-safe custom fetch for streamable HTTP MCP requests', async () => {
    const fetchMock = jest.fn(async () => {
      throw new Error('stop after inspecting MCP request')
    })
    globalThis.fetch = fetchMock as typeof fetch
    const gateway = createGateway()
    await (gateway as any).handleConfigure({
      target: 'runtime',
      enabled: true,
      transport: 'streamable-http',
      mcp_endpoint: 'http://127.0.0.1:19001/mcp',
      persist: false,
      refresh: false,
    })

    await gateway.refreshTarget('runtime')

    expect(fetchMock).toHaveBeenCalled()
    expect(fetchMock.mock.calls[0][0].toString()).toContain('http://127.0.0.1:19001/mcp')
    expect(fetchMock.mock.calls[0][1]).toEqual(expect.objectContaining({ redirect: 'error' }))
  })
})
