/**
 * Unit tests for the dynamic.runtime.status control-plane summary tool.
 */

import { describe, test, expect, afterEach, jest } from '@jest/globals'
import http from 'http'
import {
  buildRuntimeToolSupport,
  createDynamicRuntimeStatusHandler,
  dynamicRuntimeStatusToolDefinition,
  listRuntimeDelegatedToolContracts,
} from '../../src/plugins/dynamic/tools/dynamic-runtime-status.js'

const SAMPLE_SHA256 = 'b'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_SHA256}`

function createDebugSessionRow(endpoint: string) {
  return {
    id: 'runtime-session-1',
    run_id: null,
    sample_id: SAMPLE_ID,
    sample_sha256: SAMPLE_SHA256,
    status: 'captured',
    debug_state: 'captured',
    backend: 'windows-sandbox',
    current_phase: 'runtime_command_completed',
    session_tag: 'runtime-debug-runtime-s',
    artifact_refs_json: JSON.stringify([
      {
        id: 'artifact-1',
        type: 'runtime_debug_artifact',
        path: 'reports/runtime_debug/runtime-session-1/debug_session_trace.json',
        sha256: 'c'.repeat(64),
        mime: 'application/json',
      },
    ]),
    guidance_json: null,
    metadata_json: JSON.stringify({
      endpoint,
      sandbox_id: 'sandbox-1',
      last_task_id: 'task-1',
      capabilities: [{ type: 'inline', handler: 'executeDebugSession' }],
    }),
    created_at: '2026-04-18T00:00:00.000Z',
    updated_at: '2026-04-18T00:00:01.000Z',
    finished_at: '2026-04-18T00:00:02.000Z',
  }
}

describe('dynamic.runtime.status tool', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  test('exports a read-only runtime status tool definition', () => {
    expect(dynamicRuntimeStatusToolDefinition.name).toBe('dynamic.runtime.status')
  })

  test('maps runtime capabilities to delegated MCP tools', () => {
    const contracts = listRuntimeDelegatedToolContracts()

    const support = buildRuntimeToolSupport([
      { type: 'inline', handler: 'executeDebugSession', requiresSample: true },
      { type: 'python-worker', handler: 'frida_worker.py', requiresSample: true },
    ])

    expect(contracts.length).toBeGreaterThan(20)
    expect(support.find((entry) => entry.tool_name === 'debug.session.start')).toEqual(
      expect.objectContaining({
        supported: true,
        requires_sample: true,
        runtime_contract: { type: 'inline', handler: 'executeDebugSession' },
      })
    )
    expect(support.find((entry) => entry.tool_name === 'frida.runtime.instrument')).toEqual(
      expect.objectContaining({ supported: true })
    )
    expect(support.find((entry) => entry.tool_name === 'managed.fake_c2')).toEqual(
      expect.objectContaining({ supported: false, capability: null, requires_sample: null })
    )
  })

  test('aggregates Runtime Node, Host Agent, capabilities, and persisted sessions', async () => {
    const runtimeServer = http.createServer((req, res) => {
      const requestUrl = new URL(req.url || '/', 'http://127.0.0.1')
      if (req.method === 'GET' && requestUrl.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, role: 'runtime-node' }))
        return
      }
      if (req.method === 'GET' && requestUrl.pathname === '/capabilities') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            data: {
              runtime_backends: [
                { type: 'inline', handler: 'executeDebugSession', requiresSample: true },
                { type: 'inline', handler: 'executeSandboxExecute', requiresSample: true },
                { type: 'inline', handler: 'executeBehaviorCapture', requiresSample: true },
                { type: 'python-worker', handler: 'frida_worker.py', requiresSample: true },
                {
                  type: 'python-worker',
                  handler: 'src/plugins/runtime-deobfuscate/workers/deobfuscate_worker.py',
                  requiresSample: true,
                },
                {
                  type: 'python-worker',
                  handler: 'src/plugins/managed-fake-c2/workers/managed_fake_c2_worker.py',
                  requiresSample: true,
                },
              ],
            },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'not found' }))
    })
    const hostAgentServer = http.createServer((req, res) => {
      const requestUrl = new URL(req.url || '/', 'http://127.0.0.1')
      if (req.method === 'GET' && requestUrl.pathname === '/sandbox/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            ok: true,
            backend: 'windows-sandbox',
            hyperv: { configured: false },
          })
        )
        return
      }
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'not found' }))
    })

    await new Promise<void>((resolve) => runtimeServer.listen(0, '127.0.0.1', resolve))
    await new Promise<void>((resolve) => hostAgentServer.listen(0, '127.0.0.1', resolve))
    const runtimeAddress = runtimeServer.address()
    const hostAgentAddress = hostAgentServer.address()
    if (!runtimeAddress || typeof runtimeAddress === 'string')
      throw new Error('Failed to bind runtime server')
    if (!hostAgentAddress || typeof hostAgentAddress === 'string')
      throw new Error('Failed to bind host agent server')

    const runtimeEndpoint = `http://127.0.0.1:${runtimeAddress.port}`
    const hostAgentEndpoint = `http://127.0.0.1:${hostAgentAddress.port}`
    const deps: any = {
      config: {
        runtime: {
          mode: 'remote-sandbox',
          hostAgentEndpoint,
        },
      },
      database: {
        findDebugSession: jest.fn().mockReturnValue(createDebugSessionRow(runtimeEndpoint)),
        findDebugSessionsBySample: jest
          .fn()
          .mockReturnValue([createDebugSessionRow(runtimeEndpoint)]),
      },
    }

    try {
      const result = await createDynamicRuntimeStatusHandler(deps)({
        sample_id: SAMPLE_ID,
        session_id: 'runtime-session-1',
      })

      expect(result.ok).toBe(true)
      expect((result.data as any).status).toBe('ready')
      expect((result.data as any).runtime_endpoint).toBe(runtimeEndpoint)
      expect((result.data as any).host_agent_endpoint).toBe(hostAgentEndpoint)
      expect((result.data as any).runtime_health).toEqual({ ok: true, role: 'runtime-node' })
      expect((result.data as any).host_agent_health.backend).toBe('windows-sandbox')
      expect((result.data as any).runtime_capabilities).toHaveLength(6)
      expect((result.data as any).runtime_tool_summary).toEqual(
        expect.objectContaining({
          supported_count: expect.any(Number),
          missing_count: expect.any(Number),
          total_count: expect.any(Number),
        })
      )
      expect((result.data as any).supported_runtime_tools).toEqual(
        expect.arrayContaining([
          'debug.session.start',
          'sandbox.execute',
          'behavior.capture',
          'dynamic.behavior.capture',
          'frida.runtime.instrument',
          'deobf.strings',
          'managed.fake_c2',
        ])
      )
      expect((result.data as any).missing_runtime_tools).toContain('managed.safe_run')
      expect((result.data as any).runtime_tool_support).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            tool_name: 'managed.fake_c2',
            supported: true,
            runtime_contract: {
              type: 'python-worker',
              handler: 'src/plugins/managed-fake-c2/workers/managed_fake_c2_worker.py',
            },
          }),
        ])
      )
      expect((result.data as any).sessions).toHaveLength(1)
      expect((result.data as any).artifact_count).toBe(1)
      expect((result.data as any).backend_interface.supported_backends).toEqual(
        expect.objectContaining({
          debug_session: true,
          sandbox_execute: true,
          behavior_capture: true,
          frida_runtime: true,
          runtime_deobfuscation: true,
          managed_fake_c2: true,
        })
      )
      expect((result.data as any).execution_semantics).toEqual(
        expect.objectContaining({
          mcp_connect_opens_sandbox: false,
          live_execution_requires_explicit_tool_call: true,
          sandbox_execute_is_live_only_when_runtime_online: true,
          current_live_execution_state: 'runtime_ready',
        })
      )
      expect((result.data as any).recommended_next_tools).toContain('runtime.debug.command')
      expect((result.data as any).recommended_next_tools).toContain('frida.runtime.instrument')
      expect((result.data as any).recommended_next_tools).toContain('deobf.strings')
      expect((result.data as any).recommended_next_tools).toContain('managed.fake_c2')
      expect((result.data as any).recommended_next_tools).toContain('dynamic.behavior.capture')
    } finally {
      await new Promise<void>((resolve) => runtimeServer.close(() => resolve()))
      await new Promise<void>((resolve) => hostAgentServer.close(() => resolve()))
    }
  })

  test('returns setup guidance without launching runtime when no endpoints are configured', async () => {
    const deps: any = {
      config: { runtime: { mode: 'disabled' } },
      database: {},
    }

    const result = await createDynamicRuntimeStatusHandler(deps)({})

    expect(result.ok).toBe(false)
    expect((result.data as any).status).toBe('not_configured')
    expect((result.data as any).runtime_endpoint).toBeNull()
    expect((result.data as any).host_agent_endpoint).toBeNull()
    expect((result.data as any).backend_interface.can_execute_runtime_command).toBe(false)
    expect((result.data as any).execution_semantics).toEqual(
      expect.objectContaining({
        mcp_connect_opens_sandbox: false,
        dynamic_plan_opens_sandbox: false,
        current_live_execution_state: 'not_configured',
      })
    )
    expect((result.data as any).recommended_next_tools).toContain('runtime.debug.session.start')
    expect((result.data as any).next_actions.join(' ')).toContain(
      'Configure runtime.hostAgentEndpoint'
    )
  })
})
