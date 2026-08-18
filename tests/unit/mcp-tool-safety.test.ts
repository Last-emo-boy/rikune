import { describe, expect, test } from '@jest/globals'
import { join } from 'path'
import pino from 'pino'
import { z } from 'zod'
import { MCPRegistry } from '../../src/core/mcp-registry.js'
import { ToolExecutor } from '../../src/core/tool-executor.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import { createToolsDiscoverHandler } from '../../src/tools/tools-discover.js'
import {
  BackendWorkerContractSchema,
  createPluginTestHarness,
  type Plugin,
} from '../../src/plugins/sdk.js'
import {
  buildBackendWorkerRequest,
  checkBackendWorkerReadiness,
  runBackendWorker,
} from '../../src/worker/backend-worker-client.js'
import externalReBridgePlugin from '../../src/plugins/external-re-bridge/index.js'
import type { WorkerResult } from '../../src/types.js'

const logger = pino({ level: 'silent' })

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function makeToolDef(name: string, schema: z.ZodTypeAny = z.object({})) {
  return {
    name,
    canonicalName: name,
    description: `Tool ${name}`,
    inputSchema: schema,
  } as any
}

function fixtureBackendContract(overrides: Record<string, unknown> = {}) {
  return BackendWorkerContractSchema.parse({
    backendName: 'SafetyFixtureBackend',
    backendKind: 'external',
    adapter: 'safety.fixture.adapter',
    supportedModes: ['builtin', 'external'],
    defaultMode: 'builtin',
    outputArtifactTypes: ['safety_fixture_output'],
    policy: {
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 1000,
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: ['Configure a fixture backend only when external mode is explicitly enabled.'],
    },
    ...overrides,
  })
}

describe('MCP tool and backend safety boundaries', () => {
  test('blocks direct calls to registered tools hidden behind the progressive surface', async () => {
    resetSurfaceForTest()
    const registry = new MCPRegistry(logger)
    const executor = new ToolExecutor(logger)

    registry.registerTool(makeToolDef('workflow.analyze.start'), async () => ({ ok: true }))
    getToolSurfaceManager().registerCoreTools(['workflow.analyze.start'])
    getToolSurfaceManager().registerGatewayCoreTools(['tools.discover'])

    await expect(
      executor.executeTool('workflow_analyze_start', {}, { registry, logger })
    ).rejects.toThrow(/Tool hidden by progressive surface/)
  })

  test('rejects invalid tool schemas and oversized backend input before execution', async () => {
    resetSurfaceForTest()
    const registry = new MCPRegistry(logger)
    const executor = new ToolExecutor(logger)
    registry.registerTool(
      makeToolDef('sample.safe.inspect', z.object({ sample_id: z.string().min(1) })),
      async (): Promise<WorkerResult> => ({ ok: true })
    )
    getToolSurfaceManager().registerCoreTools(['sample.safe.inspect'])
    getToolSurfaceManager().registerGatewayCoreTools(['sample.safe.inspect'])

    await expect(
      executor.executeTool(
        'sample_safe_inspect',
        { sample_id: '' },
        { registry, logger }
      )
    ).rejects.toThrow(/Invalid arguments/)

    const backend = fixtureBackendContract({
      policy: {
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        maxInputBytes: 64,
      },
    })
    const request = buildBackendWorkerRequest({
      tool: 'sample.safe.inspect',
      backend,
      args: { payload: 'x'.repeat(1024) },
    })
    const backendResult = await runBackendWorker(request)

    expect(backendResult.ok).toBe(false)
    expect(backendResult.errors).toEqual(
      expect.arrayContaining(['backend_worker_input_limit_exceeded'])
    )
    expect(backendResult.metrics?.elapsed_ms).toBe(0)
  })

  test('records activation audit metadata without starting backends', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugin: Plugin = {
      id: 'safety-yara-test',
      name: 'Safety YARA Test',
      description: 'Safety activation fixture',
      aspects: {
        formats: ['pe'],
        execution: ['static'],
        capabilities: ['c2-detection'],
      },
      surfaceRules: {
        tier: 2,
        category: 'malware-analysis',
        activateOn: { findings: ['c2'] },
      },
      tools: [
        {
          definition: {
            name: 'safety.yara.scan',
            description: 'Fixture YARA scan',
            inputSchema: {},
            aspects: { formats: ['pe'], execution: ['static'] },
          },
          handler: async () => ({ ok: true }),
        },
      ],
    }
    surface.registerPlugin(plugin, ['safety.yara.scan'])

    const handler = createToolsDiscoverHandler({
      getStatuses: () => [
        {
          id: plugin.id,
          name: plugin.name,
          description: plugin.description,
          status: 'loaded',
          tools: ['safety.yara.scan'],
        },
      ],
      getDiscoveredPlugins: () => [plugin],
      getPlugin: (id: string) => (id === plugin.id ? plugin : undefined),
    } as any)

    const result = await handler({ action: 'activate', finding: 'c2' })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.activated).toEqual(['safety-yara-test'])
    expect(data.activation_audit).toEqual(
      expect.objectContaining({
        action: 'activate',
        activated_plugins: ['safety-yara-test'],
        activated_tools: ['safety.yara.scan'],
        policy: expect.objectContaining({
          progressive_surface_enabled: true,
          discovery_required_for_hidden_tools: true,
          readiness_not_bypassed: true,
          backend_execution_started: false,
        }),
      })
    )
    expect(data.activation_audit.request).toEqual(
      expect.objectContaining({
        finding: 'c2',
        plugin_id: null,
        tool_name: null,
      })
    )
  })

  test('rejects shell launchers and shell control tokens for external backends', () => {
    const workerPath = join(process.cwd(), 'tests', 'fixtures', 'workers', 'fixture-worker.mjs')
    const shellContract = fixtureBackendContract({
      commandHint: `powershell -Command node ${workerPath}`,
      defaultMode: 'external',
    })
    const chainedContract = fixtureBackendContract({
      commandHint: `node ${workerPath} && whoami`,
      defaultMode: 'external',
    })

    expect(checkBackendWorkerReadiness(shellContract, { mode: 'external' })).toEqual(
      expect.objectContaining({
        status: 'policy_denied',
        reasons: expect.arrayContaining(['backend_shell_launcher_rejected']),
      })
    )
    expect(checkBackendWorkerReadiness(chainedContract, { mode: 'external' })).toEqual(
      expect.objectContaining({
        status: 'policy_denied',
        reasons: expect.arrayContaining(['backend_shell_metacharacter_rejected']),
      })
    )
  })

  test('rejects remote external RE bridge endpoints without contacting sidecars', async () => {
    const harness = createPluginTestHarness()
    harness.registerPlugin(externalReBridgePlugin)
    const bridgeTool = harness.registeredTools.find(
      (entry) => entry.definition.name === 'external_re.bridge.sync'
    )
    expect(bridgeTool).toBeDefined()

    const result = (await bridgeTool!.handler({
      profile: 'ghidra',
      endpoint: 'http://192.168.1.10:4011',
      sample_id: 'sha256:remote',
      artifact_manifest: {
        functions: [{ address: '0x401000', name: 'remote_entry' }],
      },
    })) as WorkerResult

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(
      expect.arrayContaining(['endpoint_host_must_be_localhost_or_loopback'])
    )
    expect(result.data).toEqual(
      expect.objectContaining({
        policy_denied: true,
        execution_semantics: expect.objectContaining({
          actual_mode: 'policy_denied',
          sidecar_contacted: false,
          live_execution: false,
        }),
      })
    )
    expect(result.artifacts).toBeUndefined()
  })
})
