import { describe, expect, test } from '@jest/globals'
import { z } from 'zod'
import pino from 'pino'
import {
  createWorkflowSearchHandler,
  workflowSearchToolDefinition,
} from '../../src/tools/workflow-search.js'
import { MCPRegistry } from '../../src/core/mcp-registry.js'
import { ToolExecutor } from '../../src/core/tool-executor.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import type { Plugin } from '../../src/plugins/sdk.js'

const logger = pino({ level: 'silent' })

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function createPluginManager(plugins: Plugin[]) {
  return {
    getStatuses: () =>
      plugins.map((plugin) => ({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        status: 'loaded',
        tools: plugin.tools.map((tool) => tool.definition.name),
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any
}

function registerPluginsForSearch(plugins: Plugin[]) {
  const surface = getToolSurfaceManager()
  for (const plugin of plugins) {
    surface.registerPlugin(
      plugin,
      plugin.tools.map((tool) => tool.definition.name)
    )
  }
}

describe('workflow.search', () => {
  test('recommends hidden plugin capabilities without activating them', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'jsvmp-search-test',
        name: 'JSVMP Search Test',
        description: 'Recover JavaScript virtual machine bytecode handlers',
        aspects: {
          formats: ['js', 'javascript'],
          capabilities: ['jsvmp-bytecode-recovery', 'handler-map-recovery'],
          execution: ['static'],
        },
        surfaceRules: {
          tier: 2,
          category: 'reverse-engineering',
          activateOn: { fileTypes: ['js', 'javascript'], findings: ['jsvmp'] },
        },
        tools: [
          {
            definition: {
              name: 'jsvmp.bytecode.recover',
              description: 'Recover bytecode handlers from JSVMP samples',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['js'],
                capabilities: ['jsvmp-bytecode-recovery', 'handler-map-recovery'],
                execution: ['static'],
              },
              workflowRecipes: [
                {
                  id: 'jsvmp.handler.recovery',
                  title: 'JSVMP handler recovery',
                  startsWith: ['jsvmp.bytecode.recover'],
                  evidence: ['bytecode-handlers'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerPlugin(plugins[0], ['jsvmp.bytecode.recover'])

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))

    const result = await handler({ query: 'bytecode handler', top_k: 5 })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.result_mode).toBe('workflow_search')
    expect(data.results[0]).toEqual(
      expect.objectContaining({
        kind: 'plugin',
        plugin_id: 'jsvmp-search-test',
        readiness_state: 'hidden_activation_required',
        activation_required: true,
        activation_command: expect.objectContaining({
          action: 'activate',
          tool: 'workflow.search',
          via: 'workflow.search',
        }),
      })
    )
    expect(data.search_profile.recommended_tools).toContain('jsvmp.bytecode.recover')
    expect(data.recommended_next_tools).toBeUndefined()
    expect(surface.isToolVisible('jsvmp.bytecode.recover')).toBe(false)
  })

  test('can explicitly activate selected hidden tools through workflow.search', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'activate-search-test',
        name: 'Activate Search Test',
        description: 'Hidden specialist plugin activated through workflow.search',
        surfaceRules: {
          tier: 2,
          category: 'reverse-engineering',
          activateOn: { fileTypes: ['pe'], findings: ['packed'] },
        },
        tools: [
          {
            definition: {
              name: 'packed.deep.scan',
              description: 'Deep packed sample scan',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe'],
                capabilities: ['packed-analysis'],
                execution: ['static'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerCoreTools(['workflow.search', 'tools.discover'])
    surface.registerGatewayCoreTools(['workflow.search'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({ action: 'activate', plugin_id: 'activate-search-test' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.result_mode).toBe('workflow_search')
    expect(data.action).toBe('activate')
    expect(data.activated).toEqual(['activate-search-test'])
    expect(data.activated_tools).toContain('packed.deep.scan')
    expect(data.activation_audit.policy.backend_execution_started).toBe(false)
    expect(data.recommended_next_tools).toBeUndefined()
    expect(surface.isToolVisible('packed.deep.scan')).toBe(true)
    expect(surface.isToolVisible('tools.discover')).toBe(false)
  })

  test('reranks recommendations with file profile, query, and goal signals', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'windows-generic-rerank-test',
        name: 'Windows Generic Rerank Test',
        description: 'General Windows reverse static analysis helper',
        aspects: {
          formats: ['windows'],
          platforms: ['windows'],
          execution: ['static'],
          capabilities: ['reverse-engineering', 'metadata'],
        },
        surfaceRules: {
          tier: 1,
          category: 'static-analysis',
          activateOn: { fileTypes: ['windows'] },
        },
        tools: [
          {
            definition: {
              name: 'windows.metadata.inspect',
              description: 'Inspect generic Windows metadata',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['windows'],
                platforms: ['windows'],
                execution: ['static'],
                capabilities: ['metadata'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'pe-rerank-test',
        name: 'PE Rerank Test',
        description: 'PE executable structure, imports, and reverse engineering analysis',
        aspects: {
          formats: ['pe', 'exe'],
          platforms: ['windows'],
          execution: ['static'],
          capabilities: ['structure', 'imports', 'reverse-engineering'],
          evidence: ['structure', 'imports'],
        },
        surfaceRules: {
          tier: 1,
          category: 'static-analysis',
          activateOn: { fileTypes: ['pe', 'exe'] },
        },
        tools: [
          {
            definition: {
              name: 'pe.structure.analyze',
              description: 'Analyze PE executable structure and imports',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe', 'exe'],
                platforms: ['windows'],
                execution: ['static'],
                capabilities: ['structure', 'imports', 'reverse-engineering'],
                evidence: ['structure', 'imports'],
              },
              workflowRecipes: [
                {
                  id: 'pe.static.reverse',
                  title: 'PE static reverse workflow',
                  startsWith: ['pe.structure.analyze'],
                  evidence: ['structure', 'imports'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'js-bytecode-rerank-test',
        name: 'JS Bytecode Rerank Test',
        description: 'Recover JavaScript virtual machine bytecode handlers',
        aspects: {
          formats: ['js', 'javascript'],
          execution: ['static'],
          capabilities: ['jsvmp-bytecode-recovery', 'handler-map-recovery'],
        },
        surfaceRules: {
          tier: 2,
          category: 'reverse-engineering',
          activateOn: { fileTypes: ['js', 'javascript'], findings: ['jsvmp'] },
        },
        tools: [
          {
            definition: {
              name: 'jsvmp.bytecode.recover',
              description: 'Recover bytecode handler maps from JSVMP samples',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['js'],
                execution: ['static'],
                capabilities: ['jsvmp-bytecode-recovery', 'handler-map-recovery'],
              },
              workflowRecipes: [
                {
                  id: 'jsvmp.bytecode.recovery',
                  title: 'JSVMP bytecode recovery',
                  startsWith: ['jsvmp.bytecode.recover'],
                  evidence: ['bytecode-handlers'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))

    const peResult = await handler({
      file_type: '.exe',
      query: 'reverse static analysis',
      goal: 'reverse',
      top_k: 2,
    })
    expect(peResult.ok).toBe(true)
    const peData = peResult.data as any
    expect(peData.search_profile.file_type_tags).toEqual(
      expect.arrayContaining(['pe', 'exe', 'windows'])
    )
    expect(peData.results[0]).toEqual(
      expect.objectContaining({
        plugin_id: 'pe-rerank-test',
        recommended_tools: expect.arrayContaining(['pe.structure.analyze']),
      })
    )
    expect(peData.results[0].score_breakdown.profile_score).toBeGreaterThan(0)
    expect(peData.results[0].score_breakdown.goal_score).toBeGreaterThan(0)
    expect(peData.results[0].matched_profile_fields.join(' ')).toContain('file_type/profile tags')
    expect(peData.recommended_next_tools).toBeUndefined()

    const jsResult = await handler({
      query: 'bytecode handler recovery',
      goal: 'reverse',
      top_k: 1,
    })
    expect(jsResult.ok).toBe(true)
    const jsData = jsResult.data as any
    expect(jsData.results[0]).toEqual(
      expect.objectContaining({
        plugin_id: 'js-bytecode-rerank-test',
        recommended_tools: expect.arrayContaining(['jsvmp.bytecode.recover']),
      })
    )
    expect(jsData.results[0].score_breakdown.query_score).toBeGreaterThan(0)
    expect(jsData.results[0].matched_profile_fields.join(' ')).toContain('query terms')
    expect(surface.isToolVisible('pe.structure.analyze')).toBe(false)
    expect(surface.isToolVisible('jsvmp.bytecode.recover')).toBe(false)
  })

  test('recommends hidden core tools without exposing them', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerCoreTools(['workflow.search', 'workflow.analyze.start', 'tool.readiness'])
    surface.registerGatewayCoreTools(['workflow.search'])

    const handler = createWorkflowSearchHandler(createPluginManager([]), {
      toolDefinitions: () => [
        {
          name: 'workflow.analyze.start',
          description: 'Start staged analysis for a registered sample',
          inputSchema: z.object({ sample_id: z.string() }),
        },
        {
          name: 'tool.readiness',
          description: 'Check backend readiness before dynamic or expert tools',
          inputSchema: z.object({ tool_name: z.string() }),
        },
      ],
    })

    const result = await handler({ query: 'workflow_analyze_start', top_k: 5 })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.results[0]).toEqual(
      expect.objectContaining({
        kind: 'tool',
        tool_name: 'workflow.analyze.start',
        readiness_state: 'hidden_activation_required',
        activation_required: true,
      })
    )
    expect(data.recommended_next_tools).toBeUndefined()
    expect([...surface.getVisibleToolNames()]).toEqual(['workflow.search'])
    expect(surface.isToolVisible('workflow.analyze.start')).toBe(false)
  })

  test('executor result scanning does not expand the tool surface', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerCoreTools(['workflow.search', 'workflow.analyze.start', 'tool.readiness'])
    surface.registerGatewayCoreTools(['workflow.search'])
    const signalPlugin: Plugin = {
      id: 'query-signal-test',
      name: 'Query Signal Test',
      surfaceRules: {
        tier: 2,
        category: 'malware-analysis',
        activateOn: { findings: ['packed'] },
        signalMap: { query: ['packed'] },
      },
      tools: [],
    }
    surface.registerPlugin(signalPlugin, ['packed.deep.scan'])

    const registry = new MCPRegistry(logger)
    const executor = new ToolExecutor(logger)
    registry.registerTool(
      workflowSearchToolDefinition,
      createWorkflowSearchHandler(createPluginManager([]), {
        toolDefinitions: () => [
          {
            name: 'workflow.analyze.start',
            description: 'Start staged analysis for a registered sample',
            inputSchema: z.object({ sample_id: z.string() }),
          },
          {
            name: 'tool.readiness',
            description: 'Check backend readiness before dynamic or expert tools',
            inputSchema: z.object({ tool_name: z.string() }),
          },
        ],
      })
    )

    const result = await executor.executeTool(
      'workflow_search',
      { query: 'workflow_analyze_start', top_k: 5 },
      { registry, logger }
    )

    expect(result.isError).toBe(false)
    expect((result.structuredContent as any).data.result_mode).toBe('workflow_search')
    expect((result.structuredContent as any).data.recommended_next_tools).toBeUndefined()
    expect((result.structuredContent as any).data.results[0].tool_name).toBe(
      'workflow.analyze.start'
    )
    expect([...surface.getVisibleToolNames()]).toEqual(['workflow.search'])
    expect(surface.isToolVisible('workflow.analyze.start')).toBe(false)
    expect(surface.isToolVisible('packed.deep.scan')).toBe(false)
  })
})
