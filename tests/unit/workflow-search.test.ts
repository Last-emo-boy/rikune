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
import btfPlugin from '../../src/plugins/btf/index.js'
import containerAnalysisPlugin from '../../src/plugins/container-analysis/index.js'
import ebpfBytecodePlugin from '../../src/plugins/ebpf-bytecode/index.js'
import llvmBitcodePlugin from '../../src/plugins/llvm-bitcode/index.js'

const logger = pino({ level: 'silent' })

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
  surface.visiblePluginTools = new Set()
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
    expect(data.top_k).toBe(5)
    expect(data.search_profile.top_k_strategy).toEqual(
      expect.objectContaining({ mode: 'manual', value: 5 })
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

  test('can explicitly expose a single hidden plugin tool without exposing sibling tools', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'scoped-activate-search-test',
        name: 'Scoped Activate Search Test',
        description: 'Hidden plugin with several specialist tools',
        surfaceRules: {
          tier: 3,
          category: 'dynamic-analysis',
        },
        tools: [
          {
            definition: {
              name: 'dynamic.deep_plan',
              description: 'Plan dynamic analysis without executing the sample',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe'],
                capabilities: ['dynamic-planning'],
                execution: ['dynamic'],
                safety: ['passive', 'no_live_sample_by_default'],
              },
            },
            handler: async () => ({ ok: true }),
          },
          {
            definition: {
              name: 'dynamic.behavior.capture',
              description: 'Capture live behavior in an isolated runtime',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe'],
                capabilities: ['behavior-capture'],
                execution: ['dynamic'],
                safety: ['requires_isolation', 'no_live_sample_by_default'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerCoreTools(['workflow.search'])
    surface.registerGatewayCoreTools(['workflow.search'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({ action: 'activate', tool_name: 'dynamic.deep_plan' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.result_mode).toBe('workflow_search')
    expect(data.action).toBe('activate')
    expect(data.activated).toEqual([])
    expect(data.activated_tools).toEqual(['dynamic.deep_plan'])
    expect(data.activation_audit.activated_plugins).toEqual([])
    expect(data.activation_audit.activated_scoped_tools).toEqual(['dynamic.deep_plan'])
    expect(data.activation_audit.policy.scoped_tool_activation_used).toBe(true)
    expect(data.activation_audit.policy.backend_execution_started).toBe(false)
    expect(data.recommended_next_tools).toBeUndefined()
    expect(surface.isToolVisible('dynamic.deep_plan')).toBe(true)
    expect(surface.isToolVisible('dynamic.behavior.capture')).toBe(false)
  })

  test('can activate a search result as a scoped tool set', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'result-scoped-search-test',
        name: 'Result Scoped Search Test',
        description: 'Hidden dynamic plugin with a planning tool and execution sibling',
        aspects: {
          formats: ['pe'],
          execution: ['dynamic'],
          capabilities: ['dynamic-planning', 'behavior-capture'],
        },
        surfaceRules: {
          tier: 3,
          category: 'dynamic-analysis',
        },
        tools: [
          {
            definition: {
              name: 'dynamic.deep_plan',
              description: 'Plan dynamic analysis safely before any live capture',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe'],
                capabilities: ['dynamic-planning'],
                execution: ['dynamic'],
                safety: ['passive', 'no_live_sample_by_default'],
              },
              workflowRecipes: [
                {
                  id: 'dynamic.safe-planning',
                  title: 'Dynamic safe planning',
                  startsWith: ['dynamic.deep_plan'],
                  nextTools: ['tool.readiness', 'dynamic.behavior.capture'],
                  producesArtifacts: ['dynamic_plan'],
                  evidence: ['workflow'],
                  safety: ['passive', 'no_live_sample_by_default'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
          {
            definition: {
              name: 'dynamic.behavior.capture',
              description: 'Capture live behavior in an isolated runtime',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe'],
                capabilities: ['behavior-capture'],
                execution: ['dynamic'],
                safety: ['requires_isolation', 'no_live_sample_by_default'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerCoreTools(['workflow.search'])
    surface.registerGatewayCoreTools(['workflow.search'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const search = await handler({
      file_type: '.exe',
      query: 'dynamic planning',
      goal: 'dynamic',
    })

    expect(search.ok).toBe(true)
    const searchData = search.data as any
    const result = searchData.results.find(
      (item: any) => item.plugin_id === 'result-scoped-search-test'
    )
    expect(result).toEqual(
      expect.objectContaining({
        result_id: 'plugin:result-scoped-search-test',
        activation_command: expect.objectContaining({
          action: 'activate',
          result_id: 'plugin:result-scoped-search-test',
          tool: 'workflow.search',
        }),
        activation_scope: expect.objectContaining({
          mode: 'result_scoped',
          tool_names: ['dynamic.deep_plan'],
        }),
      })
    )

    const activated = await handler({
      action: 'activate',
      result_id: result.result_id,
      file_type: '.exe',
      query: 'dynamic planning',
      goal: 'dynamic',
    })

    expect(activated.ok).toBe(true)
    const data = activated.data as any
    expect(data.result_mode).toBe('workflow_search')
    expect(data.activated).toEqual([])
    expect(data.activated_tools).toEqual(['dynamic.deep_plan'])
    expect(data.activation_audit.selected_result.result_id).toBe('plugin:result-scoped-search-test')
    expect(data.activation_audit.policy.result_scoped_activation_used).toBe(true)
    expect(data.activation_audit.policy.plugin_level_activation_used).toBe(false)
    expect(data.activation_audit.policy.backend_execution_started).toBe(false)
    expect(surface.isToolVisible('dynamic.deep_plan')).toBe(true)
    expect(surface.isToolVisible('dynamic.behavior.capture')).toBe(false)
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

  test('routes CUDA binary file profiles to hidden static GPU inventory without runtime opt-in', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'cuda-binary-search-test',
        name: 'CUDA Binary Search Test',
        description: 'Static CUDA PTX CUBIN fatbin GPU kernel inventory',
        aspects: {
          formats: ['cuda', 'ptx', 'cubin', 'fatbin', 'sass'],
          platforms: ['cuda', 'cross-platform'],
          execution: ['static'],
          capabilities: ['cuda-artifact-inventory', 'gpu-kernel-summary', 'culifter-handoff'],
          evidence: ['structure', 'symbols', 'workflow'],
        },
        surfaceRules: {
          tier: 2,
          category: 'reverse-engineering',
          activateOn: { fileTypes: ['cuda', 'ptx', 'cubin', 'fatbin'] },
        },
        tools: [
          {
            definition: {
              name: 'cuda.binary.inventory',
              description: 'Static CUDA binary inventory',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['cuda', 'ptx', 'cubin', 'fatbin'],
                execution: ['static'],
                capabilities: ['cuda-artifact-inventory', 'gpu-kernel-summary'],
                safety: ['passive', 'no_cuda_driver', 'no_gpu_access'],
              },
              workflowRecipes: [
                {
                  id: 'cuda.binary.static-inventory-handoff',
                  title: 'CUDA binary inventory',
                  startsWith: ['cuda.binary.inventory'],
                  nextTools: ['culifter.gpu.plan', 'native.object.inventory'],
                  evidence: ['structure', 'symbols', 'workflow'],
                  safety: ['passive', 'no_cuda_driver', 'no_gpu_access'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerGatewayCoreTools(['workflow.search'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({
      file_type: 'CUDA-PTX',
      query: 'gpu kernel ptx inventory',
      goal: 'reverse',
      top_k: 3,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.search_profile.file_type_tags).toEqual(
      expect.arrayContaining(['cuda-ptx', 'ptx', 'cuda', 'gpu', 'sass'])
    )
    const cudaResult = data.results.find(
      (item: any) => item.plugin_id === 'cuda-binary-search-test'
    )
    expect(cudaResult).toEqual(
      expect.objectContaining({
        readiness_state: 'hidden_activation_required',
        activation_required: true,
        recommended_tools: expect.arrayContaining(['cuda.binary.inventory']),
      })
    )
    expect(cudaResult.readiness_state).not.toBe('runtime_opt_in_required')
    expect(surface.isToolVisible('cuda.binary.inventory')).toBe(false)
  })

  test('recommends passive eBPF bytecode inventory without activating runtime telemetry tools', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins = [ebpfBytecodePlugin]
    registerPluginsForSearch(plugins)
    surface.registerGatewayCoreTools(['workflow.search'])

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))

    const result = await handler({
      query: 'inspect ebpf bytecode verifier helper map xdp',
      file_type: '.bpf',
      goal: 'static',
      top_k: 5,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const ebpfResult = data.results.find((item: any) => item.plugin_id === 'ebpf-bytecode')
    expect(ebpfResult).toEqual(
      expect.objectContaining({
        readiness_state: 'hidden_activation_required',
        activation_required: true,
      })
    )
    expect(ebpfResult.recommended_tools).toContain('ebpf.bytecode.inventory')
    expect(ebpfResult.score_breakdown.total_score).toBeGreaterThan(0)
    expect(data.search_profile.file_type_tags).toEqual(
      expect.arrayContaining(['ebpf', 'bpf', 'ebpf-bytecode'])
    )
    expect(surface.isToolVisible('ebpf.bytecode.inventory')).toBe(false)
  })

  test('recommends LLVM bitcode inventory through file-type routing without gateway expansion', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [llvmBitcodePlugin]
    surface.registerCoreTools([
      'workflow.search',
      'workflow.run',
      'artifact.read',
      'tools.discover',
    ])
    surface.registerGatewayCoreTools(['workflow.search', 'workflow.run', 'artifact.read'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({
      query: 'inspect LLVM bitcode IR metadata',
      file_type: '.bc',
      top_k: 5,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'plugin',
          plugin_id: 'llvm-bitcode',
          readiness_state: 'hidden_activation_required',
        }),
      ])
    )
    expect(data.search_profile.recommended_tools).toContain('llvm.bitcode.inventory')
    expect(surface.isToolVisible('llvm.bitcode.inventory')).toBe(false)
    expect(surface.isToolVisible('tools.discover')).toBe(false)

    const activated = await handler({ action: 'activate', plugin_id: 'llvm-bitcode' })
    expect(activated.ok).toBe(true)
    const activatedData = activated.data as any
    expect(activatedData.activated_tools).toContain('llvm.bitcode.inventory')
    expect(activatedData.activation_audit.policy.backend_execution_started).toBe(false)
    expect(surface.isToolVisible('llvm.bitcode.inventory')).toBe(true)
    expect(surface.isToolVisible('tools.discover')).toBe(false)
  })

  test('recommends passive BTF inventory for CO-RE metadata without gateway expansion', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [btfPlugin]
    surface.registerCoreTools([
      'workflow.search',
      'workflow.run',
      'artifact.read',
      'tools.discover',
    ])
    surface.registerGatewayCoreTools(['workflow.search', 'workflow.run', 'artifact.read'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({
      query: 'inspect BTF CO-RE relocation type metadata',
      file_type: '.btf',
      top_k: 5,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.search_profile.file_type_tags).toEqual(
      expect.arrayContaining(['btf', 'bpf-btf', 'ebpf', 'linux'])
    )
    const btfResult = data.results.find((item: any) => item.plugin_id === 'btf')
    expect(btfResult).toEqual(
      expect.objectContaining({
        readiness_state: 'hidden_activation_required',
        activation_required: true,
        recommended_tools: expect.arrayContaining(['btf.type.inventory']),
      })
    )
    expect(btfResult.readiness_state).not.toBe('runtime_opt_in_required')
    expect(surface.isToolVisible('btf.type.inventory')).toBe(false)
    expect(surface.isToolVisible('tools.discover')).toBe(false)
  })

  test('recommends passive container image security profile without gateway expansion', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [containerAnalysisPlugin]
    surface.registerCoreTools([
      'workflow.search',
      'workflow.run',
      'artifact.read',
      'tools.discover',
    ])
    surface.registerGatewayCoreTools(['workflow.search', 'workflow.run', 'artifact.read'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({
      query: 'container image static security profile root entrypoint secret env layer risks',
      file_type: 'oci-image',
      top_k: 5,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.search_profile.file_type_tags).toEqual(
      expect.arrayContaining(['oci-image', 'container', 'archive'])
    )
    const containerResult = data.results.find((item: any) => item.plugin_id === 'container-analysis')
    expect(containerResult).toEqual(
      expect.objectContaining({
        readiness_state: 'hidden_activation_required',
        activation_required: true,
        recommended_tools: expect.arrayContaining([
          'container.structure.analyze',
          'container.image.security.profile',
        ]),
      })
    )
    expect(containerResult.readiness_state).not.toBe('runtime_opt_in_required')
    expect(data.search_profile.recommended_tools).toContain('container.image.security.profile')
    expect(surface.isToolVisible('container.image.security.profile')).toBe(false)
    expect(surface.isToolVisible('tools.discover')).toBe(false)
  })

  test('routes PE hardening queries to the static security profile without runtime opt-in', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'pe-security-search-test',
        name: 'PE Security Search Test',
        description: 'Static PE hardening mitigation exploitability profile',
        aspects: {
          formats: ['pe', 'exe', 'dll'],
          platforms: ['windows'],
          execution: ['static'],
          capabilities: ['security-profile', 'hardening-assessment', 'exploitability-posture'],
          evidence: ['structure', 'mitigations', 'sections', 'workflow'],
        },
        surfaceRules: {
          tier: 1,
          category: 'static-analysis',
          activateOn: { fileTypes: ['pe', 'exe', 'dll'] },
        },
        tools: [
          {
            definition: {
              name: 'pe.security.profile',
              description: 'Static PE security hardening mitigation profile',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe', 'exe', 'dll'],
                platforms: ['windows'],
                execution: ['static'],
                capabilities: ['security-profile', 'hardening-assessment'],
                safety: ['passive', 'no_network_by_default', 'no_mutation'],
              },
              workflowRecipes: [
                {
                  id: 'pe.security.hardening-profile',
                  title: 'PE security hardening profile',
                  startsWith: ['pe.security.profile', 'pe.structure.analyze'],
                  nextTools: ['pe.structure.analyze', 'analysis.evidence.graph'],
                  producesArtifacts: ['pe_security_profile'],
                  evidence: ['structure', 'mitigations', 'workflow'],
                  safety: ['passive', 'no_network_by_default', 'no_mutation'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerGatewayCoreTools(['workflow.search'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({
      file_type: '.exe',
      query: 'security hardening mitigations profile',
      goal: 'triage',
      top_k: 3,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.search_profile.file_type_tags).toEqual(
      expect.arrayContaining(['pe', 'exe', 'windows'])
    )
    const peResult = data.results.find((item: any) => item.plugin_id === 'pe-security-search-test')
    expect(peResult).toEqual(
      expect.objectContaining({
        readiness_state: 'hidden_activation_required',
        activation_required: true,
        recommended_tools: expect.arrayContaining(['pe.security.profile']),
      })
    )
    expect(peResult.readiness_state).not.toBe('runtime_opt_in_required')
    expect(surface.isToolVisible('pe.security.profile')).toBe(false)
  })

  test('preserves one result per search profile lane when topK is constrained', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'pe-format-quota-test',
        name: 'PE Format Quota Test',
        description: 'PE executable structure, imports, sections, and inventory',
        aspects: {
          formats: ['pe', 'exe'],
          platforms: ['windows'],
          execution: ['static'],
          capabilities: ['structure', 'imports', 'inventory'],
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
              description: 'Analyze PE structure, imports, sections, and headers',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe', 'exe'],
                platforms: ['windows'],
                execution: ['static'],
                capabilities: ['structure', 'imports', 'inventory'],
                evidence: ['structure', 'imports'],
              },
              workflowRecipes: [
                {
                  id: 'pe.static.inventory',
                  title: 'PE static inventory',
                  startsWith: ['pe.structure.analyze'],
                  producesArtifacts: ['pe_structure'],
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
        id: 'ghidra-intent-quota-test',
        name: 'Ghidra Intent Quota Test',
        description: 'Ghidra decompile CFG xref function recovery',
        aspects: {
          formats: ['pe', 'exe'],
          platforms: ['windows'],
          execution: ['decompilation'],
          capabilities: ['decompile', 'cfg', 'xref', 'function-recovery'],
          evidence: ['symbols', 'structure'],
        },
        surfaceRules: {
          tier: 3,
          category: 'reverse-engineering',
        },
        tools: [
          {
            definition: {
              name: 'ghidra.analyze',
              description: 'Recover functions, CFG, xrefs, and pseudocode with Ghidra',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe', 'exe'],
                execution: ['decompilation'],
                capabilities: ['decompile', 'cfg', 'xref', 'function-recovery'],
                evidence: ['symbols', 'structure'],
              },
              workflowRecipes: [
                {
                  id: 'ghidra.function-recovery',
                  title: 'Ghidra function recovery',
                  startsWith: ['ghidra.analyze'],
                  nextTools: ['code.cross_decompiler.consensus'],
                  producesArtifacts: ['function_index', 'cfg_summary'],
                  evidence: ['symbols', 'structure'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'rizin-intent-overflow-quota-test',
        name: 'Rizin Intent Overflow Quota Test',
        description: 'Rizin decompile CFG xref function recovery',
        aspects: {
          formats: ['pe', 'exe'],
          platforms: ['windows'],
          execution: ['decompilation'],
          capabilities: ['decompile', 'cfg', 'xref', 'function-recovery'],
          evidence: ['symbols', 'structure'],
        },
        surfaceRules: {
          tier: 3,
          category: 'reverse-engineering',
        },
        tools: [
          {
            definition: {
              name: 'rizin.analyze',
              description: 'Recover functions, CFG, xrefs, and analysis facts with Rizin',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe', 'exe'],
                execution: ['decompilation'],
                capabilities: ['decompile', 'cfg', 'xref', 'function-recovery'],
                evidence: ['symbols', 'structure'],
              },
              workflowRecipes: [
                {
                  id: 'rizin.function-recovery',
                  title: 'Rizin function recovery',
                  startsWith: ['rizin.analyze'],
                  nextTools: ['code.cross_decompiler.consensus'],
                  producesArtifacts: ['function_index', 'cfg_summary'],
                  evidence: ['symbols', 'structure'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'evidence-artifact-quota-test',
        name: 'Evidence Artifact Quota Test',
        description: 'Artifact evidence workflow handoff correlation graph report summary',
        aspects: {
          formats: ['artifact', 'analysis-evidence'],
          execution: ['correlation'],
          capabilities: ['evidence-correlation', 'workflow-handoff', 'report-summary'],
          evidence: ['workflow', 'correlation-graph', 'provenance'],
        },
        surfaceRules: {
          tier: 0,
          category: 'static-analysis',
        },
        tools: [
          {
            definition: {
              name: 'analysis.evidence.graph',
              description: 'Build an artifact evidence workflow handoff correlation graph',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['artifact', 'analysis-evidence'],
                execution: ['correlation'],
                capabilities: ['evidence-correlation', 'workflow-handoff', 'report-summary'],
                evidence: ['workflow', 'correlation-graph', 'provenance'],
              },
              workflowRecipes: [
                {
                  id: 'artifact.evidence.graph',
                  title: 'Artifact evidence graph',
                  startsWith: ['analysis.evidence.graph'],
                  nextTools: ['report.generate'],
                  producesArtifacts: ['evidence_graph'],
                  evidence: ['workflow', 'correlation-graph', 'provenance'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerGatewayCoreTools(['workflow.search'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({
      file_type: '.exe',
      query: 'decompile cfg function recovery',
      goal: 'reverse',
      top_k: 3,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.top_k).toBe(3)
    expect(data.search_profiles.map((profile: any) => profile.lane)).toEqual([
      'format',
      'intent',
      'artifact',
    ])
    expect(data.search_profile.lane_top_k).toEqual(
      expect.objectContaining({
        enabled: true,
        requested_top_k: 3,
        resolved_top_k: 3,
      })
    )
    expect(data.results).toHaveLength(3)
    expect(data.results.map((item: any) => item.plugin_id)).toEqual([
      'ghidra-intent-quota-test',
      'pe-format-quota-test',
      'evidence-artifact-quota-test',
    ])
    expect(data.results.map((item: any) => item.plugin_id)).not.toContain(
      'rizin-intent-overflow-quota-test'
    )
    expect(data.results.find((item: any) => item.plugin_id === 'pe-format-quota-test')).toEqual(
      expect.objectContaining({
        matched_lanes: expect.arrayContaining(['format']),
        selected_via_lane: 'format',
      })
    )
    expect(data.results.find((item: any) => item.plugin_id === 'ghidra-intent-quota-test')).toEqual(
      expect.objectContaining({
        matched_lanes: expect.arrayContaining(['intent']),
        selected_via_lane: 'intent',
      })
    )
    expect(
      data.results.find((item: any) => item.plugin_id === 'evidence-artifact-quota-test')
    ).toEqual(
      expect.objectContaining({
        matched_lanes: expect.arrayContaining(['artifact']),
        selected_via_lane: 'artifact',
      })
    )
    expect(data.quota_decisions).toEqual([
      expect.objectContaining({
        lane: 'format',
        quota: 1,
        selected_result_ids: ['plugin:pe-format-quota-test'],
      }),
      expect.objectContaining({
        lane: 'intent',
        quota: 1,
        selected_result_ids: ['plugin:ghidra-intent-quota-test'],
        overflow_result_ids: expect.arrayContaining(['plugin:rizin-intent-overflow-quota-test']),
      }),
      expect.objectContaining({
        lane: 'artifact',
        quota: 1,
        selected_result_ids: ['plugin:evidence-artifact-quota-test'],
        promoted: true,
      }),
    ])
    expect(surface.isToolVisible('analysis.evidence.graph')).toBe(false)
    expect(surface.isToolVisible('rizin.analyze')).toBe(false)
  })

  test('uses adaptive search profiles and topK when top_k is auto', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'pe-auto-profile-test',
        name: 'PE Auto Profile Test',
        description: 'PE structure and import inventory',
        aspects: {
          formats: ['pe', 'exe'],
          platforms: ['windows'],
          execution: ['static'],
          capabilities: ['structure', 'imports', 'inventory'],
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
              description: 'Analyze PE structure and imports',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe', 'exe'],
                platforms: ['windows'],
                execution: ['static'],
                capabilities: ['structure', 'imports', 'inventory'],
                evidence: ['structure', 'imports'],
              },
              workflowRecipes: [
                {
                  id: 'pe.static.inventory',
                  title: 'PE static inventory',
                  startsWith: ['pe.structure.analyze'],
                  nextTools: ['strings.extract'],
                  producesArtifacts: ['pe_structure'],
                  evidence: ['structure', 'imports'],
                  safety: ['passive'],
                },
              ],
              artifacts: [{ type: 'pe_structure' }],
              workerBackend: {
                backendKind: 'external',
                backendName: 'FixturePEWorker',
                adapter: 'fixture.pe.structure',
                outputArtifactTypes: ['pe_structure'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'decompiler-auto-profile-test',
        name: 'Decompiler Auto Profile Test',
        description: 'Ghidra decompile CFG xref function recovery',
        aspects: {
          formats: ['pe', 'exe'],
          platforms: ['windows'],
          execution: ['decompilation'],
          capabilities: ['decompile', 'cfg', 'xref', 'function-recovery'],
          evidence: ['symbols', 'structure'],
        },
        surfaceRules: {
          tier: 3,
          category: 'reverse-engineering',
        },
        tools: [
          {
            definition: {
              name: 'ghidra.analyze',
              description: 'Recover functions, CFG, xrefs, and pseudocode with Ghidra',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe', 'exe'],
                execution: ['decompilation'],
                capabilities: ['decompile', 'cfg', 'xref', 'function-recovery'],
                evidence: ['symbols', 'structure'],
              },
              workflowRecipes: [
                {
                  id: 'decompiler.function-recovery',
                  title: 'Decompiler function recovery',
                  startsWith: ['ghidra.analyze'],
                  nextTools: ['code.cross_decompiler.consensus'],
                  producesArtifacts: ['function_index', 'cfg_summary'],
                  evidence: ['symbols', 'structure'],
                  safety: ['passive'],
                },
              ],
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'report-auto-profile-test',
        name: 'Report Auto Profile Test',
        description: 'Evidence graph and reporting handoff',
        aspects: {
          formats: ['artifact', 'analysis-evidence'],
          execution: ['correlation'],
          capabilities: ['evidence-correlation', 'report-summary'],
          evidence: ['artifact', 'workflow', 'correlation-graph'],
        },
        surfaceRules: {
          tier: 0,
          category: 'static-analysis',
        },
        tools: [
          {
            definition: {
              name: 'analysis.evidence.graph',
              description: 'Build an evidence graph for reporting',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['artifact', 'analysis-evidence'],
                execution: ['correlation'],
                capabilities: ['evidence-correlation', 'report-summary'],
                evidence: ['artifact', 'workflow', 'correlation-graph'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerGatewayCoreTools(['workflow.search'])
    registerPluginsForSearch(plugins)

    const handler = createWorkflowSearchHandler(createPluginManager(plugins))
    const result = await handler({
      file_type: '.exe',
      query: 'decompile cfg function recovery',
      goal: 'reverse',
      depth: 'deep',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.top_k).toBe(12)
    expect(data.search_profile.requested_top_k).toBe('auto')
    expect(data.search_profile.top_k_strategy).toEqual(
      expect.objectContaining({
        mode: 'adaptive',
        value: 12,
        reason: 'Deep reverse-engineering intent.',
      })
    )
    expect(data.search_profiles.map((profile: any) => profile.lane)).toEqual(
      expect.arrayContaining(['format', 'intent', 'artifact'])
    )
    expect(data.search_profile.search_profiles).toEqual(data.search_profiles)
    expect(data.search_profiles.find((profile: any) => profile.lane === 'format')).toEqual(
      expect.objectContaining({
        triggers: expect.arrayContaining(['pe', 'exe', 'windows']),
        recommended_tools: expect.arrayContaining(['pe.structure.analyze', 'ghidra.analyze']),
      })
    )
    expect(data.search_profile.plugin_matrix_summary).toEqual(
      expect.objectContaining({
        capability_count: expect.any(Number),
        runtime_count: expect.any(Number),
        safety_count: expect.any(Number),
        artifact_type_count: expect.any(Number),
        worker_backend_count: expect.any(Number),
      })
    )
    expect(data.search_profile.plugin_matrix_summary.capability_count).toBeGreaterThan(0)
    expect(data.search_profile.plugin_matrix_summary.artifact_type_count).toBeGreaterThan(0)
    expect(data.search_profile.plugin_matrix_summary.worker_backend_count).toBeGreaterThan(0)
    expect(data.results.map((item: any) => item.plugin_id)).toEqual(
      expect.arrayContaining(['decompiler-auto-profile-test', 'pe-auto-profile-test'])
    )
    expect(surface.isToolVisible('ghidra.analyze')).toBe(false)
  })

  test('uses sample-scoped route facts to rank follow-up tools without activating them', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    const plugins: Plugin[] = [
      {
        id: 'sample-facts-evidence-test',
        name: 'Sample Facts Evidence Test',
        description: 'Build evidence graph and reporting handoff from existing artifacts',
        aspects: {
          formats: ['artifact', 'analysis-evidence', 'pe'],
          execution: ['correlation'],
          capabilities: ['evidence-correlation', 'reporting', 'workflow-handoff'],
          evidence: ['workflow', 'correlation-graph', 'yara-scan'],
        },
        surfaceRules: {
          tier: 0,
          category: 'static-analysis',
        },
        tools: [
          {
            definition: {
              name: 'analysis.evidence.graph',
              description: 'Build an evidence graph from YARA scan artifacts and workflow handoffs',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['artifact', 'analysis-evidence', 'pe'],
                execution: ['correlation'],
                capabilities: ['evidence-correlation', 'reporting', 'workflow-handoff'],
                evidence: ['workflow', 'correlation-graph', 'yara-scan'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
      {
        id: 'sample-facts-generic-test',
        name: 'Sample Facts Generic Test',
        description: 'Generic PE metadata inventory',
        aspects: {
          formats: ['pe'],
          execution: ['static'],
          capabilities: ['metadata', 'inventory'],
        },
        surfaceRules: {
          tier: 1,
          category: 'static-analysis',
          activateOn: { fileTypes: ['pe'] },
        },
        tools: [
          {
            definition: {
              name: 'pe.metadata.inspect',
              description: 'Inspect generic PE metadata',
              inputSchema: z.object({ sample_id: z.string() }),
              aspects: {
                formats: ['pe'],
                execution: ['static'],
                capabilities: ['metadata', 'inventory'],
              },
            },
            handler: async () => ({ ok: true }),
          },
        ],
      },
    ]
    surface.registerGatewayCoreTools(['workflow.search'])
    registerPluginsForSearch(plugins)

    const artifactRef = {
      id: 'artifact-yara',
      type: 'backend_yara_scan',
      path: 'reports/yara/scan.json',
      sha256: 'a'.repeat(64),
      mime: 'application/json',
    }
    const database = {
      findSample: () => ({ file_type: 'PE32', sha256: 'b'.repeat(64) }),
      findArtifacts: () => [artifactRef],
      findAnalysisRunsBySample: () => [
        {
          id: 'run-1',
          status: 'completed',
          goal: 'triage',
          depth: 'balanced',
          latest_stage: 'fast_profile',
          artifact_refs_json: JSON.stringify([artifactRef]),
          updated_at: '2026-06-09T00:00:00.000Z',
        },
      ],
      findAnalysisRunStages: () => [
        {
          stage: 'fast_profile',
          status: 'completed',
          tool: 'workflow.analyze.stage',
          artifact_refs_json: JSON.stringify([artifactRef]),
          coverage_json: JSON.stringify({
            coverage_gaps: [
              {
                domain: 'reporting',
                status: 'missing',
                reason: 'Evidence graph has not been built from YARA scan artifacts.',
              },
            ],
            upgrade_paths: [
              {
                tool: 'analysis.evidence.graph',
                purpose: 'Build evidence graph from scan artifacts before report generation.',
                closes_gaps: ['reporting'],
                expected_coverage_gain: 'correlation graph',
                cost_tier: 'low',
                availability: 'ready',
                prerequisites: [],
                blockers: [],
                requires_approval: false,
              },
            ],
            suspected_findings: ['yara-match'],
          }),
        },
      ],
      findAnalysisEvidenceBySample: () => [
        {
          evidence_family: 'yara-scan',
          backend: 'yara',
          mode: 'static',
          artifact_refs_json: JSON.stringify([artifactRef]),
        },
      ],
    }

    const handler = createWorkflowSearchHandler(createPluginManager(plugins), { database })
    const result = await handler({
      sample_id: 'sha256:sample',
      query: 'continue analysis',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.top_k).toBe(8)
    expect(data.search_profiles.map((profile: any) => profile.lane)).toContain('sample_facts')
    expect(data.search_profile.sample_route_facts).toEqual(
      expect.objectContaining({
        artifact_types: expect.arrayContaining(['backend-yara-scan']),
        evidence_families: expect.arrayContaining(['yara-scan']),
        coverage_gap_domains: expect.arrayContaining(['reporting']),
        upgrade_tools: expect.arrayContaining(['analysis.evidence.graph']),
        recommended_tools: expect.arrayContaining(['analysis.evidence.graph']),
      })
    )
    expect(data.search_profile.top_k_strategy).toEqual(
      expect.objectContaining({
        reason: 'Sample-scoped route facts were available for follow-up ranking.',
      })
    )
    expect(data.results[0]).toEqual(
      expect.objectContaining({
        plugin_id: 'sample-facts-evidence-test',
        recommended_tools: expect.arrayContaining(['analysis.evidence.graph']),
      })
    )
    expect(data.results[0].score_breakdown.sample_score).toBeGreaterThan(0)
    expect(data.results[0].matched_profile_fields.join(' ')).toContain('sample recommended tools')
    expect(surface.isToolVisible('analysis.evidence.graph')).toBe(false)
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
