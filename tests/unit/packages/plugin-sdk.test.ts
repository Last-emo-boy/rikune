/**
 * Unit tests for @rikune/plugin-sdk contracts.
 */

import { describe, expect, jest, test } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import {
  DynamicRuntimePolicySchema,
  PluginAspectsSchema,
  SURFACE_FILE_TYPE_TAGS,
  ToolRuntimeContractSchema,
  auditPluginQuality,
  buildSampleProfileAspects,
  createEvidenceRef,
  createEvidenceTimelineEntry,
  createPluginTestHarness,
  createToolOutputEnvelope,
  describeAspectCoverage,
  defineManifestPlugin,
  definePlugin,
  defineTool,
  envIsSet,
  fail,
  getRuntimeConfig,
  getWorkspaceServices,
  matchSampleProfile,
  normalizePluginAspects,
  ok,
  pathExists,
  requireDatabase,
  requirePlatformServer,
  requireServices,
  toolText,
  validatePlugin,
  validateTool,
} from '../../../packages/plugin-sdk/src/index.js'
import type {
  Plugin,
  PluginServices,
  PluginStatus,
  ToolRuntimeContract,
  ToolDefinition,
  WorkerResult,
} from '../../../packages/plugin-sdk/src/index.js'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

describe('@rikune/plugin-sdk', () => {
  test('runtime contract supports declared backend types', () => {
    const contracts: ToolRuntimeContract[] = [
      { type: 'python-worker', handler: 'worker.py' },
      { type: 'spawn', handler: 'native.sample.execute' },
      { type: 'inline', handler: 'executeSandboxExecute' },
    ]

    expect(contracts.map((contract) => contract.type)).toEqual(['python-worker', 'spawn', 'inline'])
    expect(contracts.every((contract) => contract.handler.length > 0)).toBe(true)
  })

  test('runtime policy schema accepts expanded dynamic backends safely', () => {
    const policy = DynamicRuntimePolicySchema.parse({
      passiveByDefault: true,
      requiresUserOptIn: true,
      requiresIsolation: true,
      allowedBackends: ['windows-host-agent', 'android-emulator', 'frida-server', 'wasmtime'],
      networkPolicy: 'disabled',
      maxRuntimeMs: 30000,
    })
    const contract = ToolRuntimeContractSchema.parse({
      type: 'spawn',
      handler: 'android.runtime.plan',
      modes: ['plan_only'],
      policy,
      isolation: { required: true, backends: ['android-emulator'] },
      capabilities: ['readiness', 'behavior-plan'],
      safety: ['passive', 'opt_in_dynamic'],
    })

    expect(contract.policy?.allowedBackends).toEqual(
      expect.arrayContaining(['android-emulator', 'wasmtime'])
    )
    expect(contract.isolation?.backends).toEqual(['android-emulator'])
  })

  test('tool and worker result contracts can be expressed without server internals', () => {
    const tool: ToolDefinition = {
      name: 'dynamic.sample.run',
      description: 'Run sample dynamically',
      inputSchema: { type: 'object' },
      runtime: { type: 'spawn', handler: 'dynamic.sample.run' },
    }

    const result: WorkerResult = {
      ok: true,
      data: { status: 'completed' },
      warnings: [],
      artifacts: [{ id: 'a1', type: 'json', path: '/tmp/out.json', sha256: 'abc' }],
    }

    expect(tool.runtime?.handler).toBe('dynamic.sample.run')
    expect(result.artifacts?.[0]?.type).toBe('json')
  })

  test('plugin status supports skipped and loaded states with control-plane metadata', () => {
    const loaded: PluginStatus = {
      id: 'dynamic',
      name: 'Dynamic',
      status: 'loaded',
      tools: ['dynamic.sample.run'],
      controlPlaneStatus: 'completed',
      statusDetail: 'Plugin loaded with 1 tool',
    }
    const skipped: PluginStatus = {
      id: 'ghidra',
      name: 'Ghidra',
      status: 'skipped-check',
      tools: [],
      reasonCode: 'system-deps-missing',
      controlPlaneStatus: 'failed',
      error: 'Missing dependency',
    }

    expect(loaded.controlPlaneStatus).toBe('completed')
    expect(skipped.reasonCode).toBe('system-deps-missing')
    expect(skipped.error).toContain('Missing')
  })

  test('surface file type tags provide normalized vocabulary', () => {
    expect(SURFACE_FILE_TYPE_TAGS.pe).toEqual(expect.arrayContaining(['pe', 'windows']))
    expect(SURFACE_FILE_TYPE_TAGS['pe32+']).toEqual(
      expect.arrayContaining(['pe32-plus', 'pe64', 'pe', 'windows'])
    )
    expect(SURFACE_FILE_TYPE_TAGS['mach-o']).toContain('macos')
    expect(SURFACE_FILE_TYPE_TAGS.apk).toContain('android')
    expect(SURFACE_FILE_TYPE_TAGS.apks).toEqual(expect.arrayContaining(['android', 'split-apk']))
    expect(SURFACE_FILE_TYPE_TAGS.ipa).toEqual(expect.arrayContaining(['ios', 'macho']))
    expect(SURFACE_FILE_TYPE_TAGS.wasm).toContain('wasi')
    expect(SURFACE_FILE_TYPE_TAGS['wasm-component']).toEqual(
      expect.arrayContaining([
        'wasm-component',
        'component-model',
        'wit-component',
        'wasi-preview2',
      ])
    )
    expect(SURFACE_FILE_TYPE_TAGS['wasi-preview2']).toEqual(
      expect.arrayContaining(['wasi-preview2', 'component-model', 'wasm-component', 'wasi'])
    )
    expect(SURFACE_FILE_TYPE_TAGS['cuda-ptx']).toEqual(
      expect.arrayContaining(['ptx', 'cuda', 'gpu', 'sass'])
    )
    expect(SURFACE_FILE_TYPE_TAGS['cuda-cubin']).toEqual(
      expect.arrayContaining(['cubin', 'cuda', 'gpu', 'sass', 'elf'])
    )
    expect(SURFACE_FILE_TYPE_TAGS['cuda-fatbin']).toEqual(
      expect.arrayContaining(['fatbin', 'cuda', 'gpu', 'ptx', 'cubin'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.ebpf).toEqual(
      expect.arrayContaining(['ebpf', 'bpf', 'ebpf-bytecode', 'linux', 'bytecode'])
    )
    expect(SURFACE_FILE_TYPE_TAGS['ebpf-elf']).toEqual(
      expect.arrayContaining(['ebpf', 'bpf', 'elf', 'linux', 'object', 'btf'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.btf).toEqual(
      expect.arrayContaining(['btf', 'bpf-btf', 'ebpf', 'linux', 'types'])
    )
    expect(SURFACE_FILE_TYPE_TAGS['btf-ext']).toEqual(
      expect.arrayContaining(['btf-ext', 'btf', 'core-relocations', 'co-re'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.bc).toEqual(
      expect.arrayContaining(['bc', 'llvm-bc', 'llvm-bitcode', 'llvm-ir'])
    )
    expect(SURFACE_FILE_TYPE_TAGS['llvm-bitcode-wrapper']).toEqual(
      expect.arrayContaining(['llvm-bitcode-wrapper', 'llvm-bitcode', 'llvm-ir'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.spv).toEqual(
      expect.arrayContaining(['spir-v', 'shader-ir', 'vulkan', 'webgpu', 'gpu'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.dxil).toEqual(
      expect.arrayContaining(['dxcontainer', 'shader-ir', 'directx', 'gpu', 'llvm-ir'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.wgsl).toEqual(
      expect.arrayContaining(['wgsl', 'webgpu', 'shader-ir', 'source'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.safetensors).toEqual(
      expect.arrayContaining(['safetensors', 'ml-model', 'ai-model', 'tensor'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.gguf).toEqual(
      expect.arrayContaining(['gguf', 'ggml', 'ml-model', 'ai-model'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.onnx).toEqual(
      expect.arrayContaining(['onnx', 'ml-model', 'model-graph'])
    )
    expect(SURFACE_FILE_TYPE_TAGS['pytorch-checkpoint']).toEqual(
      expect.arrayContaining(['pytorch-checkpoint', 'pickle', 'ml-model'])
    )
    expect(SURFACE_FILE_TYPE_TAGS.npz).toEqual(
      expect.arrayContaining(['npz', 'numpy', 'zip', 'archive', 'ml-model'])
    )
  })

  test('aspect helpers normalize, describe, and match sample profiles', () => {
    const pluginAspects = normalizePluginAspects({
      formats: ['APK', 'DEX', 'native_lib'],
      platforms: ['Android'],
      execution: ['Static'],
      evidence: ['Manifest', 'Certificates'],
    })
    const sampleAspects = buildSampleProfileAspects({
      fileTypes: ['apk'],
      platforms: ['android'],
      execution: ['static'],
      findings: ['permissions'],
    })
    const match = matchSampleProfile(pluginAspects, sampleAspects)

    expect(PluginAspectsSchema.parse(pluginAspects).formats).toEqual(
      expect.arrayContaining(['apk', 'dex', 'native-lib'])
    )
    expect(match.matched).toBe(true)
    expect(match.matchedAspects.formats).toEqual(expect.arrayContaining(['apk', 'dex']))
    expect(describeAspectCoverage(pluginAspects)).toEqual(
      expect.arrayContaining(['platforms: android', 'execution: static'])
    )
  })

  test('plugin contract can describe dependencies and registration', () => {
    const plugin: Plugin = {
      id: 'test-plugin',
      name: 'Test Plugin',
      executionDomain: 'dynamic',
      dependencies: ['shared-base'],
      register: () => ['test.tool'],
    }

    expect(plugin.executionDomain).toBe('dynamic')
    expect(plugin.register?.({ registerTool() {}, unregisterTool() {} }, {})).toEqual(['test.tool'])
  })

  test('defineTool and definePlugin auto-register declarative tools', async () => {
    const handler = jest.fn(async () => ok({ completed: true }))
    const tool = defineTool({
      name: 'demo.echo',
      description: 'Echo demo input',
      inputSchema: { type: 'object' },
      handler,
    })
    const plugin = definePlugin({
      id: 'demo',
      name: 'Demo',
      executionDomain: 'static',
      tools: [tool],
    })
    const registered: Array<{ name: string; handler: (args: unknown) => Promise<unknown> }> = []
    const server = {
      registerTool(
        definition: ToolDefinition,
        registeredHandler: (args: unknown) => Promise<unknown>
      ) {
        registered.push({ name: definition.name, handler: registeredHandler })
      },
      unregisterTool() {},
    }

    expect(plugin.register?.(server, {})).toEqual(['demo.echo'])
    expect(registered.map((item) => item.name)).toEqual(['demo.echo'])
    await registered[0].handler({ sample_id: 'sha256:test' })
    expect(handler).toHaveBeenCalledWith({ sample_id: 'sha256:test' }, {}, undefined)
  })

  test('defineTool preserves workflow recipe metadata', () => {
    const tool = defineTool({
      name: 'demo.workflow.seed',
      description: 'Seed a cross-plugin workflow',
      inputSchema: { type: 'object' },
      outputSchema: { type: 'object' },
      aspects: {
        execution: ['static', 'correlation'],
        capabilities: ['workflow-seed'],
        evidence: ['workflow'],
      },
      workflowRecipes: [
        {
          id: 'demo.workflow',
          title: 'Demo workflow',
          startsWith: ['demo.workflow.seed'],
          nextTools: ['demo.workflow.next'],
          requiredArtifacts: ['demo_input'],
          producesArtifacts: ['demo_output'],
          evidence: ['workflow'],
          safety: ['passive'],
        },
      ],
      handler: async () => ok({}),
    })

    expect(tool.definition.workflowRecipes).toEqual([
      expect.objectContaining({
        id: 'demo.workflow',
        nextTools: ['demo.workflow.next'],
      }),
    ])
    expect(validateTool(tool).ok).toBe(true)
  })

  test('defineManifestPlugin binds manifest tools to named handlers', async () => {
    const plugin = defineManifestPlugin(
      {
        id: 'manifest-demo',
        name: 'Manifest Demo',
        executionDomain: 'static',
        tools: [
          {
            name: 'manifest_demo.echo',
            description: 'Manifest-backed echo',
            inputSchema: { type: 'object' },
          },
        ],
      },
      {
        'manifest_demo.echo': async () => ok({ source: 'manifest' }),
      }
    )
    const registered: Array<{ name: string }> = []
    plugin.register?.(
      {
        registerTool(definition: ToolDefinition) {
          registered.push({ name: definition.name })
        },
        unregisterTool() {},
      },
      {}
    )

    expect(registered).toEqual([{ name: 'manifest_demo.echo' }])
  })

  test('manifest plugin preserves aspects, evidence, artifacts, and runtime policy', async () => {
    const plugin = defineManifestPlugin(
      {
        id: 'manifest-dynamic-demo',
        name: 'Manifest Dynamic Demo',
        executionDomain: 'dynamic',
        aspects: {
          formats: ['apk'],
          platforms: ['android'],
          execution: ['dynamic'],
          safety: ['passive', 'opt_in_dynamic'],
        },
        runtimePolicy: {
          passiveByDefault: true,
          requiresUserOptIn: true,
          requiresIsolation: true,
          allowedBackends: ['android-emulator'],
          networkPolicy: 'disabled',
        },
        tools: [
          {
            name: 'manifest_dynamic.plan',
            description: 'Manifest-backed dynamic plan',
            inputSchema: { type: 'object' },
            outputSchema: { type: 'object' },
            aspects: { formats: ['apk'], platforms: ['android'], execution: ['dynamic'] },
            artifacts: [{ type: 'manifest-dynamic.json' }],
            evidence: [{ category: 'timeline', artifactTypes: ['manifest-dynamic.json'] }],
            workflowRecipes: [
              {
                id: 'manifest.dynamic.plan',
                title: 'Manifest dynamic plan',
                startsWith: ['manifest_dynamic.plan'],
                nextTools: ['tool.readiness'],
                producesArtifacts: ['manifest-dynamic.json'],
                evidence: ['timeline', 'workflow'],
                safety: ['passive', 'opt_in_dynamic'],
              },
            ],
            runtimePolicy: {
              passiveByDefault: true,
              requiresUserOptIn: true,
              allowedBackends: ['android-emulator'],
            },
            runtime: {
              type: 'spawn',
              handler: 'manifest_dynamic.runtime.plan',
              modes: ['plan_only'],
              policy: {
                passiveByDefault: true,
                requiresUserOptIn: true,
                allowedBackends: ['android-emulator'],
              },
            },
          },
        ],
      },
      {
        'manifest_dynamic.plan': async () => ok({ source: 'manifest' }),
      }
    )

    expect(plugin.aspects?.formats).toEqual(['apk'])
    expect(plugin.runtimePolicy?.networkPolicy).toBe('disabled')
    expect(plugin.tools?.[0].definition.evidence?.[0].category).toBe('timeline')
    expect(plugin.tools?.[0].definition.workflowRecipes?.[0].id).toBe('manifest.dynamic.plan')
    expect(plugin.tools?.[0].definition.runtime?.policy?.allowedBackends).toEqual([
      'android-emulator',
    ])
  })

  test('artifact/evidence fixture can be loaded as a manifest v2 plugin', async () => {
    const fixturePath = path.join(
      repoRoot,
      'tests',
      'fixtures',
      'plugins',
      'artifact-evidence',
      'plugin.json'
    )
    const manifest = JSON.parse(fs.readFileSync(fixturePath, 'utf8'))
    const plugin = defineManifestPlugin(manifest, {
      'fixture.artifact.evidence': async () =>
        ok(
          { fixture: true },
          {
            artifacts: [
              {
                id: 'fixture-artifact',
                type: 'fixture_analysis',
                path: 'fixtures/fixture.json',
                sha256: '0'.repeat(64),
              },
            ],
            evidence: [
              createEvidenceRef({
                id: 'fixture-evidence',
                category: 'timeline',
                source: 'fixture',
                toolName: 'fixture.artifact.evidence',
              }),
            ],
          }
        ),
    })
    const harness = createPluginTestHarness()

    harness.registerPlugin(plugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'fixture.artifact.evidence'
    )
    const result = (await tool?.handler({ sample_id: 'sha256:fixture' })) as WorkerResult

    expect(plugin.aspects?.evidence).toEqual(expect.arrayContaining(['structure', 'timeline']))
    expect(plugin.runtimePolicy?.requiresUserOptIn).toBe(true)
    expect(tool?.definition.artifacts?.[0].type).toBe('fixture_analysis')
    expect(tool?.definition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining(['structure', 'timeline'])
    )
    expect(result.artifacts?.[0].type).toBe('fixture_analysis')
    expect(result.evidence?.[0].category).toBe('timeline')
  })

  test('manifest plugins fail fast when a handler is missing', () => {
    expect(() =>
      defineManifestPlugin(
        {
          id: 'manifest-demo',
          name: 'Manifest Demo',
          tools: [{ name: 'manifest_demo.echo', description: 'Manifest-backed echo' }],
        },
        {}
      )
    ).toThrow(/Missing handler/)
  })

  test('validation reports actionable plugin and tool errors', () => {
    expect(validateTool({ name: 'Bad Tool', description: '', inputSchema: {} }).ok).toBe(false)
    const plugin = {
      id: 'bad plugin',
      name: 'Bad',
      tools: [
        defineTool({
          name: 'bad.tool',
          description: 'Bad tool',
          inputSchema: {},
          handler: async () => ok({}),
        }),
        defineTool({
          name: 'bad.tool',
          description: 'Duplicate tool',
          inputSchema: {},
          handler: async () => ok({}),
        }),
      ],
    } as Plugin

    const result = validatePlugin(plugin)
    expect(result.ok).toBe(false)
    expect(result.errors.join('\n')).toContain('Duplicate tool name')
  })

  test('auditPluginQuality reports warning-first plugin standard gaps', () => {
    const plugin = definePlugin({
      id: 'audit-demo',
      name: 'Audit Demo',
      executionDomain: 'dynamic',
      tools: [
        defineTool({
          name: 'audit_demo.run',
          description: 'Audit demo runtime-like tool',
          inputSchema: { type: 'object' },
          handler: async () => ok({}),
        }),
      ],
    })

    const warnings = auditPluginQuality(plugin)
    const codes = warnings.map((warning) => warning.code)

    expect(codes).toEqual(
      expect.arrayContaining([
        'missing-surface-rules',
        'missing-aspects',
        'missing-system-deps',
        'missing-readiness-check',
        'missing-output-schema',
        'missing-evidence',
        'dynamic-runtime-contract-missing',
        'missing-runtime-policy',
      ])
    )
    expect(
      warnings.every((warning) => warning.severity === 'info' || warning.severity === 'warning')
    ).toBe(true)
    expect(warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          plugin_id: 'audit-demo',
          suggested_task_owner: 'TASK-006',
        }),
      ])
    )
  })

  test('auditPluginQuality reports workflow-capable tools without workflow recipes', () => {
    const plugin = definePlugin({
      id: 'workflow-audit-demo',
      name: 'Workflow Audit Demo',
      executionDomain: 'static',
      aspects: {
        execution: ['static', 'correlation'],
        capabilities: ['workflow-summary'],
        evidence: ['workflow'],
      },
      surfaceRules: { tier: 1, category: 'static-analysis' },
      tools: [
        defineTool({
          name: 'workflow_audit.seed',
          description: 'Workflow-capable tool with no recipe',
          inputSchema: { type: 'object' },
          outputSchema: { type: 'object' },
          artifacts: [{ type: 'workflow_audit_seed' }],
          evidence: [{ category: 'workflow', artifactTypes: ['workflow_audit_seed'] }],
          handler: async () => ok({}),
        }),
      ],
    })

    expect(auditPluginQuality(plugin)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'missing-workflow-recipe',
          severity: 'info',
          tool: 'workflow_audit.seed',
          plugin_id: 'workflow-audit-demo',
          suggested_task_owner: 'TASK-002',
        }),
      ])
    )
  })

  test('result helpers produce compatible tool and worker results', () => {
    expect(ok({ status: 'ready' })).toEqual({ ok: true, data: { status: 'ready' } })
    expect(fail('missing dependency')).toEqual({
      ok: false,
      status: 'failed',
      errors: ['missing dependency'],
    })
    expect(toolText({ ok: true, data: { value: 1 } }).structuredContent).toEqual({
      ok: true,
      data: { value: 1 },
    })
  })

  test('evidence helpers produce tool output envelopes and worker-compatible refs', () => {
    const evidence = createEvidenceRef({
      id: 'ev-1',
      category: 'structure',
      source: 'unit-test',
      toolName: 'demo.tool',
      confidence: 0.9,
    })
    const timeline = createEvidenceTimelineEntry({
      source: 'unit-test',
      toolName: 'demo.tool',
      category: 'filesystem',
      action: 'read',
      target: '/tmp/sample',
      confidence: 0.8,
    })
    const envelope = createToolOutputEnvelope({
      ok: true,
      data: { status: 'ready' },
      evidence: [evidence],
      timeline: [timeline],
    })

    expect(envelope.evidence?.[0].id).toBe('ev-1')
    expect(envelope.timeline?.[0].category).toBe('filesystem')
    expect(ok({ status: 'ready' }, { evidence: [evidence] }).evidence).toEqual([evidence])
  })

  test('plugin test harness registers tools with deps and context', async () => {
    const handler = jest.fn(async (_args: { sample_id: string }, deps, ctx) =>
      ok({ db: deps.database.kind, plugin: ctx?.pluginId })
    )
    const plugin = definePlugin({
      id: 'harness-demo',
      name: 'Harness Demo',
      executionDomain: 'static',
      tools: [
        defineTool({
          name: 'harness_demo.run',
          description: 'Harness demo',
          inputSchema: { type: 'object' },
          outputSchema: { type: 'object' },
          aspects: { formats: ['pe'], platforms: ['windows'], execution: ['static'] },
          artifacts: [{ type: 'harness-demo.json' }],
          evidence: [{ category: 'structure' }],
          handler,
        }),
      ],
    })
    const harness = createPluginTestHarness({
      deps: { database: { kind: 'test-db' } },
      ctx: { pluginId: 'harness-demo' },
    })

    expect(harness.registerPlugin(plugin)).toEqual(['harness_demo.run'])
    expect(harness.registeredTools[0].definition.aspects?.formats).toEqual(['pe'])
    await harness.registeredTools[0].handler({ sample_id: 'sha256:test' })
    expect(handler).toHaveBeenCalledWith(
      { sample_id: 'sha256:test' },
      expect.objectContaining({ database: { kind: 'test-db' } }),
      expect.objectContaining({ pluginId: 'harness-demo' })
    )
  })

  test('plugin deps expose grouped services alongside top-level fields', () => {
    const services: PluginServices = {
      workspace: {
        manager: { kind: 'workspace' },
        database: { kind: 'db' },
      },
      runtime: {
        client: { execute: async () => ({ ok: true }) },
        mode: 'remote-sandbox',
      },
      platform: {
        logger: { info() {} },
      },
    }

    expect(services.workspace?.manager).toEqual({ kind: 'workspace' })
    expect(services.runtime?.mode).toBe('remote-sandbox')
    expect(typeof services.platform?.logger?.info).toBe('function')
  })

  test('service helpers prefer grouped services and fall back to top-level fields', () => {
    const deps = {
      workspaceManager: { kind: 'top-level-workspace' },
      database: { kind: 'top-level-db' },
      config: { runtime: { mode: 'top-level' } },
      services: {
        workspace: {
          manager: { kind: 'grouped-workspace' },
          database: { kind: 'grouped-db' },
        },
        runtime: {
          mode: 'remote-sandbox',
          config: { mode: 'grouped', endpoint: 'http://127.0.0.1:18081' },
        },
      },
    }

    expect(getWorkspaceServices(deps as any)).toEqual(
      expect.objectContaining({
        manager: { kind: 'grouped-workspace' },
        database: { kind: 'grouped-db' },
      })
    )
    expect(getRuntimeConfig(deps as any)).toEqual({
      mode: 'grouped',
      endpoint: 'http://127.0.0.1:18081',
    })
  })

  test('require helpers fail fast with actionable dependency labels', () => {
    expect(() => requireDatabase({} as any, 'analysis.notes')).toThrow(
      'database is required for analysis.notes'
    )
    expect(() => requirePlatformServer({} as any, 'batch.submit')).toThrow(
      'platform server is required for batch.submit'
    )
  })

  test('requireServices resolves grouped service paths', () => {
    const deps = {
      services: {
        workspace: { database: { kind: 'db' } },
        platform: { server: { kind: 'server' } },
      },
    }
    const services = requireServices(
      deps as any,
      ['workspace.database', 'platform.server'],
      'demo.tool'
    )

    expect(services['workspace.database']).toEqual({ kind: 'db' })
    expect(services['platform.server']).toEqual({ kind: 'server' })
    expect(() => requireServices({} as any, ['runtime.client'], 'demo.tool')).toThrow(
      'runtime.client is required for demo.tool'
    )
  })

  test('environment and path helpers expose simple checks', () => {
    const original = process.env.RIKUNE_PLUGIN_TEST
    process.env.RIKUNE_PLUGIN_TEST = '1'
    expect(envIsSet('RIKUNE_PLUGIN_TEST')).toBe(true)
    expect(pathExists(process.cwd())).toBe(true)
    if (original === undefined) {
      delete process.env.RIKUNE_PLUGIN_TEST
    } else {
      process.env.RIKUNE_PLUGIN_TEST = original
    }
  })
})
