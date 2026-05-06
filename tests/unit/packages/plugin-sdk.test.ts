/**
 * Unit tests for @rikune/plugin-sdk contracts.
 */

import { describe, expect, jest, test } from '@jest/globals'
import {
  SURFACE_FILE_TYPE_TAGS,
  defineManifestPlugin,
  definePlugin,
  defineTool,
  envIsSet,
  fail,
  getRuntimeConfig,
  getWorkspaceServices,
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
    expect(SURFACE_FILE_TYPE_TAGS['mach-o']).toContain('macos')
    expect(SURFACE_FILE_TYPE_TAGS.apk).toContain('android')
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
