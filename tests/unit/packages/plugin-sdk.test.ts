/**
 * Unit tests for @rikune/plugin-sdk contracts.
 */

import { describe, expect, test } from '@jest/globals'
import {
  SURFACE_FILE_TYPE_TAGS,
  getRuntimeConfig,
  getWorkspaceServices,
  requireDatabase,
  requirePlatformServer,
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

    expect(contracts.map(contract => contract.type)).toEqual(['python-worker', 'spawn', 'inline'])
    expect(contracts.every(contract => contract.handler.length > 0)).toBe(true)
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
    expect(plugin.register({ registerTool() {}, unregisterTool() {} }, {})).toEqual(['test.tool'])
  })

  test('plugin deps expose grouped services without removing legacy fields', () => {
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

  test('service helpers prefer grouped services and fall back to legacy fields', () => {
    const deps = {
      workspaceManager: { kind: 'legacy-workspace' },
      database: { kind: 'legacy-db' },
      config: { runtime: { mode: 'legacy' } },
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
})
