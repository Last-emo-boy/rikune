/**
 * Unit tests for @rikune/plugin-sdk contracts.
 */

import { describe, expect, test } from '@jest/globals'
import { SURFACE_FILE_TYPE_TAGS } from '../../../packages/plugin-sdk/src/index.js'
import type {
  Plugin,
  PluginStatus,
  RuntimeBackendHint,
  ToolDefinition,
  WorkerResult,
} from '../../../packages/plugin-sdk/src/index.js'

describe('@rikune/plugin-sdk', () => {
  test('runtime backend hint contract supports declared backend types', () => {
    const hints: RuntimeBackendHint[] = [
      { type: 'python-worker', handler: 'worker.py' },
      { type: 'spawn', handler: 'native.sample.execute' },
      { type: 'inline', handler: 'executeSandboxExecute' },
    ]

    expect(hints.map(h => h.type)).toEqual(['python-worker', 'spawn', 'inline'])
    expect(hints.every(h => h.handler.length > 0)).toBe(true)
  })

  test('tool and worker result contracts can be expressed without server internals', () => {
    const tool: ToolDefinition = {
      name: 'dynamic.sample.run',
      description: 'Run sample dynamically',
      inputSchema: { type: 'object' },
      runtimeBackendHint: { type: 'spawn', handler: 'dynamic.sample.run' },
    }

    const result: WorkerResult = {
      ok: true,
      data: { status: 'completed' },
      warnings: [],
      artifacts: [{ id: 'a1', type: 'json', path: '/tmp/out.json', sha256: 'abc' }],
    }

    expect(tool.runtimeBackendHint?.handler).toBe('dynamic.sample.run')
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
})
