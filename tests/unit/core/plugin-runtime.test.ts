/**
 * Unit tests for core/plugin-runtime.ts
 */

import { describe, test, expect, jest } from '@jest/globals'
import { PluginRuntime } from '../../../src/core/plugin-runtime.js'
import type { Plugin } from '../../../src/plugins/sdk.js'

describe('PluginRuntime', () => {
  function makePlugin(id: string, opts?: { globalHooks?: boolean; hooks?: Plugin['hooks'] }): Plugin {
    return {
      id,
      name: id,
      version: '1.0.0',
      register: () => [],
      globalHooks: opts?.globalHooks,
      hooks: opts?.hooks,
    } as Plugin
  }

  test('should call onBeforeToolCall on owner plugin', async () => {
    const onBeforeToolCall = jest.fn().mockResolvedValue(undefined)
    const owner = makePlugin('owner', { hooks: { onBeforeToolCall } })
    const runtime = new PluginRuntime()
    runtime.setMaps(new Map([['tool.a', 'owner']]), new Map([['owner', owner]]))

    await runtime.fireHook('before', 'tool.a', { x: 1 })
    expect(onBeforeToolCall).toHaveBeenCalledWith('tool.a', { x: 1 })
  })

  test('should call onAfterToolCall with elapsedMs', async () => {
    const onAfterToolCall = jest.fn().mockResolvedValue(undefined)
    const owner = makePlugin('owner', { hooks: { onAfterToolCall } })
    const runtime = new PluginRuntime()
    runtime.setMaps(new Map([['tool.a', 'owner']]), new Map([['owner', owner]]))

    await runtime.fireHook('after', 'tool.a', { x: 1 }, { elapsedMs: 42 })
    expect(onAfterToolCall).toHaveBeenCalledWith('tool.a', { x: 1 }, 42)
  })

  test('should call onToolError on owner plugin', async () => {
    const onToolError = jest.fn().mockResolvedValue(undefined)
    const owner = makePlugin('owner', { hooks: { onToolError } })
    const runtime = new PluginRuntime()
    runtime.setMaps(new Map([['tool.a', 'owner']]), new Map([['owner', owner]]))

    const err = new Error('boom')
    await runtime.fireHook('error', 'tool.a', { x: 1 }, { error: err })
    expect(onToolError).toHaveBeenCalledWith('tool.a', err)
  })

  test('should fire global observer hooks but skip owner twice', async () => {
    const ownerBefore = jest.fn().mockResolvedValue(undefined)
    const observerBefore = jest.fn().mockResolvedValue(undefined)
    const owner = makePlugin('owner', { hooks: { onBeforeToolCall: ownerBefore } })
    const observer = makePlugin('observer', { globalHooks: true, hooks: { onBeforeToolCall: observerBefore } })
    const runtime = new PluginRuntime()
    runtime.setMaps(new Map([['tool.a', 'owner']]), new Map([
      ['owner', owner],
      ['observer', observer],
    ]))

    await runtime.fireHook('before', 'tool.a', {})
    expect(ownerBefore).toHaveBeenCalledTimes(1)
    expect(observerBefore).toHaveBeenCalledTimes(1)
  })

  test('should swallow hook errors gracefully', async () => {
    const onBeforeToolCall = jest.fn().mockRejectedValue(new Error('hook failed'))
    const owner = makePlugin('owner', { hooks: { onBeforeToolCall } })
    const runtime = new PluginRuntime()
    runtime.setMaps(new Map([['tool.a', 'owner']]), new Map([['owner', owner]]))

    await expect(runtime.fireHook('before', 'tool.a', {})).resolves.toBeUndefined()
  })

  test('should do nothing when no matching plugin', async () => {
    const runtime = new PluginRuntime()
    runtime.setMaps(new Map(), new Map())
    await expect(runtime.fireHook('before', 'tool.a', {})).resolves.toBeUndefined()
  })
})
