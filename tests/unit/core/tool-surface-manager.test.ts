import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import { ToolSurfaceManager } from '../../../src/core/tool-surface-manager.js'
import type { Plugin } from '../../../src/plugins/sdk.js'

describe('ToolSurfaceManager', () => {
  const originalSurfaceAutoActivateTier0 = process.env.SURFACE_AUTO_ACTIVATE_TIER0

  beforeEach(() => {
    delete process.env.SURFACE_AUTO_ACTIVATE_TIER0
  })

  afterEach(() => {
    if (originalSurfaceAutoActivateTier0 === undefined) {
      delete process.env.SURFACE_AUTO_ACTIVATE_TIER0
    } else {
      process.env.SURFACE_AUTO_ACTIVATE_TIER0 = originalSurfaceAutoActivateTier0
    }
  })

  test('starts with only explicit gateway core tools visible', () => {
    const surface = new ToolSurfaceManager()

    surface.registerCoreTools([
      'artifact.read',
      'sample.ingest',
      'workflow.analyze.start',
      'workflow.search',
      'workflow.run',
    ])
    surface.registerGatewayCoreTools(['workflow.search', 'workflow.run', 'artifact.read'])

    expect([...surface.getVisibleToolNames()]).toEqual([
      'workflow.search',
      'workflow.run',
      'artifact.read',
    ])
    expect(surface.listCoreTools()).toEqual([
      { name: 'artifact.read', transportName: 'artifact_read', visible: true },
      { name: 'sample.ingest', transportName: 'sample_ingest', visible: false },
      { name: 'workflow.analyze.start', transportName: 'workflow_analyze_start', visible: false },
      { name: 'workflow.run', transportName: 'workflow_run', visible: true },
      { name: 'workflow.search', transportName: 'workflow_search', visible: true },
    ])
    expect(surface.isToolVisible('artifact.read')).toBe(true)
    expect(surface.isToolVisible('sample.ingest')).toBe(false)
    expect(surface.isToolVisible('workflow.analyze.start')).toBe(false)
    expect(surface.isToolVisible('workflow.search')).toBe(true)
    expect(surface.isToolVisible('workflow.run')).toBe(true)
  })

  test('can expose hidden core tools by canonical or transport tool name', () => {
    const surface = new ToolSurfaceManager()

    surface.registerCoreTools(['workflow.analyze.start', 'workflow.analyze.status'])
    surface.registerGatewayCoreTools(['tools.discover'])

    expect(surface.activateCoreTools(['workflow_analyze_start'])).toEqual([
      'workflow.analyze.start',
    ])
    expect(surface.activateCoreTools(['workflow.analyze.status'])).toEqual([
      'workflow.analyze.status',
    ])
    expect(surface.isToolVisible('workflow.analyze.start')).toBe(true)
    expect(surface.isToolVisible('workflow.analyze.status')).toBe(true)
  })

  test('does not expose plugin tools through core activation unless they are registered as core tools', () => {
    const surface = new ToolSurfaceManager()
    const plugin: Plugin = {
      id: 'plugin-owned-test',
      name: 'Plugin Owned Test',
      surfaceRules: { tier: 3, category: 'reverse-engineering' },
      tools: [],
    }

    surface.registerGatewayCoreTools(['tools.discover'])
    surface.registerPlugin(plugin, ['ghidra.analyze'])

    expect(surface.activateCoreTools(['ghidra.analyze'])).toEqual([])
    expect(surface.isToolVisible('ghidra.analyze')).toBe(false)
  })

  test('does not expose tier 0 plugins at startup by default', () => {
    const surface = new ToolSurfaceManager()
    const plugin: Plugin = {
      id: 'gateway-capable-test',
      name: 'Gateway Capable Test',
      surfaceRules: { tier: 0, category: 'utility' },
      tools: [],
    }

    surface.registerGatewayCoreTools(['tools.discover'])
    surface.registerPlugin(plugin, ['plugin.utility.hidden'])

    expect(surface.getVisibleToolNames()).toEqual(new Set(['tools.discover']))
    expect(surface.isToolVisible('plugin.utility.hidden')).toBe(false)
  })

  test('explicit file-type activation can include tier 2 while automatic activation stays tier 1', () => {
    const surface = new ToolSurfaceManager()
    const tier1: Plugin = {
      id: 'pe-tier1-test',
      name: 'PE Tier 1 Test',
      surfaceRules: { tier: 1, category: 'static-analysis', activateOn: { fileTypes: ['pe'] } },
      tools: [],
    }
    const tier2: Plugin = {
      id: 'pe-tier2-test',
      name: 'PE Tier 2 Test',
      surfaceRules: { tier: 2, category: 'malware-analysis', activateOn: { fileTypes: ['pe'] } },
      tools: [],
    }

    surface.registerPlugin(tier1, ['pe.inspect'])
    surface.registerPlugin(tier2, ['pe.deep.recover'])

    expect(surface.activateByFileType('PE')).toEqual(['pe-tier1-test'])
    expect(surface.isToolVisible('pe.deep.recover')).toBe(false)
    expect(surface.activateByFileType('PE', { includeTier2: true })).toEqual(['pe-tier2-test'])
    expect(surface.isToolVisible('pe.deep.recover')).toBe(true)
  })

  test('unregisterPlugin removes visibility, discovery state, activation state, and signal rules', () => {
    const surface = new ToolSurfaceManager()
    const notify = jest.fn()
    const plugin: Plugin = {
      id: 'unpack-surface-test',
      name: 'Unpack Surface Test',
      surfaceRules: {
        tier: 2,
        category: 'unpacking',
        activateOn: { findings: ['packed'] },
        signalMap: { has_packer: ['packed'] },
        extractSignals: (data: Record<string, unknown>) =>
          data.deep_packer === true ? ['packed'] : [],
      },
      tools: [],
    }

    surface.setNotifyCallback(notify)
    surface.registerPlugin(plugin, ['unpack.workflow.plan'])

    expect(surface.activateByCategory('unpacking')).toEqual(['unpack-surface-test'])
    expect(surface.isToolVisible('unpack.workflow.plan')).toBe(true)
    expect(notify).toHaveBeenCalledTimes(1)

    expect(surface.unregisterPlugin('unpack-surface-test')).toEqual(['unpack.workflow.plan'])
    expect(surface.isToolVisible('unpack.workflow.plan')).toBe(false)
    expect(surface.listCategories(new Map([[plugin.id, { name: plugin.name }]]))).toEqual([])
    expect(surface.getSurfaceStatus()).toMatchObject({
      totalPlugins: 0,
      activatedPlugins: 0,
      totalTools: 0,
      visibleTools: 0,
    })
    expect(notify).toHaveBeenCalledTimes(2)

    expect(
      surface.processToolResult('triage.inspect', {
        data: { has_packer: true, deep_packer: true },
      })
    ).toEqual([])
    expect(notify).toHaveBeenCalledTimes(2)

    surface.registerPlugin(plugin, ['unpack.workflow.plan'])
    expect(surface.isToolVisible('unpack.workflow.plan')).toBe(false)
    expect(surface.activatePlugins(['unpack-surface-test'])).toEqual(['unpack-surface-test'])
    expect(surface.isToolVisible('unpack.workflow.plan')).toBe(true)
    expect(notify).toHaveBeenCalledTimes(3)
  })

  test('unregisterPlugin is a no-op for unknown plugin ids', () => {
    const surface = new ToolSurfaceManager()
    const notify = jest.fn()

    surface.setNotifyCallback(notify)

    expect(surface.unregisterPlugin('missing-plugin')).toEqual([])
    expect(notify).not.toHaveBeenCalled()
  })
})
