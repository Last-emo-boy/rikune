import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import macosRuntimePlugin from '../../src/plugins/macos-runtime/index.js'

describe('macos.runtime.plan readiness', () => {
  test('generates macos_host_required plan-only guidance without running LLDB or DTrace', async () => {
    const harness = createPluginTestHarness()
    harness.registerPlugin(macosRuntimePlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'macos.runtime.plan'
    )

    const result = (await tool?.handler({
      sample_id: 'sha256:macho',
      requested_backends: ['lldb', 'dtrace'],
      static_evidence: ['LC_LOAD_DYLIB', 'entitlements', 'Info.plist'],
    })) as any

    expect(result.ok).toBe(true)
    expect(result.data.platform).toBe('macos')
    expect(result.data.execution_semantics).toEqual(
      expect.objectContaining({ actual_mode: 'plan_only', live_execution: false })
    )
    expect(result.data.readiness).toEqual(
      expect.objectContaining({
        status: 'plan_only',
        opt_in_required: true,
        requires_isolation: true,
        policy_denied: true,
      })
    )
    expect(result.data.selected_backends.map((backend: any) => backend.backend)).toEqual([
      'lldb',
      'dtrace',
    ])
    expect(result.data.safety_notes.join(' ')).toMatch(/Do not run LLDB, DTrace/)
    expect(result.data.safety_notes.join(' ')).toMatch(/No sample was installed/)
  })

  test('declares macOS dynamic aspects and opt-in runtime policy', () => {
    expect(macosRuntimePlugin.executionDomain).toBe('dynamic')
    expect(macosRuntimePlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['macho', 'dmg', 'pkg'])
    )
    expect(macosRuntimePlugin.aspects?.runtimes).toEqual(
      expect.arrayContaining(['lldb', 'dtrace', 'fs-usage', 'sandbox-exec'])
    )
    expect(macosRuntimePlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'disabled',
      })
    )
  })
})
