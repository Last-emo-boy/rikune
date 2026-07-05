import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import iosRuntimePlugin from '../../src/plugins/ios-runtime/index.js'

describe('ios.runtime.plan readiness', () => {
  test('generates device/provisioning-gated plan without installing or attaching', async () => {
    const harness = createPluginTestHarness()
    harness.registerPlugin(iosRuntimePlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'ios.runtime.plan'
    )

    const result = (await tool?.handler({
      sample_id: 'sha256:ipa',
      requested_backends: ['frida', 'idevice-tools'],
      static_evidence: ['mobileprovision', 'entitlements', 'Info.plist'],
    })) as any

    expect(result.ok).toBe(true)
    expect(result.data.platform).toBe('ios')
    expect(result.data.execution_semantics.live_execution).toBe(false)
    expect(result.data.selected_backends.map((backend: any) => backend.backend)).toEqual([
      'frida',
      'idevice-tools',
    ])
    expect(result.data.static_correlation.mapping.join(' ')).toMatch(/provisioning profile/)
    expect(result.data.safety_notes.join(' ')).toMatch(/Do not install IPA files/)
    expect(result.data.safety_notes.join(' ')).toMatch(/connect to a device/)
  })

  test('distinguishes iOS device gating from macOS host runtime gating', () => {
    expect(iosRuntimePlugin.aspects?.platforms).toEqual(['ios'])
    expect(iosRuntimePlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['ipa', 'mobileprovision', 'entitlements'])
    )
    expect(iosRuntimePlugin.aspects?.runtimes).toEqual(
      expect.arrayContaining(['frida', 'idevice-tools', 'lldb'])
    )
    expect(iosRuntimePlugin.runtimePolicy?.requiresUserOptIn).toBe(true)
  })
})
