import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import androidRuntimePlugin from '../../src/plugins/android-runtime/index.js'

describe('android.runtime.plan readiness', () => {
  test('maps APK static evidence to ADB/emulator/Frida plans without live device use', async () => {
    const harness = createPluginTestHarness()
    harness.registerPlugin(androidRuntimePlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'android.runtime.plan'
    )

    const result = (await tool?.handler({
      sample_id: 'sha256:apk',
      requested_backends: ['adb', 'android-emulator', 'frida'],
      static_evidence: ['android.permission.INTERNET', 'classes.dex', 'lib/arm64-v8a/libdemo.so'],
    })) as any

    expect(result.ok).toBe(true)
    expect(result.data.platform).toBe('android')
    expect(result.data.execution_semantics).toEqual(
      expect.objectContaining({ actual_mode: 'plan_only', live_execution: false })
    )
    expect(result.data.selected_backends.map((backend: any) => backend.backend)).toEqual([
      'adb',
      'android-emulator',
      'frida',
    ])
    expect(result.data.static_correlation.mapping.join(' ')).toMatch(/manifest permissions/)
    expect(result.data.recommended_next_tools).toEqual(
      expect.arrayContaining(['android.package.inventory', 'frida.script.generate', 'tool.readiness'])
    )
    expect(result.data.safety_notes.join(' ')).toMatch(/Do not start emulator/)
    expect(result.data.safety_notes.join(' ')).toMatch(/run adb install/)
    expect(result.data.safety_notes.join(' ')).toMatch(/attach Frida/)
  })

  test('declares Android opt-in dynamic policy for ADB, emulator, and Frida backends', () => {
    expect(androidRuntimePlugin.executionDomain).toBe('dynamic')
    expect(androidRuntimePlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['apk', 'aab', 'apks', 'dex'])
    )
    expect(androidRuntimePlugin.aspects?.runtimes).toEqual(
      expect.arrayContaining(['adb', 'android-emulator', 'frida', 'frida-server'])
    )
    expect(androidRuntimePlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'disabled',
      })
    )
  })
})
