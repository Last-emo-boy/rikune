import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness, type Plugin } from '../../src/plugins/sdk.js'
import androidRuntimePlugin from '../../src/plugins/android-runtime/index.js'
import iosRuntimePlugin from '../../src/plugins/ios-runtime/index.js'
import linuxRuntimePlugin from '../../src/plugins/linux-runtime/index.js'
import macosRuntimePlugin from '../../src/plugins/macos-runtime/index.js'
import wasmRuntimePlugin from '../../src/plugins/wasm-runtime/index.js'
import windowsRuntimePlugin from '../../src/plugins/windows-runtime/index.js'

const runtimePlugins: Array<{
  plugin: Plugin
  toolName: string
  platform: string
  backend: string
  sampleId: string
}> = [
  {
    plugin: windowsRuntimePlugin,
    toolName: 'windows.runtime.plan',
    platform: 'windows',
    backend: 'windows-sandbox',
    sampleId: 'sha256:pe',
  },
  {
    plugin: linuxRuntimePlugin,
    toolName: 'linux.runtime.plan',
    platform: 'linux',
    backend: 'qiling',
    sampleId: 'sha256:elf',
  },
  {
    plugin: macosRuntimePlugin,
    toolName: 'macos.runtime.plan',
    platform: 'macos',
    backend: 'lldb',
    sampleId: 'sha256:macho',
  },
  {
    plugin: iosRuntimePlugin,
    toolName: 'ios.runtime.plan',
    platform: 'ios',
    backend: 'frida',
    sampleId: 'sha256:ipa',
  },
  {
    plugin: androidRuntimePlugin,
    toolName: 'android.runtime.plan',
    platform: 'android',
    backend: 'adb',
    sampleId: 'sha256:apk',
  },
  {
    plugin: wasmRuntimePlugin,
    toolName: 'wasm.runtime.plan',
    platform: 'wasm',
    backend: 'wasmtime',
    sampleId: 'sha256:wasm',
  },
]

describe('runtime opt-in session templates', () => {
  test.each(runtimePlugins)(
    '$toolName emits a passive opt-in session template with workflow metadata',
    async ({ plugin, toolName, platform, backend, sampleId }) => {
      const harness = createPluginTestHarness()
      harness.registerPlugin(plugin)
      const tool = harness.registeredTools.find(
        (candidate) => candidate.definition.name === toolName
      )

      expect(tool?.definition.workflowRecipes?.[0]).toEqual(
        expect.objectContaining({
          id: `${platform}.runtime.opt-in`,
          startsWith: expect.arrayContaining([toolName, 'tool.readiness']),
          runtimeBackends: expect.arrayContaining([backend]),
          safety: expect.arrayContaining([
            'passive',
            'opt_in_dynamic',
            'requires_isolation',
            'no_live_sample_by_default',
            'no_network_by_default',
          ]),
        })
      )

      const result = (await tool?.handler({
        sample_id: sampleId,
        requested_backends: [backend],
        static_evidence: ['fixture-static-evidence'],
      })) as any
      const template = result.data.session_templates[0]

      expect(result.ok).toBe(true)
      expect(result.data.platform).toBe(platform)
      expect(result.data.command_templates).toHaveLength(1)
      expect(template).toEqual(
        expect.objectContaining({
          id: `${platform}.${backend}.opt-in-session`,
          backend,
          template_only: true,
          explicit_opt_in_required: true,
          live_execution: false,
          readiness_checks: expect.any(Array),
          setup_tools: expect.any(Array),
          execution_tools: expect.any(Array),
          teardown: expect.arrayContaining([
            expect.stringContaining('Restore snapshot or discard ephemeral runtime workspace'),
          ]),
        })
      )
      expect(template.isolation).toEqual(
        expect.objectContaining({ required: true, profile: `${platform}-${backend}-isolated` })
      )
      expect(template.network).toEqual(
        expect.objectContaining({
          default_policy: 'disabled',
          allowed_after_opt_in: expect.arrayContaining(['disabled', 'record_only', 'simulated']),
        })
      )
      expect(template.mounts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: 'sample',
            mode: 'ro',
            path_template: `workspace://samples/${sampleId}`,
          }),
          expect.objectContaining({ name: 'artifacts', mode: 'rw' }),
        ])
      )
      expect(template.artifacts[0]).toEqual(
        expect.objectContaining({
          type: `${platform}_${backend.replace(/-/g, '_')}_runtime_session`,
          required: true,
        })
      )
    }
  )

  test('can suppress non-executed command and session templates for compact output', async () => {
    const harness = createPluginTestHarness()
    harness.registerPlugin(androidRuntimePlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'android.runtime.plan'
    )

    const result = (await tool?.handler({
      requested_backends: ['adb'],
      include_command_templates: false,
    })) as any

    expect(result.ok).toBe(true)
    expect(result.data.command_templates).toEqual([])
    expect(result.data.session_templates).toEqual([])
    expect(result.data.readiness.live_execution).toBe(false)
  })
})
