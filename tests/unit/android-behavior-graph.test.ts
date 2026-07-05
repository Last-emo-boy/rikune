import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import androidPlugin from '../../src/plugins/android/index.js'
import { buildAndroidBehaviorGraph } from '../../src/plugins/android/tools/android-behavior-graph.js'

describe('android.behavior.graph', () => {
  test('correlates manifest, DEX, smali, and native library hints without runtime use', () => {
    const graph = buildAndroidBehaviorGraph({
      sample_id: 'sha256:apk',
      manifest: {
        permissions: ['android.permission.INTERNET', 'android.permission.READ_EXTERNAL_STORAGE'],
        intents: ['android.intent.action.BOOT_COMPLETED'],
      },
      package_inventory: {
        native_library_candidates: [{ path: 'lib/arm64-v8a/libdemo.so' }],
      },
      dex_classes: ['com.demo.CryptoClient', 'dalvik.system.DexClassLoader'],
      smali_snippets: [
        'invoke-static {}, Ljavax/crypto/Cipher;->getInstance',
        'const-string v0, "https://example.test/c2"',
      ],
    })

    expect(graph.result_mode).toBe('android_behavior_graph')
    expect(graph.indicators.permissions).toEqual(
      expect.arrayContaining(['android.permission.INTERNET'])
    )
    expect(graph.indicators.urls).toEqual(expect.arrayContaining(['https://example.test/c2']))
    expect(graph.runtime_hook_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'network' }),
        expect.objectContaining({ category: 'crypto' }),
        expect.objectContaining({ category: 'classloader-reflection' }),
      ])
    )
    expect(graph.native_library_handoff).toEqual([
      expect.objectContaining({
        path: 'lib/arm64-v8a/libdemo.so',
        recommended_tools: expect.arrayContaining(['linux.binary.inventory']),
      }),
    ])
    expect(graph.recommended_next_tools).toEqual(
      expect.arrayContaining(['android.runtime.plan', 'frida.script.generate'])
    )
    expect(graph.safety_notes.join(' ')).toMatch(/no emulator/i)
  })

  test('registers Android static behavior workflow metadata', () => {
    const harness = createPluginTestHarness({
      deps: {
        config: { workers: { static: { pythonPath: 'python3' } } },
        resolvePackagePath: (...parts: string[]) => parts.join('/'),
      } as any,
    })
    const names = harness.registerPlugin(androidPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'android.behavior.graph'
    )

    expect(names).toContain('android.behavior.graph')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'android.static.behavior-graph',
        nextTools: expect.arrayContaining(['android.runtime.plan']),
      })
    )
  })
})
