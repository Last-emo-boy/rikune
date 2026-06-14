import fs from 'fs'
import os from 'os'
import path from 'path'
import { describe, expect, test, afterEach } from '@jest/globals'
import apkSmaliPlugin from '../../src/plugins/apk-smali/index.js'
import {
  apkDisassembleToolDefinition,
  collectApktoolSmaliFiles,
} from '../../src/plugins/apk-smali/tools/apk-disassemble.js'
import { apkManifestParseToolDefinition } from '../../src/plugins/apk-smali/tools/apk-manifest-parse.js'
import { apkResourcesDecodeToolDefinition } from '../../src/plugins/apk-smali/tools/apk-resources-decode.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'

let tempRoot: string | null = null

function resetSurfaceForSearchTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function createPluginManager(plugins: any[]) {
  return {
    getStatuses: () =>
      plugins.map((plugin) => ({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        status: 'loaded',
        tools: plugin.tools.map((tool: any) => tool.definition.name),
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any
}

afterEach(() => {
  if (tempRoot) {
    fs.rmSync(tempRoot, { recursive: true, force: true })
    tempRoot = null
  }
  resetSurfaceForSearchTest()
})

describe('apk-smali metadata and routing', () => {
  test('declares passive Android Smali, manifest, and resources workflow metadata', () => {
    expect(apkSmaliPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'smali',
        'multi-dex',
        'manifest',
        'permissions',
        'resources',
        'workflow-handoff',
      ])
    )
    expect(apkSmaliPlugin.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_network_by_default', 'no_live_execution'])
    )
    expect(apkSmaliPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )

    expect(apkDisassembleToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'apk-smali.multi-dex-static-disassembly',
          nextTools: expect.arrayContaining([
            'apk.manifest.parse',
            'apk.resources.decode',
            'dex.classes.list',
            'analysis.evidence.graph',
          ]),
          producesArtifacts: ['backend_apk_smali-listing'],
          evidence: expect.arrayContaining(['multi-dex', 'workflow', 'provenance']),
        }),
      ])
    )
    expect(apkDisassembleToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({ noNetwork: true, noMutation: true, noLiveExecution: true })
    )

    expect(apkManifestParseToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'apk-smali.manifest-component-profile',
        nextTools: expect.arrayContaining(['apk.disassemble', 'android.behavior.graph']),
        producesArtifacts: ['backend_apk_manifest'],
      })
    )
    expect(apkManifestParseToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'permissions' }),
        expect.objectContaining({ category: 'android-components' }),
      ])
    )

    expect(apkResourcesDecodeToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'apk-smali.resource-string-profile',
        nextTools: expect.arrayContaining(['strings.extract', 'artifact.read']),
        producesArtifacts: ['backend_apk_resources-listing'],
      })
    )
  })

  test('collects smali and smali_classes multi-dex roots from apktool output', () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-apk-smali-'))
    const smaliOne = path.join(tempRoot, 'smali', 'com', 'example')
    const smaliTwo = path.join(tempRoot, 'smali_classes2', 'com', 'example')
    const ignored = path.join(tempRoot, 'smali_assets', 'com', 'example')
    fs.mkdirSync(smaliOne, { recursive: true })
    fs.mkdirSync(smaliTwo, { recursive: true })
    fs.mkdirSync(ignored, { recursive: true })
    fs.writeFileSync(path.join(smaliOne, 'MainActivity.smali'), '.class public LMainActivity;')
    fs.writeFileSync(path.join(smaliTwo, 'Secondary.smali'), '.class public LSecondary;')
    fs.writeFileSync(path.join(ignored, 'Ignored.smali'), '.class public LIgnored;')

    const result = collectApktoolSmaliFiles(tempRoot)

    expect(result.roots).toEqual([
      { root: 'smali', class_count: 1 },
      { root: 'smali_classes2', class_count: 1 },
    ])
    expect(result.files.map((file) => file.rel.replace(/\\/g, '/'))).toEqual(
      expect.arrayContaining([
        'smali/com/example/MainActivity.smali',
        'smali_classes2/com/example/Secondary.smali',
      ])
    )
    expect(result.files.some((file) => file.rel.includes('Ignored'))).toBe(false)
  })

  test('workflow.search can match APK Smali multi-dex and manifest terms', async () => {
    resetSurfaceForSearchTest()
    const pluginForSearch = {
      ...apkSmaliPlugin,
      tools: [
        { definition: apkDisassembleToolDefinition, handler: async () => ({ ok: true }) },
        { definition: apkManifestParseToolDefinition, handler: async () => ({ ok: true }) },
        { definition: apkResourcesDecodeToolDefinition, handler: async () => ({ ok: true }) },
      ],
    }
    getToolSurfaceManager().registerPlugin(pluginForSearch as any, [
      'apk.disassemble',
      'apk.manifest.parse',
      'apk.resources.decode',
    ])

    const handler = createWorkflowSearchHandler(createPluginManager([pluginForSearch]))
    const result = await handler({
      file_type: '.apk',
      query: 'smali multi-dex AndroidManifest permissions resources',
      goal: 'static',
      top_k: 5,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const apkResult = data.results.find((item: any) => item.plugin_id === 'apk-smali')

    expect(apkResult).toEqual(
      expect.objectContaining({
        plugin_id: 'apk-smali',
        recommended_tools: expect.arrayContaining(['apk.disassemble']),
      })
    )
    expect(apkResult.score_breakdown.profile_score).toBeGreaterThan(0)
    expect(apkResult.score_breakdown.query_score).toBeGreaterThan(0)
  })
})
