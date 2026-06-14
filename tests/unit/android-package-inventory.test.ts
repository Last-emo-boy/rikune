import { describe, expect, test } from '@jest/globals'
import {
  androidPackageInventoryToolDefinition,
  buildAndroidPackageInventoryFromBuffer,
} from '../../src/plugins/android-package/tools/android-package-inventory.js'
import androidPackagePlugin from '../../src/plugins/android-package/index.js'

function localZip(entries: string[]): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry)
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name)
  }
  return Buffer.concat(chunks)
}

describe('android.package.inventory', () => {
  test('declares static inventory workflow metadata and builtin safety policy', () => {
    const recipe = androidPackageInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'android-package.static-inventory-handoff'
    )

    expect(androidPackagePlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['android-package', 'android-bytecode', 'apk', 'dex'])
    )
    expect(androidPackagePlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining(['workflow-plan', 'metadata-only-handoff'])
    )
    expect(androidPackageInventoryToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['android-package', 'android-bytecode', 'apk', 'dex', 'vdex'])
    )
    expect(androidPackageInventoryToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['workflow-plan', 'metadata-only-handoff'])
    )
    expect(androidPackageInventoryToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'manifest',
          artifactTypes: expect.arrayContaining(['android_package_inventory']),
        }),
        expect.objectContaining({
          category: 'package-metadata',
          artifactTypes: expect.arrayContaining(['android_package_inventory']),
        }),
        expect.objectContaining({
          category: 'provenance',
          artifactTypes: expect.arrayContaining(['android_package_inventory']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['android.package.inventory'],
        nextTools: expect.arrayContaining([
          'apk.manifest.parse',
          'dex.classes.list',
          'analysis.evidence.graph',
          'workflow.plan',
        ]),
        producesArtifacts: expect.arrayContaining(['android_package_inventory']),
        evidence: expect.arrayContaining([
          'manifest',
          'signatures',
          'nested-binaries',
          'package-metadata',
          'provenance',
        ]),
        safety: expect.arrayContaining([
          'passive',
          'no_install',
          'no_device_connection',
          'no_decompiler_launch',
        ]),
      })
    )
    expect(androidPackageInventoryToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendKind: 'builtin',
        availability: 'builtin',
        supportedModes: ['builtin'],
        defaultMode: 'builtin',
        policy: expect.objectContaining({
          passiveByDefault: true,
          noNetwork: true,
          noMutation: true,
          noLiveExecution: true,
        }),
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
        }),
      })
    )
  })

  test('returns profile-friendly handoff metadata without install, device, or decompiler behavior', () => {
    const inventory = buildAndroidPackageInventoryFromBuffer(
      localZip([
        'AndroidManifest.xml',
        'classes.dex',
        'lib/arm64-v8a/libdemo.so',
        'META-INF/CERT.RSA',
        'splits/base.apk',
        'base/dex/classes2.vdex',
      ]),
      { filename: 'Demo.apk', sampleId: 'sha256:demo' }
    )

    expect(inventory.package_format).toBe('apk')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_install: true,
        no_runtime_start: true,
        no_decompiler_launch: true,
        no_device_connection: true,
      })
    )
    expect(inventory.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'android-package.static-inventory-handoff' }),
      ])
    )
    expect(inventory.formats).toEqual(
      expect.arrayContaining(['android-package', 'android-bytecode', 'apk', 'dex'])
    )
    expect(inventory.platforms).toEqual(expect.arrayContaining(['android', 'jvm', 'linux']))
    expect(inventory.evidence).toEqual(
      expect.arrayContaining(['manifest', 'signatures', 'nested-binaries', 'provenance'])
    )
    expect(inventory.native_library_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'lib/arm64-v8a/libdemo.so',
          format: 'elf',
          architecture: 'arm64',
          routed_formats: expect.arrayContaining(['elf', 'so', 'native-lib']),
          recommended_tools: expect.arrayContaining(['elf.structure.analyze']),
        }),
      ])
    )
    expect(inventory.nested_package_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'splits/base.apk',
          format: 'apk',
          routed_formats: expect.arrayContaining(['apk', 'android-package']),
        }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['apk.manifest.parse', 'dex.classes.list', 'strings.extract'])
    )
  })
})
