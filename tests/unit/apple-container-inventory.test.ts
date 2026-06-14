import { describe, expect, test } from '@jest/globals'
import {
  appleContainerInventoryToolDefinition,
  buildAppleContainerInventoryFromBuffer,
} from '../../src/plugins/apple-container/tools/apple-container-inventory.js'

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

describe('apple.container.inventory', () => {
  test('declares static inventory workflow metadata and passive safety boundaries', () => {
    expect(appleContainerInventoryToolDefinition.workflowRecipes?.[0]).toEqual({
      id: 'apple.container.static-inventory',
      title: 'Apple static container inventory',
      startsWith: ['apple.container.inventory'],
      nextTools: [
        'apple.signing.inspect',
        'macho.structure.analyze',
        'apple.security.profile',
        'macos.runtime.plan',
        'ios.runtime.plan',
      ],
      producesArtifacts: ['apple_container_inventory'],
      evidence: ['manifest', 'package-metadata', 'nested-binaries', 'provenance'],
      safety: ['passive', 'no_auto_mount', 'no_installer_execution', 'no_live_sample_by_default'],
    })

    expect(appleContainerInventoryToolDefinition.aspects?.evidence).toEqual([
      'manifest',
      'package-metadata',
      'nested-binaries',
      'provenance',
    ])
    expect(appleContainerInventoryToolDefinition.aspects?.evidence).not.toContain('certificates')
    expect(appleContainerInventoryToolDefinition.evidence).toEqual([
      { category: 'manifest', artifactTypes: ['apple_container_inventory'] },
      { category: 'package-metadata', artifactTypes: ['apple_container_inventory'] },
      { category: 'nested-binaries', artifactTypes: ['apple_container_inventory'] },
      { category: 'provenance', artifactTypes: ['apple_container_inventory'] },
    ])
    expect(appleContainerInventoryToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_auto_mount',
        'no_installer_execution',
        'no_live_sample_by_default',
      ])
    )
  })

  test('inventories IPA app bundles without mounting, installing, launching, or device access', () => {
    const inventory = buildAppleContainerInventoryFromBuffer(
      localZip([
        'Payload/Demo.app/Info.plist',
        'Payload/Demo.app/embedded.mobileprovision',
        'Payload/Demo.app/Frameworks/libDemo.dylib',
      ]),
      { filename: 'Demo.ipa' }
    )

    expect(inventory.container_format).toBe('ipa')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_install: true,
        no_mount: true,
        no_device_connection: true,
      })
    )
    expect(inventory.plist_candidates).toContain('Payload/Demo.app/Info.plist')
    expect(inventory.provisioning_candidates).toContain('Payload/Demo.app/embedded.mobileprovision')
    expect(inventory.nested_macho_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'Payload/Demo.app/Frameworks/libDemo.dylib',
          routed_formats: expect.arrayContaining(['macho']),
          recommended_tools: expect.arrayContaining(['macho.structure.analyze']),
        }),
      ])
    )
  })

  test('represents DMG and PKG as passive no-mount/no-install inventories', () => {
    const dmg = buildAppleContainerInventoryFromBuffer(
      Buffer.concat([Buffer.alloc(512), Buffer.from('koly')]),
      { filename: 'Demo.dmg' }
    )
    const pkg = buildAppleContainerInventoryFromBuffer(Buffer.from('xar!0000'), {
      filename: 'Demo.pkg',
    })

    expect(dmg.container_format).toBe('dmg')
    expect(dmg.unsupported_detail).toMatch(/does neither by default/i)
    expect(pkg.container_format).toBe('pkg')
    expect(pkg.unsupported_detail).toMatch(/installer scripts are not executed/i)
    expect([dmg, pkg].every((item) => item.policy.no_mount && item.policy.no_install)).toBe(true)
  })
})
