import { describe, expect, test } from '@jest/globals'
import linuxPackagePlugin from '../../src/plugins/linux-package/index.js'
import {
  buildLinuxPackageInventoryFromBuffer,
  linuxPackageInventoryToolDefinition,
} from '../../src/plugins/linux-package/tools/linux-package-inventory.js'

function arMember(name: string, body: Buffer = Buffer.alloc(0)): Buffer {
  const header = Buffer.alloc(60, ' ')
  header.write(`${name}/`.slice(0, 16), 0, 'ascii')
  header.write(String(body.length).padEnd(10, ' '), 48, 'ascii')
  header.write('`\n', 58, 'ascii')
  return Buffer.concat([header, body, body.length % 2 ? Buffer.from('\n') : Buffer.alloc(0)])
}

describe('linux.package.inventory', () => {
  test('declares passive package, supply-chain, and firmware handoff metadata', () => {
    const recipe = linuxPackageInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'linux-package.passive-inventory-handoff'
    )

    expect(linuxPackagePlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'workflow-plan',
        'metadata-only-handoff',
        'supply-chain-handoff',
        'firmware-handoff',
      ])
    )
    expect(linuxPackagePlugin.aspects?.evidence).toEqual(
      expect.arrayContaining(['workflow', 'provenance', 'package-metadata', 'nested-binaries'])
    )
    expect(linuxPackageInventoryToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_install',
        'no_script_execution',
        'no_live_sample_by_default',
      ])
    )
    expect(linuxPackageInventoryToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'linux_package_inventory' }),
      ])
    )
    expect(linuxPackageInventoryToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'workflow',
          artifactTypes: expect.arrayContaining(['linux_package_inventory']),
        }),
        expect.objectContaining({
          category: 'provenance',
          artifactTypes: expect.arrayContaining(['linux_package_inventory']),
        }),
        expect.objectContaining({
          category: 'package-metadata',
          artifactTypes: expect.arrayContaining(['linux_package_inventory']),
        }),
        expect.objectContaining({
          category: 'nested-binaries',
          artifactTypes: expect.arrayContaining(['linux_package_inventory']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['linux.package.inventory'],
        nextTools: expect.arrayContaining([
          'sbom.provenance.graph',
          'linux.binary.inventory',
          'firmware.workflow.plan',
          'container.structure.analyze',
          'analysis.evidence.graph',
          'report.generate',
        ]),
        producesArtifacts: expect.arrayContaining(['linux_package_inventory']),
        evidence: expect.arrayContaining([
          'workflow',
          'provenance',
          'package-metadata',
          'nested-binaries',
        ]),
        safety: expect.arrayContaining([
          'passive',
          'no_install',
          'no_script_execution',
          'no_live_sample_by_default',
        ]),
      })
    )
  })

  test('inventories deb packages without installing or executing maintainer scripts', () => {
    const inventory = buildLinuxPackageInventoryFromBuffer(
      Buffer.concat([
        Buffer.from('!<arch>\n'),
        arMember('debian-binary', Buffer.from('2.0\n')),
        arMember('control.tar', Buffer.from('postinst\npreinst\nusr/lib/libdemo.so\nclasses.dex\n')),
      ]),
      { filename: 'demo.deb' }
    )

    expect(inventory.package_format).toBe('deb')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_install: true,
        no_mount: true,
      })
    )
    expect(inventory.archive_members).toEqual(expect.arrayContaining(['debian-binary', 'control.tar']))
    expect(inventory.maintainer_script_candidates).toEqual(
      expect.arrayContaining(['postinst', 'preinst'])
    )
    expect(inventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: expect.stringContaining('libdemo.so'),
          routed_formats: expect.arrayContaining(['elf']),
          recommended_tools: expect.arrayContaining(['elf.structure.analyze']),
        }),
        expect.objectContaining({
          path: expect.stringContaining('classes.dex'),
          recommended_tools: expect.arrayContaining(['dex.classes.list']),
        }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'sbom.provenance.graph',
        'linux.binary.inventory',
        'firmware.workflow.plan',
        'container.structure.analyze',
        'analysis.evidence.graph',
        'report.generate',
        'elf.structure.analyze',
      ])
    )
  })

  test('covers rpm, Alpine apk, snap, flatpak, and AppImage as no-execute inventory families', () => {
    const rpm = buildLinuxPackageInventoryFromBuffer(Buffer.from([0xed, 0xab, 0xee, 0xdb]), {
      filename: 'demo.rpm',
    })
    const alpine = buildLinuxPackageInventoryFromBuffer(Buffer.from([0x1f, 0x8b, 0x08, 0x00]), {
      filename: 'demo.apk',
    })
    const appImageData = Buffer.alloc(16)
    appImageData[0] = 0x7f
    appImageData[1] = 0x45
    appImageData[2] = 0x4c
    appImageData[3] = 0x46
    appImageData.write('AI', 8, 'ascii')
    const appImage = buildLinuxPackageInventoryFromBuffer(appImageData, {
      filename: 'demo.AppImage',
    })
    const snap = buildLinuxPackageInventoryFromBuffer(Buffer.alloc(16), { filename: 'demo.snap' })
    const flatpak = buildLinuxPackageInventoryFromBuffer(Buffer.alloc(16), {
      filename: 'demo.flatpak',
    })

    expect([rpm.package_format, alpine.package_format, appImage.package_format, snap.package_format, flatpak.package_format]).toEqual([
      'rpm',
      'apk-alpine',
      'appimage',
      'snap',
      'flatpak',
    ])
    expect([rpm, alpine, appImage, snap, flatpak].every((item) => item.policy.no_execute)).toBe(true)
    expect(rpm.unsupported_detail).toMatch(/does not install or execute/i)
  })
})
