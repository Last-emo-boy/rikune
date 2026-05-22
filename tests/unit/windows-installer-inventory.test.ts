import { describe, expect, test } from '@jest/globals'
import { buildWindowsInstallerInventoryFromBuffer } from '../../src/plugins/windows-installer/tools/windows-installer-inventory.js'

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

function cabFixture(): Buffer {
  const data = Buffer.alloc(36)
  data.write('MSCF', 0, 'ascii')
  data.writeUInt32LE(data.length, 8)
  data.writeUInt32LE(36, 16)
  data[24] = 3
  data[25] = 1
  data.writeUInt16LE(1, 26)
  data.writeUInt16LE(2, 28)
  return data
}

describe('installer.inventory', () => {
  test('inventories MSIX payloads without install, custom-action execution, or payload launch', () => {
    const inventory = buildWindowsInstallerInventoryFromBuffer(
      Buffer.concat([
        localZip(['AppxManifest.xml', 'VFS/Demo.exe', 'scripts/install.ps1']),
        Buffer.from('CustomAction Binary.Demo VFS/Demo.dll install.ps1'),
      ]),
      { filename: 'demo.msix' }
    )

    expect(inventory.installer_format).toBe('msix')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_install: true,
        no_payload_launch: true,
      })
    )
    expect(inventory.script_candidates).toContain('scripts/install.ps1')
    expect(inventory.custom_action_candidates.length).toBeGreaterThan(0)
    expect(inventory.nested_payload_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: expect.stringContaining('Demo.exe'),
          routed_formats: expect.arrayContaining(['pe']),
          recommended_tools: expect.arrayContaining(['pe.structure.analyze']),
        }),
      ])
    )
  })

  test('recognizes CAB, NSIS, and Inno formats as passive inventory only', () => {
    const cab = buildWindowsInstallerInventoryFromBuffer(cabFixture(), { filename: 'payload.cab' })
    const nsis = buildWindowsInstallerInventoryFromBuffer(
      Buffer.concat([Buffer.from('MZ'), Buffer.from('NullsoftInst setup.exe')]),
      { filename: 'setup.exe' }
    )
    const inno = buildWindowsInstallerInventoryFromBuffer(
      Buffer.concat([Buffer.from('MZ'), Buffer.from('Inno Setup setup.exe')]),
      { filename: 'setup.exe' }
    )

    expect(cab.installer_format).toBe('cab')
    expect(cab.cab_summary?.file_count).toBe(2)
    expect(nsis.installer_format).toBe('nsis')
    expect(nsis.unsupported_detail).toMatch(/does not execute/i)
    expect(inno.installer_format).toBe('inno')
    expect([cab, nsis, inno].every((item) => item.policy.no_install && item.policy.no_execute)).toBe(
      true
    )
  })
})
