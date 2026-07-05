import { describe, expect, test } from '@jest/globals'
import { detectFileType } from '../../src/sample/sample-finalization.js'
import { buildContainerStructureFromBuffer } from '../../src/plugins/container-analysis/tools/container-structure-analyze.js'
import firmwarePlugin from '../../src/plugins/firmware/index.js'
import { firmwareScanToolDefinition } from '../../src/plugins/firmware/tools/firmware-scan.js'
import { firmwareExtractToolDefinition } from '../../src/plugins/firmware/tools/firmware-extract.js'
import { firmwareEntropyToolDefinition } from '../../src/plugins/firmware/tools/firmware-entropy.js'

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

describe('firmware.scan static contract', () => {
  test('declares embedded/static aspects, output schema, artifacts, and evidence', () => {
    expect(firmwareScanToolDefinition.name).toBe('firmware.scan')
    expect(firmwareScanToolDefinition.outputSchema).toBeDefined()
    expect(firmwareScanToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['firmware', 'uimage', 'dtb', 'squashfs', 'jffs2']),
        platforms: expect.arrayContaining(['embedded', 'linux']),
        execution: expect.arrayContaining(['static', 'triage']),
        safety: expect.arrayContaining(['passive', 'no_installer_execution']),
      })
    )
    expect(firmwareScanToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
      'firmware_scan'
    )
    expect(firmwareScanToolDefinition.evidence?.map((entry) => entry.category)).toContain(
      'signatures'
    )
  })

  test('keeps firmware extract and entropy as passive no-execute metadata surfaces', () => {
    expect(firmwareExtractToolDefinition.outputSchema).toBeDefined()
    expect(firmwareExtractToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_installer_execution'])
    )
    expect(firmwareExtractToolDefinition.aspects?.capabilities).toContain('extraction-plan')
    expect(firmwareExtractToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining(['filesystem', 'nested-binaries'])
    )
    expect(firmwareEntropyToolDefinition.outputSchema).toBeDefined()
    expect(firmwareEntropyToolDefinition.aspects?.safety).toContain('passive')
  })

  test('extracts firmware activation signal from firmware.scan signatures output', () => {
    expect(
      firmwarePlugin.surfaceRules?.extractSignals?.({
        signature_count: 1,
        signatures: [{ offset: '0x0', description: 'Squashfs filesystem' }],
      })
    ).toEqual(['firmware'])

    expect(
      firmwarePlugin.surfaceRules?.extractSignals?.({
        signature_count: 0,
        signatures: [],
      })
    ).toEqual([])
  })

  test('detects firmware, boot image, and embedded filesystem families', () => {
    const uimage = Buffer.alloc(16)
    uimage.writeUInt32BE(0x27051956, 0)
    const dtb = Buffer.alloc(16)
    dtb.writeUInt32BE(0xd00dfeed, 0)
    const cramfs = Buffer.alloc(16)
    cramfs.writeUInt32LE(0x28cd3d45, 0)
    const ubifs = Buffer.alloc(16)
    ubifs.writeUInt32LE(0x06101831, 0)

    expect(detectFileType(uimage, 'firmware.uImage')).toBe('U-Boot-uImage')
    expect(detectFileType(dtb, 'board.dtb')).toBe('DTB')
    expect(detectFileType(dtb, 'kernel.itb')).toBe('FIT-Image')
    expect(detectFileType(Buffer.from('070701demo'), 'initramfs.cpio')).toBe('CPIO')
    expect(detectFileType(Buffer.from('hsqs'), 'rootfs.squashfs')).toBe('SquashFS')
    expect(detectFileType(cramfs, 'rootfs.cramfs')).toBe('CramFS')
    expect(detectFileType(Buffer.from([0x85, 0x19]), 'rootfs.jffs2')).toBe('JFFS2')
    expect(detectFileType(Buffer.from('UBI#'), 'rootfs.ubi')).toBe('UBI')
    expect(detectFileType(ubifs, 'rootfs.ubifs')).toBe('UBIFS')
    expect(detectFileType(Buffer.from('-rom1fs-'), 'rootfs.romfs')).toBe('ROMFS')
  })

  test('routes nested firmware and ELF candidates without executing extracted files', () => {
    const inventory = buildContainerStructureFromBuffer(
      localZip(['boot/uImage', 'rootfs.squashfs', 'lib/modules/demo.ko', 'usr/bin/tool.elf']),
      { filename: 'firmware-bundle.zip' }
    )

    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_extract_to_execution_path: true,
        no_install: true,
        no_mount: true,
        no_entrypoint_run: true,
      })
    )
    expect(inventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'boot/uImage',
          recommended_tools: expect.arrayContaining(['firmware.scan']),
        }),
        expect.objectContaining({
          path: 'rootfs.squashfs',
          recommended_tools: expect.arrayContaining(['firmware.entropy']),
        }),
        expect.objectContaining({
          path: 'lib/modules/demo.ko',
          recommended_tools: expect.arrayContaining(['linux.binary.inventory']),
        }),
        expect.objectContaining({
          path: 'usr/bin/tool.elf',
          recommended_tools: expect.arrayContaining(['elf.structure.analyze']),
        }),
      ])
    )
  })
})
