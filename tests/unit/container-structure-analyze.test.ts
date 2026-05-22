import { describe, expect, test } from '@jest/globals'
import { buildContainerStructureFromBuffer } from '../../src/plugins/container-analysis/tools/container-structure-analyze.js'

function localZip(entries: Array<{ name: string; compressedSize?: number; uncompressedSize?: number }>): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry.name)
    const compressedSize = entry.compressedSize ?? 0
    const uncompressedSize = entry.uncompressedSize ?? compressedSize
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt32LE(compressedSize, 18)
    header.writeUInt32LE(uncompressedSize, 22)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name, Buffer.alloc(compressedSize))
  }
  return Buffer.concat(chunks)
}

function tarFixture(entries: string[]): Buffer {
  const blocks: Buffer[] = []
  for (const entry of entries) {
    const header = Buffer.alloc(512)
    header.write(entry, 0, Math.min(Buffer.byteLength(entry), 100), 'utf8')
    header.write('0000644\0', 100, 'ascii')
    header.write('0000000\0', 108, 'ascii')
    header.write('0000000\0', 116, 'ascii')
    header.write('00000000000\0', 124, 'ascii')
    header.write('00000000000\0', 136, 'ascii')
    header[156] = entry.endsWith('/') ? 0x35 : 0x30
    header.write('ustar\0', 257, 'ascii')
    header.write('00', 263, 'ascii')
    header.fill(0x20, 148, 156)
    let checksum = 0
    for (const byte of header) checksum += byte
    header.write(checksum.toString(8).padStart(6, '0'), 148, 'ascii')
    header[154] = 0
    header[155] = 0x20
    blocks.push(header)
  }
  blocks.push(Buffer.alloc(1024))
  return Buffer.concat(blocks)
}

describe('container.structure.analyze', () => {
  test('flags zip traversal and compression risks while routing nested binaries', () => {
    const inventory = buildContainerStructureFromBuffer(
      localZip([
        { name: '../evil.exe', compressedSize: 1, uncompressedSize: 1000 },
        { name: 'lib/libdemo.so' },
        { name: 'Payload/App.app/Frameworks/libDemo.dylib' },
        { name: 'classes.dex' },
        { name: 'module.wasm' },
      ]),
      { filename: 'bundle.zip' }
    )

    expect(inventory.container_format).toBe('zip')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_extract_to_execution_path: true,
        no_mount: true,
        no_entrypoint_run: true,
      })
    )
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining(['path-traversal', 'high-compression-ratio'])
    )
    expect(inventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: '../evil.exe',
          routed_formats: expect.arrayContaining(['pe']),
          recommended_tools: expect.arrayContaining(['pe.structure.analyze']),
        }),
        expect.objectContaining({
          path: 'module.wasm',
          recommended_tools: expect.arrayContaining(['wasm.structure.analyze']),
        }),
      ])
    )
  })

  test('plans Docker/OCI and installer payload handling without entrypoint or install execution', () => {
    const docker = buildContainerStructureFromBuffer(
      tarFixture(['manifest.json', 'layer.tar', 'bin/tool', 'usr/lib/libdemo.so', 'Dockerfile']),
      { filename: 'image.tar' }
    )
    const installerBundle = buildContainerStructureFromBuffer(
      localZip([{ name: 'setup.msi' }, { name: 'Payload/Demo.pkg' }]),
      { filename: 'payloads.zip' }
    )

    expect(docker.container_format).toBe('docker-image')
    expect(docker.policy.no_entrypoint_run).toBe(true)
    expect(docker.risk_flags).toContain('container-entrypoint-not-run')
    expect(docker.entrypoint_candidates).toContain('Dockerfile')
    expect(installerBundle.policy.no_install).toBe(true)
    expect(installerBundle.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'setup.msi',
          recommended_tools: expect.arrayContaining(['installer.inventory']),
        }),
        expect.objectContaining({
          path: 'Payload/Demo.pkg',
          recommended_tools: expect.arrayContaining(['apple.container.inventory']),
        }),
      ])
    )
  })
})
