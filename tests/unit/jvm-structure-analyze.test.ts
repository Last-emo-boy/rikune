import { describe, expect, test } from '@jest/globals'
import { buildJvmStructureFromBuffer } from '../../src/plugins/jvm/tools/jvm-structure-analyze.js'

function localZip(entries: Array<{ name: string; content?: Buffer }>): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry.name)
    const content = entry.content ?? Buffer.alloc(0)
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt16LE(0, 8)
    header.writeUInt32LE(content.length, 18)
    header.writeUInt32LE(content.length, 22)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name, content)
  }
  return Buffer.concat(chunks)
}

describe('jvm.structure.analyze', () => {
  test('extracts JAR manifest, class inventory, dependencies, and nested archives passively', () => {
    const inventory = buildJvmStructureFromBuffer(
      localZip([
        {
          name: 'META-INF/MANIFEST.MF',
          content: Buffer.from('Manifest-Version: 1.0\nMain-Class: demo.Main\nClass-Path: lib/a.jar\n'),
        },
        { name: 'demo/Main.class', content: Buffer.from([0xca, 0xfe, 0xba, 0xbe]) },
        { name: 'demo/internal/Helper.class', content: Buffer.from([0xca, 0xfe, 0xba, 0xbe]) },
        { name: 'META-INF/demo.kotlin_module' },
        { name: 'lib/nested.jar' },
      ]),
      { filename: 'demo.jar' }
    )

    expect(inventory.format).toBe('jar')
    expect(inventory.manifest).toEqual(
      expect.objectContaining({ 'Main-Class': 'demo.Main', 'Class-Path': 'lib/a.jar' })
    )
    expect(inventory.class_files).toEqual(
      expect.arrayContaining(['demo/Main.class', 'demo/internal/Helper.class'])
    )
    expect(inventory.packages).toEqual(expect.arrayContaining(['demo', 'demo.internal']))
    expect(inventory.dependency_hints).toEqual(
      expect.arrayContaining(['lib/a.jar', 'META-INF/demo.kotlin_module'])
    )
    expect(inventory.nested_archive_candidates).toContain('lib/nested.jar')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_decompiler_launch: true,
      })
    )
    expect(inventory.decompile_plan.status).toBe('plan_only')
  })

  test('covers standalone CLASS and JVM archive family naming without executing bytecode', () => {
    const classInventory = buildJvmStructureFromBuffer(Buffer.from([0xca, 0xfe, 0xba, 0xbe]), {
      filename: 'Main.class',
    })
    const aarInventory = buildJvmStructureFromBuffer(localZip([{ name: 'classes.jar' }]), {
      filename: 'lib.aar',
    })
    const jmodInventory = buildJvmStructureFromBuffer(localZip([{ name: 'classes/module-info.class' }]), {
      filename: 'demo.jmod',
    })

    expect(classInventory.format).toBe('class')
    expect(classInventory.class_files).toContain('Main.class')
    expect(aarInventory.format).toBe('aar')
    expect(jmodInventory.format).toBe('jmod')
    expect([classInventory, aarInventory, jmodInventory].every((item) => item.policy.no_execute)).toBe(
      true
    )
  })
})
