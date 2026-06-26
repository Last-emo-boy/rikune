import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import appleObjcSwiftPlugin from '../../src/plugins/apple-objc-swift/index.js'
import {
  appleObjcSwiftMetadataInspectToolDefinition,
  buildAppleObjcSwiftMetadataFromBuffer,
} from '../../src/plugins/apple-objc-swift/tools/apple-objc-swift-metadata-inspect.js'

function writeFixedName(data: Buffer, offset: number, value: string): void {
  data.fill(0, offset, offset + 16)
  data.write(value, offset, Math.min(Buffer.byteLength(value), 16), 'ascii')
}

function writeSection(
  data: Buffer,
  offset: number,
  section: string,
  segment: string,
  fileOffset: number,
  size: number
): void {
  writeFixedName(data, offset, section)
  writeFixedName(data, offset + 16, segment)
  data.writeBigUInt64LE(BigInt(fileOffset), offset + 32)
  data.writeBigUInt64LE(BigInt(size), offset + 40)
  data.writeUInt32LE(fileOffset, offset + 48)
  data.writeUInt32LE(0, offset + 52)
  data.writeUInt32LE(0, offset + 56)
  data.writeUInt32LE(0, offset + 60)
  data.writeUInt32LE(0, offset + 64)
}

function writeCStringBlob(data: Buffer, offset: number, values: string[]): number {
  const blob = Buffer.from(`${values.join('\0')}\0`, 'utf8')
  blob.copy(data, offset)
  return blob.length
}

function machoObjcSwiftFixture(): Buffer {
  const data = Buffer.alloc(0x600)
  const sectionCount = 5
  const commandSize = 72 + sectionCount * 80
  const commandOffset = 32
  const sectionTableOffset = commandOffset + 72

  data.writeUInt32LE(0xfeedfacf, 0)
  data.writeInt32LE(0x0100000c, 4)
  data.writeInt32LE(0, 8)
  data.writeUInt32LE(6, 12)
  data.writeUInt32LE(1, 16)
  data.writeUInt32LE(commandSize, 20)
  data.writeUInt32LE(0, 24)
  data.writeUInt32LE(0, 28)

  data.writeUInt32LE(0x19, commandOffset)
  data.writeUInt32LE(commandSize, commandOffset + 4)
  writeFixedName(data, commandOffset + 8, '__DATA_CONST')
  data.writeBigUInt64LE(0n, commandOffset + 24)
  data.writeBigUInt64LE(0n, commandOffset + 32)
  data.writeBigUInt64LE(0n, commandOffset + 40)
  data.writeBigUInt64LE(0n, commandOffset + 48)
  data.writeUInt32LE(0, commandOffset + 56)
  data.writeUInt32LE(0, commandOffset + 60)
  data.writeUInt32LE(sectionCount, commandOffset + 64)
  data.writeUInt32LE(0, commandOffset + 68)

  writeSection(data, sectionTableOffset, '__objc_classlist', '__DATA_CONST', 0x300, 16)
  const methSize = writeCStringBlob(data, 0x320, [
    'viewDidLoad',
    'performSelector:',
    'URLSession:didReceiveChallenge:',
  ])
  writeSection(data, sectionTableOffset + 80, '__objc_methname', '__TEXT', 0x320, methSize)
  const classSize = writeCStringBlob(data, 0x380, ['DemoViewController', 'NetworkClient'])
  writeSection(data, sectionTableOffset + 160, '__objc_classname', '__TEXT', 0x380, classSize)
  const reflSize = writeCStringBlob(data, 0x3c0, ['$s4Demo5ModelV', 'Demo.Model', 'Swift.Task'])
  writeSection(data, sectionTableOffset + 240, '__swift5_reflstr', '__TEXT', 0x3c0, reflSize)
  writeSection(data, sectionTableOffset + 320, '__swift5_types', '__TEXT', 0x430, 8)

  return data
}

describe('apple.objc_swift.metadata.inspect', () => {
  test('declares passive Apple ObjC/Swift metadata workflow', () => {
    expect(appleObjcSwiftPlugin.id).toBe('apple-objc-swift')
    expect(appleObjcSwiftPlugin.executionDomain).toBe('static')
    expect(appleObjcSwiftPlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['objc-metadata', 'swift-metadata', 'macho'])
    )
    expect(appleObjcSwiftPlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_debug_attach',
        'no_app_launch',
        'no_external_tool',
        'no_runtime_start',
      ])
    )
    expect(appleObjcSwiftMetadataInspectToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'apple.objc-swift-metadata-static-inventory',
        startsWith: ['apple.objc_swift.metadata.inspect'],
        nextTools: expect.arrayContaining([
          'macho.structure.analyze',
          'apple.signing.inspect',
          'analysis.evidence.graph',
          'macos.runtime.plan',
          'ios.runtime.plan',
        ]),
        producesArtifacts: ['apple_objc_swift_metadata_inventory'],
        safety: expect.arrayContaining([
          'passive',
          'no_debug_attach',
          'no_app_launch',
          'no_external_tool',
        ]),
      })
    )
  })

  test('parses Mach-O ObjC sections, Swift section hints, and static safety gates', () => {
    const inventory = buildAppleObjcSwiftMetadataFromBuffer(machoObjcSwiftFixture(), {
      filename: 'Demo.framework/Demo',
      sampleId: 'sha256:apple',
    })

    expect(inventory.format).toBe('macho')
    expect(inventory.macho).toEqual(
      expect.objectContaining({
        valid_magic: true,
        is_fat: false,
        cputype: 'arm64',
        filetype: 'dylib',
        section_count: 5,
      })
    )
    expect(inventory.objc.present).toBe(true)
    expect(inventory.objc.pointer_reference_counts.classlist).toBe(2)
    expect(inventory.objc.class_name_hints).toEqual(
      expect.arrayContaining(['DemoViewController', 'NetworkClient'])
    )
    expect(inventory.objc.selector_hints).toEqual(
      expect.arrayContaining(['performSelector:', 'URLSession:didReceiveChallenge:'])
    )
    expect(inventory.swift.present).toBe(true)
    expect(inventory.swift.section_hints).toEqual(
      expect.arrayContaining(['__TEXT.__swift5_reflstr', '__TEXT.__swift5_types'])
    )
    expect(inventory.swift.module_hints).toContain('Demo')
    expect(inventory.swift.mangled_symbol_hints).toContain('$s4Demo5ModelV')
    expect(inventory.capability_risk_summary).toEqual(
      expect.objectContaining({
        dynamic_dispatch: true,
        reflection_or_selector_invocation: true,
        network_api: true,
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_debug_attach: true,
        no_app_launch: true,
        no_external_tool: true,
        no_runtime_start: true,
        no_network: true,
        no_mutation: true,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        external_tool_invoked_by_tool: false,
        debugger_attached_by_tool: false,
        app_launched_by_tool: false,
        runtime_started_by_tool: false,
      })
    )
    expect(inventory.demangle_plan).toEqual(
      expect.objectContaining({
        status: 'plan_only',
        external_tool_invoked_by_tool: false,
      })
    )
  })

  test('handles standalone Swift metadata without Mach-O magic', () => {
    const inventory = buildAppleObjcSwiftMetadataFromBuffer(
      Buffer.from(
        'target arm64-apple-ios module Demo swift-version 6.0 $s4Demo8FeatureV',
        'utf8'
      ),
      { filename: 'Demo.swiftinterface' }
    )

    expect(inventory.format).toBe('swiftinterface')
    expect(inventory.macho.valid_magic).toBe(false)
    expect(inventory.swift.present).toBe(true)
    expect(inventory.swift.standalone_metadata).toBe(true)
    expect(inventory.swift.module_hints).toContain('Demo')
    expect(inventory.policy.no_external_tool).toBe(true)
  })

  test('registers in the plugin test harness', () => {
    const harness = createPluginTestHarness()
    const names = harness.registerPlugin(appleObjcSwiftPlugin)
    expect(names).toContain('apple.objc_swift.metadata.inspect')
  })
})
