import { describe, expect, test } from '@jest/globals'
import {
  buildWasmComponentInventoryFromBuffer,
  wasmComponentInventoryToolDefinition,
} from '../../src/plugins/wasm-component/tools/wasm-component-inventory.js'

function u32Leb(value: number): number[] {
  const bytes: number[] = []
  let remaining = value >>> 0
  do {
    let byte = remaining & 0x7f
    remaining >>>= 7
    if (remaining !== 0) byte |= 0x80
    bytes.push(byte)
  } while (remaining !== 0)
  return bytes
}

function nameBytes(value: string): number[] {
  const bytes = [...Buffer.from(value, 'utf8')]
  return [...u32Leb(bytes.length), ...bytes]
}

function externName(value: string): number[] {
  return [0x00, ...nameBytes(value)]
}

function section(id: number, payload: number[]): number[] {
  return [id, ...u32Leb(payload.length), ...payload]
}

function wasmComponentFixture(): Buffer {
  return Buffer.from([
    0x00,
    0x61,
    0x73,
    0x6d,
    0x0d,
    0x00,
    0x01,
    0x00,
    ...section(0, nameBytes('component-name')),
    ...section(1, [0x00]),
    ...section(8, [0x01, 0x00]),
    ...section(10, [
      0x02,
      ...externName('wasi:http/outgoing-handler@0.2.0'),
      0x01,
      0x00,
      ...externName('wasi:filesystem/types@0.2.0'),
      0x05,
      0x00,
    ]),
    ...section(11, [0x01, ...externName('example:component/run@1.0.0'), 0x01, 0x00]),
  ])
}

describe('wasm.component.inventory', () => {
  test('declares passive Component Model workflow metadata', () => {
    expect(wasmComponentInventoryToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['wasm-component', 'component-model', 'wit-component'])
    )
    expect(wasmComponentInventoryToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'component-model-inventory',
        'wit-interface-hints',
        'wasi-preview2-capability-review',
        'canonical-abi-summary',
        'runtime-handoff',
      ])
    )
    expect(wasmComponentInventoryToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'wasm.component-static-inventory',
        startsWith: ['wasm.component.inventory'],
        nextTools: expect.arrayContaining([
          'wasm.structure.analyze',
          'wasm.runtime.plan',
          'analysis.evidence.graph',
          'artifact.read',
        ]),
        producesArtifacts: ['wasm_component_inventory'],
        safety: expect.arrayContaining([
          'passive',
          'no_instantiation',
          'no_wasi_grants',
          'no_external_tool',
          'no_network_by_default',
        ]),
      })
    )
  })

  test('parses component preamble, sections, imports, exports, and risk hints', () => {
    const inventory = buildWasmComponentInventoryFromBuffer(wasmComponentFixture(), {
      filename: 'demo.component.wasm',
      sampleId: 'sha256:component',
    })

    expect(inventory.valid_magic).toBe(true)
    expect(inventory.component_preamble).toEqual(
      expect.objectContaining({
        version_field: 13,
        layer_field: 1,
        is_component: true,
      })
    )
    expect(inventory.custom_sections).toContain('component-name')
    expect(inventory.embedded_core_module_count).toBe(1)
    expect(inventory.canonical_abi_definition_count).toBe(1)
    expect(inventory.imports.map((item) => item.name)).toEqual(
      expect.arrayContaining(['wasi:http/outgoing-handler@0.2.0', 'wasi:filesystem/types@0.2.0'])
    )
    expect(inventory.exports.map((item) => item.name)).toContain('example:component/run@1.0.0')
    expect(inventory.wit_package_hints).toEqual(
      expect.arrayContaining(['wasi:http/outgoing-handler@0.2.0', 'wasi:filesystem/types@0.2.0'])
    )
    expect(inventory.wasi_capability_hints).toEqual(
      expect.arrayContaining(['filesystem', 'http', 'wasi'])
    )
    expect(inventory.capability_risk_summary).toEqual(
      expect.objectContaining({
        filesystem: true,
        http: true,
        risk_level: 'high',
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_runtime_start: true,
        no_instantiation: true,
        no_wasi_grants: true,
        no_external_tool: true,
        no_network: true,
        no_mutation: true,
        resource_grants: 'none',
      })
    )
    expect(inventory.runtime_plan.handoff).toEqual(
      expect.objectContaining({
        primary_tool: 'wasm.runtime.plan',
        readiness_tool: 'tool.readiness',
        static_evidence_artifact_type: 'wasm_component_inventory',
      })
    )
  })

  test('distinguishes core modules and malformed buffers without throwing', () => {
    const core = buildWasmComponentInventoryFromBuffer(
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
      { filename: 'module.wasm' }
    )
    const malformed = buildWasmComponentInventoryFromBuffer(Buffer.from('not wasm'), {
      filename: 'component.wasm',
    })

    expect(core.valid_magic).toBe(true)
    expect(core.component_preamble.is_component).toBe(false)
    expect(core.component_preamble.is_core_module_layer).toBe(true)
    expect(core.summary).toMatch(/not a Component Model layer/i)
    expect(malformed.valid_magic).toBe(false)
    expect(malformed.sections).toEqual([])
    expect(malformed.policy.no_instantiation).toBe(true)
  })
})
