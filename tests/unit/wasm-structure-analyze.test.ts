import { describe, expect, test } from '@jest/globals'
import {
  buildWasmStructureFromBuffer,
  wasmStructureAnalyzeToolDefinition,
} from '../../src/plugins/wasm/tools/wasm-structure-analyze.js'

describe('wasm.structure.analyze', () => {
  test('declares searchable WASM/WASI static workflow and passive runtime policy metadata', () => {
    expect(wasmStructureAnalyzeToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['wasm', 'wasi', 'wat'])
    )
    expect(wasmStructureAnalyzeToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'wasi-capability-review',
        'resource-grant-review',
        'preopen-policy-review',
        'network-policy-review',
        'custom-section-inventory',
        'runtime-handoff',
      ])
    )
    expect(wasmStructureAnalyzeToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining([
        'structure',
        'imports',
        'exports',
        'wasi-capability',
        'resource-grant',
        'custom-section',
        'workflow',
        'provenance',
      ])
    )
    expect(wasmStructureAnalyzeToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'wasm.static.inventory',
        startsWith: ['wasm.structure.analyze'],
        nextTools: expect.arrayContaining([
          'wasm.runtime.plan',
          'tool.readiness',
          'analysis.evidence.graph',
          'artifact.read',
        ]),
        producesArtifacts: ['wasm_structure'],
        evidence: expect.arrayContaining([
          'imports',
          'exports',
          'wasi-capability',
          'resource-grant',
          'custom-section',
          'provenance',
        ]),
        safety: expect.arrayContaining([
          'no_instantiation',
          'no_wasi_grants',
          'no_resource_grants',
          'no_network_by_default',
        ]),
      })
    )
    expect(wasmStructureAnalyzeToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noInstantiation: true,
        noWasiGrants: true,
        noResourceGrants: true,
        resourceGrants: 'none',
      })
    )
  })

  test('parses valid WASM module headers without starting a runtime', () => {
    const inventory = buildWasmStructureFromBuffer(
      Buffer.from([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03, 0x6e, 0x61, 0x6d, 0x07,
        0x01, 0x00,
      ]),
      { filename: 'module.wasm' }
    )

    expect(inventory.format).toBe('wasm')
    expect(inventory.valid_magic).toBe(true)
    expect(inventory.version).toBe(1)
    expect(inventory.custom_sections).toContain('nam')
    expect(inventory.runtime_plan.status).toBe('plan_only')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_runtime_start: true,
        no_instantiation: true,
        no_wasi_grants: true,
        no_network: true,
        resource_grants: 'none',
      })
    )
    expect(inventory.runtime_plan.handoff).toEqual(
      expect.objectContaining({
        primary_tool: 'wasm.runtime.plan',
        readiness_tool: 'tool.readiness',
        evidence_tools: expect.arrayContaining(['analysis.evidence.graph', 'artifact.read']),
        static_evidence_artifact_type: 'wasm_structure',
        runtime_policy: expect.objectContaining({
          no_instantiation: true,
          no_wasi_grants: true,
          no_network: true,
          resource_grants: 'none',
        }),
      })
    )
    expect(inventory.next_actions.join(' ')).toMatch(/Do not instantiate/i)
    expect(inventory.next_actions.join(' ')).toMatch(/resource grants/i)
  })

  test('parses imports, exports, memories, tables, start function, and WASI capability risk', () => {
    const inventory = buildWasmStructureFromBuffer(
      Buffer.from([
        // wasm magic + version
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        // type section: one function type () -> ()
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
        // import section: wasi_snapshot_preview1.fd_write function type 0
        0x02, 0x24, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68,
        0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31, 0x08, 0x66, 0x64, 0x5f,
        0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x00,
        // function section: one local function with type 0
        0x03, 0x02, 0x01, 0x00,
        // table section: one funcref table min 1
        0x04, 0x04, 0x01, 0x70, 0x00, 0x01,
        // memory section: one memory min 1 max 2
        0x05, 0x04, 0x01, 0x01, 0x01, 0x02,
        // export section: export local function index 1 as run
        0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x01,
        // start section: start at local function index 1
        0x08, 0x01, 0x01,
        // code section: empty body for the local function
        0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
      ]),
      { filename: 'wasi-module.wasm', sampleId: 'sha256:wasi' }
    )

    expect(inventory.imports).toEqual([
      {
        module: 'wasi_snapshot_preview1',
        name: 'fd_write',
        kind: 'function',
      },
    ])
    expect(inventory.exports).toEqual([
      {
        name: 'run',
        kind: 'function',
        index: 1,
      },
    ])
    expect(inventory.memory_declarations).toEqual([
      expect.objectContaining({ min_pages: 1, max_pages: 2, shared: false }),
    ])
    expect(inventory.table_declarations).toEqual([
      expect.objectContaining({ element_type: '0x70', min: 1, max: null, shared: false }),
    ])
    expect(inventory.start_function_index).toBe(1)
    expect(inventory.wasi_capability_hints).toEqual(
      expect.arrayContaining(['wasi_snapshot_preview1', 'filesystem'])
    )
    expect(inventory.capability_risk_summary).toEqual(
      expect.objectContaining({
        filesystem: true,
        risk_level: 'medium',
      })
    )
    expect(inventory.runtime_plan.recommended_tools).toEqual(
      expect.arrayContaining([
        'wasm.runtime.plan',
        'tool.readiness',
        'analysis.evidence.graph',
        'artifact.read',
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'wasm.runtime.plan',
        'tool.readiness',
        'analysis.evidence.graph',
        'artifact.read',
      ])
    )
  })

  test('returns explicit invalid magic summary while preserving passive policy', () => {
    const inventory = buildWasmStructureFromBuffer(Buffer.from('not wasm'), {
      filename: 'module.wasm',
    })

    expect(inventory.valid_magic).toBe(false)
    expect(inventory.sections).toEqual([])
    expect(inventory.policy.no_runtime_start).toBe(true)
    expect(inventory.summary).toMatch(/does not contain a valid WASM/i)
  })
})
