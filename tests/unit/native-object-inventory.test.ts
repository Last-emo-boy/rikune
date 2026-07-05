import { describe, expect, test } from '@jest/globals'

import nativeObjectPlugin from '../../src/plugins/native-object/index.js'
import {
  NATIVE_OBJECT_EVIDENCE_SUMMARY_SCHEMA,
  NATIVE_OBJECT_FOLLOW_UP_TOOLS,
  NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE,
  NATIVE_OBJECT_QUALITY_GATES_SCHEMA,
  NATIVE_OBJECT_ROUTE_TERMS,
  NATIVE_OBJECT_RUNTIME_POLICY,
  NATIVE_OBJECT_WORKFLOW_HANDOFF_SCHEMA,
} from '../../src/plugins/native-object/native-object-metadata.js'
import {
  buildNativeObjectInventoryFromBuffer,
  nativeObjectInventoryToolDefinition,
} from '../../src/plugins/native-object/tools/native-object-inventory.js'

const FORBIDDEN_NEXT_TOOLS = [
  'sandbox.execute',
  'dynamic.runtime.status',
  'dynamic.trace.import',
  'safe.run',
  'wine.run',
  'frida.runtime.instrument',
  'qiling.inspect',
  'speakeasy.emulate',
  'upx.inspect',
  'lldb.debug',
  'gdb.debug',
  'tools.discover',
]

function arMember(name: string, body: Buffer = Buffer.alloc(0)): Buffer {
  const header = Buffer.alloc(60, ' ')
  header.write(`${name}/`.slice(0, 16), 0, 'ascii')
  header.write(String(body.length).padEnd(10, ' '), 48, 'ascii')
  header.write('`\n', 58, 'ascii')
  return Buffer.concat([header, body, body.length % 2 ? Buffer.from('\n') : Buffer.alloc(0)])
}

describe('native.object.inventory', () => {
  test('declares passive object, symbol, debug metadata, and workflow handoff profile', () => {
    const recipe = nativeObjectInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'native-object.passive-inventory-handoff'
    )

    expect(nativeObjectPlugin.version).toBe('1.1.0')
    expect(nativeObjectPlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['object', 'static-lib', 'coff-lib', 'linux-kernel-module', 'dwp'])
    )
    expect(nativeObjectPlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining([
        'coff',
        'coff-lib',
        'elf-object',
        'linux-kernel-module',
        'macho-object',
      ])
    )
    expect(nativeObjectPlugin.surfaceRules?.activateOn?.fileTypes ?? []).not.toEqual(
      expect.arrayContaining(['object', 'static-lib', 'ar', 'ar-static-lib', 'dwarf'])
    )
    expect(nativeObjectPlugin.aspects?.execution).toEqual(
      expect.arrayContaining(['static', 'triage', 'workflow-handoff'])
    )
    expect(nativeObjectPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'workflow-plan',
        'workflow-handoff',
        'symbol-handoff',
        'debug-metadata-handoff',
        'function-boundary-handoff',
        'search-profile',
      ])
    )
    expect(nativeObjectPlugin.aspects?.route_terms).toEqual(
      expect.arrayContaining(NATIVE_OBJECT_ROUTE_TERMS)
    )
    expect(nativeObjectPlugin.aspects?.search).toEqual(
      expect.arrayContaining(['native object', 'static library', 'symbol recovery'])
    )
    expect(nativeObjectPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        ...NATIVE_OBJECT_RUNTIME_POLICY,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noLink: true,
        noLoad: true,
        noStripOrSign: true,
      })
    )
    expect(nativeObjectInventoryToolDefinition.aspects?.evidence).toEqual(
      expect.arrayContaining(['symbols', 'debug-metadata', 'nested-binaries', 'workflow'])
    )
    expect(nativeObjectInventoryToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_execute',
        'no_link',
        'no_load',
        'no_strip_or_sign',
        'no_mutation',
        'no_network',
      ])
    )
    expect(nativeObjectInventoryToolDefinition.aspects?.profile).toEqual(expect.any(Array))
    expect(nativeObjectInventoryToolDefinition.aspects?.route_terms).toEqual(
      expect.arrayContaining(NATIVE_OBJECT_ROUTE_TERMS)
    )
    expect(nativeObjectInventoryToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE,
          mime: 'application/json',
        }),
      ])
    )
    expect(nativeObjectInventoryToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'symbols',
          artifactTypes: expect.arrayContaining([NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE]),
        }),
        expect.objectContaining({
          category: 'debug-metadata',
          artifactTypes: expect.arrayContaining([NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE]),
        }),
        expect.objectContaining({
          category: 'workflow',
          artifactTypes: expect.arrayContaining([NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE]),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['native.object.inventory'],
        nextTools: NATIVE_OBJECT_FOLLOW_UP_TOOLS,
        requiredArtifacts: expect.arrayContaining(['sample']),
        producesArtifacts: expect.arrayContaining([NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE]),
        evidence: expect.arrayContaining(['symbols', 'debug-metadata', 'workflow', 'provenance']),
        safety: expect.arrayContaining(['passive', 'no_link', 'no_load', 'no_mutation']),
      })
    )
    for (const forbidden of FORBIDDEN_NEXT_TOOLS) {
      expect(recipe?.nextTools ?? []).not.toContain(forbidden)
    }
    expect(nativeObjectInventoryToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noLink: true,
        noLoad: true,
        noStripOrSign: true,
      })
    )
  })

  test('routes static library members and debug metadata without linking or loading', () => {
    const inventory = buildNativeObjectInventoryFromBuffer(
      Buffer.concat([
        Buffer.from('!<arch>\n', 'ascii'),
        arMember('module.o', Buffer.from('Java_com_example_Native_init\0')),
        arMember('driver.ko'),
        arMember('app.pdb'),
        arMember('libdemo.dylib'),
      ]),
      { filename: 'libdemo.a', sampleId: 'sha256:native-object' }
    )

    expect(inventory.format).toBe('ar-static-lib')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_link: true,
        no_load: true,
        no_strip_or_sign: true,
        no_mutation: true,
      })
    )
    expect(inventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'module.o',
          recommended_tools: expect.arrayContaining(['native.object.inventory']),
        }),
        expect.objectContaining({
          path: 'driver.ko',
          recommended_tools: expect.arrayContaining(['elf.structure.analyze']),
        }),
        expect.objectContaining({
          path: 'app.pdb',
          recommended_tools: expect.arrayContaining(['windows.debug.metadata.inspect']),
        }),
        expect.objectContaining({
          path: 'libdemo.dylib',
          recommended_tools: expect.arrayContaining(['macho.structure.analyze']),
        }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'artifact.read',
        'metadata.extract',
        'strings.extract',
        'elf.structure.analyze',
        'macho.structure.analyze',
        'windows.debug.metadata.inspect',
        'code.functions.smart_recover',
        'code.functions.define',
        'analysis.evidence.graph',
        'native.object.inventory',
      ])
    )
    expect(inventory.recommended_next_tools).not.toContain('report.generate')
    for (const forbidden of FORBIDDEN_NEXT_TOOLS) {
      expect(inventory.recommended_next_tools).not.toContain(forbidden)
      expect(
        inventory.nested_binary_candidates.flatMap((candidate) => candidate.recommended_tools)
      ).not.toContain(forbidden)
    }
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: NATIVE_OBJECT_EVIDENCE_SUMMARY_SCHEMA,
        source_tool: 'native.object.inventory',
        sample_id: 'sha256:native-object',
        artifact_type: NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE,
        route_terms: NATIVE_OBJECT_ROUTE_TERMS,
        static_only: true,
      })
    )
    expect(inventory.evidence_summary?.counts).toEqual(
      expect.objectContaining({
        members: 4,
        nested_binary_candidates: 4,
      })
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: NATIVE_OBJECT_WORKFLOW_HANDOFF_SCHEMA,
        handoff_mode: 'native_object_inventory_to_symbol_and_debug_analysis',
        artifact_contract: expect.objectContaining({
          consumes: ['sample'],
          produces: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
          mime: 'application/json',
          expected_consumers: NATIVE_OBJECT_FOLLOW_UP_TOOLS,
        }),
      })
    )
    expect(inventory.workflow_handoff?.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'debug-metadata-review',
          next_tools: ['windows.debug.metadata.inspect'],
        }),
        expect.objectContaining({
          goal: 'function-boundary-recovery',
          next_tools: ['code.functions.smart_recover', 'code.functions.define'],
        }),
        expect.objectContaining({
          goal: 'nested-native-member-routing',
          blocking_conditions: expect.arrayContaining([
            expect.stringContaining('Ingest relevant member binaries separately'),
          ]),
        }),
      ])
    )
    expect(inventory.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        activation_boundary: 'result-scoped',
        sample_execution_allowed: false,
        link_allowed: false,
        load_allowed: false,
        strip_or_sign_allowed: false,
        mutation_allowed: false,
        network_allowed: false,
        sample_executed_by_tool: false,
        linked_by_tool: false,
        loaded_by_tool: false,
        stripped_or_signed_by_tool: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: NATIVE_OBJECT_QUALITY_GATES_SCHEMA,
        passive_static_inventory: true,
        bounded_preview_only: true,
        format_detected: true,
        native_object_or_debug_format: true,
        nested_binary_candidates_present: true,
        sample_executed_by_tool: false,
        linked_by_tool: false,
        loaded_by_tool: false,
        stripped_or_signed_by_tool: false,
        mutation_performed: false,
      })
    )
  })
})
