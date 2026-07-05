import { describe, expect, test } from '@jest/globals'

import windowsDebugSymbolsPlugin from '../../src/plugins/windows-debug-symbols/index.js'
import {
  buildWindowsDebugMetadataFromBuffer,
  windowsDebugMetadataInspectToolDefinition,
} from '../../src/plugins/windows-debug-symbols/tools/windows-debug-metadata-inspect.js'

describe('windows-debug-symbols metadata deepening', () => {
  test('plugin exposes debug metadata search profile tags', () => {
    expect(windowsDebugSymbolsPlugin.version).toBe('1.1.0')
    expect(windowsDebugSymbolsPlugin.executionDomain).toBe('static')
    expect(windowsDebugSymbolsPlugin.aspects?.formats).toEqual(
      expect.arrayContaining([
        'pdb',
        'obj',
        'lib',
        'coff',
        'coff-lib',
        'codeview',
        'pdb-codeview',
        'dwo',
        'dwp',
        'debug',
        'debug-symbols',
        'debug-metadata',
      ])
    )
    expect(windowsDebugSymbolsPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'search-profile',
        'workflow-handoff',
        'metadata-only-handoff',
        'debug-metadata-handoff',
        'symbol-handoff',
        'function-boundary-handoff',
        'pdb-identity',
        'coff-symbols',
        'source-path-profile',
      ])
    )
    expect(windowsDebugSymbolsPlugin.aspects?.evidence).toEqual(
      expect.arrayContaining([
        'symbols',
        'debug-metadata',
        'pdb-identity',
        'codeview',
        'coff-symbols',
        'source-map',
        'source-paths',
        'workflow',
      ])
    )
    expect(windowsDebugSymbolsPlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_execute',
        'no_network',
        'no_network_by_default',
        'no_symbol_server_network_by_default',
        'no_symbol_server_download',
        'no_source_fetch',
        'no_mutation',
        'no_live_sample_by_default',
      ])
    )
    expect(windowsDebugSymbolsPlugin.aspects?.search).toEqual(
      expect.arrayContaining(['pdb', 'codeview', 'coff symbols', 'source map'])
    )
    expect(windowsDebugSymbolsPlugin.aspects?.profile).toEqual(
      expect.arrayContaining([
        'pdb-identity-profile',
        'codeview-profile',
        'coff-symbol-table-profile',
        'source-map-profile',
      ])
    )
    expect(windowsDebugSymbolsPlugin.aspects?.route_terms).toEqual(
      expect.arrayContaining([
        'pdb_identity_handoff',
        'codeview_metadata_handoff',
        'coff_symbol_table_handoff',
        'function_boundary_handoff',
      ])
    )
    expect(windowsDebugSymbolsPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noSymbolServerDownload: true,
        noSourceFetch: true,
      })
    )
    expect(windowsDebugSymbolsPlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining([
        'pdb',
        'obj',
        'lib',
        'dwo',
        'dwp',
        '.debug',
        'codeview',
        'CodeView',
        'debug-metadata',
      ])
    )
  })

  test('tool declares passive recipe, artifacts, evidence, and safety profile', () => {
    const definition = windowsDebugMetadataInspectToolDefinition
    const recipe = definition.workflowRecipes?.find(
      (candidate) => candidate.id === 'windows-debug-symbols.passive-metadata-handoff'
    )

    expect(definition.aspects?.formats).toEqual(
      expect.arrayContaining([
        'pdb',
        'obj',
        'lib',
        'coff',
        'coff-lib',
        'codeview',
        'pdb-codeview',
        'dwo',
        'dwp',
        'debug',
        'debug-symbols',
        'debug-metadata',
      ])
    )
    expect(definition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'search-profile',
        'source-map-plan',
        'workflow-plan',
        'workflow-handoff',
        'metadata-only-handoff',
        'debug-metadata-handoff',
        'symbol-handoff',
        'function-boundary-handoff',
        'pdb-identity',
        'coff-symbols',
        'source-path-profile',
      ])
    )
    expect(definition.aspects?.evidence).toEqual(
      expect.arrayContaining([
        'symbols',
        'debug-metadata',
        'pdb-identity',
        'codeview',
        'coff-symbols',
        'source-map',
        'source-paths',
        'object-members',
        'workflow',
        'provenance',
      ])
    )
    expect(definition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_network_by_default',
        'no_symbol_server_network_by_default',
        'no_symbol_server_download',
        'no_source_fetch',
        'no_mutation',
        'no_live_sample_by_default',
      ])
    )
    expect(definition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'windows_debug_metadata',
          mime: 'application/json',
          mimeTypes: expect.arrayContaining(['application/json']),
        }),
      ])
    )
    expect(definition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'symbols',
          artifactTypes: expect.arrayContaining(['windows_debug_metadata']),
        }),
        expect.objectContaining({
          category: 'debug-metadata',
          artifactTypes: expect.arrayContaining(['windows_debug_metadata']),
        }),
        expect.objectContaining({
          category: 'pdb-identity',
          artifactTypes: expect.arrayContaining(['windows_debug_metadata']),
        }),
        expect.objectContaining({
          category: 'coff-symbols',
          artifactTypes: expect.arrayContaining(['windows_debug_metadata']),
        }),
        expect.objectContaining({
          category: 'source-map',
          artifactTypes: expect.arrayContaining(['windows_debug_metadata']),
        }),
        expect.objectContaining({
          category: 'workflow',
          artifactTypes: expect.arrayContaining(['windows_debug_metadata']),
        }),
        expect.objectContaining({
          category: 'provenance',
          artifactTypes: expect.arrayContaining(['windows_debug_metadata']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['windows.debug.metadata.inspect'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'pe.structure.analyze',
          'native.object.inventory',
          'code.functions.smart_recover',
          'code.functions.define',
          'analysis.evidence.graph',
          'report.generate',
        ]),
        requiredArtifacts: expect.arrayContaining(['sample']),
        producesArtifacts: expect.arrayContaining(['windows_debug_metadata']),
        evidence: expect.arrayContaining(['symbols', 'debug-metadata', 'workflow', 'provenance']),
        safety: expect.arrayContaining([
          'passive',
          'no_symbol_server_network_by_default',
          'no_mutation',
          'no_live_sample_by_default',
        ]),
      })
    )
    expect(definition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noSymbolServerDownload: true,
        noSourceFetch: true,
      })
    )
  })

  test('inventory returns structured handoff envelope for PDB identity evidence', () => {
    const pdb = Buffer.alloc(512)
    pdb.write('Microsoft C/C++ MSF 7.00\r\n\x1aDS', 0, 'latin1')
    pdb.writeUInt32LE(4096, 32)
    pdb.writeUInt32LE(1, 36)
    pdb.writeUInt32LE(8, 40)
    pdb.writeUInt32LE(512, 44)
    pdb.write('?DemoFunction@@YAXXZ\0', 80, 'latin1')
    pdb.write('RSDS', 128, 'ascii')
    pdb.writeUInt32LE(0x11223344, 132)
    pdb.writeUInt16LE(0x5566, 136)
    pdb.writeUInt16LE(0x7788, 138)
    Buffer.from([0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10]).copy(pdb, 140)
    pdb.writeUInt32LE(2, 148)
    pdb.write('C:\\Users\\alice\\src\\demo.cpp\0', 152, 'latin1')

    const inventory = buildWindowsDebugMetadataFromBuffer(pdb, {
      filename: 'demo.pdb',
      sampleId: 'sample-pdb',
      size: 1024,
      maxReadBytes: 512,
    })

    expect(inventory.format).toBe('pdb')
    expect(inventory.pdb_identity_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'RSDS',
          age: 2,
          guid: '11223344-5566-7788-99aa-bbccddeeff10',
          pdb_path: 'C:\\Users\\alice\\src\\demo.cpp',
        }),
      ])
    )
    expect(inventory.codeview_markers).toEqual(expect.arrayContaining(['RSDS@0x80']))
    expect(inventory.preview_profile).toEqual(
      expect.objectContaining({
        bytes_read: 512,
        size: 1024,
        truncated: true,
        max_read_bytes: 512,
      })
    )
    expect(inventory.source_path_profile).toEqual(
      expect.objectContaining({
        total: expect.any(Number),
        windows_paths: expect.any(Number),
        possible_sensitive_paths: expect.any(Number),
        redacted_examples: expect.arrayContaining(['C:\\Users\\<user>\\src\\demo.cpp']),
      })
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'artifact.read',
        'metadata.extract',
        'strings.extract',
        'pe.structure.analyze',
        'code.functions.smart_recover',
        'code.functions.define',
        'analysis.evidence.graph',
      ])
    )
    for (const forbidden of [
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
    ]) {
      expect(inventory.recommended_next_tools).not.toContain(forbidden)
    }
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.windows_debug_metadata.evidence_summary.v1',
        source_tool: 'windows.debug.metadata.inspect',
        sample_id: 'sample-pdb',
        artifact_type: 'windows_debug_metadata',
        route_terms: expect.arrayContaining(['pdb_identity_handoff', 'source_map_review']),
        static_only: true,
      })
    )
    expect(inventory.evidence_summary?.counts).toEqual(
      expect.objectContaining({
        pdb_identity_hints: 1,
        codeview_markers: 1,
      })
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.windows_debug_metadata.workflow_handoff.v1',
        handoff_mode: 'windows_debug_metadata_to_symbol_source_and_function_boundary_analysis',
        artifact_contract: expect.objectContaining({
          consumes: ['sample'],
          produces: ['windows_debug_metadata'],
          mime: 'application/json',
          expected_consumers: expect.arrayContaining([
            'artifact.read',
            'pe.structure.analyze',
            'analysis.evidence.graph',
            'report.generate',
          ]),
        }),
      })
    )
    expect(inventory.workflow_handoff?.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'pdb-identity-correlation',
          priority: 'high',
          next_tools: expect.arrayContaining(['pe.structure.analyze']),
        }),
        expect.objectContaining({
          goal: 'function-boundary-recovery',
          priority: 'medium',
          next_tools: expect.arrayContaining(['code.functions.smart_recover']),
        }),
      ])
    )
    expect(inventory.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_execution_allowed: false,
        symbol_server_download_allowed: false,
        source_fetch_allowed: false,
        network_allowed: false,
        mutation_allowed: false,
        sample_executed_by_tool: false,
        symbol_server_contacted: false,
        source_fetched: false,
        network_used_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.windows_debug_metadata.quality_gates.v1',
        passive_static_inventory: true,
        bounded_preview_only: true,
        format_detected: true,
        debug_metadata_format: true,
        pdb_identity_present: true,
        codeview_markers_present: true,
        source_path_hints_present: true,
        sample_executed_by_tool: false,
        symbol_server_contacted: false,
        source_fetched: false,
        network_used_by_tool: false,
        mutation_performed: false,
      })
    )
  })
})
