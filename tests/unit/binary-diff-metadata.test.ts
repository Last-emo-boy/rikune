import { describe, expect, jest, test } from '@jest/globals'
import binaryDiffPlugin from '../../src/plugins/binary-diff/index.js'
import {
  BINARY_DIFF_ARTIFACT_TYPE,
  buildBinaryDiffEvidenceSummary,
  buildBinaryDiffWorkflowHandoff,
} from '../../src/plugins/binary-diff/binary-diff-metadata.js'
import {
  binaryDiffToolDefinition,
  createBinaryDiffHandler,
} from '../../src/plugins/binary-diff/tools/binary-diff.js'
import {
  binaryDiffSummaryToolDefinition,
  generateDiffSummary,
} from '../../src/plugins/binary-diff/tools/binary-diff-summary.js'
import type { BinaryDiffResult } from '../../src/plugins/binary-diff/binary-diff-engine.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import type { Plugin } from '../../src/plugins/sdk.js'

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function toolNames(plugin: Plugin): string[] {
  return (plugin.tools ?? []).map((tool) => tool.definition.name)
}

function createPluginManager(plugins: Plugin[]) {
  return {
    getStatuses: () =>
      plugins.map((plugin) => ({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        status: 'loaded',
        tools: toolNames(plugin),
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any
}

function sampleDiff(): BinaryDiffResult {
  return {
    ok: true,
    sample_id_a: 'sha256:aaaaaaaa',
    sample_id_b: 'sha256:bbbbbbbb',
    function_diff: {
      ok: true,
      functions_added: [{ name: 'new_stage', similarity: 0 }],
      functions_removed: [{ name: 'old_stage', similarity: 0 }],
      functions_modified: [
        { name: 'decrypt_config', similarity: 0.42, address_a: '0x401000', address_b: '0x402000' },
        { name: 'main', similarity: 0.9 },
      ],
    },
    structural_delta: {
      imports: {
        added: ['ws2_32.dll:connect'],
        removed: ['user32.dll:messageboxa'],
        common_count: 3,
      },
      exports: {
        added: ['NewExport'],
        removed: ['OldExport'],
        common_count: 1,
      },
      sections: {
        added: ['.rsrc'],
        removed: ['.reloc'],
        size_changed: [{ name: '.text', size_a: 1024, size_b: 2048 }],
      },
      strings: {
        added: ['https://c2.example/api'],
        removed: ['debug mode'],
        common_count: 4,
      },
    },
    attack_delta: {
      techniques_added: [{ id: 'T1059', name: 'Command and Scripting Interpreter' }],
      techniques_removed: [],
      confidence_changed: [
        { id: 'T1055', name: 'Process Injection', confidence_a: 0.4, confidence_b: 0.8 },
      ],
    },
    summary_stats: {
      functions_added: 1,
      functions_removed: 1,
      functions_modified: 2,
      imports_added: 1,
      imports_removed: 1,
      strings_added: 1,
      strings_removed: 1,
      attack_techniques_added: 1,
      attack_techniques_removed: 0,
    },
    errors: [],
    warnings: [],
  }
}

describe('binary-diff metadata/search/profile', () => {
  test('declares artifact, evidence, workflow, runtime policy, and worker backend metadata', () => {
    expect(binaryDiffToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'binary-diff',
        'variant-comparison',
        'function-comparison',
        'structural-delta',
        'radiff2-readiness',
      ])
    )
    expect(binaryDiffToolDefinition.artifacts).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: BINARY_DIFF_ARTIFACT_TYPE })])
    )
    expect(binaryDiffToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'function-similarity' }),
        expect.objectContaining({ category: 'structural-delta' }),
        expect.objectContaining({ category: 'attack' }),
        expect.objectContaining({ category: 'provenance' }),
      ])
    )
    expect(binaryDiffToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'binary-diff.variant-comparison',
          nextTools: expect.arrayContaining(['analysis.evidence.graph', 'report.generate']),
        }),
        expect.objectContaining({ id: 'binary-diff.structural-delta-handoff' }),
      ])
    )
    expect(binaryDiffToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(binaryDiffToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'RizinRadiff2',
        adapter: 'binary-diff.radiff2',
        availability: 'optional',
      })
    )
    expect(binaryDiffSummaryToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'binary-diff.report-summary',
        requiredArtifacts: [BINARY_DIFF_ARTIFACT_TYPE],
      })
    )
  })

  test('workflow.search matches binary diff, variant/function comparison, structural delta, and radiff2 readiness queries', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerPlugin(binaryDiffPlugin, toolNames(binaryDiffPlugin))
    const handler = createWorkflowSearchHandler(createPluginManager([binaryDiffPlugin]))

    for (const query of [
      'binary diff variant comparison',
      'function comparison radiff2 readiness',
      'structural delta imports exports strings attack',
    ]) {
      const result = await handler({ query, goal: 'reverse', top_k: 5 })
      expect(result.ok).toBe(true)
      const data = result.data as any
      const match = data.results.find((item: any) => item.plugin_id === 'binary-diff')
      expect(match).toEqual(
        expect.objectContaining({
          recommended_tools: expect.arrayContaining(['binary.diff']),
          workflow_id: expect.stringMatching(/^binary-diff\./),
        })
      )
      expect(match.matched_profile_fields.join(' ')).toMatch(/query terms|workflow\/tools/)
    }
  })

  test('builds similarity, evidence, and workflow handoff from an existing diff result', () => {
    const diff = sampleDiff()
    const evidenceSummary = buildBinaryDiffEvidenceSummary(diff)
    const handoff = buildBinaryDiffWorkflowHandoff(diff)

    expect(evidenceSummary.delta_counts).toEqual(
      expect.objectContaining({
        functions: { added: 1, removed: 1, modified: 2 },
        imports: { added: 1, removed: 1, common: 3 },
      })
    )
    expect(evidenceSummary.similarity_profile).toEqual(
      expect.objectContaining({
        schema: 'rikune.binary_diff.similarity_profile.v1',
        classification: expect.stringMatching(/variant|divergence|identical/),
      })
    )
    expect(handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'structural-delta',
          next_tools: expect.arrayContaining(['analysis.evidence.graph', 'report.generate']),
        }),
        expect.objectContaining({
          goal: 'function-comparison',
          backend: 'radiff2',
        }),
      ])
    )
    expect(handoff.dynamic_boundary).toEqual(
      expect.objectContaining({ status: 'static_only', no_live_sample_execution: true })
    )
  })

  test('summary includes similarity, provenance/readiness, exports, and sections when metadata exists', () => {
    const diff = sampleDiff()
    diff.similarity_profile = buildBinaryDiffEvidenceSummary(diff).similarity_profile as any
    diff.provenance = {
      schema: 'rikune.binary_diff.provenance.v1',
      sources: {
        function_diff: {
          backend: 'radiff2',
          ok: true,
          available: true,
        },
      },
    }

    const summary = generateDiffSummary(diff, 4000)

    expect(summary).toContain('Similarity:')
    expect(summary).toContain('Provenance and Readiness')
    expect(summary).toContain('Export Changes')
    expect(summary).toContain('Section Changes')
  })

  test('handler returns structural and ATT&CK handoff metadata without running function diff', async () => {
    const sampleA = 'sha256:aaaaaaaa'
    const sampleB = 'sha256:bbbbbbbb'
    const evidenceBySample: Record<string, any[]> = {
      [sampleA]: [
        { evidence_family: 'imports', result_json: { imports: ['kernel32.dll:CreateFileA'] } },
        { evidence_family: 'exports', result_json: { exports: ['DllMain'] } },
        {
          evidence_family: 'structure',
          result_json: { sections: [{ name: '.text', size: 1024 }] },
        },
        { evidence_family: 'strings', result_json: { strings: ['stable-string'] } },
        {
          evidence_family: 'attack',
          result_json: {
            techniques: [{ id: 'T1055', name: 'Process Injection', confidence: 0.4 }],
          },
        },
      ],
      [sampleB]: [
        {
          evidence_family: 'imports',
          result_json: { imports: ['kernel32.dll:CreateFileA', 'ws2_32.dll:connect'] },
        },
        { evidence_family: 'exports', result_json: { exports: ['DllMain', 'NewExport'] } },
        {
          evidence_family: 'structure',
          result_json: {
            sections: [
              { name: '.text', size: 2048 },
              { name: '.rsrc', size: 256 },
            ],
          },
        },
        {
          evidence_family: 'strings',
          result_json: { strings: ['stable-string', 'https://c2.example/api'] },
        },
        {
          evidence_family: 'attack',
          result_json: {
            techniques: [
              { id: 'T1055', name: 'Process Injection', confidence: 0.8 },
              { id: 'T1059', name: 'Command and Scripting Interpreter', confidence: 0.7 },
            ],
          },
        },
      ],
    }
    const database = {
      findSample: jest.fn(() => ({ id: 'sample' })),
      findAnalysisEvidenceBySample: jest.fn((sampleId: string) => evidenceBySample[sampleId] ?? []),
    }
    const handler = createBinaryDiffHandler({} as any, database as any)

    const result = await handler({
      sample_id_a: sampleA,
      sample_id_b: sampleB,
      include_function_diff: false,
      include_structural_diff: true,
      include_attack_diff: true,
    })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.structural_delta.imports.added).toContain('ws2_32.dll:connect')
    expect(data.structural_delta.exports.added).toContain('NewExport')
    expect(data.attack_delta.techniques_added).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'T1059' })])
    )
    expect(data.provenance.sources.function_diff.requested).toBe(false)
    expect(data.evidence_summary.delta_counts.sections).toEqual(
      expect.objectContaining({ added: 1, size_changed: 1 })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'structural-delta',
          evidence: expect.arrayContaining(['imports', 'exports', 'sections', 'strings', 'attack']),
        }),
      ])
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['analysis.evidence.graph', 'report.generate'])
    )
  })
})
