import { describe, expect, jest, test } from '@jest/globals'

import kbCollaborationPlugin from '../../src/plugins/kb-collaboration/index.js'
import {
  createKbFunctionMatchHandler,
  enrichKbFunctionMatchResultData,
  kbFunctionMatchToolDefinition,
} from '../../src/plugins/kb-collaboration/tools/kb-function-match.js'
import { kbContextSuggestToolDefinition } from '../../src/plugins/kb-collaboration/tools/kb-context-suggest.js'

describe('kb-collaboration metadata deepening', () => {
  test('declares passive function reuse search profile and workflow metadata', () => {
    const definition = kbFunctionMatchToolDefinition
    const recipe = definition.workflowRecipes?.find(
      (candidate) => candidate.id === 'kb.function-match.reuse-handoff'
    )

    expect(definition.aspects?.formats).toEqual(
      expect.arrayContaining([
        'analysis-evidence',
        'function',
        'function-index',
        'function-signature',
        'code-reuse',
      ])
    )
    expect(definition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'analysis-memory',
        'knowledge-reuse',
        'function-matching',
        'code-reuse-detection',
        'workflow-handoff',
        'search-profile',
      ])
    )
    expect(kbCollaborationPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noSampleExecution: true,
      })
    )
    expect(definition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'function_match',
          mime: 'application/json',
        }),
      ])
    )
    expect(definition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'analysis-memory',
          artifactTypes: expect.arrayContaining(['function_match']),
        }),
        expect.objectContaining({
          category: 'functions',
          artifactTypes: expect.arrayContaining(['function_match']),
        }),
        expect.objectContaining({
          category: 'code-reuse',
          artifactTypes: expect.arrayContaining(['function_match']),
        }),
        expect.objectContaining({
          category: 'workflow',
          artifactTypes: expect.arrayContaining(['function_match']),
        }),
        expect.objectContaining({
          category: 'provenance',
          artifactTypes: expect.arrayContaining(['function_match']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['kb.function.match'],
        nextTools: expect.arrayContaining([
          'artifact.read',
          'analysis.evidence.graph',
          'analysis.notes',
          'kb.context.suggest',
          'kb.export',
        ]),
        requiredArtifacts: expect.arrayContaining([
          'sample',
          'analysis_evidence',
          'function_index',
        ]),
        producesArtifacts: expect.arrayContaining(['function_match']),
        evidence: expect.arrayContaining(['analysis-memory', 'functions', 'code-reuse']),
        safety: expect.arrayContaining(['passive', 'no_network_by_default', 'no_mutation']),
        runtimeBackends: expect.arrayContaining(['local']),
      })
    )
    expect(definition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        allowedBackends: ['local'],
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noSampleExecution: true,
      })
    )
  })

  test('keeps context suggestion activation scoped to its own entry tool', () => {
    const definition = kbContextSuggestToolDefinition
    const recipe = definition.workflowRecipes?.find(
      (candidate) => candidate.id === 'kb.analysis-memory.reuse'
    )

    expect(definition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'analysis_memory',
          mime: 'application/json',
        }),
      ])
    )
    expect(definition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'analysis-memory',
          artifactTypes: expect.arrayContaining(['analysis_memory']),
        }),
        expect.objectContaining({
          category: 'workflow',
          artifactTypes: expect.arrayContaining(['analysis_memory']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: expect.arrayContaining(['kb.context.suggest', 'analysis.notes']),
        nextTools: expect.arrayContaining([
          'kb.function.match',
          'analysis.notes',
          'rule.library',
          'kb.export',
        ]),
        producesArtifacts: expect.arrayContaining(['analysis_memory']),
        runtimeBackends: expect.arrayContaining(['local']),
      })
    )
    expect(definition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noSampleExecution: true,
      })
    )
  })

  test('adds function match handoff envelope without execution, network, or mutation', () => {
    const result = enrichKbFunctionMatchResultData({
      sample_id: 'sha256:kb-demo',
      target_function_count: 3,
      reference_function_count: 5,
      match_count: 2,
      exact_matches: 1,
      high_confidence_matches: 1,
      min_confidence: 0.75,
      match_against: ['sha256:ref-a', 'sha256:ref-b'],
      matches: [
        {
          target_function: 'sub_401000',
          target_address: '0x401000',
          matched_function: 'decrypt_config',
          matched_sample_id: 'sha256:ref-a',
          matched_address: '0x402000',
          confidence: 1,
        },
        {
          target_function: 'sub_401100',
          target_address: '0x401100',
          matched_function: 'resolve_api',
          matched_sample_id: 'sha256:ref-b',
          matched_address: '0x403000',
          confidence: 0.86,
        },
      ],
    })

    expect(result.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_network: true,
        no_mutation: true,
        no_sample_execution: true,
        no_live_sample: true,
      })
    )
    expect(result.workflowRecipes).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'kb.function-match.reuse-handoff' })])
    )
    expect(result.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'artifact.read',
        'analysis.evidence.graph',
        'analysis.notes',
        'rule.library',
        'kb.context.suggest',
        'kb.export',
      ])
    )
    expect(result.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.kb_function_match.evidence_summary.v1',
        source_tool: 'kb.function.match',
        artifact_type: 'function_match',
        sample_id: 'sha256:kb-demo',
        static_only: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(result.evidence_summary.function_counts).toEqual(
      expect.objectContaining({
        target_functions: 3,
        reference_functions: 5,
        matches: 2,
        exact_matches: 1,
        high_confidence_matches: 1,
      })
    )
    expect(result.evidence_summary.match_scope).toEqual(
      expect.objectContaining({
        match_against: ['sha256:ref-a', 'sha256:ref-b'],
        all_kb_entries_requested: false,
        min_confidence: 0.75,
      })
    )
    expect(result.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.kb_function_match.workflow_handoff.v1',
        handoff_mode: 'function_reuse_to_analysis_memory_and_evidence_graph',
        artifact_type: 'function_match',
        recommended_next_tools: expect.arrayContaining([
          'analysis.evidence.graph',
          'analysis.notes',
          'kb.context.suggest',
        ]),
      })
    )
    expect(result.workflow_handoff.artifact_contract).toEqual(
      expect.objectContaining({
        consumes: ['analysis_evidence', 'function_index'],
        produces: ['function_match'],
        expected_consumers: expect.arrayContaining([
          'workflow.search',
          'artifact.read',
          'kb.context.suggest',
          'analysis.evidence.graph',
        ]),
      })
    )
    expect(result.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'exact-and-high-confidence-function-reuse',
          priority: 'high',
          consumes: ['function_match'],
          produces: ['function_reuse_evidence'],
        }),
        expect.objectContaining({
          goal: 'analysis-memory-context-refresh',
          consumes: ['function_match'],
          produces: ['analysis_memory'],
        }),
      ])
    )
    expect(result.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        binary_modified_by_tool: false,
      })
    )
    expect(result.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.kb_function_match.quality_gates.v1',
        passive_local_kb_match: true,
        target_functions_present: true,
        reference_functions_present: true,
        matches_present: true,
        exact_or_high_confidence_matches_present: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
  })

  test('handler persists enriched function match payload while preserving legacy fields', async () => {
    const persistStaticAnalysisJsonArtifact = jest.fn(async () => ({
      id: 'artifact:function-match',
      type: 'function_match',
      path: 'artifacts/function-match.json',
      sha256: '0'.repeat(64),
    }))
    const database = {
      findSample: jest.fn(() => ({ id: 'sample', sha256: 'abc' })),
      findAnalysisEvidenceBySample: jest.fn((sampleId: string) => {
        if (sampleId === 'sha256:target') {
          return [
            {
              evidence_family: 'function_index',
              result_json: {
                data: {
                  functions: [
                    {
                      address: '0x401000',
                      name: 'sub_401000',
                      hash: 'b'.repeat(64),
                      size: 64,
                      api_calls: ['CreateFileW'],
                    },
                  ],
                },
              },
            },
          ]
        }
        return [
          {
            evidence_family: 'function_index',
            result_json: {
              functions: [
                {
                  address: '0x402000',
                  name: 'known_loader',
                  hash: 'b'.repeat(64),
                  size: 64,
                  api_calls: ['CreateFileW'],
                },
              ],
            },
          },
        ]
      }),
    }
    const handler = createKbFunctionMatchHandler({
      workspaceManager: {},
      database,
      persistStaticAnalysisJsonArtifact,
    } as any)

    const result = await handler({
      sample_id: 'sha256:target',
      match_against: ['sha256:reference'],
      min_confidence: 0.7,
      max_matches: 10,
    })

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        sample_id: 'sha256:target',
        target_function_count: 1,
        reference_function_count: 1,
        match_count: 1,
        exact_matches: 1,
        recommended_next_tools: expect.arrayContaining([
          'analysis.evidence.graph',
          'kb.context.suggest',
          'kb.export',
        ]),
        evidence_summary: expect.objectContaining({
          schema: 'rikune.kb_function_match.evidence_summary.v1',
          sample_id: 'sha256:target',
        }),
        quality_gates: expect.objectContaining({
          passive_local_kb_match: true,
          matches_present: true,
        }),
      })
    )
    expect((result.data as any).matches[0]).toEqual(
      expect.objectContaining({
        target_function: 'sub_401000',
        matched_function: 'known_loader',
        confidence: 1,
      })
    )
    expect(persistStaticAnalysisJsonArtifact).toHaveBeenCalledWith(
      expect.anything(),
      database,
      'sha256:target',
      'function_match',
      'kb-function-match',
      expect.objectContaining({
        workflow_handoff: expect.objectContaining({
          schema: 'rikune.kb_function_match.workflow_handoff.v1',
        }),
        matches: expect.arrayContaining([
          expect.objectContaining({ matched_function: 'known_loader' }),
        ]),
      })
    )
  })
})
