import { describe, expect, jest, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import kbCollaborationPlugin from '../../src/plugins/kb-collaboration/index.js'
import { createKbContextSuggestHandler } from '../../src/plugins/kb-collaboration/tools/kb-context-suggest.js'

describe('kb.context.suggest', () => {
  test('suggests local analysis-memory context with provenance', async () => {
    const database = {
      findSample: jest.fn(() => ({ id: 'sha256:kb' })),
      findAnalysisEvidenceBySample: jest.fn(() => [
        { evidence_family: 'function_map' },
        { evidence_family: 'yara_rule' },
      ]),
      listArtifacts: jest.fn(() => [
        { id: 'a1', type: 'decompilation' },
        { id: 'a2', type: 'sigma_rule' },
      ]),
    }
    const handler = createKbContextSuggestHandler({ database } as any)

    const result = await handler({
      sample_id: 'sha256:kb',
      goal: 'reuse prior function knowledge',
      evidence_tags: ['ghidra'],
      max_recommendations: 3,
    })

    expect(result.ok).toBe(true)
    expect(result.data?.result_mode).toBe('kb_context_suggest')
    expect(result.data?.analysis_memory.evidence_tags).toEqual(
      expect.arrayContaining(['ghidra', 'function_map', 'yara_rule', 'decompilation'])
    )
    expect(result.data?.recommendations[0].tool).toBe('kb.function.match')
    expect(result.data?.recommended_next_tools).toEqual(
      expect.arrayContaining(['kb.function.match', 'analysis.notes'])
    )
    expect(result.data?.provenance).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ source: 'analysis_evidence', family: 'function_map' }),
        expect.objectContaining({ source: 'artifact', type: 'sigma_rule' }),
      ])
    )
  })

  test('registers as analysis-memory workflow tool', () => {
    const database = {
      findSample: jest.fn(() => ({ id: 'sha256:kb' })),
      findAnalysisEvidenceBySample: jest.fn(() => []),
      listArtifacts: jest.fn(() => []),
    }
    const harness = createPluginTestHarness({
      deps: {
        workspaceManager: {},
        database,
      },
    })
    const names = harness.registerPlugin(kbCollaborationPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'kb.context.suggest'
    )

    expect(names).toContain('kb.context.suggest')
    expect(kbCollaborationPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining(['analysis-memory', 'knowledge-reuse'])
    )
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'kb.analysis-memory.reuse',
        nextTools: expect.arrayContaining(['kb.function.match', 'analysis.notes', 'rule.library']),
      })
    )
  })
})
