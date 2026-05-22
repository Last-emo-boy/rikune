import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import similarityPlugin from '../../src/plugins/similarity/index.js'
import { buildSampleFamilyCluster } from '../../src/plugins/similarity/tools/sample-family-cluster.js'

describe('sample.family.cluster', () => {
  test('clusters samples deterministically from shared features and diff evidence', () => {
    const result = buildSampleFamilyCluster({
      samples: [
        {
          sample_id: 'sha256:a',
          imports: ['CreateFileW', 'InternetOpenA', 'VirtualAlloc'],
          strings: ['campaign-alpha', 'https://c2.example.test/a'],
          functions: ['decrypt_config', 'beacon_loop'],
          family: 'demo',
        },
        {
          sample_id: 'sha256:b',
          imports: ['CreateFileW', 'InternetOpenA', 'VirtualAlloc'],
          strings: ['campaign-alpha', 'https://c2.example.test/b'],
          functions: ['decrypt_config', 'beacon_loop'],
          family: 'demo',
        },
        {
          sample_id: 'sha256:c',
          imports: ['RegOpenKeyW'],
          strings: ['unrelated'],
          functions: ['main'],
        },
      ],
      binary_diffs: [{ sample_id_a: 'sha256:a', sample_id_b: 'sha256:b', similarity: 0.82 }],
      min_shared_features: 2,
    })

    expect(result.result_mode).toBe('sample_family_cluster')
    expect(result.clusters).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          members: ['sha256:a', 'sha256:b'],
          suggested_family_label: 'demo',
        }),
      ])
    )
    expect(result.relationships).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          source: 'sha256:a',
          target: 'sha256:b',
          shared_feature_count: expect.any(Number),
        }),
      ])
    )
    expect(result.kb_handoff.tool).toBe('kb.context.suggest')
    expect(result.reporting_handoff.tool).toBe('report.generate')
  })

  test('registers similarity family workflow metadata', () => {
    const harness = createPluginTestHarness({
      deps: { workspaceManager: {}, database: {} },
    })
    const names = harness.registerPlugin(similarityPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'sample.family.cluster'
    )

    expect(names).toContain('sample.family.cluster')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'similarity.family-cluster',
        nextTools: expect.arrayContaining(['binary.diff.summary', 'kb.context.suggest']),
      })
    )
  })
})
