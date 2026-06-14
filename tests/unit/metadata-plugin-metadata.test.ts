import { describe, expect, test } from '@jest/globals'

import metadataPlugin from '../../src/plugins/metadata/index.js'
import {
  buildMetadataExtractProfile,
  metadataExtractToolDefinition,
  METADATA_EXTRACT_FOLLOW_UP_TOOLS,
} from '../../src/plugins/metadata/tools/metadata-extract.js'

function expectPassiveNoSideEffects(policy: Record<string, unknown> | undefined) {
  expect(policy).toEqual(
    expect.objectContaining({
      passiveByDefault: true,
      requiresUserOptIn: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      networkPolicy: 'disabled',
    })
  )
}

describe('metadata.extract metadata deepening', () => {
  test('plugin and tool expose unknown-file search profile tags', () => {
    expect(metadataPlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['unknown', 'generic-file', 'raw-file', 'binary', 'container'])
    )
    expect(metadataPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'file-profile',
        'search-profile',
        'unknown-file-triage',
        'generic-file-triage',
        'metadata-only-handoff',
        'workflow-handoff',
      ])
    )
    expect(metadataExtractToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['unknown', 'generic-file', 'pe', 'elf', 'office', 'pdf'])
    )
    expect(metadataExtractToolDefinition.aspects?.evidence).toEqual(
      expect.arrayContaining(['file-metadata', 'package-metadata', 'workflow', 'search-profile'])
    )
  })

  test('declares passive file profile workflow recipe and follow-up chain', () => {
    const recipe = metadataExtractToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'metadata.passive-file-profile'
    )

    expect(metadataExtractToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'metadata',
          mimeTypes: expect.arrayContaining(['application/json']),
        }),
      ])
    )
    expect(metadataExtractToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'file-metadata',
          artifactTypes: expect.arrayContaining(['metadata']),
        }),
        expect.objectContaining({
          category: 'workflow',
          artifactTypes: expect.arrayContaining(['metadata']),
        }),
        expect.objectContaining({
          category: 'provenance',
          artifactTypes: expect.arrayContaining(['metadata']),
        }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['metadata.extract'],
        nextTools: expect.arrayContaining([
          'container.structure.analyze',
          'strings.extract',
          'analysis.evidence.graph',
          'report.generate',
        ]),
        requiredArtifacts: expect.arrayContaining(['sample']),
        producesArtifacts: expect.arrayContaining(['metadata']),
        evidence: expect.arrayContaining(['file-metadata', 'workflow', 'provenance']),
        safety: expect.arrayContaining([
          'passive',
          'no_network_by_default',
          'no_mutation',
          'no_live_sample_by_default',
          'no_sample_execution',
        ]),
      })
    )
    expect(METADATA_EXTRACT_FOLLOW_UP_TOOLS).toEqual(
      expect.arrayContaining([
        'container.structure.analyze',
        'strings.extract',
        'analysis.evidence.graph',
        'report.generate',
      ])
    )
  })

  test('declares no-network no-mutation runtime policy without a worker backend', () => {
    expect(metadataExtractToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_network',
        'no_network_by_default',
        'no_mutation',
        'no_live_sample',
        'no_live_sample_by_default',
      ])
    )
    expectPassiveNoSideEffects(
      metadataExtractToolDefinition.runtimePolicy as Record<string, unknown>
    )
    expect(metadataExtractToolDefinition.workerBackend).toBeUndefined()
  })

  test('builds result-level passive profile handoff for generic file routing', () => {
    const profile = buildMetadataExtractProfile({
      sampleId: 'sample-meta',
      metadata: {
        'File:FileType': 'ZIP',
        'File:MIMEType': 'application/zip',
        'File:FileSize': '42 KiB',
        'File:FileModifyDate': '2026:06:09 12:00:00+08:00',
        'ZIP:ZipRequiredVersion': 20,
      },
    })

    expect(profile.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.metadata_extract.evidence_summary.v1',
        source_tool: 'metadata.extract',
        sample_id: 'sample-meta',
        artifact_type: 'metadata',
        file_type: 'ZIP',
        mime_type: 'application/zip',
        metadata_field_count: 5,
        timestamp_metadata_present: true,
        static_only: true,
      })
    )
    expect(profile.evidence_summary.metadata_groups).toEqual(
      expect.objectContaining({ File: 4, ZIP: 1 })
    )
    expect(profile.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.metadata_extract.workflow_handoff.v1',
        handoff_mode: 'metadata_file_profile_to_format_routing',
        source_tool: 'metadata.extract',
        sample_id: 'sample-meta',
        artifact_type: 'metadata',
      })
    )
    expect(profile.workflow_handoff.artifact_contract).toEqual(
      expect.objectContaining({
        consumes: ['sample'],
        produces: ['metadata'],
      })
    )
    expect(profile.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'format-specific-inventory',
          priority: 'high',
          next_tools: expect.arrayContaining([
            'container.structure.analyze',
            'strings.extract',
            'analysis.evidence.graph',
          ]),
        }),
        expect.objectContaining({
          goal: 'strings-evidence-and-reporting',
          next_tools: expect.arrayContaining([
            'strings.extract',
            'analysis.evidence.graph',
            'report.generate',
          ]),
        }),
      ])
    )
    expect(profile.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        runtime_started_by_tool: false,
        decompiler_launched_by_tool: false,
      })
    )
    expect(profile.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.metadata_extract.quality_gates.v1',
        passive_metadata_only: true,
        metadata_fields_present: true,
        file_identity_present: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(profile.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'artifact.read',
        'container.structure.analyze',
        'strings.extract',
        'analysis.evidence.graph',
        'report.generate',
      ])
    )
  })
})
