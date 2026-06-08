import { describe, expect, test } from '@jest/globals'
import pcapAnalysisPlugin from '../../src/plugins/pcap-analysis/index.js'
import {
  buildPcapWorkflowEnvelope,
  PCAP_NETWORK_WORKFLOW_RECIPES,
} from '../../src/plugins/pcap-analysis/pcap-workflow-metadata.js'
import { pcapAnalyzeToolDefinition } from '../../src/plugins/pcap-analysis/tools/pcap-analyze.js'
import { pcapDnsListToolDefinition } from '../../src/plugins/pcap-analysis/tools/pcap-dns-list.js'
import { pcapExtractStreamsToolDefinition } from '../../src/plugins/pcap-analysis/tools/pcap-extract-streams.js'

describe('pcap-analysis workflow profile metadata', () => {
  test('plugin exposes network evidence handoff search profile aspects', () => {
    expect(pcapAnalysisPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'packet-analysis',
        'dns-analysis',
        'stream-extraction',
        'workflow-handoff',
        'evidence-correlation',
        'reporting',
      ])
    )
    expect(pcapAnalysisPlugin.aspects?.evidence).toEqual(
      expect.arrayContaining(['network', 'timeline', 'dns', 'streams', 'workflow', 'provenance'])
    )
  })

  test('pcap tools declare shared network evidence workflow recipe', () => {
    for (const definition of [
      pcapAnalyzeToolDefinition,
      pcapDnsListToolDefinition,
      pcapExtractStreamsToolDefinition,
    ]) {
      expect(definition.workflowRecipes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'pcap.network-evidence-handoff',
            startsWith: expect.arrayContaining([
              'pcap.analyze',
              'pcap.dns.list',
              'pcap.extract.streams',
            ]),
            nextTools: expect.arrayContaining([
              'artifact.read',
              'ioc.export',
              'analysis.evidence.graph',
              'report.generate',
            ]),
            producesArtifacts: expect.arrayContaining([
              'pcap_analysis',
              'pcap_dns_records',
              'pcap_streams',
            ]),
            evidence: expect.arrayContaining(['network', 'timeline', 'dns', 'streams', 'workflow']),
          }),
        ])
      )
      expect(definition.aspects?.capabilities).toEqual(
        expect.arrayContaining(['workflow-handoff', 'evidence-correlation'])
      )
    }
    expect(PCAP_NETWORK_WORKFLOW_RECIPES).toHaveLength(1)
  })

  test('builds standard result envelope for pcap network evidence', () => {
    const envelope = buildPcapWorkflowEnvelope({
      sourceTool: 'pcap.dns.list',
      sampleId: `sha256:${'a'.repeat(64)}`,
      artifactType: 'pcap_dns_records',
      artifact: {
        id: 'artifact-pcap-dns',
        type: 'pcap_dns_records',
        path: 'artifacts/pcap/dns.json',
        sha256: 'b'.repeat(64),
      },
      summary: '2 DNS queries, 1 unique domain.',
      evidenceCounts: {
        dns_query_count: 2,
        unique_domain_count: 1,
      },
      recommendedNextTools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
    })

    expect(envelope.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.pcap_network.evidence_summary.v1',
        source_tool: 'pcap.dns.list',
        artifact_type: 'pcap_dns_records',
      })
    )
    expect(envelope.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.pcap_network.workflow_handoff.v1',
        handoff_mode: 'pcap_network_evidence_to_correlation_reporting',
        recommended_next_tools: expect.arrayContaining([
          'artifact.read',
          'analysis.evidence.graph',
          'report.generate',
        ]),
      })
    )
    expect(envelope.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.pcap_network.quality_gates.v1',
        passive_capture_analysis: true,
        sample_executed_by_tool: false,
        traffic_replayed_by_tool: false,
        network_accessed_by_tool: false,
        artifact_persisted: true,
        evidence_graph_handoff_ready: true,
      })
    )
  })
})
