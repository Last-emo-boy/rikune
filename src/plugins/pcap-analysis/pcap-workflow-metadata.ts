import type { ArtifactRef, ToolDefinition } from '../../types.js'

export const PCAP_NETWORK_EVIDENCE_TOOLS = [
  'artifact.read',
  'pcap.analyze',
  'pcap.dns.list',
  'pcap.extract.streams',
  'ioc.export',
  'analysis.evidence.graph',
  'report.generate',
]

export const PCAP_NETWORK_EVIDENCE = [
  'network',
  'timeline',
  'dns',
  'streams',
  'artifact',
  'workflow',
  'provenance',
]

export const PCAP_NETWORK_SAFETY = [
  'passive',
  'external_static_backend',
  'no_live_sample_by_default',
  'no_network_by_default',
]

export const PCAP_NETWORK_WORKFLOW_RECIPES: NonNullable<ToolDefinition['workflowRecipes']> = [
  {
    id: 'pcap.network-evidence-handoff',
    title: 'PCAP network evidence to IOC correlation and reporting',
    description:
      'Turn passive tshark protocol, DNS, and stream evidence into artifact-first IOC extraction, evidence graph, and reporting handoffs without replaying traffic or contacting observed hosts.',
    startsWith: ['pcap.analyze', 'pcap.dns.list', 'pcap.extract.streams'],
    nextTools: PCAP_NETWORK_EVIDENCE_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: ['pcap_analysis', 'pcap_dns_records', 'pcap_streams'],
    evidence: PCAP_NETWORK_EVIDENCE,
    safety: PCAP_NETWORK_SAFETY,
    runtimeBackends: ['tshark'],
  },
]

export interface PcapWorkflowEnvelopeInput {
  sourceTool: string
  sampleId?: string
  artifactType: string
  artifact?: ArtifactRef
  summary: string
  evidenceCounts: Record<string, number | boolean | string | null | undefined>
  recommendedNextTools: string[]
}

function compactCounts(
  counts: Record<string, number | boolean | string | null | undefined>
): Record<string, number | boolean | string> {
  return Object.fromEntries(
    Object.entries(counts).filter(
      (entry): entry is [string, number | boolean | string] =>
        entry[1] !== null && entry[1] !== undefined
    )
  )
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

export function buildPcapEvidenceSummary(
  input: PcapWorkflowEnvelopeInput
): Record<string, unknown> {
  return {
    schema: 'rikune.pcap_network.evidence_summary.v1',
    source_tool: input.sourceTool,
    sample_id: input.sampleId ?? null,
    artifact_type: input.artifactType,
    artifact_ref: input.artifact ?? null,
    evidence_counts: compactCounts(input.evidenceCounts),
    summary: input.summary,
    passive_network_capture_analysis: true,
  }
}

export function buildPcapWorkflowHandoff(
  input: PcapWorkflowEnvelopeInput
): Record<string, unknown> {
  const nextTools = uniqueStrings(input.recommendedNextTools)
  return {
    schema: 'rikune.pcap_network.workflow_handoff.v1',
    handoff_mode: 'pcap_network_evidence_to_correlation_reporting',
    source_tool: input.sourceTool,
    sample_id: input.sampleId ?? null,
    artifact_type: input.artifactType,
    recommended_next_tools: nextTools,
    artifact_contract: {
      consumes: ['sample bytes'],
      produces: [input.artifactType],
      expected_consumers: nextTools,
    },
    routing: [
      {
        goal: 'network-evidence-correlation',
        priority: input.artifact ? 'high' : 'normal',
        next_tools: ['artifact.read', 'analysis.evidence.graph'],
        required_evidence: [input.artifactType],
      },
      {
        goal: 'ioc-and-reporting',
        priority: 'normal',
        next_tools: ['ioc.export', 'analysis.evidence.graph', 'report.generate'],
        required_evidence: [input.artifactType, 'network indicators'],
      },
    ],
    dynamic_boundary: {
      static_backend_started: true,
      runtime_started_by_tool: false,
      sample_executed_by_tool: false,
      traffic_replayed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

export function buildPcapQualityGates(input: PcapWorkflowEnvelopeInput): Record<string, unknown> {
  return {
    schema: 'rikune.pcap_network.quality_gates.v1',
    passive_capture_analysis: true,
    external_static_backend_started: true,
    sample_executed_by_tool: false,
    traffic_replayed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    runtime_started_by_tool: false,
    artifact_persisted: Boolean(input.artifact),
    evidence_graph_handoff_ready: Boolean(input.artifact),
    analyst_review_required: true,
    evidence_counts: compactCounts(input.evidenceCounts),
  }
}

export function buildPcapWorkflowEnvelope(input: PcapWorkflowEnvelopeInput): {
  evidence_summary: Record<string, unknown>
  workflow_handoff: Record<string, unknown>
  quality_gates: Record<string, unknown>
} {
  return {
    evidence_summary: buildPcapEvidenceSummary(input),
    workflow_handoff: buildPcapWorkflowHandoff(input),
    quality_gates: buildPcapQualityGates(input),
  }
}
