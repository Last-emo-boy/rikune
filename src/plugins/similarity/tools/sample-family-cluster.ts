import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'sample.family.cluster'
const TOOL_VERSION = '0.2.0'
const SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE = 'sample_family_cluster'
const SAMPLE_FAMILY_CLUSTER_RECOMMENDED_NEXT_TOOLS = [
  'binary.diff.summary',
  'kb.context.suggest',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

export const SampleFamilyClusterInputSchema = z
  .object({
    samples: z.array(z.record(z.string(), z.any())).min(1).default([]),
    binary_diffs: z.array(z.record(z.string(), z.any())).optional().default([]),
    kb_context: z.any().optional(),
    min_shared_features: z.number().int().min(1).max(20).optional().default(2),
  })
  .passthrough()

const SampleFamilyClusterDataSchema = z
  .object({
    schema: z.literal('rikune.sample_family_cluster.v1'),
    tool_version: z.string(),
    result_mode: z.literal('sample_family_cluster'),
    cluster_count: z.number().int().nonnegative(),
    clusters: z.array(z.record(z.string(), z.any())),
    relationships: z.array(z.record(z.string(), z.any())),
    evidence_summary: z.record(z.string(), z.any()),
    workflow_handoff: z.record(z.string(), z.any()),
    route_profile: z.record(z.string(), z.any()),
    quality_gates: z.record(z.string(), z.any()),
    kb_handoff: z.record(z.string(), z.any()),
    reporting_handoff: z.record(z.string(), z.any()),
    recommended_next_tools: z.array(z.string()),
    safety_notes: z.array(z.string()),
  })
  .passthrough()

export const SampleFamilyClusterOutputSchema = z.object({
  ok: z.boolean(),
  data: SampleFamilyClusterDataSchema.optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const sampleFamilyClusterToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build deterministic sample-family clusters from existing hash, fuzzy hash, import, string, function, and binary diff evidence. It is fixture-friendly and does not require ssdeep/TLSH native backends.',
  inputSchema: SampleFamilyClusterInputSchema,
  outputSchema: SampleFamilyClusterOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'apk', 'dotnet', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: [
      'similarity',
      'family-clustering',
      'variant-analysis',
      'binary-diff',
      'reporting',
      'workflow-plan',
      'workflow-handoff',
    ],
    evidence: ['hashes', 'imports', 'strings', 'functions', 'provenance'],
  },
  artifacts: [
    {
      type: SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE,
      description: 'Deterministic sample family cluster with explainable shared evidence',
    },
  ],
  evidence: [
    { category: 'hashes', artifactTypes: [SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE] },
    { category: 'imports', artifactTypes: [SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'similarity.family-cluster',
      title: 'Sample family cluster and binary diff workflow',
      startsWith: [
        'sample.similarity',
        'sample.cluster.fuzzy',
        'binary.diff',
        'sample.family.cluster',
      ],
      nextTools: SAMPLE_FAMILY_CLUSTER_RECOMMENDED_NEXT_TOOLS,
      requiredArtifacts: ['sample_similarity', 'binary_diff'],
      producesArtifacts: [SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE],
      evidence: ['hashes', 'imports', 'strings', 'functions', 'provenance'],
      safety: ['passive', 'no_network_by_default'],
    },
  ],
}

type SampleRow = Record<string, any>

function stringList(value: unknown): string[] {
  if (!value) return []
  if (Array.isArray(value)) {
    return value
      .flatMap((item) => stringList(item))
      .map((item) => item.trim())
      .filter(Boolean)
  }
  if (typeof value === 'string') return value.trim() ? [value.trim()] : []
  if (typeof value === 'number') return [String(value)]
  if (typeof value === 'object') {
    const obj = value as Record<string, any>
    return stringList(obj.name ?? obj.value ?? obj.import ?? obj.function ?? obj.string)
  }
  return []
}

function sampleId(row: SampleRow, index: number): string {
  return String(row.sample_id ?? row.id ?? row.sha256 ?? `sample-${index + 1}`)
}

function featureSet(row: SampleRow): Set<string> {
  const values = [
    ...stringList(row.sha256).map((value) => `hash:${value}`),
    ...stringList(row.fuzzy_hash ?? row.ssdeep ?? row.tlsh).map((value) => `fuzzy:${value}`),
    ...stringList(row.imports).map((value) => `import:${value.toLowerCase()}`),
    ...stringList(row.strings)
      .filter((value) => value.length >= 5)
      .slice(0, 100)
      .map((value) => `string:${value.toLowerCase()}`),
    ...stringList(row.functions).map((value) => `function:${value.toLowerCase()}`),
    ...stringList(row.family ?? row.family_label).map((value) => `family:${value.toLowerCase()}`),
  ]
  return new Set(values)
}

function connectedComponents(nodes: string[], edges: Array<[string, string]>) {
  const adjacency = new Map(nodes.map((node) => [node, new Set<string>()]))
  for (const [a, b] of edges) {
    adjacency.get(a)?.add(b)
    adjacency.get(b)?.add(a)
  }
  const visited = new Set<string>()
  const clusters: string[][] = []
  for (const node of nodes) {
    if (visited.has(node)) continue
    const stack = [node]
    const members: string[] = []
    while (stack.length) {
      const current = stack.pop()!
      if (visited.has(current)) continue
      visited.add(current)
      members.push(current)
      for (const next of adjacency.get(current) ?? []) {
        if (!visited.has(next)) stack.push(next)
      }
    }
    clusters.push(members.sort())
  }
  return clusters
}

function diffEdges(binaryDiffs: SampleRow[]): Array<[string, string]> {
  return binaryDiffs
    .map((diff) => {
      const a = diff.sample_id_a ?? diff.a ?? diff.left
      const b = diff.sample_id_b ?? diff.b ?? diff.right
      const similarity = Number(
        diff.similarity ?? diff.score ?? diff.summary_stats?.similarity ?? 0
      )
      return a && b && similarity >= 0.5 ? ([String(a), String(b)] as [string, string]) : null
    })
    .filter((edge): edge is [string, string] => Boolean(edge))
}

function average(values: number[]): number {
  if (values.length === 0) return 0
  return values.reduce((sum, value) => sum + value, 0) / values.length
}

function topSharedFeatures(clusters: Array<Record<string, any>>) {
  const counts = new Map<string, number>()
  for (const cluster of clusters) {
    const sharedFeatures = Array.isArray(cluster.shared_features) ? cluster.shared_features : []
    for (const entry of sharedFeatures) {
      const feature = String(entry?.feature ?? '')
      if (!feature) continue
      counts.set(feature, (counts.get(feature) ?? 0) + Number(entry?.count ?? 1))
    }
  }
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 20)
    .map(([feature, count]) => ({ feature, count }))
}

function relationshipDiffCandidates(relationships: Array<Record<string, unknown>>) {
  return relationships
    .map((relationship) => ({
      sample_id_a: String(relationship.source ?? ''),
      sample_id_b: String(relationship.target ?? ''),
      confidence: Number(relationship.confidence ?? 0),
      shared_feature_count: Number(relationship.shared_feature_count ?? 0),
    }))
    .filter((candidate) => candidate.sample_id_a && candidate.sample_id_b)
    .sort(
      (a, b) =>
        b.confidence - a.confidence ||
        b.shared_feature_count - a.shared_feature_count ||
        a.sample_id_a.localeCompare(b.sample_id_a)
    )
    .slice(0, 20)
}

export function buildSampleFamilyCluster(rawInput: unknown) {
  const input = SampleFamilyClusterInputSchema.parse(rawInput)
  const rows = input.samples
  const ids = rows.map(sampleId)
  const features = new Map<string, Set<string>>()
  rows.forEach((row, index) => features.set(ids[index], featureSet(row)))

  const relationships: Array<Record<string, unknown>> = []
  const edges: Array<[string, string]> = []
  for (let i = 0; i < ids.length; i += 1) {
    for (let j = i + 1; j < ids.length; j += 1) {
      const a = ids[i]
      const b = ids[j]
      const shared = Array.from(features.get(a) ?? []).filter((feature) =>
        features.get(b)?.has(feature)
      )
      if (shared.length >= input.min_shared_features) {
        edges.push([a, b])
        relationships.push({
          source: a,
          target: b,
          shared_feature_count: shared.length,
          shared_features: shared.sort().slice(0, 20),
          confidence: Math.min(0.95, 0.35 + shared.length * 0.1),
        })
      }
    }
  }
  for (const edge of diffEdges(input.binary_diffs)) {
    if (ids.includes(edge[0]) && ids.includes(edge[1])) edges.push(edge)
  }

  const clusters = connectedComponents(ids, edges).map((members, index) => {
    const memberFeatures = members.flatMap((member) => Array.from(features.get(member) ?? []))
    const counts = new Map<string, number>()
    for (const feature of memberFeatures) counts.set(feature, (counts.get(feature) ?? 0) + 1)
    const sharedFeatures = Array.from(counts.entries())
      .filter(([, count]) => count > 1)
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([feature, count]) => ({ feature, count }))
    return {
      id: `family-${index + 1}`,
      members,
      confidence: members.length > 1 ? Math.min(0.95, 0.45 + sharedFeatures.length * 0.08) : 0.2,
      shared_features: sharedFeatures.slice(0, 25),
      suggested_family_label:
        sharedFeatures.find((entry) => entry.feature.startsWith('family:'))?.feature.slice(7) ??
        `cluster-${index + 1}`,
    }
  })

  const singletonCount = clusters.filter((cluster) => cluster.members.length === 1).length
  const multiSampleClusters = clusters.filter((cluster) => cluster.members.length > 1)
  const groupedSampleCount = multiSampleClusters.reduce(
    (count, cluster) => count + cluster.members.length,
    0
  )
  const relationshipCandidates = relationshipDiffCandidates(relationships)
  const sharedFeatureSummary = topSharedFeatures(clusters)
  const clusterConfidences = clusters.map((cluster) => Number(cluster.confidence ?? 0))
  const knownFindings = multiSampleClusters.length > 0 ? ['family-cluster', 'variant-group'] : []
  const suspectedFindings =
    relationships.length > 0
      ? ['shared-code-or-campaign-evidence']
      : ['insufficient-shared-evidence']

  return {
    schema: 'rikune.sample_family_cluster.v1',
    tool_version: TOOL_VERSION,
    result_mode: 'sample_family_cluster',
    cluster_count: clusters.length,
    clusters,
    relationships,
    evidence_summary: {
      schema: 'rikune.sample_family_cluster.evidence_summary.v1',
      source_tool: TOOL_NAME,
      artifact_type: SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE,
      sample_count: ids.length,
      sample_ids: ids,
      cluster_count: clusters.length,
      multi_sample_cluster_count: multiSampleClusters.length,
      singleton_count: singletonCount,
      grouped_sample_count: groupedSampleCount,
      relationship_count: relationships.length,
      min_shared_features: input.min_shared_features,
      top_shared_features: sharedFeatureSummary,
      confidence_summary: {
        max_cluster_confidence: Math.max(0, ...clusterConfidences),
        average_cluster_confidence: Number(average(clusterConfidences).toFixed(3)),
      },
      known_findings: knownFindings,
      suspected_findings: suspectedFindings,
    },
    workflow_handoff: {
      schema: 'rikune.sample_family_cluster.workflow_handoff.v1',
      source_tool: TOOL_NAME,
      handoff_mode: 'family_cluster_to_variant_review',
      artifact_type: SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE,
      recommended_next_tools: SAMPLE_FAMILY_CLUSTER_RECOMMENDED_NEXT_TOOLS,
      artifact_contract: {
        produces: [SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE],
        persisted_by_tool: false,
        expected_consumers: [
          'binary.diff.summary',
          'kb.context.suggest',
          'analysis.evidence.graph',
          'report.generate',
        ],
      },
      binary_diff_candidates: relationshipCandidates,
      routing: [
        {
          goal: 'compare-family-members',
          next_tools: ['binary.diff.summary'],
          required_evidence: ['multi-sample clusters', 'relationship confidence'],
          candidate_pairs: relationshipCandidates.slice(0, 5),
        },
        {
          goal: 'reuse-family-knowledge',
          next_tools: ['kb.context.suggest'],
          required_evidence: ['suggested_family_label', 'shared_features'],
        },
        {
          goal: 'publish-family-evidence',
          next_tools: ['analysis.evidence.graph', 'report.generate'],
          required_evidence: ['clusters', 'relationships', 'top_shared_features'],
        },
        {
          goal: 'continue-profile-routing',
          next_tools: ['workflow.search'],
          query: 'family variant similarity binary diff shared features',
        },
      ],
    },
    route_profile: {
      schema: 'rikune.sample_family_cluster.route_profile.v1',
      source_tool: TOOL_NAME,
      artifact_type: SAMPLE_FAMILY_CLUSTER_ARTIFACT_TYPE,
      route_terms: ['similarity', 'family', 'variant', 'cluster', 'binary-diff', 'shared-features'],
      known_findings: knownFindings,
      suspected_findings: suspectedFindings,
      coverage_gap_domains:
        multiSampleClusters.length > 0
          ? ['variant-diff-review', 'family-kb-correlation']
          : ['insufficient-family-evidence'],
      recommended_tools: SAMPLE_FAMILY_CLUSTER_RECOMMENDED_NEXT_TOOLS,
    },
    quality_gates: {
      schema: 'rikune.sample_family_cluster.quality_gates.v1',
      passive_static_correlation: true,
      no_fuzzy_backend_required: true,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
      min_shared_features: input.min_shared_features,
      sample_count: ids.length,
      relationship_count: relationships.length,
      has_multi_sample_cluster: multiSampleClusters.length > 0,
    },
    kb_handoff: {
      tool: 'kb.context.suggest',
      evidence: ['sample_family_cluster', 'shared_features', 'binary_diff_relationships'],
      args_hint: {
        query: multiSampleClusters
          .map((cluster) => cluster.suggested_family_label)
          .filter(Boolean)
          .join(' '),
      },
    },
    reporting_handoff: {
      tool: 'report.generate',
      summary_topics: ['family-level relationships', 'shared imports', 'shared functions'],
    },
    recommended_next_tools: SAMPLE_FAMILY_CLUSTER_RECOMMENDED_NEXT_TOOLS,
    safety_notes: ['No fuzzy-hash backend, live analysis, or network lookup is required.'],
  }
}

export function createSampleFamilyClusterHandler() {
  return async (args: unknown): Promise<WorkerResult> => ({
    ok: true,
    data: buildSampleFamilyCluster(args),
    metrics: { elapsed_ms: 0, tool: TOOL_NAME },
  })
}
