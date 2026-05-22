import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'sample.family.cluster'

export const SampleFamilyClusterInputSchema = z
  .object({
    samples: z.array(z.record(z.any())).min(1).default([]),
    binary_diffs: z.array(z.record(z.any())).optional().default([]),
    kb_context: z.any().optional(),
    min_shared_features: z.number().int().min(1).max(20).optional().default(2),
  })
  .passthrough()

export const SampleFamilyClusterOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
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
    capabilities: ['similarity', 'family-clustering', 'binary-diff', 'reporting', 'workflow-plan'],
    evidence: ['hashes', 'imports', 'strings', 'functions', 'provenance'],
  },
  artifacts: [
    {
      type: 'sample_family_cluster',
      description: 'Deterministic sample family cluster with explainable shared evidence',
    },
  ],
  evidence: [
    { category: 'hashes', artifactTypes: ['sample_family_cluster'] },
    { category: 'imports', artifactTypes: ['sample_family_cluster'] },
    { category: 'strings', artifactTypes: ['sample_family_cluster'] },
    { category: 'provenance', artifactTypes: ['sample_family_cluster'] },
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
      nextTools: ['binary.diff.summary', 'kb.context.suggest', 'report.generate'],
      requiredArtifacts: ['sample_similarity', 'binary_diff'],
      producesArtifacts: ['sample_family_cluster'],
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

  return {
    result_mode: 'sample_family_cluster',
    cluster_count: clusters.length,
    clusters,
    relationships,
    kb_handoff: {
      tool: 'kb.context.suggest',
      evidence: ['sample_family_cluster', 'shared_features', 'binary_diff_relationships'],
    },
    reporting_handoff: {
      tool: 'report.generate',
      summary_topics: ['family-level relationships', 'shared imports', 'shared functions'],
    },
    recommended_next_tools: ['binary.diff.summary', 'kb.context.suggest', 'report.generate'],
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
