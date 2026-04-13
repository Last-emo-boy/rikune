/**
 * sample.cluster.fuzzy — Batch fuzzy-hash clustering of multiple samples.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  normalizeError, runPythonJson,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolvePythonModuleBackend,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'sample.cluster.fuzzy'

export const sampleClusterFuzzyInputSchema = z.object({
  sample_ids: z.array(z.string()).min(2).max(200).describe('List of sample IDs to cluster.'),
  threshold: z.number().int().min(0).max(100).default(30).describe('Minimum ssdeep similarity % to link samples.'),
  persist_artifact: z.boolean().default(true).describe('Persist cluster results as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const sampleClusterFuzzyOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    cluster_count: z.number().optional(),
    clusters: z.array(z.object({
      id: z.number(),
      members: z.array(z.string()),
      avg_similarity: z.number().optional(),
    })).optional(),
    singleton_count: z.number().optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const sampleClusterFuzzyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Cluster multiple samples by ssdeep fuzzy hash similarity. Identifies malware families and variants.',
  inputSchema: sampleClusterFuzzyInputSchema,
  outputSchema: sampleClusterFuzzyOutputSchema,
}

const CLUSTER_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
samples = payload["samples"]  # [{id, path}, ...]
threshold = int(payload.get("threshold", 30))

import ppdeep

hashes = {}
for s in samples:
    try:
        with open(s["path"], "rb") as f:
            data = f.read()
        hashes[s["id"]] = ppdeep.hash(data)
    except Exception:
        pass

ids = list(hashes.keys())
n = len(ids)
adj = {i: set() for i in ids}
scores = {}

for i in range(n):
    for j in range(i+1, n):
        score = ppdeep.compare(hashes[ids[i]], hashes[ids[j]])
        if score >= threshold:
            adj[ids[i]].add(ids[j])
            adj[ids[j]].add(ids[i])
            scores[(ids[i], ids[j])] = score

# Simple connected components
visited = set()
clusters = []
for node in ids:
    if node in visited:
        continue
    cluster = []
    stack = [node]
    while stack:
        n_id = stack.pop()
        if n_id in visited:
            continue
        visited.add(n_id)
        cluster.append(n_id)
        for neighbor in adj[n_id]:
            if neighbor not in visited:
                stack.append(neighbor)
    clusters.append(cluster)

result_clusters = []
singletons = 0
for idx, members in enumerate(clusters):
    if len(members) == 1:
        singletons += 1
        continue
    pair_scores = []
    for i in range(len(members)):
        for j in range(i+1, len(members)):
            key = tuple(sorted([members[i], members[j]]))
            if key in scores:
                pair_scores.append(scores[key])
    avg = sum(pair_scores) / len(pair_scores) if pair_scores else 0
    result_clusters.append({"id": idx, "members": members, "avg_similarity": round(avg, 1)})

print(json.dumps({
    "cluster_count": len(result_clusters),
    "clusters": result_clusters,
    "singleton_count": singletons,
}, ensure_ascii=False))
`.trim()

export function createSampleClusterFuzzyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = sampleClusterFuzzyInputSchema.parse(args)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.SIMILARITY_PYTHON, moduleNames: ['ppdeep'], distributionNames: ['ppdeep'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'similarity', available: false, error: 'ppdeep Python module not available' } as any, startTime, TOOL_NAME)
      }

      const samples: Array<{ id: string; path: string }> = []
      for (const sid of input.sample_ids) {
        try {
          const p = await resolveSampleFile(workspaceManager, database, sid)
          samples.push({ id: sid, path: p })
        } catch {
          // skip missing samples
        }
      }

      if (samples.length < 2) {
        return { ok: false, errors: ['Need at least 2 resolvable samples for clustering'], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const result = await runPythonJson(
        backend.path,
        CLUSTER_SCRIPT,
        { samples, threshold: input.threshold },
        120_000,
      )

      const clusters = result.parsed?.clusters || []
      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_ids[0], 'similarity', 'cluster', JSON.stringify(result.parsed, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          cluster_count: clusters.length,
          clusters: clusters.slice(0, 20),
          singleton_count: result.parsed?.singleton_count || 0,
          artifact,
          summary: `Clustered ${samples.length} samples into ${clusters.length} group(s) (threshold ${input.threshold}%), ${result.parsed?.singleton_count || 0} singletons.`,
          recommended_next_tools: ['artifact.read', 'malware.classify', 'binary.diff'],
          next_actions: [
            'Use artifact.read for full cluster details.',
            'Use binary.diff to compare members within a cluster.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
