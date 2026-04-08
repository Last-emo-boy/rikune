/**
 * sample.cluster — Similarity clustering across multiple samples.
 *
 * Computes pairwise similarity using import hash, section hashes,
 * string overlap, and structural features to produce a similarity
 * matrix and cluster assignments.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from './static-worker-client.js'

const TOOL_NAME = 'sample.cluster'
const TOOL_VERSION = '0.1.0'

export const SampleClusterInputSchema = z.object({
  sample_ids: z.array(z.string()).min(2).max(100)
    .describe('List of sample identifiers to cluster'),
  features: z.array(z.enum([
    'imphash',
    'section_hash',
    'string_overlap',
    'byte_histogram',
    'opcode_ngram',
    'api_call_sequence',
  ])).default(['imphash', 'section_hash', 'string_overlap'])
    .describe('Features to use for similarity computation'),
  algorithm: z.enum(['hierarchical', 'dbscan', 'kmeans']).default('hierarchical')
    .describe('Clustering algorithm'),
  similarity_threshold: z.number().min(0).max(1).default(0.6)
    .describe('Minimum similarity to consider two samples related'),
  force_refresh: z.boolean().default(false),
})
export type SampleClusterInput = z.infer<typeof SampleClusterInputSchema>

export const sampleClusterToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Cluster multiple samples by similarity using import hashes, section hashes, ' +
    'string overlap, byte histograms, opcode n-grams, and API call sequences. ' +
    'Produces a similarity matrix and cluster assignments for malware family grouping.',
  inputSchema: SampleClusterInputSchema,
}

export function createSampleClusterHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = SampleClusterInputSchema.parse(args)
    const startTime = Date.now()

    try {
      // Validate all samples exist
      const samples: Array<{ id: string; sha256: string }> = []
      const missing: string[] = []
      for (const sid of input.sample_ids) {
        const s = database.findSample(sid)
        if (!s) missing.push(sid)
        else samples.push({ id: sid, sha256: s.sha256 })
      }
      if (missing.length > 0) {
        return { ok: false, errors: [`Samples not found: ${missing.join(', ')}`] }
      }

      // Call Python worker for actual clustering
      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_ids[0],
        samplePath: '', // Multi-sample; worker resolves paths
        args: {
          sample_ids: input.sample_ids,
          features: input.features,
          algorithm: input.algorithm,
          similarity_threshold: input.similarity_threshold,
        },
        toolVersion: TOOL_VERSION,
      })
      const workerResponse = await callPooledStaticWorker(workerRequest, { database })

      if (workerResponse.ok) {
        // Persist cluster result
        const artifacts: ArtifactRef[] = []
        try {
          artifacts.push(await persistStaticAnalysisJsonArtifact(
            workspaceManager, database, input.sample_ids[0],
            'sample_cluster', 'cluster_analysis', { tool: TOOL_NAME, data: workerResponse.data },
          ))
        } catch { /* best effort */ }

        return {
          ok: true,
          data: workerResponse.data,
          warnings: workerResponse.warnings,
          artifacts,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      // Fallback: compute basic similarity locally
      const warnings = ['Python worker unavailable; using basic local similarity']
      const pairwiseSimilarity: Array<{
        sample_a: string; sample_b: string; similarity: number; features_matched: string[]
      }> = []

      for (let i = 0; i < samples.length; i++) {
        for (let j = i + 1; j < samples.length; j++) {
          const artA = database.findArtifacts(samples[i].id)
          const artB = database.findArtifacts(samples[j].id)
          const commonTypes = artA
            .map((a: { type: string }) => a.type)
            .filter((t: string) => artB.some((b: { type: string }) => b.type === t))
          const similarity = commonTypes.length / Math.max(artA.length, artB.length, 1)

          pairwiseSimilarity.push({
            sample_a: samples[i].id,
            sample_b: samples[j].id,
            similarity: Math.round(similarity * 1000) / 1000,
            features_matched: commonTypes,
          })
        }
      }

      // Simple threshold-based clustering
      const clusters: Array<{ cluster_id: number; members: string[] }> = []
      const assigned = new Set<string>()
      let clusterId = 0

      for (const pair of pairwiseSimilarity.filter(p => p.similarity >= input.similarity_threshold)) {
        const existing = clusters.find(c =>
          c.members.includes(pair.sample_a) || c.members.includes(pair.sample_b),
        )
        if (existing) {
          if (!existing.members.includes(pair.sample_a)) existing.members.push(pair.sample_a)
          if (!existing.members.includes(pair.sample_b)) existing.members.push(pair.sample_b)
        } else {
          clusters.push({
            cluster_id: clusterId++,
            members: [pair.sample_a, pair.sample_b],
          })
        }
        assigned.add(pair.sample_a)
        assigned.add(pair.sample_b)
      }

      // Singletons
      for (const s of samples) {
        if (!assigned.has(s.id)) {
          clusters.push({ cluster_id: clusterId++, members: [s.id] })
        }
      }

      return {
        ok: true,
        data: {
          total_samples: samples.length,
          total_clusters: clusters.length,
          algorithm: input.algorithm,
          features_used: input.features,
          similarity_threshold: input.similarity_threshold,
          clusters,
          similarity_matrix: pairwiseSimilarity,
          recommended_next: ['sample.family.track', 'sample.timeline'],
        },
        warnings,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
