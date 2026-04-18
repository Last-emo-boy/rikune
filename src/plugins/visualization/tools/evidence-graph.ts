/**
 * analysis.evidence.graph tool.
 *
 * Correlates specialist static artifacts and runtime trace artifacts into a
 * compact evidence graph for reports, dashboard navigation, and AI grounding.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  buildEvidenceGraph,
  loadCorrelationEvidence,
} from '../../../artifacts/evidence-correlation.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'analysis.evidence.graph'
const TOOL_VERSION = '0.1.0'

export const EvidenceGraphInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  evidence_scope: z.enum(['all', 'latest', 'session']).optional().default('all'),
  evidence_session_tag: z.string().optional(),
  max_static_artifacts: z.number().int().min(1).max(100).optional().default(20),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

export const evidenceGraphToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a compact evidence graph that links specialist static artifacts, static expectations, dynamic trace observations, and corroboration edges. Does not execute the sample.',
  inputSchema: EvidenceGraphInputSchema,
}

export function createEvidenceGraphHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = EvidenceGraphInputSchema.parse(args || {})
      const sample = deps.database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`], metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME } }
      }

      const bundle = await loadCorrelationEvidence(deps.workspaceManager, deps.database, input.sample_id, {
        evidenceScope: input.evidence_scope,
        sessionTag: input.evidence_session_tag,
        maxStaticArtifacts: input.max_static_artifacts,
      })
      const graph = buildEvidenceGraph(bundle)
      const data = {
        schema: 'rikune.analysis_evidence_graph.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag || null,
        summary: {
          static_artifact_count: bundle.static_artifacts.length,
          dynamic_artifact_count: bundle.dynamic_summary?.artifact_count || 0,
          dynamic_executed: Boolean(bundle.dynamic_summary?.executed),
          expectation_count: bundle.expectations.length,
          observation_count: bundle.observations.length,
          node_count: graph.nodes.length,
          edge_count: graph.edges.length,
          corroboration_edge_count: graph.edges.filter((edge) => edge.label === 'corroborated_by').length,
        },
        graph,
        warnings: bundle.warnings,
        recommended_next_tools: [
          'static.config.carver',
          'static.resource.graph',
          'dynamic.behavior.diff',
          'dynamic.persona.plan',
          'dynamic.behavior.capture',
        ],
      }

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          input.sample_id,
          'analysis_evidence_graph',
          'evidence_graph',
          data,
          input.session_tag
        ))
      }

      return {
        ok: true,
        data,
        warnings: bundle.warnings.length > 0 ? bundle.warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
