/**
 * dynamic.behavior.diff tool.
 *
 * Compares static expectations against runtime observations. This is a
 * correlation/reporting tool only; it never starts a runtime or executes a
 * sample.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  buildBehaviorDiff,
  loadCorrelationEvidence,
} from '../../../artifacts/evidence-correlation.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'dynamic.behavior.diff'
const TOOL_VERSION = '0.1.0'

export const DynamicBehaviorDiffInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  evidence_scope: z.enum(['all', 'latest', 'session']).optional().default('all'),
  evidence_session_tag: z.string().optional(),
  max_static_artifacts: z.number().int().min(1).max(100).optional().default(20),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

export const dynamicBehaviorDiffToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compare static behavior expectations from config/resource artifacts against runtime observations from dynamic traces. Produces confirmed behavior, dormant/missing expectations, unexpected runtime observations, and next runtime steps without executing the sample.',
  inputSchema: DynamicBehaviorDiffInputSchema,
}

export function createDynamicBehaviorDiffHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = DynamicBehaviorDiffInputSchema.parse(args || {})
      const sample = deps.database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`], metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME } }
      }

      const bundle = await loadCorrelationEvidence(deps.workspaceManager, deps.database, input.sample_id, {
        evidenceScope: input.evidence_scope,
        sessionTag: input.evidence_session_tag,
        maxStaticArtifacts: input.max_static_artifacts,
      })
      const diff = buildBehaviorDiff(bundle)
      const data = {
        schema: 'rikune.dynamic_behavior_diff.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag || null,
        static_artifacts: bundle.static_artifacts.map(({ artifact }) => ({
          id: artifact.id,
          type: artifact.type,
          path: artifact.path,
        })),
        dynamic_summary: bundle.dynamic_summary
          ? {
              artifact_count: bundle.dynamic_summary.artifact_count,
              executed: bundle.dynamic_summary.executed,
              observed_apis: bundle.dynamic_summary.observed_apis,
              stages: bundle.dynamic_summary.stages,
              scope_note: bundle.dynamic_summary.scope_note,
            }
          : null,
        diff,
        warnings: bundle.warnings,
      }

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          input.sample_id,
          'dynamic_behavior_diff',
          'behavior_diff',
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
