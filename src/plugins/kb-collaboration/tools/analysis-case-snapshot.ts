import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
  ANALYSIS_CASE_STATE_ARTIFACT_TYPE,
  AnalysisCaseIdSchema,
  AnalysisCaseSampleIdSchema,
  AnalysisCaseSessionTagSchema,
  AnalysisCaseStateArtifactSchema,
  loadAnalysisCaseStateIndex,
} from '../../../artifacts/analysis-case-artifacts.js'

const TOOL_NAME = 'analysis.case.snapshot'

export const AnalysisCaseSnapshotInputSchema = z
  .object({
    sample_id: AnalysisCaseSampleIdSchema,
    case_id: AnalysisCaseIdSchema.optional(),
    session_tag: AnalysisCaseSessionTagSchema.optional(),
    max_artifacts: z.number().int().positive().max(1000).optional().default(128),
  })
  .strict()

const CaseStateArtifactRefSchema = z
  .object({
    id: z.string(),
    type: z.literal(ANALYSIS_CASE_STATE_ARTIFACT_TYPE),
    path: z.string(),
    sha256: z.string(),
    mime: z.string().optional(),
    created_at: z.string(),
  })
  .strict()

export const AnalysisCaseSnapshotOutputSchema = z
  .object({
    ok: z.boolean(),
    data: z
      .object({
        sample_id: z.string(),
        case_id: AnalysisCaseIdSchema,
        artifact_role: z.literal(ANALYSIS_CASE_STATE_ARTIFACT_ROLE),
        state: AnalysisCaseStateArtifactSchema,
        artifact: CaseStateArtifactRefSchema,
        history: z
          .array(
            z
              .object({
                revision: z.number().int().positive(),
                parent_artifact_id: z.string().nullable(),
                created_at: z.string(),
                artifact: CaseStateArtifactRefSchema,
              })
              .strict()
          )
          .max(1000),
        available_cases: z.array(
          z
            .object({
              case_id: AnalysisCaseIdSchema,
              revision: z.number().int().positive(),
              updated_at: z.string(),
              objective: z.string(),
            })
            .strict()
        ),
        marker: z.string(),
        truncated: z.boolean(),
        total_artifact_count: z.number().int().nonnegative(),
        next_steps: z.array(z.string()),
      })
      .strict()
      .optional(),
    warnings: z.array(z.string()).optional(),
    errors: z.array(z.string()).optional(),
    artifacts: z.array(z.any()).optional(),
    metrics: z
      .object({
        elapsed_ms: z.number(),
        tool: z.string(),
      })
      .optional(),
  })
  .strict()

export const analysisCaseSnapshotToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Load the newest immutable Case Workspace snapshot and its bounded revision history. Case state is context-only: it supports resume and handoff but is never Claim evidence.',
  inputSchema: AnalysisCaseSnapshotInputSchema,
  outputSchema: AnalysisCaseSnapshotOutputSchema,
  aspects: {
    execution: ['static', 'correlation'],
    capabilities: ['case-workspace', 'snapshot', 'agent-handoff'],
    safety: ['read-only', 'context-only', 'bounded-output'],
  },
  artifacts: [
    {
      type: ANALYSIS_CASE_STATE_ARTIFACT_TYPE,
      description: 'Existing immutable context-only Case Workspace state',
      mimeTypes: ['application/json'],
      required: false,
    },
  ],
  workflowRecipes: [
    {
      id: 'analysis-case-resume',
      title: 'Resume an agent case',
      description: 'Restore bounded case state before continuing analysis.',
      startsWith: [TOOL_NAME],
      nextTools: ['analysis.case.checkpoint', 'analysis.claims.apply'],
      producesArtifacts: [],
      safety: ['read-only', 'context-only'],
    },
  ],
}

export function createAnalysisCaseSnapshotHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = AnalysisCaseSnapshotInputSchema.parse(args)
      if (!database.findSample(input.sample_id)) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }
      const index = await loadAnalysisCaseStateIndex(workspaceManager, database, input.sample_id, {
        caseId: input.case_id,
        sessionTag: input.session_tag,
        maxArtifacts: input.max_artifacts,
      })
      const latest = input.case_id
        ? index.byCaseId.get(input.case_id) || null
        : index.case_states[0] || null
      if (!latest) {
        return {
          ok: false,
          errors: [
            input.case_id
              ? `Case state not found for case_id=${input.case_id}.`
              : 'No case-state artifact matched the requested sample/session.',
          ],
          warnings: index.warnings.length > 0 ? index.warnings : undefined,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const history = index.case_states
        .filter((entry) => entry.payload.case_id === latest.payload.case_id)
        .sort((left, right) => right.payload.revision - left.payload.revision)
        .map((entry) => ({
          revision: entry.payload.revision,
          parent_artifact_id: entry.payload.parent_artifact_id,
          created_at: entry.payload.created_at,
          artifact: entry.artifact,
        }))
      const availableCases = Array.from(index.byCaseId.values())
        .sort((left, right) => right.payload.created_at.localeCompare(left.payload.created_at))
        .map((entry) => ({
          case_id: entry.payload.case_id,
          revision: entry.payload.revision,
          updated_at: entry.payload.created_at,
          objective: entry.payload.objective,
        }))
      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          case_id: latest.payload.case_id,
          artifact_role: ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
          state: latest.payload,
          artifact: latest.artifact,
          history,
          available_cases: availableCases,
          marker: index.marker,
          truncated: index.truncated,
          total_artifact_count: index.total_artifact_count,
          next_steps: [
            `Pass parent_artifact_id=${latest.artifact.id} to analysis.case.checkpoint when appending revision ${latest.payload.revision + 1}.`,
            'Use analysis.claims.apply for evidence-backed assertions; do not cite this context-only case state as evidence.',
          ],
        },
        warnings: index.warnings.length > 0 ? index.warnings : undefined,
        artifacts: history.map((entry) => entry.artifact),
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
