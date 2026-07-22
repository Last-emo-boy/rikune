import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { loadAnalysisClaimLedgerIndex } from '../../../artifacts/analysis-claim-artifacts.js'
import {
  ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
  ANALYSIS_CASE_STATE_ARTIFACT_TYPE,
  ANALYSIS_CASE_STATE_SCHEMA,
  AnalysisCaseAgentNameSchema,
  AnalysisCaseArtifactIdSchema,
  AnalysisCaseIdSchema,
  AnalysisCaseSampleIdSchema,
  AnalysisCaseSessionTagSchema,
  AnalysisCaseStateArtifactSchema,
  AnalysisCaseStateDraftSchema,
  loadAnalysisCaseStateIndex,
  persistAnalysisCaseStateArtifact,
  validateAndCanonicalizeAnalysisCaseState,
  type AnalysisCaseStateArtifact,
} from '../../../artifacts/analysis-case-artifacts.js'

const TOOL_NAME = 'analysis.case.checkpoint'

const AnalysisCaseProducerInputSchema = z
  .object({
    kind: z.literal('external_agent').optional().default('external_agent'),
    agent_name: AnalysisCaseAgentNameSchema.optional(),
  })
  .strict()
  .optional()
  .default({ kind: 'external_agent' })

export const AnalysisCaseCheckpointInputSchema = z
  .object({
    sample_id: AnalysisCaseSampleIdSchema,
    case_id: AnalysisCaseIdSchema.optional().describe(
      'Stable case identifier. Omit only when creating a new case.'
    ),
    parent_artifact_id: AnalysisCaseArtifactIdSchema.nullable()
      .optional()
      .default(null)
      .describe('Latest case-state artifact ID, or null for revision 1.'),
    session_tag: AnalysisCaseSessionTagSchema.optional(),
    producer: AnalysisCaseProducerInputSchema,
    state: AnalysisCaseStateDraftSchema.describe(
      'Full replacement snapshot. Store decisions and next actions, never prompts, private reasoning, secrets, or raw tool arguments.'
    ),
  })
  .strict()

const AnalysisCaseArtifactRefOutputSchema = z
  .object({
    id: z.string(),
    type: z.literal(ANALYSIS_CASE_STATE_ARTIFACT_TYPE),
    path: z.string(),
    sha256: z.string(),
    mime: z.string().optional(),
  })
  .strict()

export const AnalysisCaseCheckpointOutputSchema = z
  .object({
    ok: z.boolean(),
    data: z
      .object({
        sample_id: z.string(),
        case_id: AnalysisCaseIdSchema,
        revision: z.number().int().positive(),
        parent_artifact_id: z.string().nullable(),
        artifact_role: z.literal(ANALYSIS_CASE_STATE_ARTIFACT_ROLE),
        state: AnalysisCaseStateArtifactSchema,
        artifact: AnalysisCaseArtifactRefOutputSchema,
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

export const analysisCaseCheckpointToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Append an immutable, context-only Case Workspace checkpoint. Each write is a full snapshot with optimistic parent/revision checks and canonical same-sample artifact references. Prompts, private reasoning, secrets, and raw tool arguments are prohibited.',
  inputSchema: AnalysisCaseCheckpointInputSchema,
  outputSchema: AnalysisCaseCheckpointOutputSchema,
  aspects: {
    execution: ['static', 'correlation'],
    capabilities: ['case-workspace', 'checkpoint', 'agent-handoff'],
    safety: ['no-live-execution', 'append-only', 'context-only', 'same-sample-references'],
  },
  artifacts: [
    {
      type: ANALYSIS_CASE_STATE_ARTIFACT_TYPE,
      description: 'Immutable context-only Case Workspace state',
      mimeTypes: ['application/json'],
      required: true,
    },
  ],
  workflowRecipes: [
    {
      id: 'analysis-case-workspace',
      title: 'Persistent agent case workspace',
      description: 'Checkpoint bounded analysis state for resume and handoff.',
      startsWith: [TOOL_NAME],
      nextTools: ['analysis.case.snapshot', 'analysis.claims.apply', 'workflow.summarize'],
      producesArtifacts: [ANALYSIS_CASE_STATE_ARTIFACT_TYPE],
      safety: ['append-only', 'context-only'],
    },
  ],
}

export function createAnalysisCaseCheckpointHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = AnalysisCaseCheckpointInputSchema.parse(args)
      if (!database.findSample(input.sample_id)) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }
      await workspaceManager.createWorkspace(input.sample_id)

      const caseId = input.case_id || `case_${randomUUID()}`
      const index = await loadAnalysisCaseStateIndex(workspaceManager, database, input.sample_id, {
        caseId,
      })
      const latest = index.byCaseId.get(caseId) || null
      const expectedParentId = latest?.artifact.id || null
      if (input.parent_artifact_id !== expectedParentId) {
        return {
          ok: false,
          errors: [
            `Case-state revision conflict: expected parent ${expectedParentId || 'null'}, received ${input.parent_artifact_id || 'null'}.`,
          ],
          warnings: index.warnings.length > 0 ? index.warnings : undefined,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const warnings = [...index.warnings]
      if (input.state.active_claim_ids.length > 0) {
        const ledger = await loadAnalysisClaimLedgerIndex(
          workspaceManager,
          database,
          input.sample_id,
          { scope: 'latest', activeClaimIds: input.state.active_claim_ids }
        )
        warnings.push(...ledger.warnings)
        if (
          ledger.active_claim_resolution?.status !== 'complete' &&
          ledger.active_claim_resolution?.status !== 'missing'
        ) {
          return {
            ok: false,
            errors: [
              'active_claim_ids could not be resolved through a complete, integrity-validated Claim Ledger scan.',
            ],
            warnings: warnings.length > 0 ? Array.from(new Set(warnings)) : undefined,
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }
        const missingClaimIds = input.state.active_claim_ids.filter(
          (claimId) => !ledger.byClaimId.has(claimId)
        )
        if (missingClaimIds.length > 0) {
          return {
            ok: false,
            errors: [
              `active_claim_ids contains Claim Ledger IDs that do not exist for this sample: ${missingClaimIds.join(', ')}`,
            ],
            warnings: warnings.length > 0 ? Array.from(new Set(warnings)) : undefined,
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }
      }

      const canonical = await validateAndCanonicalizeAnalysisCaseState({
        workspaceManager,
        database,
        sampleId: input.sample_id,
        draft: input.state,
      })
      if (canonical.errors.length > 0) {
        return {
          ok: false,
          errors: canonical.errors,
          warnings: warnings.length > 0 ? Array.from(new Set(warnings)) : undefined,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const payload: AnalysisCaseStateArtifact = {
        schema: ANALYSIS_CASE_STATE_SCHEMA,
        schema_version: 1,
        artifact_role: ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
        sample_id: input.sample_id,
        case_id: caseId,
        revision: (latest?.payload.revision || 0) + 1,
        parent_artifact_id: expectedParentId,
        created_at: new Date().toISOString(),
        session_tag: input.session_tag || null,
        objective: input.state.objective,
        decisions: input.state.decisions,
        open_questions: input.state.open_questions,
        attempted_actions: canonical.attempted_actions,
        active_claim_ids: input.state.active_claim_ids,
        pinned_artifacts: canonical.pinned_artifacts,
        next_actions: input.state.next_actions,
        producer: {
          kind: 'external_agent',
          agent_name: input.producer.agent_name || null,
        },
      }
      const artifact = await persistAnalysisCaseStateArtifact(workspaceManager, database, payload)
      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          case_id: caseId,
          revision: payload.revision,
          parent_artifact_id: payload.parent_artifact_id,
          artifact_role: ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
          state: payload,
          artifact,
          next_steps: [
            `Use analysis.case.snapshot with sample_id=${input.sample_id} and case_id=${caseId} to resume this case.`,
            `Pass parent_artifact_id=${artifact.id} when appending the next checkpoint.`,
            'Use analysis.claims.apply for evidence-backed assertions; case state is context-only and cannot be Claim evidence.',
          ],
        },
        warnings: warnings.length > 0 ? Array.from(new Set(warnings)) : undefined,
        artifacts: [artifact],
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
