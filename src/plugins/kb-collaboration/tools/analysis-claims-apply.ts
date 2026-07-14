import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
  ANALYSIS_CLAIM_SET_SCHEMA,
  MAX_ANALYSIS_CLAIM_EVIDENCE_REFERENCES,
  AnalysisClaimDraftSchema,
  AnalysisClaimValidationSummarySchema,
  loadAnalysisClaimLedgerIndex,
  persistAnalysisClaimSetArtifact,
  validateAndCanonicalizeAnalysisClaims,
  type AnalysisClaimDraft,
  type AnalysisClaimSetArtifact,
} from '../../../artifacts/analysis-claim-artifacts.js'

const TOOL_NAME = 'analysis.claims.apply'

const AnalysisClaimProducerInputSchema = z
  .object({
    kind: z.enum(['llm', 'imported']).optional().default('llm'),
    client_name: z.string().min(1).max(200).optional(),
    model_name: z.string().min(1).max(200).optional(),
  })
  .strict()
  .optional()
  .default({ kind: 'llm' })

export const AnalysisClaimsApplyInputSchema = z
  .object({
    sample_id: z.string().min(1).describe('Sample identifier that owns every evidence artifact'),
    goal: z
      .string()
      .min(1)
      .max(1000)
      .optional()
      .describe('Optional bounded analysis goal for this claim-set revision'),
    session_tag: z
      .string()
      .min(1)
      .max(200)
      .optional()
      .describe('Optional session selector used to group claim-set artifacts'),
    producer: AnalysisClaimProducerInputSchema.describe(
      'Untrusted producer provenance. This MCP surface only accepts LLM/imported inferred claims.'
    ),
    claims: z
      .array(AnalysisClaimDraftSchema)
      .min(1)
      .max(100)
      .describe(
        'Structured claims. Evidence must reference existing same-sample artifacts by artifact_id.'
      ),
  })
  .strict()
  .superRefine((value, ctx) => {
    const evidenceReferenceCount = value.claims.reduce(
      (count, claim) => count + claim.supporting_evidence.length + claim.counter_evidence.length,
      0
    )
    if (evidenceReferenceCount > MAX_ANALYSIS_CLAIM_EVIDENCE_REFERENCES) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['claims'],
        message: `claim set may reference at most ${MAX_ANALYSIS_CLAIM_EVIDENCE_REFERENCES} evidence entries.`,
      })
    }
  })

const AppliedClaimSummarySchema = z
  .object({
    claim_id: z.string(),
    category: z.string(),
    subject: z.string(),
    statement: z.string(),
    status: z.string(),
    source: z.string(),
    supporting_evidence_count: z.number().int().nonnegative(),
    counter_evidence_count: z.number().int().nonnegative(),
    review_required: z.boolean(),
  })
  .strict()

export const AnalysisClaimsApplyOutputSchema = z
  .object({
    ok: z.boolean(),
    data: z
      .object({
        sample_id: z.string(),
        ledger_revision: z.number().int().positive(),
        parent_artifact_id: z.string().nullable(),
        accepted_count: z.number().int().positive(),
        claims: z.array(AppliedClaimSummarySchema),
        validation_summary: AnalysisClaimValidationSummarySchema,
        artifact: z.object({
          id: z.string(),
          type: z.literal(ANALYSIS_CLAIM_SET_ARTIFACT_TYPE),
          path: z.string(),
          sha256: z.string(),
          mime: z.string().optional(),
        }),
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

export const analysisClaimsApplyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Persist an append-only, evidence-backed Claim Ledger revision. The tool verifies artifact existence, same-sample ownership, file SHA-256, and optional JSON pointers before writing. It validates evidence integrity, not semantic truth. This AI-facing surface only writes inferred LLM/imported claims; analyst revisions remain fail-closed until a signed operator boundary is available.',
  inputSchema: AnalysisClaimsApplyInputSchema,
  outputSchema: AnalysisClaimsApplyOutputSchema,
  aspects: {
    execution: ['static', 'correlation'],
    capabilities: ['claim-ledger', 'evidence-grounded-analysis', 'review-ready'],
    evidence: ['artifact', 'provenance'],
    safety: ['no-live-execution', 'append-only', 'same-sample-evidence'],
  },
  artifacts: [
    {
      type: ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
      description: 'Versioned claims with canonical evidence references and review provenance',
      mimeTypes: ['application/json'],
      required: true,
    },
  ],
  workflowRecipes: [
    {
      id: 'analysis-claim-ledger',
      title: 'Evidence-backed claim production',
      description:
        'Turn prior analysis artifacts into explicit claims, surface them in the evidence graph, and hand them to reporting.',
      startsWith: [TOOL_NAME],
      nextTools: ['analysis.evidence.graph', 'artifact.read', 'workflow.summarize'],
      producesArtifacts: [ANALYSIS_CLAIM_SET_ARTIFACT_TYPE],
      evidence: ['artifact', 'provenance'],
      safety: ['no-live-execution', 'same-sample-evidence'],
    },
  ],
}

function assignClaimIds(
  claims: AnalysisClaimDraft[]
): Array<AnalysisClaimDraft & { claim_id: string }> {
  return claims.map((claim) => ({
    ...claim,
    claim_id: claim.claim_id || 'claim_' + randomUUID(),
  }))
}

export function createAnalysisClaimsApplyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = AnalysisClaimsApplyInputSchema.parse(args)
      if (!database.findSample(input.sample_id)) {
        return {
          ok: false,
          errors: ['Sample not found: ' + input.sample_id],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }
      await workspaceManager.createWorkspace(input.sample_id)

      const drafts = assignClaimIds(input.claims)
      const claimIds = drafts.map((claim) => claim.claim_id)
      if (new Set(claimIds).size !== claimIds.length) {
        return {
          ok: false,
          errors: ['claims contains duplicate claim_id values.'],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const ledger = await loadAnalysisClaimLedgerIndex(
        workspaceManager,
        database,
        input.sample_id,
        {
          scope: 'all',
        }
      )
      const terminalRevisionErrors = drafts.flatMap((draft) => {
        const previous = ledger.byClaimId.get(draft.claim_id)
        if (previous && ['verified', 'rejected'].includes(previous.claim.status)) {
          return [
            draft.claim_id +
              ': this AI-facing tool cannot revise a previously ' +
              previous.claim.status +
              ' claim.',
          ]
        }
        return []
      })
      if (terminalRevisionErrors.length > 0) {
        return {
          ok: false,
          errors: terminalRevisionErrors,
          warnings: ledger.warnings.length > 0 ? ledger.warnings : undefined,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const createdAt = new Date().toISOString()
      const validation = await validateAndCanonicalizeAnalysisClaims({
        workspaceManager,
        database,
        sampleId: input.sample_id,
        source: input.producer.kind,
        drafts,
        reviewedAt: createdAt,
      })
      if (validation.errors.length > 0) {
        return {
          ok: false,
          errors: validation.errors,
          warnings: ledger.warnings.length > 0 ? ledger.warnings : undefined,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const parent = ledger.claim_sets.reduce<(typeof ledger.claim_sets)[number] | null>(
        (latest, candidate) =>
          !latest || candidate.payload.ledger_revision > latest.payload.ledger_revision
            ? candidate
            : latest,
        null
      )
      const ledgerRevision = (parent?.payload.ledger_revision || 0) + 1
      const evidenceReferences = validation.claims.flatMap((claim) => [
        ...claim.supporting_evidence,
        ...claim.counter_evidence,
      ])
      const payload: AnalysisClaimSetArtifact = {
        schema: ANALYSIS_CLAIM_SET_SCHEMA,
        schema_version: 1,
        sample_id: input.sample_id,
        ledger_revision: ledgerRevision,
        parent_artifact_id: parent?.artifact.id || null,
        created_at: createdAt,
        session_tag: input.session_tag || null,
        goal: input.goal || null,
        producer: {
          kind: input.producer.kind,
          client_name: input.producer.client_name || null,
          model_name: input.producer.model_name || null,
        },
        claims: validation.claims,
        validation_results: validation.validation_results,
        validation_summary: {
          status: 'passed',
          claim_count: validation.claims.length,
          evidence_reference_count: evidenceReferences.length,
          json_pointer_count: evidenceReferences.filter(
            (reference) => reference.json_pointer !== undefined
          ).length,
        },
      }
      const artifact = await persistAnalysisClaimSetArtifact(workspaceManager, database, payload)

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          ledger_revision: ledgerRevision,
          parent_artifact_id: payload.parent_artifact_id,
          accepted_count: validation.claims.length,
          claims: validation.claims.map((claim) => ({
            claim_id: claim.claim_id,
            category: claim.category,
            subject: claim.subject,
            statement: claim.statement,
            status: claim.status,
            source: claim.source,
            supporting_evidence_count: claim.supporting_evidence.length,
            counter_evidence_count: claim.counter_evidence.length,
            review_required: ['inferred', 'contradicted'].includes(claim.status),
          })),
          validation_summary: payload.validation_summary,
          artifact,
          next_steps: [
            'Use artifact.read with artifact_id=' +
              artifact.id +
              ' to inspect the immutable claim set.',
            'Run analysis.evidence.graph to correlate the Claim Ledger with deterministic evidence.',
            'Run workflow.summarize to incorporate evidence-backed claims into a report.',
          ],
        },
        warnings: ledger.warnings.length > 0 ? ledger.warnings : undefined,
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
