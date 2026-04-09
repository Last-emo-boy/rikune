import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  persistSemanticFunctionExplanationsArtifact,
  type SemanticFunctionExplanationArtifactPayload,
  SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE,
} from '../../../artifacts/semantic-name-suggestion-artifacts.js'

const TOOL_NAME = 'code.function.explain.apply'

const ExplanationSuggestionInputSchema = z
  .object({
    address_or_function: z
      .string()
      .optional()
      .describe('Optional combined identifier when the reviewing client returns a single address_or_function field'),
    address: z.string().optional().describe('Optional function address for precise matching'),
    function: z.string().optional().describe('Optional function symbol/name for fallback matching'),
    summary: z.string().min(1).max(1200).describe('Evidence-grounded plain-language explanation of the function'),
    behavior: z.string().min(1).max(160).describe('Short behavior label, such as resolve_dynamic_imports or dispatch_exported_command'),
    confidence: z.number().min(0).max(1).describe('Heuristic support score for the explanation'),
    assumptions: z.array(z.string()).optional().default([]).describe('Assumptions that must hold for the explanation to remain valid'),
    evidence_used: z.array(z.string()).optional().default([]).describe('Evidence sources used by the external LLM'),
    rewrite_guidance: z
      .union([z.string().min(1), z.array(z.string().min(1))])
      .optional()
      .describe('One or more rewrite-oriented guidance items derived from the evidence'),
  })
  .refine(
    (value) =>
      Boolean(value.address_or_function?.trim()) ||
      Boolean(value.address?.trim()) ||
      Boolean(value.function?.trim()),
    {
      message: 'Each explanation must provide at least one of `address_or_function`, `address`, or `function`.',
    }
  )

function normalizeExplanationIdentifier(
  explanation: z.infer<typeof ExplanationSuggestionInputSchema>
): { address: string | null; function: string | null } {
  const normalizedAddress = explanation.address?.trim() || null
  const normalizedFunction = explanation.function?.trim() || null

  if (normalizedAddress || normalizedFunction) {
    return {
      address: normalizedAddress,
      function: normalizedFunction,
    }
  }

  const identifier = explanation.address_or_function?.trim()
  if (!identifier) {
    return {
      address: null,
      function: null,
    }
  }

  if (/^(0x)?[0-9a-f]+$/i.test(identifier)) {
    return {
      address: identifier,
      function: null,
    }
  }

  return {
    address: null,
    function: identifier,
  }
}

function normalizeRewriteGuidance(
  input: string | string[] | undefined
): string[] {
  if (!input) {
    return []
  }
  const values = Array.isArray(input) ? input : [input]
  return values.map((item) => item.trim()).filter((item) => item.length > 0).slice(0, 8)
}

export const codeFunctionExplainApplyInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  explanations: z
    .array(ExplanationSuggestionInputSchema)
    .min(1)
    .describe('Structured explanation outputs returned by an external MCP client / LLM'),
  client_name: z
    .string()
    .optional()
    .describe('Optional client identifier, such as claude-desktop or codex-cli'),
  model_name: z
    .string()
    .optional()
    .describe('Optional model identifier for provenance only'),
  prepare_artifact_id: z
    .string()
    .optional()
    .describe('Optional semantic_explanation_prepare_bundle artifact ID that produced this review task'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional semantic explanation session tag used for artifact grouping'),
})

export const codeFunctionExplainApplyOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      accepted_count: z.number().int().nonnegative(),
      rejected_count: z.number().int().nonnegative(),
      accepted_explanations: z.array(
        z.object({
          address: z.string().nullable(),
          function: z.string().nullable(),
          behavior: z.string(),
          confidence: z.number().min(0).max(1),
          rewrite_guidance_count: z.number().int().nonnegative(),
        })
      ),
      artifact: z.object({
        id: z.string(),
        type: z.literal(SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE),
        path: z.string(),
        sha256: z.string(),
        mime: z.string().optional(),
      }),
      next_steps: z.array(z.string()),
    })
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

export const codeFunctionExplainApplyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Persist structured function explanations returned by any external MCP client / LLM so export and report layers can consume them.',
  inputSchema: codeFunctionExplainApplyInputSchema,
  outputSchema: codeFunctionExplainApplyOutputSchema,
}

export function createCodeFunctionExplainApplyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = codeFunctionExplainApplyInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const acceptedExplanations: SemanticFunctionExplanationArtifactPayload['explanations'] = []
      const acceptedSummary: Array<{
        address: string | null
        function: string | null
        behavior: string
        confidence: number
        rewrite_guidance_count: number
      }> = []
      const warnings: string[] = []

      for (const explanation of input.explanations) {
        const normalizedIdentifier = normalizeExplanationIdentifier(explanation)
        const rewriteGuidance = normalizeRewriteGuidance(explanation.rewrite_guidance)
        const summary = explanation.summary.trim()
        const behavior = explanation.behavior.trim()
        if (summary.length === 0 || behavior.length === 0) {
          warnings.push(
            `Rejected explanation for ${normalizedIdentifier.address || normalizedIdentifier.function || explanation.address_or_function || 'unknown'} because summary or behavior was empty after normalization.`
          )
          continue
        }

        acceptedExplanations.push({
          address: normalizedIdentifier.address,
          function: normalizedIdentifier.function,
          summary,
          behavior,
          confidence: explanation.confidence,
          assumptions: explanation.assumptions || [],
          evidence_used: explanation.evidence_used || [],
          rewrite_guidance: rewriteGuidance,
        })
        acceptedSummary.push({
          address: normalizedIdentifier.address,
          function: normalizedIdentifier.function,
          behavior,
          confidence: explanation.confidence,
          rewrite_guidance_count: rewriteGuidance.length,
        })
      }

      if (acceptedExplanations.length === 0) {
        return {
          ok: false,
          errors: ['No explanations were accepted after normalization.'],
          warnings: warnings.length > 0 ? warnings : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const payload: SemanticFunctionExplanationArtifactPayload = {
        schema_version: 1,
        sample_id: input.sample_id,
        created_at: new Date().toISOString(),
        session_tag: input.session_tag || null,
        client_name: input.client_name || null,
        model_name: input.model_name || null,
        prepare_artifact_id: input.prepare_artifact_id || null,
        explanations: acceptedExplanations,
      }

      const artifact = await persistSemanticFunctionExplanationsArtifact(
        workspaceManager,
        database,
        payload
      )

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          accepted_count: acceptedExplanations.length,
          rejected_count: input.explanations.length - acceptedExplanations.length,
          accepted_explanations: acceptedSummary,
          artifact,
          next_steps: [
            'rerun code.reconstruct.export to propagate explanation summaries and rewrite guidance into rewrite output',
            'rerun report.generate or report.summarize if you want explanation artifacts reflected in higher-level analyst output',
          ],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: [artifact],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
