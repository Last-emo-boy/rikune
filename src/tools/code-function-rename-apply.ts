import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import {
  persistSemanticNameSuggestionsArtifact,
  sanitizeSemanticName,
  type SemanticNameSuggestionArtifactPayload,
  SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE,
} from '../semantic-name-suggestion-artifacts.js'

const TOOL_NAME = 'code.function.rename.apply'

const SemanticNameSuggestionInputSchema = z
  .object({
    address_or_function: z
      .string()
      .optional()
      .describe('Optional combined identifier when the reviewing client returns a single address_or_function field'),
    address: z.string().optional().describe('Optional function address for precise matching'),
    function: z.string().optional().describe('Optional function symbol/name for fallback matching'),
    candidate_name: z.string().min(1).max(160).describe('LLM-proposed human-readable semantic name'),
    confidence: z.number().min(0).max(1).describe('Confidence score for the proposed name'),
    why: z.string().min(1).max(1000).describe('Short rationale grounded in the provided evidence'),
    required_assumptions: z
      .array(z.string())
      .optional()
      .default([])
      .describe('Assumptions that must hold for the proposed name to remain valid'),
    evidence_used: z
      .array(z.string())
      .optional()
      .default([])
      .describe('Evidence sources used by the LLM, such as strings, runtime trace, xrefs, or CFG shape'),
  })
  .refine(
    (value) =>
      Boolean(value.address_or_function?.trim()) ||
      Boolean(value.address?.trim()) ||
      Boolean(value.function?.trim()),
    {
      message: 'Each suggestion must provide at least one of `address_or_function`, `address`, or `function`.',
    }
  )

function normalizeSuggestionIdentifier(suggestion: z.infer<typeof SemanticNameSuggestionInputSchema>): {
  address: string | null
  function: string | null
} {
  const normalizedAddress = suggestion.address?.trim() || null
  const normalizedFunction = suggestion.function?.trim() || null

  if (normalizedAddress || normalizedFunction) {
    return {
      address: normalizedAddress,
      function: normalizedFunction,
    }
  }

  const identifier = suggestion.address_or_function?.trim()
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

export const codeFunctionRenameApplyInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  suggestions: z
    .array(SemanticNameSuggestionInputSchema)
    .min(1)
    .describe('Structured name suggestions returned by an external MCP client / LLM'),
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
    .describe('Optional semantic_name_prepare_bundle artifact ID that produced this review task'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional semantic naming session tag used for artifact grouping'),
})

export const codeFunctionRenameApplyOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      accepted_count: z.number().int().nonnegative(),
      rejected_count: z.number().int().nonnegative(),
      accepted_suggestions: z.array(
        z.object({
          address: z.string().nullable(),
          function: z.string().nullable(),
          candidate_name: z.string(),
          normalized_candidate_name: z.string(),
          confidence: z.number().min(0).max(1),
        })
      ),
      artifact: z.object({
        id: z.string(),
        type: z.literal(SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE),
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

export const codeFunctionRenameApplyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Persist structured semantic name suggestions returned by any external MCP client / LLM so reconstruct/export can reuse them.',
  inputSchema: codeFunctionRenameApplyInputSchema,
  outputSchema: codeFunctionRenameApplyOutputSchema,
}

export function createCodeFunctionRenameApplyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = codeFunctionRenameApplyInputSchema.parse(args)
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

      const acceptedSuggestions: SemanticNameSuggestionArtifactPayload['suggestions'] = []
      const acceptedSummary: Array<{
        address: string | null
        function: string | null
        candidate_name: string
        normalized_candidate_name: string
        confidence: number
      }> = []
      const warnings: string[] = []

      for (const suggestion of input.suggestions) {
        const normalizedIdentifier = normalizeSuggestionIdentifier(suggestion)
        const normalizedName = sanitizeSemanticName(suggestion.candidate_name)
        if (!normalizedName) {
          warnings.push(
            `Rejected suggestion for ${normalizedIdentifier.address || normalizedIdentifier.function || suggestion.address_or_function || 'unknown'} because candidate_name could not be normalized.`
          )
          continue
        }

        acceptedSuggestions.push({
          address: normalizedIdentifier.address,
          function: normalizedIdentifier.function,
          candidate_name: suggestion.candidate_name,
          normalized_candidate_name: normalizedName,
          confidence: suggestion.confidence,
          why: suggestion.why,
          required_assumptions: suggestion.required_assumptions || [],
          evidence_used: suggestion.evidence_used || [],
        })
        acceptedSummary.push({
          address: normalizedIdentifier.address,
          function: normalizedIdentifier.function,
          candidate_name: suggestion.candidate_name,
          normalized_candidate_name: normalizedName,
          confidence: suggestion.confidence,
        })
      }

      if (acceptedSuggestions.length === 0) {
        return {
          ok: false,
          errors: ['No suggestions were accepted after normalization.'],
          warnings: warnings.length > 0 ? warnings : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const payload: SemanticNameSuggestionArtifactPayload = {
        schema_version: 1,
        sample_id: input.sample_id,
        created_at: new Date().toISOString(),
        session_tag: input.session_tag || null,
        client_name: input.client_name || null,
        model_name: input.model_name || null,
        prepare_artifact_id: input.prepare_artifact_id || null,
        suggestions: acceptedSuggestions,
      }

      const artifact = await persistSemanticNameSuggestionsArtifact(
        workspaceManager,
        database,
        payload
      )

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          accepted_count: acceptedSuggestions.length,
          rejected_count: input.suggestions.length - acceptedSuggestions.length,
          accepted_suggestions: acceptedSummary,
          artifact,
          next_steps: [
            'rerun code.functions.reconstruct to materialize llm_suggested_name / validated_name',
            'rerun code.reconstruct.export to propagate validated names into rewrite output',
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
