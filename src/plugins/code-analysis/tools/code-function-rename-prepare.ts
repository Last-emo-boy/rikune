import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { CacheManager } from '../../../cache-manager.js'
import { createCodeFunctionsReconstructHandler } from './code-functions-reconstruct.js'
import {
  persistSemanticNamePrepareBundleArtifact,
  SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE,
} from '../../../artifacts/semantic-name-suggestion-artifacts.js'
import { buildSemanticNameReviewPromptText } from '../../../prompts/semantic-name-review.js'

const TOOL_NAME = 'code.function.rename.prepare'

const PreparedFunctionSchema = z.object({
  function: z.string(),
  address: z.string(),
  confidence: z.number().min(0).max(1),
  suggested_name: z.string().nullable().optional(),
  name_resolution: z.any().optional(),
  semantic_evidence: z.any().optional(),
  suggestion_required: z.boolean(),
})

const PreparedBundleSchema = z.object({
  schema_version: z.literal(1),
  sample_id: z.string(),
  analysis_goal: z.string(),
  generated_at: z.string(),
  selection: z.object({
    address: z.string().nullable(),
    symbol: z.string().nullable(),
    topk: z.number().int().positive(),
    include_resolved: z.boolean(),
    max_functions: z.number().int().positive(),
    evidence_scope: z.enum(['all', 'latest', 'session']),
    evidence_session_tag: z.string().nullable(),
    semantic_scope: z.enum(['all', 'latest', 'session']),
    semantic_session_tag: z.string().nullable(),
  }),
  suggestion_contract: z.object({
    output_root: z.literal('suggestions'),
    required_fields: z.array(z.string()),
  }),
  functions: z.array(PreparedFunctionSchema),
})

export const codeFunctionRenamePrepareInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  address: z.string().optional().describe('Optional specific function address'),
  symbol: z.string().optional().describe('Optional specific function symbol'),
  topk: z
    .number()
    .int()
    .min(1)
    .max(20)
    .default(6)
    .describe('When address/symbol not provided, prepare up to top-K reconstructed functions'),
  max_functions: z
    .number()
    .int()
    .min(1)
    .max(20)
    .default(6)
    .describe('Maximum number of functions included in the prepared bundle'),
  include_resolved: z
    .boolean()
    .default(false)
    .describe('Include functions that already have validated rule-based names'),
  analysis_goal: z
    .string()
    .min(1)
    .max(400)
    .default(
      'Reverse-engineer the prepared functions and propose precise human-readable semantic names.'
    )
    .describe('Human-readable analysis goal injected into the task prompt for any external LLM'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist the prepared evidence bundle as a JSON artifact for later review and provenance'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional semantic naming session tag used for artifact grouping'),
  evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Runtime evidence scope forwarded to code.functions.reconstruct for semantic review preparation'),
  evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
  semantic_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Semantic naming artifact scope forwarded to code.functions.reconstruct for review preparation'),
  semantic_session_tag: z
    .string()
    .optional()
    .describe('Optional semantic naming session selector used when semantic_scope=session or to narrow all/latest results'),
})
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })
  .refine((value) => value.semantic_scope !== 'session' || Boolean(value.semantic_session_tag?.trim()), {
    message: 'semantic_session_tag is required when semantic_scope=session',
    path: ['semantic_session_tag'],
  })

export const codeFunctionRenamePrepareOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      analysis_goal: z.string(),
      prepared_count: z.number().int().nonnegative(),
      unresolved_count: z.number().int().nonnegative(),
      prompt_name: z.literal('reverse.semantic_name_review'),
      prompt_arguments: z.object({
        analysis_goal: z.string(),
        prepared_bundle_json: z.string(),
      }),
      task_prompt: z.string(),
      prepared_bundle: PreparedBundleSchema,
      artifact: z
        .object({
          id: z.string(),
          type: z.literal(SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE),
          path: z.string(),
          sha256: z.string(),
          mime: z.string().optional(),
        })
        .optional(),
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

export const codeFunctionRenamePrepareToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Prepare structured semantic-evidence bundles and a model-agnostic MCP prompt contract for external LLM function renaming review.',
  inputSchema: codeFunctionRenamePrepareInputSchema,
  outputSchema: codeFunctionRenamePrepareOutputSchema,
}

interface CodeFunctionRenamePrepareDependencies {
  reconstructHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

function shouldIncludePreparedFunction(
  func: any,
  includeResolved: boolean
): boolean {
  if (includeResolved) {
    return true
  }

  return !func?.name_resolution?.validated_name
}

function dedupePreparedFunctions(functions: any[]): any[] {
  const seen = new Set<string>()
  const deduped: any[] = []

  for (const item of functions) {
    const key = `${String(item?.address || 'unknown').toLowerCase()}::${String(item?.function || 'unknown').toLowerCase()}`
    if (seen.has(key)) {
      continue
    }
    seen.add(key)
    deduped.push(item)
  }

  return deduped
}

export function createCodeFunctionRenamePrepareHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: CodeFunctionRenamePrepareDependencies
) {
  const reconstructHandler =
    dependencies?.reconstructHandler ||
    createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = codeFunctionRenamePrepareInputSchema.parse(args)
      const reconstructResult = await reconstructHandler({
        sample_id: input.sample_id,
        address: input.address,
        symbol: input.symbol,
        topk: input.topk,
        include_xrefs: true,
        max_pseudocode_lines: 80,
        max_assembly_lines: 60,
        timeout: 45,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag,
        semantic_scope: input.semantic_scope,
        semantic_session_tag: input.semantic_session_tag,
      })

      if (!reconstructResult.ok) {
        return {
          ok: false,
          errors: reconstructResult.errors || ['code.functions.reconstruct failed'],
          warnings: reconstructResult.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const functions = dedupePreparedFunctions(
        ((reconstructResult.data as any)?.functions || []).filter((item: any) =>
          shouldIncludePreparedFunction(item, input.include_resolved)
        )
      )
        .slice(0, input.max_functions)
        .map((item: any) => ({
          function: item.function,
          address: item.address,
          confidence: item.confidence,
          suggested_name: item.suggested_name || null,
          name_resolution: item.name_resolution,
          semantic_evidence: item.semantic_evidence,
          suggestion_required: !item?.name_resolution?.validated_name,
        }))

      const preparedBundle = {
        schema_version: 1 as const,
        sample_id: input.sample_id,
        analysis_goal: input.analysis_goal,
        generated_at: new Date().toISOString(),
        selection: {
          address: input.address || null,
          symbol: input.symbol || null,
          topk: input.topk,
          include_resolved: input.include_resolved,
          max_functions: input.max_functions,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag || null,
          semantic_scope: input.semantic_scope,
          semantic_session_tag: input.semantic_session_tag || null,
        },
        suggestion_contract: {
          output_root: 'suggestions' as const,
          required_fields: [
            'address_or_function',
            'candidate_name',
            'confidence',
            'why',
            'required_assumptions',
            'evidence_used',
          ],
        },
        functions,
      }

      const preparedBundleJson = JSON.stringify(preparedBundle, null, 2)
      const taskPrompt = buildSemanticNameReviewPromptText(
        preparedBundleJson,
        input.analysis_goal
      )

      const warnings = [...(reconstructResult.warnings || [])]
      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined

      if (functions.length === 0) {
        warnings.push('No functions matched the preparation filter. Consider include_resolved=true or a larger topk.')
      }

      if (input.persist_artifact) {
        artifact = await persistSemanticNamePrepareBundleArtifact(
          workspaceManager,
          database,
          input.sample_id,
          preparedBundle,
          input.session_tag
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          analysis_goal: input.analysis_goal,
          prepared_count: functions.length,
          unresolved_count: functions.filter((item: { suggestion_required: boolean }) => item.suggestion_required).length,
          prompt_name: 'reverse.semantic_name_review',
          prompt_arguments: {
            analysis_goal: input.analysis_goal,
            prepared_bundle_json: preparedBundleJson,
          },
          task_prompt: taskPrompt,
          prepared_bundle: preparedBundle,
          artifact,
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
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
