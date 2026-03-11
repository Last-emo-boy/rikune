import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { createCodeFunctionsReconstructHandler } from './code-functions-reconstruct.js'
import {
  persistSemanticExplanationPrepareBundleArtifact,
  SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE,
} from '../semantic-name-suggestion-artifacts.js'
import { buildFunctionExplanationReviewPromptText } from '../prompts/function-explanation-review.js'

const TOOL_NAME = 'code.function.explain.prepare'

const PreparedExplanationFunctionSchema = z.object({
  function: z.string(),
  address: z.string(),
  confidence: z.number().min(0).max(1),
  validated_name: z.string().nullable(),
  resolution_source: z.string().nullable(),
  semantic_summary: z.string(),
  confidence_profile: z.any().optional(),
  runtime_confidence_profile: z.any().nullable().optional(),
  naming_confidence_profile: z.any().optional(),
  behavior_tags: z.array(z.string()).optional(),
  xref_signals: z.array(z.any()).optional(),
  call_relationships: z.any().optional(),
  runtime_context: z.any().nullable().optional(),
  semantic_evidence: z.any().optional(),
  source_like_snippet: z.string().nullable().optional(),
  assembly_excerpt: z.string().nullable().optional(),
  gaps: z.array(z.string()).optional(),
})

const PreparedExplanationBundleSchema = z.object({
  schema_version: z.literal(1),
  sample_id: z.string(),
  analysis_goal: z.string(),
  generated_at: z.string(),
  selection: z.object({
    address: z.string().nullable(),
    symbol: z.string().nullable(),
    topk: z.number().int().positive(),
    max_functions: z.number().int().positive(),
    include_resolved: z.boolean(),
    evidence_scope: z.enum(['all', 'latest', 'session']),
    evidence_session_tag: z.string().nullable(),
  }),
  output_contract: z.object({
    output_root: z.literal('explanations'),
    required_fields: z.array(z.string()),
  }),
  functions: z.array(PreparedExplanationFunctionSchema),
})

export const codeFunctionExplainPrepareInputSchema = z
  .object({
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
      .describe('Maximum number of functions included in the prepared explanation bundle'),
    include_resolved: z
      .boolean()
      .default(true)
      .describe('Include already resolved functions so the external LLM can explain stable names and unresolved ones together'),
    analysis_goal: z
      .string()
      .min(1)
      .max(400)
      .default(
        'Explain the prepared functions in plain language and propose evidence-grounded rewrite guidance.'
      )
      .describe('Human-readable analysis goal injected into the prompt contract for any external LLM'),
    persist_artifact: z
      .boolean()
      .default(true)
      .describe('Persist the prepared explanation bundle as a JSON artifact for later review and provenance'),
    session_tag: z
      .string()
      .optional()
      .describe('Optional semantic explanation session tag used for artifact grouping'),
    evidence_scope: z
      .enum(['all', 'latest', 'session'])
      .default('all')
      .describe('Runtime evidence scope forwarded to code.functions.reconstruct for explanation preparation'),
    evidence_session_tag: z
      .string()
      .optional()
      .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
  })
  .refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
    message: 'evidence_session_tag is required when evidence_scope=session',
    path: ['evidence_session_tag'],
  })

export const codeFunctionExplainPrepareOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      analysis_goal: z.string(),
      prepared_count: z.number().int().nonnegative(),
      prompt_name: z.literal('reverse.function_explanation_review'),
      prompt_arguments: z.object({
        analysis_goal: z.string(),
        prepared_bundle_json: z.string(),
      }),
      task_prompt: z.string(),
      prepared_bundle: PreparedExplanationBundleSchema,
      artifact: z
        .object({
          id: z.string(),
          type: z.literal(SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE),
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

export const codeFunctionExplainPrepareToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Prepare a structured evidence bundle and MCP prompt contract so any tool-calling LLM can explain reconstructed functions and produce a universal output layer.',
  inputSchema: codeFunctionExplainPrepareInputSchema,
  outputSchema: codeFunctionExplainPrepareOutputSchema,
}

interface CodeFunctionExplainPrepareDependencies {
  reconstructHandler?: (args: ToolArgs) => Promise<WorkerResult>
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

export function createCodeFunctionExplainPrepareHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: CodeFunctionExplainPrepareDependencies
) {
  const reconstructHandler =
    dependencies?.reconstructHandler ||
    createCodeFunctionsReconstructHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = codeFunctionExplainPrepareInputSchema.parse(args)
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

      const functions = dedupePreparedFunctions(((reconstructResult.data as any)?.functions || []))
        .filter((item: any) => input.include_resolved || !item?.name_resolution?.validated_name)
        .slice(0, input.max_functions)
        .map((item: any) => ({
          function: item.function,
          address: item.address,
          confidence: item.confidence,
          validated_name: item?.name_resolution?.validated_name || null,
          resolution_source: item?.name_resolution?.resolution_source || null,
          semantic_summary: item.semantic_summary || '',
          confidence_profile: item.confidence_profile,
          runtime_confidence_profile: item.runtime_confidence_profile || null,
          naming_confidence_profile: item.naming_confidence_profile,
          behavior_tags: Array.isArray(item.behavior_tags) ? item.behavior_tags : [],
          xref_signals: Array.isArray(item.xref_signals) ? item.xref_signals : [],
          call_relationships: item.call_relationships || { callers: [], callees: [] },
          runtime_context: item.runtime_context || null,
          semantic_evidence: item.semantic_evidence || {},
          source_like_snippet: item.source_like_snippet || null,
          assembly_excerpt: item.assembly_excerpt || null,
          gaps: Array.isArray(item.gaps) ? item.gaps : [],
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
          max_functions: input.max_functions,
          include_resolved: input.include_resolved,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag || null,
        },
        output_contract: {
          output_root: 'explanations' as const,
          required_fields: [
            'address_or_function',
            'summary',
            'behavior',
            'confidence',
            'assumptions',
            'evidence_used',
            'rewrite_guidance',
          ],
        },
        functions,
      }

      const preparedBundleJson = JSON.stringify(preparedBundle, null, 2)
      const taskPrompt = buildFunctionExplanationReviewPromptText(
        preparedBundleJson,
        input.analysis_goal
      )

      const warnings = [...(reconstructResult.warnings || [])]
      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined

      if (functions.length === 0) {
        warnings.push(
          'No functions matched the explanation preparation filter. Consider include_resolved=true or a larger topk.'
        )
      }

      if (input.persist_artifact) {
        artifact = await persistSemanticExplanationPrepareBundleArtifact(
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
          prompt_name: 'reverse.function_explanation_review',
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
