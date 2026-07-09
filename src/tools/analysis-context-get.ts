/**
 * analysis.context.get MCP tool
 * Read-only preflight for prior work and reuse hints before expensive analysis.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { DatabaseManager } from '../database.js'
import type { JobQueue } from '../job-queue.js'
import { buildSampleReuseHints } from '../analysis/reuse-hints.js'

const TOOL_NAME = 'analysis.context.get'

export const AnalysisContextGetInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  intended_tool: z
    .string()
    .optional()
    .describe('Optional tool the client is considering next, such as attack.map'),
  function_address: z
    .string()
    .optional()
    .describe('Optional function address for function-level reuse hints'),
  function_name: z
    .string()
    .optional()
    .describe('Optional function name or substring for function-level reuse hints'),
  limit: z.number().int().min(1).max(50).optional().default(10),
})

export type AnalysisContextGetInput = z.infer<typeof AnalysisContextGetInputSchema>

export const AnalysisContextGetOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      intended_tool: z.string().optional(),
      reuse_hints: z.record(z.string(), z.any()),
      result_mode: z.literal('preflight'),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const analysisContextGetToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Read-only preflight for existing analysis context. Use before rerunning expensive tools to discover active jobs, completed jobs, staged runs, cache entries, and function-level reuse hints for a sample.',
  inputSchema: AnalysisContextGetInputSchema,
  outputSchema: AnalysisContextGetOutputSchema,
}

export function createAnalysisContextGetHandler(database: DatabaseManager, jobQueue?: JobQueue) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = AnalysisContextGetInputSchema.parse(args)
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

      const reuseHints = await buildSampleReuseHints({
        database,
        jobQueue,
        sampleId: input.sample_id,
        sampleSha256: sample.sha256,
        intendedTool: input.intended_tool,
        functionAddress: input.function_address,
        functionName: input.function_name,
        limit: input.limit,
      })

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          ...(input.intended_tool ? { intended_tool: input.intended_tool } : {}),
          reuse_hints: reuseHints,
          result_mode: 'preflight',
          recommended_next_tools: reuseHints.recommended_next_tools,
          next_actions: reuseHints.next_actions,
        },
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
