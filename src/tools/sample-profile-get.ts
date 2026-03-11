/**
 * sample.profile.get tool implementation
 * Retrieves sample profile including basic information and completed analyses
 * Requirements: Data Model
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { DatabaseManager } from '../database.js'

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for sample.profile.get tool
 */
export const SampleProfileGetInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  stale_running_ms: z
    .number()
    .int()
    .min(1000)
    .nullable()
    .optional()
    .describe('Optional stale-analysis reap threshold in milliseconds. Omit or null to disable auto-reaping.'),
})

export type SampleProfileGetInput = z.infer<typeof SampleProfileGetInputSchema>

/**
 * Output schema for sample.profile.get tool
 */
export const SampleProfileGetOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample: z.object({
      id: z.string(),
      sha256: z.string(),
      md5: z.string(),
      size: z.number(),
      file_type: z.string().optional(),
      created_at: z.string(),
      source: z.string(),
    }),
    analyses: z.array(z.object({
      id: z.string(),
      stage: z.string(),
      backend: z.string(),
      status: z.string(),
      started_at: z.string().optional(),
      finished_at: z.string().optional(),
      output_json: z.string().optional(),
      metrics_json: z.string().optional(),
    })),
  }).optional(),
  errors: z.array(z.string()).optional(),
})

export type SampleProfileGetOutput = z.infer<typeof SampleProfileGetOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for sample.profile.get
 */
export const sampleProfileGetToolDefinition: ToolDefinition = {
  name: 'sample.profile.get',
  description: '查询样本基础信息和已完成的分析',
  inputSchema: SampleProfileGetInputSchema,
  outputSchema: SampleProfileGetOutputSchema,
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create sample.profile.get tool handler
 * Requirements: Data Model
 */
export function createSampleProfileGetHandler(
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    try {
      const input = SampleProfileGetInputSchema.parse(args)

      // 1. Query sample from database
      const sample = database.findSample(input.sample_id)

      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      // 2. Query analyses for this sample
      if (typeof input.stale_running_ms === 'number') {
        database.reapStaleAnalyses(input.stale_running_ms, input.sample_id)
      }
      const analyses = database.findAnalysesBySample(input.sample_id)

      // 3. Return profile data
      return {
        ok: true,
        data: {
          sample: {
            id: sample.id,
            sha256: sample.sha256,
            md5: sample.md5,
            size: sample.size,
            file_type: sample.file_type || undefined,
            created_at: sample.created_at,
            source: sample.source,
          },
          analyses: analyses.map(analysis => ({
            id: analysis.id,
            stage: analysis.stage,
            backend: analysis.backend,
            status: analysis.status,
            started_at: analysis.started_at || undefined,
            finished_at: analysis.finished_at || undefined,
            output_json: analysis.output_json || undefined,
            metrics_json: analysis.metrics_json || undefined,
          })),
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
      }
    }
  }
}
