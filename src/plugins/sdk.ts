/**
 * Plugin SDK — Re-exported from the shared @rikune/plugin-sdk package.
 *
 * This file exists to preserve backward compatibility for all existing
 * internal plugins that import from './sdk' or '@/plugins/sdk'.
 */

import { z } from 'zod'

export * from '@rikune/plugin-sdk'

export const ArtifactRefSchema = z
  .object({
    id: z.string(),
    type: z.string(),
    path: z.string(),
    sha256: z.string(),
    mime: z.string().optional(),
    metadata: z.record(z.string(), z.any()).optional(),
  })
  .passthrough()

export const WorkerResultMetricsSchema = z
  .object({
    elapsed_ms: z.number().optional(),
    tool: z.string().optional(),
  })
  .passthrough()

export const EvidenceRefSchema = z
  .object({
    id: z.string(),
    category: z.string(),
    source: z.string(),
    toolName: z.string().optional(),
    sampleId: z.string().optional(),
    artifactRefs: z.array(ArtifactRefSchema).optional(),
    confidence: z.number().min(0).max(1).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
  })
  .passthrough()

export const EvidenceTimelineEntrySchema = z
  .object({
    timestamp: z.string().optional(),
    source: z.string(),
    toolName: z.string(),
    sampleId: z.string().optional(),
    category: z.string(),
    subject: z.string().optional(),
    action: z.string().optional(),
    target: z.string().optional(),
    confidence: z.number().min(0).max(1).optional(),
    artifactRefs: z.array(ArtifactRefSchema).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
  })
  .passthrough()

export function createWorkerResultOutputSchema<TData extends z.ZodTypeAny = z.ZodAny>(
  dataSchema: TData = z.any() as unknown as TData
) {
  return z
    .object({
      ok: z.boolean(),
      data: dataSchema.optional(),
      warnings: z.array(z.string()).optional(),
      errors: z.array(z.string()).optional(),
      artifacts: z.array(ArtifactRefSchema).optional(),
      evidence: z.array(EvidenceRefSchema).optional(),
      timeline: z.array(EvidenceTimelineEntrySchema).optional(),
      metrics: WorkerResultMetricsSchema.optional(),
      setup_actions: z.array(z.any()).optional(),
      required_user_inputs: z.array(z.any()).optional(),
    })
    .passthrough()
}

export const WorkerResultOutputSchema = createWorkerResultOutputSchema()
