/**
 * dynamic.trace.import tool
 * Import external runtime API traces or memory-snapshot summaries into the MCP workspace.
 */

import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import {
  normalizeDynamicTrace,
  normalizeDynamicTraceArtifactPayload,
  summarizeDynamicTrace,
  type DynamicEvidenceKind,
  type DynamicTraceSourceFormat,
} from '../dynamic-trace.js'

const TOOL_NAME = 'dynamic.trace.import'

const DynamicTraceImportInputSchema = z
  .object({
    sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
    format: z
      .enum(['auto', 'normalized', 'generic_json', 'frida_json', 'speakeasy_json'])
      .optional()
      .default('auto')
      .describe('Format hint for imported trace payload'),
    evidence_kind: z
      .enum(['trace', 'memory_snapshot', 'hybrid'])
      .optional()
      .default('trace')
      .describe('Whether the imported evidence reflects executed runtime trace, memory snapshot, or hybrid evidence'),
    path: z.string().optional().describe('Path to external JSON trace file'),
    trace_json: z.any().optional().describe('Inline JSON payload to import when path is not used'),
    trace_name: z.string().optional().describe('Optional source name used in persisted artifact naming'),
    persist_artifact: z
      .boolean()
      .optional()
      .default(true)
      .describe('Persist normalized trace into workspace reports/dynamic'),
    register_analysis: z
      .boolean()
      .optional()
      .default(true)
      .describe('Insert a completed analysis row for imported runtime evidence'),
  })
  .refine((value) => Boolean(value.path) !== Boolean(value.trace_json), {
    message: 'Provide exactly one of `path` or `trace_json`.',
  })

type DynamicTraceImportInput = z.infer<typeof DynamicTraceImportInputSchema>

const DynamicTraceImportOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      trace_id: z.string(),
      format: z.string(),
      evidence_kind: z.string(),
      executed: z.boolean(),
      summary: z.object({
        artifact_count: z.number(),
        executed: z.boolean(),
        api_count: z.number(),
        memory_region_count: z.number(),
        stage_count: z.number(),
        observed_apis: z.array(z.string()),
        high_signal_apis: z.array(z.string()),
        memory_regions: z.array(z.string()),
        stages: z.array(z.string()),
        risk_hints: z.array(z.string()),
        evidence: z.array(z.string()),
        summary: z.string(),
      }),
      normalized_trace: z.any(),
      analysis_id: z.string().optional(),
      artifact: z
        .object({
          id: z.string(),
          type: z.string(),
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

export const dynamicTraceImportToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Import external runtime API traces or memory-snapshot summaries (Frida/Speakeasy/generic JSON) into the workspace and register them as MCP artifacts.',
  inputSchema: DynamicTraceImportInputSchema,
  outputSchema: DynamicTraceImportOutputSchema,
}

function sanitizeName(value: string | undefined): string {
  const base = (value || 'trace').trim().toLowerCase()
  const normalized = base.replace(/[^a-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 48) : 'trace'
}

function resolveSourceFormat(
  inputFormat: DynamicTraceImportInput['format'],
  normalizedHint: ReturnType<typeof normalizeDynamicTraceArtifactPayload> | null
): DynamicTraceSourceFormat {
  if (normalizedHint) {
    return normalizedHint.source_format
  }
  if (inputFormat === 'auto' || inputFormat === 'normalized') {
    return 'generic_json'
  }
  return inputFormat
}

async function readInputPayload(input: DynamicTraceImportInput): Promise<unknown> {
  if (input.path) {
    const content = await fs.readFile(input.path, 'utf-8')
    return JSON.parse(content) as unknown
  }

  if (typeof input.trace_json === 'string') {
    return JSON.parse(input.trace_json) as unknown
  }

  return input.trace_json
}

export function createDynamicTraceImportHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = DynamicTraceImportInputSchema.parse(args)
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

      const rawPayload = await readInputPayload(input)
      const autoNormalized =
        input.format === 'auto' || input.format === 'normalized'
          ? normalizeDynamicTraceArtifactPayload(rawPayload)
          : null
      const normalizedTrace =
        autoNormalized ||
        normalizeDynamicTrace(rawPayload, {
          sourceFormat: resolveSourceFormat(input.format, autoNormalized),
          evidenceKind: input.evidence_kind as DynamicEvidenceKind,
          sourceName: input.trace_name || (input.path ? path.basename(input.path) : undefined),
        })
      const summary = summarizeDynamicTrace(normalizedTrace)
      const warnings: string[] = []
      const artifacts: ArtifactRef[] = []
      let persistedArtifact: ArtifactRef | undefined
      let analysisId: string | undefined

      if (!normalizedTrace.executed) {
        warnings.push(
          'Imported evidence does not prove full execution; treat it as memory or hybrid runtime evidence until corroborated.'
        )
      }

      if (input.persist_artifact) {
        const workspace = await workspaceManager.createWorkspace(input.sample_id)
        const reportDir = path.join(workspace.reports, 'dynamic')
        await fs.mkdir(reportDir, { recursive: true })

        const fileName = `imported_${sanitizeName(input.trace_name || path.basename(input.path || 'trace'))}_${Date.now()}.json`
        const absPath = path.join(reportDir, fileName)
        const serialized = JSON.stringify(normalizedTrace, null, 2)
        await fs.writeFile(absPath, serialized, 'utf-8')

        const artifactId = randomUUID()
        const artifactSha256 = createHash('sha256').update(serialized).digest('hex')
        const relativePath = `reports/dynamic/${fileName}`

        database.insertArtifact({
          id: artifactId,
          sample_id: input.sample_id,
          type: 'dynamic_trace_json',
          path: relativePath,
          sha256: artifactSha256,
          mime: 'application/json',
          created_at: new Date().toISOString(),
        })

        persistedArtifact = {
          id: artifactId,
          type: 'dynamic_trace_json',
          path: relativePath,
          sha256: artifactSha256,
          mime: 'application/json',
        }
        artifacts.push(persistedArtifact)
      }

      if (input.register_analysis) {
        analysisId = randomUUID()
        database.insertAnalysis({
          id: analysisId,
          sample_id: input.sample_id,
          stage: 'dynamic_trace_import',
          backend: 'runtime_import',
          status: 'done',
          started_at: new Date(startTime).toISOString(),
          finished_at: new Date().toISOString(),
          output_json: JSON.stringify({
            trace_format: normalizedTrace.source_format,
            evidence_kind: normalizedTrace.evidence_kind,
            executed: normalizedTrace.executed,
            summary,
            artifact_id: persistedArtifact?.id,
          }),
          metrics_json: JSON.stringify({
            api_count: summary.api_count,
            memory_region_count: summary.memory_region_count,
            stage_count: summary.stage_count,
          }),
        })
      }

      return {
        ok: true,
        data: {
          trace_id: randomUUID(),
          format: normalizedTrace.source_format,
          evidence_kind: normalizedTrace.evidence_kind,
          executed: normalizedTrace.executed,
          summary,
          normalized_trace: normalizedTrace,
          analysis_id: analysisId,
          artifact: persistedArtifact,
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
        errors: [(error as Error).message],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
