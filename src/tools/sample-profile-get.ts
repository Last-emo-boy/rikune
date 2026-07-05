/**
 * sample.profile.get tool implementation
 * Retrieves sample profile including basic information, completed analyses,
 * and workspace/original integrity status.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { DatabaseManager } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { JobQueue } from '../job-queue.js'
import type { CacheManager } from '../cache-manager.js'
import { inspectSampleWorkspace } from '../sample/sample-workspace.js'
import { buildSampleReuseHints } from '../analysis/reuse-hints.js'
import { normalizeFileTypeTags } from './tool-aspect-matrix.js'

const DEFAULT_ANALYSIS_DETAIL = 'compact' as const
const DEFAULT_MAX_ANALYSES = 25
const DEFAULT_JSON_PREVIEW_CHARS = 2048
const DEFAULT_WORKSPACE_FILE_PREVIEW_LIMIT = 16

export const SampleProfileGetInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  stale_running_ms: z
    .number()
    .int()
    .min(1000)
    .nullable()
    .optional()
    .describe(
      'Optional stale-analysis reap threshold in milliseconds. Omit or null to disable auto-reaping.'
    ),
  analysis_detail: z
    .enum(['compact', 'full'])
    .default(DEFAULT_ANALYSIS_DETAIL)
    .describe(
      'compact is the default bounded mode and returns preview snippets plus byte counts for analysis output. full returns full output_json/metrics_json for the returned analyses and is intended for targeted debugging only.'
    ),
  max_analyses: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(DEFAULT_MAX_ANALYSES)
    .describe(
      'Maximum number of analyses to return inline. Most recent analyses are returned first.'
    ),
  json_preview_chars: z
    .number()
    .int()
    .min(128)
    .max(20000)
    .default(DEFAULT_JSON_PREVIEW_CHARS)
    .describe(
      'Maximum number of characters to inline for each analysis output/metrics preview when analysis_detail=compact.'
    ),
  workspace_file_preview_limit: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(DEFAULT_WORKSPACE_FILE_PREVIEW_LIMIT)
    .describe(
      'Maximum number of filenames to inline from workspace/original and alternate original directories.'
    ),
})

export type SampleProfileGetInput = z.infer<typeof SampleProfileGetInputSchema>

export const SampleProfileGetOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample: z.object({
        id: z.string(),
        sha256: z.string(),
        md5: z.string(),
        size: z.number(),
        file_type: z.string().optional(),
        created_at: z.string(),
        source: z.string(),
      }),
      analysis_summary: z.object({
        detail: z.enum(['compact', 'full']),
        total_count: z.number().int().nonnegative(),
        returned_count: z.number().int().nonnegative(),
        analyses_truncated: z.boolean(),
        json_preview_chars: z.number().int().positive(),
      }),
      analyses: z.array(
        z.object({
          id: z.string(),
          stage: z.string(),
          backend: z.string(),
          status: z.string(),
          started_at: z.string().optional(),
          finished_at: z.string().optional(),
          output_json: z.string().optional(),
          metrics_json: z.string().optional(),
          output_json_preview: z.string().optional(),
          metrics_json_preview: z.string().optional(),
          output_json_bytes: z.number().int().nonnegative().optional(),
          metrics_json_bytes: z.number().int().nonnegative().optional(),
          output_json_truncated: z.boolean().optional(),
          metrics_json_truncated: z.boolean().optional(),
        })
      ),
      sample_profile: z
        .object({
          file_type_tags: z.array(z.string()),
          formats: z.array(z.string()),
          platforms: z.array(z.string()),
          architectures: z.array(z.string()),
          evidence_signals: z.array(z.string()),
          workflow_recipes: z.array(z.string()),
          nested_route_hints: z.array(
            z.object({
              source_analysis_id: z.string(),
              source_stage: z.string(),
              path: z.string().optional(),
              format: z.string().optional(),
              recommended_tools: z.array(z.string()),
            })
          ),
          recommended_tools: z.array(z.string()),
          next_actions: z.array(z.string()),
        })
        .optional(),
      routing_profile: z.record(z.any()).optional(),
      workspace: z
        .object({
          status: z.enum([
            'ready',
            'workspace_missing',
            'original_dir_missing',
            'original_file_missing',
          ]),
          workspace_root: z.string().nullable(),
          original_dir: z.string().nullable(),
          reports_dir: z.string().nullable(),
          ghidra_dir: z.string().nullable(),
          workspace_exists: z.boolean(),
          original_dir_exists: z.boolean(),
          reports_dir_exists: z.boolean(),
          ghidra_dir_exists: z.boolean(),
          original_present: z.boolean(),
          original_file_count: z.number().int().nonnegative(),
          original_files: z.array(z.string()),
          original_file_list_truncated: z.boolean(),
          alternate_workspace_root: z.string().nullable(),
          alternate_original_dir: z.string().nullable(),
          alternate_original_present: z.boolean(),
          alternate_original_file_count: z.number().int().nonnegative(),
          alternate_original_files: z.array(z.string()),
          alternate_original_file_list_truncated: z.boolean(),
          remediation: z.array(z.string()),
        })
        .optional(),
      reuse_hints: z.record(z.any()).optional(),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
})

export type SampleProfileGetOutput = z.infer<typeof SampleProfileGetOutputSchema>

export const sampleProfileGetToolDefinition: ToolDefinition = {
  name: 'sample.profile.get',
  description:
    'Query sample metadata, analysis history, and workspace integrity. Defaults to a bounded compact view with analysis output previews instead of returning every raw analysis payload inline.',
  inputSchema: SampleProfileGetInputSchema,
  outputSchema: SampleProfileGetOutputSchema,
}

function truncateInlineText(
  value: string | null,
  limit: number
): {
  full: string | undefined
  preview: string | undefined
  bytes: number | undefined
  truncated: boolean | undefined
} {
  if (!value) {
    return {
      full: undefined,
      preview: undefined,
      bytes: undefined,
      truncated: undefined,
    }
  }

  const preview = value.length > limit ? `${value.slice(0, limit)}…` : value
  return {
    full: value,
    preview,
    bytes: Buffer.byteLength(value, 'utf8'),
    truncated: value.length > limit,
  }
}

function limitInlineFiles(files: string[], limit: number): { files: string[]; truncated: boolean } {
  return {
    files: files.slice(0, limit),
    truncated: files.length > limit,
  }
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function parseJson(value: string | null): unknown {
  if (!value) return null
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : []
}

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {}
}

function normalizeSignalKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .toLowerCase()
    .replace(/_/g, '-')
}

function collectAspectSignals(value: unknown): {
  formats: string[]
  platforms: string[]
  architectures: string[]
  evidence: string[]
  workflowRecipes: string[]
  recommendedTools: string[]
} {
  const formats: string[] = []
  const platforms: string[] = []
  const architectures: string[] = []
  const evidence: string[] = []
  const workflowRecipes: string[] = []
  const recommendedTools: string[] = []
  const seen = new Set<unknown>()

  function pushWorkflowRecipe(value: unknown): void {
    if (typeof value === 'string') {
      const normalized = value.toLowerCase().trim().replace(/_/g, '-')
      if (normalized) workflowRecipes.push(normalized)
      return
    }
    if (Array.isArray(value)) {
      for (const item of value) pushWorkflowRecipe(item)
      return
    }
    if (value && typeof value === 'object') {
      const id = objectValue(value).id
      if (typeof id === 'string') pushWorkflowRecipe(id)
    }
  }

  function visit(node: unknown, key = '', depth = 0): void {
    if (!node || depth > 8 || seen.has(node)) return
    if (typeof node === 'object') seen.add(node)

    if (typeof node === 'string') {
      const normalized = node.toLowerCase().trim().replace(/_/g, '-')
      if (!normalized) return
      const keyName = normalizeSignalKey(key)
      if (keyName.includes('format') || keyName.includes('file-type') || keyName === 'type') {
        formats.push(...normalizeFileTypeTags(normalized))
      }
      if (keyName.includes('platform') || keyName.includes('os')) {
        platforms.push(normalized)
      }
      if (keyName.includes('arch') || keyName.includes('machine') || keyName.includes('cpu')) {
        architectures.push(normalized)
      }
      if (
        keyName.includes('evidence') ||
        keyName.includes('category') ||
        keyName.includes('signal') ||
        keyName.includes('finding')
      ) {
        evidence.push(normalized)
      }
      if (keyName.includes('tool')) {
        recommendedTools.push(normalized)
      }
      if (
        keyName.includes('workflow-recipe') ||
        keyName === 'workflow-id' ||
        keyName === 'recipe-id'
      ) {
        workflowRecipes.push(normalized)
      }
      return
    }

    if (Array.isArray(node)) {
      for (const item of node) visit(item, key, depth + 1)
      return
    }

    if (typeof node === 'object') {
      for (const [childKey, childValue] of Object.entries(node)) {
        const normalizedChildKey = normalizeSignalKey(childKey)
        if (childKey === 'recommended_next_tools' || childKey === 'recommended_tools') {
          recommendedTools.push(...stringArray(childValue))
        } else if (childKey === 'artifact_refs' || childKey === 'artifacts') {
          evidence.push('artifact')
        } else if (childKey === 'evidence' || childKey === 'evidence_state') {
          evidence.push('evidence')
        } else if (
          normalizedChildKey === 'workflow-recipes' ||
          normalizedChildKey === 'workflow-recipe' ||
          normalizedChildKey === 'workflow-id'
        ) {
          pushWorkflowRecipe(childValue)
        }
        visit(childValue, childKey, depth + 1)
      }
    }
  }

  visit(value)
  return {
    formats: uniqueStrings(formats),
    platforms: uniqueStrings(platforms),
    architectures: uniqueStrings(architectures),
    evidence: uniqueStrings(evidence),
    workflowRecipes: uniqueStrings(workflowRecipes),
    recommendedTools: uniqueStrings(recommendedTools),
  }
}

function collectNestedRouteHints(
  analysis: { id: string; stage: string; output_json: string | null },
  parsed: unknown
): Array<{
  source_analysis_id: string
  source_stage: string
  path?: string
  format?: string
  recommended_tools: string[]
}> {
  const hints: Array<{
    source_analysis_id: string
    source_stage: string
    path?: string
    format?: string
    recommended_tools: string[]
  }> = []
  const seen = new Set<unknown>()

  function visit(node: unknown, depth = 0): void {
    if (!node || depth > 8 || seen.has(node)) return
    if (typeof node === 'object') seen.add(node)
    if (Array.isArray(node)) {
      for (const item of node) visit(item, depth + 1)
      return
    }
    if (typeof node !== 'object') return

    const obj = objectValue(node)
    const recommendedTools = uniqueStrings([
      ...stringArray(obj.recommended_tools),
      ...stringArray(obj.recommended_next_tools),
    ])
    const path =
      typeof obj.path === 'string'
        ? obj.path
        : typeof obj.file === 'string'
          ? obj.file
          : typeof obj.name === 'string'
            ? obj.name
            : undefined
    const format =
      typeof obj.format === 'string'
        ? obj.format
        : typeof obj.type === 'string'
          ? obj.type
          : typeof obj.file_type === 'string'
            ? obj.file_type
            : undefined

    if (recommendedTools.length > 0 || /nested|candidate/i.test(Object.keys(obj).join(' '))) {
      hints.push({
        source_analysis_id: analysis.id,
        source_stage: analysis.stage,
        path,
        format,
        recommended_tools: recommendedTools,
      })
    }

    for (const value of Object.values(obj)) visit(value, depth + 1)
  }

  visit(parsed)
  return hints
}

function buildSampleRoutingProfile(params: {
  fileType: string | null
  analyses: Array<{ id: string; stage: string; output_json: string | null }>
}) {
  const fileTypeTags = normalizeFileTypeTags(params.fileType)
  const formats = [...fileTypeTags]
  const platforms: string[] = []
  const architectures: string[] = []
  const evidenceSignals: string[] = []
  const workflowRecipes: string[] = []
  const recommendedTools: string[] = []
  const nestedRouteHints: Array<{
    source_analysis_id: string
    source_stage: string
    path?: string
    format?: string
    recommended_tools: string[]
  }> = []

  for (const analysis of params.analyses) {
    const parsed = parseJson(analysis.output_json)
    const signals = collectAspectSignals(parsed)
    formats.push(...signals.formats)
    platforms.push(...signals.platforms)
    architectures.push(...signals.architectures)
    evidenceSignals.push(...signals.evidence)
    workflowRecipes.push(...signals.workflowRecipes)
    recommendedTools.push(...signals.recommendedTools)
    nestedRouteHints.push(...collectNestedRouteHints(analysis, parsed))
  }

  const normalizedFormats = uniqueStrings(formats)
  const normalizedPlatforms = uniqueStrings([
    ...platforms,
    ...fileTypeTags.filter((tag) =>
      [
        'windows',
        'linux',
        'macos',
        'ios',
        'android',
        'java',
        'dotnet',
        'wasm',
        'embedded',
      ].includes(tag)
    ),
    ...normalizedFormats.filter((tag) =>
      [
        'windows',
        'linux',
        'macos',
        'ios',
        'android',
        'java',
        'dotnet',
        'wasm',
        'embedded',
      ].includes(tag)
    ),
  ])
  const nextActions = [
    normalizedFormats.length > 0
      ? `Use workflow.search file_type=${normalizedFormats[0]} to rank matching workflows and static plugins before exposing specialist tools.`
      : 'Use workflow.search to inspect available format workflows before selecting specialist tools.',
    nestedRouteHints.length > 0
      ? 'Review nested_route_hints before selecting deep static or extraction tools.'
      : 'Run a passive inventory tool first when the sample is an archive, package, container, or bundle.',
  ]

  return {
    file_type_tags: fileTypeTags,
    formats: normalizedFormats,
    platforms: normalizedPlatforms,
    architectures: uniqueStrings(architectures),
    evidence_signals: uniqueStrings(evidenceSignals),
    workflow_recipes: uniqueStrings(workflowRecipes),
    nested_route_hints: nestedRouteHints.slice(0, 50),
    recommended_tools: uniqueStrings(recommendedTools).slice(0, 50),
    next_actions: uniqueStrings(nextActions),
  }
}

export function createSampleProfileGetHandler(
  database: DatabaseManager,
  workspaceManager?: WorkspaceManager,
  options: { jobQueue?: JobQueue; cacheManager?: CacheManager } = {}
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    try {
      const input = SampleProfileGetInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)

      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      if (typeof input.stale_running_ms === 'number') {
        database.reapStaleAnalyses(input.stale_running_ms, input.sample_id)
      }
      const analyses = database.findAnalysesBySample(input.sample_id)
      const workspace = workspaceManager
        ? await inspectSampleWorkspace(workspaceManager, input.sample_id)
        : undefined
      const reuseHints = await buildSampleReuseHints({
        database,
        jobQueue: options.jobQueue,
        sampleId: input.sample_id,
        sampleSha256: sample.sha256,
        limit: Math.min(input.max_analyses, 10),
      })
      const boundedAnalyses = analyses.slice(0, input.max_analyses)
      const sampleProfile = buildSampleRoutingProfile({
        fileType: sample.file_type,
        analyses: boundedAnalyses,
      })
      const limitedWorkspace = workspace
        ? (() => {
            const originalFiles = limitInlineFiles(
              workspace.original_files,
              input.workspace_file_preview_limit
            )
            const alternateOriginalFiles = limitInlineFiles(
              workspace.alternate_original_files,
              input.workspace_file_preview_limit
            )

            return {
              ...workspace,
              original_files: originalFiles.files,
              original_file_list_truncated: originalFiles.truncated,
              alternate_original_file_count: workspace.alternate_original_files.length,
              alternate_original_files: alternateOriginalFiles.files,
              alternate_original_file_list_truncated: alternateOriginalFiles.truncated,
            }
          })()
        : undefined

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
          analysis_summary: {
            detail: input.analysis_detail,
            total_count: analyses.length,
            returned_count: boundedAnalyses.length,
            analyses_truncated: analyses.length > boundedAnalyses.length,
            json_preview_chars: input.json_preview_chars,
          },
          analyses: boundedAnalyses.map((analysis) => {
            const output = truncateInlineText(analysis.output_json, input.json_preview_chars)
            const metrics = truncateInlineText(analysis.metrics_json, input.json_preview_chars)
            return {
              id: analysis.id,
              stage: analysis.stage,
              backend: analysis.backend,
              status: analysis.status,
              started_at: analysis.started_at || undefined,
              finished_at: analysis.finished_at || undefined,
              output_json: input.analysis_detail === 'full' ? output.full : undefined,
              metrics_json: input.analysis_detail === 'full' ? metrics.full : undefined,
              output_json_preview: input.analysis_detail === 'compact' ? output.preview : undefined,
              metrics_json_preview:
                input.analysis_detail === 'compact' ? metrics.preview : undefined,
              output_json_bytes: output.bytes,
              metrics_json_bytes: metrics.bytes,
              output_json_truncated:
                input.analysis_detail === 'compact' ? output.truncated : undefined,
              metrics_json_truncated:
                input.analysis_detail === 'compact' ? metrics.truncated : undefined,
            }
          }),
          sample_profile: sampleProfile,
          routing_profile: sampleProfile,
          workspace: limitedWorkspace,
          reuse_hints: reuseHints,
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
