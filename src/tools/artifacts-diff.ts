import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { listArtifactInventory, normalizeRelativeArtifactPath } from '../artifacts/artifact-inventory.js'

const TOOL_NAME = 'artifacts.diff'
const TOOL_VERSION = '0.1.0'

export const artifactsDiffInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  left_session_tag: z
    .string()
    .min(1)
    .describe('Base session tag such as reports/reconstruct/<session>'),
  right_session_tag: z
    .string()
    .min(1)
    .describe('Comparison session tag such as reports/reconstruct/<session>'),
  artifact_type: z.string().optional().describe('Optional artifact type filter'),
  artifact_types: z
    .array(z.string())
    .optional()
    .describe('Optional artifact type filter list (union with artifact_type)'),
  path_prefix: z
    .string()
    .optional()
    .describe('Optional relative path prefix filter applied to both sessions before diffing'),
  include_untracked_files: z
    .boolean()
    .optional()
    .default(true)
    .describe('Include untracked export files while diffing session contents'),
  recursive: z
    .boolean()
    .optional()
    .default(true)
    .describe('Recursively scan export roots for untracked files'),
  scan_roots: z
    .array(z.string())
    .optional()
    .default(['reports', 'ghidra', 'dotnet'])
    .describe('Workspace subdirectories to scan for untracked export files'),
  match_by: z
    .enum(['type_path', 'path', 'type'])
    .default('type_path')
    .describe('Keying strategy used to align artifacts across sessions'),
  latest_per_key: z
    .boolean()
    .optional()
    .default(true)
    .describe('Keep only the newest artifact per comparison key inside each session before diffing'),
})

const ArtifactSnapshotSchema = z.object({
  id: z.string(),
  type: z.string(),
  path: z.string(),
  sha256: z.string(),
  created_at: z.string(),
  exists: z.boolean(),
  tracked: z.boolean(),
  size_bytes: z.number().nullable(),
  modified_at: z.string().nullable(),
  retention_bucket: z.enum(['active', 'recent', 'archive']),
  age_days: z.number().int().nonnegative(),
})

const ArtifactChangeSchema = z.object({
  key: z.string(),
  differences: z.array(z.string()),
  left: ArtifactSnapshotSchema,
  right: ArtifactSnapshotSchema,
})

export const artifactsDiffOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      left_session_tag: z.string(),
      right_session_tag: z.string(),
      artifact_type: z.string().nullable(),
      artifact_types: z.array(z.string()).nullable(),
      path_prefix: z.string().nullable(),
      match_by: z.enum(['type_path', 'path', 'type']),
      latest_per_key: z.boolean(),
      tool_version: z.string(),
      left_count: z.number().int().nonnegative(),
      right_count: z.number().int().nonnegative(),
      added: z.array(z.object({ key: z.string(), artifact: ArtifactSnapshotSchema })),
      removed: z.array(z.object({ key: z.string(), artifact: ArtifactSnapshotSchema })),
      changed: z.array(ArtifactChangeSchema),
      unchanged_count: z.number().int().nonnegative(),
      summary: z.object({
        added_count: z.number().int().nonnegative(),
        removed_count: z.number().int().nonnegative(),
        changed_count: z.number().int().nonnegative(),
        unchanged_count: z.number().int().nonnegative(),
        changed_fields: z.record(z.number().int().nonnegative()),
        left_types: z.array(z.string()),
        right_types: z.array(z.string()),
      }),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const artifactsDiffToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compare artifact inventory between two sessions for one sample, including tracked and optional untracked files.',
  inputSchema: artifactsDiffInputSchema,
  outputSchema: artifactsDiffOutputSchema,
}

type ArtifactInventoryRow = z.infer<typeof ArtifactSnapshotSchema>

function toTimestamp(value: string | null): number {
  if (!value) {
    return 0
  }
  const parsed = new Date(value).getTime()
  return Number.isFinite(parsed) ? parsed : 0
}

function makeKey(
  item: ArtifactInventoryRow,
  matchBy: 'type_path' | 'path' | 'type'
): string {
  const normalizedPath = normalizeRelativeArtifactPath(item.path).toLowerCase()
  if (matchBy === 'path') {
    return normalizedPath
  }
  if (matchBy === 'type') {
    return item.type
  }
  return `${item.type}::${normalizedPath}`
}

function simplifyArtifact(item: any): ArtifactInventoryRow {
  return {
    id: item.id,
    type: item.type,
    path: item.path,
    sha256: item.sha256,
    created_at: item.created_at,
    exists: item.exists,
    tracked: item.tracked,
    size_bytes: item.size_bytes,
    modified_at: item.modified_at,
    retention_bucket: item.retention_bucket,
    age_days: item.age_days,
  }
}

function selectArtifactsForSession(
  artifacts: any[],
  sessionTag: string,
  pathPrefix?: string,
  matchBy: 'type_path' | 'path' | 'type' = 'type_path',
  latestPerKey = true
): Map<string, ArtifactInventoryRow> {
  let filtered = artifacts.filter((item) => item.session_tag === sessionTag)
  if (pathPrefix) {
    const normalizedPrefix = normalizeRelativeArtifactPath(pathPrefix).toLowerCase()
    filtered = filtered.filter((item) =>
      normalizeRelativeArtifactPath(item.path).toLowerCase().startsWith(normalizedPrefix)
    )
  }

  const selected = new Map<string, ArtifactInventoryRow>()
  for (const item of filtered) {
    const simplified = simplifyArtifact(item)
    const key = makeKey(simplified, matchBy)
    if (!latestPerKey) {
      if (!selected.has(key)) {
        selected.set(key, simplified)
      }
      continue
    }
    const existing = selected.get(key)
    if (!existing || toTimestamp(simplified.created_at) > toTimestamp(existing.created_at)) {
      selected.set(key, simplified)
    }
  }
  return selected
}

function collectDifferences(left: ArtifactInventoryRow, right: ArtifactInventoryRow): string[] {
  const differences: string[] = []
  const fields: Array<keyof ArtifactInventoryRow> = [
    'type',
    'path',
    'sha256',
    'exists',
    'tracked',
    'size_bytes',
    'modified_at',
    'retention_bucket',
    'created_at',
  ]
  for (const field of fields) {
    if (left[field] !== right[field]) {
      differences.push(field)
    }
  }
  return differences
}

export function createArtifactsDiffHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = artifactsDiffInputSchema.parse(args)
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

      const typeFilter = new Set<string>()
      if (input.artifact_type) {
        typeFilter.add(input.artifact_type)
      }
      for (const item of input.artifact_types || []) {
        typeFilter.add(item)
      }

      const inventory = await listArtifactInventory(workspaceManager, database, input.sample_id, {
        artifactTypes: typeFilter,
        includeMissing: true,
        includeUntrackedFiles: input.include_untracked_files,
        recursive: input.recursive,
        scanRoots: input.scan_roots,
      })

      const leftItems = selectArtifactsForSession(
        inventory,
        input.left_session_tag,
        input.path_prefix,
        input.match_by,
        input.latest_per_key
      )
      const rightItems = selectArtifactsForSession(
        inventory,
        input.right_session_tag,
        input.path_prefix,
        input.match_by,
        input.latest_per_key
      )

      const allKeys = new Set<string>([...leftItems.keys(), ...rightItems.keys()])
      const added: Array<{ key: string; artifact: ArtifactInventoryRow }> = []
      const removed: Array<{ key: string; artifact: ArtifactInventoryRow }> = []
      const changed: Array<z.infer<typeof ArtifactChangeSchema>> = []
      let unchangedCount = 0
      const changedFields: Record<string, number> = {}

      for (const key of Array.from(allKeys).sort()) {
        const left = leftItems.get(key)
        const right = rightItems.get(key)
        if (!left && right) {
          added.push({ key, artifact: right })
          continue
        }
        if (left && !right) {
          removed.push({ key, artifact: left })
          continue
        }
        if (!left || !right) {
          continue
        }
        const differences = collectDifferences(left, right)
        if (differences.length === 0) {
          unchangedCount += 1
          continue
        }
        for (const field of differences) {
          changedFields[field] = (changedFields[field] || 0) + 1
        }
        changed.push({ key, differences, left, right })
      }

      const warnings: string[] = []
      if (leftItems.size === 0) {
        warnings.push(`No artifacts matched left_session_tag=${input.left_session_tag}.`)
      }
      if (rightItems.size === 0) {
        warnings.push(`No artifacts matched right_session_tag=${input.right_session_tag}.`)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          left_session_tag: input.left_session_tag,
          right_session_tag: input.right_session_tag,
          artifact_type: input.artifact_type || null,
          artifact_types: typeFilter.size > 0 ? Array.from(typeFilter) : null,
          path_prefix: input.path_prefix || null,
          match_by: input.match_by,
          latest_per_key: input.latest_per_key,
          tool_version: TOOL_VERSION,
          left_count: leftItems.size,
          right_count: rightItems.size,
          added,
          removed,
          changed,
          unchanged_count: unchangedCount,
          summary: {
            added_count: added.length,
            removed_count: removed.length,
            changed_count: changed.length,
            unchanged_count: unchangedCount,
            changed_fields: changedFields,
            left_types: Array.from(new Set(Array.from(leftItems.values()).map((item) => item.type))).sort(),
            right_types: Array.from(new Set(Array.from(rightItems.values()).map((item) => item.type))).sort(),
          },
        },
        warnings: warnings.length > 0 ? warnings : undefined,
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
