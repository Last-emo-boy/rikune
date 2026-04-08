/**
 * dotnet.types.list tool implementation
 * Filtered type inventory derived from managed metadata extraction.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import { normalizeError } from '../utils/shared-helpers.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import {
  createDotNetMetadataExtractHandler,
  type DotNetMetadataData,
} from './dotnet-metadata-extract.js'

const TOOL_NAME = 'dotnet.types.list'

export const DotNetTypesListInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  namespace_prefix: z
    .string()
    .min(1)
    .max(160)
    .optional()
    .describe('Only return managed types whose namespace starts with this prefix'),
  include_methods: z
    .boolean()
    .default(false)
    .describe('Include per-method rows for each returned type'),
  max_types: z
    .number()
    .int()
    .min(1)
    .max(400)
    .default(120)
    .describe('Maximum number of managed types to return'),
  max_methods_per_type: z
    .number()
    .int()
    .min(1)
    .max(128)
    .default(24)
    .describe('Maximum number of methods returned per type when include_methods=true'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache lookup in the underlying metadata extract step'),
})

export type DotNetTypesListInput = z.infer<typeof DotNetTypesListInputSchema>

const DotNetTypesListMethodSchema = z.object({
  name: z.string(),
  token: z.string(),
  rva: z.number().int().nonnegative(),
  attributes: z.array(z.string()),
  is_constructor: z.boolean(),
  is_static: z.boolean(),
})

const DotNetTypesListTypeSchema = z.object({
  token: z.string(),
  namespace: z.string(),
  name: z.string(),
  full_name: z.string(),
  kind: z.string(),
  visibility: z.string(),
  is_public: z.boolean(),
  base_type: z.string().nullable(),
  method_count: z.number().int().nonnegative(),
  field_count: z.number().int().nonnegative(),
  nested_type_count: z.number().int().nonnegative(),
  flags: z.array(z.string()),
  methods: z.array(DotNetTypesListMethodSchema),
})

export const DotNetTypesListOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      is_dotnet: z.boolean(),
      assembly_name: z.string().nullable(),
      module_name: z.string().nullable(),
      dotnet_version: z.string().nullable(),
      target_framework: z.string().nullable(),
      namespace_prefix: z.string().nullable(),
      returned_type_count: z.number().int().nonnegative(),
      total_type_count: z.number().int().nonnegative(),
      truncated: z.boolean(),
      types: z.array(DotNetTypesListTypeSchema),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
      cached: z.boolean().optional(),
      cache_key: z.string().optional(),
      cache_tier: z.string().optional(),
      cache_created_at: z.string().optional(),
      cache_expires_at: z.string().optional(),
      cache_hit_at: z.string().optional(),
    })
    .optional(),
})

export type DotNetTypesListOutput = z.infer<typeof DotNetTypesListOutputSchema>

export const dotNetTypesListToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'List managed types from CLR metadata, with optional namespace filtering and per-method rows.',
  inputSchema: DotNetTypesListInputSchema,
  outputSchema: DotNetTypesListOutputSchema,
}

interface DotNetTypesListDependencies {
  metadataHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

function isPublicVisibility(value: string): boolean {
  return /\bpublic\b/i.test(value)
}

export function createDotNetTypesListHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: DotNetTypesListDependencies
) {
  const metadataHandler =
    dependencies?.metadataHandler ||
    createDotNetMetadataExtractHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = DotNetTypesListInputSchema.parse(args)
      const metadataResult = await metadataHandler({
        sample_id: input.sample_id,
        include_types: true,
        include_methods: input.include_methods,
        max_types: input.max_types,
        max_methods_per_type: input.max_methods_per_type,
        force_refresh: input.force_refresh,
      })

      if (!metadataResult.ok || !metadataResult.data) {
        return {
          ok: false,
          errors: metadataResult.errors || ['dotnet.metadata.extract failed'],
          warnings: metadataResult.warnings,
          metrics: {
            ...(metadataResult.metrics || {}),
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const metadata = metadataResult.data as DotNetMetadataData
      const namespacePrefix = input.namespace_prefix?.trim() || null
      const filteredTypes = (metadata.types || []).filter((typeInfo) => {
        if (!namespacePrefix) {
          return true
        }
        return typeInfo.namespace.startsWith(namespacePrefix)
      })

      const types = filteredTypes.slice(0, input.max_types).map((typeInfo) => ({
        token: typeInfo.token,
        namespace: typeInfo.namespace,
        name: typeInfo.name,
        full_name: typeInfo.full_name,
        kind: typeInfo.kind,
        visibility: typeInfo.visibility,
        is_public: isPublicVisibility(typeInfo.visibility),
        base_type: typeInfo.base_type,
        method_count: typeInfo.method_count,
        field_count: typeInfo.field_count,
        nested_type_count: typeInfo.nested_type_count,
        flags: typeInfo.flags,
        methods: input.include_methods ? typeInfo.methods.slice(0, input.max_methods_per_type) : [],
      }))

      const warnings = [...(metadataResult.warnings || [])]
      if (namespacePrefix && filteredTypes.length === 0) {
        warnings.push(`No managed types matched namespace_prefix=${namespacePrefix}.`)
      }
      if (filteredTypes.length > input.max_types) {
        warnings.push(`Type list truncated from ${filteredTypes.length} to ${input.max_types}.`)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          is_dotnet: metadata.is_dotnet,
          assembly_name: metadata.assembly_name,
          module_name: metadata.module_name,
          dotnet_version: metadata.dotnet_version,
          target_framework: metadata.target_framework,
          namespace_prefix: namespacePrefix,
          returned_type_count: types.length,
          total_type_count: filteredTypes.length,
          truncated: filteredTypes.length > input.max_types,
          types,
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        metrics: {
          ...(metadataResult.metrics || {}),
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
