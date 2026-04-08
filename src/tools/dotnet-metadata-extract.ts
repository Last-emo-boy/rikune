/**
 * dotnet.metadata.extract tool implementation
 * Extract managed assembly metadata without executing the sample.
 */

import { spawn } from 'child_process'
import path from 'path'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import { normalizeError } from '../utils/shared-helpers.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { getPackageRoot, resolvePackagePath } from '../runtime-paths.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { createRuntimeDetectHandler } from './runtime-detect.js'
import { buildStaticWorkerRequest, callStaticWorker } from './static-worker-client.js'
import { CACHE_TTL_7_DAYS } from '../constants/cache-ttl.js'

const TOOL_NAME = 'dotnet.metadata.extract'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = CACHE_TTL_7_DAYS
const DEFAULT_TIMEOUT_MS = 120000

export const DotNetMetadataExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  include_types: z
    .boolean()
    .default(true)
    .describe('Include per-type rows from CLR metadata'),
  include_methods: z
    .boolean()
    .default(true)
    .describe('Include per-method rows for returned types'),
  max_types: z
    .number()
    .int()
    .min(1)
    .max(400)
    .default(80)
    .describe('Maximum number of managed types to return'),
  max_methods_per_type: z
    .number()
    .int()
    .min(1)
    .max(128)
    .default(24)
    .describe('Maximum number of methods returned per type'),
  force_refresh: z
    .boolean()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

export type DotNetMetadataExtractInput = z.infer<typeof DotNetMetadataExtractInputSchema>

const DotNetMetadataMethodSchema = z.object({
  name: z.string(),
  token: z.string(),
  rva: z.number().int().nonnegative(),
  attributes: z.array(z.string()),
  is_constructor: z.boolean(),
  is_static: z.boolean(),
})

const DotNetMetadataTypeSchema = z.object({
  token: z.string(),
  namespace: z.string(),
  name: z.string(),
  full_name: z.string(),
  kind: z.string(),
  visibility: z.string(),
  base_type: z.string().nullable(),
  method_count: z.number().int().nonnegative(),
  field_count: z.number().int().nonnegative(),
  nested_type_count: z.number().int().nonnegative(),
  flags: z.array(z.string()),
  methods: z.array(DotNetMetadataMethodSchema),
})

const DotNetAssemblyReferenceSchema = z.object({
  name: z.string(),
  version: z.string(),
  culture: z.string().nullable(),
})

const DotNetManifestResourceSchema = z.object({
  name: z.string(),
  attributes: z.string(),
  implementation: z.string(),
})

const DotNetNamespaceSchema = z.object({
  name: z.string(),
  type_count: z.number().int().nonnegative(),
  method_count: z.number().int().nonnegative(),
})

const DotNetMetadataSummarySchema = z.object({
  type_count: z.number().int().nonnegative(),
  method_count: z.number().int().nonnegative(),
  namespace_count: z.number().int().nonnegative(),
  assembly_reference_count: z.number().int().nonnegative(),
  resource_count: z.number().int().nonnegative(),
})

export const DotNetMetadataExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      is_dotnet: z.boolean(),
      assembly_name: z.string().nullable(),
      assembly_version: z.string().nullable(),
      module_name: z.string().nullable(),
      metadata_version: z.string().nullable(),
      dotnet_version: z.string().nullable(),
      target_framework: z.string().nullable(),
      is_library: z.boolean(),
      entry_point_token: z.string().nullable(),
      assembly_references: z.array(DotNetAssemblyReferenceSchema),
      resources: z.array(DotNetManifestResourceSchema),
      namespaces: z.array(DotNetNamespaceSchema),
      types: z.array(DotNetMetadataTypeSchema),
      summary: DotNetMetadataSummarySchema,
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
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

export type DotNetMetadataExtractOutput = z.infer<typeof DotNetMetadataExtractOutputSchema>

export const dotNetMetadataExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract managed assembly metadata (assembly refs, types, methods, resources, DLL/EXE role) for .NET samples without executing them.',
  inputSchema: DotNetMetadataExtractInputSchema,
  outputSchema: DotNetMetadataExtractOutputSchema,
}

interface RuntimeSuspected {
  runtime: string
  confidence: number
  evidence: string[]
}

interface RuntimeDetectData {
  is_dotnet?: boolean
  dotnet_version?: string | null
  target_framework?: string | null
  suspected?: RuntimeSuspected[]
}

export interface DotNetMetadataMethod {
  name: string
  token: string
  rva: number
  attributes: string[]
  is_constructor: boolean
  is_static: boolean
}

export interface DotNetMetadataType {
  token: string
  namespace: string
  name: string
  full_name: string
  kind: string
  visibility: string
  base_type: string | null
  method_count: number
  field_count: number
  nested_type_count: number
  flags: string[]
  methods: DotNetMetadataMethod[]
}

export interface DotNetAssemblyReference {
  name: string
  version: string
  culture: string | null
}

export interface DotNetManifestResource {
  name: string
  attributes: string
  implementation: string
}

export interface DotNetNamespaceSummary {
  name: string
  type_count: number
  method_count: number
}

export interface DotNetMetadataData {
  is_dotnet: boolean
  assembly_name: string | null
  assembly_version: string | null
  module_name: string | null
  metadata_version: string | null
  dotnet_version: string | null
  target_framework: string | null
  is_library: boolean
  entry_point_token: string | null
  assembly_references: DotNetAssemblyReference[]
  resources: DotNetManifestResource[]
  namespaces: DotNetNamespaceSummary[]
  types: DotNetMetadataType[]
  summary: {
    type_count: number
    method_count: number
    namespace_count: number
    assembly_reference_count: number
    resource_count: number
  }
}

interface DotNetMetadataProbeResult {
  ok: boolean
  data?: Omit<DotNetMetadataData, 'dotnet_version'>
  warnings?: string[]
  errors?: string[]
}

interface DotNetMetadataExtractDependencies {
  runtimeDetectHandler?: (args: ToolArgs) => Promise<WorkerResult>
  probeRunner?: (
    samplePath: string,
    options: {
      includeTypes: boolean
      includeMethods: boolean
      maxTypes: number
      maxMethodsPerType: number
      timeoutMs?: number
    }
  ) => Promise<DotNetMetadataProbeResult>
}

function extractVersionFromTargetFramework(targetFramework: string | null | undefined): string | null {
  if (!targetFramework) {
    return null
  }
  const match = targetFramework.match(/Version=v?([0-9]+(?:\.[0-9]+)?)/i)
  return match ? match[1] : null
}

export async function runDotNetMetadataProbe(
  samplePath: string,
  options: {
    includeTypes: boolean
    includeMethods: boolean
    maxTypes: number
    maxMethodsPerType: number
    timeoutMs?: number
  }
): Promise<DotNetMetadataProbeResult> {
  return new Promise((resolve) => {
    const projectPath = resolvePackagePath('helpers', 'DotNetMetadataProbe', 'DotNetMetadataProbe.csproj')
    const args = [
      'run',
      '--project',
      projectPath,
      '--configuration',
      'Release',
      '--',
      samplePath,
      `--include-types=${options.includeTypes}`,
      `--include-methods=${options.includeMethods}`,
      `--max-types=${options.maxTypes}`,
      `--max-methods-per-type=${options.maxMethodsPerType}`,
    ]

    const child = spawn('dotnet', args, {
      cwd: getPackageRoot(),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })

    let stdout = ''
    let stderr = ''
    let settled = false
    const effectiveTimeoutMs = Math.max(10000, options.timeoutMs || DEFAULT_TIMEOUT_MS)

    const finish = (result: DotNetMetadataProbeResult) => {
      if (settled) {
        return
      }
      settled = true
      clearTimeout(timer)
      resolve(result)
    }

    const timer = setTimeout(() => {
      child.kill()
      finish({
        ok: false,
        errors: [`dotnet metadata probe timed out after ${effectiveTimeoutMs}ms`],
      })
    }, effectiveTimeoutMs)

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })

    child.on('error', (error: NodeJS.ErrnoException) => {
      finish({
        ok: false,
        errors: [
          error.code === 'ENOENT'
            ? 'dotnet CLI is not available in PATH'
            : `Failed to spawn dotnet metadata probe: ${error.message}`,
        ],
      })
    })

    child.on('close', (code) => {
      const output = stdout.trim()
      if (code !== 0 && output.length === 0) {
        finish({
          ok: false,
          errors: [`dotnet metadata probe failed with exit code ${code ?? 'unknown'}: ${stderr.trim() || 'no stderr'}`],
        })
        return
      }

      try {
        const parsed = JSON.parse(output || '{}') as DotNetMetadataProbeResult
        if (!parsed.ok && stderr.trim().length > 0) {
          parsed.errors = [...(parsed.errors || []), stderr.trim()]
        }
        finish(parsed)
      } catch (error) {
        finish({
          ok: false,
          errors: [
            `Failed to parse dotnet metadata probe output: ${(error as Error).message}`,
            stderr.trim() || stdout.trim() || 'no output',
          ],
        })
      }
    })
  })
}

export function createDotNetMetadataExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: DotNetMetadataExtractDependencies
) {
  const runtimeDetectHandler =
    dependencies?.runtimeDetectHandler ||
    createRuntimeDetectHandler(workspaceManager, database, cacheManager)
  const probeRunner = dependencies?.probeRunner || runDotNetMetadataProbe

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = DotNetMetadataExtractInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      const runtimeResult = await runtimeDetectHandler({ sample_id: input.sample_id })
      const runtimeData = (runtimeResult.ok ? runtimeResult.data : undefined) as RuntimeDetectData | undefined
      if (!runtimeResult.ok || runtimeData?.is_dotnet !== true) {
        const suspected = (runtimeData?.suspected || [])
          .map((item) => `${item.runtime}(${item.confidence.toFixed(2)})`)
          .join(', ')
        return {
          ok: false,
          errors: ['Target sample is not recognized as a .NET assembly.'],
          warnings:
            suspected.length > 0
              ? [`runtime.detect suspected: ${suspected}`]
              : runtimeResult.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          include_types: input.include_types,
          include_methods: input.include_methods,
          max_types: input.max_types,
          max_methods_per_type: input.max_methods_per_type,
          dotnet_version: runtimeData.dotnet_version || null,
          target_framework: runtimeData.target_framework || null,
        },
      })

      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          return {
            ok: true,
            data: cachedLookup.data,
            warnings: ['Result from cache', formatCacheWarning(cachedLookup.metadata)],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
              cache_key: cachedLookup.metadata.key,
              cache_tier: cachedLookup.metadata.tier,
              cache_created_at: cachedLookup.metadata.createdAt,
              cache_expires_at: cachedLookup.metadata.expiresAt,
              cache_hit_at: cachedLookup.metadata.fetchedAt,
            },
          }
        }
      }

      const workspace = await workspaceManager.getWorkspace(input.sample_id)
      const files = await (await import('fs/promises')).readdir(workspace.original)
      if (files.length === 0) {
        return {
          ok: false,
          errors: ['Sample file not found in workspace'],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const samplePath = path.join(workspace.original, files[0])
      let probeResult = await probeRunner(samplePath, {
        includeTypes: input.include_types,
        includeMethods: input.include_methods,
        maxTypes: input.max_types,
        maxMethodsPerType: input.max_methods_per_type,
      })

      // Fallback to Python/dnfile worker when dotnet CLI is unavailable
      if (!probeResult.ok && probeResult.errors?.some(e => e.includes('not available in PATH') || e.includes('ENOENT'))) {
        const workerRequest = buildStaticWorkerRequest({
          tool: TOOL_NAME,
          sampleId: input.sample_id,
          samplePath,
          args: {
            include_types: input.include_types,
            include_methods: input.include_methods,
            max_types: input.max_types,
            max_methods_per_type: input.max_methods_per_type,
          },
          toolVersion: TOOL_VERSION,
        })
        const workerResponse = await callStaticWorker(workerRequest, { database })
        if (workerResponse.ok && workerResponse.data) {
          probeResult = {
            ok: true,
            data: workerResponse.data as Omit<DotNetMetadataData, 'dotnet_version'>,
            warnings: [...(workerResponse.warnings || []), 'Used Python/dnfile backend (dotnet CLI unavailable)'],
          }
        } else {
          probeResult = {
            ok: false,
            errors: workerResponse.errors?.length ? workerResponse.errors : ['Python dnfile backend also failed'],
            warnings: workerResponse.warnings,
          }
        }
      }

      if (!probeResult.ok || !probeResult.data) {
        return {
          ok: false,
          errors: probeResult.errors || ['dotnet metadata probe failed'],
          warnings: probeResult.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const data: DotNetMetadataData = {
        ...probeResult.data,
        dotnet_version: runtimeData.dotnet_version || null,
        target_framework: runtimeData.target_framework || probeResult.data.target_framework || null,
      }
      if (!data.dotnet_version) {
        data.dotnet_version = extractVersionFromTargetFramework(data.target_framework)
      }

      await cacheManager.setCachedResult(cacheKey, data, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data,
        warnings: probeResult.warnings?.length ? probeResult.warnings : runtimeResult.warnings,
        metrics: {
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
