/**
 * dotnet.reconstruct.export tool implementation
 * .NET-oriented source skeleton export with confidence annotations and fallback guidance.
 */

import { createHash, randomUUID } from 'crypto'
import fs from 'fs/promises'
import path from 'path'
import { spawn } from 'child_process'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import { normalizeError, clamp } from '../../../utils/shared-helpers.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { CacheManager } from '../../../cache-manager.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from '../../../tools/cache-observability.js'
import { createRuntimeDetectHandler } from '../../static-triage/tools/runtime-detect.js'
import { createPackerDetectHandler } from '../../static-triage/tools/packer-detect.js'
import { createCodeReconstructExportHandler } from './code-reconstruct-export.js'
import {
  createDotNetMetadataExtractHandler,
  type DotNetMetadataData,
  type DotNetMetadataType,
  type DotNetMetadataMethod,
} from '../../static-triage/tools/dotnet-metadata-extract.js'
import { findBestGhidraAnalysis } from '../../../ghidra-analysis-status.js'
import { CACHE_TTL_7_DAYS } from '../../../constants/cache-ttl.js'

const TOOL_NAME = 'dotnet.reconstruct.export'
const TOOL_VERSION = '0.2.0'
const CACHE_TTL_MS = CACHE_TTL_7_DAYS

export const DotNetReconstructExportInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  topk: z
    .number()
    .int()
    .min(1)
    .max(40)
    .default(16)
    .describe('Top-K high-value functions used for reconstruction'),
  project_name: z
    .string()
    .min(1)
    .max(64)
    .default('RecoveredDotNet')
    .describe('Exported C# project name'),
  namespace: z
    .string()
    .min(1)
    .max(128)
    .default('Recovered')
    .describe('Root C# namespace for reconstructed classes'),
  include_metadata_types: z
    .boolean()
    .default(true)
    .describe('Generate CLR metadata-driven type skeletons alongside module skeletons'),
  max_managed_types: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(64)
    .describe('Maximum number of managed metadata types emitted as C# skeletons'),
  export_name: z
    .string()
    .min(1)
    .max(64)
    .optional()
    .describe('Optional folder name for export'),
  include_obfuscation_fallback: z
    .boolean()
    .default(true)
    .describe('Generate IL fallback notes when packed/obfuscated signals exist'),
  validate_build: z
    .boolean()
    .default(true)
    .describe('Run dotnet build validation for exported project skeleton'),
  build_timeout_ms: z
    .number()
    .int()
    .min(5000)
    .max(180000)
    .default(45000)
    .describe('Timeout for dotnet build validation in milliseconds'),
  evidence_scope: z
    .enum(['all', 'latest', 'session'])
    .default('all')
    .describe('Runtime evidence scope forwarded to native reconstruction fallback: all artifacts, latest artifact window, or a specific session selector'),
  evidence_session_tag: z
    .string()
    .optional()
    .describe('Optional runtime evidence session selector used when evidence_scope=session or to narrow all/latest results'),
  reuse_cached: z
    .boolean()
    .default(true)
    .describe('Reuse cached result for identical inputs'),
}).refine((value) => value.evidence_scope !== 'session' || Boolean(value.evidence_session_tag?.trim()), {
  message: 'evidence_session_tag is required when evidence_scope=session',
  path: ['evidence_session_tag'],
})

export type DotNetReconstructExportInput = z.infer<typeof DotNetReconstructExportInputSchema>

const DotNetMethodSchema = z.object({
  name: z.string(),
  address: z.string().nullable(),
  token: z.string().nullable(),
  confidence: z.number().min(0).max(1),
  gaps: z.array(z.string()),
})

const DotNetClassSchema = z.object({
  class_name: z.string(),
  source: z.enum(['module', 'metadata']),
  module: z.string(),
  namespace: z.string(),
  full_name: z.string().nullable(),
  kind: z.string(),
  confidence: z.number().min(0).max(1),
  file_path: z.string(),
  methods: z.array(DotNetMethodSchema),
})

const ManagedProfileSchema = z.object({
  assembly_name: z.string().nullable(),
  assembly_version: z.string().nullable(),
  module_name: z.string().nullable(),
  metadata_version: z.string().nullable(),
  is_library: z.boolean(),
  entry_point_token: z.string().nullable(),
  type_count: z.number().int().nonnegative(),
  method_count: z.number().int().nonnegative(),
  namespace_count: z.number().int().nonnegative(),
  assembly_reference_count: z.number().int().nonnegative(),
  resource_count: z.number().int().nonnegative(),
  dominant_namespaces: z.array(z.string()),
  notable_types: z.array(z.string()),
  assembly_references: z.array(z.string()),
  resources: z.array(z.string()),
  analysis_priorities: z.array(z.string()),
})

const BuildValidationSchema = z.object({
  attempted: z.boolean(),
  status: z.enum(['passed', 'failed', 'skipped', 'unavailable']),
  command: z.string().nullable(),
  dotnet_cli_available: z.boolean(),
  exit_code: z.number().int().nullable(),
  timed_out: z.boolean(),
  error: z.string().nullable(),
  log_path: z.string().nullable(),
})

export const DotNetReconstructExportOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string(),
      is_dotnet: z.boolean(),
      dotnet_version: z.string().nullable(),
      target_framework: z.string().nullable(),
      packed: z.boolean(),
      packing_confidence: z.number().min(0).max(1),
      export_root: z.string(),
      csproj_path: z.string(),
      readme_path: z.string(),
      metadata_path: z.string().nullable(),
      reverse_notes_path: z.string().nullable(),
      fallback_notes_path: z.string().nullable(),
      degraded_mode: z.boolean(),
      degradation_reasons: z.array(z.string()),
      build_validation: BuildValidationSchema,
      managed_profile: ManagedProfileSchema.nullable(),
      classes: z.array(DotNetClassSchema),
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

export type DotNetReconstructExportOutput = z.infer<typeof DotNetReconstructExportOutputSchema>

export const dotNetReconstructExportToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Export a maintainable C# reconstruction skeleton for .NET samples with confidence annotations and IL fallback guidance.',
  inputSchema: DotNetReconstructExportInputSchema,
  outputSchema: DotNetReconstructExportOutputSchema,
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

interface PackerDetectData {
  packed?: boolean
  confidence?: number
}

interface ReconstructModuleFunction {
  function: string
  address: string
  confidence: number
  gaps: string[]
}

interface ReconstructModule {
  name: string
  confidence: number
  functions: ReconstructModuleFunction[]
}

interface ReconstructExportData {
  modules: ReconstructModule[]
  gaps_path?: string
}

interface LowConfidenceMethod {
  module: string
  method: string
  address: string
  confidence: number
  gaps: string[]
}

interface ManagedProfile {
  assembly_name: string | null
  assembly_version: string | null
  module_name: string | null
  metadata_version: string | null
  is_library: boolean
  entry_point_token: string | null
  type_count: number
  method_count: number
  namespace_count: number
  assembly_reference_count: number
  resource_count: number
  dominant_namespaces: string[]
  notable_types: string[]
  assembly_references: string[]
  resources: string[]
  analysis_priorities: string[]
}

interface BuildValidationResult {
  attempted: boolean
  status: 'passed' | 'failed' | 'skipped' | 'unavailable'
  command: string | null
  dotnet_cli_available: boolean
  exit_code: number | null
  timed_out: boolean
  stdout: string
  stderr: string
  error: string | null
}

interface DotNetReconstructDependencies {
  runtimeDetectHandler?: (args: ToolArgs) => Promise<WorkerResult>
  packerDetectHandler?: (args: ToolArgs) => Promise<WorkerResult>
  reconstructExportHandler?: (args: ToolArgs) => Promise<WorkerResult>
  dotNetMetadataHandler?: (args: ToolArgs) => Promise<WorkerResult>
  buildValidator?: (
    csprojPath: string,
    cwd: string,
    timeoutMs: number
  ) => Promise<BuildValidationResult>
}

function toPosixRelative(root: string, filePath: string): string {
  return path.relative(root, filePath).split(path.sep).join('/')
}

function sanitizeIdentifier(value: string): string {
  const cleaned = value.replace(/[^a-zA-Z0-9_]/g, '_')
  if (cleaned.length === 0) {
    return 'RecoveredItem'
  }
  if (/^[0-9]/.test(cleaned)) {
    return `Recovered_${cleaned}`
  }
  return cleaned
}

function toPascalCase(value: string): string {
  const parts = value
    .replace(/[^a-zA-Z0-9]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter((item) => item.length > 0)
  if (parts.length === 0) {
    return 'RecoveredModule'
  }
  return parts
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1).toLowerCase()}`)
    .join('')
}

function mapTargetFramework(raw: string | null | undefined): string {
  if (!raw) {
    return 'net6.0'
  }
  const lowered = raw.toLowerCase()
  if (lowered.includes('netframework') || lowered.includes('.net framework')) {
    return 'net48'
  }
  const match = lowered.match(/net\s*([0-9]+)(?:\.([0-9]+))?/)
  if (match) {
    const major = match[1]
    const minor = match[2] || '0'
    if (parseInt(major, 10) >= 5) {
      return `net${major}.${minor}`
    }
  }
  return 'net6.0'
}

function buildCsproj(projectName: string, targetFramework: string): string {
  return [
    '<Project Sdk="Microsoft.NET.Sdk">',
    '  <PropertyGroup>',
    `    <AssemblyName>${projectName}</AssemblyName>`,
    `    <RootNamespace>${projectName}</RootNamespace>`,
    '    <OutputType>Library</OutputType>',
    `    <TargetFramework>${targetFramework}</TargetFramework>`,
    '    <Nullable>enable</Nullable>',
    '    <ImplicitUsings>enable</ImplicitUsings>',
    '    <LangVersion>latest</LangVersion>',
    '  </PropertyGroup>',
    '</Project>',
    '',
  ].join('\n')
}

function sanitizeNamespaceSegment(value: string): string {
  return sanitizeIdentifier(value).replace(/_+/g, '_')
}

function buildNamespace(root: string, suffix?: string): string {
  const parts = [root, suffix]
    .filter((item): item is string => Boolean(item && item.trim()))
    .flatMap((item) => item.split('.'))
    .map((item) => sanitizeNamespaceSegment(item))
    .filter((item) => item.length > 0)
  return parts.length > 0 ? parts.join('.') : 'Recovered'
}

function buildModuleClassContent(
  namespaceRoot: string,
  className: string,
  moduleName: string,
  moduleConfidence: number,
  methods: ReconstructModuleFunction[]
): string {
  const lines: string[] = []
  lines.push(`namespace ${namespaceRoot};`)
  lines.push('')
  lines.push(`// Module: ${moduleName} | confidence=${moduleConfidence.toFixed(2)}`)
  lines.push(`public static partial class ${className}`)
  lines.push('{')

  if (methods.length === 0) {
    lines.push('    // No methods recovered for this module.')
  } else {
    for (const method of methods) {
      const methodName = sanitizeIdentifier(`m_${method.function}`)
      lines.push(
        `    // address=${method.address} confidence=${method.confidence.toFixed(2)} gaps=${method.gaps.join(',') || 'none'}`
      )
      lines.push(`    public static void ${methodName}()`)
      lines.push('    {')
      lines.push('        // TODO: Recover exact managed semantics by comparing IL with native reconstruction.')
      lines.push('    }')
      lines.push('')
    }
    if (lines[lines.length - 1] === '') {
      lines.pop()
    }
  }

  lines.push('}')
  lines.push('')
  return lines.join('\n')
}

function inferTypeModuleHints(typeInfo: DotNetMetadataType, modules: ReconstructModule[]): string[] {
  const lowered = `${typeInfo.full_name} ${typeInfo.name}`.toLowerCase()
  const hints: string[] = []
  const keywordMap: Record<string, string[]> = {
    process_ops: ['process', 'thread', 'inject', 'remote', 'context'],
    network_ops: ['net', 'http', 'socket', 'dns', 'web', 'client', 'server'],
    file_ops: ['file', 'path', 'stream', 'io', 'archive', 'disk'],
    registry_ops: ['registry', 'reg'],
    crypto_ops: ['crypto', 'hash', 'cipher', 'aes', 'rsa', 'encrypt', 'decrypt'],
    anti_analysis: ['debug', 'analysis', 'sandbox', 'vm', 'anti'],
    packer_analysis: ['packer', 'entropy', 'section', 'image', 'header'],
  }

  for (const [moduleName, tokens] of Object.entries(keywordMap)) {
    if (!modules.some((module) => module.name === moduleName)) {
      continue
    }
    if (tokens.some((token) => lowered.includes(token))) {
      hints.push(moduleName)
    }
  }

  return hints.slice(0, 3)
}

function pickMetadataTypeConfidence(typeInfo: DotNetMetadataType): number {
  let confidence = 0.48
  confidence += Math.min(0.18, typeInfo.method_count * 0.015)
  confidence += Math.min(0.08, typeInfo.field_count * 0.01)
  if (typeInfo.visibility === 'public') {
    confidence += 0.07
  }
  if (typeInfo.kind === 'interface' || typeInfo.kind === 'delegate') {
    confidence += 0.03
  }
  return clamp(confidence, 0.35, 0.82)
}

function buildManagedMethodName(method: DotNetMetadataMethod, usedNames: Set<string>): string {
  const baseName =
    method.name === '.ctor'
      ? 'Ctor'
      : method.name === '.cctor'
        ? 'TypeInitializer'
        : sanitizeIdentifier(method.name)
  let candidate = baseName
  const tokenSuffix = method.token.replace(/^0x/i, '')
  if (candidate.length === 0) {
    candidate = `Method_${tokenSuffix}`
  }
  while (usedNames.has(candidate)) {
    candidate = `${baseName}_${tokenSuffix}`
  }
  usedNames.add(candidate)
  return candidate
}

function buildMetadataClassContent(
  namespaceRoot: string,
  className: string,
  typeInfo: DotNetMetadataType,
  relatedModules: string[]
): string {
  const lines: string[] = []
  const usedMethodNames = new Set<string>()
  lines.push(`namespace ${namespaceRoot};`)
  lines.push('')
  lines.push('/// <summary>')
  lines.push(`/// Metadata-driven reconstruction for ${typeInfo.full_name}.`)
  lines.push(`/// token=${typeInfo.token} kind=${typeInfo.kind} visibility=${typeInfo.visibility}`)
  lines.push(
    `/// base_type=${typeInfo.base_type || 'unknown'} methods=${typeInfo.method_count} fields=${typeInfo.field_count}`
  )
  if (relatedModules.length > 0) {
    lines.push(`/// related_modules=${relatedModules.join(', ')}`)
  }
  lines.push('/// </summary>')
  lines.push(`public partial class ${className}`)
  lines.push('{')

  if (typeInfo.methods.length === 0) {
    lines.push('    // No CLR methods were emitted for this type.')
  } else {
    for (const method of typeInfo.methods) {
      const methodName = buildManagedMethodName(method, usedMethodNames)
      lines.push('    /// <summary>')
      lines.push(
        `    /// token=${method.token} rva=${method.rva > 0 ? `0x${method.rva.toString(16)}` : 'n/a'} flags=${method.attributes.join(',') || 'none'}`
      )
      lines.push('    /// </summary>')
      lines.push(`    public void ${methodName}()`)
      lines.push('    {')
      lines.push(`        // TODO: Recover IL body for ${typeInfo.full_name}.${method.name}.`)
      if (relatedModules.length > 0) {
        lines.push(`        // Likely related reconstructed modules: ${relatedModules.join(', ')}.`)
      }
      lines.push('    }')
      lines.push('')
    }
    if (lines[lines.length - 1] === '') {
      lines.pop()
    }
  }

  lines.push('}')
  lines.push('')
  return lines.join('\n')
}

function buildManagedProfile(
  metadata: DotNetMetadataData | null,
  packed: boolean,
  packingConfidence: number
): ManagedProfile | null {
  if (!metadata) {
    return null
  }

  const assemblyRefs = metadata.assembly_references.map((item) => item.name).filter(Boolean)
  const resources = metadata.resources.map((item) => item.name).filter(Boolean)
  const dominantNamespaces = metadata.namespaces.slice(0, 6).map((item) => item.name)
  const notableTypes = metadata.types.slice(0, 8).map((item) => item.full_name)
  const priorities: string[] = []
  const refsLower = assemblyRefs.map((item) => item.toLowerCase())

  if (metadata.is_library || !metadata.entry_point_token) {
    priorities.push('inspect_public_surface_and_host_integration')
  } else {
    priorities.push('trace_entrypoint_and_dispatch_chain')
  }
  if (packed || packingConfidence >= 0.45) {
    priorities.push('deobfuscate_before_claiming_source_equivalence')
  }
  if (refsLower.some((item) => item.includes('system.net'))) {
    priorities.push('review_managed_network_paths')
  }
  if (refsLower.some((item) => item.includes('system.management'))) {
    priorities.push('review_wmi_and_inventory_collection_paths')
  }
  if (refsLower.some((item) => item.includes('system.reflection'))) {
    priorities.push('review_dynamic_loading_and_plugin_paths')
  }
  if (refsLower.some((item) => item.includes('system.security') || item.includes('crypt'))) {
    priorities.push('review_crypto_and_secret_handling')
  }
  if (resources.length > 0) {
    priorities.push('inspect_embedded_resources_and_config_payloads')
  }

  return {
    assembly_name: metadata.assembly_name,
    assembly_version: metadata.assembly_version,
    module_name: metadata.module_name,
    metadata_version: metadata.metadata_version,
    is_library: metadata.is_library,
    entry_point_token: metadata.entry_point_token,
    type_count: metadata.summary.type_count,
    method_count: metadata.summary.method_count,
    namespace_count: metadata.summary.namespace_count,
    assembly_reference_count: metadata.summary.assembly_reference_count,
    resource_count: metadata.summary.resource_count,
    dominant_namespaces: dominantNamespaces,
    notable_types: notableTypes,
    assembly_references: assemblyRefs.slice(0, 16),
    resources: resources.slice(0, 16),
    analysis_priorities: priorities.slice(0, 8),
  }
}

function buildDotNetReverseNotes(
  input: DotNetReconstructExportInput,
  runtime: RuntimeDetectData,
  managedProfile: ManagedProfile | null,
  modules: ReconstructModule[],
  packed: boolean,
  packingConfidence: number,
  degradationReasons: string[],
  warnings: string[]
): string {
  const lines: string[] = []
  lines.push('# REVERSE_NOTES.md')
  lines.push('')
  lines.push('## Runtime')
  lines.push(`- sample_id: ${input.sample_id}`)
  lines.push(`- dotnet_version: ${runtime.dotnet_version || 'unknown'}`)
  lines.push(`- target_framework: ${runtime.target_framework || 'unknown'}`)
  lines.push(`- packed: ${packed} (confidence=${packingConfidence.toFixed(2)})`)
  lines.push('')

  lines.push('## Managed Profile')
  if (!managedProfile) {
    lines.push('- CLR metadata profile unavailable; rely on module skeletons and fallback notes.')
  } else {
    lines.push(`- assembly_name: ${managedProfile.assembly_name || 'unknown'}`)
    lines.push(`- assembly_version: ${managedProfile.assembly_version || 'unknown'}`)
    lines.push(`- module_name: ${managedProfile.module_name || 'unknown'}`)
    lines.push(`- is_library: ${managedProfile.is_library}`)
    lines.push(`- entry_point_token: ${managedProfile.entry_point_token || 'none'}`)
    lines.push(
      `- counts: types=${managedProfile.type_count}, methods=${managedProfile.method_count}, namespaces=${managedProfile.namespace_count}, refs=${managedProfile.assembly_reference_count}, resources=${managedProfile.resource_count}`
    )
    lines.push(
      `- dominant_namespaces: ${managedProfile.dominant_namespaces.length > 0 ? managedProfile.dominant_namespaces.join(', ') : 'none'}`
    )
    lines.push(
      `- notable_types: ${managedProfile.notable_types.length > 0 ? managedProfile.notable_types.join(', ') : 'none'}`
    )
    lines.push(
      `- assembly_references: ${managedProfile.assembly_references.length > 0 ? managedProfile.assembly_references.join(', ') : 'none'}`
    )
    if (managedProfile.resources.length > 0) {
      lines.push(`- resources: ${managedProfile.resources.join(', ')}`)
    }
  }
  lines.push('')

  lines.push('## Module Skeleton Guide')
  if (modules.length === 0) {
    lines.push('- No native reconstruction modules were available.')
  } else {
    for (const module of modules.slice(0, 10)) {
      lines.push(
        `- ${module.name}: confidence=${module.confidence.toFixed(2)} functions=${module.functions.length}`
      )
    }
  }
  lines.push('')

  lines.push('## Analyst Priorities')
  if (!managedProfile || managedProfile.analysis_priorities.length === 0) {
    lines.push('- Compare exported type skeletons with IL and module skeletons before renaming methods.')
  } else {
    for (const item of managedProfile.analysis_priorities) {
      lines.push(`- ${item}`)
    }
  }
  lines.push('')

  if (degradationReasons.length > 0) {
    lines.push('## Degradation Reasons')
    for (const reason of degradationReasons) {
      lines.push(`- ${reason}`)
    }
    lines.push('')
  }

  if (warnings.length > 0) {
    lines.push('## Warnings')
    for (const warning of warnings.slice(0, 12)) {
      lines.push(`- ${warning}`)
    }
    lines.push('')
  }

  return lines.join('\n')
}

function buildReadme(
  input: DotNetReconstructExportInput,
  runtime: RuntimeDetectData,
  packed: boolean,
  packingConfidence: number,
  classesCount: number,
  degradedMode: boolean,
  degradationReasons: string[],
  managedProfile: ManagedProfile | null
): string {
  return [
    `# ${input.project_name}`,
    '',
    '## Reconstruction Summary',
    `- Sample: ${input.sample_id}`,
    `- Runtime: .NET (${runtime.dotnet_version || 'unknown'})`,
    `- Target framework hint: ${runtime.target_framework || 'unknown'}`,
    `- Classes generated: ${classesCount}`,
    `- Metadata-driven types enabled: ${input.include_metadata_types}`,
    `- Packed/obfuscated signal: ${packed} (confidence=${packingConfidence.toFixed(2)})`,
    `- Degraded mode: ${degradedMode}`,
    `- Degradation reasons: ${degradationReasons.length > 0 ? degradationReasons.join('; ') : 'none'}`,
    `- Assembly name: ${managedProfile?.assembly_name || 'unknown'}`,
    `- Managed type count: ${managedProfile?.type_count ?? 0}`,
    `- Assembly references: ${managedProfile?.assembly_references.slice(0, 6).join(', ') || 'none'}`,
    '',
    '## Notes',
    '- This project is a source-like reconstruction, not the original source code.',
    '- Module classes preserve recovered behavioral groupings from native reconstruction.',
    '- Metadata classes preserve namespace/type/method structure from CLR metadata.',
    '- Method bodies are placeholders and require IL/decompiler evidence review.',
    '- Preserve confidence annotations and gap notes during manual refinement.',
    '',
  ].join('\n')
}

function collectLowConfidenceMethods(
  modules: ReconstructModule[],
  confidenceThreshold: number = 0.55
): LowConfidenceMethod[] {
  const lowConfidence: LowConfidenceMethod[] = []
  for (const module of modules) {
    for (const method of module.functions || []) {
      const hasHeavyGaps = Array.isArray(method.gaps) && method.gaps.length >= 2
      if (method.confidence < confidenceThreshold || hasHeavyGaps) {
        lowConfidence.push({
          module: module.name,
          method: method.function,
          address: method.address,
          confidence: method.confidence,
          gaps: method.gaps || [],
        })
      }
    }
  }
  return lowConfidence
}

function buildFallbackNotes(
  runtime: RuntimeDetectData,
  packed: boolean,
  degradationReasons: string[],
  lowConfidenceMethods: LowConfidenceMethod[]
): string {
  const lines: string[] = []
  lines.push('# IL_FALLBACK_NOTES.md')
  lines.push('')
  lines.push('## Why fallback is needed')
  if (degradationReasons.length === 0) {
    lines.push('- Fallback was requested, but no explicit degradation reason was detected.')
  } else if (packed) {
    lines.push('- Packer/obfuscation signals detected; high-fidelity C# requires IL-level recovery.')
    lines.push(`- Reasons: ${degradationReasons.join('; ')}`)
  } else {
    lines.push(`- Reasons: ${degradationReasons.join('; ')}`)
  }
  lines.push('')
  lines.push('## Suggested workflow')
  lines.push('1. Use ILSpy/dnlib to export IL and metadata (types, methods, resources).')
  lines.push('2. Compare IL control flow with recovered placeholders in this project.')
  lines.push('3. Restore method signatures and attributes before rewriting method bodies.')
  lines.push('4. Keep unresolved APIs/types in TODO comments with confidence notes.')
  lines.push('')
  lines.push('## Runtime hints')
  lines.push(`- dotnet_version: ${runtime.dotnet_version || 'unknown'}`)
  lines.push(`- target_framework: ${runtime.target_framework || 'unknown'}`)
  lines.push('')
  lines.push('## Priority methods for IL-first recovery')
  if (lowConfidenceMethods.length === 0) {
    lines.push('- No low-confidence methods were auto-detected.')
  } else {
    for (const method of lowConfidenceMethods.slice(0, 24)) {
      lines.push(
        `- ${method.module}::${method.method} @ ${method.address} confidence=${method.confidence.toFixed(2)} gaps=${method.gaps.join(',') || 'none'}`
      )
    }
    if (lowConfidenceMethods.length > 24) {
      lines.push(`- ... ${lowConfidenceMethods.length - 24} more low-confidence methods omitted`)
    }
  }
  lines.push('')
  return lines.join('\n')
}

function buildValidationLog(validation: BuildValidationResult): string {
  const lines: string[] = []
  lines.push('# BUILD_VALIDATION.log')
  lines.push('')
  lines.push(`status: ${validation.status}`)
  lines.push(`attempted: ${validation.attempted}`)
  lines.push(`dotnet_cli_available: ${validation.dotnet_cli_available}`)
  lines.push(`command: ${validation.command || 'n/a'}`)
  lines.push(`exit_code: ${validation.exit_code === null ? 'n/a' : validation.exit_code}`)
  lines.push(`timed_out: ${validation.timed_out}`)
  lines.push(`error: ${validation.error || 'none'}`)
  lines.push('')
  lines.push('## stdout')
  lines.push('```text')
  lines.push(validation.stdout || '')
  lines.push('```')
  lines.push('')
  lines.push('## stderr')
  lines.push('```text')
  lines.push(validation.stderr || '')
  lines.push('```')
  lines.push('')
  return lines.join('\n')
}

async function runDotNetBuildValidation(
  csprojPath: string,
  cwd: string,
  timeoutMs: number
): Promise<BuildValidationResult> {
  return new Promise((resolve) => {
    const args = ['build', csprojPath, '-nologo', '-v', 'minimal']
    const command = 'dotnet'
    const commandDisplay = `${command} ${args.map((arg) => `"${arg}"`).join(' ')}`
    const effectiveTimeoutMs = Math.max(5000, timeoutMs)

    const child = spawn(command, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })

    let stdout = ''
    let stderr = ''
    let settled = false
    let timedOut = false

    const finish = (result: BuildValidationResult) => {
      if (settled) {
        return
      }
      settled = true
      clearTimeout(timer)
      resolve(result)
    }

    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
      finish({
        attempted: true,
        status: 'failed',
        command: commandDisplay,
        dotnet_cli_available: true,
        exit_code: null,
        timed_out: true,
        stdout,
        stderr,
        error: `dotnet build timed out after ${effectiveTimeoutMs}ms`,
      })
    }, effectiveTimeoutMs)

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })

    child.on('error', (error: NodeJS.ErrnoException) => {
      const unavailable = error.code === 'ENOENT'
      finish({
        attempted: true,
        status: unavailable ? 'unavailable' : 'failed',
        command: commandDisplay,
        dotnet_cli_available: !unavailable,
        exit_code: null,
        timed_out: false,
        stdout,
        stderr,
        error: unavailable ? 'dotnet CLI is not available in PATH' : error.message,
      })
    })

    child.on('close', (code) => {
      if (timedOut) {
        return
      }
      finish({
        attempted: true,
        status: code === 0 ? 'passed' : 'failed',
        command: commandDisplay,
        dotnet_cli_available: true,
        exit_code: code ?? null,
        timed_out: false,
        stdout,
        stderr,
        error: code === 0 ? null : `dotnet build failed with exit code ${code ?? 'unknown'}`,
      })
    })
  })
}

async function sha256File(filePath: string): Promise<string> {
  const content = await fs.readFile(filePath)
  return createHash('sha256').update(content).digest('hex')
}

export function createDotNetReconstructExportHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: DotNetReconstructDependencies
) {
  const runtimeDetectHandler =
    dependencies?.runtimeDetectHandler ||
    createRuntimeDetectHandler(workspaceManager, database, cacheManager)
  const packerDetectHandler =
    dependencies?.packerDetectHandler ||
    createPackerDetectHandler(workspaceManager, database, cacheManager)
  const reconstructExportHandler =
    dependencies?.reconstructExportHandler ||
    createCodeReconstructExportHandler(workspaceManager, database, cacheManager)
  const dotNetMetadataHandler =
    dependencies?.dotNetMetadataHandler ||
    createDotNetMetadataExtractHandler(workspaceManager, database, cacheManager)
  const runBuildValidation = dependencies?.buildValidator || runDotNetBuildValidation

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = DotNetReconstructExportInputSchema.parse(args)
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
      if (!runtimeResult.ok || !runtimeResult.data) {
        return {
          ok: false,
          errors: runtimeResult.errors || ['runtime.detect failed'],
          warnings: runtimeResult.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const runtime = runtimeResult.data as RuntimeDetectData
      if (!runtime.is_dotnet) {
        const suspected = (runtime.suspected || [])
          .map((item) => `${item.runtime}(${item.confidence.toFixed(2)})`)
          .join(', ')
        return {
          ok: false,
          errors: ['Target sample is not recognized as .NET runtime.'],
          warnings:
            suspected.length > 0
              ? [`runtime.detect suspected: ${suspected}`]
              : ['runtime.detect found no .NET signal'],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const completedGhidraAnalysis = findBestGhidraAnalysis(
        database.findAnalysesBySample(input.sample_id),
        'function_index'
      )
      const analysisMarker =
        completedGhidraAnalysis?.finished_at || completedGhidraAnalysis?.id || 'none'
      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          topk: input.topk,
          project_name: input.project_name,
          namespace: input.namespace,
          include_metadata_types: input.include_metadata_types,
          max_managed_types: input.max_managed_types,
          export_name: input.export_name || null,
          include_obfuscation_fallback: input.include_obfuscation_fallback,
          validate_build: input.validate_build,
          build_timeout_ms: input.build_timeout_ms,
          evidence_scope: input.evidence_scope,
          evidence_session_tag: input.evidence_session_tag || null,
          dotnet_version: runtime.dotnet_version || null,
          target_framework: runtime.target_framework || null,
          analysis_marker: analysisMarker,
        },
      })

      if (input.reuse_cached) {
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

      const warnings: string[] = []
      const packerResult = await packerDetectHandler({
        sample_id: input.sample_id,
        engines: ['yara', 'entropy', 'entrypoint'],
      })
      const packerData = (packerResult.ok ? packerResult.data : undefined) as
        | PackerDetectData
        | undefined
      const packed = packerData?.packed === true
      const packingConfidence = clamp(packerData?.confidence ?? 0, 0, 1)

      if (!packerResult.ok) {
        warnings.push(`packer.detect unavailable: ${(packerResult.errors || ['unknown']).join('; ')}`)
      }

      const baseExportName =
        input.export_name ||
        `dotnet_${new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').replace('Z', '')}`
      const nativeExportName = `${baseExportName}_native`
      const reconstructExportResult = await reconstructExportHandler({
        sample_id: input.sample_id,
        topk: input.topk,
        module_limit: 8,
        min_module_size: 1,
        include_imports: true,
        include_strings: true,
        export_name: nativeExportName,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag,
        reuse_cached: true,
      })
      if (reconstructExportResult.warnings && reconstructExportResult.warnings.length > 0) {
        warnings.push(...reconstructExportResult.warnings.map((item) => `reconstruct: ${item}`))
      }

      let modules: ReconstructModule[] = []
      const degradationReasons: string[] = []
      if (reconstructExportResult.ok && reconstructExportResult.data) {
        const reconstructedData = reconstructExportResult.data as ReconstructExportData
        modules = reconstructedData.modules || []
      } else {
        warnings.push(
          `module reconstruction unavailable: ${(reconstructExportResult.errors || ['code.reconstruct.export failed']).join('; ')}`
        )
        degradationReasons.push('module reconstruction unavailable')
      }

      let managedMetadata: DotNetMetadataData | null = null
      const metadataResult = await dotNetMetadataHandler({
        sample_id: input.sample_id,
        include_types: input.include_metadata_types,
        include_methods: true,
        max_types: input.max_managed_types,
        max_methods_per_type: 24,
      })
      if (metadataResult.ok && metadataResult.data) {
        managedMetadata = metadataResult.data as DotNetMetadataData
        if (metadataResult.warnings && metadataResult.warnings.length > 0) {
          warnings.push(...metadataResult.warnings.map((item) => `metadata: ${item}`))
        }
      } else {
        warnings.push(
          `managed metadata unavailable: ${(metadataResult.errors || ['dotnet.metadata.extract failed']).join('; ')}`
        )
        degradationReasons.push('managed metadata unavailable')
      }

      if (modules.length === 0 && !managedMetadata) {
        return {
          ok: false,
          errors: ['Neither native reconstruction modules nor CLR metadata were available for export.'],
          warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const workspace = await workspaceManager.getWorkspace(input.sample_id)
      const dotnetExportRoot = path.join(workspace.reports, 'dotnet_reconstruct', baseExportName)
      const srcRoot = path.join(dotnetExportRoot, 'src')
      const moduleSrcRoot = path.join(srcRoot, 'modules')
      const typeSrcRoot = path.join(srcRoot, 'types')
      await fs.mkdir(srcRoot, { recursive: true })
      await fs.mkdir(moduleSrcRoot, { recursive: true })
      await fs.mkdir(typeSrcRoot, { recursive: true })

      const framework = mapTargetFramework(runtime.target_framework)
      const csprojPath = path.join(dotnetExportRoot, `${sanitizeIdentifier(input.project_name)}.csproj`)
      await fs.writeFile(csprojPath, buildCsproj(input.project_name, framework), 'utf-8')

      const classOutputs: Array<z.infer<typeof DotNetClassSchema>> = []
      for (const module of modules) {
        const className = `${toPascalCase(module.name)}Module`
        const classFile = path.join(moduleSrcRoot, `${className}.cs`)
        const classNamespace = buildNamespace(input.namespace, 'Modules')
        await fs.writeFile(
          classFile,
          buildModuleClassContent(classNamespace, className, module.name, module.confidence, module.functions),
          'utf-8'
        )
        classOutputs.push({
          class_name: className,
          source: 'module',
          module: module.name,
          namespace: classNamespace,
          full_name: `${classNamespace}.${className}`,
          kind: 'class',
          confidence: module.confidence,
          file_path: toPosixRelative(workspace.root, classFile),
          methods: module.functions.map((method) => ({
            name: sanitizeIdentifier(`m_${method.function}`),
            address: method.address,
            token: null,
            confidence: method.confidence,
            gaps: method.gaps,
          })),
        })
      }

      const usedMetadataFiles = new Set<string>()
      if (input.include_metadata_types && managedMetadata?.types?.length) {
        for (const typeInfo of managedMetadata.types) {
          const typeNamespaceSuffix =
            typeInfo.namespace && typeInfo.namespace.trim().length > 0
              ? `Types.${typeInfo.namespace}`
              : 'Types.Global'
          const classNamespace = buildNamespace(input.namespace, typeNamespaceSuffix)
          const relativeTypeDir = path.join(
            typeSrcRoot,
            ...(typeInfo.namespace && typeInfo.namespace.trim().length > 0
              ? typeInfo.namespace.split('.').map((part) => sanitizeNamespaceSegment(part))
              : ['Global'])
          )
          await fs.mkdir(relativeTypeDir, { recursive: true })
          const classBaseName = sanitizeIdentifier(typeInfo.name)
          let className = classBaseName
          let classFile = path.join(relativeTypeDir, `${className}.cs`)
          while (usedMetadataFiles.has(classFile)) {
            className = `${classBaseName}_${typeInfo.token.replace(/^0x/i, '')}`
            classFile = path.join(relativeTypeDir, `${className}.cs`)
          }
          usedMetadataFiles.add(classFile)

          const relatedModules = inferTypeModuleHints(typeInfo, modules)
          await fs.writeFile(
            classFile,
            buildMetadataClassContent(classNamespace, className, typeInfo, relatedModules),
            'utf-8'
          )
          classOutputs.push({
            class_name: className,
            source: 'metadata',
            module: typeInfo.namespace || '<global>',
            namespace: classNamespace,
            full_name: typeInfo.full_name,
            kind: typeInfo.kind,
            confidence: pickMetadataTypeConfidence(typeInfo),
            file_path: toPosixRelative(workspace.root, classFile),
            methods: typeInfo.methods.map((method) => ({
              name: sanitizeIdentifier(method.name === '.ctor' ? 'Ctor' : method.name),
              address: method.rva > 0 ? `0x${method.rva.toString(16)}` : null,
              token: method.token,
              confidence: pickMetadataTypeConfidence(typeInfo),
              gaps: ['metadata_only_rewrite'],
            })),
          })
        }
      }

      const lowConfidenceMethods = collectLowConfidenceMethods(modules)
      if (packed || packingConfidence >= 0.6) {
        degradationReasons.push(
          `packer/obfuscation signal=${packed} confidence=${packingConfidence.toFixed(2)}`
        )
      }
      if (lowConfidenceMethods.length > 0) {
        degradationReasons.push(`low-confidence methods detected: ${lowConfidenceMethods.length}`)
      }
      if (managedMetadata && input.include_metadata_types && managedMetadata.types.length === 0) {
        degradationReasons.push('managed metadata contained no analyst-facing types after filtering')
      }

      const managedProfile = buildManagedProfile(managedMetadata, packed, packingConfidence)

      let buildValidation: BuildValidationResult = {
        attempted: false,
        status: 'skipped',
        command: null,
        dotnet_cli_available: false,
        exit_code: null,
        timed_out: false,
        stdout: '',
        stderr: '',
        error: null,
      }
      let buildLogPath: string | null = null
      if (input.validate_build) {
        buildValidation = await runBuildValidation(csprojPath, dotnetExportRoot, input.build_timeout_ms)
        buildLogPath = path.join(dotnetExportRoot, 'BUILD_VALIDATION.log')
        await fs.writeFile(buildLogPath, buildValidationLog(buildValidation), 'utf-8')

        if (buildValidation.status === 'failed') {
          warnings.push('dotnet build validation failed; review BUILD_VALIDATION.log before using exported project.')
          degradationReasons.push('dotnet build validation failed')
        } else if (buildValidation.status === 'unavailable') {
          warnings.push('dotnet CLI unavailable; skipped compile validation (export still generated).')
        }
      }

      const degradedMode = degradationReasons.length > 0
      const readmePath = path.join(dotnetExportRoot, 'README.md')
      await fs.writeFile(
        readmePath,
        buildReadme(
          input,
          runtime,
          packed,
          packingConfidence,
          classOutputs.length,
          degradedMode,
          degradationReasons,
          managedProfile
        ),
        'utf-8'
      )

      const reverseNotesPath = path.join(dotnetExportRoot, 'REVERSE_NOTES.md')
      await fs.writeFile(
        reverseNotesPath,
        buildDotNetReverseNotes(
          input,
          runtime,
          managedProfile,
          modules,
          packed,
          packingConfidence,
          degradationReasons,
          warnings
        ),
        'utf-8'
      )

      let metadataPath: string | null = null
      if (managedMetadata) {
        metadataPath = path.join(dotnetExportRoot, 'MANAGED_METADATA.json')
        await fs.writeFile(metadataPath, JSON.stringify(managedMetadata, null, 2), 'utf-8')
      }

      let fallbackPath: string | null = null
      if (input.include_obfuscation_fallback && degradedMode) {
        fallbackPath = path.join(dotnetExportRoot, 'IL_FALLBACK_NOTES.md')
        await fs.writeFile(
          fallbackPath,
          buildFallbackNotes(runtime, packed, degradationReasons, lowConfidenceMethods),
          'utf-8'
        )
        warnings.push('Degraded reconstruction detected; generated IL fallback notes with priority methods.')
      }

      const artifacts: ArtifactRef[] = []

      const csprojSha = await sha256File(csprojPath)
      const csprojArtifactId = randomUUID()
      const csprojRelative = toPosixRelative(workspace.root, csprojPath)
      database.insertArtifact({
        id: csprojArtifactId,
        sample_id: input.sample_id,
        type: 'dotnet_csproj',
        path: csprojRelative,
        sha256: csprojSha,
        mime: 'text/xml',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: csprojArtifactId,
        type: 'dotnet_csproj',
        path: csprojRelative,
        sha256: csprojSha,
        mime: 'text/xml',
      })

      const readmeSha = await sha256File(readmePath)
      const readmeArtifactId = randomUUID()
      const readmeRelative = toPosixRelative(workspace.root, readmePath)
      database.insertArtifact({
        id: readmeArtifactId,
        sample_id: input.sample_id,
        type: 'dotnet_readme',
        path: readmeRelative,
        sha256: readmeSha,
        mime: 'text/markdown',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: readmeArtifactId,
        type: 'dotnet_readme',
        path: readmeRelative,
        sha256: readmeSha,
        mime: 'text/markdown',
      })

      const reverseNotesSha = await sha256File(reverseNotesPath)
      const reverseNotesArtifactId = randomUUID()
      const reverseNotesRelative = toPosixRelative(workspace.root, reverseNotesPath)
      database.insertArtifact({
        id: reverseNotesArtifactId,
        sample_id: input.sample_id,
        type: 'dotnet_reverse_notes',
        path: reverseNotesRelative,
        sha256: reverseNotesSha,
        mime: 'text/markdown',
        created_at: new Date().toISOString(),
      })
      artifacts.push({
        id: reverseNotesArtifactId,
        type: 'dotnet_reverse_notes',
        path: reverseNotesRelative,
        sha256: reverseNotesSha,
        mime: 'text/markdown',
      })

      let metadataRelative: string | null = null
      if (metadataPath) {
        const metadataSha = await sha256File(metadataPath)
        const metadataArtifactId = randomUUID()
        metadataRelative = toPosixRelative(workspace.root, metadataPath)
        database.insertArtifact({
          id: metadataArtifactId,
          sample_id: input.sample_id,
          type: 'dotnet_metadata',
          path: metadataRelative,
          sha256: metadataSha,
          mime: 'application/json',
          created_at: new Date().toISOString(),
        })
        artifacts.push({
          id: metadataArtifactId,
          type: 'dotnet_metadata',
          path: metadataRelative,
          sha256: metadataSha,
          mime: 'application/json',
        })
      }

      let buildLogRelative: string | null = null
      if (buildLogPath) {
        const buildLogSha = await sha256File(buildLogPath)
        const buildLogArtifactId = randomUUID()
        buildLogRelative = toPosixRelative(workspace.root, buildLogPath)
        database.insertArtifact({
          id: buildLogArtifactId,
          sample_id: input.sample_id,
          type: 'dotnet_build_log',
          path: buildLogRelative,
          sha256: buildLogSha,
          mime: 'text/plain',
          created_at: new Date().toISOString(),
        })
        artifacts.push({
          id: buildLogArtifactId,
          type: 'dotnet_build_log',
          path: buildLogRelative,
          sha256: buildLogSha,
          mime: 'text/plain',
        })
      }

      if (fallbackPath) {
        const fallbackSha = await sha256File(fallbackPath)
        const fallbackArtifactId = randomUUID()
        const fallbackRelative = toPosixRelative(workspace.root, fallbackPath)
        database.insertArtifact({
          id: fallbackArtifactId,
          sample_id: input.sample_id,
          type: 'dotnet_il_fallback',
          path: fallbackRelative,
          sha256: fallbackSha,
          mime: 'text/markdown',
          created_at: new Date().toISOString(),
        })
        artifacts.push({
          id: fallbackArtifactId,
          type: 'dotnet_il_fallback',
          path: fallbackRelative,
          sha256: fallbackSha,
          mime: 'text/markdown',
        })
      }

      const outputData = {
        sample_id: input.sample_id,
        is_dotnet: true,
        dotnet_version: runtime.dotnet_version || null,
        target_framework: runtime.target_framework || null,
        packed,
        packing_confidence: packingConfidence,
        export_root: toPosixRelative(workspace.root, dotnetExportRoot),
        csproj_path: csprojRelative,
        readme_path: readmeRelative,
        metadata_path: metadataRelative,
        reverse_notes_path: reverseNotesRelative,
        degraded_mode: degradedMode,
        degradation_reasons: degradationReasons,
        build_validation: {
          attempted: buildValidation.attempted,
          status: buildValidation.status,
          command: buildValidation.command,
          dotnet_cli_available: buildValidation.dotnet_cli_available,
          exit_code: buildValidation.exit_code,
          timed_out: buildValidation.timed_out,
          error: buildValidation.error,
          log_path: buildLogRelative,
        },
        managed_profile: managedProfile,
        fallback_notes_path: fallbackPath
          ? toPosixRelative(workspace.root, fallbackPath)
          : null,
        classes: classOutputs,
      }

      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: outputData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
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
