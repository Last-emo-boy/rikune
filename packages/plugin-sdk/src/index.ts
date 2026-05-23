/**
 * Plugin SDK — The public contract for all plugins.
 *
 * Every plugin imports types ONLY from this file (+ npm packages).
 * No server internals, no cross-plugin imports.
 *
 * This file defines:
 *   - Plugin interface — the contract every plugin implements
 *   - PluginToolDeps — injected dependencies (server provides implementations)
 *   - ToolDefinition / WorkerResult / ArtifactRef — standard return types
 *   - PluginServerInterface — what the server exposes to plugins
 */

import { existsSync } from 'node:fs'
import { z } from 'zod'
import { DynamicRuntimePolicySchema, ToolRuntimeContractSchema } from '@rikune/shared'
import type {
  ArtifactRef,
  DynamicRuntimePolicy,
  RuntimeBackendCapability,
  RuntimeBackendType,
  RuntimeDelegationFailureCategory,
  RuntimeExecutionMode,
  RuntimeExecutionSemantics,
  RuntimeFallbackRule,
  RuntimeIsolationBackend,
  RuntimeIsolationRequirement,
  RuntimeNetworkPolicy,
  ToolRuntimeContract,
  WorkerResult,
} from '@rikune/shared'
export {
  DynamicRuntimePolicySchema,
  PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPES,
  RuntimeBackendCapabilitySchema,
  RuntimeDelegationFailureCategorySchema,
  RuntimeDelegationFailureDataSchema,
  RuntimeDelegationFailureResultSchema,
  RuntimeExecutionModeSchema,
  RuntimeFallbackRuleSchema,
  RuntimeIsolationBackendSchema,
  RuntimeIsolationRequirementSchema,
  RuntimeNetworkPolicySchema,
  ToolRuntimeContractSchema,
  buildRuntimeArtifactControlPlaneMetadata,
  inferRuntimeArtifactFamily,
  inferRuntimeArtifactType,
  listRuntimeDynamicTraceArtifactTypes,
} from '@rikune/shared'
export type {
  ArtifactRef,
  DynamicRuntimePolicy,
  RuntimeBackendCapability,
  RuntimeBackendType,
  RuntimeDelegationFailureCategory,
  RuntimeExecutionMode,
  RuntimeExecutionSemantics,
  RuntimeFallbackRule,
  RuntimeIsolationBackend,
  RuntimeIsolationRequirement,
  RuntimeNetworkPolicy,
  ToolRuntimeContract,
  WorkerResult,
} from '@rikune/shared'

// ═══════════════════════════════════════════════════════════════════════════
// Result Types
// ═══════════════════════════════════════════════════════════════════════════

/** Standard tool result (MCP protocol). */
export interface ToolResult {
  content: Array<{ type: string; text: string }>
  isError?: boolean
  structuredContent?: Record<string, unknown>
}

// ═══════════════════════════════════════════════════════════════════════════
// Tool Definition
// ═══════════════════════════════════════════════════════════════════════════

/** Schema for a tool's inputs. */
export interface ToolDefinition {
  name: string
  canonicalName?: string
  description: string
  inputSchema: any
  outputSchema?: any
  /** Aspect metadata used by sample profiling and progressive discovery. */
  aspects?: PluginAspects
  /** Artifact families this tool may write. */
  artifacts?: ToolArtifactSpec[]
  /** Evidence families this tool may produce. */
  evidence?: ToolEvidenceSpec[]
  /** Cross-plugin workflow recipes this tool starts, advances, or completes. */
  workflowRecipes?: WorkflowRecipeSpec[]
  /** Dynamic execution policy surfaced by readiness and scaffold templates. */
  runtimePolicy?: DynamicRuntimePolicy
  /** Runtime execution contract for tools delegated to a runtime node. */
  runtime?: ToolRuntimeContract
  /** Bounded backend worker contract for optional worker-backed tools. */
  workerBackend?: BackendWorkerContract
}

/** Generic tool arguments (for tools that don't use Zod parsing). */
export type ToolArgs = Record<string, unknown>

export type ToolHandler<TArgs = ToolArgs, TResult = WorkerResult | ToolResult | unknown> = (
  args: TArgs,
  deps: PluginToolDeps,
  ctx?: PluginContext
) => TResult | Promise<TResult>

export interface DefinedTool<TArgs = ToolArgs> {
  definition: ToolDefinition
  handler: ToolHandler<TArgs>
}

export interface DefineToolConfig<TArgs = ToolArgs> extends ToolDefinition {
  handler: ToolHandler<TArgs>
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin aspects — shared taxonomy for routing and discovery
// ═══════════════════════════════════════════════════════════════════════════

export const PLUGIN_ASPECT_FORMATS = [
  'pe',
  'efi',
  'sys',
  'coff',
  'coff-lib',
  'pdb',
  'msi',
  'msix',
  'appx',
  'cab',
  'nsis',
  'inno',
  'linux-binary',
  'elf',
  'elf-executable',
  'so',
  'core',
  'elf-core',
  'elf-object',
  'linux-kernel-module',
  'dwarf',
  'object',
  'static-lib',
  'ar',
  'ar-static-lib',
  'deb',
  'rpm',
  'apk-alpine',
  'snap',
  'flatpak',
  'appimage',
  'macho',
  'fat',
  'universal',
  'macho-object',
  'dylib',
  'framework',
  'xcframework',
  'app-bundle',
  'dsym',
  'dmg',
  'pkg',
  'ipa',
  'apple-signing',
  'codesignature',
  'entitlements',
  'plist',
  'mobileprovision',
  'android-package',
  'android-bytecode',
  'apk',
  'aab',
  'apks',
  'dex',
  'multi-dex',
  'oat',
  'art',
  'odex',
  'vdex',
  'aar',
  'xapk',
  'split-apk',
  'apk-signature',
  'arsc',
  'jar',
  'class',
  'war',
  'jmod',
  'kotlin-metadata',
  'dotnet',
  'pe-clr',
  'nupkg',
  'mono',
  'winmd',
  'unity',
  'unity-metadata',
  'il2cpp',
  'wasm',
  'wasi',
  'wat',
  'pyc',
  'lua-bytecode',
  'v8-cache',
  'js',
  'javascript',
  'mjs',
  'cjs',
  'typescript',
  'source-map',
  'html',
  'firmware',
  'uimage',
  'fit',
  'dtb',
  'itb',
  'initramfs',
  'cpio',
  'squashfs',
  'cramfs',
  'jffs2',
  'ubi',
  'ubifs',
  'romfs',
  'archive',
  'zip',
  '7z',
  'rar',
  'tar',
  'gz',
  'xz',
  'zstd',
  'iso',
  'installer',
  'container',
  'docker-image',
  'oci-image',
] as const

export const PLUGIN_ASPECT_PLATFORMS = [
  'windows',
  'linux',
  'macos',
  'ios',
  'android',
  'jvm',
  'dotnet',
  'wasm',
  'python',
  'lua',
  'node',
  'embedded',
  'cross-platform',
  'all',
] as const

export const PLUGIN_ASPECT_ARCHITECTURES = [
  'x86',
  'x64',
  'arm',
  'arm64',
  'mips',
  'mipsel',
  'ppc',
  'riscv',
  'wasm',
] as const

export const PLUGIN_ASPECT_EXECUTIONS = [
  'static',
  'dynamic',
  'emulation',
  'decompilation',
  'triage',
  'correlation',
] as const

export const PLUGIN_ASPECT_SAFETY = [
  'passive',
  'opt_in_dynamic',
  'requires_isolation',
  'no_live_sample_by_default',
  'no_installer_execution',
  'no_auto_mount',
  'no_network_by_default',
] as const

export const PLUGIN_ASPECT_EVIDENCE = [
  'structure',
  'symbols',
  'imports',
  'exports',
  'strings',
  'resources',
  'signatures',
  'behavior',
  'network',
  'filesystem',
  'registry',
  'memory',
  'timeline',
  'artifact',
  'manifest',
  'certificates',
  'package-metadata',
  'nested-binaries',
  'sbom',
  'vulnerabilities',
  'provenance',
  'workflow',
  'analysis-memory',
  'correlation-graph',
  'provenance-graph',
] as const

export type PluginAspectFormat = (typeof PLUGIN_ASPECT_FORMATS)[number] | string
export type PluginAspectPlatform = (typeof PLUGIN_ASPECT_PLATFORMS)[number] | string
export type PluginAspectArchitecture = (typeof PLUGIN_ASPECT_ARCHITECTURES)[number] | string
export type PluginAspectExecution = (typeof PLUGIN_ASPECT_EXECUTIONS)[number] | string
export type PluginAspectSafety = (typeof PLUGIN_ASPECT_SAFETY)[number] | string
export type PluginAspectEvidence = (typeof PLUGIN_ASPECT_EVIDENCE)[number] | string

const AspectTagsSchema = z.array(z.string().min(1)).default([])

export const PluginAspectsSchema = z
  .object({
    formats: AspectTagsSchema.optional(),
    platforms: AspectTagsSchema.optional(),
    architectures: AspectTagsSchema.optional(),
    execution: AspectTagsSchema.optional(),
    runtimes: AspectTagsSchema.optional(),
    safety: AspectTagsSchema.optional(),
    capabilities: AspectTagsSchema.optional(),
    evidence: AspectTagsSchema.optional(),
  })
  .passthrough()

export type PluginAspects = z.infer<typeof PluginAspectsSchema>

export interface SampleProfileAspectInput {
  fileTypes?: string[]
  findings?: string[]
  platforms?: string[]
  architectures?: string[]
  execution?: string[]
  runtimes?: string[]
  evidence?: string[]
}

export interface AspectMatchResult {
  matched: boolean
  score: number
  matchedAspects: Record<string, string[]>
  missingAspects: Record<string, string[]>
  reasons: string[]
}

function normalizeAspectTag(tag: unknown): string | null {
  if (typeof tag !== 'string') {
    return null
  }
  const normalized = tag.trim().toLowerCase().replace(/_/g, '-')
  return normalized.length > 0 ? normalized : null
}

function normalizeAspectTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) {
    return []
  }
  return Array.from(
    new Set(tags.map(normalizeAspectTag).filter((tag): tag is string => Boolean(tag)))
  )
}

export function normalizePluginAspects(aspects: PluginAspects | null | undefined): PluginAspects {
  return {
    ...((aspects ?? {}) as Record<string, unknown>),
    formats: normalizeAspectTags(aspects?.formats),
    platforms: normalizeAspectTags(aspects?.platforms),
    architectures: normalizeAspectTags(aspects?.architectures),
    execution: normalizeAspectTags(aspects?.execution),
    runtimes: normalizeAspectTags(aspects?.runtimes),
    safety: normalizeAspectTags(aspects?.safety),
    capabilities: normalizeAspectTags(aspects?.capabilities),
    evidence: normalizeAspectTags(aspects?.evidence),
  }
}

export function buildSampleProfileAspects(profile: SampleProfileAspectInput): PluginAspects {
  const fileTypeTags = normalizeAspectTags(profile.fileTypes).flatMap(
    (tag) => SURFACE_FILE_TYPE_TAGS[tag] ?? [tag]
  )
  return normalizePluginAspects({
    formats: fileTypeTags,
    platforms: profile.platforms,
    architectures: profile.architectures,
    execution: profile.execution,
    runtimes: profile.runtimes,
    capabilities: profile.findings,
    evidence: profile.evidence,
  })
}

function matchAspectGroup(pluginTags: string[], sampleTags: string[]): string[] {
  if (pluginTags.length === 0 || sampleTags.length === 0) {
    return []
  }
  const sample = new Set(sampleTags)
  return pluginTags.filter((tag) => sample.has(tag))
}

export function matchSampleProfile(
  pluginAspects: PluginAspects | null | undefined,
  sampleProfile: SampleProfileAspectInput | PluginAspects
): AspectMatchResult {
  const plugin = normalizePluginAspects(pluginAspects)
  const sample =
    'fileTypes' in sampleProfile || 'findings' in sampleProfile
      ? buildSampleProfileAspects(sampleProfile as SampleProfileAspectInput)
      : normalizePluginAspects(sampleProfile as PluginAspects)

  const groups: Array<keyof PluginAspects> = [
    'formats',
    'platforms',
    'architectures',
    'execution',
    'runtimes',
    'capabilities',
    'evidence',
  ]
  const matchedAspects: Record<string, string[]> = {}
  const missingAspects: Record<string, string[]> = {}
  let declaredGroups = 0
  let matchedGroups = 0

  for (const group of groups) {
    const pluginTags = normalizeAspectTags(plugin[group])
    if (pluginTags.length === 0) {
      continue
    }
    declaredGroups += 1
    const sampleTags = normalizeAspectTags(sample[group])
    const matches = matchAspectGroup(pluginTags, sampleTags)
    if (matches.length > 0) {
      matchedAspects[group] = matches
      matchedGroups += 1
    } else if (sampleTags.length > 0) {
      missingAspects[group] = pluginTags.filter((tag) => !sampleTags.includes(tag))
    }
  }

  const matched = declaredGroups === 0 || matchedGroups > 0
  return {
    matched,
    score: declaredGroups === 0 ? 0 : matchedGroups / declaredGroups,
    matchedAspects,
    missingAspects,
    reasons:
      declaredGroups === 0
        ? ['plugin has no declared aspects']
        : matched
          ? Object.entries(matchedAspects).map(([group, tags]) => `${group}: ${tags.join(', ')}`)
          : ['no declared plugin aspects matched the sample profile'],
  }
}

export function describeAspectCoverage(aspects: PluginAspects | null | undefined): string[] {
  const normalized = normalizePluginAspects(aspects)
  return Object.entries(normalized)
    .filter(([, value]) => Array.isArray(value) && value.length > 0)
    .map(([group, value]) => `${group}: ${(value as string[]).join(', ')}`)
}

// ═══════════════════════════════════════════════════════════════════════════
// Server Interface (what plugins see)
// ═══════════════════════════════════════════════════════════════════════════

/** The server facade exposed to plugins during registration. */
export interface PluginServerInterface {
  registerTool(definition: ToolDefinition, handler: (args: any) => Promise<any>): void
  unregisterTool(canonicalName: string): void
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin Context — scoped runtime context passed to plugins at registration
// ═══════════════════════════════════════════════════════════════════════════

/** Scoped logger interface for plugins. */
export interface PluginLogger {
  info(msg: string, data?: Record<string, unknown>): void
  warn(msg: string, data?: Record<string, unknown>): void
  error(msg: string, data?: Record<string, unknown>): void
  debug(msg: string, data?: Record<string, unknown>): void
}

/**
 * Runtime context provided to each plugin during registration.
 *
 * Gives plugins a scoped logger (prefixed with plugin ID) and a type-safe
 * config reader that validates against the plugin's declared configSchema.
 */
export interface PluginContext {
  /** The plugin's unique ID. */
  pluginId: string
  /** Scoped logger with plugin ID prefix. */
  logger: PluginLogger
  /** Read a config value declared in configSchema (resolved from env vars). */
  getConfig(envVar: string): string | undefined
  /** Read a required config value — throws if missing. */
  getRequiredConfig(envVar: string): string
  /** Data directory path for this plugin (for persistent state). */
  dataDir: string
}

// ═══════════════════════════════════════════════════════════════════════════
// Dependency Injection
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Dependencies injected by the server into plugins.
 *
 * Core services (workspaceManager, database, config, etc.) are always available.
 * Utility functions (resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, etc.)
 * are provided so plugins never import server internals directly.
 *
 * Plugins should destructure what they need:
 * ```ts
 * register(server, deps) {
 *   const { workspaceManager, database, config } = deps
 * }
 * ```
 */
export interface PluginToolDeps {
  // ── Core services ──────────────────────────────────────────────────────
  workspaceManager: any
  database: any
  config?: any
  policyGuard?: any
  cacheManager?: any
  jobQueue?: any
  storageManager?: any
  server?: any
  services?: PluginServices

  // ── Utility functions ──────────────────────────────────────────────────
  /** Resolve a sample_id to its primary file path on disk. */
  resolvePrimarySamplePath?: (
    wm: any,
    sampleId: string
  ) => Promise<{ samplePath: string; integrity?: any }>
  /** Write a JSON analysis artifact to the workspace and register in DB. */
  persistStaticAnalysisJsonArtifact?: (
    wm: any,
    db: any,
    sampleId: string,
    artifactType: string,
    filePrefix: string,
    payload: unknown,
    sessionTag?: string | null
  ) => Promise<ArtifactRef>
  /** Resolve a path relative to the project root (e.g. for Python workers). */
  resolvePackagePath?: (...segments: string[]) => string
  /** Generate a deterministic cache key for a tool invocation. */
  generateCacheKey?: (params: {
    sampleSha256: string
    toolName: string
    toolVersion: string
    args: Record<string, unknown>
    rulesetVersion?: string
  }) => string

  // ── Logging ────────────────────────────────────────────────────────────
  logger?: any

  // ── Specialized (Ghidra, Frida, etc.) ──────────────────────────────────
  /** DecompilerWorker class constructor (Ghidra plugins). */
  DecompilerWorker?: any
  getGhidraDiagnostics?: any
  normalizeGhidraError?: any
  findBestGhidraAnalysis?: any
  getGhidraReadiness?: any
  parseGhidraAnalysisMetadata?: any
  buildPollingGuidance?: any
  PollingGuidanceSchema?: any
  SetupActionSchema?: any
  RequiredUserInputSchema?: any

  /** Allow additional properties for extensibility. */
  [key: string]: any
}

export interface PluginWorkspaceServices {
  manager?: any
  database?: any
  storage?: any
  resolvePrimarySamplePath?: PluginToolDeps['resolvePrimarySamplePath']
  persistStaticAnalysisJsonArtifact?: PluginToolDeps['persistStaticAnalysisJsonArtifact']
}

export interface PluginPlatformServices {
  cacheManager?: any
  jobQueue?: any
  logger?: any
  policyGuard?: any
  resolvePackagePath?: PluginToolDeps['resolvePackagePath']
  generateCacheKey?: PluginToolDeps['generateCacheKey']
  server?: any
}

export interface PluginRuntimeServices {
  client?: any
  mode?: string
  sandboxDir?: string | null
  config?: any
}

export interface PluginGhidraServices {
  DecompilerWorker?: any
  getDiagnostics?: any
  normalizeError?: any
  findBestAnalysis?: any
  getReadiness?: any
  parseAnalysisMetadata?: any
  buildPollingGuidance?: any
  PollingGuidanceSchema?: any
  SetupActionSchema?: any
  RequiredUserInputSchema?: any
}

export interface PluginServices {
  workspace?: PluginWorkspaceServices
  platform?: PluginPlatformServices
  runtime?: PluginRuntimeServices
  ghidra?: PluginGhidraServices
}

export function getWorkspaceServices(deps: PluginToolDeps): PluginWorkspaceServices {
  return {
    manager: deps.services?.workspace?.manager ?? deps.workspaceManager,
    database: deps.services?.workspace?.database ?? deps.database,
    storage: deps.services?.workspace?.storage ?? deps.storageManager,
    resolvePrimarySamplePath:
      deps.services?.workspace?.resolvePrimarySamplePath ?? deps.resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact:
      deps.services?.workspace?.persistStaticAnalysisJsonArtifact ??
      deps.persistStaticAnalysisJsonArtifact,
  }
}

export function getPlatformServices(deps: PluginToolDeps): PluginPlatformServices {
  return {
    cacheManager: deps.services?.platform?.cacheManager ?? deps.cacheManager,
    jobQueue: deps.services?.platform?.jobQueue ?? deps.jobQueue,
    logger: deps.services?.platform?.logger ?? deps.logger,
    policyGuard: deps.services?.platform?.policyGuard ?? deps.policyGuard,
    resolvePackagePath: deps.services?.platform?.resolvePackagePath ?? deps.resolvePackagePath,
    generateCacheKey: deps.services?.platform?.generateCacheKey ?? deps.generateCacheKey,
    server: deps.services?.platform?.server ?? deps.server,
  }
}

export function getRuntimeServices(deps: PluginToolDeps): PluginRuntimeServices {
  return {
    client: deps.services?.runtime?.client ?? deps.runtimeClient,
    mode: deps.services?.runtime?.mode ?? deps.config?.runtime?.mode,
    sandboxDir: deps.services?.runtime?.sandboxDir ?? deps.sandboxDir ?? null,
    config: deps.services?.runtime?.config ?? deps.config?.runtime ?? {},
  }
}

export function getGhidraServices(deps: PluginToolDeps): PluginGhidraServices {
  return {
    DecompilerWorker: deps.services?.ghidra?.DecompilerWorker ?? deps.DecompilerWorker,
    getDiagnostics: deps.services?.ghidra?.getDiagnostics ?? deps.getGhidraDiagnostics,
    normalizeError: deps.services?.ghidra?.normalizeError ?? deps.normalizeGhidraError,
    findBestAnalysis: deps.services?.ghidra?.findBestAnalysis ?? deps.findBestGhidraAnalysis,
    getReadiness: deps.services?.ghidra?.getReadiness ?? deps.getGhidraReadiness,
    parseAnalysisMetadata:
      deps.services?.ghidra?.parseAnalysisMetadata ?? deps.parseGhidraAnalysisMetadata,
    buildPollingGuidance: deps.services?.ghidra?.buildPollingGuidance ?? deps.buildPollingGuidance,
    PollingGuidanceSchema:
      deps.services?.ghidra?.PollingGuidanceSchema ?? deps.PollingGuidanceSchema,
    SetupActionSchema: deps.services?.ghidra?.SetupActionSchema ?? deps.SetupActionSchema,
    RequiredUserInputSchema:
      deps.services?.ghidra?.RequiredUserInputSchema ?? deps.RequiredUserInputSchema,
  }
}

export function getWorkspaceManager(deps: PluginToolDeps): any {
  return getWorkspaceServices(deps).manager
}

export function getDatabase(deps: PluginToolDeps): any {
  return getWorkspaceServices(deps).database
}

export function getRuntimeConfig(deps: PluginToolDeps): any {
  return getRuntimeServices(deps).config ?? {}
}

export function getPlatformServer(deps: PluginToolDeps): any {
  return getPlatformServices(deps).server
}

export function getRuntimeClient(deps: PluginToolDeps): any {
  return getRuntimeServices(deps).client
}

function requireInjectedDependency<T>(
  value: T | null | undefined,
  label: string,
  consumer?: string
): T {
  if (value !== null && value !== undefined) {
    return value
  }
  throw new Error(
    consumer
      ? `${label} is required for ${consumer}`
      : `${label} is required by this plugin handler`
  )
}

export function requireWorkspaceManager(deps: PluginToolDeps, consumer?: string): any {
  return requireInjectedDependency(getWorkspaceManager(deps), 'workspace manager', consumer)
}

export function requireDatabase(deps: PluginToolDeps, consumer?: string): any {
  return requireInjectedDependency(getDatabase(deps), 'database', consumer)
}

export function requirePlatformServer(deps: PluginToolDeps, consumer?: string): any {
  return requireInjectedDependency(getPlatformServer(deps), 'platform server', consumer)
}

export function requireRuntimeClient(deps: PluginToolDeps, consumer?: string): any {
  return requireInjectedDependency(getRuntimeClient(deps), 'runtime client', consumer)
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin Contract
// ═══════════════════════════════════════════════════════════════════════════

/** Declarative description of one config field a plugin needs. */
export interface PluginConfigField {
  envVar: string
  description: string
  required: boolean
  defaultValue?: string
}

// ═══════════════════════════════════════════════════════════════════════════
// System Dependencies — declarative runtime requirement descriptors
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Describes a single runtime dependency a plugin requires.
 *
 * The plugin system uses these to:
 *   1. Auto-generate `check()` when the plugin doesn't provide one
 *   2. Produce a structured health report at startup
 *   3. **Drive Docker image generation** — the generator scans all plugins,
 *      collects their systemDeps, and only includes the build stages, apt
 *      packages, env vars, and validation commands that are actually needed.
 *   4. Generate documentation of per-plugin requirements
 *
 * Example:
 * ```ts
 * systemDeps: [
 *   {
 *     type: 'binary', name: 'frida', versionFlag: '--version',
 *     envVar: 'FRIDA_PATH', required: true,
 *     dockerFeature: 'frida',
 *     aptPackages: [],
 *     dockerValidation: ['frida-ps --help >/dev/null 2>&1'],
 *   },
 *   { type: 'python', name: 'dnfile', importName: 'dnfile', required: true },
 * ]
 * ```
 */
export interface PluginSystemDep {
  /** Kind of dependency. */
  type: 'binary' | 'python' | 'python-venv' | 'env-var' | 'directory' | 'file'

  /** Human-readable name (e.g. `'frida'`, `'dnfile'`, `'Ghidra'`). */
  name: string

  /**
   * For `binary`: the executable name or absolute path to test.
   * For `python`: the pip package name.
   * For `python-venv`: path to the venv's python binary.
   * For `env-var`: the environment variable name.
   * For `directory` / `file`: the path to check (may reference an env var via `$ENV_VAR`).
   */
  target?: string

  /** For `python`: the importable module name if different from package name. */
  importName?: string

  /** For `binary`: flag to get version output (e.g. `'--version'`). */
  versionFlag?: string

  /** Environment variable that provides / overrides the path to this dependency. */
  envVar?: string

  /** Default path inside the Docker image (used for health reporting). */
  dockerDefault?: string

  /** Whether the dependency is required (true) or optional/nice-to-have (false). */
  required: boolean

  /** Short human-readable description shown in health reports. */
  description?: string

  /** Docker `RUN` instruction or package name that installs this dep. */
  dockerInstall?: string

  // ── Docker generation fields (drive Dockerfile output) ───────────────

  /**
   * Docker feature group ID that controls conditional blocks in the
   * Dockerfile template.  Deps with the same `dockerFeature` share a
   * build stage (e.g. `'ghidra'`, `'rizin'`, `'angr'`).
   *
   * When the generator scans plugins, it collects all unique
   * `dockerFeature` values and enables the corresponding `# @if <feature>`
   * blocks in the template.
   *
   * Leave undefined for deps that don't require a dedicated Docker stage
   * (e.g. Python packages already in requirements.txt).
   */
  dockerFeature?: string

  /**
   * apt-get packages to install in the runtime Docker image.
   * Merged across all enabled plugins into a single `apt-get install`.
   */
  aptPackages?: string[]

  /**
   * Shell commands to validate this dependency inside the Docker image.
   * Merged into a single `RUN` validation step at the end of the build.
   */
  dockerValidation?: string[]

  // ── Extended Docker metadata (replaces hardcoded maps in generator) ──

  /**
   * Additional Docker ENV vars beyond the primary `envVar`/`dockerDefault`.
   * Merged across all plugins into the runtime ENV block and
   * docker-compose environment section.
   *
   * Example: `{ JAVA_HOME: '/opt/java/openjdk', GHIDRA_LOG_ROOT: '/ghidra-logs' }`
   */
  extraEnv?: Record<string, string>

  /**
   * Docker build ARG names and their default values.
   * Merged across all plugins into global ARG declarations and
   * docker-compose build args.
   *
   * Example: `{ GHIDRA_VERSION: '12.0.4' }`
   */
  buildArgs?: Record<string, string>

  /**
   * Directories to create and optionally chown in the runtime Docker image.
   * Merged into the `mkdir` + `chown` block near the end of the Dockerfile.
   *
   * Example: `[{ path: '/ghidra-projects', chown: 'appuser:appuser' }]`
   */
  directories?: Array<{ path: string; chown?: string }>

  /**
   * docker-compose volume mounts this dependency requires.
   * Merged into the volumes section of docker-compose.yml.
   *
   * Example: `[{ source: '${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/ghidra-projects', target: '/ghidra-projects', mode: 'rw' }]`
   */
  volumes?: Array<{ source: string; target: string; mode?: 'ro' | 'rw' }>

  /**
   * Docker/backend packaging classification used by the generator and release
   * guards. `installed` means the default selected profile has a concrete
   * install route. `profile-gated`, `byo`, and `sidecar` are explicit
   * non-default routes; they prevent descriptive `dockerInstall` text from
   * being mistaken for an executable install step.
   */
  dockerInstallRoute?: 'installed' | 'profile-gated' | 'byo' | 'sidecar' | 'validation-only'
  dockerInstallProfile?:
    | 'default'
    | 'optional'
    | 'heavy'
    | 'research'
    | 'runtime'
    | 'gpu'
    | 'license-gated'
  dockerInstallNotes?: string[]
}

/**
 * Result of validating a single system dependency at runtime.
 */
export interface DepCheckResult {
  dep: PluginSystemDep
  available: boolean
  resolvedPath?: string
  version?: string
  error?: string
}

export interface BackendWorkerPolicy {
  passiveByDefault?: boolean
  requiresUserOptIn?: boolean
  requiresIsolation?: boolean
  noNetwork?: boolean
  noMutation?: boolean
  noLiveExecution?: boolean
  maxInputBytes?: number
  maxOutputBytes?: number
  defaultTimeoutMs?: number
  allowedRoots?: string[]
  notes?: string[]
  [key: string]: unknown
}

export interface BackendWorkerContract {
  version?: 'backend-worker.v1'
  backendName: string
  backendKind: 'builtin' | 'external' | 'delegated-runtime'
  adapter: string
  availability?: 'builtin' | 'optional' | 'required'
  envVar?: string
  commandHint?: string
  versionHint?: string
  supportedModes?: string[]
  defaultMode?: string
  inputArtifactTypes?: string[]
  outputArtifactTypes?: string[]
  policy?: BackendWorkerPolicy
  readiness?: {
    doesNotStartBackend?: boolean
    setupActions?: string[]
    missingBackendBehavior?: string
    [key: string]: unknown
  }
  packaging?: {
    installRoute?: 'installed' | 'profile-gated' | 'byo' | 'sidecar' | 'validation-only'
    installProfile?:
      | 'default'
      | 'optional'
      | 'heavy'
      | 'research'
      | 'runtime'
      | 'gpu'
      | 'license-gated'
    dockerFeature?: string
    envVar?: string
    dockerDefault?: string
    notes?: string[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

export interface PluginQualityWarning {
  code:
    | 'missing-output-schema'
    | 'missing-surface-rules'
    | 'missing-aspects'
    | 'missing-evidence'
    | 'missing-workflow-recipe'
    | 'missing-runtime-policy'
    | 'dynamic-runtime-contract-missing'
    | 'missing-system-deps'
    | 'missing-tools'
    | 'missing-readiness-check'
  message: string
  tool?: string
  severity?: 'info' | 'warning'
  plugin_id?: string
  suggested_task_owner?: string
}

function suggestedTaskOwnerForPlugin(plugin: Plugin): string {
  const id = plugin.id
  if (id.includes('memory')) return 'TASK-003'
  if (id.includes('vm-analysis') || id.includes('angr') || id.includes('crackme')) return 'TASK-004'
  if (id.includes('kb-collaboration')) return 'TASK-005'
  if (plugin.executionDomain === 'dynamic') return 'TASK-006'
  if (
    id.includes('runtime') ||
    id.includes('dynamic') ||
    id.includes('debug-session') ||
    id.includes('frida') ||
    id.includes('qiling') ||
    id.includes('wine') ||
    id.includes('speakeasy') ||
    id.includes('panda')
  ) {
    return 'TASK-006'
  }
  if (
    id.includes('sbom') ||
    id.includes('container') ||
    id.includes('linux-package') ||
    id.includes('windows-installer')
  ) {
    return 'TASK-007'
  }
  if (id.includes('android') || id.includes('apk') || id.includes('dex')) return 'TASK-008'
  if (id.includes('apple') || id.includes('ios') || id.includes('macos')) return 'TASK-009'
  if (id.includes('wasm')) return 'TASK-010'
  if (id.includes('firmware')) return 'TASK-011'
  if (id.includes('office')) return 'TASK-012'
  if (id.includes('unpack') || id.includes('deobf') || id.includes('upx')) return 'TASK-013'
  if (id.includes('similarity') || id.includes('binary-diff')) return 'TASK-014'
  if (
    id.includes('malware') ||
    id.includes('threat-intel') ||
    id.includes('yara') ||
    id.includes('vuln')
  ) {
    return 'TASK-015'
  }
  return 'TASK-002'
}

function withQualityWarningOwner(
  plugin: Plugin,
  warning: Omit<PluginQualityWarning, 'plugin_id' | 'suggested_task_owner'>
): PluginQualityWarning {
  return {
    ...warning,
    plugin_id: plugin.id,
    suggested_task_owner: suggestedTaskOwnerForPlugin(plugin),
  }
}

function hasDeclaredAspects(aspects: PluginAspects | null | undefined): boolean {
  return Boolean(
    aspects && Object.values(aspects).some((value) => Array.isArray(value) && value.length > 0)
  )
}

function hasWorkflowCapability(aspects: PluginAspects | null | undefined): boolean {
  const normalized = normalizePluginAspects(aspects)
  return [
    ...(normalized.capabilities ?? []),
    ...(normalized.evidence ?? []),
    ...(normalized.execution ?? []),
  ].some((tag) => tag.includes('workflow') || tag.includes('correlation'))
}

export function auditPluginQuality(plugin: Plugin): PluginQualityWarning[] {
  const warnings: PluginQualityWarning[] = []
  const tools = plugin.tools ?? []
  const pluginHasAspects = hasDeclaredAspects(plugin.aspects)
  const pluginHasRuntimePolicy = Boolean(plugin.runtimePolicy)

  if (tools.length === 0 && typeof plugin.register !== 'function') {
    warnings.push(
      withQualityWarningOwner(plugin, {
        code: 'missing-tools',
        message: 'Plugin declares no tools or register() handler.',
        severity: 'warning',
      })
    )
  }

  if (!plugin.surfaceRules) {
    warnings.push(
      withQualityWarningOwner(plugin, {
        code: 'missing-surface-rules',
        message: 'Plugin does not declare progressive surfaceRules; it defaults to always visible.',
        severity: 'info',
      })
    )
  }

  if (!pluginHasAspects) {
    warnings.push(
      withQualityWarningOwner(plugin, {
        code: 'missing-aspects',
        message: 'Plugin does not declare aspect metadata for routing and progressive discovery.',
        severity: 'info',
      })
    )
  }

  if ((plugin.systemDeps ?? []).length === 0 && plugin.executionDomain !== 'static') {
    warnings.push(
      withQualityWarningOwner(plugin, {
        code: 'missing-system-deps',
        message:
          'Plugin has no declared systemDeps, so runtime/dependency degradation cannot be reported.',
        severity: 'info',
      })
    )
  }

  if (
    !plugin.check &&
    (plugin.systemDeps ?? []).length === 0 &&
    plugin.executionDomain === 'dynamic'
  ) {
    warnings.push(
      withQualityWarningOwner(plugin, {
        code: 'missing-readiness-check',
        message: 'Dynamic plugin has neither check() nor systemDeps readiness metadata.',
        severity: 'warning',
      })
    )
  }

  for (const tool of tools) {
    const definition = tool.definition
    if (!definition.outputSchema) {
      warnings.push(
        withQualityWarningOwner(plugin, {
          code: 'missing-output-schema',
          message: `Tool ${definition.name} has no outputSchema.`,
          tool: definition.name,
          severity: 'warning',
        })
      )
    }
    if (!pluginHasAspects && !definition.aspects) {
      warnings.push(
        withQualityWarningOwner(plugin, {
          code: 'missing-aspects',
          message: `Tool ${definition.name} has no aspect metadata.`,
          tool: definition.name,
          severity: 'info',
        })
      )
    }
    if ((definition.evidence ?? []).length === 0 && (definition.artifacts ?? []).length === 0) {
      warnings.push(
        withQualityWarningOwner(plugin, {
          code: 'missing-evidence',
          message: `Tool ${definition.name} does not declare artifact or evidence output metadata.`,
          tool: definition.name,
          severity: 'info',
        })
      )
    }
    if (
      (hasWorkflowCapability(plugin.aspects) || hasWorkflowCapability(definition.aspects)) &&
      (definition.workflowRecipes ?? []).length === 0
    ) {
      warnings.push(
        withQualityWarningOwner(plugin, {
          code: 'missing-workflow-recipe',
          message: `Workflow-capable tool ${definition.name} does not declare workflowRecipes metadata.`,
          tool: definition.name,
          severity: 'info',
        })
      )
    }
    if (plugin.executionDomain === 'dynamic' && !definition.runtime) {
      warnings.push(
        withQualityWarningOwner(plugin, {
          code: 'dynamic-runtime-contract-missing',
          message: `Dynamic tool ${definition.name} has no runtime delegation contract.`,
          tool: definition.name,
          severity: 'info',
        })
      )
    }
    if (
      (plugin.executionDomain === 'dynamic' || definition.runtime) &&
      !pluginHasRuntimePolicy &&
      !definition.runtimePolicy &&
      !definition.runtime?.policy
    ) {
      warnings.push(
        withQualityWarningOwner(plugin, {
          code: 'missing-runtime-policy',
          message: `Runtime-backed tool ${definition.name} has no dynamic runtime policy.`,
          tool: definition.name,
          severity: 'info',
        })
      )
    }
  }

  return warnings
}

/** Lifecycle hooks a plugin can implement. */
export interface PluginHooks {
  onBeforeToolCall?: (toolName: string, args: Record<string, unknown>) => void | Promise<void>
  onAfterToolCall?: (
    toolName: string,
    args: Record<string, unknown>,
    elapsedMs: number
  ) => void | Promise<void>
  onToolError?: (toolName: string, error: unknown) => void | Promise<void>
  onActivate?: () => void | Promise<void>
  onDeactivate?: () => void | Promise<void>
}

/** Runtime metadata about a loaded (or skipped) plugin. */
export interface PluginStatus {
  id: string
  name: string
  description?: string
  version?: string
  executionDomain?: 'static' | 'dynamic' | 'both'
  status: 'loaded' | 'skipped-disabled' | 'skipped-check' | 'skipped-deps' | 'error'
  tools: string[]
  configFields?: PluginConfigField[]
  /** Results of system dependency checks (populated at load time). */
  depChecks?: DepCheckResult[]
  /** Non-blocking plugin quality contract warnings exposed for maintenance. */
  qualityWarnings?: PluginQualityWarning[]
  /** Short machine-friendly reason code for skips/errors exposed to control-plane views. */
  reasonCode?:
    | 'disabled-by-config'
    | 'role-incompatible'
    | 'missing-dependency'
    | 'prerequisite-check-failed'
    | 'system-deps-missing'
    | 'registration-failed'
    | 'manually-unloaded'
  /** Human-readable explanation of the current status or skip/error outcome. */
  statusDetail?: string
  /** Unified control-plane status used by dashboard/ops surfaces. */
  controlPlaneStatus?: 'pending' | 'active' | 'completed' | 'failed' | 'cancelled' | 'recoverable'
  error?: string
}

// ═══════════════════════════════════════════════════════════════════════════
// Progressive Tool Surface — visibility control
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Surface tier determines when a plugin's tools become visible to the AI.
 *
 * - `0` (Gateway): Always visible. Entry-point tools for sample intake, triage,
 *   task management, discovery, and reporting. Aim for ≤15 tools at this tier.
 *
 * - `1` (Context-activated): Activated when a sample's file type or format
 *   matches the plugin's declared `activateOn.fileTypes`. For example, PE analysis
 *   tools appear only after a PE file is ingested.
 *
 * - `2` (Finding-activated): Activated when another tool's result contains
 *   a matching finding/signal from `activateOn.findings`. For example, unpacking
 *   tools activate when a packer is detected.
 *
 * - `3` (Expert): Never auto-activated; only shown when the AI calls
 *   `tools.discover` with the matching category. For heavyweight backends
 *   (Ghidra, angr, PANDA, etc.) that require explicit intent.
 */
export type SurfaceTier = 0 | 1 | 2 | 3

/**
 * Declarative visibility rules for a plugin's tools.
 *
 * The ToolSurfaceManager reads these at startup. No hardcoded lists in the core
 * — every plugin self-describes when its tools should become visible.
 *
 * Examples:
 * ```ts
 * // Tier 0 — always visible
 * surfaceRules: { tier: 0 }
 *
 * // Tier 1 — activated when a PE file is loaded
 * surfaceRules: { tier: 1, activateOn: { fileTypes: ['pe32', 'pe64', 'dll'] } }
 *
 * // Tier 2 — activated when packing is detected
 * surfaceRules: { tier: 2, activateOn: { findings: ['packed', 'upx'] } }
 *
 * // Tier 3 — expert tool, manual discovery only
 * surfaceRules: { tier: 3, category: 'symbolic-execution' }
 * ```
 */
export interface SurfaceRules {
  /** Visibility tier (0 = always, 1 = file-type, 2 = finding, 3 = expert). */
  tier: SurfaceTier

  /** Conditions that trigger automatic activation (tier 1 and 2). */
  activateOn?: {
    /**
     * File type / format tags that activate this plugin's tools.
     * Matched against the `file_type` field from triage results.
     *
     * Standard tags: `pe32`, `pe64`, `dll`, `elf`, `macho`, `apk`, `dex`,
     * `jar`, `office`, `pdf`, `pcap`, `firmware`, `dotnet`, `go`, `class`
     */
    fileTypes?: string[]

    /**
     * Finding / signal tags that activate this plugin's tools.
     * Matched against `recommended_next_tools`, packer detections, and
     * structured flags returned by other tools.
     *
     * Standard tags: `packed`, `upx`, `dotnet`, `go`, `signed`, `obfuscated`,
     * `crypto`, `c2`, `shellcode`, `vba_macros`, `suspicious_imports`,
     * `anti_debug`, `vm_detect`
     */
    findings?: string[]
  }

  /**
   * Discovery category for `tools.discover` (primarily tier 3, but any tier
   * can specify a category for discoverability).
   *
   * Standard categories: `reverse-engineering`, `dynamic-analysis`,
   * `symbolic-execution`, `memory-forensics`, `network-analysis`,
   * `malware-analysis`, `vulnerability-research`, `static-analysis`
   */
  category?: string

  /**
   * Declarative signal mapping: when a tool from this plugin produces output
   * where `data[field]` is truthy, the corresponding signal tag(s) are emitted
   * and can activate tier-2 plugins.
   *
   * All plugins' signalMaps are collected into a global lookup. When any tool
   * result arrives, the surface manager checks every registered signalMap.
   *
   * Example:
   * ```ts
   * signalMap: {
   *   'is_packed': 'packed',
   *   'is_dotnet': 'dotnet',
   *   'anti_debug': ['anti_debug', 'suspicious_imports'],
   * }
   * ```
   */
  signalMap?: Record<string, string | string[]>

  /**
   * Custom signal extractor for complex output structures (e.g., arrays of
   * detections). Called after signalMap processing.
   *
   * The function receives the tool result's `data` object and should return
   * an array of signal tags.
   *
   * Example:
   * ```ts
   * extractSignals: (data) => {
   *   const signals: string[] = []
   *   if (Array.isArray(data.detections)) {
   *     for (const d of data.detections) {
   *       if (String(d.type).includes('UPX')) signals.push('packed', 'upx')
   *     }
   *   }
   *   return signals
   * }
   * ```
   */
  extractSignals?: (data: Record<string, unknown>) => string[]
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared vocabulary — file-type tag normalization
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Canonical mapping from raw `detectFileType()` output (lowercased) to the
 * set of file-type tags that tier-1 plugins can match against.
 *
 * This is shared vocabulary — used by the ToolSurfaceManager to normalize
 * file types before matching against plugins' `activateOn.fileTypes`.
 *
 * `detectFileType()` returns: `'PE'`, `'ELF'`, `'Mach-O'`, `'Mach-O-Fat'`,
 * `'unknown'`. Plugins declare tag names from the expanded set below.
 */
export const SURFACE_FILE_TYPE_TAGS: Record<string, string[]> = {
  pe: ['pe', 'pe32', 'pe64', 'dll', 'exe', 'windows'],
  dll: ['pe', 'dll', 'windows'],
  exe: ['pe', 'exe', 'windows'],
  efi: ['efi', 'pe', 'windows', 'firmware'],
  sys: ['sys', 'pe', 'windows', 'driver'],
  'pe-clr': ['pe-clr', 'dotnet', 'pe', 'windows'],
  msi: ['msi', 'installer', 'windows'],
  msix: ['msix', 'appx', 'installer', 'windows'],
  appx: ['appx', 'msix', 'installer', 'windows'],
  cab: ['cab', 'installer', 'archive', 'windows'],
  nsis: ['nsis', 'installer', 'windows'],
  inno: ['inno', 'installer', 'windows'],
  pdb: ['pdb', 'symbols', 'debug-metadata', 'windows'],
  coff: ['coff', 'symbols', 'windows'],
  'coff-lib': ['coff', 'coff-lib', 'symbols', 'windows', 'archive'],
  object: ['object', 'native', 'symbols'],
  'static-lib': ['static-lib', 'archive', 'symbols', 'native'],
  'linux-binary': ['linux-binary', 'elf', 'linux'],
  elf: ['elf', 'linux', 'linux-binary'],
  'elf-executable': ['elf-executable', 'elf', 'linux', 'linux-binary'],
  so: ['elf', 'so', 'linux', 'linux-binary'],
  'elf-so': ['elf', 'so', 'linux', 'linux-binary'],
  'elf-core': ['elf-core', 'core', 'elf', 'linux', 'memory', 'linux-binary'],
  'elf-object': ['elf-object', 'object', 'elf', 'linux', 'symbols'],
  'linux-kernel-module': ['linux-kernel-module', 'elf', 'linux', 'driver', 'linux-binary'],
  'ar-static-lib': ['ar-static-lib', 'static-lib', 'ar', 'archive', 'object'],
  deb: ['deb', 'linux', 'package'],
  rpm: ['rpm', 'linux', 'package'],
  'apk-alpine': ['apk-alpine', 'linux', 'package'],
  snap: ['snap', 'linux', 'package'],
  flatpak: ['flatpak', 'linux', 'package'],
  appimage: ['appimage', 'linux', 'package'],
  'mach-o': ['macho', 'mach-o', 'macos', 'ios', 'apple-signing'],
  'mach-o-fat': ['macho', 'mach-o', 'mach-o-fat', 'macos', 'ios', 'apple-signing'],
  macho: ['macho', 'mach-o', 'macos', 'ios', 'apple-signing'],
  'macho-object': ['macho-object', 'object', 'macho', 'macos', 'ios'],
  dylib: ['dylib', 'macho', 'macos', 'ios', 'apple-signing'],
  framework: ['framework', 'macho', 'macos', 'ios', 'container', 'apple-signing'],
  xcframework: ['xcframework', 'macho', 'macos', 'ios', 'container', 'apple-signing'],
  'app-bundle': ['app-bundle', 'macho', 'macos', 'ios', 'container', 'apple-signing'],
  dsym: ['dsym', 'macho', 'symbols', 'debug-metadata', 'macos', 'ios'],
  'apple-signing': ['apple-signing', 'macos', 'ios', 'certificates', 'package-metadata'],
  codesignature: ['codesignature', 'apple-signing', 'macos', 'ios', 'certificates'],
  entitlements: ['entitlements', 'apple-signing', 'macos', 'ios', 'manifest'],
  plist: ['plist', 'apple-signing', 'macos', 'ios', 'manifest'],
  mobileprovision: ['mobileprovision', 'ios', 'certificates', 'package-metadata', 'apple-signing'],
  ipa: ['ipa', 'ios', 'macho', 'apple-signing'],
  dmg: ['dmg', 'macos', 'container'],
  pkg: ['pkg', 'macos', 'installer'],
  'android-package': ['android-package', 'android', 'apk', 'dex'],
  'android-bytecode': ['android-bytecode', 'android', 'dex'],
  apk: ['apk', 'android', 'dex', 'android-package'],
  aab: ['aab', 'android', 'dex', 'android-package'],
  apks: ['apks', 'android', 'split-apk', 'android-package'],
  xapk: ['xapk', 'android', 'apk', 'android-package'],
  'split-apk': ['split-apk', 'android', 'apk', 'android-package'],
  dex: ['dex', 'android', 'android-bytecode'],
  'multi-dex': ['multi-dex', 'dex', 'android', 'android-bytecode'],
  oat: ['oat', 'android', 'android-bytecode'],
  odex: ['odex', 'android', 'android-bytecode'],
  art: ['art', 'android', 'android-bytecode'],
  vdex: ['vdex', 'android', 'android-bytecode'],
  aar: ['aar', 'android', 'jvm', 'java', 'archive', 'android-package'],
  'apk-signature': ['apk-signature', 'android', 'certificates', 'android-package'],
  arsc: ['arsc', 'android', 'resources', 'android-package'],
  jar: ['jar', 'jvm', 'java', 'class'],
  war: ['war', 'jvm', 'java', 'archive'],
  jmod: ['jmod', 'jvm', 'java', 'archive'],
  class: ['class', 'jvm', 'java'],
  'kotlin-metadata': ['kotlin-metadata', 'jvm', 'java'],
  dotnet: ['dotnet', 'pe-clr'],
  nupkg: ['nupkg', 'dotnet', 'archive'],
  mono: ['mono', 'dotnet'],
  winmd: ['winmd', 'dotnet', 'pe-clr'],
  unity: ['unity', 'unity-metadata', 'dotnet'],
  'unity-metadata': ['unity-metadata', 'unity', 'il2cpp'],
  il2cpp: ['il2cpp', 'unity', 'native'],
  wasm: ['wasm', 'wasi'],
  wat: ['wat', 'wasm', 'wasi'],
  pyc: ['pyc', 'python'],
  'lua-bytecode': ['lua-bytecode', 'lua'],
  'v8-cache': ['v8-cache', 'node'],
  js: ['js', 'javascript', 'node', 'browser'],
  javascript: ['js', 'javascript', 'node', 'browser'],
  mjs: ['mjs', 'js', 'javascript', 'node'],
  cjs: ['cjs', 'js', 'javascript', 'node'],
  typescript: ['typescript', 'js', 'javascript', 'node'],
  'source-map': ['source-map', 'js', 'javascript'],
  html: ['html', 'js', 'javascript', 'browser'],
  firmware: ['firmware', 'embedded'],
  uimage: ['uimage', 'firmware', 'embedded', 'linux'],
  fit: ['fit', 'firmware', 'embedded', 'linux'],
  dtb: ['dtb', 'firmware', 'embedded', 'linux'],
  itb: ['itb', 'fit', 'firmware', 'embedded', 'linux'],
  initramfs: ['initramfs', 'firmware', 'archive', 'linux', 'linux-binary'],
  cpio: ['cpio', 'initramfs', 'archive', 'linux', 'linux-binary'],
  squashfs: ['squashfs', 'firmware', 'filesystem', 'embedded'],
  cramfs: ['cramfs', 'firmware', 'filesystem', 'embedded'],
  jffs2: ['jffs2', 'firmware', 'filesystem', 'embedded'],
  ubi: ['ubi', 'firmware', 'filesystem', 'embedded'],
  ubifs: ['ubifs', 'firmware', 'filesystem', 'embedded'],
  romfs: ['romfs', 'firmware', 'filesystem', 'embedded'],
  zip: ['zip', 'archive', 'container'],
  '7z': ['7z', 'archive', 'container'],
  rar: ['rar', 'archive', 'container'],
  tar: ['tar', 'archive', 'container'],
  gz: ['gz', 'archive', 'container'],
  xz: ['xz', 'archive', 'container'],
  zstd: ['zstd', 'archive', 'container'],
  iso: ['iso', 'archive', 'container'],
  ar: ['ar', 'archive', 'container'],
  archive: ['archive', 'container'],
  container: ['container', 'archive'],
  'docker-image': ['docker-image', 'container', 'archive'],
  'oci-image': ['oci-image', 'container', 'archive'],
  office: ['office', 'doc', 'xls', 'ppt', 'docx', 'xlsx'],
  pdf: ['pdf'],
  pcap: ['pcap', 'pcapng', 'network'],
}

const PluginIdSchema = z
  .string()
  .regex(/^[a-z][a-z0-9-]*$/, 'Plugin id must be kebab-case, for example my-plugin')

const ToolNameSchema = z
  .string()
  .regex(
    /^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)*$/,
    'Tool name must use lowercase dot-separated segments'
  )

export const PluginConfigFieldSchema = z
  .object({
    envVar: z.string().min(1),
    description: z.string(),
    required: z.boolean(),
    defaultValue: z.string().optional(),
  })
  .passthrough()

export const PluginSystemDepSchema = z
  .object({
    type: z.enum(['binary', 'python', 'python-venv', 'env-var', 'directory', 'file']),
    name: z.string().min(1),
    target: z.string().optional(),
    importName: z.string().optional(),
    versionFlag: z.string().optional(),
    envVar: z.string().optional(),
    dockerDefault: z.string().optional(),
    required: z.boolean(),
    description: z.string().optional(),
    dockerInstall: z.string().optional(),
    dockerFeature: z.string().optional(),
    aptPackages: z.array(z.string()).optional(),
    dockerValidation: z.array(z.string()).optional(),
    extraEnv: z.record(z.string()).optional(),
    buildArgs: z.record(z.string()).optional(),
    directories: z.array(z.object({ path: z.string(), chown: z.string().optional() })).optional(),
    volumes: z
      .array(
        z.object({
          source: z.string(),
          target: z.string(),
          mode: z.enum(['ro', 'rw']).optional(),
        })
      )
      .optional(),
    dockerInstallRoute: z
      .enum(['installed', 'profile-gated', 'byo', 'sidecar', 'validation-only'])
      .optional(),
    dockerInstallProfile: z
      .enum(['default', 'optional', 'heavy', 'research', 'runtime', 'gpu', 'license-gated'])
      .optional(),
    dockerInstallNotes: z.array(z.string()).optional(),
  })
  .passthrough()

export const SurfaceRulesSchema = z
  .object({
    tier: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]),
    activateOn: z
      .object({
        fileTypes: z.array(z.string()).optional(),
        findings: z.array(z.string()).optional(),
      })
      .optional(),
    category: z.string().optional(),
    signalMap: z.record(z.union([z.string(), z.array(z.string())])).optional(),
  })
  .passthrough()

export const ToolArtifactSpecSchema = z
  .object({
    type: z.string().min(1),
    description: z.string().optional(),
    mime: z.string().optional(),
    required: z.boolean().optional(),
  })
  .passthrough()

export const ToolEvidenceSpecSchema = z
  .object({
    category: z.string().min(1),
    description: z.string().optional(),
    artifactTypes: z.array(z.string()).optional(),
    required: z.boolean().optional(),
  })
  .passthrough()

export const WorkflowRecipeSpecSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    description: z.string().optional(),
    startsWith: z.array(z.string()).optional(),
    nextTools: z.array(z.string()).optional(),
    requiredArtifacts: z.array(z.string()).optional(),
    producesArtifacts: z.array(z.string()).optional(),
    evidence: z.array(z.string()).optional(),
    safety: z.array(z.string()).optional(),
    runtimeBackends: z.array(z.string()).optional(),
  })
  .passthrough()

export const BackendWorkerPolicySchema = z
  .object({
    passiveByDefault: z.boolean().optional().default(true),
    requiresUserOptIn: z.boolean().optional().default(false),
    requiresIsolation: z.boolean().optional().default(false),
    noNetwork: z.boolean().optional().default(true),
    noMutation: z.boolean().optional().default(true),
    noLiveExecution: z.boolean().optional().default(true),
    maxInputBytes: z.number().int().positive().optional(),
    maxOutputBytes: z.number().int().positive().optional(),
    defaultTimeoutMs: z.number().int().positive().optional(),
    allowedRoots: z.array(z.string()).optional(),
    notes: z.array(z.string()).optional(),
  })
  .passthrough()

export const BackendWorkerContractSchema = z
  .object({
    version: z.literal('backend-worker.v1').optional().default('backend-worker.v1'),
    backendName: z.string().min(1),
    backendKind: z.enum(['builtin', 'external', 'delegated-runtime']),
    adapter: z.string().min(1),
    availability: z.enum(['builtin', 'optional', 'required']).optional().default('optional'),
    envVar: z.string().optional(),
    commandHint: z.string().optional(),
    versionHint: z.string().optional(),
    supportedModes: z.array(z.string()).optional().default(['builtin']),
    defaultMode: z.string().optional().default('builtin'),
    inputArtifactTypes: z.array(z.string()).optional().default([]),
    outputArtifactTypes: z.array(z.string()).optional().default([]),
    policy: BackendWorkerPolicySchema.optional().default({}),
    readiness: z
      .object({
        doesNotStartBackend: z.boolean().optional().default(true),
        setupActions: z.array(z.string()).optional().default([]),
        missingBackendBehavior: z.string().optional(),
      })
      .passthrough()
      .optional()
      .default({}),
    packaging: z
      .object({
        installRoute: z
          .enum(['installed', 'profile-gated', 'byo', 'sidecar', 'validation-only'])
          .optional(),
        installProfile: z
          .enum(['default', 'optional', 'heavy', 'research', 'runtime', 'gpu', 'license-gated'])
          .optional(),
        dockerFeature: z.string().optional(),
        envVar: z.string().optional(),
        dockerDefault: z.string().optional(),
        notes: z.array(z.string()).optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough()

export type ToolArtifactSpec = z.infer<typeof ToolArtifactSpecSchema>
export type ToolEvidenceSpec = z.infer<typeof ToolEvidenceSpecSchema>
export type WorkflowRecipeSpec = z.infer<typeof WorkflowRecipeSpecSchema>
export type BackendWorkerPolicySchemaType = z.infer<typeof BackendWorkerPolicySchema>
export type BackendWorkerContractSchemaType = z.infer<typeof BackendWorkerContractSchema>

export const ToolManifestSchema = z
  .object({
    name: ToolNameSchema,
    description: z.string().min(1),
    inputSchema: z.any().default({ type: 'object', properties: {} }),
    outputSchema: z.any().optional(),
    aspects: PluginAspectsSchema.optional(),
    artifacts: z.array(ToolArtifactSpecSchema).optional(),
    evidence: z.array(ToolEvidenceSpecSchema).optional(),
    workflowRecipes: z.array(WorkflowRecipeSpecSchema).optional(),
    runtimePolicy: DynamicRuntimePolicySchema.optional(),
    runtime: ToolRuntimeContractSchema.optional(),
    workerBackend: BackendWorkerContractSchema.optional(),
    handler: z.string().optional(),
  })
  .passthrough()

export const PluginManifestSchema = z
  .object({
    id: PluginIdSchema,
    name: z.string().min(1),
    description: z.string().optional(),
    version: z.string().optional(),
    executionDomain: z.enum(['static', 'dynamic', 'both']).optional(),
    dependencies: z.array(PluginIdSchema).optional(),
    configSchema: z.array(PluginConfigFieldSchema).optional(),
    systemDeps: z.array(PluginSystemDepSchema).optional(),
    aspects: PluginAspectsSchema.optional(),
    runtimePolicy: DynamicRuntimePolicySchema.optional(),
    resources: z
      .object({
        workers: z.string().optional(),
        scripts: z.string().optional(),
        data: z.string().optional(),
      })
      .optional(),
    surfaceRules: SurfaceRulesSchema.optional(),
    tools: z.array(ToolManifestSchema).default([]),
  })
  .passthrough()

export type ToolManifest = z.infer<typeof ToolManifestSchema>
export type PluginManifest = z.infer<typeof PluginManifestSchema>

export interface Plugin {
  /** Unique kebab-case identifier, e.g. `'android'`, `'ghidra'`. */
  id: string
  /** Human-readable display name. */
  name: string
  /** Short description of the plugin's capabilities. */
  description?: string
  /** Semantic version string, e.g. `'1.0.0'`. */
  version?: string
  /**
   * Execution domain controls which node role may load this plugin.
   * - `static` — loaded only on analyzer nodes (pure static analysis)
   * - `dynamic` — loaded only on runtime nodes (executes sample code)
   * - `both` (default) — loaded everywhere; backward compatible
   */
  executionDomain?: 'static' | 'dynamic' | 'both'
  /** IDs of plugins that must load before this one. */
  dependencies?: string[]
  /** Declarative config fields the plugin expects. */
  configSchema?: PluginConfigField[]
  /**
   * Declarative system dependencies this plugin requires at runtime.
   * Used for auto-check, health reporting, and Docker validation.
   * When provided and no explicit `check()` is defined, the plugin system
   * will auto-generate a check from these declarations.
   */
  systemDeps?: PluginSystemDep[]
  /** Aspect metadata used by sample profiling and progressive discovery. */
  aspects?: PluginAspects
  /** Dynamic execution policy applied to this plugin's runtime-backed tools by default. */
  runtimePolicy?: DynamicRuntimePolicy
  /**
   * Declares co-located resource directories relative to the plugin root.
   * Used by the Docker generator and build tooling to discover plugin assets.
   *
   * Convention (all optional):
   * - `workers` — Python worker scripts (default: `'workers'`)
   * - `scripts` — Frida/Ghidra scripts (default: `'scripts'`)
   * - `data`    — Data files (JSON, YARA rules, etc.) (default: `'data'`)
   *
   * Set a key to declare the resource exists. The value is the directory name
   * relative to the plugin root (almost always the default).
   *
   * Example:
   * ```ts
   * resources: { workers: 'workers', scripts: 'scripts', data: 'data' }
   * ```
   */
  resources?: {
    workers?: string
    scripts?: string
    data?: string
  }
  /**
   * Progressive Tool Surface — controls when this plugin's tools are
   * visible to the AI.  See {@link SurfaceRules} for full documentation.
   *
   * Omit to default to tier 0 (always visible) for backward compatibility.
   */
  surfaceRules?: SurfaceRules
  /** Optional lifecycle hooks. */
  hooks?: PluginHooks
  /** If true, hooks fire for ALL tool invocations, not just this plugin's tools. */
  globalHooks?: boolean
  /** Optional prerequisite check; return false to skip loading. */
  check?: () => boolean | Promise<boolean>
  /**
   * Declarative tools belonging to this plugin. Plugins created with
   * definePlugin() can use this instead of hand-writing register().
   */
  tools?: DefinedTool[]
  /** Register all tools belonging to this plugin. Return tool names registered. */
  register?: (
    server: PluginServerInterface,
    deps: PluginToolDeps,
    ctx?: PluginContext
  ) => string[] | void
  /** Optional cleanup when the plugin is unloaded at runtime. */
  teardown?: () => void | Promise<void>
}

export interface ValidationIssue {
  path: string
  message: string
}

export interface ValidationResult<T = unknown> {
  ok: boolean
  value?: T
  errors: string[]
  issues: ValidationIssue[]
}

export interface WorkerResultOptions extends Omit<
  WorkerResult,
  'ok' | 'data' | 'errors' | 'warnings'
> {
  warnings?: string[]
}

export interface ToolResultOptions {
  isError?: boolean
}

export const ArtifactRefSchema = z
  .object({
    id: z.string(),
    type: z.string(),
    path: z.string(),
    sha256: z.string(),
    mime: z.string().optional(),
    metadata: z.record(z.any()).optional(),
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
    metadata: z.record(z.any()).optional(),
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
    metadata: z.record(z.any()).optional(),
  })
  .passthrough()

export const ToolOutputEnvelopeSchema = z
  .object({
    ok: z.boolean(),
    data: z.any().optional(),
    warnings: z.array(z.string()).optional(),
    errors: z.array(z.string()).optional(),
    artifacts: z.array(ArtifactRefSchema).optional(),
    evidence: z.array(EvidenceRefSchema).optional(),
    timeline: z.array(EvidenceTimelineEntrySchema).optional(),
    metrics: WorkerResultMetricsSchema.optional(),
  })
  .passthrough()

export type EvidenceRef = z.infer<typeof EvidenceRefSchema>
export type EvidenceTimelineEntry = z.infer<typeof EvidenceTimelineEntrySchema>
export type ToolOutputEnvelope = z.infer<typeof ToolOutputEnvelopeSchema>

export function createEvidenceRef(input: z.input<typeof EvidenceRefSchema>): EvidenceRef {
  return EvidenceRefSchema.parse(input)
}

export function createEvidenceTimelineEntry(
  input: z.input<typeof EvidenceTimelineEntrySchema>
): EvidenceTimelineEntry {
  return EvidenceTimelineEntrySchema.parse(input)
}

export function createToolOutputEnvelope(
  input: z.input<typeof ToolOutputEnvelopeSchema>
): ToolOutputEnvelope {
  return ToolOutputEnvelopeSchema.parse(input)
}

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

export interface DefinePluginConfig extends Omit<Plugin, 'register' | 'tools'> {
  tools?: DefinedTool[]
  register?: Plugin['register']
}

export type ManifestHandlers = Record<string, ToolHandler>

export interface RegisteredHarnessTool {
  definition: ToolDefinition
  handler: (args: unknown) => Promise<unknown>
}

export interface PluginTestHarnessOptions {
  deps?: Partial<PluginToolDeps>
  ctx?: Partial<PluginContext>
  server?: Partial<PluginServerInterface>
}

export interface PluginTestHarness {
  deps: PluginToolDeps
  ctx: PluginContext
  registeredTools: RegisteredHarnessTool[]
  server: PluginServerInterface
  registerPlugin(plugin: Plugin): string[]
}

export type PluginServicePath =
  | 'workspace.manager'
  | 'workspace.database'
  | 'workspace.storage'
  | 'workspace.resolvePrimarySamplePath'
  | 'workspace.persistStaticAnalysisJsonArtifact'
  | 'platform.cacheManager'
  | 'platform.jobQueue'
  | 'platform.logger'
  | 'platform.policyGuard'
  | 'platform.resolvePackagePath'
  | 'platform.generateCacheKey'
  | 'platform.server'
  | 'runtime.client'
  | 'runtime.mode'
  | 'runtime.sandboxDir'
  | 'runtime.config'
  | 'ghidra.DecompilerWorker'
  | 'ghidra.getDiagnostics'
  | 'ghidra.normalizeError'
  | 'ghidra.findBestAnalysis'
  | 'ghidra.getReadiness'
  | 'ghidra.parseAnalysisMetadata'
  | 'ghidra.buildPollingGuidance'

const PluginShapeSchema = z
  .object({
    id: PluginIdSchema,
    name: z.string().min(1),
    description: z.string().optional(),
    version: z.string().optional(),
    executionDomain: z.enum(['static', 'dynamic', 'both']).optional(),
    dependencies: z.array(PluginIdSchema).optional(),
    configSchema: z.array(PluginConfigFieldSchema).optional(),
    systemDeps: z.array(PluginSystemDepSchema).optional(),
    aspects: PluginAspectsSchema.optional(),
    runtimePolicy: DynamicRuntimePolicySchema.optional(),
    resources: z
      .object({
        workers: z.string().optional(),
        scripts: z.string().optional(),
        data: z.string().optional(),
      })
      .optional(),
    surfaceRules: SurfaceRulesSchema.optional(),
    tools: z.array(z.any()).optional(),
    register: z.any().optional(),
  })
  .passthrough()

function zodIssues(error: z.ZodError): ValidationIssue[] {
  return error.issues.map((issue) => ({
    path: issue.path.length > 0 ? issue.path.join('.') : '$',
    message: issue.message,
  }))
}

function validationFailure<T>(issues: ValidationIssue[]): ValidationResult<T> {
  return {
    ok: false,
    errors: issues.map((issue) => `${issue.path}: ${issue.message}`),
    issues,
  }
}

function validationSuccess<T>(value: T): ValidationResult<T> {
  return {
    ok: true,
    value,
    errors: [],
    issues: [],
  }
}

function isDefinedTool(value: unknown): value is DefinedTool {
  return value !== null && typeof value === 'object' && 'definition' in value && 'handler' in value
}

function toolDefinitionFrom(
  value: ToolDefinition | DefinedTool<any> | ToolManifest
): ToolDefinition {
  return isDefinedTool(value) ? value.definition : (value as ToolDefinition)
}

function registerDefinedTools(
  tools: DefinedTool[] | undefined,
  server: PluginServerInterface,
  deps: PluginToolDeps,
  ctx?: PluginContext
): string[] {
  const names: string[] = []
  for (const tool of tools ?? []) {
    server.registerTool(tool.definition, async (args: unknown) =>
      tool.handler(args as never, deps, ctx)
    )
    names.push(tool.definition.name)
  }
  return names
}

function createHarnessLogger(): PluginLogger {
  return {
    info() {},
    warn() {},
    error() {},
    debug() {},
  }
}

export function createPluginTestHarness(options: PluginTestHarnessOptions = {}): PluginTestHarness {
  const registeredTools: RegisteredHarnessTool[] = []
  const deps = {
    workspaceManager: {},
    database: {},
    config: {},
    services: {
      workspace: {},
      platform: {},
      runtime: {},
      ghidra: {},
    },
    ...options.deps,
  } as PluginToolDeps
  const ctx: PluginContext = {
    pluginId: 'test-plugin',
    logger: createHarnessLogger(),
    getConfig(envVar: string) {
      return process.env[envVar]
    },
    getRequiredConfig(envVar: string) {
      const value = process.env[envVar]
      if (value === undefined || value.trim().length === 0) {
        throw new Error(`${envVar} is required`)
      }
      return value
    },
    dataDir: '.',
    ...options.ctx,
  }
  const server: PluginServerInterface = {
    registerTool(definition, handler) {
      registeredTools.push({ definition, handler })
    },
    unregisterTool(canonicalName) {
      const index = registeredTools.findIndex(
        (tool) =>
          tool.definition.canonicalName === canonicalName || tool.definition.name === canonicalName
      )
      if (index >= 0) {
        registeredTools.splice(index, 1)
      }
    },
    ...options.server,
  }

  return {
    deps,
    ctx,
    registeredTools,
    server,
    registerPlugin(plugin) {
      const names = plugin.register?.(server, deps, ctx)
      return Array.isArray(names) ? names : registeredTools.map((tool) => tool.definition.name)
    },
  }
}

export function defineTool<TArgs = ToolArgs>(config: DefineToolConfig<TArgs>): DefinedTool<TArgs> {
  const definition: ToolDefinition = {
    name: config.name,
    canonicalName: config.canonicalName,
    description: config.description,
    inputSchema: config.inputSchema,
    outputSchema: config.outputSchema,
    aspects: config.aspects,
    artifacts: config.artifacts,
    evidence: config.evidence,
    workflowRecipes: config.workflowRecipes,
    runtimePolicy: config.runtimePolicy,
    runtime: config.runtime,
    workerBackend: config.workerBackend,
  }
  const definedTool: DefinedTool<TArgs> = {
    definition,
    handler: config.handler,
  }
  const validation = validateTool(definedTool as DefinedTool<any>)
  if (!validation.ok) {
    throw new Error(`Invalid tool ${config.name}: ${validation.errors.join('; ')}`)
  }
  return definedTool
}

export function definePlugin(config: DefinePluginConfig): Plugin {
  const customRegister = config.register
  const tools = config.tools ?? []
  const plugin: Plugin = {
    ...config,
    tools,
    register(server, deps, ctx) {
      const names = registerDefinedTools(tools, server, deps, ctx)
      const customNames = customRegister?.(server, deps, ctx)
      if (Array.isArray(customNames)) {
        names.push(...customNames)
      }
      return Array.from(new Set(names))
    },
  }
  const validation = validatePlugin(plugin)
  if (!validation.ok) {
    throw new Error(`Invalid plugin ${config.id}: ${validation.errors.join('; ')}`)
  }
  return plugin
}

export function defineManifestPlugin(
  manifestInput: PluginManifest,
  handlers: ManifestHandlers
): Plugin {
  const manifest = PluginManifestSchema.parse(manifestInput)
  const tools = manifest.tools.map((toolManifest: ToolManifest) => {
    const handlerName = String(toolManifest.handler ?? toolManifest.name)
    const handler = handlers[handlerName]
    if (typeof handler !== 'function') {
      throw new Error(
        `Missing handler '${handlerName}' for manifest tool '${toolManifest.name}' in plugin '${manifest.id}'`
      )
    }
    return defineTool({
      name: toolManifest.name,
      description: toolManifest.description,
      inputSchema: toolManifest.inputSchema,
      outputSchema: toolManifest.outputSchema,
      aspects: toolManifest.aspects,
      artifacts: toolManifest.artifacts,
      evidence: toolManifest.evidence,
      workflowRecipes: toolManifest.workflowRecipes,
      runtimePolicy: toolManifest.runtimePolicy,
      runtime: toolManifest.runtime as ToolRuntimeContract | undefined,
      workerBackend: toolManifest.workerBackend as BackendWorkerContract | undefined,
      handler,
    })
  })

  return definePlugin({
    id: manifest.id,
    name: manifest.name,
    description: manifest.description,
    version: manifest.version,
    executionDomain: manifest.executionDomain,
    dependencies: manifest.dependencies,
    configSchema: manifest.configSchema,
    systemDeps: manifest.systemDeps,
    aspects: manifest.aspects,
    runtimePolicy: manifest.runtimePolicy,
    resources: manifest.resources,
    surfaceRules: manifest.surfaceRules,
    tools,
  })
}

export function validateTool(
  value: ToolDefinition | DefinedTool<any> | ToolManifest
): ValidationResult<ToolDefinition> {
  const definition = toolDefinitionFrom(value)
  const result = ToolManifestSchema.safeParse({
    name: definition.name,
    description: definition.description,
    inputSchema: definition.inputSchema,
    outputSchema: definition.outputSchema,
    aspects: definition.aspects,
    artifacts: definition.artifacts,
    evidence: definition.evidence,
    workflowRecipes: definition.workflowRecipes,
    runtimePolicy: definition.runtimePolicy,
    runtime: definition.runtime,
    workerBackend: definition.workerBackend,
  })
  const issues = result.success ? [] : zodIssues(result.error)
  if (isDefinedTool(value) && typeof value.handler !== 'function') {
    issues.push({ path: 'handler', message: 'Tool handler must be a function' })
  }
  if (issues.length > 0) {
    return validationFailure(issues)
  }
  return validationSuccess(definition)
}

export function validatePlugin(plugin: Plugin): ValidationResult<Plugin> {
  const result = PluginShapeSchema.safeParse(plugin)
  const issues = result.success ? [] : zodIssues(result.error)

  const hasRegister = typeof plugin.register === 'function'
  const tools = Array.isArray(plugin.tools) ? plugin.tools : []
  if (!hasRegister && tools.length === 0) {
    issues.push({
      path: 'register',
      message: 'Plugin must provide register() or at least one declarative tool',
    })
  }

  const seenToolNames = new Set<string>()
  for (let index = 0; index < tools.length; index += 1) {
    const validation = validateTool(tools[index])
    for (const issue of validation.issues) {
      issues.push({ path: `tools.${index}.${issue.path}`, message: issue.message })
    }
    const name = tools[index]?.definition?.name
    if (typeof name === 'string') {
      if (seenToolNames.has(name)) {
        issues.push({ path: `tools.${index}.name`, message: `Duplicate tool name '${name}'` })
      }
      seenToolNames.add(name)
    }
  }

  if (issues.length > 0) {
    return validationFailure(issues)
  }
  return validationSuccess(plugin)
}

export function ok(data?: unknown, options: WorkerResultOptions = {}): WorkerResult {
  return {
    ok: true,
    ...options,
    data,
  }
}

export function fail(
  errors: string | string[],
  options: WorkerResultOptions & { data?: unknown } = {}
): WorkerResult {
  return {
    ok: false,
    status: options.status ?? 'failed',
    ...options,
    errors: Array.isArray(errors) ? errors : [errors],
  }
}

export function toolText(payload: unknown, options: ToolResultOptions = {}): ToolResult {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2)
  const structuredContent =
    payload && typeof payload === 'object' && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : undefined
  return {
    content: [{ type: 'text', text }],
    structuredContent,
    isError: options.isError || undefined,
  }
}

export function pathExists(filePath: string | null | undefined): boolean {
  return Boolean(filePath && existsSync(filePath))
}

export function envIsSet(varName: string): boolean {
  const value = process.env[varName]
  return value !== undefined && value.trim().length > 0
}

function getServiceByPath(deps: PluginToolDeps, path: PluginServicePath): unknown {
  switch (path) {
    case 'workspace.manager':
      return getWorkspaceServices(deps).manager
    case 'workspace.database':
      return getWorkspaceServices(deps).database
    case 'workspace.storage':
      return getWorkspaceServices(deps).storage
    case 'workspace.resolvePrimarySamplePath':
      return getWorkspaceServices(deps).resolvePrimarySamplePath
    case 'workspace.persistStaticAnalysisJsonArtifact':
      return getWorkspaceServices(deps).persistStaticAnalysisJsonArtifact
    case 'platform.cacheManager':
      return getPlatformServices(deps).cacheManager
    case 'platform.jobQueue':
      return getPlatformServices(deps).jobQueue
    case 'platform.logger':
      return getPlatformServices(deps).logger
    case 'platform.policyGuard':
      return getPlatformServices(deps).policyGuard
    case 'platform.resolvePackagePath':
      return getPlatformServices(deps).resolvePackagePath
    case 'platform.generateCacheKey':
      return getPlatformServices(deps).generateCacheKey
    case 'platform.server':
      return getPlatformServices(deps).server
    case 'runtime.client':
      return getRuntimeServices(deps).client
    case 'runtime.mode':
      return getRuntimeServices(deps).mode
    case 'runtime.sandboxDir':
      return getRuntimeServices(deps).sandboxDir
    case 'runtime.config':
      return getRuntimeServices(deps).config
    case 'ghidra.DecompilerWorker':
      return getGhidraServices(deps).DecompilerWorker
    case 'ghidra.getDiagnostics':
      return getGhidraServices(deps).getDiagnostics
    case 'ghidra.normalizeError':
      return getGhidraServices(deps).normalizeError
    case 'ghidra.findBestAnalysis':
      return getGhidraServices(deps).findBestAnalysis
    case 'ghidra.getReadiness':
      return getGhidraServices(deps).getReadiness
    case 'ghidra.parseAnalysisMetadata':
      return getGhidraServices(deps).parseAnalysisMetadata
    case 'ghidra.buildPollingGuidance':
      return getGhidraServices(deps).buildPollingGuidance
  }
}

export function requireServices<const TPath extends PluginServicePath>(
  deps: PluginToolDeps,
  paths: readonly TPath[],
  consumer?: string
): Record<TPath, unknown> {
  const result = {} as Record<TPath, unknown>
  for (const path of paths) {
    result[path] = requireInjectedDependency(getServiceByPath(deps, path), path, consumer)
  }
  return result
}
