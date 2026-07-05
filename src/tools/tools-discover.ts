/**
 * tools.discover — Progressive tool discovery meta-tool.
 *
 * Hidden low-level portal for progressive capability inspection/activation.
 * The AI-facing gateway is workflow.search; this handler remains registered
 * for compatibility and as the internal activation backend.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import { getToolSurfaceManager } from '../tool-surface-manager.js'
import type { PluginManager } from '../plugins.js'
import type { Plugin, PluginQualityWarning } from '../plugins/sdk.js'
import { toTransportToolName } from '../core/tool-name-normalization.js'
import { buildPluginBackendInstallProfile } from '../core/backend-install-profile.js'
import { buildToolSurfaceGuidance, ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'
import {
  buildPluginAspectMatrix,
  buildPluginMatrixSources,
  buildToolAspectSummary,
  describeAspectCoverage,
  normalizeAspects,
  normalizeFileTypeTags,
  type ToolAspectSource,
} from './tool-aspect-matrix.js'

// ═══════════════════════════════════════════════════════════════════════════
// Schema
// ═══════════════════════════════════════════════════════════════════════════

export const toolsDiscoverInputSchema = z.object({
  action: z
    .enum(['status', 'list', 'recommend', 'activate'])
    .default('list')
    .describe(
      'Action to perform.\n' +
        '- `status`: Show surface state (how many tools visible vs total).\n' +
        '- `list`: List available categories and plugins that can be activated.\n' +
        '- `recommend`: Return ranked, explainable toolchain recommendations for a sample, file type, query, or goal.\n' +
        '- `activate`: Activate a specific category or plugin.'
    ),
  query: z
    .string()
    .optional()
    .describe(
      'Free-text search across plugin IDs, names, descriptions, tool names, formats, platforms, capabilities, evidence, and workflow recipes.'
    ),
  sample_id: z
    .string()
    .optional()
    .describe(
      'Optional sample ID. When database context is available, its file_type is used as the discovery target.'
    ),
  category: z
    .string()
    .optional()
    .describe(
      'Category to activate (with action=activate) or filter by (with action=list).\n' +
        'Standard categories: reverse-engineering, dynamic-analysis, symbolic-execution, ' +
        'memory-forensics, network-analysis, malware-analysis, vulnerability-research, ' +
        'static-analysis, unpacking, dotnet-analysis, go-analysis, android-analysis.'
    ),
  plugin_id: z
    .string()
    .optional()
    .describe(
      'Specific plugin ID to activate (with action=activate). Use action=list to see available IDs.'
    ),
  tool_name: z
    .string()
    .optional()
    .describe(
      'Specific canonical or transport tool name to search for or activate. Activating a tool opens its owning plugin, or exposes the core tool when it is registered as a core tool.'
    ),
  finding: z
    .string()
    .optional()
    .describe(
      'Finding/signal tag to activate matching plugins (with action=activate).\n' +
        'Tags: packed, dotnet, go, signed, obfuscated, vba_macros, crypto, c2, shellcode, firmware.'
    ),
  file_type: z
    .string()
    .optional()
    .describe(
      'File type tag to activate matching plugins (with action=activate).\n' +
        'Tags: pe, elf, macho, apk, office, pcap, jar, pdf.'
    ),
})

export const toolsDiscoverOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    action: z.string(),
    status: z
      .object({
        enabled: z.boolean(),
        total_plugins: z.number(),
        activated_plugins: z.number(),
        total_tools: z.number(),
        visible_tools: z.number(),
      })
      .optional(),
    categories: z
      .array(
        z.object({
          category: z.string(),
          plugins: z.array(
            z.object({
              id: z.string(),
              name: z.string(),
              description: z.string().optional(),
              tool_count: z.number(),
              tier: z.number(),
              activated: z.boolean(),
              tool_surface_role: ToolSurfaceRoleSchema,
              preferred_primary_tools: z.array(z.string()),
              aspects: z.record(z.array(z.string())).nullable().optional(),
              aspect_coverage: z.array(z.string()).optional(),
              format_matrix: z.record(z.any()).optional(),
              runtime_policy: z.any().nullable().optional(),
              runtime_contract: z.any().nullable().optional(),
              worker_backend: z.any().nullable().optional(),
              backend_install_profile: z.array(z.any()).optional(),
              backend_profile_summary: z.any().optional(),
              artifact_declarations: z.array(z.any()).optional(),
              evidence_declarations: z.array(z.any()).optional(),
              workflow_recipes: z.array(z.any()).optional(),
              recommended_tools: z.array(z.string()).optional(),
              available_tools: z.array(z.string()).optional(),
              blocked_tools: z.array(z.string()).optional(),
              missing_deps: z.array(z.string()).optional(),
              next_actions: z.array(z.string()).optional(),
              score: z.number().optional(),
              match_reasons: z.array(z.string()).optional(),
              readiness_state: z.string().optional(),
              activation_plan: z.array(z.string()).optional(),
              activation_command: z.record(z.any()).optional(),
              why_hidden: z.array(z.string()).optional(),
              quality_warnings: z.array(z.any()).optional(),
            })
          ),
          plugin_matrix: z.any().optional(),
          format_matrix: z.any().optional(),
          recommended_tools: z.array(z.string()).optional(),
          available_tools: z.array(z.string()).optional(),
          blocked_tools: z.array(z.string()).optional(),
          missing_deps: z.array(z.string()).optional(),
          next_actions: z.array(z.string()).optional(),
        })
      )
      .optional(),
    core_tools: z
      .array(
        z.object({
          name: z.string(),
          transport_name: z.string(),
          description: z.string(),
          visible: z.boolean(),
          tool_surface_role: ToolSurfaceRoleSchema,
          preferred_primary_tools: z.array(z.string()),
          aspects: z.record(z.array(z.string())).nullable().optional(),
          aspect_coverage: z.array(z.string()).optional(),
          format_matrix: z.record(z.any()).optional(),
          runtime_contract: z.any().nullable().optional(),
          worker_backend: z.any().nullable().optional(),
          artifact_declarations: z.array(z.any()).optional(),
          evidence_declarations: z.array(z.any()).optional(),
          workflow_recipes: z.array(z.any()).optional(),
          next_actions: z.array(z.string()).optional(),
          score: z.number().optional(),
          match_reasons: z.array(z.string()).optional(),
          readiness_state: z.string().optional(),
          activation_plan: z.array(z.string()).optional(),
          activation_command: z.record(z.any()).optional(),
          why_hidden: z.array(z.string()).optional(),
        })
      )
      .optional(),
    recommendations: z.array(z.any()).optional(),
    recommendation_summary: z.any().optional(),
    activation_audit: z.any().optional(),
    activated: z.array(z.string()).optional(),
    activated_tools: z.array(z.string()).optional(),
    target_file_type_tags: z.array(z.string()).optional(),
    query: z.string().optional(),
    sample_id: z.string().optional(),
    sample_file_type: z.string().optional(),
    matched_plugins: z.array(z.string()).optional(),
    matched_tools: z.array(z.string()).optional(),
    plugin_matrix: z.any().optional(),
    format_matrix: z.any().optional(),
    recommended_tools: z.array(z.string()).optional(),
    available_tools: z.array(z.string()).optional(),
    blocked_tools: z.array(z.string()).optional(),
    missing_deps: z.array(z.string()).optional(),
    next_actions: z.array(z.string()).optional(),
    message: z.string(),
  }),
})

export const toolsDiscoverToolDefinition: ToolDefinition = {
  name: 'tools.discover',
  description:
    'Compatibility low-level portal for searching and activating Rikune tools progressively. Prefer workflow.search for the default AI-facing search and activation gateway. ' +
    'Use `action=status` to see how many tools are visible. ' +
    'Use `action=list` with query, sample_id, file_type, category, plugin_id, or tool_name to search all registered core and plugin capabilities, including tools not currently visible in tools/list. ' +
    'Use `action=recommend` to rank matching tools and return match reasons, readiness state, activation plan, and hidden-surface explanation. ' +
    'Use `action=activate` with tool_name, plugin_id, category, finding, or file_type to expose selected tools when explicitly routed here. ' +
    'This tool is hidden by default in the minimal MCP surface; workflow.search wraps the normal search/activation path.',
  inputSchema: toolsDiscoverInputSchema,
  outputSchema: toolsDiscoverOutputSchema,
}

type DiscoverPluginMetadata = Pick<
  Plugin,
  'id' | 'name' | 'description' | 'aspects' | 'runtimePolicy' | 'systemDeps' | 'tools'
>

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function collectToolDeclarations(
  plugin: DiscoverPluginMetadata | undefined,
  toolNames: string[]
): {
  artifact_declarations: unknown[]
  evidence_declarations: unknown[]
  workflow_recipes: unknown[]
} {
  const toolNameSet = new Set(toolNames)
  const definitions = (plugin?.tools ?? [])
    .map((tool) => tool.definition)
    .filter((definition) => toolNameSet.has(definition.name))

  return {
    artifact_declarations: definitions.flatMap((definition) => definition.artifacts ?? []),
    evidence_declarations: definitions.flatMap((definition) => definition.evidence ?? []),
    workflow_recipes: definitions.flatMap((definition) => definition.workflowRecipes ?? []),
  }
}

function buildPluginMetadataIndex(
  pluginManager: PluginManager
): Map<string, DiscoverPluginMetadata> {
  const manager = pluginManager as PluginManager & {
    getDiscoveredPlugins?: () => Plugin[]
    getPlugin?: (id: string) => Plugin | undefined
  }
  const index = new Map<string, DiscoverPluginMetadata>()
  for (const plugin of manager.getDiscoveredPlugins?.() ?? []) {
    index.set(plugin.id, plugin)
  }
  for (const status of pluginManager.getStatuses()) {
    const loadedPlugin = manager.getPlugin?.(status.id)
    if (loadedPlugin) {
      index.set(status.id, loadedPlugin)
    }
  }
  return index
}

function collectSurfaceMaps(
  categories: ReturnType<ReturnType<typeof getToolSurfaceManager>['listCategories']>
): {
  activatedByPlugin: Map<string, boolean>
  toolNamesByPlugin: Map<string, string[]>
} {
  const activatedByPlugin = new Map<string, boolean>()
  const toolNamesByPlugin = new Map<string, string[]>()
  for (const category of categories) {
    for (const plugin of category.plugins) {
      activatedByPlugin.set(plugin.id, plugin.activated)
      toolNamesByPlugin.set(plugin.id, uniqueStrings(plugin.tools))
    }
  }
  return { activatedByPlugin, toolNamesByPlugin }
}

function buildToolNameLookup(plugins: DiscoverPluginMetadata[]): Map<string, ToolAspectSource> {
  const lookup = new Map<string, ToolAspectSource>()
  for (const plugin of plugins) {
    for (const tool of plugin.tools ?? []) {
      lookup.set(tool.definition.name, tool.definition)
    }
  }
  return lookup
}

function canonicalToolName(value: string | undefined): string | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

function toolNameCandidates(value: string | undefined): string[] {
  const canonical = canonicalToolName(value)
  if (!canonical) return []
  return uniqueStrings([canonical, canonical.replace(/_/g, '.')])
}

function toolNameMatches(candidate: string, requested: string | undefined): boolean {
  if (!requested) return false
  const requestedNames = toolNameCandidates(requested)
  return (
    requestedNames.includes(candidate) || requestedNames.includes(toTransportToolName(candidate))
  )
}

function collectSearchText(values: unknown[]): string {
  const parts: string[] = []
  const seen = new Set<unknown>()
  function visit(value: unknown, depth = 0): void {
    if (value == null || depth > 5 || seen.has(value)) return
    if (typeof value === 'object') seen.add(value)
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      parts.push(String(value))
      return
    }
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1)
      return
    }
    if (typeof value === 'object') {
      for (const item of Object.values(value as Record<string, unknown>)) visit(item, depth + 1)
    }
  }
  for (const value of values) visit(value)
  return parts.join(' ').toLowerCase()
}

function pluginSearchText(plugin: DiscoverPluginMetadata | undefined, toolNames: string[]): string {
  return collectSearchText([
    plugin?.id,
    plugin?.name,
    plugin?.description,
    plugin?.aspects,
    toolNames,
    toolNames.map((toolName) => toTransportToolName(toolName)),
    ...(plugin?.tools ?? []).map((tool) => [
      tool.definition.name,
      toTransportToolName(tool.definition.name),
      tool.definition.description,
      tool.definition.aspects,
      tool.definition.artifacts,
      tool.definition.evidence,
      tool.definition.workflowRecipes,
      tool.definition.runtime,
      tool.definition.workerBackend,
    ]),
  ])
}

function searchTerms(input: z.infer<typeof toolsDiscoverInputSchema>): string[] {
  return uniqueStrings(
    [input.query, input.tool_name, input.plugin_id, input.finding, input.category]
      .filter((value): value is string => typeof value === 'string')
      .flatMap((value) =>
        value
          .toLowerCase()
          .split(/\s+/)
          .map((item) => item.trim())
          .filter(Boolean)
      )
  )
}

function pluginMatchesSearch(params: {
  pluginId: string
  category: string
  plugin?: DiscoverPluginMetadata
  toolNames: string[]
  input: z.infer<typeof toolsDiscoverInputSchema>
  targetMatchedPluginIds: Set<string>
}): boolean {
  const { pluginId, category, plugin, toolNames, input, targetMatchedPluginIds } = params
  if (input.category && !category.toLowerCase().includes(input.category.toLowerCase())) {
    return false
  }
  if (input.plugin_id && pluginId !== input.plugin_id) {
    return false
  }
  if (input.tool_name && !toolNames.some((tool) => toolNameMatches(tool, input.tool_name))) {
    return false
  }
  if (targetMatchedPluginIds.size > 0 && !targetMatchedPluginIds.has(pluginId)) {
    return false
  }
  const terms = searchTerms(input)
  if (terms.length === 0) return true
  const haystack = `${pluginId} ${category} ${pluginSearchText(plugin, toolNames)}`
  return terms.every((term) => haystack.includes(term))
}

function coreToolMatchesSearch(params: {
  tool: { name: string; transportName: string; visible: boolean }
  definition?: ToolDefinition
  input: z.infer<typeof toolsDiscoverInputSchema>
  hasTargetFileType: boolean
}): boolean {
  const { tool, definition, input, hasTargetFileType } = params
  if (input.plugin_id || input.category || input.finding) return false
  if (input.tool_name && !toolNameMatches(tool.name, input.tool_name)) return false
  const terms = searchTerms(input)
  if (terms.length === 0) return !hasTargetFileType
  const haystack = collectSearchText([
    tool.name,
    tool.transportName,
    definition?.description,
    definition?.aspects,
    definition?.artifacts,
    definition?.evidence,
    definition?.workflowRecipes,
    definition?.runtime,
    definition?.workerBackend,
  ])
  return terms.every((term) => haystack.includes(term))
}

function readinessState(params: {
  activated?: boolean
  missingDeps: string[]
  blockedTools: string[]
  qualityWarnings?: PluginQualityWarning[]
  runtimeRequired?: boolean
  workerRequired?: boolean
  backendProfile?: ReturnType<typeof buildPluginBackendInstallProfile>
}): string {
  const {
    activated,
    missingDeps,
    blockedTools,
    qualityWarnings,
    runtimeRequired,
    workerRequired,
    backendProfile,
  } = params
  if (missingDeps.length > 0 || blockedTools.length > 0) return 'blocked'
  if (qualityWarnings?.some((warning) => warning.code.includes('readiness'))) {
    return 'readiness_warning'
  }
  const backendEntries = backendProfile?.entries ?? []
  if (backendEntries.some((entry) => entry.requires_byo)) return 'byo_backend_required'
  if (backendEntries.some((entry) => entry.requires_sidecar)) return 'sidecar_backend_required'
  if (backendEntries.some((entry) => entry.license_gate)) return 'license_profile_required'
  if (backendEntries.some((entry) => entry.runtime_gate || entry.gpu_gate)) {
    return 'runtime_or_gpu_profile_required'
  }
  if (backendEntries.some((entry) => entry.requires_profile)) return 'backend_profile_required'
  if (runtimeRequired) return 'runtime_opt_in_required'
  if (workerRequired) return 'backend_readiness_required'
  return activated ? 'ready' : 'hidden_activation_required'
}

function scoreTermsInText(terms: string[], text: string): number {
  return terms.filter((term) => text.includes(term)).length
}

function aspectsIndicateRuntimeGate(aspects: Record<string, string[]> | null): boolean {
  const execution = aspects?.execution ?? []
  const safety = aspects?.safety ?? []
  const runtimes = aspects?.runtimes ?? []
  return (
    execution.includes('dynamic') ||
    runtimes.length > 0 ||
    safety.some((tag) =>
      ['opt-in-dynamic', 'requires-isolation', 'no-live-sample-by-default'].includes(tag)
    )
  )
}

function buildPluginRecommendationFields(params: {
  input: z.infer<typeof toolsDiscoverInputSchema>
  fileTypeTags: string[]
  category: string
  pluginId: string
  toolNames: string[]
  tier: number
  activated: boolean
  plugin?: DiscoverPluginMetadata
  aspects: Record<string, string[]> | null
  perPluginMatrix: ReturnType<typeof buildPluginAspectMatrix> | null
  toolSummaries: ReturnType<typeof buildToolAspectSummary>[]
  backendProfile: ReturnType<typeof buildPluginBackendInstallProfile>
  qualityWarnings: PluginQualityWarning[]
}) {
  const {
    input,
    fileTypeTags,
    category,
    pluginId,
    toolNames,
    tier,
    activated,
    plugin,
    aspects,
    perPluginMatrix,
    toolSummaries,
    backendProfile,
    qualityWarnings,
  } = params
  const terms = searchTerms(input)
  const searchText = `${pluginId} ${category} ${pluginSearchText(plugin, toolNames)}`
  const matchedTerms = scoreTermsInText(terms, searchText)
  const matchedTargetTags = fileTypeTags.filter((tag) =>
    Object.keys(perPluginMatrix?.by_format ?? {}).includes(tag)
  )
  const runtimeRequired =
    aspectsIndicateRuntimeGate(aspects) ||
    toolSummaries.some((summary) => Boolean(summary.runtime_contract || summary.runtime_policy))
  const workerRequired = toolSummaries.some((summary) => Boolean(summary.worker_backend))
  const missingDeps = perPluginMatrix?.missing_deps ?? []
  const blockedTools = perPluginMatrix?.blocked_tools ?? []
  const recommendedTools = perPluginMatrix?.target?.recommended_tools.length
    ? perPluginMatrix.target.recommended_tools
    : (perPluginMatrix?.recommended_tools ?? [])
  const backendEntries = backendProfile.entries
  const matchReasons: string[] = []
  let score = 0

  if (matchedTargetTags.length > 0) {
    score += 80 + matchedTargetTags.length * 5
    matchReasons.push(`Matches target file type tags: ${matchedTargetTags.join(', ')}.`)
  }
  if (input.plugin_id === pluginId) {
    score += 100
    matchReasons.push(`Matches requested plugin_id=${pluginId}.`)
  }
  if (input.category && category.toLowerCase().includes(input.category.toLowerCase())) {
    score += 35
    matchReasons.push(`Matches requested category=${input.category}.`)
  }
  if (input.tool_name && toolNames.some((tool) => toolNameMatches(tool, input.tool_name))) {
    score += 100
    matchReasons.push(`Owns requested tool ${input.tool_name}.`)
  }
  if (matchedTerms > 0) {
    score += matchedTerms * 20
    matchReasons.push(`Matches ${matchedTerms}/${terms.length} query term(s).`)
  }
  if (recommendedTools.length > 0) {
    score += 20
    matchReasons.push(`Has recommended tools: ${recommendedTools.slice(0, 4).join(', ')}.`)
  }
  if (toolSummaries.some((summary) => summary.workflow_recipes.length > 0)) {
    score += 8
    matchReasons.push('Declares workflow recipes for chaining.')
  }
  if (toolSummaries.some((summary) => summary.artifact_declarations.length > 0)) {
    score += 6
    matchReasons.push('Declares output artifacts.')
  }
  if (workerRequired) {
    score += 5
    matchReasons.push('Has a bounded worker backend contract.')
  }
  if (backendEntries.length > 0) {
    matchReasons.push(
      `Backend install routes: ${backendEntries
        .map((entry) => `${entry.docker_feature}:${entry.install_route}/${entry.install_profile}`)
        .join(', ')}.`
    )
    if (backendEntries.some((entry) => entry.default_enabled)) score += 6
    if (backendEntries.some((entry) => entry.requires_profile)) score -= 4
    if (backendEntries.some((entry) => entry.requires_byo || entry.requires_sidecar)) score -= 10
    if (
      backendEntries.some((entry) => entry.license_gate || entry.runtime_gate || entry.gpu_gate)
    ) {
      score -= 8
    }
  }
  score += tier === 1 ? 12 : tier === 2 ? 8 : tier === 0 ? 4 : 0
  if (activated) score += 10
  if (runtimeRequired) score -= 8
  if (missingDeps.length > 0 || blockedTools.length > 0) score -= 35
  if (qualityWarnings.length > 0) score -= Math.min(20, qualityWarnings.length * 5)

  const hiddenReasons = activated
    ? []
    : [
        `Plugin is not currently visible in the progressive surface.`,
        `Surface tier ${tier} requires ${
          tier === 1
            ? 'sample/file-type activation'
            : tier === 2
              ? 'finding or explicit activation'
              : tier === 3
                ? 'expert/manual activation'
                : 'explicit gateway activation'
        }.`,
      ]
  const activationPlan = activated
    ? [`Call the recommended tool(s) directly: ${recommendedTools.slice(0, 4).join(', ')}.`]
    : uniqueStrings([
        `Call tools.discover action=activate plugin_id=${pluginId}.`,
        ...(matchedTargetTags.length > 0 && tier <= 2
          ? [`Or call tools.discover action=activate file_type=${matchedTargetTags[0]}.`]
          : []),
        ...(runtimeRequired || workerRequired
          ? ['Call tool.readiness for the selected tool before execution.']
          : []),
        ...backendEntries.flatMap((entry) => {
          if (entry.requires_byo) {
            return [
              `Provide BYO backend for ${entry.docker_feature} via ${entry.env_var ?? 'configured path'}.`,
            ]
          }
          if (entry.requires_sidecar) {
            return [`Start or configure the ${entry.docker_feature} sidecar before execution.`]
          }
          if (
            entry.requires_profile ||
            entry.license_gate ||
            entry.runtime_gate ||
            entry.gpu_gate
          ) {
            return [
              `Use backend profile ${entry.enabled_by_profiles[0] ?? entry.install_profile} for ${entry.docker_feature} when building the analyzer image.`,
            ]
          }
          if (entry.validation_only) {
            return [
              `${entry.docker_feature} is validation-only; use the owning backend plugin for execution.`,
            ]
          }
          return []
        }),
      ])

  return {
    score: Math.max(0, score),
    match_reasons: matchReasons.length > 0 ? matchReasons : ['Available through discovery.'],
    readiness_state: readinessState({
      activated,
      missingDeps,
      blockedTools,
      qualityWarnings,
      runtimeRequired,
      workerRequired,
      backendProfile,
    }),
    activation_plan: activationPlan,
    activation_command: { action: 'activate', plugin_id: pluginId },
    why_hidden: hiddenReasons,
  }
}

function buildCoreToolRecommendationFields(params: {
  tool: { name: string; transportName: string; visible: boolean }
  definition?: ToolDefinition
  input: z.infer<typeof toolsDiscoverInputSchema>
}) {
  const { tool, definition, input } = params
  const terms = searchTerms(input)
  const searchText = collectSearchText([
    tool.name,
    tool.transportName,
    definition?.description,
    definition?.aspects,
    definition?.artifacts,
    definition?.evidence,
    definition?.workflowRecipes,
    definition?.runtime,
    definition?.workerBackend,
  ])
  const matchedTerms = scoreTermsInText(terms, searchText)
  const runtimeRequired = Boolean(definition?.runtime)
  const workerRequired = Boolean(definition?.workerBackend)
  const guidance = buildToolSurfaceGuidance(tool.name, {
    runtimeRequired: runtimeRequired || workerRequired,
  })
  const matchReasons: string[] = []
  let score = guidance.tool_surface_role === 'primary' ? 45 : 20

  if (input.tool_name && toolNameMatches(tool.name, input.tool_name)) {
    score += 100
    matchReasons.push(`Matches requested tool ${input.tool_name}.`)
  }
  if (matchedTerms > 0) {
    score += matchedTerms * 20
    matchReasons.push(`Matches ${matchedTerms}/${terms.length} query term(s).`)
  }
  if (tool.visible) {
    score += 15
    matchReasons.push('Already visible in tools/list.')
  }
  if (runtimeRequired || workerRequired) {
    score -= 8
    matchReasons.push('Requires readiness review before execution.')
  }

  return {
    score: Math.max(0, score),
    match_reasons: matchReasons.length > 0 ? matchReasons : ['Core tool is registered.'],
    readiness_state: readinessState({
      activated: tool.visible,
      missingDeps: [],
      blockedTools: [],
      runtimeRequired,
      workerRequired,
    }),
    activation_plan: tool.visible
      ? [`Call ${tool.name} directly; it is already visible in tools/list.`]
      : [`Call tools.discover action=activate tool_name=${tool.name}.`],
    activation_command: { action: 'activate', tool_name: tool.name },
    why_hidden: tool.visible
      ? []
      : ['Core tool is registered but not currently exposed in the gateway surface.'],
  }
}

function buildRecommendationSummary(recommendations: Array<Record<string, unknown>>) {
  const topTools = uniqueStrings(
    recommendations.flatMap((item) =>
      Array.isArray(item.recommended_tools)
        ? (item.recommended_tools as string[])
        : typeof item.tool_name === 'string'
          ? [item.tool_name]
          : []
    )
  ).slice(0, 12)
  return {
    count: recommendations.length,
    top_tools: topTools,
    activation_required: recommendations.filter(
      (item) =>
        typeof item.readiness_state === 'string' &&
        [
          'hidden_activation_required',
          'backend_readiness_required',
          'runtime_opt_in_required',
        ].includes(item.readiness_state)
    ).length,
    blocked: recommendations.filter((item) => item.readiness_state === 'blocked').length,
  }
}

function buildCoreToolPortalEntry(params: {
  tool: { name: string; transportName: string; visible: boolean }
  definition?: ToolDefinition
  input: z.infer<typeof toolsDiscoverInputSchema>
}) {
  const { tool, definition, input } = params
  const summary = definition
    ? buildToolAspectSummary(definition, { pluginAspects: definition.aspects })
    : null
  const guidance = buildToolSurfaceGuidance(tool.name, {
    runtimeRequired: Boolean(definition?.runtime || definition?.workerBackend),
  })
  const nextActions = tool.visible
    ? [`Call ${tool.name} directly; it is already visible in tools/list.`]
    : [`Use tools.discover action=activate tool_name=${tool.name} to expose this core tool.`]

  return {
    name: tool.name,
    transport_name: tool.transportName,
    description: definition?.description ?? `Core tool ${tool.name}`,
    visible: tool.visible,
    tool_surface_role: guidance.tool_surface_role,
    preferred_primary_tools: guidance.preferred_primary_tools,
    aspects: summary?.aspects ?? null,
    aspect_coverage: summary?.aspect_coverage ?? [],
    format_matrix: summary?.format_matrix ?? {},
    runtime_contract: summary?.runtime_contract ?? null,
    worker_backend: summary?.worker_backend ?? null,
    artifact_declarations: summary?.artifact_declarations ?? [],
    evidence_declarations: summary?.evidence_declarations ?? [],
    workflow_recipes: summary?.workflow_recipes ?? [],
    next_actions: nextActions,
    ...buildCoreToolRecommendationFields({ tool, definition, input }),
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Handler
// ═══════════════════════════════════════════════════════════════════════════

export function createToolsDiscoverHandler(
  pluginManager: PluginManager,
  options: {
    database?: { findSample?: (sampleId: string) => { file_type?: string | null } | null }
    toolDefinitions?: () => ToolDefinition[]
  } = {}
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = toolsDiscoverInputSchema.parse(args)
    const surface = getToolSurfaceManager()
    const sample = input.sample_id ? options.database?.findSample?.(input.sample_id) : null
    const resolvedFileType = input.file_type ?? sample?.file_type ?? undefined

    // Build a plugin index for name/description lookups
    const pluginIndex = new Map<string, { name: string; description?: string }>()
    const pluginMetadataIndex = buildPluginMetadataIndex(pluginManager)
    for (const plugin of pluginMetadataIndex.values()) {
      pluginIndex.set(plugin.id, { name: plugin.name, description: plugin.description })
    }
    const pluginStatusIndex = new Map<string, { qualityWarnings?: PluginQualityWarning[] }>()
    for (const p of pluginManager.getStatuses()) {
      pluginIndex.set(p.id, { name: p.name, description: p.description })
      pluginStatusIndex.set(p.id, { qualityWarnings: p.qualityWarnings })
    }
    const allCategories = surface.listCategories(pluginIndex)
    const toolDefinitionIndex = new Map(
      (options.toolDefinitions?.() ?? []).map((definition) => [definition.name, definition])
    )
    const coreTools = surface.listCoreTools()
    const surfaceMaps = collectSurfaceMaps(allCategories)
    const matrixSources = buildPluginMatrixSources({
      statuses: pluginManager.getStatuses(),
      plugins: [...pluginMetadataIndex.values()],
      toolNameLookup: buildToolNameLookup([...pluginMetadataIndex.values()]),
      activatedByPlugin: surfaceMaps.activatedByPlugin,
      toolNamesByPlugin: surfaceMaps.toolNamesByPlugin,
    })
    const fileTypeTags = normalizeFileTypeTags(resolvedFileType)
    const pluginMatrix = buildPluginAspectMatrix(matrixSources, { targetTags: fileTypeTags })
    const targetMatchedPluginIds = new Set(pluginMatrix.target?.matched_plugins ?? [])
    const buildPluginPortalEntry = (
      category: string,
      p: ReturnType<typeof surface.listCategories>[number]['plugins'][number]
    ) => {
      const plugin = pluginMetadataIndex.get(p.id)
      const pluginSource = matrixSources.find((source) => source.id === p.id)
      const perPluginMatrix = pluginSource
        ? buildPluginAspectMatrix([pluginSource], { targetTags: fileTypeTags })
        : null
      const normalizedAspects = normalizeAspects(plugin?.aspects)
      const aspects = Object.keys(normalizedAspects).length > 0 ? normalizedAspects : null
      const toolSummaries = (plugin?.tools ?? [])
        .filter((tool) => p.tools.includes(tool.definition.name))
        .map((tool) =>
          buildToolAspectSummary(tool.definition, {
            pluginAspects: plugin?.aspects,
            pluginRuntimePolicy: plugin?.runtimePolicy,
          })
        )
      const backendProfile = plugin
        ? buildPluginBackendInstallProfile(plugin)
        : buildPluginBackendInstallProfile({ systemDeps: [], tools: [] })
      const qualityWarnings = pluginStatusIndex.get(p.id)?.qualityWarnings ?? []
      return {
        id: p.id,
        name: p.name,
        description: p.description,
        tool_count: p.tools.length,
        tier: p.tier,
        activated: p.activated,
        tool_surface_role: p.tools.some(
          (tool) => buildToolSurfaceGuidance(tool).tool_surface_role === 'runtime_gated'
        )
          ? 'runtime_gated'
          : p.tier === 3
            ? 'expert'
            : p.tools.some(
                  (tool) => buildToolSurfaceGuidance(tool).tool_surface_role === 'specialist'
                )
              ? 'specialist'
              : 'primary',
        preferred_primary_tools: Array.from(
          new Set(p.tools.flatMap((tool) => buildToolSurfaceGuidance(tool).preferred_primary_tools))
        ),
        aspects,
        aspect_coverage: describeAspectCoverage(aspects),
        format_matrix: perPluginMatrix?.by_format ?? {},
        runtime_policy: plugin?.runtimePolicy ?? null,
        runtime_contract:
          toolSummaries.find((summary) => summary.runtime_contract)?.runtime_contract ?? null,
        worker_backend:
          toolSummaries.find((summary) => summary.worker_backend)?.worker_backend ?? null,
        backend_install_profile: backendProfile.entries,
        backend_profile_summary: backendProfile.summary,
        ...collectToolDeclarations(plugin, p.tools),
        recommended_tools: perPluginMatrix?.target?.recommended_tools.length
          ? perPluginMatrix.target.recommended_tools
          : (perPluginMatrix?.recommended_tools ?? []),
        available_tools: perPluginMatrix?.available_tools ?? [],
        blocked_tools: perPluginMatrix?.blocked_tools ?? [],
        missing_deps: perPluginMatrix?.missing_deps ?? [],
        next_actions: perPluginMatrix?.target?.next_actions.length
          ? uniqueStrings([...perPluginMatrix.target.next_actions, ...perPluginMatrix.next_actions])
          : (perPluginMatrix?.next_actions ?? []),
        ...buildPluginRecommendationFields({
          input,
          fileTypeTags,
          category,
          pluginId: p.id,
          toolNames: p.tools,
          tier: p.tier,
          activated: p.activated,
          plugin,
          aspects,
          perPluginMatrix,
          toolSummaries,
          backendProfile,
          qualityWarnings,
        }),
        quality_warnings: qualityWarnings,
      }
    }
    const buildRecommendationList = (
      categories: typeof allCategories,
      matchingCoreTools: typeof coreTools
    ) =>
      [
        ...categories.flatMap((category) =>
          category.plugins.map((plugin) => ({
            kind: 'plugin',
            category: category.category,
            plugin_id: plugin.id,
            ...buildPluginPortalEntry(category.category, plugin),
          }))
        ),
        ...matchingCoreTools.map((tool) => ({
          kind: 'core_tool',
          tool_name: tool.name,
          ...buildCoreToolPortalEntry({
            tool,
            definition: toolDefinitionIndex.get(tool.name),
            input,
          }),
        })),
      ]
        .sort((a, b) => Number(b.score ?? 0) - Number(a.score ?? 0))
        .slice(0, 25)
    const buildFilteredCategories = (
      options: { queryAsHardFilter?: boolean } = { queryAsHardFilter: true }
    ) =>
      allCategories
        .map((c) => {
          const matchInput =
            options.queryAsHardFilter || fileTypeTags.length === 0
              ? input
              : { ...input, query: undefined }
          const plugins = c.plugins.filter((p) =>
            pluginMatchesSearch({
              pluginId: p.id,
              category: c.category,
              plugin: pluginMetadataIndex.get(p.id),
              toolNames: p.tools,
              input: matchInput,
              targetMatchedPluginIds,
            })
          )
          return { ...c, plugins }
        })
        .filter((c) => c.plugins.length > 0)
    const buildFilteredCoreTools = () =>
      coreTools.filter((tool) =>
        coreToolMatchesSearch({
          tool,
          definition: toolDefinitionIndex.get(tool.name),
          input,
          hasTargetFileType: fileTypeTags.length > 0,
        })
      )

    switch (input.action) {
      case 'status': {
        const status = surface.getSurfaceStatus()
        return {
          ok: true,
          data: {
            action: 'status',
            status: {
              enabled: status.enabled,
              total_plugins: status.totalPlugins,
              activated_plugins: status.activatedPlugins,
              total_tools: status.totalTools,
              visible_tools: status.visibleTools,
            },
            message: status.enabled
              ? `Progressive surface active: ${status.visibleTools}/${status.totalTools} tools visible from ${status.activatedPlugins}/${status.totalPlugins} plugins. ` +
                `Tier 0: ${status.tiers[0].activated}/${status.tiers[0].total}, ` +
                `Tier 1: ${status.tiers[1].activated}/${status.tiers[1].total}, ` +
                `Tier 2: ${status.tiers[2].activated}/${status.tiers[2].total}, ` +
                `Tier 3: ${status.tiers[3].activated}/${status.tiers[3].total}. ` +
                'Use action=list to browse categories, or action=activate to unlock more tools.'
              : `Progressive surface is disabled — all ${status.totalTools} tools are visible.`,
          },
        }
      }

      case 'recommend': {
        const filtered = buildFilteredCategories({ queryAsHardFilter: false })
        const filteredCoreTools = buildFilteredCoreTools()
        const recommendations = buildRecommendationList(filtered, filteredCoreTools)
        return {
          ok: true,
          data: {
            action: 'recommend',
            recommendations,
            recommendation_summary: buildRecommendationSummary(recommendations),
            query: input.query,
            sample_id: input.sample_id,
            sample_file_type: resolvedFileType,
            target_file_type_tags: fileTypeTags.length > 0 ? fileTypeTags : undefined,
            plugin_matrix: pluginMatrix,
            format_matrix: pluginMatrix.by_format,
            recommended_tools: pluginMatrix.target?.recommended_tools.length
              ? pluginMatrix.target.recommended_tools
              : pluginMatrix.recommended_tools,
            available_tools: pluginMatrix.available_tools,
            blocked_tools: pluginMatrix.blocked_tools,
            missing_deps: pluginMatrix.missing_deps,
            next_actions: pluginMatrix.target?.next_actions.length
              ? uniqueStrings([...pluginMatrix.target.next_actions, ...pluginMatrix.next_actions])
              : pluginMatrix.next_actions,
            message:
              `Ranked ${recommendations.length} recommendation(s). ` +
              'Use activation_command from a recommendation to expose hidden tools before execution.',
          },
        }
      }

      case 'list': {
        const filtered = buildFilteredCategories()
        const filteredCoreTools = buildFilteredCoreTools()
        const recommendations = buildRecommendationList(filtered, filteredCoreTools)

        return {
          ok: true,
          data: {
            action: 'list',
            categories: filtered.map((c) => ({
              category: c.category,
              ...(() => {
                const categorySources = matrixSources.filter((source) =>
                  c.plugins.some((plugin) => plugin.id === source.id)
                )
                const categoryMatrix = buildPluginAspectMatrix(categorySources, {
                  targetTags: fileTypeTags,
                })
                return {
                  plugin_matrix: categoryMatrix,
                  format_matrix: categoryMatrix.by_format,
                  recommended_tools: categoryMatrix.target?.recommended_tools.length
                    ? categoryMatrix.target.recommended_tools
                    : categoryMatrix.recommended_tools,
                  available_tools: categoryMatrix.available_tools,
                  blocked_tools: categoryMatrix.blocked_tools,
                  missing_deps: categoryMatrix.missing_deps,
                  next_actions: categoryMatrix.target?.next_actions.length
                    ? uniqueStrings([
                        ...categoryMatrix.target.next_actions,
                        ...categoryMatrix.next_actions,
                      ])
                    : categoryMatrix.next_actions,
                }
              })(),
              plugins: c.plugins.map((p) => buildPluginPortalEntry(c.category, p)),
            })),
            core_tools: filteredCoreTools.map((tool) =>
              buildCoreToolPortalEntry({
                tool,
                definition: toolDefinitionIndex.get(tool.name),
                input,
              })
            ),
            recommendations,
            recommendation_summary: buildRecommendationSummary(recommendations),
            query: input.query,
            sample_id: input.sample_id,
            sample_file_type: resolvedFileType,
            target_file_type_tags: fileTypeTags.length > 0 ? fileTypeTags : undefined,
            plugin_matrix: pluginMatrix,
            format_matrix: pluginMatrix.by_format,
            recommended_tools: pluginMatrix.target?.recommended_tools.length
              ? pluginMatrix.target.recommended_tools
              : pluginMatrix.recommended_tools,
            available_tools: pluginMatrix.available_tools,
            blocked_tools: pluginMatrix.blocked_tools,
            missing_deps: pluginMatrix.missing_deps,
            next_actions: pluginMatrix.target?.next_actions.length
              ? uniqueStrings([...pluginMatrix.target.next_actions, ...pluginMatrix.next_actions])
              : pluginMatrix.next_actions,
            message:
              `Found ${filtered.length} categories with ${filtered.reduce((sum, c) => sum + c.plugins.length, 0)} matching plugins and ${filteredCoreTools.length} matching core tools. ` +
              'Use action=activate with tool_name=<name>, plugin_id=<id>, category=<name>, or file_type=<type> to expose selected tools.',
          },
        }
      }

      case 'activate': {
        const activated: string[] = []
        const activatedCoreTools: string[] = []
        const activatedScopedTools: string[] = []

        if (input.plugin_id) {
          activated.push(...surface.activatePlugins([input.plugin_id]))
        }
        if (input.tool_name) {
          const targetTools = toolNameCandidates(input.tool_name)
          if (targetTools.length > 0) {
            activatedCoreTools.push(...surface.activateCoreTools(targetTools))
            activatedScopedTools.push(...surface.activatePluginTools(targetTools))
          }
        }
        if (input.category) {
          activated.push(...surface.activateByCategory(input.category))
        }
        if (input.finding) {
          activated.push(...surface.activateByFinding(input.finding))
        }
        if (resolvedFileType) {
          activated.push(...surface.activateByFileType(resolvedFileType, { includeTier2: true }))
        }

        const unique = [...new Set(activated)]

        // Collect activated tool names for display
        const activatedTools: string[] = [...activatedCoreTools, ...activatedScopedTools]
        for (const pid of unique) {
          const updatedCategories = surface.listCategories(pluginIndex)
          for (const c of updatedCategories) {
            const p = c.plugins.find((p) => p.id === pid)
            if (p) activatedTools.push(...p.tools)
          }
        }
        const updatedCategories = surface.listCategories(pluginIndex)
        const updatedSurfaceMaps = collectSurfaceMaps(updatedCategories)
        const updatedMatrixSources = buildPluginMatrixSources({
          statuses: pluginManager.getStatuses(),
          plugins: [...pluginMetadataIndex.values()],
          toolNameLookup: buildToolNameLookup([...pluginMetadataIndex.values()]),
          activatedByPlugin: updatedSurfaceMaps.activatedByPlugin,
          toolNamesByPlugin: updatedSurfaceMaps.toolNamesByPlugin,
        })
        const updatedPluginMatrix = buildPluginAspectMatrix(updatedMatrixSources, {
          targetTags: fileTypeTags,
        })
        const activationAudit = {
          at: new Date().toISOString(),
          action: 'activate',
          request: {
            plugin_id: input.plugin_id ?? null,
            tool_name: input.tool_name ?? null,
            category: input.category ?? null,
            finding: input.finding ?? null,
            file_type: resolvedFileType ?? null,
            sample_id: input.sample_id ?? null,
          },
          activated_plugins: unique,
          activated_core_tools: uniqueStrings(activatedCoreTools),
          activated_scoped_tools: uniqueStrings(activatedScopedTools),
          activated_tools: uniqueStrings(activatedTools),
          matched_plugins: updatedPluginMatrix.target?.matched_plugins ?? [],
          matched_tools: updatedPluginMatrix.target?.matched_tools ?? [],
          policy: {
            progressive_surface_enabled: surface.isEnabled(),
            discovery_required_for_hidden_tools: true,
            file_type_activation_includes_tier2: Boolean(resolvedFileType),
            readiness_not_bypassed: true,
            backend_execution_started: false,
            scoped_tool_activation_used: activatedScopedTools.length > 0,
          },
        }

        if (unique.length === 0) {
          const exposedTools = uniqueStrings([...activatedCoreTools, ...activatedScopedTools])
          return {
            ok: true,
            data: {
              action: 'activate',
              activation_audit: activationAudit,
              activated: [],
              activated_tools: exposedTools,
              query: input.query,
              sample_id: input.sample_id,
              sample_file_type: resolvedFileType,
              target_file_type_tags: fileTypeTags.length > 0 ? fileTypeTags : undefined,
              matched_plugins: updatedPluginMatrix.target?.matched_plugins ?? [],
              matched_tools: updatedPluginMatrix.target?.matched_tools ?? [],
              plugin_matrix: updatedPluginMatrix,
              format_matrix: updatedPluginMatrix.by_format,
              recommended_tools: updatedPluginMatrix.target?.recommended_tools.length
                ? updatedPluginMatrix.target.recommended_tools
                : updatedPluginMatrix.recommended_tools,
              available_tools: updatedPluginMatrix.available_tools,
              blocked_tools: updatedPluginMatrix.blocked_tools,
              missing_deps: updatedPluginMatrix.missing_deps,
              next_actions: updatedPluginMatrix.target?.next_actions.length
                ? uniqueStrings([
                    ...updatedPluginMatrix.target.next_actions,
                    ...updatedPluginMatrix.next_actions,
                  ])
                : updatedPluginMatrix.next_actions,
              message:
                exposedTools.length > 0
                  ? `Exposed ${exposedTools.length} scoped tool(s): ${exposedTools.join(', ')}.`
                  : 'No new plugins were activated. They may already be active, or no matching plugins were found. Use action=list to see available categories and plugins.',
            },
          }
        }

        return {
          ok: true,
          data: {
            action: 'activate',
            activation_audit: activationAudit,
            activated: unique,
            activated_tools: activatedTools,
            query: input.query,
            sample_id: input.sample_id,
            sample_file_type: resolvedFileType,
            target_file_type_tags: fileTypeTags.length > 0 ? fileTypeTags : undefined,
            matched_plugins: updatedPluginMatrix.target?.matched_plugins ?? unique,
            matched_tools: updatedPluginMatrix.target?.matched_tools ?? activatedTools,
            plugin_matrix: updatedPluginMatrix,
            format_matrix: updatedPluginMatrix.by_format,
            recommended_tools: updatedPluginMatrix.target?.recommended_tools.length
              ? updatedPluginMatrix.target.recommended_tools
              : updatedPluginMatrix.recommended_tools,
            available_tools: updatedPluginMatrix.available_tools,
            blocked_tools: updatedPluginMatrix.blocked_tools,
            missing_deps: updatedPluginMatrix.missing_deps,
            next_actions: updatedPluginMatrix.target?.next_actions.length
              ? uniqueStrings([
                  ...updatedPluginMatrix.target.next_actions,
                  ...updatedPluginMatrix.next_actions,
                ])
              : updatedPluginMatrix.next_actions,
            message:
              `Activated ${unique.length} plugin(s): ${unique.join(', ')}. ` +
              `${activatedTools.length} new tools are now available.`,
          },
        }
      }

      default:
        return { ok: false, errors: [`Unknown action: ${input.action}`] }
    }
  }
}
