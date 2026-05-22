import { SURFACE_FILE_TYPE_TAGS } from '../plugins/sdk.js'
import type { PluginStatus } from '../plugins/sdk.js'

export type AspectMap = Record<string, string[]>

export type ToolAspectSource = unknown

export interface MatrixToolSource {
  name: string
  definition?: ToolAspectSource | null
}

export interface MatrixPluginSource {
  id: string
  name?: string
  status?: string | null
  activated?: boolean
  aspects?: unknown
  tools?: MatrixToolSource[]
  toolNames?: string[]
  depChecks?: PluginStatus['depChecks']
  qualityWarnings?: PluginStatus['qualityWarnings']
}

export interface AspectMatrixBucket {
  plugins: string[]
  tools: string[]
  available_tools: string[]
  blocked_tools: string[]
}

export interface PluginAspectMatrix {
  summary: {
    plugin_count: number
    tool_count: number
    available_tool_count: number
    blocked_tool_count: number
    format_count: number
    platform_count: number
    execution_count: number
    evidence_count: number
    workflow_recipe_count: number
  }
  by_format: Record<string, AspectMatrixBucket>
  by_platform: Record<string, AspectMatrixBucket>
  by_execution: Record<string, AspectMatrixBucket>
  by_evidence: Record<string, AspectMatrixBucket>
  by_workflow: Record<string, AspectMatrixBucket>
  recommended_tools: string[]
  available_tools: string[]
  blocked_tools: string[]
  missing_deps: string[]
  next_actions: string[]
  target?: {
    tags: string[]
    matched_formats: string[]
    matched_plugins: string[]
    matched_tools: string[]
    recommended_tools: string[]
    next_actions: string[]
  }
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

export function normalizeAspectTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) return []
  return uniqueStrings(
    tags
      .filter((tag): tag is string => typeof tag === 'string')
      .map((tag) => tag.trim().toLowerCase().replace(/_/g, '-'))
      .filter(Boolean)
  )
}

export function normalizeFileTypeTags(rawType: string | null | undefined): string[] {
  if (!rawType) return []
  const lower = rawType.toLowerCase().trim().replace(/_/g, '-')
  if (!lower) return []
  if (SURFACE_FILE_TYPE_TAGS[lower]) return uniqueStrings(SURFACE_FILE_TYPE_TAGS[lower])
  const extension = lower.includes('.') ? lower.slice(lower.lastIndexOf('.') + 1) : lower
  if (extension && SURFACE_FILE_TYPE_TAGS[extension]) {
    return uniqueStrings(SURFACE_FILE_TYPE_TAGS[extension])
  }
  return [lower]
}

export function normalizeAspects(aspects: unknown): AspectMap {
  const normalized: AspectMap = {}
  if (!aspects || typeof aspects !== 'object') return normalized
  for (const [group, tags] of Object.entries(aspects)) {
    const values = normalizeAspectTags(tags)
    if (values.length > 0) normalized[group] = values
  }
  return normalized
}

export function mergeAspects(...sources: unknown[]): AspectMap {
  const merged: AspectMap = {}
  for (const source of sources) {
    const normalized = normalizeAspects(source)
    for (const [group, tags] of Object.entries(normalized)) {
      merged[group] = uniqueStrings([...(merged[group] ?? []), ...tags])
    }
  }
  return merged
}

export function describeAspectCoverage(aspects: unknown): string[] {
  return Object.entries(normalizeAspects(aspects))
    .filter(([, tags]) => tags.length > 0)
    .map(([group, tags]) => `${group}: ${tags.join(', ')}`)
}

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {}
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function workflowRecipeId(value: unknown): string | null {
  const id = objectValue(value).id
  return typeof id === 'string' && id.trim().length > 0 ? id.trim() : null
}

function workflowRecipeIds(definition: ToolAspectSource): string[] {
  return uniqueStrings(
    arrayValue(objectValue(definition).workflowRecipes).flatMap((recipe) => {
      const id = workflowRecipeId(recipe)
      return id ? [id] : []
    })
  )
}

function emptyBucket(): AspectMatrixBucket {
  return {
    plugins: [],
    tools: [],
    available_tools: [],
    blocked_tools: [],
  }
}

function addBucketValue(
  buckets: Record<string, AspectMatrixBucket>,
  tag: string,
  pluginId: string,
  tools: string[],
  availableTools: string[],
  blockedTools: string[]
): void {
  const bucket = buckets[tag] ?? emptyBucket()
  bucket.plugins = uniqueStrings([...bucket.plugins, pluginId])
  bucket.tools = uniqueStrings([...bucket.tools, ...tools])
  bucket.available_tools = uniqueStrings([...bucket.available_tools, ...availableTools])
  bucket.blocked_tools = uniqueStrings([...bucket.blocked_tools, ...blockedTools])
  buckets[tag] = bucket
}

function pluginMissingDeps(plugin: MatrixPluginSource): string[] {
  const deps = plugin.depChecks ?? []
  const missing = deps
    .filter((check) => !check.available)
    .map((check) => check.dep?.name || check.dep?.target || check.error || 'unknown dependency')
  if (plugin.status && !['loaded', 'active'].includes(plugin.status)) {
    missing.push(`plugin status: ${plugin.status}`)
  }
  return uniqueStrings(missing)
}

function toolNamesFor(plugin: MatrixPluginSource): string[] {
  const fromTools = (plugin.tools ?? []).map((tool) => tool.name)
  return uniqueStrings([...(plugin.toolNames ?? []), ...fromTools])
}

function recommendTools(plugin: MatrixPluginSource, tools: string[], aspects: AspectMap): string[] {
  const runtimeGated = normalizeAspectTags(aspects.execution).includes('dynamic')
  const inventoryTools = tools.filter(
    (tool) =>
      tool.endsWith('.inventory') ||
      tool.endsWith('.inspect') ||
      tool.endsWith('.analyze') ||
      tool.endsWith('.scan') ||
      tool.includes('structure')
  )
  const recommended = inventoryTools.length > 0 ? inventoryTools : tools
  if (runtimeGated) return uniqueStrings(['tool.readiness', ...recommended])
  if (plugin.status && !['loaded', 'active'].includes(plugin.status)) return []
  return recommended.slice(0, 12)
}

export function buildToolAspectSummary(
  definition: ToolAspectSource,
  options: {
    pluginAspects?: unknown
    pluginRuntimePolicy?: unknown
  } = {}
): {
  aspects: AspectMap | null
  aspect_coverage: string[]
  format_matrix: Record<
    string,
    {
      platforms: string[]
      execution: string[]
      evidence: string[]
      artifacts: string[]
      workflow_recipes: string[]
    }
  >
  artifact_declarations: unknown[]
  evidence_declarations: unknown[]
  workflow_recipes: unknown[]
  runtime_policy: unknown | null
  runtime_contract: unknown | null
} {
  const source = objectValue(definition)
  const runtime = objectValue(source.runtime)
  const artifactsDeclared = arrayValue(source.artifacts)
  const evidenceDeclared = arrayValue(source.evidence)
  const workflowRecipes = arrayValue(source.workflowRecipes)
  const workflowRecipeIds = uniqueStrings(
    workflowRecipes.flatMap((recipe) => {
      const id = workflowRecipeId(recipe)
      return id ? [id] : []
    })
  )
  const aspects = mergeAspects(options.pluginAspects, source.aspects)
  const formats = aspects.formats ?? []
  const platforms = aspects.platforms ?? []
  const execution = aspects.execution ?? []
  const evidence = aspects.evidence ?? []
  const artifacts = artifactsDeclared
    .map((artifact) => objectValue(artifact).type)
    .filter((type): type is string => typeof type === 'string')
  const formatMatrix: Record<
    string,
    {
      platforms: string[]
      execution: string[]
      evidence: string[]
      artifacts: string[]
      workflow_recipes: string[]
    }
  > = {}

  for (const format of formats) {
    formatMatrix[format] = {
      platforms,
      execution,
      evidence,
      artifacts,
      workflow_recipes: workflowRecipeIds,
    }
  }

  return {
    aspects: Object.keys(aspects).length > 0 ? aspects : null,
    aspect_coverage: describeAspectCoverage(aspects),
    format_matrix: formatMatrix,
    artifact_declarations: artifactsDeclared,
    evidence_declarations: evidenceDeclared,
    workflow_recipes: workflowRecipes,
    runtime_policy: source.runtimePolicy ?? runtime.policy ?? options.pluginRuntimePolicy ?? null,
    runtime_contract: source.runtime ?? null,
  }
}

function summarizeMatrixTarget(
  byFormat: Record<string, AspectMatrixBucket>,
  targetTags: string[]
): PluginAspectMatrix['target'] | undefined {
  const tags = normalizeAspectTags(targetTags)
  if (tags.length === 0) return undefined

  const matchedFormats = Object.keys(byFormat).filter((format) => tags.includes(format))
  const matchedPlugins: string[] = []
  const matchedTools: string[] = []
  const recommendedTools: string[] = []
  const nextActions: string[] = []

  for (const format of matchedFormats) {
    const bucket = byFormat[format]
    matchedPlugins.push(...bucket.plugins)
    matchedTools.push(...bucket.tools)
    recommendedTools.push(...bucket.available_tools)
    if (bucket.blocked_tools.length > 0) {
      nextActions.push(`Resolve readiness for ${format} blocked tools before using them.`)
    }
  }

  if (matchedTools.length === 0) {
    nextActions.push(
      `No plugin matrix entry matched file type tags: ${tags.join(', ')}. Use tools.discover action=list to browse plugins.`
    )
  } else {
    nextActions.push(
      `Use tools.discover action=activate file_type=${tags[0]} to expose matching format tools when they are not visible.`
    )
  }

  return {
    tags,
    matched_formats: uniqueStrings(matchedFormats),
    matched_plugins: uniqueStrings(matchedPlugins),
    matched_tools: uniqueStrings(matchedTools),
    recommended_tools: uniqueStrings(recommendedTools).slice(0, 25),
    next_actions: uniqueStrings(nextActions),
  }
}

export function buildPluginAspectMatrix(
  plugins: MatrixPluginSource[],
  options: { targetTags?: string[] } = {}
): PluginAspectMatrix {
  const byFormat: Record<string, AspectMatrixBucket> = {}
  const byPlatform: Record<string, AspectMatrixBucket> = {}
  const byExecution: Record<string, AspectMatrixBucket> = {}
  const byEvidence: Record<string, AspectMatrixBucket> = {}
  const byWorkflow: Record<string, AspectMatrixBucket> = {}
  const recommendedTools: string[] = []
  const availableTools: string[] = []
  const blockedTools: string[] = []
  const missingDeps: string[] = []
  const nextActions: string[] = []
  const workflowRecipes: string[] = []
  let toolCount = 0

  for (const plugin of plugins) {
    const toolNames = toolNamesFor(plugin)
    toolCount += toolNames.length
    const toolAspects = (plugin.tools ?? []).map((tool) => objectValue(tool.definition).aspects)
    const toolWorkflowRecipes = uniqueStrings(
      (plugin.tools ?? []).flatMap((tool) => workflowRecipeIds(tool.definition))
    )
    const aspects = mergeAspects(plugin.aspects, ...toolAspects)
    const missing = pluginMissingDeps(plugin)
    const isBlocked = missing.length > 0 || Boolean(plugin.status && plugin.status !== 'loaded')
    const pluginAvailableTools = isBlocked ? [] : toolNames
    const pluginBlockedTools = isBlocked ? toolNames : []

    availableTools.push(...pluginAvailableTools)
    blockedTools.push(...pluginBlockedTools)
    missingDeps.push(...missing.map((dep) => `${plugin.id}: ${dep}`))
    recommendedTools.push(...recommendTools(plugin, toolNames, aspects))
    workflowRecipes.push(...toolWorkflowRecipes)

    for (const format of aspects.formats ?? []) {
      addBucketValue(
        byFormat,
        format,
        plugin.id,
        toolNames,
        pluginAvailableTools,
        pluginBlockedTools
      )
    }
    for (const platform of aspects.platforms ?? []) {
      addBucketValue(
        byPlatform,
        platform,
        plugin.id,
        toolNames,
        pluginAvailableTools,
        pluginBlockedTools
      )
    }
    for (const execution of aspects.execution ?? []) {
      addBucketValue(
        byExecution,
        execution,
        plugin.id,
        toolNames,
        pluginAvailableTools,
        pluginBlockedTools
      )
    }
    for (const evidence of aspects.evidence ?? []) {
      addBucketValue(
        byEvidence,
        evidence,
        plugin.id,
        toolNames,
        pluginAvailableTools,
        pluginBlockedTools
      )
    }
    for (const recipe of toolWorkflowRecipes) {
      addBucketValue(
        byWorkflow,
        recipe,
        plugin.id,
        toolNames,
        pluginAvailableTools,
        pluginBlockedTools
      )
    }

    if (isBlocked) {
      nextActions.push(`Resolve ${plugin.id} plugin readiness before using its tools.`)
    } else if (toolNames.length > 0 && plugin.activated === false) {
      nextActions.push(
        `Use tools.discover action=activate plugin_id=${plugin.id} to expose ${plugin.id} tools.`
      )
    }
  }

  const matrix: PluginAspectMatrix = {
    summary: {
      plugin_count: plugins.length,
      tool_count: toolCount,
      available_tool_count: uniqueStrings(availableTools).length,
      blocked_tool_count: uniqueStrings(blockedTools).length,
      format_count: Object.keys(byFormat).length,
      platform_count: Object.keys(byPlatform).length,
      execution_count: Object.keys(byExecution).length,
      evidence_count: Object.keys(byEvidence).length,
      workflow_recipe_count: uniqueStrings(workflowRecipes).length,
    },
    by_format: byFormat,
    by_platform: byPlatform,
    by_execution: byExecution,
    by_evidence: byEvidence,
    by_workflow: byWorkflow,
    recommended_tools: uniqueStrings(recommendedTools).slice(0, 50),
    available_tools: uniqueStrings(availableTools),
    blocked_tools: uniqueStrings(blockedTools),
    missing_deps: uniqueStrings(missingDeps),
    next_actions: uniqueStrings(nextActions).slice(0, 50),
  }
  const target = summarizeMatrixTarget(byFormat, options.targetTags ?? [])
  if (target) matrix.target = target
  return matrix
}

export function buildPluginMatrixSources(params: {
  statuses?: PluginStatus[]
  plugins?: Array<{
    id: string
    name?: string
    aspects?: unknown
    tools?: Array<{ definition: ToolAspectSource }>
    runtimePolicy?: unknown
  }>
  toolNameLookup?: Map<string, ToolAspectSource>
  activatedByPlugin?: Map<string, boolean>
  toolNamesByPlugin?: Map<string, string[]>
}): MatrixPluginSource[] {
  const pluginById = new Map((params.plugins ?? []).map((plugin) => [plugin.id, plugin]))
  const statusById = new Map((params.statuses ?? []).map((status) => [status.id, status]))
  const ids = uniqueStrings([...pluginById.keys(), ...statusById.keys()])

  return ids.map((id) => {
    const plugin = pluginById.get(id)
    const status = statusById.get(id)
    const statusToolNames = status?.tools ?? []
    const pluginToolNames =
      plugin?.tools
        ?.map((tool) => objectValue(tool.definition).name)
        .filter((name): name is string => typeof name === 'string') ?? []
    const surfaceToolNames = params.toolNamesByPlugin?.get(id) ?? []
    const toolNames = uniqueStrings([...statusToolNames, ...pluginToolNames, ...surfaceToolNames])
    const tools = uniqueStrings(toolNames).map((name) => ({
      name,
      definition:
        plugin?.tools?.find((tool) => objectValue(tool.definition).name === name)?.definition ??
        params.toolNameLookup?.get(name) ??
        null,
    }))
    return {
      id,
      name: plugin?.name ?? status?.name,
      status: status?.status ?? (statusById.size > 0 ? 'unknown' : 'loaded'),
      activated: params.activatedByPlugin?.get(id),
      aspects: plugin?.aspects ?? null,
      tools,
      toolNames: uniqueStrings(toolNames),
      depChecks: status?.depChecks,
      qualityWarnings: status?.qualityWarnings,
    }
  })
}
