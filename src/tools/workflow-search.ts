import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { PluginManager } from '../plugins.js'
import { createToolsDiscoverHandler } from './tools-discover.js'
import { normalizeFileTypeTags } from './tool-aspect-matrix.js'

const WorkflowSearchActionSchema = z.enum(['status', 'search', 'recommend', 'list', 'activate'])

export const workflowSearchInputSchema = z.object({
  action: WorkflowSearchActionSchema.default('search').describe(
    'Search gateway action. search/recommend return passive ranked topK candidates; list returns matching categories/tools; status returns surface status; activate explicitly exposes the selected hidden tools without starting backends.'
  ),
  query: z.string().optional().describe('Natural-language user request or capability query.'),
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample ID used for file-type/profile routing.'),
  file_type: z
    .string()
    .optional()
    .describe('Optional file type or extension hint, such as pe, .exe, elf, apk, wasm.'),
  goal: z
    .enum(['triage', 'static', 'reverse', 'dynamic', 'report'])
    .optional()
    .describe('Analyst goal used to enrich passive routing search.'),
  depth: z
    .enum(['safe', 'balanced', 'deep'])
    .optional()
    .describe('Requested analysis depth used to enrich passive routing search.'),
  category: z.string().optional().describe('Optional capability category filter.'),
  plugin_id: z.string().optional().describe('Optional plugin ID filter.'),
  tool_name: z.string().optional().describe('Optional canonical or transport tool name filter.'),
  finding: z
    .string()
    .optional()
    .describe('Optional finding/signal hint, such as packed, crypto, shellcode, c2.'),
  top_k: z
    .number()
    .int()
    .min(1)
    .max(25)
    .default(5)
    .describe('Maximum ranked recommendations to return for search/recommend.'),
})

export const workflowSearchOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      result_mode: z.literal('workflow_search'),
      action: WorkflowSearchActionSchema,
      query: z.string().optional(),
      sample_id: z.string().optional(),
      goal: z.string().optional(),
      depth: z.string().optional(),
      top_k: z.number().int().positive(),
      search_profile: z.record(z.any()),
      results: z.array(z.record(z.any())).optional(),
      recommendations: z.array(z.any()).optional(),
      recommendation_summary: z.any().optional(),
      raw_discovery: z.any().optional(),
      activation_audit: z.any().optional(),
      activated: z.array(z.string()).optional(),
      activated_tools: z.array(z.string()).optional(),
      message: z.string(),
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

const TOOL_NAME = 'workflow.search'
type WorkflowSearchInput = z.infer<typeof workflowSearchInputSchema>

type ScoreBreakdown = {
  discovery_score: number
  profile_score: number
  query_score: number
  goal_score: number
  depth_score: number
  finding_score: number
  workflow_score: number
  readiness_score: number
  total_score: number
}

type RankedRecommendation = {
  item: Record<string, unknown>
  original_index: number
  total_score: number
  score_breakdown: ScoreBreakdown
  matched_profile_fields: string[]
}

const GOAL_PROFILE_TERMS: Record<string, string[]> = {
  triage: ['triage', 'profile', 'inventory', 'identify', 'structure', 'metadata'],
  static: ['static', 'structure', 'imports', 'strings', 'symbols', 'disassembly', 'yara'],
  reverse: [
    'reverse',
    'reverse-engineering',
    'decompile',
    'disassembly',
    'cfg',
    'function',
    'bytecode',
    'handler',
    'structure',
  ],
  dynamic: ['dynamic', 'sandbox', 'runtime', 'trace', 'behavior', 'memory', 'network'],
  report: ['report', 'summary', 'summarize', 'artifact', 'evidence', 'export'],
}

const DEPTH_PROFILE_TERMS: Record<string, string[]> = {
  safe: ['safe', 'passive', 'static', 'triage', 'inventory'],
  balanced: ['balanced', 'staged', 'workflow', 'static', 'worker'],
  deep: ['deep', 'decompile', 'symbolic', 'dynamic', 'unpack', 'expert'],
}

const FINDING_PROFILE_TERMS: Record<string, string[]> = {
  packed: ['packed', 'packer', 'unpack', 'unpacking', 'entropy', 'overlay'],
  crypto: ['crypto', 'cryptography', 'hash', 'key', 'algorithm'],
  shellcode: ['shellcode', 'payload', 'disassembly', 'memory'],
  c2: ['c2', 'network', 'beacon', 'domain', 'url'],
  dotnet: ['dotnet', 'clr', 'managed', 'reactor'],
  go: ['go', 'golang'],
  obfuscated: ['obfuscated', 'obfuscation', 'deobfuscation', 'jsvmp', 'javascript'],
}

const ACTIVATION_REQUIRED_STATES = new Set([
  'hidden_activation_required',
  'backend_readiness_required',
  'runtime_opt_in_required',
  'byo_backend_required',
  'sidecar_backend_required',
  'license_profile_required',
  'runtime_or_gpu_profile_required',
  'backend_profile_required',
])

export const workflowSearchToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passive profile-based search gateway for Rikune workflows and specialist tools. ' +
    'Use this as the default entrypoint when deciding what capability to use for a sample or user request. ' +
    'It ranks hidden and visible workflows/tools using sample profile hints, file type, query terms, plugin metadata, workflow recipes, readiness state, and activation requirements. ' +
    'search/recommend/list/status are passive. action=activate is explicit and only exposes selected tools through the progressive surface; it does not start backends or execute analysis.',
  inputSchema: workflowSearchInputSchema,
  outputSchema: workflowSearchOutputSchema,
}

function buildDiscoverQuery(input: WorkflowSearchInput): string | undefined {
  const terms = [input.query, input.goal, input.depth].filter(
    (value): value is string => typeof value === 'string' && value.trim().length > 0
  )
  return terms.length > 0 ? terms.join(' ') : undefined
}

function toDiscoverAction(action: z.infer<typeof WorkflowSearchActionSchema>) {
  return action === 'status' || action === 'list' || action === 'activate' ? action : 'recommend'
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {}
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : []
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value : undefined
}

function normalizeProfileTag(value: string): string {
  return value.toLowerCase().trim().replace(/^\./, '').replace(/_/g, '-')
}

function termsFromText(value: string | undefined): string[] {
  if (!value) return []
  return uniqueStrings(
    value
      .toLowerCase()
      .replace(/[_./\\:]+/g, ' ')
      .split(/[^a-z0-9+#-]+/)
      .flatMap((term) => term.split('-'))
      .map((term) => term.trim())
      .filter((term) => term.length > 1)
  )
}

function normalizeSearchText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[_./\\:]+/g, ' ')
    .replace(/[^a-z0-9+#-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function collectSearchText(values: unknown[]): string {
  const parts: string[] = []
  const seen = new Set<unknown>()

  function visit(value: unknown, depth = 0): void {
    if (value == null || depth > 6 || seen.has(value)) return
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
  return normalizeSearchText(parts.join(' '))
}

function recommendationSearchText(item: Record<string, unknown>): string {
  return collectSearchText([
    item.kind,
    item.category,
    item.plugin_id,
    item.id,
    item.name,
    item.description,
    item.tool_name,
    item.aspects,
    item.aspect_coverage,
    item.format_matrix,
    item.artifact_declarations,
    item.evidence_declarations,
    item.workflow_recipes,
    item.recommended_tools,
    item.available_tools,
    item.preferred_primary_tools,
    item.tool_surface_role,
    item.match_reasons,
  ])
}

function targetRecord(discoveryData: Record<string, unknown>): Record<string, unknown> {
  return asRecord(asRecord(discoveryData.plugin_matrix).target)
}

function profileTagsFor(input: WorkflowSearchInput, discoveryData: Record<string, unknown>) {
  const sampleFileType = stringValue(discoveryData.sample_file_type)
  return uniqueStrings(
    [
      ...normalizeFileTypeTags(input.file_type ?? sampleFileType),
      ...stringArray(discoveryData.target_file_type_tags),
      ...stringArray(targetRecord(discoveryData).tags),
    ].map(normalizeProfileTag)
  )
}

function profileTermSetForItem(item: Record<string, unknown>): Set<string> {
  const aspects = asRecord(item.aspects)
  const tags = [
    ...Object.keys(asRecord(item.format_matrix)),
    ...stringArray(aspects.formats),
    ...stringArray(aspects.platforms),
    ...stringArray(aspects.architectures),
    ...stringArray(aspects.capabilities),
    ...stringArray(aspects.evidence),
  ]
  return new Set(tags.map(normalizeProfileTag))
}

function scoreTerms(terms: string[], searchText: string): { score: number; matched: string[] } {
  if (terms.length === 0) return { score: 0, matched: [] }
  const textTerms = new Set(termsFromText(searchText))
  const matched = uniqueStrings(
    terms.filter((term) => textTerms.has(term) || searchText.includes(term))
  )
  const allTermsMatched = matched.length === terms.length
  return {
    score: matched.length * 10 + (allTermsMatched && terms.length > 1 ? 8 : 0),
    matched,
  }
}

function termsForGoal(goal: WorkflowSearchInput['goal']): string[] {
  return goal ? uniqueStrings([goal, ...(GOAL_PROFILE_TERMS[goal] ?? [])]) : []
}

function termsForDepth(depth: WorkflowSearchInput['depth']): string[] {
  return depth ? uniqueStrings([depth, ...(DEPTH_PROFILE_TERMS[depth] ?? [])]) : []
}

function termsForFinding(finding: string | undefined): string[] {
  const findingTerms = termsFromText(finding)
  const aliases = findingTerms.flatMap((term) => FINDING_PROFILE_TERMS[term] ?? [])
  return uniqueStrings([...findingTerms, ...aliases])
}

function readinessScore(readinessState: string): number {
  if (readinessState === 'ready') return 8
  if (readinessState === 'blocked') return -60
  if (readinessState === 'readiness_warning') return -8
  if (readinessState === 'hidden_activation_required') return 0
  if (
    [
      'backend_readiness_required',
      'runtime_opt_in_required',
      'backend_profile_required',
    ].includes(readinessState)
  ) {
    return -10
  }
  if (
    [
      'byo_backend_required',
      'sidecar_backend_required',
      'license_profile_required',
      'runtime_or_gpu_profile_required',
    ].includes(readinessState)
  ) {
    return -16
  }
  return 0
}

function rankRecommendation(params: {
  item: Record<string, unknown>
  input: WorkflowSearchInput
  discoveryData: Record<string, unknown>
  originalIndex: number
}): RankedRecommendation {
  const { item, input, discoveryData, originalIndex } = params
  const discoveryScore = typeof item.score === 'number' ? item.score : 0
  const searchText = recommendationSearchText(item)
  const matchedProfileFields: string[] = []
  const itemProfileTerms = profileTermSetForItem(item)
  const profileTags = profileTagsFor(input, discoveryData)
  const matchedProfileTags = profileTags.filter((tag) => itemProfileTerms.has(tag))
  let profileScore = 0

  if (matchedProfileTags.length > 0) {
    profileScore += 55 + matchedProfileTags.length * 8
    matchedProfileFields.push(`file_type/profile tags: ${matchedProfileTags.join(', ')}`)
  }

  const pluginId = stringValue(item.plugin_id) ?? stringValue(item.id)
  const toolName = stringValue(item.tool_name) ?? stringValue(item.name)
  const target = targetRecord(discoveryData)
  if (pluginId && stringArray(target.matched_plugins).includes(pluginId)) {
    profileScore += 25
    matchedProfileFields.push(`plugin_matrix target plugin: ${pluginId}`)
  }
  if (toolName && stringArray(target.matched_tools).includes(toolName)) {
    profileScore += 20
    matchedProfileFields.push(`plugin_matrix target tool: ${toolName}`)
  }

  const queryTerms = uniqueStrings([
    ...termsFromText(input.query),
    ...termsFromText(input.tool_name),
    ...termsFromText(input.plugin_id),
    ...termsFromText(input.category),
  ])
  const queryMatch = scoreTerms(queryTerms, searchText)
  let queryScore = queryMatch.score
  const normalizedQuery = input.query ? normalizeSearchText(input.query) : ''
  if (normalizedQuery && searchText.includes(normalizedQuery)) queryScore += 12
  if (queryMatch.matched.length > 0) {
    matchedProfileFields.push(`query terms: ${queryMatch.matched.join(', ')}`)
  }

  const goalMatch = scoreTerms(termsForGoal(input.goal), searchText)
  const goalScore = goalMatch.score
  if (input.goal && goalMatch.matched.length > 0) {
    matchedProfileFields.push(`goal=${input.goal}: ${goalMatch.matched.join(', ')}`)
  }

  const depthMatch = scoreTerms(termsForDepth(input.depth), searchText)
  const depthScore = depthMatch.score
  if (input.depth && depthMatch.matched.length > 0) {
    matchedProfileFields.push(`depth=${input.depth}: ${depthMatch.matched.join(', ')}`)
  }

  const findingMatch = scoreTerms(termsForFinding(input.finding), searchText)
  const findingScore = findingMatch.score
  if (input.finding && findingMatch.matched.length > 0) {
    matchedProfileFields.push(`finding=${input.finding}: ${findingMatch.matched.join(', ')}`)
  }

  const workflowRecipes = Array.isArray(item.workflow_recipes)
    ? (item.workflow_recipes as unknown[])
    : []
  const recommendedTools = stringArray(item.recommended_tools)
  const availableTools = stringArray(item.available_tools)
  let workflowScore = 0
  if (workflowRecipes.length > 0) workflowScore += 10
  if (recommendedTools.length > 0) workflowScore += 8
  if (availableTools.length > 0) workflowScore += 4
  if (workflowRecipes.length > 0 || recommendedTools.length > 0) {
    matchedProfileFields.push(
      `workflow/tools: ${[
        workflowRecipes.length > 0 ? `${workflowRecipes.length} recipe(s)` : '',
        recommendedTools.length > 0 ? `${recommendedTools.length} recommended tool(s)` : '',
      ]
        .filter(Boolean)
        .join(', ')}`
    )
  }

  const readinessState = stringValue(item.readiness_state) ?? 'unknown'
  const readiness = readinessScore(readinessState)
  const totalScore =
    discoveryScore +
    profileScore +
    queryScore +
    goalScore +
    depthScore +
    findingScore +
    workflowScore +
    readiness

  return {
    item,
    original_index: originalIndex,
    total_score: totalScore,
    score_breakdown: {
      discovery_score: discoveryScore,
      profile_score: profileScore,
      query_score: queryScore,
      goal_score: goalScore,
      depth_score: depthScore,
      finding_score: findingScore,
      workflow_score: workflowScore,
      readiness_score: readiness,
      total_score: totalScore,
    },
    matched_profile_fields: uniqueStrings(matchedProfileFields).slice(0, 10),
  }
}

function buildSearchProfile(input: WorkflowSearchInput, discoveryData: Record<string, unknown>) {
  const pluginMatrix = asRecord(discoveryData.plugin_matrix)
  const queryTerms = termsFromText(input.query)
  const findingTerms = termsForFinding(input.finding)
  return {
    sample_file_type: discoveryData.sample_file_type ?? null,
    requested_file_type: input.file_type ?? null,
    file_type_tags: profileTagsFor(input, discoveryData),
    query_terms: queryTerms,
    goal_terms: termsForGoal(input.goal),
    depth_terms: termsForDepth(input.depth),
    finding_terms: findingTerms,
    formats: Object.keys(asRecord(discoveryData.format_matrix)),
    recommended_tools: stringArray(discoveryData.recommended_tools),
    available_tools: stringArray(discoveryData.available_tools),
    blocked_tools: stringArray(discoveryData.blocked_tools),
    missing_deps: stringArray(discoveryData.missing_deps),
    next_actions: stringArray(discoveryData.next_actions),
    matched_plugins: stringArray(discoveryData.matched_plugins),
    matched_tools: stringArray(discoveryData.matched_tools),
    plugin_matrix_summary: {
      formats: Object.keys(asRecord(discoveryData.format_matrix)),
      recommended_tools: stringArray(discoveryData.recommended_tools).slice(0, 12),
      available_tool_count: stringArray(discoveryData.available_tools).length,
      blocked_tool_count: stringArray(discoveryData.blocked_tools).length,
      missing_dep_count: stringArray(discoveryData.missing_deps).length,
      workflow_count: Object.keys(asRecord(pluginMatrix.by_workflow)).length,
    },
  }
}

function normalizeRecommendation(ranked: RankedRecommendation, index: number) {
  const item = ranked.item
  const workflowRecipes = Array.isArray(item.workflow_recipes)
    ? (item.workflow_recipes as Array<Record<string, unknown>>)
    : []
  const readinessState = typeof item.readiness_state === 'string' ? item.readiness_state : 'unknown'
  return {
    rank: index + 1,
    score: ranked.total_score,
    kind: item.kind === 'core_tool' ? 'tool' : item.kind,
    tool_name: item.tool_name ?? item.name,
    plugin_id: item.plugin_id ?? item.id,
    workflow_id: workflowRecipes.length > 0 ? workflowRecipes[0]?.id : undefined,
    title: item.name ?? item.tool_name ?? item.plugin_id ?? item.id,
    description: item.description,
    readiness_state: readinessState,
    tool_surface_role: item.tool_surface_role,
    preferred_primary_tools: stringArray(item.preferred_primary_tools),
    activation_required: ACTIVATION_REQUIRED_STATES.has(readinessState),
    activation_command: normalizeActivationCommand(item.activation_command),
    closes_gaps: [],
    matched_profile_fields: uniqueStrings([
      ...ranked.matched_profile_fields,
      ...stringArray(item.match_reasons).filter((reason) =>
        /file type|query|workflow|recommended/i.test(reason)
      ),
    ]).slice(0, 10),
    match_reasons: stringArray(item.match_reasons).slice(0, 10),
    recommended_tools: stringArray(item.recommended_tools).slice(0, 8),
    available_tools: stringArray(item.available_tools).slice(0, 8),
    blocked_tools: stringArray(item.blocked_tools).slice(0, 8),
    score_breakdown: ranked.score_breakdown,
    next_actions: normalizeActivationActions(item.next_actions),
  }
}

function normalizeActivationCommand(value: unknown): Record<string, unknown> | undefined {
  const command = asRecord(value)
  if (Object.keys(command).length === 0) return undefined
  return {
    ...command,
    action: 'activate',
    tool: TOOL_NAME,
    via: 'workflow.search',
  }
}

function normalizeActivationActions(actions: unknown): string[] {
  return stringArray(actions)
    .map((action) =>
      action
        .replaceAll('tools.discover action=activate', 'workflow.search action=activate')
        .replaceAll('tools.discover action=list', 'workflow.search action=list')
        .replaceAll('tools.discover action=recommend', 'workflow.search action=search')
        .replaceAll('tools.discover', 'workflow.search')
    )
    .slice(0, 8)
}

export function createWorkflowSearchHandler(
  pluginManager: PluginManager,
  options: {
    database?: { findSample?: (sampleId: string) => { file_type?: string | null } | null }
    toolDefinitions?: () => ToolDefinition[]
  } = {}
) {
  const discover = createToolsDiscoverHandler(pluginManager, options)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = workflowSearchInputSchema.parse(args)
      const discovery = await discover({
        action: toDiscoverAction(input.action),
        query: buildDiscoverQuery(input),
        sample_id: input.sample_id,
        file_type: input.file_type,
        category: input.category,
        plugin_id: input.plugin_id,
        tool_name: input.tool_name,
        finding: input.finding,
      })

      if (!discovery.ok) {
        return {
          ok: false,
          errors: discovery.errors ?? ['workflow.search failed to build recommendations'],
          warnings: discovery.warnings,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const discoveryData = asRecord(discovery.data)
      if (input.action === 'activate') {
        return {
          ok: true,
          data: {
            result_mode: 'workflow_search',
            action: input.action,
            query: input.query,
            sample_id: input.sample_id,
            goal: input.goal,
            depth: input.depth,
            top_k: input.top_k,
            search_profile: buildSearchProfile(input, discoveryData),
            activation_audit: discoveryData.activation_audit,
            activated: stringArray(discoveryData.activated),
            activated_tools: stringArray(discoveryData.activated_tools),
            raw_discovery: {
              action: discoveryData.action,
              sample_file_type: discoveryData.sample_file_type,
              target_file_type_tags: discoveryData.target_file_type_tags,
              matched_plugins: discoveryData.matched_plugins,
              matched_tools: discoveryData.matched_tools,
            },
            message: String(
              discoveryData.message ??
                'workflow.search action=activate completed without starting backends.'
            ).replaceAll('Use action=list', 'Use workflow.search action=list'),
          },
          warnings: discovery.warnings,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const recommendations = Array.isArray(discoveryData.recommendations)
        ? (discoveryData.recommendations as Record<string, unknown>[])
        : []
      const results = recommendations
        .map((item, index) =>
          rankRecommendation({
            item,
            input,
            discoveryData,
            originalIndex: index,
          })
        )
        .sort((a, b) => b.total_score - a.total_score || a.original_index - b.original_index)
        .slice(0, input.top_k)
        .map((item, index) => normalizeRecommendation(item, index))

      return {
        ok: true,
        data: {
          result_mode: 'workflow_search',
          action: input.action,
          query: input.query,
          sample_id: input.sample_id,
          goal: input.goal,
          depth: input.depth,
          top_k: input.top_k,
          search_profile: buildSearchProfile(input, discoveryData),
          results: input.action === 'status' ? undefined : results,
          recommendations: input.action === 'status' ? undefined : results,
          recommendation_summary: discoveryData.recommendation_summary,
          raw_discovery: input.action === 'status' ? discoveryData : undefined,
          message:
            input.action === 'status'
              ? String(discoveryData.message ?? 'Workflow search status returned.')
              : `Ranked ${results.length} passive workflow/search recommendation(s). No tools were activated or executed.`,
        },
        warnings: discovery.warnings,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
