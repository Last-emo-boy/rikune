import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import type { PluginManager } from '../plugins.js'
import {
  createToolsDiscoverHandler,
  listLiveSurfaceToolNames,
  resolveLiveSurfaceToolNames,
} from './tools-discover.js'
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
  result_id: z
    .string()
    .optional()
    .describe(
      'Stable result ID returned by a prior workflow.search result. With action=activate, exposes only that result scoped tool set instead of activating a whole plugin/category/file profile.'
    ),
  finding: z
    .string()
    .optional()
    .describe('Optional finding/signal hint, such as packed, crypto, shellcode, c2.'),
  top_k: z
    .union([z.number().int().min(1).max(25), z.literal('auto')])
    .default('auto')
    .describe(
      'Maximum ranked recommendations to return for search/recommend. Use auto to let workflow.search adapt the result window to the file profile and analyst intent.'
    ),
  verbose: z
    .boolean()
    .default(false)
    .describe(
      'When false (default) the response is compact: the large echoed format arrays (search_profile.formats, plugin_matrix_summary.formats, and per-lane formats) are dropped in favor of format_count, while ranked results and tool lists stay intact. Set true to return the full uncompacted payload.'
    ),
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
      search_profiles: z.array(z.record(z.any())).optional(),
      quota_decisions: z.array(z.record(z.any())).optional(),
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
type SearchProfileLane = Record<string, unknown>

type LaneQuotaDecision = {
  lane: string
  lane_id: string
  priority: number
  quota: number
  candidate_result_ids: string[]
  selected_result_ids: string[]
  overflow_result_ids: string[]
  promoted: boolean
  reason: string
}

type LaneQuotaSelection = {
  selected: RankedRecommendation[]
  quota_decisions: LaneQuotaDecision[]
  selection_metadata: Map<string, { matched_lanes: string[]; selected_via_lane: string }>
}

type ResolvedTopK = {
  value: number
  mode: 'manual' | 'adaptive'
  reason: string
}

type ScoreBreakdown = {
  discovery_score: number
  profile_score: number
  sample_score: number
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

type WorkflowSearchDatabase = {
  findSample?: (sampleId: string) => { file_type?: string | null; sha256?: string | null } | null
  findArtifacts?: (sampleId: string) => Array<{
    id?: string
    type?: string
    path?: string
    mime?: string | null
    created_at?: string
  }>
  findAnalysisRunsBySample?: (sampleId: string) => Array<{
    id?: string
    status?: string
    goal?: string
    depth?: string
    latest_stage?: string | null
    artifact_refs_json?: string | null
    updated_at?: string
  }>
  findAnalysisRunStages?: (runId: string) => Array<{
    stage?: string
    status?: string
    tool?: string | null
    artifact_refs_json?: string | null
    coverage_json?: string | null
  }>
  findAnalysisEvidenceBySample?: (
    sampleId: string,
    family?: string,
    limit?: number
  ) => Array<{
    evidence_family?: string
    backend?: string
    mode?: string
    artifact_refs_json?: string | null
  }>
}

type SampleRouteFacts = {
  sample_id: string
  artifact_types: string[]
  artifact_paths: string[]
  evidence_families: string[]
  evidence_backends: string[]
  latest_stage?: string
  completed_stages: string[]
  coverage_gap_domains: string[]
  known_findings: string[]
  suspected_findings: string[]
  unverified_areas: string[]
  upgrade_tools: string[]
  recommended_tools: string[]
  route_terms: string[]
  fact_sources: string[]
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
  if (exactToolNameFromQuery(input.query)) return undefined
  const terms = [input.query, input.goal, input.depth].filter(
    (value): value is string => typeof value === 'string' && value.trim().length > 0
  )
  return terms.length > 0 ? terms.join(' ') : undefined
}

function exactToolNameFromQuery(value: string | undefined): string | undefined {
  const match = value?.trim().match(/^tool:([A-Za-z0-9_.-]+)$/i)
  return match?.[1]
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

function numberValue(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function asRecordArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Record<string, unknown> =>
          item !== null && typeof item === 'object' && !Array.isArray(item)
      )
    : []
}

function parseJsonRecord(value: string | null | undefined): Record<string, unknown> {
  if (!value || value.trim().length === 0) return {}
  try {
    return asRecord(JSON.parse(value))
  } catch {
    return {}
  }
}

function parseJsonArray(value: string | null | undefined): Record<string, unknown>[] {
  if (!value || value.trim().length === 0) return []
  try {
    return asRecordArray(JSON.parse(value))
  } catch {
    return []
  }
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

function termsFromValues(values: Array<string | undefined>): string[] {
  return uniqueStrings(values.flatMap((value) => termsFromText(value)))
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

function collectArtifactFacts(
  facts: {
    artifactTypes: string[]
    artifactPaths: string[]
    routeTerms: string[]
    factSources: string[]
  },
  artifact: Record<string, unknown>,
  source: string
): void {
  const type = stringValue(artifact.type)
  const artifactPath = stringValue(artifact.path)
  if (type) facts.artifactTypes.push(normalizeProfileTag(type))
  if (artifactPath) facts.artifactPaths.push(artifactPath)
  facts.routeTerms.push(...termsFromValues([type, artifactPath]))
  if (type || artifactPath) facts.factSources.push(source)
}

function collectCoverageFacts(
  facts: {
    coverageGapDomains: string[]
    knownFindings: string[]
    suspectedFindings: string[]
    unverifiedAreas: string[]
    upgradeTools: string[]
    recommendedTools: string[]
    routeTerms: string[]
    factSources: string[]
  },
  coverage: Record<string, unknown>,
  source: string
): void {
  const gaps = asRecordArray(coverage.coverage_gaps)
  for (const gap of gaps) {
    const domain = stringValue(gap.domain)
    const reason = stringValue(gap.reason)
    if (domain) facts.coverageGapDomains.push(normalizeProfileTag(domain))
    facts.routeTerms.push(...termsFromValues([domain, reason, stringValue(gap.status)]))
  }

  const upgradePaths = asRecordArray(coverage.upgrade_paths)
  for (const path of upgradePaths) {
    const tool = stringValue(path.tool)
    const purpose = stringValue(path.purpose)
    if (tool) {
      facts.upgradeTools.push(tool)
      facts.recommendedTools.push(tool)
    }
    facts.routeTerms.push(...termsFromValues([tool, purpose, ...stringArray(path.closes_gaps)]))
  }

  const known = stringArray(coverage.known_findings).map(normalizeProfileTag)
  const suspected = stringArray(coverage.suspected_findings).map(normalizeProfileTag)
  const unverified = stringArray(coverage.unverified_areas).map(normalizeProfileTag)
  facts.knownFindings.push(...known)
  facts.suspectedFindings.push(...suspected)
  facts.unverifiedAreas.push(...unverified)
  facts.routeTerms.push(...termsFromValues([...known, ...suspected, ...unverified]))

  if (gaps.length > 0 || upgradePaths.length > 0 || known.length > 0 || suspected.length > 0) {
    facts.factSources.push(source)
  }
}

function collectRunArtifactRefs(run: Record<string, unknown>): Record<string, unknown>[] {
  return parseJsonArray(stringValue(run.artifact_refs_json))
}

function buildSampleRouteFacts(input: WorkflowSearchInput, database?: WorkflowSearchDatabase) {
  if (!input.sample_id || !database) return undefined

  const sampleId = input.sample_id
  const artifactTypes: string[] = []
  const artifactPaths: string[] = []
  const evidenceFamilies: string[] = []
  const evidenceBackends: string[] = []
  const completedStages: string[] = []
  const coverageGapDomains: string[] = []
  const knownFindings: string[] = []
  const suspectedFindings: string[] = []
  const unverifiedAreas: string[] = []
  const upgradeTools: string[] = []
  const recommendedTools: string[] = []
  const routeTerms: string[] = []
  const factSources: string[] = []
  let latestStage: string | undefined

  const artifactFactSink = { artifactTypes, artifactPaths, routeTerms, factSources }
  for (const artifact of database.findArtifacts?.(sampleId)?.slice(0, 50) ?? []) {
    collectArtifactFacts(artifactFactSink, artifact, 'artifacts')
  }

  const runs = database.findAnalysisRunsBySample?.(sampleId)?.slice(0, 3) ?? []
  for (const run of runs) {
    if (!latestStage) latestStage = stringValue(run.latest_stage)
    const runRecord = run as Record<string, unknown>
    for (const artifact of collectRunArtifactRefs(runRecord).slice(0, 50)) {
      collectArtifactFacts(artifactFactSink, artifact, 'analysis_run.artifact_refs')
    }

    const stages = run.id ? (database.findAnalysisRunStages?.(run.id)?.slice(0, 20) ?? []) : []
    for (const stage of stages) {
      const stageName = stringValue(stage.stage)
      if (stageName) {
        if (stage.status === 'completed') completedStages.push(stageName)
        routeTerms.push(...termsFromText(stageName))
      }
      const tool = stringValue(stage.tool)
      if (tool) {
        recommendedTools.push(tool)
        routeTerms.push(...termsFromText(tool))
      }
      for (const artifact of parseJsonArray(stage.artifact_refs_json).slice(0, 25)) {
        collectArtifactFacts(artifactFactSink, artifact, 'analysis_stage.artifact_refs')
      }
      const coverage = parseJsonRecord(stage.coverage_json)
      if (Object.keys(coverage).length > 0) {
        collectCoverageFacts(
          {
            coverageGapDomains,
            knownFindings,
            suspectedFindings,
            unverifiedAreas,
            upgradeTools,
            recommendedTools,
            routeTerms,
            factSources,
          },
          coverage,
          'analysis_stage.coverage'
        )
      }
    }
  }

  const evidenceRows = database.findAnalysisEvidenceBySample?.(sampleId, undefined, 20) ?? []
  for (const evidence of evidenceRows) {
    const family = stringValue(evidence.evidence_family)
    const backend = stringValue(evidence.backend)
    const mode = stringValue(evidence.mode)
    if (family) evidenceFamilies.push(normalizeProfileTag(family))
    if (backend) evidenceBackends.push(normalizeProfileTag(backend))
    routeTerms.push(...termsFromValues([family, backend, mode]))
    for (const artifact of parseJsonArray(evidence.artifact_refs_json).slice(0, 15)) {
      collectArtifactFacts(artifactFactSink, artifact, 'analysis_evidence.artifact_refs')
    }
    if (family || backend) factSources.push('analysis_evidence')
  }

  const normalized: SampleRouteFacts = {
    sample_id: sampleId,
    artifact_types: uniqueStrings(artifactTypes).slice(0, 40),
    artifact_paths: uniqueStrings(artifactPaths).slice(0, 25),
    evidence_families: uniqueStrings(evidenceFamilies).slice(0, 20),
    evidence_backends: uniqueStrings(evidenceBackends).slice(0, 20),
    latest_stage: latestStage,
    completed_stages: uniqueStrings(completedStages).slice(0, 20),
    coverage_gap_domains: uniqueStrings(coverageGapDomains).slice(0, 20),
    known_findings: uniqueStrings(knownFindings).slice(0, 20),
    suspected_findings: uniqueStrings(suspectedFindings).slice(0, 20),
    unverified_areas: uniqueStrings(unverifiedAreas).slice(0, 20),
    upgrade_tools: uniqueStrings(upgradeTools).slice(0, 20),
    recommended_tools: uniqueStrings(recommendedTools).slice(0, 30),
    route_terms: uniqueStrings(routeTerms.map(normalizeProfileTag)).slice(0, 80),
    fact_sources: uniqueStrings(factSources).slice(0, 12),
  }

  const hasFacts =
    normalized.artifact_types.length > 0 ||
    normalized.evidence_families.length > 0 ||
    normalized.coverage_gap_domains.length > 0 ||
    normalized.upgrade_tools.length > 0 ||
    normalized.recommended_tools.length > 0
  return hasFacts ? normalized : undefined
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

function buildSearchProfiles(
  input: WorkflowSearchInput,
  discoveryData: Record<string, unknown>,
  sampleRouteFacts?: SampleRouteFacts
): SearchProfileLane[] {
  const pluginMatrix = asRecord(discoveryData.plugin_matrix)
  const target = targetRecord(discoveryData)
  const fileTypeTags = profileTagsFor(input, discoveryData)
  const queryTerms = termsFromText(input.query)
  const goalTerms = termsForGoal(input.goal)
  const depthTerms = termsForDepth(input.depth)
  const findingTerms = termsForFinding(input.finding)
  const formatMatrix = asRecord(discoveryData.format_matrix)
  const byEvidence = asRecord(pluginMatrix.by_evidence)
  const byWorkflow = asRecord(pluginMatrix.by_workflow)
  const lanes: SearchProfileLane[] = []

  if (fileTypeTags.length > 0) {
    lanes.push({
      id: 'format-lane',
      lane: 'format',
      priority: 100,
      triggers: fileTypeTags,
      matched_formats: stringArray(target.matched_formats),
      matched_plugins: stringArray(target.matched_plugins),
      matched_tools: stringArray(target.matched_tools),
      recommended_tools: stringArray(target.recommended_tools).slice(0, 12),
      rationale:
        'Use normalized extension and sample file-type tags to keep format-specific tools in the topK window.',
    })
  }

  if (
    queryTerms.length > 0 ||
    goalTerms.length > 0 ||
    depthTerms.length > 0 ||
    findingTerms.length > 0
  ) {
    lanes.push({
      id: 'intent-lane',
      lane: 'intent',
      priority: 90,
      query_terms: queryTerms,
      goal_terms: goalTerms,
      depth_terms: depthTerms,
      finding_terms: findingTerms,
      rationale:
        'Use analyst wording, goal, depth, and finding hints to preserve intent-specific specialist tools.',
    })
  }

  if (
    Object.keys(formatMatrix).length > 0 ||
    Object.keys(byEvidence).length > 0 ||
    Object.keys(byWorkflow).length > 0
  ) {
    lanes.push({
      id: 'artifact-lane',
      lane: 'artifact',
      priority: 80,
      formats: Object.keys(formatMatrix),
      evidence: Object.keys(byEvidence),
      workflows: Object.keys(byWorkflow).slice(0, 25),
      recommended_tools: stringArray(discoveryData.recommended_tools).slice(0, 12),
      rationale:
        'Use declared artifact, evidence, and workflow contracts so downstream consumers are not crowded out by raw format matches.',
    })
  }

  if (sampleRouteFacts) {
    lanes.push({
      id: 'sample-facts-lane',
      lane: 'sample_facts',
      priority: 85,
      sample_id: sampleRouteFacts.sample_id,
      artifact_types: sampleRouteFacts.artifact_types.slice(0, 20),
      evidence_families: sampleRouteFacts.evidence_families.slice(0, 12),
      latest_stage: sampleRouteFacts.latest_stage ?? null,
      completed_stages: sampleRouteFacts.completed_stages.slice(0, 12),
      coverage_gap_domains: sampleRouteFacts.coverage_gap_domains.slice(0, 12),
      upgrade_tools: sampleRouteFacts.upgrade_tools.slice(0, 12),
      recommended_tools: sampleRouteFacts.recommended_tools.slice(0, 12),
      fact_sources: sampleRouteFacts.fact_sources,
      rationale:
        'Use existing sample artifacts, staged coverage gaps, upgrade paths, and evidence rows to rank the next likely workflow without exposing more tools.',
    })
  }

  const validationTerms = ['validate', 'validation', 'corroborate', 'corroboration', 'rule', 'yara']
  if (
    [...queryTerms, ...findingTerms].some((term) => validationTerms.includes(term)) ||
    findingTerms.length > 0
  ) {
    lanes.push({
      id: 'validation-lane',
      lane: 'validation',
      priority: 70,
      triggers: uniqueStrings([...queryTerms, ...findingTerms]).filter((term) =>
        [
          'validate',
          'validation',
          'corroborate',
          'corroboration',
          'rule',
          'ruleset',
          'yara',
          'sigma',
        ].includes(term)
      ),
      rationale:
        'Reserve room for rule validation, corroboration, and evidence graph consumers when the request includes findings or detection terms.',
    })
  }

  const reportingTerms = ['report', 'summary', 'summarize', 'artifact', 'evidence', 'export']
  if (input.goal === 'report' || queryTerms.some((term) => reportingTerms.includes(term))) {
    lanes.push({
      id: 'reporting-lane',
      lane: 'reporting',
      priority: 60,
      triggers: uniqueStrings([...queryTerms, ...(input.goal ? [input.goal] : [])]).filter((term) =>
        reportingTerms.includes(term)
      ),
      next_actions: stringArray(discoveryData.next_actions).slice(0, 8),
      rationale:
        'Keep reporting, artifact reading, and evidence summarization paths visible for low-context report requests.',
    })
  }

  return lanes
}

function resolveTopK(
  input: WorkflowSearchInput,
  discoveryData: Record<string, unknown>,
  sampleRouteFacts?: SampleRouteFacts
): ResolvedTopK {
  if (typeof input.top_k === 'number') {
    return { value: input.top_k, mode: 'manual', reason: 'Caller provided an explicit top_k.' }
  }

  const queryTerms = termsFromText(input.query)
  const findingTerms = termsForFinding(input.finding)
  const profileTags = profileTagsFor(input, discoveryData)
  const hasPreciseProfile = profileTags.length > 0
  const intentTerms = uniqueStrings([
    ...queryTerms,
    ...termsForGoal(input.goal),
    ...termsForDepth(input.depth),
    ...findingTerms,
  ])
  const asksForDeepReverse =
    input.goal === 'reverse' ||
    input.depth === 'deep' ||
    intentTerms.some((term) =>
      ['decompile', 'decompiler', 'disassembly', 'cfg', 'xref', 'function', 'reconstruct'].includes(
        term
      )
    )
  const asksForValidation =
    findingTerms.length > 0 ||
    intentTerms.some((term) =>
      ['packed', 'unpack', 'c2', 'ioc', 'yara', 'sigma', 'validate', 'corroboration'].includes(term)
    )
  const asksForReport = input.goal === 'report' || intentTerms.some((term) => term === 'report')
  const asksForDynamic = input.goal === 'dynamic' || input.depth === 'deep'
  const isDirectLookup = Boolean(input.tool_name || input.plugin_id || input.category)

  if (isDirectLookup) {
    return { value: 3, mode: 'adaptive', reason: 'Direct plugin/tool/category lookup.' }
  }
  if (asksForDeepReverse) {
    return { value: 12, mode: 'adaptive', reason: 'Deep reverse-engineering intent.' }
  }
  if (asksForValidation || asksForDynamic || asksForReport) {
    return {
      value: 8,
      mode: 'adaptive',
      reason: 'Validation, runtime planning, or reporting intent needs a broader workflow window.',
    }
  }
  if (sampleRouteFacts && sampleRouteFacts.route_terms.length > 0) {
    return {
      value: 8,
      mode: 'adaptive',
      reason: 'Sample-scoped route facts were available for follow-up ranking.',
    }
  }
  if (hasPreciseProfile && queryTerms.length <= 3) {
    return {
      value: 5,
      mode: 'adaptive',
      reason: 'Precise file profile with a narrow user query.',
    }
  }
  if (!hasPreciseProfile && queryTerms.length === 0) {
    return { value: 8, mode: 'adaptive', reason: 'Broad discovery without profile or query.' }
  }
  return { value: 6, mode: 'adaptive', reason: 'Balanced profile and intent search.' }
}

function laneName(profile: SearchProfileLane): string | undefined {
  return stringValue(profile.lane)
}

function lanePriority(profile: SearchProfileLane): number {
  return numberValue(profile.priority)
}

function laneTerms(profile: SearchProfileLane): string[] {
  return uniqueStrings(
    [
      ...termsFromValues([
        laneName(profile),
        stringValue(profile.id),
        stringValue(profile.rationale),
        ...stringArray(profile.triggers),
        ...stringArray(profile.formats),
        ...stringArray(profile.evidence),
        ...stringArray(profile.workflows),
        ...stringArray(profile.recommended_tools),
        ...stringArray(profile.next_actions),
      ]),
      ...stringArray(profile.query_terms),
      ...stringArray(profile.goal_terms),
      ...stringArray(profile.depth_terms),
      ...stringArray(profile.finding_terms),
      ...stringArray(profile.artifact_types),
      ...stringArray(profile.evidence_families),
      ...stringArray(profile.coverage_gap_domains),
    ].map(normalizeProfileTag)
  )
}

function laneCandidateScore(ranked: RankedRecommendation, profile: SearchProfileLane): number {
  const lane = laneName(profile)
  if (!lane) return 0

  const text = recommendationSearchText(ranked.item)
  const terms = laneTerms(profile)
  const termMatch = scoreTerms(terms, text)
  const score = ranked.score_breakdown

  if (lane === 'format') {
    const intentPenalty = Math.min(24, score.query_score + score.depth_score + score.finding_score)
    return Math.max(0, score.profile_score + termMatch.score * 2 - intentPenalty)
  }

  if (lane === 'intent') {
    return score.query_score + score.goal_score + score.depth_score + score.finding_score
  }

  if (lane === 'sample_facts') {
    return score.sample_score + termMatch.score
  }

  if (lane === 'artifact') {
    const artifactTerms = uniqueStrings([
      ...termsFromValues([...stringArray(profile.formats), ...stringArray(profile.evidence)]),
      'artifact',
      'evidence',
      'workflow',
      'handoff',
      'correlation',
      'graph',
      'report',
      'summary',
      'provenance',
    ])
    const artifactMatch = scoreTerms(artifactTerms, text)
    const consumerBonus = [
      'artifact',
      'evidence',
      'correlation',
      'graph',
      'report',
      'handoff',
    ].filter((term) => text.includes(term)).length
    return artifactMatch.score + consumerBonus * 18
  }

  if (lane === 'validation') {
    const validationTerms = uniqueStrings([
      ...terms,
      'validate',
      'validation',
      'corroborate',
      'rule',
      'yara',
      'sigma',
    ])
    return score.finding_score + scoreTerms(validationTerms, text).score
  }

  if (lane === 'reporting') {
    const reportingTerms = uniqueStrings([
      ...terms,
      'report',
      'summary',
      'artifact',
      'evidence',
      'export',
      'graph',
    ])
    return scoreTerms(reportingTerms, text).score + (text.includes('report') ? 12 : 0)
  }

  return termMatch.score
}

function resultIdForRanked(ranked: RankedRecommendation): string {
  return recommendationResultId(ranked.item, ranked.original_index)
}

function recommendationKey(item: Record<string, unknown>, index: number): string {
  if (stringValue(item.kind) === 'plugin_tool') {
    const toolName = stringValue(item.tool_name) ?? stringValue(item.name)
    if (toolName) return `tool:${toolName}`
  }
  const pluginId = stringValue(item.plugin_id) ?? stringValue(item.id)
  if (pluginId) return `plugin:${pluginId}`
  const toolName = stringValue(item.tool_name) ?? stringValue(item.name)
  if (toolName) return `tool:${toolName}`
  return `result:${index}`
}

function mergeRecommendations(
  primary: Record<string, unknown>[],
  supplemental: Record<string, unknown>[]
): Record<string, unknown>[] {
  const seen = new Set<string>()
  const merged: Record<string, unknown>[] = []
  for (const item of [...primary, ...supplemental]) {
    const key = recommendationKey(item, merged.length)
    if (seen.has(key)) continue
    seen.add(key)
    merged.push(item)
  }
  return merged
}

function shouldSupplementArtifactCandidates(
  input: WorkflowSearchInput,
  searchProfiles: SearchProfileLane[]
): boolean {
  if (input.plugin_id || input.tool_name || input.category) return false
  return searchProfiles.some((profile) => {
    const lane = laneName(profile)
    return lane === 'artifact' || lane === 'reporting'
  })
}

function matchedLanesForRecommendation(
  ranked: RankedRecommendation,
  searchProfiles: SearchProfileLane[]
): string[] {
  return uniqueStrings(
    searchProfiles
      .filter((profile) => laneCandidateScore(ranked, profile) > 0)
      .map((profile) => laneName(profile))
      .filter((lane): lane is string => Boolean(lane))
  )
}

function assignLaneQuotas(searchProfiles: SearchProfileLane[], topK: number) {
  const activeProfiles = searchProfiles
    .filter((profile) => laneName(profile))
    .sort((a, b) => lanePriority(b) - lanePriority(a))
  const quotaProfiles = activeProfiles.slice(0, Math.max(0, topK))
  return new Map(quotaProfiles.map((profile) => [laneName(profile), 1]))
}

function selectLaneAwareTopK(
  rankedRecommendations: RankedRecommendation[],
  searchProfiles: SearchProfileLane[],
  topK: number
): LaneQuotaSelection {
  const selected: RankedRecommendation[] = []
  const selectedIds = new Set<string>()
  const selectionMetadata = new Map<
    string,
    { matched_lanes: string[]; selected_via_lane: string }
  >()
  const quotaDecisions: LaneQuotaDecision[] = []
  const laneQuotas = assignLaneQuotas(searchProfiles, topK)
  const rankedIndex = new Map(
    rankedRecommendations.map((item, index) => [resultIdForRanked(item), index])
  )

  for (const profile of searchProfiles
    .filter((candidate) => laneName(candidate))
    .sort((a, b) => lanePriority(b) - lanePriority(a))) {
    const lane = laneName(profile)
    const quota = laneQuotas.get(lane) ?? 0
    const candidates = rankedRecommendations
      .map((candidate) => ({ candidate, lane_score: laneCandidateScore(candidate, profile) }))
      .filter((candidate) => candidate.lane_score > 0)
      .sort(
        (a, b) =>
          b.lane_score - a.lane_score ||
          b.candidate.total_score - a.candidate.total_score ||
          a.candidate.original_index - b.candidate.original_index
      )

    const picked: RankedRecommendation[] = []
    for (const { candidate } of candidates) {
      if (picked.length >= quota) break
      const resultId = resultIdForRanked(candidate)
      if (selectedIds.has(resultId)) continue
      picked.push(candidate)
      selected.push(candidate)
      selectedIds.add(resultId)
      selectionMetadata.set(resultId, {
        matched_lanes: matchedLanesForRecommendation(candidate, searchProfiles),
        selected_via_lane: lane,
      })
    }

    const selectedResultIds = picked.map(resultIdForRanked)
    const candidateResultIds = candidates.map(({ candidate }) => resultIdForRanked(candidate))
    quotaDecisions.push({
      lane,
      lane_id: stringValue(profile.id) ?? lane,
      priority: lanePriority(profile),
      quota,
      candidate_result_ids: candidateResultIds.slice(0, 12),
      selected_result_ids: selectedResultIds,
      overflow_result_ids: candidateResultIds
        .filter((resultId) => !selectedResultIds.includes(resultId))
        .slice(0, 12),
      promoted: selectedResultIds.some((resultId) => (rankedIndex.get(resultId) ?? topK) >= topK),
      reason:
        quota > 0
          ? `Reserved ${quota} topK slot(s) for the ${lane} search profile lane.`
          : `No reserved topK slot remained for the ${lane} search profile lane.`,
    })
  }

  for (const candidate of rankedRecommendations) {
    if (selected.length >= topK) break
    const resultId = resultIdForRanked(candidate)
    if (selectedIds.has(resultId)) continue
    selected.push(candidate)
    selectedIds.add(resultId)
    selectionMetadata.set(resultId, {
      matched_lanes: matchedLanesForRecommendation(candidate, searchProfiles),
      selected_via_lane: 'global_fill',
    })
  }

  return {
    selected: selected
      .slice(0, topK)
      .sort(
        (a, b) =>
          (rankedIndex.get(resultIdForRanked(a)) ?? 0) -
          (rankedIndex.get(resultIdForRanked(b)) ?? 0)
      ),
    quota_decisions: quotaDecisions,
    selection_metadata: selectionMetadata,
  }
}

function applyQuotaMetadataToProfiles(
  searchProfiles: SearchProfileLane[],
  quotaDecisions: LaneQuotaDecision[]
): SearchProfileLane[] {
  return searchProfiles.map((profile) => {
    const lane = laneName(profile)
    const decision = lane ? quotaDecisions.find((item) => item.lane === lane) : undefined
    if (!decision) return profile
    return {
      ...profile,
      top_k_quota: decision.quota,
      candidate_count: decision.candidate_result_ids.length,
      selected_count: decision.selected_result_ids.length,
    }
  })
}

function compactSearchProfilesForOutput(profiles: SearchProfileLane[]): SearchProfileLane[] {
  return profiles.map((profile) => {
    if (!Array.isArray(profile.formats)) return profile
    const compact: SearchProfileLane = { ...profile, format_count: profile.formats.length }
    delete compact.formats
    return compact
  })
}

// Default (compact) shaping of the workflow.search response: the search path otherwise
// echoes several large arrays that either duplicate top-level fields (search_profile.search_profiles /
// quota_decisions) or are reference-only (full available_tools/blocked_tools, per-lane evidence/workflows,
// per-result diagnostics). They are replaced with *_count and the ranked results stay intact. The full
// payload is preserved when the caller passes verbose:true.
function countAndStrip(target: Record<string, unknown>, keys: string[]): void {
  for (const key of keys) {
    const value = target[key]
    if (Array.isArray(value)) {
      target[`${key}_count`] = value.length
      delete target[key]
    }
  }
}
function compactWorkflowSearchData(data: Record<string, unknown>): Record<string, unknown> {
  // search_profile: keep the ranked-relevant fields (recommended_tools, search_profiles,
  // sample_route_facts) but drop the reference-only full tool lists and the quota_decisions
  // copy that already exists at the response top level.
  const profile = asRecord(data.search_profile)
  if (Object.keys(profile).length > 0) {
    delete profile.quota_decisions
    countAndStrip(profile, [
      'available_tools',
      'blocked_tools',
      'missing_deps',
      'matched_tools',
      'matched_plugins',
    ])
    const matrix = asRecord(profile.plugin_matrix_summary)
    if (Object.keys(matrix).length > 0) {
      delete matrix.formats
      profile.plugin_matrix_summary = matrix
    }
    data.search_profile = profile
  }
  // recommendations is an exact copy of results; keep a lightweight index only. results keeps
  // the full per-result detail (rank, score_breakdown, matched_profile_fields, activation, ...).
  if (Array.isArray(data.recommendations)) {
    data.recommendations = data.recommendations.map((entry) => {
      const item = asRecord(entry)
      return {
        result_id: item.result_id,
        rank: item.rank,
        score: item.score,
        kind: item.kind,
        tool_name: item.tool_name,
        plugin_id: item.plugin_id,
        readiness_state: item.readiness_state,
        activation_required: item.activation_required,
      }
    })
  }
  return data
}

function readinessScore(readinessState: string): number {
  if (readinessState === 'ready') return 8
  if (readinessState === 'blocked') return -60
  if (readinessState === 'readiness_warning') return -8
  if (readinessState === 'hidden_activation_required') return 0
  if (
    ['backend_readiness_required', 'runtime_opt_in_required', 'backend_profile_required'].includes(
      readinessState
    )
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

function sampleFactsScore(params: {
  item: Record<string, unknown>
  searchText: string
  sampleRouteFacts?: SampleRouteFacts
}): { score: number; matched: string[] } {
  const facts = params.sampleRouteFacts
  if (!facts) return { score: 0, matched: [] }

  const matched: string[] = []
  let score = 0
  const toolName = stringValue(params.item.tool_name) ?? stringValue(params.item.name)
  const itemTools = uniqueStrings([
    ...(toolName ? [toolName] : []),
    ...stringArray(params.item.recommended_tools),
    ...stringArray(params.item.available_tools),
    ...stringArray(params.item.preferred_primary_tools),
  ])
  const preferredTools = uniqueStrings([...facts.upgrade_tools, ...facts.recommended_tools])
  const toolMatches = itemTools.filter((tool) =>
    preferredTools.some(
      (preferred) =>
        tool === preferred ||
        tool.startsWith(`${preferred}.`) ||
        preferred.startsWith(`${tool}.`) ||
        normalizeProfileTag(tool) === normalizeProfileTag(preferred)
    )
  )
  if (toolMatches.length > 0) {
    score += 45 + toolMatches.length * 10
    matched.push(`sample recommended tools: ${toolMatches.slice(0, 4).join(', ')}`)
  }

  const routeTerms = uniqueStrings([
    ...facts.route_terms,
    ...facts.artifact_types,
    ...facts.evidence_families,
    ...facts.coverage_gap_domains,
    ...facts.known_findings,
    ...facts.suspected_findings,
    ...facts.unverified_areas,
  ]).slice(0, 80)
  const routeMatch = scoreTerms(routeTerms, params.searchText)
  if (routeMatch.matched.length > 0) {
    score += Math.min(45, routeMatch.matched.length * 7)
    matched.push(`sample route facts: ${routeMatch.matched.slice(0, 8).join(', ')}`)
  }

  const artifactMatches = facts.artifact_types.filter((type) => params.searchText.includes(type))
  if (artifactMatches.length > 0) {
    score += Math.min(24, artifactMatches.length * 6)
    matched.push(`sample artifact types: ${artifactMatches.slice(0, 6).join(', ')}`)
  }

  return { score, matched: uniqueStrings(matched).slice(0, 6) }
}

function rankRecommendation(params: {
  item: Record<string, unknown>
  input: WorkflowSearchInput
  discoveryData: Record<string, unknown>
  sampleRouteFacts?: SampleRouteFacts
  originalIndex: number
}): RankedRecommendation {
  const { item, input, discoveryData, sampleRouteFacts, originalIndex } = params
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

  const sampleMatch = sampleFactsScore({ item, searchText, sampleRouteFacts })
  if (sampleMatch.matched.length > 0) {
    matchedProfileFields.push(...sampleMatch.matched)
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
    sampleMatch.score +
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
      sample_score: sampleMatch.score,
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

function buildSearchProfile(
  input: WorkflowSearchInput,
  discoveryData: Record<string, unknown>,
  resolvedTopK: ResolvedTopK,
  searchProfiles: SearchProfileLane[],
  sampleRouteFacts?: SampleRouteFacts,
  quotaDecisions: LaneQuotaDecision[] = []
) {
  const pluginMatrix = asRecord(discoveryData.plugin_matrix)
  const queryTerms = termsFromText(input.query)
  const findingTerms = termsForFinding(input.finding)
  const verbose = input.verbose
  const formatKeys = Object.keys(asRecord(discoveryData.format_matrix))
  return {
    sample_file_type: discoveryData.sample_file_type ?? null,
    requested_file_type: input.file_type ?? null,
    requested_top_k: input.top_k,
    resolved_top_k: resolvedTopK.value,
    top_k_strategy: resolvedTopK,
    file_type_tags: profileTagsFor(input, discoveryData),
    query_terms: queryTerms,
    goal_terms: termsForGoal(input.goal),
    depth_terms: termsForDepth(input.depth),
    finding_terms: findingTerms,
    search_profiles: searchProfiles,
    lane_top_k: {
      enabled: quotaDecisions.length > 0,
      requested_top_k: input.top_k,
      resolved_top_k: resolvedTopK.value,
      quotas: quotaDecisions.map((decision) => ({
        lane: decision.lane,
        quota: decision.quota,
        selected_count: decision.selected_result_ids.length,
        candidate_count: decision.candidate_result_ids.length,
        promoted: decision.promoted,
      })),
    },
    quota_decisions: quotaDecisions,
    sample_route_facts: sampleRouteFacts
      ? {
          sample_id: sampleRouteFacts.sample_id,
          artifact_types: sampleRouteFacts.artifact_types.slice(0, 20),
          evidence_families: sampleRouteFacts.evidence_families.slice(0, 12),
          latest_stage: sampleRouteFacts.latest_stage ?? null,
          completed_stages: sampleRouteFacts.completed_stages.slice(0, 12),
          coverage_gap_domains: sampleRouteFacts.coverage_gap_domains.slice(0, 12),
          known_findings: sampleRouteFacts.known_findings.slice(0, 12),
          suspected_findings: sampleRouteFacts.suspected_findings.slice(0, 12),
          upgrade_tools: sampleRouteFacts.upgrade_tools.slice(0, 12),
          recommended_tools: sampleRouteFacts.recommended_tools.slice(0, 12),
          route_terms: sampleRouteFacts.route_terms.slice(0, 25),
          fact_sources: sampleRouteFacts.fact_sources,
        }
      : undefined,
    format_count: formatKeys.length,
    ...(verbose ? { formats: formatKeys } : {}),
    recommended_tools: stringArray(discoveryData.recommended_tools),
    available_tools: stringArray(discoveryData.available_tools),
    blocked_tools: stringArray(discoveryData.blocked_tools),
    missing_deps: stringArray(discoveryData.missing_deps),
    next_actions: stringArray(discoveryData.next_actions),
    matched_plugins: stringArray(discoveryData.matched_plugins),
    matched_tools: stringArray(discoveryData.matched_tools),
    plugin_matrix_summary: {
      format_count: formatKeys.length,
      ...(verbose ? { formats: formatKeys } : {}),
      recommended_tools: stringArray(discoveryData.recommended_tools).slice(0, 12),
      available_tool_count: stringArray(discoveryData.available_tools).length,
      blocked_tool_count: stringArray(discoveryData.blocked_tools).length,
      missing_dep_count: stringArray(discoveryData.missing_deps).length,
      capability_count: Object.keys(asRecord(pluginMatrix.by_capability)).length,
      runtime_count: Object.keys(asRecord(pluginMatrix.by_runtime)).length,
      safety_count: Object.keys(asRecord(pluginMatrix.by_safety)).length,
      artifact_type_count: Object.keys(asRecord(pluginMatrix.by_artifact_type)).length,
      workflow_count: Object.keys(asRecord(pluginMatrix.by_workflow)).length,
      worker_backend_count: Object.keys(asRecord(pluginMatrix.by_worker_backend)).length,
    },
  }
}

function normalizeRecommendation(
  ranked: RankedRecommendation,
  index: number,
  metadata: { matched_lanes?: string[]; selected_via_lane?: string } | undefined,
  liveToolNames: string[]
) {
  const item = ranked.item
  const workflowRecipes = Array.isArray(item.workflow_recipes)
    ? (item.workflow_recipes as Array<Record<string, unknown>>)
    : []
  const readinessState = typeof item.readiness_state === 'string' ? item.readiness_state : 'unknown'
  const resultId = recommendationResultId(item, index)
  const scopedToolNames = resultScopedToolNames(item, liveToolNames)
  return {
    result_id: resultId,
    rank: index + 1,
    score: ranked.total_score,
    matched_lanes: metadata?.matched_lanes ?? [],
    selected_via_lane: metadata?.selected_via_lane ?? 'global_fill',
    kind: item.kind === 'core_tool' || item.kind === 'plugin_tool' ? 'tool' : item.kind,
    tool_name: item.tool_name ?? item.name,
    plugin_id: item.plugin_id ?? item.id,
    workflow_id: workflowRecipes.length > 0 ? workflowRecipes[0]?.id : undefined,
    title: item.name ?? item.tool_name ?? item.plugin_id ?? item.id,
    description: item.description,
    readiness_state: readinessState,
    tool_surface_role: item.tool_surface_role,
    preferred_primary_tools: stringArray(item.preferred_primary_tools),
    activation_required: ACTIVATION_REQUIRED_STATES.has(readinessState),
    activation_command: normalizeActivationCommand(item.activation_command, resultId),
    activation_scope: {
      mode: 'result_scoped',
      tool_names: scopedToolNames,
      fallback_available_tools: stringArray(item.available_tools).slice(0, 8),
      plugin_level_activation_required: scopedToolNames.length === 0 && Boolean(item.plugin_id),
    },
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

function recommendationResultId(item: Record<string, unknown>, index: number): string {
  if (stringValue(item.kind) === 'plugin_tool') {
    const toolName = stringValue(item.tool_name) ?? stringValue(item.name)
    if (toolName) return `tool:${toolName}`
  }
  const pluginId = stringValue(item.plugin_id) ?? stringValue(item.id)
  if (pluginId) return `plugin:${pluginId}`
  const toolName = stringValue(item.tool_name) ?? stringValue(item.name)
  if (toolName) return `tool:${toolName}`
  return `result:${index + 1}`
}

function workflowRecipeStartTools(item: Record<string, unknown>): string[] {
  const recipes = Array.isArray(item.workflow_recipes)
    ? (item.workflow_recipes as Array<Record<string, unknown>>)
    : []
  return uniqueStrings(
    recipes.flatMap((recipe) => [
      ...stringArray(recipe.startsWith),
      ...stringArray(recipe.starts_with),
    ])
  )
}

function resultScopedToolNames(item: Record<string, unknown>, liveToolNames: string[]): string[] {
  const resolveLive = (toolNames: string[]) =>
    resolveLiveSurfaceToolNames(toolNames, liveToolNames).resolvedToolNames.slice(0, 8)
  const kind = stringValue(item.kind)
  if (kind === 'core_tool' || kind === 'plugin_tool') {
    const toolName = stringValue(item.tool_name) ?? stringValue(item.name)
    return toolName ? resolveLive([toolName]) : []
  }

  const workflowStartTools = resolveLive(workflowRecipeStartTools(item))
  if (workflowStartTools.length > 0) return workflowStartTools.slice(0, 8)

  const recommendedTools = resolveLive(stringArray(item.recommended_tools))
  if (recommendedTools.length > 0) return recommendedTools.slice(0, 8)

  return resolveLive(stringArray(item.available_tools)).slice(0, 1)
}

function normalizeActivationCommand(
  value: unknown,
  resultId?: string
): Record<string, unknown> | undefined {
  const command = asRecord(value)
  if (Object.keys(command).length === 0 && !resultId) return undefined
  return {
    action: 'activate',
    ...(resultId ? { result_id: resultId } : command),
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

function directActivationFromResultId(
  resultId: string | undefined
): { plugin_id?: string; tool_name?: string } | null {
  if (!resultId) return null
  if (resultId.startsWith('plugin:')) {
    const pluginId = resultId.slice('plugin:'.length).trim()
    return pluginId ? { plugin_id: pluginId } : null
  }
  if (resultId.startsWith('tool:')) {
    const toolName = resultId.slice('tool:'.length).trim()
    return toolName ? { tool_name: toolName } : null
  }
  return null
}

export function createWorkflowSearchHandler(
  pluginManager: PluginManager,
  options: {
    database?: WorkflowSearchDatabase
    toolDefinitions?: () => ToolDefinition[]
  } = {}
) {
  const discover = createToolsDiscoverHandler(pluginManager, options)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const parsedInput = workflowSearchInputSchema.parse(args)
      const input = parsedInput.tool_name
        ? parsedInput
        : { ...parsedInput, tool_name: exactToolNameFromQuery(parsedInput.query) }
      const discoveryAction =
        input.action === 'activate' && input.result_id
          ? 'recommend'
          : toDiscoverAction(input.action)
      const discovery = await discover({
        action: discoveryAction,
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
      const sampleRouteFacts = buildSampleRouteFacts(input, options.database)
      const resolvedTopK = resolveTopK(input, discoveryData, sampleRouteFacts)
      const searchProfiles = buildSearchProfiles(input, discoveryData, sampleRouteFacts)
      const primaryRecommendations = Array.isArray(discoveryData.recommendations)
        ? (discoveryData.recommendations as Record<string, unknown>[])
        : []
      const supplementalRecommendations: Record<string, unknown>[] = []
      if (!input.tool_name && shouldSupplementArtifactCandidates(input, searchProfiles)) {
        const supplementalDiscovery = await discover({
          action: 'recommend',
          query: 'evidence',
          category: 'static-analysis',
        })
        if (supplementalDiscovery.ok) {
          const supplementalData = asRecord(supplementalDiscovery.data)
          supplementalRecommendations.push(
            ...asRecordArray(supplementalData.recommendations).slice(0, 8)
          )
        }
      }
      const recommendations = mergeRecommendations(
        primaryRecommendations,
        supplementalRecommendations
      )
      const rankedRecommendations = recommendations
        .map((item, index) =>
          rankRecommendation({
            item,
            input,
            discoveryData,
            sampleRouteFacts,
            originalIndex: index,
          })
        )
        .sort((a, b) => b.total_score - a.total_score || a.original_index - b.original_index)
      const resultWindow = input.action === 'activate' && input.result_id ? 25 : resolvedTopK.value
      const quotaSelection = selectLaneAwareTopK(
        rankedRecommendations,
        searchProfiles,
        resolvedTopK.value
      )
      const enhancedSearchProfiles = applyQuotaMetadataToProfiles(
        searchProfiles,
        quotaSelection.quota_decisions
      )
      const outputSearchProfiles = input.verbose
        ? enhancedSearchProfiles
        : compactSearchProfilesForOutput(enhancedSearchProfiles)
      const searchProfile = buildSearchProfile(
        input,
        discoveryData,
        resolvedTopK,
        outputSearchProfiles,
        sampleRouteFacts,
        quotaSelection.quota_decisions
      )
      const selectedRecommendations =
        input.action === 'activate' && input.result_id
          ? rankedRecommendations.slice(0, resultWindow)
          : quotaSelection.selected
      const registeredToolDefinitions = options.toolDefinitions
        ? options.toolDefinitions()
        : undefined
      const liveToolNames = listLiveSurfaceToolNames(registeredToolDefinitions)
      const results = selectedRecommendations.map((item, index) => {
        const resultId = resultIdForRanked(item)
        const metadata = quotaSelection.selection_metadata.get(resultId) ?? {
          matched_lanes: matchedLanesForRecommendation(item, searchProfiles),
          selected_via_lane: 'global_fill',
        }
        return normalizeRecommendation(item, index, metadata, liveToolNames)
      })

      if (input.action === 'activate' && input.result_id) {
        const selected = results.find((result) => result.result_id === input.result_id)
        if (!selected) {
          const directActivation = directActivationFromResultId(input.result_id)
          if (directActivation) {
            const activation = await discover({
              action: 'activate',
              ...directActivation,
              sample_id: input.sample_id,
              file_type: input.file_type,
              finding: input.finding,
            })
            const activationData = asRecord(activation.data)
            if (activation.ok) {
              return {
                ok: true,
                data: {
                  result_mode: 'workflow_search',
                  action: input.action,
                  query: input.query,
                  sample_id: input.sample_id,
                  goal: input.goal,
                  depth: input.depth,
                  top_k: resolvedTopK.value,
                  search_profile: searchProfile,
                  search_profiles: outputSearchProfiles,
                  quota_decisions: quotaSelection.quota_decisions,
                  activation_audit: {
                    ...asRecord(activationData.activation_audit),
                    result_id: input.result_id,
                    result_id_direct_activation_used: true,
                  },
                  activated: stringArray(activationData.activated),
                  activated_tools: stringArray(activationData.activated_tools),
                  raw_discovery: {
                    action: activationData.action,
                    sample_file_type: activationData.sample_file_type,
                    target_file_type_tags: activationData.target_file_type_tags,
                    matched_plugins: activationData.matched_plugins,
                    matched_tools: activationData.matched_tools,
                  },
                  message: `Activated ${input.result_id} directly from result_id; no backend execution was started.`,
                },
                warnings: uniqueStrings([
                  ...(discovery.warnings ?? []),
                  ...(activation.warnings ?? []),
                ]),
                metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
              }
            }

            return {
              ok: false,
              errors: activation.errors ?? [
                `Failed to activate workflow.search result_id=${input.result_id}.`,
              ],
              warnings: uniqueStrings([
                ...(discovery.warnings ?? []),
                ...(activation.warnings ?? []),
              ]),
              metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
            }
          }

          return {
            ok: false,
            errors: [
              `No workflow.search result matched result_id=${input.result_id}. Re-run the same search and activate a returned result_id, or activate a specific tool_name.`,
            ],
            warnings: discovery.warnings,
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        const activationScope = asRecord(selected.activation_scope)
        const scopedToolNames = stringArray(activationScope.tool_names)
        if (scopedToolNames.length === 0) {
          return {
            ok: false,
            errors: [
              `Result ${input.result_id} does not expose a scoped tool set. Use workflow.search action=activate tool_name=<tool> or inspect the result before plugin-level activation.`,
            ],
            warnings: discovery.warnings,
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        const preflight = resolveLiveSurfaceToolNames(scopedToolNames)
        if (preflight.unknownToolNames.length > 0) {
          return {
            ok: false,
            errors: [
              `Result ${input.result_id} references unknown or unloaded tools: ${preflight.unknownToolNames.join(', ')}. Re-run discovery.`,
            ],
            warnings: discovery.warnings,
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        const activation = await discover({
          action: 'activate',
          tool_names: preflight.resolvedToolNames,
        })
        if (!activation.ok) {
          return {
            ok: false,
            errors: activation.errors ?? [
              `Failed to activate scoped tools: ${preflight.resolvedToolNames.join(', ')}.`,
            ],
            warnings: uniqueStrings([
              ...(discovery.warnings ?? []),
              ...(activation.warnings ?? []),
            ]),
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }
        const activationResults = [asRecord(activation.data)]

        const activationAudits = activationResults.map((result) =>
          asRecord(result.activation_audit)
        )
        const activated = uniqueStrings(
          activationResults.flatMap((result) => stringArray(result.activated))
        )
        const activatedTools = uniqueStrings(
          activationResults.flatMap((result) => stringArray(result.activated_tools))
        )
        const activatedCoreTools = uniqueStrings(
          activationAudits.flatMap((audit) => stringArray(audit.activated_core_tools))
        )
        const activatedScopedTools = uniqueStrings(
          activationAudits.flatMap((audit) => stringArray(audit.activated_scoped_tools))
        )

        return {
          ok: true,
          data: {
            result_mode: 'workflow_search',
            action: input.action,
            query: input.query,
            sample_id: input.sample_id,
            goal: input.goal,
            depth: input.depth,
            top_k: resolvedTopK.value,
            search_profile: searchProfile,
            search_profiles: outputSearchProfiles,
            quota_decisions: quotaSelection.quota_decisions,
            activation_audit: {
              at: new Date().toISOString(),
              action: 'activate',
              request: {
                result_id: input.result_id,
                query: input.query ?? null,
                file_type: input.file_type ?? null,
                sample_id: input.sample_id ?? null,
                goal: input.goal ?? null,
                depth: input.depth ?? null,
                finding: input.finding ?? null,
              },
              selected_result: selected,
              scoped_tool_names: scopedToolNames,
              activated_plugins: activated,
              activated_tools: activatedTools,
              activated_core_tools: activatedCoreTools,
              activated_scoped_tools: activatedScopedTools,
              policy: {
                progressive_surface_enabled: true,
                result_scoped_activation_used: true,
                plugin_level_activation_used: false,
                backend_execution_started: false,
                readiness_not_bypassed: true,
              },
              child_audits: activationAudits,
            },
            activated,
            activated_tools: activatedTools,
            raw_discovery: {
              action: discoveryData.action,
              sample_file_type: discoveryData.sample_file_type,
              target_file_type_tags: discoveryData.target_file_type_tags,
              matched_plugins: discoveryData.matched_plugins,
              matched_tools: discoveryData.matched_tools,
            },
            message: `Exposed ${activatedTools.length} result-scoped tool(s) for ${input.result_id}: ${activatedTools.join(', ')}.`,
          },
          warnings: discovery.warnings,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

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
            top_k: resolvedTopK.value,
            search_profile: searchProfile,
            search_profiles: outputSearchProfiles,
            quota_decisions: quotaSelection.quota_decisions,
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

      const searchResponseData: Record<string, unknown> = {
        result_mode: 'workflow_search',
        action: input.action,
        query: input.query,
        sample_id: input.sample_id,
        goal: input.goal,
        depth: input.depth,
        top_k: resolvedTopK.value,
        search_profile: searchProfile,
        search_profiles: outputSearchProfiles,
        quota_decisions: quotaSelection.quota_decisions,
        results: input.action === 'status' ? undefined : results,
        recommendations: input.action === 'status' ? undefined : results,
        recommendation_summary: discoveryData.recommendation_summary,
        raw_discovery: input.action === 'status' ? discoveryData : undefined,
        message:
          input.action === 'status'
            ? String(discoveryData.message ?? 'Workflow search status returned.')
            : `Ranked ${results.length} passive workflow/search recommendation(s). No tools were activated or executed.`,
      }
      return {
        ok: true,
        data: input.verbose ? searchResponseData : compactWorkflowSearchData(searchResponseData),
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
