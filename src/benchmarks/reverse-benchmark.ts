export type ReverseBenchmarkDimension =
  | 'tool_discovery_quality'
  | 'function_recovery_coverage'
  | 'decompile_consensus'
  | 'string_config_recovery'
  | 'js_obfuscation_routing'
  | 'safety_gate_correctness'

export interface ReverseBenchmarkExpectedDiscover {
  recommended_tools?: string[]
  plugin_ids?: string[]
  readiness_states?: Record<string, string>
  blocked_tools?: string[]
  missing_deps?: string[]
  safety_gates?: string[]
}

export interface ReverseBenchmarkCase {
  id: string
  profile: string
  default_ci: boolean
  fixture_mode: 'metadata-only' | 'tiny-synthetic' | 'external-corpus'
  dimensions: ReverseBenchmarkDimension[]
  discover_request: {
    action: 'recommend'
    file_type?: string
    query?: string
    sample_id?: string
  }
  expected: {
    discover: ReverseBenchmarkExpectedDiscover
  }
  residual_gaps?: string[]
  external_corpus?: {
    env_flag: string
    description: string
  }
}

export interface ReverseBenchmarkManifest {
  schema_version: number
  policy: {
    allows_live_malware: boolean
    allows_host_execution: boolean
    default_ci_static_only: boolean
    external_corpus_env?: string
  }
  dimensions: Array<{
    id: ReverseBenchmarkDimension
    description: string
    default_ci_metric: string
    residual_gap_policy: string
  }>
  cases: ReverseBenchmarkCase[]
}

export interface ReverseBenchmarkSelectionOptions {
  includeExternalCorpus?: boolean
  env?: NodeJS.ProcessEnv
}

export interface ReverseBenchmarkDiscoverEvaluation {
  case_id: string
  passed: boolean
  matched: {
    recommended_tools: string[]
    plugin_ids: string[]
    readiness_states: Record<string, string>
    blocked_tools: string[]
    missing_deps: string[]
    safety_gates: string[]
  }
  missing: {
    recommended_tools: string[]
    plugin_ids: string[]
    readiness_states: Record<string, string>
    blocked_tools: string[]
    missing_deps: string[]
    safety_gates: string[]
  }
  residual_gaps: string[]
}

export interface ReverseBenchmarkSummary {
  total_cases: number
  passed_cases: number
  failed_cases: number
  residual_gaps: string[]
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {}
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function stringValues(value: unknown): string[] {
  return asArray(value).filter((item): item is string => typeof item === 'string')
}

function pluginIdFromRecommendation(value: unknown): string | null {
  const recommendation = asRecord(value)
  const pluginId = recommendation.plugin_id
  return typeof pluginId === 'string' ? pluginId : null
}

function collectRecommendationTools(discoverData: unknown): string[] {
  const data = asRecord(discoverData)
  const fromTopLevel = stringValues(data.recommended_tools)
  const fromRecommendations = asArray(data.recommendations).flatMap((item) => {
    const recommendation = asRecord(item)
    return stringValues(recommendation.recommended_tools)
  })
  return uniqueStrings([...fromTopLevel, ...fromRecommendations])
}

function collectRecommendationPluginIds(discoverData: unknown): string[] {
  const data = asRecord(discoverData)
  const fromRecommendations = asArray(data.recommendations).flatMap((item) => {
    const pluginId = pluginIdFromRecommendation(item)
    return pluginId ? [pluginId] : []
  })
  const matrix = asRecord(data.plugin_matrix)
  const target = asRecord(matrix.target)
  return uniqueStrings([...fromRecommendations, ...stringValues(target.matched_plugins)])
}

function collectReadinessStates(discoverData: unknown): Record<string, string> {
  const states: Record<string, string> = {}
  for (const item of asArray(asRecord(discoverData).recommendations)) {
    const recommendation = asRecord(item)
    const pluginId = pluginIdFromRecommendation(item)
    const readiness = recommendation.readiness_state
    if (pluginId && typeof readiness === 'string') {
      states[pluginId] = readiness
    }
  }
  return states
}

function collectSafetyGates(discoverData: unknown): string[] {
  const gates: string[] = []
  for (const item of asArray(asRecord(discoverData).recommendations)) {
    const recommendation = asRecord(item)
    for (const profile of asArray(recommendation.backend_install_profile)) {
      const safetyGate = asRecord(profile).safety_gate
      if (typeof safetyGate === 'string') gates.push(safetyGate)
    }
  }
  return uniqueStrings(gates)
}

function missingStrings(expected: string[] | undefined, actual: string[]): string[] {
  const actualSet = new Set(actual)
  return (expected ?? []).filter((value) => !actualSet.has(value))
}

export function selectReverseBenchmarkCases(
  manifest: ReverseBenchmarkManifest,
  options: ReverseBenchmarkSelectionOptions = {}
): ReverseBenchmarkCase[] {
  const env = options.env ?? process.env
  const manifestExternalFlag = manifest.policy.external_corpus_env
  const includeExternal =
    options.includeExternalCorpus === true ||
    Boolean(manifestExternalFlag && env[manifestExternalFlag] === '1')

  return manifest.cases.filter((testCase) => {
    if (testCase.default_ci) return true
    if (testCase.fixture_mode !== 'external-corpus') return false
    const caseFlag = testCase.external_corpus?.env_flag
    return includeExternal || Boolean(caseFlag && env[caseFlag] === '1')
  })
}

export function evaluateReverseBenchmarkDiscoverCase(
  testCase: ReverseBenchmarkCase,
  discoverData: unknown
): ReverseBenchmarkDiscoverEvaluation {
  const expected = testCase.expected.discover
  const matched = {
    recommended_tools: collectRecommendationTools(discoverData),
    plugin_ids: collectRecommendationPluginIds(discoverData),
    readiness_states: collectReadinessStates(discoverData),
    blocked_tools: stringValues(asRecord(discoverData).blocked_tools),
    missing_deps: stringValues(asRecord(discoverData).missing_deps),
    safety_gates: collectSafetyGates(discoverData),
  }
  const missingReadiness = Object.fromEntries(
    Object.entries(expected.readiness_states ?? {}).filter(
      ([pluginId, state]) => matched.readiness_states[pluginId] !== state
    )
  )
  const missing = {
    recommended_tools: missingStrings(expected.recommended_tools, matched.recommended_tools),
    plugin_ids: missingStrings(expected.plugin_ids, matched.plugin_ids),
    readiness_states: missingReadiness,
    blocked_tools: missingStrings(expected.blocked_tools, matched.blocked_tools),
    missing_deps: missingStrings(expected.missing_deps, matched.missing_deps),
    safety_gates: missingStrings(expected.safety_gates, matched.safety_gates),
  }
  const passed =
    missing.recommended_tools.length === 0 &&
    missing.plugin_ids.length === 0 &&
    Object.keys(missing.readiness_states).length === 0 &&
    missing.blocked_tools.length === 0 &&
    missing.missing_deps.length === 0 &&
    missing.safety_gates.length === 0

  return {
    case_id: testCase.id,
    passed,
    matched,
    missing,
    residual_gaps: testCase.residual_gaps ?? [],
  }
}

export function summarizeReverseBenchmarkResults(
  results: ReverseBenchmarkDiscoverEvaluation[]
): ReverseBenchmarkSummary {
  return {
    total_cases: results.length,
    passed_cases: results.filter((result) => result.passed).length,
    failed_cases: results.filter((result) => !result.passed).length,
    residual_gaps: uniqueStrings(results.flatMap((result) => result.residual_gaps)),
  }
}
