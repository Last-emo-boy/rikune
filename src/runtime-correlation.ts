import type { DynamicTraceSummary } from './dynamic-trace.js'

export interface RuntimeCorrelationInput {
  functionName?: string
  moduleName?: string
  behaviorTags?: string[]
  xrefApis?: string[]
  rankReasons?: string[]
  semanticSummary?: string
  stringHints?: string[]
  callTargets?: string[]
}

export interface RuntimeCorrelation {
  corroborated_apis: string[]
  corroborated_stages: string[]
  notes: string[]
  confidence: number
  executed?: boolean
  evidence_sources?: string[]
  source_names?: string[]
  artifact_count?: number
  executed_artifact_count?: number
  matched_memory_regions?: string[]
  suggested_modules?: string[]
  matched_by?: string[]
  provenance_layers?: string[]
  latest_artifact_at?: string | null
  scope_note?: string
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values.map((item) => item.trim()).filter((item) => item.length > 0)))
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}

function summarizeEvidenceSources(dynamicEvidence: DynamicTraceSummary): string[] {
  const formats = dynamicEvidence.source_formats || []
  const kinds = dynamicEvidence.evidence_kinds || []
  const pairCount = Math.max(formats.length, kinds.length)
  const pairs: string[] = []

  for (let index = 0; index < pairCount; index += 1) {
    const format = formats[index] || formats[formats.length - 1] || 'runtime'
    const kind = kinds[index] || kinds[kinds.length - 1] || 'hybrid'
    pairs.push(`${format}:${kind}`)
  }

  if (pairs.length > 0) {
    return dedupe(pairs).slice(0, 6)
  }

  return dynamicEvidence.executed ? ['runtime:trace'] : ['runtime:memory_snapshot']
}

function summarizeSourceNames(dynamicEvidence: DynamicTraceSummary): string[] {
  return dedupe(dynamicEvidence.source_names || []).slice(0, 6)
}

function summarizeProvenanceLayers(dynamicEvidence: DynamicTraceSummary): string[] {
  return (dynamicEvidence.confidence_layers || []).map(
    (item) => `${item.layer}(${item.artifact_count})`
  )
}

export function normalizeRuntimeApiName(value: string): string {
  return value.trim().replace(/\(.*/, '').replace(/^.*!/, '').replace(/^.*\./, '')
}

export function extractSensitiveApisFromReasons(rankReasons: string[] = []): string[] {
  const apis: string[] = []
  for (const reason of rankReasons) {
    const match = /^calls_sensitive_api:(.+)$/i.exec(reason)
    if (!match) {
      continue
    }
    const api = normalizeRuntimeApiName(match[1])
    if (api.length > 0) {
      apis.push(api)
    }
  }
  return dedupe(apis)
}

function collectCandidateApis(input: RuntimeCorrelationInput): string[] {
  const fromCallTargets = (input.callTargets || [])
    .map((item) => normalizeRuntimeApiName(item))
    .filter((item) => /^[A-Za-z_][A-Za-z0-9_]+(?:W|A)?$/.test(item))
  return dedupe([
    ...(input.xrefApis || []).map((item) => normalizeRuntimeApiName(item)),
    ...extractSensitiveApisFromReasons(input.rankReasons || []),
    ...fromCallTargets,
  ])
}

function buildSemanticCorpus(input: RuntimeCorrelationInput): string {
  return [
    input.functionName || '',
    input.moduleName || '',
    input.semanticSummary || '',
    ...(input.stringHints || []),
    ...(input.callTargets || []),
  ]
    .join('\n')
    .toLowerCase()
}

export function deriveRuntimeStageCandidates(input: RuntimeCorrelationInput): string[] {
  const behaviorTags = new Set((input.behaviorTags || []).map((item) => item.toLowerCase()))
  const apis = collectCandidateApis(input)
  const apiCorpus = apis.join(' ').toLowerCase()
  const semanticCorpus = buildSemanticCorpus(input)
  const stages = new Set<string>()

  if (
    /\b(getprocaddress|loadlibrary|getmodulehandle)\b/i.test(apiCorpus) ||
    semanticCorpus.includes('dynamic api') ||
    semanticCorpus.includes('dispatch table') ||
    semanticCorpus.includes('resolver')
  ) {
    stages.add('resolve_dynamic_apis')
  }

  if (
    behaviorTags.has('process_injection') ||
    behaviorTags.has('process_spawn') ||
    /\b(openprocess|writeprocessmemory|readprocessmemory|setthreadcontext|resumethread|createremotethread|virtualallocex|createprocess)\b/i.test(
      apiCorpus
    ) ||
    semanticCorpus.includes('remote process') ||
    semanticCorpus.includes('thread context')
  ) {
    stages.add('prepare_remote_process_access')
  }

  if (
    behaviorTags.has('anti_debug') ||
    /\b(ntqueryinformationprocess|ntquerysysteminformation|isdebuggerpresent|checkremotedebuggerpresent)\b/i.test(
      apiCorpus
    ) ||
    semanticCorpus.includes('code integrity') ||
    semanticCorpus.includes('execution environment') ||
    semanticCorpus.includes('anti-analysis')
  ) {
    stages.add('anti_analysis_checks')
    stages.add('check_execution_environment')
  }

  if (
    behaviorTags.has('file_io') ||
    /\b(createfile|readfile|writefile|deletefile|copyfile|findfirstfile|findnextfile)\b/i.test(
      apiCorpus
    ) ||
    semanticCorpus.includes('file system') ||
    semanticCorpus.includes('on-disk')
  ) {
    stages.add('file_operations')
  }

  if (
    behaviorTags.has('registry') ||
    /\b(regopenkey|regcreatekey|regsetvalue|regqueryvalue|regdeletekey)\b/i.test(apiCorpus) ||
    semanticCorpus.includes('registry')
  ) {
    stages.add('registry_operations')
    stages.add('stage_registry_state')
  }

  if (
    semanticCorpus.includes('packer') ||
    semanticCorpus.includes('entropy') ||
    semanticCorpus.includes('section') ||
    semanticCorpus.includes('protector') ||
    semanticCorpus.includes('overlay')
  ) {
    stages.add('scan_pe_layout')
  }

  return Array.from(stages)
}

function regionMatchersForStage(stage: string): RegExp[] {
  switch (stage) {
    case 'resolve_dynamic_apis':
      return [/resolution/i, /dispatch/i, /api/i, /loader/i]
    case 'prepare_remote_process_access':
      return [/process/i, /remote/i, /thread/i, /injection/i]
    case 'anti_analysis_checks':
    case 'check_execution_environment':
      return [/analysis/i, /integrity/i, /environment/i, /telemetry/i]
    case 'file_operations':
      return [/file/i, /path/i, /filesystem/i]
    case 'registry_operations':
    case 'stage_registry_state':
      return [/registry/i, /key/i]
    case 'scan_pe_layout':
      return [/packer/i, /entropy/i, /section/i, /layout/i]
    default:
      return []
  }
}

function collectMatchedMemoryRegions(
  candidateStages: string[],
  input: RuntimeCorrelationInput,
  dynamicEvidence: DynamicTraceSummary
): string[] {
  const semanticCorpus = buildSemanticCorpus(input)
  const matched = new Set<string>()
  const regions = dynamicEvidence.memory_regions || []

  for (const region of regions) {
    const lowered = region.toLowerCase()
    for (const stage of candidateStages) {
      if (regionMatchersForStage(stage).some((matcher) => matcher.test(lowered))) {
        matched.add(region)
      }
    }
    if (semanticCorpus.includes('dispatch') && /dispatch|resolution|api/i.test(lowered)) {
      matched.add(region)
    }
    if (semanticCorpus.includes('process') && /process|thread|remote/i.test(lowered)) {
      matched.add(region)
    }
    if (semanticCorpus.includes('registry') && /registry|key/i.test(lowered)) {
      matched.add(region)
    }
  }

  return Array.from(matched).slice(0, 6)
}

export function correlateFunctionWithRuntimeEvidence(
  input: RuntimeCorrelationInput,
  dynamicEvidence: DynamicTraceSummary | null | undefined
): RuntimeCorrelation | undefined {
  if (!dynamicEvidence) {
    return undefined
  }

  const candidateApis = collectCandidateApis(input)
  const observedMap = new Map(
    (dynamicEvidence.observed_apis || []).map((item) => [normalizeRuntimeApiName(item).toLowerCase(), item])
  )
  const highSignalSet = new Set(
    (dynamicEvidence.high_signal_apis || []).map((item) => normalizeRuntimeApiName(item).toLowerCase())
  )
  const matchedApis = candidateApis
    .map((item) => observedMap.get(item.toLowerCase()) || '')
    .filter((item) => item.length > 0)
  const candidateStages = deriveRuntimeStageCandidates(input)
  const observedStages = new Set((dynamicEvidence.stages || []).map((item) => item.toLowerCase()))
  const matchedStages = candidateStages.filter((item) => observedStages.has(item.toLowerCase()))
  const matchedMemoryRegions = collectMatchedMemoryRegions(candidateStages, input, dynamicEvidence)
  const evidenceSources = summarizeEvidenceSources(dynamicEvidence)
  const sourceNames = summarizeSourceNames(dynamicEvidence)
  const provenanceLayers = summarizeProvenanceLayers(dynamicEvidence)
  const matchedBy = dedupe([
    (input.xrefApis || []).length > 0 ? 'xref_api' : '',
    (input.rankReasons || []).length > 0 ? 'rank_reason' : '',
    (input.callTargets || []).length > 0 ? 'call_target' : '',
    (input.stringHints || []).length > 0 ? 'string_hint' : '',
    input.semanticSummary ? 'semantic_summary' : '',
  ])

  if (matchedApis.length === 0 && matchedStages.length === 0 && matchedMemoryRegions.length === 0) {
    return undefined
  }

  const highSignalMatches = matchedApis.filter((item) =>
    highSignalSet.has(normalizeRuntimeApiName(item).toLowerCase())
  )
  const notes: string[] = []
  if (matchedApis.length > 0) {
    notes.push(`Runtime-observed APIs overlap with this function: ${dedupe(matchedApis).slice(0, 6).join(', ')}`)
  }
  if (matchedStages.length > 0) {
    notes.push(`Runtime stages align with this function: ${dedupe(matchedStages).slice(0, 4).join(', ')}`)
  }
  if (matchedMemoryRegions.length > 0) {
    notes.push(`Runtime memory regions align with this function: ${matchedMemoryRegions.slice(0, 4).join(', ')}`)
  }
  if (dynamicEvidence.executed) {
    notes.push('Correlation includes executed runtime evidence, not just static or memory-only hints.')
  }
  if (evidenceSources.length > 0) {
    notes.push(`Runtime evidence sources: ${evidenceSources.join(', ')}`)
  }
  if (sourceNames.length > 0) {
    notes.push(`Runtime source names: ${sourceNames.join(', ')}`)
  }
  if (provenanceLayers.length > 0) {
    notes.push(`Runtime evidence layers: ${provenanceLayers.join(', ')}`)
  }
  if (dynamicEvidence.scope_note) {
    notes.push(dynamicEvidence.scope_note)
  }
  if ((dynamicEvidence.executed_artifact_count || 0) > 0) {
    notes.push(
      `Matched against ${dynamicEvidence.executed_artifact_count} executed runtime artifact(s).`
    )
  }

  const suggestedModules = dedupe([
    ...modulesSuggestedByRuntimeStages(matchedStages),
    ...(matchedMemoryRegions.some((item) => /process|thread|dispatch|resolution|command/i.test(item))
      ? ['process_ops']
      : []),
    ...(matchedMemoryRegions.some((item) => /registry|key/i.test(item)) ? ['registry_ops'] : []),
    ...(matchedMemoryRegions.some((item) => /analysis|integrity|environment/i.test(item))
      ? ['anti_analysis']
      : []),
    ...(matchedMemoryRegions.some((item) => /packer|entropy|section|layout/i.test(item))
      ? ['packer_analysis']
      : []),
    ...(matchedMemoryRegions.some((item) => /network|socket|http|pipe|ipc/i.test(item))
      ? ['network_ops']
      : []),
  ])

  if (suggestedModules.length > 0) {
    notes.push(`Suggested semantic modules: ${suggestedModules.slice(0, 4).join(', ')}`)
  }

  const confidence = clamp(
    0.42 +
      Math.min(0.24, dedupe(matchedApis).length * 0.08) +
      Math.min(0.16, dedupe(matchedStages).length * 0.06) +
      Math.min(0.12, highSignalMatches.length * 0.05) +
      Math.min(0.1, matchedMemoryRegions.length * 0.04),
    0.45,
    0.97
  )

  return {
    corroborated_apis: dedupe(matchedApis).slice(0, 8),
    corroborated_stages: dedupe(matchedStages).slice(0, 6),
    notes: dedupe(notes).slice(0, 5),
    confidence: Number(confidence.toFixed(2)),
    executed: dynamicEvidence.executed,
    evidence_sources: evidenceSources,
    source_names: sourceNames,
    artifact_count: dynamicEvidence.artifact_count,
    executed_artifact_count: dynamicEvidence.executed_artifact_count || 0,
    matched_memory_regions: matchedMemoryRegions,
    suggested_modules: suggestedModules,
    matched_by: matchedBy,
    provenance_layers: provenanceLayers,
    latest_artifact_at: dynamicEvidence.latest_imported_at || null,
    scope_note: dynamicEvidence.scope_note,
  }
}

export function modulesSuggestedByRuntimeStages(stages: string[] = []): string[] {
  const modules = new Set<string>()
  for (const stage of stages.map((item) => item.toLowerCase())) {
    if (stage === 'prepare_remote_process_access' || stage === 'launch_operator_command') {
      modules.add('process_ops')
    } else if (stage === 'file_operations') {
      modules.add('file_ops')
    } else if (stage === 'registry_operations' || stage === 'stage_registry_state') {
      modules.add('registry_ops')
    } else if (stage === 'anti_analysis_checks' || stage === 'check_execution_environment') {
      modules.add('anti_analysis')
    } else if (stage === 'scan_pe_layout') {
      modules.add('packer_analysis')
    } else if (stage === 'resolve_dynamic_apis') {
      modules.add('process_ops')
    }
  }
  return Array.from(modules)
}
