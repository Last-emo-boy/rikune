import fs from 'fs/promises'
import type { DatabaseManager } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { ArtifactRef } from '../types.js'
import { loadDynamicTraceEvidence, type DynamicEvidenceScope, type DynamicTraceSummary } from './dynamic-trace.js'

export type EvidenceExpectationCategory =
  | 'network'
  | 'registry'
  | 'persistence'
  | 'environment_state'
  | 'encoded_config'
  | 'embedded_payload'
  | 'encrypted_or_packed_resource'
  | 'file_activity'
  | 'process'
  | 'injection'
  | 'crypto'
  | 'anti_analysis'
  | 'execution'
  | 'memory'
  | 'dynamic_resolution'
  | 'unknown'

export interface CorrelationArtifactPayload {
  artifact: ArtifactRef & { created_at?: string }
  payload: Record<string, unknown>
}

export interface EvidenceExpectation {
  id: string
  category: EvidenceExpectationCategory
  label: string
  value: string
  confidence: number
  source_artifact_id: string
  source_artifact_type: string
  evidence: string[]
}

export interface RuntimeObservation {
  id: string
  category: EvidenceExpectationCategory
  label: string
  value: string
  confidence: number
  source: string
  evidence: string[]
}

export interface EvidenceCorrelationBundle {
  sample_id: string
  static_artifacts: CorrelationArtifactPayload[]
  dynamic_summary: DynamicTraceSummary | null
  expectations: EvidenceExpectation[]
  observations: RuntimeObservation[]
  warnings: string[]
}

export interface EvidenceGraphNode {
  id: string
  kind: 'sample' | 'artifact' | 'expectation' | 'observation'
  label: string
  category?: string
  confidence?: number
  source?: string
  details?: Record<string, unknown>
}

export interface EvidenceGraphEdge {
  from: string
  to: string
  label: string
  confidence: number
}

export interface EvidenceGraph {
  nodes: EvidenceGraphNode[]
  edges: EvidenceGraphEdge[]
}

export interface BehaviorDiff {
  confirmed_behaviors: Array<{
    category: EvidenceExpectationCategory
    expectation: EvidenceExpectation
    observations: RuntimeObservation[]
  }>
  missing_expectations: EvidenceExpectation[]
  unexpected_observations: RuntimeObservation[]
  coverage: {
    expected_category_count: number
    observed_category_count: number
    confirmed_category_count: number
    expectation_count: number
    observation_count: number
    missing_count: number
    unexpected_count: number
    dynamic_executed: boolean
  }
  hypotheses: string[]
  recommended_next_tools: string[]
}

export interface LoadCorrelationEvidenceOptions {
  evidenceScope?: DynamicEvidenceScope
  sessionTag?: string
  maxStaticArtifacts?: number
}

const STATIC_ARTIFACT_TYPES = [
  'static_config_carver',
  'static_resource_graph',
  'static_capability_triage',
  'compiler_packer_attribution',
]

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function readString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function readNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function sanitizeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9_.:-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 120) || 'item'
}

function artifactRef(artifact: { id: string; type: string; path: string; sha256: string; mime?: string | null; created_at?: string }): ArtifactRef & { created_at?: string } {
  return {
    id: artifact.id,
    type: artifact.type,
    path: artifact.path,
    sha256: artifact.sha256,
    mime: artifact.mime || undefined,
    created_at: artifact.created_at,
  }
}

async function readArtifactPayload(
  workspaceManager: WorkspaceManager,
  sampleId: string,
  artifact: ArtifactRef
): Promise<Record<string, unknown> | null> {
  try {
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
    const raw = await fs.readFile(absolutePath, 'utf8')
    return asRecord(JSON.parse(raw))
  } catch {
    return null
  }
}

function configExpectationCategory(candidate: Record<string, unknown>): EvidenceExpectationCategory {
  const kind = readString(candidate.kind)
  const value = readString(candidate.value).toLowerCase()
  if (['url', 'domain', 'ip', 'ip_port', 'user_agent_or_http_client'].includes(kind)) return 'network'
  if (kind === 'registry_path') {
    if (/\\run|\\runonce|\\services|winlogon|startup/i.test(value)) return 'persistence'
    return 'registry'
  }
  if (kind === 'mutex_like' || kind === 'guid_or_mutex') return 'environment_state'
  if (kind === 'config_keyword_string') {
    if (/sleep|interval|debugger|sandbox|vmware|virtualbox/.test(value)) return 'anti_analysis'
    if (/gate|panel|beacon|campaign|botid|install_id/.test(value)) return 'network'
  }
  return 'unknown'
}

function expectationsFromConfigArtifact(artifact: ArtifactRef, payload: Record<string, unknown>): EvidenceExpectation[] {
  const expectations: EvidenceExpectation[] = []
  let index = 0
  for (const candidateValue of asArray(payload.candidates)) {
    const candidate = asRecord(candidateValue)
    if (!candidate) continue
    const value = readString(candidate.value)
    if (!value) continue
    const category = configExpectationCategory(candidate)
    expectations.push({
      id: `expect:${artifact.id}:${index++}`,
      category,
      label: `${category}:${readString(candidate.kind) || 'candidate'}`,
      value,
      confidence: readNumber(candidate.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: asArray(candidate.evidence).map(readString).filter(Boolean),
    })
  }

  for (const blobValue of asArray(payload.blob_candidates)) {
    const blob = asRecord(blobValue)
    if (!blob) continue
    expectations.push({
      id: `expect:${artifact.id}:blob:${index++}`,
      category: 'encoded_config',
      label: `encoded_blob:${readString(blob.kind) || 'blob'}`,
      value: readString(blob.value_preview) || readString(blob.kind) || 'encoded blob',
      confidence: readNumber(blob.confidence, 0.48),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: asArray(blob.evidence).map(readString).filter(Boolean),
    })
  }

  return expectations
}

function expectationsFromResourceArtifact(artifact: ArtifactRef, payload: Record<string, unknown>): EvidenceExpectation[] {
  const expectations: EvidenceExpectation[] = []
  let index = 0
  for (const resourceValue of asArray(payload.resources)) {
    const resource = asRecord(resourceValue)
    if (!resource) continue
    const pathParts = asArray(resource.path).map(readString).filter(Boolean)
    const label = pathParts.length > 0 ? pathParts.join('/') : `resource_${index}`
    const magic = readString(resource.magic)
    const entropy = readNumber(resource.entropy, 0)
    const size = readNumber(resource.size, 0)
    const previews = asArray(resource.stringPreview).map(readString).filter(Boolean)

    if (['pe_or_dos', 'elf', 'zip', 'cab'].includes(magic)) {
      expectations.push({
        id: `expect:${artifact.id}:resource:${index++}`,
        category: 'embedded_payload',
        label: `embedded_payload:${magic}`,
        value: label,
        confidence: 0.82,
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: [`magic=${magic}`, `size=${size}`],
      })
    }
    if (entropy >= 7.2) {
      expectations.push({
        id: `expect:${artifact.id}:resource:${index++}`,
        category: 'encrypted_or_packed_resource',
        label: 'high_entropy_resource',
        value: label,
        confidence: 0.74,
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: [`entropy=${entropy}`, `size=${size}`],
      })
    }
    for (const preview of previews) {
      if (/https?:\/\//i.test(preview)) {
        expectations.push({
          id: `expect:${artifact.id}:resource:${index++}`,
          category: 'network',
          label: 'resource_url_string',
          value: preview,
          confidence: 0.68,
          source_artifact_id: artifact.id,
          source_artifact_type: artifact.type,
          evidence: [`resource=${label}`],
        })
      }
    }
  }

  return expectations
}

function categoryFromApi(api: string): EvidenceExpectationCategory {
  if (/Reg(Open|Set|Query|Create|Delete)|NtSetValueKey/i.test(api)) return 'registry'
  if (/RunOnce|CreateService|StartService|schtasks|WMI|Winlogon/i.test(api)) return 'persistence'
  if (/WSA|socket|connect|send|recv|Internet|Http|WinHttp|URLDownload|Dns/i.test(api)) return 'network'
  if (/CreateFile|ReadFile|WriteFile|DeleteFile|CopyFile|MoveFile|FindFirstFile/i.test(api)) return 'file_activity'
  if (/CreateProcess|ShellExecute|WinExec|OpenProcess|TerminateProcess/i.test(api)) return 'process'
  if (/WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|SetThreadContext|NtMapViewOfSection|QueueUserAPC/i.test(api)) return 'injection'
  if (/Crypt|BCrypt|NCrypt|Hash|RtlDecrypt|SystemFunction0/i.test(api)) return 'crypto'
  if (/IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|NtQuerySystemInformation|GetTickCount|QueryPerformanceCounter|Sleep/i.test(api)) return 'anti_analysis'
  if (/VirtualAlloc|VirtualProtect|LoadLibrary|CreateThread|ResumeThread/i.test(api)) return 'execution'
  if (/ReadProcessMemory|MiniDump|VirtualQuery/i.test(api)) return 'memory'
  if (/GetProcAddress|LdrGetProcedureAddress/i.test(api)) return 'dynamic_resolution'
  return 'unknown'
}

function categoryFromStage(stage: string): EvidenceExpectationCategory {
  if (/network/i.test(stage)) return 'network'
  if (/registry|persistence|service/i.test(stage)) return 'registry'
  if (/file/i.test(stage)) return 'file_activity'
  if (/process/i.test(stage)) return 'process'
  if (/inject|remote_process/i.test(stage)) return 'injection'
  if (/crypto|decrypt|encrypt/i.test(stage)) return 'crypto'
  if (/anti|debug|sandbox|analysis/i.test(stage)) return 'anti_analysis'
  if (/resolve/i.test(stage)) return 'dynamic_resolution'
  if (/memory|dump|region/i.test(stage)) return 'memory'
  return 'unknown'
}

function observationsFromDynamicSummary(summary: DynamicTraceSummary | null): RuntimeObservation[] {
  if (!summary) return []
  const observations: RuntimeObservation[] = []
  let index = 0
  for (const api of summary.observed_apis || []) {
    const category = categoryFromApi(api)
    if (category === 'unknown') continue
    observations.push({
      id: `obs:api:${index++}:${sanitizeId(api)}`,
      category,
      label: `api:${api}`,
      value: api,
      confidence: summary.executed ? 0.9 : 0.62,
      source: 'dynamic_trace',
      evidence: summary.high_signal_apis?.includes(api) ? ['high_signal_api'] : [],
    })
  }
  for (const stage of summary.stages || []) {
    const category = categoryFromStage(stage)
    if (category === 'unknown') continue
    observations.push({
      id: `obs:stage:${index++}:${sanitizeId(stage)}`,
      category,
      label: `stage:${stage}`,
      value: stage,
      confidence: summary.executed ? 0.82 : 0.58,
      source: 'dynamic_trace',
      evidence: ['derived_stage'],
    })
  }
  for (const region of summary.memory_regions || []) {
    observations.push({
      id: `obs:memory:${index++}:${sanitizeId(region)}`,
      category: 'memory',
      label: 'memory_region',
      value: region,
      confidence: summary.executed ? 0.78 : 0.55,
      source: 'dynamic_trace',
      evidence: ['memory_region'],
    })
  }
  return observations
}

export function categoriesCompatible(expected: EvidenceExpectationCategory, observed: EvidenceExpectationCategory): boolean {
  if (expected === observed) return true
  if (expected === 'persistence' && observed === 'registry') return true
  if (expected === 'embedded_payload' && ['memory', 'execution', 'injection', 'process'].includes(observed)) return true
  if (expected === 'encrypted_or_packed_resource' && ['memory', 'crypto', 'execution'].includes(observed)) return true
  if (expected === 'encoded_config' && ['crypto', 'network', 'registry'].includes(observed)) return true
  if (expected === 'environment_state' && ['anti_analysis', 'process', 'registry'].includes(observed)) return true
  return false
}

export async function loadCorrelationEvidence(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  options: LoadCorrelationEvidenceOptions = {}
): Promise<EvidenceCorrelationBundle> {
  const warnings: string[] = []
  const staticArtifacts: CorrelationArtifactPayload[] = []
  const maxStaticArtifacts = options.maxStaticArtifacts ?? 20

  for (const artifactType of STATIC_ARTIFACT_TYPES) {
    const artifacts = database.findArtifactsByType(sampleId, artifactType).slice(0, maxStaticArtifacts)
    for (const dbArtifact of artifacts) {
      const artifact = artifactRef(dbArtifact)
      const payload = await readArtifactPayload(workspaceManager, sampleId, artifact)
      if (payload) {
        staticArtifacts.push({ artifact, payload })
      }
    }
  }

  const expectations = staticArtifacts.flatMap(({ artifact, payload }) => {
    if (artifact.type === 'static_config_carver') return expectationsFromConfigArtifact(artifact, payload)
    if (artifact.type === 'static_resource_graph') return expectationsFromResourceArtifact(artifact, payload)
    return []
  })

  const dynamicSummary = await loadDynamicTraceEvidence(workspaceManager, database, sampleId, {
    evidenceScope: options.evidenceScope || 'all',
    sessionTag: options.sessionTag,
  })
  const observations = observationsFromDynamicSummary(dynamicSummary)

  if (staticArtifacts.length === 0) {
    warnings.push('No specialist static artifacts found. Run static.config.carver and static.resource.graph for richer correlation.')
  }
  if (!dynamicSummary) {
    warnings.push('No dynamic trace artifacts found. Run dynamic.behavior.capture, sandbox.execute, or dynamic.trace.import for runtime correlation.')
  }

  return {
    sample_id: sampleId,
    static_artifacts: staticArtifacts,
    dynamic_summary: dynamicSummary,
    expectations,
    observations,
    warnings,
  }
}

export function buildEvidenceGraph(bundle: EvidenceCorrelationBundle): EvidenceGraph {
  const nodes: EvidenceGraphNode[] = [
    {
      id: `sample:${bundle.sample_id}`,
      kind: 'sample',
      label: bundle.sample_id,
      details: {
        static_artifact_count: bundle.static_artifacts.length,
        expectation_count: bundle.expectations.length,
        observation_count: bundle.observations.length,
      },
    },
  ]
  const edges: EvidenceGraphEdge[] = []

  for (const { artifact } of bundle.static_artifacts) {
    const artifactNodeId = `artifact:${artifact.id}`
    nodes.push({
      id: artifactNodeId,
      kind: 'artifact',
      label: artifact.type,
      category: artifact.type,
      source: artifact.path,
      details: { artifact_id: artifact.id, sha256: artifact.sha256 },
    })
    edges.push({ from: `sample:${bundle.sample_id}`, to: artifactNodeId, label: 'has_artifact', confidence: 1 })
  }

  if (bundle.dynamic_summary) {
    nodes.push({
      id: 'artifact:dynamic_trace_summary',
      kind: 'artifact',
      label: 'dynamic_trace_summary',
      category: 'dynamic_trace',
      details: {
        artifact_count: bundle.dynamic_summary.artifact_count,
        executed: bundle.dynamic_summary.executed,
        scope_note: bundle.dynamic_summary.scope_note,
      },
    })
    edges.push({ from: `sample:${bundle.sample_id}`, to: 'artifact:dynamic_trace_summary', label: 'has_runtime_evidence', confidence: 1 })
  }

  for (const expectation of bundle.expectations) {
    const nodeId = expectation.id
    nodes.push({
      id: nodeId,
      kind: 'expectation',
      label: expectation.label,
      category: expectation.category,
      confidence: expectation.confidence,
      source: expectation.source_artifact_type,
      details: {
        value: expectation.value,
        evidence: expectation.evidence,
      },
    })
    edges.push({ from: `artifact:${expectation.source_artifact_id}`, to: nodeId, label: 'suggests', confidence: expectation.confidence })
  }

  for (const observation of bundle.observations) {
    const nodeId = observation.id
    nodes.push({
      id: nodeId,
      kind: 'observation',
      label: observation.label,
      category: observation.category,
      confidence: observation.confidence,
      source: observation.source,
      details: {
        value: observation.value,
        evidence: observation.evidence,
      },
    })
    edges.push({ from: 'artifact:dynamic_trace_summary', to: nodeId, label: 'observed', confidence: observation.confidence })
  }

  for (const expectation of bundle.expectations) {
    for (const observation of bundle.observations) {
      if (categoriesCompatible(expectation.category, observation.category)) {
        edges.push({
          from: expectation.id,
          to: observation.id,
          label: 'corroborated_by',
          confidence: Number(Math.min(expectation.confidence, observation.confidence).toFixed(3)),
        })
      }
    }
  }

  return { nodes, edges }
}

function hypothesisForMissingExpectation(expectation: EvidenceExpectation): string {
  switch (expectation.category) {
    case 'network':
      return `Network indicator "${expectation.value}" was not observed at runtime; try a longer run, network sinkhole, DNS/HTTP fake services, or a richer persona.`
    case 'persistence':
    case 'registry':
      return `Registry/persistence hint "${expectation.value}" was not observed; try a longer behavior capture or Hyper-V telemetry profile.`
    case 'embedded_payload':
    case 'encrypted_or_packed_resource':
      return `Resource payload "${expectation.value}" was not observed executing; try memory dump, breakpoint planning, unpack handoff, or a trigger-specific persona.`
    case 'encoded_config':
      return `Encoded config candidate "${expectation.value}" was not observed decoded; try crypto/key lifecycle tracing or memory dump scanning.`
    case 'anti_analysis':
    case 'environment_state':
      return `Environment-sensitive hint "${expectation.value}" was not observed; try dynamic.persona.plan and anti-evasion hooks.`
    default:
      return `Static expectation "${expectation.value}" was not observed in runtime evidence.`
  }
}

export function buildBehaviorDiff(bundle: EvidenceCorrelationBundle): BehaviorDiff {
  const confirmed: BehaviorDiff['confirmed_behaviors'] = []
  const missing: EvidenceExpectation[] = []
  const observedMatches = new Set<string>()

  for (const expectation of bundle.expectations) {
    const matching = bundle.observations.filter((observation) => categoriesCompatible(expectation.category, observation.category))
    if (matching.length > 0) {
      confirmed.push({ category: expectation.category, expectation, observations: matching })
      for (const observation of matching) observedMatches.add(observation.id)
    } else {
      missing.push(expectation)
    }
  }

  const unexpected = bundle.observations.filter((observation) => !observedMatches.has(observation.id))
  const expectedCategories = new Set(bundle.expectations.map((item) => item.category))
  const observedCategories = new Set(bundle.observations.map((item) => item.category))
  const confirmedCategories = new Set(confirmed.map((item) => item.category))
  const hypotheses = Array.from(new Set(missing.slice(0, 12).map(hypothesisForMissingExpectation)))
  const recommendedNextTools = new Set<string>([
    'dynamic.persona.plan',
    'dynamic.deep_plan',
    'dynamic.behavior.capture',
    'dynamic.toolkit.status',
    'analysis.evidence.graph',
  ])
  if (missing.some((item) => ['embedded_payload', 'encrypted_or_packed_resource', 'encoded_config'].includes(item.category))) {
    recommendedNextTools.add('dynamic.memory_dump')
    recommendedNextTools.add('breakpoint.smart')
  }
  if (missing.some((item) => item.category === 'network')) {
    recommendedNextTools.add('dynamic.behavior.capture')
  }

  return {
    confirmed_behaviors: confirmed,
    missing_expectations: missing,
    unexpected_observations: unexpected,
    coverage: {
      expected_category_count: expectedCategories.size,
      observed_category_count: observedCategories.size,
      confirmed_category_count: confirmedCategories.size,
      expectation_count: bundle.expectations.length,
      observation_count: bundle.observations.length,
      missing_count: missing.length,
      unexpected_count: unexpected.length,
      dynamic_executed: Boolean(bundle.dynamic_summary?.executed),
    },
    hypotheses,
    recommended_next_tools: Array.from(recommendedNextTools),
  }
}
