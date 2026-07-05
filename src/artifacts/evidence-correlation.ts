import fs from 'fs/promises'
import type { DatabaseManager } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { ArtifactRef } from '../types.js'
import {
  loadDynamicTraceEvidence,
  type DynamicEvidenceScope,
  type DynamicTraceSummary,
} from './dynamic-trace.js'

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
  plugin_evidence?: PluginEvidence[]
  warnings: string[]
}

export interface EvidenceGraphNode {
  id: string
  kind:
    | 'sample'
    | 'artifact'
    | 'expectation'
    | 'observation'
    | 'plugin_evidence'
    | 'function_handoff'
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

export interface PluginEvidence {
  id: string
  kind:
    | 'ioc'
    | 'behavior_cluster'
    | 'triage_signal'
    | 'capability'
    | 'workflow_route'
    | 'stable_function'
    | 'disputed_function'
    | 'backend_gap'
  category: string
  label: string
  value: string
  confidence: number
  source_artifact_id: string
  source_artifact_type: string
  evidence: string[]
  recommended_tools?: string[]
  details?: Record<string, unknown>
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
  'static_behavior_classifier',
  'crypto_identification',
  'compiler_packer_attribution',
  'static_triage_correlation_bundle',
  'malware_intel_loop',
  'api_hash_resolver_plan',
  'cross_decompiler_consensus',
  'function_evidence_handoff',
  'enriched_string_analysis',
  'backend_die_scan',
  'backend_yara_scan',
  'backend_yara_x_scan',
  'backend_upx_list',
  'backend_upx_test',
  'yara_rule_generation',
  'yara_family_rule',
  'sigma_rules',
  'ioc_export_json',
  'ioc_export_csv',
  'ioc_export_stix2',
  'metadata',
  'container_structure',
  'windows_installer_inventory',
  'binary_diff',
  'cross_module_graph',
  'cyclonedx_sbom',
  'spdx_lite_sbom',
  'sbom_generation_evidence',
]

const PLUGIN_EVIDENCE_ARTIFACT_TYPES = new Set([
  'static_config_carver',
  'static_resource_graph',
  'static_capability_triage',
  'static_behavior_classifier',
  'crypto_identification',
  'compiler_packer_attribution',
  'static_triage_correlation_bundle',
  'malware_intel_loop',
  'api_hash_resolver_plan',
  'cross_decompiler_consensus',
  'function_evidence_handoff',
  'enriched_string_analysis',
  'backend_die_scan',
  'backend_yara_scan',
  'backend_yara_x_scan',
  'backend_upx_list',
  'backend_upx_test',
  'yara_rule_generation',
  'yara_family_rule',
  'sigma_rules',
  'ioc_export_json',
  'ioc_export_csv',
  'ioc_export_stix2',
  'metadata',
  'container_structure',
  'windows_installer_inventory',
  'binary_diff',
  'cross_module_graph',
  'cyclonedx_sbom',
  'spdx_lite_sbom',
  'sbom_generation_evidence',
])

const GENERIC_WORKFLOW_HANDOFF_ARTIFACT_TYPES = new Set([
  'metadata',
  'container_structure',
  'windows_installer_inventory',
  'binary_diff',
  'cross_module_graph',
  'cyclonedx_sbom',
  'spdx_lite_sbom',
  'sbom_generation_evidence',
])

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

function readStringList(value: unknown, limit = 12): string[] {
  return asArray(value).map(readString).filter(Boolean).slice(0, limit)
}

function readNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function boundedConfidence(value: unknown, fallback: number): number {
  return Number(Math.max(0, Math.min(1, readNumber(value, fallback))).toFixed(3))
}

function unwrapPayload(payload: Record<string, unknown>): Record<string, unknown> {
  return asRecord(payload.data) ?? payload
}

function sanitizeId(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9_.:-]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 120) || 'item'
  )
}

function artifactRef(artifact: {
  id: string
  type: string
  path: string
  sha256: string
  mime?: string | null
  created_at?: string
}): ArtifactRef & { created_at?: string } {
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
    if (artifact.type === 'ioc_export_csv') {
      return { schema: 'rikune.ioc_export_csv.raw.v1', content: raw }
    }
    return asRecord(JSON.parse(raw))
  } catch {
    return null
  }
}

function configExpectationCategory(
  candidate: Record<string, unknown>
): EvidenceExpectationCategory {
  const kind = readString(candidate.kind)
  const value = readString(candidate.value).toLowerCase()
  if (['url', 'domain', 'ip', 'ip_port', 'user_agent_or_http_client'].includes(kind))
    return 'network'
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

function expectationsFromConfigArtifact(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): EvidenceExpectation[] {
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

function expectationsFromResourceArtifact(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): EvidenceExpectation[] {
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

function categoryFromIocType(type: string): EvidenceExpectationCategory {
  if (['url', 'domain', 'ip', 'ip_port', 'user_agent_or_http_client'].includes(type))
    return 'network'
  if (['mutex', 'guid', 'guid_or_mutex'].includes(type)) return 'environment_state'
  if (/reg/i.test(type)) return 'registry'
  if (/file|path/i.test(type)) return 'file_activity'
  return 'unknown'
}

function categoryFromCapabilityText(value: string): EvidenceExpectationCategory {
  if (/network|http|dns|socket|c2|beacon|connect|download/i.test(value)) return 'network'
  if (/registry|run key|runonce|service|startup|persistence|autorun/i.test(value))
    return 'persistence'
  if (/inject|remote thread|writeprocessmemory|process injection/i.test(value)) return 'injection'
  if (/crypt|encrypt|decrypt|cipher|hash|key|rc4|aes|rsa/i.test(value)) return 'crypto'
  if (/pack|unpack|upx|vmprotect|themida|obfuscat|entropy/i.test(value))
    return 'encrypted_or_packed_resource'
  if (/anti|debug|sandbox|vm|timing/i.test(value)) return 'anti_analysis'
  if (/process|command|powershell|cmd\.exe|execute|shell/i.test(value)) return 'process'
  if (/file|write|read|delete/i.test(value)) return 'file_activity'
  return 'unknown'
}

function categoryFromAttackTechnique(id: string): EvidenceExpectationCategory {
  if (id === 'T1071') return 'network'
  if (id === 'T1547') return 'persistence'
  if (id === 'T1055') return 'injection'
  if (id === 'T1059') return 'process'
  return 'unknown'
}

function categoryFromStringEvidence(
  categories: string[],
  value: string
): EvidenceExpectationCategory {
  if (categories.some((category) => ['url', 'network'].includes(category))) return 'network'
  if (categories.includes('registry')) return 'registry'
  if (categories.includes('file_path')) return 'file_activity'
  if (categories.includes('ipc')) return 'environment_state'
  if (categories.includes('command')) return 'process'
  if (categories.includes('config_like')) return 'encoded_config'
  if (categories.includes('suspicious_api')) return categoryFromCapabilityText(value)
  return categoryFromCapabilityText(value)
}

function evidenceFromStringHighlight(args: {
  artifact: ArtifactRef
  value: Record<string, unknown>
  kind: PluginEvidence['kind']
  labelPrefix: string
  fallbackCategory: EvidenceExpectationCategory
  recommendedTools: string[]
  index: number
}): PluginEvidence | null {
  const value = readString(args.value.value)
  if (!value) return null
  const categories = readStringList(args.value.categories, 8)
  const labels = readStringList(args.value.labels, 8)
  const sourceLabels = readStringList(args.value.source_labels, 8)
  const category =
    categories.length > 0 ? categoryFromStringEvidence(categories, value) : args.fallbackCategory
  return {
    id: pluginEvidenceNodeId(args.artifact, args.kind, `${args.labelPrefix}:${value}`, args.index),
    kind: args.kind,
    category,
    label: `${args.labelPrefix}:${categories[0] || labels[0] || 'string'}`,
    value,
    confidence: boundedConfidence(args.value.confidence, 0.58),
    source_artifact_id: args.artifact.id,
    source_artifact_type: args.artifact.type,
    evidence: [
      ...categories.map((category) => `category=${category}`),
      ...labels.map((label) => `label=${label}`),
      ...sourceLabels.map((source) => `source=${source}`),
    ],
    recommended_tools: args.recommendedTools,
    details: {
      offset: readNumber(args.value.offset, -1),
      score: readNumber(args.value.score, 0),
      categories,
      labels,
      source_labels: sourceLabels,
    },
  }
}

function severityConfidence(value: string): number {
  if (value === 'high') return 0.9
  if (value === 'medium') return 0.7
  if (value === 'low') return 0.55
  return 0.5
}

function pluginEvidenceNodeId(
  artifact: ArtifactRef,
  kind: PluginEvidence['kind'],
  value: string,
  index: number
): string {
  return `plugin:${artifact.id}:${kind}:${index}:${sanitizeId(value)}`
}

function uniqueStringValues(values: string[], limit = 16): string[] {
  return Array.from(new Set(values.filter(Boolean))).slice(0, limit)
}

function routeConfidence(route: Record<string, unknown>): number {
  const priority = readString(route.priority)
  if (priority === 'critical') return 0.9
  if (priority === 'high') return 0.85
  if (priority === 'low') return 0.52
  return 0.62
}

function routeEvidence(route: Record<string, unknown>): string[] {
  const requiredEvidence = readStringList(route.required_evidence, 8)
  if (requiredEvidence.length > 0) return requiredEvidence
  return readStringList(route.evidence, 8)
}

function evidenceFromWorkflowRoutes(args: {
  artifact: ArtifactRef
  workflowHandoff: Record<string, unknown> | null
  labelPrefix: string
  startIndex: number
  details?: Record<string, unknown>
}): { evidence: PluginEvidence[]; nextIndex: number } {
  const evidence: PluginEvidence[] = []
  let index = args.startIndex

  for (const value of asArray(args.workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal) || readString(route.name) || readString(route.id)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(args.artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `${args.labelPrefix}:${goal}`,
      value: goal,
      confidence: routeConfidence(route),
      source_artifact_id: args.artifact.id,
      source_artifact_type: args.artifact.type,
      evidence: routeEvidence(route),
      recommended_tools: readStringList(route.next_tools, 12),
      details: {
        ...(args.details || {}),
        priority: readString(route.priority) || 'normal',
        handoff_schema: readString(args.workflowHandoff?.schema) || null,
      },
    })
  }

  return { evidence, nextIndex: index }
}

function standardHandoffData(payload: Record<string, unknown>): {
  data: Record<string, unknown>
  workflowHandoff: Record<string, unknown> | null
  evidenceSummary: Record<string, unknown> | null
  qualityGates: Record<string, unknown> | null
} {
  const data = unwrapPayload(payload)
  return {
    data,
    workflowHandoff: asRecord(data.workflow_handoff) ?? asRecord(data.x_mcp_workflow_handoff),
    evidenceSummary: asRecord(data.evidence_summary) ?? asRecord(data.x_mcp_evidence_summary),
    qualityGates: asRecord(data.quality_gates) ?? asRecord(data.x_mcp_quality_gates),
  }
}

function genericArtifactCategory(artifactType: string): string {
  if (artifactType === 'binary_diff') return 'binary_diff'
  if (artifactType === 'cross_module_graph') return 'cross_module'
  if (/sbom/i.test(artifactType)) return 'supply_chain'
  const category = categoryFromCapabilityText(artifactType)
  return category === 'unknown' ? 'workflow' : category
}

function genericEvidenceFacts(evidenceSummary: Record<string, unknown> | null): string[] {
  if (!evidenceSummary) return []
  const fields = [
    'artifact_type',
    'evidence_kind',
    'source_tool',
    'sbom_format',
    'match_count',
    'component_count',
    'sample_hash_count',
    'rules_generated',
    'total_indicators',
  ]
  const facts = fields
    .map((field) => {
      const value = evidenceSummary[field]
      if (value === undefined || value === null || value === '') return ''
      return `${field}=${String(value)}`
    })
    .filter(Boolean)
  if (asRecord(evidenceSummary.delta_counts)) facts.push('delta_counts_present')
  if (asRecord(evidenceSummary.similarity_profile)) facts.push('similarity_profile_present')
  return facts.slice(0, 12)
}

function genericRecommendedTools(
  data: Record<string, unknown>,
  workflowHandoff: Record<string, unknown> | null,
  evidenceSummary: Record<string, unknown> | null
): string[] {
  const routeTools = asArray(workflowHandoff?.routing).flatMap((value) => {
    const route = asRecord(value)
    return route ? readStringList(route.next_tools, 8) : []
  })
  return uniqueStringValues(
    [
      ...readStringList(data.recommended_next_tools, 12),
      ...readStringList(workflowHandoff?.recommended_next_tools, 12),
      ...readStringList(evidenceSummary?.recommended_next_tools, 12),
      ...routeTools,
      'analysis.evidence.graph',
      'report.generate',
    ],
    16
  )
}

function evidenceFromGenericWorkflowHandoff(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  if (!GENERIC_WORKFLOW_HANDOFF_ARTIFACT_TYPES.has(artifact.type)) return []
  const { data, workflowHandoff, evidenceSummary, qualityGates } = standardHandoffData(payload)
  if (!workflowHandoff && !evidenceSummary && !qualityGates) return []

  const evidence: PluginEvidence[] = []
  let index = 0
  const artifactType =
    readString(evidenceSummary?.artifact_type) ||
    readString(workflowHandoff?.artifact_type) ||
    artifact.type
  const summaryValue =
    readString(evidenceSummary?.evidence_kind) ||
    readString(evidenceSummary?.sbom_format) ||
    readString(workflowHandoff?.handoff_mode) ||
    artifactType
  const evidenceSummarySchema = readString(evidenceSummary?.schema)
  const workflowHandoffSchema = readString(workflowHandoff?.schema)
  const qualityGatesSchema = readString(qualityGates?.schema)

  if (evidenceSummary || qualityGates) {
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `generic:${summaryValue}`, index++),
      kind: 'triage_signal',
      category: genericArtifactCategory(artifact.type),
      label: `generic_handoff:${artifact.type}`,
      value: summaryValue,
      confidence: evidenceSummary ? 0.66 : 0.56,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: genericEvidenceFacts(evidenceSummary),
      recommended_tools: genericRecommendedTools(data, workflowHandoff, evidenceSummary),
      details: {
        artifact_type: artifactType,
        evidence_summary_schema: evidenceSummarySchema || null,
        workflow_handoff_schema: workflowHandoffSchema || null,
        quality_gates_schema: qualityGatesSchema || null,
        quality_gates: qualityGates || null,
      },
    })
  }

  const routes = evidenceFromWorkflowRoutes({
    artifact,
    workflowHandoff,
    labelPrefix: `${artifact.type}_route`,
    startIndex: index,
    details: {
      evidence_summary_schema: evidenceSummarySchema || null,
      quality_gates: qualityGates || null,
    },
  })
  evidence.push(...routes.evidence)

  return evidence
}

function evidenceFromMalwareIntelLoop(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0

  for (const value of asArray(data.normalized_iocs)) {
    const ioc = asRecord(value)
    if (!ioc) continue
    const type = readString(ioc.type)
    const normalizedValue = readString(ioc.normalized_value) || readString(ioc.value)
    if (!type || !normalizedValue) continue
    const sources = readStringList(ioc.sources)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'ioc', `${type}:${normalizedValue}`, index++),
      kind: 'ioc',
      category: categoryFromIocType(type),
      label: `malware_ioc:${type}`,
      value: normalizedValue,
      confidence: boundedConfidence(ioc.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: sources.map((source) => `source=${source}`),
      recommended_tools: ['ioc.export', 'attack.map', 'report.generate'],
      details: {
        type,
        sources,
        sightings: readNumber(ioc.sightings, 1),
        first_seen_in: readString(ioc.first_seen_in) || null,
      },
    })
  }

  const fusionSummary = asRecord(data.fusion_summary)
  for (const value of asArray(fusionSummary?.behavior_clusters)) {
    const cluster = asRecord(value)
    if (!cluster) continue
    const capability = readString(cluster.capability)
    if (!capability) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'behavior_cluster', capability, index++),
      kind: 'behavior_cluster',
      category: categoryFromCapabilityText(capability),
      label: `behavior:${capability}`,
      value: capability,
      confidence: boundedConfidence(cluster.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(cluster.techniques).map((technique) => `technique=${technique}`),
      recommended_tools: ['analysis.evidence.graph', 'report.generate'],
      details: {
        techniques: readStringList(cluster.techniques),
      },
    })
  }

  const attackMap = asRecord(data.attack_map)
  for (const value of asArray(attackMap?.techniques).slice(0, 12)) {
    const technique = asRecord(value)
    if (!technique) continue
    const id = readString(technique.id)
    if (!id) continue
    const name = readString(technique.name)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'behavior_cluster', id, index++),
      kind: 'behavior_cluster',
      category: categoryFromAttackTechnique(id),
      label: `attack:${id}`,
      value: name || id,
      confidence: boundedConfidence(technique.confidence, 0.5),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: ['malware_intel_loop_attack_hint'],
      recommended_tools: ['attack.map', 'sigma.rule.generate', 'report.generate'],
      details: { technique_id: id, technique_name: name || null },
    })
  }

  return evidence
}

function triageCorrelationBundle(payload: Record<string, unknown>): Record<string, unknown> | null {
  const data = unwrapPayload(payload)
  if (readString(data.result_mode) === 'static_triage_correlation_bundle') return data
  return asRecord(data.correlation_bundle)
}

function evidenceFromStaticTriageBundle(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const bundle = triageCorrelationBundle(payload)
  if (!bundle) return []

  const evidence: PluginEvidence[] = []
  let index = 0
  const bundles = asRecord(bundle.bundles)

  for (const sectionName of ['config', 'crypto', 'packer'] as const) {
    const section = asRecord(bundles?.[sectionName])
    for (const value of asArray(section?.signals)) {
      const signal = asRecord(value)
      if (!signal) continue
      const kind = readString(signal.kind) || sectionName
      evidence.push({
        id: pluginEvidenceNodeId(artifact, 'triage_signal', `${sectionName}:${kind}`, index++),
        kind: 'triage_signal',
        category: categoryFromCapabilityText(`${sectionName} ${kind}`),
        label: `triage:${sectionName}:${kind}`,
        value: kind,
        confidence: boundedConfidence(signal.confidence, 0.55),
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: readStringList(signal.evidence, 8),
        recommended_tools: readStringList(signal.recommended_tools, 8),
        details: {
          section: sectionName,
          rationale: readString(signal.rationale) || null,
          source_capabilities: asArray(signal.source_capabilities).slice(0, 6),
        },
      })
    }
  }

  const behavior = asRecord(bundles?.behavior)
  for (const value of asArray(behavior?.high_confidence_capabilities)) {
    const capability = asRecord(value)
    if (!capability) continue
    const name = readString(capability.name) || readString(capability.rule_id)
    if (!name) continue
    const group = readString(capability.group)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', name, index++),
      kind: 'capability',
      category: categoryFromCapabilityText(`${group} ${name}`),
      label: `capability:${name}`,
      value: name,
      confidence: boundedConfidence(capability.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(capability.evidence_summary)
        ? [readString(capability.evidence_summary)]
        : [],
      recommended_tools: readStringList(behavior?.recommended_tools, 8),
      details: {
        rule_id: readString(capability.rule_id) || null,
        namespace: readString(capability.namespace) || null,
        group: group || null,
      },
    })
  }

  for (const value of asArray(bundle.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `route:${goal}`,
      value: goal,
      confidence: route.priority === 'high' ? 0.85 : 0.6,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function evidenceFromStaticConfigCarver(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0

  for (const value of asArray(data.candidates).slice(0, 16)) {
    const candidate = asRecord(value)
    if (!candidate) continue
    const kind = readString(candidate.kind)
    const candidateValue = readString(candidate.value)
    if (!kind || !candidateValue) continue
    const isIoc =
      /^(url|domain|ip|ip_port|registry_path|mutex_like|guid_or_mutex|user_agent_or_http_client)$/.test(
        kind
      )
    evidence.push({
      id: pluginEvidenceNodeId(
        artifact,
        isIoc ? 'ioc' : 'triage_signal',
        `${kind}:${candidateValue}`,
        index++
      ),
      kind: isIoc ? 'ioc' : 'triage_signal',
      category: categoryFromIocType(kind),
      label: `config_candidate:${kind}`,
      value: candidateValue,
      confidence: boundedConfidence(candidate.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(candidate.evidence, 8),
      recommended_tools: ['malware.intel.loop', 'ioc.export', 'analysis.evidence.graph'],
      details: {
        kind,
      },
    })
  }

  for (const value of asArray(data.blob_candidates).slice(0, 8)) {
    const blob = asRecord(value)
    if (!blob) continue
    const kind = readString(blob.kind)
    const preview = readString(blob.value_preview) || kind
    if (!preview) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `blob:${preview}`, index++),
      kind: 'triage_signal',
      category: 'encoded_config',
      label: `encoded_blob:${kind || 'blob'}`,
      value: preview,
      confidence: boundedConfidence(blob.confidence, 0.5),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(blob.evidence, 8),
      recommended_tools: ['static.resource.graph', 'crypto.identify', 'unpack.workflow.plan'],
      details: {
        kind: kind || null,
        decoded_size: readNumber(blob.decoded_size, 0),
      },
    })
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `static_config_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function evidenceFromStaticResourceGraph(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  const executableLike = new Set(['pe_or_dos', 'elf', 'zip', 'cab'])
  let index = 0

  for (const value of asArray(data.resources).slice(0, 16)) {
    const resource = asRecord(value)
    if (!resource) continue
    const pathParts = asArray(resource.path).map(readString).filter(Boolean)
    const label = pathParts.length > 0 ? pathParts.join('/') : `resource_${index}`
    const magic = readString(resource.magic)
    const entropy = readNumber(resource.entropy, 0)
    const size = readNumber(resource.size, 0)
    const sha256 = readString(resource.sha256)
    const stringPreview = readStringList(resource.stringPreview, 4)
    const commonDetails = {
      path: pathParts,
      magic: magic || null,
      entropy,
      size,
      sha256: sha256 || null,
      string_preview: stringPreview,
    }

    if (executableLike.has(magic)) {
      evidence.push({
        id: pluginEvidenceNodeId(artifact, 'triage_signal', `payload:${label}`, index++),
        kind: 'triage_signal',
        category: 'embedded_payload',
        label: `resource_payload:${magic}`,
        value: label,
        confidence: 0.84,
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: [`magic=${magic}`, `size=${size}`],
        recommended_tools: [
          'unpack.workflow.plan',
          'static.config.carver',
          'analysis.evidence.graph',
        ],
        details: commonDetails,
      })
    }

    if (entropy >= 7.2) {
      evidence.push({
        id: pluginEvidenceNodeId(artifact, 'triage_signal', `entropy:${label}`, index++),
        kind: 'triage_signal',
        category: 'encrypted_or_packed_resource',
        label: 'high_entropy_resource',
        value: label,
        confidence: 0.74,
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: [`entropy=${entropy}`, `size=${size}`],
        recommended_tools: ['entropy.analyze', 'crypto.identify', 'static.config.carver'],
        details: commonDetails,
      })
    }

    if (size >= 1024 * 1024 && !executableLike.has(magic) && entropy < 7.2) {
      evidence.push({
        id: pluginEvidenceNodeId(artifact, 'triage_signal', `large:${label}`, index++),
        kind: 'triage_signal',
        category: 'embedded_payload',
        label: 'large_resource_blob',
        value: label,
        confidence: 0.58,
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: [`size=${size}`],
        recommended_tools: [
          'static.config.carver',
          'unpack.workflow.plan',
          'analysis.evidence.graph',
        ],
        details: commonDetails,
      })
    }

    for (const preview of stringPreview) {
      if (!/https?:\/\//i.test(preview)) continue
      evidence.push({
        id: pluginEvidenceNodeId(artifact, 'ioc', `resource_url:${preview}`, index++),
        kind: 'ioc',
        category: 'network',
        label: 'resource_url_string',
        value: preview,
        confidence: 0.68,
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: [`resource=${label}`],
        recommended_tools: ['malware.intel.loop', 'ioc.export', 'static.config.carver'],
        details: commonDetails,
      })
    }
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `static_resource_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function evidenceFromCompilerPackerAttribution(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0

  for (const value of asArray(data.compiler_findings).slice(0, 12)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', `compiler:${name}`, index++),
      kind: 'capability',
      category: 'toolchain',
      label: `compiler:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.58),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: [
        'static.capability.triage',
        'code.cross_decompiler.consensus',
        'analysis.evidence.graph',
        'report.generate',
      ],
      details: {
        source: readString(finding.source) || null,
      },
    })
  }

  for (const value of asArray(data.packer_findings).slice(0, 12)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `packer:${name}`, index++),
      kind: 'triage_signal',
      category: 'encrypted_or_packed_resource',
      label: `packer:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.62),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: [
        'packer.detect',
        'entropy.analyze',
        'static.resource.graph',
        'unpack.workflow.plan',
        'analysis.evidence.graph',
      ],
      details: {
        source: readString(finding.source) || null,
      },
    })
  }

  for (const value of asArray(data.protector_findings).slice(0, 12)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `protector:${name}`, index++),
      kind: 'triage_signal',
      category: 'anti_analysis',
      label: `protector:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.62),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: [
        'packer.detect',
        'entropy.analyze',
        'unpack.workflow.plan',
        'static.behavior.classify',
        'analysis.evidence.graph',
      ],
      details: {
        source: readString(finding.source) || null,
      },
    })
  }

  for (const value of asArray(data.file_type_findings).slice(0, 8)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `file_type:${name}`, index++),
      kind: 'triage_signal',
      category: 'file_type',
      label: `file_type:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: [
        'static.resource.graph',
        'static.config.carver',
        'analysis.evidence.graph',
      ],
      details: {
        source: readString(finding.source) || null,
      },
    })
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `compiler_packer_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function evidenceFromDieScan(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0
  const workflowHandoff = asRecord(data.workflow_handoff)
  const evidenceSummary = asRecord(data.evidence_summary)
  const qualityGates = asRecord(data.quality_gates)

  for (const value of asArray(data.compiler_findings).slice(0, 12)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', `die_compiler:${name}`, index++),
      kind: 'capability',
      category: 'toolchain',
      label: `die_compiler:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.58),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: [
        'compiler.packer.detect',
        'static.capability.triage',
        'code.cross_decompiler.consensus',
        'analysis.evidence.graph',
      ],
      details: {
        source: readString(finding.source) || null,
        version: readString(finding.version) || null,
        type: readString(finding.type) || null,
        quality_gates: qualityGates || null,
      },
    })
  }

  for (const value of asArray(data.packer_findings).slice(0, 12)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `die_packer:${name}`, index++),
      kind: 'triage_signal',
      category: 'encrypted_or_packed_resource',
      label: `die_packer:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.62),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: [
        'packer.detect',
        'entropy.analyze',
        'static.resource.graph',
        'unpack.workflow.plan',
        'analysis.evidence.graph',
      ],
      details: {
        source: readString(finding.source) || null,
        version: readString(finding.version) || null,
        type: readString(finding.type) || null,
        quality_gates: qualityGates || null,
      },
    })
  }

  for (const value of asArray(data.protector_findings).slice(0, 12)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `die_protector:${name}`, index++),
      kind: 'triage_signal',
      category: 'anti_analysis',
      label: `die_protector:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.62),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: [
        'packer.detect',
        'entropy.analyze',
        'unpack.workflow.plan',
        'static.behavior.classify',
        'analysis.evidence.graph',
      ],
      details: {
        source: readString(finding.source) || null,
        version: readString(finding.version) || null,
        type: readString(finding.type) || null,
        quality_gates: qualityGates || null,
      },
    })
  }

  for (const value of asArray(data.crypto_findings).slice(0, 12)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', `die_crypto:${name}`, index++),
      kind: 'capability',
      category: 'crypto',
      label: `die_crypto:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.58),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: ['crypto.identify', 'static.capability.triage', 'analysis.evidence.graph'],
      details: {
        source: readString(finding.source) || null,
        version: readString(finding.version) || null,
        type: readString(finding.type) || null,
      },
    })
  }

  for (const value of asArray(data.file_type_findings).slice(0, 8)) {
    const finding = asRecord(value)
    if (!finding) continue
    const name = readString(finding.name)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `die_file_type:${name}`, index++),
      kind: 'triage_signal',
      category: 'file_type',
      label: `die_file_type:${name}`,
      value: name,
      confidence: boundedConfidence(finding.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(finding.evidence_summary) ? [readString(finding.evidence_summary)] : [],
      recommended_tools: [
        'compiler.packer.detect',
        'static.resource.graph',
        'static.config.carver',
        'analysis.evidence.graph',
      ],
      details: {
        source: readString(finding.source) || null,
        version: readString(finding.version) || null,
        type: readString(finding.type) || null,
      },
    })
  }

  if (evidenceSummary) {
    const detectCount = readNumber(evidenceSummary.detect_count, asArray(data.detects).length)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `die_summary:${detectCount}`, index++),
      kind: 'triage_signal',
      category: 'signatures',
      label: 'die_scan_summary',
      value: `detects=${detectCount}`,
      confidence: detectCount > 0 ? 0.7 : 0.42,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        `compiler_count=${readNumber(evidenceSummary.compiler_count, 0)}`,
        `packer_count=${readNumber(evidenceSummary.packer_count, 0)}`,
        `protector_count=${readNumber(evidenceSummary.protector_count, 0)}`,
        `crypto_count=${readNumber(evidenceSummary.crypto_count, 0)}`,
      ],
      recommended_tools: [
        'artifact.read',
        'compiler.packer.detect',
        'analysis.evidence.graph',
        'report.generate',
      ],
      details: {
        artifact_type: readString(evidenceSummary.artifact_type) || artifact.type,
        file_type: readString(evidenceSummary.file_type) || null,
        arch: readString(evidenceSummary.arch) || null,
        mode: readString(evidenceSummary.mode) || null,
        quality_gates: qualityGates || null,
      },
    })
  }

  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `die_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function evidenceFromEnrichedStringAnalysis(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const enriched = asRecord(data.enriched) ?? data
  const evidence: PluginEvidence[] = []
  let index = 0

  for (const value of asArray(enriched.top_iocs).slice(0, 12)) {
    const highlight = asRecord(value)
    if (!highlight) continue
    const item = evidenceFromStringHighlight({
      artifact,
      value: highlight,
      kind: 'ioc',
      labelPrefix: 'decoded_string_ioc',
      fallbackCategory: 'network',
      recommendedTools: ['ioc.export', 'malware.intel.loop', 'analysis.evidence.graph'],
      index: index++,
    })
    if (item) evidence.push(item)
  }

  for (const value of asArray(enriched.top_suspicious).slice(0, 12)) {
    const highlight = asRecord(value)
    if (!highlight) continue
    const item = evidenceFromStringHighlight({
      artifact,
      value: highlight,
      kind: 'triage_signal',
      labelPrefix: 'suspicious_string',
      fallbackCategory: 'unknown',
      recommendedTools: [
        'static.config.carver',
        'static.behavior.classify',
        'analysis.evidence.graph',
      ],
      index: index++,
    })
    if (item) evidence.push(item)
  }

  for (const value of asArray(enriched.top_decoded).slice(0, 8)) {
    const highlight = asRecord(value)
    if (!highlight) continue
    const item = evidenceFromStringHighlight({
      artifact,
      value: highlight,
      kind: 'triage_signal',
      labelPrefix: 'decoded_string',
      fallbackCategory: 'encoded_config',
      recommendedTools: ['analysis.context.link', 'static.config.carver', 'report.generate'],
      index: index++,
    })
    if (item) evidence.push(item)
  }

  for (const value of asArray(enriched.records).slice(0, 24)) {
    const record = asRecord(value)
    if (!record) continue
    const labels = readStringList(record.labels, 12)
    if (!labels.includes('encoded_candidate')) continue
    const encodedValue = readString(record.value)
    if (!encodedValue) continue
    const categories = readStringList(record.categories, 8)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `encoded:${encodedValue}`, index++),
      kind: 'triage_signal',
      category: 'encoded_config',
      label: 'encoded_string_candidate',
      value: encodedValue,
      confidence: boundedConfidence(record.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        ...categories.map((category) => `category=${category}`),
        ...labels.map((label) => `label=${label}`),
      ],
      recommended_tools: ['crypto.identify', 'unpack.workflow.plan', 'analysis.evidence.graph'],
      details: {
        offset: readNumber(record.primary_offset, -1),
        score: readNumber(record.score, 0),
        categories,
        labels,
      },
    })
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `string_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function confidenceFromYaraLevel(level: string): number {
  if (level === 'high') return 0.86
  if (level === 'medium') return 0.68
  if (level === 'low') return 0.48
  return 0.58
}

function confidenceFromYaraMatch(match: Record<string, unknown>): number {
  const confidence = asRecord(match.confidence)
  const score = readNumber(confidence?.score, -1)
  if (score >= 0) return boundedConfidence(score, 0.58)
  return confidenceFromYaraLevel(readString(confidence?.level))
}

function yaraMatchStringCount(match: Record<string, unknown>): number {
  return asArray(match.strings).filter((value) => Boolean(asRecord(value))).length
}

function evidenceFromYaraScan(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const { data, workflowHandoff, evidenceSummary, qualityGates } = standardHandoffData(payload)
  const evidence: PluginEvidence[] = []
  let index = 0
  const matches = asArray(data.matches)
    .map(asRecord)
    .filter((match): match is Record<string, unknown> => Boolean(match))
  const confidenceSummary =
    asRecord(data.confidence_summary) ?? asRecord(evidenceSummary?.confidence_summary)
  const ruleProvenance = asRecord(evidenceSummary?.rule_provenance)
  const matchCount = readNumber(
    data.match_count,
    readNumber(evidenceSummary?.match_count, matches.length)
  )
  const stringEvidenceCount = readNumber(
    data.string_evidence_count,
    readNumber(
      evidenceSummary?.string_evidence_count,
      matches.reduce((total, match) => total + yaraMatchStringCount(match), 0)
    )
  )
  const ruleSet =
    readString(data.rule_set) ||
    readString(evidenceSummary?.rule_set) ||
    readString(ruleProvenance?.rule_set)
  const ruleTier =
    readString(data.rule_tier) ||
    readString(evidenceSummary?.rule_tier) ||
    readString(ruleProvenance?.rule_tier)
  const rulesetVersion =
    readString(data.ruleset_version) ||
    readString(evidenceSummary?.ruleset_version) ||
    readString(ruleProvenance?.ruleset_version)
  const timedOut = data.timed_out === true || evidenceSummary?.timed_out === true
  const recommendedTools = uniqueStringValues(
    [
      ...genericRecommendedTools(data, workflowHandoff, evidenceSummary),
      'artifact.read',
      'yara.scan',
      matchCount > 0 ? 'malware.intel.loop' : 'yara.generate',
      matchCount > 0 ? 'ioc.export' : '',
    ],
    16
  )

  for (const match of matches.slice(0, 16)) {
    const rule = readString(match.rule) || readString(match.identifier) || `rule_${index}`
    const tags = readStringList(match.tags, 8)
    const strings = asArray(match.strings)
      .map(asRecord)
      .filter((entry): entry is Record<string, unknown> => Boolean(entry))
    const matchEvidence = asRecord(match.evidence)
    const confidence = asRecord(match.confidence)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', `yara:${rule}`, index++),
      kind: 'capability',
      category: 'signatures',
      label: `yara_match:${rule}`,
      value: rule,
      confidence: confidenceFromYaraMatch(match),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        ...tags.map((tag) => `tag=${tag}`),
        `strings=${strings.length}`,
        readString(confidence?.level) ? `confidence=${readString(confidence?.level)}` : '',
        readNumber(matchEvidence?.near_entrypoint_hits, 0) > 0
          ? `near_entrypoint_hits=${readNumber(matchEvidence?.near_entrypoint_hits, 0)}`
          : '',
      ].filter(Boolean),
      recommended_tools: recommendedTools,
      details: {
        rule,
        tags,
        meta: asRecord(match.meta) || null,
        string_evidence_count: strings.length,
        string_identifiers: strings.map((entry) => readString(entry.identifier)).filter(Boolean),
        confidence_level: readString(confidence?.level) || null,
        import_dll_hits: readStringList(matchEvidence?.import_dll_hits, 8),
        import_api_hits: readStringList(matchEvidence?.import_api_hits, 8),
        section_hits: readStringList(matchEvidence?.section_hits, 8),
        inference: asRecord(match.inference) || null,
        rule_set: ruleSet || null,
        ruleset_version: rulesetVersion || null,
        quality_gates: qualityGates || null,
      },
    })
  }

  const highCount = readNumber(confidenceSummary?.high, 0)
  const mediumCount = readNumber(confidenceSummary?.medium, 0)
  const summaryConfidence = timedOut
    ? 0.4
    : matchCount > 0
      ? highCount > 0
        ? 0.82
        : mediumCount > 0
          ? 0.7
          : 0.58
      : 0.45
  evidence.push({
    id: pluginEvidenceNodeId(
      artifact,
      'triage_signal',
      `yara_summary:${matchCount}:${stringEvidenceCount}`,
      index++
    ),
    kind: 'triage_signal',
    category: 'signatures',
    label: 'yara_scan_summary',
    value: `matches=${matchCount};strings=${stringEvidenceCount}`,
    confidence: summaryConfidence,
    source_artifact_id: artifact.id,
    source_artifact_type: artifact.type,
    evidence: [
      ruleSet ? `rule_set=${ruleSet}` : '',
      ruleTier ? `rule_tier=${ruleTier}` : '',
      rulesetVersion ? `ruleset_version=${rulesetVersion}` : '',
      `match_count=${matchCount}`,
      `string_evidence_count=${stringEvidenceCount}`,
      timedOut ? 'timed_out=true' : '',
    ].filter(Boolean),
    recommended_tools: recommendedTools,
    details: {
      artifact_type: readString(evidenceSummary?.artifact_type) || artifact.type,
      evidence_summary_schema: readString(evidenceSummary?.schema) || null,
      rule_provenance: ruleProvenance || null,
      confidence_summary: confidenceSummary || null,
      matched_rule_names: readStringList(evidenceSummary?.matched_rule_names, 16),
      offset_evidence: asRecord(evidenceSummary?.offset_evidence) || null,
      quality_gates: qualityGates || null,
    },
  })

  const routes = evidenceFromWorkflowRoutes({
    artifact,
    workflowHandoff,
    labelPrefix: 'yara_scan_route',
    startIndex: index,
    details: {
      rule_set: ruleSet || null,
      ruleset_version: rulesetVersion || null,
      quality_gates: qualityGates || null,
    },
  })
  evidence.push(...routes.evidence)

  return evidence
}

function ruleNameFromText(ruleText: string): string {
  const match = /^rule\s+([A-Za-z0-9_]+)/m.exec(ruleText)
  return match?.[1] || ''
}

function yaraXPatternMatchCount(rule: Record<string, unknown>): number {
  return asArray(rule.patterns)
    .map(asRecord)
    .filter((pattern): pattern is Record<string, unknown> => Boolean(pattern))
    .reduce((total, pattern) => total + asArray(pattern.matches).length, 0)
}

function evidenceFromYaraXScan(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0
  const matchingRules = (
    asArray(data.matching_rules).length > 0 ? asArray(data.matching_rules) : asArray(data.matches)
  )
    .map(asRecord)
    .filter((rule): rule is Record<string, unknown> => Boolean(rule))
  const evidenceSummary = asRecord(data.evidence_summary)
  const workflowHandoff = asRecord(data.workflow_handoff)
  const qualityGates = asRecord(data.quality_gates)
  const rulesSource = readString(data.rules_source) || readString(evidenceSummary?.rules_source)
  const rulesDigest = readString(data.rules_digest) || readString(evidenceSummary?.rules_digest)

  for (const rule of matchingRules.slice(0, 16)) {
    const identifier = readString(rule.identifier) || `rule_${index}`
    const namespace = readString(rule.namespace)
    const patternCount = asArray(rule.patterns).length
    const patternMatchCount = yaraXPatternMatchCount(rule)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', `yara_x:${identifier}`, index++),
      kind: 'capability',
      category: 'signatures',
      label: `yara_x_match:${identifier}`,
      value: namespace ? `${namespace}:${identifier}` : identifier,
      confidence: boundedConfidence(0.55 + Math.min(patternMatchCount, 10) * 0.03, 0.6),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        namespace ? `namespace=${namespace}` : '',
        `pattern_count=${patternCount}`,
        `pattern_match_count=${patternMatchCount}`,
        rulesDigest ? `rules_digest=${rulesDigest}` : '',
      ].filter(Boolean),
      recommended_tools: [
        'artifact.read',
        'yara.scan',
        'analysis.evidence.graph',
        'report.generate',
      ],
      details: {
        identifier,
        namespace: namespace || null,
        pattern_count: patternCount,
        pattern_match_count: patternMatchCount,
        rules_source: rulesSource || null,
        quality_gates: qualityGates || null,
      },
    })
  }

  if (evidenceSummary) {
    const matchCount = readNumber(evidenceSummary.match_count, matchingRules.length)
    const patternMatchCount = readNumber(
      evidenceSummary.pattern_match_count,
      matchingRules.reduce((total, rule) => total + yaraXPatternMatchCount(rule), 0)
    )
    evidence.push({
      id: pluginEvidenceNodeId(
        artifact,
        'triage_signal',
        `yara_x_summary:${matchCount}:${patternMatchCount}`,
        index++
      ),
      kind: 'triage_signal',
      category: 'signatures',
      label: 'yara_x_scan_summary',
      value: `rules=${matchCount};pattern_matches=${patternMatchCount}`,
      confidence: matchCount > 0 ? 0.72 : 0.45,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        rulesSource ? `rules_source=${rulesSource}` : '',
        rulesDigest ? `rules_digest=${rulesDigest}` : '',
        `timeout_sec=${readNumber(evidenceSummary.timeout_sec, 0)}`,
      ].filter(Boolean),
      recommended_tools: [
        'artifact.read',
        'yara.scan',
        'analysis.evidence.graph',
        'report.generate',
      ],
      details: {
        artifact_type: readString(evidenceSummary.artifact_type) || artifact.type,
        rules_source: rulesSource || null,
        module_output_keys: readStringList(evidenceSummary.module_output_keys, 12),
        quality_gates: qualityGates || null,
      },
    })
  }

  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `yara_x_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
        rules_source: rulesSource || null,
      },
    })
  }

  return evidence
}

function evidenceFromUpxInspection(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0
  const evidenceSummary = asRecord(data.evidence_summary)
  const workflowHandoff = asRecord(data.workflow_handoff)
  const qualityGates = asRecord(data.quality_gates)
  const operation = readString(data.operation) || readString(evidenceSummary?.operation)
  const exitCode = readNumber(data.exit_code, readNumber(evidenceSummary?.exit_code, -1))
  const upxDetected =
    data.upx_detected === true ||
    evidenceSummary?.upx_detected === true ||
    /upx|packed|compressed|unpacked|decompress/i.test(
      `${readString(data.stdout_preview)} ${readString(data.stderr_preview)}`
    )
  const artifactType = readString(evidenceSummary?.artifact_type) || artifact.type

  evidence.push({
    id: pluginEvidenceNodeId(artifact, 'triage_signal', `upx:${operation}:${exitCode}`, index++),
    kind: 'triage_signal',
    category: 'encrypted_or_packed_resource',
    label: `upx_${operation || 'inspection'}_summary`,
    value: `operation=${operation || 'unknown'};exit_code=${exitCode}`,
    confidence: upxDetected ? 0.82 : exitCode === 0 ? 0.65 : 0.45,
    source_artifact_id: artifact.id,
    source_artifact_type: artifact.type,
    evidence: [
      operation ? `operation=${operation}` : '',
      `exit_code=${exitCode}`,
      upxDetected ? 'upx_signal_present' : '',
    ].filter(Boolean),
    recommended_tools: [
      'artifact.read',
      'unpack.workflow.plan',
      'packer.detect',
      'analysis.evidence.graph',
      'report.generate',
    ],
    details: {
      operation: operation || null,
      artifact_type: artifactType,
      upx_detected: upxDetected,
      command_args: readStringList(evidenceSummary?.command_args, 8),
      quality_gates: qualityGates || null,
    },
  })

  if (upxDetected || operation === 'decompress') {
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', `upx:${operation || 'packed'}`, index++),
      kind: 'capability',
      category: 'packed',
      label: 'upx_packer_signal',
      value: operation || 'upx',
      confidence: upxDetected ? 0.84 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        readString(data.stdout_preview),
        readString(data.stderr_preview),
        readString(evidenceSummary?.decompressed_artifact_type),
      ]
        .filter(Boolean)
        .slice(0, 4),
      recommended_tools: ['unpack.workflow.plan', 'static.triage', 'analysis.evidence.graph'],
      details: {
        operation: operation || null,
        exit_code: exitCode,
        decompressed_artifact_type: readString(evidenceSummary?.decompressed_artifact_type) || null,
        decompressed_artifact_sha256:
          readString(evidenceSummary?.decompressed_artifact_sha256) || null,
      },
    })
  }

  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `upx_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
        operation: operation || null,
      },
    })
  }

  return evidence
}

function evidenceFromYaraRuleGeneration(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  const topLevelFamilyRule = asRecord(data.family_rule)
  const rules =
    asArray(data.rules).length > 0
      ? asArray(data.rules)
      : topLevelFamilyRule
        ? [topLevelFamilyRule]
        : readString(data.rule_text)
          ? [
              {
                type: readString(data.family_name) ? 'family_hybrid' : 'hybrid',
                rule_text: readString(data.rule_text),
                score: readNumber(data.score, 0),
              },
            ]
          : []
  let index = 0

  for (const value of rules.slice(0, 12)) {
    const rule = asRecord(value)
    if (!rule) continue
    const type = readString(rule.type) || `rule_${index}`
    const ruleText = readString(rule.rule_text)
    const ruleName = ruleNameFromText(ruleText) || type
    const score = readNumber(rule.score, 0)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', `yara:${ruleName}`, index++),
      kind: 'capability',
      category: 'signatures',
      label: `yara_rule:${type}`,
      value: ruleName,
      confidence: boundedConfidence(score / 100, 0.5),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [`score=${score}`, `type=${type}`],
      recommended_tools: ['yara.scan', 'analysis.evidence.graph', 'report.generate'],
      details: {
        rule_type: type,
        score,
        quality_tier: readString(asRecord(data.quality_gates)?.quality_tier) || null,
        family_name: readString(data.family_name) || null,
        sample_count: readNumber(data.sample_count, 0) || null,
      },
    })
  }

  const evidenceSummary = asRecord(data.evidence_summary)
  const evidenceCounts = asRecord(evidenceSummary?.evidence_counts)
  if (evidenceCounts) {
    const suspiciousImports = readNumber(evidenceCounts.suspicious_imports, 0)
    const uniqueStrings = readNumber(evidenceCounts.unique_strings, 0)
    if (suspiciousImports > 0 || uniqueStrings > 0) {
      evidence.push({
        id: pluginEvidenceNodeId(
          artifact,
          'triage_signal',
          `yara_evidence:${suspiciousImports}:${uniqueStrings}`,
          index++
        ),
        kind: 'triage_signal',
        category: 'signatures',
        label: 'yara_rule_evidence_inputs',
        value: `strings=${uniqueStrings};suspicious_imports=${suspiciousImports}`,
        confidence: 0.66,
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: [
          `unique_strings=${uniqueStrings}`,
          `suspicious_imports=${suspiciousImports}`,
          `byte_patterns=${readNumber(evidenceCounts.byte_patterns, 0)}`,
        ],
        recommended_tools: ['yara.scan', 'malware.intel.loop', 'ioc.export'],
        details: {
          strictness: readString(data.strictness) || null,
          deploy_requested: Boolean(data.deploy_requested),
        },
      })
    }
  }
  const commonFeatureCounts = asRecord(evidenceSummary?.common_feature_counts)
  if (commonFeatureCounts) {
    const commonStrings = readNumber(commonFeatureCounts.strings, 0)
    const commonImports = readNumber(commonFeatureCounts.imports, 0)
    if (commonStrings > 0 || commonImports > 0) {
      evidence.push({
        id: pluginEvidenceNodeId(
          artifact,
          'triage_signal',
          `yara_family:${commonStrings}:${commonImports}`,
          index++
        ),
        kind: 'triage_signal',
        category: 'signatures',
        label: 'yara_family_common_features',
        value: `common_strings=${commonStrings};common_imports=${commonImports}`,
        confidence: 0.7,
        source_artifact_id: artifact.id,
        source_artifact_type: artifact.type,
        evidence: [
          `common_strings=${commonStrings}`,
          `common_imports=${commonImports}`,
          `min_occurrence=${readNumber(commonFeatureCounts.min_occurrence, 0)}`,
        ],
        recommended_tools: ['yara.scan', 'sample.family.cluster', 'analysis.evidence.graph'],
        details: {
          family_name: readString(data.family_name) || null,
          sample_count: readNumber(data.sample_count, 0),
          strictness: readString(data.strictness) || null,
        },
      })
    }
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `yara_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

interface IOCExportEvidenceRecord {
  type: string
  value: string
  confidence: string
  source: string
  tags: string[]
}

interface IOCExportTechniqueRecord {
  technique_id: string
  name: string
  tactics: string[]
  confidence: number
}

function parseCsvLine(line: string): string[] {
  const values: string[] = []
  let current = ''
  let inQuotes = false
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index]
    const next = line[index + 1]
    if (char === '"' && inQuotes && next === '"') {
      current += '"'
      index += 1
      continue
    }
    if (char === '"') {
      inQuotes = !inQuotes
      continue
    }
    if (char === ',' && !inQuotes) {
      values.push(current)
      current = ''
      continue
    }
    current += char
  }
  values.push(current)
  return values
}

function iocExportRecordsFromCsv(content: string): IOCExportEvidenceRecord[] {
  const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0)
  if (lines.length <= 1) return []
  const [headerLine, ...rows] = lines
  const headers = parseCsvLine(headerLine)
  const indexOf = (name: string) => headers.indexOf(name)
  const typeIndex = indexOf('type')
  const valueIndex = indexOf('value')
  const confidenceIndex = indexOf('confidence')
  const sourceIndex = indexOf('source')
  const tagsIndex = indexOf('tags')

  return rows
    .map((row) => {
      const cells = parseCsvLine(row)
      const type = readString(cells[typeIndex])
      const value = readString(cells[valueIndex])
      if (!type || !value) return null
      return {
        type,
        value,
        confidence: readString(cells[confidenceIndex]) || 'medium',
        source: readString(cells[sourceIndex]) || 'ioc_export_csv',
        tags: readString(cells[tagsIndex])
          .split('|')
          .map((tag) => tag.trim())
          .filter(Boolean),
      }
    })
    .filter((record): record is IOCExportEvidenceRecord => Boolean(record))
}

function iocExportCategory(type: string): string {
  if (['url', 'domain', 'ipv4', 'ip', 'ip_port'].includes(type)) return 'network'
  if (/reg/i.test(type)) return 'registry'
  if (/file|path/i.test(type)) return 'file_activity'
  if (['command', 'api'].includes(type)) return 'process'
  if (type === 'pipe') return 'environment_state'
  if (/yara|signature|rule/i.test(type)) return 'signatures'
  return 'unknown'
}

function confidenceFromIOCExport(value: string): number {
  if (value === 'high') return 0.86
  if (value === 'medium') return 0.68
  if (value === 'low') return 0.42
  return 0.55
}

function stixObjectValue(stixObject: Record<string, unknown>): string {
  return (
    readString(stixObject.value) ||
    readString(stixObject.command_line) ||
    readString(stixObject.key) ||
    readString(stixObject.name)
  )
}

function iocTypeFromStixObject(type: string): string {
  if (type === 'url') return 'url'
  if (type === 'ipv4-addr') return 'ipv4'
  if (type === 'windows-registry-key') return 'registry_key'
  if (type === 'file') return 'file_path'
  if (type === 'process') return 'command'
  if (type === 'x-mcp-api-call') return 'api'
  if (type === 'x-mcp-pipe') return 'pipe'
  return 'ioc'
}

function iocExportRecordsFromStix(data: Record<string, unknown>): IOCExportEvidenceRecord[] {
  const records: IOCExportEvidenceRecord[] = []
  for (const value of asArray(data.objects)) {
    const object = asRecord(value)
    if (!object || readString(object.type) !== 'observed-data') continue
    const observedObjects = asRecord(object.objects)
    const firstObject = asRecord(observedObjects?.['0'])
    if (!firstObject) continue
    const observedType = readString(firstObject.type)
    const recordValue = stixObjectValue(firstObject)
    if (!recordValue) continue
    records.push({
      type: iocTypeFromStixObject(observedType),
      value: recordValue,
      confidence: readString(object.x_mcp_confidence_level) || 'medium',
      source: readString(object.x_mcp_source) || 'stix.observed-data',
      tags: readStringList(object.labels, 8),
    })
  }
  return records
}

function iocExportTechniquesFromStix(data: Record<string, unknown>): IOCExportTechniqueRecord[] {
  const techniques: IOCExportTechniqueRecord[] = []
  for (const value of asArray(data.objects)) {
    const object = asRecord(value)
    if (!object || readString(object.type) !== 'attack-pattern') continue
    const references = asArray(object.external_references)
      .map(asRecord)
      .filter((reference): reference is Record<string, unknown> => Boolean(reference))
    const attackRef = references.find(
      (reference) => readString(reference.source_name) === 'mitre-attack'
    )
    const techniqueId = readString(attackRef?.external_id)
    if (!techniqueId) continue
    const tactics = asArray(object.kill_chain_phases)
      .map(asRecord)
      .map((phase) => readString(phase?.phase_name))
      .filter(Boolean)
    techniques.push({
      technique_id: techniqueId,
      name: readString(object.name).replace(`${techniqueId} `, '') || techniqueId,
      tactics,
      confidence: boundedConfidence(object.x_mcp_confidence, 0.55),
    })
  }
  return techniques
}

function normalizeIOCExportData(payload: Record<string, unknown>): {
  data: Record<string, unknown>
  records: IOCExportEvidenceRecord[]
  techniques: IOCExportTechniqueRecord[]
  workflowHandoff: Record<string, unknown> | null
  evidenceSummary: Record<string, unknown> | null
  qualityGates: Record<string, unknown> | null
} {
  const data = unwrapPayload(payload)
  const content = readString(data.content)
  const isCsv = content.length > 0 && /^type,value,confidence,source,tags\r?\n/.test(content)
  const isStix = readString(data.type) === 'bundle' && readString(data.spec_version) === '2.1'

  const records = isCsv
    ? iocExportRecordsFromCsv(content)
    : isStix
      ? iocExportRecordsFromStix(data)
      : asArray(data.iocs)
          .map(asRecord)
          .filter((record): record is Record<string, unknown> => Boolean(record))
          .map((record) => ({
            type: readString(record.type),
            value: readString(record.value),
            confidence: readString(record.confidence) || 'medium',
            source: readString(record.source) || 'ioc.export',
            tags: readStringList(record.tags, 8),
          }))
          .filter((record) => record.type && record.value)

  const techniques = isStix
    ? iocExportTechniquesFromStix(data)
    : asArray(data.attack_map)
        .map(asRecord)
        .filter((technique): technique is Record<string, unknown> => Boolean(technique))
        .map((technique) => ({
          technique_id: readString(technique.technique_id) || readString(technique.id),
          name: readString(technique.name),
          tactics: readStringList(technique.tactics, 8),
          confidence: boundedConfidence(technique.confidence, 0.55),
        }))
        .filter((technique) => technique.technique_id)

  return {
    data,
    records,
    techniques,
    workflowHandoff: asRecord(data.workflow_handoff) ?? asRecord(data.x_mcp_workflow_handoff),
    evidenceSummary: asRecord(data.evidence_summary) ?? asRecord(data.x_mcp_evidence_summary),
    qualityGates: asRecord(data.quality_gates) ?? asRecord(data.x_mcp_quality_gates),
  }
}

function evidenceFromIOCExport(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const { data, records, techniques, workflowHandoff, evidenceSummary, qualityGates } =
    normalizeIOCExportData(payload)
  const evidence: PluginEvidence[] = []
  let index = 0
  const exportFormat =
    readString(data.format) ||
    (artifact.type === 'ioc_export_stix2'
      ? 'stix2'
      : artifact.type === 'ioc_export_csv'
        ? 'csv'
        : 'json')

  for (const record of records.slice(0, 24)) {
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'ioc', `${record.type}:${record.value}`, index++),
      kind: 'ioc',
      category: iocExportCategory(record.type),
      label: `ioc_export:${record.type}`,
      value: record.value,
      confidence: confidenceFromIOCExport(record.confidence),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        `source=${record.source}`,
        `confidence=${record.confidence}`,
        ...record.tags.map((tag) => `tag=${tag}`),
      ],
      recommended_tools: ['malware.intel.loop', 'attack.map', 'analysis.evidence.graph'],
      details: {
        type: record.type,
        source: record.source,
        tags: record.tags,
        export_format: exportFormat,
        confidence_level: record.confidence,
      },
    })
  }

  for (const technique of techniques.slice(0, 12)) {
    evidence.push({
      id: pluginEvidenceNodeId(
        artifact,
        'behavior_cluster',
        `attack:${technique.technique_id}`,
        index++
      ),
      kind: 'behavior_cluster',
      category: categoryFromAttackTechnique(technique.technique_id),
      label: `ioc_export_attack:${technique.technique_id}`,
      value: technique.name || technique.technique_id,
      confidence: boundedConfidence(technique.confidence, 0.55),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: technique.tactics.map((tactic) => `tactic=${tactic}`),
      recommended_tools: ['attack.map', 'sigma.rule.generate', 'report.generate'],
      details: {
        technique_id: technique.technique_id,
        tactics: technique.tactics,
        export_format: exportFormat,
      },
    })
  }

  if (evidenceSummary) {
    const exportedIocCount = readNumber(evidenceSummary.exported_ioc_count, records.length)
    const attackTechniqueCount = readNumber(
      evidenceSummary.attack_technique_count,
      techniques.length
    )
    evidence.push({
      id: pluginEvidenceNodeId(
        artifact,
        'triage_signal',
        `ioc_export_summary:${exportedIocCount}:${attackTechniqueCount}`,
        index++
      ),
      kind: 'triage_signal',
      category: 'workflow',
      label: 'ioc_export_summary',
      value: `iocs=${exportedIocCount};attack=${attackTechniqueCount}`,
      confidence: exportedIocCount > 0 ? 0.72 : 0.45,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        `format=${exportFormat}`,
        `available_ioc_count=${readNumber(evidenceSummary.available_ioc_count, exportedIocCount)}`,
        `truncated=${Boolean(evidenceSummary.truncated_by_max_iocs)}`,
      ],
      recommended_tools: ['analysis.evidence.graph', 'report.generate', 'artifact.read'],
      details: {
        export_format: exportFormat,
        artifact_type: readString(evidenceSummary.artifact_type) || artifact.type,
        quality_gates: qualityGates || null,
      },
    })
  }

  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `ioc_export_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
        export_format: exportFormat,
      },
    })
  }

  return evidence
}

function sigmaRuleCategory(ruleType: string): string {
  if (ruleType === 'network_connection' || ruleType === 'dns_query') return 'network'
  if (ruleType === 'registry_event') return 'persistence'
  if (ruleType === 'process_creation') return 'process'
  if (ruleType === 'file_event') return 'file_activity'
  if (ruleType === 'image_load') return 'execution'
  return categoryFromCapabilityText(ruleType)
}

function sigmaRuleKind(ruleType: string): PluginEvidence['kind'] {
  if (ruleType === 'network_connection' || ruleType === 'dns_query') return 'behavior_cluster'
  if (ruleType === 'registry_event' || ruleType === 'process_creation') return 'behavior_cluster'
  return 'capability'
}

function normalizeSigmaRules(data: Record<string, unknown>): Record<string, unknown>[] {
  const rules = asArray(data.rules)
    .map(asRecord)
    .filter((rule): rule is Record<string, unknown> => Boolean(rule))
  if (rules.length > 0) return rules

  return readStringList(data.rule_types, 24).map((ruleType) => ({
    type: ruleType,
    title: ruleType,
    indicator_count: 0,
  }))
}

function evidenceFromSigmaRules(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0
  const level = readString(data.level) || readString(asRecord(data.evidence_summary)?.level)
  const rules = normalizeSigmaRules(data)

  for (const value of rules.slice(0, 16)) {
    const ruleType = readString(value.type) || `rule_${index}`
    const title = readString(value.title) || ruleType
    const indicatorCount = readNumber(value.indicator_count, 0)
    const category = sigmaRuleCategory(ruleType)
    const kind = sigmaRuleKind(ruleType)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, kind, `sigma:${ruleType}:${title}`, index++),
      kind,
      category,
      label: `sigma_rule:${ruleType}`,
      value: title,
      confidence: boundedConfidence(0.52 + Math.min(indicatorCount, 10) * 0.04, 0.56),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        `type=${ruleType}`,
        `indicator_count=${indicatorCount}`,
        level ? `level=${level}` : '',
      ].filter(Boolean),
      recommended_tools: ['attack.map', 'ioc.export', 'analysis.evidence.graph', 'report.generate'],
      details: {
        rule_type: ruleType,
        title,
        level: level || null,
        indicator_count: indicatorCount,
        deploy_requested: Boolean(data.deploy_requested),
      },
    })
  }

  const evidenceSummary = asRecord(data.evidence_summary)
  const evidenceCounts = asRecord(evidenceSummary?.evidence_counts)
  if (evidenceSummary) {
    const generatedRuleCount = readNumber(evidenceSummary.rules_generated, rules.length)
    const totalIndicators = readNumber(
      evidenceSummary.total_indicators,
      readNumber(data.total_indicators, 0)
    )
    evidence.push({
      id: pluginEvidenceNodeId(
        artifact,
        'triage_signal',
        `sigma_summary:${generatedRuleCount}:${totalIndicators}`,
        index++
      ),
      kind: 'triage_signal',
      category: 'workflow',
      label: 'sigma_rule_generation_summary',
      value: `rules=${generatedRuleCount};indicators=${totalIndicators}`,
      confidence: generatedRuleCount > 0 ? 0.72 : 0.45,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: [
        `strings=${readNumber(evidenceCounts?.strings, 0)}`,
        `imports=${readNumber(evidenceCounts?.imports, 0)}`,
        `network_indicators=${
          readNumber(evidenceCounts?.urls, 0) +
          readNumber(evidenceCounts?.ips, 0) +
          readNumber(evidenceCounts?.domains, 0)
        }`,
      ],
      recommended_tools: ['analysis.evidence.graph', 'report.generate', 'artifact.read'],
      details: {
        artifact_type: readString(evidenceSummary.artifact_type) || artifact.type,
        requested_rule_types: readStringList(evidenceSummary.requested_rule_types, 12),
        generated_rule_types: readStringList(evidenceSummary.generated_rule_types, 12),
        quality_gates: asRecord(data.quality_gates) || null,
      },
    })
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `sigma_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
        deploy_requested: Boolean(data.deploy_requested),
      },
    })
  }

  return evidence
}

function evidenceFromApiHashResolverPlan(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0

  for (const value of asArray(data.resolver_indicators).slice(0, 12)) {
    const indicator = asRecord(value)
    if (!indicator) continue
    const name = readString(indicator.indicator)
    if (!name) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `resolver:${name}`, index++),
      kind: 'triage_signal',
      category: 'dynamic_resolution',
      label: `api_hash_resolver:${name}`,
      value: name,
      confidence: boundedConfidence(indicator.confidence, 0.6),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(indicator.evidence, 8),
      recommended_tools: ['hash.identify', 'hash.resolve', 'analysis.evidence.graph'],
      details: {
        category: readString(indicator.category) || null,
        offset: readNumber(indicator.offset, -1) >= 0 ? readNumber(indicator.offset, -1) : null,
      },
    })
  }

  for (const value of asArray(data.hash_candidates).slice(0, 12)) {
    const candidate = asRecord(value)
    if (!candidate) continue
    const normalized = readString(candidate.normalized) || readString(candidate.value)
    if (!normalized) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `hash:${normalized}`, index++),
      kind: 'triage_signal',
      category: 'dynamic_resolution',
      label: `api_hash_candidate:${normalized}`,
      value: normalized,
      confidence: boundedConfidence(candidate.confidence, 0.45),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(candidate.evidence, 8),
      recommended_tools: ['hash.identify', 'hash.resolve'],
      details: {
        source: readString(candidate.source) || null,
        offset: readNumber(candidate.offset, -1) >= 0 ? readNumber(candidate.offset, -1) : null,
      },
    })
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `api_hash_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function categoryFromBehaviorFinding(
  category: string,
  technique: string
): EvidenceExpectationCategory {
  if (category === 'persistence') return 'persistence'
  if (category === 'injection') return 'injection'
  if (category === 'anti_analysis') return 'anti_analysis'
  if (category === 'execution') return 'execution'
  return categoryFromCapabilityText(technique)
}

function evidenceFromStaticBehaviorClassifier(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0

  for (const value of asArray(data.findings).slice(0, 16)) {
    const finding = asRecord(value)
    if (!finding) continue
    const id = readString(finding.id)
    const technique = readString(finding.technique)
    if (!id && !technique) continue
    const category = readString(finding.category)
    const severity = readString(finding.severity)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'behavior_cluster', id || technique, index++),
      kind: 'behavior_cluster',
      category: categoryFromBehaviorFinding(category, technique),
      label: `static_behavior:${id || technique}`,
      value: technique || id,
      confidence: boundedConfidence(finding.confidence, 0.6),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: asArray(finding.evidence)
        .map((item) => {
          const record = asRecord(item)
          if (!record) return readString(item)
          const kind = readString(record.kind)
          const source = readString(record.source)
          const itemValue = readString(record.value)
          return [source, kind, itemValue].filter(Boolean).join(':')
        })
        .filter(Boolean)
        .slice(0, 10),
      recommended_tools: readStringList(finding.recommended_next_tools, 8),
      details: {
        rule_id: id || null,
        technique: technique || null,
        severity: severity || 'unknown',
        evidence_count: asArray(finding.evidence).length,
      },
    })
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `static_behavior_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function evidenceFromCryptoIdentification(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const evidence: PluginEvidence[] = []
  let index = 0

  for (const value of asArray(data.algorithms).slice(0, 16)) {
    const finding = asRecord(value)
    if (!finding) continue
    const family = readString(finding.algorithm_family)
    const algorithm = readString(finding.algorithm_name) || family
    if (!algorithm) continue
    const functionName = readString(finding.function)
    const address = readString(finding.address)
    const sourceApis = readStringList(finding.source_apis, 8)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'capability', `${family}:${algorithm}`, index++),
      kind: 'capability',
      category: 'crypto',
      label: `crypto_algorithm:${algorithm}`,
      value: algorithm,
      confidence: boundedConfidence(finding.confidence, 0.6),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: asArray(finding.evidence)
        .map((item) => {
          const record = asRecord(item)
          if (!record) return readString(item)
          const sourceTool = readString(record.source_tool)
          const kind = readString(record.kind)
          const itemValue = readString(record.value)
          return [sourceTool, kind, itemValue].filter(Boolean).join(':')
        })
        .filter(Boolean)
        .slice(0, 10),
      recommended_tools: [
        'crypto.lifecycle.graph',
        'breakpoint.smart',
        'trace.condition',
        'analysis.evidence.graph',
      ],
      details: {
        algorithm_family: family || null,
        function: functionName || null,
        address: address || null,
        source_apis: sourceApis,
        dynamic_support: Boolean(finding.dynamic_support),
        xref_available: Boolean(finding.xref_available),
        candidate_constant_count: asArray(finding.candidate_constants).length,
      },
    })
  }

  for (const value of asArray(data.candidate_constants).slice(0, 12)) {
    const constant = asRecord(value)
    if (!constant) continue
    const kind = readString(constant.kind)
    const label = readString(constant.label) || kind
    if (!label) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'triage_signal', `constant:${label}`, index++),
      kind: 'triage_signal',
      category: 'crypto',
      label: `crypto_constant:${label}`,
      value: label,
      confidence: 0.66,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(constant.rationale, 8),
      recommended_tools: ['crypto.lifecycle.graph', 'breakpoint.smart', 'trace.condition'],
      details: {
        kind: kind || null,
        encoding: readString(constant.encoding) || null,
        source: readString(constant.source) || null,
        function: readString(constant.function) || null,
      },
    })
  }

  const workflowHandoff = asRecord(data.workflow_handoff)
  for (const value of asArray(workflowHandoff?.routing).slice(0, 8)) {
    const route = asRecord(value)
    if (!route) continue
    const goal = readString(route.goal)
    if (!goal) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'workflow_route', goal, index++),
      kind: 'workflow_route',
      category: 'workflow',
      label: `crypto_route:${goal}`,
      value: goal,
      confidence: readString(route.priority) === 'high' ? 0.85 : 0.62,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(route.required_evidence, 8),
      recommended_tools: readStringList(route.next_tools, 8),
      details: {
        priority: readString(route.priority) || 'normal',
      },
    })
  }

  return evidence
}

function crossDecompilerHandoff(payload: Record<string, unknown>): Record<string, unknown> | null {
  const data = unwrapPayload(payload)
  if (readString(data.schema) === 'rikune.cross_decompiler.function_evidence_handoff.v1') {
    return data
  }
  return asRecord(data.function_evidence_handoff)
}

function evidenceFromCrossDecompiler(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  const data = unwrapPayload(payload)
  const handoff = crossDecompilerHandoff(payload)
  const evidence: PluginEvidence[] = []
  let index = 0

  for (const value of asArray(handoff?.stable_functions)) {
    const fn = asRecord(value)
    if (!fn) continue
    const key = readString(fn.key)
    if (!key) continue
    const names = readStringList(fn.names, 6)
    const addresses = readStringList(fn.addresses, 6)
    const labelValue = names[0] || addresses[0] || key
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'stable_function', key, index++),
      kind: 'stable_function',
      category: 'function',
      label: `stable_function:${labelValue}`,
      value: key,
      confidence: boundedConfidence(fn.confidence, 0.6),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(fn.stable_facts, 10),
      recommended_tools: readStringList(fn.recommended_tools, 8),
      details: {
        backends: readStringList(fn.backends, 8),
        addresses,
        names,
        signatures: readStringList(fn.signatures, 6),
      },
    })
  }

  for (const value of asArray(handoff?.disputed_functions)) {
    const fn = asRecord(value)
    if (!fn) continue
    const key = readString(fn.key)
    if (!key) continue
    const severity = readString(fn.severity)
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'disputed_function', key, index++),
      kind: 'disputed_function',
      category: 'function_disagreement',
      label: `disputed_function:${key}`,
      value: key,
      confidence: severityConfidence(severity),
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readStringList(fn.conflict_fields, 10),
      recommended_tools: readStringList(fn.recommended_tools, 8),
      details: {
        severity: severity || 'unknown',
        backends: readStringList(fn.backends, 8),
      },
    })
  }

  for (const value of asArray(data.missing_backend_gaps).slice(0, 8)) {
    const gap = asRecord(value)
    if (!gap) continue
    const backend = readString(gap.backend)
    if (!backend) continue
    evidence.push({
      id: pluginEvidenceNodeId(artifact, 'backend_gap', backend, index++),
      kind: 'backend_gap',
      category: 'backend_coverage',
      label: `missing_backend:${backend}`,
      value: backend,
      confidence: 0.65,
      source_artifact_id: artifact.id,
      source_artifact_type: artifact.type,
      evidence: readString(gap.impact) ? [readString(gap.impact)] : [],
      recommended_tools: readStringList(gap.recommended_tools, 8),
    })
  }

  return evidence
}

function pluginEvidenceFromArtifact(
  artifact: ArtifactRef,
  payload: Record<string, unknown>
): PluginEvidence[] {
  if (artifact.type === 'static_config_carver') {
    return evidenceFromStaticConfigCarver(artifact, payload)
  }
  if (artifact.type === 'static_resource_graph') {
    return evidenceFromStaticResourceGraph(artifact, payload)
  }
  if (artifact.type === 'compiler_packer_attribution') {
    return evidenceFromCompilerPackerAttribution(artifact, payload)
  }
  if (artifact.type === 'backend_die_scan') {
    return evidenceFromDieScan(artifact, payload)
  }
  if (artifact.type === 'malware_intel_loop') {
    return evidenceFromMalwareIntelLoop(artifact, payload)
  }
  if (
    artifact.type === 'static_capability_triage' ||
    artifact.type === 'static_triage_correlation_bundle'
  ) {
    return evidenceFromStaticTriageBundle(artifact, payload)
  }
  if (artifact.type === 'static_behavior_classifier') {
    return evidenceFromStaticBehaviorClassifier(artifact, payload)
  }
  if (artifact.type === 'crypto_identification') {
    return evidenceFromCryptoIdentification(artifact, payload)
  }
  if (artifact.type === 'api_hash_resolver_plan') {
    return evidenceFromApiHashResolverPlan(artifact, payload)
  }
  if (
    artifact.type === 'cross_decompiler_consensus' ||
    artifact.type === 'function_evidence_handoff'
  ) {
    return evidenceFromCrossDecompiler(artifact, payload)
  }
  if (artifact.type === 'enriched_string_analysis') {
    return evidenceFromEnrichedStringAnalysis(artifact, payload)
  }
  if (artifact.type === 'backend_yara_scan') {
    return evidenceFromYaraScan(artifact, payload)
  }
  if (artifact.type === 'backend_yara_x_scan') {
    return evidenceFromYaraXScan(artifact, payload)
  }
  if (artifact.type === 'backend_upx_list' || artifact.type === 'backend_upx_test') {
    return evidenceFromUpxInspection(artifact, payload)
  }
  if (artifact.type === 'yara_rule_generation') {
    return evidenceFromYaraRuleGeneration(artifact, payload)
  }
  if (artifact.type === 'yara_family_rule') {
    return evidenceFromYaraRuleGeneration(artifact, payload)
  }
  if (artifact.type === 'sigma_rules') {
    return evidenceFromSigmaRules(artifact, payload)
  }
  if (
    artifact.type === 'ioc_export_json' ||
    artifact.type === 'ioc_export_csv' ||
    artifact.type === 'ioc_export_stix2'
  ) {
    return evidenceFromIOCExport(artifact, payload)
  }
  if (GENERIC_WORKFLOW_HANDOFF_ARTIFACT_TYPES.has(artifact.type)) {
    return evidenceFromGenericWorkflowHandoff(artifact, payload)
  }
  return []
}

function categoryFromApi(api: string): EvidenceExpectationCategory {
  if (/Reg(Open|Set|Query|Create|Delete)|NtSetValueKey/i.test(api)) return 'registry'
  if (/RunOnce|CreateService|StartService|schtasks|WMI|Winlogon/i.test(api)) return 'persistence'
  if (/WSA|socket|connect|send|recv|Internet|Http|WinHttp|URLDownload|Dns/i.test(api))
    return 'network'
  if (/CreateFile|ReadFile|WriteFile|DeleteFile|CopyFile|MoveFile|FindFirstFile/i.test(api))
    return 'file_activity'
  if (/CreateProcess|ShellExecute|WinExec|OpenProcess|TerminateProcess/i.test(api)) return 'process'
  if (
    /WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|SetThreadContext|NtMapViewOfSection|QueueUserAPC/i.test(
      api
    )
  )
    return 'injection'
  if (/Crypt|BCrypt|NCrypt|Hash|RtlDecrypt|SystemFunction0/i.test(api)) return 'crypto'
  if (
    /IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|NtQuerySystemInformation|GetTickCount|QueryPerformanceCounter|Sleep/i.test(
      api
    )
  )
    return 'anti_analysis'
  if (/VirtualAlloc|VirtualProtect|LoadLibrary|CreateThread|ResumeThread/i.test(api))
    return 'execution'
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

export function categoriesCompatible(
  expected: EvidenceExpectationCategory,
  observed: EvidenceExpectationCategory
): boolean {
  if (expected === observed) return true
  if (expected === 'persistence' && observed === 'registry') return true
  if (
    expected === 'embedded_payload' &&
    ['memory', 'execution', 'injection', 'process'].includes(observed)
  )
    return true
  if (
    expected === 'encrypted_or_packed_resource' &&
    ['memory', 'crypto', 'execution'].includes(observed)
  )
    return true
  if (expected === 'encoded_config' && ['crypto', 'network', 'registry'].includes(observed))
    return true
  if (
    expected === 'environment_state' &&
    ['anti_analysis', 'process', 'registry'].includes(observed)
  )
    return true
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
    const artifacts = database
      .findArtifactsByType(sampleId, artifactType)
      .slice(0, maxStaticArtifacts)
    for (const dbArtifact of artifacts) {
      const artifact = artifactRef(dbArtifact)
      const payload = await readArtifactPayload(workspaceManager, sampleId, artifact)
      if (payload) {
        staticArtifacts.push({ artifact, payload })
      }
    }
  }

  const expectations = staticArtifacts.flatMap(({ artifact, payload }) => {
    if (artifact.type === 'static_config_carver')
      return expectationsFromConfigArtifact(artifact, payload)
    if (artifact.type === 'static_resource_graph')
      return expectationsFromResourceArtifact(artifact, payload)
    return []
  })
  const pluginEvidence = staticArtifacts.flatMap(({ artifact, payload }) =>
    PLUGIN_EVIDENCE_ARTIFACT_TYPES.has(artifact.type)
      ? pluginEvidenceFromArtifact(artifact, payload)
      : []
  )

  const dynamicSummary = await loadDynamicTraceEvidence(workspaceManager, database, sampleId, {
    evidenceScope: options.evidenceScope || 'all',
    sessionTag: options.sessionTag,
  })
  const observations = observationsFromDynamicSummary(dynamicSummary)

  if (staticArtifacts.length === 0) {
    warnings.push(
      'No specialist static artifacts found. Run static.config.carver, static.resource.graph, malware.intel.loop, static.capability.triage, static.behavior.classify, or code.cross_decompiler.consensus for richer correlation.'
    )
  } else if (expectations.length === 0 && pluginEvidence.length === 0) {
    warnings.push(
      'Specialist static artifacts were found, but no reportable expectations or plugin evidence could be normalized.'
    )
  }
  if (!dynamicSummary) {
    warnings.push(
      'No dynamic trace artifacts found. Run dynamic.behavior.capture, sandbox.execute, or dynamic.trace.import for runtime correlation.'
    )
  }

  return {
    sample_id: sampleId,
    static_artifacts: staticArtifacts,
    dynamic_summary: dynamicSummary,
    expectations,
    observations,
    plugin_evidence: pluginEvidence,
    warnings,
  }
}

export function buildEvidenceGraph(bundle: EvidenceCorrelationBundle): EvidenceGraph {
  const pluginEvidence = bundle.plugin_evidence ?? []
  const nodes: EvidenceGraphNode[] = [
    {
      id: `sample:${bundle.sample_id}`,
      kind: 'sample',
      label: bundle.sample_id,
      details: {
        static_artifact_count: bundle.static_artifacts.length,
        expectation_count: bundle.expectations.length,
        observation_count: bundle.observations.length,
        plugin_evidence_count: pluginEvidence.length,
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
    edges.push({
      from: `sample:${bundle.sample_id}`,
      to: artifactNodeId,
      label: 'has_artifact',
      confidence: 1,
    })
  }

  if (bundle.dynamic_summary) {
    nodes.push({
      id: 'artifact:dynamic_trace_summary',
      kind: 'artifact',
      label: 'dynamic_trace_summary',
      category: 'dynamic_trace',
      details: {
        artifact_count: bundle.dynamic_summary.artifact_count,
        artifact_types: bundle.dynamic_summary.artifact_types,
        artifact_families: bundle.dynamic_summary.artifact_families,
        executed: bundle.dynamic_summary.executed,
        scope_note: bundle.dynamic_summary.scope_note,
      },
    })
    edges.push({
      from: `sample:${bundle.sample_id}`,
      to: 'artifact:dynamic_trace_summary',
      label: 'has_runtime_evidence',
      confidence: 1,
    })
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
    edges.push({
      from: `artifact:${expectation.source_artifact_id}`,
      to: nodeId,
      label: 'suggests',
      confidence: expectation.confidence,
    })
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
    edges.push({
      from: 'artifact:dynamic_trace_summary',
      to: nodeId,
      label: 'observed',
      confidence: observation.confidence,
    })
  }

  for (const item of pluginEvidence) {
    const nodeId = item.id
    const nodeKind =
      item.kind === 'stable_function' || item.kind === 'disputed_function'
        ? 'function_handoff'
        : 'plugin_evidence'
    nodes.push({
      id: nodeId,
      kind: nodeKind,
      label: item.label,
      category: item.category,
      confidence: item.confidence,
      source: item.source_artifact_type,
      details: {
        value: item.value,
        evidence: item.evidence,
        recommended_tools: item.recommended_tools || [],
        plugin_evidence_kind: item.kind,
        ...item.details,
      },
    })
    edges.push({
      from: `artifact:${item.source_artifact_id}`,
      to: nodeId,
      label: item.kind === 'workflow_route' ? 'routes' : 'supports',
      confidence: item.confidence,
    })
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

  for (const expectation of bundle.expectations) {
    for (const item of pluginEvidence) {
      if (
        item.category === expectation.category ||
        (item.category === 'function' && expectation.category !== 'unknown')
      ) {
        edges.push({
          from: expectation.id,
          to: item.id,
          label: 'supported_by_plugin_evidence',
          confidence: Number(Math.min(expectation.confidence, item.confidence).toFixed(3)),
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
    const matching = bundle.observations.filter((observation) =>
      categoriesCompatible(expectation.category, observation.category)
    )
    if (matching.length > 0) {
      confirmed.push({ category: expectation.category, expectation, observations: matching })
      for (const observation of matching) observedMatches.add(observation.id)
    } else {
      missing.push(expectation)
    }
  }

  const unexpected = bundle.observations.filter(
    (observation) => !observedMatches.has(observation.id)
  )
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
  if (
    missing.some((item) =>
      ['embedded_payload', 'encrypted_or_packed_resource', 'encoded_config'].includes(item.category)
    )
  ) {
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
