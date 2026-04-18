/**
 * crypto.lifecycle.graph tool.
 *
 * Connects crypto-identification artifacts with imported runtime evidence into
 * a compact graph. This is a reporting/correlation tool only and never starts
 * a runtime or executes a sample.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import { loadDynamicTraceEvidence, type DynamicEvidenceScope } from '../../../artifacts/dynamic-trace.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import type { CryptoConstantCandidate, CryptoFinding } from '../../../artifacts/crypto-breakpoint-analysis.js'
import {
  CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
  loadCryptoPlanningArtifactSelection,
  type CryptoPlanningArtifactScope,
} from '../../static-triage/crypto-planning-artifacts.js'

const TOOL_NAME = 'crypto.lifecycle.graph'
const TOOL_VERSION = '0.1.0'

interface GraphNode {
  id: string
  label: string
  kind: string
  category?: string
  confidence?: number
  metadata?: Record<string, unknown>
}

interface GraphEdge {
  from: string
  to: string
  label: string
  confidence?: number
  metadata?: Record<string, unknown>
}

interface CryptoIdentificationPayload {
  algorithms?: CryptoFinding[]
  candidate_constants?: CryptoConstantCandidate[]
  runtime_observed_apis?: string[]
  summary?: string
}

export const CryptoLifecycleGraphInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  crypto_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  crypto_session_tag: z.string().optional(),
  runtime_evidence_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  runtime_evidence_session_tag: z.string().optional(),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

export const cryptoLifecycleGraphToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a crypto lifecycle graph from crypto.identify artifacts and imported runtime evidence, linking algorithms, functions, APIs, constants, stages, and memory regions. Does not execute the sample.',
  inputSchema: CryptoLifecycleGraphInputSchema,
}

function normalizeApiName(value: string): string {
  return value.trim().replace(/\(.*/, '').replace(/^.*!/, '')
}

function safeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9_.:-]+/g, '_').slice(0, 120)
}

function addNode(nodes: Map<string, GraphNode>, node: GraphNode) {
  const existing = nodes.get(node.id)
  if (!existing) {
    nodes.set(node.id, node)
    return
  }
  existing.confidence = Math.max(existing.confidence || 0, node.confidence || 0)
  existing.metadata = { ...(existing.metadata || {}), ...(node.metadata || {}) }
}

function addEdge(edges: GraphEdge[], edge: GraphEdge) {
  if (edges.some((item) => item.from === edge.from && item.to === edge.to && item.label === edge.label)) {
    return
  }
  edges.push(edge)
}

function collectFindings(payloads: CryptoIdentificationPayload[]): CryptoFinding[] {
  return payloads.flatMap((payload) => (Array.isArray(payload.algorithms) ? payload.algorithms : []))
}

function collectPayloadConstants(payloads: CryptoIdentificationPayload[]): CryptoConstantCandidate[] {
  return payloads.flatMap((payload) => (Array.isArray(payload.candidate_constants) ? payload.candidate_constants : []))
}

function constantPreview(constant: CryptoConstantCandidate): string {
  return constant.preview || constant.label || constant.kind
}

function buildGraph(options: {
  sampleId: string
  artifacts: ArtifactRef[]
  payloads: CryptoIdentificationPayload[]
  runtimeApis: string[]
  runtimeStages: string[]
  runtimeMemoryRegions: string[]
  runtimeExecuted: boolean
}) {
  const nodes = new Map<string, GraphNode>()
  const edges: GraphEdge[] = []
  const sampleNodeId = `sample:${options.sampleId}`
  const findingRecords = options.payloads.flatMap((payload, payloadIndex) =>
    (Array.isArray(payload.algorithms) ? payload.algorithms : []).map((finding) => ({
      finding,
      artifact: options.artifacts[payloadIndex],
    }))
  )
  const findings = findingRecords.map((record) => record.finding)
  const payloadConstants = collectPayloadConstants(options.payloads)
  const runtimeApiSet = new Set(options.runtimeApis.map((api) => normalizeApiName(api).toLowerCase()))
  const staticApiSet = new Set<string>()
  const corroboratedApis = new Set<string>()

  addNode(nodes, {
    id: sampleNodeId,
    label: options.sampleId,
    kind: 'sample',
    category: 'sample',
    confidence: 1,
  })

  options.artifacts.forEach((artifact, index) => {
    const artifactNodeId = `artifact:${artifact.id}`
    addNode(nodes, {
      id: artifactNodeId,
      label: artifact.type,
      kind: 'artifact',
      category: artifact.type,
      confidence: 1,
      metadata: { path: artifact.path, index },
    })
    addEdge(edges, { from: sampleNodeId, to: artifactNodeId, label: 'has_crypto_artifact', confidence: 1 })
  })

  findingRecords.forEach(({ finding, artifact }, index) => {
    const artifactNodeId = artifact ? `artifact:${artifact.id}` : sampleNodeId
    const algorithmLabel = finding.algorithm_name || finding.algorithm_family || `crypto_${index}`
    const algorithmNodeId = `crypto:${safeId(`${algorithmLabel}:${finding.function || finding.address || index}`)}`
    addNode(nodes, {
      id: algorithmNodeId,
      label: algorithmLabel,
      kind: 'crypto_algorithm',
      category: finding.algorithm_family,
      confidence: finding.confidence,
      metadata: {
        mode: finding.mode || null,
        dynamic_support: finding.dynamic_support,
        xref_available: finding.xref_available,
      },
    })
    addEdge(edges, { from: artifactNodeId, to: algorithmNodeId, label: 'reports_algorithm', confidence: finding.confidence })

    if (finding.function || finding.address) {
      const functionLabel = finding.function || finding.address || 'unknown_function'
      const functionNodeId = `function:${safeId(finding.address || functionLabel)}`
      addNode(nodes, {
        id: functionNodeId,
        label: functionLabel,
        kind: 'function',
        category: 'code_location',
        confidence: finding.confidence,
        metadata: { address: finding.address || null },
      })
      addEdge(edges, { from: algorithmNodeId, to: functionNodeId, label: 'localized_to', confidence: finding.confidence })
    }

    finding.source_apis.forEach((api) => {
      const normalized = normalizeApiName(api)
      if (!normalized) {
        return
      }
      const apiNodeId = `api:${safeId(normalized)}`
      staticApiSet.add(normalized.toLowerCase())
      addNode(nodes, {
        id: apiNodeId,
        label: normalized,
        kind: 'api',
        category: 'crypto_or_runtime_api',
        confidence: finding.confidence,
      })
      addEdge(edges, { from: algorithmNodeId, to: apiNodeId, label: 'uses_api', confidence: finding.confidence })
      if (runtimeApiSet.has(normalized.toLowerCase())) {
        corroboratedApis.add(normalized)
        addEdge(edges, { from: apiNodeId, to: algorithmNodeId, label: 'corroborates_crypto_path', confidence: Math.max(0.8, finding.confidence) })
      }
    })

    finding.candidate_constants.forEach((constant, constantIndex) => {
      const label = constant.label || `${constant.kind}_${constantIndex}`
      const constantNodeId = `constant:${safeId(`${constant.kind}:${label}:${constantPreview(constant)}`)}`
      addNode(nodes, {
        id: constantNodeId,
        label,
        kind: 'constant',
        category: constant.kind,
        confidence: finding.confidence,
        metadata: {
          preview: constantPreview(constant),
          encoding: constant.encoding,
          source: constant.source,
          byte_length: constant.byte_length || null,
          function: constant.function || null,
        },
      })
      addEdge(edges, { from: algorithmNodeId, to: constantNodeId, label: 'uses_constant', confidence: finding.confidence })
    })
  })

  payloadConstants.forEach((constant, index) => {
    const label = constant.label || `${constant.kind}_${index}`
    const constantNodeId = `constant:${safeId(`${constant.kind}:${label}:${constantPreview(constant)}`)}`
    addNode(nodes, {
      id: constantNodeId,
      label,
      kind: 'constant',
      category: constant.kind,
      confidence: 0.72,
      metadata: {
        preview: constantPreview(constant),
        encoding: constant.encoding,
        source: constant.source,
      },
    })
    addEdge(edges, { from: sampleNodeId, to: constantNodeId, label: 'has_crypto_constant_candidate', confidence: 0.72 })
  })

  if (options.runtimeApis.length > 0 || options.runtimeStages.length > 0 || options.runtimeMemoryRegions.length > 0) {
    const runtimeNodeId = 'runtime:summary'
    addNode(nodes, {
      id: runtimeNodeId,
      label: options.runtimeExecuted ? 'executed runtime evidence' : 'runtime or memory evidence',
      kind: 'runtime_evidence',
      category: options.runtimeExecuted ? 'executed_trace' : 'runtime_evidence',
      confidence: options.runtimeExecuted ? 0.92 : 0.72,
    })
    addEdge(edges, { from: sampleNodeId, to: runtimeNodeId, label: 'has_runtime_evidence', confidence: options.runtimeExecuted ? 0.92 : 0.72 })

    options.runtimeApis.forEach((api) => {
      const normalized = normalizeApiName(api)
      const apiNodeId = `api:${safeId(normalized)}`
      addNode(nodes, {
        id: apiNodeId,
        label: normalized,
        kind: 'api',
        category: 'runtime_api',
        confidence: options.runtimeExecuted ? 0.9 : 0.72,
      })
      addEdge(edges, { from: runtimeNodeId, to: apiNodeId, label: 'observed_api', confidence: options.runtimeExecuted ? 0.9 : 0.72 })
      if (staticApiSet.has(normalized.toLowerCase())) {
        corroboratedApis.add(normalized)
      }
    })

    options.runtimeStages.forEach((stage) => {
      const stageNodeId = `stage:${safeId(stage)}`
      addNode(nodes, {
        id: stageNodeId,
        label: stage,
        kind: 'runtime_stage',
        category: 'stage',
        confidence: options.runtimeExecuted ? 0.88 : 0.68,
      })
      addEdge(edges, { from: runtimeNodeId, to: stageNodeId, label: 'observed_stage', confidence: options.runtimeExecuted ? 0.88 : 0.68 })
    })

    options.runtimeMemoryRegions.forEach((region) => {
      const memoryNodeId = `memory:${safeId(region)}`
      addNode(nodes, {
        id: memoryNodeId,
        label: region,
        kind: 'memory_region',
        category: 'runtime_memory',
        confidence: options.runtimeExecuted ? 0.84 : 0.7,
      })
      addEdge(edges, { from: runtimeNodeId, to: memoryNodeId, label: 'observed_memory_region', confidence: options.runtimeExecuted ? 0.84 : 0.7 })
    })
  }

  return {
    nodes: Array.from(nodes.values()),
    edges,
    corroborated_apis: Array.from(corroboratedApis).sort(),
    static_api_count: staticApiSet.size,
  }
}

export function createCryptoLifecycleGraphHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = CryptoLifecycleGraphInputSchema.parse(args || {})
      const sample = deps.database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
        }
      }

      const cryptoSelection = await loadCryptoPlanningArtifactSelection<CryptoIdentificationPayload>(
        deps.workspaceManager,
        deps.database,
        input.sample_id,
        CRYPTO_IDENTIFICATION_ARTIFACT_TYPE,
        {
          scope: input.crypto_scope as CryptoPlanningArtifactScope,
          sessionTag: input.crypto_session_tag,
        }
      )
      const runtimeEvidence = await loadDynamicTraceEvidence(deps.workspaceManager, deps.database, input.sample_id, {
        evidenceScope: input.runtime_evidence_scope as DynamicEvidenceScope,
        sessionTag: input.runtime_evidence_session_tag,
      })

      const payloads = cryptoSelection.artifacts.map((item) => item.payload)
      const graph = buildGraph({
        sampleId: input.sample_id,
        artifacts: cryptoSelection.artifact_refs,
        payloads,
        runtimeApis: runtimeEvidence?.observed_apis || [],
        runtimeStages: runtimeEvidence?.stages || [],
        runtimeMemoryRegions: runtimeEvidence?.memory_regions || [],
        runtimeExecuted: Boolean(runtimeEvidence?.executed),
      })
      const findings = collectFindings(payloads)
      const constants = [
        ...collectPayloadConstants(payloads),
        ...findings.flatMap((finding) => finding.candidate_constants || []),
      ]
      const warnings: string[] = []
      if (cryptoSelection.artifacts.length === 0) {
        warnings.push('No crypto_identification artifacts were found. Run crypto.identify first for a richer lifecycle graph.')
      }
      if (!runtimeEvidence) {
        warnings.push('No dynamic trace artifacts were found; graph is limited to static crypto evidence.')
      }

      const data = {
        schema: 'rikune.crypto_lifecycle_graph.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        crypto_scope: input.crypto_scope,
        crypto_session_tag: input.crypto_session_tag || null,
        runtime_evidence_scope: input.runtime_evidence_scope,
        runtime_evidence_session_tag: input.runtime_evidence_session_tag || null,
        summary: {
          crypto_artifact_count: cryptoSelection.artifacts.length,
          algorithm_count: findings.length,
          constant_count: constants.length,
          runtime_api_count: runtimeEvidence?.observed_apis.length || 0,
          runtime_stage_count: runtimeEvidence?.stages.length || 0,
          runtime_memory_region_count: runtimeEvidence?.memory_regions.length || 0,
          dynamic_executed: Boolean(runtimeEvidence?.executed),
          static_api_count: graph.static_api_count,
          corroborated_api_count: graph.corroborated_apis.length,
          node_count: graph.nodes.length,
          edge_count: graph.edges.length,
        },
        crypto_selection: {
          artifact_refs: cryptoSelection.artifact_refs,
          session_tags: cryptoSelection.session_tags,
          scope_note: cryptoSelection.scope_note,
        },
        dynamic_summary: runtimeEvidence
          ? {
              artifact_count: runtimeEvidence.artifact_count,
              executed: runtimeEvidence.executed,
              observed_apis: runtimeEvidence.observed_apis,
              stages: runtimeEvidence.stages,
              memory_regions: runtimeEvidence.memory_regions,
              scope_note: runtimeEvidence.scope_note,
            }
          : null,
        graph,
        recommended_next_tools: [
          'breakpoint.smart',
          'trace.condition',
          'frida.runtime.instrument',
          'dynamic.behavior.diff',
          'analysis.evidence.graph',
        ],
        next_actions: graph.corroborated_apis.length > 0
          ? [
              `Prioritize trace.condition capture around corroborated API(s): ${graph.corroborated_apis.slice(0, 8).join(', ')}.`,
              'Use breakpoint.smart to turn crypto APIs/functions into bounded runtime capture plans.',
            ]
          : [
              'Run crypto.identify with include_runtime_evidence=true after importing a runtime trace.',
              'Use breakpoint.smart and trace.condition to collect key/IV buffer snapshots for suspected crypto calls.',
            ],
        warnings,
      }

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          input.sample_id,
          'crypto_lifecycle_graph',
          'crypto_lifecycle_graph',
          data,
          input.session_tag
        ))
      }

      return {
        ok: true,
        data,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
