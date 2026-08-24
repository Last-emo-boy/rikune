import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  buildCapabilityConfidenceSemantics,
  ConfidenceSemanticsSchema,
} from '../../../analysis/confidence-semantics.js'
import {
  buildStaticAnalysisRequiredUserInputs,
  buildStaticAnalysisSetupActions,
} from '../../../setup-guidance.js'
import {
  persistStaticAnalysisJsonArtifact,
  STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
} from '../../../artifacts/static-analysis-artifacts.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker,
  type StaticWorkerResponse,
} from '../../../tools/static-worker-client.js'
import { throwIfAnalysisAborted } from '../../../analysis/analysis-cancellation.js'

const TOOL_NAME = 'static.capability.triage'
const TOOL_VERSION = '0.2.0'

const CapabilityFindingSchema = z.object({
  rule_id: z.string(),
  name: z.string(),
  namespace: z.string().nullable().optional(),
  scopes: z.array(z.string()),
  group: z.string(),
  confidence: z.number().min(0).max(1),
  match_count: z.number().int().nonnegative(),
  evidence_summary: z.string(),
})

const CapabilityBackendSchema = z.object({
  available: z.boolean(),
  engine: z.string().nullable().optional(),
  source: z.string().nullable().optional(),
  version: z.string().nullable().optional(),
  command: z.array(z.string()).optional(),
  error: z.string().nullable().optional(),
  rules: z
    .object({
      available: z.boolean(),
      path: z.string().nullable().optional(),
      source: z.string().nullable().optional(),
      error: z.string().nullable().optional(),
    })
    .optional(),
})

export const staticCapabilityTriageInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  rules_path: z
    .string()
    .optional()
    .describe('Optional explicit capa rules directory or rules file path'),
  timeout: z
    .number()
    .int()
    .min(10)
    .max(600)
    .default(300)
    .describe('Maximum capa execution time in seconds'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist normalized capability findings into reports/static_analysis'),
  register_analysis: z
    .boolean()
    .default(true)
    .describe('Insert a completed analysis row for capability triage runs'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag for persisted static-analysis artifacts'),
})

export const StaticCapabilityTriageDataSchema = z.object({
  status: z.enum(['ready', 'setup_required']),
  sample_id: z.string(),
  capability_count: z.number().int().nonnegative(),
  behavior_namespaces: z.array(z.string()),
  capability_groups: z.record(z.number().int().nonnegative()),
  capabilities: z.array(CapabilityFindingSchema),
  summary: z.string(),
  backend: CapabilityBackendSchema,
  confidence_semantics: ConfidenceSemanticsSchema.nullable(),
  analysis_id: z.string().optional(),
  artifact: z
    .object({
      id: z.string(),
      type: z.string(),
      path: z.string(),
      sha256: z.string(),
      mime: z.string().optional(),
    })
    .optional(),
  raw_backend: z.any().nullable().optional(),
  raw_backend_summary: z.record(z.unknown()).optional(),
  evidence_summary: z.record(z.any()).optional(),
  correlation_bundle: z.record(z.any()).optional(),
  workflow_handoff: z.record(z.any()).optional(),
  quality_gates: z.record(z.any()).optional(),
})

export const staticCapabilityTriageOutputSchema = z.object({
  ok: z.boolean(),
  data: StaticCapabilityTriageDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
      worker_elapsed_ms: z.number().optional(),
    })
    .optional(),
})

export const staticCapabilityTriageToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze executable behavior capabilities with a capa-style backend and return normalized capability groups, behavior/config/crypto/packer correlation bundles, evidence summaries, workflow handoffs, and setup guidance.',
  inputSchema: staticCapabilityTriageInputSchema,
  outputSchema: staticCapabilityTriageOutputSchema,
  aspects: {
    formats: ['pe', 'dll', 'elf', 'macho', 'shellcode'],
    platforms: ['windows', 'linux', 'macos', 'cross-platform'],
    execution: ['static', 'triage', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'capability-triage',
      'behavior-correlation',
      'config-correlation',
      'crypto-correlation',
      'packer-correlation',
      'workflow-handoff',
    ],
    evidence: ['behavior', 'crypto', 'strings', 'signatures', 'workflow', 'correlation-graph'],
  },
  artifacts: [
    {
      type: STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
      description: 'Normalized static capability findings and correlation bundle',
    },
    {
      type: 'static_triage_correlation_bundle',
      description: 'Behavior/config/crypto/packer routing bundle derived from capability findings',
    },
  ],
  evidence: [
    { category: 'behavior', artifactTypes: [STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE] },
    { category: 'crypto', artifactTypes: [STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE] },
    { category: 'signatures', artifactTypes: [STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE] },
    { category: 'correlation-graph', artifactTypes: ['static_triage_correlation_bundle'] },
    { category: 'provenance', artifactTypes: [STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'static-triage.capability-correlation',
      title: 'Static capability correlation loop',
      startsWith: ['static.capability.triage', 'strings.extract', 'pe.imports.extract'],
      nextTools: [
        'static.config.carver',
        'static.behavior.classify',
        'crypto.identify',
        'packer.detect',
        'analysis.evidence.graph',
        'malware.intel.loop',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [
        STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
        'static_triage_correlation_bundle',
      ],
      evidence: ['behavior', 'crypto', 'signatures', 'workflow', 'correlation-graph'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

interface StaticCapabilityTriageDependencies {
  callWorker?: (
    request: ReturnType<typeof buildStaticWorkerRequest>,
    options?: { database?: DatabaseManager; family?: string }
  ) => Promise<StaticWorkerResponse>
}

type CapabilityFinding = z.infer<typeof CapabilityFindingSchema>

interface CapabilitySignalSpec {
  kind: string
  pattern: RegExp
  rationale: string
  recommendedTools: string[]
}

const CONFIG_SIGNAL_SPECS: CapabilitySignalSpec[] = [
  {
    kind: 'network_config',
    pattern:
      /http|https|dns|url|uri|domain|socket|connect|download|c2|command[- ]?and[- ]?control/i,
    rationale: 'Network or HTTP capability findings can seed config carving and IOC export.',
    recommendedTools: ['static.config.carver', 'ioc.export', 'malware.intel.loop'],
  },
  {
    kind: 'registry_or_persistence_config',
    pattern: /registry|run key|service|scheduled task|startup|wmi|persistence|autorun/i,
    rationale:
      'Persistence capability findings can seed registry/config extraction and behavior classification.',
    recommendedTools: [
      'static.config.carver',
      'static.behavior.classify',
      'analysis.evidence.graph',
    ],
  },
  {
    kind: 'identity_or_mutex_config',
    pattern: /mutex|guid|botid|campaign|install|user-agent|beacon|sleep|interval/i,
    rationale:
      'Identifier-like capability findings can seed generic config carving before family labeling.',
    recommendedTools: ['static.config.carver', 'malware.intel.loop', 'report.generate'],
  },
]

const CRYPTO_SIGNAL_SPECS: CapabilitySignalSpec[] = [
  {
    kind: 'crypto_or_hashing',
    pattern: /crypt|encrypt|decrypt|cipher|aes|des|rc4|rsa|sha|md5|hash|hmac|key|iv/i,
    rationale: 'Crypto capability findings can seed function-localized crypto identification.',
    recommendedTools: ['crypto.identify', 'breakpoint.smart', 'analysis.evidence.graph'],
  },
]

const PACKER_SIGNAL_SPECS: CapabilitySignalSpec[] = [
  {
    kind: 'packer_or_obfuscation',
    pattern: /pack|unpack|upx|themida|vmprotect|obfuscat|virtualiz|entropy|compressed|encrypted/i,
    rationale:
      'Packing or obfuscation hints should be routed through packer detection and unpack planning.',
    recommendedTools: ['packer.detect', 'unpack.workflow.plan', 'analysis.evidence.graph'],
  },
  {
    kind: 'anti_analysis',
    pattern: /anti[-_ ]?debug|debugger|anti[-_ ]?vm|sandbox|timing|environment|isdebuggerpresent/i,
    rationale:
      'Anti-analysis findings affect unpacking, runtime planning, and breakpoint strategy.',
    recommendedTools: ['packer.detect', 'unpack.workflow.plan', 'dynamic.deep.plan'],
  },
]

function uniqueStrings(values: string[], limit?: number): string[] {
  const deduped = Array.from(new Set(values.filter((value) => value.trim().length > 0)))
  return typeof limit === 'number' ? deduped.slice(0, limit) : deduped
}

function compactCapability(finding: CapabilityFinding) {
  return {
    rule_id: finding.rule_id,
    name: finding.name,
    namespace: finding.namespace ?? null,
    group: finding.group,
    confidence: finding.confidence,
    match_count: finding.match_count,
    evidence_summary: finding.evidence_summary,
  }
}

function capabilityText(finding: CapabilityFinding): string {
  return [
    finding.rule_id,
    finding.name,
    finding.namespace ?? '',
    finding.group,
    finding.evidence_summary,
    ...finding.scopes,
  ].join(' ')
}

function collectCapabilitySignals(
  capabilities: CapabilityFinding[],
  specs: CapabilitySignalSpec[]
) {
  return specs
    .map((spec) => {
      const matched = capabilities.filter((finding) => spec.pattern.test(capabilityText(finding)))
      if (matched.length === 0) return null
      return {
        kind: spec.kind,
        confidence: Number(
          Math.min(0.98, Math.max(...matched.map((finding) => finding.confidence))).toFixed(2)
        ),
        source_capabilities: matched.slice(0, 6).map(compactCapability),
        evidence: uniqueStrings(
          matched.map((finding) => `${finding.rule_id}: ${finding.evidence_summary}`),
          8
        ),
        rationale: spec.rationale,
        recommended_tools: spec.recommendedTools,
      }
    })
    .filter((signal): signal is NonNullable<typeof signal> => Boolean(signal))
}

function buildEvidenceSummary(args: {
  status: 'ready' | 'setup_required'
  sampleId: string
  capabilities: CapabilityFinding[]
  behaviorNamespaces: string[]
  capabilityGroups: Record<string, number>
  backend: ReturnType<typeof normalizeBackend>
  confidenceScore: number
  warnings: string[]
}) {
  const topCapabilityGroups = Object.entries(args.capabilityGroups)
    .map(([group, count]) => ({ group, count }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 10)

  return {
    schema: 'rikune.static_triage.evidence_summary.v1',
    sample_id: args.sampleId,
    status: args.status,
    source_tool: TOOL_NAME,
    backend: {
      engine: args.backend.engine,
      source: args.backend.source,
      version: args.backend.version,
      rules_source: args.backend.rules?.source ?? null,
      rules_path: args.backend.rules?.path ?? null,
    },
    capability_count: args.capabilities.length,
    behavior_namespace_count: args.behaviorNamespaces.length,
    capability_group_count: Object.keys(args.capabilityGroups).length,
    top_capability_groups: topCapabilityGroups,
    high_confidence_count: args.capabilities.filter((finding) => finding.confidence >= 0.75).length,
    confidence_score: Number(args.confidenceScore.toFixed(2)),
    warning_count: args.warnings.length,
    warnings: args.warnings,
  }
}

function buildCorrelationBundle(args: {
  sampleId: string
  capabilities: CapabilityFinding[]
  behaviorNamespaces: string[]
  capabilityGroups: Record<string, number>
  confidenceScore: number
}) {
  const configSignals = collectCapabilitySignals(args.capabilities, CONFIG_SIGNAL_SPECS)
  const cryptoSignals = collectCapabilitySignals(args.capabilities, CRYPTO_SIGNAL_SPECS)
  const packerSignals = collectCapabilitySignals(args.capabilities, PACKER_SIGNAL_SPECS)
  const highConfidenceCapabilities = args.capabilities
    .filter((finding) => finding.confidence >= 0.7)
    .sort((left, right) => right.confidence - left.confidence)
    .slice(0, 12)
    .map(compactCapability)
  const behaviorCategories = uniqueStrings([
    ...args.behaviorNamespaces.map((namespace) => namespace.split('/')[0] || namespace),
    ...Object.keys(args.capabilityGroups),
  ])
  const recommendedNextTools = uniqueStrings([
    ...configSignals.flatMap((signal) => signal.recommended_tools),
    ...cryptoSignals.flatMap((signal) => signal.recommended_tools),
    ...packerSignals.flatMap((signal) => signal.recommended_tools),
    'static.behavior.classify',
    'analysis.evidence.graph',
    'report.generate',
  ])

  return {
    schema: 'rikune.static_triage.correlation_bundle.v1',
    result_mode: 'static_triage_correlation_bundle',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    confidence_score: Number(args.confidenceScore.toFixed(2)),
    bundles: {
      behavior: {
        namespaces: args.behaviorNamespaces,
        groups: args.capabilityGroups,
        behavior_categories: behaviorCategories,
        high_confidence_capabilities: highConfidenceCapabilities,
        recommended_tools: ['static.behavior.classify', 'analysis.evidence.graph'],
      },
      config: {
        suspected: configSignals.length > 0,
        signals: configSignals,
        recommended_tools:
          configSignals.length > 0
            ? ['static.config.carver', 'ioc.export', 'malware.intel.loop']
            : ['static.config.carver'],
      },
      crypto: {
        suspected: cryptoSignals.length > 0,
        signals: cryptoSignals,
        recommended_tools:
          cryptoSignals.length > 0
            ? ['crypto.identify', 'breakpoint.smart', 'analysis.evidence.graph']
            : ['crypto.identify'],
      },
      packer: {
        suspected: packerSignals.length > 0,
        signals: packerSignals,
        recommended_tools:
          packerSignals.length > 0
            ? ['packer.detect', 'unpack.workflow.plan', 'analysis.evidence.graph']
            : ['packer.detect'],
      },
    },
    routing: [
      {
        goal: 'config-and-ioc-correlation',
        priority: configSignals.length > 0 ? 'high' : 'normal',
        next_tools: ['static.config.carver', 'ioc.export', 'malware.intel.loop'],
        required_evidence: ['static capability findings', 'strings or config artifacts'],
      },
      {
        goal: 'crypto-localization',
        priority: cryptoSignals.length > 0 ? 'high' : 'normal',
        next_tools: ['crypto.identify', 'breakpoint.smart'],
        required_evidence: ['crypto capability or API hints', 'function/string context'],
      },
      {
        goal: 'packer-and-unpack-planning',
        priority: packerSignals.length > 0 ? 'high' : 'normal',
        next_tools: ['packer.detect', 'unpack.workflow.plan'],
        required_evidence: ['packer, obfuscation, entropy, or anti-analysis hints'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: ['correlation bundle', 'capability findings'],
      },
    ],
    recommended_next_tools: recommendedNextTools,
  }
}

function buildWorkflowHandoff(correlationBundle: ReturnType<typeof buildCorrelationBundle>) {
  return {
    handoff_mode: 'static_capability_to_correlation',
    recommended_next_tools: correlationBundle.recommended_next_tools,
    artifact_contract: {
      produces: [STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE, 'static_triage_correlation_bundle'],
      expected_consumers: [
        'static.config.carver',
        'static.behavior.classify',
        'crypto.identify',
        'packer.detect',
        'malware.intel.loop',
        'analysis.evidence.graph',
        'report.generate',
      ],
    },
    dynamic_boundary: {
      runtime_started: false,
      sample_executed: false,
      network_accessed: false,
      dynamic_tools_require_opt_in: true,
    },
  }
}

function normalizeBackend(rawBackend: unknown) {
  if (!rawBackend || typeof rawBackend !== 'object') {
    return {
      available: false,
      engine: null,
      source: null,
      version: null,
      command: undefined,
      error: null,
      rules: undefined,
    }
  }

  const raw = rawBackend as Record<string, unknown>
  const rulesValue =
    raw.rules && typeof raw.rules === 'object' ? (raw.rules as Record<string, unknown>) : undefined

  return {
    available: Boolean(raw.available),
    engine: typeof raw.engine === 'string' ? raw.engine : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    version: typeof raw.version === 'string' ? raw.version : null,
    command: Array.isArray(raw.command) ? raw.command.map((item) => String(item)) : undefined,
    error: typeof raw.error === 'string' ? raw.error : null,
    rules: rulesValue
      ? {
          available: Boolean(rulesValue.available),
          path: typeof rulesValue.path === 'string' ? rulesValue.path : null,
          source: typeof rulesValue.source === 'string' ? rulesValue.source : null,
          error: typeof rulesValue.error === 'string' ? rulesValue.error : null,
        }
      : undefined,
  }
}

function collectWarnings(response: StaticWorkerResponse, data: Record<string, unknown>): string[] {
  const warnings: string[] = []
  if (Array.isArray(response.warnings)) {
    warnings.push(...response.warnings.map((item) => String(item)))
  }
  if (Array.isArray(data.warnings)) {
    warnings.push(...data.warnings.map((item) => String(item)))
  }
  return Array.from(new Set(warnings.filter((item) => item.trim().length > 0)))
}

export function createStaticCapabilityTriageHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies: StaticCapabilityTriageDependencies = {}
) {
  const callWorker = dependencies.callWorker || callStaticWorker

  return async (args: ToolArgs, abortSignal?: AbortSignal): Promise<WorkerResult> => {
    throwIfAnalysisAborted(abortSignal)
    const startTime = Date.now()

    try {
      const input = staticCapabilityTriageInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          rules_path: input.rules_path,
          timeout: input.timeout,
        },
        toolVersion: TOOL_VERSION,
      })
      const workerResponse = await callWorker(workerRequest, {
        database,
        family: 'static_python.preview',
        abortSignal,
      })
      throwIfAnalysisAborted(abortSignal)
      if (!workerResponse.ok || !workerResponse.data || typeof workerResponse.data !== 'object') {
        return {
          ok: false,
          errors: workerResponse.errors?.length
            ? workerResponse.errors
            : ['Static capability triage failed.'],
          warnings: workerResponse.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
            worker_elapsed_ms: Number(workerResponse.metrics?.elapsed_ms || 0) || undefined,
          },
        }
      }

      const workerData = workerResponse.data as Record<string, unknown>
      const status = workerData.status === 'setup_required' ? 'setup_required' : 'ready'
      const capabilities = Array.isArray(workerData.capabilities)
        ? workerData.capabilities.map((item) => CapabilityFindingSchema.parse(item))
        : []
      const behaviorNamespaces = Array.isArray(workerData.behavior_namespaces)
        ? workerData.behavior_namespaces.map((item) => String(item))
        : []
      const capabilityGroups =
        workerData.capability_groups && typeof workerData.capability_groups === 'object'
          ? Object.fromEntries(
              Object.entries(workerData.capability_groups as Record<string, unknown>).map(
                ([key, value]) => [key, Number(value) || 0]
              )
            )
          : {}
      const backend = normalizeBackend(workerData.backend)
      const confidenceScore =
        status === 'ready'
          ? Math.min(
              0.97,
              0.28 +
                Math.min(0.45, capabilities.length * 0.04) +
                Math.min(0.18, Object.keys(capabilityGroups).length * 0.05)
            )
          : 0
      const confidenceSemantics =
        status === 'ready'
          ? buildCapabilityConfidenceSemantics({
              score: confidenceScore,
              findings: capabilities.length,
              groups: Object.keys(capabilityGroups),
              rulesSource: backend.rules?.source || backend.source || null,
            })
          : null
      const warnings = collectWarnings(workerResponse, workerData)
      const evidenceSummary = buildEvidenceSummary({
        status,
        sampleId: input.sample_id,
        capabilities,
        behaviorNamespaces,
        capabilityGroups,
        backend,
        confidenceScore,
        warnings,
      })
      const correlationBundle = buildCorrelationBundle({
        sampleId: input.sample_id,
        capabilities,
        behaviorNamespaces,
        capabilityGroups,
        confidenceScore,
      })
      const workflowHandoff = buildWorkflowHandoff(correlationBundle)
      const qualityGates = {
        passive_static_only: true,
        static_backend_used: Boolean(backend.available),
        dynamic_backend_started: false,
        sample_executed: false,
        network_accessed: false,
        runtime_started: false,
        setup_required: status === 'setup_required',
        minimum_capability_evidence_met: capabilities.length > 0,
        correlation_bundle_ready: status === 'ready',
        analyst_review_required:
          confidenceScore < 0.75 ||
          correlationBundle.bundles.crypto.suspected ||
          correlationBundle.bundles.packer.suspected,
        confidence_score: Number(confidenceScore.toFixed(2)),
      }
      const setupActions =
        status === 'setup_required' ? buildStaticAnalysisSetupActions() : undefined
      const requiredUserInputs =
        status === 'setup_required' ? buildStaticAnalysisRequiredUserInputs() : undefined

      let artifact
      const artifacts = []
      if (status === 'ready' && input.persist_artifact) {
        const artifactPayload = {
          session_tag: input.session_tag || null,
          sample_id: input.sample_id,
          status,
          capability_count: capabilities.length,
          behavior_namespaces: behaviorNamespaces,
          capability_groups: capabilityGroups,
          capabilities,
          summary:
            typeof workerData.summary === 'string'
              ? workerData.summary
              : `Recovered ${capabilities.length} static capability findings.`,
          backend,
          confidence_semantics: confidenceSemantics,
          raw_backend: workerData.raw_backend ?? null,
          raw_backend_summary:
            workerData.raw_backend_summary && typeof workerData.raw_backend_summary === 'object'
              ? workerData.raw_backend_summary
              : undefined,
          evidence_summary: evidenceSummary,
          correlation_bundle: correlationBundle,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
          created_at: new Date().toISOString(),
        }
        artifact = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE,
          'capabilities',
          artifactPayload,
          input.session_tag
        )
        artifacts.push(artifact)
      }

      let analysisId: string | undefined
      if (status === 'ready' && input.register_analysis) {
        analysisId = randomUUID()
        database.insertAnalysis({
          id: analysisId,
          sample_id: input.sample_id,
          stage: 'static_capability_triage',
          backend: 'capa',
          status: 'done',
          started_at: new Date(startTime).toISOString(),
          finished_at: new Date().toISOString(),
          output_json: JSON.stringify({
            capability_count: capabilities.length,
            behavior_namespaces: behaviorNamespaces,
            capability_groups: capabilityGroups,
            artifact_id: artifact?.id || null,
            correlation_bundle_ready: qualityGates.correlation_bundle_ready,
            recommended_next_tools: workflowHandoff.recommended_next_tools,
          }),
          metrics_json: JSON.stringify({
            capability_count: capabilities.length,
            group_count: Object.keys(capabilityGroups).length,
            confidence_score: qualityGates.confidence_score,
          }),
        })
      }

      return {
        ok: true,
        data: {
          status,
          sample_id: input.sample_id,
          capability_count: capabilities.length,
          behavior_namespaces: behaviorNamespaces,
          capability_groups: capabilityGroups,
          capabilities,
          summary:
            typeof workerData.summary === 'string'
              ? workerData.summary
              : `Recovered ${capabilities.length} static capability findings.`,
          backend,
          confidence_semantics: confidenceSemantics,
          analysis_id: analysisId,
          artifact,
          raw_backend: workerData.raw_backend ?? null,
          raw_backend_summary:
            workerData.raw_backend_summary && typeof workerData.raw_backend_summary === 'object'
              ? workerData.raw_backend_summary
              : undefined,
          evidence_summary: evidenceSummary,
          correlation_bundle: correlationBundle,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        setup_actions: setupActions,
        required_user_inputs: requiredUserInputs,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
          worker_elapsed_ms: Number(workerResponse.metrics?.elapsed_ms || 0) || undefined,
        },
      }
    } catch (error) {
      throwIfAnalysisAborted(abortSignal)
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
