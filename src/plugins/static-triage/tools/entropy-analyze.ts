/**
 * entropy.analyze tool implementation
 * Section-level entropy analysis for packing/crypto detection.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { CacheManager } from '../../../cache-manager.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from '../../../tools/cache-observability.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from '../../../tools/static-worker-client.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import { CACHE_TTL_30_DAYS } from '../../../constants/cache-ttl.js'

const TOOL_NAME = 'entropy.analyze'
const TOOL_VERSION = '0.2.0'
const ENTROPY_ANALYSIS_ARTIFACT_TYPE = 'entropy_analysis'
const ENTROPY_RECOMMENDED_NEXT_TOOLS = ['artifact.read', 'workflow.search']
const ENTROPY_PROFILE_NEXT_TOOLS = [
  'packer.detect',
  'obfuscation.detect',
  'unpack.workflow.plan',
  'analysis.evidence.graph',
  'report.generate',
]
const ENTROPY_SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]
const CACHE_TTL_MS = CACHE_TTL_30_DAYS

type EntropyAnalyzeDependencies = {
  resolvePrimarySamplePath?: typeof resolvePrimarySamplePath
  callStaticWorker?: typeof callPooledStaticWorker
  persistStaticAnalysisJsonArtifact?: typeof persistStaticAnalysisJsonArtifact
}

export const EntropyAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  block_size: z
    .number()
    .int()
    .min(64)
    .max(4096)
    .default(256)
    .describe('Block size in bytes for entropy calculation'),
  high_entropy_threshold: z
    .number()
    .min(5.0)
    .max(8.0)
    .default(7.2)
    .describe('Threshold for marking high-entropy regions (0-8 scale)'),
  force_refresh: z.boolean().default(false).describe('Bypass cache lookup'),
})

export type EntropyAnalyzeInput = z.infer<typeof EntropyAnalyzeInputSchema>

const EntropyAnalyzeDataSchema = z.object({
  schema: z.string().optional(),
  tool_version: z.string().optional(),
  sample_id: z.string().optional(),
  artifact_type: z.string().optional(),
  file_size: z.number(),
  overall_entropy: z.number(),
  block_size: z.number(),
  block_count: z.number(),
  histogram: z.array(z.number()),
  sections: z.array(
    z.object({
      name: z.string(),
      entropy: z.number(),
      raw_size: z.number(),
      virtual_size: z.number(),
      vsize_ratio: z.number(),
      characteristics: z.string(),
      suspicious: z.boolean(),
    })
  ),
  high_entropy_regions: z.array(
    z.object({
      offset: z.number(),
      end_offset: z.number(),
      length: z.number(),
      avg_entropy: z.number(),
    })
  ),
  classification: z.object({
    packing_likelihood: z.string(),
    crypto_data_likelihood: z.string(),
    is_pe: z.boolean(),
  }),
  evidence_summary: z.record(z.any()).optional(),
  workflow_handoff: z.record(z.any()).optional(),
  quality_gates: z.record(z.any()).optional(),
  source_recommended_next_tools: z.array(z.string()).optional(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()).optional(),
})

export const EntropyAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: EntropyAnalyzeDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).passthrough().optional(),
})

export const entropyAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compute byte-level and section-level Shannon entropy for a binary sample. ' +
    'Identifies packed regions, encrypted data, and high-entropy anomalies. ' +
    'Outputs per-section entropy, a block histogram, and packing/crypto likelihood classification.',
  inputSchema: EntropyAnalyzeInputSchema,
  outputSchema: EntropyAnalyzeOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dll', 'shellcode', 'firmware', 'raw'],
    platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel'],
    execution: ['static', 'triage'],
    runtimes: ['static-worker'],
    safety: ENTROPY_SAFETY,
    capabilities: [
      'entropy-analysis',
      'packer-triage',
      'crypto-data-triage',
      'section-anomaly-detection',
      'workflow-handoff',
    ],
    evidence: ['structure', 'signatures', 'artifact', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: ENTROPY_ANALYSIS_ARTIFACT_TYPE,
      description: 'Static entropy analysis envelope with section and high-entropy region evidence',
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: [ENTROPY_ANALYSIS_ARTIFACT_TYPE],
    },
    {
      category: 'signatures',
      artifactTypes: [ENTROPY_ANALYSIS_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [ENTROPY_ANALYSIS_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [ENTROPY_ANALYSIS_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'entropy.static-handoff',
      title: 'Entropy static triage handoff',
      description:
        'Run passive entropy analysis, persist section and high-entropy region evidence, then route packed or crypto-like samples into scoped packer, obfuscation, unpacking, evidence graph, and reporting workflows.',
      startsWith: [TOOL_NAME],
      nextTools: [...ENTROPY_RECOMMENDED_NEXT_TOOLS, ...ENTROPY_PROFILE_NEXT_TOOLS],
      requiredArtifacts: ['sample'],
      producesArtifacts: [ENTROPY_ANALYSIS_ARTIFACT_TYPE],
      evidence: ['structure', 'signatures', 'artifact', 'workflow', 'provenance'],
      safety: ENTROPY_SAFETY,
      runtimeBackends: ['static-worker'],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    maxRuntimeMs: 60000,
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'entropy.analyze reads sample bytes through the static worker and never executes the sample.',
      'workflow.search should use the persisted entropy envelope to select scoped packer, unpacking, or evidence graph follow-ups.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'static-worker',
    backendKind: 'builtin',
    adapter: 'static_worker.entropy_analyze',
    availability: 'builtin',
    supportedModes: ['entropy'],
    defaultMode: 'entropy',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [ENTROPY_ANALYSIS_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 60000,
      maxOutputBytes: 8 * 1024 * 1024,
      notes: ['Only byte entropy summaries and bounded region lists are returned by this tool.'],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [],
      missingBackendBehavior: 'Return worker error without falling back to sample execution.',
    },
  },
}

function unwrapWorkerEnvelope(payload: unknown): {
  data: unknown
  warnings: string[]
  errors: string[]
  metrics: Record<string, unknown>
} {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { data: payload, warnings: [], errors: [], metrics: {} }
  }
  const record = payload as Record<string, unknown>
  if (
    'ok' in record &&
    'data' in record &&
    ('warnings' in record || 'errors' in record || 'metrics' in record)
  ) {
    return {
      data: record.data,
      warnings: Array.isArray(record.warnings) ? record.warnings.map(String) : [],
      errors: Array.isArray(record.errors) ? record.errors.map(String) : [],
      metrics:
        record.metrics && typeof record.metrics === 'object' && !Array.isArray(record.metrics)
          ? (record.metrics as Record<string, unknown>)
          : {},
    }
  }
  return { data: payload, warnings: [], errors: [], metrics: {} }
}

function suspiciousSectionCount(data: z.infer<typeof EntropyAnalyzeDataSchema>): number {
  return data.sections.filter((section) => section.suspicious).length
}

function buildEntropyEvidenceSummary(args: {
  sampleId: string
  data: z.infer<typeof EntropyAnalyzeDataSchema>
  artifact?: ArtifactRef
}) {
  return {
    schema: 'rikune.entropy_analysis.evidence_summary.v1',
    source_tool: TOOL_NAME,
    tool_version: TOOL_VERSION,
    artifact_type: ENTROPY_ANALYSIS_ARTIFACT_TYPE,
    sample_id: args.sampleId,
    file_size: args.data.file_size,
    overall_entropy: args.data.overall_entropy,
    block_size: args.data.block_size,
    block_count: args.data.block_count,
    section_count: args.data.sections.length,
    suspicious_section_count: suspiciousSectionCount(args.data),
    high_entropy_region_count: args.data.high_entropy_regions.length,
    packing_likelihood: args.data.classification.packing_likelihood,
    crypto_data_likelihood: args.data.classification.crypto_data_likelihood,
    is_pe: args.data.classification.is_pe,
    artifact_id: args.artifact?.id ?? null,
  }
}

function buildEntropyWorkflowHandoff(args: {
  sampleId: string
  data: z.infer<typeof EntropyAnalyzeDataSchema>
  artifact?: ArtifactRef
}) {
  const packed =
    args.data.classification.packing_likelihood !== 'low' ||
    args.data.high_entropy_regions.length > 0 ||
    suspiciousSectionCount(args.data) > 0
  return {
    schema: 'rikune.entropy_analysis.workflow_handoff.v1',
    handoff_mode: 'entropy_static_triage_to_packer_or_crypto_review',
    artifact_type: ENTROPY_ANALYSIS_ARTIFACT_TYPE,
    sample_id: args.sampleId,
    recommended_next_tools: ENTROPY_RECOMMENDED_NEXT_TOOLS,
    artifact_contract: {
      type: ENTROPY_ANALYSIS_ARTIFACT_TYPE,
      suggested_read_mode: 'profile',
      artifact_id: args.artifact?.id ?? null,
      content_kind: 'entropy_section_and_region_summary',
    },
    routing: [
      {
        goal: 'review-entropy-profile',
        priority: args.artifact ? 'high' : 'normal',
        next_tools: ['artifact.read'],
        required_evidence: [ENTROPY_ANALYSIS_ARTIFACT_TYPE],
      },
      {
        goal: 'packer-and-obfuscation-corroboration',
        priority: packed ? 'high' : 'normal',
        next_tools: ['packer.detect', 'obfuscation.detect', 'analysis.evidence.graph'],
        required_evidence: [
          ENTROPY_ANALYSIS_ARTIFACT_TYPE,
          'high_entropy_regions',
          'section_entropy',
        ],
      },
      {
        goal: 'unpack-planning',
        priority: packed ? 'normal' : 'low',
        next_tools: ['unpack.workflow.plan'],
        required_evidence: [ENTROPY_ANALYSIS_ARTIFACT_TYPE, 'packer evidence'],
      },
      {
        goal: 'report-entropy-findings',
        priority: 'normal',
        next_tools: ['report.generate'],
        required_evidence: [ENTROPY_ANALYSIS_ARTIFACT_TYPE],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: true,
      backend_kind: 'builtin-static-worker',
      live_execution_started: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildEntropyQualityGates(args: {
  data: z.infer<typeof EntropyAnalyzeDataSchema>
  artifactPersisted: boolean
}) {
  return {
    schema: 'rikune.entropy_analysis.quality_gates.v1',
    passive_static_analysis: true,
    read_only_backend: true,
    sample_executed_by_tool: false,
    backend_started_with_bounded_command: true,
    network_accessed_by_tool: false,
    mutation_performed: false,
    output_bounded_inline: true,
    artifact_persisted: args.artifactPersisted,
    analyst_review_required: true,
    high_entropy_region_count: args.data.high_entropy_regions.length,
    suspicious_section_count: suspiciousSectionCount(args.data),
  }
}

function buildEntropyNextActions(args: {
  data: z.infer<typeof EntropyAnalyzeDataSchema>
  artifact?: ArtifactRef
}) {
  const packed =
    args.data.classification.packing_likelihood !== 'low' ||
    args.data.high_entropy_regions.length > 0
  return [
    args.artifact
      ? 'Use artifact.read in profile mode to inspect the persisted entropy analysis envelope.'
      : 'Persist entropy analysis before relying on it as packer or crypto evidence.',
    packed
      ? 'Use workflow.search to activate scoped packer, obfuscation, or unpack-planning follow-ups.'
      : 'Use workflow.search to select evidence graph or reporting follow-ups without exposing unpacking tools.',
    'Corroborate high-entropy regions with packer signatures, imports, strings, or section metadata before reporting.',
  ]
}

function buildEntropyOutputData(args: {
  sampleId: string
  data: z.infer<typeof EntropyAnalyzeDataSchema>
  artifact?: ArtifactRef
}) {
  const sourceRecommendedNextTools = args.data.recommended_next_tools ?? []
  return {
    ...args.data,
    schema: 'rikune.entropy_analysis.v1',
    tool_version: TOOL_VERSION,
    sample_id: args.sampleId,
    artifact_type: ENTROPY_ANALYSIS_ARTIFACT_TYPE,
    source_recommended_next_tools: sourceRecommendedNextTools,
    evidence_summary: buildEntropyEvidenceSummary(args),
    workflow_handoff: buildEntropyWorkflowHandoff(args),
    quality_gates: buildEntropyQualityGates({
      data: args.data,
      artifactPersisted: Boolean(args.artifact),
    }),
    recommended_next_tools: ENTROPY_RECOMMENDED_NEXT_TOOLS,
    next_actions: buildEntropyNextActions(args),
  }
}

export function createEntropyAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: EntropyAnalyzeDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = EntropyAnalyzeInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          block_size: input.block_size,
          high_entropy_threshold: input.high_entropy_threshold,
        },
      })

      if (!input.force_refresh) {
        const cached = await lookupCachedResult(cacheManager, cacheKey)
        if (cached) {
          const normalized = unwrapWorkerEnvelope(cached.data)
          const data = EntropyAnalyzeDataSchema.parse(normalized.data)
          const outputData = buildEntropyOutputData({
            sampleId: input.sample_id,
            data,
          })
          return {
            ok: true,
            data: outputData,
            warnings: [
              'Result from cache',
              formatCacheWarning(cached.metadata),
              ...normalized.warnings,
            ],
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME, cached: true },
          }
        }
      }

      const resolvePrimarySamplePathImpl =
        dependencies?.resolvePrimarySamplePath || resolvePrimarySamplePath
      const { samplePath } = await resolvePrimarySamplePathImpl(workspaceManager, input.sample_id)
      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          block_size: input.block_size,
          high_entropy_threshold: input.high_entropy_threshold,
        },
        toolVersion: TOOL_VERSION,
      })

      const callStaticWorkerImpl = dependencies?.callStaticWorker || callPooledStaticWorker
      const workerResponse = await callStaticWorkerImpl(workerRequest, { database })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const normalized = unwrapWorkerEnvelope(workerResponse.data)
      if (normalized.errors.length > 0) {
        return {
          ok: false,
          errors: normalized.errors,
          warnings: [...(workerResponse.warnings || []), ...normalized.warnings],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }
      const data = EntropyAnalyzeDataSchema.parse(normalized.data)
      await cacheManager.setCachedResult(cacheKey, data, CACHE_TTL_MS, sample.sha256)

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      const persistStaticAnalysisJsonArtifactImpl =
        dependencies?.persistStaticAnalysisJsonArtifact || persistStaticAnalysisJsonArtifact
      try {
        artifact = await persistStaticAnalysisJsonArtifactImpl(
          workspaceManager,
          database,
          input.sample_id,
          ENTROPY_ANALYSIS_ARTIFACT_TYPE,
          'entropy',
          {
            tool: TOOL_NAME,
            data: buildEntropyOutputData({ sampleId: input.sample_id, data }),
          }
        )
        artifacts.push(artifact)
      } catch {
        /* best effort */
      }

      const outputData = buildEntropyOutputData({
        sampleId: input.sample_id,
        data,
        artifact,
      })

      return {
        ok: true,
        data: outputData,
        warnings: [...(workerResponse.warnings || []), ...normalized.warnings],
        artifacts,
        metrics: {
          ...normalized.metrics,
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
