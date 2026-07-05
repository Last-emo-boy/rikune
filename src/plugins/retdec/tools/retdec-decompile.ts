/**
 * RetDec decompile tool - decompile a sample with RetDec.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from '../../docker-shared.js'
import {
  fs,
  os,
  path,
  ArtifactRefSchema,
  BackendSchema,
  SharedMetricsSchema,
  executeCommand,
  truncateText,
  normalizeError,
  persistBackendArtifact,
  buildMetrics,
  buildStaticSetupRequired,
  resolveSampleFile,
  resolveAnalysisBackends,
} from '../../docker-shared.js'

const TOOL_NAME = 'retdec.decompile'
const TOOL_VERSION = '0.2.0'
const RETDEC_OUTPUT_FORMATS = ['plain', 'json-human'] as const
const RETDEC_ARTIFACT_TYPES = RETDEC_OUTPUT_FORMATS.map(
  (format) => `backend_retdec_decompile_${format}`
)
const RETDEC_RECOMMENDED_NEXT_TOOLS = ['artifact.read', 'workflow.search']
const RETDEC_PROFILE_NEXT_TOOLS = [
  'code.cross_decompiler.consensus',
  'workflow.reconstruct',
  'analysis.evidence.graph',
  'report.generate',
]
const RETDEC_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
const RETDEC_SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]
const CONTROL_FLOW_KEYWORDS = new Set([
  'if',
  'for',
  'while',
  'switch',
  'return',
  'sizeof',
  'case',
  'do',
])

interface RetDecSemanticCompleteness {
  semantic_completeness: 'suspect' | 'unverified'
  decompiler_confidence_score: number
  risk_flags: string[]
  reasons: string[]
}

export const retdecDecompileInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  output_format: z
    .enum(RETDEC_OUTPUT_FORMATS)
    .default('plain')
    .describe('RetDec output format for the main decompilation file.'),
  timeout_sec: z
    .number()
    .int()
    .min(10)
    .max(900)
    .default(300)
    .describe('RetDec timeout in seconds.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist the generated decompilation output as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const retdecDecompileOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      output_format: z.string().optional(),
      preview: z
        .object({
          inline_text: z.string(),
          truncated: z.boolean(),
          char_count: z.number().int().nonnegative(),
        })
        .optional(),
      artifact: ArtifactRefSchema.optional(),
      supporting_artifacts: z.array(ArtifactRefSchema).optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const retdecDecompileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decompile a sample with RetDec and persist the generated high-level output as an artifact. Use this when you explicitly want a RetDec alternative to the default Ghidra-oriented flow.',
  inputSchema: retdecDecompileInputSchema,
  outputSchema: retdecDecompileOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho'],
    platforms: ['windows', 'linux', 'macos', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips'],
    execution: ['static', 'decompilation'],
    runtimes: ['retdec'],
    safety: RETDEC_SAFETY,
    capabilities: [
      'decompile',
      'source-reconstruction',
      'cross-backend-corroboration',
      'workflow-handoff',
    ],
    evidence: ['artifact', 'symbols', 'structure', 'decompiled-code', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'backend_retdec_decompile_plain',
      description: 'RetDec plain C-like high-level decompilation output',
    },
    {
      type: 'backend_retdec_decompile_json-human',
      description: 'RetDec JSON high-level decompilation output',
    },
  ],
  evidence: [
    {
      category: 'artifact',
      artifactTypes: ['backend_retdec_decompile_plain', 'backend_retdec_decompile_json-human'],
    },
    {
      category: 'decompiled-code',
      artifactTypes: ['backend_retdec_decompile_plain', 'backend_retdec_decompile_json-human'],
    },
    {
      category: 'workflow',
      artifactTypes: ['backend_retdec_decompile_plain', 'backend_retdec_decompile_json-human'],
    },
    {
      category: 'provenance',
      artifactTypes: ['backend_retdec_decompile_plain', 'backend_retdec_decompile_json-human'],
    },
  ],
  workflowRecipes: [
    {
      id: 'retdec.decompile-handoff',
      title: 'RetDec decompile handoff',
      description:
        'Run a bounded RetDec static decompile, then hand off the persisted output to artifact review, cross-decompiler consensus, reconstruction, evidence graph, and reporting.',
      startsWith: [TOOL_NAME],
      nextTools: [...RETDEC_RECOMMENDED_NEXT_TOOLS, ...RETDEC_PROFILE_NEXT_TOOLS],
      requiredArtifacts: ['sample'],
      producesArtifacts: RETDEC_ARTIFACT_TYPES,
      evidence: ['decompiled-code', 'symbols', 'structure', 'workflow', 'provenance'],
      safety: RETDEC_SAFETY,
      runtimeBackends: ['retdec'],
      outputFormats: RETDEC_OUTPUT_FORMATS,
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: false,
    allowedBackends: ['local'],
    maxRuntimeMs: 900000,
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'RetDec is used as a bounded read-only static decompiler and must not execute the sample.',
      'workflow.search should activate only retdec.decompile for this profile before any broader cross-backend workflow.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'retdec',
    backendKind: 'external',
    adapter: 'retdec.static.decompile',
    availability: 'optional',
    envVar: 'RETDEC_PATH',
    commandHint:
      'retdec-decompiler --cleanup --output-format <plain|json-human> --output <output> <sample>',
    versionHint: 'retdec-decompiler --version',
    supportedModes: [...RETDEC_OUTPUT_FORMATS],
    defaultMode: 'plain',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: RETDEC_ARTIFACT_TYPES,
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 300000,
      maxOutputBytes: RETDEC_MAX_OUTPUT_BYTES,
      notes: ['Only bounded static decompilation output is persisted by this tool.'],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Set RETDEC_PATH to a pinned retdec-decompiler binary or install retdec-decompiler on PATH.',
      ],
      missingBackendBehavior: 'Return setup_required without running any backend command.',
    },
    packaging: {
      installRoute: 'profile-gated',
      installProfile: 'heavy',
      dockerFeature: 'retdec',
      envVar: 'RETDEC_PATH',
      dockerDefault: '/opt/retdec/bin/retdec-decompiler',
    },
  },
}

function retdecArtifactType(
  outputFormat: z.infer<typeof retdecDecompileInputSchema>['output_format']
) {
  return `backend_retdec_decompile_${outputFormat}`
}

function buildRetDecEvidenceSummary(args: {
  sampleId: string
  outputFormat: z.infer<typeof retdecDecompileInputSchema>['output_format']
  charCount: number
  previewTruncated: boolean
  artifact?: ArtifactRef
  backendVersion?: string | null
}) {
  return {
    schema: 'rikune.retdec_decompile.evidence_summary.v1',
    source_tool: TOOL_NAME,
    tool_version: TOOL_VERSION,
    artifact_type: retdecArtifactType(args.outputFormat),
    sample_id: args.sampleId,
    output_format: args.outputFormat,
    output_char_count: args.charCount,
    preview_truncated: args.previewTruncated,
    artifact_id: args.artifact?.id ?? null,
    backend_version: args.backendVersion ?? null,
  }
}

function buildRetDecQualityGates(args: {
  outputFormat: z.infer<typeof retdecDecompileInputSchema>['output_format']
  artifactPersisted: boolean
  previewTruncated: boolean
  semanticCompleteness: RetDecSemanticCompleteness
}) {
  return {
    schema: 'rikune.retdec_decompile.quality_gates.v1',
    passive_static_analysis: true,
    read_only_backend: true,
    sample_executed_by_tool: false,
    backend_started_with_bounded_command: true,
    network_accessed_by_tool: false,
    mutation_performed: false,
    output_bounded_inline: true,
    artifact_persisted: args.artifactPersisted,
    analyst_review_required: true,
    output_format: args.outputFormat,
    preview_truncated: args.previewTruncated,
    semantic_completeness: args.semanticCompleteness.semantic_completeness,
    decompiler_confidence_score: args.semanticCompleteness.decompiler_confidence_score,
    decompiler_confidence_reasons: args.semanticCompleteness.reasons,
    risk_flags: args.semanticCompleteness.risk_flags,
    cross_backend_corroboration_required: true,
    trust_policy: 'RetDec missing calls are not negative evidence; corroborate with CFG/xref data.',
  }
}

function buildRetDecSemanticCompleteness(args: {
  output: string
  outputFormat: z.infer<typeof retdecDecompileInputSchema>['output_format']
  previewTruncated: boolean
}): RetDecSemanticCompleteness {
  const reasons = [
    'RetDec output has not been correlated with a separate CFG or xref source.',
    'Absent calls in RetDec output do not prove the original function has no calls.',
  ]
  const riskFlags: string[] = []
  let score = 0.55

  if (args.previewTruncated) {
    riskFlags.push('inline_preview_truncated')
    reasons.push('The inline preview was truncated before review.')
    score = Math.min(score, 0.4)
  }

  if (args.outputFormat === 'plain') {
    const mainMatch =
      /\b(?:int|void|undefined\d*|int\d+_t)\s+(?:__cdecl\s+|__fastcall\s+|__stdcall\s+)?main\s*\(/i.test(
        args.output
      )
    const callNames = Array.from(args.output.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g))
      .map((match) => match[1])
      .filter((name) => !CONTROL_FLOW_KEYWORDS.has(name.toLowerCase()))
    const nonEntrypointCalls = callNames.filter((name) => name.toLowerCase() !== 'main')

    if (mainMatch && args.output.length < 2000 && nonEntrypointCalls.length <= 1) {
      riskFlags.push('short_entrypoint_low_call_coverage')
      reasons.push(
        'The recovered main-like function is very short and has little visible call coverage.'
      )
      score = Math.min(score, 0.35)
    }
  } else {
    reasons.push('JSON-human RetDec output requires a separate normalizer before semantic review.')
    score = Math.min(score, 0.5)
  }

  return {
    semantic_completeness: riskFlags.length > 0 ? 'suspect' : 'unverified',
    decompiler_confidence_score: score,
    risk_flags: riskFlags,
    reasons,
  }
}

function buildRetDecWarnings(semanticCompleteness: RetDecSemanticCompleteness): string[] {
  if (semanticCompleteness.semantic_completeness !== 'suspect') {
    return [
      'RetDec semantic completeness is unverified; corroborate missing calls with CFG/xref evidence before relying on this output.',
    ]
  }

  return [
    `RetDec semantic completeness is suspect (${semanticCompleteness.risk_flags.join(', ')}); do not treat missing calls as proof they are absent in the original binary.`,
  ]
}

function buildRetDecWorkflowHandoff(args: {
  sampleId: string
  outputFormat: z.infer<typeof retdecDecompileInputSchema>['output_format']
  artifact?: ArtifactRef
}) {
  const artifactType = retdecArtifactType(args.outputFormat)
  return {
    schema: 'rikune.retdec_decompile.workflow_handoff.v1',
    handoff_mode: 'retdec_decompile_to_cross_backend_review',
    artifact_type: artifactType,
    sample_id: args.sampleId,
    output_format: args.outputFormat,
    recommended_next_tools: RETDEC_RECOMMENDED_NEXT_TOOLS,
    artifact_contract: {
      type: artifactType,
      suggested_read_mode: 'profile',
      artifact_id: args.artifact?.id ?? null,
      content_kind: args.outputFormat === 'plain' ? 'c_like_decompiled_text' : 'retdec_json_human',
    },
    routing: [
      {
        goal: 'review-retdec-output',
        priority: 'high',
        next_tools: ['artifact.read'],
        required_evidence: [artifactType],
      },
      {
        goal: 'cross-backend-corroboration',
        priority: 'high',
        next_tools: ['code.cross_decompiler.consensus', 'analysis.evidence.graph'],
        required_evidence: [artifactType, 'paired backend artifacts'],
      },
      {
        goal: 'reconstruct-with-retdec-corroboration',
        priority: 'normal',
        next_tools: ['workflow.reconstruct'],
        required_evidence: [artifactType],
      },
      {
        goal: 'report-retdec-findings',
        priority: 'normal',
        next_tools: ['report.generate'],
        required_evidence: [artifactType],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: true,
      backend_kind: 'external-static',
      live_execution_started: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildRetDecNextActions(args: {
  outputFormat: z.infer<typeof retdecDecompileInputSchema>['output_format']
  artifact?: ArtifactRef
}) {
  return [
    args.artifact
      ? 'Use artifact.read in profile or summary mode before loading the full RetDec decompile output.'
      : 'Persist a RetDec decompile artifact before relying on this result for cross-backend review.',
    'Use workflow.search to select a result-scoped cross-decompiler or evidence graph follow-up instead of exposing broad reverse-engineering tools.',
    args.outputFormat === 'plain'
      ? 'Corroborate RetDec C-like output with Ghidra, Rizin, or another backend before applying reconstruction changes.'
      : 'Normalize RetDec JSON-human output through cross-decompiler consensus before using it as function evidence.',
  ]
}

export function createRetDecDecompileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = retdecDecompileInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.retdec
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, retdecDecompileToolDefinition.name)
      }

      const runner = dependencies?.executeCommand || executeCommand
      let tempDir: string | undefined
      try {
        tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'retdec-decompile-'))
        const outputExtension = input.output_format === 'plain' ? 'c' : 'json'
        const outputPath = path.join(tempDir, `retdec_output.${outputExtension}`)
        const result = await runner(
          backend.path,
          ['--cleanup', '--output-format', input.output_format, '--output', outputPath, samplePath],
          input.timeout_sec * 1000
        )

        if (result.timedOut) {
          return {
            ok: false,
            errors: [
              `RetDec timed out after ${input.timeout_sec} seconds.`,
              result.stderr || result.stdout || 'No backend output was returned before timeout.',
            ],
            metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
          }
        }

        if (result.exitCode !== 0) {
          return {
            ok: false,
            errors: [
              `RetDec exited with code ${result.exitCode}`,
              result.stderr || result.stdout || 'No backend output was returned.',
            ],
            metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
          }
        }

        let outputStat
        try {
          outputStat = await fs.stat(outputPath)
        } catch {
          return {
            ok: false,
            errors: [
              `RetDec completed but did not produce the expected output file: ${outputPath}`,
              result.stderr || result.stdout || 'No backend output was returned.',
            ],
            metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
          }
        }

        if (outputStat.size > RETDEC_MAX_OUTPUT_BYTES) {
          return {
            ok: false,
            errors: [
              `RetDec output exceeded the ${RETDEC_MAX_OUTPUT_BYTES} byte limit.`,
              'Use a narrower workflow or external artifact handling for very large decompilation output.',
            ],
            metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
          }
        }

        const mainOutput = await fs.readFile(outputPath, 'utf8')
        const preview = truncateText(mainOutput, 3000)
        const semanticCompleteness = buildRetDecSemanticCompleteness({
          output: mainOutput,
          outputFormat: input.output_format,
          previewTruncated: preview.truncated,
        })
        const artifacts: ArtifactRef[] = []
        let artifact: ArtifactRef | undefined
        if (input.persist_artifact) {
          artifact = await persistBackendArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'retdec',
            `decompile_${input.output_format}`,
            mainOutput,
            {
              extension: outputExtension,
              mime: input.output_format === 'plain' ? 'text/x-csrc' : 'application/json',
              sessionTag: input.session_tag,
            }
          )
          artifacts.push(artifact)
        }

        return {
          ok: true,
          data: {
            schema: 'rikune.retdec_decompile.v1',
            tool_version: TOOL_VERSION,
            status: 'ready',
            backend,
            sample_id: input.sample_id,
            output_format: input.output_format,
            preview: {
              inline_text: preview.text,
              truncated: preview.truncated,
              char_count: mainOutput.length,
            },
            artifact,
            supporting_artifacts: [],
            evidence_summary: buildRetDecEvidenceSummary({
              sampleId: input.sample_id,
              outputFormat: input.output_format,
              charCount: mainOutput.length,
              previewTruncated: preview.truncated,
              artifact,
              backendVersion: backend.version,
            }),
            workflow_handoff: buildRetDecWorkflowHandoff({
              sampleId: input.sample_id,
              outputFormat: input.output_format,
              artifact,
            }),
            quality_gates: buildRetDecQualityGates({
              outputFormat: input.output_format,
              artifactPersisted: Boolean(artifact),
              previewTruncated: preview.truncated,
              semanticCompleteness,
            }),
            summary: `RetDec produced ${input.output_format} decompilation output for ${input.sample_id}.`,
            recommended_next_tools: RETDEC_RECOMMENDED_NEXT_TOOLS,
            next_actions: buildRetDecNextActions({ outputFormat: input.output_format, artifact }),
          },
          warnings: buildRetDecWarnings(semanticCompleteness),
          artifacts,
          metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
        }
      } finally {
        if (tempDir) {
          await fs.rm(tempDir, { recursive: true, force: true })
        }
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, retdecDecompileToolDefinition.name),
      }
    }
  }
}
