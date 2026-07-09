/**
 * UPX inspect tool �?inspect or decompress a sample with UPX.
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
  ensureSampleExists,
  executeCommand,
  truncateText,
  normalizeError,
  persistBackendArtifact,
  buildMetrics,
  buildStaticSetupRequired,
  findBackendPreviewEvidence,
  persistBackendPreviewEvidence,
  buildEvidenceReuseWarnings,
  resolveSampleFile,
  resolveAnalysisBackends,
} from '../../docker-shared.js'

const TOOL_NAME = 'upx.inspect'
const TOOL_VERSION = '0.1.0'
const UPX_LIST_ARTIFACT_TYPE = 'backend_upx_list'
const UPX_TEST_ARTIFACT_TYPE = 'backend_upx_test'
const UPX_DECOMPRESS_ARTIFACT_TYPE = 'backend_upx_decompress'

export const upxInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  operation: z
    .enum(['list', 'test', 'decompress'])
    .default('test')
    .describe('UPX list/test/decompress operation.'),
  timeout_sec: z.number().int().min(1).max(180).default(30).describe('UPX timeout in seconds.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist decompressed output or inspection text as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const upxInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      operation: z.string().optional(),
      exit_code: z.number().int().optional(),
      stdout_preview: z.string().optional(),
      stderr_preview: z.string().optional(),
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      artifact_type: z.string().optional(),
      command_args: z.array(z.string()).optional(),
      upx_detected: z.boolean().optional(),
      decompressed_artifact: ArtifactRefSchema.optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
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

export const upxInspectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Inspect or decompress a sample with UPX. Use this when you explicitly want UPX-aware packed-sample checks rather than generic packer heuristics.',
  inputSchema: upxInspectInputSchema,
  outputSchema: upxInspectOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'upx-packed'],
    platforms: ['windows', 'linux', 'macos', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'unpacking', 'triage'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'upx-detection',
      'upx-unpacking',
      'packer-analysis',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: ['packed', 'structure', 'unpacked-binary', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: UPX_LIST_ARTIFACT_TYPE,
      description: 'Structured UPX list output with validation workflow handoff',
      mime: 'application/json',
    },
    {
      type: UPX_TEST_ARTIFACT_TYPE,
      description: 'Structured UPX integrity test output with validation workflow handoff',
      mime: 'application/json',
    },
    {
      type: UPX_DECOMPRESS_ARTIFACT_TYPE,
      description: 'UPX decompressed binary produced by explicit decompress operation',
      mime: 'application/octet-stream',
    },
  ],
  evidence: [
    {
      category: 'packed',
      artifactTypes: [UPX_LIST_ARTIFACT_TYPE, UPX_TEST_ARTIFACT_TYPE],
    },
    {
      category: 'structure',
      artifactTypes: [UPX_LIST_ARTIFACT_TYPE, UPX_TEST_ARTIFACT_TYPE],
    },
    {
      category: 'unpacked-binary',
      artifactTypes: [UPX_DECOMPRESS_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [UPX_LIST_ARTIFACT_TYPE, UPX_TEST_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [UPX_LIST_ARTIFACT_TYPE, UPX_TEST_ARTIFACT_TYPE, UPX_DECOMPRESS_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'upx.inspect-validation-handoff',
      title: 'UPX inspection to unpack validation and re-triage',
      description:
        'Run bounded UPX list/test/decompress operations with passive gates, unpack workflow routing, evidence graph correlation, and re-triage handoff.',
      startsWith: ['upx.inspect', 'packer.detect', 'die.scan', 'unpack.workflow.plan'],
      nextTools: [
        'artifact.read',
        'unpack.workflow.plan',
        'static.triage',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['sample', 'UPX packed-sample evidence'],
      producesArtifacts: [
        UPX_LIST_ARTIFACT_TYPE,
        UPX_TEST_ARTIFACT_TYPE,
        UPX_DECOMPRESS_ARTIFACT_TYPE,
      ],
      evidence: ['packed', 'structure', 'unpacked-binary', 'workflow', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      runtimeBackends: ['upx'],
    },
  ],
}

type UpxInspectInput = z.infer<typeof upxInspectInputSchema>
type UpxBackend = z.infer<typeof BackendSchema>
type UpxOperation = UpxInspectInput['operation']

function artifactTypeForOperation(operation: UpxOperation): string {
  if (operation === 'list') return UPX_LIST_ARTIFACT_TYPE
  if (operation === 'test') return UPX_TEST_ARTIFACT_TYPE
  return UPX_DECOMPRESS_ARTIFACT_TYPE
}

function detectUpxSignal(text: string, operation: UpxOperation, exitCode: number): boolean {
  if (
    /upx|ultimate packer for executables|ultimate packer for executables|packed|compressed|unpacked|decompress|testing/i.test(
      text
    )
  )
    return true
  return operation === 'decompress' && exitCode === 0
}

function buildRecommendedNextTools(operation: UpxOperation): string[] {
  if (operation === 'decompress') {
    return [
      'static.triage',
      'strings.extract',
      'yara.scan',
      'analysis.evidence.graph',
      'report.generate',
    ]
  }
  return [
    'artifact.read',
    'unpack.workflow.plan',
    'packer.detect',
    'analysis.evidence.graph',
    'report.generate',
  ]
}

function buildEvidenceSummary(args: {
  input: UpxInspectInput
  sampleId: string
  artifactType: string
  commandArgs: string[]
  exitCode: number
  stdout: string
  stderr: string
  upxDetected: boolean
  decompressedArtifact?: ArtifactRef
}) {
  return {
    schema: 'rikune.upx_inspect.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: args.artifactType,
    operation: args.input.operation,
    timeout_sec: args.input.timeout_sec,
    command_args: args.commandArgs,
    exit_code: args.exitCode,
    upx_detected: args.upxDetected,
    stdout_bytes: Buffer.byteLength(args.stdout),
    stderr_bytes: Buffer.byteLength(args.stderr),
    decompressed_artifact_type: args.decompressedArtifact?.type ?? null,
    decompressed_artifact_sha256: args.decompressedArtifact?.sha256 ?? null,
  }
}

function buildQualityGates(args: {
  input: UpxInspectInput
  exitCode: number
  upxDetected: boolean
  decompressedArtifact?: ArtifactRef
}) {
  return {
    schema: 'rikune.upx_inspect.quality_gates.v1',
    passive_inspection_only: args.input.operation !== 'decompress',
    backend_started: true,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    live_sample_mutation_performed: false,
    file_transformation_performed: args.input.operation === 'decompress',
    decompressed_artifact_created: Boolean(args.decompressedArtifact),
    exit_code_ok: args.exitCode === 0,
    upx_signal_present: args.upxDetected,
    artifact_review_required: args.input.persist_artifact,
    retriage_required_after_decompress: args.input.operation === 'decompress',
  }
}

function buildWorkflowHandoff(args: {
  input: UpxInspectInput
  sampleId: string
  artifactType: string
  exitCode: number
  upxDetected: boolean
  recommendedNextTools: string[]
  decompressedArtifact?: ArtifactRef
}) {
  const validationPriority = args.upxDetected || args.exitCode === 0 ? 'high' : 'normal'
  const routing = [
    {
      goal: 'artifact-review-and-packer-validation',
      priority: validationPriority,
      next_tools: ['artifact.read', 'packer.detect', 'unpack.workflow.plan'],
      required_evidence: [args.artifactType, 'UPX stdout/stderr evidence'],
    },
    {
      goal: 'evidence-graph-and-reporting',
      priority: validationPriority,
      next_tools: ['analysis.evidence.graph', 'report.generate'],
      required_evidence: [args.artifactType],
    },
  ]

  if (args.input.operation === 'decompress') {
    routing.push({
      goal: 'decompressed-artifact-retriage',
      priority: args.decompressedArtifact ? 'high' : 'normal',
      next_tools: ['static.triage', 'strings.extract', 'yara.scan'],
      required_evidence: [UPX_DECOMPRESS_ARTIFACT_TYPE, 'decompressed payload artifact'],
    })
  }

  return {
    schema: 'rikune.upx_inspect.workflow_handoff.v1',
    handoff_mode: 'upx_inspection_to_unpack_validation_retriage_and_reporting',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: args.artifactType,
    operation: args.input.operation,
    exit_code: args.exitCode,
    upx_detected: args.upxDetected,
    recommended_next_tools: args.recommendedNextTools,
    dynamic_boundary: {
      backend_started: true,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      live_sample_mutation_performed: false,
      file_transformation_performed: args.input.operation === 'decompress',
    },
    routing,
  }
}

function buildNextActions(args: {
  operation: UpxOperation
  exitCode: number
  upxDetected: boolean
  decompressedArtifact?: ArtifactRef
}) {
  const actions =
    args.operation === 'decompress'
      ? [
          'Run static.triage, strings.extract, and yara.scan on the decompressed artifact before deeper decompilation.',
          'Route the UPX handoff into analysis.evidence.graph before report.generate.',
        ]
      : [
          'Use artifact.read for the full UPX inspection payload when stdout/stderr previews are not enough.',
          'Feed the UPX evidence into unpack.workflow.plan before attempting decompression.',
          'Route the artifact into analysis.evidence.graph before report.generate.',
        ]
  if (args.exitCode !== 0) {
    actions.unshift('Review UPX stderr and confirm whether the sample is actually UPX packed.')
  }
  if (args.operation === 'decompress' && !args.decompressedArtifact) {
    actions.unshift('Do not promote decompression until a decompressed artifact exists.')
  }
  if (!args.upxDetected) {
    actions.unshift('Corroborate with packer.detect or die.scan because UPX signal is weak.')
  }
  return actions
}

function buildStructuredResult(args: {
  input: UpxInspectInput
  backend: UpxBackend
  sampleId: string
  commandArgs: string[]
  exitCode: number
  stdout: string
  stderr: string
  decompressedArtifact?: ArtifactRef
}) {
  const artifactType = artifactTypeForOperation(args.input.operation)
  const combinedOutput = `${args.stdout}\n${args.stderr}`.trim()
  const upxDetected = detectUpxSignal(combinedOutput, args.input.operation, args.exitCode)
  const recommendedNextTools = buildRecommendedNextTools(args.input.operation)
  const evidenceSummary = buildEvidenceSummary({
    input: args.input,
    sampleId: args.sampleId,
    artifactType,
    commandArgs: args.commandArgs,
    exitCode: args.exitCode,
    stdout: args.stdout,
    stderr: args.stderr,
    upxDetected,
    decompressedArtifact: args.decompressedArtifact,
  })
  const workflowHandoff = buildWorkflowHandoff({
    input: args.input,
    sampleId: args.sampleId,
    artifactType,
    exitCode: args.exitCode,
    upxDetected,
    recommendedNextTools,
    decompressedArtifact: args.decompressedArtifact,
  })
  const qualityGates = buildQualityGates({
    input: args.input,
    exitCode: args.exitCode,
    upxDetected,
    decompressedArtifact: args.decompressedArtifact,
  })

  return {
    status: 'ready',
    backend: args.backend,
    schema: 'rikune.upx_inspect.v1',
    tool_version: TOOL_VERSION,
    sample_id: args.sampleId,
    operation: args.input.operation,
    artifact_type: artifactType,
    command_args: args.commandArgs,
    exit_code: args.exitCode,
    upx_detected: upxDetected,
    stdout_preview: truncateText(args.stdout, 2000).text || undefined,
    stderr_preview: truncateText(args.stderr, 2000).text || undefined,
    decompressed_artifact: args.decompressedArtifact,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
    summary:
      args.input.operation === 'decompress'
        ? `UPX decompress completed with exit code ${args.exitCode}.`
        : `UPX ${args.input.operation} completed with exit code ${args.exitCode}.`,
    recommended_next_tools: recommendedNextTools,
    next_actions: buildNextActions({
      operation: args.input.operation,
      exitCode: args.exitCode,
      upxDetected,
      decompressedArtifact: args.decompressedArtifact,
    }),
  }
}

export function createUPXInspectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = upxInspectInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      const evidenceArgs = {
        operation: input.operation,
      }
      const reused = findBackendPreviewEvidence(
        database,
        sample,
        'upx',
        input.operation,
        evidenceArgs
      )
      if (reused) {
        return {
          ok: true,
          data: reused.result as Record<string, unknown>,
          warnings: buildEvidenceReuseWarnings({
            source: 'analysis_evidence',
            record: reused,
          }),
          artifacts: reused.artifact_refs,
          metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.upx
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, upxInspectToolDefinition.name)
      }

      const runner = dependencies?.executeCommand || executeCommand
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'upx-inspect-'))
      let commandArgs: string[] = []
      let outputPath: string | null = null
      if (input.operation === 'list') {
        commandArgs = ['-l', samplePath]
      } else if (input.operation === 'test') {
        commandArgs = ['-t', samplePath]
      } else {
        outputPath = path.join(tempDir, path.basename(samplePath))
        commandArgs = ['-d', '-o', outputPath, samplePath]
      }

      const commandResult = await runner(backend.path, commandArgs, input.timeout_sec * 1000)

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        if (input.operation === 'decompress' && outputPath) {
          const decompressed = await fs.readFile(outputPath)
          artifact = await persistBackendArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'upx',
            'decompress',
            decompressed,
            {
              extension: path.extname(samplePath).replace(/^\./, '') || 'bin',
              mime: 'application/octet-stream',
              sessionTag: input.session_tag,
              metadata: {
                schema: 'rikune.upx_decompress.artifact.v1',
                source_tool: TOOL_NAME,
                operation: input.operation,
              },
            }
          )
          artifact.metadata = {
            ...(artifact.metadata || {}),
            decompressed_binary: true,
          }
        } else {
          artifact = undefined
        }
        if (artifact) artifacts.push(artifact)
      }

      await fs.rm(tempDir, { recursive: true, force: true })

      let outputData: Record<string, unknown> = buildStructuredResult({
        input,
        backend,
        sampleId: input.sample_id,
        commandArgs,
        exitCode: commandResult.exitCode,
        stdout: commandResult.stdout,
        stderr: commandResult.stderr,
        decompressedArtifact: artifact,
      }) satisfies Record<string, unknown>

      if (input.persist_artifact && input.operation !== 'decompress') {
        const reportArtifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'upx',
          input.operation,
          JSON.stringify(outputData, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
            metadata: {
              schema: 'rikune.upx_inspect.v1',
              operation: input.operation,
            },
          }
        )
        artifacts.push(reportArtifact)
        outputData = { ...outputData, artifact: reportArtifact }
      } else if (input.operation === 'decompress' && artifact) {
        outputData = { ...outputData, artifact }
      }

      persistBackendPreviewEvidence(
        database,
        sample,
        'upx',
        input.operation,
        evidenceArgs,
        outputData,
        artifacts,
        {
          backend_version: backend.version,
        }
      )

      return {
        ok: true,
        data: outputData,
        artifacts,
        warnings:
          commandResult.exitCode !== 0
            ? [`UPX returned non-zero exit code ${commandResult.exitCode}.`]
            : undefined,
        metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, upxInspectToolDefinition.name),
      }
    }
  }
}
