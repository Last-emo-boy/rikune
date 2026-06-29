/**
 * die.scan — Full DIE signature scan with detailed results.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from '../../docker-shared.js'
import {
  ArtifactRefSchema,
  BackendSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  normalizeError,
  executeCommand,
  truncateText,
  persistBackendArtifact,
  buildMetrics,
  safeJsonParse,
  resolveSampleFile,
  resolveAnalysisBackends,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'die.scan'
const TOOL_VERSION = '0.1.0'
const DIE_SCAN_ARTIFACT_TYPE = 'backend_die_scan'

type DieFindingCategory =
  | 'compiler'
  | 'packer'
  | 'protector'
  | 'linker'
  | 'crypto'
  | 'file_type'
  | 'unknown'

interface DieDetection {
  type: string
  name: string
  version: string
  options: string
}

interface DieFinding extends DieDetection {
  category: DieFindingCategory
  confidence: number
  evidence_summary: string
  source: string
}

export const dieScanInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  deep_scan: z.boolean().default(true).describe('Enable deep scan mode for thorough analysis.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('DIE scan timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist scan results as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

const DieFindingSchema = z.object({
  category: z.string(),
  type: z.string().optional(),
  name: z.string(),
  version: z.string().optional(),
  options: z.string().optional(),
  confidence: z.number().optional(),
  evidence_summary: z.string().optional(),
  source: z.string().optional(),
})

export const dieScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']).optional(),
      backend: BackendSchema.optional(),
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      artifact_type: z.string().optional(),
      command_args: z.array(z.string()).optional(),
      deep_scan: z.boolean().optional(),
      timeout_sec: z.number().optional(),
      exit_code: z.number().int().optional(),
      timed_out: z.boolean().optional(),
      file_type: z.string().optional(),
      arch: z.string().optional(),
      mode: z.string().optional(),
      entropy: z.number().optional(),
      detects: z
        .array(
          z.object({
            type: z.string().optional(),
            name: z.string().optional(),
            version: z.string().optional(),
            options: z.string().optional(),
          })
        )
        .optional(),
      compiler_findings: z.array(DieFindingSchema).optional(),
      packer_findings: z.array(DieFindingSchema).optional(),
      protector_findings: z.array(DieFindingSchema).optional(),
      linker_findings: z.array(DieFindingSchema).optional(),
      crypto_findings: z.array(DieFindingSchema).optional(),
      file_type_findings: z.array(DieFindingSchema).optional(),
      stdout_preview: z.string().optional(),
      stderr_preview: z.string().optional(),
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
  metrics: SharedMetricsSchema.optional(),
})

export const dieScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run a full Detect It Easy signature scan. Returns detailed compiler, packer, linker, and crypto detections with version info.',
  inputSchema: dieScanInputSchema,
  outputSchema: dieScanOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'apk', 'firmware', 'archive'],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
    execution: ['static', 'triage'],
    safety: ['passive'],
    capabilities: [
      'compiler-detect',
      'packer',
      'linker-detect',
      'crypto-detect',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: [
      'signatures',
      'toolchain',
      'packer',
      'protector',
      'file-type',
      'workflow',
      'provenance',
      'structure',
    ],
  },
  artifacts: [
    {
      type: DIE_SCAN_ARTIFACT_TYPE,
      description:
        'Structured Detect It Easy compiler, packer, linker, crypto, workflow, and quality-gate scan',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'signatures',
      artifactTypes: [DIE_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'structure',
      artifactTypes: [DIE_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'toolchain',
      artifactTypes: [DIE_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'packer',
      artifactTypes: [DIE_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'protector',
      artifactTypes: [DIE_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'file-type',
      artifactTypes: [DIE_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [DIE_SCAN_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [DIE_SCAN_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'die.scan-validation-handoff',
      title: 'DIE signature scan to packer validation and reporting',
      description:
        'Turn Detect It Easy compiler, packer, protector, linker, crypto, and file-type signatures into passive unpack planning, evidence graph, and reporting handoffs.',
      startsWith: ['die.scan', 'compiler.packer.detect', 'packer.detect'],
      nextTools: [
        'artifact.read',
        'compiler.packer.detect',
        'packer.detect',
        'entropy.analyze',
        'static.resource.graph',
        'unpack.workflow.plan',
        'static.capability.triage',
        'crypto.identify',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [DIE_SCAN_ARTIFACT_TYPE],
      evidence: ['signatures', 'toolchain', 'packer', 'protector', 'file-type', 'workflow'],
      safety: [
        'passive',
        'external_static_backend',
        'no_live_sample_by_default',
        'no_network_by_default',
      ],
      runtimeBackends: ['detect-it-easy'],
    },
  ],
}

type DieScanInput = z.infer<typeof dieScanInputSchema>
type DieBackend = z.infer<typeof BackendSchema>
type DiePartition = ReturnType<typeof partitionFindings>

function readString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function readNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function uniqueStrings(values: string[], limit = 16): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean))).slice(0, limit)
}

function categoryFromDieDetection(detection: DieDetection): DieFindingCategory {
  const text = `${detection.type} ${detection.name} ${detection.options}`.toLowerCase()
  if (/(packer|upx|aspack|mpress|petite|fsg|compressed|packed)/.test(text)) return 'packer'
  if (/(protector|obfuscator|virtualizer|themida|vmprotect|enigma|armadillo|anti-debug)/.test(text))
    return 'protector'
  if (/(compiler|visual c\+\+|msvc|gcc|clang|borland|delphi|rust|golang|go build)/.test(text))
    return 'compiler'
  if (/(linker|link\.exe|gold|lld|ld\b)/.test(text)) return 'linker'
  if (/(crypto|crypt|aes|rsa|rc4|sha|md5|blowfish|twofish|des\b)/.test(text)) return 'crypto'
  if (/(file|filetype|format|pe32|pe32\+|elf|mach-o|ms-dos|exe|dll|library|archive)/.test(text))
    return 'file_type'
  return 'unknown'
}

function confidenceForCategory(category: DieFindingCategory): number {
  if (category === 'packer' || category === 'protector') return 0.82
  if (category === 'compiler' || category === 'linker' || category === 'crypto') return 0.76
  if (category === 'file_type') return 0.72
  return 0.48
}

function normalizeDieDetection(value: unknown): DieDetection | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const record = value as Record<string, unknown>
  const type = readString(record.type) || readString(record.filetype) || readString(record.category)
  const name =
    readString(record.name) ||
    readString(record.string) ||
    readString(record.value) ||
    readString(record.description)
  const version = readString(record.version)
  const options = readString(record.options)
  if (!type && !name) return null
  return {
    type,
    name: name || type,
    version,
    options,
  }
}

function findingFromDetection(detection: DieDetection, source = 'die-json'): DieFinding {
  const category = categoryFromDieDetection(detection)
  const evidenceParts = [
    detection.type ? `type=${detection.type}` : '',
    detection.version ? `version=${detection.version}` : '',
    detection.options ? `options=${detection.options}` : '',
  ].filter(Boolean)
  return {
    ...detection,
    category,
    confidence: confidenceForCategory(category),
    evidence_summary:
      evidenceParts.length > 0
        ? evidenceParts.join(', ')
        : `${source}: ${detection.type || detection.name}`,
    source,
  }
}

function normalizeDieFindings(parsed: Record<string, unknown>, detects: DieDetection[]) {
  const findings = detects.map((detection) => findingFromDetection(detection))
  const primaryFileType = readString(parsed.filetype) || readString(parsed.type)
  if (primaryFileType) {
    findings.push(
      findingFromDetection(
        {
          type: 'file_type',
          name: primaryFileType,
          version: '',
          options: '',
        },
        'die-filetype'
      )
    )
  }

  const deduped = new Map<string, DieFinding>()
  for (const finding of findings) {
    const key = `${finding.category}:${finding.name.toLowerCase()}:${finding.version.toLowerCase()}`
    if (!deduped.has(key)) deduped.set(key, finding)
  }
  return Array.from(deduped.values())
}

function partitionFindings(findings: DieFinding[]) {
  const pick = (category: DieFindingCategory) =>
    findings.filter((finding) => finding.category === category)
  return {
    compiler_findings: pick('compiler'),
    packer_findings: pick('packer'),
    protector_findings: pick('protector'),
    linker_findings: pick('linker'),
    crypto_findings: pick('crypto'),
    file_type_findings: pick('file_type'),
    unknown_findings: pick('unknown'),
  }
}

function topFindingNames(findings: DieFinding[], limit = 8): string[] {
  return [...findings]
    .sort((left, right) => right.confidence - left.confidence)
    .slice(0, limit)
    .map((finding) => finding.name)
}

function buildRecommendedNextTools(partitioned: DiePartition): string[] {
  const tools = [
    'artifact.read',
    'compiler.packer.detect',
    'analysis.evidence.graph',
    'report.generate',
  ]
  if (partitioned.packer_findings.length > 0 || partitioned.protector_findings.length > 0) {
    tools.push('packer.detect', 'entropy.analyze', 'static.resource.graph', 'unpack.workflow.plan')
  }
  if (partitioned.compiler_findings.length > 0 || partitioned.linker_findings.length > 0) {
    tools.push('static.capability.triage', 'code.cross_decompiler.consensus')
  }
  if (partitioned.crypto_findings.length > 0) {
    tools.push('crypto.identify')
  }
  if (partitioned.file_type_findings.length > 0) {
    tools.push('static.resource.graph', 'static.config.carver')
  }
  return uniqueStrings(tools, 14)
}

function buildEvidenceSummary(args: {
  input: DieScanInput
  sampleId: string
  backend: DieBackend
  commandArgs: string[]
  exitCode: number
  timedOut: boolean
  stdout: string
  stderr: string
  parsed: Record<string, unknown>
  detects: DieDetection[]
  partitioned: DiePartition
}) {
  return {
    schema: 'rikune.die_scan.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: DIE_SCAN_ARTIFACT_TYPE,
    deep_scan: args.input.deep_scan,
    timeout_sec: args.input.timeout_sec,
    command_args: args.commandArgs,
    exit_code: args.exitCode,
    timed_out: args.timedOut,
    backend: {
      available: args.backend.available,
      source: args.backend.source,
      version: args.backend.version,
      checked_candidate_count: args.backend.checked_candidates.length,
      error: args.backend.error,
    },
    detect_count: args.detects.length,
    compiler_count: args.partitioned.compiler_findings.length,
    packer_count: args.partitioned.packer_findings.length,
    protector_count: args.partitioned.protector_findings.length,
    linker_count: args.partitioned.linker_findings.length,
    crypto_count: args.partitioned.crypto_findings.length,
    file_type_count: args.partitioned.file_type_findings.length,
    unknown_count: args.partitioned.unknown_findings.length,
    file_type: readString(args.parsed.filetype) || readString(args.parsed.type) || null,
    arch: readString(args.parsed.arch) || null,
    mode: readString(args.parsed.mode) || null,
    entropy: readNumber(args.parsed.entropy) ?? null,
    top_compilers: topFindingNames(args.partitioned.compiler_findings),
    top_packers: topFindingNames(args.partitioned.packer_findings),
    top_protectors: topFindingNames(args.partitioned.protector_findings),
    top_crypto: topFindingNames(args.partitioned.crypto_findings),
    stdout_bytes: Buffer.byteLength(args.stdout),
    stderr_bytes: Buffer.byteLength(args.stderr),
  }
}

function buildWorkflowHandoff(args: {
  sampleId: string
  partitioned: DiePartition
  recommendedNextTools: string[]
}) {
  const hasPackerOrProtector =
    args.partitioned.packer_findings.length > 0 || args.partitioned.protector_findings.length > 0
  const hasToolchain =
    args.partitioned.compiler_findings.length > 0 || args.partitioned.linker_findings.length > 0
  const hasCrypto = args.partitioned.crypto_findings.length > 0

  return {
    schema: 'rikune.die_scan.workflow_handoff.v1',
    handoff_mode: 'die_scan_to_packer_validation_toolchain_correlation_and_reporting',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: DIE_SCAN_ARTIFACT_TYPE,
    recommended_next_tools: args.recommendedNextTools,
    signature_context: {
      compiler_names: topFindingNames(args.partitioned.compiler_findings),
      packer_names: topFindingNames(args.partitioned.packer_findings),
      protector_names: topFindingNames(args.partitioned.protector_findings),
      linker_names: topFindingNames(args.partitioned.linker_findings),
      crypto_names: topFindingNames(args.partitioned.crypto_findings),
      packer_or_protector_present: hasPackerOrProtector,
    },
    routing: [
      {
        goal: 'packer-validation-and-unpack-planning',
        priority: hasPackerOrProtector ? 'high' : 'optional',
        next_tools: [
          'packer.detect',
          'entropy.analyze',
          'static.resource.graph',
          'unpack.workflow.plan',
        ],
        required_evidence: [DIE_SCAN_ARTIFACT_TYPE, 'DIE packer/protector signatures'],
      },
      {
        goal: 'toolchain-aware-static-correlation',
        priority: hasToolchain ? 'normal' : 'optional',
        next_tools: [
          'static.capability.triage',
          'code.cross_decompiler.consensus',
          'analysis.evidence.graph',
        ],
        required_evidence: [DIE_SCAN_ARTIFACT_TYPE, 'DIE compiler/linker signatures'],
      },
      {
        goal: 'crypto-followup-and-capability-correlation',
        priority: hasCrypto ? 'normal' : 'optional',
        next_tools: ['crypto.identify', 'static.capability.triage', 'analysis.evidence.graph'],
        required_evidence: [DIE_SCAN_ARTIFACT_TYPE, 'DIE crypto signatures'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [DIE_SCAN_ARTIFACT_TYPE],
      },
    ],
    artifact_contract: {
      consumes: ['sample bytes'],
      produces: [DIE_SCAN_ARTIFACT_TYPE],
      expected_consumers: [
        'compiler.packer.detect',
        'packer.detect',
        'unpack.workflow.plan',
        'static.capability.triage',
        'analysis.evidence.graph',
        'report.generate',
      ],
    },
    dynamic_boundary: {
      static_backend_started: true,
      runtime_started_by_tool: false,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
      runtime_followup_requires_opt_in: true,
    },
  }
}

function buildQualityGates(args: {
  backend: DieBackend
  partitioned: DiePartition
  exitCode: number
  timedOut: boolean
}) {
  return {
    schema: 'rikune.die_scan.quality_gates.v1',
    passive_static_scan: true,
    static_backend_available: args.backend.available,
    static_backend_started: true,
    runtime_started_by_tool: false,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    exit_code_ok: args.exitCode === 0,
    timed_out: args.timedOut,
    compiler_evidence_present: args.partitioned.compiler_findings.length > 0,
    packer_evidence_present: args.partitioned.packer_findings.length > 0,
    protector_evidence_present: args.partitioned.protector_findings.length > 0,
    linker_evidence_present: args.partitioned.linker_findings.length > 0,
    crypto_evidence_present: args.partitioned.crypto_findings.length > 0,
    file_type_evidence_present: args.partitioned.file_type_findings.length > 0,
    unpack_handoff_ready:
      args.partitioned.packer_findings.length > 0 || args.partitioned.protector_findings.length > 0,
    evidence_graph_handoff_ready: true,
    runtime_followup_requires_opt_in: true,
    analyst_review_required:
      args.partitioned.packer_findings.length > 0 || args.partitioned.protector_findings.length > 0,
  }
}

function buildNextActions(partitioned: DiePartition): string[] {
  const actions = [
    'Send backend_die_scan to analysis.evidence.graph and report.generate for provenance-aware reporting.',
  ]
  if (partitioned.packer_findings.length > 0 || partitioned.protector_findings.length > 0) {
    actions.unshift(
      'Validate DIE packer/protector signatures with packer.detect and entropy.analyze.',
      'Use unpack.workflow.plan before any runtime dumping or live unpacking path.'
    )
  }
  if (partitioned.compiler_findings.length > 0 || partitioned.linker_findings.length > 0) {
    actions.push(
      'Use static.capability.triage and code.cross_decompiler.consensus when toolchain attribution affects static analysis confidence.'
    )
  }
  if (partitioned.crypto_findings.length > 0) {
    actions.push(
      'Use crypto.identify to confirm DIE crypto signatures with constants and API evidence.'
    )
  }
  return actions
}

function buildStructuredResult(args: {
  input: DieScanInput
  backend: DieBackend
  sampleId: string
  commandArgs: string[]
  result: { stdout: string; stderr: string; exitCode: number; timedOut: boolean }
  parsed: Record<string, unknown>
  detects: DieDetection[]
  findings: DieFinding[]
}) {
  const partitioned = partitionFindings(args.findings)
  const recommendedNextTools = buildRecommendedNextTools(partitioned)
  const evidenceSummary = buildEvidenceSummary({
    input: args.input,
    sampleId: args.sampleId,
    backend: args.backend,
    commandArgs: args.commandArgs,
    exitCode: args.result.exitCode,
    timedOut: args.result.timedOut,
    stdout: args.result.stdout,
    stderr: args.result.stderr,
    parsed: args.parsed,
    detects: args.detects,
    partitioned,
  })
  const workflowHandoff = buildWorkflowHandoff({
    sampleId: args.sampleId,
    partitioned,
    recommendedNextTools,
  })
  const qualityGates = buildQualityGates({
    backend: args.backend,
    partitioned,
    exitCode: args.result.exitCode,
    timedOut: args.result.timedOut,
  })

  return {
    status: 'ready',
    backend: args.backend,
    schema: 'rikune.die_scan.v1',
    tool_version: TOOL_VERSION,
    sample_id: args.sampleId,
    artifact_type: DIE_SCAN_ARTIFACT_TYPE,
    command_args: args.commandArgs,
    deep_scan: args.input.deep_scan,
    timeout_sec: args.input.timeout_sec,
    exit_code: args.result.exitCode,
    timed_out: args.result.timedOut,
    file_type: readString(args.parsed.filetype) || readString(args.parsed.type) || '',
    arch: readString(args.parsed.arch),
    mode: readString(args.parsed.mode),
    entropy: readNumber(args.parsed.entropy),
    detects: args.detects,
    compiler_findings: partitioned.compiler_findings,
    packer_findings: partitioned.packer_findings,
    protector_findings: partitioned.protector_findings,
    linker_findings: partitioned.linker_findings,
    crypto_findings: partitioned.crypto_findings,
    file_type_findings: partitioned.file_type_findings,
    stdout_preview: truncateText(args.result.stdout, 2000).text || undefined,
    stderr_preview: truncateText(args.result.stderr, 2000).text || undefined,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
    summary: `DIE detected ${args.detects.length} signature(s): ${
      args.detects.map((detection) => `${detection.type}:${detection.name}`).join(', ') || 'none'
    }.`,
    recommended_next_tools: recommendedNextTools,
    next_actions: buildNextActions(partitioned),
  }
}

export function createDieScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = dieScanInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.die
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(
          backend ||
            ({
              name: 'die',
              available: false,
              error: 'diec (Detect It Easy console) not installed',
            } as any),
          startTime,
          TOOL_NAME
        )
      }

      const dieArgs = [samplePath, '-j']
      if (input.deep_scan) dieArgs.push('-d')
      const runner = dependencies?.executeCommand || executeCommand
      const result = await runner(backend.path, dieArgs, input.timeout_sec * 1000)

      if (result.exitCode !== 0 && !result.stdout.trim()) {
        return {
          ok: false,
          errors: [`DIE exited with code ${result.exitCode}: ${result.stderr}`],
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }

      const parsed = safeJsonParse<Record<string, unknown>>(result.stdout)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return {
          ok: false,
          errors: ['Failed to parse DIE JSON output'],
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }

      const detects = Array.isArray(parsed.detects)
        ? parsed.detects
            .map((detection) => normalizeDieDetection(detection))
            .filter((detection): detection is DieDetection => Boolean(detection))
        : []
      const findings = normalizeDieFindings(parsed, detects)
      let outputData: Record<string, unknown> = buildStructuredResult({
        input,
        backend,
        sampleId: input.sample_id,
        commandArgs: dieArgs,
        result,
        parsed,
        detects,
        findings,
      })

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'die',
          'scan',
          JSON.stringify({ ...outputData, raw_die_json: parsed }, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
            metadata: {
              schema: 'rikune.die_scan.v1',
              deep_scan: input.deep_scan,
            },
          }
        )
        artifacts.push(artifact)
        outputData = { ...outputData, artifact }
      }

      return {
        ok: true,
        data: outputData,
        artifacts,
        warnings:
          result.exitCode !== 0
            ? [`DIE returned non-zero exit code ${result.exitCode}.`]
            : undefined,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    }
  }
}
