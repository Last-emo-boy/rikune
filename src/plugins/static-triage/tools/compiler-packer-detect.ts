import { execFile } from 'child_process'
import { promisify } from 'util'
import { randomUUID } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { config } from '../../../config.js'
import {
  resolveDieCli,
  type ExternalExecutableResolution,
} from '../../../static-backend-discovery.js'
import {
  buildStaticAnalysisRequiredUserInputs,
  buildStaticAnalysisSetupActions,
} from '../../../setup-guidance.js'
import {
  buildToolchainConfidenceSemantics,
  ConfidenceSemanticsSchema,
} from '../../../analysis/confidence-semantics.js'
import {
  COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
  persistStaticAnalysisJsonArtifact,
} from '../../../artifacts/static-analysis-artifacts.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'

const TOOL_NAME = 'compiler.packer.detect'
const execFileAsync = promisify(execFile)

const AttributionFindingSchema = z.object({
  name: z.string(),
  category: z.enum(['compiler', 'packer', 'protector', 'file_type', 'unknown']),
  confidence: z.number().min(0).max(1),
  evidence_summary: z.string(),
  source: z.string(),
})

const BackendSchema = z.object({
  available: z.boolean(),
  source: z.string().nullable(),
  path: z.string().nullable(),
  version: z.string().nullable(),
  checked_candidates: z.array(z.string()),
  error: z.string().nullable(),
})

export const compilerPackerDetectInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout_sec: z
    .number()
    .int()
    .min(5)
    .max(300)
    .default(config.workers.static.dieTimeout)
    .describe('Timeout for Detect It Easy execution in seconds'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist normalized compiler/packer attribution into reports/static_analysis'),
  register_analysis: z
    .boolean()
    .default(true)
    .describe('Insert a completed analysis row for compiler/packer attribution'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional session tag for persisted static-analysis artifacts'),
})

export const CompilerPackerDetectDataSchema = z.object({
  status: z.enum(['ready', 'setup_required']),
  sample_id: z.string(),
  compiler_findings: z.array(AttributionFindingSchema),
  packer_findings: z.array(AttributionFindingSchema),
  protector_findings: z.array(AttributionFindingSchema),
  file_type_findings: z.array(AttributionFindingSchema),
  summary: z.object({
    compiler_count: z.number().int().nonnegative(),
    packer_count: z.number().int().nonnegative(),
    protector_count: z.number().int().nonnegative(),
    file_type_count: z.number().int().nonnegative(),
    likely_primary_file_type: z.string().nullable(),
  }),
  backend: BackendSchema,
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
  evidence_summary: z.record(z.string(), z.any()).optional(),
  workflow_handoff: z.record(z.string(), z.any()).optional(),
  quality_gates: z.record(z.string(), z.any()).optional(),
  recommended_next_tools: z.array(z.string()).optional(),
  next_actions: z.array(z.string()).optional(),
})

export const compilerPackerDetectOutputSchema = z.object({
  ok: z.boolean(),
  data: CompilerPackerDetectDataSchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const compilerPackerDetectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Identify likely compiler, packer, protector, and file-type signatures with a Detect It Easy-style backend, normalized MCP output, evidence handoff, and passive workflow routing.',
  inputSchema: compilerPackerDetectInputSchema,
  outputSchema: compilerPackerDetectOutputSchema,
  aspects: {
    formats: ['pe', 'dll', 'elf', 'macho', 'apk', 'jar', 'wasm', 'raw-bytes'],
    platforms: ['windows', 'linux', 'macos', 'android', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'cil', 'wasm32'],
    execution: ['static', 'triage', 'correlation'],
    safety: [
      'passive',
      'external_static_backend',
      'no_live_sample_by_default',
      'no_network_by_default',
    ],
    capabilities: [
      'compiler-attribution',
      'packer-attribution',
      'protector-attribution',
      'file-type-attribution',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: [
      'toolchain',
      'signatures',
      'packer',
      'protector',
      'file-type',
      'workflow',
      'provenance',
    ],
  },
  artifacts: [
    {
      type: COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
      description:
        'Compiler, packer, protector, file-type attribution, workflow handoff, and passive quality gates',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'toolchain', artifactTypes: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE] },
    { category: 'signatures', artifactTypes: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE] },
    { category: 'packer', artifactTypes: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE] },
    { category: 'protector', artifactTypes: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE] },
    { category: 'file-type', artifactTypes: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'static-triage.compiler-packer-attribution',
      title: 'Compiler and packer attribution correlation',
      description:
        'Turn Detect It Easy-style compiler, packer, protector, and file-type attribution into packer validation, unpack planning, capability triage, evidence graph, and reporting handoffs.',
      startsWith: ['compiler.packer.detect', 'die.scan', 'packer.detect'],
      nextTools: [
        'packer.detect',
        'entropy.analyze',
        'static.resource.graph',
        'unpack.workflow.plan',
        'static.capability.triage',
        'code.cross_decompiler.consensus',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE],
      evidence: ['toolchain', 'signatures', 'packer', 'protector', 'file-type', 'workflow'],
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

interface DieExecutionResult {
  stdout: string
  stderr: string
  format: 'json' | 'text'
  command: string[]
}

interface CompilerPackerDetectDependencies {
  resolveBackend?: () => ExternalExecutableResolution
  executeBackend?: (
    binaryPath: string,
    samplePath: string,
    timeoutSec: number
  ) => Promise<DieExecutionResult>
}

type AttributionFinding = z.infer<typeof AttributionFindingSchema>
type AttributionPartition = ReturnType<typeof partitionFindings>

function detectCategory(
  text: string
): 'compiler' | 'packer' | 'protector' | 'file_type' | 'unknown' {
  const lowered = text.toLowerCase()
  if (/(compiler|visual c\+\+|msvc|borland|gcc|clang|delphi|rust|go build)/.test(lowered))
    return 'compiler'
  if (/(packer|upx|aspack|mpress|petite|themida|vmprotect|fsg)/.test(lowered)) return 'packer'
  if (/(protector|obfuscator|virtualizer|sig)/.test(lowered)) return 'protector'
  if (/(pe32|pe32\+|elf|mach-o|ms-dos|file type|library|exe|dll)/.test(lowered)) return 'file_type'
  return 'unknown'
}

function buildFinding(
  name: string,
  category: z.infer<typeof AttributionFindingSchema>['category'],
  source: string,
  evidenceSummary?: string
) {
  const confidence =
    category === 'compiler' || category === 'packer' || category === 'protector'
      ? 0.78
      : category === 'file_type'
        ? 0.72
        : 0.46
  return {
    name,
    category,
    confidence,
    evidence_summary: evidenceSummary || `${source}: ${name}`,
    source,
  }
}

function normalizeJsonFindings(raw: unknown): z.infer<typeof AttributionFindingSchema>[] {
  const findings: z.infer<typeof AttributionFindingSchema>[] = []
  const visit = (value: unknown, source = 'die-json') => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item, source)
      return
    }
    if (!value || typeof value !== 'object') {
      if (typeof value === 'string' && value.trim()) {
        findings.push(buildFinding(value.trim(), detectCategory(value), source))
      }
      return
    }
    const record = value as Record<string, unknown>
    const nameCandidate = ['name', 'type', 'value', 'string', 'title', 'description']
      .map((key) => record[key])
      .find((item) => typeof item === 'string' && item.trim().length > 0)
    if (typeof nameCandidate === 'string') {
      const categoryCandidate = ['category', 'kind', 'class', 'type']
        .map((key) => record[key])
        .find((item) => typeof item === 'string' && item.trim().length > 0)
      const category =
        typeof categoryCandidate === 'string'
          ? detectCategory(`${categoryCandidate} ${nameCandidate}`)
          : detectCategory(nameCandidate)
      findings.push(
        buildFinding(
          nameCandidate.trim(),
          category,
          source,
          Object.entries(record)
            .slice(0, 4)
            .map(([key, item]) => `${key}=${String(item)}`)
            .join(', ')
        )
      )
    }
    for (const nested of Object.values(record)) {
      if (typeof nested === 'object') visit(nested, source)
    }
  }
  visit(raw)
  return findings
}

function normalizeTextFindings(
  stdout: string,
  stderr: string
): z.infer<typeof AttributionFindingSchema>[] {
  const findings: z.infer<typeof AttributionFindingSchema>[] = []
  const lines = `${stdout}\n${stderr}`
    .split(/\r?\n/)
    .map((item) => item.replace(/\0/g, '').trim())
    .filter((item) => item.length > 0)
  for (const line of lines) {
    const normalizedLine = line.replace(/^\[[^\]]+\]\s*/, '')
    const parts = normalizedLine.split(/\s*:\s*/, 2)
    const payload = parts.length === 2 ? parts[1] : normalizedLine
    if (!payload.trim()) continue
    findings.push(
      buildFinding(
        payload.trim(),
        detectCategory(parts[0] || normalizedLine),
        'die-text',
        normalizedLine
      )
    )
  }
  return findings
}

function parseLooseJsonOutput(stdout: string): unknown | null {
  const trimmed = stdout.trim()
  if (!trimmed) {
    return null
  }

  const candidates = new Set<string>()
  candidates.add(trimmed)

  const lines = trimmed.split(/\r?\n/)
  const jsonStartIndex = lines.findIndex((line) => {
    const normalized = line.trim()
    return /^(?:\{|\[(?!\!))/.test(normalized)
  })
  if (jsonStartIndex >= 0) {
    candidates.add(lines.slice(jsonStartIndex).join('\n').trim())
  }

  const objectStart = trimmed.indexOf('{')
  const objectEnd = trimmed.lastIndexOf('}')
  if (objectStart >= 0 && objectEnd > objectStart) {
    candidates.add(trimmed.slice(objectStart, objectEnd + 1).trim())
  }

  const arrayStart = trimmed.search(/\[(?!\!)/)
  const arrayEnd = trimmed.lastIndexOf(']')
  if (arrayStart >= 0 && arrayEnd > arrayStart) {
    candidates.add(trimmed.slice(arrayStart, arrayEnd + 1).trim())
  }

  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate)
    } catch {
      // Try the next candidate.
    }
  }

  return null
}

function partitionFindings(findings: z.infer<typeof AttributionFindingSchema>[]) {
  const pick = (category: z.infer<typeof AttributionFindingSchema>['category']) =>
    findings.filter((item) => item.category === category)
  return {
    compiler_findings: pick('compiler'),
    packer_findings: pick('packer'),
    protector_findings: pick('protector'),
    file_type_findings: pick('file_type'),
  }
}

function uniqueStrings(values: string[], limit = 16): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean))).slice(0, limit)
}

function topFindingNames(findings: AttributionFinding[], limit = 8): string[] {
  return [...findings]
    .sort((left, right) => right.confidence - left.confidence)
    .slice(0, limit)
    .map((finding) => finding.name)
}

function buildRecommendedNextTools(
  summary: z.infer<typeof CompilerPackerDetectDataSchema>['summary'],
  status: 'ready' | 'setup_required'
): string[] {
  if (status === 'setup_required') {
    return ['tool.readiness', 'tools.discover']
  }

  const tools = ['analysis.evidence.graph', 'report.generate']
  if (summary.packer_count > 0 || summary.protector_count > 0) {
    tools.push('packer.detect', 'entropy.analyze', 'static.resource.graph', 'unpack.workflow.plan')
  }
  if (summary.compiler_count > 0) {
    tools.push('static.capability.triage', 'code.cross_decompiler.consensus')
  }
  if (summary.file_type_count > 0) {
    tools.push('static.resource.graph', 'static.config.carver')
  }
  return uniqueStrings(tools, 12)
}

function buildEvidenceSummary(args: {
  status: 'ready' | 'setup_required'
  sampleId: string
  partitioned: AttributionPartition
  summary: z.infer<typeof CompilerPackerDetectDataSchema>['summary']
  backend: z.infer<typeof BackendSchema>
  confidenceScore: number | null
  warnings: string[]
}) {
  return {
    schema: 'rikune.compiler_packer_attribution.evidence_summary.v1',
    sample_id: args.sampleId,
    status: args.status,
    source_tool: TOOL_NAME,
    backend: {
      available: args.backend.available,
      source: args.backend.source,
      version: args.backend.version,
      checked_candidate_count: args.backend.checked_candidates.length,
      error: args.backend.error,
    },
    compiler_count: args.summary.compiler_count,
    packer_count: args.summary.packer_count,
    protector_count: args.summary.protector_count,
    file_type_count: args.summary.file_type_count,
    likely_primary_file_type: args.summary.likely_primary_file_type,
    top_compilers: topFindingNames(args.partitioned.compiler_findings),
    top_packers: topFindingNames(args.partitioned.packer_findings),
    top_protectors: topFindingNames(args.partitioned.protector_findings),
    confidence_score: args.confidenceScore,
    warning_count: args.warnings.length,
    warnings: args.warnings,
  }
}

function buildWorkflowHandoff(args: {
  status: 'ready' | 'setup_required'
  sampleId: string
  partitioned: AttributionPartition
  summary: z.infer<typeof CompilerPackerDetectDataSchema>['summary']
  recommendedNextTools: string[]
}) {
  const hasPackerOrProtector = args.summary.packer_count > 0 || args.summary.protector_count > 0
  const hasCompiler = args.summary.compiler_count > 0

  return {
    schema: 'rikune.compiler_packer_attribution.workflow_handoff.v1',
    handoff_mode: 'compiler_packer_attribution_to_unpack_and_reporting',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    recommended_next_tools: args.recommendedNextTools,
    attribution_context: {
      status: args.status,
      compiler_names: topFindingNames(args.partitioned.compiler_findings),
      packer_names: topFindingNames(args.partitioned.packer_findings),
      protector_names: topFindingNames(args.partitioned.protector_findings),
      likely_primary_file_type: args.summary.likely_primary_file_type,
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
        required_evidence: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE],
      },
      {
        goal: 'toolchain-aware-static-correlation',
        priority: hasCompiler ? 'normal' : 'optional',
        next_tools: [
          'static.capability.triage',
          'code.cross_decompiler.consensus',
          'analysis.evidence.graph',
        ],
        required_evidence: ['compiler findings', COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE],
      },
    ],
    artifact_contract: {
      consumes: ['sample bytes'],
      produces: [COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE],
      expected_consumers: [
        'packer.detect',
        'unpack.workflow.plan',
        'static.capability.triage',
        'analysis.evidence.graph',
        'report.generate',
      ],
    },
    dynamic_boundary: {
      static_backend_started: args.status === 'ready',
      runtime_started_by_tool: false,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
      runtime_followup_requires_opt_in: true,
    },
  }
}

function buildQualityGates(args: {
  status: 'ready' | 'setup_required'
  summary: z.infer<typeof CompilerPackerDetectDataSchema>['summary']
  backend: z.infer<typeof BackendSchema>
  warningCount: number
}) {
  return {
    passive_static_attribution: true,
    static_backend_available: args.backend.available,
    static_backend_started: args.status === 'ready',
    runtime_started_by_tool: false,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    compiler_evidence_present: args.summary.compiler_count > 0,
    packer_evidence_present: args.summary.packer_count > 0,
    protector_evidence_present: args.summary.protector_count > 0,
    file_type_evidence_present: args.summary.file_type_count > 0,
    unpack_handoff_ready: args.summary.packer_count > 0 || args.summary.protector_count > 0,
    evidence_graph_handoff_ready: args.status === 'ready',
    setup_required: args.status === 'setup_required',
    runtime_followup_requires_opt_in: true,
    analyst_review_required: args.summary.packer_count > 0 || args.summary.protector_count > 0,
    warning_count: args.warningCount,
  }
}

function buildNextActions(summary: z.infer<typeof CompilerPackerDetectDataSchema>['summary']) {
  if (summary.packer_count > 0 || summary.protector_count > 0) {
    return [
      'Review compiler_packer_attribution before choosing any live unpacking path.',
      'Run packer.detect and entropy.analyze to validate the packer/protector attribution.',
      'Use unpack.workflow.plan for a passive unpack plan; runtime dumping requires explicit opt-in.',
      'Send compiler_packer_attribution to analysis.evidence.graph and report.generate for correlation.',
    ]
  }
  if (summary.compiler_count > 0) {
    return [
      'Use static.capability.triage to correlate compiler/toolchain context with behavior findings.',
      'Use code.cross_decompiler.consensus when compiler attribution affects decompiler confidence.',
      'Send compiler_packer_attribution to analysis.evidence.graph and report.generate for correlation.',
    ]
  }
  return [
    'Review Detect It Easy findings and file type attribution before escalating.',
    'Use analysis.evidence.graph and report.generate to preserve attribution provenance.',
  ]
}

async function defaultExecuteBackend(
  binaryPath: string,
  samplePath: string,
  timeoutSec: number
): Promise<DieExecutionResult> {
  const attempts: Array<{ args: string[]; format: 'json' | 'text' }> = [
    { args: ['-j', samplePath], format: 'json' },
    { args: ['--json', samplePath], format: 'json' },
    { args: [samplePath], format: 'text' },
  ]

  let lastStdout = ''
  let lastStderr = ''
  for (const attempt of attempts) {
    try {
      const result = await execFileAsync(binaryPath, attempt.args, {
        timeout: Math.max(5000, timeoutSec * 1000),
        windowsHide: true,
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
      })
      return {
        stdout: result.stdout || '',
        stderr: result.stderr || '',
        format: attempt.format,
        command: [binaryPath, ...attempt.args],
      }
    } catch (error) {
      const failed = error as { stdout?: string; stderr?: string }
      lastStdout = typeof failed.stdout === 'string' ? failed.stdout : ''
      lastStderr = typeof failed.stderr === 'string' ? failed.stderr : String(error)
      if (attempt.format === 'text') break
    }
  }

  throw new Error(
    `Detect It Easy execution failed: ${(lastStderr || lastStdout || 'unknown error').trim()}`
  )
}

export function createCompilerPackerDetectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies: CompilerPackerDetectDependencies = {}
) {
  const resolveBackend = dependencies.resolveBackend || (() => resolveDieCli())
  const executeBackend = dependencies.executeBackend || defaultExecuteBackend

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const warnings: string[] = []

    try {
      const input = compilerPackerDetectInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const backend = resolveBackend()
      if (!backend.available || !backend.path) {
        const setupSummary = {
          compiler_count: 0,
          packer_count: 0,
          protector_count: 0,
          file_type_count: 0,
          likely_primary_file_type: null,
        }
        const setupPartitioned = partitionFindings([])
        const setupWarnings = backend.error ? [backend.error] : []
        const recommendedNextTools = buildRecommendedNextTools(setupSummary, 'setup_required')
        const evidenceSummary = buildEvidenceSummary({
          status: 'setup_required',
          sampleId: input.sample_id,
          partitioned: setupPartitioned,
          summary: setupSummary,
          backend,
          confidenceScore: null,
          warnings: setupWarnings,
        })
        const workflowHandoff = buildWorkflowHandoff({
          status: 'setup_required',
          sampleId: input.sample_id,
          partitioned: setupPartitioned,
          summary: setupSummary,
          recommendedNextTools,
        })
        const qualityGates = buildQualityGates({
          status: 'setup_required',
          summary: setupSummary,
          backend,
          warningCount: setupWarnings.length,
        })

        return {
          ok: true,
          data: {
            status: 'setup_required',
            sample_id: input.sample_id,
            compiler_findings: [],
            packer_findings: [],
            protector_findings: [],
            file_type_findings: [],
            summary: {
              compiler_count: 0,
              packer_count: 0,
              protector_count: 0,
              file_type_count: 0,
              likely_primary_file_type: null,
            },
            backend,
            confidence_semantics: null,
            raw_backend: null,
            evidence_summary: evidenceSummary,
            workflow_handoff: workflowHandoff,
            quality_gates: qualityGates,
            recommended_next_tools: recommendedNextTools,
            next_actions: [
              'Configure Detect It Easy before relying on compiler_packer_attribution.',
              'Use tool.readiness to verify the DIE backend path without executing the sample.',
              'After setup, rerun compiler.packer.detect and send the artifact to analysis.evidence.graph.',
            ],
          },
          warnings: setupWarnings.length > 0 ? setupWarnings : undefined,
          setup_actions: buildStaticAnalysisSetupActions(),
          required_user_inputs: buildStaticAnalysisRequiredUserInputs(),
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const execution = await executeBackend(backend.path, samplePath, input.timeout_sec)
      const findings =
        execution.format === 'json'
          ? (() => {
              const parsed = parseLooseJsonOutput(execution.stdout)
              if (parsed !== null) {
                return normalizeJsonFindings(parsed)
              }
              warnings.push(
                'Detect It Easy emitted non-JSON output while JSON mode was requested; fell back to text normalization.'
              )
              return normalizeTextFindings(execution.stdout, execution.stderr)
            })()
          : normalizeTextFindings(execution.stdout, execution.stderr)
      const deduped = new Map<string, z.infer<typeof AttributionFindingSchema>>()
      for (const finding of findings) {
        const key = `${finding.category}:${finding.name.toLowerCase()}`
        if (!deduped.has(key)) deduped.set(key, finding)
      }
      const normalizedFindings = Array.from(deduped.values())
      const partitioned = partitionFindings(normalizedFindings)
      const summary = {
        compiler_count: partitioned.compiler_findings.length,
        packer_count: partitioned.packer_findings.length,
        protector_count: partitioned.protector_findings.length,
        file_type_count: partitioned.file_type_findings.length,
        likely_primary_file_type: partitioned.file_type_findings[0]?.name || null,
      }
      const confidenceSemantics = buildToolchainConfidenceSemantics({
        score: Math.min(
          0.97,
          0.36 +
            Math.min(0.2, summary.compiler_count * 0.18) +
            Math.min(0.2, summary.packer_count * 0.18) +
            Math.min(0.16, summary.protector_count * 0.16) +
            (summary.file_type_count > 0 ? 0.08 : 0)
        ),
        compilerCount: summary.compiler_count,
        packerCount: summary.packer_count,
        protectorCount: summary.protector_count,
        backendSource: backend.source,
      })
      const recommendedNextTools = buildRecommendedNextTools(summary, 'ready')
      const evidenceSummary = buildEvidenceSummary({
        status: 'ready',
        sampleId: input.sample_id,
        partitioned,
        summary,
        backend,
        confidenceScore: confidenceSemantics.score,
        warnings,
      })
      const workflowHandoff = buildWorkflowHandoff({
        status: 'ready',
        sampleId: input.sample_id,
        partitioned,
        summary,
        recommendedNextTools,
      })
      const qualityGates = buildQualityGates({
        status: 'ready',
        summary,
        backend,
        warningCount: warnings.length,
      })
      const nextActions = buildNextActions(summary)

      let artifact
      const artifacts = []
      if (input.persist_artifact) {
        const artifactPayload = {
          schema: 'rikune.compiler_packer_attribution.v1',
          session_tag: input.session_tag || null,
          sample_id: input.sample_id,
          status: 'ready',
          ...partitioned,
          summary,
          backend,
          confidence_semantics: confidenceSemantics,
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
          recommended_next_tools: recommendedNextTools,
          next_actions: nextActions,
          raw_backend: {
            format: execution.format,
            command: execution.command,
            stdout: execution.stdout,
            stderr: execution.stderr,
          },
          created_at: new Date().toISOString(),
        }
        artifact = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE,
          'compiler_packer',
          artifactPayload,
          input.session_tag
        )
        artifacts.push(artifact)
      }

      let analysisId: string | undefined
      if (input.register_analysis) {
        analysisId = randomUUID()
        database.insertAnalysis({
          id: analysisId,
          sample_id: input.sample_id,
          stage: 'compiler_packer_detection',
          backend: 'die',
          status: 'done',
          started_at: new Date(startTime).toISOString(),
          finished_at: new Date().toISOString(),
          output_json: JSON.stringify({
            summary,
            artifact_id: artifact?.id || null,
            backend_source: backend.source,
            recommended_next_tools: recommendedNextTools,
            workflow_handoff_ready: true,
          }),
          metrics_json: JSON.stringify(summary),
        })
      }

      return {
        ok: true,
        data: {
          status: 'ready',
          sample_id: input.sample_id,
          ...partitioned,
          summary,
          backend,
          confidence_semantics: confidenceSemantics,
          analysis_id: analysisId,
          artifact,
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
          recommended_next_tools: recommendedNextTools,
          next_actions: nextActions,
          raw_backend: {
            format: execution.format,
            command: execution.command,
            stdout: execution.stdout,
            stderr: execution.stderr,
          },
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
