import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'unpack.workflow.plan'

export const UnpackWorkflowPlanInputSchema = z
  .object({
    sample_id: z.string().optional(),
    packer_findings: z.any().optional(),
    static_triage: z.any().optional(),
    die: z.any().optional(),
    upx: z.any().optional(),
    unpack_guide: z.any().optional(),
    goals: z.array(z.string()).optional().default([]),
  })
  .passthrough()

export const UnpackWorkflowPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.string(), z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const unpackWorkflowPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a detect-to-plan-to-dump-to-reconstruct-to-retriage unpacking workflow from static packer/protector evidence. It adds packer confidence, evidence provenance, runtime opt-in gates, and re-triage handoffs without starting a debugger, emulator, or sample.',
  inputSchema: UnpackWorkflowPlanInputSchema,
  outputSchema: UnpackWorkflowPlanOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'dotnet', 'apk', 'macho'],
    platforms: ['windows', 'linux', 'macos', 'android', 'cross-platform'],
    execution: ['static', 'triage', 'correlation'],
    runtimes: ['debugger', 'sandbox', 'speakeasy', 'qiling', 'frida'],
    safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
    capabilities: ['unpacking', 'workflow-plan', 'runtime-routing', 'reanalysis'],
    evidence: ['signatures', 'structure', 'behavior', 'workflow', 'provenance'],
  },
  artifacts: [
    { type: 'unpack_plan', description: 'Passive unpacking workflow plan' },
    {
      type: 'reanalysis_request',
      description: 'Static re-triage request after dumped payloads exist',
    },
  ],
  evidence: [
    { category: 'signatures', artifactTypes: ['unpack_plan'] },
    { category: 'workflow', artifactTypes: ['unpack_plan', 'reanalysis_request'] },
    { category: 'provenance', artifactTypes: ['unpack_plan'] },
  ],
  workflowRecipes: [
    {
      id: 'unpacking.detect-plan-retriage',
      title: 'Unpacking detect-plan-retriage loop',
      startsWith: ['packer.detect', 'die.scan', 'unpack.guide', 'unpack.workflow.plan'],
      nextTools: ['unpack.auto', 'runtime.deobfuscate.plan', 'debug.session.plan', 'static.triage'],
      requiredArtifacts: ['packer_detection', 'static_triage'],
      producesArtifacts: ['unpack_plan', 'reanalysis_request'],
      evidence: ['signatures', 'workflow', 'provenance'],
      safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
      runtimeBackends: ['debugger', 'sandbox', 'speakeasy', 'qiling', 'frida'],
    },
  ],
}

function stringify(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(stringify).join('\n')
  if (value && typeof value === 'object') return JSON.stringify(value)
  return ''
}

function uniqueMatches(text: string, pattern: RegExp): string[] {
  return Array.from(new Set(Array.from(text.matchAll(pattern)).map((match) => match[0]))).sort()
}

type EvidenceSection = {
  source: string
  text: string
  value: unknown
}

const PACKER_PATTERN =
  /(?:\b(?:UPX|Themida|VMProtect|ASPack|PECompact|ConfuserEx|Enigma|ASProtect|MPRESS)\b|\.NET Reactor)/gi

function sourceTextSections(
  input: z.infer<typeof UnpackWorkflowPlanInputSchema>
): EvidenceSection[] {
  return [
    {
      source: 'packer_findings',
      value: input.packer_findings,
      text: stringify(input.packer_findings),
    },
    { source: 'static_triage', value: input.static_triage, text: stringify(input.static_triage) },
    { source: 'die', value: input.die, text: stringify(input.die) },
    { source: 'upx', value: input.upx, text: stringify(input.upx) },
    { source: 'unpack_guide', value: input.unpack_guide, text: stringify(input.unpack_guide) },
    { source: 'goals', value: input.goals, text: input.goals.join('\n') },
  ].filter((section) => section.text.trim().length > 0)
}

function normalizePackerName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '')
}

function clampConfidence(value: number): number {
  if (!Number.isFinite(value)) return 0
  const normalized = value > 1 ? value / 100 : value
  return Number(Math.max(0, Math.min(0.99, normalized)).toFixed(2))
}

function collectConfidenceValues(value: unknown, values: number[] = []): number[] {
  if (Array.isArray(value)) {
    for (const item of value) collectConfidenceValues(item, values)
    return values
  }
  if (!value || typeof value !== 'object') return values

  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    const normalizedKey = key.toLowerCase()
    if (
      typeof nested === 'number' &&
      (normalizedKey.includes('confidence') || normalizedKey.includes('score'))
    ) {
      values.push(clampConfidence(nested))
      continue
    }
    collectConfidenceValues(nested, values)
  }
  return values
}

function maxConfidence(value: unknown): number {
  return Math.max(0, ...collectConfidenceValues(value))
}

function hasPackedSignal(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasPackedSignal)
  if (!value || typeof value !== 'object') return false
  return Object.entries(value as Record<string, unknown>).some(([key, nested]) => {
    const normalizedKey = key.toLowerCase()
    if (
      typeof nested === 'boolean' &&
      nested &&
      (normalizedKey === 'packed' || normalizedKey === 'is_packed')
    ) {
      return true
    }
    return hasPackedSignal(nested)
  })
}

function packerConfidence(section: EvidenceSection): number {
  const explicitConfidence = maxConfidence(section.value)
  if (explicitConfidence > 0) return explicitConfidence
  if (hasPackedSignal(section.value)) return 0.7
  if (/high entropy|packed|compressed|encrypted/i.test(section.text)) return 0.58
  return 0.52
}

function collectPackerEvidence(sections: EvidenceSection[]) {
  const grouped = new Map<
    string,
    {
      name: string
      normalized_name: string
      sources: string[]
      confidence: number
      evidence: string[]
    }
  >()

  for (const section of sections) {
    const matches = uniqueMatches(section.text, PACKER_PATTERN)
    for (const match of matches) {
      const normalized = normalizePackerName(match)
      const existing = grouped.get(normalized)
      const confidence = packerConfidence(section)
      if (!existing) {
        grouped.set(normalized, {
          name: match,
          normalized_name: normalized,
          sources: [section.source],
          confidence,
          evidence: [`${section.source}:${match}`],
        })
        continue
      }
      existing.confidence = Math.max(existing.confidence, confidence)
      if (!existing.sources.includes(section.source)) existing.sources.push(section.source)
      existing.evidence.push(`${section.source}:${match}`)
    }
  }

  return Array.from(grouped.values()).sort((a, b) => b.confidence - a.confidence)
}

function collectProtectorHints(sections: EvidenceSection[]) {
  const grouped = new Map<string, { hint: string; sources: string[]; confidence: number }>()
  for (const section of sections) {
    const hints = uniqueMatches(
      section.text,
      /\b(?:anti-debug|anti-vm|virtualized|packed|compressed|encrypted|overlay|high entropy|OEP|IAT)\b/gi
    )
    for (const hint of hints) {
      const key = hint.toLowerCase()
      const confidence = /anti-debug|anti-vm|virtualized|high entropy/i.test(hint) ? 0.74 : 0.62
      const existing = grouped.get(key)
      if (!existing) {
        grouped.set(key, { hint, sources: [section.source], confidence })
        continue
      }
      existing.confidence = Math.max(existing.confidence, confidence)
      if (!existing.sources.includes(section.source)) existing.sources.push(section.source)
    }
  }
  return Array.from(grouped.values()).sort((a, b) => b.confidence - a.confidence)
}

function difficultyFor(packers: string[]) {
  const lower = packers.join(' ').toLowerCase()
  if (/themida|vmprotect|enigma/.test(lower)) return 'hard'
  if (/confuser|reactor|asprotect/.test(lower)) return 'moderate'
  if (/upx|aspack|pecompact/.test(lower)) return 'easy'
  return packers.length ? 'moderate' : 'unknown'
}

function dumpStrategy(packers: string[]) {
  const lower = packers.join(' ').toLowerCase()
  if (/upx/.test(lower)) {
    return {
      strategy: 'static_decompress_first',
      candidate_tools: ['upx.inspect', 'unpack.auto'],
      readiness: ['Confirm UPX header integrity before any runtime dump.'],
    }
  }
  if (/themida|vmprotect|enigma/.test(lower)) {
    return {
      strategy: 'runtime_dump_after_explicit_opt_in',
      candidate_tools: ['debug.session.plan', 'frida.script.generate', 'unpack.auto'],
      readiness: [
        'Require isolated runtime, analyst opt-in, network disabled, and debugger backend readiness.',
      ],
    }
  }
  return {
    strategy: 'guided_oep_or_emulation_plan',
    candidate_tools: ['unpack.guide', 'unpack.auto', 'dynamic.deep.plan'],
    readiness: ['Review packer guide and choose a runtime backend only after static triage.'],
  }
}

function confidenceLevel(score: number): 'low' | 'medium' | 'high' {
  if (score >= 0.8) return 'high'
  if (score >= 0.55) return 'medium'
  return 'low'
}

function buildRuntimeGateMatrix(dump: ReturnType<typeof dumpStrategy>) {
  const runtimeRequired = dump.strategy !== 'static_decompress_first'
  return {
    dump_requires_runtime: runtimeRequired,
    static_preconditions: [
      'packer.detect or die.scan evidence reviewed',
      'unpack.guide generated or packer family identified',
      'tool.readiness checked for selected unpacking tool',
    ],
    runtime_preconditions: runtimeRequired
      ? [
          'analyst approved live unpacking',
          'isolated runtime selected',
          'network disabled',
          'backend readiness confirmed',
        ]
      : [],
    readiness_tools: ['tool.readiness', 'dynamic.runtime.status', 'dynamic.toolkit.status'],
    allowed_runtime_backends: runtimeRequired
      ? ['debugger', 'sandbox', 'speakeasy', 'qiling', 'frida']
      : [],
    denied_by_default: runtimeRequired,
  }
}

function buildRetriageHandoff(
  packers: string[],
  dump: ReturnType<typeof dumpStrategy>,
  confidenceScore: number
) {
  const staticFirst = dump.strategy === 'static_decompress_first'
  return {
    trigger_artifact_types: ['dumped_payload', 'reconstructed_binary', 'deobfuscated_assembly'],
    child_sample_policy: {
      register_child_sample: true,
      preserve_parent_provenance: true,
      require_artifact_hash: true,
      execute_child_sample: false,
    },
    recommended_tools: [
      'static.triage',
      'packer.detect',
      'pe.structure.analyze',
      'strings.extract',
      'yara.scan',
      'analysis.evidence.graph',
    ],
    comparison_tools: ['artifacts.diff', 'binary.diff.summary', 'sample.similarity'],
    analysis_goals: [
      staticFirst
        ? 'Confirm static decompression removed the packer layer.'
        : 'Confirm runtime dump reached a stable unpacked payload artifact.',
      'Compare original and unpacked imports, sections, strings, and behavior hints.',
      'Route dumped child samples back through static triage before deeper decompilation.',
    ],
    confidence: confidenceScore,
    packer_context: packers,
  }
}

function packedState(
  packers: string[],
  protectorHints: Array<{ hint: string }>,
  confidenceScore: number
) {
  if (packers.length > 0 && confidenceScore >= 0.55) return 'confirmed_packed'
  if (protectorHints.length > 0 || confidenceScore >= 0.45) return 'suspected_packed'
  return 'unknown'
}

export function buildUnpackWorkflowPlan(rawInput: unknown) {
  const input = UnpackWorkflowPlanInputSchema.parse(rawInput)
  const sections = sourceTextSections(input)
  const text = sections.map((section) => section.text).join('\n')
  const packerEvidence = collectPackerEvidence(sections)
  const packers = packerEvidence.map((packer) => packer.name)
  const protectorEvidence = collectProtectorHints(sections)
  const protectorHints = protectorEvidence.map((hint) => hint.hint)
  const dump = dumpStrategy(packers)
  const evidenceConfidence = Math.max(
    ...packerEvidence.map((packer) => packer.confidence),
    ...sections.map((section) => maxConfidence(section.value)),
    protectorEvidence.length > 0 ? 0.5 : 0
  )
  const confidenceScore = Number(
    Math.min(0.98, evidenceConfidence + Math.min(0.12, protectorEvidence.length * 0.03)).toFixed(2)
  )
  const runtimeGateMatrix = buildRuntimeGateMatrix(dump)
  const warnings = [
    ...(confidenceScore < 0.55
      ? ['Packer evidence confidence is weak; confirm with die.scan.']
      : []),
    ...(runtimeGateMatrix.dump_requires_runtime
      ? ['Runtime dump path is blocked until explicit opt-in and isolation are present.']
      : []),
  ]

  return {
    result_mode: 'unpack_workflow_plan',
    sample_id: input.sample_id ?? null,
    detected_packers: packers,
    protector_hints: protectorHints,
    difficulty: difficultyFor(packers),
    packer_assessment: {
      packed_state: packedState(packers, protectorEvidence, confidenceScore),
      confidence_score: confidenceScore,
      confidence_level: confidenceLevel(confidenceScore),
      detected_packers: packerEvidence,
      protector_hints: protectorEvidence,
      analyst_review_required: confidenceScore < 0.8 || runtimeGateMatrix.dump_requires_runtime,
    },
    evidence_summary: {
      sources: sections.map((section) => ({
        source: section.source,
        bytes: Buffer.byteLength(section.text),
        confidence: maxConfidence(section.value),
        packed_signal: hasPackedSignal(section.value),
      })),
      packer_evidence_count: packerEvidence.length,
      protector_hint_count: protectorEvidence.length,
      warnings,
    },
    workflow_steps: [
      {
        phase: 'detect',
        tool: 'packer.detect',
        mode: 'passive',
        purpose: 'Confirm packer, protector, entropy, section, and import evidence.',
        gates: ['no_execution', 'metadata_only'],
      },
      {
        phase: 'plan',
        tool: 'unpack.guide',
        mode: 'passive',
        purpose: 'Generate packer-specific guidance and static preconditions.',
        gates: ['no_execution', 'readiness_metadata_only'],
      },
      {
        phase: 'dump',
        tool: 'unpack.auto',
        mode: dump.strategy === 'static_decompress_first' ? 'static_or_opt_in' : 'opt_in_runtime',
        purpose: 'Dump or decompress only after readiness gates are satisfied.',
        gates: runtimeGateMatrix.dump_requires_runtime
          ? ['explicit_opt_in', 'isolation_required', 'network_disabled']
          : ['tool_readiness_required', 'no_runtime_required_for_static_decompress'],
      },
      {
        phase: 'reconstruct',
        tool: 'runtime.deobfuscate.plan',
        mode: 'plan_only',
        purpose: 'Plan import reconstruction, section repair, and string/deobfuscation checks.',
        gates: ['plan_only', 'no_backend_started'],
      },
      {
        phase: 'retriage',
        tool: 'static.triage',
        mode: 'passive_after_artifact',
        purpose: 'Run static analysis on dumped payload artifacts after they exist.',
        gates: ['requires_dump_artifact', 'child_sample_provenance_required'],
      },
    ],
    dump_strategy: dump,
    runtime_gates: {
      live_execution: false,
      requires_explicit_opt_in: true,
      requires_isolation: true,
      network_policy: 'disabled',
    },
    runtime_gate_matrix: runtimeGateMatrix,
    reanalysis_request: {
      trigger_artifact_types: ['dumped_payload', 'reconstructed_binary'],
      recommended_tools: ['static.triage', 'pe.structure.analyze', 'strings.extract', 'yara.scan'],
    },
    retriage_handoff: buildRetriageHandoff(packers, dump, confidenceScore),
    quality_gates: {
      passive_plan_only: true,
      backend_started: false,
      sample_executed: false,
      minimum_packer_evidence_met: packerEvidence.length > 0 || protectorEvidence.length > 0,
      runtime_opt_in_required: runtimeGateMatrix.dump_requires_runtime,
      reanalysis_requires_artifact: true,
      confidence_level: confidenceLevel(confidenceScore),
      warnings,
    },
    recommended_next_tools: [
      'unpack.guide',
      'unpack.auto',
      'dynamic.deep.plan',
      'static.triage',
      'analysis.evidence.graph',
    ],
    safety_notes: ['No debugger, emulator, sandbox, process dump, or sample execution is started.'],
  }
}

export function createUnpackWorkflowPlanHandler() {
  return async (args: unknown): Promise<WorkerResult> => ({
    ok: true,
    data: buildUnpackWorkflowPlan(args),
    metrics: { elapsed_ms: 0, tool: TOOL_NAME },
  })
}
