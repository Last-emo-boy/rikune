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
  data: z.record(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const unpackWorkflowPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a detect-to-plan-to-dump-to-reconstruct-to-retriage unpacking workflow from static packer/protector evidence. It generates readiness-gated dump strategy and reanalysis steps without starting a debugger, emulator, or sample.',
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

export function buildUnpackWorkflowPlan(rawInput: unknown) {
  const input = UnpackWorkflowPlanInputSchema.parse(rawInput)
  const text = [
    stringify(input.packer_findings),
    stringify(input.static_triage),
    stringify(input.die),
    stringify(input.upx),
    stringify(input.unpack_guide),
    input.goals.join('\n'),
  ].join('\n')
  const packers = uniqueMatches(
    text,
    /\b(?:UPX|Themida|VMProtect|ASPack|PECompact|ConfuserEx|\.NET Reactor|Enigma|ASProtect|MPRESS)\b/gi
  )
  const protectorHints = uniqueMatches(
    text,
    /\b(?:anti-debug|anti-vm|virtualized|packed|compressed|encrypted|overlay|high entropy|OEP|IAT)\b/gi
  )
  const dump = dumpStrategy(packers)

  return {
    result_mode: 'unpack_workflow_plan',
    sample_id: input.sample_id ?? null,
    detected_packers: packers,
    protector_hints: protectorHints,
    difficulty: difficultyFor(packers),
    workflow_steps: [
      {
        phase: 'detect',
        tool: 'packer.detect',
        mode: 'passive',
        purpose: 'Confirm packer, protector, entropy, section, and import evidence.',
      },
      {
        phase: 'plan',
        tool: 'unpack.guide',
        mode: 'passive',
        purpose: 'Generate packer-specific guidance and static preconditions.',
      },
      {
        phase: 'dump',
        tool: 'unpack.auto',
        mode: dump.strategy === 'static_decompress_first' ? 'static_or_opt_in' : 'opt_in_runtime',
        purpose: 'Dump or decompress only after readiness gates are satisfied.',
      },
      {
        phase: 'reconstruct',
        tool: 'runtime.deobfuscate.plan',
        mode: 'plan_only',
        purpose: 'Plan import reconstruction, section repair, and string/deobfuscation checks.',
      },
      {
        phase: 'retriage',
        tool: 'static.triage',
        mode: 'passive_after_artifact',
        purpose: 'Run static analysis on dumped payload artifacts after they exist.',
      },
    ],
    dump_strategy: dump,
    runtime_gates: {
      live_execution: false,
      requires_explicit_opt_in: true,
      requires_isolation: true,
      network_policy: 'disabled',
    },
    reanalysis_request: {
      trigger_artifact_types: ['dumped_payload', 'reconstructed_binary'],
      recommended_tools: ['static.triage', 'pe.structure.analyze', 'strings.extract', 'yara.scan'],
    },
    recommended_next_tools: ['unpack.guide', 'unpack.auto', 'dynamic.deep.plan', 'static.triage'],
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
