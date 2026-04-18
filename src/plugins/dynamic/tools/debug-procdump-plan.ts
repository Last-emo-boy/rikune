/**
 * debug.procdump.plan tool.
 *
 * Planning-only ProcDump profiles for Runtime Node capture. Produces
 * runtime.debug.command templates; it never starts a runtime or executes a
 * sample.
 */

import { z } from 'zod'
import type { PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  loadStaticAnalysisArtifactSelection,
  type StaticArtifactScope,
} from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'debug.procdump.plan'

const ProcDumpModeSchema = z.enum([
  'launch_crash',
  'launch_first_chance',
  'launch_timeout',
  'pid_snapshot',
  'all',
])

export const DebugProcDumpPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID used to render launch-mode runtime.debug.command templates.'),
  modes: z.array(ProcDumpModeSchema).optional().default(['launch_crash']),
  dump_type: z.enum(['full', 'mini']).optional().default('full'),
  seconds: z.number().int().min(1).max(3600).optional().default(30),
  max_dumps: z.number().int().min(1).max(64).optional().default(1),
  pid: z.number().int().min(1).optional().describe('PID for pid_snapshot mode.'),
  arguments: z.array(z.string()).optional().default([]).describe('Optional sample arguments for launch modes.'),
  timeout_ms: z.number().int().min(1000).max(30 * 60 * 1000).optional().default(180_000),
  use_static_behavior_artifacts: z.boolean().optional().default(true),
  static_artifact_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  static_artifact_session_tag: z.string().optional(),
})

const DebugProcDumpPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const debugProcDumpPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build planning-only Sysinternals ProcDump capture profiles for crash, first-chance exception, timeout, and PID snapshot dumps. Produces runtime.debug.command templates but does not start or execute a runtime.',
  inputSchema: DebugProcDumpPlanInputSchema,
  outputSchema: DebugProcDumpPlanOutputSchema,
}

interface StaticBehaviorFinding {
  id?: string
  category?: string
  severity?: string
  confidence?: number
}

interface StaticBehaviorClassifierPayload {
  findings?: StaticBehaviorFinding[]
}

interface ProcDumpCapturePlan {
  id: string
  mode: string
  title: string
  purpose: string
  runtime_command_template: Record<string, unknown>
  artifact_expectations: string[]
  notes: string[]
}

function dedupe(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .filter((value): value is string => typeof value === 'string')
        .map((value) => value.trim())
        .filter((value) => value.length > 0)
    )
  )
}

function expandModes(modes: string[]): string[] {
  if (modes.includes('all')) {
    return ['launch_crash', 'launch_first_chance', 'launch_timeout', 'pid_snapshot']
  }
  return dedupe(modes)
}

function buildRuntimeTemplate(
  input: z.infer<typeof DebugProcDumpPlanInputSchema>,
  mode: string
): Record<string, unknown> {
  const args: Record<string, unknown> = {
    mode,
    dump_type: input.dump_type,
    seconds: input.seconds,
    max_dumps: input.max_dumps,
    arguments: input.arguments,
  }
  if (mode === 'pid_snapshot' && input.pid) {
    args.pid = input.pid
  }

  return {
    tool: 'runtime.debug.command',
    args: {
      session_id: '<runtime_debug_session_id>',
      ...(input.sample_id && mode !== 'pid_snapshot' ? { sample_id: input.sample_id } : {}),
      tool: 'debug.procdump.capture',
      args,
      runtime_backend_hint: { type: 'inline', handler: 'executeProcDumpCapture' },
      timeout_ms: input.timeout_ms,
    },
  }
}

async function loadStaticBehaviorHint(
  deps: PluginToolDeps,
  input: z.infer<typeof DebugProcDumpPlanInputSchema>
): Promise<{ artifact_ids: string[]; scope_note: string | null; suggested_modes: string[]; warnings: string[] }> {
  if (!input.use_static_behavior_artifacts || !input.sample_id) {
    return { artifact_ids: [], scope_note: null, suggested_modes: [], warnings: [] }
  }
  if (!deps.workspaceManager || !deps.database) {
    return {
      artifact_ids: [],
      scope_note: null,
      suggested_modes: [],
      warnings: ['Static behavior artifact lookup is unavailable in this handler context.'],
    }
  }

  try {
    const selection = await loadStaticAnalysisArtifactSelection<StaticBehaviorClassifierPayload>(
      deps.workspaceManager,
      deps.database,
      input.sample_id,
      'static_behavior_classifier',
      {
        scope: input.static_artifact_scope as StaticArtifactScope,
        sessionTag: input.static_artifact_session_tag,
      }
    )
    const findings = selection.artifacts.flatMap((artifact) => artifact.payload.findings || [])
    const highSignal = findings.filter((finding) =>
      finding.severity === 'critical' ||
      finding.severity === 'high' ||
      (finding.confidence || 0) >= 0.75
    )
    const suggested = [
      highSignal.some((finding) => finding.category === 'injection') ? 'launch_first_chance' : null,
      highSignal.some((finding) => finding.category === 'anti_analysis') ? 'launch_timeout' : null,
      highSignal.length > 0 ? 'launch_crash' : null,
    ]
    return {
      artifact_ids: selection.artifact_ids,
      scope_note: selection.scope_note,
      suggested_modes: dedupe(suggested),
      warnings: [],
    }
  } catch (error) {
    return {
      artifact_ids: [],
      scope_note: null,
      suggested_modes: [],
      warnings: [`Failed to load static behavior artifacts: ${error instanceof Error ? error.message : String(error)}`],
    }
  }
}

function buildPlans(input: z.infer<typeof DebugProcDumpPlanInputSchema>, modes: string[]): ProcDumpCapturePlan[] {
  return modes.map((mode): ProcDumpCapturePlan => {
    const title = {
      launch_crash: 'ProcDump crash-triggered launch capture',
      launch_first_chance: 'ProcDump first-chance exception launch capture',
      launch_timeout: 'ProcDump timeout/interval launch capture',
      pid_snapshot: 'ProcDump existing-process snapshot capture',
    }[mode] || 'ProcDump capture'
    const purpose = {
      launch_crash: 'Launch the sample under ProcDump and capture a dump on unhandled exception.',
      launch_first_chance: 'Launch the sample under ProcDump and capture first-chance exception behavior for anti-debug or unpacking triage.',
      launch_timeout: 'Launch the sample under ProcDump and capture time-based dumps when it does not crash deterministically.',
      pid_snapshot: 'Capture a full dump from an already-running process ID inside the runtime.',
    }[mode] || 'Capture a runtime dump with ProcDump.'
    return {
      id: `procdump_${mode}`,
      mode,
      title,
      purpose,
      runtime_command_template: buildRuntimeTemplate(input, mode),
      artifact_expectations: ['procdump_capture.json', '*.dmp', 'runtime_debug_artifact'],
      notes: [
        'Call dynamic.toolkit.status first and confirm procdump is available in the runtime tool cache.',
        mode === 'pid_snapshot'
          ? 'Fill args.pid or choose a launch mode when you want the Runtime Node to start the sample.'
          : 'Provide sample_id so runtime.debug.command uploads the sample before dispatching debug.procdump.capture.',
      ],
    }
  })
}

export function createDebugProcDumpPlanHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    const input = DebugProcDumpPlanInputSchema.parse(args || {})
    const staticHint = await loadStaticBehaviorHint(deps, input)
    const selectedModes = dedupe([...expandModes(input.modes), ...staticHint.suggested_modes])
    const plans = buildPlans(input, selectedModes)

    return {
      ok: true,
      data: {
        schema: 'rikune.debug_procdump_plan.v1',
        sample_id: input.sample_id || null,
        selected_modes: selectedModes,
        dump_type: input.dump_type,
        static_behavior_context: {
          artifact_ids: staticHint.artifact_ids,
          scope_note: staticHint.scope_note,
          suggested_modes: staticHint.suggested_modes,
        },
        capture_plans: plans,
        runtime_command_sequence: plans.map((plan) => plan.runtime_command_template),
        safety: {
          plan_executes_sample: false,
          capture_requires_explicit_runtime_debug_command: true,
          procdump_availability_should_be_checked_with: 'dynamic.toolkit.status',
        },
        recommended_next_tools: [
          'dynamic.toolkit.status',
          'runtime.debug.session.start',
          'runtime.debug.command',
          'dynamic.memory.import',
          'unpack.child.handoff',
          'analysis.evidence.graph',
        ],
        next_actions: [
          'Call dynamic.toolkit.status before using the generated ProcDump templates.',
          'Start or attach a runtime.debug.session, then fill session_id in the runtime_command_template entries.',
          'Use dynamic.memory.import or unpack.child.handoff on produced dump artifacts when unpacked payloads are expected.',
        ],
      },
      warnings: staticHint.warnings.length > 0 ? staticHint.warnings : undefined,
      metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
    }
  }
}
