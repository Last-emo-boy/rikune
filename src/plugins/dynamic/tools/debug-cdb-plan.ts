/**
 * debug.cdb.plan tool.
 *
 * Planning-only CDB automation profiles for Runtime Node debug sessions.
 * Produces command batches and runtime.debug.command templates; it never starts
 * a runtime or executes a sample.
 */

import { z } from 'zod'
import type { PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  loadStaticAnalysisArtifactSelection,
  type StaticArtifactScope,
} from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'debug.cdb.plan'

const CdbProfileSchema = z.enum([
  'api_breakpoints',
  'exception_trace',
  'dump_on_break',
  'module_breakpoints',
  'injection_watch',
  'all',
])

export const DebugCdbPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID used to render runtime.debug.command templates.'),
  profiles: z.array(CdbProfileSchema).optional().default(['api_breakpoints']),
  breakpoint_apis: z.array(z.string()).optional().default([]),
  modules: z.array(z.string()).optional().default([]),
  dump_path: z.string().optional().default('debug_snapshot.dmp'),
  max_breakpoints: z.number().int().min(1).max(64).optional().default(24),
  timeout_ms: z.number().int().min(1000).max(30 * 60 * 1000).optional().default(120_000),
  use_static_behavior_artifacts: z.boolean().optional().default(true),
  static_artifact_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  static_artifact_session_tag: z.string().optional(),
})

const DebugCdbPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const debugCdbPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build planning-only CDB automation command batches for API breakpoints, exception tracing, dump-on-break, module-load breakpoints, and injection watch profiles. Produces runtime.debug.command templates but does not start or execute a runtime.',
  inputSchema: DebugCdbPlanInputSchema,
  outputSchema: DebugCdbPlanOutputSchema,
}

interface StaticBehaviorFinding {
  id?: string
  category?: string
  technique?: string
  severity?: string
  confidence?: number
  evidence?: Array<{ kind?: string; value?: string }>
}

interface StaticBehaviorClassifierPayload {
  findings?: StaticBehaviorFinding[]
}

interface CdbCommandBatch {
  id: string
  title: string
  profile: string
  commands: string[]
  purpose: string
  runtime_command_template: Record<string, unknown>
  notes: string[]
}

const DEFAULT_INJECTION_APIS = [
  'OpenProcess',
  'VirtualAllocEx',
  'WriteProcessMemory',
  'CreateRemoteThread',
  'NtCreateThreadEx',
  'QueueUserAPC',
  'SetThreadContext',
  'ResumeThread',
]

const DEFAULT_BEHAVIOR_APIS = [
  'CreateProcessW',
  'RegSetValueExW',
  'CreateServiceW',
  'ShellExecuteW',
  'LoadLibraryW',
  'GetProcAddress',
]

function dedupe(values: Array<string | null | undefined>, limit?: number): string[] {
  const output = Array.from(
    new Set(
      values
        .filter((value): value is string => typeof value === 'string')
        .map((value) => value.trim())
        .filter((value) => value.length > 0)
    )
  )
  return typeof limit === 'number' ? output.slice(0, limit) : output
}

function expandProfiles(profiles: string[]): string[] {
  if (profiles.includes('all')) {
    return ['api_breakpoints', 'exception_trace', 'dump_on_break', 'module_breakpoints', 'injection_watch']
  }
  return dedupe(profiles)
}

function sanitizeCdbToken(value: string): string {
  return value.replace(/\0/g, '').replace(/[;"`]/g, '').trim().slice(0, 120)
}

function inferModuleForApi(api: string): string {
  const name = api.replace(/^.*!/, '')
  if (/^(Nt|Zw|Rtl|Ldr)/i.test(name)) return 'ntdll'
  if (/^(Reg|OpenSCManager|CreateService|StartService|ChangeServiceConfig)/i.test(name)) return 'advapi32'
  if (/^(Internet|Http|WinHttp)/i.test(name)) return /^WinHttp/i.test(name) ? 'winhttp' : 'wininet'
  if (/^(ShellExecute)/i.test(name)) return 'shell32'
  if (/^(CoCreateInstance|CoInitialize)/i.test(name)) return 'ole32'
  return 'kernel32'
}

function normalizeBreakpointTarget(api: string): string | null {
  const sanitized = sanitizeCdbToken(api)
  if (!sanitized) return null
  if (sanitized.includes('!')) return sanitized
  return `${inferModuleForApi(sanitized)}!${sanitized}`
}

function buildBreakpointCommand(target: string): string {
  return `bm ${target} ".printf \\"rikune_hit ${target}\\n\\"; r; kv; g"`
}

function runtimeCommandTemplate(
  sampleId: string | undefined,
  commands: string[],
  timeoutMs: number
): Record<string, unknown> {
  return {
    tool: 'runtime.debug.command',
    args: {
      session_id: '<runtime_debug_session_id>',
      ...(sampleId ? { sample_id: sampleId } : { sample_id: '<sample_id>' }),
      tool: 'debug.session.command_batch',
      args: { commands },
      runtime_backend_hint: { type: 'inline', handler: 'executeDebugSession' },
      timeout_ms: timeoutMs,
    },
  }
}

async function loadStaticBehaviorApis(
  deps: PluginToolDeps,
  input: z.infer<typeof DebugCdbPlanInputSchema>
): Promise<{ apis: string[]; artifact_ids: string[]; scope_note: string | null; warnings: string[] }> {
  if (!input.use_static_behavior_artifacts || !input.sample_id) {
    return { apis: [], artifact_ids: [], scope_note: null, warnings: [] }
  }
  if (!deps.workspaceManager || !deps.database) {
    return {
      apis: [],
      artifact_ids: [],
      scope_note: null,
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
    const apis = selection.artifacts.flatMap((artifact) =>
      (artifact.payload.findings || []).flatMap((finding) =>
        (finding.evidence || [])
          .filter((entry) => entry.kind === 'api_match' && typeof entry.value === 'string')
          .map((entry) => entry.value)
      )
    )
    return {
      apis: dedupe(apis),
      artifact_ids: selection.artifact_ids,
      scope_note: selection.scope_note,
      warnings: [],
    }
  } catch (error) {
    return {
      apis: [],
      artifact_ids: [],
      scope_note: null,
      warnings: [`Failed to load static behavior artifacts: ${error instanceof Error ? error.message : String(error)}`],
    }
  }
}

function buildBatches(
  input: z.infer<typeof DebugCdbPlanInputSchema>,
  selectedProfiles: string[],
  breakpointTargets: string[],
  modules: string[]
): CdbCommandBatch[] {
  const batches: CdbCommandBatch[] = []
  const baseCommands = ['.symfix', '.reload /f']

  if (selectedProfiles.includes('api_breakpoints') && breakpointTargets.length > 0) {
    const commands = [...baseCommands, ...breakpointTargets.map(buildBreakpointCommand), 'g']
    batches.push({
      id: 'api_breakpoint_batch',
      title: 'CDB API breakpoint batch',
      profile: 'api_breakpoints',
      commands,
      purpose: 'Break on high-signal APIs, print registers and stack, then continue within the configured timeout budget.',
      runtime_command_template: runtimeCommandTemplate(input.sample_id, commands, input.timeout_ms),
      notes: ['Use after runtime.debug.session.start returns a session id and dynamic.toolkit.status confirms cdb availability.'],
    })
  }

  if (selectedProfiles.includes('injection_watch')) {
    const injectionTargets = dedupe(
      [...DEFAULT_INJECTION_APIS, ...breakpointTargets.map((target) => target.replace(/^.*!/, ''))]
        .map(normalizeBreakpointTarget)
        .filter((target): target is string => Boolean(target)),
      input.max_breakpoints
    )
    const commands = [...baseCommands, ...injectionTargets.map(buildBreakpointCommand), 'g']
    batches.push({
      id: 'injection_watch_batch',
      title: 'CDB process-injection watch batch',
      profile: 'injection_watch',
      commands,
      purpose: 'Watch classic process-injection and hollowing APIs with register/stack snapshots on every hit.',
      runtime_command_template: runtimeCommandTemplate(input.sample_id, commands, input.timeout_ms),
      notes: ['Pair with dynamic.behavior.capture and dynamic.behavior.diff to confirm whether injection code paths executed.'],
    })
  }

  if (selectedProfiles.includes('exception_trace')) {
    const commands = [...baseCommands, 'sxe av', 'sxe ibp', 'sxe eh', 'g']
    batches.push({
      id: 'exception_trace_batch',
      title: 'CDB exception trace batch',
      profile: 'exception_trace',
      commands,
      purpose: 'Stop on access violations, breakpoint exceptions, and C++ exceptions for triage snapshots.',
      runtime_command_template: runtimeCommandTemplate(input.sample_id, commands, input.timeout_ms),
      notes: ['Use with bounded timeouts; exception-heavy samples can produce noisy transcripts.'],
    })
  }

  if (selectedProfiles.includes('module_breakpoints') && modules.length > 0) {
    const commands = [...baseCommands, ...modules.map((moduleName) => `sxe ld:${moduleName}`), 'g']
    batches.push({
      id: 'module_load_batch',
      title: 'CDB module-load breakpoint batch',
      profile: 'module_breakpoints',
      commands,
      purpose: 'Stop when selected DLLs load so follow-up API breakpoints can be attached at the right point.',
      runtime_command_template: runtimeCommandTemplate(input.sample_id, commands, input.timeout_ms),
      notes: ['Useful when delayed imports, plugin DLLs, or unpacked child modules appear only after startup.'],
    })
  }

  if (selectedProfiles.includes('dump_on_break')) {
    const dumpPath = sanitizeCdbToken(input.dump_path) || 'debug_snapshot.dmp'
    const commands = [...baseCommands, `.dump /ma "${dumpPath}"`, 'q']
    batches.push({
      id: 'dump_on_break_batch',
      title: 'CDB dump-on-break batch',
      profile: 'dump_on_break',
      commands,
      purpose: 'Capture a full user-mode dump at the current debugger stop point.',
      runtime_command_template: runtimeCommandTemplate(input.sample_id, commands, input.timeout_ms),
      notes: ['For canonical artifact import, prefer debug.session.snapshot when a simple immediate dump is enough.'],
    })
  }

  return batches
}

export function createDebugCdbPlanHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    const input = DebugCdbPlanInputSchema.parse(args || {})
    const selectedProfiles = expandProfiles(input.profiles)
    const staticBehavior = await loadStaticBehaviorApis(deps, input)
    const requestedTargets = dedupe(
      [...input.breakpoint_apis, ...staticBehavior.apis, ...DEFAULT_BEHAVIOR_APIS]
        .map(normalizeBreakpointTarget)
        .filter((target): target is string => Boolean(target)),
      input.max_breakpoints
    )
    const modules = dedupe(
      [
        ...input.modules,
        ...requestedTargets.map((target) => target.split('!')[0]),
        'kernel32',
        'ntdll',
      ].map((moduleName) => sanitizeCdbToken(moduleName).replace(/\.dll$/i, '')),
      16
    )
    const batches = buildBatches(input, selectedProfiles, requestedTargets, modules)

    return {
      ok: true,
      data: {
        schema: 'rikune.debug_cdb_plan.v1',
        sample_id: input.sample_id || null,
        selected_profiles: selectedProfiles,
        breakpoint_targets: requestedTargets,
        modules,
        static_behavior_context: {
          artifact_ids: staticBehavior.artifact_ids,
          scope_note: staticBehavior.scope_note,
          inferred_api_count: staticBehavior.apis.length,
        },
        command_batches: batches,
        runtime_command_sequence: batches.map((batch) => batch.runtime_command_template),
        safety: {
          plan_executes_sample: false,
          requires_explicit_runtime_session: true,
          uses_runtime_debug_command: true,
          cdb_availability_should_be_checked_with: 'dynamic.toolkit.status',
        },
        recommended_next_tools: [
          'dynamic.toolkit.status',
          'runtime.debug.session.start',
          'runtime.debug.command',
          'dynamic.behavior.capture',
          'dynamic.behavior.diff',
          'analysis.evidence.graph',
        ],
        next_actions: [
          'Call dynamic.toolkit.status before using the generated CDB batches.',
          'Start or attach a runtime.debug.session, then fill session_id in the runtime_command_template entries.',
          'Import produced transcripts or dumps before running dynamic.behavior.diff.',
        ],
      },
      warnings: staticBehavior.warnings.length > 0 ? staticBehavior.warnings : undefined,
      metrics: {
        elapsed_ms: Date.now() - started,
        tool: TOOL_NAME,
      },
    }
  }
}
