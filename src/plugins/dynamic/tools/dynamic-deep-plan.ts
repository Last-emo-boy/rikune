/**
 * dynamic.deep_plan tool.
 *
 * Planning-only dynamic analysis profile builder. It converts the dynamic
 * roadmap into concrete MCP tool sequences while keeping execution explicit.
 */

import { z } from 'zod'
import type { PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  loadStaticAnalysisArtifactSelection,
  type StaticArtifactScope,
} from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'dynamic.deep_plan'

const DynamicDeepGoalSchema = z.enum([
  'all',
  'behavior',
  'debugger',
  'memory',
  'telemetry',
  'network',
  'dotnet',
  'anti_evasion',
  'ttd',
  'manual_gui',
])

export const DynamicDeepPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID used to render sample-bound command examples.'),
  goals: z.array(DynamicDeepGoalSchema).optional().default(['all']),
  runtime_preference: z
    .enum(['auto', 'sandbox', 'hyperv-vm', 'manual-runtime', 'wine-local'])
    .optional()
    .default('auto'),
  include_gui_profiles: z.boolean().optional().default(true),
  include_heavy_profiles: z.boolean().optional().default(true),
  use_static_behavior_artifacts: z.boolean().optional().default(true),
  static_artifact_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  static_artifact_session_tag: z.string().optional(),
})

const DynamicDeepPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const dynamicDeepPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a planning-only deep dynamic analysis profile covering behavior capture, CDB breakpoints, memory dumps, ProcMon/Sysmon/ETW-style telemetry, FakeNet-style network labs, .NET runtime debugging, anti-evasion hooks, TTD, x64dbg, and dnSpy. Does not launch or execute anything.',
  inputSchema: DynamicDeepPlanInputSchema,
  outputSchema: DynamicDeepPlanOutputSchema,
}

interface DynamicPlanProfile {
  id: string
  title: string
  goals: string[]
  runtimeFit: string[]
  setupTools: string[]
  executionTools: string[]
  artifacts: string[]
  notes: string[]
  priority?: number
  evidence_hooks?: string[]
}

interface StaticBehaviorEvidence {
  kind?: string
  value?: string
  source?: string
}

interface StaticBehaviorFinding {
  id?: string
  category?: string
  technique?: string
  severity?: string
  confidence?: number
  evidence?: StaticBehaviorEvidence[]
  recommended_next_tools?: string[]
}

interface StaticBehaviorClassifierPayload {
  summary?: { finding_count?: number; high_or_critical_count?: number }
  findings?: StaticBehaviorFinding[]
  recommended_next_tools?: string[]
}

interface StaticBehaviorContext {
  enabled: boolean
  artifact_ids: string[]
  scope_note: string | null
  finding_count: number
  high_or_critical_count: number
  high_signal_findings: Array<{
    id: string
    category: string
    technique: string
    severity: string
    confidence: number
  }>
  inferred_goals: string[]
  suggested_profile_ids: string[]
  breakpoint_targets: string[]
  recommended_next_tools: string[]
  runtime_notes: string[]
  warnings: string[]
}

function sampleArg(sampleId: string | undefined): Record<string, string> {
  return sampleId ? { sample_id: sampleId } : {}
}

function buildProfiles(sampleId: string | undefined): DynamicPlanProfile[] {
  return [
    {
      id: 'behavior_capture',
      title: 'Bounded behavior capture',
      goals: ['behavior'],
      runtimeFit: ['sandbox', 'hyperv-vm', 'manual-runtime'],
      setupTools: ['dynamic.runtime.status', 'dynamic.toolkit.status'],
      executionTools: ['dynamic.persona.plan', 'dynamic.behavior.capture', 'dynamic.trace.import', 'dynamic.behavior.diff'],
      artifacts: ['behavior_capture.json', 'dynamic_trace_json', 'dynamic_behavior_diff'],
      notes: [
        'Use first for process/module/file/TCP/stdout/stderr evidence.',
        'ProcMon, Sysmon, ETW, and FakeNet are optional upgrades on top of this baseline.',
      ],
    },
    {
      id: 'debugger_cdb',
      title: 'CDB breakpoint and snapshot debugging',
      goals: ['debugger', 'memory'],
      runtimeFit: ['sandbox', 'hyperv-vm', 'manual-runtime'],
      setupTools: ['dynamic.toolkit.status', 'debug.cdb.plan', 'runtime.debug.session.start'],
      executionTools: ['debug.cdb.plan', 'runtime.debug.command'],
      artifacts: ['debug_session_trace.json', 'debug_snapshot.dmp'],
      notes: [
        'Requires cdb.exe inside the Runtime Node or mounted runtime tool cache.',
        `Example args: ${JSON.stringify({ tool: 'debug.session.inspect', ...sampleArg(sampleId) })}`,
      ],
    },
    {
      id: 'memory_dump',
      title: 'Runtime memory dump and scan',
      goals: ['memory'],
      runtimeFit: ['sandbox', 'hyperv-vm', 'manual-runtime'],
      setupTools: ['dynamic.runtime.status', 'dynamic.toolkit.status', 'debug.procdump.plan'],
      executionTools: ['debug.procdump.plan', 'dynamic.memory_dump', 'runtime.debug.command'],
      artifacts: ['memory dump artifacts', 'procdump_capture.json', 'runtime_debug_artifact'],
      notes: [
        'Use after behavior capture or debugger breakpoints when unpacked/config material is expected in memory.',
        'ProcDump and CDB improve dump capture, but the runtime memory workflow can still report setup guidance without them.',
      ],
    },
    {
      id: 'telemetry_procmon_sysmon',
      title: 'ProcMon/Sysmon/ETW-grade telemetry',
      goals: ['telemetry', 'behavior'],
      runtimeFit: ['hyperv-vm', 'manual-runtime', 'sandbox'],
      setupTools: ['dynamic.toolkit.status', 'debug.telemetry.plan'],
      executionTools: ['debug.telemetry.plan', 'runtime.debug.command', 'dynamic.behavior.capture'],
      artifacts: ['procmon_capture.pml', 'eventlog_snapshot.json', 'etw_process.etl', 'etw_dns.etl', 'telemetry_capture.json'],
      notes: [
        'ProcMon and Sysmon are optional runtime tools; ETW and PowerShell event-log snapshots provide lower-friction fallbacks.',
        'Hyper-V is the preferred backend for service-backed telemetry because it can retain or rollback dirty state.',
      ],
    },
    {
      id: 'network_lab',
      title: 'Fake service and network sinkhole lab',
      goals: ['network'],
      runtimeFit: ['hyperv-vm', 'manual-runtime', 'sandbox'],
      setupTools: ['dynamic.toolkit.status', 'debug.network.plan'],
      executionTools: ['debug.network.plan', 'runtime.debug.command', 'dynamic.behavior.capture', 'debug.telemetry.plan', 'dynamic.trace.import'],
      artifacts: ['behavior_capture.json', 'network_events', 'etw_dns.etl', 'eventlog_snapshot.json', 'future fakenet_report'],
      notes: [
        'Baseline network safety uses proxy sinkholing through dynamic.behavior.capture; FakeNet-style services require explicit runtime setup.',
        'Prefer Hyper-V when realistic DNS/HTTP service emulation or packet capture is required.',
      ],
    },
    {
      id: 'dotnet_runtime',
      title: '.NET runtime debugging and resource inspection',
      goals: ['dotnet'],
      runtimeFit: ['sandbox', 'hyperv-vm', 'manual-runtime'],
      setupTools: ['dynamic.toolkit.status', 'dotnet.metadata.extract', 'debug.managed.plan'],
      executionTools: ['debug.managed.plan', 'runtime.debug.command', 'managed.safe_run', 'debug.gui.handoff'],
      artifacts: ['managed safe-run output', 'debug_session_trace.json', 'procdump_capture.json', 'debug_gui_handoff'],
      notes: [
        'dotnet is required for managed execution; dnSpyEx is a manual GUI companion for retained runtime sessions.',
        'Pair with static dotnet metadata and resource extraction before live execution.',
      ],
    },
    {
      id: 'anti_evasion',
      title: 'Anti-debug and anti-sandbox evasion checks',
      goals: ['anti_evasion'],
      runtimeFit: ['sandbox', 'hyperv-vm', 'manual-runtime'],
      setupTools: ['dynamic.auto_hook', 'dynamic.toolkit.status', 'dynamic.persona.plan'],
      executionTools: ['frida.script.generate', 'runtime.debug.command', 'dynamic.behavior.capture'],
      artifacts: ['frida trace jsonl', 'debug_session_trace.json', 'behavior_capture.json'],
      notes: [
        'Start with hook generation for IsDebuggerPresent, NtQueryInformationProcess, timing, firmware, window, and cursor checks.',
        'Keep bypasses explicit; this plan does not automatically patch or transform samples.',
      ],
    },
    {
      id: 'ttd_recording',
      title: 'Time Travel Debugging recording',
      goals: ['ttd', 'debugger'],
      runtimeFit: ['hyperv-vm', 'manual-runtime'],
      setupTools: ['dynamic.toolkit.status', 'runtime.debug.session.start'],
      executionTools: ['runtime.debug.command'],
      artifacts: ['future ttd trace', 'debug_session_trace.json'],
      notes: [
        'TTD is heavy and should prefer Hyper-V/manual runtime profiles with preserved state.',
        'Requires Windows Debugging Tools with TTD components exposed inside the runtime.',
      ],
    },
    {
      id: 'manual_gui_debug',
      title: 'Manual GUI debugging profile',
      goals: ['manual_gui', 'debugger', 'dotnet'],
      runtimeFit: ['hyperv-vm', 'sandbox'],
      setupTools: ['runtime.debug.session.start', 'runtime.hyperv.control', 'dynamic.toolkit.status', 'debug.gui.handoff'],
      executionTools: ['debug.gui.handoff', 'runtime.debug.session.status'],
      artifacts: ['debug_gui_handoff', 'retained VM state', 'manual notes'],
      notes: [
        'Use x64dbg, WinDbg, or dnSpyEx inside a visible runtime when automated probes are insufficient.',
        'Use Hyper-V preserve_dirty retention for manual continuation after MCP-triggered setup.',
      ],
    },
  ]
}

function goalSet(goals: string[]): Set<string> {
  if (goals.includes('all')) {
    return new Set(['behavior', 'debugger', 'memory', 'telemetry', 'network', 'dotnet', 'anti_evasion', 'ttd', 'manual_gui'])
  }
  return new Set(goals)
}

function profileMatches(profile: DynamicPlanProfile, goals: Set<string>, includeGui: boolean, includeHeavy: boolean): boolean {
  if (!includeGui && profile.goals.includes('manual_gui')) return false
  if (!includeHeavy && (profile.goals.includes('ttd') || profile.id === 'telemetry_procmon_sysmon')) return false
  return profile.goals.some((goal) => goals.has(goal))
}

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

function severityScore(severity: string | undefined): number {
  const normalized = (severity || '').toLowerCase()
  if (normalized === 'critical') return 4
  if (normalized === 'high') return 3
  if (normalized === 'medium') return 2
  if (normalized === 'low') return 1
  return 0
}

function extractBreakpointTargets(findings: StaticBehaviorFinding[]): string[] {
  return dedupe(
    findings.flatMap((finding) =>
      (finding.evidence || [])
        .filter((item) => item.kind === 'api_match' && typeof item.value === 'string')
        .map((item) => item.value)
    ),
    24
  )
}

function buildStaticBehaviorContextFromPayloads(
  artifactIds: string[],
  scopeNote: string,
  payloads: StaticBehaviorClassifierPayload[]
): StaticBehaviorContext {
  const findings = payloads.flatMap((payload) => payload.findings || [])
  const highSignalFindings = findings
    .filter((finding) => severityScore(finding.severity) >= 3 || (finding.confidence || 0) >= 0.72)
    .sort((left, right) => {
      const severityDiff = severityScore(right.severity) - severityScore(left.severity)
      return severityDiff !== 0 ? severityDiff : (right.confidence || 0) - (left.confidence || 0)
    })

  const inferredGoals: string[] = []
  const suggestedProfiles: string[] = []
  const runtimeNotes: string[] = []

  for (const finding of highSignalFindings) {
    const id = finding.id || ''
    const category = finding.category || ''
    if (category === 'persistence') {
      inferredGoals.push('behavior')
      suggestedProfiles.push('behavior_capture')
      if (/service|wmi|scheduled_task/i.test(id)) {
        inferredGoals.push('telemetry')
        suggestedProfiles.push('telemetry_procmon_sysmon')
        runtimeNotes.push('Persistence findings involving services, WMI, or scheduled tasks are better validated in Hyper-V/manual runtime when service lifecycle telemetry matters.')
      }
    }
    if (category === 'injection') {
      inferredGoals.push('debugger', 'memory')
      suggestedProfiles.push('debugger_cdb', 'memory_dump')
      runtimeNotes.push('Injection findings should start with debugger/API breakpoints and a bounded memory capture plan before broad execution.')
    }
    if (category === 'anti_analysis') {
      inferredGoals.push('anti_evasion')
      suggestedProfiles.push('anti_evasion')
      runtimeNotes.push('Anti-analysis findings should be paired with persona planning and explicit hook/debugger choices.')
    }
  }

  const recommendedTools = dedupe([
    ...payloads.flatMap((payload) => payload.recommended_next_tools || []),
    ...findings.flatMap((finding) => finding.recommended_next_tools || []),
    highSignalFindings.some((finding) => finding.category === 'injection') ? 'breakpoint.smart' : null,
    highSignalFindings.some((finding) => finding.category === 'injection') ? 'trace.condition' : null,
    highSignalFindings.length > 0 ? 'dynamic.behavior.diff' : null,
    highSignalFindings.length > 0 ? 'analysis.evidence.graph' : null,
  ], 16)

  return {
    enabled: true,
    artifact_ids: artifactIds,
    scope_note: scopeNote,
    finding_count: findings.length,
    high_or_critical_count: highSignalFindings.filter((finding) => severityScore(finding.severity) >= 3).length,
    high_signal_findings: highSignalFindings.slice(0, 12).map((finding) => ({
      id: finding.id || 'unknown',
      category: finding.category || 'unknown',
      technique: finding.technique || finding.id || 'unknown',
      severity: finding.severity || 'unknown',
      confidence: typeof finding.confidence === 'number' ? finding.confidence : 0,
    })),
    inferred_goals: dedupe(inferredGoals),
    suggested_profile_ids: dedupe(suggestedProfiles),
    breakpoint_targets: extractBreakpointTargets(highSignalFindings),
    recommended_next_tools: recommendedTools,
    runtime_notes: dedupe(runtimeNotes, 8),
    warnings: [],
  }
}

function emptyStaticBehaviorContext(enabled: boolean, warning?: string): StaticBehaviorContext {
  return {
    enabled,
    artifact_ids: [],
    scope_note: null,
    finding_count: 0,
    high_or_critical_count: 0,
    high_signal_findings: [],
    inferred_goals: [],
    suggested_profile_ids: [],
    breakpoint_targets: [],
    recommended_next_tools: [],
    runtime_notes: [],
    warnings: warning ? [warning] : [],
  }
}

async function loadStaticBehaviorContext(
  deps: PluginToolDeps,
  input: z.infer<typeof DynamicDeepPlanInputSchema>
): Promise<StaticBehaviorContext> {
  if (!input.use_static_behavior_artifacts || !input.sample_id) {
    return emptyStaticBehaviorContext(false)
  }
  if (!deps.workspaceManager || !deps.database) {
    return emptyStaticBehaviorContext(false, 'Static behavior artifact lookup is unavailable in this handler context.')
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
    if (selection.artifacts.length === 0) {
      return {
        ...emptyStaticBehaviorContext(true),
        scope_note: selection.scope_note,
      }
    }
    return buildStaticBehaviorContextFromPayloads(
      selection.artifact_ids,
      selection.scope_note,
      selection.artifacts.map((artifact) => artifact.payload)
    )
  } catch (error) {
    return emptyStaticBehaviorContext(
      true,
      `Failed to load static behavior artifacts: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

function applyStaticBehaviorContext(
  profiles: DynamicPlanProfile[],
  context: StaticBehaviorContext
): DynamicPlanProfile[] {
  const suggested = new Set(context.suggested_profile_ids)
  const highSignalTechniques = context.high_signal_findings.map((finding) => `${finding.id}:${finding.technique}`)
  return profiles
    .map((profile, index) => {
      const evidenceBoost = suggested.has(profile.id) ? 40 : 0
      const priority = 100 - index + evidenceBoost
      const evidenceHooks = suggested.has(profile.id) ? highSignalTechniques.slice(0, 8) : []
      return {
        ...profile,
        priority,
        evidence_hooks: evidenceHooks,
        notes: evidenceHooks.length > 0
          ? [
              ...profile.notes,
              `Prioritized by static.behavior.classify findings: ${evidenceHooks.join(', ')}`,
            ]
          : profile.notes,
      }
    })
    .sort((left, right) => (right.priority || 0) - (left.priority || 0))
}

function buildExecutionOrder(profiles: DynamicPlanProfile[], runtimePreference: string) {
  const order = [
    {
      phase: 'preflight',
      tools: ['static.behavior.classify', 'dynamic.runtime.status', 'dynamic.toolkit.status', 'dynamic.dependencies', 'dynamic.persona.plan'],
      purpose: 'Collect static behavior expectations, verify configured runtime endpoint, Host Agent, Runtime Node capabilities, and runtime-side tools without launching or executing samples.',
    },
    {
      phase: 'session',
      tools: ['runtime.debug.session.start', 'runtime.debug.session.status'],
      purpose: `Start or attach a runtime only when live execution is explicitly needed. Runtime preference: ${runtimePreference}.`,
    },
    {
      phase: 'execute',
      tools: Array.from(new Set(profiles.flatMap((profile) => profile.executionTools))),
      purpose: 'Run the selected live or emulated dynamic actions under explicit tool calls.',
    },
    {
      phase: 'import',
      tools: ['dynamic.trace.import', 'dynamic.memory.import', 'dynamic.behavior.diff', 'analysis.evidence.graph', 'artifact.read', 'artifacts.list'],
      purpose: 'Normalize runtime evidence back into sample artifacts and correlate it against static expectations.',
    },
  ]
  return order
}

export function createDynamicDeepPlanHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    const input = DynamicDeepPlanInputSchema.parse(args || {})
    const staticBehaviorContext = await loadStaticBehaviorContext(deps, input)
    const requestedGoals = goalSet(input.goals)
    const effectiveGoals = new Set([
      ...Array.from(requestedGoals),
      ...staticBehaviorContext.inferred_goals,
    ])
    const profiles = applyStaticBehaviorContext(
      buildProfiles(input.sample_id).filter((profile) =>
        profileMatches(profile, effectiveGoals, input.include_gui_profiles, input.include_heavy_profiles)
      ),
      staticBehaviorContext
    )

    return {
      ok: true,
      data: {
        schema: 'rikune.dynamic_deep_plan.v1',
        sample_id: input.sample_id || null,
        runtime_preference: input.runtime_preference,
        requested_goals: Array.from(requestedGoals),
        selected_goals: Array.from(effectiveGoals),
        static_behavior_context: staticBehaviorContext,
        profiles,
        execution_order: buildExecutionOrder(profiles, input.runtime_preference),
        recommended_next_tools: [
          'static.behavior.classify',
          'dynamic.runtime.status',
          'dynamic.toolkit.status',
          'runtime.debug.session.start',
          ...Array.from(new Set(profiles.flatMap((profile) => profile.executionTools))),
          ...staticBehaviorContext.recommended_next_tools,
          'analysis.evidence.graph',
        ].filter((value, index, array) => array.indexOf(value) === index),
        safety: {
          mcp_connect_starts_runtime: false,
          plan_executes_sample: false,
          live_execution_requires_explicit_runtime_tool: true,
          transformations_are_not_automatic: true,
        },
        next_actions: staticBehaviorContext.artifact_ids.length > 0
          ? [
              'Use prioritized profiles first; they were inferred from static.behavior.classify evidence.',
              'After runtime evidence is imported, run dynamic.behavior.diff and analysis.evidence.graph to compare observations with these static expectations.',
            ]
          : [
              'Run static.behavior.classify first when persistence, injection, or anti-analysis behavior is suspected.',
              'Start a runtime session only after dynamic.runtime.status and dynamic.toolkit.status confirm the desired backend.',
            ],
      },
      warnings: staticBehaviorContext.warnings.length > 0 ? staticBehaviorContext.warnings : undefined,
      metrics: {
        elapsed_ms: Date.now() - started,
        tool: TOOL_NAME,
      },
    }
  }
}
