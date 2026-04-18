/**
 * debug.telemetry.plan tool.
 *
 * Planning-only telemetry profiles for ProcMon, Sysmon, ETW, and PowerShell
 * event-log collection. It does not install services, start drivers, or launch
 * a runtime by itself.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  loadStaticAnalysisArtifactSelection,
  persistStaticAnalysisJsonArtifact,
  type StaticArtifactScope,
} from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'debug.telemetry.plan'
const TOOL_VERSION = '0.1.0'

const TelemetryProfileSchema = z.enum([
  'procmon',
  'sysmon',
  'etw_process',
  'etw_dns',
  'powershell_eventlog',
  'all',
])

export const DebugTelemetryPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID used to persist the plan and render sample-bound guidance.'),
  profiles: z.array(TelemetryProfileSchema).optional().default(['procmon', 'etw_process']),
  runtime_backend: z.enum(['auto', 'windows-sandbox', 'hyperv-vm', 'manual-runtime']).optional().default('auto'),
  capture_seconds: z.number().int().min(5).max(3600).optional().default(90),
  include_cleanup: z.boolean().optional().default(true),
  use_static_behavior_artifacts: z.boolean().optional().default(true),
  static_artifact_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  static_artifact_session_tag: z.string().optional(),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

const DebugTelemetryPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const debugTelemetryPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a planning-only telemetry capture plan for ProcMon, Sysmon, ETW process/DNS providers, and PowerShell event-log collection. Does not install services, start drivers, launch runtimes, or execute samples.',
  inputSchema: DebugTelemetryPlanInputSchema,
  outputSchema: DebugTelemetryPlanOutputSchema,
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

function expandProfiles(profiles: string[]): string[] {
  if (profiles.includes('all')) {
    return ['procmon', 'sysmon', 'etw_process', 'etw_dns', 'powershell_eventlog']
  }
  return dedupe(profiles)
}

async function loadStaticTelemetryHints(
  deps: PluginToolDeps,
  input: z.infer<typeof DebugTelemetryPlanInputSchema>
): Promise<{ artifact_ids: string[]; scope_note: string | null; suggested_profiles: string[]; warnings: string[] }> {
  if (!input.use_static_behavior_artifacts || !input.sample_id) {
    return { artifact_ids: [], scope_note: null, suggested_profiles: [], warnings: [] }
  }
  if (!deps.workspaceManager || !deps.database) {
    return {
      artifact_ids: [],
      scope_note: null,
      suggested_profiles: [],
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
    const suggested = [
      findings.some((finding) => finding.category === 'persistence') ? 'procmon' : null,
      findings.some((finding) => finding.category === 'persistence') ? 'sysmon' : null,
      findings.some((finding) => finding.category === 'injection') ? 'etw_process' : null,
      findings.some((finding) => finding.category === 'anti_analysis') ? 'powershell_eventlog' : null,
    ]
    return {
      artifact_ids: selection.artifact_ids,
      scope_note: selection.scope_note,
      suggested_profiles: dedupe(suggested),
      warnings: [],
    }
  } catch (error) {
    return {
      artifact_ids: [],
      scope_note: null,
      suggested_profiles: [],
      warnings: [`Failed to load static behavior artifacts: ${error instanceof Error ? error.message : String(error)}`],
    }
  }
}

function backendFit(profile: string, runtimeBackend: string): string {
  if (profile === 'sysmon' || profile === 'procmon') {
    if (runtimeBackend === 'hyperv-vm' || runtimeBackend === 'manual-runtime') return 'preferred'
    if (runtimeBackend === 'windows-sandbox') return 'best_effort'
    return 'prefer_hyperv_or_manual'
  }
  return 'supported'
}

function buildRuntimeTemplate(input: z.infer<typeof DebugTelemetryPlanInputSchema>, profile: string): Record<string, unknown> {
  return {
    tool: 'runtime.debug.command',
    args: {
      session_id: '<runtime_debug_session_id>',
      ...(input.sample_id ? { sample_id: input.sample_id } : {}),
      tool: 'debug.telemetry.capture',
      args: {
        profiles: [profile],
        capture_seconds: input.capture_seconds,
        include_cleanup: input.include_cleanup,
      },
      runtime_backend_hint: { type: 'inline', handler: 'executeTelemetryCapture' },
      timeout_ms: Math.max(30_000, (input.capture_seconds + 60) * 1000),
    },
  }
}

function buildProfilePlan(profile: string, input: z.infer<typeof DebugTelemetryPlanInputSchema>) {
  const common = {
    capture_seconds: input.capture_seconds,
    backend_fit: backendFit(profile, input.runtime_backend),
    cleanup_required: input.include_cleanup,
  }
  switch (profile) {
    case 'procmon':
      return {
        id: 'procmon_capture',
        title: 'ProcMon file/registry/process/network telemetry',
        ...common,
        required_tools: ['Procmon64.exe or Procmon.exe'],
        setup: ['dynamic.toolkit.status', 'runtime.debug.session.start'],
        capture_outline: [
          'Accept ProcMon EULA inside the runtime image or tool cache preparation step.',
          'Start ProcMon with backing file under the runtime outbox.',
          'Run explicit sample execution or behavior capture.',
          'Stop ProcMon and convert PML to CSV/XML before importing.',
        ],
        artifacts: ['procmon.pml', 'procmon.csv or procmon.xml', 'telemetry_manifest.json'],
        runtime_command_template: buildRuntimeTemplate(input, profile),
        risks: ['ProcMon driver/service lifecycle requires cleanup; Hyper-V checkpoint rollback is preferred.'],
      }
    case 'sysmon':
      return {
        id: 'sysmon_capture',
        title: 'Sysmon service-backed telemetry',
        ...common,
        required_tools: ['Sysmon64.exe or Sysmon.exe', 'sandbox-safe Sysmon config'],
        setup: ['dynamic.toolkit.status', 'runtime.hyperv.control', 'runtime.debug.session.start'],
        capture_outline: [
          'Restore or create a clean Hyper-V checkpoint.',
          'Install Sysmon with a bounded config focused on process, network, registry, image-load, and file-create events.',
          'Run explicit sample execution or behavior capture.',
          'Export Windows Event Log records and uninstall Sysmon or rollback the VM.',
        ],
        artifacts: ['sysmon_events.json', 'sysmon_config.xml', 'telemetry_manifest.json'],
        runtime_command_template: buildRuntimeTemplate(input, profile),
        risks: ['Service-backed capture should use Hyper-V/manual runtime, not shared host state.'],
      }
    case 'etw_dns':
      return {
        id: 'etw_dns_capture',
        title: 'ETW DNS/network telemetry',
        ...common,
        required_tools: ['logman or PowerShell ETW access'],
        setup: ['dynamic.toolkit.status', 'runtime.debug.session.start'],
        capture_outline: [
          'Start DNS Client and TCP/IP ETW providers with bounded duration.',
          'Run explicit sample execution or behavior capture.',
          'Stop collectors and export ETL/JSON summaries.',
        ],
        artifacts: ['network.etl', 'dns_events.json', 'telemetry_manifest.json'],
        runtime_command_template: buildRuntimeTemplate(input, profile),
        risks: ['Provider availability and admin rights vary across Sandbox and VM images.'],
      }
    case 'powershell_eventlog':
      return {
        id: 'powershell_eventlog_capture',
        title: 'PowerShell event-log snapshot',
        ...common,
        required_tools: ['PowerShell'],
        setup: ['runtime.debug.session.start'],
        capture_outline: [
          'Record event-log cursor before execution.',
          'Run explicit sample execution or behavior capture.',
          'Export process, service-control-manager, task scheduler, WMI, Defender, and PowerShell event records since the cursor.',
        ],
        artifacts: ['eventlog_snapshot.json', 'telemetry_manifest.json'],
        runtime_command_template: buildRuntimeTemplate(input, profile),
        risks: ['Lower fidelity than ProcMon/Sysmon but safer for Sandbox and minimal runtime images.'],
      }
    default:
      return {
        id: 'etw_process_capture',
        title: 'ETW process/image-load telemetry',
        ...common,
        required_tools: ['logman or PowerShell ETW access'],
        setup: ['dynamic.toolkit.status', 'runtime.debug.session.start'],
        capture_outline: [
          'Start process and image-load ETW providers with bounded duration.',
          'Run explicit sample execution or behavior capture.',
          'Stop collectors and export ETL/JSON summaries.',
        ],
        artifacts: ['process.etl', 'process_events.json', 'image_load_events.json', 'telemetry_manifest.json'],
        runtime_command_template: buildRuntimeTemplate(input, profile),
        risks: ['Use Hyper-V/manual runtime when provider permissions are not available in Sandbox.'],
      }
  }
}

function buildTelemetryPlan(input: z.infer<typeof DebugTelemetryPlanInputSchema>, profiles: string[], staticHints: Awaited<ReturnType<typeof loadStaticTelemetryHints>>) {
  return {
    schema: 'rikune.debug_telemetry_plan.v1',
    tool_version: TOOL_VERSION,
    sample_id: input.sample_id || null,
    runtime_backend: input.runtime_backend,
    selected_profiles: profiles,
    static_behavior_context: {
      artifact_ids: staticHints.artifact_ids,
      scope_note: staticHints.scope_note,
      suggested_profiles: staticHints.suggested_profiles,
    },
    profiles: profiles.map((profile) => buildProfilePlan(profile, input)),
    runtime_command_sequence: profiles.map((profile) => buildRuntimeTemplate(input, profile)),
    execution_order: [
      {
        phase: 'preflight',
        tools: ['dynamic.runtime.status', 'dynamic.toolkit.status', 'debug.telemetry.plan'],
        purpose: 'Confirm Runtime Node, Host Agent, and runtime-side telemetry tool availability without starting capture.',
      },
      {
        phase: 'isolation',
        tools: ['runtime.hyperv.control', 'runtime.debug.session.start'],
        purpose: 'Prefer Hyper-V/manual runtime for service or driver-backed capture; Sandbox is best-effort.',
      },
      {
        phase: 'capture',
        tools: ['dynamic.behavior.capture', 'runtime.debug.command'],
        purpose: 'Run explicit behavior capture or future telemetry capture commands after setup is intentionally complete.',
      },
      {
        phase: 'correlate',
        tools: ['dynamic.trace.import', 'dynamic.behavior.diff', 'analysis.evidence.graph'],
        purpose: 'Normalize telemetry artifacts and compare observations with static expectations.',
      },
      ...(input.include_cleanup
        ? [{
            phase: 'cleanup',
            tools: ['runtime.debug.session.stop', 'runtime.hyperv.control'],
            purpose: 'Stop collectors, uninstall service-backed telemetry when needed, or rollback Hyper-V checkpoint.',
          }]
        : []),
    ],
    safety: {
      planning_only: true,
      starts_runtime: false,
      installs_services: false,
      starts_drivers: false,
      prefer_hyperv_for_service_backed_capture: true,
      live_execution_requires_explicit_tool: true,
    },
    recommended_next_tools: [
      'dynamic.runtime.status',
      'dynamic.toolkit.status',
      'runtime.debug.session.start',
      'dynamic.behavior.capture',
      'dynamic.behavior.diff',
      'analysis.evidence.graph',
    ],
    next_actions: [
      'Use dynamic.toolkit.status to see whether ProcMon, Sysmon, PowerShell, and ETW helpers are available in the runtime.',
      'Use Hyper-V checkpoint rollback for ProcMon/Sysmon profiles unless you intentionally preserve dirty runtime state.',
      'Run dynamic.behavior.diff after telemetry import to identify dormant static expectations.',
    ],
  }
}

export function createDebugTelemetryPlanHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = DebugTelemetryPlanInputSchema.parse(args || {})
      const staticHints = await loadStaticTelemetryHints(deps, input)
      const selectedProfiles = dedupe([...expandProfiles(input.profiles), ...staticHints.suggested_profiles])
      const data = buildTelemetryPlan(input, selectedProfiles, staticHints)
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && input.sample_id && deps.workspaceManager && deps.database) {
        const sample = deps.database.findSample?.(input.sample_id)
        if (sample) {
          artifacts.push(await persistStaticAnalysisJsonArtifact(
            deps.workspaceManager,
            deps.database,
            input.sample_id,
            'debug_telemetry_plan',
            'debug_telemetry_plan',
            data,
            input.session_tag
          ))
        }
      }

      return {
        ok: true,
        data,
        artifacts,
        warnings: staticHints.warnings.length > 0 ? staticHints.warnings : undefined,
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
