/**
 * debug.network.plan tool.
 *
 * Planning-only network lab profiles for FakeNet-style service emulation,
 * DNS/HTTP sinkholing, ETW DNS capture, and behavior-capture correlation.
 * It never starts services or executes samples by itself.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  loadStaticAnalysisArtifactSelection,
  persistStaticAnalysisJsonArtifact,
  type StaticArtifactScope,
} from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'debug.network.plan'
const TOOL_VERSION = '0.1.0'

const NetworkProfileSchema = z.enum([
  'proxy_sinkhole',
  'dns_sinkhole',
  'http_sinkhole',
  'fakenet',
  'etw_dns',
  'all',
])

export const DebugNetworkPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID used to render runtime.debug.command templates and static context.'),
  profiles: z.array(NetworkProfileSchema).optional().default(['proxy_sinkhole', 'etw_dns']),
  runtime_backend: z.enum(['auto', 'windows-sandbox', 'hyperv-vm', 'manual-runtime']).optional().default('auto'),
  capture_seconds: z.number().int().min(5).max(3600).optional().default(90),
  use_static_config_artifacts: z.boolean().optional().default(true),
  static_artifact_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  static_artifact_session_tag: z.string().optional(),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

const DebugNetworkPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const debugNetworkPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build planning-only network lab profiles for proxy sinkholing, DNS/HTTP fake services, FakeNet-style tooling, and ETW DNS capture. Produces runtime.debug.command templates but does not start services or execute samples.',
  inputSchema: DebugNetworkPlanInputSchema,
  outputSchema: DebugNetworkPlanOutputSchema,
}

interface StaticConfigCandidate {
  kind?: string
  value?: string
  confidence?: number
}

interface StaticConfigCarverPayload {
  candidates?: StaticConfigCandidate[]
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

function expandProfiles(profiles: string[]): string[] {
  if (profiles.includes('all')) {
    return ['proxy_sinkhole', 'dns_sinkhole', 'http_sinkhole', 'fakenet', 'etw_dns']
  }
  return dedupe(profiles)
}

function behaviorCaptureTemplate(input: z.infer<typeof DebugNetworkPlanInputSchema>): Record<string, unknown> {
  return {
    tool: 'runtime.debug.command',
    args: {
      session_id: '<runtime_debug_session_id>',
      ...(input.sample_id ? { sample_id: input.sample_id } : { sample_id: '<sample_id>' }),
      tool: 'dynamic.behavior.capture',
      args: {
        timeout_sec: Math.min(input.capture_seconds, 300),
        network_sinkhole: true,
        capture_network_snapshot: true,
      },
      runtime_backend_hint: { type: 'inline', handler: 'executeBehaviorCapture' },
      timeout_ms: Math.max(30_000, (Math.min(input.capture_seconds, 300) + 45) * 1000),
    },
  }
}

function etwDnsTemplate(input: z.infer<typeof DebugNetworkPlanInputSchema>): Record<string, unknown> {
  return {
    tool: 'runtime.debug.command',
    args: {
      session_id: '<runtime_debug_session_id>',
      ...(input.sample_id ? { sample_id: input.sample_id } : { sample_id: '<sample_id>' }),
      tool: 'debug.telemetry.capture',
      args: {
        profiles: ['etw_dns', 'powershell_eventlog'],
        capture_seconds: input.capture_seconds,
        include_cleanup: true,
      },
      runtime_backend_hint: { type: 'inline', handler: 'executeTelemetryCapture' },
      timeout_ms: Math.max(60_000, (input.capture_seconds + 75) * 1000),
    },
  }
}

function backendFit(profile: string, backend: string): string {
  if (profile === 'fakenet' || profile === 'dns_sinkhole' || profile === 'http_sinkhole') {
    if (backend === 'hyperv-vm' || backend === 'manual-runtime') return 'preferred'
    if (backend === 'windows-sandbox') return 'best_effort'
    return 'prefer_hyperv_or_manual'
  }
  return 'supported'
}

async function loadNetworkIndicators(
  deps: PluginToolDeps,
  input: z.infer<typeof DebugNetworkPlanInputSchema>
): Promise<{ artifact_ids: string[]; scope_note: string | null; indicators: string[]; warnings: string[] }> {
  if (!input.use_static_config_artifacts || !input.sample_id) {
    return { artifact_ids: [], scope_note: null, indicators: [], warnings: [] }
  }
  if (!deps.workspaceManager || !deps.database) {
    return {
      artifact_ids: [],
      scope_note: null,
      indicators: [],
      warnings: ['Static config artifact lookup is unavailable in this handler context.'],
    }
  }
  try {
    const selection = await loadStaticAnalysisArtifactSelection<StaticConfigCarverPayload>(
      deps.workspaceManager,
      deps.database,
      input.sample_id,
      'static_config_carver',
      {
        scope: input.static_artifact_scope as StaticArtifactScope,
        sessionTag: input.static_artifact_session_tag,
      }
    )
    const indicators = selection.artifacts.flatMap((artifact) =>
      (artifact.payload.candidates || [])
        .filter((candidate) =>
          ['url', 'domain', 'ip', 'ip_port', 'user_agent_or_http_client'].includes(candidate.kind || '') &&
          (candidate.confidence || 0) >= 0.55
        )
        .map((candidate) => candidate.value)
    )
    return {
      artifact_ids: selection.artifact_ids,
      scope_note: selection.scope_note,
      indicators: dedupe(indicators, 80),
      warnings: [],
    }
  } catch (error) {
    return {
      artifact_ids: [],
      scope_note: null,
      indicators: [],
      warnings: [`Failed to load static config artifacts: ${error instanceof Error ? error.message : String(error)}`],
    }
  }
}

function buildProfile(profile: string, input: z.infer<typeof DebugNetworkPlanInputSchema>, indicators: string[]) {
  const common = {
    capture_seconds: input.capture_seconds,
    backend_fit: backendFit(profile, input.runtime_backend),
    static_network_indicators: indicators.slice(0, 20),
  }
  if (profile === 'etw_dns') {
    return {
      id: 'etw_dns_network_capture',
      title: 'ETW DNS and event-log network telemetry',
      ...common,
      required_tools: ['logman.exe', 'PowerShell'],
      runtime_command_template: etwDnsTemplate(input),
      artifacts: ['etw_dns.etl', 'eventlog_snapshot.json', 'telemetry_capture.json'],
      notes: ['Use this after baseline behavior capture when DNS or network-client strings are present.'],
    }
  }
  if (profile === 'fakenet') {
    return {
      id: 'fakenet_service_lab',
      title: 'FakeNet-style service emulation lab',
      ...common,
      required_tools: ['FakeNet-NG or compatible fake-service harness'],
      runtime_command_template: null,
      artifacts: ['future fakenet report', 'behavior_capture.json', 'network_events'],
      notes: [
        'Run dynamic.toolkit.status first; FakeNet availability is runtime-image dependent.',
        'Prefer Hyper-V or manual runtime for DNS/HTTP service binding and repeatable rollback.',
      ],
    }
  }
  if (profile === 'dns_sinkhole' || profile === 'http_sinkhole') {
    return {
      id: `${profile}_lab`,
      title: profile === 'dns_sinkhole' ? 'DNS sinkhole preparation' : 'HTTP sinkhole preparation',
      ...common,
      required_tools: ['PowerShell', profile === 'dns_sinkhole' ? 'hosts/firewall control' : 'local HTTP listener'],
      runtime_command_template: behaviorCaptureTemplate(input),
      artifacts: ['behavior_capture.json', 'network_events'],
      notes: [
        'Treat host/network mutation as explicit runtime setup; rollback with Hyper-V checkpoint or sandbox reset.',
        'Use sidecars for config files when the sample expects adjacent network settings.',
      ],
    }
  }
  return {
    id: 'proxy_sinkhole_behavior_capture',
    title: 'Proxy environment sinkhole behavior capture',
    ...common,
    required_tools: ['Runtime Node behavior capture'],
    runtime_command_template: behaviorCaptureTemplate(input),
    artifacts: ['behavior_capture.json', 'network_events'],
    notes: ['This is the safest first network run: it sets proxy environment variables for the sample process only.'],
  }
}

export function createDebugNetworkPlanHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = DebugNetworkPlanInputSchema.parse(args || {})
      const staticContext = await loadNetworkIndicators(deps, input)
      const selectedProfiles = expandProfiles(input.profiles)
      const profiles = selectedProfiles.map((profile) => buildProfile(profile, input, staticContext.indicators))
      const data = {
        schema: 'rikune.debug_network_plan.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id || null,
        runtime_backend: input.runtime_backend,
        selected_profiles: selectedProfiles,
        static_network_context: {
          artifact_ids: staticContext.artifact_ids,
          scope_note: staticContext.scope_note,
          indicators: staticContext.indicators,
        },
        profiles,
        runtime_command_sequence: profiles
          .map((profile) => profile.runtime_command_template)
          .filter((entry): entry is Record<string, unknown> => Boolean(entry)),
        safety: {
          planning_only: true,
          starts_runtime: false,
          starts_services: false,
          mutates_dns_or_hosts: false,
          live_execution_requires_explicit_runtime_debug_command: true,
        },
        recommended_next_tools: [
          'dynamic.toolkit.status',
          'runtime.debug.session.start',
          'runtime.debug.command',
          'debug.telemetry.plan',
          'dynamic.behavior.diff',
          'analysis.evidence.graph',
        ],
        next_actions: [
          'Start with proxy_sinkhole behavior capture, then upgrade to ETW DNS or FakeNet-style profiles only when runtime tooling is ready.',
          'Use Hyper-V checkpoint rollback before DNS, hosts, or service-emulation changes.',
          'Correlate produced network observations with static.config.carver indicators through dynamic.behavior.diff.',
        ],
      }
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && input.sample_id && deps.workspaceManager && deps.database?.findSample?.(input.sample_id)) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          input.sample_id,
          'debug_network_plan',
          'debug_network_plan',
          data,
          input.session_tag
        ))
      }
      return {
        ok: true,
        data,
        artifacts,
        warnings: staticContext.warnings.length > 0 ? staticContext.warnings : undefined,
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
