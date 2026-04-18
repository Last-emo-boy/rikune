/**
 * debug.managed.plan tool.
 *
 * Planning-only .NET runtime debug profiles. It combines managed safe-run,
 * SOS/CDB command templates, ProcDump follow-up, and dnSpyEx handoff guidance
 * without launching a runtime or executing a sample.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  loadStaticAnalysisArtifactSelection,
  persistStaticAnalysisJsonArtifact,
  type StaticArtifactScope,
} from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'debug.managed.plan'
const TOOL_VERSION = '0.1.0'

const ManagedProfileSchema = z.enum([
  'safe_run',
  'sos_stack',
  'managed_dump',
  'resource_review',
  'dnspy_handoff',
  'all',
])

export const DebugManagedPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID used to render runtime.debug.command templates and static metadata context.'),
  profiles: z.array(ManagedProfileSchema).optional().default(['safe_run', 'sos_stack']),
  timeout_sec: z.number().int().min(5).max(600).optional().default(90),
  network_sinkhole: z.boolean().optional().default(true),
  use_dotnet_metadata_artifacts: z.boolean().optional().default(true),
  static_artifact_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  static_artifact_session_tag: z.string().optional(),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

const DebugManagedPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const debugManagedPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build planning-only .NET runtime debugging profiles for managed safe-run, SOS/CDB stack/object inspection, ProcDump follow-up, resource review, and dnSpyEx handoff. Produces runtime.debug.command templates but does not execute samples.',
  inputSchema: DebugManagedPlanInputSchema,
  outputSchema: DebugManagedPlanOutputSchema,
}

interface DotNetTypeRow {
  full_name?: string
  name?: string
  namespace?: string
  method_count?: number
}

interface DotNetMetadataPayload {
  is_dotnet?: boolean
  assembly_name?: string | null
  target_framework?: string | null
  types?: DotNetTypeRow[]
  resources?: Array<{ name?: string }>
  summary?: {
    type_count?: number
    method_count?: number
    resource_count?: number
  }
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
    return ['safe_run', 'sos_stack', 'managed_dump', 'resource_review', 'dnspy_handoff']
  }
  return dedupe(profiles)
}

async function loadDotNetMetadataContext(
  deps: PluginToolDeps,
  input: z.infer<typeof DebugManagedPlanInputSchema>
): Promise<{ artifact_ids: string[]; scope_note: string | null; assemblies: string[]; types: string[]; resources: string[]; warnings: string[] }> {
  if (!input.use_dotnet_metadata_artifacts || !input.sample_id) {
    return { artifact_ids: [], scope_note: null, assemblies: [], types: [], resources: [], warnings: [] }
  }
  if (!deps.workspaceManager || !deps.database) {
    return {
      artifact_ids: [],
      scope_note: null,
      assemblies: [],
      types: [],
      resources: [],
      warnings: ['.NET metadata artifact lookup is unavailable in this handler context.'],
    }
  }
  try {
    const selection = await loadStaticAnalysisArtifactSelection<DotNetMetadataPayload>(
      deps.workspaceManager,
      deps.database,
      input.sample_id,
      'dotnet_metadata',
      {
        scope: input.static_artifact_scope as StaticArtifactScope,
        sessionTag: input.static_artifact_session_tag,
      }
    )
    const payloads = selection.artifacts.map((artifact) => artifact.payload)
    return {
      artifact_ids: selection.artifact_ids,
      scope_note: selection.scope_note,
      assemblies: dedupe(payloads.map((payload) => payload.assembly_name || null), 10),
      types: dedupe(payloads.flatMap((payload) => (payload.types || []).map((type) => type.full_name || type.name)), 50),
      resources: dedupe(payloads.flatMap((payload) => (payload.resources || []).map((resource) => resource.name)), 50),
      warnings: [],
    }
  } catch (error) {
    return {
      artifact_ids: [],
      scope_note: null,
      assemblies: [],
      types: [],
      resources: [],
      warnings: [`Failed to load .NET metadata artifacts: ${error instanceof Error ? error.message : String(error)}`],
    }
  }
}

function safeRunTemplate(input: z.infer<typeof DebugManagedPlanInputSchema>): Record<string, unknown> {
  return {
    tool: 'runtime.debug.command',
    args: {
      session_id: '<runtime_debug_session_id>',
      ...(input.sample_id ? { sample_id: input.sample_id } : { sample_id: '<sample_id>' }),
      tool: 'managed.safe_run',
      args: {
        timeout_sec: input.timeout_sec,
        network_sinkhole: input.network_sinkhole,
      },
      runtime_backend_hint: { type: 'inline', handler: 'executeManagedSafeRun' },
      timeout_ms: Math.max(30_000, (input.timeout_sec + 45) * 1000),
    },
  }
}

function sosTemplate(input: z.infer<typeof DebugManagedPlanInputSchema>): Record<string, unknown> {
  const commands = [
    '.symfix',
    '.reload /f',
    '.loadby sos clr',
    '.loadby sos coreclr',
    '!clrstack',
    '!dumpdomain',
    '!threads',
    'q',
  ]
  return {
    tool: 'runtime.debug.command',
    args: {
      session_id: '<runtime_debug_session_id>',
      ...(input.sample_id ? { sample_id: input.sample_id } : { sample_id: '<sample_id>' }),
      tool: 'debug.session.command_batch',
      args: { commands },
      runtime_backend_hint: { type: 'inline', handler: 'executeDebugSession' },
      timeout_ms: Math.max(60_000, (input.timeout_sec + 60) * 1000),
    },
  }
}

function procDumpTemplate(input: z.infer<typeof DebugManagedPlanInputSchema>): Record<string, unknown> {
  return {
    tool: 'runtime.debug.command',
    args: {
      session_id: '<runtime_debug_session_id>',
      ...(input.sample_id ? { sample_id: input.sample_id } : { sample_id: '<sample_id>' }),
      tool: 'debug.procdump.capture',
      args: {
        mode: 'launch_first_chance',
        dump_type: 'full',
        seconds: Math.min(input.timeout_sec, 300),
        max_dumps: 2,
      },
      runtime_backend_hint: { type: 'inline', handler: 'executeProcDumpCapture' },
      timeout_ms: Math.max(90_000, (input.timeout_sec + 90) * 1000),
    },
  }
}

function buildProfile(profile: string, input: z.infer<typeof DebugManagedPlanInputSchema>, metadata: Awaited<ReturnType<typeof loadDotNetMetadataContext>>) {
  const common = {
    metadata_context: {
      assemblies: metadata.assemblies,
      notable_types: metadata.types.slice(0, 20),
      resources: metadata.resources.slice(0, 20),
    },
  }
  if (profile === 'sos_stack') {
    return {
      id: 'managed_sos_cdb_stack',
      title: 'SOS/CDB managed stack and domain inspection',
      ...common,
      required_tools: ['cdb.exe', 'SOS extension via CLR/CoreCLR'],
      runtime_command_template: sosTemplate(input),
      artifacts: ['debug_session_trace.json'],
      notes: ['Use after dotnet.metadata.extract confirms a managed sample and CDB is available inside the runtime.'],
    }
  }
  if (profile === 'managed_dump') {
    return {
      id: 'managed_procdump_first_chance',
      title: 'Managed first-chance exception dump capture',
      ...common,
      required_tools: ['ProcDump'],
      runtime_command_template: procDumpTemplate(input),
      artifacts: ['procdump_capture.json', '*.dmp'],
      notes: ['Use dynamic.memory.import or unpack.child.handoff on produced dumps when decrypted resources or unpacked assemblies are expected.'],
    }
  }
  if (profile === 'resource_review') {
    return {
      id: 'managed_resource_review',
      title: 'Managed resource and metadata review',
      ...common,
      required_tools: ['dotnet.metadata.extract', 'static.resource.graph'],
      runtime_command_template: null,
      artifacts: ['dotnet_metadata', 'static_resource_graph'],
      notes: ['This profile is static-first; use runtime execution only after metadata/resource pivots identify behavior to trigger.'],
    }
  }
  if (profile === 'dnspy_handoff') {
    return {
      id: 'managed_dnspy_handoff',
      title: 'dnSpyEx manual handoff',
      ...common,
      required_tools: ['dnSpyEx in visible runtime'],
      runtime_command_template: null,
      artifacts: ['debug_gui_handoff', 'retained Hyper-V VM state'],
      notes: ['Prefer Hyper-V preserve_dirty retention for manual dnSpyEx review; Windows service sessions cannot reliably show GUI tools.'],
    }
  }
  return {
    id: 'managed_safe_run',
    title: 'Managed safe-run with network sinkhole',
    ...common,
    required_tools: ['dotnet runtime or direct Windows EXE launch inside Runtime Node'],
    runtime_command_template: safeRunTemplate(input),
    artifacts: ['managed safe-run stdout/stderr', 'runtime_debug_artifact'],
    notes: ['Use as the first managed runtime run before debugger-heavy SOS or dump workflows.'],
  }
}

export function createDebugManagedPlanHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = DebugManagedPlanInputSchema.parse(args || {})
      const metadata = await loadDotNetMetadataContext(deps, input)
      const selectedProfiles = expandProfiles(input.profiles)
      const profiles = selectedProfiles.map((profile) => buildProfile(profile, input, metadata))
      const data = {
        schema: 'rikune.debug_managed_plan.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id || null,
        selected_profiles: selectedProfiles,
        dotnet_metadata_context: {
          artifact_ids: metadata.artifact_ids,
          scope_note: metadata.scope_note,
          assemblies: metadata.assemblies,
          notable_types: metadata.types,
          resources: metadata.resources,
        },
        profiles,
        runtime_command_sequence: profiles
          .map((profile) => profile.runtime_command_template)
          .filter((entry): entry is Record<string, unknown> => Boolean(entry)),
        safety: {
          planning_only: true,
          starts_runtime: false,
          executes_sample: false,
          live_execution_requires_explicit_runtime_debug_command: true,
          gui_handoff_requires_user_session: true,
        },
        recommended_next_tools: [
          'runtime.detect',
          'dotnet.metadata.extract',
          'dynamic.toolkit.status',
          'runtime.debug.session.start',
          'runtime.debug.command',
          'debug.gui.handoff',
        ],
        next_actions: [
          'Run dotnet.metadata.extract first when managed metadata has not been persisted yet.',
          'Use managed.safe_run for bounded first execution, then add SOS/CDB or ProcDump only when tool readiness is confirmed.',
          'Use debug.gui.handoff for dnSpyEx review in a visible Sandbox or preserved Hyper-V VM.',
        ],
      }
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && input.sample_id && deps.workspaceManager && deps.database?.findSample?.(input.sample_id)) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          input.sample_id,
          'debug_managed_plan',
          'debug_managed_plan',
          data,
          input.session_tag
        ))
      }
      return {
        ok: true,
        data,
        artifacts,
        warnings: metadata.warnings.length > 0 ? metadata.warnings : undefined,
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
