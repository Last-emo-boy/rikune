/**
 * debug.gui.handoff tool.
 *
 * Artifact-backed handoff plan for visible x64dbg, WinDbg, and dnSpyEx review
 * in Windows Sandbox, Hyper-V VM, or a manual Runtime Node. It prepares the
 * workflow and safety constraints without launching GUI tools itself.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'debug.gui.handoff'
const TOOL_VERSION = '0.1.0'

const GuiToolSchema = z.enum(['x64dbg', 'windbg', 'dnspy', 'all'])

export const DebugGuiHandoffInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID to bind handoff notes and runtime session templates.'),
  tools: z.array(GuiToolSchema).optional().default(['x64dbg', 'windbg']),
  runtime_backend: z.enum(['auto', 'windows-sandbox', 'hyperv-vm', 'manual-runtime']).optional().default('hyperv-vm'),
  retention_policy: z.enum(['clean_rollback', 'stop_only', 'preserve_dirty']).optional().default('preserve_dirty'),
  include_managed_hints: z.boolean().optional().default(true),
  include_native_hints: z.boolean().optional().default(true),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

const DebugGuiHandoffOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const debugGuiHandoffToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build artifact-backed manual GUI debugging handoff notes for x64dbg, WinDbg, and dnSpyEx in visible Sandbox, Hyper-V VM, or manual runtime sessions. Does not launch GUI tools automatically.',
  inputSchema: DebugGuiHandoffInputSchema,
  outputSchema: DebugGuiHandoffOutputSchema,
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

function expandTools(tools: string[]): string[] {
  if (tools.includes('all')) {
    return ['x64dbg', 'windbg', 'dnspy']
  }
  return dedupe(tools)
}

function sessionStartTemplate(input: z.infer<typeof DebugGuiHandoffInputSchema>): Record<string, unknown> {
  return {
    tool: 'runtime.debug.session.start',
    args: {
      ...(input.sample_id ? { sample_id: input.sample_id } : {}),
      hyperv_retention_policy: input.retention_policy,
      ...(input.retention_policy === 'preserve_dirty'
        ? { hyperv_restore_on_release: false, hyperv_stop_on_release: false }
        : {}),
    },
  }
}

function buildToolHandoff(tool: string, input: z.infer<typeof DebugGuiHandoffInputSchema>) {
  if (tool === 'dnspy') {
    return {
      id: 'dnspy_manual_review',
      tool: 'dnSpyEx',
      best_backend: input.runtime_backend === 'windows-sandbox' ? 'windows-sandbox-visible' : 'hyperv-vm-preserve_dirty',
      required_runtime_tools: ['dnSpy.exe'],
      sample_staging: input.sample_id ? 'Stage sample with runtime.debug.command sidecar upload before manual review.' : 'Provide sample_id before staging into the visible runtime.',
      checklist: [
        'Open the sample assembly in dnSpyEx inside the visible runtime.',
        'Review entry point, resources, embedded configs, and suspicious static constructors.',
        'If a runtime-generated assembly appears, export it and re-ingest as a child sample.',
      ],
      artifact_expectations: ['debug_gui_handoff', 'manual_notes', 'exported child sample candidates'],
    }
  }
  if (tool === 'windbg') {
    return {
      id: 'windbg_manual_review',
      tool: 'WinDbg',
      best_backend: 'hyperv-vm-preserve_dirty',
      required_runtime_tools: ['windbg.exe or WinDbgX.exe'],
      sample_staging: input.sample_id ? 'Upload sample to the Runtime Node inbox/outbox workspace and open it from the visible desktop.' : 'Provide sample_id before staging into WinDbg.',
      checklist: [
        'Open executable or produced dump in WinDbg inside the runtime user session.',
        'Set breakpoints from debug.cdb.plan or inspect ProcDump outputs.',
        'Save dump, command log, and notes to a mapped outbox folder before releasing the runtime.',
      ],
      artifact_expectations: ['debug_session_trace.json', 'procdump_capture.json', 'manual dump/log artifacts'],
    }
  }
  return {
    id: 'x64dbg_manual_review',
    tool: 'x64dbg',
    best_backend: 'hyperv-vm-preserve_dirty',
    required_runtime_tools: ['x64dbg.exe'],
    sample_staging: input.sample_id ? 'Upload sample to the Runtime Node workspace and open it from x64dbg in the visible desktop.' : 'Provide sample_id before staging into x64dbg.',
    checklist: [
      'Start from static behavior classifier APIs and CDB plan breakpoints.',
      'Use Hyper-V dirty retention when unpacking or manual patching is expected.',
      'Export memory dumps or unpacked files to the runtime outbox for import.',
    ],
    artifact_expectations: ['manual dump/log artifacts', 'dynamic.memory.import inputs', 'unpack.child.handoff inputs'],
  }
}

function buildGuidance(input: z.infer<typeof DebugGuiHandoffInputSchema>, selectedTools: string[]) {
  const needsManaged = selectedTools.includes('dnspy') || input.include_managed_hints
  const needsNative = selectedTools.includes('x64dbg') || selectedTools.includes('windbg') || input.include_native_hints
  return {
    recommended_preflight_tools: [
      'dynamic.runtime.status',
      'dynamic.toolkit.status',
      ...(needsManaged ? ['runtime.detect', 'dotnet.metadata.extract', 'debug.managed.plan'] : []),
      ...(needsNative ? ['static.behavior.classify', 'debug.cdb.plan', 'debug.procdump.plan'] : []),
    ],
    recommended_followup_tools: [
      'dynamic.memory.import',
      'unpack.child.handoff',
      'dynamic.behavior.diff',
      'analysis.evidence.graph',
      'workflow.summarize',
    ],
    user_session_constraints: [
      'Windows GUI tools must run in an interactive desktop session; service-launched Host Agent contexts can prepare state but may not show UI.',
      'Windows Sandbox is quick but less reliable for long manual sessions; Hyper-V preserve_dirty is preferred for iterative GUI debugging.',
      'Do not rely on MCP connection alone to open Sandbox or GUI tools. Start or attach a runtime session explicitly.',
    ],
  }
}

export function createDebugGuiHandoffHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = DebugGuiHandoffInputSchema.parse(args || {})
      const selectedTools = expandTools(input.tools)
      const data = {
        schema: 'rikune.debug_gui_handoff.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id || null,
        runtime_backend: input.runtime_backend,
        retention_policy: input.retention_policy,
        selected_tools: selectedTools,
        runtime_session_template: sessionStartTemplate(input),
        handoff_profiles: selectedTools.map((tool) => buildToolHandoff(tool, input)),
        safety: {
          planning_only: true,
          launches_gui: false,
          starts_runtime: false,
          requires_interactive_user_session: true,
          preserve_dirty_default: input.retention_policy === 'preserve_dirty',
        },
        ...buildGuidance(input, selectedTools),
        next_actions: [
          'Call dynamic.toolkit.status to confirm the requested GUI tools are mounted in the runtime image or tool cache.',
          'Use runtime.debug.session.start with preserve_dirty when manual analysis must continue after automated setup.',
          'Copy or export manual dumps/logs into the mapped runtime outbox, then import them with dynamic.memory.import or unpack.child.handoff.',
        ],
      }
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && input.sample_id && deps.workspaceManager && deps.database?.findSample?.(input.sample_id)) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          input.sample_id,
          'debug_gui_handoff',
          'debug_gui_handoff',
          data,
          input.session_tag
        ))
      }
      return {
        ok: true,
        data,
        artifacts,
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
