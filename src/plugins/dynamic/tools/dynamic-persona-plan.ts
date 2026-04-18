/**
 * dynamic.persona.plan tool.
 *
 * Planning-only runtime persona builder. It prepares an explicit checklist for
 * human-like Sandbox/Hyper-V runtime state without modifying the host, VM, or
 * sandbox by itself.
 */

import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'dynamic.persona.plan'
const TOOL_VERSION = '0.1.0'

const PersonaProfileSchema = z.enum([
  'desktop_user',
  'office_user',
  'developer_workstation',
  'analyst_vm',
  'enterprise_joined',
])

export const DynamicPersonaPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample id used to persist the persona plan as an artifact.'),
  profile: PersonaProfileSchema.optional().default('desktop_user'),
  runtime_backend: z.enum(['auto', 'windows-sandbox', 'hyperv-vm', 'manual-runtime']).optional().default('auto'),
  include_network_persona: z.boolean().optional().default(true),
  include_user_activity: z.boolean().optional().default(true),
  include_office_artifacts: z.boolean().optional().default(false),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

const DynamicPersonaPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const dynamicPersonaPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a planning-only runtime persona checklist for Windows Sandbox or Hyper-V: user profile files, RecentDocs, browser-like traces, timezone/locale hints, office artifacts, network persona, and interaction timing. Does not launch or modify any runtime.',
  inputSchema: DynamicPersonaPlanInputSchema,
  outputSchema: DynamicPersonaPlanOutputSchema,
}

function basePersona(profile: z.infer<typeof PersonaProfileSchema>) {
  const common = {
    username: profile === 'developer_workstation' ? 'devuser' : profile === 'analyst_vm' ? 'analyst' : 'j.smith',
    locale: 'en-US',
    timezone: 'Pacific Standard Time',
    screen: { width: 1920, height: 1080, scale: 100 },
  }
  switch (profile) {
    case 'office_user':
      return {
        ...common,
        username: 'm.roberts',
        documents: ['Q1 Forecast.xlsx', 'Meeting Notes.docx', 'Vendor List.pdf'],
        recentApps: ['WINWORD.EXE', 'EXCEL.EXE', 'chrome.exe', 'Teams.exe'],
      }
    case 'developer_workstation':
      return {
        ...common,
        documents: ['build.log', 'notes.md', 'sample-output.json'],
        recentApps: ['Code.exe', 'powershell.exe', 'git.exe', 'chrome.exe'],
      }
    case 'analyst_vm':
      return {
        ...common,
        username: 'analyst',
        documents: ['triage.md', 'hashes.txt', 'ioc-notes.json'],
        recentApps: ['Procmon64.exe', 'x64dbg.exe', 'dnSpy.exe', 'powershell.exe'],
      }
    case 'enterprise_joined':
      return {
        ...common,
        username: 'a.patel',
        documents: ['VPN Instructions.pdf', 'Expense Report.xlsx', 'HR Portal.url'],
        recentApps: ['OUTLOOK.EXE', 'Teams.exe', 'msedge.exe', 'OneDrive.exe'],
      }
    default:
      return {
        ...common,
        documents: ['Downloads\\invoice.pdf', 'Desktop\\notes.txt', 'Pictures\\screenshot.png'],
        recentApps: ['explorer.exe', 'chrome.exe', 'notepad.exe'],
      }
  }
}

function buildPersonaPlan(input: z.infer<typeof DynamicPersonaPlanInputSchema>) {
  const persona = basePersona(input.profile)
  const filesystem = [
    `%USERPROFILE%\\Desktop\\notes.txt`,
    `%USERPROFILE%\\Downloads\\invoice.pdf`,
    `%USERPROFILE%\\Documents\\${persona.documents[0]}`,
    '%APPDATA%\\Microsoft\\Windows\\Recent',
    '%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer',
  ]
  const registry = [
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',
    'HKCU\\Control Panel\\International',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders',
  ]
  if (input.include_office_artifacts || input.profile === 'office_user' || input.profile === 'enterprise_joined') {
    registry.push('HKCU\\Software\\Microsoft\\Office')
    filesystem.push('%APPDATA%\\Microsoft\\Office\\Recent')
  }
  const network = input.include_network_persona
    ? {
        dns_suffixes: ['corp.example.local'],
        proxy_mode: 'disabled_by_default',
        fake_services: ['dns', 'http', 'https_metadata_only'],
        guidance: 'Pair with dynamic.network.lab or runtime sinkhole when network behavior must be exercised.',
      }
    : null
  const userActivity = input.include_user_activity
    ? {
        mouse_warmup_seconds: 8,
        idle_jitter_seconds: [1, 4],
        recent_app_sequence: persona.recentApps,
      }
    : null

  return {
    schema: 'rikune.dynamic_persona_plan.v1',
    tool_version: TOOL_VERSION,
    sample_id: input.sample_id || null,
    profile: input.profile,
    runtime_backend: input.runtime_backend,
    persona,
    preparation_steps: [
      {
        phase: 'preflight',
        tools: ['dynamic.runtime.status', 'dynamic.toolkit.status', 'dynamic.deep_plan'],
        purpose: 'Confirm runtime availability and choose behavior/debugger/network profile before any persona mutation.',
      },
      {
        phase: 'runtime_state',
        backend_fit: input.runtime_backend === 'hyperv-vm' ? 'preferred' : 'supported',
        filesystem,
        registry,
        network,
        user_activity: userActivity,
      },
      {
        phase: 'execution',
        tools: ['runtime.debug.session.start', 'dynamic.behavior.capture', 'runtime.debug.command'],
        purpose: 'Run explicit dynamic tools after persona state is prepared.',
      },
      {
        phase: 'cleanup',
        tools: ['runtime.debug.session.stop', 'runtime.hyperv.control'],
        purpose: 'Rollback checkpoint for Hyper-V or discard Sandbox state after capture.',
      },
    ],
    safety: {
      planning_only: true,
      starts_runtime: false,
      modifies_host: false,
      live_execution_requires_explicit_tool: true,
      prefer_hyperv_for_persistent_persona: true,
    },
    recommended_next_tools: [
      'dynamic.runtime.status',
      'dynamic.toolkit.status',
      'runtime.debug.session.start',
      'dynamic.behavior.capture',
    ],
  }
}

export function createDynamicPersonaPlanHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = DynamicPersonaPlanInputSchema.parse(args || {})
      const data = buildPersonaPlan(input)
      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && input.sample_id && deps.workspaceManager && deps.database) {
        const sample = deps.database.findSample?.(input.sample_id)
        if (sample) {
          artifacts.push(await persistStaticAnalysisJsonArtifact(
            deps.workspaceManager,
            deps.database,
            input.sample_id,
            'dynamic_persona_plan',
            'dynamic_persona_plan',
            data,
            input.session_tag
          ))
        }
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
