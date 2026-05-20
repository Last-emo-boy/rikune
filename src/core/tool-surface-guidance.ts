import { z } from 'zod'

export const TOOL_SURFACE_ROLE_VALUES = [
  'primary',
  'compatibility',
  'specialist',
  'expert',
  'runtime_gated',
  'export_only',
  'renderer_helper',
] as const

export const ToolSurfaceRoleSchema = z.enum(TOOL_SURFACE_ROLE_VALUES)

export type ToolSurfaceRole = z.infer<typeof ToolSurfaceRoleSchema>

const PRIMARY_TOOLS = new Set([
  'sample.ingest',
  'sample.request_upload',
  'tool.help',
  'tool.readiness',
  'workflow.analyze.auto',
  'workflow.analyze.start',
  'workflow.analyze.status',
  'workflow.analyze.promote',
  'workflow.summarize',
])

const EXPORT_ONLY_TOOLS = new Set(['report.generate'])

const RENDERER_HELPER_TOOLS = new Set(['graphviz.render'])

const COMPATIBILITY_PRIMARY_TOOLS = new Map<string, string[]>([
  [
    'workflow.triage',
    ['workflow.analyze.start', 'workflow.analyze.status', 'workflow.analyze.promote'],
  ],
  ['task.status', ['workflow.analyze.status']],
  ['report.summarize', ['workflow.summarize']],
])

const EXPORT_PRIMARY_TOOLS = new Map<string, string[]>([
  ['report.generate', ['workflow.summarize', 'report.summarize']],
])

const RENDERER_PRIMARY_TOOLS = new Map<string, string[]>([
  ['graphviz.render', ['code.function.cfg', 'workflow.summarize', 'report.summarize']],
])

const SPECIALIST_TOOL_PREFIXES = [
  'pe.',
  'elf.',
  'macho.',
  'apk.',
  'dex.',
  'strings.',
  'yara.',
  'crypto.',
  'static.',
  'binary.',
  'dll.',
  'com.',
  'code.',
  'dotnet.',
  'rust_',
  'go.',
]

const EXPERT_TOOL_PREFIXES = [
  'ghidra.',
  'rizin.',
  'retdec.',
  'angr.',
  'qiling.',
  'panda.',
  'vm.',
  'symbolic.',
  'patch.',
]

const RUNTIME_GATED_TOOL_PREFIXES = [
  'sandbox.',
  'frida.',
  'runtime.debug.',
  'dynamic.behavior.',
  'dynamic.memory.',
  'dynamic.trace.',
  'deobf.',
  'managed.',
  'wine.',
]

export function buildPreferredPrimaryTools(role: ToolSurfaceRole, preferredPrimaryTools: string[]) {
  return role === 'primary' ? [] : preferredPrimaryTools
}

export function classifyToolSurfaceRole(
  toolName: string,
  options: { runtimeRequired?: boolean } = {}
): ToolSurfaceRole {
  if (options.runtimeRequired) {
    return 'runtime_gated'
  }

  if (PRIMARY_TOOLS.has(toolName)) {
    return 'primary'
  }

  if (EXPORT_ONLY_TOOLS.has(toolName)) {
    return 'export_only'
  }

  if (RENDERER_HELPER_TOOLS.has(toolName)) {
    return 'renderer_helper'
  }

  if (COMPATIBILITY_PRIMARY_TOOLS.has(toolName)) {
    return 'compatibility'
  }

  if (RUNTIME_GATED_TOOL_PREFIXES.some((prefix) => toolName.startsWith(prefix))) {
    return 'runtime_gated'
  }

  if (EXPERT_TOOL_PREFIXES.some((prefix) => toolName.startsWith(prefix))) {
    return 'expert'
  }

  if (SPECIALIST_TOOL_PREFIXES.some((prefix) => toolName.startsWith(prefix))) {
    return 'specialist'
  }

  return 'primary'
}

export function preferredPrimaryToolsFor(
  toolName: string,
  options: { runtimeRequired?: boolean } = {}
): string[] {
  const role = classifyToolSurfaceRole(toolName, options)
  const preferredPrimaryTools =
    COMPATIBILITY_PRIMARY_TOOLS.get(toolName) ||
    EXPORT_PRIMARY_TOOLS.get(toolName) ||
    RENDERER_PRIMARY_TOOLS.get(toolName) ||
    (role === 'runtime_gated'
      ? ['dynamic.runtime.status', 'runtime.debug.session.start', 'workflow.analyze.status']
      : role === 'expert'
        ? ['workflow.analyze.start', 'workflow.analyze.promote', 'tool.readiness']
        : role === 'specialist'
          ? ['workflow.analyze.start', 'workflow.analyze.status', 'tools.discover']
          : []) ||
    []

  return buildPreferredPrimaryTools(role, preferredPrimaryTools)
}

export function buildToolSurfaceGuidance(
  toolName: string,
  options: { runtimeRequired?: boolean } = {}
) {
  return {
    tool_surface_role: classifyToolSurfaceRole(toolName, options),
    preferred_primary_tools: preferredPrimaryToolsFor(toolName, options),
  }
}
