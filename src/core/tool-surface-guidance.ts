import { z } from 'zod'

export const TOOL_SURFACE_ROLE_VALUES = [
  'primary',
  'compatibility',
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

export function buildPreferredPrimaryTools(role: ToolSurfaceRole, preferredPrimaryTools: string[]) {
  return role === 'primary' ? [] : preferredPrimaryTools
}

export function classifyToolSurfaceRole(toolName: string): ToolSurfaceRole {
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

  return 'primary'
}

export function preferredPrimaryToolsFor(toolName: string): string[] {
  const role = classifyToolSurfaceRole(toolName)
  const preferredPrimaryTools =
    COMPATIBILITY_PRIMARY_TOOLS.get(toolName) ||
    EXPORT_PRIMARY_TOOLS.get(toolName) ||
    RENDERER_PRIMARY_TOOLS.get(toolName) ||
    []

  return buildPreferredPrimaryTools(role, preferredPrimaryTools)
}

export function buildToolSurfaceGuidance(toolName: string) {
  return {
    tool_surface_role: classifyToolSurfaceRole(toolName),
    preferred_primary_tools: preferredPrimaryToolsFor(toolName),
  }
}
