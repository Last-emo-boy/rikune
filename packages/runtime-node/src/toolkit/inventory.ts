import fs from 'fs'
import path from 'path'
import { config } from '../config.js'
import {
  RUNTIME_TOOL_PROFILE_DEFINITIONS,
  RUNTIME_TOOL_SPECS,
  getRuntimeToolSpec,
  type RuntimeToolCategory,
  type RuntimeToolSpec,
} from './manifest.js'

export type { RuntimeToolCategory, RuntimeToolSpec } from './manifest.js'

export interface RuntimeToolStatus {
  id: string
  displayName: string
  category: RuntimeToolCategory
  role: string
  available: boolean
  path: string | null
  source: string | null
  installHint: string
  profiles: string[]
}

export interface RuntimeToolProfile {
  id: string
  status: 'ready' | 'partial' | 'missing'
  requiredTools: string[]
  optionalTools: string[]
  availableTools: string[]
  missingTools: string[]
  recommendedTools: string[]
}

export interface RuntimeToolInventory {
  schema: 'rikune.runtime_tool_inventory.v1'
  generatedAt: string
  runtime: {
    platform: NodeJS.Platform
    mode: string
    toolSearchRoots: string[]
    pathEntries: string[]
  }
  tools: RuntimeToolStatus[]
  profiles: RuntimeToolProfile[]
  summary: {
    availableToolCount: number
    missingToolCount: number
    readyProfiles: string[]
    partialProfiles: string[]
    missingProfiles: string[]
  }
}

function splitEnvList(value: string | undefined): string[] {
  if (!value) {
    return []
  }
  const separator = process.platform === 'win32' ? /[;\n\r]+/u : /[:;\n\r]+/u
  return value
    .split(separator)
    .map((entry) => entry.trim())
    .filter(Boolean)
}

export function runtimeToolSearchRoots(): string[] {
  const roots = [
    ...splitEnvList(process.env.RUNTIME_TOOL_DIRS),
    process.env.RUNTIME_TOOL_CACHE_DIR,
    process.env.RIKUNE_RUNTIME_TOOLS,
    process.env.RIKUNE_TOOL_CACHE_DIR,
    'C:\\rikune-tools',
    'C:\\Tools',
    'C:\\ProgramData\\Rikune\\tools',
    'C:\\Program Files',
    'C:\\Program Files (x86)',
    path.join(process.cwd(), 'tools'),
    '/opt/rikune-tools',
    '/usr/local/rikune-tools',
  ].filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
  return Array.from(new Set(roots.map((entry) => path.resolve(entry))))
}

export function runtimePathEntries(): string[] {
  return (process.env.PATH || '')
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean)
}

function findExecutableOnPath(filenames: string[]): { path: string; source: string } | null {
  for (const dir of runtimePathEntries()) {
    for (const filename of filenames) {
      const candidate = path.join(dir, filename)
      if (fs.existsSync(candidate)) {
        return { path: candidate, source: 'PATH' }
      }
    }
  }
  return null
}

function resolveRuntimeToolCandidate(root: string, relativePath: string): string {
  return path.join(root, ...relativePath.split(/[\\/]+/u))
}

export function findRuntimeTool(
  spec: RuntimeToolSpec | undefined
): { path: string; source: string } | null {
  if (!spec) {
    return null
  }
  for (const root of runtimeToolSearchRoots()) {
    for (const relativePath of spec.relativePaths) {
      const candidate = resolveRuntimeToolCandidate(root, relativePath)
      if (fs.existsSync(candidate)) {
        return { path: candidate, source: root }
      }
    }
  }

  const pathMatch = findExecutableOnPath(spec.filenames)
  if (pathMatch) {
    return pathMatch
  }

  if (spec.id === 'python') {
    const pythonPath = config.runtime.pythonPath
    if (pythonPath && fs.existsSync(pythonPath)) {
      return { path: pythonPath, source: 'runtime.pythonPath' }
    }
  }
  return null
}

export function findRuntimeToolById(id: string): { path: string; source: string } | null {
  return findRuntimeTool(getRuntimeToolSpec(id))
}

function buildRuntimeToolProfiles(tools: RuntimeToolStatus[]): RuntimeToolProfile[] {
  const available = new Set(tools.filter((tool) => tool.available).map((tool) => tool.id))
  return RUNTIME_TOOL_PROFILE_DEFINITIONS.map((profile) => {
    const requiredAvailable = profile.requiredTools.filter((tool) => available.has(tool))
    const optionalAvailable = profile.optionalTools.filter((tool) => available.has(tool))
    const missingTools = [...profile.requiredTools, ...profile.optionalTools].filter(
      (tool) => !available.has(tool)
    )
    let status: RuntimeToolProfile['status'] = 'missing'
    if (profile.requiredTools.length === 0) {
      status =
        optionalAvailable.length > 0 || profile.optionalTools.length === 0 ? 'ready' : 'partial'
    } else if (requiredAvailable.length === profile.requiredTools.length) {
      status = 'ready'
    } else if (requiredAvailable.length > 0 || optionalAvailable.length > 0) {
      status = 'partial'
    }

    return {
      id: profile.id,
      status,
      requiredTools: profile.requiredTools,
      optionalTools: profile.optionalTools,
      availableTools: [...requiredAvailable, ...optionalAvailable],
      missingTools,
      recommendedTools: profile.recommendedTools,
    }
  })
}

export function buildRuntimeToolInventory(): RuntimeToolInventory {
  const tools = RUNTIME_TOOL_SPECS.map((spec): RuntimeToolStatus => {
    const match = findRuntimeTool(spec)
    return {
      id: spec.id,
      displayName: spec.displayName,
      category: spec.category,
      role: spec.role,
      available: Boolean(match),
      path: match?.path ?? null,
      source: match?.source ?? null,
      installHint: spec.installHint,
      profiles: spec.profiles,
    }
  })
  const profiles = buildRuntimeToolProfiles(tools)
  return {
    schema: 'rikune.runtime_tool_inventory.v1',
    generatedAt: new Date().toISOString(),
    runtime: {
      platform: process.platform,
      mode: config.runtime.mode,
      toolSearchRoots: runtimeToolSearchRoots(),
      pathEntries: runtimePathEntries(),
    },
    tools,
    profiles,
    summary: {
      availableToolCount: tools.filter((tool) => tool.available).length,
      missingToolCount: tools.filter((tool) => !tool.available).length,
      readyProfiles: profiles
        .filter((profile) => profile.status === 'ready')
        .map((profile) => profile.id),
      partialProfiles: profiles
        .filter((profile) => profile.status === 'partial')
        .map((profile) => profile.id),
      missingProfiles: profiles
        .filter((profile) => profile.status === 'missing')
        .map((profile) => profile.id),
    },
  }
}
