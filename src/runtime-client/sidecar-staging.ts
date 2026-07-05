import fs from 'fs/promises'
import type { Dirent } from 'fs'
import path from 'path'

export interface RuntimeSidecarUpload {
  path: string
  name?: string
  size?: number
  source?: 'explicit' | 'auto'
}

export interface RuntimeSidecarResolveResult {
  sidecars: RuntimeSidecarUpload[]
  warnings: string[]
}

export interface RuntimeSidecarResolveOptions {
  sidecarPaths?: unknown
  autoStageSidecars?: boolean
  maxSidecars?: number
  maxTotalBytes?: number
  allowedExtensions?: string[]
}

const DEFAULT_SIDECAR_EXTENSIONS = new Set([
  '.cfg',
  '.config',
  '.dat',
  '.dll',
  '.ini',
  '.json',
  '.pdb',
  '.so',
  '.txt',
  '.xml',
  '.yaml',
  '.yml',
])

const DEFAULT_MAX_SIDECARS = 32
const DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024

function normalizeContainmentPath(value: string): string {
  const resolved = path.resolve(value)
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved
}

function isPathWithinRoot(candidate: string, root: string): boolean {
  const relative = path.relative(
    normalizeContainmentPath(root),
    normalizeContainmentPath(candidate)
  )
  return (
    relative === '' ||
    (relative.length > 0 && !relative.startsWith('..') && !path.isAbsolute(relative))
  )
}

function formatAllowedRoots(roots: string[]): string {
  return roots.map((root) => path.resolve(root)).join(', ')
}

async function realpathOrResolved(value: string): Promise<string> {
  try {
    return await fs.realpath(value)
  } catch {
    return path.resolve(value)
  }
}

function normalizeExplicitSidecarPaths(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value
    .filter((entry): entry is string => typeof entry === 'string')
    .map((entry) => entry.trim())
    .filter(Boolean)
}

function getAllowedExtensions(extensions?: string[]): Set<string> {
  if (!extensions || extensions.length === 0) {
    return DEFAULT_SIDECAR_EXTENSIONS
  }
  return new Set(
    extensions
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean)
      .map((entry) => (entry.startsWith('.') ? entry : `.${entry}`))
  )
}

async function collectExplicitSidecars(
  samplePath: string,
  sidecarPaths: string[],
  state: {
    seen: Set<string>
    totalBytes: number
    maxSidecars: number
    maxTotalBytes: number
    sidecars: RuntimeSidecarUpload[]
    warnings: string[]
  }
): Promise<void> {
  const sampleResolved = path.resolve(samplePath)
  const sampleSidecarRoot = path.dirname(sampleResolved)
  const sampleRealPath = await realpathOrResolved(sampleResolved)
  const allowedRoots = [await realpathOrResolved(sampleSidecarRoot)]
  const lexicalAllowedRoots = [sampleSidecarRoot, ...allowedRoots]
  const allowedRootSummary = formatAllowedRoots(allowedRoots)

  for (const sidecarPath of sidecarPaths) {
    const resolved = path.resolve(sampleSidecarRoot, sidecarPath)
    if (!lexicalAllowedRoots.some((root) => isPathWithinRoot(resolved, root))) {
      state.warnings.push(
        `Rejected sidecar ${sidecarPath}: path escapes allowed sample sidecar root ${allowedRootSummary}.`
      )
      continue
    }

    let realResolved: string
    try {
      realResolved = await fs.realpath(resolved)
    } catch (err) {
      state.warnings.push(`Skipped sidecar ${sidecarPath}: ${(err as Error).message}`)
      continue
    }

    if (!allowedRoots.some((root) => isPathWithinRoot(realResolved, root))) {
      state.warnings.push(
        `Rejected sidecar ${sidecarPath}: real path escapes allowed sample sidecar root ${allowedRootSummary}.`
      )
      continue
    }

    if (realResolved === sampleRealPath) {
      continue
    }
    const seenKey = normalizeContainmentPath(realResolved)
    if (state.seen.has(seenKey)) {
      continue
    }
    if (state.sidecars.length >= state.maxSidecars) {
      state.warnings.push(
        `Skipped sidecar ${sidecarPath}: max sidecar count ${state.maxSidecars} reached.`
      )
      continue
    }

    try {
      const stat = await fs.stat(realResolved)
      if (!stat.isFile()) {
        state.warnings.push(`Skipped sidecar ${sidecarPath}: not a file.`)
        continue
      }
      if (state.totalBytes + stat.size > state.maxTotalBytes) {
        state.warnings.push(`Skipped sidecar ${sidecarPath}: sidecar byte budget exceeded.`)
        continue
      }
      state.seen.add(seenKey)
      state.totalBytes += stat.size
      state.sidecars.push({
        path: realResolved,
        name: path.basename(realResolved),
        size: stat.size,
        source: 'explicit',
      })
    } catch (err) {
      state.warnings.push(`Skipped sidecar ${sidecarPath}: ${(err as Error).message}`)
    }
  }
}

async function collectAutoSidecars(
  samplePath: string,
  allowedExtensions: Set<string>,
  state: {
    seen: Set<string>
    totalBytes: number
    maxSidecars: number
    maxTotalBytes: number
    sidecars: RuntimeSidecarUpload[]
    warnings: string[]
  }
): Promise<void> {
  const sampleResolved = path.resolve(samplePath)
  const sampleDir = path.dirname(sampleResolved)
  let entries: Dirent[]
  try {
    entries = await fs.readdir(sampleDir, { withFileTypes: true })
  } catch (err) {
    state.warnings.push(`Auto sidecar scan skipped: ${(err as Error).message}`)
    return
  }

  for (const entry of entries) {
    if (!entry.isFile()) {
      continue
    }
    const candidate = path.join(sampleDir, entry.name)
    const resolved = path.resolve(candidate)
    if (resolved === sampleResolved) {
      continue
    }
    if (!allowedExtensions.has(path.extname(entry.name).toLowerCase())) {
      continue
    }
    const seenKey = normalizeContainmentPath(resolved)
    if (state.seen.has(seenKey)) {
      continue
    }
    if (state.sidecars.length >= state.maxSidecars) {
      state.warnings.push(
        `Auto sidecar scan stopped: max sidecar count ${state.maxSidecars} reached.`
      )
      return
    }

    try {
      const stat = await fs.stat(resolved)
      if (!stat.isFile()) {
        continue
      }
      if (state.totalBytes + stat.size > state.maxTotalBytes) {
        state.warnings.push(`Skipped auto sidecar ${entry.name}: sidecar byte budget exceeded.`)
        continue
      }
      state.seen.add(seenKey)
      state.totalBytes += stat.size
      state.sidecars.push({
        path: resolved,
        name: entry.name,
        size: stat.size,
        source: 'auto',
      })
    } catch (err) {
      state.warnings.push(`Skipped auto sidecar ${entry.name}: ${(err as Error).message}`)
    }
  }
}

export async function resolveRuntimeSidecarUploads(
  samplePath: string,
  options: RuntimeSidecarResolveOptions = {}
): Promise<RuntimeSidecarResolveResult> {
  const maxSidecars = Math.max(0, Math.min(options.maxSidecars ?? DEFAULT_MAX_SIDECARS, 256))
  const maxTotalBytes = Math.max(
    0,
    Math.min(options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES, 1024 * 1024 * 1024)
  )
  const state = {
    seen: new Set<string>(),
    totalBytes: 0,
    maxSidecars,
    maxTotalBytes,
    sidecars: [] as RuntimeSidecarUpload[],
    warnings: [] as string[],
  }

  await collectExplicitSidecars(
    samplePath,
    normalizeExplicitSidecarPaths(options.sidecarPaths),
    state
  )

  if (options.autoStageSidecars && state.sidecars.length < maxSidecars) {
    await collectAutoSidecars(samplePath, getAllowedExtensions(options.allowedExtensions), state)
  }

  return {
    sidecars: state.sidecars,
    warnings: state.warnings,
  }
}
