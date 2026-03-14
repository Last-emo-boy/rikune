import fs from 'fs'
import path from 'path'
import { execFileSync } from 'child_process'
import { config, type Config } from './config.js'

export type ExecutableSource = 'config' | 'env' | 'path' | 'none'

export interface ExternalExecutableResolution {
  available: boolean
  source: ExecutableSource
  path: string | null
  version: string | null
  checked_candidates: string[]
  error: string | null
}

export interface CapaRulesResolution {
  available: boolean
  source: 'config' | 'env' | 'none'
  path: string | null
  error: string | null
}

export interface StaticBackendResolution {
  capa_cli: ExternalExecutableResolution
  capa_rules: CapaRulesResolution
  die: ExternalExecutableResolution
}

function pathExists(targetPath: string | null | undefined): targetPath is string {
  if (!targetPath || targetPath.trim().length === 0) {
    return false
  }
  try {
    fs.accessSync(targetPath, fs.constants.F_OK)
    return true
  } catch {
    return false
  }
}

function isExecutableFile(targetPath: string | null | undefined): targetPath is string {
  if (!pathExists(targetPath)) {
    return false
  }

  try {
    const stats = fs.statSync(targetPath)
    return stats.isFile()
  } catch {
    return false
  }
}

function uniquePreserve(values: string[]): string[] {
  const seen = new Set<string>()
  const output: string[] = []
  for (const value of values) {
    const normalized = value.trim()
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    output.push(normalized)
  }
  return output
}

function splitPathEntries(rawPath: string | undefined): string[] {
  return (rawPath || '')
    .split(path.delimiter)
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
}

function expandExecutableCandidates(baseName: string): string[] {
  const candidates = [baseName]
  if (process.platform === 'win32') {
    const lower = baseName.toLowerCase()
    if (!lower.endsWith('.exe') && !lower.endsWith('.bat') && !lower.endsWith('.cmd')) {
      candidates.push(`${baseName}.exe`, `${baseName}.bat`, `${baseName}.cmd`)
    }
  }
  return candidates
}

function findOnPath(candidateNames: string[]): string | null {
  const entries = splitPathEntries(process.env.PATH)
  for (const entry of entries) {
    for (const candidateName of candidateNames) {
      for (const expanded of expandExecutableCandidates(candidateName)) {
        const absolutePath = path.join(entry, expanded)
        if (isExecutableFile(absolutePath)) {
          return absolutePath
        }
      }
    }
  }
  return null
}

function probeVersion(binaryPath: string, versionArgSets: string[][]): string | null {
  for (const args of versionArgSets) {
    try {
      const output = execFileSync(binaryPath, args, {
        encoding: 'utf8',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      const line = output.split(/\r?\n/).map((item) => item.trim()).find((item) => item.length > 0)
      if (line) {
        return line
      }
    } catch (error) {
      const stderr = (error as { stderr?: string | Buffer | null }).stderr
      const text = typeof stderr === 'string' ? stderr : Buffer.isBuffer(stderr) ? stderr.toString('utf8') : ''
      const line = text.split(/\r?\n/).map((item) => item.trim()).find((item) => item.length > 0)
      if (line) {
        return line
      }
    }
  }
  return null
}

function resolveExecutable(options: {
  configuredPath?: string | null
  envPath?: string | null
  pathCandidates: string[]
  versionArgSets: string[][]
}): ExternalExecutableResolution {
  const checkedCandidates: string[] = []
  const configuredPath = options.configuredPath?.trim()
  if (configuredPath) {
    checkedCandidates.push(configuredPath)
    if (isExecutableFile(configuredPath)) {
      return {
        available: true,
        source: 'config',
        path: configuredPath,
        version: probeVersion(configuredPath, options.versionArgSets),
        checked_candidates: checkedCandidates,
        error: null,
      }
    }
    return {
      available: false,
      source: 'config',
      path: configuredPath,
      version: null,
      checked_candidates: checkedCandidates,
      error: 'Configured path does not exist or is not an executable file.',
    }
  }

  const envPath = options.envPath?.trim()
  if (envPath) {
    checkedCandidates.push(envPath)
    if (isExecutableFile(envPath)) {
      return {
        available: true,
        source: 'env',
        path: envPath,
        version: probeVersion(envPath, options.versionArgSets),
        checked_candidates: checkedCandidates,
        error: null,
      }
    }
    return {
      available: false,
      source: 'env',
      path: envPath,
      version: null,
      checked_candidates: checkedCandidates,
      error: 'Environment-provided path does not exist or is not an executable file.',
    }
  }

  const discovered = findOnPath(options.pathCandidates)
  checkedCandidates.push(...options.pathCandidates)
  if (discovered) {
    return {
      available: true,
      source: 'path',
      path: discovered,
      version: probeVersion(discovered, options.versionArgSets),
      checked_candidates: uniquePreserve(checkedCandidates),
      error: null,
    }
  }

  return {
    available: false,
    source: 'none',
    path: null,
    version: null,
    checked_candidates: uniquePreserve(checkedCandidates),
    error: 'Executable was not found in config, environment variables, or PATH.',
  }
}

export function resolveCapaRulesPath(currentConfig: Config = config): CapaRulesResolution {
  const configuredPath = currentConfig.workers.static.capaRulesPath?.trim()
  if (configuredPath) {
    if (pathExists(configuredPath)) {
      return {
        available: true,
        source: 'config',
        path: configuredPath,
        error: null,
      }
    }
    return {
      available: false,
      source: 'config',
      path: configuredPath,
      error: 'Configured capa rules path does not exist.',
    }
  }

  const envPath = process.env.CAPA_RULES_PATH?.trim()
  if (envPath) {
    if (pathExists(envPath)) {
      return {
        available: true,
        source: 'env',
        path: envPath,
        error: null,
      }
    }
    return {
      available: false,
      source: 'env',
      path: envPath,
      error: 'Environment-provided capa rules path does not exist.',
    }
  }

  return {
    available: false,
    source: 'none',
    path: null,
    error: 'No capa rules path was configured.',
  }
}

export function resolveCapaCli(currentConfig: Config = config): ExternalExecutableResolution {
  return resolveExecutable({
    configuredPath: currentConfig.workers.static.capaPath,
    envPath: process.env.CAPA_PATH,
    pathCandidates: ['capa'],
    versionArgSets: [['--version'], ['-v']],
  })
}

export function resolveDieCli(currentConfig: Config = config): ExternalExecutableResolution {
  return resolveExecutable({
    configuredPath: currentConfig.workers.static.diePath,
    envPath: process.env.DIE_PATH,
    pathCandidates: ['diec', 'die'],
    versionArgSets: [['--version'], ['-v'], ['-h']],
  })
}

export function resolveStaticBackends(currentConfig: Config = config): StaticBackendResolution {
  return {
    capa_cli: resolveCapaCli(currentConfig),
    capa_rules: resolveCapaRulesPath(currentConfig),
    die: resolveDieCli(currentConfig),
  }
}
