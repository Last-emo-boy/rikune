import fs from 'fs'
import path from 'path'
import type { Config } from './config.js'

export interface ResolvedStaticPathStatus {
  available: boolean
  path: string | null
  source: 'config' | 'env' | 'path' | null
  error?: string | null
}

function normalizeExecutableCandidates(rawValue: string): string[] {
  const trimmed = rawValue.trim()
  if (!trimmed) {
    return []
  }

  const candidates = [trimmed]
  const lower = trimmed.toLowerCase()
  if (fs.existsSync(trimmed) && fs.statSync(trimmed).isDirectory()) {
    candidates.push(
      path.join(trimmed, 'diec.exe'),
      path.join(trimmed, 'diec'),
      path.join(trimmed, 'die.exe'),
      path.join(trimmed, 'die')
    )
  } else if (!/[\\/]/.test(trimmed) && !lower.endsWith('.exe')) {
    candidates.push(`${trimmed}.exe`)
  }

  return Array.from(new Set(candidates))
}

function resolveFromPath(candidates: string[]): string | null {
  const pathEnv = process.env.PATH || process.env.Path || ''
  const segments = pathEnv.split(path.delimiter).filter((item) => item.trim().length > 0)
  for (const name of candidates) {
    for (const segment of segments) {
      const absolute = path.join(segment, name)
      if (fs.existsSync(absolute)) {
        return absolute
      }
    }
  }
  return null
}

export function resolveCapaRulesPath(config: Config): ResolvedStaticPathStatus {
  const envValue = process.env.CAPA_RULES_PATH?.trim()
  if (envValue) {
    if (fs.existsSync(envValue)) {
      return { available: true, path: envValue, source: 'env', error: null }
    }
    return {
      available: false,
      path: envValue,
      source: 'env',
      error: `Configured CAPA_RULES_PATH does not exist: ${envValue}`,
    }
  }

  const configValue = config.workers.static.capaRulesPath?.trim()
  if (configValue) {
    if (fs.existsSync(configValue)) {
      return { available: true, path: configValue, source: 'config', error: null }
    }
    return {
      available: false,
      path: configValue,
      source: 'config',
      error: `Configured capa rules path does not exist: ${configValue}`,
    }
  }

  return {
    available: false,
    path: null,
    source: null,
    error: 'No capa rules path configured. Provide CAPA_RULES_PATH or workers.static.capaRulesPath.',
  }
}

export function resolveDetectItEasyExecutable(config: Config): ResolvedStaticPathStatus {
  const envValue = process.env.DIE_PATH?.trim()
  if (envValue) {
    for (const candidate of normalizeExecutableCandidates(envValue)) {
      if (fs.existsSync(candidate)) {
        return { available: true, path: candidate, source: 'env', error: null }
      }
    }
    return {
      available: false,
      path: envValue,
      source: 'env',
      error: `Configured DIE_PATH could not be resolved: ${envValue}`,
    }
  }

  const configValue = config.workers.static.diePath?.trim()
  if (configValue) {
    for (const candidate of normalizeExecutableCandidates(configValue)) {
      if (fs.existsSync(candidate)) {
        return { available: true, path: candidate, source: 'config', error: null }
      }
    }
    return {
      available: false,
      path: configValue,
      source: 'config',
      error: `Configured Detect It Easy path could not be resolved: ${configValue}`,
    }
  }

  const pathResolved = resolveFromPath(['diec.exe', 'diec', 'die.exe', 'die'])
  if (pathResolved) {
    return { available: true, path: pathResolved, source: 'path', error: null }
  }

  return {
    available: false,
    path: null,
    source: null,
    error: 'Detect It Easy CLI was not found via DIE_PATH, config, or PATH.',
  }
}

