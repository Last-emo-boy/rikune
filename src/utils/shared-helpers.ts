/**
 * Shared utility functions used across multiple tools and workflows.
 */

import type { ArtifactRef } from '../types.js'

export function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

export function clamp(value: number, min = 0, max = 1): number {
  if (!Number.isFinite(value)) return min
  return Math.max(min, Math.min(max, value))
}

export function dedupe(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .filter((value): value is string => typeof value === 'string')
        .map((value) => value.trim())
        .filter((value) => value.length > 0)
    )
  )
}

export function dedupeStrings(values: Array<string | null | undefined>, limit?: number): string[] {
  const unique = Array.from(
    new Set(
      values
        .filter((value): value is string => typeof value === 'string')
        .map((value) => value.trim())
        .filter((value) => value.length > 0)
    )
  )
  return typeof limit === 'number' ? unique.slice(0, limit) : unique
}

export function sanitizePathSegment(value: string | undefined, fallback: string): string {
  const normalized = (value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 64) : fallback
}

export function matchesSessionTag(sessionTags: string[], selector?: string | null): boolean {
  if (!selector || !selector.trim()) {
    return false
  }
  const normalized = selector.trim()
  return sessionTags.some((tag) => tag === normalized)
}

export function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is string => typeof item === 'string')
}

export function collectArtifactRefs(result: { artifacts?: unknown[]; data?: unknown } | undefined): ArtifactRef[] {
  if (!result) {
    return []
  }
  const refs: ArtifactRef[] = []
  if (Array.isArray(result.artifacts)) {
    refs.push(...(result.artifacts.filter((item) => item && typeof item === 'object') as ArtifactRef[]))
  }
  const data = result.data && typeof result.data === 'object' ? (result.data as Record<string, unknown>) : {}
  if (data.artifact && typeof data.artifact === 'object') {
    refs.push(data.artifact as ArtifactRef)
  }
  if (Array.isArray(data.source_artifact_refs)) {
    refs.push(...(data.source_artifact_refs.filter((item) => item && typeof item === 'object') as ArtifactRef[]))
  }
  return refs
}

export function dedupeArtifactRefs(artifacts: ArtifactRef[]): ArtifactRef[] {
  const seen = new Set<string>()
  const output: ArtifactRef[] = []
  for (const artifact of artifacts) {
    const key = artifact.id || `${artifact.type}:${artifact.path}`
    if (!key || seen.has(key)) {
      continue
    }
    seen.add(key)
    output.push(artifact)
  }
  return output
}

export function escapeDot(text: string): string {
  return text.replace(/"/g, '\\"').replace(/\n/g, '\\n')
}

export function escapeMermaid(text: string): string {
  return text.replace(/"/g, "'").replace(/\n/g, ' ')
}

export function getPythonCommand(platform: NodeJS.Platform = process.platform): string {
  return platform === 'win32' ? 'python' : 'python3'
}

export function extractJsonCandidates(rawText: string): string[] {
  const candidates: string[] = []
  const trimmed = rawText.trim()
  if (trimmed.length > 0) {
    candidates.push(trimmed)
  }

  const fencedMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  if (fencedMatch?.[1]) {
    candidates.push(fencedMatch[1].trim())
  }

  const firstBrace = trimmed.indexOf('{')
  const lastBrace = trimmed.lastIndexOf('}')
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    candidates.push(trimmed.slice(firstBrace, lastBrace + 1))
  }

  const firstBracket = trimmed.indexOf('[')
  const lastBracket = trimmed.lastIndexOf(']')
  if (firstBracket >= 0 && lastBracket > firstBracket) {
    candidates.push(trimmed.slice(firstBracket, lastBracket + 1))
  }

  return Array.from(new Set(candidates.filter((item) => item.length > 0)))
}
