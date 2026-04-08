/**
 * Shared utility functions used across multiple tools and workflows.
 */

export function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

export function clamp(value: number, min: number, max: number): number {
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
