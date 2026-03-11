import type { CacheManager, CacheHitLookup, CacheHitMetadata } from '../cache-manager.js'

type CacheManagerWithMetadata = CacheManager & {
  getCachedResultWithMetadata?: (key: string) => Promise<CacheHitLookup | null>
}

export async function lookupCachedResult(
  cacheManager: CacheManager,
  cacheKey: string
): Promise<CacheHitLookup | null> {
  const manager = cacheManager as CacheManagerWithMetadata

  if (typeof manager.getCachedResultWithMetadata === 'function') {
    return manager.getCachedResultWithMetadata(cacheKey)
  }

  const data = await cacheManager.getCachedResult(cacheKey)
  if (data === null) {
    return null
  }

  return {
    data,
    metadata: {
      key: cacheKey,
      tier: 'unknown',
      fetchedAt: new Date().toISOString(),
    },
  }
}

export function formatCacheWarning(metadata: CacheHitMetadata): string {
  const parts = [
    `tier=${metadata.tier}`,
    `key=${metadata.key}`,
    `hit_at=${metadata.fetchedAt}`,
  ]

  if (metadata.createdAt) {
    parts.push(`created_at=${metadata.createdAt}`)
  }
  if (metadata.expiresAt) {
    parts.push(`expires_at=${metadata.expiresAt}`)
  }
  if (metadata.sampleSha256) {
    parts.push(`sample_sha256=${metadata.sampleSha256}`)
  }

  return `Cache details: ${parts.join(', ')}`
}

