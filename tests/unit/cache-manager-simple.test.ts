/**
 * Simple unit tests for Cache Manager (without database dependency)
 * Tests memory and filesystem caching layers
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { CacheManager } from '../../src/cache-manager.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'

describe('CacheManager - Simple Tests (L1 and L2 only)', () => {
  let cacheManager: CacheManager
  let tempDir: string

  beforeEach(async () => {
    // Create temporary directory for testing
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cache-test-'))
    
    // Create cache manager without database
    const cacheDir = path.join(tempDir, 'cache')
    await fs.mkdir(cacheDir, { recursive: true })
    cacheManager = new CacheManager(cacheDir)
  })

  afterEach(async () => {
    // Clean up
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test('should store and retrieve from memory cache (L1)', async () => {
    const key = 'cache:test123'
    const data = { result: 'test data' }

    await cacheManager.setCachedResult(key, data)
    const retrieved = await cacheManager.getCachedResult(key)

    expect(retrieved).toEqual(data)
  })

  test('should retrieve from file system cache (L2) when not in memory', async () => {
    const key = 'cache:test456'
    const data = { result: 'fs cache data' }

    // Set in cache
    await cacheManager.setCachedResult(key, data)

    // Clear memory cache to force L2 lookup
    cacheManager.clearAll()

    // Should retrieve from L2 and populate L1
    const retrieved = await cacheManager.getCachedResult(key)
    expect(retrieved).toEqual(data)
  })

  test('should return null for non-existent cache key', async () => {
    const retrieved = await cacheManager.getCachedResult('cache:nonexistent')
    expect(retrieved).toBeNull()
  })

  test('should handle complex data structures', async () => {
    const key = 'cache:complex'
    const data = {
      nested: {
        array: [1, 2, 3],
        object: { a: 'b' }
      },
      boolean: true,
      number: 42,
      string: 'test'
    }

    await cacheManager.setCachedResult(key, data)
    const retrieved = await cacheManager.getCachedResult(key)

    expect(retrieved).toEqual(data)
  })

  test('should handle null values in data', async () => {
    const key = 'cache:nulldata'
    const data = {
      nullValue: null,
      definedValue: 'test'
    }

    await cacheManager.setCachedResult(key, data)
    const retrieved = await cacheManager.getCachedResult(key)

    expect(retrieved).toEqual(data)
  })

  test('should handle concurrent cache operations', async () => {
    const operations = Array.from({ length: 10 }, (_, i) => ({
      key: `cache:concurrent${i}`,
      data: { index: i }
    }))

    // Set all concurrently
    await Promise.all(
      operations.map(op => cacheManager.setCachedResult(op.key, op.data))
    )

    // Get all concurrently
    const results = await Promise.all(
      operations.map(op => cacheManager.getCachedResult(op.key))
    )

    // Verify all results
    results.forEach((result, i) => {
      expect(result).toEqual({ index: i })
    })
  })

  test('should handle cache expiration in filesystem', async () => {
    const key = 'cache:expire123'
    const data = { result: 'expiring data' }

    // Set with 1ms TTL
    await cacheManager.setCachedResult(key, data, 1)

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 10))

    // Clear memory cache to force filesystem lookup
    cacheManager.clearAll()

    // Should return null (expired)
    const retrieved = await cacheManager.getCachedResult(key)
    expect(retrieved).toBeNull()
  })

  test('should create bucketed directories for filesystem cache', async () => {
    const key = 'cache:abcdef123456'
    const data = { result: 'bucketed data' }

    await cacheManager.setCachedResult(key, data)

    // Check that bucket directory was created (first 2 chars after "cache:")
    const bucketDir = path.join(tempDir, 'cache', 'ab')
    const exists = await fs.access(bucketDir).then(() => true).catch(() => false)
    expect(exists).toBe(true)
  })
})
