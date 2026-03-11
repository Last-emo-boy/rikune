/**
 * Unit tests for Cache Manager
 * Tests cache key generation, argument normalization, and three-tier caching
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { generateCacheKey, normalizeArgs, CacheManager } from '../../src/cache-manager.js'
import { DatabaseManager } from '../../src/database.js'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import fc from 'fast-check'

describe('Cache Manager', () => {
  describe('generateCacheKey', () => {
    test('should generate consistent cache keys for identical parameters', () => {
      const params = {
        sampleSha256: 'abc123def456',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { fast: true, extra: 'value' }
      }

      const key1 = generateCacheKey(params)
      const key2 = generateCacheKey(params)

      expect(key1).toBe(key2)
      expect(key1).toMatch(/^cache:[a-f0-9]{64}$/)
    })

    test('should generate same key regardless of argument order', () => {
      const params1 = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { fast: true, extra: 'value', another: 'param' }
      }

      const params2 = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { another: 'param', extra: 'value', fast: true }
      }

      const key1 = generateCacheKey(params1)
      const key2 = generateCacheKey(params2)

      expect(key1).toBe(key2)
    })

    test('should generate different keys for different sample SHA256', () => {
      const params1 = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { fast: true }
      }

      const params2 = {
        sampleSha256: 'def456',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { fast: true }
      }

      const key1 = generateCacheKey(params1)
      const key2 = generateCacheKey(params2)

      expect(key1).not.toBe(key2)
    })

    test('should generate different keys for different tool names', () => {
      const params1 = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { fast: true }
      }

      const params2 = {
        sampleSha256: 'abc123',
        toolName: 'strings.extract',
        toolVersion: '1.0.0',
        args: { fast: true }
      }

      const key1 = generateCacheKey(params1)
      const key2 = generateCacheKey(params2)

      expect(key1).not.toBe(key2)
    })

    test('should generate different keys for different tool versions', () => {
      const params1 = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { fast: true }
      }

      const params2 = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '2.0.0',
        args: { fast: true }
      }

      const key1 = generateCacheKey(params1)
      const key2 = generateCacheKey(params2)

      expect(key1).not.toBe(key2)
    })

    test('should generate different keys for different arguments', () => {
      const params1 = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { fast: true }
      }

      const params2 = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: { fast: false }
      }

      const key1 = generateCacheKey(params1)
      const key2 = generateCacheKey(params2)

      expect(key1).not.toBe(key2)
    })

    test('should include ruleset version when provided', () => {
      const params1 = {
        sampleSha256: 'abc123',
        toolName: 'yara.scan',
        toolVersion: '1.0.0',
        args: { rule_set: 'malware' },
        rulesetVersion: 'v1.0'
      }

      const params2 = {
        sampleSha256: 'abc123',
        toolName: 'yara.scan',
        toolVersion: '1.0.0',
        args: { rule_set: 'malware' },
        rulesetVersion: 'v2.0'
      }

      const key1 = generateCacheKey(params1)
      const key2 = generateCacheKey(params2)

      expect(key1).not.toBe(key2)
    })

    test('should handle empty arguments', () => {
      const params = {
        sampleSha256: 'abc123',
        toolName: 'pe.fingerprint',
        toolVersion: '1.0.0',
        args: {}
      }

      const key = generateCacheKey(params)

      expect(key).toMatch(/^cache:[a-f0-9]{64}$/)
    })

    test('should handle nested objects in arguments', () => {
      const params1 = {
        sampleSha256: 'abc123',
        toolName: 'test.tool',
        toolVersion: '1.0.0',
        args: {
          config: {
            timeout: 30,
            retries: 3
          }
        }
      }

      const params2 = {
        sampleSha256: 'abc123',
        toolName: 'test.tool',
        toolVersion: '1.0.0',
        args: {
          config: {
            retries: 3,
            timeout: 30
          }
        }
      }

      const key1 = generateCacheKey(params1)
      const key2 = generateCacheKey(params2)

      // Should be same despite different order in nested object
      expect(key1).toBe(key2)
    })
  })

  describe('normalizeArgs', () => {
    test('should sort object keys', () => {
      const args = {
        zebra: 1,
        apple: 2,
        middle: 3
      }

      const normalized = normalizeArgs(args)
      const keys = Object.keys(normalized)

      expect(keys).toEqual(['apple', 'middle', 'zebra'])
    })

    test('should remove null values', () => {
      const args = {
        keep: 'value',
        remove: null
      }

      const normalized = normalizeArgs(args)

      expect(normalized).toEqual({ keep: 'value' })
      expect('remove' in normalized).toBe(false)
    })

    test('should remove undefined values', () => {
      const args = {
        keep: 'value',
        remove: undefined
      }

      const normalized = normalizeArgs(args)

      expect(normalized).toEqual({ keep: 'value' })
      expect('remove' in normalized).toBe(false)
    })

    test('should recursively normalize nested objects', () => {
      const args = {
        outer: {
          zebra: 1,
          apple: 2,
          nested: {
            z: 'last',
            a: 'first'
          }
        }
      }

      const normalized = normalizeArgs(args)

      expect(Object.keys(normalized.outer as Record<string, unknown>)).toEqual([
        'apple',
        'nested',
        'zebra'
      ])
      expect(
        Object.keys((normalized.outer as Record<string, unknown>).nested as Record<string, unknown>)
      ).toEqual(['a', 'z'])
    })

    test('should preserve arrays as-is', () => {
      const args = {
        items: [3, 1, 2],
        config: {
          values: ['z', 'a', 'm']
        }
      }

      const normalized = normalizeArgs(args)

      expect(normalized.items).toEqual([3, 1, 2])
      expect((normalized.config as Record<string, unknown>).values).toEqual(['z', 'a', 'm'])
    })

    test('should handle empty objects', () => {
      const args = {}

      const normalized = normalizeArgs(args)

      expect(normalized).toEqual({})
    })

    test('should handle null input', () => {
      const normalized = normalizeArgs(null as unknown as Record<string, unknown>)

      expect(normalized).toEqual({})
    })

    test('should handle undefined input', () => {
      const normalized = normalizeArgs(undefined as unknown as Record<string, unknown>)

      expect(normalized).toEqual({})
    })

    test('should preserve boolean values', () => {
      const args = {
        enabled: true,
        disabled: false
      }

      const normalized = normalizeArgs(args)

      expect(normalized).toEqual({
        disabled: false,
        enabled: true
      })
    })

    test('should preserve number values including zero', () => {
      const args = {
        count: 0,
        timeout: 30,
        negative: -1
      }

      const normalized = normalizeArgs(args)

      expect(normalized).toEqual({
        count: 0,
        negative: -1,
        timeout: 30
      })
    })

    test('should preserve empty strings', () => {
      const args = {
        empty: '',
        filled: 'value'
      }

      const normalized = normalizeArgs(args)

      expect(normalized).toEqual({
        empty: '',
        filled: 'value'
      })
    })

    test('should handle complex nested structures', () => {
      const args = {
        z_last: 'value',
        a_first: 'value',
        nested: {
          z_nested: 1,
          a_nested: 2,
          deep: {
            z_deep: true,
            a_deep: false,
            remove_me: null
          }
        },
        array: [{ z: 1 }, { a: 2 }],
        remove: undefined
      }

      const normalized = normalizeArgs(args)

      // Check top-level keys are sorted
      expect(Object.keys(normalized)).toEqual(['a_first', 'array', 'nested', 'z_last'])

      // Check nested object keys are sorted
      const nested = normalized.nested as Record<string, unknown>
      expect(Object.keys(nested)).toEqual(['a_nested', 'deep', 'z_nested'])

      // Check deep nested object keys are sorted and null removed
      const deep = nested.deep as Record<string, unknown>
      expect(Object.keys(deep)).toEqual(['a_deep', 'z_deep'])
      expect('remove_me' in deep).toBe(false)

      // Check arrays are preserved
      expect(normalized.array).toEqual([{ z: 1 }, { a: 2 }])

      // Check undefined removed
      expect('remove' in normalized).toBe(false)
    })
  })

  describe('CacheManager - Three-Tier Architecture', () => {
    let cacheManager: CacheManager
    let tempDir: string
    let dbPath: string
    let db: DatabaseManager

    beforeEach(async () => {
      // Create temporary directory for testing
      tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cache-test-'))
      dbPath = path.join(tempDir, 'test.db')
      
      // Create database
      db = new DatabaseManager(dbPath)
      
      // Create cache manager
      const cacheDir = path.join(tempDir, 'cache')
      await fs.mkdir(cacheDir, { recursive: true })
      cacheManager = new CacheManager(cacheDir, db)
    })

    afterEach(async () => {
      // Clean up
      db.close()
      await fs.rm(tempDir, { recursive: true, force: true })
    })

    test('should store and retrieve from memory cache (L1)', async () => {
      const key = 'cache:test123'
      const data = { result: 'test data' }

      await cacheManager.setCachedResult(key, data)
      const retrieved = await cacheManager.getCachedResult(key)

      expect(retrieved).toEqual(data)
    })

    test('should expose cache hit metadata for memory tier', async () => {
      const key = 'cache:meta-memory'
      const data = { result: 'memory hit' }

      await cacheManager.setCachedResult(key, data)
      const lookup = await cacheManager.getCachedResultWithMetadata(key)

      expect(lookup?.data).toEqual(data)
      expect(lookup?.metadata.tier).toBe('memory')
      expect(lookup?.metadata.key).toBe(key)
      expect(lookup?.metadata.fetchedAt).toBeDefined()
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

    test('should expose cache hit metadata for filesystem tier', async () => {
      const key = 'cache:meta-fs'
      const data = { result: 'filesystem hit' }

      await cacheManager.setCachedResult(key, data)
      cacheManager.clearAll()

      const lookup = await cacheManager.getCachedResultWithMetadata(key)

      expect(lookup?.data).toEqual(data)
      expect(lookup?.metadata.tier).toBe('filesystem')
      expect(lookup?.metadata.createdAt).toBeDefined()
      expect(lookup?.metadata.fetchedAt).toBeDefined()
    })

    test('should retrieve from database cache (L3) when not in L1 or L2', async () => {
      const key = 'cache:test789'
      const data = { result: 'db cache data' }

      // Set in cache
      await cacheManager.setCachedResult(key, data)

      // Clear memory cache
      cacheManager.clearAll()

      // Remove from file system cache
      const cacheDir = path.join(tempDir, 'cache')
      await fs.rm(cacheDir, { recursive: true, force: true })
      await fs.mkdir(cacheDir, { recursive: true })

      // Should retrieve from L3 and populate L1 and L2
      const retrieved = await cacheManager.getCachedResult(key)
      expect(retrieved).toEqual(data)
    })

    test('should expose cache hit metadata for database tier', async () => {
      const key = 'cache:meta-db'
      const data = { result: 'database hit' }

      await cacheManager.setCachedResult(key, data)
      cacheManager.clearAll()

      const cacheDir = path.join(tempDir, 'cache')
      await fs.rm(cacheDir, { recursive: true, force: true })
      await fs.mkdir(cacheDir, { recursive: true })

      const lookup = await cacheManager.getCachedResultWithMetadata(key)

      expect(lookup?.data).toEqual(data)
      expect(lookup?.metadata.tier).toBe('database')
      expect(lookup?.metadata.createdAt).toBeDefined()
      expect(lookup?.metadata.fetchedAt).toBeDefined()
    })

    test('should return null for non-existent cache key', async () => {
      const retrieved = await cacheManager.getCachedResult('cache:nonexistent')
      expect(retrieved).toBeNull()
    })

    test('should handle cache expiration', async () => {
      const key = 'cache:expire123'
      const data = { result: 'expiring data' }

      // Set with 1ms TTL
      await cacheManager.setCachedResult(key, data, 1)

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10))

      // Clear memory cache to force database lookup
      cacheManager.clearAll()

      // Should return null (expired)
      const retrieved = await cacheManager.getCachedResult(key)
      expect(retrieved).toBeNull()
    })

    test('should store in all three tiers', async () => {
      const key = 'cache:alltiers'
      const data = { result: 'all tiers data' }

      await cacheManager.setCachedResult(key, data)

      // Verify in database
      const dbResult = await db.getCachedResult(key)
      expect(dbResult?.data).toEqual(data)

      // Verify in file system (by clearing memory and retrieving)
      cacheManager.clearAll()
      const fsResult = await cacheManager.getCachedResult(key)
      expect(fsResult).toEqual(data)
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

    test('should work without database (L1 and L2 only)', async () => {
      const cacheDir = path.join(tempDir, 'cache-no-db')
      await fs.mkdir(cacheDir, { recursive: true })
      const cacheManagerNoDb = new CacheManager(cacheDir)

      const key = 'cache:nodb'
      const data = { result: 'no db data' }

      await cacheManagerNoDb.setCachedResult(key, data)
      const retrieved = await cacheManagerNoDb.getCachedResult(key)

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

    test('should prewarm cache from database', async () => {
      // Store some cache entries
      const entries = Array.from({ length: 5 }, (_, i) => ({
        key: `cache:prewarm${i}`,
        data: { index: i }
      }))

      for (const entry of entries) {
        await cacheManager.setCachedResult(entry.key, entry.data)
      }

      // Clear memory cache
      cacheManager.clearAll()

      // Prewarm cache
      const prewarmedCount = await cacheManager.prewarmCache(10)

      // Should have prewarmed all entries
      expect(prewarmedCount).toBe(5)

      // Verify entries are in memory cache (fast lookup)
      for (const entry of entries) {
        const retrieved = await cacheManager.getCachedResult(entry.key)
        expect(retrieved).toEqual(entry.data)
      }
    })

    test('should prewarm sample-specific cache', async () => {
      const sampleSha256 = 'abc123def456'
      
      // Store cache entries for the sample
      const entries = [
        {
          key: generateCacheKey({
            sampleSha256,
            toolName: 'pe.fingerprint',
            toolVersion: '1.0.0',
            args: {}
          }),
          data: { result: 'fingerprint' }
        },
        {
          key: generateCacheKey({
            sampleSha256,
            toolName: 'strings.extract',
            toolVersion: '1.0.0',
            args: {}
          }),
          data: { result: 'strings' }
        }
      ]

      for (const entry of entries) {
        await cacheManager.setCachedResult(entry.key, entry.data, undefined, sampleSha256)
      }

      // Clear memory cache
      cacheManager.clearAll()

      // Prewarm sample cache
      const prewarmedCount = await cacheManager.prewarmSampleCache(sampleSha256)

      // Should have prewarmed sample entries
      expect(prewarmedCount).toBeGreaterThan(0)

      // Verify entries are in memory cache
      for (const entry of entries) {
        const retrieved = await cacheManager.getCachedResult(entry.key)
        expect(retrieved).toEqual(entry.data)
      }
    })

    test('should skip expired entries during prewarming', async () => {
      // Store an expired entry
      const expiredKey = 'cache:expired'
      await cacheManager.setCachedResult(expiredKey, { result: 'expired' }, 1)

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10))

      // Store a valid entry
      const validKey = 'cache:valid'
      await cacheManager.setCachedResult(validKey, { result: 'valid' })

      // Clear memory cache
      cacheManager.clearAll()

      // Prewarm cache
      const prewarmedCount = await cacheManager.prewarmCache(10)

      // Should only prewarm valid entry
      expect(prewarmedCount).toBe(1)

      // Expired entry should not be in cache
      const expiredResult = await cacheManager.getCachedResult(expiredKey)
      expect(expiredResult).toBeNull()

      // Valid entry should be in cache
      const validResult = await cacheManager.getCachedResult(validKey)
      expect(validResult).toEqual({ result: 'valid' })
    })

    test('should not prewarm if already in progress', async () => {
      // Start prewarming
      const prewarm1 = cacheManager.prewarmCache(10)

      // Try to prewarm again immediately
      const prewarm2 = cacheManager.prewarmCache(10)

      const [_count1, count2] = await Promise.all([prewarm1, prewarm2])

      // Second prewarm should return 0 (already in progress)
      expect(count2).toBe(0)
    })
  })

  /**
   * Property-Based Tests for Cache Consistency

  /**
   * Property-Based Tests for Cache Consistency
   * 
   * **Validates: Requirements 20.1, 20.2**
   * **Property 2: Cache Consistency**
   * 
   * These tests verify that:
   * 1. Cache keys are deterministic (same inputs always produce same key)
   * 2. Different parameters produce different keys
   * 3. Cache invalidation works correctly when tool versions change
   */
  describe('Property-Based Tests - Cache Consistency', () => {
    // Custom generator for SHA256 hex strings (64 hex characters)
    const sha256Gen = fc.string({ minLength: 64, maxLength: 64 }).map(s => 
      s.split('').map(c => '0123456789abcdef'[c.charCodeAt(0) % 16]).join('')
    )

    /**
     * Property: Cache keys must be deterministic
     * 
     * For any valid cache key parameters, generating the key multiple times
     * should always produce the same result.
     */
    test('Property: cache keys are deterministic', () => {
      fc.assert(
        fc.property(
          sha256Gen,
          fc.constantFrom('pe.fingerprint', 'strings.extract', 'yara.scan'),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.dictionary(fc.string(), fc.oneof(fc.boolean(), fc.integer(), fc.string())),
          (sampleSha256: string, toolName: string, toolVersion: string, args: Record<string, unknown>) => {
            const params = { sampleSha256, toolName, toolVersion, args }
            const key1 = generateCacheKey(params)
            const key2 = generateCacheKey(params)
            
            // Same parameters should always produce the same key
            expect(key1).toBe(key2)
            
            // Key should have correct format
            expect(key1).toMatch(/^cache:[a-f0-9]{64}$/)
            
            return key1 === key2
          }
        ),
        { numRuns: 100 }
      )
    })

    /**
     * Property: Different arguments produce different cache keys
     * 
     * When any parameter changes (sample, tool, version, or args),
     * the cache key must be different to prevent cache collisions.
     */
    test('Property: different arguments produce different keys', () => {
      fc.assert(
        fc.property(
          sha256Gen,
          fc.constantFrom('pe.fingerprint', 'strings.extract', 'yara.scan'),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.record({
            param1: fc.boolean(),
            param2: fc.integer({ min: 0, max: 100 })
          }),
          fc.record({
            param1: fc.boolean(),
            param2: fc.integer({ min: 0, max: 100 })
          }),
          (sampleSha256: string, toolName: string, toolVersion: string, args1: Record<string, unknown>, args2: Record<string, unknown>) => {
            // Precondition: args must be different
            fc.pre(
              JSON.stringify(args1) !== JSON.stringify(args2)
            )

            const key1 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion,
              args: args1
            })

            const key2 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion,
              args: args2
            })

            // Different arguments should produce different keys
            return key1 !== key2
          }
        ),
        { numRuns: 100 }
      )
    })

    /**
     * Property: Argument order does not affect cache key
     * 
     * Cache keys should be deterministic regardless of the order
     * in which arguments are provided (normalization requirement).
     */
    test('Property: argument order does not affect cache key', () => {
      fc.assert(
        fc.property(
          sha256Gen,
          fc.constantFrom('pe.fingerprint', 'strings.extract'),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.array(
            fc.tuple(
              fc.string({ minLength: 1, maxLength: 10 }),
              fc.oneof(fc.boolean(), fc.integer(), fc.string())
            ),
            { minLength: 2, maxLength: 5 }
          ),
          (sampleSha256: string, toolName: string, toolVersion: string, argPairs: Array<[string, unknown]>) => {
            // Exclude duplicate keys so both objects represent the same argument set.
            fc.pre(new Set(argPairs.map(([key]) => key)).size === argPairs.length)

            // Create two argument objects with different key orders
            const args1: Record<string, unknown> = {}
            const args2: Record<string, unknown> = {}

            // Add in original order
            argPairs.forEach(([key, value]) => {
              args1[key] = value
            })

            // Add in reverse order
            const reversedPairs = [...argPairs].reverse()
            reversedPairs.forEach(([key, value]) => {
              args2[key] = value
            })

            const key1 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion,
              args: args1
            })

            const key2 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion,
              args: args2
            })

            // Same arguments in different order should produce same key
            return key1 === key2
          }
        ),
        { numRuns: 100 }
      )
    })

    /**
     * Property: Tool version changes invalidate cache
     * 
     * When the tool version changes, the cache key must be different
     * to ensure old cached results are not used with new tool versions.
     */
    test('Property: tool version changes produce different keys', () => {
      fc.assert(
        fc.property(
          sha256Gen,
          fc.constantFrom('pe.fingerprint', 'strings.extract', 'yara.scan'),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.dictionary(fc.string(), fc.oneof(fc.boolean(), fc.integer(), fc.string())),
          (sampleSha256: string, toolName: string, version1: string, version2: string, args: Record<string, unknown>) => {
            // Precondition: versions must be different
            fc.pre(version1 !== version2)

            const key1 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion: version1,
              args
            })

            const key2 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion: version2,
              args
            })

            // Different versions should produce different keys
            return key1 !== key2
          }
        ),
        { numRuns: 100 }
      )
    })

    /**
     * Property: Ruleset version changes invalidate cache
     * 
     * For tools that use rulesets (like YARA), changing the ruleset
     * version should produce a different cache key.
     */
    test('Property: ruleset version changes produce different keys', () => {
      fc.assert(
        fc.property(
          sha256Gen,
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.dictionary(fc.string(), fc.string()),
          (sampleSha256: string, rulesetV1: string, rulesetV2: string, args: Record<string, unknown>) => {
            // Precondition: ruleset versions must be different
            fc.pre(rulesetV1 !== rulesetV2)

            const key1 = generateCacheKey({
              sampleSha256,
              toolName: 'yara.scan',
              toolVersion: '1.0.0',
              args,
              rulesetVersion: rulesetV1
            })

            const key2 = generateCacheKey({
              sampleSha256,
              toolName: 'yara.scan',
              toolVersion: '1.0.0',
              args,
              rulesetVersion: rulesetV2
            })

            // Different ruleset versions should produce different keys
            return key1 !== key2
          }
        ),
        { numRuns: 100 }
      )
    })

    /**
     * Property: Null and undefined values are normalized consistently
     * 
     * Null and undefined values in arguments should be removed during
     * normalization, ensuring consistent cache keys.
     */
    test('Property: null and undefined values are normalized', () => {
      fc.assert(
        fc.property(
          sha256Gen,
          fc.constantFrom('pe.fingerprint', 'strings.extract'),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.string(),
          (sampleSha256: string, toolName: string, toolVersion: string, validParam: string) => {
            // Create args with null/undefined
            const argsWithNulls = {
              validParam,
              nullParam: null,
              undefinedParam: undefined
            }

            // Create args without null/undefined
            const argsClean = {
              validParam
            }

            const key1 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion,
              args: argsWithNulls
            })

            const key2 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion,
              args: argsClean
            })

            // Keys should be the same (null/undefined removed)
            return key1 === key2
          }
        ),
        { numRuns: 100 }
      )
    })

    /**
     * Property: Nested object normalization is consistent
     * 
     * Nested objects in arguments should be normalized recursively,
     * with keys sorted at all levels.
     */
    test('Property: nested objects are normalized consistently', () => {
      fc.assert(
        fc.property(
          sha256Gen,
          fc.constantFrom('pe.fingerprint', 'strings.extract'),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.string(),
          fc.integer(),
          fc.boolean(),
          (sampleSha256: string, toolName: string, toolVersion: string, inner1: string, inner2: number, outer2: boolean) => {
            // Create nested args with one key order
            const nestedArgs = {
              outer1: {
                inner1,
                inner2
              },
              outer2
            }

            // Create same structure with different key order
            const reorderedArgs = {
              outer2,
              outer1: {
                inner2,
                inner1
              }
            }

            const key1 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion,
              args: nestedArgs
            })

            const key2 = generateCacheKey({
              sampleSha256,
              toolName,
              toolVersion,
              args: reorderedArgs
            })

            // Keys should be the same (normalized)
            return key1 === key2
          }
        ),
        { numRuns: 100 }
      )
    })

    /**
     * Property: Sample SHA256 changes produce different keys
     * 
     * Different samples (identified by SHA256) should always produce
     * different cache keys, even with identical tool and arguments.
     */
    test('Property: different samples produce different keys', () => {
      fc.assert(
        fc.property(
          sha256Gen,
          sha256Gen,
          fc.constantFrom('pe.fingerprint', 'strings.extract'),
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.dictionary(fc.string(), fc.string()),
          (sha256_1: string, sha256_2: string, toolName: string, toolVersion: string, args: Record<string, unknown>) => {
            // Precondition: samples must be different
            fc.pre(sha256_1 !== sha256_2)

            const key1 = generateCacheKey({
              sampleSha256: sha256_1,
              toolName,
              toolVersion,
              args
            })

            const key2 = generateCacheKey({
              sampleSha256: sha256_2,
              toolName,
              toolVersion,
              args
            })

            // Different samples should produce different keys
            return key1 !== key2
          }
        ),
        { numRuns: 100 }
      )
    })
  })
})
