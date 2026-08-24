import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { DatabaseManager, type ContextWriteLease } from '../../src/database.js'
import { withContextWriteLease } from '../../src/persistence/context-write-lease.js'

describe('context write leases', () => {
  let tempRoot: string
  let databaseA: DatabaseManager
  let databaseB: DatabaseManager

  beforeEach(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-context-lease-'))
    const databasePath = path.join(tempRoot, 'rikune.db')
    databaseA = new DatabaseManager(databasePath)
    databaseB = new DatabaseManager(databasePath)
  })

  afterEach(async () => {
    databaseA.close()
    databaseB.close()
    await fs.rm(tempRoot, { recursive: true, force: true })
  })

  const lease = (
    ownerToken: string,
    heartbeatAt: string,
    lockKey = 'claim:sample-a'
  ): ContextWriteLease => ({
    lock_key: lockKey,
    owner_token: ownerToken,
    host_id: `host-${ownerToken}`,
    pid: 100,
    acquired_at: heartbeatAt,
    heartbeat_at: heartbeatAt,
  })

  test('creates the generic lease table and grants only one live owner', () => {
    const columns = databaseA.getDatabase().pragma('table_info(context_write_leases)') as Array<{
      name: string
    }>
    expect(columns.map((column) => column.name)).toEqual([
      'lock_key',
      'owner_token',
      'host_id',
      'pid',
      'acquired_at',
      'heartbeat_at',
    ])

    const now = '2026-07-15T08:00:00.000Z'
    expect(
      databaseA.tryAcquireContextWriteLease(lease('owner-a', now), '2026-07-15T07:55:00.000Z')
    ).toMatchObject({ acquired: true, takeover: false })
    expect(
      databaseB.tryAcquireContextWriteLease(lease('owner-b', now), '2026-07-15T07:55:00.000Z')
    ).toMatchObject({
      acquired: false,
      takeover: false,
      lease: { owner_token: 'owner-a' },
    })
  })

  test('allows exactly one CAS winner to take over an observed stale lease', () => {
    const oldHeartbeat = '2026-07-15T07:00:00.000Z'
    const staleBefore = '2026-07-15T07:55:00.000Z'
    const takeoverAt = '2026-07-15T08:00:00.000Z'
    expect(
      databaseA.tryAcquireContextWriteLease(
        lease('owner-stale', oldHeartbeat),
        '2026-07-15T06:55:00.000Z'
      ).acquired
    ).toBe(true)

    expect(
      databaseB.tryAcquireContextWriteLease(lease('owner-winner', takeoverAt), staleBefore)
    ).toMatchObject({ acquired: true, takeover: true })
    expect(
      databaseA.tryAcquireContextWriteLease(lease('owner-loser', takeoverAt), staleBefore)
    ).toMatchObject({
      acquired: false,
      takeover: false,
      lease: { owner_token: 'owner-winner' },
    })
  })

  test('heartbeat prevents takeover and stale owners cannot heartbeat or release a new owner', () => {
    const lockKey = 'case:sample-a:case-a'
    expect(
      databaseA.tryAcquireContextWriteLease(
        lease('owner-a', '2026-07-15T07:00:00.000Z', lockKey),
        '2026-07-15T06:55:00.000Z'
      ).acquired
    ).toBe(true)
    expect(
      databaseA.heartbeatContextWriteLease(lockKey, 'owner-a', '2026-07-15T08:00:00.000Z')
    ).toBe(true)
    expect(
      databaseB.tryAcquireContextWriteLease(
        lease('owner-b', '2026-07-15T08:01:00.000Z', lockKey),
        '2026-07-15T07:56:00.000Z'
      ).acquired
    ).toBe(false)

    databaseA.runSql(
      'UPDATE context_write_leases SET heartbeat_at = ? WHERE lock_key = ? AND owner_token = ?',
      ['2026-07-15T07:00:00.000Z', lockKey, 'owner-a']
    )
    expect(
      databaseB.tryAcquireContextWriteLease(
        lease('owner-b', '2026-07-15T08:01:00.000Z', lockKey),
        '2026-07-15T07:56:00.000Z'
      )
    ).toMatchObject({ acquired: true, takeover: true })
    expect(
      databaseA.heartbeatContextWriteLease(lockKey, 'owner-a', '2026-07-15T08:02:00.000Z')
    ).toBe(false)
    expect(databaseA.releaseContextWriteLease(lockKey, 'owner-a')).toBe(false)
    expect(databaseA.findContextWriteLease(lockKey)?.owner_token).toBe('owner-b')
    expect(databaseB.releaseContextWriteLease(lockKey, 'owner-b')).toBe(true)
  })

  test('the commit-boundary guard fails closed after CAS ownership loss', async () => {
    const lockKey = 'claim:guard-loss'
    await expect(
      withContextWriteLease({
        database: databaseA,
        lockKey,
        staleMs: 300_000,
        label: 'Claim Ledger',
        operation: async (guard) => {
          const staleHeartbeat = new Date(Date.now() - 600_000).toISOString()
          databaseB.runSql(
            'UPDATE context_write_leases SET heartbeat_at = ? WHERE lock_key = ? AND owner_token = ?',
            [staleHeartbeat, lockKey, guard.ownerToken]
          )
          const takeoverAt = new Date().toISOString()
          const takeover = databaseB.tryAcquireContextWriteLease(
            lease('owner-takeover', takeoverAt, lockKey),
            new Date(Date.now() - 300_000).toISOString()
          )
          expect(takeover).toMatchObject({ acquired: true, takeover: true })
          guard.assertOwned()
        },
      })
    ).rejects.toThrow(/lost its context write lease ownership/i)
    expect(databaseB.findContextWriteLease(lockKey)?.owner_token).toBe('owner-takeover')
    databaseB.releaseContextWriteLease(lockKey, 'owner-takeover')
  })

  test('atomically fences an Artifact insert when takeover occurs after the last assertion', async () => {
    const sampleSha256 = 'a'.repeat(64)
    const sampleId = `sha256:${sampleSha256}`
    const lockKey = 'claim:artifact-fence'
    const takeoverToken = 'owner-takeover'
    databaseA.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: sampleSha256,
      md5: null,
      size: 1,
      file_type: null,
      created_at: '2026-07-15T08:00:00.000Z',
      source: null,
    })

    await withContextWriteLease({
      database: databaseA,
      lockKey,
      staleMs: 300_000,
      label: 'Claim Ledger',
      operation: async (guard) => {
        guard.assertOwned()

        databaseB.runSql(
          'UPDATE context_write_leases SET heartbeat_at = ? WHERE lock_key = ? AND owner_token = ?',
          [new Date(Date.now() - 600_000).toISOString(), lockKey, guard.ownerToken]
        )
        const takeoverAt = new Date().toISOString()
        expect(
          databaseB.tryAcquireContextWriteLease(
            lease(takeoverToken, takeoverAt, lockKey),
            new Date(Date.now() - 300_000).toISOString()
          )
        ).toMatchObject({ acquired: true, takeover: true })

        expect(
          databaseA.insertArtifactIfContextLeaseOwned(
            {
              id: 'artifact-stale-owner',
              sample_id: sampleId,
              type: 'analysis_claim_set',
              path: 'reports/claims/stale.json',
              sha256: 'b'.repeat(64),
              mime: 'application/json',
              created_at: takeoverAt,
            },
            lockKey,
            guard.ownerToken
          )
        ).toBe(false)
        expect(databaseA.findArtifact('artifact-stale-owner')).toBeFalsy()

        expect(
          databaseB.insertArtifactIfContextLeaseOwned(
            {
              id: 'artifact-current-owner',
              sample_id: sampleId,
              type: 'analysis_claim_set',
              path: 'reports/claims/current.json',
              sha256: 'c'.repeat(64),
              mime: 'application/json',
              created_at: takeoverAt,
            },
            lockKey,
            takeoverToken
          )
        ).toBe(true)
      },
    })

    expect(databaseA.findArtifact('artifact-stale-owner')).toBeFalsy()
    expect(databaseA.findArtifact('artifact-current-owner')).not.toBeNull()
    expect(databaseB.releaseContextWriteLease(lockKey, takeoverToken)).toBe(true)
  })
})
