import { DATABASE_FIXTURE_CAPABILITY } from '../../src/database.js'
import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import fs from 'node:fs'
import crypto from 'node:crypto'
import os from 'node:os'
import path from 'node:path'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { StorageManager } from '../../src/storage/storage-manager.js'
import { CacheManager } from '../../src/cache-manager.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import {
  SampleOperationGate,
  SampleOperationBusyError,
  SampleOperationLeaseLostError,
} from '../../src/sample/sample-operation-gate.js'
import { SampleDeletionService } from '../../src/sample/sample-deletion.js'
import { createSampleFinalizationService } from '../../src/sample/sample-finalization.js'
import { JournalRecoveryCoordinator } from '../../src/sample/journal-recovery-coordinator.js'
import {
  secureIngestPublish,
  securePurgeQuarantine,
  securePurgeQuarantineForTest,
  secureQuarantineRenameForTest,
} from '../../src/sample/secure-filesystem.js'
import {
  createSampleDeleteHandler,
  sampleDeleteOutputSchema,
} from '../../src/tools/sample-delete.js'
import { zodToJsonSchema } from '../../src/core/zod-schema-converter.js'
import { JobQueue } from '../../src/job-queue.js'
import { JobPriority } from '../../src/types.js'

const SHA = 'a'.repeat(64)
const SAMPLE_ID = `sha256:${SHA}`
const OTHER_SHA = 'b'.repeat(64)
const OTHER_SAMPLE_ID = `sha256:${OTHER_SHA}`

test('sample.delete exports an MCP SDK-compatible object output schema', () => {
  const schema = zodToJsonSchema(sampleDeleteOutputSchema)

  expect(schema.type).toBe('object')
  expect(schema.anyOf).toHaveLength(2)
})

describe('sample.delete crash-safe lifecycle', () => {
  let root: string
  let workspaceRoot: string
  let storageRoot: string
  let cacheRoot: string
  let ghidraProjectRoot: string
  let ghidraLogRoot: string
  let database: DatabaseManager
  let workspace: WorkspaceManager
  let storage: StorageManager
  let cache: CacheManager
  let policy: PolicyGuard
  let gate: SampleOperationGate
  let service: SampleDeletionService

  beforeEach(async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-sample-delete-'))
    workspaceRoot = path.join(root, 'workspaces')
    storageRoot = path.join(root, 'storage')
    cacheRoot = path.join(root, 'cache')
    ghidraProjectRoot = path.join(root, 'ghidra-projects')
    ghidraLogRoot = path.join(root, 'ghidra-logs')
    for (const directory of [
      workspaceRoot,
      storageRoot,
      cacheRoot,
      ghidraProjectRoot,
      ghidraLogRoot,
    ]) {
      fs.mkdirSync(directory, { recursive: true })
    }
    database = new DatabaseManager(path.join(root, 'state', 'database.db'))
    workspace = new WorkspaceManager(workspaceRoot)
    storage = new StorageManager({
      root: storageRoot,
      maxFileSize: 1024 * 1024,
      retentionDays: 30,
    })
    await storage.initialize()
    cache = new CacheManager(cacheRoot, database)
    policy = new PolicyGuard(path.join(root, 'audit', 'audit.log'))
    gate = new SampleOperationGate(database, {
      instanceId: 'test-instance',
      bootId: 'test-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    service = createService()
  })

  afterEach(() => {
    try {
      gate.close()
    } catch {
      // A test may intentionally close the gate before recovery.
    }
    try {
      database.close()
    } catch {
      // Ignore already-closed handles in cleanup.
    }
    fs.rmSync(root, { recursive: true, force: true })
  })

  function createService(onPhase?: (phase: string) => void): SampleDeletionService {
    return new SampleDeletionService(database, workspace, storage, cache, policy, gate, {
      ghidraProjectRoot,
      ghidraLogRoot,
      onPhase: onPhase ? (phase) => onPhase(phase) : undefined,
    })
  }

  async function expectRejectedWithMessage(
    promise: Promise<unknown>,
    expected: RegExp
  ): Promise<void> {
    let rejection: unknown
    try {
      await promise
    } catch (error) {
      rejection = error
    }
    expect(rejection).toBeDefined()
    expect(String(rejection)).toMatch(expected)
  }

  async function seedSample(): Promise<void> {
    const now = new Date().toISOString()
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: SHA,
      md5: null,
      size: 7,
      file_type: 'PE',
      created_at: now,
      source: 'test',
    })
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: OTHER_SAMPLE_ID,
      sha256: OTHER_SHA,
      md5: null,
      size: 3,
      file_type: 'PE',
      created_at: now,
      source: 'other-test',
    })
    const sampleWorkspace = await workspace.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(sampleWorkspace.original, 'sample.exe'), 'payload')
    const partition = path.join(storageRoot, 'samples', '2026-08-23')
    fs.mkdirSync(partition, { recursive: true })
    fs.writeFileSync(path.join(partition, `${SHA}_sample.exe`), 'payload')
    const artifactDirectory = path.join(storageRoot, 'artifacts', SAMPLE_ID)
    fs.mkdirSync(artifactDirectory, { recursive: true })
    const artifactPath = path.join(artifactDirectory, 'case.json')
    fs.writeFileSync(artifactPath, '{}')
    database.insertArtifact({
      id: 'artifact-1',
      sample_id: SAMPLE_ID,
      type: 'analysis_case_state',
      path: artifactPath,
      sha256: 'b'.repeat(64),
      mime: 'application/json',
      created_at: new Date().toISOString(),
    })
    database.runSql(
      `INSERT INTO analyses
       (id, sample_id, stage, backend, status, started_at, finished_at)
       VALUES ('analysis-1', ?, 'static', 'test', 'completed', ?, ?)`,
      [SAMPLE_ID, now, now]
    )
    database.runSql(
      `INSERT INTO analysis_runs
       (id, sample_id, sample_sha256, goal, depth, backend_policy,
        compatibility_marker, pipeline_version, status, latest_stage,
        stage_plan_json, artifact_refs_json, metadata_json, created_at, updated_at, finished_at)
       VALUES ('run-1', ?, ?, 'static', 'standard', 'static', 'compat', '1',
               'completed', 'function_map', '[]', '[]', '{}', ?, ?, ?)`,
      [SAMPLE_ID, SHA, now, now, now]
    )
    database.runSql(
      `INSERT INTO analysis_run_stages
       (run_id, stage, status, execution_state, created_at, updated_at, finished_at)
       VALUES ('run-1', 'function_map', 'completed', 'completed', ?, ?, ?)`,
      [now, now, now]
    )
    database.runSql(
      `INSERT INTO analysis_evidence
       (id, sample_id, sample_sha256, evidence_family, backend, mode,
        compatibility_marker, result_json, created_at, updated_at)
       VALUES ('evidence-1', ?, ?, 'function_index', 'test', 'static', 'compat', '{}', ?, ?)`,
      [SAMPLE_ID, SHA, now, now]
    )
    database.runSql(
      `INSERT INTO debug_sessions
       (id, run_id, sample_id, sample_sha256, status, debug_state, created_at, updated_at, finished_at)
       VALUES ('debug-1', 'run-1', ?, ?, 'completed', 'completed', ?, ?, ?)`,
      [SAMPLE_ID, SHA, now, now, now]
    )
    database.runSql(
      `INSERT INTO functions
       (sample_id, address, name, size, score) VALUES (?, '0x401000', 'entry', 12, 1.0)`,
      [SAMPLE_ID]
    )
    const stagedDirectory = path.join(storageRoot, 'uploads')
    fs.mkdirSync(stagedDirectory, { recursive: true })
    const stagedPath = path.join(stagedDirectory, `${SHA}.upload`)
    fs.writeFileSync(stagedPath, 'staged')
    database.runSql(
      `INSERT INTO upload_sessions
       (id, token, status, filename, source, created_at, expires_at, uploaded_at,
        staged_path, size, sha256, sample_id)
       VALUES ('upload-1', 'token-1', 'completed', 'sample.exe', 'test', ?, ?, ?, ?, 7, ?, ?)`,
      [now, new Date(Date.now() + 60_000).toISOString(), now, stagedPath, SHA, SAMPLE_ID]
    )
    database.runSql(
      `INSERT INTO jobs
       (id, type, tool, sample_id, args_json, priority, timeout, status,
        progress, created_at, updated_at, started_at, finished_at)
       VALUES ('job-1', 'analysis', 'test.tool', ?, '{}', 5, 1000,
               'completed', 100, ?, ?, ?, ?)`,
      [SAMPLE_ID, now, now, now, now]
    )
    database.runSql(
      `INSERT INTO scheduler_events
       (id, job_id, run_id, sample_id, tool, stage, execution_bucket,
        cost_class, decision, created_at)
       VALUES ('scheduler-1', 'job-1', 'run-1', ?, 'test.tool', 'function_map',
               'static', 'low', 'admit', ?)`,
      [SAMPLE_ID, now]
    )
    for (const batch of [
      { id: 'batch-shared', total: 2 },
      { id: 'batch-single', total: 1 },
    ]) {
      database.runSql(
        `INSERT INTO batches
         (id, status, total_samples, completed_samples, failed_samples,
          cancelled_samples, created_at, updated_at)
         VALUES (?, 'completed', ?, ?, 0, 0, ?, ?)`,
        [batch.id, batch.total, batch.total, now, now]
      )
      database.runSql(
        `INSERT INTO batch_samples
         (batch_id, sample_id, status, filename, size, sha256, created_at, updated_at)
         VALUES (?, ?, 'completed', 'sample.exe', 7, ?, ?, ?)`,
        [batch.id, SAMPLE_ID, SHA, now, now]
      )
    }
    database.runSql(
      `INSERT INTO batch_samples
       (batch_id, sample_id, status, filename, size, sha256, created_at, updated_at)
       VALUES ('batch-shared', ?, 'failed', 'other.exe', 3, ?, ?, ?)`,
      [OTHER_SAMPLE_ID, OTHER_SHA, now, now]
    )
    database.runSql(
      `INSERT INTO sample_kb
       (id, sample_id, created_at, updated_at) VALUES (?, ?, ?, ?)`,
      ['sample-kb-1', SAMPLE_ID, new Date().toISOString(), new Date().toISOString()]
    )
    database.runSql(
      `INSERT INTO function_kb
       (id, features_apis_json, features_strings_json, features_cfg_shape,
        semantics_name, semantics_explanation, semantics_behavior,
        semantics_confidence, semantics_source, samples_json, created_at, updated_at)
       VALUES (?, '[]', '[]', 'shape', 'fn', 'explanation', 'behavior', 0.9,
               'test', ?, ?, ?)`,
      [
        'function-kb-1',
        JSON.stringify([SAMPLE_ID, OTHER_SAMPLE_ID]),
        new Date().toISOString(),
        new Date().toISOString(),
      ]
    )
    database.runSql(
      `INSERT INTO kb_index
       (id, entry_type, entry_id, created_at, updated_at)
       VALUES ('kb-index-1', 'function_kb', 'function-kb-1', ?, ?)`,
      [new Date().toISOString(), new Date().toISOString()]
    )
    await cache.setCachedResult('cache:test-delete', { value: 1 }, 60_000, SHA)
    for (const directory of [path.join(ghidraProjectRoot, SHA), path.join(ghidraLogRoot, SHA)]) {
      fs.mkdirSync(directory, { recursive: true })
      fs.writeFileSync(path.join(directory, 'state.bin'), 'state')
    }
  }

  test('creates the lease, generation, instance, and journal migration tables', () => {
    const names = database
      .querySql<{ name: string }>(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'sample_operation_%'
         OR name = 'sample_deletions' ORDER BY name`
      )
      .map((row) => row.name)
    expect(names).toEqual([
      'sample_deletions',
      'sample_operation_generations',
      'sample_operation_instances',
      'sample_operation_leases',
    ])
  })

  test('returns a strict, machine-readable confirmation mismatch without mutation', async () => {
    await seedSample()
    const handler = createSampleDeleteHandler(service)
    const response = await handler({ sample_id: SAMPLE_ID, confirm_sha256: 'b'.repeat(64) })
    expect(response.content).toEqual([])
    expect(response.isError).toBe(true)
    expect(response.structuredContent).toEqual({
      ok: false,
      error: {
        code: 'E_SAMPLE_CONFIRMATION_MISMATCH',
        retryable: false,
        blockers: [],
      },
    })
    expect(database.findSample(SAMPLE_ID)).toBeDefined()
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_deletions')
        ?.count
    ).toBe(0)
  })

  test('fails closed before mutation when the deletion audit log is retargeted', async () => {
    await seedSample()
    const outside = path.join(root, 'outside-audit-sentinel')
    fs.writeFileSync(outside, 'keep')
    fs.unlinkSync(policy.getAuditLogPath())
    fs.symlinkSync(outside, policy.getAuditLogPath())
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      /audit log/i
    )
    expect(fs.readFileSync(outside, 'utf8')).toBe('keep')
    expect(database.findSample(SAMPLE_ID)).toBeDefined()
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_deletions')
        ?.count
    ).toBe(0)
  })

  test('deletion audit loops across a short write and persists complete JSONL', async () => {
    const originalWrite = fs.writeSync.bind(fs)
    let calls = 0
    const writeSpy = jest.spyOn(fs, 'writeSync').mockImplementation(((
      descriptor: number,
      buffer: Uint8Array,
      offset: number,
      length: number,
      position: number | null
    ) => {
      calls++
      const boundedLength = calls === 1 ? Math.max(1, Math.floor(length / 2)) : length
      return originalWrite(descriptor, buffer, offset, boundedLength, position)
    }) as typeof fs.writeSync)
    try {
      await expect(
        service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
      ).resolves.toEqual(expect.objectContaining({ outcome: 'already_absent' }))
    } finally {
      writeSpy.mockRestore()
    }
    expect(calls).toBeGreaterThan(1)
    const auditLines = fs.readFileSync(policy.getAuditLogPath(), 'utf8').trim().split('\n')
    expect(auditLines.length).toBeGreaterThan(0)
    for (const line of auditLines) expect(() => JSON.parse(line)).not.toThrow()
  })

  test('zero-progress deletion audit retains the journal until recovery succeeds', async () => {
    await seedSample()
    const originalWrite = fs.writeSync.bind(fs)
    const writeSpy = jest.spyOn(fs, 'writeSync').mockImplementation(((
      descriptor: number,
      buffer: Uint8Array,
      offset: number,
      length: number,
      position: number | null
    ) => {
      const line = Buffer.from(buffer)
        .subarray(offset, offset + length)
        .toString('utf8')
      if (line.includes('Deletion completed')) return 0
      return originalWrite(descriptor, buffer, offset, length, position)
    }) as typeof fs.writeSync)
    try {
      await expect(
        service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
      ).rejects.toThrow(/no forward progress/i)
    } finally {
      writeSpy.mockRestore()
    }
    expect(
      database.queryOneSql<{ phase: string; audit_phases_json: string }>(
        `SELECT phase, audit_phases_json FROM sample_deletions
         WHERE sample_id = ? ORDER BY created_at DESC LIMIT 1`,
        [SAMPLE_ID]
      )
    ).toEqual({
      phase: 'files_purged',
      audit_phases_json: JSON.stringify(['start', 'failure:files_purged']),
    })
    await expect(service.recoverPendingDeletions()).resolves.toEqual({
      recovered: 1,
      skipped: 0,
      failed: 0,
    })
  })

  test('atomically rolls back multi-sample shared acquisition when any sample is tombstoned', () => {
    const other = `sha256:${'b'.repeat(64)}`
    database.runSql(
      `INSERT INTO sample_operation_generations
       (sample_id, generation, tombstoned, deletion_id, updated_at)
       VALUES (?, 4, 1, 'delete-other', ?)`,
      [other, new Date().toISOString()]
    )
    expect(() => gate.acquireShared([SAMPLE_ID, other])).toThrow()
    expect(
      database.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
        [SAMPLE_ID]
      )?.count
    ).toBe(0)
  })

  test('keeps expired shared leases while their owner instance is live and reaps only proven-dead owners', async () => {
    await seedSample()
    const ownerLease = gate.acquireShared([SAMPLE_ID])
    database.runSql(`UPDATE sample_operation_leases SET lease_until = ? WHERE lease_token = ?`, [
      new Date(Date.now() - 60_000).toISOString(),
      ownerLease.token,
    ])
    const contender = new SampleOperationGate(database, {
      instanceId: 'lease-contender',
      bootId: 'test-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    try {
      const liveOwnerLease = contender.acquireShared([SAMPLE_ID])
      expect(
        database.queryOneSql<{ count: number }>(
          'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
          [SAMPLE_ID]
        )?.count
      ).toBe(2)
      liveOwnerLease.release()

      database.runSql(
        `UPDATE sample_operation_instances SET lease_until = ? WHERE instance_id = ?`,
        [new Date(Date.now() - 60_000).toISOString(), gate.instanceId]
      )
      const reapedOwnerLease = contender.acquireShared([SAMPLE_ID])
      expect(
        database.queryOneSql<{ count: number }>(
          'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
          [SAMPLE_ID]
        )?.count
      ).toBe(1)
      reapedOwnerLease.release()
    } finally {
      ownerLease.release()
      contender.close()
    }
  })

  test('fails fencing after the sample generation changes', async () => {
    await seedSample()
    const lease = gate.acquireShared([SAMPLE_ID])
    database.runSql(
      `UPDATE sample_operation_generations
       SET generation = generation + 1, tombstoned = 1,
           deletion_id = 'replacement-delete', updated_at = ?
       WHERE sample_id = ?`,
      [new Date().toISOString(), SAMPLE_ID]
    )
    expect(() => lease.assertOwned()).toThrow(SampleOperationLeaseLostError)
    lease.release()
  })

  test('DB triggers reject unguarded writers after a tombstone is established', async () => {
    await seedSample()
    database.runSql(
      `UPDATE sample_operation_generations
       SET generation = generation + 1, tombstoned = 1, deletion_id = 'manual-delete'
       WHERE sample_id = ?`,
      [SAMPLE_ID]
    )
    expect(() =>
      database.runSql(
        `INSERT INTO analyses
         (id, sample_id, stage, backend, status) VALUES ('late-analysis', ?, 'x', 'x', 'queued')`,
        [SAMPLE_ID]
      )
    ).toThrow(/E_SAMPLE_TOMBSTONED/)
    await expectRejectedWithMessage(
      cache.setCachedResult('cache:late', {}, 60_000, SHA),
      /E_SAMPLE_TOMBSTONED/
    )

    const freshSha = 'c'.repeat(64)
    const freshId = `sha256:${freshSha}`
    database.runSql(
      `INSERT INTO sample_operation_generations
        (sample_id, generation, tombstoned, deletion_id, updated_at)
       VALUES (?, 1, 1, 'prepared-delete', ?)`,
      [freshId, new Date().toISOString()]
    )
    expect(() =>
      database.runSql(
        `INSERT INTO samples
          (id, sha256, size, created_at, source) VALUES (?, ?, 1, ?, 'unguarded')`,
        [freshId, freshSha, new Date().toISOString()]
      )
    ).toThrow(/E_SAMPLE_TOMBSTONED/)
  })

  test.each(['db_committed', 'fs_committed'] as const)(
    'ingest lease loss at %s leaves fenced state for a new owner to converge',
    async (failurePhase) => {
      let observed: { sampleId: string; tempPath: string; finalPath: string } | undefined
      const finalizer = createSampleFinalizationService(workspace, database, policy, gate, {
        onPhase: (phase, context) => {
          observed = context
          if (phase === failurePhase) {
            database.runSql('DELETE FROM sample_operation_leases WHERE sample_id = ?', [
              context.sampleId,
            ])
          }
        },
      })

      await expect(
        finalizer.finalizeBuffer({
          data: Buffer.from(`ingest-fence-${failurePhase}`),
          filename: 'race.bin',
          source: 'race-test',
        })
      ).rejects.toBeInstanceOf(SampleOperationLeaseLostError)

      expect(observed).toBeDefined()
      if (failurePhase === 'db_committed') {
        expect(database.findSample(observed!.sampleId)).toBeDefined()
      } else {
        expect(database.findSample(observed!.sampleId)).toBeUndefined()
      }
      expect(fs.existsSync(observed!.tempPath)).toBe(false)
      expect(fs.existsSync(observed!.finalPath)).toBe(true)
      expect(
        database.queryOneSql<{ count: number }>(
          'SELECT COUNT(*) AS count FROM sample_ingests WHERE sample_id = ?',
          [observed!.sampleId]
        )?.count
      ).toBe(1)
      if (failurePhase === 'fs_committed') {
        let busy: unknown
        try {
          await service.deleteSample({
            sampleId: observed!.sampleId,
            confirmSha256: observed!.sampleId.slice('sha256:'.length),
          })
        } catch (error) {
          busy = error
        }
        expect(busy).toBeInstanceOf(SampleOperationBusyError)
        expect((busy as SampleOperationBusyError).blockers).toEqual(
          expect.arrayContaining([expect.objectContaining({ kind: 'ingest_journal' })])
        )
      }

      const recovery = createSampleFinalizationService(workspace, database, policy, gate)
      await expect(recovery.recoverPendingIngests()).resolves.toEqual({
        recovered: 1,
        cleaned: 0,
        failed: 0,
      })
      expect(database.findSample(observed!.sampleId)).toBeDefined()
      expect(fs.existsSync(observed!.finalPath)).toBe(true)
      expect(
        database.queryOneSql<{ count: number }>(
          'SELECT COUNT(*) AS count FROM sample_ingests WHERE sample_id = ?',
          [observed!.sampleId]
        )?.count
      ).toBe(0)
    }
  )

  test('durable ingest audit failure retains a claimable journal until recovery succeeds', async () => {
    const payload = Buffer.from('durable-audit-recovery')
    const finalizer = createSampleFinalizationService(workspace, database, policy, gate)
    const auditPath = policy.getAuditLogPath()
    fs.rmSync(auditPath, { force: true })
    fs.mkdirSync(auditPath)

    await expect(
      finalizer.finalizeBuffer({
        data: payload,
        filename: 'audit.bin',
        source: 'audit-test',
      })
    ).rejects.toThrow(/E_AUDIT_DURABILITY/)
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_ingests')?.count
    ).toBe(1)

    fs.rmSync(auditPath, { recursive: true })
    fs.writeFileSync(auditPath, '')
    await expect(finalizer.recoverPendingIngests()).resolves.toEqual({
      recovered: 1,
      cleaned: 0,
      failed: 0,
    })
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_ingests')?.count
    ).toBe(0)
  })

  test('durable audit loops across a short write and persists complete JSONL', () => {
    const originalWrite = fs.writeSync.bind(fs)
    let calls = 0
    const writeSpy = jest.spyOn(fs, 'writeSync').mockImplementation(((
      descriptor: number,
      buffer: Uint8Array,
      offset: number,
      length: number,
      position: number | null
    ) => {
      calls++
      const boundedLength = calls === 1 ? Math.max(1, Math.floor(length / 2)) : length
      return originalWrite(descriptor, buffer, offset, boundedLength, position)
    }) as typeof fs.writeSync)
    try {
      policy.auditLogFailClosed({
        timestamp: new Date().toISOString(),
        operation: 'sample.ingest.short-write-test',
        sampleId: SAMPLE_ID,
        decision: 'allow',
      })
    } finally {
      writeSpy.mockRestore()
    }
    expect(calls).toBeGreaterThan(1)
    expect(() => JSON.parse(fs.readFileSync(policy.getAuditLogPath(), 'utf8').trim())).not.toThrow()
  })

  test('zero-progress audit write retains the ingest journal for recovery', async () => {
    const payload = Buffer.from('zero-progress-audit')
    const finalizer = createSampleFinalizationService(workspace, database, policy, gate)
    const writeSpy = jest.spyOn(fs, 'writeSync').mockImplementation(() => 0)
    try {
      await expect(
        finalizer.finalizeBuffer({ data: payload, filename: 'audit-zero.bin' })
      ).rejects.toThrow(/E_AUDIT_DURABILITY/)
    } finally {
      writeSpy.mockRestore()
    }
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_ingests')?.count
    ).toBe(1)
    await expect(finalizer.recoverPendingIngests()).resolves.toEqual({
      recovered: 1,
      cleaned: 0,
      failed: 0,
    })
  })

  test('ingest publish resumes a deterministic hidden temp cleanup claim', () => {
    if (process.platform !== 'linux') return
    const secureRoot = path.join(root, 'ingest-cleanup-root')
    const original = path.join(secureRoot, 'original')
    fs.mkdirSync(original, { recursive: true })
    const payload = Buffer.from('deterministic-cleanup-payload')
    const digest = crypto.createHash('sha256').update(payload).digest('hex')
    const tempName = '.rikune-ingest-known.tmp'
    const cleanupName = `.rikune-remove-${crypto.createHash('sha256').update(tempName).digest('hex')}`
    fs.writeFileSync(path.join(original, 'sample.bin'), payload, { mode: 0o400 })
    fs.writeFileSync(path.join(original, cleanupName), payload, { mode: 0o400 })
    const rootStat = fs.lstatSync(secureRoot)

    expect(
      secureIngestPublish({
        root: secureRoot,
        rootDevice: Number(rootStat.dev),
        rootInode: Number(rootStat.ino),
        directoryRelative: 'original',
        tempName,
        finalName: 'sample.bin',
        expectedSha256: digest,
        data: payload,
      })
    ).toEqual(expect.objectContaining({ status: 'already_present' }))
    expect(fs.existsSync(path.join(original, cleanupName))).toBe(false)
  })

  test('recovery atomically removes a journal-owned partial temp after a write crash', async () => {
    const payload = Buffer.from('expected-complete-payload')
    const sha256 = crypto.createHash('sha256').update(payload).digest('hex')
    const sampleId = `sha256:${sha256}`
    const lease = gate.acquireIngestLease(sampleId)
    const generation = lease.generations.get(sampleId)!
    const journalId = crypto.randomUUID()
    const ownerToken = crypto.randomUUID()
    const tempName = `.rikune-ingest-${crypto.randomUUID()}.tmp`
    database.prepareSampleIngestJournal(
      {
        id: journalId,
        sample_id: sampleId,
        sha256,
        md5: null,
        size: payload.length,
        file_type: 'unknown',
        filename: 'partial.bin',
        temp_name: tempName,
        source: 'partial-crash-test',
      },
      { leaseToken: lease.token, instanceId: lease.instanceId, generation },
      { token: ownerToken, until: new Date(Date.now() + 60_000).toISOString() }
    )
    const sampleWorkspace = await workspace.createWorkspace(sampleId)
    const partialPath = path.join(sampleWorkspace.original, tempName)
    fs.writeFileSync(partialPath, payload.subarray(0, 4), { mode: 0o400 })
    expect(
      database.abandonSampleIngestJournal(journalId, ownerToken, {
        instanceId: lease.instanceId,
        generation,
      })
    ).toBe(true)
    lease.release()

    const finalizer = createSampleFinalizationService(workspace, database, policy, gate)
    await expect(finalizer.recoverPendingIngests()).resolves.toEqual({
      recovered: 0,
      cleaned: 1,
      failed: 0,
    })
    expect(fs.existsSync(partialPath)).toBe(false)
    expect(database.findSampleIngestJournal(journalId)).toBeUndefined()
  })

  test('recovery completes a rename-published payload after a crash before fs journal mark', async () => {
    const payload = Buffer.from('published-before-journal-mark')
    const sha256 = crypto.createHash('sha256').update(payload).digest('hex')
    const sampleId = `sha256:${sha256}`
    const lease = gate.acquireIngestLease(sampleId)
    const generation = lease.generations.get(sampleId)!
    const journalId = crypto.randomUUID()
    const ownerToken = crypto.randomUUID()
    const tempName = `.rikune-ingest-${crypto.randomUUID()}.tmp`
    database.prepareSampleIngestJournal(
      {
        id: journalId,
        sample_id: sampleId,
        sha256,
        md5: null,
        size: payload.length,
        file_type: 'unknown',
        filename: 'published.bin',
        temp_name: tempName,
        source: 'publish-crash-test',
      },
      { leaseToken: lease.token, instanceId: lease.instanceId, generation },
      { token: ownerToken, until: new Date(Date.now() + 60_000).toISOString() }
    )
    const sampleWorkspace = await workspace.createWorkspace(sampleId)
    const trusted = workspace.getTrustedRootIdentity()
    const published = secureIngestPublish({
      root: trusted.root,
      rootDevice: trusted.device,
      rootInode: trusted.inode,
      directoryRelative: path.relative(trusted.root, sampleWorkspace.original),
      tempName,
      finalName: 'published.bin',
      expectedSha256: sha256,
      data: payload,
    })
    expect(published.status).toBe('published')
    expect(fs.lstatSync(path.join(sampleWorkspace.original, 'published.bin')).nlink).toBe(1)
    database.abandonSampleIngestJournal(journalId, ownerToken, {
      instanceId: lease.instanceId,
      generation,
    })
    lease.release()

    const finalizer = createSampleFinalizationService(workspace, database, policy, gate)
    await expect(finalizer.recoverPendingIngests()).resolves.toEqual({
      recovered: 1,
      cleaned: 0,
      failed: 0,
    })
    expect(database.findSample(sampleId)).toBeDefined()
    expect(database.findSampleIngestJournal(journalId)).toBeUndefined()
    expect(fs.readFileSync(path.join(sampleWorkspace.original, 'published.bin'))).toEqual(payload)
  })

  test('periodic recovery claims an abandoned live-instance ingest without a server restart', async () => {
    let reached!: () => void
    let resume!: () => void
    const atFilesystemCommit = new Promise<void>((resolve) => {
      reached = resolve
    })
    const continueTask = new Promise<void>((resolve) => {
      resume = resolve
    })
    const owner = createSampleFinalizationService(workspace, database, policy, gate, {
      onPhase: async (phase, context) => {
        if (phase !== 'fs_committed') return
        reached()
        await continueTask
        database.runSql(
          'DELETE FROM sample_operation_leases WHERE sample_id = ? AND instance_id = ?',
          [context.sampleId, gate.instanceId]
        )
      },
    })
    const ownerTask = owner.finalizeBuffer({
      data: Buffer.from('rolling-owner-crash'),
      filename: 'rolling.bin',
      source: 'rolling-test',
    })
    await atFilesystemCommit

    const successorGate = new SampleOperationGate(database, {
      instanceId: 'rolling-successor',
      bootId: 'rolling-successor-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    const successorFinalization = createSampleFinalizationService(
      workspace,
      database,
      policy,
      successorGate
    )
    const successorDeletion = new SampleDeletionService(
      database,
      workspace,
      storage,
      cache,
      policy,
      successorGate,
      { ghidraProjectRoot, ghidraLogRoot }
    )
    const coordinator = new JournalRecoveryCoordinator(successorFinalization, successorDeletion, 10)
    coordinator.start()
    await new Promise((resolve) => setTimeout(resolve, 25))
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_ingests')?.count
    ).toBe(1)

    resume()
    await expect(ownerTask).rejects.toBeInstanceOf(SampleOperationLeaseLostError)
    const deadline = Date.now() + 2_000
    while (
      (database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_ingests')
        ?.count ?? 0) > 0 &&
      Date.now() < deadline
    ) {
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_ingests')?.count
    ).toBe(0)
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM samples')?.count
    ).toBe(1)
    await coordinator.stop()
    successorGate.close()
  })

  test('concurrent same-hash finalizers coalesce behind the journal owner', async () => {
    let reached!: () => void
    let resume!: () => void
    const ownerReady = new Promise<void>((resolve) => {
      reached = resolve
    })
    const continueOwner = new Promise<void>((resolve) => {
      resume = resolve
    })
    const payload = Buffer.from('coalesced-same-hash-payload')
    const owner = createSampleFinalizationService(workspace, database, policy, gate, {
      onPhase: async (phase) => {
        if (phase !== 'fs_committed') return
        reached()
        await continueOwner
      },
    })
    const follower = createSampleFinalizationService(workspace, database, policy, gate)
    const ownerTask = owner.finalizeBuffer({ data: payload, filename: 'owner.bin' })
    await ownerReady
    const followerTask = follower.finalizeBuffer({ data: payload, filename: 'follower.bin' })
    await new Promise((resolve) => setTimeout(resolve, 25))
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_ingests')?.count
    ).toBe(1)
    resume()

    const [ownerResult, followerResult] = await Promise.all([ownerTask, followerTask])
    expect(ownerResult.existed).not.toBe(true)
    expect(followerResult).toEqual(
      expect.objectContaining({ sample_id: ownerResult.sample_id, existed: true })
    )
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM samples')?.count
    ).toBe(1)
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_ingests')?.count
    ).toBe(0)
  })

  test('dirfd quarantine rename cannot be redirected by an ancestor symlink swap', async () => {
    if (process.platform !== 'linux') return
    const secureRoot = path.join(root, 'secure-root')
    const ancestor = path.join(secureRoot, 'aa')
    const originalAncestor = path.join(secureRoot, 'aa-original')
    const sourceDirectory = path.join(ancestor, 'bb')
    const sourcePath = path.join(sourceDirectory, 'sample.bin')
    const outside = path.join(root, 'outside')
    const outsideSource = path.join(outside, 'bb', 'sample.bin')
    const readyFile = path.join(root, 'secure-helper.ready')
    const continueFile = path.join(root, 'secure-helper.continue')
    fs.mkdirSync(sourceDirectory, { recursive: true })
    fs.mkdirSync(path.dirname(outsideSource), { recursive: true })
    fs.writeFileSync(sourcePath, 'journaled')
    fs.writeFileSync(outsideSource, 'outside-must-survive')
    const rootStat = fs.lstatSync(secureRoot)
    const sourceStat = fs.lstatSync(sourcePath)

    const renamePromise = secureQuarantineRenameForTest({
      root: secureRoot,
      rootDevice: Number(rootStat.dev),
      rootInode: Number(rootStat.ino),
      sourceRelative: 'aa/bb/sample.bin',
      destinationRelative: '.trash/delete-race/aa/bb/sample.bin',
      expectedDevice: Number(sourceStat.dev),
      expectedInode: Number(sourceStat.ino),
      expectedType: 'file',
      readyFile,
      continueFile,
    })

    for (let attempt = 0; attempt < 400 && !fs.existsSync(readyFile); attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 5))
    }
    expect(fs.existsSync(readyFile)).toBe(true)
    fs.renameSync(ancestor, originalAncestor)
    fs.symlinkSync(outside, ancestor, 'dir')
    fs.writeFileSync(continueFile, 'continue')

    await expect(renamePromise).resolves.toEqual({ status: 'renamed' })
    expect(fs.readFileSync(outsideSource, 'utf8')).toBe('outside-must-survive')
    expect(fs.existsSync(path.join(originalAncestor, 'bb', 'sample.bin'))).toBe(false)
    expect(
      fs.readFileSync(
        path.join(secureRoot, '.trash', 'delete-race', 'aa', 'bb', 'sample.bin'),
        'utf8'
      )
    ).toBe('journaled')
  })

  test('secure purge atomically claims a basename before identity validation', async () => {
    if (process.platform !== 'linux') return
    const secureRoot = path.join(root, 'purge-race-root')
    const deletionRoot = path.join(secureRoot, '.trash', 'delete-race')
    const victimTree = path.join(deletionRoot, 'victim-tree')
    const victim = path.join(victimTree, 'victim.bin')
    const savedTree = path.join(secureRoot, 'saved-owned-tree')
    const readyFile = path.join(root, 'purge-helper.ready')
    const continueFile = path.join(root, 'purge-helper.continue')
    fs.mkdirSync(victimTree, { recursive: true })
    fs.writeFileSync(victim, 'journaled-owned-file')
    const rootStat = fs.lstatSync(secureRoot)
    const treeStat = fs.lstatSync(victimTree)
    const victimStat = fs.lstatSync(victim)

    const purge = securePurgeQuarantineForTest({
      root: secureRoot,
      rootDevice: Number(rootStat.dev),
      rootInode: Number(rootStat.ino),
      directoryRelative: '.trash/delete-race',
      entries: [
        {
          relativePath: 'victim-tree',
          device: Number(treeStat.dev),
          inode: Number(treeStat.ino),
          type: 'directory',
          size: 0,
          quarantineTarget: true,
        },
        {
          relativePath: 'victim-tree/victim.bin',
          device: Number(victimStat.dev),
          inode: Number(victimStat.ino),
          type: 'file',
          size: victimStat.size,
          quarantineTarget: false,
        },
      ],
      readyFile,
      continueFile,
    })

    for (let attempt = 0; attempt < 400 && !fs.existsSync(readyFile); attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 5))
    }
    expect(fs.existsSync(readyFile)).toBe(true)
    const claimedDeletionRoot = path.join(secureRoot, '.trash', '.purging-delete-race')
    const claimedVictimTree = path.join(claimedDeletionRoot, 'victim-tree')
    const claimedVictim = path.join(claimedVictimTree, 'victim.bin')
    fs.renameSync(claimedVictimTree, savedTree)
    fs.mkdirSync(claimedVictimTree)
    fs.writeFileSync(claimedVictim, 'competitor-must-survive')
    fs.writeFileSync(continueFile, 'continue')

    await expect(purge).rejects.toThrow(/identity changed/i)
    expect(fs.readFileSync(path.join(savedTree, 'victim.bin'), 'utf8')).toBe('journaled-owned-file')
    const preservedCompetitors: string[] = []
    const walk = (directory: string): void => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const candidate = path.join(directory, entry.name)
        if (entry.isDirectory()) walk(candidate)
        else if (
          entry.isFile() &&
          fs.readFileSync(candidate, 'utf8') === 'competitor-must-survive'
        ) {
          preservedCompetitors.push(candidate)
        }
      }
    }
    walk(secureRoot)
    expect(preservedCompetitors).toHaveLength(1)
  })

  test('secure purge resumes after a crash following a partial unlink', async () => {
    if (process.platform !== 'linux') return
    const secureRoot = path.join(root, 'purge-resume-root')
    const deletionRoot = path.join(secureRoot, '.trash', 'delete-resume', 'tree')
    fs.mkdirSync(deletionRoot, { recursive: true })
    fs.writeFileSync(path.join(deletionRoot, 'a.bin'), 'a')
    fs.writeFileSync(path.join(deletionRoot, 'b.bin'), 'b')
    const rootStat = fs.lstatSync(secureRoot)
    const treeStat = fs.lstatSync(deletionRoot)
    const entries = ['a.bin', 'b.bin'].map((name) => {
      const stat = fs.lstatSync(path.join(deletionRoot, name))
      return {
        relativePath: `tree/${name}`,
        device: Number(stat.dev),
        inode: Number(stat.ino),
        type: 'file' as const,
        size: stat.size,
        quarantineTarget: false,
      }
    })
    const request = {
      root: secureRoot,
      rootDevice: Number(rootStat.dev),
      rootInode: Number(rootStat.ino),
      directoryRelative: '.trash/delete-resume',
      entries: [
        {
          relativePath: 'tree',
          device: Number(treeStat.dev),
          inode: Number(treeStat.ino),
          type: 'directory' as const,
          size: 0,
          quarantineTarget: true,
        },
        ...entries,
      ],
    }

    await expect(
      securePurgeQuarantineForTest({ ...request, testFailAfterUnlinks: 1 })
    ).rejects.toThrow(/test purge crash/i)
    await expect(securePurgeQuarantine(request)).resolves.toEqual({ status: 'purged' })
    expect(fs.existsSync(path.join(secureRoot, '.trash', 'delete-resume'))).toBe(false)
    expect(fs.existsSync(path.join(secureRoot, '.trash', '.purging-delete-resume'))).toBe(false)
  })

  test('secure purge converges across bounded chunks after a committed-chunk crash', async () => {
    if (process.platform !== 'linux') return
    const secureRoot = path.join(root, 'purge-chunk-root')
    const tree = path.join(secureRoot, '.trash', 'delete-chunks', 'nested', 'tree')
    fs.mkdirSync(tree, { recursive: true })
    for (let index = 0; index < 24; index++) {
      fs.writeFileSync(path.join(tree, `sample-${String(index).padStart(2, '0')}.bin`), `${index}`)
    }
    const rootStat = fs.lstatSync(secureRoot)
    const nestedStat = fs.lstatSync(path.join(secureRoot, '.trash', 'delete-chunks', 'nested'))
    const treeStat = fs.lstatSync(tree)
    const entries = [
      {
        relativePath: 'nested',
        device: Number(nestedStat.dev),
        inode: Number(nestedStat.ino),
        type: 'directory' as const,
        size: 0,
        quarantineTarget: true,
      },
      {
        relativePath: 'nested/tree',
        device: Number(treeStat.dev),
        inode: Number(treeStat.ino),
        type: 'directory' as const,
        size: 0,
        quarantineTarget: false,
      },
      ...Array.from({ length: 24 }, (_, index) => {
        const relative = `nested/tree/sample-${String(index).padStart(2, '0')}.bin`
        const stat = fs.lstatSync(path.join(secureRoot, '.trash', 'delete-chunks', relative))
        return {
          relativePath: relative,
          device: Number(stat.dev),
          inode: Number(stat.ino),
          type: 'file' as const,
          size: stat.size,
          quarantineTarget: false,
        }
      }),
    ]
    const request = {
      root: secureRoot,
      rootDevice: Number(rootStat.dev),
      rootInode: Number(rootStat.ino),
      directoryRelative: '.trash/delete-chunks',
      entries,
      testChunkBytes: 1024,
    }

    await expect(securePurgeQuarantine({ ...request, testFailAfterChunks: 1 })).rejects.toThrow(
      /committed chunk/i
    )
    expect(fs.existsSync(path.join(secureRoot, '.trash', '.purging-delete-chunks'))).toBe(true)
    await expect(securePurgeQuarantine(request)).resolves.toEqual({ status: 'purged' })
    expect(fs.existsSync(path.join(secureRoot, '.trash', 'delete-chunks'))).toBe(false)
    expect(fs.existsSync(path.join(secureRoot, '.trash', '.purging-delete-chunks'))).toBe(false)
  })

  test('secure purge streams a manifest larger than Linux argv limits over stdin', async () => {
    if (process.platform !== 'linux') return
    const secureRoot = path.join(root, 'purge-large-root')
    fs.mkdirSync(path.join(secureRoot, '.trash', 'delete-large'), { recursive: true })
    const rootStat = fs.lstatSync(secureRoot)
    const entries = Array.from({ length: 1_500 }, (_, index) => ({
      relativePath: `missing-${String(index).padStart(4, '0')}-${'x'.repeat(160)}.bin`,
      device: Number(rootStat.dev),
      inode: index + 1,
      type: 'file' as const,
      size: 1,
      quarantineTarget: true,
    }))
    expect(JSON.stringify(entries).length).toBeGreaterThan(128 * 1024)
    await expect(
      securePurgeQuarantine({
        root: secureRoot,
        rootDevice: Number(rootStat.dev),
        rootInode: Number(rootStat.ino),
        directoryRelative: '.trash/delete-large',
        entries,
      })
    ).resolves.toEqual({ status: 'purged' })
  })

  test('job queue holds leases across queued and cancelled-running worker lifetimes', async () => {
    await seedSample()
    const queue = new JobQueue(database, gate)
    const jobId = queue.enqueue({
      type: 'analysis',
      tool: 'test.tool',
      sampleId: SAMPLE_ID,
      args: {},
      priority: JobPriority.NORMAL,
      timeout: 5_000,
    })
    expect(queue.startQueuedJob(jobId)?.id).toBe(jobId)
    expect(queue.cancel(jobId, 'test cancellation')).toBe(true)
    await expect(
      service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
    ).rejects.toBeInstanceOf(SampleOperationBusyError)
    queue.complete(jobId, {
      jobId,
      ok: false,
      errors: ['cancelled'],
      warnings: [],
      artifacts: [],
      metrics: { elapsedMs: 1, peakRssMb: 0 },
    })
    await expect(
      service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
    ).resolves.toEqual(expect.objectContaining({ outcome: 'deleted' }))
    queue.close()
  })

  test('stale running reaper keeps the lease through cancelling until worker exit', async () => {
    await seedSample()
    const queue = new JobQueue(database, gate)
    const jobId = queue.enqueue({
      type: 'static',
      tool: 'test.tool',
      sampleId: SAMPLE_ID,
      args: {},
      priority: JobPriority.NORMAL,
      timeout: 5_000,
    })
    expect(queue.startQueuedJob(jobId)?.id).toBe(jobId)

    expect(queue.reapStaleRunningJobs(1, Date.now() + 10_000)).toEqual([jobId])
    expect(queue.getStatus(jobId)?.status).toBe('cancelling')
    expect(
      database.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
        [SAMPLE_ID]
      )?.count
    ).toBe(1)
    await expect(
      service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
    ).rejects.toBeInstanceOf(SampleOperationBusyError)

    queue.complete(jobId, {
      jobId,
      ok: false,
      errors: ['aborted'],
      warnings: [],
      artifacts: [],
      metrics: { elapsedMs: 10_000, peakRssMb: 0 },
    })
    expect(queue.getStatus(jobId)?.status).toBe('interrupted')
    expect(
      database.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) AS count FROM sample_operation_leases WHERE sample_id = ?',
        [SAMPLE_ID]
      )?.count
    ).toBe(0)
    await expect(
      service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
    ).resolves.toEqual(expect.objectContaining({ outcome: 'deleted' }))
    queue.close()
  })

  test('completion fails lease-lost when the queue-owned lease is missing', async () => {
    await seedSample()
    const queue = new JobQueue(database, gate)
    const jobId = queue.enqueue({
      type: 'static',
      tool: 'test.tool',
      sampleId: SAMPLE_ID,
      args: {},
      priority: JobPriority.NORMAL,
      timeout: 5_000,
    })
    expect(queue.startQueuedJob(jobId)?.id).toBe(jobId)
    queue.close()
    expect(() =>
      queue.complete(jobId, {
        jobId,
        ok: true,
        errors: [],
        warnings: [],
        artifacts: [],
        metrics: { elapsedMs: 1, peakRssMb: 0 },
      })
    ).toThrow(/E_SAMPLE_LEASE_LOST/)
    expect(queue.getStatus(jobId)?.status).toBe('running')
  })

  test('blocks deletion while a shared lease is live and succeeds after release', async () => {
    await seedSample()
    const lease = gate.acquireShared([SAMPLE_ID])
    await expect(
      service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
    ).rejects.toBeInstanceOf(SampleOperationBusyError)
    lease.release()
    const deleted = await service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
    expect(deleted.outcome).toBe('deleted')
  })

  test('quarantines and removes all files, DB rows, KB, cache and exclusive lease', async () => {
    await seedSample()
    const result = await service.deleteSample({
      sampleId: SAMPLE_ID,
      confirmSha256: SHA,
      reason: 'owner request',
    })
    expect(result).toEqual(
      expect.objectContaining({
        sample_id: SAMPLE_ID,
        outcome: 'deleted',
        deletion_id: expect.any(String),
        reclaimed: expect.objectContaining({
          files: expect.any(Number),
          bytes: expect.any(Number),
        }),
      })
    )
    expect(result.reclaimed.files).toBeGreaterThanOrEqual(5)
    expect(database.findSample(SAMPLE_ID)).toBeUndefined()
    expect(database.findSample(OTHER_SAMPLE_ID)).toBeDefined()
    expect(database.findArtifacts(SAMPLE_ID)).toEqual([])
    for (const [table, predicate] of [
      ['scheduler_events', 'sample_id = ?'],
      ['analysis_run_stages', "run_id = 'run-1'"],
      ['debug_sessions', 'sample_id = ?'],
      ['analyses', 'sample_id = ?'],
      ['analysis_evidence', 'sample_id = ?'],
      ['functions', 'sample_id = ?'],
      ['upload_sessions', 'sample_id = ?'],
      ['jobs', 'sample_id = ?'],
      ['analysis_runs', 'sample_id = ?'],
      ['batch_samples', 'sample_id = ?'],
    ] as const) {
      const params = predicate.includes('?') ? [SAMPLE_ID] : []
      expect(
        database.queryOneSql<{ count: number }>(
          `SELECT COUNT(*) AS count FROM ${table} WHERE ${predicate}`,
          params
        )?.count
      ).toBe(0)
    }
    expect(
      database.queryOneSql<{
        total_samples: number
        completed_samples: number
        failed_samples: number
        cancelled_samples: number
      }>(
        `SELECT total_samples, completed_samples, failed_samples, cancelled_samples
         FROM batches WHERE id = 'batch-shared'`
      )
    ).toEqual({
      total_samples: 1,
      completed_samples: 0,
      failed_samples: 1,
      cancelled_samples: 0,
    })
    expect(
      database.queryOneSql<{ count: number }>(
        `SELECT COUNT(*) AS count FROM batches WHERE id = 'batch-single'`
      )?.count
    ).toBe(0)
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM sample_kb')?.count
    ).toBe(0)
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM function_kb')?.count
    ).toBe(0)
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM kb_index')?.count
    ).toBe(0)
    expect(
      database.queryOneSql<{
        phase: string
        kb_overdelete_count: number
        audit_phases_json: string
      }>(
        `SELECT phase, kb_overdelete_count, audit_phases_json
         FROM sample_deletions WHERE id = ?`,
        [result.deletion_id]
      )
    ).toEqual({
      phase: 'completed',
      kb_overdelete_count: 1,
      audit_phases_json: JSON.stringify(['start', 'completed']),
    })
    expect(
      database.queryOneSql<{ count: number }>(
        'SELECT COUNT(*) AS count FROM sample_operation_leases'
      )?.count
    ).toBe(0)
    expect(fs.existsSync(path.join(workspaceRoot, SHA.slice(0, 2), SHA.slice(2, 4), SHA))).toBe(
      false
    )
    expect(fs.existsSync(path.join(ghidraProjectRoot, SHA))).toBe(false)
    expect(fs.existsSync(path.join(ghidraLogRoot, SHA))).toBe(false)
    const auditEvents = fs
      .readFileSync(policy.getAuditLogPath(), 'utf8')
      .trim()
      .split('\n')
      .map(
        (line) => JSON.parse(line) as { metadata: { phase: string; kb_overdelete_count?: number } }
      )
    expect(auditEvents.map((event) => event.metadata.phase)).toEqual(['start', 'completed'])
    expect(auditEvents[1]?.metadata.kb_overdelete_count).toBe(1)
  })

  test('removes a late context writer lease in the atomic database cleanup', async () => {
    await seedSample()
    service = createService((phase) => {
      if (phase !== 'cache_purged') return
      const now = new Date().toISOString()
      database.runSql(
        `INSERT INTO context_write_leases
         (lock_key, owner_token, host_id, pid, acquired_at, heartbeat_at)
         VALUES (?, 'late-owner', 'test-host', 1, ?, ?)`,
        [`analysis-case-state:${SAMPLE_ID}:case-1`, now, now]
      )
    })
    await expect(
      service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
    ).resolves.toEqual(expect.objectContaining({ outcome: 'deleted' }))
    expect(
      database.queryOneSql<{ count: number }>('SELECT COUNT(*) AS count FROM context_write_leases')
        ?.count
    ).toBe(0)
  })

  test.each([
    'prepared',
    'workspace_quarantined',
    'cache_purged',
    'db_deleted',
    'files_purged',
    'completed',
  ])('restart recovery converges after a crash at %s', async (crashPhase) => {
    await seedSample()
    service = createService((phase) => {
      if (phase === crashPhase) throw new Error(`crash injection: ${crashPhase}`)
    })
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      `crash injection: ${crashPhase}`
    )

    gate.close()
    gate = new SampleOperationGate(database, {
      instanceId: 'recovery-instance',
      bootId: 'test-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    service = createService()
    await expect(service.recoverPendingDeletions()).resolves.toEqual({
      recovered: 1,
      skipped: 0,
      failed: 0,
    })
    expect(database.findSample(SAMPLE_ID)).toBeUndefined()
    expect(
      database.queryOneSql<{ phase: string; audit_phases_json: string }>(
        `SELECT phase, audit_phases_json FROM sample_deletions
         WHERE sample_id = ? ORDER BY created_at DESC LIMIT 1`,
        [SAMPLE_ID]
      )
    ).toEqual(
      expect.objectContaining({
        phase: 'completed',
        audit_phases_json: expect.stringContaining('"completed"'),
      })
    )
  })

  test('does not steal an exclusive journal from a live process instance', async () => {
    await seedSample()
    service = createService((phase) => {
      if (phase === 'prepared') throw new Error('owner paused after prepare')
    })
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      'owner paused after prepare'
    )

    const ownerGate = gate
    gate = new SampleOperationGate(database, {
      instanceId: 'contender-instance',
      bootId: 'test-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    service = createService()
    await expect(service.recoverPendingDeletions()).resolves.toEqual({
      recovered: 0,
      skipped: 1,
      failed: 0,
    })
    expect(
      database.queryOneSql<{ instance_id: string }>(
        `SELECT instance_id FROM sample_operation_leases
         WHERE sample_id = ? AND mode = 'exclusive'`,
        [SAMPLE_ID]
      )?.instance_id
    ).toBe('test-instance')

    ownerGate.close()
    await expect(service.recoverPendingDeletions()).resolves.toEqual({
      recovered: 1,
      skipped: 0,
      failed: 0,
    })
    expect(database.findSample(SAMPLE_ID)).toBeUndefined()
  })

  test('keeps purge ownership while an async helper runs longer than the instance TTL', async () => {
    if (process.platform !== 'linux') return
    const now = new Date().toISOString()
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: SHA,
      md5: null,
      size: 7,
      file_type: 'PE',
      created_at: now,
      source: 'slow-purge-test',
    })
    const sampleWorkspace = await workspace.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(sampleWorkspace.original, 'sample.exe'), 'payload')
    gate.close()
    gate = new SampleOperationGate(database, {
      instanceId: 'slow-purge-owner',
      bootId: 'slow-purge-boot',
      sharedLeaseTtlMs: 300,
      instanceTtlMs: 300,
    })
    let signalDatabaseDeleted: (() => void) | undefined
    const databaseDeleted = new Promise<void>((resolve) => {
      signalDatabaseDeleted = resolve
    })
    service = new SampleDeletionService(database, workspace, storage, cache, policy, gate, {
      ghidraProjectRoot,
      ghidraLogRoot,
      purgeChunkDelayMs: 600,
      onPhase: (phase) => {
        if (phase === 'db_deleted') signalDatabaseDeleted?.()
      },
    })

    const deletion = service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })
    await databaseDeleted
    await new Promise((resolve) => setTimeout(resolve, 450))
    expect(
      database.queryOneSql<{ lease_until: string }>(
        `SELECT lease_until FROM sample_operation_instances WHERE instance_id = ?`,
        [gate.instanceId]
      )?.lease_until
    ).toBeDefined()
    expect(
      Date.parse(
        database.queryOneSql<{ lease_until: string }>(
          `SELECT lease_until FROM sample_operation_instances WHERE instance_id = ?`,
          [gate.instanceId]
        )!.lease_until
      )
    ).toBeGreaterThan(Date.now())

    const contenderGate = new SampleOperationGate(database, {
      instanceId: 'slow-purge-contender',
      bootId: 'slow-purge-contender-boot',
      sharedLeaseTtlMs: 300,
      instanceTtlMs: 300,
      startHeartbeat: false,
    })
    try {
      const contender = new SampleDeletionService(
        database,
        workspace,
        storage,
        cache,
        policy,
        contenderGate,
        { ghidraProjectRoot, ghidraLogRoot }
      )
      await expect(contender.recoverPendingDeletions()).resolves.toEqual({
        recovered: 0,
        skipped: 1,
        failed: 0,
      })
      await expect(deletion).resolves.toEqual(expect.objectContaining({ outcome: 'deleted' }))
    } finally {
      contenderGate.close()
    }
  }, 30_000)

  test('a stale deletion owner cannot advance phase or write errors after takeover', async () => {
    await seedSample()
    const deletionId = crypto.randomUUID()
    ;(service as any).prepareJournal({
      deletionId,
      sampleId: SAMPLE_ID,
      sha256: SHA,
      reason: 'takeover fence test',
    })
    const contenderGate = new SampleOperationGate(database, {
      instanceId: 'phase-takeover-instance',
      bootId: 'phase-takeover-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    try {
      database.runSql(
        `UPDATE sample_operation_leases
         SET instance_id = ?, boot_id = ?, heartbeat_at = ?
         WHERE sample_id = ? AND lease_token = ? AND mode = 'exclusive'`,
        [
          contenderGate.instanceId,
          contenderGate.bootId,
          new Date().toISOString(),
          SAMPLE_ID,
          deletionId,
        ]
      )

      await expect((service as any).runJournal(deletionId)).rejects.toThrow(/ownership was lost/i)
      expect(
        database.queryOneSql<{ phase: string; error: string | null; audit_phases_json: string }>(
          `SELECT phase, error, audit_phases_json FROM sample_deletions WHERE id = ?`,
          [deletionId]
        )
      ).toEqual({ phase: 'prepared', error: null, audit_phases_json: '["start"]' })
    } finally {
      contenderGate.close()
    }
  })

  test('refuses a symlink at any target level without touching the outside sentinel', async () => {
    await seedSample()
    const outside = path.join(root, 'outside-sentinel')
    fs.writeFileSync(outside, 'keep')
    const sampleWorkspace = await workspace.getWorkspace(SAMPLE_ID)
    fs.symlinkSync(outside, path.join(sampleWorkspace.reports, 'escape-link'))
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      /symlink/i
    )
    expect(fs.readFileSync(outside, 'utf8')).toBe('keep')
    expect(database.findSample(SAMPLE_ID)).toBeDefined()
  })

  test('refuses a broken symlink recorded as an artifact target', async () => {
    await seedSample()
    const artifactPath = database.findArtifacts(SAMPLE_ID)[0]?.path
    expect(artifactPath).toBeDefined()
    fs.unlinkSync(artifactPath!)
    fs.symlinkSync(path.join(root, 'missing-outside-target'), artifactPath!)
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      /symlink/i
    )
    expect(fs.lstatSync(artifactPath!).isSymbolicLink()).toBe(true)
    expect(database.findSample(SAMPLE_ID)).toBeDefined()
  })

  test('refuses hard-linked files and preserves both names', async () => {
    await seedSample()
    const artifactPath = database.findArtifacts(SAMPLE_ID)[0]?.path
    expect(artifactPath).toBeDefined()
    const outsideLink = path.join(root, 'outside-hardlink')
    fs.linkSync(artifactPath!, outsideLink)
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      /hard-linked/i
    )
    expect(fs.readFileSync(artifactPath!, 'utf8')).toBe('{}')
    expect(fs.readFileSync(outsideLink, 'utf8')).toBe('{}')
    expect(database.findSample(SAMPLE_ID)).toBeDefined()
  })

  test('refuses a symlinked sample date partition', async () => {
    await seedSample()
    const outside = path.join(root, 'outside-date-partition')
    fs.mkdirSync(outside)
    fs.symlinkSync(outside, path.join(storageRoot, 'samples', '2026-08-24'))
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      /symlinked sample partition/i
    )
    expect(database.findSample(SAMPLE_ID)).toBeDefined()
  })

  test('refuses trusted-root retargeting after service construction', async () => {
    await seedSample()
    const originalStorage = path.join(root, 'storage-original')
    const outside = path.join(root, 'retargeted-storage')
    fs.renameSync(storageRoot, originalStorage)
    fs.mkdirSync(outside)
    fs.symlinkSync(outside, storageRoot)
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      /trusted root|retarget/i
    )
    expect(database.findSample(SAMPLE_ID)).toBeDefined()
    expect(fs.existsSync(path.join(originalStorage, 'artifacts', SAMPLE_ID, 'case.json'))).toBe(
      true
    )
  })

  test('fails closed on unjournaled quarantine content and resumes after it is removed', async () => {
    await seedSample()
    service = createService((phase) => {
      if (phase === 'db_deleted') throw new Error('crash before quarantine purge')
    })
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      'crash before quarantine purge'
    )
    const journal = database.queryOneSql<{ id: string }>(
      `SELECT id FROM sample_deletions WHERE sample_id = ? ORDER BY created_at DESC LIMIT 1`,
      [SAMPLE_ID]
    )
    expect(journal).toBeDefined()
    const injected = path.join(storageRoot, '.trash', journal!.id, 'unjournaled.txt')
    fs.writeFileSync(injected, 'must-not-delete')

    gate.close()
    gate = new SampleOperationGate(database, {
      instanceId: 'recovery-instance',
      bootId: 'test-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    service = createService()
    await expect(service.recoverPendingDeletions()).resolves.toEqual({
      recovered: 0,
      skipped: 0,
      failed: 1,
    })
    const claimedInjected = path.join(
      storageRoot,
      '.trash',
      `.purging-${journal!.id}`,
      'unjournaled.txt'
    )
    expect(fs.readFileSync(claimedInjected, 'utf8')).toBe('must-not-delete')
    fs.unlinkSync(claimedInjected)
    await expect(service.recoverPendingDeletions()).resolves.toEqual({
      recovered: 1,
      skipped: 0,
      failed: 0,
    })
  })

  test('rolls back the complete database cleanup transaction on a row failure', async () => {
    await seedSample()
    database.runSql(
      `CREATE TRIGGER test_sample_delete_db_rollback
       BEFORE DELETE ON analyses WHEN OLD.sample_id = '${SAMPLE_ID}'
       BEGIN SELECT RAISE(ABORT, 'injected DB delete failure'); END`
    )
    await expectRejectedWithMessage(
      service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA }),
      /injected DB delete failure/
    )
    expect(database.findSample(SAMPLE_ID)).toBeDefined()
    expect(database.findArtifacts(SAMPLE_ID)).toHaveLength(1)
    expect(
      database.queryOneSql<{ phase: string }>(
        `SELECT phase FROM sample_deletions WHERE sample_id = ? ORDER BY created_at DESC LIMIT 1`,
        [SAMPLE_ID]
      )?.phase
    ).toBe('cache_purged')

    database.runSql('DROP TRIGGER test_sample_delete_db_rollback')
    gate.close()
    gate = new SampleOperationGate(database, {
      instanceId: 'db-recovery-instance',
      bootId: 'test-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    service = createService()
    await expect(service.recoverPendingDeletions()).resolves.toEqual({
      recovered: 1,
      skipped: 0,
      failed: 0,
    })
    expect(database.findSample(SAMPLE_ID)).toBeUndefined()
  })

  test('treats a missing quarantined target as an idempotent crash-recovery state', async () => {
    await seedSample()
    service = createService((phase) => {
      if (phase === 'workspace_quarantined') throw new Error('crash after quarantine')
    })
    await expect(service.deleteSample({ sampleId: SAMPLE_ID, confirmSha256: SHA })).rejects.toThrow(
      'crash after quarantine'
    )
    const journal = database.queryOneSql<{ id: string }>(
      `SELECT id FROM sample_deletions WHERE sample_id = ? ORDER BY created_at DESC LIMIT 1`,
      [SAMPLE_ID]
    )
    const quarantinedWorkspace = path.join(
      workspaceRoot,
      '.trash',
      journal!.id,
      SHA.slice(0, 2),
      SHA.slice(2, 4),
      SHA
    )
    fs.rmSync(quarantinedWorkspace, { recursive: true, force: true })

    gate.close()
    gate = new SampleOperationGate(database, {
      instanceId: 'missing-path-recovery-instance',
      bootId: 'test-boot',
      sharedLeaseTtlMs: 600,
      instanceTtlMs: 1_200,
      startHeartbeat: false,
    })
    service = createService()
    await expect(service.recoverPendingDeletions()).resolves.toEqual({
      recovered: 1,
      skipped: 0,
      failed: 0,
    })
    expect(database.findSample(SAMPLE_ID)).toBeUndefined()
  })

  test('completed deletion is idempotent and the same hash can be re-ingested safely', async () => {
    const payload = Buffer.from('same-hash-reingest-payload')
    const finalizer = createSampleFinalizationService(workspace, database, policy, gate)
    const first = await finalizer.finalizeBuffer({
      data: payload,
      filename: 'reingest.bin',
      source: 'reingest-test',
    })
    await service.deleteSample({
      sampleId: first.sample_id,
      confirmSha256: first.sha256,
    })
    const absent = await service.deleteSample({
      sampleId: first.sample_id,
      confirmSha256: first.sha256,
    })
    expect(absent).toEqual(
      expect.objectContaining({ outcome: 'already_absent', deletion_id: null })
    )
    const second = await finalizer.finalizeBuffer({
      data: payload,
      filename: 'reingest.bin',
      source: 'reingest-test',
    })
    expect(second.sample_id).toBe(first.sample_id)
    expect(second.existed).not.toBe(true)
    const state = database.queryOneSql<{ generation: number; tombstoned: number }>(
      'SELECT generation, tombstoned FROM sample_operation_generations WHERE sample_id = ?',
      [first.sample_id]
    )
    expect(state?.generation).toBeGreaterThanOrEqual(1)
    expect(state?.tombstoned).toBe(0)
  })
})
