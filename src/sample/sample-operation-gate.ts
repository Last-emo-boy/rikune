import fs from 'node:fs'
import os from 'node:os'
import { randomUUID } from 'node:crypto'
import type { DatabaseManager } from '../database.js'

export const CANONICAL_SAMPLE_ID_PATTERN = /^sha256:[a-f0-9]{64}$/

export type SampleOperationLeaseMode = 'shared' | 'exclusive'

export interface SampleOperationBlocker {
  kind:
    | 'job'
    | 'analysis_run'
    | 'analysis_stage'
    | 'debug_session'
    | 'ingest_journal'
    | 'context_lease'
    | 'operation_lease'
  state: string
  count: number
  retry_after_ms: number
}

export interface SampleReferenceSpec {
  /** Exact top-level scalar argument names containing canonical sample IDs. */
  direct?: readonly string[]
  /** Exact top-level array argument names containing canonical sample IDs. */
  arrays?: readonly string[]
  /** Exact top-level foreign-ID arguments resolved through SQLite. */
  foreign?: ReadonlyArray<{
    field: string
    relation:
      | 'analysis_run'
      | 'job'
      | 'artifact'
      | 'debug_session'
      | 'analysis'
      | 'analysis_evidence'
      | 'batch'
  }>
  /** Explicit declaration that this tool cannot reference a persisted sample. */
  none?: boolean
}

export const DEFAULT_SAMPLE_REFERENCE_SPEC: SampleReferenceSpec = Object.freeze({
  direct: Object.freeze(['sample_id', 'sample_id_a', 'sample_id_b', 'reference_sample_id']),
  arrays: Object.freeze(['sample_ids', 'known_sample_ids', 'reference_sample_ids']),
  foreign: Object.freeze([
    { field: 'run_id', relation: 'analysis_run' as const },
    { field: 'plan_id', relation: 'analysis_run' as const },
    { field: 'job_id', relation: 'job' as const },
    { field: 'artifact_id', relation: 'artifact' as const },
    { field: 'session_id', relation: 'debug_session' as const },
    { field: 'analysis_id', relation: 'analysis' as const },
    { field: 'evidence_id', relation: 'analysis_evidence' as const },
    { field: 'batch_id', relation: 'batch' as const },
  ]),
})

export interface SharedSampleOperationLease {
  readonly mode: 'shared'
  readonly token: string
  readonly instanceId: string
  readonly sampleIds: readonly string[]
  readonly generations: ReadonlyMap<string, number>
  heartbeat(): void
  assertOwned(): void
  release(): void
}

export class SampleOperationBusyError extends Error {
  readonly blockers: SampleOperationBlocker[]

  constructor(blockers: SampleOperationBlocker[]) {
    super('One or more samples are busy.')
    this.name = 'SampleOperationBusyError'
    this.blockers = blockers
  }
}

export class SampleOperationLeaseLostError extends Error {
  constructor(message = 'Sample operation lease ownership was lost.') {
    super(message)
    this.name = 'SampleOperationLeaseLostError'
  }
}

export class SampleTombstonedError extends Error {
  constructor(sampleId: string) {
    super(`Sample is being deleted: ${sampleId}`)
    this.name = 'SampleTombstonedError'
  }
}

function canonicalSampleId(value: unknown): string | null {
  return typeof value === 'string' && CANONICAL_SAMPLE_ID_PATTERN.test(value) ? value : null
}

function readBootId(): string {
  try {
    const bootId = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim()
    if (/^[a-f0-9-]{16,64}$/i.test(bootId)) return bootId.toLowerCase()
  } catch {
    // Non-Linux hosts use a process-scoped boot marker below.
  }
  return `${os.hostname()}:${process.pid}:${Date.now()}:${randomUUID()}`
}

function nowIso(nowMs = Date.now()): string {
  return new Date(nowMs).toISOString()
}

function escapeLike(value: string): string {
  return value.replaceAll('\\', '\\\\').replaceAll('%', '\\%').replaceAll('_', '\\_')
}

/**
 * Cross-process, SQLite-backed sample operation gate.
 *
 * Shared leases are acquired for all referenced samples in one transaction and
 * are never reclaimed merely because their own TTL elapsed: the owning process
 * instance must also have stopped heartbeating. Exclusive deletion leases have
 * no ordinary TTL and can only be transferred by journal recovery.
 */
export class SampleOperationGate {
  readonly instanceId: string
  readonly bootId: string
  readonly sharedLeaseTtlMs: number
  readonly instanceTtlMs: number

  private readonly database: DatabaseManager
  private instanceHeartbeatTimer: NodeJS.Timeout | null = null
  private closed = false

  constructor(
    database: DatabaseManager,
    options: {
      instanceId?: string
      bootId?: string
      sharedLeaseTtlMs?: number
      instanceTtlMs?: number
      startHeartbeat?: boolean
    } = {}
  ) {
    this.database = database
    this.instanceId = options.instanceId ?? randomUUID()
    this.bootId = options.bootId ?? readBootId()
    this.sharedLeaseTtlMs = options.sharedLeaseTtlMs ?? 30_000
    this.instanceTtlMs = options.instanceTtlMs ?? 60_000
    if (
      !Number.isSafeInteger(this.sharedLeaseTtlMs) ||
      this.sharedLeaseTtlMs < 300 ||
      !Number.isSafeInteger(this.instanceTtlMs) ||
      this.instanceTtlMs < this.sharedLeaseTtlMs
    ) {
      throw new Error('Invalid sample operation lease TTL configuration.')
    }
    this.registerInstance()
    if (options.startHeartbeat !== false) this.startInstanceHeartbeat()
  }

  private registerInstance(nowMs = Date.now()): void {
    const now = nowIso(nowMs)
    this.database
      .getDb()
      .prepare(
        `INSERT INTO sample_operation_instances
        (instance_id, boot_id, pid, started_at, heartbeat_at, lease_until)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(instance_id) DO UPDATE SET
         boot_id = excluded.boot_id,
         pid = excluded.pid,
         heartbeat_at = excluded.heartbeat_at,
         lease_until = excluded.lease_until`
      )
      .run(this.instanceId, this.bootId, process.pid, now, now, nowIso(nowMs + this.instanceTtlMs))
  }

  private startInstanceHeartbeat(): void {
    const intervalMs = Math.max(100, Math.floor(this.instanceTtlMs / 3))
    this.instanceHeartbeatTimer = setInterval(() => {
      if (this.closed) return
      try {
        this.registerInstance()
      } catch {
        // Every guarded commit also checks the instance and generation. A failed
        // background heartbeat therefore cannot silently authorize persistence.
      }
    }, intervalMs)
    this.instanceHeartbeatTimer.unref()
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    if (this.instanceHeartbeatTimer) clearInterval(this.instanceHeartbeatTimer)
    this.instanceHeartbeatTimer = null
    const db = this.database.getDb()
    const release = db.transaction(() => {
      const closedAt = nowIso()
      db.prepare(
        `DELETE FROM sample_operation_leases
         WHERE instance_id = ? AND mode = 'shared'`
      ).run(this.instanceId)
      // An exclusive journal survives graceful shutdown, but the owner
      // instance must be marked unrecoverable so startup recovery can take it
      // over immediately instead of waiting for the ordinary heartbeat TTL.
      db.prepare(
        `UPDATE sample_operation_instances
         SET heartbeat_at = ?, lease_until = ? WHERE instance_id = ?`
      ).run(closedAt, closedAt, this.instanceId)
      db.prepare(
        `DELETE FROM sample_operation_instances
         WHERE instance_id = ? AND NOT EXISTS (
           SELECT 1 FROM sample_operation_leases
           WHERE instance_id = sample_operation_instances.instance_id
         )`
      ).run(this.instanceId)
    })
    release()
  }

  /** Resolve the exact, declared argument paths and foreign IDs to a sorted set. */
  resolveSampleReferences(args: Record<string, unknown>, spec: SampleReferenceSpec): Set<string> {
    if (spec.none) return new Set()
    const sampleIds = new Set<string>()

    for (const field of spec.direct ?? []) {
      const value = args[field]
      if (value === undefined || value === null) continue
      const sampleId = canonicalSampleId(value)
      if (!sampleId) throw new Error(`Invalid canonical sample reference in ${field}.`)
      sampleIds.add(sampleId)
    }

    for (const field of spec.arrays ?? []) {
      const value = args[field]
      if (value === undefined || value === null) continue
      if (!Array.isArray(value)) throw new Error(`Sample reference ${field} must be an array.`)
      for (const item of value) {
        const sampleId = canonicalSampleId(item)
        if (!sampleId) throw new Error(`Invalid canonical sample reference in ${field}.`)
        sampleIds.add(sampleId)
      }
    }

    const db = this.database.getDb()
    for (const foreign of spec.foreign ?? []) {
      const raw = args[foreign.field]
      if (raw === undefined || raw === null) continue
      if (typeof raw !== 'string' || raw.length === 0 || raw.length > 512) {
        throw new Error(`Invalid foreign sample reference in ${foreign.field}.`)
      }
      const rows = this.resolveForeignReference(db, foreign.relation, raw)
      for (const row of rows) {
        const sampleId = canonicalSampleId(row.sample_id)
        if (!sampleId) throw new Error(`Corrupt sample reference resolved from ${foreign.field}.`)
        sampleIds.add(sampleId)
      }
    }

    return new Set([...sampleIds].sort())
  }

  private resolveForeignReference(
    db: ReturnType<DatabaseManager['getDb']>,
    relation: NonNullable<SampleReferenceSpec['foreign']>[number]['relation'],
    id: string
  ): Array<{ sample_id: string }> {
    switch (relation) {
      case 'analysis_run':
        return db.prepare('SELECT sample_id FROM analysis_runs WHERE id = ?').all(id) as Array<{
          sample_id: string
        }>
      case 'job':
        return db.prepare('SELECT sample_id FROM jobs WHERE id = ?').all(id) as Array<{
          sample_id: string
        }>
      case 'artifact':
        return db.prepare('SELECT sample_id FROM artifacts WHERE id = ?').all(id) as Array<{
          sample_id: string
        }>
      case 'debug_session':
        return db.prepare('SELECT sample_id FROM debug_sessions WHERE id = ?').all(id) as Array<{
          sample_id: string
        }>
      case 'analysis':
        return db.prepare('SELECT sample_id FROM analyses WHERE id = ?').all(id) as Array<{
          sample_id: string
        }>
      case 'analysis_evidence':
        return db.prepare('SELECT sample_id FROM analysis_evidence WHERE id = ?').all(id) as Array<{
          sample_id: string
        }>
      case 'batch':
        return db
          .prepare('SELECT sample_id FROM batch_samples WHERE batch_id = ?')
          .all(id) as Array<{
          sample_id: string
        }>
    }
  }

  acquireShared(sampleIdsInput: Iterable<string>): SharedSampleOperationLease {
    if (this.closed) throw new Error('Sample operation gate is closed.')
    const sampleIds = [...new Set(sampleIdsInput)].sort()
    for (const sampleId of sampleIds) {
      if (!CANONICAL_SAMPLE_ID_PATTERN.test(sampleId)) {
        throw new Error(`Invalid canonical sample ID: ${sampleId}`)
      }
    }
    const token = randomUUID()
    const generations = new Map<string, number>()
    const db = this.database.getDb()
    const acquire = db.transaction(() => {
      const nowMs = Date.now()
      this.registerInstance(nowMs)
      this.reapProvablyDeadSharedLeases(nowMs)
      const now = nowIso(nowMs)
      const leaseUntil = nowIso(nowMs + this.sharedLeaseTtlMs)

      for (const sampleId of sampleIds) {
        db.prepare(
          `INSERT OR IGNORE INTO sample_operation_generations
            (sample_id, generation, tombstoned, deletion_id, updated_at)
           VALUES (?, 0, 0, NULL, ?)`
        ).run(sampleId, now)
        const state = db
          .prepare(
            `SELECT generation, tombstoned
           FROM sample_operation_generations WHERE sample_id = ?`
          )
          .get(sampleId) as { generation: number; tombstoned: number }
        if (state.tombstoned === 1) throw new SampleTombstonedError(sampleId)
        const exclusive = db
          .prepare(
            `SELECT 1 FROM sample_operation_leases
           WHERE sample_id = ? AND mode = 'exclusive' LIMIT 1`
          )
          .get(sampleId)
        if (exclusive) {
          throw new SampleOperationBusyError([
            { kind: 'operation_lease', state: 'exclusive', count: 1, retry_after_ms: 0 },
          ])
        }
        db.prepare(
          `INSERT INTO sample_operation_leases
            (sample_id, lease_token, instance_id, boot_id, mode, generation,
             acquired_at, heartbeat_at, lease_until)
           VALUES (?, ?, ?, ?, 'shared', ?, ?, ?, ?)`
        ).run(sampleId, token, this.instanceId, this.bootId, state.generation, now, now, leaseUntil)
        generations.set(sampleId, state.generation)
      }
    })
    acquire.immediate()

    let released = false
    const assertOpen = (): void => {
      if (released) throw new SampleOperationLeaseLostError('Sample operation lease is released.')
    }
    const heartbeat = (): void => {
      assertOpen()
      if (sampleIds.length === 0) return
      const nowMs = Date.now()
      const now = nowIso(nowMs)
      const leaseUntil = nowIso(nowMs + this.sharedLeaseTtlMs)
      const refresh = db.transaction(() => {
        this.registerInstance(nowMs)
        for (const sampleId of sampleIds) {
          const generation = generations.get(sampleId)
          const result = db
            .prepare(
              `UPDATE sample_operation_leases
             SET heartbeat_at = ?, lease_until = ?
             WHERE sample_id = ? AND lease_token = ? AND instance_id = ?
               AND mode = 'shared' AND generation = ?
               AND EXISTS (
                 SELECT 1 FROM sample_operation_generations s
                 WHERE s.sample_id = sample_operation_leases.sample_id
                   AND s.generation = sample_operation_leases.generation
                   AND s.tombstoned = 0
               )`
            )
            .run(now, leaseUntil, sampleId, token, this.instanceId, generation)
          if (result.changes !== 1) throw new SampleOperationLeaseLostError()
        }
      })
      refresh.immediate()
    }
    const release = (): void => {
      if (released) return
      released = true
      db.prepare(
        `DELETE FROM sample_operation_leases
         WHERE lease_token = ? AND instance_id = ? AND mode = 'shared'`
      ).run(token, this.instanceId)
    }

    return {
      mode: 'shared',
      token,
      instanceId: this.instanceId,
      sampleIds,
      generations,
      heartbeat,
      assertOwned: heartbeat,
      release,
    }
  }

  /**
   * Re-open a completed tombstone for a same-hash ingest, then acquire the
   * normal shared lease. Pending journals and exclusive leases remain blocked.
   */
  acquireIngestLease(sampleId: string): SharedSampleOperationLease {
    if (!CANONICAL_SAMPLE_ID_PATTERN.test(sampleId)) throw new Error('Invalid sample ID.')
    const db = this.database.getDb()
    const revive = db.transaction(() => {
      const state = db
        .prepare(
          `SELECT generation, tombstoned, deletion_id
         FROM sample_operation_generations WHERE sample_id = ?`
        )
        .get(sampleId) as
        | { generation: number; tombstoned: number; deletion_id: string | null }
        | undefined
      if (!state || state.tombstoned === 0) return
      const completed = state.deletion_id
        ? db
            .prepare(
              `SELECT 1 FROM sample_deletions
             WHERE id = ? AND phase = 'completed' LIMIT 1`
            )
            .get(state.deletion_id)
        : undefined
      const exclusive = db
        .prepare(
          `SELECT 1 FROM sample_operation_leases
         WHERE sample_id = ? AND mode = 'exclusive' LIMIT 1`
        )
        .get(sampleId)
      if (!completed || exclusive) throw new SampleTombstonedError(sampleId)
      db.prepare(
        `UPDATE sample_operation_generations
         SET tombstoned = 0, deletion_id = NULL, updated_at = ?
         WHERE sample_id = ? AND generation = ? AND tombstoned = 1`
      ).run(nowIso(), sampleId, state.generation)
    })
    revive.immediate()
    return this.acquireShared([sampleId])
  }

  private reapProvablyDeadSharedLeases(nowMs: number): number {
    const result = this.database
      .getDb()
      .prepare(
        `DELETE FROM sample_operation_leases
       WHERE mode = 'shared'
         AND lease_until IS NOT NULL
         AND lease_until <= ?
         AND NOT EXISTS (
           SELECT 1 FROM sample_operation_instances i
           WHERE i.instance_id = sample_operation_leases.instance_id
             AND i.boot_id = sample_operation_leases.boot_id
             AND i.lease_until > ?
         )`
      )
      .run(nowIso(nowMs), nowIso(nowMs))
    return result.changes
  }

  collectBlockers(sampleId: string): SampleOperationBlocker[] {
    if (!CANONICAL_SAMPLE_ID_PATTERN.test(sampleId)) throw new Error('Invalid sample ID.')
    const db = this.database.getDb()
    const nowMs = Date.now()
    this.reapProvablyDeadSharedLeases(nowMs)
    const rows: SampleOperationBlocker[] = []
    const contextStaleBefore = nowIso(nowMs - 10 * 60 * 1000)
    const escapedSampleId = escapeLike(sampleId)
    db.prepare(
      `DELETE FROM context_write_leases
       WHERE heartbeat_at <= ? AND (
         lock_key = ? OR lock_key LIKE ? ESCAPE '\\'
       )`
    ).run(
      contextStaleBefore,
      `analysis-claim-ledger:${sampleId}`,
      `analysis-case-state:${escapedSampleId}:%`
    )
    const addGrouped = (
      kind: SampleOperationBlocker['kind'],
      query: string,
      params: unknown[]
    ): void => {
      for (const row of db.prepare(query).all(...params) as Array<{
        state: string
        count: number
      }>) {
        rows.push({ kind, state: row.state, count: row.count, retry_after_ms: 0 })
      }
    }

    addGrouped(
      'job',
      `SELECT status AS state, COUNT(*) AS count FROM jobs
       WHERE sample_id = ? AND status IN ('queued','retry_wait','running','cancelling') GROUP BY status`,
      [sampleId]
    )
    addGrouped(
      'analysis_run',
      `SELECT status AS state, COUNT(*) AS count FROM analysis_runs
       WHERE sample_id = ? AND (
         status IN ('queued','running') OR (status = 'partial' AND finished_at IS NULL)
       ) GROUP BY status`,
      [sampleId]
    )
    addGrouped(
      'analysis_stage',
      `SELECT s.status AS state, COUNT(*) AS count
       FROM analysis_run_stages s JOIN analysis_runs r ON r.id = s.run_id
       WHERE r.sample_id = ? AND (
         s.status IN ('queued','running') OR (s.status = 'partial' AND s.finished_at IS NULL)
       ) GROUP BY s.status`,
      [sampleId]
    )
    addGrouped(
      'debug_session',
      `SELECT CASE
          WHEN debug_state IN ('planned','armed','capturing','approval_gated') THEN debug_state
          ELSE status
        END AS state, COUNT(*) AS count
       FROM debug_sessions
       WHERE sample_id = ? AND (
         status IN ('planned','armed','capturing','approval_gated') OR
         debug_state IN ('planned','armed','capturing','approval_gated')
       ) GROUP BY state`,
      [sampleId]
    )
    addGrouped(
      'ingest_journal',
      `SELECT phase AS state, COUNT(*) AS count FROM sample_ingests
       WHERE sample_id = ? GROUP BY phase`,
      [sampleId]
    )
    addGrouped(
      'context_lease',
      `SELECT 'live' AS state, COUNT(*) AS count FROM context_write_leases
       WHERE lock_key = ? OR lock_key LIKE ? ESCAPE '\\'
       HAVING COUNT(*) > 0`,
      [`analysis-claim-ledger:${sampleId}`, `analysis-case-state:${escapedSampleId}:%`]
    )
    addGrouped(
      'operation_lease',
      `SELECT mode AS state, COUNT(*) AS count FROM sample_operation_leases
       WHERE sample_id = ? GROUP BY mode`,
      [sampleId]
    )

    const kindOrder: SampleOperationBlocker['kind'][] = [
      'job',
      'analysis_run',
      'analysis_stage',
      'debug_session',
      'ingest_journal',
      'context_lease',
      'operation_lease',
    ]
    return rows
      .sort((a, b) => {
        const byKind = kindOrder.indexOf(a.kind) - kindOrder.indexOf(b.kind)
        return byKind || a.state.localeCompare(b.state)
      })
      .slice(0, 16)
  }

  /** Verify a shared lease at every persistence/filesystem commit boundary. */
  assertSharedLeaseOwned(token: string, sampleId: string, generation: number): void {
    const row = this.database
      .getDb()
      .prepare(
        `SELECT 1 FROM sample_operation_leases l
       JOIN sample_operation_generations s ON s.sample_id = l.sample_id
       JOIN sample_operation_instances i ON i.instance_id = l.instance_id
       WHERE l.sample_id = ? AND l.lease_token = ? AND l.instance_id = ?
         AND l.mode = 'shared' AND l.generation = ?
         AND s.generation = l.generation AND s.tombstoned = 0
         AND l.lease_until > ? AND i.boot_id = l.boot_id AND i.lease_until > ?`
      )
      .get(sampleId, token, this.instanceId, generation, nowIso(), nowIso())
    if (!row) throw new SampleOperationLeaseLostError()
  }
}
