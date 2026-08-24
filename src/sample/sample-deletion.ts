import fs from 'node:fs'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import type { DatabaseManager } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { StorageManager } from '../storage/storage-manager.js'
import type { CacheManager } from '../cache-manager.js'
import type { PolicyGuard } from '../policy-guard.js'
import {
  CANONICAL_SAMPLE_ID_PATTERN,
  SampleOperationBusyError,
  type SampleOperationBlocker,
  type SampleOperationGate,
} from './sample-operation-gate.js'
import { securePurgeQuarantine, secureQuarantineRename } from './secure-filesystem.js'

export type SampleDeletionPhase =
  | 'prepared'
  | 'workspace_quarantined'
  | 'cache_purged'
  | 'db_deleted'
  | 'files_purged'
  | 'completed'

export interface SampleDeletionReclaimed {
  files: number
  bytes: number
  db_rows: number
  kb_rows: number
  cache_entries: number
}

export interface SampleDeletionResult {
  sample_id: string
  outcome: 'deleted' | 'already_absent'
  deletion_id: string | null
  reclaimed: SampleDeletionReclaimed
  completed_at: string
}

interface TrustedRoot {
  key: 'workspace' | 'storage' | 'ghidra_project' | 'ghidra_log'
  path: string
  realPath: string
  device: number
  inode: number
}

interface DeletionManifestEntry {
  root: TrustedRoot['key']
  relative_path: string
  device: number
  inode: number
  type: 'file' | 'directory'
  size: number
  quarantine_target: boolean
}

interface DeletionJournalRow {
  id: string
  sample_id: string
  sample_sha256: string
  generation: number
  phase: SampleDeletionPhase
  manifest_json: string
  reclaimed_json: string
  audit_phases_json: string
  kb_overdelete_count: number
  reason: string | null
  error: string | null
  created_at: string
  updated_at: string
  completed_at: string | null
}

const ZERO_RECLAIMED: SampleDeletionReclaimed = Object.freeze({
  files: 0,
  bytes: 0,
  db_rows: 0,
  kb_rows: 0,
  cache_entries: 0,
})

function parseJson<T>(value: string, fallback: T): T {
  try {
    return JSON.parse(value) as T
  } catch {
    return fallback
  }
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate)
  return (
    relative === '' ||
    (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))
  )
}

function fsyncDirectory(directory: string): void {
  const descriptor = fs.openSync(directory, 'r')
  try {
    fs.fsyncSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
}

function lstatIfExists(candidate: string): fs.Stats | null {
  try {
    return fs.lstatSync(candidate)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
}

function ensureRealDirectory(directory: string): void {
  fs.mkdirSync(directory, { recursive: true })
  const stat = fs.lstatSync(directory)
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Deletion directory is not a real directory: ${directory}`)
  }
}

function normalizeRelative(relativePath: string): string {
  if (!relativePath || path.isAbsolute(relativePath) || relativePath.includes('\0')) {
    throw new Error('Deletion manifest path must be a non-empty relative path.')
  }
  const normalized = path.normalize(relativePath)
  if (normalized === '..' || normalized.startsWith(`..${path.sep}`)) {
    throw new Error('Deletion manifest path escapes its trusted root.')
  }
  return normalized
}

/**
 * Crash-safe sample deletion orchestrator. All filesystem targets are frozen in
 * the prepared journal before any rename, and every later phase is idempotent.
 */
export class SampleDeletionService {
  private readonly roots: TrustedRoot[]
  private readonly activeRuns = new Map<string, Promise<SampleDeletionResult>>()

  constructor(
    private readonly database: DatabaseManager,
    private readonly workspaceManager: WorkspaceManager,
    private readonly storageManager: StorageManager,
    private readonly cacheManager: CacheManager,
    private readonly policyGuard: PolicyGuard,
    private readonly gate: SampleOperationGate,
    options: {
      ghidraProjectRoot?: string | null
      ghidraLogRoot?: string | null
      onPhase?: (phase: SampleDeletionPhase, deletionId: string) => void
      /** Test-only delay injected inside each secure purge chunk helper. */
      purgeChunkDelayMs?: number
    } = {}
  ) {
    this.onPhase = options.onPhase
    this.purgeChunkDelayMs = options.purgeChunkDelayMs
    const configured: Array<[TrustedRoot['key'], string | null | undefined, boolean]> = [
      ['workspace', workspaceManager.getWorkspaceRoot(), true],
      ['storage', storageManager.getRoot(), true],
      ['ghidra_project', options.ghidraProjectRoot ?? process.env.GHIDRA_PROJECT_ROOT, false],
      ['ghidra_log', options.ghidraLogRoot ?? process.env.GHIDRA_LOG_ROOT, false],
    ]
    this.roots = []
    for (const [key, configuredPath, required] of configured) {
      if (!configuredPath) {
        if (required) throw new Error(`Missing trusted deletion root: ${key}`)
        continue
      }
      const resolved = path.resolve(configuredPath)
      if (!fs.existsSync(resolved)) {
        if (required) throw new Error(`Trusted deletion root does not exist: ${resolved}`)
        continue
      }
      const stat = fs.lstatSync(resolved)
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        throw new Error(`Trusted deletion root is not a real directory: ${resolved}`)
      }
      this.roots.push({
        key,
        path: resolved,
        realPath: fs.realpathSync.native(resolved),
        device: Number(stat.dev),
        inode: Number(stat.ino),
      })
    }
  }

  private readonly onPhase?: (phase: SampleDeletionPhase, deletionId: string) => void
  private readonly purgeChunkDelayMs?: number

  async deleteSample(input: {
    sampleId: string
    confirmSha256: string
    reason?: string
  }): Promise<SampleDeletionResult> {
    if (!CANONICAL_SAMPLE_ID_PATTERN.test(input.sampleId)) {
      throw new Error('Invalid canonical sample ID.')
    }
    const sha256 = input.sampleId.slice('sha256:'.length)
    if (input.confirmSha256 !== sha256) {
      throw new SampleConfirmationMismatchError()
    }

    const inProgress = this.findLatestJournal(input.sampleId, false)
    if (inProgress) {
      const active = this.activeRuns.get(inProgress.id)
      if (active) return active
      await this.takeOverJournal(inProgress)
      return this.runJournalCoalesced(inProgress.id)
    }

    const sample = this.database.findSample(input.sampleId)
    if (!sample) {
      // Linearize the absent fast path with ingest lease acquisition. An
      // ingest that already owns a shared generation fence makes deletion
      // busy; a later ingest begins strictly after this idempotent deletion.
      const confirmAbsent = this.database.getDb().transaction(() => {
        if (this.database.findSample(input.sampleId)) return false
        const blockers = this.gate.collectBlockers(input.sampleId)
        if (blockers.length > 0) throw new SampleOperationBusyError(blockers)
        return true
      })
      let stillAbsent: boolean
      try {
        stillAbsent = confirmAbsent.immediate()
      } catch (error) {
        if (error instanceof SampleOperationBusyError) {
          this.appendAuditFailClosed({
            operation: 'sample.delete',
            sampleId: input.sampleId,
            decision: 'deny',
            reason: 'Sample has active execution or live leases',
            metadata: { phase: 'deny', blockers: error.blockers },
          })
        }
        throw error
      }
      if (!stillAbsent) {
        return this.deleteSample(input)
      }
      const completedAt = new Date().toISOString()
      this.appendAuditFailClosed({
        operation: 'sample.delete',
        sampleId: input.sampleId,
        decision: 'allow',
        reason: 'Sample was already absent',
        metadata: { phase: 'start', outcome: 'already_absent' },
      })
      this.appendAuditFailClosed({
        operation: 'sample.delete',
        sampleId: input.sampleId,
        decision: 'allow',
        reason: 'Idempotent deletion completed',
        metadata: { phase: 'completed', outcome: 'already_absent' },
      })
      return {
        sample_id: input.sampleId,
        outcome: 'already_absent',
        deletion_id: null,
        reclaimed: { ...ZERO_RECLAIMED },
        completed_at: completedAt,
      }
    }

    const deletionId = randomUUID()
    this.appendAuditFailClosed({
      operation: 'sample.delete',
      sampleId: input.sampleId,
      decision: 'allow',
      reason: input.reason || 'User-confirmed deletion started',
      metadata: { phase: 'start', deletion_id: deletionId },
    })

    try {
      this.prepareJournal({
        deletionId,
        sampleId: input.sampleId,
        sha256,
        reason: input.reason,
      })
    } catch (error) {
      if (error instanceof SampleOperationBusyError) {
        this.appendAuditFailClosed({
          operation: 'sample.delete',
          sampleId: input.sampleId,
          decision: 'deny',
          reason: 'Sample has active execution or live leases',
          metadata: { phase: 'deny', blockers: error.blockers },
        })
        throw error
      }
      this.appendAuditFailClosed({
        operation: 'sample.delete',
        sampleId: input.sampleId,
        decision: 'deny',
        reason: 'Deletion preparation failed',
        metadata: {
          phase: 'failure',
          error: error instanceof Error ? error.message : String(error),
        },
      })
      throw error
    }

    try {
      this.onPhase?.('prepared', deletionId)
    } catch (error) {
      const journal = this.loadJournal(deletionId)
      const message = error instanceof Error ? error.message : String(error)
      this.appendJournalAuditOnce(journal, 'failure:prepared', {
        operation: 'sample.delete',
        sampleId: input.sampleId,
        decision: 'deny',
        reason: 'Deletion phase failed and requires journal recovery',
        metadata: { phase: 'failure', deletion_id: deletionId, journal_phase: 'prepared' },
      })
      this.database.runSql(
        `UPDATE sample_deletions
         SET error = ?, updated_at = ?
         WHERE id = ? AND ${this.ownedJournalSql()}`,
        [message.slice(0, 4000), new Date().toISOString(), deletionId, ...this.ownedJournalParams()]
      )
      throw error
    }

    return this.runJournalCoalesced(deletionId)
  }

  /** Resume every non-completed journal before any persisted job is restored. */
  async recoverPendingDeletions(): Promise<{
    recovered: number
    skipped: number
    failed: number
  }> {
    const rows = this.database.querySql<DeletionJournalRow>(
      `SELECT * FROM sample_deletions WHERE phase <> 'completed'
       ORDER BY datetime(created_at) ASC, id ASC`
    )
    let recovered = 0
    let skipped = 0
    let failed = 0
    for (const row of rows) {
      try {
        const active = this.activeRuns.get(row.id)
        if (active) {
          await active
        } else {
          await this.takeOverJournal(row)
          await this.runJournalCoalesced(row.id)
        }
        recovered++
      } catch (error) {
        if (error instanceof SampleOperationBusyError) {
          skipped++
        } else {
          failed++
        }
      }
    }
    // A crash after the completed journal update but before lease release is
    // safe to converge without replaying filesystem or DB phases.
    this.database.runSql(
      `DELETE FROM sample_operation_leases AS lease
       WHERE lease.mode = 'exclusive' AND EXISTS (
         SELECT 1 FROM sample_deletions AS deletion
         WHERE deletion.phase = 'completed'
           AND deletion.sample_id = lease.sample_id
           AND deletion.id = lease.lease_token
           AND deletion.generation = lease.generation
       )`
    )
    return { recovered, skipped, failed }
  }

  private findLatestJournal(
    sampleId: string,
    includeCompleted: boolean
  ): DeletionJournalRow | null {
    const phaseClause = includeCompleted ? '' : ` AND phase <> 'completed'`
    return (
      this.database.queryOneSql<DeletionJournalRow>(
        `SELECT * FROM sample_deletions
         WHERE sample_id = ?${phaseClause}
         ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`,
        [sampleId]
      ) ?? null
    )
  }

  private prepareJournal(input: {
    deletionId: string
    sampleId: string
    sha256: string
    reason?: string
  }): void {
    const db = this.database.getDb()
    const prepare = db.transaction(() => {
      const blockers = this.gate.collectBlockers(input.sampleId)
      if (blockers.length > 0) throw new SampleOperationBusyError(blockers)
      const now = new Date().toISOString()
      db.prepare(
        `INSERT OR IGNORE INTO sample_operation_generations
          (sample_id, generation, tombstoned, deletion_id, updated_at)
         VALUES (?, 0, 0, NULL, ?)`
      ).run(input.sampleId, now)
      db.prepare(
        `UPDATE sample_operation_generations
         SET generation = generation + 1, tombstoned = 1,
             deletion_id = ?, updated_at = ?
         WHERE sample_id = ? AND tombstoned = 0`
      ).run(input.deletionId, now, input.sampleId)
      const state = db
        .prepare(
          `SELECT generation, tombstoned, deletion_id
         FROM sample_operation_generations WHERE sample_id = ?`
        )
        .get(input.sampleId) as {
        generation: number
        tombstoned: number
        deletion_id: string | null
      }
      if (state.tombstoned !== 1 || state.deletion_id !== input.deletionId) {
        throw new SampleOperationBusyError([
          { kind: 'operation_lease', state: 'exclusive', count: 1, retry_after_ms: 0 },
        ])
      }
      db.prepare(
        `INSERT INTO sample_operation_leases
          (sample_id, lease_token, instance_id, boot_id, mode, generation,
           acquired_at, heartbeat_at, lease_until)
         VALUES (?, ?, ?, ?, 'exclusive', ?, ?, ?, NULL)`
      ).run(
        input.sampleId,
        input.deletionId,
        this.gate.instanceId,
        this.gate.bootId,
        state.generation,
        now,
        now
      )
      // Freeze the filesystem inventory only after the exclusive tombstone is
      // established, but before committing it. The SQLite IMMEDIATE
      // transaction makes acquisition + inventory + journal publication one
      // atomic gate: a preparation failure rolls all three back, while another
      // process cannot acquire a shared lease during the inventory window.
      const manifest = this.buildManifest(input.sampleId, input.sha256)
      db.prepare(
        `INSERT INTO sample_deletions
          (id, sample_id, sample_sha256, generation, phase, manifest_json,
           reclaimed_json, audit_phases_json, reason, error, created_at, updated_at, completed_at)
         VALUES (?, ?, ?, ?, 'prepared', ?, ?, ?, ?, NULL, ?, ?, NULL)`
      ).run(
        input.deletionId,
        input.sampleId,
        input.sha256,
        state.generation,
        JSON.stringify(manifest),
        JSON.stringify(ZERO_RECLAIMED),
        JSON.stringify(['start']),
        input.reason ?? null,
        now,
        now
      )
    })
    prepare.immediate()
  }

  private async takeOverJournal(row: DeletionJournalRow): Promise<void> {
    const db = this.database.getDb()
    const takeover = db.transaction(() => {
      const now = new Date().toISOString()
      const generation = db
        .prepare(
          `SELECT generation, tombstoned, deletion_id
         FROM sample_operation_generations WHERE sample_id = ?`
        )
        .get(row.sample_id) as
        | { generation: number; tombstoned: number; deletion_id: string | null }
        | undefined
      if (
        !generation ||
        generation.generation !== row.generation ||
        generation.tombstoned !== 1 ||
        generation.deletion_id !== row.id
      ) {
        throw new Error('Deletion journal generation no longer owns the sample tombstone.')
      }

      const existing = db
        .prepare(
          `SELECT lease_token, instance_id, boot_id
         FROM sample_operation_leases
         WHERE sample_id = ? AND mode = 'exclusive'`
        )
        .get(row.sample_id) as
        | { lease_token: string; instance_id: string; boot_id: string }
        | undefined
      const alreadyOwned =
        existing?.lease_token === row.id &&
        existing.instance_id === this.gate.instanceId &&
        existing.boot_id === this.gate.bootId
      if (!alreadyOwned && existing) {
        const liveOwner = db
          .prepare(
            `SELECT 1 FROM sample_operation_instances
           WHERE instance_id = ? AND boot_id = ? AND lease_until > ?`
          )
          .get(existing.instance_id, existing.boot_id, now)
        if (liveOwner) {
          throw new SampleOperationBusyError([
            { kind: 'operation_lease', state: 'exclusive', count: 1, retry_after_ms: 0 },
          ])
        }
        db.prepare(
          `DELETE FROM sample_operation_leases
           WHERE sample_id = ? AND mode = 'exclusive'
             AND lease_token = ? AND instance_id = ? AND boot_id = ?`
        ).run(row.sample_id, existing.lease_token, existing.instance_id, existing.boot_id)
      }
      if (!alreadyOwned) {
        db.prepare(
          `INSERT INTO sample_operation_leases
            (sample_id, lease_token, instance_id, boot_id, mode, generation,
             acquired_at, heartbeat_at, lease_until)
           VALUES (?, ?, ?, ?, 'exclusive', ?, ?, ?, NULL)`
        ).run(
          row.sample_id,
          row.id,
          this.gate.instanceId,
          this.gate.bootId,
          row.generation,
          now,
          now
        )
      }
      db.prepare(
        `UPDATE sample_operation_generations SET updated_at = ?
         WHERE sample_id = ? AND generation = ? AND tombstoned = 1 AND deletion_id = ?`
      ).run(now, row.sample_id, row.generation, row.id)
    })
    takeover.immediate()
  }

  private runJournalCoalesced(deletionId: string): Promise<SampleDeletionResult> {
    const existing = this.activeRuns.get(deletionId)
    if (existing) return existing
    const run = this.runJournal(deletionId).finally(() => {
      if (this.activeRuns.get(deletionId) === run) this.activeRuns.delete(deletionId)
    })
    this.activeRuns.set(deletionId, run)
    return run
  }

  private async runJournal(deletionId: string): Promise<SampleDeletionResult> {
    try {
      let journal = this.loadJournal(deletionId)
      if (journal.phase === 'prepared') {
        this.assertExclusiveOwned(journal)
        this.quarantineManifest(journal)
        this.advancePhase(journal.id, 'workspace_quarantined')
        this.onPhase?.('workspace_quarantined', journal.id)
        journal = this.loadJournal(deletionId)
      }
      if (journal.phase === 'workspace_quarantined') {
        this.assertExclusiveOwned(journal)
        const cacheEntries = await this.cacheManager.invalidateSampleStrict(journal.sample_sha256)
        this.assertExclusiveOwned(journal)
        const reclaimed = parseJson(journal.reclaimed_json, { ...ZERO_RECLAIMED })
        reclaimed.cache_entries = Math.max(reclaimed.cache_entries, cacheEntries)
        this.advancePhase(journal.id, 'cache_purged', reclaimed)
        this.onPhase?.('cache_purged', journal.id)
        journal = this.loadJournal(deletionId)
      }
      if (journal.phase === 'cache_purged') {
        this.assertExclusiveOwned(journal)
        const reclaimed = this.deleteDatabaseRows(journal)
        this.advancePhase(journal.id, 'db_deleted', reclaimed)
        this.onPhase?.('db_deleted', journal.id)
        journal = this.loadJournal(deletionId)
      }
      if (journal.phase === 'db_deleted') {
        this.assertExclusiveOwned(journal)
        const reclaimed = await this.purgeQuarantine(journal)
        this.advancePhase(journal.id, 'files_purged', reclaimed)
        this.onPhase?.('files_purged', journal.id)
        journal = this.loadJournal(deletionId)
      }
      if (journal.phase === 'files_purged') {
        this.assertExclusiveOwned(journal)
        const reclaimed = parseJson(journal.reclaimed_json, { ...ZERO_RECLAIMED })
        this.appendJournalAuditOnce(journal, 'completed', {
          operation: 'sample.delete',
          sampleId: journal.sample_id,
          decision: 'allow',
          reason: 'Deletion completed',
          metadata: {
            phase: 'completed',
            deletion_id: journal.id,
            reclaimed,
            kb_overdelete_count: journal.kb_overdelete_count,
          },
        })
        this.onPhase?.('completed', journal.id)
        this.completeJournal(journal.id)
        journal = this.loadJournal(deletionId)
      }
      const reclaimed = parseJson(journal.reclaimed_json, { ...ZERO_RECLAIMED })
      return {
        sample_id: journal.sample_id,
        outcome: 'deleted',
        deletion_id: journal.id,
        reclaimed,
        completed_at: journal.completed_at ?? journal.updated_at,
      }
    } catch (error) {
      const journal = this.database.queryOneSql<DeletionJournalRow>(
        'SELECT * FROM sample_deletions WHERE id = ?',
        [deletionId]
      )
      if (journal) {
        const message = error instanceof Error ? error.message : String(error)
        try {
          this.assertExclusiveOwned(journal)
          this.appendJournalAuditOnce(journal, `failure:${journal.phase}`, {
            operation: 'sample.delete',
            sampleId: journal.sample_id,
            decision: 'deny',
            reason: 'Deletion phase failed and requires journal recovery',
            metadata: {
              phase: 'failure',
              deletion_id: journal.id,
              journal_phase: journal.phase,
              error: message,
            },
          })
        } finally {
          this.database.runSql(
            `UPDATE sample_deletions
             SET error = ?, updated_at = ?
             WHERE id = ? AND ${this.ownedJournalSql()}`,
            [
              message.slice(0, 4000),
              new Date().toISOString(),
              journal.id,
              ...this.ownedJournalParams(),
            ]
          )
        }
      }
      throw error
    }
  }

  private loadJournal(deletionId: string): DeletionJournalRow {
    const row = this.database.queryOneSql<DeletionJournalRow>(
      'SELECT * FROM sample_deletions WHERE id = ?',
      [deletionId]
    )
    if (!row) throw new Error('Deletion journal disappeared.')
    return row
  }

  private advancePhase(
    deletionId: string,
    phase: Exclude<SampleDeletionPhase, 'prepared' | 'completed'>,
    reclaimed?: SampleDeletionReclaimed
  ): void {
    const expectedPhase: Record<
      Exclude<SampleDeletionPhase, 'prepared' | 'completed'>,
      SampleDeletionPhase
    > = {
      workspace_quarantined: 'prepared',
      cache_purged: 'workspace_quarantined',
      db_deleted: 'cache_purged',
      files_purged: 'db_deleted',
    }
    const fields = reclaimed
      ? 'phase = ?, reclaimed_json = ?, error = NULL, updated_at = ?'
      : 'phase = ?, error = NULL, updated_at = ?'
    const params = reclaimed
      ? [
          phase,
          JSON.stringify(reclaimed),
          new Date().toISOString(),
          deletionId,
          expectedPhase[phase],
          ...this.ownedJournalParams(),
        ]
      : [
          phase,
          new Date().toISOString(),
          deletionId,
          expectedPhase[phase],
          ...this.ownedJournalParams(),
        ]
    const result = this.database
      .getDb()
      .prepare(
        `UPDATE sample_deletions SET ${fields}
       WHERE id = ? AND phase = ? AND ${this.ownedJournalSql()}`
      )
      .run(...params)
    if (result.changes !== 1) throw new Error('Deletion journal phase ownership was lost.')
  }

  private completeJournal(deletionId: string): void {
    const db = this.database.getDb()
    const complete = db.transaction(() => {
      const now = new Date().toISOString()
      const journal = db.prepare('SELECT * FROM sample_deletions WHERE id = ?').get(deletionId) as
        | DeletionJournalRow
        | undefined
      if (!journal) throw new Error('Deletion journal disappeared during completion.')
      this.assertExclusiveOwned(journal)
      const completed = db
        .prepare(
          `UPDATE sample_deletions
         SET phase = 'completed', completed_at = ?, updated_at = ?, error = NULL
         WHERE id = ? AND phase = 'files_purged'`
        )
        .run(now, now, deletionId)
      if (completed.changes !== 1) throw new Error('Deletion journal completion fence failed.')
      db.prepare(
        `DELETE FROM sample_operation_leases
         WHERE sample_id = ? AND lease_token = ? AND mode = 'exclusive'`
      ).run(journal.sample_id, deletionId)
    })
    complete.immediate()
  }

  private buildManifest(sampleId: string, sha256: string): DeletionManifestEntry[] {
    for (const root of this.roots) this.assertTrustedRoot(root)
    const targets = new Map<string, { root: TrustedRoot; relative: string }>()
    const addTarget = (root: TrustedRoot | undefined, relativePath: string): void => {
      if (!root) return
      const relative = normalizeRelative(relativePath)
      targets.set(`${root.key}:${relative}`, { root, relative })
    }
    const byKey = (key: TrustedRoot['key']): TrustedRoot | undefined =>
      this.roots.find((root) => root.key === key)

    const workspaceRoot = byKey('workspace')
    const storageRoot = byKey('storage')
    addTarget(workspaceRoot, path.join(sha256.slice(0, 2), sha256.slice(2, 4), sha256))

    if (storageRoot) {
      const samplesRoot = path.join(storageRoot.path, 'samples')
      for (const dateEntry of this.readRealDirectoryEntries(samplesRoot)) {
        if (dateEntry.isSymbolicLink()) {
          throw new Error(`Refusing symlinked sample partition: ${dateEntry.name}`)
        }
        if (!dateEntry.isDirectory()) continue
        const datePath = path.join(samplesRoot, dateEntry.name)
        for (const fileEntry of this.readRealDirectoryEntries(datePath)) {
          if (fileEntry.name.startsWith(`${sha256}_`)) {
            addTarget(storageRoot, path.join('samples', dateEntry.name, fileEntry.name))
          }
        }
      }
      addTarget(storageRoot, path.join('artifacts', sampleId))
      addTarget(storageRoot, path.join('artifacts', sha256))
    }

    for (const artifact of this.database.findArtifacts(sampleId)) {
      this.addDatabasePathTarget(targets, artifact.path)
    }
    for (const upload of this.database.querySql<{ staged_path: string | null }>(
      'SELECT staged_path FROM upload_sessions WHERE sample_id = ? AND staged_path IS NOT NULL',
      [sampleId]
    )) {
      if (upload.staged_path) this.addDatabasePathTarget(targets, upload.staged_path)
    }

    for (const rootKey of ['ghidra_project', 'ghidra_log'] as const) {
      const root = byKey(rootKey)
      addTarget(root, sha256)
      addTarget(root, path.join(sha256.slice(0, 2), sha256.slice(2, 4), sha256))
    }

    const existing = [...targets.values()].filter(
      ({ root, relative }) => lstatIfExists(path.join(root.path, relative)) !== null
    )
    existing.sort(
      (a, b) =>
        a.root.key.localeCompare(b.root.key) ||
        a.relative.split(path.sep).length - b.relative.split(path.sep).length ||
        a.relative.localeCompare(b.relative)
    )
    const rootTargets: typeof existing = []
    for (const candidate of existing) {
      const covered = rootTargets.some(
        (parent) =>
          parent.root.key === candidate.root.key &&
          isWithin(
            path.join(parent.root.path, parent.relative),
            path.join(candidate.root.path, candidate.relative)
          )
      )
      if (!covered) rootTargets.push(candidate)
    }

    const manifest: DeletionManifestEntry[] = []
    for (const target of rootTargets) {
      this.assertTrustedRoot(target.root)
      this.walkManifest(target.root, target.relative, target.relative, manifest)
    }
    manifest.sort(
      (a, b) => a.root.localeCompare(b.root) || a.relative_path.localeCompare(b.relative_path)
    )
    return manifest
  }

  private readRealDirectoryEntries(directory: string): fs.Dirent[] {
    if (!fs.existsSync(directory)) return []
    const stat = fs.lstatSync(directory)
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`Refusing non-directory or symlink during deletion inventory: ${directory}`)
    }
    return fs.readdirSync(directory, { withFileTypes: true })
  }

  private addDatabasePathTarget(
    targets: Map<string, { root: TrustedRoot; relative: string }>,
    databasePath: string
  ): void {
    const candidate = path.isAbsolute(databasePath)
      ? path.resolve(databasePath)
      : path.resolve(this.storageManager.getRoot(), databasePath)
    const root = this.roots
      .filter((item) => isWithin(item.path, candidate))
      .sort((a, b) => b.path.length - a.path.length)[0]
    if (!root) throw new Error('Artifact/upload path is outside every trusted deletion root.')
    const relative = normalizeRelative(path.relative(root.path, candidate))
    targets.set(`${root.key}:${relative}`, { root, relative })
  }

  private assertTrustedRoot(root: TrustedRoot): void {
    const stat = fs.lstatSync(root.path)
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`Trusted root was replaced: ${root.path}`)
    }
    if (Number(stat.dev) !== root.device || Number(stat.ino) !== root.inode) {
      throw new Error(`Trusted root identity changed: ${root.path}`)
    }
    if (fs.realpathSync.native(root.path) !== root.realPath) {
      throw new Error(`Trusted root retarget detected: ${root.path}`)
    }
  }

  private walkManifest(
    root: TrustedRoot,
    relativePath: string,
    topLevelRelative: string,
    output: DeletionManifestEntry[]
  ): void {
    const normalized = normalizeRelative(relativePath)
    const absolute = path.join(root.path, normalized)
    this.assertTrustedRoot(root)
    this.assertNoSymlinkComponents(root, normalized)
    const stat = fs.lstatSync(absolute)
    if (stat.isSymbolicLink()) throw new Error(`Refusing symlink in deletion target: ${absolute}`)
    const real = fs.realpathSync.native(absolute)
    if (!isWithin(root.realPath, real))
      throw new Error(`Deletion target escaped trusted root: ${absolute}`)
    if (stat.isFile() && stat.nlink > 1) {
      throw new Error(`Refusing hard-linked deletion target: ${absolute}`)
    }
    if (!stat.isFile() && !stat.isDirectory()) {
      throw new Error(`Refusing unsupported deletion target type: ${absolute}`)
    }
    output.push({
      root: root.key,
      relative_path: normalized,
      device: Number(stat.dev),
      inode: Number(stat.ino),
      type: stat.isDirectory() ? 'directory' : 'file',
      size: stat.isFile() ? stat.size : 0,
      quarantine_target: normalized === topLevelRelative,
    })
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
        this.walkManifest(root, path.join(normalized, entry.name), topLevelRelative, output)
      }
    }
  }

  private assertNoSymlinkComponents(root: TrustedRoot, relativePath: string): void {
    let current = root.path
    for (const part of normalizeRelative(relativePath).split(path.sep)) {
      current = path.join(current, part)
      const stat = fs.lstatSync(current)
      if (stat.isSymbolicLink()) {
        throw new Error(`Refusing symlink component in deletion target: ${current}`)
      }
    }
  }

  private quarantineManifest(journal: DeletionJournalRow): void {
    const manifest = parseJson<DeletionManifestEntry[]>(journal.manifest_json, [])
    for (const entry of manifest.filter((item) => item.quarantine_target)) {
      this.assertExclusiveOwned(journal)
      const root = this.rootFor(entry.root)
      this.assertTrustedRoot(root)
      secureQuarantineRename({
        root: root.path,
        rootDevice: root.device,
        rootInode: root.inode,
        sourceRelative: normalizeRelative(entry.relative_path),
        destinationRelative: path.join(
          '.trash',
          journal.id,
          normalizeRelative(entry.relative_path)
        ),
        expectedDevice: entry.device,
        expectedInode: entry.inode,
        expectedType: entry.type,
      })
      this.assertExclusiveOwned(journal)
    }
    this.workspaceManager.clearWorkspaceCache()
  }

  private deleteDatabaseRows(journal: DeletionJournalRow): SampleDeletionReclaimed {
    const db = this.database.getDb()
    const reclaimed = parseJson(journal.reclaimed_json, { ...ZERO_RECLAIMED })
    const deletion = db.transaction(() => {
      this.assertExclusiveOwned(journal)
      let dbRows = reclaimed.db_rows
      let kbRows = reclaimed.kb_rows
      const run = (sql: string, ...params: unknown[]): number => {
        const changes = db.prepare(sql).run(...params).changes
        dbRows += changes
        return changes
      }

      run('DELETE FROM scheduler_events WHERE sample_id = ?', journal.sample_id)
      run(
        `DELETE FROM analysis_run_stages WHERE run_id IN
          (SELECT id FROM analysis_runs WHERE sample_id = ?)`,
        journal.sample_id
      )
      run('DELETE FROM debug_sessions WHERE sample_id = ?', journal.sample_id)
      run('DELETE FROM analyses WHERE sample_id = ?', journal.sample_id)
      run('DELETE FROM analysis_evidence WHERE sample_id = ?', journal.sample_id)
      run('DELETE FROM functions WHERE sample_id = ?', journal.sample_id)
      run('DELETE FROM artifacts WHERE sample_id = ?', journal.sample_id)
      run('DELETE FROM upload_sessions WHERE sample_id = ?', journal.sample_id)
      run('DELETE FROM jobs WHERE sample_id = ?', journal.sample_id)

      const sampleKbRows = db
        .prepare('DELETE FROM sample_kb WHERE sample_id = ?')
        .run(journal.sample_id).changes
      kbRows += sampleKbRows

      let kbOverdeleteCount = journal.kb_overdelete_count
      const functionKbRows = db
        .prepare(
          `SELECT id, samples_json FROM function_kb
         WHERE EXISTS (
           SELECT 1 FROM json_each(function_kb.samples_json)
           WHERE json_each.value = ? OR json_each.value = ?
         )`
        )
        .all(journal.sample_id, journal.sample_sha256) as Array<{
        id: string
        samples_json: string
      }>
      for (const row of functionKbRows) {
        const linkedSamples = parseJson<unknown[]>(row.samples_json, [])
        if (
          linkedSamples.some(
            (value) => value !== journal.sample_id && value !== journal.sample_sha256
          )
        ) {
          kbOverdeleteCount++
        }
        kbRows += db
          .prepare(
            `DELETE FROM kb_index WHERE entry_id = ?
             OR (entry_type = 'function_kb' AND entry_id = ?)`
          )
          .run(row.id, row.id).changes
        kbRows += db.prepare('DELETE FROM function_kb WHERE id = ?').run(row.id).changes
      }

      run('DELETE FROM cache WHERE sample_sha256 = ?', journal.sample_sha256)
      run(
        `DELETE FROM context_write_leases
         WHERE lock_key = ? OR lock_key LIKE ? ESCAPE '\\'`,
        `analysis-claim-ledger:${journal.sample_id}`,
        `analysis-case-state:${journal.sample_id.replaceAll('\\', '\\\\').replaceAll('%', '\\%').replaceAll('_', '\\_')}:%`
      )
      run('DELETE FROM analysis_runs WHERE sample_id = ?', journal.sample_id)

      const affectedBatches = db
        .prepare('SELECT DISTINCT batch_id FROM batch_samples WHERE sample_id = ?')
        .all(journal.sample_id) as Array<{ batch_id: string }>
      run('DELETE FROM batch_samples WHERE sample_id = ?', journal.sample_id)
      for (const batch of affectedBatches) {
        const counts = db
          .prepare(
            `SELECT COUNT(*) AS total,
                  SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
                  SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
                  SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled
           FROM batch_samples WHERE batch_id = ?`
          )
          .get(batch.batch_id) as {
          total: number
          completed: number | null
          failed: number | null
          cancelled: number | null
        }
        if (counts.total === 0) {
          run('DELETE FROM batches WHERE id = ?', batch.batch_id)
        } else {
          run(
            `UPDATE batches SET total_samples = ?, completed_samples = ?,
             failed_samples = ?, cancelled_samples = ?, updated_at = ? WHERE id = ?`,
            counts.total,
            counts.completed ?? 0,
            counts.failed ?? 0,
            counts.cancelled ?? 0,
            new Date().toISOString(),
            batch.batch_id
          )
        }
      }

      run('DELETE FROM samples WHERE id = ?', journal.sample_id)
      reclaimed.db_rows = dbRows
      reclaimed.kb_rows = kbRows
      const journalUpdate = db
        .prepare(
          `UPDATE sample_deletions SET reclaimed_json = ?,
           kb_overdelete_count = ?, error = NULL, updated_at = ?
         WHERE id = ? AND phase = 'cache_purged'`
        )
        .run(JSON.stringify(reclaimed), kbOverdeleteCount, new Date().toISOString(), journal.id)
      if (journalUpdate.changes !== 1) throw new Error('Deletion database phase fence failed.')
      return reclaimed
    })
    return deletion.immediate()
  }

  private async purgeQuarantine(journal: DeletionJournalRow): Promise<SampleDeletionReclaimed> {
    const manifest = parseJson<DeletionManifestEntry[]>(journal.manifest_json, [])
    const reclaimed = parseJson(journal.reclaimed_json, { ...ZERO_RECLAIMED })
    reclaimed.files = manifest.filter((entry) => entry.type === 'file').length
    reclaimed.bytes = manifest.reduce(
      (sum, entry) => sum + (entry.type === 'file' ? entry.size : 0),
      0
    )
    const rootsWithTargets = new Set(
      manifest.filter((entry) => entry.quarantine_target).map((entry) => entry.root)
    )
    for (const rootKey of rootsWithTargets) {
      this.assertExclusiveOwned(journal)
      const root = this.rootFor(rootKey)
      this.assertTrustedRoot(root)
      await securePurgeQuarantine({
        root: root.path,
        rootDevice: root.device,
        rootInode: root.inode,
        directoryRelative: `.trash/${journal.id}`,
        testDelayMs: this.purgeChunkDelayMs,
        onChunkCommitted: () => this.assertExclusiveOwned(journal),
        entries: manifest
          .filter((entry) => entry.root === root.key)
          .map((entry) => ({
            relativePath: entry.relative_path,
            device: entry.device,
            inode: entry.inode,
            type: entry.type,
            size: entry.size,
            quarantineTarget: entry.quarantine_target,
          })),
      })
      this.assertExclusiveOwned(journal)
    }
    return reclaimed
  }

  private verifyQuarantineTree(
    root: TrustedRoot,
    deletionId: string,
    manifest: DeletionManifestEntry[]
  ): void {
    const deletionTrash = path.join(root.path, '.trash', deletionId)
    const rootEntries = manifest.filter((entry) => entry.root === root.key)
    const expected = new Map(
      rootEntries.map((entry) => [normalizeRelative(entry.relative_path), entry])
    )
    const scaffolds = new Set<string>()
    for (const entry of rootEntries.filter((candidate) => candidate.quarantine_target)) {
      let parent = path.dirname(normalizeRelative(entry.relative_path))
      while (parent !== '.' && parent !== path.dirname(parent)) {
        scaffolds.add(parent)
        parent = path.dirname(parent)
      }
    }

    const walk = (absolute: string, relative: string): void => {
      const stat = fs.lstatSync(absolute)
      if (stat.isSymbolicLink()) throw new Error('Deletion quarantine contains a symlink.')
      const normalized = normalizeRelative(relative)
      const journaled = expected.get(normalized)
      if (journaled) {
        if (
          Number(stat.dev) !== journaled.device ||
          Number(stat.ino) !== journaled.inode ||
          (journaled.type === 'file') !== stat.isFile() ||
          (journaled.type === 'directory') !== stat.isDirectory()
        ) {
          throw new Error('Deletion quarantine inode no longer matches the prepared journal.')
        }
        if (stat.isFile() && stat.nlink > 1) {
          throw new Error('Deletion quarantine contains a hard-linked file.')
        }
      } else if (!scaffolds.has(normalized) || !stat.isDirectory()) {
        throw new Error('Deletion quarantine contains an unjournaled path.')
      }
      if (stat.isDirectory()) {
        for (const child of fs.readdirSync(absolute)) {
          walk(path.join(absolute, child), path.join(normalized, child))
        }
      }
    }

    for (const child of fs.readdirSync(deletionTrash)) {
      walk(path.join(deletionTrash, child), child)
    }
  }

  private rootFor(key: TrustedRoot['key']): TrustedRoot {
    const root = this.roots.find((item) => item.key === key)
    if (!root) throw new Error(`Deletion journal references unavailable trusted root: ${key}`)
    return root
  }

  private assertExclusiveOwned(journal: DeletionJournalRow): void {
    const owned = this.database
      .getDb()
      .prepare(
        `SELECT 1 FROM sample_operation_leases l
       JOIN sample_operation_generations g ON g.sample_id = l.sample_id
       JOIN sample_operation_instances i ON i.instance_id = l.instance_id
       WHERE l.sample_id = ? AND l.lease_token = ? AND l.mode = 'exclusive'
         AND l.instance_id = ? AND l.boot_id = ? AND l.generation = ?
         AND g.generation = l.generation AND g.tombstoned = 1 AND g.deletion_id = ?
         AND i.boot_id = l.boot_id AND i.lease_until > ?`
      )
      .get(
        journal.sample_id,
        journal.id,
        this.gate.instanceId,
        this.gate.bootId,
        journal.generation,
        journal.id,
        new Date().toISOString()
      )
    if (!owned) throw new Error('Deletion exclusive lease ownership was lost.')
  }

  private ownedJournalSql(): string {
    return `EXISTS (
      SELECT 1 FROM sample_operation_leases l
      JOIN sample_operation_generations g ON g.sample_id = l.sample_id
      JOIN sample_operation_instances i ON i.instance_id = l.instance_id
      WHERE l.sample_id = sample_deletions.sample_id
        AND l.lease_token = sample_deletions.id AND l.mode = 'exclusive'
        AND l.instance_id = ? AND l.boot_id = ?
        AND l.generation = sample_deletions.generation
        AND g.generation = l.generation AND g.tombstoned = 1
        AND g.deletion_id = sample_deletions.id
        AND i.boot_id = l.boot_id AND i.lease_until > ?
    )`
  }

  private ownedJournalParams(): [string, string, string] {
    return [this.gate.instanceId, this.gate.bootId, new Date().toISOString()]
  }

  private appendAuditFailClosed(event: {
    operation: string
    sampleId: string
    decision: 'allow' | 'deny'
    reason: string
    metadata: Record<string, unknown>
  }): void {
    const auditPath = this.policyGuard.getAuditLogPath()
    const directory = path.dirname(auditPath)
    ensureRealDirectory(directory)
    const directoryStat = fs.lstatSync(directory)
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      throw new Error('Deletion audit directory is not a real directory.')
    }
    const existing = lstatIfExists(auditPath)
    if (existing && (!existing.isFile() || existing.isSymbolicLink() || existing.nlink > 1)) {
      throw new Error('Deletion audit log is not a trusted single-link file.')
    }
    const encoded = Buffer.from(
      `${JSON.stringify({ timestamp: new Date().toISOString(), ...event })}\n`,
      'utf8'
    )
    const noFollow = (fs.constants as Record<string, number>).O_NOFOLLOW ?? 0
    const descriptor = fs.openSync(
      auditPath,
      fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_WRONLY | noFollow,
      0o600
    )
    try {
      const opened = fs.fstatSync(descriptor)
      if (!opened.isFile() || opened.nlink > 1) {
        throw new Error('Deletion audit descriptor failed identity validation.')
      }
      let offset = 0
      while (offset < encoded.length) {
        const written = fs.writeSync(descriptor, encoded, offset, encoded.length - offset, null)
        if (!Number.isInteger(written) || written <= 0) {
          throw new Error('Deletion audit write made no forward progress.')
        }
        offset += written
      }
      fs.fsyncSync(descriptor)
    } finally {
      fs.closeSync(descriptor)
    }
    fsyncDirectory(directory)
  }

  private appendJournalAuditOnce(
    journal: DeletionJournalRow,
    auditPhase: string,
    event: {
      operation: string
      sampleId: string
      decision: 'allow' | 'deny'
      reason: string
      metadata: Record<string, unknown>
    }
  ): void {
    this.assertExclusiveOwned(journal)
    const phases = parseJson<string[]>(journal.audit_phases_json, [])
    if (phases.includes(auditPhase)) return
    this.appendAuditFailClosed(event)
    this.assertExclusiveOwned(journal)
    phases.push(auditPhase)
    const updated = this.database
      .getDb()
      .prepare(
        `UPDATE sample_deletions SET audit_phases_json = ?, updated_at = ?
       WHERE id = ? AND ${this.ownedJournalSql()}`
      )
      .run(
        JSON.stringify(phases),
        new Date().toISOString(),
        journal.id,
        ...this.ownedJournalParams()
      )
    if (updated.changes !== 1) {
      throw new Error('Deletion journal audit ownership was lost.')
    }
    journal.audit_phases_json = JSON.stringify(phases)
  }
}

export class SampleConfirmationMismatchError extends Error {
  constructor() {
    super('Sample confirmation digest does not match sample_id.')
    this.name = 'SampleConfirmationMismatchError'
  }
}

export function isSampleOperationBusy(error: unknown): error is SampleOperationBusyError {
  return error instanceof SampleOperationBusyError
}

export function deletionFailureBlockers(error: unknown): SampleOperationBlocker[] {
  return isSampleOperationBusy(error) ? error.blockers.slice(0, 16) : []
}
