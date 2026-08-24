/**
 * Database module for Rikune
 * Manages SQLite database schema and operations
 */

import Database from 'better-sqlite3'
import path from 'path'
import fs from 'fs'
import { randomUUID } from 'crypto'
import { logger, logDebug } from '../logger.js'
import { DatabaseError, ErrorCode } from '../errors.js'

const DEFAULT_SQLITE_BUSY_TIMEOUT_MS = 30000

function getSqliteBusyTimeoutMs(): number {
  const raw = process.env.RIKUNE_SQLITE_BUSY_TIMEOUT_MS || process.env.SQLITE_BUSY_TIMEOUT_MS
  if (!raw) {
    return DEFAULT_SQLITE_BUSY_TIMEOUT_MS
  }

  const parsed = Number.parseInt(raw, 10)
  if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 2147483647) {
    return parsed
  }

  logger.warn(
    { value: raw, fallback_ms: DEFAULT_SQLITE_BUSY_TIMEOUT_MS },
    'Invalid SQLite busy timeout; using default'
  )
  return DEFAULT_SQLITE_BUSY_TIMEOUT_MS
}

function isSqliteBusyError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false
  }

  const maybeSqliteError = error as { code?: unknown; message?: unknown }
  return (
    maybeSqliteError.code === 'SQLITE_BUSY' ||
    (typeof maybeSqliteError.message === 'string' &&
      /SQLITE_BUSY|database is locked/i.test(maybeSqliteError.message))
  )
}

// ─── Lightweight query builder ────────────────────────────────────────────────

export interface WhereClause {
  column: string
  op?: '=' | '!=' | '<' | '>' | '<=' | '>=' | 'IN' | 'LIKE' | 'IS NULL' | 'IS NOT NULL'
  value?: unknown
}

/**
 * Lightweight, safe query builder for SELECT queries.
 * Uses parameterised queries exclusively — no string interpolation of values.
 *
 * Usage:
 *   const rows = new QueryBuilder('samples')
 *     .where({ column: 'sha256', value: sha })
 *     .orderBy('created_at', 'DESC')
 *     .limit(10)
 *     .execute<Sample>(db)
 */
export class QueryBuilder {
  private _table: string
  private _columns: string = '*'
  private _wheres: { sql: string; params: unknown[] }[] = []
  private _orderBy: string | null = null
  private _limit: number | null = null
  private _offset: number | null = null

  constructor(table: string) {
    this._table = table
  }

  select(columns: string): this {
    this._columns = columns
    return this
  }

  where(clause: WhereClause): this {
    const op = clause.op ?? '='
    if (op === 'IS NULL' || op === 'IS NOT NULL') {
      this._wheres.push({ sql: `${clause.column} ${op}`, params: [] })
    } else if (op === 'IN') {
      const arr = clause.value as unknown[]
      if (!Array.isArray(arr) || arr.length === 0) {
        // Matching nothing — add impossible condition
        this._wheres.push({ sql: '0 = 1', params: [] })
      } else {
        const placeholders = arr.map(() => '?').join(', ')
        this._wheres.push({ sql: `${clause.column} IN (${placeholders})`, params: arr })
      }
    } else {
      this._wheres.push({ sql: `${clause.column} ${op} ?`, params: [clause.value] })
    }
    return this
  }

  orderBy(column: string, direction: 'ASC' | 'DESC' = 'ASC'): this {
    this._orderBy = `${column} ${direction}`
    return this
  }

  limit(n: number): this {
    this._limit = n
    return this
  }

  offset(n: number): this {
    this._offset = n
    return this
  }

  build(): { sql: string; params: unknown[] } {
    let sql = `SELECT ${this._columns} FROM ${this._table}`
    const params: unknown[] = []

    if (this._wheres.length > 0) {
      sql += ' WHERE ' + this._wheres.map((w) => w.sql).join(' AND ')
      for (const w of this._wheres) params.push(...w.params)
    }

    if (this._orderBy) {
      sql += ` ORDER BY ${this._orderBy}`
    }

    if (this._limit != null) {
      sql += ' LIMIT ?'
      params.push(this._limit)
    }

    if (this._offset != null) {
      sql += ' OFFSET ?'
      params.push(this._offset)
    }

    return { sql, params }
  }

  execute<T>(db: Database.Database): T[] {
    const { sql, params } = this.build()
    const stmt = QueryBuilder.getCachedStatement(db, sql)
    return (params.length > 0 ? stmt.all(...params) : stmt.all()) as T[]
  }

  executeOne<T>(db: Database.Database): T | undefined {
    const { sql, params } = this.build()
    const stmt = QueryBuilder.getCachedStatement(db, sql)
    return (params.length > 0 ? stmt.get(...params) : stmt.get()) as T | undefined
  }

  // ── Prepared statement cache ────────────────────────────────────────────
  private static stmtCache = new Map<string, Database.Statement>()
  private static stmtCacheDb: Database.Database | null = null
  private static readonly STMT_CACHE_MAX = 256

  static getCachedStatement(db: Database.Database, sql: string): Database.Statement {
    // Reset cache if DB instance changed (e.g. after reconnect)
    if (QueryBuilder.stmtCacheDb !== db) {
      QueryBuilder.stmtCache.clear()
      QueryBuilder.stmtCacheDb = db
    }
    let stmt = QueryBuilder.stmtCache.get(sql)
    if (!stmt) {
      // Evict oldest if cache full
      if (QueryBuilder.stmtCache.size >= QueryBuilder.STMT_CACHE_MAX) {
        const oldest = QueryBuilder.stmtCache.keys().next().value
        if (oldest) QueryBuilder.stmtCache.delete(oldest)
      }
      stmt = db.prepare(sql)
      QueryBuilder.stmtCache.set(sql, stmt)
    }
    return stmt
  }
}

// ─── End query builder ────────────────────────────────────────────────────────

/**
 * Database schema SQL statements
 */
const SCHEMA_SQL = `
-- samples 表：存储样本基础信息
CREATE TABLE IF NOT EXISTS samples (
  id TEXT PRIMARY KEY,
  sha256 TEXT UNIQUE NOT NULL,
  md5 TEXT,
  size INTEGER NOT NULL,
  file_type TEXT,
  created_at TEXT NOT NULL,
  source TEXT,
  ingest_lease_token TEXT,
  ingest_generation INTEGER
);

CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples(sha256);
CREATE INDEX IF NOT EXISTS idx_samples_created_at ON samples(created_at);

-- analyses 表：存储分析任务记录
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  backend TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  output_json TEXT,
  metrics_json TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_analyses_sample_stage ON analyses(sample_id, stage);
CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);

-- analysis_runs 表：存储非阻塞 staged analysis run
CREATE TABLE IF NOT EXISTS analysis_runs (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  sample_sha256 TEXT NOT NULL,
  goal TEXT NOT NULL,
  depth TEXT NOT NULL,
  backend_policy TEXT NOT NULL,
  compatibility_marker TEXT NOT NULL,
  pipeline_version TEXT NOT NULL,
  sample_size_tier TEXT,
  analysis_budget_profile TEXT,
  status TEXT NOT NULL,
  latest_stage TEXT,
  stage_plan_json TEXT,
  artifact_refs_json TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT,
  reused_from_run_id TEXT,
  last_accessed_at TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_sample_goal ON analysis_runs(sample_id, goal, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_compatibility ON analysis_runs(sample_id, compatibility_marker, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_status ON analysis_runs(status);

-- analysis_run_stages 表：存储 staged run 的每个阶段状态
CREATE TABLE IF NOT EXISTS analysis_run_stages (
  run_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  status TEXT NOT NULL,
  execution_state TEXT,
  tool TEXT,
  job_id TEXT,
  result_json TEXT,
  artifact_refs_json TEXT,
  coverage_json TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  PRIMARY KEY (run_id, stage),
  FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_run_stages_run ON analysis_run_stages(run_id, stage);
CREATE INDEX IF NOT EXISTS idx_analysis_run_stages_job ON analysis_run_stages(job_id);
CREATE INDEX IF NOT EXISTS idx_analysis_run_stages_status ON analysis_run_stages(status);

-- analysis_evidence 表：存储可复用的规范化分析证据
CREATE TABLE IF NOT EXISTS analysis_evidence (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  sample_sha256 TEXT NOT NULL,
  evidence_family TEXT NOT NULL,
  backend TEXT NOT NULL,
  mode TEXT NOT NULL,
  compatibility_marker TEXT NOT NULL,
  freshness_marker TEXT,
  provenance_json TEXT,
  metadata_json TEXT,
  result_json TEXT NOT NULL,
  artifact_refs_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_accessed_at TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_evidence_sample_family ON analysis_evidence(sample_id, evidence_family, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence_compatibility ON analysis_evidence(sample_id, evidence_family, compatibility_marker, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence_backend ON analysis_evidence(sample_id, backend, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence_sample_order ON analysis_evidence(sample_id, updated_at DESC, created_at DESC, id DESC);

-- debug_sessions 表：存储持久化调试会话状态
CREATE TABLE IF NOT EXISTS debug_sessions (
  id TEXT PRIMARY KEY,
  run_id TEXT,
  sample_id TEXT NOT NULL,
  sample_sha256 TEXT NOT NULL,
  status TEXT NOT NULL,
  debug_state TEXT NOT NULL,
  backend TEXT,
  current_phase TEXT,
  session_tag TEXT,
  artifact_refs_json TEXT,
  guidance_json TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_debug_sessions_run ON debug_sessions(run_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_debug_sessions_sample ON debug_sessions(sample_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_debug_sessions_status ON debug_sessions(status, updated_at DESC);

-- functions 表：存储函数信息
CREATE TABLE IF NOT EXISTS functions (
  sample_id TEXT NOT NULL,
  address TEXT NOT NULL,
  name TEXT,
  size INTEGER,
  score REAL,
  tags TEXT,
  summary TEXT,
  caller_count INTEGER DEFAULT 0,
  callee_count INTEGER DEFAULT 0,
  is_entry_point INTEGER DEFAULT 0,
  is_exported INTEGER DEFAULT 0,
  callees TEXT,
  PRIMARY KEY (sample_id, address),
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(sample_id, name);
CREATE INDEX IF NOT EXISTS idx_functions_score ON functions(sample_id, score DESC);

-- artifacts 表：存储分析产物
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  type TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  mime TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_sample_type ON artifacts(sample_id, type);

-- context_write_leases 表：为 Claim/Case 等 context-only writer 提供跨进程 CAS lease
CREATE TABLE IF NOT EXISTS context_write_leases (
  lock_key TEXT PRIMARY KEY,
  owner_token TEXT NOT NULL,
  host_id TEXT NOT NULL,
  pid INTEGER NOT NULL,
  acquired_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL
);

-- sample_operation_instances 表：证明持有 shared lease 的进程实例仍可恢复
CREATE TABLE IF NOT EXISTS sample_operation_instances (
  instance_id TEXT PRIMARY KEY,
  boot_id TEXT NOT NULL,
  pid INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  lease_until TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sample_operation_instances_lease
  ON sample_operation_instances(lease_until);

-- sample_operation_generations 表：跨删除/重摄取保持单调 fencing generation
CREATE TABLE IF NOT EXISTS sample_operation_generations (
  sample_id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
  tombstoned INTEGER NOT NULL DEFAULT 0 CHECK (tombstoned IN (0, 1)),
  deletion_id TEXT,
  updated_at TEXT NOT NULL
);

-- sample_operation_leases 表：所有 sample 读写与删除的持久化 shared/exclusive gate
CREATE TABLE IF NOT EXISTS sample_operation_leases (
  sample_id TEXT NOT NULL,
  lease_token TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  boot_id TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('shared', 'exclusive')),
  generation INTEGER NOT NULL CHECK (generation >= 0),
  acquired_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  lease_until TEXT,
  PRIMARY KEY (sample_id, lease_token),
  FOREIGN KEY (instance_id) REFERENCES sample_operation_instances(instance_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sample_operation_exclusive
  ON sample_operation_leases(sample_id) WHERE mode = 'exclusive';
CREATE INDEX IF NOT EXISTS idx_sample_operation_leases_instance
  ON sample_operation_leases(instance_id, mode, lease_until);
CREATE INDEX IF NOT EXISTS idx_sample_operation_leases_sample
  ON sample_operation_leases(sample_id, mode, generation);

-- sample_deletions 表：crash-safe 删除状态机与已冻结 quarantine 清单
CREATE TABLE IF NOT EXISTS sample_deletions (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL,
  sample_sha256 TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation > 0),
  phase TEXT NOT NULL CHECK (phase IN (
    'prepared', 'workspace_quarantined', 'cache_purged',
    'db_deleted', 'files_purged', 'completed'
  )),
  manifest_json TEXT NOT NULL,
  reclaimed_json TEXT NOT NULL,
  audit_phases_json TEXT NOT NULL,
  kb_overdelete_count INTEGER NOT NULL DEFAULT 0 CHECK (kb_overdelete_count >= 0),
  reason TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_sample_deletions_recovery
  ON sample_deletions(phase, updated_at);
CREATE INDEX IF NOT EXISTS idx_sample_deletions_sample
  ON sample_deletions(sample_id, created_at DESC);

-- sample_ingests 表：文件发布与 samples 行之间的 crash-recovery journal
CREATE TABLE IF NOT EXISTS sample_ingests (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  md5 TEXT,
  size INTEGER NOT NULL CHECK (size >= 0),
  file_type TEXT,
  filename TEXT NOT NULL,
  temp_name TEXT NOT NULL,
  source TEXT,
  phase TEXT NOT NULL CHECK (phase IN ('prepared', 'fs_committed')),
  file_device INTEGER,
  file_inode INTEGER,
  owner_instance_id TEXT,
  owner_boot_id TEXT,
  owner_token TEXT,
  owner_until TEXT,
  lease_token TEXT,
  generation INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sample_ingests_recovery
  ON sample_ingests(phase, updated_at);

-- upload_sessions 表：存储持久化上传会话
CREATE TABLE IF NOT EXISTS upload_sessions (
  id TEXT PRIMARY KEY,
  token TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL,
  filename TEXT,
  source TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  uploaded_at TEXT,
  staged_path TEXT,
  size INTEGER,
  sha256 TEXT,
  md5 TEXT,
  sample_id TEXT,
  error TEXT,
  metadata_json TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_upload_sessions_token ON upload_sessions(token);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON upload_sessions(status);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_expires_at ON upload_sessions(expires_at);

-- cache 表：存储缓存结果
CREATE TABLE IF NOT EXISTS cache (
  key TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  sample_sha256 TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_cache_expires_at ON cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_cache_sample_sha256 ON cache(sample_sha256);

-- jobs 表：存储异步作业（用于 async job pattern）
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  tool TEXT NOT NULL,
  sample_id TEXT NOT NULL,
  args_json TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 5,
  timeout INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  progress INTEGER DEFAULT 0,
  error TEXT,
  result_json TEXT,
  estimated_duration_ms INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  owner_instance_id TEXT,
  owner_boot_id TEXT,
  claim_token TEXT,
  claim_until TEXT,
  claim_heartbeat_at TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  retry_policy_json TEXT,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_sample ON jobs(sample_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);

-- runtime_worker_family_state 表：存储运行时 worker 池族摘要
CREATE TABLE IF NOT EXISTS runtime_worker_family_state (
  family TEXT NOT NULL,
  compatibility_key TEXT NOT NULL,
  deployment_key TEXT,
  pool_kind TEXT NOT NULL,
  live_workers INTEGER NOT NULL DEFAULT 0,
  idle_workers INTEGER NOT NULL DEFAULT 0,
  busy_workers INTEGER NOT NULL DEFAULT 0,
  unhealthy_workers INTEGER NOT NULL DEFAULT 0,
  warm_reuse_count INTEGER NOT NULL DEFAULT 0,
  cold_start_count INTEGER NOT NULL DEFAULT 0,
  eviction_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_used_at TEXT,
  PRIMARY KEY (family, compatibility_key)
);

CREATE INDEX IF NOT EXISTS idx_runtime_worker_family_state_family ON runtime_worker_family_state(family, updated_at DESC);

-- scheduler_events 表：存储预算调度与延期/准入遥测
CREATE TABLE IF NOT EXISTS scheduler_events (
  id TEXT PRIMARY KEY,
  job_id TEXT,
  run_id TEXT,
  sample_id TEXT,
  tool TEXT,
  stage TEXT,
  execution_bucket TEXT NOT NULL,
  cost_class TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT,
  worker_family TEXT,
  warm_reuse INTEGER,
  cold_start INTEGER,
  metadata_json TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scheduler_events_job_id ON scheduler_events(job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scheduler_events_run_id ON scheduler_events(run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scheduler_events_bucket ON scheduler_events(execution_bucket, created_at DESC);

-- batches 表：存储批量提交元数据
CREATE TABLE IF NOT EXISTS batches (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  total_samples INTEGER NOT NULL,
  completed_samples INTEGER NOT NULL DEFAULT 0,
  failed_samples INTEGER NOT NULL DEFAULT 0,
  cancelled_samples INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_batches_status ON batches(status);
CREATE INDEX IF NOT EXISTS idx_batches_created_at ON batches(created_at);

-- batch_samples 表：存储批量中的样本映射
CREATE TABLE IF NOT EXISTS batch_samples (
  batch_id TEXT NOT NULL,
  sample_id TEXT NOT NULL,
  status TEXT NOT NULL,
  filename TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  artifact_refs_json TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (batch_id, sample_id),
  FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE CASCADE,
  FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_batch_samples_batch ON batch_samples(batch_id);
CREATE INDEX IF NOT EXISTS idx_batch_samples_status ON batch_samples(status);

-- function_kb 表：存储可复用的函数特征与语义
CREATE TABLE IF NOT EXISTS function_kb (
  id TEXT PRIMARY KEY,
  features_apis_json TEXT NOT NULL,
  features_strings_json TEXT NOT NULL,
  features_cfg_shape TEXT NOT NULL,
  features_crypto_constants_json TEXT,
  semantics_name TEXT NOT NULL,
  semantics_explanation TEXT NOT NULL,
  semantics_behavior TEXT NOT NULL,
  semantics_confidence REAL NOT NULL,
  semantics_source TEXT NOT NULL,
  samples_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  user_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_function_kb_name ON function_kb(semantics_name);
CREATE INDEX IF NOT EXISTS idx_function_kb_confidence ON function_kb(semantics_confidence DESC);
CREATE INDEX IF NOT EXISTS idx_function_kb_updated ON function_kb(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_function_kb_confidence_id ON function_kb(semantics_confidence DESC, id ASC);

-- sample_kb 表：存储样本与威胁情报的本地关联
CREATE TABLE IF NOT EXISTS sample_kb (
  id TEXT PRIMARY KEY,
  sample_id TEXT NOT NULL UNIQUE,
  threat_intel_family TEXT,
  threat_intel_campaign TEXT,
  threat_intel_tags_json TEXT,
  threat_intel_attribution TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  user_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_sample_kb_sample ON sample_kb(sample_id);
CREATE INDEX IF NOT EXISTS idx_sample_kb_family ON sample_kb(threat_intel_family);

-- kb_index 表：为后续有界候选检索保存本地特征索引
CREATE TABLE IF NOT EXISTS kb_index (
  id TEXT PRIMARY KEY,
  entry_type TEXT NOT NULL,
  entry_id TEXT NOT NULL,
  api_hash TEXT,
  string_hash TEXT,
  feature_vector_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kb_index_type ON kb_index(entry_type, entry_id);
CREATE INDEX IF NOT EXISTS idx_kb_index_api_hash ON kb_index(api_hash);
CREATE INDEX IF NOT EXISTS idx_kb_index_string_hash ON kb_index(string_hash);
`

/**
 * Database interface types
 */
export interface Sample {
  id: string // sha256:<hex>
  sha256: string
  md5: string | null
  size: number
  file_type: string | null
  created_at: string
  source: string | null
}

export interface SampleIngestJournal {
  id: string
  sample_id: string
  sha256: string
  md5: string | null
  size: number
  file_type: string | null
  filename: string
  temp_name: string
  source: string | null
  phase: 'prepared' | 'fs_committed'
  file_device: number | null
  file_inode: number | null
  owner_instance_id: string | null
  owner_boot_id: string | null
  owner_token: string | null
  owner_until: string | null
  lease_token: string | null
  generation: number | null
  created_at: string
  updated_at: string
}

export interface Analysis {
  id: string // UUID
  sample_id: string // FK -> samples.id
  stage: string // fingerprint/strings/ghidra/dotnet/sandbox
  backend: string // static/ghidra/dotnet/...
  status: string // queued/running/done/failed
  started_at: string | null
  finished_at: string | null
  output_json: string | null // 结构化结果
  metrics_json: string | null // 性能指标
}

export interface AnalysisRun {
  id: string
  sample_id: string
  sample_sha256: string
  goal: string
  depth: string
  backend_policy: string
  compatibility_marker: string
  pipeline_version: string
  sample_size_tier: string | null
  analysis_budget_profile: string | null
  status: string
  latest_stage: string | null
  stage_plan_json: string | null
  artifact_refs_json: string | null
  metadata_json: string | null
  created_at: string
  updated_at: string
  finished_at: string | null
  reused_from_run_id: string | null
  last_accessed_at: string | null
}

export interface AnalysisRunStage {
  run_id: string
  stage: string
  status: string
  execution_state: string | null
  tool: string | null
  job_id: string | null
  result_json: string | null
  artifact_refs_json: string | null
  coverage_json: string | null
  metadata_json: string | null
  created_at: string
  updated_at: string
  started_at: string | null
  finished_at: string | null
}

export interface AnalysisEvidence {
  id: string
  sample_id: string
  sample_sha256: string
  evidence_family: string
  backend: string
  mode: string
  compatibility_marker: string
  freshness_marker: string | null
  provenance_json: string | null
  metadata_json: string | null
  result_json: string
  artifact_refs_json: string | null
  created_at: string
  updated_at: string
  last_accessed_at: string | null
}

export interface BoundedAnalysisEvidenceResult {
  rows: AnalysisEvidence[]
  total_rows: number
  eligible_rows: number
  oversized_rows: number
  selected_bytes: number
  truncated: boolean
  scan_truncated: boolean
}

export interface DebugSession {
  id: string
  run_id: string | null
  sample_id: string
  sample_sha256: string
  status: string
  debug_state: string
  backend: string | null
  current_phase: string | null
  session_tag: string | null
  artifact_refs_json: string | null
  guidance_json: string | null
  metadata_json: string | null
  created_at: string
  updated_at: string
  finished_at: string | null
}

export interface RuntimeWorkerFamilyState {
  family: string
  compatibility_key: string
  deployment_key: string | null
  pool_kind: string
  live_workers: number
  idle_workers: number
  busy_workers: number
  unhealthy_workers: number
  warm_reuse_count: number
  cold_start_count: number
  eviction_count: number
  last_error: string | null
  metadata_json: string | null
  created_at: string
  updated_at: string
  last_used_at: string | null
}

export interface SchedulerEvent {
  id: string
  job_id: string | null
  run_id: string | null
  sample_id: string | null
  tool: string | null
  stage: string | null
  execution_bucket: string
  cost_class: string
  decision: string
  reason: string | null
  worker_family: string | null
  warm_reuse: number | null
  cold_start: number | null
  metadata_json: string | null
  created_at: string
}

export interface Function {
  sample_id: string // FK
  address: string
  name: string | null
  size: number | null
  score: number | null // 兴趣函数排序分
  tags: string | null // JSON array
  summary: string | null
  caller_count: number | null
  callee_count: number | null
  is_entry_point: number | null // SQLite uses INTEGER for boolean (0/1)
  is_exported: number | null // SQLite uses INTEGER for boolean (0/1)
  callees: string | null // JSON array of callee names
}

export interface Artifact {
  id: string // UUID
  sample_id: string // FK
  type: string // strings/json/report/resource_dump/cfg
  path: string // workspace 相对路径
  sha256: string
  mime: string | null
  created_at: string
}

export interface ContextWriteLease {
  lock_key: string
  owner_token: string
  host_id: string
  pid: number
  acquired_at: string
  heartbeat_at: string
}

export interface ContextWriteLeaseAcquireResult {
  acquired: boolean
  takeover: boolean
  lease: ContextWriteLease | null
}

export interface CachedResult {
  key: string
  data: unknown
  created_at: string
  expires_at: string | null
}

export type UploadSessionStatus = 'pending' | 'uploaded' | 'registered' | 'expired' | 'failed'

export interface UploadSession {
  id: string
  token: string
  status: UploadSessionStatus
  filename: string | null
  source: string | null
  created_at: string
  expires_at: string
  uploaded_at: string | null
  staged_path: string | null
  size: number | null
  sha256: string | null
  md5: string | null
  sample_id: string | null
  error: string | null
  metadata_json: string | null
}

export interface CreateUploadSessionInput {
  filename?: string | null
  source?: string | null
  expires_at: string
  metadata_json?: string | null
  token?: string
}

export interface Batch {
  id: string
  status: string
  total_samples: number
  completed_samples: number
  failed_samples: number
  cancelled_samples: number
  metadata_json: string | null
  created_at: string
  updated_at: string
}

export interface BatchSample {
  batch_id: string
  sample_id: string
  status: string
  filename: string
  size: number
  sha256: string
  artifact_refs_json: string | null
  error: string | null
  created_at: string
  updated_at: string
}

/**
 * Unforgeable fixture capability. It is intentionally absent from every
 * production call site; release tests enforce that source allowlist.
 */
export const DATABASE_FIXTURE_CAPABILITY: unique symbol = Symbol('rikune.database.fixture')

/**
 * Database manager class
 */
export class DatabaseManager {
  private db: Database.Database

  constructor(dbPath: string) {
    // Ensure directory exists
    const dbDir = path.dirname(dbPath)
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true })
      logDebug('Created database directory', { path: dbDir })
    }

    // Initialize database
    logger.info({ dbPath }, 'Initializing database')
    const busyTimeoutMs = getSqliteBusyTimeoutMs()
    this.db = new Database(dbPath, { timeout: busyTimeoutMs })

    // Enable foreign keys
    this.db.pragma('foreign_keys = ON')
    this.db.pragma(`busy_timeout = ${busyTimeoutMs}`)
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('synchronous = NORMAL')

    // Initialize schema
    this.initializeSchema()
    logger.info('Database initialized successfully')
  }

  /**
   * Get the raw underlying database handle.
   * Use sparingly — prefer higher-level methods.
   */
  getDb(): Database.Database {
    return this.db
  }

  /**
   * Get logger
   */
  getLogger() {
    return logger
  }

  /**
   * Execute SQL statement
   */
  runSql(sql: string, params?: any[]): void {
    if (params && params.length > 0) {
      const stmt = this.db.prepare(sql)
      stmt.run(...params)
    } else {
      this.db.exec(sql)
    }
  }

  /**
   * Query SQL statement
   */
  querySql<T>(sql: string, params?: any[]): T[] {
    const stmt = this.db.prepare(sql)
    return params ? (stmt.all(...params) as T[]) : (stmt.all() as T[])
  }

  /**
   * Get single row from SQL query
   */
  queryOneSql<T>(sql: string, params?: any[]): T | undefined {
    const stmt = this.db.prepare(sql)
    return params ? (stmt.get(...params) as T) : (stmt.get() as T)
  }

  /**
   * Initialize database schema
   */
  private initializeSchema(): void {
    this.db.exec(SCHEMA_SQL)
    this.initializeSampleWriteFences()
    this.ensureColumnExists('jobs', 'updated_at', 'ALTER TABLE jobs ADD COLUMN updated_at TEXT')
    this.ensureColumnExists(
      'jobs',
      'owner_instance_id',
      'ALTER TABLE jobs ADD COLUMN owner_instance_id TEXT'
    )
    this.ensureColumnExists(
      'jobs',
      'owner_boot_id',
      'ALTER TABLE jobs ADD COLUMN owner_boot_id TEXT'
    )
    this.ensureColumnExists('jobs', 'claim_token', 'ALTER TABLE jobs ADD COLUMN claim_token TEXT')
    this.ensureColumnExists('jobs', 'claim_until', 'ALTER TABLE jobs ADD COLUMN claim_until TEXT')
    this.ensureColumnExists(
      'jobs',
      'claim_heartbeat_at',
      'ALTER TABLE jobs ADD COLUMN claim_heartbeat_at TEXT'
    )
    this.ensureColumnExists(
      'jobs',
      'retry_count',
      'ALTER TABLE jobs ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0'
    )
    this.ensureColumnExists(
      'jobs',
      'retry_policy_json',
      'ALTER TABLE jobs ADD COLUMN retry_policy_json TEXT'
    )
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_jobs_claim_until ON jobs(claim_until)')
    this.ensureColumnExists(
      'samples',
      'ingest_lease_token',
      'ALTER TABLE samples ADD COLUMN ingest_lease_token TEXT'
    )
    this.ensureColumnExists(
      'samples',
      'ingest_generation',
      'ALTER TABLE samples ADD COLUMN ingest_generation INTEGER'
    )
    this.ensureColumnExists(
      'sample_deletions',
      'kb_overdelete_count',
      'ALTER TABLE sample_deletions ADD COLUMN kb_overdelete_count INTEGER NOT NULL DEFAULT 0 CHECK (kb_overdelete_count >= 0)'
    )
    this.ensureColumnExists(
      'sample_ingests',
      'temp_name',
      "ALTER TABLE sample_ingests ADD COLUMN temp_name TEXT NOT NULL DEFAULT ''"
    )
    for (const [column, declaration] of [
      ['owner_instance_id', 'TEXT'],
      ['owner_boot_id', 'TEXT'],
      ['owner_token', 'TEXT'],
      ['owner_until', 'TEXT'],
      ['lease_token', 'TEXT'],
      ['generation', 'INTEGER'],
    ] as const) {
      this.ensureColumnExists(
        'sample_ingests',
        column,
        `ALTER TABLE sample_ingests ADD COLUMN ${column} ${declaration}`
      )
    }
    this.db.exec(
      'CREATE INDEX IF NOT EXISTS idx_sample_ingests_owner_until ON sample_ingests(owner_until)'
    )
    this.db.exec(`
      UPDATE jobs
      SET updated_at = COALESCE(updated_at, finished_at, started_at, created_at)
      WHERE updated_at IS NULL
    `)
  }

  /**
   * Install DB-level tombstone fences for every table that can persist a direct
   * sample reference. These triggers are a final fail-closed boundary for
   * writers that bypass the MCP executor or queue wrappers.
   */
  private initializeSampleWriteFences(): void {
    const directTables = [
      'analyses',
      'analysis_runs',
      'analysis_evidence',
      'debug_sessions',
      'functions',
      'artifacts',
      'jobs',
      'scheduler_events',
      'batch_samples',
      'sample_kb',
    ] as const
    for (const table of directTables) {
      this.db.exec(`
        CREATE TRIGGER IF NOT EXISTS trg_${table}_sample_fence_insert
        BEFORE INSERT ON ${table}
        WHEN NEW.sample_id IS NOT NULL AND EXISTS (
          SELECT 1 FROM sample_operation_generations g
          WHERE g.sample_id = NEW.sample_id AND g.tombstoned = 1
        )
        BEGIN
          SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED');
        END;
        CREATE TRIGGER IF NOT EXISTS trg_${table}_sample_fence_update
        BEFORE UPDATE ON ${table}
        WHEN NEW.sample_id IS NOT NULL AND EXISTS (
          SELECT 1 FROM sample_operation_generations g
          WHERE g.sample_id = NEW.sample_id AND g.tombstoned = 1
        )
        BEGIN
          SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED');
        END;
      `)
    }
    this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS trg_samples_sample_fence_insert
      BEFORE INSERT ON samples
      WHEN EXISTS (
        SELECT 1 FROM sample_operation_generations g
        WHERE g.sample_id = NEW.id AND g.tombstoned = 1
      )
      BEGIN SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED'); END;
      CREATE TRIGGER IF NOT EXISTS trg_samples_sample_fence_update
      BEFORE UPDATE ON samples
      WHEN EXISTS (
        SELECT 1 FROM sample_operation_generations g
        WHERE g.sample_id = NEW.id AND g.tombstoned = 1
      )
      BEGIN SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED'); END;

      CREATE TRIGGER IF NOT EXISTS trg_upload_sessions_sample_fence_insert
      BEFORE INSERT ON upload_sessions
      WHEN NEW.sample_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM sample_operation_generations g
        WHERE g.sample_id = NEW.sample_id AND g.tombstoned = 1
      )
      BEGIN SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED'); END;
      CREATE TRIGGER IF NOT EXISTS trg_upload_sessions_sample_fence_update
      BEFORE UPDATE ON upload_sessions
      WHEN NEW.sample_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM sample_operation_generations g
        WHERE g.sample_id = NEW.sample_id AND g.tombstoned = 1
      )
      BEGIN SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED'); END;

      CREATE TRIGGER IF NOT EXISTS trg_cache_sample_fence_insert
      BEFORE INSERT ON cache
      WHEN NEW.sample_sha256 IS NOT NULL AND EXISTS (
        SELECT 1 FROM sample_operation_generations g
        WHERE g.sample_id = 'sha256:' || lower(NEW.sample_sha256) AND g.tombstoned = 1
      )
      BEGIN SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED'); END;
      CREATE TRIGGER IF NOT EXISTS trg_cache_sample_fence_update
      BEFORE UPDATE ON cache
      WHEN NEW.sample_sha256 IS NOT NULL AND EXISTS (
        SELECT 1 FROM sample_operation_generations g
        WHERE g.sample_id = 'sha256:' || lower(NEW.sample_sha256) AND g.tombstoned = 1
      )
      BEGIN SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED'); END;

      CREATE TRIGGER IF NOT EXISTS trg_analysis_run_stages_sample_fence_insert
      BEFORE INSERT ON analysis_run_stages
      WHEN EXISTS (
        SELECT 1 FROM analysis_runs r
        JOIN sample_operation_generations g ON g.sample_id = r.sample_id
        WHERE r.id = NEW.run_id AND g.tombstoned = 1
      )
      BEGIN SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED'); END;
      CREATE TRIGGER IF NOT EXISTS trg_analysis_run_stages_sample_fence_update
      BEFORE UPDATE ON analysis_run_stages
      WHEN EXISTS (
        SELECT 1 FROM analysis_runs r
        JOIN sample_operation_generations g ON g.sample_id = r.sample_id
        WHERE r.id = NEW.run_id AND g.tombstoned = 1
      )
      BEGIN SELECT RAISE(ABORT, 'E_SAMPLE_TOMBSTONED'); END;
    `)
  }

  private ensureColumnExists(tableName: string, columnName: string, alterSql: string): void {
    const stmt = this.db.prepare(`PRAGMA table_info(${tableName})`)
    const columns = stmt.all() as Array<{ name: string }>
    if (!columns.some((column) => column.name === columnName)) {
      this.db.exec(alterSql)
    }
  }

  /**
   * Get the underlying database instance
   */
  getDatabase(): Database.Database {
    return this.db
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close()
  }

  /**
   * Execute a transaction
   */
  transaction<T>(fn: () => T): T {
    const txn = this.db.transaction(fn)
    return txn()
  }

  /**
   * Execute a function within a transaction with automatic rollback on error.
   * The callback receives `this` (the DatabaseManager) for convenience.
   * Nested calls are safe — SQLite uses savepoints automatically via better-sqlite3.
   */
  withTransaction<T>(fn: (db: DatabaseManager) => T): T {
    const txn = this.db.transaction(() => fn(this))
    try {
      return txn()
    } catch (err) {
      throw new DatabaseError(
        ErrorCode.E_DB_TRANSACTION,
        `Transaction failed: ${(err as Error).message}`,
        { cause: err }
      )
    }
  }

  // ==================== Sample Operations ====================

  /**
   * Insert a new sample
   */
  insertSample(
    sample: Sample,
    fence: {
      leaseToken: string
      instanceId: string
      generation: number
      journalId: string
      journalOwnerToken: string
    }
  ): void {
    if (!fence) {
      throw new Error(
        'E_SAMPLE_FENCE_REQUIRED: persisted sample insertion requires an ingest fence.'
      )
    }
    this.insertSampleInternal(sample, fence)
  }

  /**
   * Explicit fixture-only API. Production source is guarded by a regression
   * allowlist and must never reference this method; unlike NODE_ENV switches,
   * the call site is visible to type checking and source review.
   */
  insertSampleFixture(capability: typeof DATABASE_FIXTURE_CAPABILITY, sample: Sample): void {
    if (capability !== DATABASE_FIXTURE_CAPABILITY) {
      throw new Error('E_SAMPLE_FIXTURE_CAPABILITY: invalid database fixture capability.')
    }
    this.insertSampleInternal(sample, null)
  }

  private insertSampleInternal(
    sample: Sample,
    fence: {
      leaseToken: string
      instanceId: string
      generation: number
      journalId: string
      journalOwnerToken: string
    } | null
  ): void {
    const insert = this.db.transaction(() => {
      const now = new Date().toISOString()
      const state = this.db
        .prepare(
          `SELECT generation, tombstoned, deletion_id
           FROM sample_operation_generations WHERE sample_id = ?`
        )
        .get(sample.id) as
        | { generation: number; tombstoned: number; deletion_id: string | null }
        | undefined
      if (state?.tombstoned === 1) {
        throw new Error('E_SAMPLE_TOMBSTONED: sample must be revived through acquireIngestLease.')
      }
      if (fence) {
        const journalOwned = this.db
          .prepare(
            `SELECT 1 FROM sample_ingests
             WHERE id = ? AND sample_id = ? AND phase = 'fs_committed'
               AND owner_token = ? AND owner_instance_id = ?
               AND lease_token = ? AND generation = ?`
          )
          .get(
            fence.journalId,
            sample.id,
            fence.journalOwnerToken,
            fence.instanceId,
            fence.leaseToken,
            fence.generation
          )
        if (!journalOwned) {
          throw new Error('E_SAMPLE_INGEST_OWNER_LOST: sample insert journal is not owned.')
        }
        const owned = this.db
          .prepare(
            `SELECT 1 FROM sample_operation_leases l
             JOIN sample_operation_generations g ON g.sample_id = l.sample_id
             JOIN sample_operation_instances i ON i.instance_id = l.instance_id
             WHERE l.sample_id = ? AND l.lease_token = ? AND l.instance_id = ?
               AND l.mode = 'shared' AND l.generation = ?
               AND l.lease_until > ? AND i.lease_until > ?
               AND g.generation = l.generation AND g.tombstoned = 0
             LIMIT 1`
          )
          .get(sample.id, fence.leaseToken, fence.instanceId, fence.generation, now, now)
        if (!owned) throw new Error('E_SAMPLE_LEASE_LOST: ingest database fence is not owned.')
      }
      this.db
        .prepare(
          `INSERT INTO samples
            (id, sha256, md5, size, file_type, created_at, source,
             ingest_lease_token, ingest_generation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          sample.id,
          sample.sha256,
          sample.md5,
          sample.size,
          sample.file_type,
          sample.created_at,
          sample.source,
          fence?.leaseToken ?? null,
          fence?.generation ?? null
        )
      if (fence) {
        const updated = this.db
          .prepare(
            `UPDATE sample_operation_generations SET updated_at = ?
             WHERE sample_id = ? AND generation = ? AND tombstoned = 0`
          )
          .run(now, sample.id, fence.generation)
        if (updated.changes !== 1) {
          throw new Error('E_SAMPLE_LEASE_LOST: ingest generation changed during insert.')
        }
      } else {
        this.db
          .prepare(
            `INSERT INTO sample_operation_generations
              (sample_id, generation, tombstoned, deletion_id, updated_at)
             VALUES (?, 0, 0, NULL, ?)
             ON CONFLICT(sample_id) DO UPDATE SET updated_at = excluded.updated_at
             WHERE sample_operation_generations.tombstoned = 0`
          )
          .run(sample.id, now)
      }
    })
    insert.immediate()
  }

  /** Roll back only the sample row created by a specific ingest fence. */
  rollbackInsertedSample(
    sampleId: string,
    fence: { leaseToken: string; generation: number }
  ): boolean {
    if (!fence) {
      throw new Error('E_SAMPLE_FENCE_REQUIRED: sample rollback requires an ingest fence.')
    }
    const rollback = this.db.transaction(() => {
      const result = this.db
        .prepare(
          `DELETE FROM samples
           WHERE id = ? AND ingest_lease_token = ? AND ingest_generation = ?
             AND EXISTS (
               SELECT 1 FROM sample_operation_generations g
               WHERE g.sample_id = samples.id AND g.generation = ? AND g.tombstoned = 0
             )`
        )
        .run(sampleId, fence.leaseToken, fence.generation, fence.generation)
      return result.changes === 1
    })
    return rollback.immediate()
  }

  prepareSampleIngestJournal(
    journal: Omit<
      SampleIngestJournal,
      | 'phase'
      | 'file_device'
      | 'file_inode'
      | 'owner_instance_id'
      | 'owner_boot_id'
      | 'owner_token'
      | 'owner_until'
      | 'lease_token'
      | 'generation'
      | 'created_at'
      | 'updated_at'
    >,
    fence: { leaseToken: string; instanceId: string; generation: number },
    owner: { token: string; until: string }
  ): void {
    const prepare = this.db.transaction(() => {
      const now = new Date().toISOString()
      const owned = this.db
        .prepare(
          `SELECT i.boot_id FROM sample_operation_leases l
           JOIN sample_operation_generations g ON g.sample_id = l.sample_id
           JOIN sample_operation_instances i ON i.instance_id = l.instance_id
           WHERE l.sample_id = ? AND l.lease_token = ? AND l.instance_id = ?
             AND l.mode = 'shared' AND l.generation = ?
             AND l.lease_until > ? AND i.lease_until > ?
             AND g.generation = l.generation AND g.tombstoned = 0`
        )
        .get(journal.sample_id, fence.leaseToken, fence.instanceId, fence.generation, now, now) as
        | { boot_id: string }
        | undefined
      if (!owned) throw new Error('E_SAMPLE_LEASE_LOST: ingest journal fence is not owned.')
      this.db
        .prepare(
          `INSERT INTO sample_ingests
           (id, sample_id, sha256, md5, size, file_type, filename, temp_name,
            source, phase, file_device, file_inode, owner_instance_id,
            owner_boot_id, owner_token, owner_until, lease_token, generation,
            created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, NULL,
                   ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          journal.id,
          journal.sample_id,
          journal.sha256,
          journal.md5,
          journal.size,
          journal.file_type,
          journal.filename,
          journal.temp_name,
          journal.source,
          fence.instanceId,
          owned.boot_id,
          owner.token,
          owner.until,
          fence.leaseToken,
          fence.generation,
          now,
          now
        )
    })
    prepare.immediate()
  }

  markSampleIngestFilesystemCommitted(
    journalId: string,
    sampleId: string,
    identity: { device: number; inode: number },
    fence: { leaseToken: string; instanceId: string; generation: number },
    ownerToken: string
  ): void {
    const mark = this.db.transaction(() => {
      const now = new Date().toISOString()
      const result = this.db
        .prepare(
          `UPDATE sample_ingests
           SET phase = 'fs_committed', file_device = ?, file_inode = ?, updated_at = ?
           WHERE id = ? AND sample_id = ? AND owner_token = ?
             AND owner_instance_id = ? AND lease_token = ? AND generation = ?
             AND EXISTS (
             SELECT 1 FROM sample_operation_leases l
             JOIN sample_operation_generations g ON g.sample_id = l.sample_id
             JOIN sample_operation_instances i ON i.instance_id = l.instance_id
             WHERE l.sample_id = sample_ingests.sample_id
               AND l.lease_token = ? AND l.instance_id = ?
               AND l.mode = 'shared' AND l.generation = ?
               AND l.lease_until > ? AND i.lease_until > ?
               AND g.generation = l.generation AND g.tombstoned = 0
           )`
        )
        .run(
          identity.device,
          identity.inode,
          now,
          journalId,
          sampleId,
          ownerToken,
          fence.instanceId,
          fence.leaseToken,
          fence.generation,
          fence.leaseToken,
          fence.instanceId,
          fence.generation,
          now,
          now
        )
      if (result.changes !== 1) {
        throw new Error('E_SAMPLE_LEASE_LOST: filesystem commit journal fence is not owned.')
      }
    })
    mark.immediate()
  }

  heartbeatSampleIngestJournal(
    journalId: string,
    ownerToken: string,
    fence: { leaseToken: string; instanceId: string; generation: number },
    ownerUntil: string
  ): boolean {
    const now = new Date().toISOString()
    const result = this.db
      .prepare(
        `UPDATE sample_ingests SET owner_until = ?, updated_at = ?
       WHERE id = ? AND owner_token = ? AND owner_instance_id = ?
         AND lease_token = ? AND generation = ?
         AND EXISTS (
           SELECT 1 FROM sample_operation_leases l
           JOIN sample_operation_instances i ON i.instance_id = l.instance_id
           JOIN sample_operation_generations g ON g.sample_id = l.sample_id
           WHERE l.sample_id = sample_ingests.sample_id
             AND l.lease_token = ? AND l.instance_id = ? AND l.generation = ?
             AND l.mode = 'shared' AND l.lease_until > ? AND i.lease_until > ?
             AND i.boot_id = l.boot_id AND g.generation = l.generation
             AND g.tombstoned = 0
         )`
      )
      .run(
        ownerUntil,
        now,
        journalId,
        ownerToken,
        fence.instanceId,
        fence.leaseToken,
        fence.generation,
        fence.leaseToken,
        fence.instanceId,
        fence.generation,
        now,
        now
      )
    return result.changes === 1
  }

  /**
   * Fence rollback after a shared lease is lost. Cleanup is allowed only while
   * this exact journal owner still owns the current non-tombstoned generation.
   */
  renewSampleIngestCleanupOwnership(
    journalId: string,
    ownerToken: string,
    fence: { instanceId: string; generation: number },
    ownerUntil: string
  ): boolean {
    const now = new Date().toISOString()
    const result = this.db
      .prepare(
        `UPDATE sample_ingests SET owner_until = ?, updated_at = ?
       WHERE id = ? AND owner_token = ? AND owner_instance_id = ? AND generation = ?
         AND EXISTS (
           SELECT 1 FROM sample_operation_generations g
           WHERE g.sample_id = sample_ingests.sample_id
             AND g.generation = ? AND g.tombstoned = 0
         )`
      )
      .run(
        ownerUntil,
        now,
        journalId,
        ownerToken,
        fence.instanceId,
        fence.generation,
        fence.generation
      )
    return result.changes === 1
  }

  /**
   * Publish that a task has stopped touching the journal while retaining its
   * crash-recovery record. A successor still has to win the owner-token CAS.
   */
  abandonSampleIngestJournal(
    journalId: string,
    ownerToken: string,
    fence: { instanceId: string; generation: number }
  ): boolean {
    const now = new Date().toISOString()
    const result = this.db
      .prepare(
        `UPDATE sample_ingests SET owner_until = ?, updated_at = ?
       WHERE id = ? AND owner_token = ? AND owner_instance_id = ? AND generation = ?`
      )
      .run(now, now, journalId, ownerToken, fence.instanceId, fence.generation)
    return result.changes === 1
  }

  claimSampleIngestJournal(
    journalId: string,
    fence: { leaseToken: string; instanceId: string; generation: number },
    owner: { token: string; until: string }
  ): boolean {
    const claim = this.db.transaction(() => {
      const now = new Date().toISOString()
      const owned = this.db
        .prepare(
          `SELECT i.boot_id FROM sample_operation_leases l
         JOIN sample_operation_instances i ON i.instance_id = l.instance_id
         JOIN sample_operation_generations g ON g.sample_id = l.sample_id
         JOIN sample_ingests ingest ON ingest.sample_id = l.sample_id
         WHERE ingest.id = ? AND l.lease_token = ? AND l.instance_id = ?
           AND l.generation = ? AND l.mode = 'shared'
           AND l.lease_until > ? AND i.lease_until > ?
           AND i.boot_id = l.boot_id AND g.generation = l.generation
           AND g.tombstoned = 0`
        )
        .get(journalId, fence.leaseToken, fence.instanceId, fence.generation, now, now) as
        | { boot_id: string }
        | undefined
      if (!owned) return false
      const result = this.db
        .prepare(
          `UPDATE sample_ingests
         SET owner_instance_id = ?, owner_boot_id = ?, owner_token = ?,
             owner_until = ?, lease_token = ?, generation = ?, updated_at = ?
         WHERE id = ? AND (
           owner_token IS NULL OR (
             owner_until IS NULL OR owner_until <= ?
           )
         )`
        )
        .run(
          fence.instanceId,
          owned.boot_id,
          owner.token,
          owner.until,
          fence.leaseToken,
          fence.generation,
          now,
          journalId,
          now
        )
      return result.changes === 1
    })
    return claim.immediate()
  }

  closeSampleIngestJournal(
    journalId: string,
    sampleId: string,
    ownerToken: string,
    fence: { leaseToken: string; instanceId: string; generation: number },
    requirePersistedSample: boolean
  ): void {
    const close = this.db.transaction(() => {
      const now = new Date().toISOString()
      const samplePredicate = requirePersistedSample
        ? `EXISTS (
             SELECT 1 FROM samples s WHERE s.id = sample_ingests.sample_id
               AND s.sha256 = sample_ingests.sha256 AND s.size = sample_ingests.size
           )`
        : `NOT EXISTS (SELECT 1 FROM samples s WHERE s.id = sample_ingests.sample_id)`
      const params: unknown[] = []
      params.push(
        journalId,
        sampleId,
        ownerToken,
        fence.instanceId,
        fence.leaseToken,
        fence.generation,
        fence.leaseToken,
        fence.instanceId,
        fence.generation,
        now,
        now
      )
      const result = this.db
        .prepare(
          `DELETE FROM sample_ingests
         WHERE ${samplePredicate}
           AND id = ? AND sample_id = ? AND owner_token = ?
           AND owner_instance_id = ? AND lease_token = ? AND generation = ?
           AND EXISTS (
             SELECT 1 FROM sample_operation_leases l
             JOIN sample_operation_instances i ON i.instance_id = l.instance_id
             JOIN sample_operation_generations g ON g.sample_id = l.sample_id
             WHERE l.sample_id = sample_ingests.sample_id
               AND l.lease_token = ? AND l.instance_id = ? AND l.generation = ?
               AND l.mode = 'shared' AND l.lease_until > ? AND i.lease_until > ?
               AND i.boot_id = l.boot_id AND g.generation = l.generation
               AND g.tombstoned = 0
           )`
        )
        .run(...params)
      if (result.changes !== 1) {
        throw new Error('E_SAMPLE_INGEST_OWNER_LOST: journal close provenance fence failed.')
      }
    })
    close.immediate()
  }

  closeAbortedSampleIngestJournal(
    journalId: string,
    sampleId: string,
    ownerToken: string,
    fence: { instanceId: string; generation: number }
  ): void {
    const close = this.db.transaction(() => {
      const result = this.db
        .prepare(
          `DELETE FROM sample_ingests
         WHERE id = ? AND sample_id = ? AND owner_token = ?
           AND owner_instance_id = ? AND generation = ?
           AND NOT EXISTS (SELECT 1 FROM samples s WHERE s.id = sample_ingests.sample_id)
           AND EXISTS (
             SELECT 1 FROM sample_operation_generations g
             WHERE g.sample_id = sample_ingests.sample_id
               AND g.generation = ? AND g.tombstoned = 0
           )`
        )
        .run(journalId, sampleId, ownerToken, fence.instanceId, fence.generation, fence.generation)
      if (result.changes !== 1) {
        throw new Error('E_SAMPLE_INGEST_OWNER_LOST: aborted journal close fence failed.')
      }
    })
    close.immediate()
  }

  listPendingSampleIngests(): SampleIngestJournal[] {
    return this.db
      .prepare('SELECT * FROM sample_ingests ORDER BY created_at ASC, id ASC')
      .all() as SampleIngestJournal[]
  }

  findSampleIngestJournal(journalId: string): SampleIngestJournal | undefined {
    return this.db.prepare('SELECT * FROM sample_ingests WHERE id = ?').get(journalId) as
      | SampleIngestJournal
      | undefined
  }

  findSampleIngestJournalBySampleId(sampleId: string): SampleIngestJournal | undefined {
    return this.db.prepare('SELECT * FROM sample_ingests WHERE sample_id = ?').get(sampleId) as
      | SampleIngestJournal
      | undefined
  }

  /**
   * Find a sample by ID
   */
  findSample(sampleId: string): Sample | undefined {
    const stmt = this.db.prepare('SELECT * FROM samples WHERE id = ?')
    return stmt.get(sampleId) as Sample | undefined
  }

  /**
   * Find a sample by SHA256
   */
  findSampleBySha256(sha256: string): Sample | undefined {
    const stmt = this.db.prepare('SELECT * FROM samples WHERE sha256 = ?')
    return stmt.get(sha256) as Sample | undefined
  }

  // ==================== Upload Session Operations ====================

  /**
   * Create a new upload session with a durable token.
   */
  createUploadSession(input: CreateUploadSessionInput): UploadSession {
    const session: UploadSession = {
      id: randomUUID(),
      token: input.token || randomUUID(),
      status: 'pending',
      filename: input.filename ?? null,
      source: input.source ?? null,
      created_at: new Date().toISOString(),
      expires_at: input.expires_at,
      uploaded_at: null,
      staged_path: null,
      size: null,
      sha256: null,
      md5: null,
      sample_id: null,
      error: null,
      metadata_json: input.metadata_json ?? null,
    }

    const stmt = this.db.prepare(`
      INSERT INTO upload_sessions (
        id, token, status, filename, source, created_at, expires_at,
        uploaded_at, staged_path, size, sha256, md5, sample_id, error, metadata_json
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    stmt.run(
      session.id,
      session.token,
      session.status,
      session.filename,
      session.source,
      session.created_at,
      session.expires_at,
      session.uploaded_at,
      session.staged_path,
      session.size,
      session.sha256,
      session.md5,
      session.sample_id,
      session.error,
      session.metadata_json
    )

    return session
  }

  /**
   * Find an upload session by token.
   */
  findUploadSessionByToken(token: string): UploadSession | undefined {
    const stmt = this.db.prepare('SELECT * FROM upload_sessions WHERE token = ?')
    return stmt.get(token) as UploadSession | undefined
  }

  /**
   * Update an upload session by token.
   */
  updateUploadSessionByToken(
    token: string,
    updates: Partial<Omit<UploadSession, 'id' | 'token' | 'created_at'>>
  ): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.status !== undefined) {
      fields.push('status = ?')
      values.push(updates.status)
    }
    if (updates.filename !== undefined) {
      fields.push('filename = ?')
      values.push(updates.filename)
    }
    if (updates.source !== undefined) {
      fields.push('source = ?')
      values.push(updates.source)
    }
    if (updates.expires_at !== undefined) {
      fields.push('expires_at = ?')
      values.push(updates.expires_at)
    }
    if (updates.uploaded_at !== undefined) {
      fields.push('uploaded_at = ?')
      values.push(updates.uploaded_at)
    }
    if (updates.staged_path !== undefined) {
      fields.push('staged_path = ?')
      values.push(updates.staged_path)
    }
    if (updates.size !== undefined) {
      fields.push('size = ?')
      values.push(updates.size)
    }
    if (updates.sha256 !== undefined) {
      fields.push('sha256 = ?')
      values.push(updates.sha256)
    }
    if (updates.md5 !== undefined) {
      fields.push('md5 = ?')
      values.push(updates.md5)
    }
    if (updates.sample_id !== undefined) {
      fields.push('sample_id = ?')
      values.push(updates.sample_id)
    }
    if (updates.error !== undefined) {
      fields.push('error = ?')
      values.push(updates.error)
    }
    if (updates.metadata_json !== undefined) {
      fields.push('metadata_json = ?')
      values.push(updates.metadata_json)
    }

    if (fields.length === 0) {
      return
    }

    values.push(token)
    const stmt = this.db.prepare(`
      UPDATE upload_sessions SET ${fields.join(', ')} WHERE token = ?
    `)
    stmt.run(...values)
  }

  /**
   * Mark an upload session as uploaded.
   */
  markUploadSessionUploaded(
    token: string,
    details: {
      staged_path: string
      size: number
      filename?: string | null
    }
  ): void {
    this.updateUploadSessionByToken(token, {
      status: 'uploaded',
      filename: details.filename ?? undefined,
      uploaded_at: new Date().toISOString(),
      staged_path: details.staged_path,
      size: details.size,
      error: null,
    })
  }

  /**
   * Mark an upload session as registered.
   */
  markUploadSessionRegistered(
    token: string,
    details: {
      sample_id: string
      size?: number | null
      sha256?: string | null
      md5?: string | null
      clearStagedPath?: boolean
    }
  ): void {
    this.updateUploadSessionByToken(token, {
      status: 'registered',
      sample_id: details.sample_id,
      size: details.size ?? undefined,
      sha256: details.sha256 ?? undefined,
      md5: details.md5 ?? undefined,
      staged_path: details.clearStagedPath ? null : undefined,
      error: null,
    })
  }

  /**
   * Mark an upload session as failed.
   */
  markUploadSessionFailed(token: string, error: string): void {
    this.updateUploadSessionByToken(token, {
      status: 'failed',
      error,
    })
  }

  /**
   * Mark an upload session as expired.
   */
  markUploadSessionExpired(token: string): void {
    this.updateUploadSessionByToken(token, {
      status: 'expired',
      error: 'Upload session expired',
    })
  }

  /**
   * Expire all non-terminal upload sessions past their expiration time.
   */
  expireUploadSessions(nowIso: string = new Date().toISOString()): number {
    const stmt = this.db.prepare(`
      UPDATE upload_sessions
      SET status = 'expired', error = COALESCE(error, 'Upload session expired')
      WHERE status IN ('pending', 'uploaded')
        AND expires_at < ?
    `)
    const result = stmt.run(nowIso)
    return result.changes
  }

  // ==================== Analysis Operations ====================

  /**
   * Insert a new analysis
   */
  insertAnalysis(analysis: Analysis): void {
    const stmt = this.db.prepare(`
      INSERT INTO analyses (id, sample_id, stage, backend, status, started_at, finished_at, output_json, metrics_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      analysis.id,
      analysis.sample_id,
      analysis.stage,
      analysis.backend,
      analysis.status,
      analysis.started_at,
      analysis.finished_at,
      analysis.output_json,
      analysis.metrics_json
    )
  }

  /**
   * Update an analysis
   */
  updateAnalysis(analysisId: string, updates: Partial<Omit<Analysis, 'id' | 'sample_id'>>): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.stage !== undefined) {
      fields.push('stage = ?')
      values.push(updates.stage)
    }
    if (updates.backend !== undefined) {
      fields.push('backend = ?')
      values.push(updates.backend)
    }
    if (updates.status !== undefined) {
      fields.push('status = ?')
      values.push(updates.status)
    }
    if (updates.started_at !== undefined) {
      fields.push('started_at = ?')
      values.push(updates.started_at)
    }
    if (updates.finished_at !== undefined) {
      fields.push('finished_at = ?')
      values.push(updates.finished_at)
    }
    if (updates.output_json !== undefined) {
      fields.push('output_json = ?')
      values.push(updates.output_json)
    }
    if (updates.metrics_json !== undefined) {
      fields.push('metrics_json = ?')
      values.push(updates.metrics_json)
    }

    if (fields.length === 0) {
      return // No updates to perform
    }

    values.push(analysisId)
    const stmt = this.db.prepare(`
      UPDATE analyses SET ${fields.join(', ')} WHERE id = ?
    `)
    stmt.run(...values)
  }

  /**
   * Find an analysis by ID
   */
  findAnalysis(analysisId: string): Analysis | undefined {
    const stmt = this.db.prepare('SELECT * FROM analyses WHERE id = ?')
    return stmt.get(analysisId) as Analysis | undefined
  }

  /**
   * Find all analyses for a sample
   */
  findAnalysesBySample(sampleId: string): Analysis[] {
    const stmt = this.db.prepare(
      'SELECT * FROM analyses WHERE sample_id = ? ORDER BY started_at DESC'
    )
    return stmt.all(sampleId) as Analysis[]
  }

  // ==================== Analysis Run Operations ====================

  insertAnalysisRun(run: AnalysisRun): void {
    const stmt = this.db.prepare(`
      INSERT INTO analysis_runs (
        id, sample_id, sample_sha256, goal, depth, backend_policy,
        compatibility_marker, pipeline_version, sample_size_tier,
        analysis_budget_profile, status, latest_stage, stage_plan_json,
        artifact_refs_json, metadata_json, created_at, updated_at,
        finished_at, reused_from_run_id, last_accessed_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      run.id,
      run.sample_id,
      run.sample_sha256,
      run.goal,
      run.depth,
      run.backend_policy,
      run.compatibility_marker,
      run.pipeline_version,
      run.sample_size_tier,
      run.analysis_budget_profile,
      run.status,
      run.latest_stage,
      run.stage_plan_json,
      run.artifact_refs_json,
      run.metadata_json,
      run.created_at,
      run.updated_at,
      run.finished_at,
      run.reused_from_run_id,
      run.last_accessed_at
    )
  }

  updateAnalysisRun(
    runId: string,
    updates: Partial<
      Omit<
        AnalysisRun,
        | 'id'
        | 'sample_id'
        | 'sample_sha256'
        | 'goal'
        | 'depth'
        | 'backend_policy'
        | 'compatibility_marker'
        | 'pipeline_version'
        | 'created_at'
      >
    >
  ): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.sample_size_tier !== undefined) {
      fields.push('sample_size_tier = ?')
      values.push(updates.sample_size_tier)
    }
    if (updates.analysis_budget_profile !== undefined) {
      fields.push('analysis_budget_profile = ?')
      values.push(updates.analysis_budget_profile)
    }
    if (updates.status !== undefined) {
      fields.push('status = ?')
      values.push(updates.status)
    }
    if (updates.latest_stage !== undefined) {
      fields.push('latest_stage = ?')
      values.push(updates.latest_stage)
    }
    if (updates.stage_plan_json !== undefined) {
      fields.push('stage_plan_json = ?')
      values.push(updates.stage_plan_json)
    }
    if (updates.artifact_refs_json !== undefined) {
      fields.push('artifact_refs_json = ?')
      values.push(updates.artifact_refs_json)
    }
    if (updates.metadata_json !== undefined) {
      fields.push('metadata_json = ?')
      values.push(updates.metadata_json)
    }
    if (updates.updated_at !== undefined) {
      fields.push('updated_at = ?')
      values.push(updates.updated_at)
    }
    if (updates.finished_at !== undefined) {
      fields.push('finished_at = ?')
      values.push(updates.finished_at)
    }
    if (updates.reused_from_run_id !== undefined) {
      fields.push('reused_from_run_id = ?')
      values.push(updates.reused_from_run_id)
    }
    if (updates.last_accessed_at !== undefined) {
      fields.push('last_accessed_at = ?')
      values.push(updates.last_accessed_at)
    }

    if (fields.length === 0) {
      return
    }

    values.push(runId)
    const stmt = this.db.prepare(`
      UPDATE analysis_runs SET ${fields.join(', ')} WHERE id = ?
    `)
    stmt.run(...values)
  }

  findAnalysisRun(runId: string): AnalysisRun | undefined {
    const stmt = this.db.prepare('SELECT * FROM analysis_runs WHERE id = ?')
    return stmt.get(runId) as AnalysisRun | undefined
  }

  findAnalysisRunsBySample(sampleId: string): AnalysisRun[] {
    const stmt = this.db.prepare(
      'SELECT * FROM analysis_runs WHERE sample_id = ? ORDER BY datetime(updated_at) DESC'
    )
    return stmt.all(sampleId) as AnalysisRun[]
  }

  findLatestCompatibleAnalysisRun(
    sampleId: string,
    compatibilityMarker: string
  ): AnalysisRun | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM analysis_runs
      WHERE sample_id = ?
        AND compatibility_marker = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT 1
    `)
    return stmt.get(sampleId, compatibilityMarker) as AnalysisRun | undefined
  }

  insertAnalysisEvidence(evidence: AnalysisEvidence): void {
    const stmt = this.db.prepare(`
      INSERT INTO analysis_evidence (
        id, sample_id, sample_sha256, evidence_family, backend, mode, compatibility_marker,
        freshness_marker, provenance_json, metadata_json, result_json, artifact_refs_json,
        created_at, updated_at, last_accessed_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      evidence.id,
      evidence.sample_id,
      evidence.sample_sha256,
      evidence.evidence_family,
      evidence.backend,
      evidence.mode,
      evidence.compatibility_marker,
      evidence.freshness_marker,
      evidence.provenance_json,
      evidence.metadata_json,
      evidence.result_json,
      evidence.artifact_refs_json,
      evidence.created_at,
      evidence.updated_at,
      evidence.last_accessed_at
    )
  }

  updateAnalysisEvidence(
    evidenceId: string,
    updates: Partial<Omit<AnalysisEvidence, 'id' | 'sample_id' | 'sample_sha256' | 'created_at'>>
  ): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.evidence_family !== undefined) {
      fields.push('evidence_family = ?')
      values.push(updates.evidence_family)
    }
    if (updates.backend !== undefined) {
      fields.push('backend = ?')
      values.push(updates.backend)
    }
    if (updates.mode !== undefined) {
      fields.push('mode = ?')
      values.push(updates.mode)
    }
    if (updates.compatibility_marker !== undefined) {
      fields.push('compatibility_marker = ?')
      values.push(updates.compatibility_marker)
    }
    if (updates.freshness_marker !== undefined) {
      fields.push('freshness_marker = ?')
      values.push(updates.freshness_marker)
    }
    if (updates.provenance_json !== undefined) {
      fields.push('provenance_json = ?')
      values.push(updates.provenance_json)
    }
    if (updates.metadata_json !== undefined) {
      fields.push('metadata_json = ?')
      values.push(updates.metadata_json)
    }
    if (updates.result_json !== undefined) {
      fields.push('result_json = ?')
      values.push(updates.result_json)
    }
    if (updates.artifact_refs_json !== undefined) {
      fields.push('artifact_refs_json = ?')
      values.push(updates.artifact_refs_json)
    }
    if (updates.updated_at !== undefined) {
      fields.push('updated_at = ?')
      values.push(updates.updated_at)
    }
    if (updates.last_accessed_at !== undefined) {
      fields.push('last_accessed_at = ?')
      values.push(updates.last_accessed_at)
    }

    if (fields.length === 0) {
      return
    }

    values.push(evidenceId)
    const stmt = this.db.prepare(`
      UPDATE analysis_evidence SET ${fields.join(', ')} WHERE id = ?
    `)
    stmt.run(...values)
  }

  findAnalysisEvidence(evidenceId: string): AnalysisEvidence | undefined {
    const stmt = this.db.prepare('SELECT * FROM analysis_evidence WHERE id = ?')
    return stmt.get(evidenceId) as AnalysisEvidence | undefined
  }

  findAnalysisEvidenceBySample(
    sampleId: string,
    family?: string,
    limit?: number
  ): AnalysisEvidence[] {
    let sql = 'SELECT * FROM analysis_evidence WHERE sample_id = ?'
    const params: any[] = [sampleId]
    if (family) {
      sql += ' AND evidence_family = ?'
      params.push(family)
    }
    sql += ' ORDER BY updated_at DESC, created_at DESC, id DESC'
    if (typeof limit === 'number') {
      sql += ' LIMIT ?'
      params.push(limit)
    }
    const stmt = this.db.prepare(sql)
    return stmt.all(...params) as AnalysisEvidence[]
  }

  findBoundedAnalysisEvidenceBySample(
    sampleId: string,
    options: {
      families?: string[]
      maxRows: number
      maxScanRows?: number
      maxResultJsonBytes: number
      maxTotalResultJsonBytes: number
    }
  ): BoundedAnalysisEvidenceResult {
    const families = Array.from(
      new Set((options.families ?? []).filter((family) => family.trim().length > 0))
    )
    const familyFilter =
      families.length > 0 ? `WHERE evidence_family IN (${families.map(() => '?').join(', ')})` : ''
    const resultBytesSql = `length(CAST(COALESCE(result_json, '') AS BLOB))`
    const maxScanRows = Math.max(options.maxRows, options.maxScanRows ?? options.maxRows * 2)
    const stats = this.queryOneSql<{
      total_rows: number
      eligible_rows: number
      oversized_rows: number
    }>(
      `
        WITH candidates AS (
          SELECT id, evidence_family, ${resultBytesSql} AS result_bytes
          FROM analysis_evidence
          WHERE sample_id = ?
          ORDER BY updated_at DESC, created_at DESC, id DESC
          LIMIT ?
        ),
        filtered AS (
          SELECT result_bytes
          FROM candidates
          ${familyFilter}
        )
        SELECT
          (SELECT COUNT(*) FROM candidates) AS total_rows,
          COALESCE(SUM(CASE WHEN result_bytes <= ? THEN 1 ELSE 0 END), 0) AS eligible_rows,
          COALESCE(SUM(CASE WHEN result_bytes > ? THEN 1 ELSE 0 END), 0) AS oversized_rows
        FROM filtered
      `,
      [sampleId, maxScanRows, ...families, options.maxResultJsonBytes, options.maxResultJsonBytes]
    ) ?? { total_rows: 0, eligible_rows: 0, oversized_rows: 0 }

    const boundedRows = this.querySql<AnalysisEvidence & { _result_bytes: number }>(
      `
        WITH candidates AS (
          SELECT
            id,
            evidence_family,
            updated_at,
            created_at,
            ${resultBytesSql} AS result_bytes
          FROM analysis_evidence
          WHERE sample_id = ?
          ORDER BY updated_at DESC, created_at DESC, id DESC
          LIMIT ?
        ),
        eligible AS (
          SELECT id, updated_at, created_at, result_bytes
          FROM candidates
          ${familyFilter}
          ${familyFilter ? 'AND' : 'WHERE'} result_bytes <= ?
        ),
        budgeted AS (
          SELECT
            id,
            updated_at,
            created_at,
            result_bytes,
            SUM(result_bytes) OVER (
              ORDER BY updated_at DESC, created_at DESC, id DESC
            ) AS cumulative_bytes
          FROM eligible
        ),
        selected AS (
          SELECT id, updated_at, created_at, result_bytes
          FROM budgeted
          WHERE cumulative_bytes <= ?
          ORDER BY updated_at DESC, created_at DESC, id DESC
          LIMIT ?
        )
        SELECT evidence.*, selected.result_bytes AS _result_bytes
        FROM selected
        JOIN analysis_evidence AS evidence ON evidence.id = selected.id
        ORDER BY selected.updated_at DESC, selected.created_at DESC, selected.id DESC
      `,
      [
        sampleId,
        maxScanRows,
        ...families,
        options.maxResultJsonBytes,
        options.maxTotalResultJsonBytes,
        options.maxRows,
      ]
    )
    const selectedBytes = boundedRows.reduce(
      (sum, row) => sum + (Number.isFinite(row._result_bytes) ? row._result_bytes : 0),
      0
    )
    const rows = boundedRows.map(({ _result_bytes: _ignored, ...row }) => row as AnalysisEvidence)

    return {
      rows,
      total_rows: stats.total_rows,
      eligible_rows: stats.eligible_rows,
      oversized_rows: stats.oversized_rows,
      selected_bytes: selectedBytes,
      truncated: stats.eligible_rows > rows.length || stats.total_rows >= maxScanRows,
      scan_truncated: stats.total_rows >= maxScanRows,
    }
  }

  findLatestCompatibleAnalysisEvidence(
    sampleId: string,
    evidenceFamily: string,
    compatibilityMarker: string
  ): AnalysisEvidence | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM analysis_evidence
      WHERE sample_id = ? AND evidence_family = ? AND compatibility_marker = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT 1
    `)
    return stmt.get(sampleId, evidenceFamily, compatibilityMarker) as AnalysisEvidence | undefined
  }

  insertDebugSession(session: DebugSession): void {
    const stmt = this.db.prepare(`
      INSERT INTO debug_sessions (
        id, run_id, sample_id, sample_sha256, status, debug_state, backend, current_phase,
        session_tag, artifact_refs_json, guidance_json, metadata_json, created_at, updated_at, finished_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      session.id,
      session.run_id,
      session.sample_id,
      session.sample_sha256,
      session.status,
      session.debug_state,
      session.backend,
      session.current_phase,
      session.session_tag,
      session.artifact_refs_json,
      session.guidance_json,
      session.metadata_json,
      session.created_at,
      session.updated_at,
      session.finished_at
    )
  }

  updateDebugSession(
    sessionId: string,
    updates: Partial<Omit<DebugSession, 'id' | 'sample_id' | 'sample_sha256' | 'created_at'>>
  ): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.run_id !== undefined) {
      fields.push('run_id = ?')
      values.push(updates.run_id)
    }
    if (updates.status !== undefined) {
      fields.push('status = ?')
      values.push(updates.status)
    }
    if (updates.debug_state !== undefined) {
      fields.push('debug_state = ?')
      values.push(updates.debug_state)
    }
    if (updates.backend !== undefined) {
      fields.push('backend = ?')
      values.push(updates.backend)
    }
    if (updates.current_phase !== undefined) {
      fields.push('current_phase = ?')
      values.push(updates.current_phase)
    }
    if (updates.session_tag !== undefined) {
      fields.push('session_tag = ?')
      values.push(updates.session_tag)
    }
    if (updates.artifact_refs_json !== undefined) {
      fields.push('artifact_refs_json = ?')
      values.push(updates.artifact_refs_json)
    }
    if (updates.guidance_json !== undefined) {
      fields.push('guidance_json = ?')
      values.push(updates.guidance_json)
    }
    if (updates.metadata_json !== undefined) {
      fields.push('metadata_json = ?')
      values.push(updates.metadata_json)
    }
    if (updates.updated_at !== undefined) {
      fields.push('updated_at = ?')
      values.push(updates.updated_at)
    }
    if (updates.finished_at !== undefined) {
      fields.push('finished_at = ?')
      values.push(updates.finished_at)
    }

    if (fields.length === 0) {
      return
    }

    values.push(sessionId)
    const stmt = this.db.prepare(`
      UPDATE debug_sessions SET ${fields.join(', ')} WHERE id = ?
    `)
    stmt.run(...values)
  }

  findDebugSession(sessionId: string): DebugSession | undefined {
    const stmt = this.db.prepare('SELECT * FROM debug_sessions WHERE id = ?')
    return stmt.get(sessionId) as DebugSession | undefined
  }

  findLatestDebugSessionByRun(runId: string): DebugSession | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM debug_sessions
      WHERE run_id = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT 1
    `)
    return stmt.get(runId) as DebugSession | undefined
  }

  findLatestDebugSessionBySample(sampleId: string): DebugSession | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM debug_sessions
      WHERE sample_id = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT 1
    `)
    return stmt.get(sampleId) as DebugSession | undefined
  }

  findDebugSessionsBySample(sampleId: string, limit: number = 20): DebugSession[] {
    const stmt = this.db.prepare(`
      SELECT * FROM debug_sessions
      WHERE sample_id = ?
      ORDER BY datetime(updated_at) DESC
      LIMIT ?
    `)
    return stmt.all(sampleId, Math.max(1, Math.min(limit, 200))) as DebugSession[]
  }

  upsertAnalysisRunStage(stage: AnalysisRunStage): void {
    const stmt = this.db.prepare(`
      INSERT INTO analysis_run_stages (
        run_id, stage, status, execution_state, tool, job_id,
        result_json, artifact_refs_json, coverage_json, metadata_json,
        created_at, updated_at, started_at, finished_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(run_id, stage) DO UPDATE SET
        status = excluded.status,
        execution_state = excluded.execution_state,
        tool = excluded.tool,
        job_id = excluded.job_id,
        result_json = excluded.result_json,
        artifact_refs_json = excluded.artifact_refs_json,
        coverage_json = excluded.coverage_json,
        metadata_json = excluded.metadata_json,
        updated_at = excluded.updated_at,
        started_at = excluded.started_at,
        finished_at = excluded.finished_at
    `)
    stmt.run(
      stage.run_id,
      stage.stage,
      stage.status,
      stage.execution_state,
      stage.tool,
      stage.job_id,
      stage.result_json,
      stage.artifact_refs_json,
      stage.coverage_json,
      stage.metadata_json,
      stage.created_at,
      stage.updated_at,
      stage.started_at,
      stage.finished_at
    )
  }

  findAnalysisRunStage(runId: string, stage: string): AnalysisRunStage | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM analysis_run_stages WHERE run_id = ? AND stage = ?
    `)
    return stmt.get(runId, stage) as AnalysisRunStage | undefined
  }

  findAnalysisRunStages(runId: string): AnalysisRunStage[] {
    const stmt = this.db.prepare(`
      SELECT * FROM analysis_run_stages
      WHERE run_id = ?
      ORDER BY datetime(created_at) ASC, stage ASC
    `)
    return stmt.all(runId) as AnalysisRunStage[]
  }

  /**
   * Find recent samples ordered by creation time.
   */
  findRecentSamples(limit: number = 20): Sample[] {
    const safeLimit = Math.max(1, Math.min(limit, 500))
    const stmt = this.db.prepare('SELECT * FROM samples ORDER BY datetime(created_at) DESC LIMIT ?')
    return stmt.all(safeLimit) as Sample[]
  }

  /**
   * Mark stale running analyses as failed so persisted status does not remain misleading.
   */
  reapStaleAnalyses(maxRuntimeMs: number, sampleId?: string): Analysis[] {
    const cutoffIso = new Date(Date.now() - maxRuntimeMs).toISOString()
    const params: any[] = [cutoffIso]
    const sampleClause = sampleId ? ' AND sample_id = ?' : ''
    if (sampleId) {
      params.push(sampleId)
    }

    const selectStmt = this.db.prepare(
      `SELECT * FROM analyses
       WHERE status = 'running'
         AND started_at IS NOT NULL
         AND started_at < ?${sampleClause}
       ORDER BY started_at ASC`
    )
    const stale = selectStmt.all(...params) as Analysis[]
    if (stale.length === 0) {
      return []
    }

    const updateStmt = this.db.prepare(`
      UPDATE analyses
      SET status = ?, finished_at = ?, output_json = ?, metrics_json = ?
      WHERE id = ?
    `)
    const finishedAt = new Date().toISOString()

    const updated = this.db.transaction((rows: Analysis[]) => {
      for (const row of rows) {
        const error = `E_TIMEOUT: stale persisted analysis reaped after exceeding ${maxRuntimeMs}ms`
        let output: Record<string, unknown> = {}
        try {
          output =
            row.output_json && row.output_json.trim().length > 0
              ? (JSON.parse(row.output_json) as Record<string, unknown>)
              : {}
        } catch {
          output = {}
        }

        output = {
          ...output,
          error,
          stale_reaped: true,
          stale_reaped_at: finishedAt,
        }

        let metrics: Record<string, unknown> = {}
        try {
          metrics =
            row.metrics_json && row.metrics_json.trim().length > 0
              ? (JSON.parse(row.metrics_json) as Record<string, unknown>)
              : {}
        } catch {
          metrics = {}
        }

        const startedAtMs = row.started_at ? new Date(row.started_at).getTime() : NaN
        const elapsedMs = Number.isFinite(startedAtMs)
          ? Math.max(0, Date.now() - startedAtMs)
          : maxRuntimeMs

        metrics = {
          ...metrics,
          elapsed_ms: elapsedMs,
          stale_reaped: true,
        }

        updateStmt.run(
          'failed',
          finishedAt,
          JSON.stringify(output),
          JSON.stringify(metrics),
          row.id
        )
      }
    })

    updated(stale)

    return stale.map((row) => ({
      ...row,
      status: 'failed',
      finished_at: finishedAt,
      output_json: JSON.stringify({
        ...(row.output_json
          ? (() => {
              try {
                return JSON.parse(row.output_json)
              } catch {
                return {}
              }
            })()
          : {}),
        error: `E_TIMEOUT: stale persisted analysis reaped after exceeding ${maxRuntimeMs}ms`,
        stale_reaped: true,
        stale_reaped_at: finishedAt,
      }),
      metrics_json: JSON.stringify({
        ...(row.metrics_json
          ? (() => {
              try {
                return JSON.parse(row.metrics_json)
              } catch {
                return {}
              }
            })()
          : {}),
        stale_reaped: true,
      }),
    }))
  }

  // ==================== Function Operations ====================

  /**
   * Insert a new function
   */
  insertFunction(func: Function): void {
    const stmt = this.db.prepare(`
      INSERT INTO functions (sample_id, address, name, size, score, tags, summary, caller_count, callee_count, is_entry_point, is_exported, callees)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      func.sample_id,
      func.address,
      func.name,
      func.size,
      func.score,
      func.tags,
      func.summary,
      func.caller_count ?? 0,
      func.callee_count ?? 0,
      func.is_entry_point ?? 0,
      func.is_exported ?? 0,
      func.callees
    )
  }

  /**
   * Find all functions for a sample
   */
  findFunctions(sampleId: string): Function[] {
    const stmt = this.db.prepare('SELECT * FROM functions WHERE sample_id = ? ORDER BY address')
    return stmt.all(sampleId) as Function[]
  }

  /**
   * Find functions by sample with score ordering
   */
  findFunctionsByScore(sampleId: string, limit?: number): Function[] {
    let sql = 'SELECT * FROM functions WHERE sample_id = ? ORDER BY score DESC'
    if (limit !== undefined) {
      sql += ` LIMIT ${limit}`
    }
    const stmt = this.db.prepare(sql)
    return stmt.all(sampleId) as Function[]
  }

  /**
   * Update a function
   */
  updateFunction(
    sampleId: string,
    address: string,
    updates: Partial<Omit<Function, 'sample_id' | 'address'>>
  ): void {
    const fields: string[] = []
    const values: any[] = []

    if (updates.name !== undefined) {
      fields.push('name = ?')
      values.push(updates.name)
    }
    if (updates.size !== undefined) {
      fields.push('size = ?')
      values.push(updates.size)
    }
    if (updates.score !== undefined) {
      fields.push('score = ?')
      values.push(updates.score)
    }
    if (updates.tags !== undefined) {
      fields.push('tags = ?')
      values.push(updates.tags)
    }
    if (updates.summary !== undefined) {
      fields.push('summary = ?')
      values.push(updates.summary)
    }

    if (fields.length === 0) {
      return // No updates to perform
    }

    values.push(sampleId, address)
    const stmt = this.db.prepare(`
      UPDATE functions SET ${fields.join(', ')} WHERE sample_id = ? AND address = ?
    `)
    stmt.run(...values)
  }

  // ==================== Artifact Operations ====================

  /**
   * Insert a new artifact
   */
  insertArtifact(artifact: Artifact): void {
    const stmt = this.db.prepare(`
      INSERT INTO artifacts (id, sample_id, type, path, sha256, mime, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      artifact.id,
      artifact.sample_id,
      artifact.type,
      artifact.path,
      artifact.sha256,
      artifact.mime,
      artifact.created_at
    )
  }

  /**
   * Insert an artifact only while the supplied context-write fencing token still owns its lease.
   * The ownership predicate and insert are one SQLite statement so a stale writer cannot commit
   * after another process has completed a CAS takeover.
   */
  insertArtifactIfContextLeaseOwned(
    artifact: Artifact,
    lockKey: string,
    ownerToken: string
  ): boolean {
    const stmt = this.db.prepare(`
      INSERT INTO artifacts (id, sample_id, type, path, sha256, mime, created_at)
      SELECT ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1
        FROM context_write_leases
        WHERE lock_key = ? AND owner_token = ?
      )
    `)
    const result = stmt.run(
      artifact.id,
      artifact.sample_id,
      artifact.type,
      artifact.path,
      artifact.sha256,
      artifact.mime,
      artifact.created_at,
      lockKey,
      ownerToken
    )
    return result.changes === 1
  }

  /**
   * Find all artifacts for a sample
   */
  findArtifacts(sampleId: string): Artifact[] {
    const stmt = this.db.prepare(
      'SELECT * FROM artifacts WHERE sample_id = ? ORDER BY created_at DESC'
    )
    return stmt.all(sampleId) as Artifact[]
  }

  /**
   * Find all artifacts across all samples
   */
  findAllArtifacts(): Artifact[] {
    const stmt = this.db.prepare('SELECT * FROM artifacts ORDER BY created_at DESC')
    return stmt.all() as Artifact[]
  }

  /**
   * Find artifact by ID
   */
  findArtifact(artifactId: string): Artifact | null {
    const stmt = this.db.prepare('SELECT * FROM artifacts WHERE id = ?')
    return stmt.get(artifactId) as Artifact | null
  }

  /**
   * Delete artifact by ID
   */
  deleteArtifact(artifactId: string): void {
    const stmt = this.db.prepare('DELETE FROM artifacts WHERE id = ?')
    stmt.run(artifactId)
  }

  /**
   * Find artifacts by sample and type
   */
  findArtifactsByType(sampleId: string, type: string): Artifact[] {
    const stmt = this.db.prepare(
      'SELECT * FROM artifacts WHERE sample_id = ? AND type = ? ORDER BY created_at DESC'
    )
    return stmt.all(sampleId, type) as Artifact[]
  }

  countArtifactsByType(sampleId: string, type: string): number {
    const stmt = this.db.prepare(
      'SELECT COUNT(*) AS count FROM artifacts WHERE sample_id = ? AND type = ?'
    )
    const row = stmt.get(sampleId, type) as { count: number }
    return row.count
  }

  findArtifactsByTypeLimited(sampleId: string, type: string, limit: number): Artifact[] {
    if (!Number.isInteger(limit) || limit <= 0) {
      throw new Error('Artifact query limit must be a positive integer.')
    }
    const stmt = this.db.prepare(
      'SELECT * FROM artifacts WHERE sample_id = ? AND type = ? ORDER BY created_at DESC, rowid DESC LIMIT ?'
    )
    return stmt.all(sampleId, type, limit) as Artifact[]
  }

  // ==================== Context Write Lease Operations ====================

  /**
   * Atomically acquire a context writer lease, or take over an observed stale owner with CAS.
   */
  tryAcquireContextWriteLease(
    requested: ContextWriteLease,
    staleBefore: string
  ): ContextWriteLeaseAcquireResult {
    const acquire = this.db.transaction((): ContextWriteLeaseAcquireResult => {
      const inserted = this.db
        .prepare(
          `INSERT OR IGNORE INTO context_write_leases
            (lock_key, owner_token, host_id, pid, acquired_at, heartbeat_at)
           VALUES (?, ?, ?, ?, ?, ?)`
        )
        .run(
          requested.lock_key,
          requested.owner_token,
          requested.host_id,
          requested.pid,
          requested.acquired_at,
          requested.heartbeat_at
        )
      if (inserted.changes === 1) {
        return { acquired: true, takeover: false, lease: requested }
      }

      const incumbent = this.db
        .prepare('SELECT * FROM context_write_leases WHERE lock_key = ?')
        .get(requested.lock_key) as ContextWriteLease | undefined
      if (!incumbent || incumbent.heartbeat_at > staleBefore) {
        return { acquired: false, takeover: false, lease: incumbent || null }
      }

      const takenOver = this.db
        .prepare(
          `UPDATE context_write_leases
           SET owner_token = ?, host_id = ?, pid = ?, acquired_at = ?, heartbeat_at = ?
           WHERE lock_key = ?
             AND owner_token = ?
             AND heartbeat_at = ?
             AND heartbeat_at <= ?`
        )
        .run(
          requested.owner_token,
          requested.host_id,
          requested.pid,
          requested.acquired_at,
          requested.heartbeat_at,
          requested.lock_key,
          incumbent.owner_token,
          incumbent.heartbeat_at,
          staleBefore
        )
      if (takenOver.changes === 1) {
        return { acquired: true, takeover: true, lease: requested }
      }

      const current = this.db
        .prepare('SELECT * FROM context_write_leases WHERE lock_key = ?')
        .get(requested.lock_key) as ContextWriteLease | undefined
      return { acquired: false, takeover: false, lease: current || null }
    })

    return acquire()
  }

  /** Refresh and assert lease ownership in one owner-token-conditional write. */
  heartbeatContextWriteLease(lockKey: string, ownerToken: string, heartbeatAt: string): boolean {
    const result = this.db
      .prepare(
        `UPDATE context_write_leases
         SET heartbeat_at = ?
         WHERE lock_key = ? AND owner_token = ? AND heartbeat_at <= ?`
      )
      .run(heartbeatAt, lockKey, ownerToken, heartbeatAt)
    return result.changes === 1
  }

  /** Release only the lease still owned by ownerToken. */
  releaseContextWriteLease(lockKey: string, ownerToken: string): boolean {
    const result = this.db
      .prepare('DELETE FROM context_write_leases WHERE lock_key = ? AND owner_token = ?')
      .run(lockKey, ownerToken)
    return result.changes === 1
  }

  findContextWriteLease(lockKey: string): ContextWriteLease | null {
    const row = this.db
      .prepare('SELECT * FROM context_write_leases WHERE lock_key = ?')
      .get(lockKey) as ContextWriteLease | undefined
    return row || null
  }

  // ==================== Cache Operations ====================

  /**
   * Get cached result from database
   * Requirements: 20.5
   */
  async getCachedResult(key: string): Promise<{
    data: unknown
    createdAt?: string
    expiresAt?: string
    sampleSha256?: string
  } | null> {
    const stmt = this.db.prepare(
      'SELECT data, created_at, expires_at, sample_sha256 FROM cache WHERE key = ?'
    )
    const row = stmt.get(key) as
      | {
          data: string
          created_at: string | null
          expires_at: string | null
          sample_sha256: string | null
        }
      | undefined

    if (!row) {
      return null
    }

    try {
      const data = JSON.parse(row.data)
      return {
        data,
        createdAt: row.created_at || undefined,
        expiresAt: row.expires_at || undefined,
        sampleSha256: row.sample_sha256 || undefined,
      }
    } catch (error) {
      // Invalid JSON, remove from cache
      this.db.prepare('DELETE FROM cache WHERE key = ?').run(key)
      return null
    }
  }

  /**
   * Set cached result in database
   * Requirements: 20.5
   */
  async setCachedResult(
    key: string,
    data: unknown,
    expiresAt?: string,
    sampleSha256?: string
  ): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO cache (key, data, sample_sha256, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `)

    stmt.run(
      key,
      JSON.stringify(data),
      sampleSha256 || null,
      new Date().toISOString(),
      expiresAt || null
    )
  }

  /**
   * Delete expired cache entries
   */
  cleanExpiredCache(): number {
    const stmt = this.db.prepare(
      'DELETE FROM cache WHERE expires_at IS NOT NULL AND expires_at < ?'
    )
    const result = stmt.run(new Date().toISOString())
    return result.changes
  }

  /**
   * Get recent cache entries for prewarming
   * Requirements: 26.1 (cache prewarming), 26.2 (query optimization)
   *
   * @param limit - Maximum number of entries to return
   * @returns Array of cache entries ordered by creation time (most recent first)
   */
  async getRecentCacheEntries(
    limit: number
  ): Promise<Array<{ key: string; data: string; expires_at: string | null }>> {
    const stmt = this.db.prepare(`
      SELECT key, data, expires_at 
      FROM cache 
      WHERE expires_at IS NULL OR expires_at > ?
      ORDER BY created_at DESC 
      LIMIT ?
    `)
    return stmt.all(new Date().toISOString(), limit) as Array<{
      key: string
      data: string
      expires_at: string | null
    }>
  }

  /**
   * Get cache entries for a specific sample
   * Requirements: 26.1 (cache prewarming), 26.2 (query optimization)
   *
   * @param sampleSha256 - SHA256 hash of the sample
   * @returns Array of cache entries for the sample
   */
  async getCacheEntriesBySample(
    sampleSha256: string
  ): Promise<Array<{ key: string; data: string; expires_at: string | null }>> {
    // Query cache entries by sample_sha256 column
    const stmt = this.db.prepare(`
      SELECT key, data, expires_at 
      FROM cache 
      WHERE sample_sha256 = ?
        AND (expires_at IS NULL OR expires_at > ?)
      ORDER BY created_at DESC
    `)
    return stmt.all(sampleSha256, new Date().toISOString()) as Array<{
      key: string
      data: string
      expires_at: string | null
    }>
  }

  /**
   * Batch insert functions for better performance
   * Requirements: 26.2 (database query optimization)
   *
   * @param functions - Array of functions to insert
   */
  insertFunctionsBatch(functions: Function[]): void {
    if (functions.length === 0) {
      return
    }

    // Use transaction for batch insert
    const insertStmt = this.db.prepare(`
      INSERT OR REPLACE INTO functions (sample_id, address, name, size, score, tags, summary, caller_count, callee_count, is_entry_point, is_exported, callees)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

    const insertMany = this.db.transaction((funcs: Function[]) => {
      for (const func of funcs) {
        insertStmt.run(
          func.sample_id,
          func.address,
          func.name,
          func.size,
          func.score,
          func.tags,
          func.summary,
          func.caller_count ?? 0,
          func.callee_count ?? 0,
          func.is_entry_point ?? 0,
          func.is_exported ?? 0,
          func.callees
        )
      }
    })

    insertMany(functions)
  }

  /**
   * Batch insert artifacts for better performance
   * Requirements: 26.2 (database query optimization)
   *
   * @param artifacts - Array of artifacts to insert
   */
  insertArtifactsBatch(artifacts: Artifact[]): void {
    if (artifacts.length === 0) {
      return
    }

    // Use transaction for batch insert
    const insertStmt = this.db.prepare(`
      INSERT INTO artifacts (id, sample_id, type, path, sha256, mime, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)

    const insertMany = this.db.transaction((arts: Artifact[]) => {
      for (const artifact of arts) {
        insertStmt.run(
          artifact.id,
          artifact.sample_id,
          artifact.type,
          artifact.path,
          artifact.sha256,
          artifact.mime,
          artifact.created_at
        )
      }
    })

    insertMany(artifacts)
  }

  /**
   * Optimize database by running VACUUM and ANALYZE
   * Requirements: 26.2 (database query optimization)
   *
   * Should be run periodically to maintain performance
   */
  optimizeDatabase(): void {
    // ANALYZE updates statistics for query planner
    this.db.exec('ANALYZE')

    // VACUUM reclaims space and defragments
    // Note: VACUUM can be slow on large databases
    this.db.exec('VACUUM')
  }

  /**
   * Get database statistics for monitoring
   * Requirements: 26.2 (database query optimization)
   *
   * @returns Object with database statistics
   */
  getDatabaseStats(): {
    sampleCount: number
    analysisCount: number
    functionCount: number
    artifactCount: number
    cacheCount: number
    dbSizeBytes: number
  } {
    const sampleCount = this.db.prepare('SELECT COUNT(*) as count FROM samples').get() as {
      count: number
    }
    const analysisCount = this.db.prepare('SELECT COUNT(*) as count FROM analyses').get() as {
      count: number
    }
    const functionCount = this.db.prepare('SELECT COUNT(*) as count FROM functions').get() as {
      count: number
    }
    const artifactCount = this.db.prepare('SELECT COUNT(*) as count FROM artifacts').get() as {
      count: number
    }
    const cacheCount = this.db.prepare('SELECT COUNT(*) as count FROM cache').get() as {
      count: number
    }

    // Get database file size
    const dbPath = (this.db as { name?: string }).name // Access internal property
    let dbSizeBytes = 0
    try {
      if (typeof dbPath === 'string' && dbPath.length > 0) {
        const stats = fs.statSync(dbPath)
        dbSizeBytes = stats.size
      }
    } catch (e) {
      // DB file size read is best-effort
      logDebug?.('db_file_size_read_failed', { err: String(e) })
    }

    return {
      sampleCount: sampleCount.count,
      analysisCount: analysisCount.count,
      functionCount: functionCount.count,
      artifactCount: artifactCount.count,
      cacheCount: cacheCount.count,
      dbSizeBytes,
    }
  }

  // Batch submission methods

  createBatch(batch: Batch): void {
    const stmt = this.db.prepare(`
      INSERT INTO batches (id, status, total_samples, completed_samples, failed_samples, cancelled_samples, metadata_json, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      batch.id,
      batch.status,
      batch.total_samples,
      batch.completed_samples,
      batch.failed_samples,
      batch.cancelled_samples,
      batch.metadata_json,
      batch.created_at,
      batch.updated_at
    )
  }

  findBatch(batchId: string): Batch | null {
    const stmt = this.db.prepare('SELECT * FROM batches WHERE id = ?')
    return stmt.get(batchId) as Batch | null
  }

  updateBatch(batchId: string, batch: Batch): void {
    const stmt = this.db.prepare(`
      UPDATE batches
      SET status = ?, total_samples = ?, completed_samples = ?, failed_samples = ?, cancelled_samples = ?, metadata_json = ?, updated_at = ?
      WHERE id = ?
    `)
    stmt.run(
      batch.status,
      batch.total_samples,
      batch.completed_samples,
      batch.failed_samples,
      batch.cancelled_samples,
      batch.metadata_json,
      batch.updated_at,
      batchId
    )
  }

  deleteBatch(batchId: string): void {
    const stmt = this.db.prepare('DELETE FROM batches WHERE id = ?')
    stmt.run(batchId)
  }

  findBatches(options?: { status?: string; limit?: number; offset?: number }): Batch[] {
    let sql = 'SELECT * FROM batches'
    const params: any[] = []

    if (options?.status) {
      sql += ' WHERE status = ?'
      params.push(options.status)
    }

    sql += ' ORDER BY created_at DESC'

    if (options?.limit) {
      sql += ' LIMIT ?'
      params.push(options.limit)
    }

    if (options?.offset) {
      sql += ' OFFSET ?'
      params.push(options.offset)
    }

    const stmt = this.db.prepare(sql)
    return stmt.all(...params) as Batch[]
  }

  createBatchSample(batchSample: BatchSample): void {
    const stmt = this.db.prepare(`
      INSERT INTO batch_samples (batch_id, sample_id, status, filename, size, sha256, artifact_refs_json, error, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    stmt.run(
      batchSample.batch_id,
      batchSample.sample_id,
      batchSample.status,
      batchSample.filename,
      batchSample.size,
      batchSample.sha256,
      batchSample.artifact_refs_json,
      batchSample.error,
      batchSample.created_at,
      batchSample.updated_at
    )
  }

  findBatchSamples(batchId: string): BatchSample[] {
    const stmt = this.db.prepare('SELECT * FROM batch_samples WHERE batch_id = ?')
    return stmt.all(batchId) as BatchSample[]
  }

  findBatchSample(batchId: string, sampleId: string): BatchSample | null {
    const stmt = this.db.prepare('SELECT * FROM batch_samples WHERE batch_id = ? AND sample_id = ?')
    return stmt.get(batchId, sampleId) as BatchSample | null
  }

  updateBatchSampleStatus(batchId: string, sampleId: string, status: string): void {
    const stmt = this.db.prepare(`
      UPDATE batch_samples
      SET status = ?, updated_at = ?
      WHERE batch_id = ? AND sample_id = ?
    `)
    stmt.run(status, new Date().toISOString(), batchId, sampleId)
  }

  // ============================================================================
  // Job Methods (for async job pattern)
  // Tasks: mcp-async-job-pattern 1.3
  // ============================================================================

  createJob(job: {
    id: string
    type: string
    tool: string
    sampleId: string
    args: Record<string, unknown>
    priority: number
    timeout: number
    estimatedDurationMs?: number
    retryPolicy?: { maxRetries: number; backoffMs: number; retryableErrors: string[] }
  }): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO jobs (
        id, type, tool, sample_id, args_json, priority, timeout,
        estimated_duration_ms, retry_policy_json, retry_count, status, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'queued', ?, ?)
    `)
    const now = new Date().toISOString()
    stmt.run(
      job.id,
      job.type,
      job.tool,
      job.sampleId,
      JSON.stringify(job.args),
      job.priority,
      job.timeout,
      job.estimatedDurationMs,
      job.retryPolicy ? JSON.stringify(job.retryPolicy) : null,
      now,
      now
    )
  }

  findJob(jobId: string): any | null {
    const stmt = this.db.prepare('SELECT * FROM jobs WHERE id = ?')
    const row = stmt.get(jobId) as any
    if (!row) return null

    let args: unknown = {}
    let result: unknown = null
    try {
      args = JSON.parse(row.args_json)
    } catch {
      // Keep raw args_json for fail-closed recovery validation.
    }
    try {
      result = row.result_json ? JSON.parse(row.result_json) : null
    } catch {
      // Malformed terminal results remain inspectable but never executable.
    }
    return { ...row, args, result }
  }

  updateJobStatus(jobId: string, status: string, progress?: number, error?: string): void {
    const updates: string[] = ['status = ?']
    const params: any[] = [status]

    if (progress !== undefined) {
      updates.push('progress = ?')
      params.push(progress)
    }

    if (error !== undefined) {
      updates.push('error = ?')
      params.push(error)
    }

    if (status === 'running' && progress === 0) {
      updates.push('started_at = ?')
      params.push(new Date().toISOString())
    }

    if (['completed', 'failed', 'cancelled'].includes(status)) {
      updates.push('finished_at = ?')
      params.push(new Date().toISOString())
    }

    updates.push('updated_at = ?')
    params.push(new Date().toISOString())

    params.push(jobId)

    const stmt = this.db.prepare(`
      UPDATE jobs SET ${updates.join(', ')} WHERE id = ?
    `)
    stmt.run(...params)
  }

  /** Atomically claim one queued job. Exactly one server instance can win. */
  claimQueuedJob(input: {
    jobId: string
    ownerInstanceId: string
    ownerBootId: string
    claimToken: string
    claimUntil: string
    now: string
  }): boolean {
    const result = this.db
      .prepare(
        `UPDATE jobs
       SET status = 'running', progress = 0, started_at = ?, updated_at = ?,
           owner_instance_id = ?, owner_boot_id = ?, claim_token = ?,
           claim_until = ?, claim_heartbeat_at = ?
       WHERE id = ? AND status = 'queued' AND claim_token IS NULL`
      )
      .run(
        input.now,
        input.now,
        input.ownerInstanceId,
        input.ownerBootId,
        input.claimToken,
        input.claimUntil,
        input.now,
        input.jobId
      )
    return result.changes === 1
  }

  heartbeatJobClaim(input: {
    jobId: string
    ownerInstanceId: string
    ownerBootId: string
    claimToken: string
    claimUntil: string
    now: string
  }): { owned: boolean; status?: string } {
    const transaction = this.db.transaction(() => {
      const result = this.db
        .prepare(
          `UPDATE jobs SET claim_until = ?, claim_heartbeat_at = ?, updated_at = ?
         WHERE id = ? AND owner_instance_id = ? AND owner_boot_id = ?
           AND claim_token = ? AND status IN ('running','cancelling','retry_wait')`
        )
        .run(
          input.claimUntil,
          input.now,
          input.now,
          input.jobId,
          input.ownerInstanceId,
          input.ownerBootId,
          input.claimToken
        )
      if (result.changes !== 1) return { owned: false }
      const row = this.db.prepare('SELECT status FROM jobs WHERE id = ?').get(input.jobId) as
        | { status: string }
        | undefined
      return { owned: true, status: row?.status }
    })
    return transaction.immediate()
  }

  updateOwnedJobStatus(input: {
    jobId: string
    ownerInstanceId: string
    ownerBootId: string
    claimToken: string
    expectedStatuses: string[]
    status: string
    progress?: number
    error?: string
    result?: unknown
    clearClaim?: boolean
    retryCount?: number
  }): boolean {
    if (input.expectedStatuses.length === 0) return false
    const updates = ['status = ?', 'updated_at = ?']
    const now = new Date().toISOString()
    const params: unknown[] = [input.status, now]
    if (input.progress !== undefined) {
      updates.push('progress = ?')
      params.push(input.progress)
    }
    if (input.error !== undefined) {
      updates.push('error = ?')
      params.push(input.error)
    }
    if (input.result !== undefined) {
      updates.push('result_json = ?')
      params.push(JSON.stringify(input.result))
    }
    if (input.retryCount !== undefined) {
      updates.push('retry_count = ?')
      params.push(input.retryCount)
    }
    if (['completed', 'failed', 'cancelled', 'interrupted'].includes(input.status)) {
      updates.push('finished_at = ?')
      params.push(now)
    }
    if (input.status === 'queued') {
      updates.push('started_at = NULL', 'finished_at = NULL')
    }
    if (input.clearClaim) {
      updates.push(
        'owner_instance_id = NULL',
        'owner_boot_id = NULL',
        'claim_token = NULL',
        'claim_until = NULL',
        'claim_heartbeat_at = NULL'
      )
    }
    const placeholders = input.expectedStatuses.map(() => '?').join(', ')
    params.push(
      input.jobId,
      input.ownerInstanceId,
      input.ownerBootId,
      input.claimToken,
      ...input.expectedStatuses
    )
    const result = this.db
      .prepare(
        `UPDATE jobs SET ${updates.join(', ')}
       WHERE id = ? AND owner_instance_id = ? AND owner_boot_id = ?
         AND claim_token = ? AND status IN (${placeholders})`
      )
      .run(...params)
    return result.changes === 1
  }

  /** Request cancellation without stealing the current execution claim. */
  requestJobCancellation(jobId: string, reason: string): 'cancelled' | 'cancelling' | null {
    const transaction = this.db.transaction(() => {
      const row = this.db.prepare('SELECT status FROM jobs WHERE id = ?').get(jobId) as
        | { status: string }
        | undefined
      if (!row) return null
      const now = new Date().toISOString()
      if (row.status === 'queued') {
        const result = this.db
          .prepare(
            `UPDATE jobs SET status = 'cancelled', error = ?, finished_at = ?, updated_at = ?
           WHERE id = ? AND status = 'queued'`
          )
          .run(reason, now, now, jobId)
        return result.changes === 1 ? 'cancelled' : null
      }
      if (row.status === 'retry_wait') {
        const result = this.db
          .prepare(
            `UPDATE jobs SET status = 'cancelled', error = ?, finished_at = ?, updated_at = ?,
             owner_instance_id = NULL, owner_boot_id = NULL, claim_token = NULL,
             claim_until = NULL, claim_heartbeat_at = NULL
           WHERE id = ? AND status = 'retry_wait'`
          )
          .run(reason, now, now, jobId)
        return result.changes === 1 ? 'cancelled' : null
      }
      if (row.status === 'running') {
        const result = this.db
          .prepare(
            `UPDATE jobs SET status = 'cancelling', error = ?, updated_at = ?
           WHERE id = ? AND status = ?`
          )
          .run(reason, now, jobId, row.status)
        return result.changes === 1 ? 'cancelling' : null
      }
      return row.status === 'cancelling' ? 'cancelling' : null
    })
    return transaction.immediate()
  }

  /** Recover only claims whose durable heartbeat lease is proven expired. */
  recoverExpiredJobClaim(
    jobId: string,
    now: string,
    reason: string
  ): 'queued' | 'interrupted' | null {
    const transaction = this.db.transaction(() => {
      const row = this.db
        .prepare(
          `SELECT status FROM jobs
         WHERE id = ? AND claim_token IS NOT NULL
           AND (claim_until IS NULL OR claim_until <= ?)`
        )
        .get(jobId, now) as { status: string } | undefined
      if (!row) return null
      if (row.status === 'retry_wait') {
        const result = this.db
          .prepare(
            `UPDATE jobs SET status = 'queued', started_at = NULL, updated_at = ?,
             owner_instance_id = NULL, owner_boot_id = NULL, claim_token = NULL,
             claim_until = NULL, claim_heartbeat_at = NULL
           WHERE id = ? AND status = 'retry_wait'
             AND claim_token IS NOT NULL AND (claim_until IS NULL OR claim_until <= ?)`
          )
          .run(now, jobId, now)
        return result.changes === 1 ? 'queued' : null
      }
      if (row.status === 'running' || row.status === 'cancelling') {
        const result = this.db
          .prepare(
            `UPDATE jobs SET status = 'interrupted', error = ?, finished_at = ?, updated_at = ?,
             owner_instance_id = NULL, owner_boot_id = NULL, claim_token = NULL,
             claim_until = NULL, claim_heartbeat_at = NULL
           WHERE id = ? AND status IN ('running','cancelling')
             AND claim_token IS NOT NULL AND (claim_until IS NULL OR claim_until <= ?)`
          )
          .run(reason, now, now, jobId, now)
        return result.changes === 1 ? 'interrupted' : null
      }
      return null
    })
    return transaction.immediate()
  }

  setJobResult(jobId: string, result: any): void {
    const stmt = this.db.prepare(`
      UPDATE jobs
      SET result_json = ?, status = 'completed', finished_at = ?, updated_at = ?
      WHERE id = ? AND claim_token IS NULL
    `)
    const now = new Date().toISOString()
    stmt.run(JSON.stringify(result), now, now, jobId)
  }

  findJobsByStatus(status: string, limit: number = 100): any[] {
    const stmt = this.db.prepare(
      'SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?'
    )
    return stmt.all(status, limit) as any[]
  }

  findJobsByStatuses(statuses: string[], limit: number = 200): any[] {
    if (statuses.length === 0) {
      return []
    }
    const placeholders = statuses.map(() => '?').join(', ')
    const stmt = this.db.prepare(
      `SELECT * FROM jobs WHERE status IN (${placeholders}) ORDER BY created_at DESC LIMIT ?`
    )
    return stmt.all(...statuses, limit) as any[]
  }

  findJobsByStatusesPage(
    statuses: string[],
    limit: number,
    cursor?: { createdAt: string; id: string }
  ): any[] {
    if (statuses.length === 0 || !Number.isInteger(limit) || limit < 1) return []
    const placeholders = statuses.map(() => '?').join(', ')
    const cursorClause = cursor ? ' AND (created_at > ? OR (created_at = ? AND id > ?))' : ''
    const params: unknown[] = [...statuses]
    if (cursor) params.push(cursor.createdAt, cursor.createdAt, cursor.id)
    params.push(limit)
    return this.db
      .prepare(
        `SELECT * FROM jobs WHERE status IN (${placeholders})${cursorClause}
       ORDER BY created_at ASC, id ASC LIMIT ?`
      )
      .all(...params) as any[]
  }

  findExpiredClaimedJobs(now: string, limit: number = 500): any[] {
    return this.db
      .prepare(
        `SELECT * FROM jobs
       WHERE status IN ('running','cancelling','retry_wait')
         AND claim_token IS NOT NULL AND (claim_until IS NULL OR claim_until <= ?)
       ORDER BY claim_until ASC, created_at ASC, id ASC LIMIT ?`
      )
      .all(now, limit) as any[]
  }

  markJobInterrupted(jobId: string, reason: string, result?: unknown): boolean {
    const updates: string[] = ['status = ?', 'error = ?', 'finished_at = ?', 'updated_at = ?']
    const now = new Date().toISOString()
    const params: any[] = ['interrupted', reason, now, now]
    if (result !== undefined) {
      updates.unshift('result_json = ?')
      params.unshift(JSON.stringify(result))
    }
    params.push(jobId, now)
    const stmt = this.db.prepare(`
      UPDATE jobs SET ${updates.join(', ')}
      WHERE id = ? AND (claim_token IS NULL OR claim_until IS NULL OR claim_until <= ?)
    `)
    return stmt.run(...params).changes === 1
  }

  /** Terminate persisted analysis stages whose worker cannot be recovered. */
  markAnalysisStagesInterruptedByJob(jobId: string, reason: string): void {
    const now = new Date().toISOString()
    const transaction = this.db.transaction(() => {
      const runRows = this.db
        .prepare('SELECT DISTINCT run_id FROM analysis_run_stages WHERE job_id = ?')
        .all(jobId) as Array<{ run_id: string }>
      this.db
        .prepare(
          `UPDATE analysis_run_stages
           SET status = 'interrupted', execution_state = 'interrupted',
               result_json = ?, metadata_json = ?, finished_at = ?, updated_at = ?
           WHERE job_id = ? AND status IN ('queued','running','partial')`
        )
        .run(
          JSON.stringify({ status: 'interrupted', error: reason }),
          JSON.stringify({ recovery_error: reason }),
          now,
          now,
          jobId
        )
      const updateRun = this.db.prepare(
        `UPDATE analysis_runs
         SET status = 'partial', updated_at = ?
         WHERE id = ? AND status IN ('queued','running')`
      )
      for (const row of runRows) updateRun.run(now, row.run_id)
    })
    transaction.immediate()
  }

  findJobsBySample(sampleId: string, limit: number = 50): any[] {
    const stmt = this.db.prepare(
      'SELECT * FROM jobs WHERE sample_id = ? ORDER BY created_at DESC LIMIT ?'
    )
    return stmt.all(sampleId, limit) as any[]
  }

  cleanupOldJobs(retentionHours: number = 24): number {
    const cutoff = new Date(Date.now() - retentionHours * 60 * 60 * 1000).toISOString()
    const stmt = this.db.prepare(
      "DELETE FROM jobs WHERE created_at < ? AND status IN ('completed', 'failed', 'cancelled')"
    )
    const result = stmt.run(cutoff)
    return result.changes
  }

  // ============================================================================
  // Runtime worker family state
  // ============================================================================

  upsertRuntimeWorkerFamilyState(state: RuntimeWorkerFamilyState): void {
    const stmt = this.db.prepare(`
      INSERT INTO runtime_worker_family_state (
        family, compatibility_key, deployment_key, pool_kind,
        live_workers, idle_workers, busy_workers, unhealthy_workers,
        warm_reuse_count, cold_start_count, eviction_count,
        last_error, metadata_json, created_at, updated_at, last_used_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(family, compatibility_key) DO UPDATE SET
        deployment_key = excluded.deployment_key,
        pool_kind = excluded.pool_kind,
        live_workers = excluded.live_workers,
        idle_workers = excluded.idle_workers,
        busy_workers = excluded.busy_workers,
        unhealthy_workers = excluded.unhealthy_workers,
        warm_reuse_count = excluded.warm_reuse_count,
        cold_start_count = excluded.cold_start_count,
        eviction_count = excluded.eviction_count,
        last_error = excluded.last_error,
        metadata_json = excluded.metadata_json,
        updated_at = excluded.updated_at,
        last_used_at = excluded.last_used_at
    `)
    stmt.run(
      state.family,
      state.compatibility_key,
      state.deployment_key,
      state.pool_kind,
      state.live_workers,
      state.idle_workers,
      state.busy_workers,
      state.unhealthy_workers,
      state.warm_reuse_count,
      state.cold_start_count,
      state.eviction_count,
      state.last_error,
      state.metadata_json,
      state.created_at,
      state.updated_at,
      state.last_used_at
    )
  }

  findRuntimeWorkerFamilyStates(family?: string): RuntimeWorkerFamilyState[] {
    const sql = family
      ? 'SELECT * FROM runtime_worker_family_state WHERE family = ? ORDER BY datetime(updated_at) DESC'
      : 'SELECT * FROM runtime_worker_family_state ORDER BY datetime(updated_at) DESC'
    const stmt = this.db.prepare(sql)
    return (family ? stmt.all(family) : stmt.all()) as RuntimeWorkerFamilyState[]
  }

  // ============================================================================
  // Scheduler telemetry
  // ============================================================================

  insertSchedulerEvent(event: SchedulerEvent): void {
    const stmt = this.db.prepare(`
      INSERT INTO scheduler_events (
        id, job_id, run_id, sample_id, tool, stage,
        execution_bucket, cost_class, decision, reason,
        worker_family, warm_reuse, cold_start, metadata_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    try {
      stmt.run(
        event.id,
        event.job_id,
        event.run_id,
        event.sample_id,
        event.tool,
        event.stage,
        event.execution_bucket,
        event.cost_class,
        event.decision,
        event.reason,
        event.worker_family,
        event.warm_reuse,
        event.cold_start,
        event.metadata_json,
        event.created_at
      )
    } catch (error) {
      if (isSqliteBusyError(error)) {
        logger.warn(
          {
            job_id: event.job_id,
            run_id: event.run_id,
            tool: event.tool,
            decision: event.decision,
            error: error instanceof Error ? error.message : String(error),
          },
          'Skipped scheduler telemetry event because SQLite was busy'
        )
        return
      }
      throw error
    }
  }

  findLatestSchedulerEventForJob(jobId: string): SchedulerEvent | null {
    const stmt = this.db.prepare(
      'SELECT * FROM scheduler_events WHERE job_id = ? ORDER BY datetime(created_at) DESC LIMIT 1'
    )
    return stmt.get(jobId) as SchedulerEvent | null
  }

  findLatestSchedulerEventForRun(runId: string): SchedulerEvent | null {
    const stmt = this.db.prepare(
      'SELECT * FROM scheduler_events WHERE run_id = ? ORDER BY datetime(created_at) DESC LIMIT 1'
    )
    return stmt.get(runId) as SchedulerEvent | null
  }
}

/**
 * Create and initialize a database instance
 */
export function createDatabase(dbPath: string): DatabaseManager {
  return new DatabaseManager(dbPath)
}
