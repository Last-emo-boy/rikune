/**
 * Database module for Windows EXE Decompiler MCP Server
 * Manages SQLite database schema and operations
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { logger, logDebug } from './logger.js';

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
  source TEXT
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
`;

/**
 * Database interface types
 */
export interface Sample {
  id: string; // sha256:<hex>
  sha256: string;
  md5: string | null;
  size: number;
  file_type: string | null;
  created_at: string;
  source: string | null;
}

export interface Analysis {
  id: string; // UUID
  sample_id: string; // FK -> samples.id
  stage: string; // fingerprint/strings/ghidra/dotnet/sandbox
  backend: string; // static/ghidra/dotnet/...
  status: string; // queued/running/done/failed
  started_at: string | null;
  finished_at: string | null;
  output_json: string | null; // 结构化结果
  metrics_json: string | null; // 性能指标
}

export interface Function {
  sample_id: string; // FK
  address: string;
  name: string | null;
  size: number | null;
  score: number | null; // 兴趣函数排序分
  tags: string | null; // JSON array
  summary: string | null;
  caller_count: number | null;
  callee_count: number | null;
  is_entry_point: number | null; // SQLite uses INTEGER for boolean (0/1)
  is_exported: number | null; // SQLite uses INTEGER for boolean (0/1)
  callees: string | null; // JSON array of callee names
}

export interface Artifact {
  id: string; // UUID
  sample_id: string; // FK
  type: string; // strings/json/report/resource_dump/cfg
  path: string; // workspace 相对路径
  sha256: string;
  mime: string | null;
  created_at: string;
}

export interface CachedResult {
  key: string;
  data: unknown;
  created_at: string;
  expires_at: string | null;
}

/**
 * Database manager class
 */
export class DatabaseManager {
  private db: Database.Database;

  constructor(dbPath: string) {
    // Ensure directory exists
    const dbDir = path.dirname(dbPath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
      logDebug('Created database directory', { path: dbDir });
    }

    // Initialize database
    logger.info({ dbPath }, 'Initializing database');
    this.db = new Database(dbPath);

    // Enable foreign keys
    this.db.pragma('foreign_keys = ON');

    // Initialize schema
    this.initializeSchema();
    logger.info('Database initialized successfully');
  }

  /**
   * Initialize database schema
   */
  private initializeSchema(): void {
    this.db.exec(SCHEMA_SQL);
  }

  /**
   * Get the underlying database instance
   */
  getDatabase(): Database.Database {
    return this.db;
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close();
  }

  /**
   * Execute a transaction
   */
  transaction<T>(fn: () => T): T {
    const txn = this.db.transaction(fn);
    return txn();
  }

  // ==================== Sample Operations ====================

  /**
   * Insert a new sample
   */
  insertSample(sample: Sample): void {
    const stmt = this.db.prepare(`
      INSERT INTO samples (id, sha256, md5, size, file_type, created_at, source)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      sample.id,
      sample.sha256,
      sample.md5,
      sample.size,
      sample.file_type,
      sample.created_at,
      sample.source
    );
  }

  /**
   * Find a sample by ID
   */
  findSample(sampleId: string): Sample | undefined {
    const stmt = this.db.prepare('SELECT * FROM samples WHERE id = ?');
    return stmt.get(sampleId) as Sample | undefined;
  }

  /**
   * Find a sample by SHA256
   */
  findSampleBySha256(sha256: string): Sample | undefined {
    const stmt = this.db.prepare('SELECT * FROM samples WHERE sha256 = ?');
    return stmt.get(sha256) as Sample | undefined;
  }

  // ==================== Analysis Operations ====================

  /**
   * Insert a new analysis
   */
  insertAnalysis(analysis: Analysis): void {
    const stmt = this.db.prepare(`
      INSERT INTO analyses (id, sample_id, stage, backend, status, started_at, finished_at, output_json, metrics_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
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
    );
  }

  /**
   * Update an analysis
   */
  updateAnalysis(
    analysisId: string,
    updates: Partial<Omit<Analysis, 'id' | 'sample_id'>>
  ): void {
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.stage !== undefined) {
      fields.push('stage = ?');
      values.push(updates.stage);
    }
    if (updates.backend !== undefined) {
      fields.push('backend = ?');
      values.push(updates.backend);
    }
    if (updates.status !== undefined) {
      fields.push('status = ?');
      values.push(updates.status);
    }
    if (updates.started_at !== undefined) {
      fields.push('started_at = ?');
      values.push(updates.started_at);
    }
    if (updates.finished_at !== undefined) {
      fields.push('finished_at = ?');
      values.push(updates.finished_at);
    }
    if (updates.output_json !== undefined) {
      fields.push('output_json = ?');
      values.push(updates.output_json);
    }
    if (updates.metrics_json !== undefined) {
      fields.push('metrics_json = ?');
      values.push(updates.metrics_json);
    }

    if (fields.length === 0) {
      return; // No updates to perform
    }

    values.push(analysisId);
    const stmt = this.db.prepare(`
      UPDATE analyses SET ${fields.join(', ')} WHERE id = ?
    `);
    stmt.run(...values);
  }

  /**
   * Find an analysis by ID
   */
  findAnalysis(analysisId: string): Analysis | undefined {
    const stmt = this.db.prepare('SELECT * FROM analyses WHERE id = ?');
    return stmt.get(analysisId) as Analysis | undefined;
  }

  /**
   * Find all analyses for a sample
   */
  findAnalysesBySample(sampleId: string): Analysis[] {
    const stmt = this.db.prepare('SELECT * FROM analyses WHERE sample_id = ? ORDER BY started_at DESC');
    return stmt.all(sampleId) as Analysis[];
  }

  /**
   * Find recent samples ordered by creation time.
   */
  findRecentSamples(limit: number = 20): Sample[] {
    const safeLimit = Math.max(1, Math.min(limit, 500))
    const stmt = this.db.prepare(
      'SELECT * FROM samples ORDER BY datetime(created_at) DESC LIMIT ?'
    )
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
        ...(row.output_json ? (() => {
          try {
            return JSON.parse(row.output_json)
          } catch {
            return {}
          }
        })() : {}),
        error: `E_TIMEOUT: stale persisted analysis reaped after exceeding ${maxRuntimeMs}ms`,
        stale_reaped: true,
        stale_reaped_at: finishedAt,
      }),
      metrics_json: JSON.stringify({
        ...(row.metrics_json ? (() => {
          try {
            return JSON.parse(row.metrics_json)
          } catch {
            return {}
          }
        })() : {}),
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
    `);
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
    );
  }

  /**
   * Find all functions for a sample
   */
  findFunctions(sampleId: string): Function[] {
    const stmt = this.db.prepare('SELECT * FROM functions WHERE sample_id = ? ORDER BY address');
    return stmt.all(sampleId) as Function[];
  }

  /**
   * Find functions by sample with score ordering
   */
  findFunctionsByScore(sampleId: string, limit?: number): Function[] {
    let sql = 'SELECT * FROM functions WHERE sample_id = ? ORDER BY score DESC';
    if (limit !== undefined) {
      sql += ` LIMIT ${limit}`;
    }
    const stmt = this.db.prepare(sql);
    return stmt.all(sampleId) as Function[];
  }

  /**
   * Update a function
   */
  updateFunction(
    sampleId: string,
    address: string,
    updates: Partial<Omit<Function, 'sample_id' | 'address'>>
  ): void {
    const fields: string[] = [];
    const values: any[] = [];

    if (updates.name !== undefined) {
      fields.push('name = ?');
      values.push(updates.name);
    }
    if (updates.size !== undefined) {
      fields.push('size = ?');
      values.push(updates.size);
    }
    if (updates.score !== undefined) {
      fields.push('score = ?');
      values.push(updates.score);
    }
    if (updates.tags !== undefined) {
      fields.push('tags = ?');
      values.push(updates.tags);
    }
    if (updates.summary !== undefined) {
      fields.push('summary = ?');
      values.push(updates.summary);
    }

    if (fields.length === 0) {
      return; // No updates to perform
    }

    values.push(sampleId, address);
    const stmt = this.db.prepare(`
      UPDATE functions SET ${fields.join(', ')} WHERE sample_id = ? AND address = ?
    `);
    stmt.run(...values);
  }

  // ==================== Artifact Operations ====================

  /**
   * Insert a new artifact
   */
  insertArtifact(artifact: Artifact): void {
    const stmt = this.db.prepare(`
      INSERT INTO artifacts (id, sample_id, type, path, sha256, mime, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      artifact.id,
      artifact.sample_id,
      artifact.type,
      artifact.path,
      artifact.sha256,
      artifact.mime,
      artifact.created_at
    );
  }

  /**
   * Find all artifacts for a sample
   */
  findArtifacts(sampleId: string): Artifact[] {
    const stmt = this.db.prepare('SELECT * FROM artifacts WHERE sample_id = ? ORDER BY created_at DESC');
    return stmt.all(sampleId) as Artifact[];
  }

  /**
   * Find artifacts by sample and type
   */
  findArtifactsByType(sampleId: string, type: string): Artifact[] {
    const stmt = this.db.prepare('SELECT * FROM artifacts WHERE sample_id = ? AND type = ? ORDER BY created_at DESC');
    return stmt.all(sampleId, type) as Artifact[];
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
    const stmt = this.db.prepare('SELECT data, created_at, expires_at, sample_sha256 FROM cache WHERE key = ?');
    const row = stmt.get(key) as {
      data: string
      created_at: string | null
      expires_at: string | null
      sample_sha256: string | null
    } | undefined;

    if (!row) {
      return null;
    }

    try {
      const data = JSON.parse(row.data);
      return {
        data,
        createdAt: row.created_at || undefined,
        expiresAt: row.expires_at || undefined,
        sampleSha256: row.sample_sha256 || undefined,
      };
    } catch (error) {
      // Invalid JSON, remove from cache
      this.db.prepare('DELETE FROM cache WHERE key = ?').run(key);
      return null;
    }
  }

  /**
   * Set cached result in database
   * Requirements: 20.5
   */
  async setCachedResult(key: string, data: unknown, expiresAt?: string, sampleSha256?: string): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO cache (key, data, sample_sha256, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(
      key,
      JSON.stringify(data),
      sampleSha256 || null,
      new Date().toISOString(),
      expiresAt || null
    );
  }

  /**
   * Delete expired cache entries
   */
  cleanExpiredCache(): number {
    const stmt = this.db.prepare('DELETE FROM cache WHERE expires_at IS NOT NULL AND expires_at < ?');
    const result = stmt.run(new Date().toISOString());
    return result.changes;
  }

  /**
   * Get recent cache entries for prewarming
   * Requirements: 26.1 (cache prewarming), 26.2 (query optimization)
   * 
   * @param limit - Maximum number of entries to return
   * @returns Array of cache entries ordered by creation time (most recent first)
   */
  async getRecentCacheEntries(limit: number): Promise<Array<{ key: string; data: string; expires_at: string | null }>> {
    const stmt = this.db.prepare(`
      SELECT key, data, expires_at 
      FROM cache 
      WHERE expires_at IS NULL OR expires_at > ?
      ORDER BY created_at DESC 
      LIMIT ?
    `);
    return stmt.all(new Date().toISOString(), limit) as Array<{ key: string; data: string; expires_at: string | null }>;
  }

  /**
   * Get cache entries for a specific sample
   * Requirements: 26.1 (cache prewarming), 26.2 (query optimization)
   * 
   * @param sampleSha256 - SHA256 hash of the sample
   * @returns Array of cache entries for the sample
   */
  async getCacheEntriesBySample(sampleSha256: string): Promise<Array<{ key: string; data: string; expires_at: string | null }>> {
    // Query cache entries by sample_sha256 column
    const stmt = this.db.prepare(`
      SELECT key, data, expires_at 
      FROM cache 
      WHERE sample_sha256 = ?
        AND (expires_at IS NULL OR expires_at > ?)
      ORDER BY created_at DESC
    `);
    return stmt.all(sampleSha256, new Date().toISOString()) as Array<{ key: string; data: string; expires_at: string | null }>;
  }

  /**
   * Batch insert functions for better performance
   * Requirements: 26.2 (database query optimization)
   * 
   * @param functions - Array of functions to insert
   */
  insertFunctionsBatch(functions: Function[]): void {
    if (functions.length === 0) {
      return;
    }

    // Use transaction for batch insert
    const insertStmt = this.db.prepare(`
      INSERT OR REPLACE INTO functions (sample_id, address, name, size, score, tags, summary, caller_count, callee_count, is_entry_point, is_exported, callees)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

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
        );
      }
    });

    insertMany(functions);
  }

  /**
   * Batch insert artifacts for better performance
   * Requirements: 26.2 (database query optimization)
   * 
   * @param artifacts - Array of artifacts to insert
   */
  insertArtifactsBatch(artifacts: Artifact[]): void {
    if (artifacts.length === 0) {
      return;
    }

    // Use transaction for batch insert
    const insertStmt = this.db.prepare(`
      INSERT INTO artifacts (id, sample_id, type, path, sha256, mime, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

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
        );
      }
    });

    insertMany(artifacts);
  }

  /**
   * Optimize database by running VACUUM and ANALYZE
   * Requirements: 26.2 (database query optimization)
   * 
   * Should be run periodically to maintain performance
   */
  optimizeDatabase(): void {
    // ANALYZE updates statistics for query planner
    this.db.exec('ANALYZE');
    
    // VACUUM reclaims space and defragments
    // Note: VACUUM can be slow on large databases
    this.db.exec('VACUUM');
  }

  /**
   * Get database statistics for monitoring
   * Requirements: 26.2 (database query optimization)
   * 
   * @returns Object with database statistics
   */
  getDatabaseStats(): {
    sampleCount: number;
    analysisCount: number;
    functionCount: number;
    artifactCount: number;
    cacheCount: number;
    dbSizeBytes: number;
  } {
    const sampleCount = this.db.prepare('SELECT COUNT(*) as count FROM samples').get() as { count: number };
    const analysisCount = this.db.prepare('SELECT COUNT(*) as count FROM analyses').get() as { count: number };
    const functionCount = this.db.prepare('SELECT COUNT(*) as count FROM functions').get() as { count: number };
    const artifactCount = this.db.prepare('SELECT COUNT(*) as count FROM artifacts').get() as { count: number };
    const cacheCount = this.db.prepare('SELECT COUNT(*) as count FROM cache').get() as { count: number };
    
    // Get database file size
    const dbPath = (this.db as { name?: string }).name; // Access internal property
    let dbSizeBytes = 0;
    try {
      if (typeof dbPath === 'string' && dbPath.length > 0) {
        const stats = fs.statSync(dbPath);
        dbSizeBytes = stats.size;
      }
    } catch {
      // Ignore errors
    }

    return {
      sampleCount: sampleCount.count,
      analysisCount: analysisCount.count,
      functionCount: functionCount.count,
      artifactCount: artifactCount.count,
      cacheCount: cacheCount.count,
      dbSizeBytes
    };
  }
}

/**
 * Create and initialize a database instance
 */
export function createDatabase(dbPath: string): DatabaseManager {
  return new DatabaseManager(dbPath);
}
