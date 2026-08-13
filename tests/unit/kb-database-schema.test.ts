import { describe, expect, test } from '@jest/globals'

import { DatabaseManager } from '../../src/database.js'

describe('knowledge-base core schema', () => {
  test('initializes local knowledge-base tables with every database', () => {
    const database = new DatabaseManager(':memory:')

    try {
      const tables = database.querySql<{ name: string }>(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('function_kb', 'sample_kb', 'kb_index') ORDER BY name"
      )
      expect(tables.map((row) => row.name)).toEqual(['function_kb', 'kb_index', 'sample_kb'])
    } finally {
      database.close()
    }
  })

  test('installs deterministic bounded-read indexes for KB and evidence ordering', () => {
    const database = new DatabaseManager(':memory:')

    try {
      const indexes = database.querySql<{ name: string }>(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('idx_function_kb_confidence_id', 'idx_analysis_evidence_sample_order') ORDER BY name"
      )
      expect(indexes.map((row) => row.name)).toEqual([
        'idx_analysis_evidence_sample_order',
        'idx_function_kb_confidence_id',
      ])

      const kbPlan = database.querySql<{ detail: string }>(
        'EXPLAIN QUERY PLAN SELECT id FROM function_kb ORDER BY semantics_confidence DESC, id ASC LIMIT 10'
      )
      expect(kbPlan.map((row) => row.detail).join(' ')).toMatch(/idx_function_kb_confidence_id/i)

      const evidencePlan = database.querySql<{ detail: string }>(
        'EXPLAIN QUERY PLAN SELECT id FROM analysis_evidence WHERE sample_id = ? ORDER BY updated_at DESC, created_at DESC, id DESC LIMIT 10',
        ['sha256:test']
      )
      expect(evidencePlan.map((row) => row.detail).join(' ')).toMatch(
        /idx_analysis_evidence_sample_order/i
      )
    } finally {
      database.close()
    }
  })

  test('bounds evidence candidates before payload materialization and preserves deterministic order', () => {
    const database = new DatabaseManager(':memory:')
    const sampleId = `sha256:${'a'.repeat(64)}`

    try {
      database.runSql(
        'INSERT INTO samples (id, sha256, md5, size, file_type, created_at, source) VALUES (?, ?, NULL, 1, NULL, ?, NULL)',
        [sampleId, 'a'.repeat(64), '2026-08-13T00:00:00.000Z']
      )
      for (const [id, resultJson] of [
        ['x-oldest', '{"ok":true}'],
        ['y-selected', '{"ok":true}'],
        ['z-oversized', 'x'.repeat(32)],
      ]) {
        database.runSql(
          `INSERT INTO analysis_evidence (
            id, sample_id, sample_sha256, evidence_family, backend, mode,
            compatibility_marker, result_json, created_at, updated_at
          ) VALUES (?, ?, ?, 'function_index', 'test', 'static', 'v1', ?, ?, ?)`,
          [
            id,
            sampleId,
            'a'.repeat(64),
            resultJson,
            '2026-08-13T00:00:00.000Z',
            '2026-08-13T00:00:00.000Z',
          ]
        )
      }

      const result = database.findBoundedAnalysisEvidenceBySample(sampleId, {
        families: ['function_index'],
        maxRows: 2,
        maxScanRows: 2,
        maxResultJsonBytes: 16,
        maxTotalResultJsonBytes: 16,
      })

      expect(result.rows.map((row) => row.id)).toEqual(['y-selected'])
      expect(result.oversized_rows).toBe(1)
      expect(result.selected_bytes).toBe(Buffer.byteLength('{"ok":true}', 'utf8'))
      expect(result.scan_truncated).toBe(true)
      expect(result.truncated).toBe(true)
    } finally {
      database.close()
    }
  })

  test('applies evidence-family filtering after the indexed scan window', () => {
    const database = new DatabaseManager(':memory:')
    const sampleId = `sha256:${'b'.repeat(64)}`

    try {
      database.runSql(
        'INSERT INTO samples (id, sha256, md5, size, file_type, created_at, source) VALUES (?, ?, NULL, 1, NULL, ?, NULL)',
        [sampleId, 'b'.repeat(64), '2026-08-13T00:00:00.000Z']
      )
      for (const [id, family, updatedAt] of [
        ['function-outside-window', 'function_index', '2026-08-13T00:00:00.000Z'],
        ['newer-summary', 'analysis_summary', '2026-08-13T00:00:01.000Z'],
        ['newest-note', 'analysis_note', '2026-08-13T00:00:02.000Z'],
      ]) {
        database.runSql(
          `INSERT INTO analysis_evidence (
            id, sample_id, sample_sha256, evidence_family, backend, mode,
            compatibility_marker, result_json, created_at, updated_at
          ) VALUES (?, ?, ?, ?, 'test', 'static', 'v1', '{"ok":true}', ?, ?)`,
          [id, sampleId, 'b'.repeat(64), family, '2026-08-13T00:00:00.000Z', updatedAt]
        )
      }

      const result = database.findBoundedAnalysisEvidenceBySample(sampleId, {
        families: ['function_index'],
        maxRows: 2,
        maxScanRows: 2,
        maxResultJsonBytes: 16,
        maxTotalResultJsonBytes: 32,
      })

      expect(result.rows).toEqual([])
      expect(result.total_rows).toBe(2)
      expect(result.scan_truncated).toBe(true)
      expect(result.truncated).toBe(true)
    } finally {
      database.close()
    }
  })
})
