import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import fs from 'fs'
import os from 'os'
import path from 'path'
import {
  buildDeferredEvidenceState,
  buildEvidenceProvenanceSummary,
  buildFreshEvidenceState,
  buildChunkedEvidenceManifest,
  buildResolvedEvidenceState,
  buildAnalysisEvidenceCompatibilityMarker,
  findCanonicalEvidence,
  persistCanonicalEvidence,
  resolveCanonicalEvidenceOrCache,
} from '../../src/analysis/analysis-evidence.js'
import { CacheManager } from '../../src/cache-manager.js'
import { DatabaseManager } from '../../src/database.js'

describe('analysis evidence', () => {
  let tempDir: string
  let database: DatabaseManager
  let cacheManager: CacheManager
  const sample = {
    id: 'sha256:test-sample',
    sha256: 'a'.repeat(64),
    md5: null,
    size: 1024,
    file_type: 'PE32',
    created_at: new Date().toISOString(),
    source: 'unit-test',
  }

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analysis-evidence-'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    cacheManager = new CacheManager(path.join(tempDir, 'cache'), database)
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, sample)
  })

  afterEach(() => {
    database.close()
    fs.rmSync(tempDir, { recursive: true, force: true })
  })

  test('persists and reuses compatible canonical evidence', () => {
    const record = persistCanonicalEvidence(database, {
      sample,
      evidenceFamily: 'strings',
      backend: 'strings.extract',
      mode: 'preview',
      args: { max_strings: 32 },
      result: {
        sample_id: sample.id,
        strings: [{ offset: 0, string: 'hello', encoding: 'ascii' }],
      },
      provenance: {
        tool: 'strings.extract',
      },
    })

    expect(record.evidence_family).toBe('strings')
    expect(record.backend).toBe('strings.extract')

    const reused = findCanonicalEvidence(database, {
      sample,
      evidenceFamily: 'strings',
      backend: 'strings.extract',
      mode: 'preview',
      args: { max_strings: 32 },
    })

    expect(reused).not.toBeNull()
    expect(reused?.result).toEqual({
      sample_id: sample.id,
      strings: [{ offset: 0, string: 'hello', encoding: 'ascii' }],
    })
    expect(reused?.provenance?.tool).toBe('strings.extract')
  })

  test('prefers canonical evidence over cache for the same compatibility marker', async () => {
    const compatibilityMarker = buildAnalysisEvidenceCompatibilityMarker({
      sample,
      evidenceFamily: 'binary_role',
      backend: 'binary.role.profile',
      mode: 'fast',
      args: { max_exports: 8 },
    })

    await cacheManager.setCachedResult(
      compatibilityMarker,
      { binary_role: 'cached-role' },
      60_000,
      sample.sha256
    )

    persistCanonicalEvidence(database, {
      sample,
      evidenceFamily: 'binary_role',
      backend: 'binary.role.profile',
      mode: 'fast',
      args: { max_exports: 8 },
      result: { binary_role: 'canonical-role' },
    })

    const resolved = await resolveCanonicalEvidenceOrCache(
      database,
      cacheManager,
      compatibilityMarker,
      {
        sample,
        evidenceFamily: 'binary_role',
        backend: 'binary.role.profile',
        mode: 'fast',
        args: { max_exports: 8 },
      }
    )

    expect(resolved).not.toBeNull()
    expect(resolved?.source).toBe('analysis_evidence')
    expect(resolved?.record.result).toEqual({ binary_role: 'canonical-role' })
  })

  test('classifies fresh, reused, and deferred evidence states', async () => {
    const record = persistCanonicalEvidence(database, {
      sample,
      evidenceFamily: 'context_link',
      backend: 'analysis.context.link',
      mode: 'preview',
      args: { max_records: 32 },
      result: { sample_id: sample.id, status: 'partial' },
    })

    const resolved = await resolveCanonicalEvidenceOrCache(
      database,
      cacheManager,
      'missing-cache-key',
      {
        sample,
        evidenceFamily: 'context_link',
        backend: 'analysis.context.link',
        mode: 'preview',
        args: { max_records: 32 },
      }
    )

    expect(resolved).not.toBeNull()
    expect(buildResolvedEvidenceState(resolved!).state).toBe('reused')
    expect(buildResolvedEvidenceState(resolved!).backend).toBe('analysis.context.link')
    expect(buildResolvedEvidenceState(resolved!).provenance?.source_tool).toBe(
      'analysis.context.link'
    )
    expect(
      buildFreshEvidenceState({
        evidenceFamily: 'context_link',
        backend: 'analysis.context.link',
        mode: 'full',
      }).state
    ).toBe('fresh')
    expect(
      buildDeferredEvidenceState({
        evidenceFamily: 'context_link',
        backend: 'analysis.context.link',
        mode: 'full',
        reason: 'queued for later',
      }).state
    ).toBe('deferred')
    expect(record.evidence_family).toBe('context_link')
  })

  test('builds compact provenance summaries with validation tools and artifact ids', () => {
    const summary = buildEvidenceProvenanceSummary({
      evidenceFamily: 'crypto_identify',
      backend: 'crypto.identify',
      mode: 'preview',
      source: 'run_stage',
      reason: 'Crypto preview was included in a staged run.',
      confidence: 0.91,
      artifactRefs: [
        {
          id: 'artifact-1',
          type: 'crypto_identification',
          path: 'reports/crypto.json',
          sha256: 'abc',
        },
      ],
    })

    expect(summary).toMatchObject({
      source_tool: 'crypto.identify',
      source_backend: 'crypto.identify',
      source_mode: 'preview',
      evidence_family: 'crypto_identify',
      source: 'run_stage',
      confidence: 0.91,
      artifact_ids: ['artifact-1'],
    })
    expect(summary.validation_tools).toEqual(
      expect.arrayContaining(['crypto.identify', 'breakpoint.smart', 'artifact.read'])
    )
  })

  test('classifies chunked partial evidence so callers can resume from manifests explicitly', async () => {
    persistCanonicalEvidence(database, {
      sample,
      evidenceFamily: 'strings',
      backend: 'strings.extract',
      mode: 'full',
      args: { max_strings: 800 },
      result: {
        sample_id: sample.id,
        strings: [{ offset: 0, string: 'hello', encoding: 'ascii' }],
        chunk_manifest: buildChunkedEvidenceManifest({
          family: 'strings',
          totalItems: 500,
          inlineItems: 1,
          chunkSize: 100,
          completeness: 'partial',
          chunks: [],
        }),
      },
      metadata: {
        chunk_manifest: buildChunkedEvidenceManifest({
          family: 'strings',
          totalItems: 500,
          inlineItems: 1,
          chunkSize: 100,
          completeness: 'partial',
          chunks: [],
        }),
      },
    })

    const resolved = await resolveCanonicalEvidenceOrCache(
      database,
      cacheManager,
      'missing-cache-key',
      {
        sample,
        evidenceFamily: 'strings',
        backend: 'strings.extract',
        mode: 'full',
        args: { max_strings: 800 },
      }
    )

    expect(resolved).not.toBeNull()
    const state = buildResolvedEvidenceState(resolved!)
    expect(state.state).toBe('partial')
    expect(state.reason).toContain('partially complete')
  })
})
