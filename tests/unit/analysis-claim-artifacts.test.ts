import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals'
import crypto from 'crypto'
import { spawn } from 'child_process'
import { once } from 'events'
import { unlinkSync, writeFileSync } from 'fs'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import {
  ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
  ANALYSIS_CLAIM_SET_SCHEMA,
  ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS,
  AnalysisClaimSetArtifactSchema,
  analysisClaimLedgerWriteLeaseKey,
  loadAnalysisClaimLedgerIndex,
  persistAnalysisClaimSetArtifact,
  scopeAnalysisClaimLedgerIndex,
  type AnalysisClaimSetArtifact,
} from '../../src/artifacts/analysis-claim-artifacts.js'
import { DatabaseManager } from '../../src/database.js'
import { createAnalysisClaimsApplyHandler } from '../../src/plugins/kb-collaboration/tools/analysis-claims-apply.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import {
  startContextWriteLeaseWriter,
  waitForContextWriterReady,
} from '../helpers/context-write-lease-worker.js'
import { seedAnalysisClaimLedgerFixture } from '../helpers/analysis-claim-ledger-fixture.js'

const PRIMARY_SHA256 = 'a'.repeat(64)
const SECONDARY_SHA256 = 'b'.repeat(64)
const PRIMARY_SAMPLE_ID = `sha256:${PRIMARY_SHA256}`
const SECONDARY_SAMPLE_ID = `sha256:${SECONDARY_SHA256}`
const PRIMARY_EVIDENCE_ID = 'artifact-primary-evidence'
const SECONDARY_EVIDENCE_ID = 'artifact-secondary-evidence'
const CORRUPTED_EVIDENCE_ID = 'artifact-corrupted-evidence'
const symlinkTest = process.platform === 'win32' ? test.skip : test
const replacementLockTest = process.platform === 'win32' ? test.skip : test

interface PersistedArtifactFixture {
  id: string
  type: string
  path: string
  sha256: string
  absolutePath: string
}

interface AppliedClaimData {
  ledger_revision: number
  parent_artifact_id: string | null
  artifact: {
    id: string
    type: string
    path: string
    sha256: string
  }
}

describe('analysis Claim Ledger artifacts', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let handler: ReturnType<typeof createAnalysisClaimsApplyHandler>
  let primaryEvidence: PersistedArtifactFixture

  beforeEach(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-analysis-claims-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    handler = createAnalysisClaimsApplyHandler(workspaceManager, database)

    insertSample(database, PRIMARY_SAMPLE_ID, PRIMARY_SHA256)
    insertSample(database, SECONDARY_SAMPLE_ID, SECONDARY_SHA256)
    await workspaceManager.createWorkspace(PRIMARY_SAMPLE_ID)
    await workspaceManager.createWorkspace(SECONDARY_SAMPLE_ID)

    primaryEvidence = await persistFixtureArtifact({
      workspaceManager,
      database,
      sampleId: PRIMARY_SAMPLE_ID,
      id: PRIMARY_EVIDENCE_ID,
      type: 'static_behavior_profile',
      relativePath: 'reports/static/behavior.json',
      content: JSON.stringify({
        findings: [
          {
            indicator: 'Run registry key',
            key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          },
        ],
      }),
    })

    await persistFixtureArtifact({
      workspaceManager,
      database,
      sampleId: SECONDARY_SAMPLE_ID,
      id: SECONDARY_EVIDENCE_ID,
      type: 'static_behavior_profile',
      relativePath: 'reports/static/behavior.json',
      content: JSON.stringify({ findings: [{ indicator: 'secondary sample' }] }),
    })

    const corruptedEvidence = await persistFixtureArtifact({
      workspaceManager,
      database,
      sampleId: PRIMARY_SAMPLE_ID,
      id: CORRUPTED_EVIDENCE_ID,
      type: 'static_behavior_profile',
      relativePath: 'reports/static/corrupted.json',
      content: JSON.stringify({ findings: [{ indicator: 'original content' }] }),
    })
    await fs.writeFile(
      corruptedEvidence.absolutePath,
      JSON.stringify({ findings: [{ indicator: 'tampered content' }] }),
      'utf8'
    )
  })

  afterEach(async () => {
    jest.useRealTimers()
    database.close()
    await fs.rm(tempRoot, { recursive: true, force: true })
  })

  const appendOpenQuestion = async (suffix: string) =>
    await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model' },
      claims: [
        {
          claim_id: `claim-lock-${suffix}`,
          category: 'open_question',
          subject: 'Claim Ledger lock boundary',
          statement: 'Can this writer safely acquire the sample-level Claim Ledger lock?',
          status: 'inferred',
        },
      ],
    })

  test('persists canonical evidence metadata and a validated JSON pointer', async () => {
    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      goal: 'Explain persistence behavior',
      session_tag: 'triage-a',
      producer: {
        kind: 'llm',
        client_name: 'unit-test',
        model_name: 'test-model',
      },
      claims: [
        {
          claim_id: 'claim-persistence',
          category: 'finding',
          subject: 'Persistence behavior',
          statement: 'The sample contains a Run-key persistence indicator.',
          status: 'inferred',
          supporting_evidence: [
            {
              artifact_id: PRIMARY_EVIDENCE_ID,
              json_pointer: '/findings/0/key',
              locator: 'behavior.findings[0]',
              summary: 'Run-key path reported by static analysis.',
            },
          ],
        },
      ],
    })

    expect(result.ok).toBe(true)
    const data = result.data as AppliedClaimData
    expect(data.ledger_revision).toBe(1)
    expect(data.parent_artifact_id).toBeNull()
    expect(data.artifact.type).toBe(ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)

    const storedArtifact = database.findArtifact(data.artifact.id)
    expect(storedArtifact).not.toBeNull()
    expect(storedArtifact?.path).toBe(data.artifact.path)
    expect(storedArtifact?.sha256).toBe(data.artifact.sha256)

    const workspace = await workspaceManager.getWorkspace(PRIMARY_SAMPLE_ID)
    const serialized = await fs.readFile(path.join(workspace.root, data.artifact.path), 'utf8')
    const payload = AnalysisClaimSetArtifactSchema.parse(JSON.parse(serialized))
    const reference = payload.claims[0].supporting_evidence[0]

    expect(reference).toEqual({
      artifact_id: primaryEvidence.id,
      artifact_type: primaryEvidence.type,
      artifact_path: primaryEvidence.path,
      artifact_sha256: primaryEvidence.sha256,
      json_pointer: '/findings/0/key',
      locator: 'behavior.findings[0]',
      summary: 'Run-key path reported by static analysis.',
    })
    expect(payload.validation_results[0].checks).toContain('json_pointer_resolves')
    expect(payload.validation_summary).toMatchObject({
      status: 'passed',
      claim_count: 1,
      evidence_reference_count: 1,
      json_pointer_count: 1,
    })
  })

  test.each([
    ['cross-sample evidence', 'cross_sample', 'does not belong to sample'],
    ['missing JSON pointer', 'missing_pointer', 'does not resolve'],
    ['SHA-256 mismatch', 'sha_mismatch', 'SHA-256 mismatch'],
    ['claim-set evidence', 'claim_set', 'Claim-set artifacts cannot be used as evidence'],
  ])('rejects the entire batch for %s', async (_label, scenario, expectedError) => {
    let invalidEvidence: { artifact_id: string; json_pointer?: string }

    if (scenario === 'cross_sample') {
      invalidEvidence = { artifact_id: SECONDARY_EVIDENCE_ID }
    } else if (scenario === 'missing_pointer') {
      invalidEvidence = {
        artifact_id: PRIMARY_EVIDENCE_ID,
        json_pointer: '/findings/9/indicator',
      }
    } else if (scenario === 'sha_mismatch') {
      invalidEvidence = { artifact_id: CORRUPTED_EVIDENCE_ID }
    } else {
      const seedResult = await handler({
        sample_id: PRIMARY_SAMPLE_ID,
        producer: { kind: 'llm' },
        claims: [
          {
            claim_id: 'claim-set-seed',
            category: 'open_question',
            subject: 'Seed',
            statement: 'Seed a valid claim set for the evidence-type rejection test.',
            status: 'inferred',
          },
        ],
      })
      expect(seedResult.ok).toBe(true)
      invalidEvidence = {
        artifact_id: (seedResult.data as AppliedClaimData).artifact.id,
      }
    }

    const countBefore = database.findArtifactsByType(
      PRIMARY_SAMPLE_ID,
      ANALYSIS_CLAIM_SET_ARTIFACT_TYPE
    ).length
    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm' },
      claims: [
        {
          claim_id: `claim-valid-${scenario}`,
          category: 'finding',
          subject: 'Valid claim in rejected batch',
          statement: 'This claim has valid evidence but must not be persisted alone.',
          status: 'inferred',
          supporting_evidence: [{ artifact_id: PRIMARY_EVIDENCE_ID }],
        },
        {
          claim_id: `claim-invalid-${scenario}`,
          category: 'finding',
          subject: 'Invalid claim in rejected batch',
          statement: 'This claim contains an invalid evidence reference.',
          status: 'inferred',
          supporting_evidence: [invalidEvidence],
        },
      ],
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.join('\n')).toContain(expectedError)
    expect(
      database.findArtifactsByType(PRIMARY_SAMPLE_ID, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    ).toHaveLength(countBefore)
  })

  test.each([
    'summary_triage_digest',
    'summary_static_digest',
    'summary_deep_digest',
    'summary_final_digest',
    'workflow_summary',
    'report_summary',
    'report_custom_export',
    'analysis_report',
    'html_report',
    'report',
  ])('rejects context-only %s artifacts as Claim evidence', async (artifactType) => {
    const artifactId = `context-only-${artifactType}`
    await persistFixtureArtifact({
      workspaceManager,
      database,
      sampleId: PRIMARY_SAMPLE_ID,
      id: artifactId,
      type: artifactType,
      relativePath: `reports/context/${artifactType}.json`,
      content: JSON.stringify({ summary: 'Context-only analyst synthesis.' }),
    })

    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm' },
      claims: [
        {
          claim_id: `claim-cites-${artifactType}`,
          category: 'finding',
          subject: 'Invalid context-only citation',
          statement: 'A summary or report must not become self-referential Claim evidence.',
          status: 'inferred',
          supporting_evidence: [{ artifact_id: artifactId }],
        },
      ],
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.join('\n')).toContain(
      `Context-only artifact type cannot be used as claim evidence: ${artifactType}`
    )
    expect(
      database.findArtifactsByType(PRIMARY_SAMPLE_ID, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    ).toHaveLength(0)
  })

  test('does not misclassify deterministic analyzer artifacts ending in _report', async () => {
    const artifactId = 'deterministic-strings-report'
    await persistFixtureArtifact({
      workspaceManager,
      database,
      sampleId: PRIMARY_SAMPLE_ID,
      id: artifactId,
      type: 'strings_report',
      relativePath: 'reports/static/strings-report.json',
      content: JSON.stringify({ strings: ['accepted', 'rejected'] }),
    })

    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm' },
      claims: [
        {
          claim_id: 'claim-cites-strings-report',
          category: 'finding',
          subject: 'Deterministic strings output',
          statement: 'The deterministic analyzer output contains validation strings.',
          status: 'inferred',
          supporting_evidence: [{ artifact_id: artifactId }],
        },
      ],
    })

    expect(result.ok).toBe(true)
  })

  test('does not allow an LLM producer to promote a claim to verified', async () => {
    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model' },
      claims: [
        {
          claim_id: 'claim-llm-verified',
          category: 'finding',
          subject: 'Unreviewed promotion',
          statement: 'An LLM must not be able to mark this finding as verified.',
          status: 'verified',
          supporting_evidence: [{ artifact_id: PRIMARY_EVIDENCE_ID }],
          review: {
            decision: 'verified',
            reviewer: 'spoofed-reviewer',
          },
        },
      ],
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.join('\n')).toContain(
      'only analyst-produced claims may use status=verified'
    )
    expect(
      database.findArtifactsByType(PRIMARY_SAMPLE_ID, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    ).toHaveLength(0)
  })

  test('rejects an analyst producer at the public tool boundary', async () => {
    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'analyst', client_name: 'review-console' },
      claims: [
        {
          claim_id: 'claim-analyst-verified',
          category: 'finding',
          subject: 'Reviewed persistence behavior',
          statement: 'The Run-key persistence indicator is confirmed in the artifact.',
          status: 'verified',
          supporting_evidence: [
            {
              artifact_id: PRIMARY_EVIDENCE_ID,
              json_pointer: '/findings/0/key',
            },
          ],
          review: {
            decision: 'verified',
            reviewer: 'analyst@example.test',
            note: 'Verified against the canonical static-analysis output.',
          },
        },
      ],
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.join('\n')).toContain('analyst')
    expect(
      database.findArtifactsByType(PRIMARY_SAMPLE_ID, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    ).toHaveLength(0)
  })

  test('uses the newest revision when the same claim_id is appended again', async () => {
    jest.useFakeTimers()
    jest.setSystemTime(new Date('2026-07-14T08:00:00.000Z'))

    const firstResult = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model-v1' },
      claims: [
        {
          claim_id: 'claim-revised',
          category: 'finding',
          subject: 'Persistence behavior',
          statement: 'Revision one: the sample may use a Run key.',
          status: 'inferred',
          supporting_evidence: [{ artifact_id: PRIMARY_EVIDENCE_ID }],
        },
      ],
    })
    expect(firstResult.ok).toBe(true)

    jest.setSystemTime(new Date('2026-07-14T08:00:01.000Z'))
    const secondResult = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model-v2' },
      claims: [
        {
          claim_id: 'claim-revised',
          category: 'finding',
          subject: 'Persistence behavior',
          statement: 'Revision two: the artifact contains a specific Run-key path.',
          status: 'inferred',
          supporting_evidence: [
            {
              artifact_id: PRIMARY_EVIDENCE_ID,
              json_pointer: '/findings/0/key',
            },
          ],
        },
      ],
    })

    expect(secondResult.ok).toBe(true)
    const firstData = firstResult.data as AppliedClaimData
    const secondData = secondResult.data as AppliedClaimData
    expect(secondData.ledger_revision).toBe(2)
    expect(secondData.parent_artifact_id).toBe(firstData.artifact.id)

    const ledger = await loadAnalysisClaimLedgerIndex(
      workspaceManager,
      database,
      PRIMARY_SAMPLE_ID,
      { scope: 'all' }
    )
    const newest = ledger.byClaimId.get('claim-revised')

    expect(ledger.claim_sets).toHaveLength(2)
    expect(newest?.ledger_revision).toBe(2)
    expect(newest?.claim_set_artifact_id).toBe(secondData.artifact.id)
    expect(newest?.claim.statement).toBe(
      'Revision two: the artifact contains a specific Run-key path.'
    )
    expect(newest?.claim.supporting_evidence[0].json_pointer).toBe('/findings/0/key')
  })

  test('keeps active claims from older delta revisions when scope is latest', async () => {
    jest.useFakeTimers()
    jest.setSystemTime(new Date('2026-07-14T09:00:00.000Z'))

    const firstResult = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model-v1' },
      claims: [
        {
          claim_id: 'claim-active-from-r1',
          category: 'open_question',
          subject: 'Revision one question',
          statement: 'This active claim exists only in the first delta revision.',
          status: 'inferred',
        },
      ],
    })
    expect(firstResult.ok).toBe(true)

    jest.setSystemTime(new Date('2026-07-14T09:00:01.000Z'))
    const secondResult = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model-v2' },
      claims: [
        {
          claim_id: 'claim-active-from-r2',
          category: 'open_question',
          subject: 'Revision two question',
          statement: 'This different active claim exists only in the second delta revision.',
          status: 'inferred',
        },
      ],
    })
    expect(secondResult.ok).toBe(true)

    const latest = await loadAnalysisClaimLedgerIndex(
      workspaceManager,
      database,
      PRIMARY_SAMPLE_ID,
      { scope: 'latest' }
    )
    const firstData = firstResult.data as AppliedClaimData
    const secondData = secondResult.data as AppliedClaimData

    expect(Array.from(latest.byClaimId.keys()).sort()).toEqual([
      'claim-active-from-r1',
      'claim-active-from-r2',
    ])
    expect(latest.byClaimId.get('claim-active-from-r1')).toMatchObject({
      claim_set_artifact_id: firstData.artifact.id,
      ledger_revision: 1,
    })
    expect(latest.byClaimId.get('claim-active-from-r2')).toMatchObject({
      claim_set_artifact_id: secondData.artifact.id,
      ledger_revision: 2,
    })
    expect(new Set(latest.artifact_ids)).toEqual(
      new Set([firstData.artifact.id, secondData.artifact.id])
    )
  })

  test('rejects forged producer, source, status, and validation summary fields', async () => {
    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model' },
      claims: [
        {
          claim_id: 'claim-schema-baseline',
          category: 'finding',
          subject: 'Schema baseline',
          statement: 'A canonical baseline claim used to test payload forgery.',
          status: 'inferred',
          supporting_evidence: [
            {
              artifact_id: PRIMARY_EVIDENCE_ID,
              json_pointer: '/findings/0/key',
            },
          ],
        },
      ],
    })
    expect(result.ok).toBe(true)

    const workspace = await workspaceManager.getWorkspace(PRIMARY_SAMPLE_ID)
    const artifact = (result.data as AppliedClaimData).artifact
    const baseline = AnalysisClaimSetArtifactSchema.parse(
      JSON.parse(await fs.readFile(path.join(workspace.root, artifact.path), 'utf8'))
    )
    const forgeries: Array<{
      name: string
      expectedPath: string
      mutate: (payload: AnalysisClaimSetArtifact) => void
    }> = [
      {
        name: 'producer',
        expectedPath: 'claims.0.source',
        mutate: (payload) => {
          payload.producer.kind = 'analyst'
        },
      },
      {
        name: 'source',
        expectedPath: 'claims.0.source',
        mutate: (payload) => {
          payload.claims[0].source = 'imported'
        },
      },
      {
        name: 'status',
        expectedPath: 'claims.0.status',
        mutate: (payload) => {
          payload.claims[0].status = 'verified'
          payload.claims[0].review = {
            decision: 'verified',
            reviewer: 'forged-reviewer',
            reviewed_at: payload.created_at,
          }
        },
      },
      {
        name: 'validation summary',
        expectedPath: 'validation_summary',
        mutate: (payload) => {
          payload.validation_summary.claim_count += 1
          payload.validation_summary.evidence_reference_count += 1
        },
      },
    ]

    for (const forgery of forgeries) {
      const forged = structuredClone(baseline)
      forgery.mutate(forged)
      const parsed = AnalysisClaimSetArtifactSchema.safeParse(forged)

      expect(parsed.success).toBe(false)
      if (!parsed.success) {
        expect(
          parsed.error.issues.some((issue) => issue.path.join('.').startsWith(forgery.expectedPath))
        ).toBe(true)
      }
    }
  })

  test('serializes same-millisecond concurrent applies without file or revision collisions', async () => {
    jest.useFakeTimers()
    jest.setSystemTime(new Date('2026-07-14T10:00:00.000Z'))

    const [left, right] = await Promise.all([
      handler({
        sample_id: PRIMARY_SAMPLE_ID,
        producer: { kind: 'llm', model_name: 'concurrent-left' },
        claims: [
          {
            claim_id: 'claim-concurrent-left',
            category: 'finding',
            subject: 'Concurrent left',
            statement: 'The left concurrent request references valid evidence.',
            status: 'inferred',
            supporting_evidence: [{ artifact_id: PRIMARY_EVIDENCE_ID }],
          },
        ],
      }),
      handler({
        sample_id: PRIMARY_SAMPLE_ID,
        producer: { kind: 'llm', model_name: 'concurrent-right' },
        claims: [
          {
            claim_id: 'claim-concurrent-right',
            category: 'finding',
            subject: 'Concurrent right',
            statement: 'The right concurrent request references valid evidence.',
            status: 'inferred',
            supporting_evidence: [{ artifact_id: PRIMARY_EVIDENCE_ID }],
          },
        ],
      }),
    ])
    const successes = [left, right].filter((entry) => entry.ok)
    const failures = [left, right].filter((entry) => !entry.ok)

    expect(successes.length).toBeGreaterThanOrEqual(1)
    expect(failures.length).toBeLessThanOrEqual(1)
    for (const failure of failures) {
      expect(failure.errors?.join('\n')).toContain('Claim Ledger revision conflict')
    }

    const artifacts = database.findArtifactsByType(
      PRIMARY_SAMPLE_ID,
      ANALYSIS_CLAIM_SET_ARTIFACT_TYPE
    )
    expect(artifacts).toHaveLength(successes.length)
    expect(new Set(artifacts.map((artifact) => artifact.path)).size).toBe(artifacts.length)

    const workspace = await workspaceManager.getWorkspace(PRIMARY_SAMPLE_ID)
    const payloads = await Promise.all(
      artifacts.map(async (artifact) =>
        AnalysisClaimSetArtifactSchema.parse(
          JSON.parse(await fs.readFile(path.join(workspace.root, artifact.path), 'utf8'))
        )
      )
    )
    const revisions = payloads.map((payload) => payload.ledger_revision)
    expect(new Set(revisions).size).toBe(revisions.length)
    expect(revisions.sort((leftRevision, rightRevision) => leftRevision - rightRevision)).toEqual(
      successes.length === 2 ? [1, 2] : [1]
    )

    const claimDirectory = path.join(workspace.reports, 'claims', 'default')
    expect(await fs.readdir(claimDirectory)).toHaveLength(successes.length)
  })

  test('recovers a stale Claim Ledger lock only after its PID and timestamps prove abandonment', async () => {
    const lockPath = await claimLedgerLockPath(workspaceManager, PRIMARY_SAMPLE_ID)
    const oldTimestamp = new Date(Date.now() - ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2)
    await writeClaimLedgerLockFixture({
      lockPath,
      sampleId: PRIMARY_SAMPLE_ID,
      ownerToken: '11111111-1111-4111-8111-111111111111',
      pid: await exitedProcessPid(),
      acquiredAt: oldTimestamp,
      modifiedAt: oldTimestamp,
    })

    const result = await appendOpenQuestion('stale-recovery')
    expect(result.ok).toBe(true)
    await expect(fs.stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test('allows only one cross-process writer to recover the same stale Claim Ledger lock', async () => {
    const lockPath = await claimLedgerLockPath(workspaceManager, PRIMARY_SAMPLE_ID)
    const oldTimestamp = new Date(Date.now() - ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2)
    await fs.writeFile(lockPath, '', 'utf8')
    await fs.utimes(lockPath, oldTimestamp, oldTimestamp)

    const readyPath = path.join(tempRoot, 'claim-lease-ready')
    const releasePath = path.join(tempRoot, 'claim-lease-release')
    const first = startContextWriteLeaseWriter({
      kind: 'claim',
      databasePath: path.join(tempRoot, 'rikune.db'),
      workspaceRoot: workspaceManager.getWorkspaceRoot(),
      sampleId: PRIMARY_SAMPLE_ID,
      suffix: 'winner',
      readyPath,
      releasePath,
    })

    try {
      await waitForContextWriterReady(readyPath)
      const second = startContextWriteLeaseWriter({
        kind: 'claim',
        databasePath: path.join(tempRoot, 'rikune.db'),
        workspaceRoot: workspaceManager.getWorkspaceRoot(),
        sampleId: PRIMARY_SAMPLE_ID,
        suffix: 'loser',
      })
      const loser = await second.completion
      expect(loser.ok).toBe(false)
      expect(loser.errors?.join('\n')).toContain('another live context writer')
      expect(await fs.readFile(lockPath, 'utf8')).toBe('')

      await fs.writeFile(releasePath, 'release', 'utf8')
      const winner = await first.completion
      expect(winner.ok).toBe(true)
    } finally {
      await fs.writeFile(releasePath, 'release', 'utf8').catch(() => undefined)
      if (first.child.exitCode === null) first.child.kill()
    }

    expect(
      database.findArtifactsByType(PRIMARY_SAMPLE_ID, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    ).toHaveLength(1)
    expect(
      database.findContextWriteLease(analysisClaimLedgerWriteLeaseKey(PRIMARY_SAMPLE_ID))
    ).toBeNull()
    await expect(fs.stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' })
  }, 30_000)

  test('fences a stale Claim writer at Artifact commit and removes its final file', async () => {
    const lockKey = analysisClaimLedgerWriteLeaseKey(PRIMARY_SAMPLE_ID)
    const takeoverToken = '66666666-6666-4666-8666-666666666666'
    const originalInsert = database.insertArtifactIfContextLeaseOwned.bind(database)
    let takeoverSucceeded = false

    database.insertArtifactIfContextLeaseOwned = ((artifact, candidateLockKey, ownerToken) => {
      if (artifact.type === ANALYSIS_CLAIM_SET_ARTIFACT_TYPE) {
        database.runSql(
          'UPDATE context_write_leases SET heartbeat_at = ? WHERE lock_key = ? AND owner_token = ?',
          [
            new Date(Date.now() - ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2).toISOString(),
            candidateLockKey,
            ownerToken,
          ]
        )
        const takeoverAt = new Date().toISOString()
        const takeover = database.tryAcquireContextWriteLease(
          {
            lock_key: candidateLockKey,
            owner_token: takeoverToken,
            host_id: os.hostname(),
            pid: process.pid,
            acquired_at: takeoverAt,
            heartbeat_at: takeoverAt,
          },
          new Date(Date.now() - ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS).toISOString()
        )
        takeoverSucceeded = takeover.acquired && takeover.takeover
      }
      return originalInsert(artifact, candidateLockKey, ownerToken)
    }) as typeof database.insertArtifactIfContextLeaseOwned

    let result: Awaited<ReturnType<typeof appendOpenQuestion>>
    try {
      result = await appendOpenQuestion('artifact-fence-loss')
    } finally {
      database.insertArtifactIfContextLeaseOwned = originalInsert
    }

    expect(takeoverSucceeded).toBe(true)
    expect(result.ok).toBe(false)
    expect(result.errors?.join('\n')).toContain(
      'lost its context write lease before Artifact commit'
    )
    expect(
      database.findArtifactsByType(PRIMARY_SAMPLE_ID, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    ).toHaveLength(0)

    const workspace = await workspaceManager.getWorkspace(PRIMARY_SAMPLE_ID)
    const claimDirectory = path.join(workspace.reports, 'claims', 'default')
    expect(await fs.readdir(claimDirectory)).toEqual([])
    expect(database.releaseContextWriteLease(lockKey, takeoverToken)).toBe(true)
    await expect(
      fs.stat(path.join(workspace.root, '.analysis-claim-ledger.lock'))
    ).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test.each([
    ['empty', ''],
    ['partial JSON', '{"version":1'],
    ['schema-invalid', JSON.stringify({ version: 1 })],
  ])(
    'recovers an old %s Claim Ledger lock but preserves it while fresh',
    async (label, content) => {
      const lockPath = await claimLedgerLockPath(workspaceManager, PRIMARY_SAMPLE_ID)
      await fs.writeFile(lockPath, content, 'utf8')

      const fresh = await appendOpenQuestion(`fresh-invalid-${label.replace(/\s+/g, '-')}`)
      expect(fresh.ok).toBe(false)
      expect(fresh.errors?.join('\n')).toContain('live or recently-active')
      expect(await fs.readFile(lockPath, 'utf8')).toBe(content)

      const oldTimestamp = new Date(Date.now() - ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2)
      await fs.utimes(lockPath, oldTimestamp, oldTimestamp)
      const recovered = await appendOpenQuestion(`stale-invalid-${label.replace(/\s+/g, '-')}`)
      expect(recovered.ok).toBe(true)
      await expect(fs.stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' })
    }
  )

  test('recovers an old complete Claim Ledger lock from another host namespace', async () => {
    const lockPath = await claimLedgerLockPath(workspaceManager, PRIMARY_SAMPLE_ID)
    const oldTimestamp = new Date(Date.now() - ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2)
    await writeClaimLedgerLockFixture({
      lockPath,
      sampleId: PRIMARY_SAMPLE_ID,
      ownerToken: '55555555-5555-4555-8555-555555555555',
      pid: process.pid,
      acquiredAt: oldTimestamp,
      modifiedAt: oldTimestamp,
      hostId: 'foreign-host.example',
    })

    const result = await appendOpenQuestion('stale-foreign-host')
    expect(result.ok).toBe(true)
    await expect(fs.stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  test.each([
    [
      'a live PID',
      'live-pid',
      process.pid,
      ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2,
      ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2,
      undefined,
    ],
    ['a fresh dead-PID lock', 'fresh-lock', null, 0, 0, undefined],
    [
      'an old metadata timestamp on a fresh lock file',
      'fresh-file',
      null,
      ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2,
      0,
      undefined,
    ],
    [
      'a fresh metadata timestamp on an old lock file',
      'fresh-metadata',
      null,
      0,
      ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2,
      undefined,
    ],
    [
      'a fresh lock from another host namespace',
      'foreign-host',
      null,
      0,
      0,
      'foreign-host.example',
    ],
  ])(
    'does not recover %s',
    async (_label, suffix, configuredPid, metadataAgeMs, fileAgeMs, hostId) => {
      const lockPath = await claimLedgerLockPath(workspaceManager, PRIMARY_SAMPLE_ID)
      const acquiredAt = new Date(Date.now() - metadataAgeMs)
      const modifiedAt = new Date(Date.now() - fileAgeMs)
      await writeClaimLedgerLockFixture({
        lockPath,
        sampleId: PRIMARY_SAMPLE_ID,
        ownerToken: '22222222-2222-4222-8222-222222222222',
        pid: configuredPid ?? (await exitedProcessPid()),
        acquiredAt,
        modifiedAt,
        hostId,
      })

      const result = await appendOpenQuestion(suffix)
      expect(result.ok).toBe(false)
      expect(result.errors?.join('\n')).toContain('live or recently-active')
      expect(JSON.parse(await fs.readFile(lockPath, 'utf8')).owner_token).toBe(
        '22222222-2222-4222-8222-222222222222'
      )
    }
  )

  test('does not recover an old dead lock for another sample', async () => {
    const lockPath = await claimLedgerLockPath(workspaceManager, PRIMARY_SAMPLE_ID)
    const timestamp = new Date(Date.now() - ANALYSIS_CLAIM_LEDGER_LOCK_STALE_MS * 2)
    await writeClaimLedgerLockFixture({
      lockPath,
      sampleId: SECONDARY_SAMPLE_ID,
      ownerToken: '33333333-3333-4333-8333-333333333333',
      pid: await exitedProcessPid(),
      acquiredAt: timestamp,
      modifiedAt: timestamp,
    })

    const result = await appendOpenQuestion('ownership-mismatch')
    expect(result.ok).toBe(false)
    expect(result.errors?.join('\n')).toContain('ownership does not match')
    expect(JSON.parse(await fs.readFile(lockPath, 'utf8')).owner_token).toBe(
      '33333333-3333-4333-8333-333333333333'
    )
  })

  replacementLockTest(
    'release never unlinks a replacement Claim Ledger lock owned by another writer',
    async () => {
      const lockPath = await claimLedgerLockPath(workspaceManager, PRIMARY_SAMPLE_ID)
      const originalInsertArtifact = database.insertArtifactIfContextLeaseOwned.bind(database)
      let replaced = false
      database.insertArtifactIfContextLeaseOwned = ((artifact, lockKey, ownerToken) => {
        if (!replaced && artifact.type === ANALYSIS_CLAIM_SET_ARTIFACT_TYPE) {
          replaced = true
          unlinkSync(lockPath)
          writeFileSync(
            lockPath,
            JSON.stringify({
              version: 1,
              owner_token: '44444444-4444-4444-8444-444444444444',
              pid: process.pid,
              host_id: os.hostname(),
              sample_id: PRIMARY_SAMPLE_ID,
              acquired_at: new Date().toISOString(),
            }),
            'utf8'
          )
        }
        return originalInsertArtifact(artifact, lockKey, ownerToken)
      }) as typeof database.insertArtifactIfContextLeaseOwned

      const result = await appendOpenQuestion('owner-replacement')
      database.insertArtifactIfContextLeaseOwned = originalInsertArtifact

      expect(result.ok).toBe(true)
      expect(replaced).toBe(true)
      expect(JSON.parse(await fs.readFile(lockPath, 'utf8')).owner_token).toBe(
        '44444444-4444-4444-8444-444444444444'
      )
    }
  )

  test('does not let an LLM replace a trusted analyst rejected claim', async () => {
    const reviewedAt = '2026-07-14T11:00:00.000Z'
    const trustedPayload: AnalysisClaimSetArtifact = {
      schema: ANALYSIS_CLAIM_SET_SCHEMA,
      schema_version: 1,
      sample_id: PRIMARY_SAMPLE_ID,
      ledger_revision: 1,
      parent_artifact_id: null,
      created_at: reviewedAt,
      session_tag: null,
      goal: 'Record a trusted terminal review decision',
      producer: {
        kind: 'analyst',
        client_name: 'trusted-review-entry-point',
        model_name: null,
      },
      claims: [
        {
          claim_id: 'claim-trusted-rejected',
          source: 'analyst',
          category: 'finding',
          subject: 'Rejected persistence hypothesis',
          statement: 'The reviewed evidence does not support the persistence hypothesis.',
          status: 'rejected',
          supporting_evidence: [],
          counter_evidence: [],
          assumptions: [],
          alternatives: [],
          falsification_tests: [],
          review: {
            decision: 'rejected',
            reviewer: 'analyst@example.test',
            note: 'Rejected after reviewing the deterministic evidence.',
            reviewed_at: reviewedAt,
          },
        },
      ],
      validation_results: [
        {
          claim_id: 'claim-trusted-rejected',
          validation_type: 'evidence_reference_integrity',
          status: 'not_applicable',
          validator: 'analysis.claims.review',
          validated_at: reviewedAt,
          supporting_evidence_count: 0,
          counter_evidence_count: 0,
          checks: [],
          note: 'No artifact evidence references were supplied; semantic truth was not validated.',
        },
      ],
      validation_summary: {
        status: 'passed',
        claim_count: 1,
        evidence_reference_count: 0,
        json_pointer_count: 0,
      },
    }
    const mismatchedValidator = AnalysisClaimSetArtifactSchema.safeParse({
      ...trustedPayload,
      validation_results: trustedPayload.validation_results.map((result) => ({
        ...result,
        validator: 'analysis.claims.apply',
      })),
    })
    expect(mismatchedValidator.success).toBe(false)
    if (!mismatchedValidator.success) {
      expect(mismatchedValidator.error.issues.map((issue) => issue.message).join('\n')).toContain(
        'producer.kind=analyst requires validator=analysis.claims.review'
      )
    }
    await expect(
      persistAnalysisClaimSetArtifact(workspaceManager, database, trustedPayload)
    ).rejects.toThrow('fail-closed until a signed operator boundary is configured')
    const trustedArtifact = await persistFixtureArtifact({
      workspaceManager,
      database,
      sampleId: PRIMARY_SAMPLE_ID,
      id: 'legacy-trusted-review-artifact',
      type: ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
      relativePath: 'reports/claims/default/legacy_trusted_review.json',
      content: JSON.stringify(trustedPayload, null, 2),
    })

    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model' },
      claims: [
        {
          claim_id: 'claim-trusted-rejected',
          category: 'finding',
          subject: 'Attempted AI downgrade',
          statement: 'An AI-facing request attempts to replace the terminal review decision.',
          status: 'inferred',
          supporting_evidence: [{ artifact_id: PRIMARY_EVIDENCE_ID }],
        },
      ],
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.join('\n')).toContain('cannot revise a previously rejected claim')

    const bypassAt = '2026-07-14T11:01:00.000Z'
    const lowLevelBypass: AnalysisClaimSetArtifact = {
      schema: ANALYSIS_CLAIM_SET_SCHEMA,
      schema_version: 1,
      sample_id: PRIMARY_SAMPLE_ID,
      ledger_revision: 2,
      parent_artifact_id: trustedArtifact.id,
      created_at: bypassAt,
      session_tag: null,
      goal: 'Attempt to bypass the public terminal-state guard',
      producer: { kind: 'llm', client_name: 'direct-writer', model_name: 'test-model' },
      claims: [
        {
          claim_id: 'claim-trusted-rejected',
          source: 'llm',
          category: 'finding',
          subject: 'Attempted low-level downgrade',
          statement: 'A direct writer call attempts to replace the reviewed terminal decision.',
          status: 'inferred',
          supporting_evidence: [
            {
              artifact_id: primaryEvidence.id,
              artifact_type: primaryEvidence.type,
              artifact_path: primaryEvidence.path,
              artifact_sha256: primaryEvidence.sha256,
            },
          ],
          counter_evidence: [],
          assumptions: [],
          alternatives: [],
          falsification_tests: [],
          review: null,
        },
      ],
      validation_results: [
        {
          claim_id: 'claim-trusted-rejected',
          validation_type: 'evidence_reference_integrity',
          status: 'passed',
          validator: 'analysis.claims.apply',
          validated_at: bypassAt,
          supporting_evidence_count: 1,
          counter_evidence_count: 0,
          checks: [
            'artifact_exists',
            'sample_matches',
            'artifact_type_allowed',
            'artifact_readable',
            'artifact_sha256_matches',
          ],
          note: 'Evidence identity was validated, but the terminal status transition is forbidden.',
        },
      ],
      validation_summary: {
        status: 'passed',
        claim_count: 1,
        evidence_reference_count: 1,
        json_pointer_count: 0,
      },
    }
    await expect(
      persistAnalysisClaimSetArtifact(workspaceManager, database, lowLevelBypass)
    ).rejects.toThrow('terminal reviewed claims cannot be replaced or reopened')
    expect(
      database.findArtifactsByType(PRIMARY_SAMPLE_ID, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    ).toHaveLength(1)

    const active = await loadAnalysisClaimLedgerIndex(
      workspaceManager,
      database,
      PRIMARY_SAMPLE_ID,
      { scope: 'all' }
    )
    expect(active.byClaimId.get('claim-trusted-rejected')).toMatchObject({
      claim_set_artifact_id: trustedArtifact.id,
      ledger_revision: 1,
      claim: {
        source: 'analyst',
        status: 'rejected',
        statement: 'The reviewed evidence does not support the persistence hypothesis.',
        review: {
          reviewer: 'analyst@example.test',
          decision: 'rejected',
        },
      },
    })
  })

  symlinkTest('does not write Claim JSON through a reports/claims symlink', async () => {
    const workspace = await workspaceManager.getWorkspace(PRIMARY_SAMPLE_ID)
    const externalClaimDirectory = path.join(tempRoot, 'outside-workspace-claims')
    const claimsLink = path.join(workspace.reports, 'claims')
    await fs.mkdir(externalClaimDirectory, { recursive: true })
    await fs.symlink(externalClaimDirectory, claimsLink, 'dir')

    const result = await handler({
      sample_id: PRIMARY_SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'test-model' },
      claims: [
        {
          claim_id: 'claim-symlink-boundary',
          category: 'open_question',
          subject: 'Workspace boundary',
          statement: 'This claim must not be written through an external symlink.',
          status: 'inferred',
        },
      ],
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.join('\n')).toMatch(/symlink|resolves outside the workspace/)
    expect(
      database.findArtifactsByType(PRIMARY_SAMPLE_ID, ANALYSIS_CLAIM_SET_ARTIFACT_TYPE)
    ).toHaveLength(0)
    const externalEntries = await fs.readdir(externalClaimDirectory, { recursive: true })
    expect(externalEntries.filter((entry) => entry.endsWith('.json'))).toHaveLength(0)
  })

  test('resolves an old Case-active Claim through 65 delta revisions', async () => {
    await seedAnalysisClaimLedgerFixture({
      workspaceManager,
      database,
      sampleId: PRIMARY_SAMPLE_ID,
      revisionCount: 65,
      artifactIdPrefix: 'strict-scan-65',
      createdAtBase: '2026-07-14T10:00:00.000Z',
      claimForRevision: (revision) =>
        revision === 1
          ? {
              claim_id: 'claim-case-a-old',
              subject: 'Case A old Claim',
              statement: 'Case A must retain this Claim through unrelated Case B churn.',
            }
          : {
              claim_id: 'claim-case-b-churn',
              subject: 'Case B churn',
              statement: `Case B Claim revision ${revision}.`,
            },
    })

    const loaded = await loadAnalysisClaimLedgerIndex(
      workspaceManager,
      database,
      PRIMARY_SAMPLE_ID,
      { scope: 'all', activeClaimIds: ['claim-case-a-old'] }
    )
    const scoped = scopeAnalysisClaimLedgerIndex(loaded, ['claim-case-a-old'])

    expect(loaded.active_claim_resolution).toMatchObject({
      status: 'complete',
      requested_claim_ids: ['claim-case-a-old'],
      unresolved_claim_ids: [],
      scanned_artifact_count: 65,
    })
    expect(scoped.truncated).toBe(false)
    expect(scoped.warnings).toEqual([])
    expect(Array.from(scoped.byClaimId.keys())).toEqual(['claim-case-a-old'])
    expect(scoped.byClaimId.get('claim-case-a-old')?.ledger_revision).toBe(1)
  })

  test('withholds the entire active Claim view when the strict scan limit is reached', async () => {
    await seedAnalysisClaimLedgerFixture({
      workspaceManager,
      database,
      sampleId: PRIMARY_SAMPLE_ID,
      revisionCount: 4,
      artifactIdPrefix: 'strict-scan-cap',
      createdAtBase: '2026-07-14T11:00:00.000Z',
      claimForRevision: (revision) =>
        revision === 1
          ? {
              claim_id: 'claim-old-beyond-cap',
              subject: 'Old Claim beyond cap',
              statement: 'This Claim is intentionally beyond the strict test scan cap.',
            }
          : revision === 4
            ? {
                claim_id: 'claim-recent-within-cap',
                subject: 'Recent Claim within cap',
                statement: 'This Claim resolves before the strict test scan cap.',
              }
            : {
                claim_id: 'claim-cap-churn',
                subject: 'Cap churn',
                statement: `Churn revision ${revision}.`,
              },
    })

    const loaded = await loadAnalysisClaimLedgerIndex(
      workspaceManager,
      database,
      PRIMARY_SAMPLE_ID,
      {
        scope: 'all',
        activeClaimIds: ['claim-recent-within-cap', 'claim-old-beyond-cap'],
        maxScanArtifacts: 2,
      }
    )
    const scoped = scopeAnalysisClaimLedgerIndex(loaded, [
      'claim-recent-within-cap',
      'claim-old-beyond-cap',
    ])

    expect(loaded.active_claim_resolution).toMatchObject({
      status: 'scan_limit',
      unresolved_claim_ids: ['claim-old-beyond-cap'],
      scanned_artifact_count: 2,
    })
    expect(loaded.byClaimId.size).toBe(0)
    expect(scoped.byClaimId.size).toBe(0)
    expect(scoped.claim_sets).toEqual([])
    expect(scoped.truncated).toBe(true)
    expect(scoped.warnings.join('\n')).toMatch(/entire Case Claim view was withheld/i)
  })

  symlinkTest(
    'rejects a cold-cache replaced sample root before creating a Claim lock',
    async () => {
      const workspace = await workspaceManager.getWorkspace(PRIMARY_SAMPLE_ID)
      const externalWorkspaceRoot = path.join(tempRoot, 'outside-sample-workspace')
      await fs.mkdir(path.join(externalWorkspaceRoot, 'reports'), { recursive: true })
      await fs.rm(workspace.root, { recursive: true, force: true })
      await fs.symlink(externalWorkspaceRoot, workspace.root, 'dir')
      const externalEntriesBefore = (
        await fs.readdir(externalWorkspaceRoot, { recursive: true })
      ).sort()
      const coldWorkspaceManager = new WorkspaceManager(workspaceManager.getWorkspaceRoot())
      const coldHandler = createAnalysisClaimsApplyHandler(coldWorkspaceManager, database)

      const result = await coldHandler({
        sample_id: PRIMARY_SAMPLE_ID,
        producer: { kind: 'llm', model_name: 'test-model' },
        claims: [
          {
            claim_id: 'claim-replaced-workspace-root',
            category: 'open_question',
            subject: 'Workspace root boundary',
            statement: 'This claim must not follow a replaced sample workspace root.',
            status: 'inferred',
          },
        ],
      })

      expect(result.ok).toBe(false)
      expect(result.errors?.join('\n')).toMatch(/sample workspace root.*symlink/i)
      await expect(
        fs.stat(path.join(externalWorkspaceRoot, '.analysis-claim-ledger.lock'))
      ).rejects.toMatchObject({ code: 'ENOENT' })
      const externalEntriesAfter = (
        await fs.readdir(externalWorkspaceRoot, { recursive: true })
      ).sort()
      expect(externalEntriesAfter).toEqual(externalEntriesBefore)
    }
  )
})

function insertSample(database: DatabaseManager, sampleId: string, sha256: string): void {
  database.insertSample({
    id: sampleId,
    sha256,
    md5: null,
    size: 1024,
    file_type: 'PE32',
    created_at: '2026-07-14T07:00:00.000Z',
    source: 'unit-test',
  })
}

async function persistFixtureArtifact(args: {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  sampleId: string
  id: string
  type: string
  relativePath: string
  content: string
}): Promise<PersistedArtifactFixture> {
  const workspace = await args.workspaceManager.getWorkspace(args.sampleId)
  const absolutePath = path.join(workspace.root, args.relativePath)
  await fs.mkdir(path.dirname(absolutePath), { recursive: true })
  await fs.writeFile(absolutePath, args.content, 'utf8')
  const sha256 = crypto.createHash('sha256').update(args.content).digest('hex')

  args.database.insertArtifact({
    id: args.id,
    sample_id: args.sampleId,
    type: args.type,
    path: args.relativePath,
    sha256,
    mime: 'application/json',
    created_at: '2026-07-14T07:30:00.000Z',
  })

  return {
    id: args.id,
    type: args.type,
    path: args.relativePath,
    sha256,
    absolutePath,
  }
}

async function claimLedgerLockPath(
  workspaceManager: WorkspaceManager,
  sampleId: string
): Promise<string> {
  const workspace = await workspaceManager.getWorkspace(sampleId)
  return path.join(workspace.root, '.analysis-claim-ledger.lock')
}

async function exitedProcessPid(): Promise<number> {
  const child = spawn(process.execPath, ['-e', 'process.exit(0)'], { stdio: 'ignore' })
  if (!child.pid) throw new Error('Failed to start the dead-PID test process.')
  const pid = child.pid
  await once(child, 'exit')
  return pid
}

async function writeClaimLedgerLockFixture(input: {
  lockPath: string
  sampleId: string
  ownerToken: string
  pid: number
  acquiredAt: Date
  modifiedAt: Date
  hostId?: string
}): Promise<void> {
  await fs.writeFile(
    input.lockPath,
    JSON.stringify({
      version: 1,
      owner_token: input.ownerToken,
      pid: input.pid,
      host_id: input.hostId || os.hostname(),
      sample_id: input.sampleId,
      acquired_at: input.acquiredAt.toISOString(),
    }),
    'utf8'
  )
  await fs.utimes(input.lockPath, input.modifiedAt, input.modifiedAt)
}
