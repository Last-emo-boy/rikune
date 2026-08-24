import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import { createHash } from 'crypto'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { DatabaseManager, type AnalysisEvidence } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import {
  ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
  ANALYSIS_CASE_STATE_SCHEMA,
  persistAnalysisCaseStateArtifact,
} from '../../src/artifacts/analysis-case-artifacts.js'
import { createAnalysisClaimsApplyHandler } from '../../src/plugins/kb-collaboration/tools/analysis-claims-apply.js'
import {
  AnalysisContextPackOutputSchema,
  createAnalysisContextPackHandler,
} from '../../src/plugins/kb-collaboration/tools/analysis-context-pack.js'
import { seedAnalysisClaimLedgerFixture } from '../helpers/analysis-claim-ledger-fixture.js'

const SHA256 = 'a'.repeat(64)
const SAMPLE_ID = `sha256:${SHA256}`

function evidenceRow(input: {
  id: string
  family: string
  role: 'primary' | 'derived'
  result: Record<string, unknown>
  updatedAt: string
  artifactRefs?: unknown[]
  backend?: string
  mode?: string
  provenance?: Record<string, unknown>
  metadata?: Record<string, unknown> | null
}): AnalysisEvidence {
  const backend = input.backend ?? (input.family === 'strings' ? 'strings.extract' : 'workflow')
  const mode = input.mode ?? 'static'
  return {
    id: input.id,
    sample_id: SAMPLE_ID,
    sample_sha256: SHA256,
    evidence_family: input.family,
    backend,
    mode,
    compatibility_marker: `compat-${input.id}`,
    freshness_marker: null,
    provenance_json: JSON.stringify(
      input.provenance ?? {
        tool: input.family === 'strings' ? 'strings.extract' : 'workflow.summarize',
        evidence_role: input.role,
      }
    ),
    metadata_json: input.metadata === undefined ? null : JSON.stringify(input.metadata),
    result_json: JSON.stringify(input.result),
    artifact_refs_json: JSON.stringify(input.artifactRefs || []),
    created_at: input.updatedAt,
    updated_at: input.updatedAt,
    last_accessed_at: null,
  }
}

describe('analysis.context.pack', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-context-pack-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: SHA256,
      md5: 'b'.repeat(32),
      size: 1024,
      file_type: 'PE32',
      created_at: '2026-07-14T08:00:00.000Z',
      source: 'unit-test',
    })
    await workspaceManager.createWorkspace(SAMPLE_ID)
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempRoot, { recursive: true, force: true })
  })

  test('packs deterministic partitions and supports an incremental marker', async () => {
    database.insertArtifact({
      id: 'artifact-strings',
      sample_id: SAMPLE_ID,
      type: 'strings_report',
      path: 'reports/static/strings.json',
      sha256: 'c'.repeat(64),
      mime: 'application/json',
      created_at: '2026-07-14T08:01:00.000Z',
    })
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-primary',
        family: 'strings',
        role: 'primary',
        updatedAt: '2026-07-14T08:01:00.000Z',
        artifactRefs: [
          {
            id: 'artifact-strings',
            type: 'strings_report',
            path: 'reports/static/strings.json',
            sha256: 'c'.repeat(64),
          },
        ],
        result: {
          strings: ['serial accepted', 'try again'],
          coverage_gaps: ['Validation branch has not been decompiled.'],
        },
      })
    )
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-derived',
        family: 'context_link',
        role: 'derived',
        updatedAt: '2026-07-14T08:02:00.000Z',
        result: { links: [{ function: 'main', string: 'serial accepted' }] },
      })
    )
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-summary-context-only',
        family: 'summary',
        role: 'derived',
        updatedAt: '2026-07-14T08:03:00.000Z',
        result: { coverage_gaps: ['Runtime success path remains unverified.'] },
      })
    )

    const claimsHandler = createAnalysisClaimsApplyHandler(workspaceManager, database)
    const claimResult = await claimsHandler({
      sample_id: SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'unit-test' },
      claims: [
        {
          claim_id: 'claim-open-question',
          category: 'open_question',
          subject: 'Crackme validation',
          statement: 'Which input reaches the success branch?',
          status: 'inferred',
        },
      ],
    })
    expect(claimResult.ok).toBe(true)

    await persistAnalysisCaseStateArtifact(workspaceManager, database, {
      schema: ANALYSIS_CASE_STATE_SCHEMA,
      schema_version: 1,
      artifact_role: ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
      sample_id: SAMPLE_ID,
      case_id: 'case-crackme',
      revision: 1,
      parent_artifact_id: null,
      created_at: '2026-07-14T08:04:00.000Z',
      session_tag: null,
      objective: 'Recover and verify the accepted crackme input.',
      decisions: ['Start from the observed validation strings.'],
      open_questions: ['Does the success branch require a checksum?'],
      attempted_actions: [],
      active_claim_ids: ['claim-open-question'],
      pinned_artifacts: [],
      next_actions: ['Read the validation function pseudocode.'],
      producer: { kind: 'external_agent', agent_name: 'unit-test' },
    })

    const handler = createAnalysisContextPackHandler(workspaceManager, database)
    const first = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Recover and verify the accepted crackme input.',
      token_budget: 12_000,
      evidence_scope: 'latest',
      claim_scope: 'latest',
      include_case: true,
    })

    expect(first.ok).toBe(true)
    expect(AnalysisContextPackOutputSchema.safeParse(first).success).toBe(true)
    const data = first.data as any
    expect(data.primary_evidence.map((entry: any) => entry.evidence_id)).toEqual([
      'evidence-primary',
    ])
    expect(data.derived_evidence.map((entry: any) => entry.evidence_id)).toEqual([
      'evidence-derived',
    ])
    expect(
      [...data.primary_evidence, ...data.derived_evidence].some(
        (entry: any) => entry.evidence_id === 'evidence-summary-context-only'
      )
    ).toBe(false)
    expect(data.claims[0]).toMatchObject({
      review_required: true,
      claim: { claim_id: 'claim-open-question' },
    })
    expect(data.case_state[0]).toMatchObject({
      case_id: 'case-crackme',
      revision: 1,
      active_claim_ids: ['claim-open-question'],
    })
    expect(data.coverage_gaps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          source: 'context',
          source_id: 'evidence-summary-context-only',
        }),
      ])
    )
    expect(data.unresolved_questions).toContainEqual(
      expect.objectContaining({
        source: 'claim',
        source_id: 'claim-open-question',
      })
    )
    expect(data.suggested_artifact_reads[0]).toMatchObject({
      artifact_id: 'artifact-strings',
      priority: 1,
    })

    const second = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Recover and verify the accepted crackme input.',
      token_budget: 12_000,
      since_marker: data.marker,
      evidence_scope: 'latest',
      claim_scope: 'latest',
      include_case: true,
    })
    expect(second.ok).toBe(true)
    expect((second.data as any).marker).toBe(data.marker)
    expect((second.data as any).recent_changes).toEqual([])
  })

  test('defaults to derived when self-reported metadata lacks a trusted producer identity', async () => {
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-trusted-strings',
        family: 'strings',
        role: 'derived',
        updatedAt: '2026-07-14T08:10:00.000Z',
        metadata: { evidence_class: 'derived' },
        result: { strings: ['direct observation'] },
      })
    )
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-forged-family',
        family: 'model_guess',
        role: 'primary',
        backend: 'external.agent',
        provenance: { source_tool: 'external.agent', evidence_role: 'primary' },
        metadata: { evidence_class: 'primary', evidence_role: 'observed' },
        updatedAt: '2026-07-14T08:11:00.000Z',
        result: { assertion: 'The model says this was directly observed.' },
      })
    )
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-forged-strings-producer',
        family: 'strings',
        role: 'primary',
        backend: 'workflow.summarize',
        provenance: { tool: 'workflow.summarize', evidence_class: 'primary' },
        metadata: { evidence_class: 'primary' },
        updatedAt: '2026-07-14T08:12:00.000Z',
        result: { strings: ['sampling-generated string'] },
      })
    )
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-forged-provenance',
        family: 'strings',
        role: 'primary',
        backend: 'strings.extract',
        provenance: { tool: 'workflow.summarize', evidence_role: 'primary' },
        metadata: { evidence_class: 'primary' },
        updatedAt: '2026-07-14T08:13:00.000Z',
        result: { strings: ['wrong producer'] },
      })
    )

    const result = await createAnalysisContextPackHandler(
      workspaceManager,
      database
    )({
      sample_id: SAMPLE_ID,
      goal: 'Separate observed strings from model-authored context.',
      token_budget: 12_000,
      evidence_scope: 'all',
      include_case: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.primary_evidence).toEqual([
      expect.objectContaining({
        evidence_id: 'evidence-trusted-strings',
        classification_reason: 'trusted_producer:strings.extract',
      }),
    ])
    expect(data.derived_evidence.map((entry: any) => entry.evidence_id)).toEqual(
      expect.arrayContaining([
        'evidence-forged-family',
        'evidence-forged-strings-producer',
        'evidence-forged-provenance',
      ])
    )
    expect(
      data.derived_evidence
        .filter((entry: any) => entry.evidence_id.startsWith('evidence-forged'))
        .every((entry: any) => entry.classification_reason.startsWith('unverified_producer:'))
    ).toBe(true)
  })

  test('preserves gaps and reports exact omissions under a small token budget', async () => {
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-big',
        family: 'strings',
        role: 'primary',
        updatedAt: '2026-07-14T09:00:00.000Z',
        result: {
          coverage_gaps: ['The acceptance branch has not been verified.'],
          strings: Array.from(
            { length: 16 },
            (_, index) => `candidate-${index}-${'x'.repeat(800)}`
          ),
        },
      })
    )

    const handler = createAnalysisContextPackHandler(workspaceManager, database)
    const result = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Recover the accepted input.',
      token_budget: 900,
      include_case: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.coverage_gaps).toContainEqual(
      expect.objectContaining({
        source: 'primary_evidence',
        source_id: 'evidence-big',
      })
    )
    expect(data.primary_evidence).toEqual([])
    expect(data.truncation_manifest.truncated).toBe(true)
    expect(data.truncation_manifest.sections.primary_evidence).toMatchObject({
      available_count: 1,
      included_count: 0,
      omitted_count: 1,
      omitted_ids: ['evidence-big'],
    })
    expect(data.truncation_manifest.sections.primary_evidence.estimated_tokens).toBeGreaterThan(0)
    expect(data.truncation_manifest.budget_floor_exceeded).toBe(false)
    expect(data.truncation_manifest.estimated_tokens).toBeLessThanOrEqual(900)
  })

  test('rebuilds evidence references from same-sample canonical artifact records', async () => {
    const otherSha = 'd'.repeat(64)
    const otherSampleId = `sha256:${otherSha}`
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: otherSampleId,
      sha256: otherSha,
      md5: 'e'.repeat(32),
      size: 2048,
      file_type: 'ELF',
      created_at: '2026-07-14T09:10:00.000Z',
      source: 'unit-test',
    })
    database.insertArtifact({
      id: 'artifact-local',
      sample_id: SAMPLE_ID,
      type: 'strings_report',
      path: 'reports/static/canonical.json',
      sha256: '1'.repeat(64),
      mime: 'application/json',
      created_at: '2026-07-14T09:11:00.000Z',
    })
    database.insertArtifact({
      id: 'artifact-foreign',
      sample_id: otherSampleId,
      type: 'secret_foreign_type',
      path: 'reports/private/foreign.json',
      sha256: '2'.repeat(64),
      mime: 'application/json',
      created_at: '2026-07-14T09:12:00.000Z',
    })
    database.insertArtifact({
      id: 'artifact-summary',
      sample_id: SAMPLE_ID,
      type: 'summary_final_digest',
      path: 'reports/summary/final.json',
      sha256: '3'.repeat(64),
      mime: 'application/json',
      created_at: '2026-07-14T09:13:00.000Z',
    })
    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-forged-refs',
        family: 'strings',
        role: 'primary',
        updatedAt: '2026-07-14T09:14:00.000Z',
        artifactRefs: [
          {
            id: 'artifact-local',
            type: 'forged_type',
            path: '../../forged.json',
            sha256: 'f'.repeat(64),
          },
          { id: 'artifact-foreign', path: 'leak-me.json' },
          { id: 'artifact-summary' },
          { id: 'artifact-missing' },
        ],
        result: { strings: ['canonical reference'] },
      })
    )

    const result = await createAnalysisContextPackHandler(
      workspaceManager,
      database
    )({
      sample_id: SAMPLE_ID,
      goal: 'Verify artifact isolation.',
      token_budget: 12_000,
      include_case: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.primary_evidence[0].artifact_refs).toEqual([
      {
        id: 'artifact-local',
        type: 'strings_report',
        path: 'reports/static/canonical.json',
        sha256: '1'.repeat(64),
      },
    ])
    expect(data.suggested_artifact_reads).toContainEqual(
      expect.objectContaining({
        artifact_id: 'artifact-local',
        type: 'strings_report',
        path: 'reports/static/canonical.json',
        sha256: '1'.repeat(64),
      })
    )
    expect(JSON.stringify(data)).not.toContain('reports/private/foreign.json')
    expect(JSON.stringify(data)).not.toContain('../../forged.json')
    expect(result.warnings?.join('\n')).toMatch(/cross-sample artifact reference/i)
    expect(result.warnings?.join('\n')).toMatch(/context-only artifact reference/i)
    expect(result.warnings?.join('\n')).toMatch(/missing artifact reference/i)
  })

  test('isolates one case and fails closed when case selection is ambiguous', async () => {
    const claimsHandler = createAnalysisClaimsApplyHandler(workspaceManager, database)
    const caseBArtifactId = 'artifact-case-b-only'
    const caseBArtifactPath = 'reports/static/case-b-only.json'
    const caseBArtifactContent = JSON.stringify({ scope: 'case-b-only' })
    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    await fs.mkdir(path.dirname(path.join(workspace.root, caseBArtifactPath)), {
      recursive: true,
    })
    await fs.writeFile(path.join(workspace.root, caseBArtifactPath), caseBArtifactContent, 'utf8')
    database.insertArtifact({
      id: caseBArtifactId,
      sample_id: SAMPLE_ID,
      type: 'strings_report',
      path: caseBArtifactPath,
      sha256: createHash('sha256').update(caseBArtifactContent).digest('hex'),
      mime: 'application/json',
      created_at: '2026-07-14T09:18:00.000Z',
    })
    const seededClaims = await claimsHandler({
      sample_id: SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'unit-test' },
      claims: [
        {
          claim_id: 'claim-case-a',
          category: 'open_question',
          subject: 'Case A question',
          statement: 'Only Case A should expose this question.',
          status: 'inferred',
        },
        {
          claim_id: 'claim-case-b',
          category: 'open_question',
          subject: 'Case B question',
          statement: 'Only Case B should expose this question.',
          status: 'inferred',
          supporting_evidence: [{ artifact_id: caseBArtifactId }],
        },
      ],
    })
    expect(seededClaims.ok).toBe(true)

    const persistCase = async (caseId: string, activeClaimId: string, createdAt: string) =>
      await persistAnalysisCaseStateArtifact(workspaceManager, database, {
        schema: ANALYSIS_CASE_STATE_SCHEMA,
        schema_version: 1,
        artifact_role: ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
        sample_id: SAMPLE_ID,
        case_id: caseId,
        revision: 1,
        parent_artifact_id: null,
        created_at: createdAt,
        session_tag: null,
        objective: `Investigate ${caseId}.`,
        decisions: [],
        open_questions: [],
        attempted_actions: [],
        active_claim_ids: [activeClaimId],
        pinned_artifacts: [],
        next_actions: [],
        producer: { kind: 'external_agent', agent_name: 'unit-test' },
      })

    await persistCase('case-a', 'claim-case-a', '2026-07-14T09:20:00.000Z')
    const handler = createAnalysisContextPackHandler(workspaceManager, database)
    const first = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track independent cases.',
      token_budget: 12_000,
      include_case: true,
    })
    expect(first.ok).toBe(true)
    expect(first.data).toMatchObject({
      case_id: 'case-a',
      case_state: [expect.objectContaining({ case_id: 'case-a' })],
    })
    expect((first.data as any).claims.map((entry: any) => entry.claim.claim_id)).toEqual([
      'claim-case-a',
    ])
    expect((first.data as any).suggested_artifact_reads).not.toContainEqual(
      expect.objectContaining({ artifact_id: caseBArtifactId })
    )
    expect(JSON.stringify(first.data)).not.toContain('Only Case B should expose this question.')

    const caseBRevision1 = await persistCase('case-b', 'claim-case-b', '2026-07-14T09:21:00.000Z')
    const ambiguous = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track independent cases.',
      token_budget: 12_000,
      include_case: true,
    })
    expect(ambiguous.ok).toBe(false)
    expect(ambiguous.errors?.join('\n')).toMatch(/multiple analysis cases.*case_id/i)
    expect(ambiguous.errors?.join('\n')).toContain('case-a, case-b')

    const selectedA = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track case A only.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-a',
      since_marker: (first.data as any).marker,
    })
    expect(selectedA.ok).toBe(true)
    expect(selectedA.data).toMatchObject({
      case_id: 'case-a',
      case_state: [expect.objectContaining({ case_id: 'case-a' })],
      recent_changes: [],
      marker: (first.data as any).marker,
    })
    expect((selectedA.data as any).claims.map((entry: any) => entry.claim.claim_id)).toEqual([
      'claim-case-a',
    ])

    const revisedCaseBClaim = await claimsHandler({
      sample_id: SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'unit-test-v2' },
      claims: [
        {
          claim_id: 'claim-case-b',
          category: 'open_question',
          subject: 'Case B revised question',
          statement: 'Revised Case B content must remain invisible to Case A.',
          status: 'inferred',
          supporting_evidence: [{ artifact_id: caseBArtifactId }],
        },
      ],
    })
    expect(revisedCaseBClaim.ok).toBe(true)

    const selectedAAfterCaseBClaim = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track case A after Case B changes.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-a',
      since_marker: (selectedA.data as any).marker,
    })
    expect(selectedAAfterCaseBClaim.ok).toBe(true)
    expect((selectedAAfterCaseBClaim.data as any).marker).toBe((selectedA.data as any).marker)
    expect((selectedAAfterCaseBClaim.data as any).recent_changes).toEqual([])
    expect((selectedAAfterCaseBClaim.data as any).suggested_artifact_reads).not.toContainEqual(
      expect.objectContaining({ artifact_id: caseBArtifactId })
    )
    expect(JSON.stringify(selectedAAfterCaseBClaim.data)).not.toContain(
      'Revised Case B content must remain invisible to Case A.'
    )

    const crossCaseMarker = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track case B only.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-b',
      since_marker: (first.data as any).marker,
    })
    expect(crossCaseMarker.ok).toBe(false)
    expect(crossCaseMarker.errors?.join('\n')).toMatch(/since_marker belongs to case_id=case-a/i)

    const selectedB = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track case B only.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-b',
    })
    expect(selectedB.ok).toBe(true)
    expect(selectedB.data).toMatchObject({
      case_id: 'case-b',
      case_state: [expect.objectContaining({ case_id: 'case-b' })],
    })
    expect((selectedB.data as any).claims).toEqual([
      expect.objectContaining({
        claim: expect.objectContaining({
          claim_id: 'claim-case-b',
          statement: 'Revised Case B content must remain invisible to Case A.',
        }),
      }),
    ])
    expect(JSON.stringify(selectedB.data)).not.toContain('Investigate case-a.')
    expect(JSON.stringify(selectedB.data)).not.toContain('Only Case A should expose this question.')
    expect((selectedB.data as any).suggested_artifact_reads).toContainEqual(
      expect.objectContaining({
        artifact_id: caseBArtifactId,
        reasons: [`claim:claim-case-b`],
      })
    )

    await persistAnalysisCaseStateArtifact(workspaceManager, database, {
      schema: ANALYSIS_CASE_STATE_SCHEMA,
      schema_version: 1,
      artifact_role: ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
      sample_id: SAMPLE_ID,
      case_id: 'case-b',
      revision: 2,
      parent_artifact_id: caseBRevision1.id,
      created_at: '2026-07-14T09:22:00.000Z',
      session_tag: null,
      objective: 'Investigate case-b.',
      decisions: [],
      open_questions: [],
      attempted_actions: [],
      active_claim_ids: ['claim-case-b'],
      pinned_artifacts: [],
      next_actions: [],
      producer: { kind: 'external_agent', agent_name: 'unit-test' },
    })
    const selectedBRevision2 = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track case B revision 2.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-b',
    })
    expect(selectedBRevision2.ok).toBe(true)
    expect((selectedBRevision2.data as any).claims).toHaveLength(1)

    const selectedAAfterCaseBRevision = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track case A after Case B revision.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-a',
      since_marker: (selectedAAfterCaseBClaim.data as any).marker,
    })
    expect(selectedAAfterCaseBRevision.ok).toBe(true)
    expect((selectedAAfterCaseBRevision.data as any).marker).toBe(
      (selectedAAfterCaseBClaim.data as any).marker
    )
    expect((selectedAAfterCaseBRevision.data as any).recent_changes).toEqual([])

    await fs.appendFile(path.join(workspace.root, caseBRevision1.path), '\ncorrupted', 'utf8')

    const selectedAAfterCaseBCorruption = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track case A after Case B corruption.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-a',
      since_marker: (selectedAAfterCaseBClaim.data as any).marker,
    })
    expect(selectedAAfterCaseBCorruption.ok).toBe(true)
    expect((selectedAAfterCaseBCorruption.data as any).marker).toBe(
      (selectedAAfterCaseBClaim.data as any).marker
    )
    expect((selectedAAfterCaseBCorruption.data as any).recent_changes).toEqual([])
    expect(
      (selectedAAfterCaseBCorruption.data as any).claims.map((entry: any) => entry.claim.claim_id)
    ).toEqual(['claim-case-a'])

    const degradedCaseB = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track case B after predecessor corruption.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-b',
      since_marker: (selectedBRevision2.data as any).marker,
    })
    expect(degradedCaseB.ok).toBe(true)
    expect((degradedCaseB.data as any).claims).toEqual([])
    expect((degradedCaseB.data as any).marker).not.toBe((selectedBRevision2.data as any).marker)
    expect((degradedCaseB.data as any).recent_changes).toContainEqual(
      expect.objectContaining({ kind: 'context', id: 'marker-invalidated' })
    )
    expect((degradedCaseB.data as any).suggested_artifact_reads).not.toContainEqual(
      expect.objectContaining({ artifact_id: caseBArtifactId })
    )
    expect(degradedCaseB.warnings).toContain(
      `Skipped case state with SHA-256 mismatch: ${caseBRevision1.id}`
    )
  })

  test('invalidates a strict failure marker when the unreadable Claim head changes', async () => {
    const claimsResult = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: SAMPLE_ID,
      producer: { kind: 'llm', model_name: 'unit-test' },
      claims: [
        {
          claim_id: 'claim-failure-marker',
          category: 'open_question',
          subject: 'Failure marker integrity',
          statement: 'Which Claim head is preventing strict resolution?',
          status: 'inferred',
        },
      ],
    })
    expect(claimsResult.ok).toBe(true)
    await persistAnalysisCaseStateArtifact(workspaceManager, database, {
      schema: ANALYSIS_CASE_STATE_SCHEMA,
      schema_version: 1,
      artifact_role: ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
      sample_id: SAMPLE_ID,
      case_id: 'case-failure-marker',
      revision: 1,
      parent_artifact_id: null,
      created_at: '2026-07-14T09:23:00.000Z',
      session_tag: null,
      objective: 'Keep strict Claim resolution fail-closed and observable.',
      decisions: [],
      open_questions: [],
      attempted_actions: [],
      active_claim_ids: ['claim-failure-marker'],
      pinned_artifacts: [],
      next_actions: [],
      producer: { kind: 'external_agent', agent_name: 'unit-test' },
    })

    const handler = createAnalysisContextPackHandler(workspaceManager, database)
    const baseline = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track strict Claim integrity failures.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-failure-marker',
    })
    expect(baseline.ok).toBe(true)

    const insertUnreadableHead = (id: string, createdAt: string) =>
      database.insertArtifact({
        id,
        sample_id: SAMPLE_ID,
        type: 'analysis_claim_set',
        path: `reports/claims/missing/${id}.json`,
        sha256: createHash('sha256').update(id).digest('hex'),
        mime: 'application/json',
        created_at: createdAt,
      })

    insertUnreadableHead('broken-claim-head-1', '2099-07-14T09:24:00.000Z')
    const firstFailure = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track strict Claim integrity failures.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-failure-marker',
      since_marker: (baseline.data as any).marker,
    })
    expect(firstFailure.ok).toBe(true)
    expect((firstFailure.data as any).claims).toEqual([])
    expect((firstFailure.data as any).marker).not.toBe((baseline.data as any).marker)
    expect((firstFailure.data as any).recent_changes).toContainEqual(
      expect.objectContaining({ kind: 'context', id: 'marker-invalidated' })
    )

    insertUnreadableHead('broken-claim-head-2', '2099-07-14T09:25:00.000Z')
    const secondFailure = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track strict Claim integrity failures.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-failure-marker',
      since_marker: (firstFailure.data as any).marker,
    })
    expect(secondFailure.ok).toBe(true)
    expect((secondFailure.data as any).claims).toEqual([])
    expect((secondFailure.data as any).marker).not.toBe((firstFailure.data as any).marker)
    expect((secondFailure.data as any).recent_changes).toContainEqual(
      expect.objectContaining({ kind: 'context', id: 'marker-invalidated' })
    )
    expect(secondFailure.warnings?.join('\n')).toContain('broken-claim-head-2')

    const stableFailure = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track strict Claim integrity failures.',
      token_budget: 12_000,
      include_case: true,
      case_id: 'case-failure-marker',
      since_marker: (secondFailure.data as any).marker,
    })
    expect(stableFailure.ok).toBe(true)
    expect((stableFailure.data as any).marker).toBe((secondFailure.data as any).marker)
    expect((stableFailure.data as any).recent_changes).toEqual([])
  })

  test('preserves a Case-active Claim and suggested read through 257 cross-Case revisions', async () => {
    const retainedArtifactId = 'artifact-case-a-retained-through-churn'
    const retainedArtifactPath = 'reports/static/case-a-retained-through-churn.json'
    const retainedArtifactContent = JSON.stringify({ scope: 'case-a-retained' })
    const retainedArtifactSha256 = createHash('sha256')
      .update(retainedArtifactContent)
      .digest('hex')
    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    await fs.mkdir(path.dirname(path.join(workspace.root, retainedArtifactPath)), {
      recursive: true,
    })
    await fs.writeFile(
      path.join(workspace.root, retainedArtifactPath),
      retainedArtifactContent,
      'utf8'
    )
    database.insertArtifact({
      id: retainedArtifactId,
      sample_id: SAMPLE_ID,
      type: 'strings_report',
      path: retainedArtifactPath,
      sha256: retainedArtifactSha256,
      mime: 'application/json',
      created_at: '2026-07-14T09:30:00.000Z',
    })
    const [caseAClaimArtifact] = await seedAnalysisClaimLedgerFixture({
      workspaceManager,
      database,
      sampleId: SAMPLE_ID,
      revisionCount: 1,
      artifactIdPrefix: 'context-churn-257',
      createdAtBase: '2026-07-14T09:30:00.000Z',
      claimForRevision: () => ({
        claim_id: 'claim-context-case-a-old',
        subject: 'Case A retained context',
        statement: 'Case A context and suggested read must survive unrelated Case B churn.',
        supporting_evidence: [
          {
            artifact_id: retainedArtifactId,
            artifact_type: 'strings_report',
            artifact_path: retainedArtifactPath,
            artifact_sha256: retainedArtifactSha256,
          },
        ],
      }),
    })
    await persistAnalysisCaseStateArtifact(workspaceManager, database, {
      schema: ANALYSIS_CASE_STATE_SCHEMA,
      schema_version: 1,
      artifact_role: ANALYSIS_CASE_STATE_ARTIFACT_ROLE,
      sample_id: SAMPLE_ID,
      case_id: 'case-a-context-churn',
      revision: 1,
      parent_artifact_id: null,
      created_at: '2026-07-14T09:35:00.000Z',
      session_tag: null,
      objective: 'Keep Case A context stable through Case B Claim churn.',
      decisions: [],
      open_questions: [],
      attempted_actions: [],
      active_claim_ids: ['claim-context-case-a-old'],
      pinned_artifacts: [],
      next_actions: [],
      producer: { kind: 'external_agent', agent_name: 'unit-test' },
    })

    const handler = createAnalysisContextPackHandler(workspaceManager, database)
    const first = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track Case A through unrelated Claim churn.',
      token_budget: 32_000,
      include_case: true,
      case_id: 'case-a-context-churn',
    })
    expect(first.ok).toBe(true)
    expect((first.data as any).claims).toEqual([
      expect.objectContaining({
        claim: expect.objectContaining({ claim_id: 'claim-context-case-a-old' }),
      }),
    ])
    expect((first.data as any).suggested_artifact_reads).toContainEqual(
      expect.objectContaining({ artifact_id: retainedArtifactId })
    )

    await seedAnalysisClaimLedgerFixture({
      workspaceManager,
      database,
      sampleId: SAMPLE_ID,
      revisionCount: 256,
      startRevision: 2,
      parentArtifactId: caseAClaimArtifact.id,
      artifactIdPrefix: 'context-churn-257',
      createdAtBase: '2026-07-14T09:30:00.000Z',
      claimForRevision: (revision) => ({
        claim_id: 'claim-context-case-b-churn',
        subject: 'Case B context churn',
        statement: `Case B unrelated context Claim revision ${revision}.`,
      }),
    })

    const afterChurn = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Track Case A after unrelated Claim churn.',
      token_budget: 32_000,
      include_case: true,
      case_id: 'case-a-context-churn',
      since_marker: (first.data as any).marker,
    })
    expect(afterChurn.ok).toBe(true)
    expect((afterChurn.data as any).marker).toBe((first.data as any).marker)
    expect((afterChurn.data as any).recent_changes).toEqual([])
    expect((afterChurn.data as any).claims).toEqual((first.data as any).claims)
    expect((afterChurn.data as any).suggested_artifact_reads).toContainEqual(
      expect.objectContaining({ artifact_id: retainedArtifactId })
    )
    expect(afterChurn.warnings?.join('\n') || '').not.toMatch(
      /scan is incomplete|could not be resolved|withheld/i
    )
  })

  test('records upstream evidence omissions when scoped rows exceed the materialization cap', async () => {
    for (let index = 0; index < 257; index += 1) {
      database.insertAnalysisEvidence(
        evidenceRow({
          id: `evidence-cap-${index.toString().padStart(3, '0')}`,
          family: 'strings',
          role: 'primary',
          updatedAt: '2026-07-14T09:25:00.000Z',
          result: { value: index },
        })
      )
    }

    const result = await createAnalysisContextPackHandler(
      workspaceManager,
      database
    )({
      sample_id: SAMPLE_ID,
      goal: 'Inspect bounded evidence coverage.',
      token_budget: 32_000,
      evidence_scope: 'all',
      include_case: false,
    })

    expect(result.ok).toBe(true)
    expect((result.data as any).truncation_manifest.sections.primary_evidence).toMatchObject({
      available_count: 257,
      upstream_truncated: true,
      upstream_omitted_count: 1,
    })
    expect(result.warnings?.join('\n')).toMatch(/upstream omissions/i)
  })

  test('rejects malformed and cross-sample incremental markers', async () => {
    const handler = createAnalysisContextPackHandler(workspaceManager, database)
    const malformed = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Recover the accepted input.',
      since_marker: 'not-a-context-marker',
      include_case: false,
    })
    expect(malformed.ok).toBe(false)
    expect(malformed.errors?.join('\n')).toContain('since_marker')

    database.insertAnalysisEvidence(
      evidenceRow({
        id: 'evidence-rewritten-in-place',
        family: 'strings',
        role: 'primary',
        updatedAt: '2026-07-14T09:30:00.000Z',
        result: { strings: ['before'] },
      })
    )
    const first = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Recover the accepted input.',
      include_case: false,
    })
    expect(first.ok).toBe(true)

    const marker = (first.data as any).marker as string
    database.updateAnalysisEvidence('evidence-rewritten-in-place', {
      result_json: JSON.stringify({ strings: ['after'] }),
    })
    const invalidated = await handler({
      sample_id: SAMPLE_ID,
      goal: 'Recover the accepted input.',
      since_marker: marker,
      include_case: false,
    })
    expect(invalidated.ok).toBe(true)
    expect((invalidated.data as any).recent_changes).toContainEqual(
      expect.objectContaining({ kind: 'context', id: 'marker-invalidated' })
    )

    const otherSha = 'd'.repeat(64)
    const otherSampleId = `sha256:${otherSha}`
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: otherSampleId,
      sha256: otherSha,
      md5: 'e'.repeat(32),
      size: 2048,
      file_type: 'ELF',
      created_at: '2026-07-14T10:00:00.000Z',
      source: 'unit-test',
    })
    await workspaceManager.createWorkspace(otherSampleId)
    const crossSample = await handler({
      sample_id: otherSampleId,
      goal: 'Inspect the other sample.',
      since_marker: marker,
      include_case: false,
    })
    expect(crossSample.ok).toBe(false)
    expect(crossSample.errors?.join('\n')).toMatch(/same sample|belong|malformed/i)
  })
})
