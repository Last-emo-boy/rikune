import { createHash } from 'crypto'
import fs from 'fs/promises'
import path from 'path'
import type { DatabaseManager } from '../../src/database.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { ArtifactRef } from '../../src/types.js'
import {
  ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
  ANALYSIS_CLAIM_SET_SCHEMA,
  AnalysisClaimSetArtifactSchema,
  type AnalysisClaim,
  type AnalysisClaimEvidence,
} from '../../src/artifacts/analysis-claim-artifacts.js'

export interface ClaimLedgerFixtureClaim {
  claim_id: string
  category?: AnalysisClaim['category']
  subject: string
  statement: string
  supporting_evidence?: AnalysisClaimEvidence[]
  counter_evidence?: AnalysisClaimEvidence[]
}

export async function seedAnalysisClaimLedgerFixture(input: {
  workspaceManager: WorkspaceManager
  database: DatabaseManager
  sampleId: string
  revisionCount: number
  startRevision?: number
  parentArtifactId?: string | null
  artifactIdPrefix: string
  createdAtBase: string
  claimForRevision: (revision: number) => ClaimLedgerFixtureClaim
}): Promise<ArtifactRef[]> {
  const workspace = await input.workspaceManager.createWorkspace(input.sampleId)
  const fixtureDirectory = path.join(workspace.reports, 'claims', input.artifactIdPrefix)
  await fs.mkdir(fixtureDirectory, { recursive: true })
  const createdAtBase = Date.parse(input.createdAtBase)
  const artifacts: ArtifactRef[] = []
  const startRevision = input.startRevision || 1
  let parentArtifactId: string | null = input.parentArtifactId || null

  for (let offset = 0; offset < input.revisionCount; offset += 1) {
    const revision = startRevision + offset
    const fixtureClaim = input.claimForRevision(revision)
    const supportingEvidence = fixtureClaim.supporting_evidence || []
    const counterEvidence = fixtureClaim.counter_evidence || []
    const evidence = [...supportingEvidence, ...counterEvidence]
    const checks =
      evidence.length > 0
        ? [
            'artifact_exists' as const,
            'sample_matches' as const,
            'artifact_type_allowed' as const,
            'artifact_readable' as const,
            'artifact_sha256_matches' as const,
            ...(evidence.some((reference) => reference.json_pointer !== undefined)
              ? (['json_pointer_resolves'] as const)
              : []),
          ]
        : []
    const createdAt = new Date(createdAtBase + revision * 1000).toISOString()
    const payload = AnalysisClaimSetArtifactSchema.parse({
      schema: ANALYSIS_CLAIM_SET_SCHEMA,
      schema_version: 1,
      sample_id: input.sampleId,
      ledger_revision: revision,
      parent_artifact_id: parentArtifactId,
      created_at: createdAt,
      session_tag: null,
      goal: null,
      producer: { kind: 'llm', client_name: null, model_name: 'unit-test-fixture' },
      claims: [
        {
          claim_id: fixtureClaim.claim_id,
          source: 'llm',
          category: fixtureClaim.category || 'open_question',
          subject: fixtureClaim.subject,
          statement: fixtureClaim.statement,
          status: 'inferred',
          supporting_evidence: supportingEvidence,
          counter_evidence: counterEvidence,
          assumptions: [],
          alternatives: [],
          falsification_tests: [],
          review: null,
        },
      ],
      validation_results: [
        {
          claim_id: fixtureClaim.claim_id,
          validation_type: 'evidence_reference_integrity',
          status: evidence.length > 0 ? 'passed' : 'not_applicable',
          validator: 'analysis.claims.apply',
          validated_at: createdAt,
          supporting_evidence_count: supportingEvidence.length,
          counter_evidence_count: counterEvidence.length,
          checks,
          note: 'Deterministic Claim Ledger test fixture.',
        },
      ],
      validation_summary: {
        status: 'passed',
        claim_count: 1,
        evidence_reference_count: evidence.length,
        json_pointer_count: evidence.filter((reference) => reference.json_pointer !== undefined)
          .length,
      },
    })
    const artifactId = `${input.artifactIdPrefix}-r${revision}`
    const absolutePath = path.join(
      fixtureDirectory,
      `claim_set_r${revision.toString().padStart(4, '0')}.json`
    )
    const serialized = JSON.stringify(payload, null, 2)
    await fs.writeFile(absolutePath, serialized, 'utf8')
    const artifact: ArtifactRef = {
      id: artifactId,
      type: ANALYSIS_CLAIM_SET_ARTIFACT_TYPE,
      path: path.relative(workspace.root, absolutePath).replace(/\\/g, '/'),
      sha256: createHash('sha256').update(serialized).digest('hex'),
      mime: 'application/json',
    }
    input.database.insertArtifact({
      ...artifact,
      sample_id: input.sampleId,
      mime: artifact.mime || null,
      created_at: createdAt,
    })
    artifacts.push(artifact)
    parentArtifactId = artifact.id
  }

  return artifacts
}
