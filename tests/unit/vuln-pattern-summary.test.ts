import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
/**
 * Unit tests for vuln.pattern.summary tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import {
  createVulnPatternSummaryHandler,
  VulnPatternSummaryInputSchema,
  vulnPatternSummaryToolDefinition,
} from '../../src/plugins/vuln-scanner/tools/vuln-pattern-summary.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'

describe('vuln.pattern.summary tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      findArtifactsByType: jest.fn().mockReturnValue([]),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = VulnPatternSummaryInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = VulnPatternSummaryInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = VulnPatternSummaryInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createVulnPatternSummaryHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid|no .* found|scan first/i)
    })
  })

  describe('Summary handoff metadata', () => {
    test('declares passive summary workflow metadata', () => {
      expect(vulnPatternSummaryToolDefinition.aspects?.capabilities).toEqual(
        expect.arrayContaining([
          'risk-summary',
          'function-risk-ranking',
          'audit-prioritization',
          'workflow-handoff',
        ])
      )
      expect(vulnPatternSummaryToolDefinition.evidence).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ category: 'vulnerabilities' }),
          expect.objectContaining({ category: 'workflow' }),
          expect.objectContaining({ category: 'provenance' }),
        ])
      )
      expect(vulnPatternSummaryToolDefinition.workflowRecipes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'vuln-scanner.pattern-summary-handoff',
            startsWith: expect.arrayContaining(['vuln.pattern.summary', 'vuln.pattern.scan']),
            nextTools: expect.arrayContaining([
              'artifact.read',
              'code.functions.rank',
              'analysis.evidence.graph',
              'report.generate',
            ]),
            requiredArtifacts: ['vuln_pattern_scan'],
          }),
        ])
      )
      expect(vulnPatternSummaryToolDefinition.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          networkPolicy: 'disabled',
          noNetwork: true,
          noMutation: true,
          noLiveExecution: true,
        })
      )
    })

    test('summarizes persisted scan artifact and returns review handoff', async () => {
      const sampleHash = 'c'.repeat(64)
      const sampleId = `sha256:${sampleHash}`
      const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-vuln-summary-'))
      const workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
      const database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

      try {
        database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
          id: sampleId,
          sha256: sampleHash,
          md5: 'd'.repeat(32),
          size: 128,
          file_type: 'PE32 executable',
          created_at: new Date().toISOString(),
          source: 'unit-test',
        })
        const workspace = await workspaceManager.createWorkspace(sampleId)
        const reportDir = path.join(workspace.reports, 'static_analysis', 'default')
        fs.mkdirSync(reportDir, { recursive: true })
        const payload = {
          findings: [
            {
              pattern_id: 'CWE-120-strcpy',
              cwe: 'CWE-120',
              name: 'Buffer Copy without Checking Size',
              severity: 'high',
              confidence: 0.9,
              function_address: '0x401000',
              function_name: 'copy_user_input',
              match_snippet: 'strcpy(buf, src)',
            },
          ],
          functions_scanned: 1,
          total_findings: 1,
          severity_counts: { high: 1 },
          cwe_counts: { 'CWE-120': 1 },
        }
        const artifactPath = path.join(reportDir, 'vuln_findings_unit.json')
        fs.writeFileSync(artifactPath, JSON.stringify(payload), 'utf8')
        database.insertArtifact({
          id: 'artifact-vuln-summary',
          sample_id: sampleId,
          type: 'vuln_pattern_scan',
          path: path.relative(workspace.root, artifactPath).replace(/\\/g, '/'),
          sha256: 'e'.repeat(64),
          mime: 'application/json',
          created_at: new Date().toISOString(),
        })

        const handler = createVulnPatternSummaryHandler({ workspaceManager, database } as any)
        const result = await handler({ sample_id: sampleId, top_n_functions: 5 })

        expect(result.ok).toBe(true)
        const data = result.data as any
        expect(data.schema).toBe('rikune.vuln_pattern_summary.v1')
        expect(data.overall_risk_level).toBe('medium')
        expect(data.total_findings).toBe(1)
        expect(data.evidence_summary).toEqual(
          expect.objectContaining({
            schema: 'rikune.vuln_pattern_summary.evidence_summary.v1',
            source_artifact_type: 'vuln_pattern_scan',
            total_findings: 1,
            functions_scanned: 1,
          })
        )
        expect(data.workflow_handoff).toEqual(
          expect.objectContaining({
            schema: 'rikune.vuln_pattern_summary.workflow_handoff.v1',
            routing: expect.arrayContaining([
              expect.objectContaining({
                goal: 'high-risk-function-review',
                next_tools: expect.arrayContaining(['code.functions.rank']),
              }),
              expect.objectContaining({
                goal: 'reporting',
                next_tools: expect.arrayContaining(['report.generate']),
              }),
            ]),
          })
        )
        expect(data.quality_gates).toEqual(
          expect.objectContaining({
            passive_static_only: true,
            source_artifact_available: true,
            analyst_review_required: true,
          })
        )
        expect(data.recommended_next_tools).toEqual(
          expect.arrayContaining(['artifact.read', 'code.functions.rank', 'report.generate'])
        )
      } finally {
        database.close()
        fs.rmSync(tempRoot, { recursive: true, force: true })
      }
    })
  })
})
