import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
/**
 * Unit tests for vuln.pattern.scan tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import {
  createVulnPatternScanHandler,
  VulnPatternScanInputSchema,
  vulnPatternScanToolDefinition,
} from '../../src/plugins/vuln-scanner/tools/vuln-pattern-scan.js'
import vulnScannerPlugin from '../../src/plugins/vuln-scanner/index.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'

describe('vuln.pattern.scan tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>

  beforeEach(() => {
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    mockDatabase = {
      findSample: jest.fn(),
      getDb: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = VulnPatternScanInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = VulnPatternScanInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = VulnPatternScanInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createVulnPatternScanHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })
  })

  describe('Metadata and workflow handoff', () => {
    test('declares passive vulnerability scan artifact, evidence, workflow, and policy', () => {
      expect(vulnScannerPlugin.aspects?.capabilities).toEqual(
        expect.arrayContaining([
          'cwe-patterns',
          'function-risk-ranking',
          'audit-prioritization',
          'workflow-handoff',
        ])
      )
      expect(vulnScannerPlugin.aspects?.safety).toEqual(
        expect.arrayContaining(['passive', 'no_network_by_default', 'no_live_execution'])
      )
      expect(vulnScannerPlugin.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          networkPolicy: 'disabled',
          noNetwork: true,
          noMutation: true,
          noLiveExecution: true,
        })
      )

      expect(vulnPatternScanToolDefinition.artifacts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'vuln_pattern_scan',
            mime: 'application/json',
          }),
        ])
      )
      expect(vulnPatternScanToolDefinition.evidence).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ category: 'vulnerabilities' }),
          expect.objectContaining({ category: 'functions' }),
          expect.objectContaining({ category: 'workflow' }),
          expect.objectContaining({ category: 'provenance' }),
        ])
      )
      expect(vulnPatternScanToolDefinition.workflowRecipes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'vuln-scanner.pattern-risk-handoff',
            startsWith: expect.arrayContaining([
              'vuln.pattern.scan',
              'code.functions.reconstruct',
            ]),
            nextTools: expect.arrayContaining([
              'artifact.read',
              'vuln.pattern.summary',
              'code.functions.rank',
              'analysis.evidence.graph',
            ]),
            producesArtifacts: ['vuln_pattern_scan'],
            evidence: expect.arrayContaining([
              'vulnerabilities',
              'functions',
              'risk-ranking',
              'workflow',
            ]),
          }),
        ])
      )
      expect(vulnPatternScanToolDefinition.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          networkPolicy: 'disabled',
          noNetwork: true,
          noMutation: true,
          noLiveExecution: true,
        })
      )
    })

    test('returns evidence summary, workflow handoff, quality gates, and artifact', async () => {
      const sampleHash = 'a'.repeat(64)
      const sampleId = `sha256:${sampleHash}`
      const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-vuln-scan-'))
      const workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
      const database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

      try {
        database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
          id: sampleId,
          sha256: sampleHash,
          md5: 'b'.repeat(32),
          size: 256,
          file_type: 'PE32 executable',
          created_at: new Date().toISOString(),
          source: 'unit-test',
        })
        const now = new Date().toISOString()
        database.insertAnalysisEvidence({
          id: 'evidence-vuln-function-map',
          sample_id: sampleId,
          sample_sha256: sampleHash,
          evidence_family: 'function_map',
          backend: 'unit-test',
          mode: 'fixture',
          compatibility_marker: 'function-map-unit',
          freshness_marker: null,
          provenance_json: JSON.stringify({ source: 'unit-test' }),
          metadata_json: null,
          result_json: JSON.stringify({
            functions: [
              {
                name: 'copy_user_input',
                address: '0x401000',
                decompiled_code:
                  'void copy_user_input(char *src) { char buf[8]; read(0, src, 128); strcpy(buf, src); }',
              },
            ],
          }),
          artifact_refs_json: null,
          created_at: now,
          updated_at: now,
          last_accessed_at: null,
        })

        const handler = createVulnPatternScanHandler({ workspaceManager, database } as any)
        const result = await handler({
          sample_id: sampleId,
          min_confidence: 0.3,
          max_findings: 10,
        })

        expect(result.ok).toBe(true)
        const data = result.data as any
        expect(data.schema).toBe('rikune.vuln_pattern_scan.v1')
        expect(data.tool_version).toBe('1.1.0')
        expect(data.functions_scanned).toBe(1)
        expect(data.total_findings).toBeGreaterThan(0)
        expect(data.evidence_summary).toEqual(
          expect.objectContaining({
            schema: 'rikune.vuln_pattern_scan.evidence_summary.v1',
            artifact_type: 'vuln_pattern_scan',
            functions_scanned: 1,
            high_risk_finding_count: expect.any(Number),
          })
        )
        expect(data.workflow_handoff).toEqual(
          expect.objectContaining({
            schema: 'rikune.vuln_pattern_scan.workflow_handoff.v1',
            handoff_mode: 'vulnerability_pattern_scan_to_function_review',
            routing: expect.arrayContaining([
              expect.objectContaining({
                goal: 'function-risk-ranking',
                next_tools: expect.arrayContaining(['code.functions.rank']),
              }),
              expect.objectContaining({
                goal: 'vulnerability-summary-and-reporting',
                next_tools: expect.arrayContaining(['vuln.pattern.summary']),
              }),
            ]),
            dynamic_boundary: expect.objectContaining({
              passive_static_only: true,
              sample_executed_by_tool: false,
              network_accessed_by_tool: false,
            }),
          })
        )
        expect(data.quality_gates).toEqual(
          expect.objectContaining({
            schema: 'rikune.vuln_pattern_scan.quality_gates.v1',
            passive_static_only: true,
            decompiled_functions_available: true,
            pattern_scan_completed: true,
            artifact_persisted: true,
            analyst_review_required: true,
          })
        )
        expect(data.recommended_next_tools).toEqual(
          expect.arrayContaining([
            'artifact.read',
            'vuln.pattern.summary',
            'code.functions.rank',
            'analysis.evidence.graph',
          ])
        )
        expect(result.artifacts).toHaveLength(1)
        expect(data.artifact).toEqual(result.artifacts?.[0])
        expect(data.artifact.type).toBe('vuln_pattern_scan')

        const artifacts = database.findArtifactsByType(sampleId, 'vuln_pattern_scan')
        expect(artifacts).toHaveLength(1)
        const workspace = await workspaceManager.getWorkspace(sampleId)
        const artifactPayload = JSON.parse(
          fs.readFileSync(path.join(workspace.root, artifacts[0].path), 'utf8')
        )
        expect(artifactPayload.schema).toBe('rikune.vuln_pattern_scan.v1')
        expect(artifactPayload.workflow_handoff.routing).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ goal: 'function-risk-ranking' }),
            expect.objectContaining({ goal: 'artifact-review' }),
          ])
        )
      } finally {
        database.close()
        fs.rmSync(tempRoot, { recursive: true, force: true })
      }
    })
  })
})
