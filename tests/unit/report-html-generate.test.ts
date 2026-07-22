/**
 * Unit tests for report.html.generate tool
 */

import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { createHash } from 'crypto'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { createArtifactReadHandler } from '../../src/tools/artifact-read.js'
import { isContextOnlyArtifactType } from '../../src/artifacts/context-only-artifacts.js'
import {
  createReportHtmlGenerateHandler,
  ReportHtmlGenerateInputSchema,
  reportHtmlGenerateToolDefinition,
} from '../../src/plugins/visualization/tools/report-html-generate.js'

describe('report.html.generate tool', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleHash = '1'.repeat(64)
  const sampleId = `sha256:${sampleHash}`

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'report-html-generate-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  describe('Input validation', () => {
    test('should accept valid input', () => {
      const result = ReportHtmlGenerateInputSchema.safeParse({ sample_id: sampleId })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = ReportHtmlGenerateInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = ReportHtmlGenerateInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  test('declares an html_report artifact handoff recipe', () => {
    expect(isContextOnlyArtifactType('html_report')).toBe(true)
    expect(reportHtmlGenerateToolDefinition.description).toContain('context-only')
    expect(reportHtmlGenerateToolDefinition.description).toContain(
      'cannot be used as Claim evidence'
    )
    expect(reportHtmlGenerateToolDefinition.evidence).toBeUndefined()
    expect(reportHtmlGenerateToolDefinition.aspects?.evidence).toBeUndefined()
    expect(reportHtmlGenerateToolDefinition.aspects?.safety).toContain('context-only')
    expect(reportHtmlGenerateToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'html_report',
          mime: 'text/html',
        }),
      ])
    )
    expect(reportHtmlGenerateToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'visualization.html-report-artifact',
          startsWith: ['report.html.generate'],
          nextTools: expect.arrayContaining(['artifact.read', 'workflow.search']),
          producesArtifacts: ['html_report'],
          safety: expect.arrayContaining(['context-only']),
        }),
      ])
    )
    expect(reportHtmlGenerateToolDefinition.workflowRecipes?.[0]?.evidence).toBeUndefined()
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createReportHtmlGenerateHandler({ workspaceManager, database } as any)

      const result = await handler({ sample_id: sampleId })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })

    test('generates html_report artifact contract and artifact.read handoff', async () => {
      seedSampleWithEvidence()
      const handler = createReportHtmlGenerateHandler({ workspaceManager, database } as any)

      const result = await handler({
        sample_id: sampleId,
        title: 'Unit Test Report',
        sections: ['overview', 'strings', 'iocs', 'threat_score'],
      })

      expect(result.ok).toBe(true)
      expect(result.artifacts).toHaveLength(1)

      const data = result.data as any
      const artifact = result.artifacts?.[0]
      expect(artifact).toEqual(
        expect.objectContaining({
          type: 'html_report',
          mime: 'text/html',
        })
      )
      expect(artifact?.path).toMatch(/^reports\//)
      expect(path.isAbsolute(artifact?.path ?? '')).toBe(false)
      expect(artifact?.path).toMatch(/_report_\d{4}-\d{2}-\d{2}T.*_[a-f0-9]{8}\.html$/)
      expect(artifact?.metadata).toEqual(
        expect.objectContaining({
          source_tool: 'report.html.generate',
          sample_id: sampleId,
          artifact_role: 'context_only',
          surface_role: 'html_report_export',
          evidence_used: 3,
        })
      )

      const workspace = await workspaceManager.getWorkspace(sampleId)
      const htmlPath = path.join(workspace.root, artifact!.path)
      const html = await fs.readFile(htmlPath, 'utf8')
      const sha256 = createHash('sha256').update(html).digest('hex')

      expect(html).toContain('<!DOCTYPE html>')
      expect(html).toContain(sampleId)
      expect(html).toContain('Unit Test Report')
      expect(html).toContain('https://c2.example.test/beacon')
      expect(artifact?.sha256).toBe(sha256)

      const persisted = database.findArtifactsByType(sampleId, 'html_report')
      expect(persisted).toHaveLength(1)
      expect(persisted[0]).toEqual(
        expect.objectContaining({
          id: artifact?.id,
          sample_id: sampleId,
          type: 'html_report',
          path: artifact?.path,
          sha256,
          mime: 'text/html',
        })
      )

      expect(data).toEqual(
        expect.objectContaining({
          report_path: htmlPath,
          artifact_id: artifact?.id,
          artifact,
          sha256,
          artifact_refs: [artifact],
          recommended_next_tools: ['artifact.read', 'workflow.search'],
        })
      )
      expect(data.artifact_read).toEqual({
        tool: 'artifact.read',
        args: {
          sample_id: sampleId,
          artifact_id: artifact?.id,
          read_mode: 'content',
          include_content: true,
        },
      })
      expect(data.workflow_handoff).toEqual(
        expect.objectContaining({
          schema: 'rikune.html_report.workflow_handoff.v1',
          source_tool: 'report.html.generate',
          sample_id: sampleId,
          read_args: data.artifact_read.args,
        })
      )
      expect(data.workflow_handoff.artifact_contract).toEqual(
        expect.objectContaining({
          produces: ['html_report'],
          artifact_role: 'context_only',
          artifact_id: artifact?.id,
          artifact_path: artifact?.path,
          sha256,
          mime: 'text/html',
          expected_consumers: ['artifact.read'],
        })
      )
      expect(data.quality_gates).toEqual(
        expect.objectContaining({
          schema: 'rikune.html_report.quality_gates.v1',
          artifact_role: 'context_only',
          passive_correlation_only: true,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          mutation_performed: false,
          artifact_persisted: true,
          artifact_file_written: true,
          artifact_registered: true,
          html_nonempty: true,
          evidence_present: true,
          section_count: 4,
        })
      )

      const artifactReadHandler = createArtifactReadHandler(workspaceManager, database)
      const readResult = await artifactReadHandler(data.artifact_read.args)
      expect(readResult.ok).toBe(true)
      expect(readResult.data).toEqual(
        expect.objectContaining({
          read_mode: 'content',
          content_encoding: 'utf8',
        })
      )
      expect((readResult.data as any).artifact).toEqual(
        expect.objectContaining({
          id: artifact?.id,
          type: 'html_report',
          sha256,
        })
      )
      expect((readResult.data as any).content).toContain('Unit Test Report')
      expect((readResult.data as any).content).toContain('https://c2.example.test/beacon')
    })
  })

  function seedSampleWithEvidence() {
    const now = new Date().toISOString()
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: '2'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: now,
      source: 'unit-test',
    })

    insertEvidence('strings', {
      strings: [
        'https://c2.example.test/beacon',
        'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      ],
    })
    insertEvidence('ioc_export', {
      indicators: [{ type: 'url', value: 'https://c2.example.test/beacon' }],
    })
    insertEvidence('sandbox_report', {
      threat_score: 75,
      threat_level: 'high',
    })
  }

  function insertEvidence(family: string, result: Record<string, unknown>) {
    const now = new Date().toISOString()
    database.insertAnalysisEvidence({
      id: `${family}-evidence`,
      sample_id: sampleId,
      sample_sha256: sampleHash,
      evidence_family: family,
      backend: 'unit-test',
      mode: 'test',
      compatibility_marker: 'unit-test',
      freshness_marker: 'fresh',
      provenance_json: JSON.stringify({ source: 'unit-test' }),
      metadata_json: JSON.stringify({ family }),
      result_json: JSON.stringify(result),
      artifact_refs_json: JSON.stringify([]),
      created_at: now,
      updated_at: now,
      last_accessed_at: now,
    })
  }
})
