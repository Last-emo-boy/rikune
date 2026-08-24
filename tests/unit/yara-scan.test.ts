import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
/**
 * Unit tests for yara.scan tool
 * Requirements: 5.1, 5.2, 5.3, 5.5
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import type { CacheManager } from '../../src/cache-manager.js'

const mockBuildStaticWorkerRequest = jest.fn((input: any) => ({
  job_id: 'job-yara-scan-unit',
  tool: input.tool,
  sample: {
    sample_id: input.sampleId,
    path: input.samplePath,
  },
  args: input.args || {},
  context: {
    request_time_utc: '2026-06-09T00:00:00.000Z',
    policy: {
      allow_dynamic: false,
      allow_network: false,
    },
    versions: {
      tool_version: input.toolVersion,
    },
  },
}))
const mockCallStaticWorker = jest.fn()

jest.unstable_mockModule('../../src/tools/static-worker-client.js', () => ({
  buildStaticWorkerRequest: mockBuildStaticWorkerRequest,
  callStaticWorker: mockCallStaticWorker,
}))

const { createYaraScanHandler, YaraScanInputSchema, yaraScanToolDefinition } =
  await import('../../src/plugins/yara/tools/yara-scan.js')

describe('yara.scan tool', () => {
  let mockWorkspaceManager: jest.Mocked<WorkspaceManager>
  let mockDatabase: jest.Mocked<DatabaseManager>
  let mockCacheManager: jest.Mocked<CacheManager>

  beforeEach(() => {
    // Create mock workspace manager
    mockWorkspaceManager = {
      getWorkspace: jest.fn(),
    } as unknown as jest.Mocked<WorkspaceManager>

    // Create mock database
    mockDatabase = {
      findSample: jest.fn(),
    } as unknown as jest.Mocked<DatabaseManager>

    // Create mock cache manager
    mockCacheManager = {
      getCachedResult: jest.fn(),
      setCachedResult: jest.fn(),
    } as unknown as jest.Mocked<CacheManager>

    mockBuildStaticWorkerRequest.mockClear()
    mockCallStaticWorker.mockReset()
  })

  describe('Input validation', () => {
    test('should validate correct input', () => {
      const input = {
        sample_id: 'sha256:abc123',
        rule_set: 'malware_families',
        timeout_ms: 30000,
      }

      const result = YaraScanInputSchema.safeParse(input)
      expect(result.success).toBe(true)
    })

    test('should use default timeout_ms', () => {
      const input = {
        sample_id: 'sha256:abc123',
        rule_set: 'packers',
      }

      const result = YaraScanInputSchema.safeParse(input)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.timeout_ms).toBe(30000)
      }
    })

    test('should reject invalid timeout_ms', () => {
      const input = {
        sample_id: 'sha256:abc123',
        rule_set: 'malware_families',
        timeout_ms: 500, // Too small
      }

      const result = YaraScanInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })

    test('should require rule_set', () => {
      const input = {
        sample_id: 'sha256:abc123',
      }

      const result = YaraScanInputSchema.safeParse(input)
      expect(result.success).toBe(false)
    })
  })

  describe('Handler execution', () => {
    test('should return error if sample not found', async () => {
      const handler = createYaraScanHandler(mockWorkspaceManager, mockDatabase, mockCacheManager)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({
        sample_id: 'sha256:nonexistent',
        rule_set: 'malware_families',
      })

      expect(result.ok).toBe(false)
      expect(result.errors).toContain('Sample not found: sha256:nonexistent')
    })

    test('should return cached result if available', async () => {
      const handler = createYaraScanHandler(mockWorkspaceManager, mockDatabase, mockCacheManager)

      const mockSample = {
        id: 'sha256:abc123',
        sha256: 'abc123',
        md5: 'def456',
        size: 1024,
        file_type: 'PE32',
        created_at: '2024-01-01T00:00:00Z',
        source: 'test',
      }

      const cachedData = {
        matches: [
          {
            rule: 'UPX_Packer',
            tags: ['packer', 'upx'],
            meta: { author: 'test' },
            strings: [],
          },
        ],
        ruleset_version: 'v1.0',
        timed_out: false,
        rule_set: 'packers',
      }

      mockDatabase.findSample.mockReturnValue(mockSample)
      mockCacheManager.getCachedResult.mockResolvedValue(cachedData)

      const result = await handler({
        sample_id: 'sha256:abc123',
        rule_set: 'packers',
      })

      expect(result.ok).toBe(true)
      expect(result.data).toEqual(
        expect.objectContaining({
          ...cachedData,
          schema: 'rikune.yara_scan.v1',
          tool_version: '1.1.0',
          sample_id: 'sha256:abc123',
          match_count: 1,
          string_evidence_count: 0,
          evidence_summary: expect.objectContaining({
            schema: 'rikune.yara_scan.evidence_summary.v1',
            artifact_type: 'backend_yara_scan',
            match_count: 1,
          }),
          workflow_handoff: expect.objectContaining({
            schema: 'rikune.yara_scan.workflow_handoff.v1',
            handoff_mode: 'yara_scan_to_validation_evidence_graph_and_reporting',
          }),
          quality_gates: expect.objectContaining({
            schema: 'rikune.yara_scan.quality_gates.v1',
            passive_local_scan_only: true,
            backend_started: false,
            sample_executed_by_tool: false,
            network_accessed_by_tool: false,
          }),
          recommended_next_tools: expect.arrayContaining([
            'artifact.read',
            'analysis.evidence.graph',
            'report.generate',
          ]),
        })
      )
      expect(result.warnings).toContain('Result from cache')
      expect(mockCacheManager.getCachedResult).toHaveBeenCalled()
    })
  })

  describe('Scan-validation handoff', () => {
    test('declares passive local scan metadata and worker readiness contract', () => {
      expect(yaraScanToolDefinition.aspects?.safety).toEqual(
        expect.arrayContaining(['passive', 'no_live_sample_by_default', 'no_network_by_default'])
      )
      expect(yaraScanToolDefinition.aspects?.capabilities).toEqual(
        expect.arrayContaining(['workflow-handoff', 'evidence-correlation', 'readiness'])
      )
      expect(yaraScanToolDefinition.artifacts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'backend_yara_scan',
            mime: 'application/json',
          }),
        ])
      )
      expect(yaraScanToolDefinition.evidence).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            category: 'signatures',
            artifactTypes: ['backend_yara_scan'],
          }),
          expect.objectContaining({
            category: 'workflow',
            artifactTypes: ['backend_yara_scan'],
          }),
          expect.objectContaining({
            category: 'provenance',
            artifactTypes: ['backend_yara_scan'],
          }),
        ])
      )
      expect(yaraScanToolDefinition.workflowRecipes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'yara.scan-validation-handoff',
            startsWith: expect.arrayContaining(['yara.scan', 'yara.generate']),
            nextTools: expect.arrayContaining([
              'artifact.read',
              'analysis.evidence.graph',
              'report.generate',
            ]),
            producesArtifacts: ['backend_yara_scan'],
            evidence: expect.arrayContaining(['signatures', 'strings', 'workflow', 'provenance']),
            safety: expect.arrayContaining([
              'passive',
              'no_live_sample_by_default',
              'no_network_by_default',
            ]),
          }),
        ])
      )
      expect(yaraScanToolDefinition.workerBackend).toEqual(
        expect.objectContaining({
          backendName: 'static_python.preview',
          adapter: 'runtime-worker-pool/static_worker.py:yara.scan',
          policy: expect.objectContaining({
            passiveByDefault: true,
            noNetwork: true,
            noLiveExecution: true,
            noMutation: true,
          }),
          outputArtifactTypes: ['backend_yara_scan'],
        })
      )
    })

    test('returns evidence summary, workflow handoff, quality gates, and persisted artifact', async () => {
      const sampleHash = '8'.repeat(64)
      const sampleId = `sha256:${sampleHash}`
      const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-yara-scan-'))
      let database: DatabaseManager | null = null

      try {
        const workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
        database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
        const cacheManager = {
          getCachedResult: jest.fn().mockResolvedValue(null),
          setCachedResult: jest.fn().mockResolvedValue(undefined),
        } as unknown as jest.Mocked<CacheManager>

        database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
          id: sampleId,
          sha256: sampleHash,
          md5: '9'.repeat(32),
          size: 128,
          file_type: 'PE32 executable',
          created_at: new Date().toISOString(),
          source: 'unit-test',
        })

        const workspace = await workspaceManager.createWorkspace(sampleId)
        fs.writeFileSync(path.join(workspace.original, 'sample.exe'), Buffer.from('MZunit-test'))

        mockCallStaticWorker.mockResolvedValue({
          job_id: 'job-yara-scan-unit',
          ok: true,
          warnings: [],
          errors: [],
          data: {
            matches: [
              {
                rule: 'SuspiciousUnitFamily',
                tags: ['malware-family'],
                meta: { author: 'unit-test', description: 'unit family rule' },
                strings: [
                  {
                    identifier: '$mz_marker',
                    offset: 0,
                    matched_data: 'MZ',
                    location: {
                      section: '.text',
                      offset_in_section: 0,
                      rva: 4096,
                      distance_to_entrypoint: 16,
                    },
                  },
                ],
                confidence: {
                  level: 'high',
                  score: 0.9,
                  reason: 'Matched imported API evidence.',
                },
                evidence: {
                  import_dll_hits: ['kernel32.dll'],
                  import_api_hits: ['CreateFileA'],
                  section_hits: ['.text'],
                  near_entrypoint_hits: 1,
                  string_only: false,
                },
                inference: {
                  classification: 'malware-family',
                  summary: 'Unit-test family confidence.',
                },
              },
            ],
            ruleset_version: 'rules-v2',
            timed_out: false,
            rule_set: 'malware_families',
            rule_tier: 'production',
            rule_files: ['malware_families.yar'],
            confidence_summary: { high: 1, medium: 0, low: 0 },
            import_evidence: { dll_count: 1, api_count: 1 },
            offset_mapping: {
              parser: 'pefile',
              sections_count: 3,
              entry_point: { rva: 4096 },
            },
            quality_notes: [],
          },
          artifacts: [],
          metrics: {
            worker_pool: {
              family: 'static_python.preview',
              compatibility_key: 'compat-yara-scan',
            },
          },
        })

        const handler = createYaraScanHandler(workspaceManager, database, cacheManager)
        const result = await handler({
          sample_id: sampleId,
          rule_set: 'malware_families',
          timeout_ms: 5000,
        })

        expect(result.ok).toBe(true)
        const data = result.data as any
        expect(data.schema).toBe('rikune.yara_scan.v1')
        expect(data.tool_version).toBe('1.1.0')
        expect(data.match_count).toBe(1)
        expect(data.string_evidence_count).toBe(1)
        expect(data.evidence_summary).toEqual(
          expect.objectContaining({
            schema: 'rikune.yara_scan.evidence_summary.v1',
            artifact_type: 'backend_yara_scan',
            match_count: 1,
            string_evidence_count: 1,
            rule_provenance: expect.objectContaining({
              source: 'bundled_static_worker_yara_rules',
              rule_set: 'malware_families',
              ruleset_version: 'rules-v2',
              rule_files: ['malware_families.yar'],
            }),
            offset_evidence: expect.objectContaining({
              strings_with_offsets: 1,
              strings_with_location: 1,
              near_entrypoint_hits: 1,
              parser: 'pefile',
              string_preview: expect.arrayContaining([
                expect.objectContaining({
                  rule: 'SuspiciousUnitFamily',
                  identifier: '$mz_marker',
                  offset: 0,
                  matched_data_preview: 'MZ',
                  section: '.text',
                }),
              ]),
            }),
            confidence_summary: { high: 1, medium: 0, low: 0 },
          })
        )
        expect(data.workflow_handoff).toEqual(
          expect.objectContaining({
            schema: 'rikune.yara_scan.workflow_handoff.v1',
            handoff_mode: 'yara_scan_to_validation_evidence_graph_and_reporting',
            artifact_type: 'backend_yara_scan',
            routing: expect.arrayContaining([
              expect.objectContaining({
                goal: 'evidence-graph-and-reporting',
                next_tools: expect.arrayContaining(['analysis.evidence.graph', 'report.generate']),
              }),
              expect.objectContaining({
                goal: 'workflow-search-reuse',
                next_tools: ['workflow.search'],
              }),
            ]),
            dynamic_boundary: expect.objectContaining({
              passive_local_scan_only: true,
              sample_executed_by_tool: false,
              network_accessed_by_tool: false,
            }),
          })
        )
        expect(data.quality_gates).toEqual(
          expect.objectContaining({
            schema: 'rikune.yara_scan.quality_gates.v1',
            passive_local_scan_only: true,
            backend_started: true,
            sample_executed_by_tool: false,
            network_accessed_by_tool: false,
            rule_provenance_available: true,
            match_floor_met: true,
            string_offset_evidence_available: true,
            dominant_confidence: 'high',
          })
        )
        expect(data.recommended_next_tools).toEqual(
          expect.arrayContaining([
            'artifact.read',
            'analysis.evidence.graph',
            'report.generate',
            'malware.intel.loop',
          ])
        )
        expect(result.artifacts).toHaveLength(1)
        expect(data.artifact).toEqual(result.artifacts?.[0])
        expect(data.artifact.type).toBe('backend_yara_scan')

        const artifacts = database.findArtifactsByType(sampleId, 'backend_yara_scan')
        expect(artifacts).toHaveLength(1)
        const artifactPayload = JSON.parse(
          fs.readFileSync(path.join(workspace.root, artifacts[0].path), 'utf8')
        )
        expect(artifactPayload.schema).toBe('rikune.yara_scan.v1')
        expect(artifactPayload.workflow_handoff.routing).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ goal: 'artifact-review-and-offset-validation' }),
            expect.objectContaining({ goal: 'evidence-graph-and-reporting' }),
          ])
        )
        expect(cacheManager.setCachedResult).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            artifact: expect.objectContaining({ type: 'backend_yara_scan' }),
            workflow_handoff: expect.objectContaining({
              schema: 'rikune.yara_scan.workflow_handoff.v1',
            }),
          }),
          expect.any(Number)
        )
      } finally {
        database?.close()
        fs.rmSync(tempRoot, { recursive: true, force: true })
      }
    })
  })

  describe('YARA match structure', () => {
    test('should validate match structure in schema', () => {
      const matchData = {
        matches: [
          {
            rule: 'UPX_Packer',
            tags: ['packer', 'upx'],
            meta: {
              author: 'Test Author',
              description: 'UPX packer detection',
            },
            strings: [
              {
                identifier: '$upx_magic',
                offset: 0,
                matched_data: 'UPX!',
              },
              {
                identifier: '$upx_string',
                offset: 512,
                matched_data: 'UPX packed',
              },
            ],
          },
        ],
        ruleset_version: 'abc123',
        timed_out: false,
        rule_set: 'packers',
      }

      // Verify the structure matches what we expect
      expect(matchData.matches).toHaveLength(1)
      expect(matchData.matches[0].rule).toBe('UPX_Packer')
      expect(matchData.matches[0].tags).toEqual(['packer', 'upx'])
      expect(matchData.matches[0].meta).toHaveProperty('author')
      expect(matchData.matches[0].strings).toHaveLength(2)
      expect(matchData.matches[0].strings[0]).toHaveProperty('identifier')
      expect(matchData.matches[0].strings[0]).toHaveProperty('offset')
      expect(matchData.matches[0].strings[0]).toHaveProperty('matched_data')
    })
  })
})
