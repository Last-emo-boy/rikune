/**
 * Unit tests for pe.structure.analyze tool
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import peAnalysisPlugin from '../../src/plugins/pe-analysis/index.js'
import {
  createPEStructureAnalyzeHandler,
  peStructureAnalyzeInputSchema,
  peStructureAnalyzeToolDefinition,
} from '../../src/plugins/pe-analysis/tools/pe-structure-analyze.js'
import type { WorkspaceManager } from '../../src/workspace-manager.js'
import type { DatabaseManager } from '../../src/database.js'

describe('pe.structure.analyze tool', () => {
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
      const result = peStructureAnalyzeInputSchema.safeParse({ sample_id: 'sha256:abc123def456' })
      expect(result.success).toBe(true)
    })

    test('should reject empty input', () => {
      const result = peStructureAnalyzeInputSchema.safeParse({})
      expect(result.success).toBe(false)
    })

    test('should reject invalid types', () => {
      const result = peStructureAnalyzeInputSchema.safeParse({ sample_id: 123 })
      expect(result.success).toBe(false)
    })
  })

  describe('Handler', () => {
    test('should return error for non-existent resource', async () => {
      const handler = createPEStructureAnalyzeHandler({ workspaceManager: mockWorkspaceManager, database: mockDatabase } as any)

      mockDatabase.findSample.mockReturnValue(undefined)

      const result = await handler({ sample_id: 'sha256:abc123def456' })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toMatch(/not found|unknown|invalid/i)
    })
  })

  describe('Metadata', () => {
    test('declares PE structure artifact, evidence, workflow, and static worker policy', () => {
      expect(peStructureAnalyzeToolDefinition.artifacts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'pe_structure_analysis',
            mime: 'application/json',
          }),
        ])
      )

      expect(peStructureAnalyzeToolDefinition.evidence).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            category: 'structure',
            artifactTypes: expect.arrayContaining(['pe_structure_analysis']),
          }),
          expect.objectContaining({
            category: 'imports',
            artifactTypes: expect.arrayContaining(['pe_structure_analysis']),
          }),
          expect.objectContaining({
            category: 'exports',
            artifactTypes: expect.arrayContaining(['pe_structure_analysis']),
          }),
          expect.objectContaining({
            category: 'resources',
            artifactTypes: expect.arrayContaining(['pe_structure_analysis']),
          }),
          expect.objectContaining({
            category: 'provenance',
            artifactTypes: expect.arrayContaining(['pe_structure_analysis']),
          }),
        ])
      )

      expect(peStructureAnalyzeToolDefinition.workflowRecipes?.[0]).toEqual(
        expect.objectContaining({
          id: 'pe.static.structure-profile',
          startsWith: expect.arrayContaining(['pe.structure.analyze']),
          nextTools: expect.arrayContaining([
            'pe.imports.extract',
            'pe.exports.extract',
            'analysis.evidence.graph',
          ]),
          producesArtifacts: expect.arrayContaining(['pe_structure_analysis']),
          evidence: expect.arrayContaining([
            'structure',
            'imports',
            'exports',
            'resources',
            'provenance',
          ]),
        })
      )

      expect(peStructureAnalyzeToolDefinition.workerBackend).toEqual(
        expect.objectContaining({
          backendName: 'Static Python PE structure worker',
          backendKind: 'external',
          adapter: 'static_python.pe.structure.analyze',
          outputArtifactTypes: expect.arrayContaining(['pe_structure_analysis']),
          policy: expect.objectContaining({
            passiveByDefault: true,
            noNetwork: true,
            noMutation: true,
            noLiveExecution: true,
          }),
          readiness: expect.objectContaining({
            doesNotStartBackend: true,
          }),
        })
      )
    })

    test('profiles PE driver and EFI formats with passive parser dependencies', () => {
      expect(peAnalysisPlugin.aspects?.formats).toEqual(
        expect.arrayContaining(['pe', 'pe-clr', 'sys', 'efi'])
      )
      expect(peAnalysisPlugin.aspects?.safety).toEqual(
        expect.arrayContaining([
          'passive',
          'external_static_backend',
          'no_live_sample_by_default',
          'no_network_by_default',
          'no_mutation',
        ])
      )
      expect(peAnalysisPlugin.systemDeps).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'python',
            name: 'pefile',
            importName: 'pefile',
            required: false,
          }),
          expect.objectContaining({
            type: 'python',
            name: 'lief',
            importName: 'lief',
            required: false,
          }),
        ])
      )
    })
  })
})
