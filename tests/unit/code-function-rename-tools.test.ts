import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import {
  createCodeFunctionRenamePrepareHandler,
  codeFunctionRenamePrepareInputSchema,
} from '../../src/tools/code-function-rename-prepare.js'
import {
  createCodeFunctionRenameApplyHandler,
} from '../../src/tools/code-function-rename-apply.js'
import {
  loadSemanticNameSuggestionIndex,
  SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE,
  SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE,
} from '../../src/artifacts/semantic-name-suggestion-artifacts.js'
import type { WorkerResult, ToolArgs } from '../../src/types.js'

describe('code.function.rename prepare/apply tools', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-rename-tools')
    testDbPath = path.join(process.cwd(), 'test-rename-tools.db')
    testCachePath = path.join(process.cwd(), 'test-cache-rename-tools')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }
  })

  async function setupSample(sampleId: string, hashChar: string) {
    database.insertSample({
      id: sampleId,
      sha256: hashChar.repeat(64),
      md5: hashChar.repeat(32),
      size: 2048,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })
    await workspaceManager.createWorkspace(sampleId)
  }

  test('prepare should build a prompt-ready unresolved evidence bundle and persist an artifact', async () => {
    const sampleId = 'sha256:' + 'a'.repeat(64)
    await setupSample(sampleId, 'a')

    const reconstructHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_resolved',
              address: '0x401000',
              confidence: 0.93,
              suggested_name: 'resolve_dynamic_apis',
              name_resolution: {
                rule_based_name: 'resolve_dynamic_apis',
                llm_suggested_name: null,
                llm_confidence: null,
                llm_why: null,
                required_assumptions: [],
                evidence_used: [],
                validated_name: 'resolve_dynamic_apis',
                resolution_source: 'rule',
                unresolved_semantic_name: false,
              },
              semantic_evidence: {
                semantic_summary: 'Resolves APIs dynamically.',
                string_hints: ['GetProcAddress'],
              },
            },
            {
              function: 'FUN_unresolved',
              address: '0x402000',
              confidence: 0.71,
              suggested_name: null,
              name_resolution: {
                rule_based_name: null,
                llm_suggested_name: null,
                llm_confidence: null,
                llm_why: null,
                required_assumptions: [],
                evidence_used: [],
                validated_name: null,
                resolution_source: 'unresolved',
                unresolved_semantic_name: true,
              },
              semantic_evidence: {
                semantic_summary: 'Likely inspects PE sections and entrypoint layout.',
                string_hints: ['Entry point in non-first section'],
              },
            },
            {
              function: 'FUN_unresolved',
              address: '0x402000',
              confidence: 0.7,
              suggested_name: null,
              name_resolution: {
                rule_based_name: null,
                llm_suggested_name: null,
                llm_confidence: null,
                llm_why: null,
                required_assumptions: [],
                evidence_used: [],
                validated_name: null,
                resolution_source: 'unresolved',
                unresolved_semantic_name: true,
              },
              semantic_evidence: {
                semantic_summary: 'Duplicate fallback row that should be deduplicated.',
                string_hints: ['duplicate'],
              },
            },
          ],
        },
        warnings: ['reconstruct warning'],
      })

    const handler = createCodeFunctionRenamePrepareHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      analysis_goal: 'Review Akasha unresolved functions.',
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.prepared_count).toBe(1)
    expect(data.unresolved_count).toBe(1)
    expect(data.prepared_bundle.selection.evidence_scope).toBe('all')
    expect(data.prepared_bundle.selection.evidence_session_tag).toBeNull()
    expect(data.prepared_bundle.selection.semantic_scope).toBe('all')
    expect(data.prepared_bundle.selection.semantic_session_tag).toBeNull()
    expect(data.prompt_name).toBe('reverse.semantic_name_review')
    expect(data.prepared_bundle.functions[0].function).toBe('FUN_unresolved')
    expect(data.prepared_bundle.functions[0].suggestion_required).toBe(true)
    expect(data.task_prompt).toContain('Return strict JSON only')
    expect(data.artifact.type).toBe(SEMANTIC_NAME_PREPARE_BUNDLE_ARTIFACT_TYPE)
    expect(result.warnings).toContain('reconstruct warning')

    const workspace = await workspaceManager.getWorkspace(sampleId)
    expect(fs.existsSync(path.join(workspace.root, data.artifact.path))).toBe(true)
  })

  test('prepare should require evidence_session_tag when evidence_scope=session and forward scope to reconstruct', async () => {
    expect(() =>
      codeFunctionRenamePrepareInputSchema.parse({
        sample_id: 'sha256:' + 'f'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')

    expect(() =>
      codeFunctionRenamePrepareInputSchema.parse({
        sample_id: 'sha256:' + 'f'.repeat(64),
        semantic_scope: 'session',
      })
    ).toThrow('semantic_session_tag')

    const sampleId = 'sha256:' + 'c'.repeat(64)
    await setupSample(sampleId, 'c')

    const reconstructHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [],
        },
      })

    const handler = createCodeFunctionRenamePrepareHandler(
      workspaceManager,
      database,
      cacheManager,
      {
        reconstructHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
      semantic_scope: 'session',
      semantic_session_tag: 'semantic-beta',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    expect(reconstructHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
        semantic_scope: 'session',
        semantic_session_tag: 'semantic-beta',
      })
    )
  })

  test('apply should normalize accepted suggestions and persist suggestion artifact', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    await setupSample(sampleId, 'b')

    const handler = createCodeFunctionRenameApplyHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      client_name: 'claude-desktop',
      model_name: 'generic-tool-calling-llm',
      suggestions: [
        {
          address_or_function: '0x402000',
          candidate_name: 'Write Remote Memory',
          confidence: 0.86,
          why: 'Uses WriteProcessMemory and remote-process APIs.',
          evidence_used: ['xref:WriteProcessMemory', 'runtime:prepare_remote_process_access'],
        },
        {
          function: 'FUN_bad',
          candidate_name: '!!!',
          confidence: 0.2,
          why: 'invalid',
        },
      ],
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.accepted_count).toBe(1)
    expect(data.rejected_count).toBe(1)
    expect(data.accepted_suggestions[0].normalized_candidate_name).toBe('write_remote_memory')
    expect(data.artifact.type).toBe(SEMANTIC_NAME_SUGGESTIONS_ARTIFACT_TYPE)
    expect(result.warnings?.[0]).toContain('Rejected suggestion')

    const index = await loadSemanticNameSuggestionIndex(workspaceManager, database, sampleId)
    const loaded = index.byAddress.get('402000')
    expect(loaded?.normalized_candidate_name).toBe('write_remote_memory')
    expect(loaded?.client_name).toBe('claude-desktop')
    expect(loaded?.model_name).toBe('generic-tool-calling-llm')
  })

  test('loadSemanticNameSuggestionIndex should honor semantic session scope', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    await setupSample(sampleId, 'd')

    const handler = createCodeFunctionRenameApplyHandler(workspaceManager, database)
    await handler({
      sample_id: sampleId,
      session_tag: 'semantic-alpha',
      suggestions: [
        {
          address_or_function: '0x402000',
          candidate_name: 'alpha_name',
          confidence: 0.8,
          why: 'alpha',
        },
      ],
    })
    await handler({
      sample_id: sampleId,
      session_tag: 'semantic-beta',
      suggestions: [
        {
          address_or_function: '0x402000',
          candidate_name: 'beta_name',
          confidence: 0.9,
          why: 'beta',
        },
      ],
    })

    const scoped = await loadSemanticNameSuggestionIndex(workspaceManager, database, sampleId, {
      scope: 'session',
      sessionTag: 'semantic-beta',
    })
    expect(scoped.byAddress.get('402000')?.normalized_candidate_name).toBe('beta_name')
  })
})
