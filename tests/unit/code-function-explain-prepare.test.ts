import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import {
  createCodeFunctionExplainPrepareHandler,
  codeFunctionExplainPrepareInputSchema,
} from '../../src/tools/code-function-explain-prepare.js'
import { createCodeFunctionExplainApplyHandler } from '../../src/tools/code-function-explain-apply.js'
import {
  SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE,
  SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE,
  loadSemanticFunctionExplanationIndex,
} from '../../src/artifacts/semantic-name-suggestion-artifacts.js'
import type { WorkerResult, ToolArgs } from '../../src/types.js'

describe('code.function.explain.prepare tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-explain-prepare')
    testDbPath = path.join(process.cwd(), 'test-explain-prepare.db')
    testCachePath = path.join(process.cwd(), 'test-cache-explain-prepare')

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
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'test',
    })
    await workspaceManager.createWorkspace(sampleId)
  }

  test('should prepare a prompt-ready explanation bundle and persist an artifact', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    await setupSample(sampleId, 'd')

    const reconstructHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [
            {
              function: 'FUN_14008d790',
              address: '0x14008d790',
              confidence: 0.88,
              semantic_summary: 'Resolves dynamic APIs and prepares remote process access.',
              behavior_tags: ['dynamic_resolution', 'process_injection'],
              name_resolution: {
                validated_name: 'resolve_dynamic_apis',
                resolution_source: 'rule',
              },
              confidence_profile: {
                score_kind: 'heuristic_reconstruction',
                score: 0.88,
              },
              runtime_confidence_profile: {
                score_kind: 'runtime_correlation',
                score: 0.81,
              },
              naming_confidence_profile: {
                score_kind: 'naming_resolution',
                score: 0.9,
              },
              xref_signals: [{ api: 'GetProcAddress' }],
              call_relationships: { callers: [], callees: [{ function: 'GetProcAddress' }] },
              runtime_context: { executed: true, corroborated_apis: ['GetProcAddress'] },
              semantic_evidence: {
                string_hints: ['LoadLibraryA'],
              },
              source_like_snippet: '/* reconstructed */',
              assembly_excerpt: 'call GetProcAddress',
              gaps: ['missing_types'],
            },
          ],
        },
        warnings: ['reconstruct warning'],
      })

    const handler = createCodeFunctionExplainPrepareHandler(
      workspaceManager,
      database,
      cacheManager,
      { reconstructHandler }
    )

    const result = await handler({
      sample_id: sampleId,
      analysis_goal: 'Explain DLL-facing behavior in plain language.',
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.prepared_count).toBe(1)
    expect(data.prompt_name).toBe('reverse.function_explanation_review')
    expect(data.prepared_bundle.output_contract.output_root).toBe('explanations')
    expect(data.prepared_bundle.functions[0].validated_name).toBe('resolve_dynamic_apis')
    expect(data.task_prompt).toContain('Return strict JSON only')
    expect(data.artifact.type).toBe(SEMANTIC_EXPLANATION_PREPARE_BUNDLE_ARTIFACT_TYPE)
    expect(result.warnings).toContain('reconstruct warning')

    const workspace = await workspaceManager.getWorkspace(sampleId)
    expect(fs.existsSync(path.join(workspace.root, data.artifact.path))).toBe(true)
  })

  test('should require evidence_session_tag when evidence_scope=session and forward scope to reconstruct', async () => {
    expect(() =>
      codeFunctionExplainPrepareInputSchema.parse({
        sample_id: 'sha256:' + 'f'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')

    const sampleId = 'sha256:' + 'e'.repeat(64)
    await setupSample(sampleId, 'e')

    const reconstructHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          functions: [],
        },
      })

    const handler = createCodeFunctionExplainPrepareHandler(
      workspaceManager,
      database,
      cacheManager,
      { reconstructHandler }
    )

    const result = await handler({
      sample_id: sampleId,
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-beta',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    expect(reconstructHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-beta',
      })
    )
  })

  test('apply should persist explanation artifacts and normalize rewrite guidance', async () => {
    const sampleId = 'sha256:' + 'f'.repeat(64)
    await setupSample(sampleId, 'f')

    const handler = createCodeFunctionExplainApplyHandler(workspaceManager, database)
    const result = await handler({
      sample_id: sampleId,
      client_name: 'claude-desktop',
      model_name: 'generic-tool-calling-llm',
      explanations: [
        {
          address_or_function: '0x14008d790',
          summary: 'Resolves dynamic imports and prepares a remote process operation plan.',
          behavior: 'resolve_dynamic_imports',
          confidence: 0.84,
          evidence_used: ['xref:GetProcAddress', 'runtime:resolve_dynamic_apis'],
          rewrite_guidance: [
            'Split capability table setup from remote process staging.',
            'Promote resolved imports into an explicit dispatch table.',
          ],
        },
      ],
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.accepted_count).toBe(1)
    expect(data.rejected_count).toBe(0)
    expect(data.accepted_explanations[0].behavior).toBe('resolve_dynamic_imports')
    expect(data.accepted_explanations[0].rewrite_guidance_count).toBe(2)
    expect(data.artifact.type).toBe(SEMANTIC_FUNCTION_EXPLANATIONS_ARTIFACT_TYPE)

    const index = await loadSemanticFunctionExplanationIndex(workspaceManager, database, sampleId)
    const loaded = index.byAddress.get('14008d790')
    expect(loaded?.behavior).toBe('resolve_dynamic_imports')
    expect(loaded?.rewrite_guidance).toContain('Promote resolved imports into an explicit dispatch table.')
    expect(loaded?.client_name).toBe('claude-desktop')
  })
})
