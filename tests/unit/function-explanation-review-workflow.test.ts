import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createFunctionExplanationReviewWorkflowHandler,
  functionExplanationReviewWorkflowInputSchema,
} from '../../src/workflows/function-explanation-review.js'

describe('workflow.function_explanation_review tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-function-explanation-review-workflow')
    testDbPath = path.join(process.cwd(), 'test-function-explanation-review-workflow.db')
    testCachePath = path.join(process.cwd(), 'test-cache-function-explanation-review-workflow')

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

  test('should apply workflow defaults', () => {
    const parsed = functionExplanationReviewWorkflowInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.topk).toBe(6)
    expect(parsed.max_functions).toBe(6)
    expect(parsed.include_resolved).toBe(true)
    expect(parsed.evidence_scope).toBe('all')
    expect(parsed.rerun_export).toBe(true)
    expect(parsed.export_path).toBe('auto')
  })

  test('should require evidence_session_tag when evidence_scope=session', () => {
    expect(() =>
      functionExplanationReviewWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')
  })

  test('should orchestrate explanation review and reconstruct export refresh', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)

    const explainReviewHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          review_status: 'sampled_and_applied',
          prompt_name: 'reverse.function_explanation_review',
          client: {
            name: 'generic-mcp-client',
            version: '1.0.0',
            sampling_available: true,
          },
          prepare: {
            prepared_count: 2,
            artifact_id: 'artifact-prepare',
          },
          sampling: {
            attempted: true,
            model: 'gpt-5',
            stop_reason: 'endTurn',
            parsed_explanation_count: 1,
          },
          apply: {
            attempted: true,
            accepted_count: 1,
            rejected_count: 0,
            artifact_id: 'artifact-apply',
          },
          confidence_policy: {
            calibrated: false,
            explanation_scores_are_heuristic: true,
            meaning: 'Explanation confidence ranks evidence support only.',
          },
          next_steps: ['rerun code.reconstruct.export to propagate explanation summaries into rewrite output'],
        },
      })

    const reconstructWorkflowHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          selected_path: 'native',
          export: {
            tool: 'code.reconstruct.export',
            export_root: 'reports/reconstruct/explained',
            manifest_path: 'reports/reconstruct/explained/manifest.json',
            build_validation_status: 'passed',
            harness_validation_status: 'passed',
          },
          notes: ['Native build validation: passed'],
        },
      })

    const handler = createFunctionExplanationReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        explainReviewHandler,
        reconstructWorkflowHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      analysis_goal: 'Explain the highest-value functions in plain language.',
      evidence_scope: 'session',
      evidence_session_tag: 'runtime-alpha',
      export_name: 'explained',
      export_path: 'native',
      validate_build: true,
      run_harness: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review.review_status).toBe('sampled_and_applied')
    expect(data.review.apply.accepted_count).toBe(1)
    expect(data.review.confidence_policy.explanation_scores_are_heuristic).toBe(true)
    expect(data.export.attempted).toBe(true)
    expect(data.export.status).toBe('completed')
    expect(data.export.selected_path).toBe('native')
    expect(data.export.export_tool).toBe('code.reconstruct.export')
    expect(data.export.manifest_path).toContain('manifest.json')
    expect(data.next_steps.join(' ')).toContain('Native build validation: passed')

    expect(explainReviewHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
      })
    )
    expect(reconstructWorkflowHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        path: 'native',
        export_name: 'explained',
        validate_build: true,
        run_harness: true,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
      })
    )
  })
})
