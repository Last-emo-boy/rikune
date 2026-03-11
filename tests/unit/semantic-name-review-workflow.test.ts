import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import {
  createSemanticNameReviewWorkflowHandler,
  semanticNameReviewWorkflowInputSchema,
} from '../../src/workflows/semantic-name-review.js'

describe('workflow.semantic_name_review tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-semantic-name-review-workflow')
    testDbPath = path.join(process.cwd(), 'test-semantic-name-review-workflow.db')
    testCachePath = path.join(process.cwd(), 'test-cache-semantic-name-review-workflow')

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
    const parsed = semanticNameReviewWorkflowInputSchema.parse({
      sample_id: 'sha256:' + 'a'.repeat(64),
    })

    expect(parsed.topk).toBe(6)
    expect(parsed.max_functions).toBe(6)
    expect(parsed.evidence_scope).toBe('all')
    expect(parsed.semantic_scope).toBe('all')
    expect(parsed.rerun_export).toBe(true)
    expect(parsed.export_path).toBe('auto')
    expect(parsed.export_topk).toBe(12)
    expect(parsed.validate_build).toBe(false)
    expect(parsed.run_harness).toBe(false)
  })

  test('should require evidence_session_tag when evidence_scope=session', () => {
    expect(() =>
      semanticNameReviewWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        evidence_scope: 'session',
      })
    ).toThrow('evidence_session_tag')
  })

  test('should require semantic_session_tag when semantic_scope=session', () => {
    expect(() =>
      semanticNameReviewWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        semantic_scope: 'session',
      })
    ).toThrow('semantic_session_tag')
  })

  test('should require compare_evidence_session_tag when compare_evidence_scope=session', () => {
    expect(() =>
      semanticNameReviewWorkflowInputSchema.parse({
        sample_id: 'sha256:' + 'a'.repeat(64),
        compare_evidence_scope: 'session',
      })
    ).toThrow('compare_evidence_session_tag')
  })

  test('should orchestrate rename review and reconstruct export refresh', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)

    const renameReviewHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          review_status: 'sampled_and_applied',
          prompt_name: 'reverse.semantic_name_review',
          client: {
            name: 'generic-mcp-client',
            version: '1.0.0',
            sampling_available: true,
          },
          prepare: {
            prepared_count: 2,
            unresolved_count: 1,
            include_resolved: false,
            artifact_id: 'artifact-prepare',
          },
          sampling: {
            attempted: true,
            model: 'gpt-5',
            stop_reason: 'endTurn',
            parsed_suggestion_count: 1,
          },
          apply: {
            attempted: true,
            accepted_count: 1,
            rejected_count: 0,
            artifact_id: 'artifact-apply',
          },
          confidence_policy: {
            calibrated: false,
            rule_priority_over_llm: true,
            llm_acceptance_threshold: 0.62,
            meaning: 'Rule-based names win unless an LLM suggestion exceeds the acceptance threshold.',
          },
          reconstruct: {
            attempted: true,
            reconstructed_count: 2,
            llm_or_hybrid_count: 1,
            functions: [
              {
                function: 'FUN_140081090',
                address: '0x140081090',
                validated_name: 'prepare_remote_process_access',
                resolution_source: 'llm',
              },
            ],
          },
          next_steps: ['inspect reconstructed functions for llm or hybrid validated names'],
        },
      })

    const reconstructWorkflowHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          selected_path: 'native',
          provenance: {
            runtime: {
              scope: 'session',
              session_selector: 'runtime-alpha',
              artifact_count: 1,
              artifact_ids: ['runtime-1'],
              session_tags: ['runtime-alpha'],
              earliest_artifact_at: '2026-03-11T00:00:00.000Z',
              latest_artifact_at: '2026-03-11T00:00:00.000Z',
              scope_note: 'runtime current',
            },
            semantic_names: {
              scope: 'session',
              session_selector: 'semantic-alpha',
              artifact_count: 1,
              artifact_ids: ['semantic-name-1'],
              session_tags: ['semantic-alpha'],
              earliest_artifact_at: '2026-03-11T00:00:00.000Z',
              latest_artifact_at: '2026-03-11T00:00:00.000Z',
              scope_note: 'semantic names current',
            },
            semantic_explanations: {
              scope: 'session',
              session_selector: 'semantic-alpha',
              artifact_count: 1,
              artifact_ids: ['semantic-expl-1'],
              session_tags: ['semantic-alpha'],
              earliest_artifact_at: '2026-03-11T00:00:00.000Z',
              latest_artifact_at: '2026-03-11T00:00:00.000Z',
              scope_note: 'semantic explanations current',
            },
          },
          selection_diffs: {
            runtime: {
              label: 'runtime',
              current: {
                scope: 'session',
                session_selector: 'runtime-alpha',
                artifact_count: 1,
                artifact_ids: ['runtime-1'],
                session_tags: ['runtime-alpha'],
                earliest_artifact_at: '2026-03-11T00:00:00.000Z',
                latest_artifact_at: '2026-03-11T00:00:00.000Z',
                scope_note: 'runtime current',
              },
              baseline: {
                scope: 'all',
                session_selector: null,
                artifact_count: 3,
                artifact_ids: ['runtime-1', 'runtime-2', 'runtime-3'],
                session_tags: ['runtime-alpha', 'runtime-beta'],
                earliest_artifact_at: '2026-03-10T00:00:00.000Z',
                latest_artifact_at: '2026-03-11T00:00:00.000Z',
                scope_note: 'runtime baseline',
              },
              added_artifact_ids: [],
              removed_artifact_ids: ['runtime-2', 'runtime-3'],
              added_session_tags: [],
              removed_session_tags: ['runtime-beta'],
              artifact_count_delta: -2,
              summary: 'runtime diff',
            },
          },
          export: {
            tool: 'code.reconstruct.export',
            export_root: 'reports/reconstruct/reviewed',
            manifest_path: 'reports/reconstruct/reviewed/manifest.json',
            build_validation_status: 'passed',
            harness_validation_status: 'passed',
          },
          notes: ['Native build validation: passed'],
        },
      })

    const handler = createSemanticNameReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        renameReviewHandler,
        reconstructWorkflowHandler,
      }
    )

    const result = await handler({
      sample_id: sampleId,
      analysis_goal: 'Review the highest-value DLL-facing functions.',
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
        compare_evidence_scope: 'all',
        semantic_scope: 'session',
        semantic_session_tag: 'semantic-alpha',
        compare_semantic_scope: 'all',
        export_name: 'reviewed',
        export_path: 'native',
        validate_build: true,
      run_harness: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.review.review_status).toBe('sampled_and_applied')
    expect(data.review.apply.accepted_count).toBe(1)
    expect(data.review.confidence_policy.llm_acceptance_threshold).toBe(0.62)
    expect(data.export.attempted).toBe(true)
    expect(data.export.status).toBe('completed')
    expect(data.export.selected_path).toBe('native')
    expect(data.export.export_tool).toBe('code.reconstruct.export')
    expect(data.export.manifest_path).toContain('manifest.json')
    expect(data.export.build_validation_status).toBe('passed')
    expect(data.export.provenance.runtime.session_selector).toBe('runtime-alpha')
    expect(data.export.selection_diffs.runtime.summary).toBe('runtime diff')
    expect(data.next_steps.join(' ')).toContain('Native build validation: passed')

    expect(renameReviewHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
        semantic_scope: 'session',
        semantic_session_tag: 'semantic-alpha',
      })
    )
    expect(reconstructWorkflowHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: sampleId,
        path: 'native',
        export_name: 'reviewed',
        validate_build: true,
        run_harness: true,
        evidence_scope: 'session',
        evidence_session_tag: 'runtime-alpha',
        compare_evidence_scope: 'all',
        semantic_scope: 'session',
        semantic_session_tag: 'semantic-alpha',
        compare_semantic_scope: 'all',
      })
    )
  })

  test('should default export refresh to the current naming session when only session_tag is provided', async () => {
    const renameReviewHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          review_status: 'sampled_and_applied',
          prompt_name: 'reverse.semantic_name_review',
          client: { name: 'client', version: '1.0', sampling_available: true },
          prepare: {
            prepared_count: 1,
            unresolved_count: 1,
            include_resolved: false,
            artifact_id: 'artifact-prepare',
          },
          sampling: {
            attempted: true,
            model: 'gpt-5',
            stop_reason: 'endTurn',
            parsed_suggestion_count: 1,
          },
          apply: {
            attempted: true,
            accepted_count: 1,
            rejected_count: 0,
            artifact_id: 'artifact-apply',
          },
          confidence_policy: {
            calibrated: false,
            rule_priority_over_llm: true,
            llm_acceptance_threshold: 0.62,
            meaning: 'heuristic',
          },
          reconstruct: {
            attempted: true,
            reconstructed_count: 1,
            llm_or_hybrid_count: 1,
            functions: [],
          },
          next_steps: [],
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
            export_root: 'reports/reconstruct/reviewed',
            manifest_path: 'reports/reconstruct/reviewed/manifest.json',
            build_validation_status: 'skipped',
            harness_validation_status: 'skipped',
          },
          notes: [],
        },
      })

    const handler = createSemanticNameReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        renameReviewHandler,
        reconstructWorkflowHandler,
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'd'.repeat(64),
      session_tag: 'naming-session-live',
    })

    expect(result.ok).toBe(true)
    expect(reconstructWorkflowHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        semantic_scope: 'session',
        semantic_session_tag: 'naming-session-live',
      })
    )
  })

  test('should skip export refresh when semantic review did not apply any suggestions', async () => {
    const renameReviewHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
        data: {
          review_status: 'prompt_contract_only',
          prompt_name: 'reverse.semantic_name_review',
          client: {
            name: 'generic-mcp-client',
            version: '1.0.0',
            sampling_available: false,
          },
          prepare: {
            prepared_count: 1,
            unresolved_count: 1,
            include_resolved: false,
            artifact_id: 'artifact-prepare',
          },
          sampling: {
            attempted: false,
            model: null,
            stop_reason: null,
            parsed_suggestion_count: 0,
          },
          apply: {
            attempted: false,
            accepted_count: 0,
            rejected_count: 0,
            artifact_id: null,
          },
          confidence_policy: {
            calibrated: false,
            rule_priority_over_llm: true,
            llm_acceptance_threshold: 0.62,
            meaning: 'Rule-based names win unless an LLM suggestion exceeds the acceptance threshold.',
          },
          reconstruct: {
            attempted: false,
            reconstructed_count: 0,
            llm_or_hybrid_count: 0,
            functions: [],
          },
          next_steps: ['pass the JSON result to code.function.rename.apply'],
        },
      })

    const reconstructWorkflowHandler = jest
      .fn<(args: ToolArgs) => Promise<WorkerResult>>()
      .mockResolvedValue({
        ok: true,
      })

    const handler = createSemanticNameReviewWorkflowHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        renameReviewHandler,
        reconstructWorkflowHandler,
      }
    )

    const result = await handler({
      sample_id: 'sha256:' + 'c'.repeat(64),
      rerun_export: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.export.attempted).toBe(false)
    expect(data.export.status).toBe('skipped')
    expect(data.export.notes[0]).toContain('skipped')
    expect(reconstructWorkflowHandler).not.toHaveBeenCalled()
  })
})
