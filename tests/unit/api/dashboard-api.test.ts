/**
 * Unit tests for dashboard runtime event integration.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, jest, test } from '@jest/globals'
import type { IncomingMessage, ServerResponse } from 'http'
import { eventBus } from '../../../src/api/sse-events.js'
import type { RuntimeSseEvent } from '../../../src/runtime-client/index.js'

let handleDashboardApi: typeof import('../../../src/api/routes/dashboard-api.js').handleDashboardApi
let initDashboard: typeof import('../../../src/api/routes/dashboard-api.js').initDashboard

beforeAll(async () => {
  ;({ handleDashboardApi, initDashboard } =
    await import('../../../src/api/routes/dashboard-api.js'))
})

type SubscribeOptions = {
  taskId?: string
  onOpen?: () => void
  onEvent: (event: RuntimeSseEvent) => void
  onError?: (error: Error) => void
}

function createResponseCapture() {
  const chunks: string[] = []
  let resolveEnd: () => void = () => {}
  const ended = new Promise<void>((resolve) => {
    resolveEnd = resolve
  })
  const response = {
    writableEnded: false,
    statusCode: 0,
    headers: {} as Record<string, string>,
    writeHead: jest.fn((status: number, headers?: Record<string, string>) => {
      response.statusCode = status
      response.headers = headers ?? {}
      return response
    }),
    end: jest.fn((body?: string) => {
      if (body) chunks.push(body)
      response.writableEnded = true
      resolveEnd()
      return response
    }),
  } as unknown as ServerResponse

  return {
    response,
    getJson: () => JSON.parse(chunks.join('')) as Record<string, any>,
    waitForEnd: () => ended,
  }
}

describe('dashboard-api runtime integration', () => {
  let subscribeOptions: SubscribeOptions | null
  let closeSubscription: jest.Mock

  beforeEach(() => {
    subscribeOptions = null
    closeSubscription = jest.fn()
    initDashboard({
      server: null,
      database: {} as any,
      getPluginStatuses: () =>
        [
          { id: 'loaded-plugin', name: 'Loaded Plugin', status: 'loaded', tools: ['a.tool'] },
          { id: 'skipped-plugin', name: 'Skipped Plugin', status: 'skipped-check', tools: [] },
        ] as any,
      runtimeClient: {
        async health() {
          return {
            ok: true,
            role: 'runtime',
            isolation: 'sandbox',
            mode: 'remote-sandbox',
            pid: 4321,
          }
        },
        getEndpoint() {
          return 'http://127.0.0.1:18081'
        },
        subscribeEvents(options: SubscribeOptions) {
          subscribeOptions = options
          return { close: closeSubscription }
        },
      },
      jobQueue: {
        getQueueLength() {
          return 2
        },
        listStatuses() {
          return [
            {
              id: 'job-queued',
              status: 'queued',
              tool: 'workflow.analyze.start',
              sampleId: 'sample-1',
              attempts: 0,
              timeout: 1000,
              createdAt: '2026-04-16T10:00:00.000Z',
              updatedAt: '2026-04-16T10:00:00.000Z',
              args: {},
            },
            {
              id: 'job-running',
              status: 'running',
              tool: 'workflow.analyze.status',
              sampleId: 'sample-1',
              attempts: 1,
              timeout: 1000,
              createdAt: '2026-04-16T10:01:00.000Z',
              updatedAt: '2026-04-16T10:01:30.000Z',
              args: {},
            },
            {
              id: 'job-done',
              status: 'completed',
              tool: 'workflow.summarize',
              sampleId: 'sample-1',
              attempts: 1,
              timeout: 1000,
              createdAt: '2026-04-16T10:02:00.000Z',
              updatedAt: '2026-04-16T10:02:30.000Z',
              args: {},
            },
          ]
        },
      } as any,
    })
  })

  afterEach(() => {
    eventBus.removeAllListeners('event')
    eventBus.removeAllListeners('event:runtime-events')
  })

  test('subscribes to runtime events during dashboard init and closes previous subscription on re-init', () => {
    expect(subscribeOptions).not.toBeNull()

    initDashboard({
      server: null,
      database: {} as any,
      runtimeClient: {
        async health() {
          return null
        },
        getEndpoint() {
          return 'http://127.0.0.1:18082'
        },
        subscribeEvents(options: SubscribeOptions) {
          subscribeOptions = options
          return { close: jest.fn() }
        },
      },
    })

    expect(closeSubscription).toHaveBeenCalledTimes(1)
    expect(subscribeOptions).not.toBeNull()
  })

  test('exposes runtime event snapshot and queue stats in /workers response', () => {
    expect(subscribeOptions).not.toBeNull()

    const observedEvents: Array<{ type: string; payload: unknown }> = []
    eventBus.on('event:runtime-events', (evt) => {
      observedEvents.push({ type: evt.type, payload: evt.payload })
    })

    subscribeOptions?.onOpen?.()
    subscribeOptions?.onEvent({
      event: 'progress',
      id: 'task-123',
      data: { taskId: 'task-123', progressPercent: 42, status: 'running' },
    })

    const { response, getJson } = createResponseCapture()
    const handled = handleDashboardApi(
      { headers: {} } as IncomingMessage,
      response,
      '/api/v1/dashboard/workers',
      new URLSearchParams()
    )

    expect(handled).toBe(true)
    expect(response.writeHead).toHaveBeenCalledWith(
      200,
      expect.objectContaining({ 'Content-Type': 'application/json' })
    )

    const body = getJson()
    expect(body.runtime.connected).toBe(true)
    expect(body.runtime.endpoint).toBe('http://127.0.0.1:18081')
    expect(body.runtime.last_event.event).toBe('progress')
    expect(body.runtime.last_event.normalized_status).toBe('active')
    expect(body.runtime.recent_events).toHaveLength(1)
    expect(body.runtime.lifecycle.persistenceScope).toBe('runtime-outbox')
    expect(body.jobs.total).toBe(3)
    expect(body.jobs.queue_depth).toBe(2)
    expect(body.jobs.queued).toBe(1)
    expect(body.jobs.running).toBe(1)
    expect(body.jobs.terminal).toBe(1)
    expect(body.jobs.by_status.pending).toBe(1)
    expect(body.jobs.by_status.active).toBe(1)
    expect(body.jobs.by_status.completed).toBe(1)
    expect(body.plugins.loaded).toBe(1)
    expect(body.plugins.completed).toBe(1)
    expect(body.plugins['skipped-check']).toBe(1)
    expect(body.plugins.failed).toBe(1)
    expect(observedEvents).toEqual([
      {
        type: 'status',
        payload: expect.objectContaining({
          event: 'progress',
          id: 'task-123',
          data: expect.objectContaining({ progressPercent: 42 }),
        }),
      },
    ])
  })

  test('captures runtime subscription errors in /workers response', () => {
    expect(subscribeOptions).not.toBeNull()

    subscribeOptions?.onError?.(new Error('stream disconnected'))

    const { response, getJson } = createResponseCapture()
    handleDashboardApi(
      { headers: {} } as IncomingMessage,
      response,
      '/api/v1/dashboard/workers',
      new URLSearchParams()
    )

    const body = getJson()
    expect(body.runtime.connected).toBe(false)
    expect(body.runtime.last_error).toBe('stream disconnected')
  })
})

describe('dashboard-api local dashboard data', () => {
  afterEach(() => {
    eventBus.removeAllListeners('event')
    eventBus.removeAllListeners('event:runtime-events')
  })

  test('filters samples by search term in SQL-backed dashboard listing', () => {
    const sample = {
      id: 'sample-packed',
      sha256: 'abc123packed',
      size: 4096,
      file_type: 'pe32',
      source: 'packed.exe',
      created_at: '2026-04-16T10:00:00.000Z',
    }
    const querySql = jest.fn((sql: string, params?: any[]) => {
      if (sql.includes('COUNT(*)') && sql.includes('FROM samples')) {
        return [{ cnt: 1 }]
      }
      if (sql.includes('FROM samples')) {
        return [sample]
      }
      return []
    })

    initDashboard({
      server: null,
      database: { querySql } as any,
    })

    const { response, getJson } = createResponseCapture()
    const handled = handleDashboardApi(
      { headers: {} } as IncomingMessage,
      response,
      '/api/v1/dashboard/samples',
      new URLSearchParams('limit=10&offset=0&search=PACKED')
    )

    expect(handled).toBe(true)
    const body = getJson()
    expect(body.total).toBe(1)
    expect(body.samples).toEqual([sample])
    expect(querySql.mock.calls[0][0]).toContain('LOWER(COALESCE(sha256')
    expect(querySql.mock.calls[0][0]).toContain('LOWER(COALESCE(source')
    expect(querySql.mock.calls[0][1]).toEqual([
      '%packed%',
      '%packed%',
      '%packed%',
      '%packed%',
      '%packed%',
    ])
    expect(querySql.mock.calls[1][1]).toEqual([
      '%packed%',
      '%packed%',
      '%packed%',
      '%packed%',
      '%packed%',
      10,
      0,
    ])
  })

  test('filters artifacts by search term alongside sample and type filters', () => {
    const artifact = {
      id: 'artifact-1',
      sample_id: 'sample-1',
      type: 'semantic_name_suggestions',
      path: 'reports/semantic_naming/reviewA/semantic_name_suggestions.json',
      sha256: 'artifact-sha',
      mime: 'application/json',
      created_at: '2026-04-16T10:05:00.000Z',
    }
    const querySql = jest.fn((sql: string, params?: any[]) => {
      if (sql.includes('COUNT(*)') && sql.includes('FROM artifacts')) {
        return [{ cnt: 1 }]
      }
      if (sql.startsWith('SELECT id')) {
        return [artifact]
      }
      if (sql.startsWith('SELECT type')) {
        return [{ type: 'semantic_name_suggestions', cnt: 1 }]
      }
      return []
    })

    initDashboard({
      server: null,
      database: { querySql } as any,
    })

    const { getJson, response } = createResponseCapture()
    handleDashboardApi(
      { headers: {} } as IncomingMessage,
      response,
      '/api/v1/dashboard/artifacts',
      new URLSearchParams(
        'limit=10&offset=0&sample_id=sample-1&type=semantic_name_suggestions&search=reviewA'
      )
    )

    const body = getJson()
    expect(body.total).toBe(1)
    expect(body.artifacts).toEqual([artifact])
    expect(querySql.mock.calls[0][0]).toContain('sample_id = ?')
    expect(querySql.mock.calls[0][0]).toContain('type = ?')
    expect(querySql.mock.calls[0][0]).toContain('LOWER(COALESCE(path')
    expect(querySql.mock.calls[0][1]).toEqual([
      'sample-1',
      'semantic_name_suggestions',
      '%reviewa%',
      '%reviewa%',
      '%reviewa%',
      '%reviewa%',
      '%reviewa%',
      '%reviewa%',
    ])
  })

  test('summarizes semantic review artifacts for dashboard visibility', async () => {
    const artifacts = [
      {
        id: 'semantic-artifact-1',
        sample_id: 'sample-1',
        type: 'semantic_name_suggestions',
        path: 'reports/semantic_naming/reviewA/semantic_name_suggestions_1.json',
        sha256: 'sha-1',
        mime: 'application/json',
        created_at: '2026-04-16T10:10:00.000Z',
      },
      {
        id: 'semantic-artifact-2',
        sample_id: 'sample-1',
        type: 'semantic_function_explanations',
        path: 'reports/semantic_naming/reviewA/semantic_function_explanations_1.json',
        sha256: 'sha-2',
        mime: 'application/json',
        created_at: '2026-04-16T10:11:00.000Z',
      },
    ]
    const semanticStages = [
      {
        run_id: 'run-1',
        stage: 'semantic_name_review',
        status: 'partial',
        execution_state: 'partial',
        tool: 'workflow.analyze.stage',
        job_id: 'job-semantic-1',
        result_json: JSON.stringify({
          semantic_review: {
            prepare_artifact_id: 'semantic-artifact-1',
            apply_artifact_id: 'semantic-artifact-2',
          },
        }),
        artifact_refs_json: JSON.stringify([
          {
            id: 'semantic-artifact-1',
            type: 'semantic_name_suggestions',
            path: 'a.json',
            sha256: 'a',
          },
          {
            id: 'semantic-artifact-2',
            type: 'semantic_function_explanations',
            path: 'b.json',
            sha256: 'b',
          },
        ]),
        coverage_json: null,
        metadata_json: JSON.stringify({
          semantic_review_state: 'waiting_for_llm',
          review_status: 'prompt_contract_only',
        }),
        created_at: '2026-04-16T10:09:00.000Z',
        updated_at: '2026-04-16T10:12:00.000Z',
        started_at: '2026-04-16T10:09:00.000Z',
        finished_at: '2026-04-16T10:12:00.000Z',
      },
    ]
    const querySql = jest.fn((sql: string) => {
      if (
        sql.includes('COUNT(*)') &&
        sql.includes('FROM artifacts') &&
        !sql.startsWith('SELECT type')
      ) {
        return [{ cnt: 2 }]
      }
      if (sql.startsWith('SELECT id')) {
        return artifacts
      }
      if (sql.startsWith('SELECT type')) {
        return [
          { type: 'semantic_name_suggestions', cnt: 1 },
          { type: 'semantic_function_explanations', cnt: 1 },
        ]
      }
      if (sql.startsWith('SELECT * FROM analysis_run_stages')) {
        return semanticStages
      }
      return []
    })

    initDashboard({
      server: null,
      database: { querySql } as any,
    })

    const { response, getJson, waitForEnd } = createResponseCapture()
    const handled = handleDashboardApi(
      { headers: {} } as IncomingMessage,
      response,
      '/api/v1/dashboard/semantic',
      new URLSearchParams('limit=2&offset=0')
    )
    await waitForEnd()

    expect(handled).toBe(true)
    const body = getJson()
    expect(body.total).toBe(2)
    expect(body.counts.by_type.semantic_name_suggestions).toBe(1)
    expect(body.counts.by_type.semantic_function_explanations).toBe(1)
    expect(body.counts.by_session.reviewA).toBe(2)
    expect(body.artifacts).toHaveLength(2)
    expect(body.artifacts[0].semantic.payload_kind).toBe('name_suggestions')
    expect(body.artifacts[0].semantic.session_tag).toBe('reviewA')
    expect(body.artifacts[0].semantic.read_error).toBe('workspace_unavailable')
    expect(body.artifacts[0].run_link).toMatchObject({
      run_id: 'run-1',
      stage: 'semantic_name_review',
      review_state: 'waiting_for_llm',
      review_status: 'prompt_contract_only',
    })
  })

  test('exposes staged analysis runs with semantic reconstruction usage', () => {
    const run = {
      id: 'run-1',
      sample_id: 'sample-1',
      sample_sha256: 'sample-sha',
      goal: 'reverse',
      depth: 'balanced',
      backend_policy: 'auto',
      pipeline_version: 'nonblocking-unified-analysis-pipeline-v1',
      sample_size_tier: 'small',
      analysis_budget_profile: 'balanced',
      status: 'completed',
      latest_stage: 'semantic_name_review',
      stage_plan_json: JSON.stringify([
        'fast_profile',
        'function_map',
        'reconstruct',
        'semantic_name_review',
        'semantic_explain_review',
        'semantic_module_review',
        'summarize',
      ]),
      artifact_refs_json: JSON.stringify([]),
      metadata_json: JSON.stringify({ allow_live_execution: false }),
      created_at: '2026-04-16T10:00:00.000Z',
      updated_at: '2026-04-16T10:30:00.000Z',
      finished_at: '2026-04-16T10:30:00.000Z',
      reused_from_run_id: null,
      last_accessed_at: '2026-04-16T10:30:00.000Z',
    }
    const stages = [
      {
        run_id: 'run-1',
        stage: 'reconstruct',
        status: 'completed',
        execution_state: 'completed',
        tool: 'workflow.analyze.stage',
        job_id: 'job-1',
        result_json: JSON.stringify({
          summary: 'Reconstruct completed',
          stage_outputs: {
            reconstruct: {
              semantic_scope: 'session',
              semantic_session_tag: 'reviewA',
              provenance: {
                semantic_names: {
                  artifact_ids: ['sem-name-1'],
                  session_tags: ['reviewA'],
                },
                semantic_explanations: {
                  artifact_ids: ['sem-explain-1'],
                  session_tags: ['reviewA'],
                },
              },
            },
          },
        }),
        artifact_refs_json: JSON.stringify([
          { id: 'recon-1', type: 'reconstruct', path: 'r.json', sha256: 'r' },
        ]),
        coverage_json: null,
        metadata_json: JSON.stringify({ force_refresh: false }),
        created_at: '2026-04-16T10:20:00.000Z',
        updated_at: '2026-04-16T10:30:00.000Z',
        started_at: '2026-04-16T10:20:00.000Z',
        finished_at: '2026-04-16T10:30:00.000Z',
      },
      {
        run_id: 'run-1',
        stage: 'semantic_name_review',
        status: 'partial',
        execution_state: 'partial',
        tool: 'workflow.analyze.stage',
        job_id: 'job-semantic-1',
        result_json: JSON.stringify({
          summary: 'Semantic name review is waiting for LLM sampling',
          status: 'waiting_for_llm',
          recommended_next_tools: ['prompts/get', 'code.function.rename.apply'],
          next_actions: ['Review the prepared LLM prompt bundle.'],
          coverage_level: 'reconstruction',
          completion_state: 'partial',
          coverage_gaps: [
            {
              domain: 'semantic_name_review',
              status: 'queued',
              reason: 'LLM sampling has not returned suggestions yet.',
            },
          ],
          upgrade_paths: [
            {
              tool: 'prompts/get',
              purpose: 'Review semantic name prompt.',
              closes_gaps: ['semantic_name_review'],
              expected_coverage_gain: 'Allows analyst or LLM completion of semantic naming.',
              cost_tier: 'low',
              availability: 'ready',
              prerequisites: [],
              blockers: [],
            },
          ],
          semantic_review: {
            semantic_review_state: 'waiting_for_llm',
            prepare_artifact_id: 'sem-prepare-1',
          },
        }),
        artifact_refs_json: JSON.stringify([
          {
            id: 'sem-prepare-1',
            type: 'semantic_name_prepare_bundle',
            path: 'prepare.json',
            sha256: 'prep',
          },
        ]),
        coverage_json: null,
        metadata_json: JSON.stringify({
          semantic_review_stage: 'semantic_name_review',
          semantic_review_state: 'waiting_for_llm',
          review_status: 'prompt_contract_only',
          session_tag: 'analysis_run-1_semantic_name_review',
          prepare_artifact_id: 'sem-prepare-1',
          apply_artifact_id: null,
          accepted_count: 0,
          rejected_count: 0,
        }),
        created_at: '2026-04-16T10:31:00.000Z',
        updated_at: '2026-04-16T10:32:00.000Z',
        started_at: '2026-04-16T10:31:00.000Z',
        finished_at: '2026-04-16T10:32:00.000Z',
      },
    ]
    const semanticArtifacts = [
      {
        type: 'semantic_name_suggestions',
        path: 'reports/semantic_naming/reviewA/semantic_name_suggestions_1.json',
        created_at: '2026-04-16T10:22:00.000Z',
        cnt: 1,
      },
      {
        type: 'semantic_function_explanations',
        path: 'reports/semantic_naming/reviewA/semantic_function_explanations_1.json',
        created_at: '2026-04-16T10:23:00.000Z',
        cnt: 1,
      },
    ]
    const querySql = jest.fn((sql: string, params?: any[]) => {
      if (sql.includes('COUNT(*) as cnt FROM analysis_runs')) {
        return [{ cnt: 1 }]
      }
      if (sql.startsWith('SELECT * FROM analysis_runs')) {
        return [run]
      }
      if (sql.startsWith('SELECT status')) {
        return [{ status: 'completed', cnt: 1 }]
      }
      if (sql.startsWith('SELECT goal')) {
        return [{ goal: 'reverse', cnt: 1 }]
      }
      if (sql.startsWith('SELECT * FROM analysis_run_stages')) {
        return stages
      }
      if (sql.startsWith('SELECT type, path, created_at')) {
        return semanticArtifacts
      }
      return []
    })

    initDashboard({
      server: null,
      database: { querySql } as any,
    })

    const { response, getJson } = createResponseCapture()
    handleDashboardApi(
      { headers: {} } as IncomingMessage,
      response,
      '/api/v1/dashboard/runs',
      new URLSearchParams('limit=10&offset=0&search=sample-sha')
    )

    const body = getJson()
    expect(body.total).toBe(1)
    expect(body.runs).toHaveLength(1)
    expect(body.runs[0].normalized_status).toBe('completed')
    expect(body.runs[0].stages[0].normalized_status).toBe('completed')
    expect(body.runs[0].stage_summary).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          stage: 'reconstruct',
          status: 'completed',
          artifact_count: 1,
        }),
        expect.objectContaining({
          stage: 'semantic_name_review',
          status: 'partial',
          artifact_count: 1,
          recommended_next_tools: expect.arrayContaining([
            'prompts/get',
            'code.function.rename.apply',
          ]),
        }),
      ])
    )
    expect(body.runs[0].provenance_digest).toEqual(
      expect.objectContaining({
        stage_count: 2,
        completed_stage_count: 1,
        artifact_ref_count: expect.any(Number),
        selected_artifact_ids: expect.arrayContaining(['recon-1', 'sem-prepare-1']),
      })
    )
    expect(body.runs[0].semantic.artifact_count).toBe(2)
    expect(body.runs[0].semantic.name_suggestion_artifacts).toBe(1)
    expect(body.runs[0].semantic.explanation_artifacts).toBe(1)
    expect(body.runs[0].semantic.reconstruct_consumed).toBe(true)
    expect(body.runs[0].semantic.consumed_artifact_ids).toEqual(['sem-name-1', 'sem-explain-1'])
    expect(body.runs[0].semantic.consumed_session_tags).toEqual(['reviewA'])
    expect(body.runs[0].semantic.waiting_for_llm_stages).toBe(1)
    expect(body.runs[0].semantic.prepare_artifact_ids).toEqual(['sem-prepare-1'])
    expect(body.runs[0].coverage_level).toBe('reconstruction')
    expect(body.runs[0].completion_state).toBe('partial')
    expect(body.runs[0].coverage_gaps[0]).toMatchObject({
      domain: 'semantic_name_review',
      status: 'queued',
    })
    expect(body.runs[0].recommended_next_tools).toEqual(
      expect.arrayContaining(['prompts/get', 'code.function.rename.apply'])
    )
    expect(body.runs[0].semantic.semantic_stages).toEqual([
      expect.objectContaining({
        stage: 'semantic_name_review',
        status: 'partial',
        review_state: 'waiting_for_llm',
        review_status: 'prompt_contract_only',
        prepare_artifact_id: 'sem-prepare-1',
      }),
    ])
  })
})
