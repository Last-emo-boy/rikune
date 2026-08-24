import { describe, expect, jest, test } from '@jest/globals'
import pino from 'pino'
import { z } from 'zod'
import { MCPRegistry } from '../../src/core/mcp-registry.js'
import { ToolExecutor } from '../../src/core/tool-executor.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import {
  createWorkflowRunHandler,
  workflowRunToolDefinition,
} from '../../src/workflows/workflow-run.js'
import type { Plugin } from '../../src/plugins/sdk.js'
import type { WorkerResult } from '../../src/types.js'

const logger = pino({ level: 'silent' })

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function okRunResult(overrides: Record<string, unknown> = {}): WorkerResult {
  return {
    ok: true,
    data: {
      run_id: 'run-1',
      execution_state: 'completed',
      current_stage: 'fast_profile',
      run: {
        id: 'run-1',
        sample_id: 'sha256:abc',
        status: 'completed',
        latest_stage: 'fast_profile',
      },
      coverage_level: 'bounded',
      completion_state: 'completed',
      recommended_next_tools: ['workflow.analyze.status', 'workflow.analyze.promote'],
      next_actions: ['Inspect plan status before promoting deeper stages.'],
      ...overrides,
    },
  }
}

function okUploadResult(overrides: Record<string, unknown> = {}): WorkerResult {
  return {
    ok: true,
    data: {
      upload_url: 'http://localhost:19080/api/v1/uploads/token-1',
      status_url: 'http://localhost:19080/api/v1/uploads/token-1/status',
      token: 'token-1',
      expires_at: '2026-06-07T15:30:00.000Z',
      ttl_seconds: 300,
      result_mode: 'upload_session',
      recommended_next_tools: ['workflow.run', 'workflow.search'],
      next_actions: ['POST the file bytes to upload_url.'],
      ...overrides,
    },
  }
}

describe('workflow.run', () => {
  test('requests an upload session through the whitelisted upload handler', async () => {
    const requestUpload = jest
      .fn<Promise<WorkerResult>, [Record<string, unknown>]>()
      .mockResolvedValue(okUploadResult())
    const handler = createWorkflowRunHandler({
      requestUpload,
      start: jest.fn() as any,
      status: jest.fn() as any,
      promote: jest.fn() as any,
    })

    const result = await handler({
      action: 'request_upload',
      filename: 'sample.exe',
      ttl_seconds: 600,
    })

    expect(result.ok).toBe(true)
    expect(requestUpload).toHaveBeenCalledWith({
      filename: 'sample.exe',
      ttl_seconds: 600,
    })
    expect(result.data as any).toEqual(
      expect.objectContaining({
        result_mode: 'workflow_run',
        action: 'request_upload',
        routed_tool: 'sample.request_upload',
        upload_url: 'http://localhost:19080/api/v1/uploads/token-1',
        token: 'token-1',
        ttl_seconds: 300,
      })
    )
    expect((result.data as any).recommended_next_tools).toBeUndefined()
    expect((result.data as any).recommended_workflow_tools).toContain('workflow.run')
  })

  test('starts a plan through the whitelisted analyze start handler', async () => {
    const start = jest
      .fn<Promise<WorkerResult>, [Record<string, unknown>]>()
      .mockResolvedValue(okRunResult())
    const handler = createWorkflowRunHandler({
      requestUpload: jest.fn() as any,
      start,
      status: jest.fn() as any,
      promote: jest.fn() as any,
    })

    const result = await handler({
      action: 'start',
      sample_id: 'sha256:abc',
      goal: 'triage',
      depth: 'balanced',
    })

    expect(result.ok).toBe(true)
    expect(start).toHaveBeenCalledWith(
      expect.objectContaining({
        sample_id: 'sha256:abc',
        goal: 'triage',
        depth: 'balanced',
        backend_policy: 'auto',
      })
    )
    expect(result.data as any).toEqual(
      expect.objectContaining({
        result_mode: 'workflow_run',
        action: 'start',
        routed_tool: 'workflow.analyze.start',
        plan_id: 'run-1',
        sample_id: 'sha256:abc',
      })
    )
    expect((result.data as any).recommended_next_tools).toBeUndefined()
    expect((result.data as any).recommended_workflow_tools).toEqual(['workflow.run'])
  })

  test('maps plan_id to run_id for status and promote actions', async () => {
    const status = jest
      .fn<Promise<WorkerResult>, [Record<string, unknown>]>()
      .mockResolvedValue(okRunResult({ run_id: 'plan-7' }))
    const promote = jest
      .fn<Promise<WorkerResult>, [Record<string, unknown>]>()
      .mockResolvedValue(okRunResult({ run_id: 'plan-7', current_stage: 'function_map' }))
    const handler = createWorkflowRunHandler({
      requestUpload: jest.fn() as any,
      start: jest.fn() as any,
      status,
      promote,
    })

    const statusResult = await handler({ action: 'status', plan_id: 'plan-7' })
    const promoteResult = await handler({
      action: 'promote',
      plan_id: 'plan-7',
      stages: ['function_map'],
    })

    expect(status).toHaveBeenCalledWith({ run_id: 'plan-7' })
    expect(promote).toHaveBeenCalledWith({
      run_id: 'plan-7',
      stages: ['function_map'],
      force_refresh: false,
    })
    expect((statusResult.data as any).routed_tool).toBe('workflow.analyze.status')
    expect((promoteResult.data as any).routed_tool).toBe('workflow.analyze.promote')
  })

  test('returns compact artifact selectors from status without exposing raw result', async () => {
    const status = jest.fn<Promise<WorkerResult>, [Record<string, unknown>]>().mockResolvedValue(
      okRunResult({
        run_id: 'plan-7',
        run: {
          id: 'plan-7',
          sample_id: 'sha256:abc',
          status: 'completed',
          latest_stage: 'reconstruct',
          artifact_refs: [
            {
              id: 'artifact-run-summary',
              type: 'analysis_summary',
              path: 'reports/summary/run.json',
              sha256: 'c'.repeat(64),
              mime: 'application/json',
            },
            {
              id: 'artifact-reconstruct-manifest',
              type: 'reconstruct_manifest',
              path: 'reports/reconstruct/latest/manifest.json',
              sha256: 'b'.repeat(64),
              mime: 'application/json',
            },
          ],
          stages: [
            {
              stage: 'fast_profile',
              status: 'completed',
              artifact_refs: [
                {
                  id: 'artifact-fast-triage',
                  type: 'triage_summary',
                  path: 'reports/triage/summary.json',
                  sha256: 'a'.repeat(64),
                  mime: 'application/json',
                },
              ],
            },
            {
              stage: 'reconstruct',
              status: 'completed',
              artifact_refs: [
                {
                  id: 'artifact-reconstruct-manifest',
                  type: 'reconstruct_manifest',
                  path: 'reports/reconstruct/latest/manifest.json',
                  sha256: 'b'.repeat(64),
                  mime: 'application/json',
                },
              ],
            },
          ],
        },
        recommended_next_tools: ['artifact.read', 'workflow.analyze.promote'],
      })
    )
    const handler = createWorkflowRunHandler({
      requestUpload: jest.fn() as any,
      start: jest.fn() as any,
      status,
      promote: jest.fn() as any,
    })

    const result = await handler({ action: 'status', plan_id: 'plan-7' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.routed_tool).toBe('workflow.analyze.status')
    expect(data.routed_result).toBeUndefined()
    expect(data.recommended_next_tools).toBeUndefined()
    expect(data.recommended_workflow_tools).toEqual(['artifact.read', 'workflow.run'])
    expect(data.artifact_selectors).toEqual([
      expect.objectContaining({
        artifact_id: 'artifact-reconstruct-manifest',
        artifact_type: 'reconstruct_manifest',
        path: 'reports/reconstruct/latest/manifest.json',
        stage: 'reconstruct',
        source: 'stage',
        suggested_read_mode: 'profile',
        read_args: {
          sample_id: 'sha256:abc',
          artifact_id: 'artifact-reconstruct-manifest',
          read_mode: 'profile',
        },
      }),
      expect.objectContaining({
        artifact_id: 'artifact-fast-triage',
        artifact_type: 'triage_summary',
        stage: 'fast_profile',
        read_args: {
          sample_id: 'sha256:abc',
          artifact_id: 'artifact-fast-triage',
          read_mode: 'summary',
        },
      }),
      expect.objectContaining({
        artifact_id: 'artifact-run-summary',
        artifact_type: 'analysis_summary',
        stage: null,
        source: 'run',
        read_args: {
          sample_id: 'sha256:abc',
          artifact_id: 'artifact-run-summary',
          read_mode: 'summary',
        },
      }),
    ])
    expect(data.artifact_selector_summary).toEqual(
      expect.objectContaining({
        total_artifact_refs: 4,
        selectable_artifact_refs: 3,
        selector_count: 3,
        omitted_count: 0,
        latest_stage: 'reconstruct',
        by_type: expect.objectContaining({
          reconstruct_manifest: 1,
          triage_summary: 1,
          analysis_summary: 1,
        }),
        by_stage: expect.objectContaining({
          reconstruct: 1,
          fast_profile: 1,
          run: 1,
        }),
      })
    )
  })

  test('returns bounded stage statuses and explicit function-index readiness', async () => {
    const status = jest.fn<Promise<WorkerResult>, [Record<string, unknown>]>().mockResolvedValue(
      okRunResult({
        run: {
          id: 'plan-static',
          sample_id: 'sha256:abc',
          status: 'partial',
          latest_stage: 'function_map',
          stages: [
            {
              stage: 'fast_profile',
              status: 'completed',
              execution_state: 'completed',
              recovery_state: 'none',
              job_id: null,
            },
            {
              stage: 'function_map',
              status: 'partial',
              execution_state: 'partial',
              recovery_state: 'recoverable',
              job_id: 'job-ghidra',
              metadata: { function_index_ready: false },
            },
          ],
        },
      })
    )
    const handler = createWorkflowRunHandler({
      requestUpload: jest.fn() as any,
      start: jest.fn() as any,
      status,
      promote: jest.fn() as any,
    })

    const result = await handler({ action: 'status', plan_id: 'plan-static' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.stage_statuses).toEqual([
      {
        stage: 'fast_profile',
        status: 'completed',
        execution_state: 'completed',
        recovery_state: 'none',
        job_id: null,
      },
      {
        stage: 'function_map',
        status: 'partial',
        execution_state: 'partial',
        recovery_state: 'recoverable',
        job_id: 'job-ghidra',
      },
    ])
    expect(data.function_index_ready).toBe(false)
    expect(workflowRunToolDefinition.outputSchema?.safeParse(result).success).toBe(true)
  })

  test('prioritizes function-map artifacts over noisy string chunks in selectors', async () => {
    const status = jest.fn<Promise<WorkerResult>, [Record<string, unknown>]>().mockResolvedValue(
      okRunResult({
        run: {
          id: 'run-1',
          sample_id: 'sha256:abc',
          status: 'partial',
          latest_stage: 'function_map',
          stages: [
            {
              stage: 'function_map',
              status: 'partial',
              artifact_refs: [
                ...Array.from({ length: 14 }, (_, index) => ({
                  id: `artifact-string-${index}`,
                  type: 'enriched_string_analysis',
                  path: `reports/strings/default/enriched_strings_chunk_${index}.json`,
                  sha256: 'c'.repeat(64),
                  mime: 'application/json',
                })),
                {
                  id: 'artifact-rizin-functions',
                  type: 'backend_rizin_functions',
                  path: 'reports/backend_tools/default/rizin/functions.json',
                  sha256: 'd'.repeat(64),
                  mime: 'application/json',
                },
                {
                  id: 'artifact-ghidra-functions',
                  type: 'ghidra_functions',
                  path: 'ghidra/functions.json',
                  sha256: 'e'.repeat(64),
                  mime: 'application/json',
                },
              ],
            },
          ],
        },
      })
    )
    const handler = createWorkflowRunHandler({
      requestUpload: jest.fn() as any,
      start: jest.fn() as any,
      status,
      promote: jest.fn() as any,
    })

    const result = await handler({ action: 'status', plan_id: 'run-1' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.artifact_selectors.slice(0, 2).map((item: any) => item.artifact_id)).toEqual(
      expect.arrayContaining(['artifact-ghidra-functions', 'artifact-rizin-functions'])
    )
    expect(data.artifact_selector_summary).toEqual(
      expect.objectContaining({
        selector_count: 12,
        omitted_count: 4,
        latest_stage: 'function_map',
        by_type: expect.objectContaining({
          enriched_string_analysis: 14,
          backend_rizin_functions: 1,
          ghidra_functions: 1,
        }),
      })
    )
  })

  test('requires sample_id or plan_id according to action', async () => {
    const handler = createWorkflowRunHandler({
      requestUpload: jest.fn() as any,
      start: jest.fn() as any,
      status: jest.fn() as any,
      promote: jest.fn() as any,
    })

    const startResult = await handler({ action: 'start' })
    const statusResult = await handler({ action: 'status' })

    expect(startResult.ok).toBe(false)
    expect(startResult.errors?.[0]).toContain('sample_id is required')
    expect(statusResult.ok).toBe(false)
    expect(statusResult.errors?.[0]).toContain('plan_id is required')
  })

  test('executor result scanning does not expand the tool surface', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerCoreTools(['workflow.run', 'workflow.analyze.status'])
    surface.registerGatewayCoreTools(['workflow.run'])
    const signalPlugin: Plugin = {
      id: 'action-signal-test',
      name: 'Action Signal Test',
      surfaceRules: {
        tier: 2,
        category: 'malware-analysis',
        activateOn: { findings: ['packed'] },
        signalMap: { action: ['packed'] },
      },
      tools: [],
    }
    surface.registerPlugin(signalPlugin, ['packed.deep.scan'])

    const registry = new MCPRegistry(logger)
    registry.registerTool(
      workflowRunToolDefinition,
      createWorkflowRunHandler({
        requestUpload: async () => okUploadResult(),
        start: async () => okRunResult(),
        status: async () =>
          okRunResult({
            recommended_next_tools: ['artifact.read', 'packed.deep.scan'],
            run: {
              id: 'run-1',
              sample_id: 'sha256:abc',
              status: 'completed',
              latest_stage: 'fast_profile',
              artifact_refs: [
                {
                  id: 'artifact-fast-triage',
                  type: 'triage_summary',
                  path: 'reports/triage/summary.json',
                  sha256: 'a'.repeat(64),
                  mime: 'application/json',
                },
              ],
              stages: [
                {
                  stage: 'fast_profile',
                  status: 'completed',
                  artifact_refs: [
                    {
                      id: 'artifact-fast-triage',
                      type: 'triage_summary',
                      path: 'reports/triage/summary.json',
                      sha256: 'a'.repeat(64),
                      mime: 'application/json',
                    },
                  ],
                },
              ],
            },
          }),
        promote: async () => okRunResult(),
      })
    )
    const executor = new ToolExecutor(logger)

    const result = await executor.executeTool(
      'workflow_run',
      { action: 'status', plan_id: 'run-1' },
      { registry, logger }
    )

    expect(result.isError).toBe(false)
    expect((result.structuredContent as any).data.result_mode).toBe('workflow_run')
    expect((result.structuredContent as any).data.recommended_next_tools).toBeUndefined()
    expect((result.structuredContent as any).data.artifact_selectors).toEqual([
      expect.objectContaining({
        artifact_id: 'artifact-fast-triage',
        read_args: {
          sample_id: 'sha256:abc',
          artifact_id: 'artifact-fast-triage',
          read_mode: 'summary',
        },
      }),
    ])
    expect([...surface.getVisibleToolNames()]).toEqual(['workflow.run'])
    expect(surface.isToolVisible('workflow.analyze.status')).toBe(false)
    expect(surface.isToolVisible('artifact.read')).toBe(false)
    expect(surface.isToolVisible('packed.deep.scan')).toBe(false)
  })

  test('registry lists workflow.run while keeping workflow.analyze tools hidden', async () => {
    const registry = new MCPRegistry(logger)
    registry.registerTool(
      workflowRunToolDefinition,
      createWorkflowRunHandler({
        requestUpload: async () => okUploadResult(),
        start: async () => okRunResult(),
        status: async () => okRunResult(),
        promote: async () => okRunResult(),
      })
    )
    for (const name of [
      'workflow.analyze.start',
      'workflow.analyze.status',
      'workflow.analyze.promote',
    ]) {
      registry.registerTool(
        {
          name,
          description: `Hidden ${name}`,
          inputSchema: z.object({}),
        },
        async () => ({ ok: true })
      )
    }

    const { tools } = await registry.listTools(new Set(['workflow.run']))

    expect(tools.map((tool) => tool.name)).toEqual(['workflow_run'])
  })
})
