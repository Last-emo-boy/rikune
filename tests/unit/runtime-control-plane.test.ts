import { describe, expect, test } from '@jest/globals'
import {
  PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  buildRuntimeArtifactControlPlaneMetadata,
  extractRuntimeTaskStatusFromEvent,
  inferRuntimeArtifactType,
  listRuntimeDynamicTraceArtifactTypes,
  inferRuntimeArtifactFamily,
} from '../../packages/shared/src/index.js'

describe('runtime control-plane helpers', () => {
  test('extracts runtime task status from task lifecycle events', () => {
    expect(
      extractRuntimeTaskStatusFromEvent({
        event: 'progress',
        id: '42',
        data: { taskId: 'task-1', status: 'running' },
      })
    ).toBe('running')
    expect(
      extractRuntimeTaskStatusFromEvent({
        event: 'connected',
        data: { ok: true, subscribedAt: Date.now(), taskId: null },
      })
    ).toBeUndefined()
  })

  test('derives stable runtime artifact family metadata', () => {
    expect(listRuntimeDynamicTraceArtifactTypes()).toEqual([
      PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
      SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
    ])
    expect(inferRuntimeArtifactFamily(SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE)).toBe(
      'sandbox_trace'
    )
    expect(inferRuntimeArtifactType('sandbox.execute', 'behavior_capture.json')).toBe(
      PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE
    )
    expect(inferRuntimeArtifactType('sandbox.execute', 'sandbox_123.json')).toBe(
      SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE
    )
    expect(
      buildRuntimeArtifactControlPlaneMetadata({
        artifactType: 'runtime_debug_artifact',
        runtimeTool: 'debug.session.inspect',
        runtimeTaskId: 'task-123',
        runtimeDebugSessionId: 'session-1',
      })
    ).toEqual(
      expect.objectContaining({
        runtime_schema: 'rikune.runtime_artifact.v1',
        artifact_family: 'runtime_debug',
        runtime_tool: 'debug.session.inspect',
        runtime_task_id: 'task-123',
        runtime_debug_session_id: 'session-1',
      })
    )
  })
})
