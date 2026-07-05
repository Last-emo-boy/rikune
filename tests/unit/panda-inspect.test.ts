import { describe, expect, jest, test } from '@jest/globals'
import {
  createPandaInspectHandler,
  pandaInspectToolDefinition,
} from '../../src/plugins/panda/tools/panda-inspect.js'

function availablePandaBackend() {
  return {
    available: true,
    source: 'test',
    path: 'python',
    version: 'pandare-test',
    checked_candidates: ['python'],
    error: null,
  }
}

describe('panda.inspect', () => {
  test('declares passive readiness search profile and workflow metadata', () => {
    const recipe = pandaInspectToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'panda.runtime-readiness-profile'
    )

    expect(pandaInspectToolDefinition.name).toBe('panda.inspect')
    expect(pandaInspectToolDefinition.outputSchema).toBeDefined()
    expect(pandaInspectToolDefinition.runtime?.handler).toBe('executePandaInspect')
    expect(pandaInspectToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        allowedBackends: ['docker'],
        networkPolicy: 'disabled',
      })
    )
    expect(pandaInspectToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['pe', 'elf', 'macho', 'firmware']),
        runtimes: expect.arrayContaining(['panda', 'pandare', 'qemu']),
        safety: expect.arrayContaining([
          'passive',
          'requires_isolation',
          'no_sample_execution_by_default',
          'backend_readiness_probe_only',
        ]),
        capabilities: expect.arrayContaining([
          'readiness-profile',
          'record-replay-plan',
          'workflow-handoff',
        ]),
      })
    )
    expect(pandaInspectToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'runtime-readiness' }),
        expect.objectContaining({ category: 'record-replay' }),
      ])
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['panda.inspect'],
        nextTools: expect.arrayContaining([
          'dynamic.dependencies',
          'dynamic.runtime.status',
          'tool.readiness',
        ]),
        safety: expect.arrayContaining(['passive', 'no_network_by_default']),
        runtimeBackends: ['panda', 'pandare', 'qemu'],
      })
    )
    expect(recipe?.requiredArtifacts).toEqual([])
    expect(recipe?.producesArtifacts).toBeUndefined()
  })

  test('reports setup_required without running PANDA when backend is unavailable', async () => {
    const runPythonJson = jest.fn()
    const handler = createPandaInspectHandler(
      {} as any,
      {
        findSample: jest.fn(() => ({ id: 'sha256:test' })),
      } as any,
      {
        resolveBackends: () =>
          ({
            panda: {
              available: false,
              source: null,
              path: null,
              version: null,
              checked_candidates: [],
              error: 'pandare missing',
            },
          }) as any,
        runPythonJson,
      }
    )

    const result = await handler({ sample_id: 'sha256:test' })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.status).toBe('setup_required')
    expect(data.result_mode).toBe('panda_readiness_profile')
    expect(data.readiness).toEqual(
      expect.objectContaining({
        backend_available: false,
        pandare_available: false,
        guest_image_configured: false,
        replay_assets_configured: false,
      })
    )
    expect(data.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'plan_only',
        sample_executed_by_tool: false,
        guest_started_by_tool: false,
        replay_started_by_tool: false,
        backend_probe_started: false,
        backend_probe_attempted: false,
        backend_probe_succeeded: false,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['dynamic.dependencies', 'dynamic.runtime.status', 'tool.readiness'])
    )
    expect(data.recommended_next_tools).not.toContain('sandbox.execute')
    expect(data.recommended_next_tools).not.toContain('tool.help')
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        readiness_probe_only: true,
        backend_available: false,
        artifact_persisted: false,
        backend_probe_attempted: false,
        backend_probe_succeeded: false,
        sample_executed_by_tool: false,
        replay_started_by_tool: false,
      })
    )
    expect(result.warnings).toEqual(expect.arrayContaining(['pandare missing']))
    expect(runPythonJson).not.toHaveBeenCalled()
  })

  test('returns ready planner envelope when PANDA bindings are available', async () => {
    const runPythonJson = jest.fn(async () => ({
      stdout: '',
      stderr: '',
      parsed: {
        pandare_version: '1.5.0',
        module: 'pandare',
        note: 'test',
      },
    }))
    const handler = createPandaInspectHandler(
      {} as any,
      {
        findSample: jest.fn(() => ({ id: 'sha256:test' })),
      } as any,
      {
        resolveBackends: () =>
          ({
            panda: availablePandaBackend(),
          }) as any,
        runPythonJson,
      }
    )

    const result = await handler({ sample_id: 'sha256:test' })
    const data = result.data as any

    expect(result.ok).toBe(true)
    expect(data.status).toBe('ready')
    expect(data.readiness).toEqual(
      expect.objectContaining({
        backend_available: true,
        pandare_available: true,
        pandare_version: '1.5.0',
      })
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        guest_started_by_tool: false,
        replay_started_by_tool: false,
        instrumentation_started_by_tool: false,
        runtime_started_by_tool: false,
        network_accessed_by_tool: false,
      })
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        profile_type: 'panda_readiness_profile',
        artifact_persisted: false,
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        profile_type: 'panda_readiness_profile',
        artifact_persisted: false,
      })
    )
    expect(data.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'opt-in-record-replay-planning',
          priority: 'medium',
        }),
      ])
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        backend_available: true,
        backend_probe_started: true,
        backend_probe_attempted: true,
        backend_probe_succeeded: true,
        artifact_persisted: false,
        recommended_live_execution_tools: [],
      })
    )
    expect(data.recommended_next_tools).not.toContain('sandbox.execute')
    expect(data.recommended_next_tools).not.toContain('tool.help')
    expect(result.setup_actions).toBeUndefined()
    expect(runPythonJson).toHaveBeenCalledTimes(1)
    expect(runPythonJson.mock.calls[0]?.[2]).toEqual({})
  })

  test('keeps passive envelope when backend probe throws', async () => {
    const runPythonJson = jest.fn(async () => {
      throw new Error('probe failed')
    })
    const handler = createPandaInspectHandler(
      {} as any,
      {
        findSample: jest.fn(() => ({ id: 'sha256:test' })),
      } as any,
      {
        resolveBackends: () =>
          ({
            panda: availablePandaBackend(),
          }) as any,
        runPythonJson,
      }
    )

    const result = await handler({ sample_id: 'sha256:test' })
    const data = result.data as any

    expect(result.ok).toBe(false)
    expect(result.errors).toEqual(expect.arrayContaining(['probe failed']))
    expect(data.result_mode).toBe('panda_readiness_profile')
    expect(data.status).toBe('setup_required')
    expect(data.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'plan_only',
        live_execution: false,
        sample_executed_by_tool: false,
        guest_started_by_tool: false,
        replay_started_by_tool: false,
        runtime_started_by_tool: false,
        backend_probe_started: false,
        backend_probe_attempted: true,
        backend_probe_succeeded: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        readiness_probe_only: true,
        backend_probe_attempted: true,
        backend_probe_succeeded: false,
        sample_executed_by_tool: false,
        replay_started_by_tool: false,
      })
    )
  })
})
