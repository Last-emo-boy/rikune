import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import unpackingPlugin from '../../src/plugins/unpacking/index.js'
import { buildUnpackWorkflowPlan } from '../../src/plugins/unpacking/tools/unpack-workflow-plan.js'

describe('unpack.workflow.plan', () => {
  test('builds a readiness-gated unpacking loop without runtime execution', () => {
    const plan = buildUnpackWorkflowPlan({
      sample_id: 'sha256:packed',
      packer_findings: {
        detections: [{ name: 'VMProtect' }],
        packed: true,
        confidence: 0.92,
      },
      static_triage: {
        sections: [{ name: '.vmp0', entropy: 7.9 }],
        findings: ['anti-debug', 'high entropy', 'OEP unknown'],
      },
    })

    expect(plan.result_mode).toBe('unpack_workflow_plan')
    expect(plan.detected_packers).toEqual(expect.arrayContaining(['VMProtect']))
    expect(plan.difficulty).toBe('hard')
    expect(plan.dump_strategy).toEqual(
      expect.objectContaining({
        strategy: 'runtime_dump_after_explicit_opt_in',
        candidate_tools: expect.arrayContaining(['debug.session.plan', 'unpack.auto']),
      })
    )
    expect(plan.runtime_gates).toEqual(
      expect.objectContaining({
        live_execution: false,
        requires_explicit_opt_in: true,
        network_policy: 'disabled',
      })
    )
    expect(plan.workflow_steps.map((step: any) => step.phase)).toEqual([
      'detect',
      'plan',
      'dump',
      'reconstruct',
      'retriage',
    ])
    expect(plan.reanalysis_request.recommended_tools).toEqual(
      expect.arrayContaining(['static.triage', 'strings.extract'])
    )
  })

  test('registers unpack workflow recipe metadata', () => {
    const harness = createPluginTestHarness({
      deps: { workspaceManager: {}, database: {} },
    })
    const names = harness.registerPlugin(unpackingPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'unpack.workflow.plan'
    )

    expect(names).toContain('unpack.workflow.plan')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'unpacking.detect-plan-retriage',
        runtimeBackends: expect.arrayContaining(['debugger', 'frida']),
      })
    )
  })
})
