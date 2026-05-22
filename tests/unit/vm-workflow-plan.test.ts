import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import vmAnalysisPlugin from '../../src/plugins/vm-analysis/index.js'
import {
  buildVmWorkflowPlan,
  vmWorkflowPlanInputSchema,
} from '../../src/plugins/vm-analysis/tools/vm-workflow-plan.js'

describe('vm.workflow.plan', () => {
  test('builds a passive symbolic workflow without running solvers or emulators', () => {
    const input = vmWorkflowPlanInputSchema.parse({
      sample_id: 'sha256:vm',
      findings: ['dispatcher loop', 'VM opcode table', 'MBA expression'],
      goals: ['recover keygen'],
    })

    const plan = buildVmWorkflowPlan(input)

    expect(plan.result_mode).toBe('vm_workflow_plan')
    expect(plan.steps.map((step) => step.tool)).toEqual([
      'vm.detect',
      'vm.pattern.analyze',
      'vm.opcode.extract',
      'vm.disasm.build',
      'vm.emulate',
      'constraint.extract',
      'smt.solve',
      'keygen.synthesize',
      'mba.simplify',
    ])
    expect(plan.steps.find((step) => step.tool === 'smt.solve')).toEqual(
      expect.objectContaining({
        limits: { timeout_ms_max: 300000 },
      })
    )
    expect(plan.steps.find((step) => step.tool === 'vm.emulate')).toEqual(
      expect.objectContaining({
        limits: { max_steps: 100000, live_sample_execution: false },
      })
    )
    expect(plan.safety_notes.join(' ')).toMatch(/does not execute the sample/)
  })

  test('registers workflow planner before expert VM tools', async () => {
    const harness = createPluginTestHarness()
    const names = harness.registerPlugin(vmAnalysisPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'vm.workflow.plan'
    )

    expect(names[0]).toBe('vm.workflow.plan')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'vm.symbolic.workflow',
        nextTools: expect.arrayContaining(['constraint.extract', 'smt.solve', 'mba.simplify']),
      })
    )
    expect(vmAnalysisPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining(['symbolic-workflow', 'workflow-plan'])
    )
    expect(vmAnalysisPlugin.systemDeps?.map((dep) => dep.name)).toEqual(
      expect.arrayContaining(['python', 'z3-solver'])
    )

    const result = (await tool?.handler({
      findings: ['vm dispatcher'],
      include_solver_steps: false,
    })) as any
    expect(result.ok).toBe(true)
    expect(result.data.steps.find((step: any) => step.tool === 'smt.solve').required).toBe(false)
  })
})
