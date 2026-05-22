import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import firmwarePlugin from '../../src/plugins/firmware/index.js'
import { buildFirmwareWorkflowPlan } from '../../src/plugins/firmware/tools/firmware-workflow-plan.js'

describe('firmware.workflow.plan', () => {
  test('builds passive SBOM and Qiling handoff guidance from firmware hints', () => {
    const plan = buildFirmwareWorkflowPlan({
      sample_id: 'sha256:fw',
      architecture_hint: 'mipsel',
      signatures: [{ description: 'Squashfs filesystem, little endian' }],
      container_inventory: {
        entries: [
          { path: 'etc/init.d/S99demo' },
          { path: 'lib/modules/demo.ko' },
          { path: 'usr/bin/busybox' },
        ],
      },
      package_inventory: {
        archive_members: ['control.tar.gz', 'data.tar.gz'],
        maintainer_script_candidates: ['postinst'],
      },
    })

    expect(plan.result_mode).toBe('firmware_workflow_plan')
    expect(plan.architecture_hint).toBe('mipsel')
    expect(plan.passive_findings.filesystem_hints.join(' ')).toMatch(/Squashfs/i)
    expect(plan.passive_findings.init_script_hints).toEqual(
      expect.arrayContaining(['etc/init.d/S99demo', 'busybox'])
    )
    expect(plan.workflow_steps.map((step: any) => step.tool)).toEqual(
      expect.arrayContaining(['sbom.provenance.graph', 'qiling.inspect'])
    )
    expect(plan.qiling_handoff).toEqual(
      expect.objectContaining({
        status: 'plan_only',
        requires_rootfs: true,
        requires_explicit_opt_in: true,
      })
    )
    expect(plan.safety_notes.join(' ')).toMatch(/No extraction/)
  })

  test('registers firmware passive workflow metadata', () => {
    const harness = createPluginTestHarness({
      deps: { workspaceManager: {}, database: {} },
    })
    const names = harness.registerPlugin(firmwarePlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'firmware.workflow.plan'
    )

    expect(names).toContain('firmware.workflow.plan')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'firmware.iot.passive-workflow',
        nextTools: expect.arrayContaining(['sbom.provenance.graph', 'qiling.inspect']),
      })
    )
  })
})
