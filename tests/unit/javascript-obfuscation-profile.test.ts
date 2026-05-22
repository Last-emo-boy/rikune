import { describe, expect, test } from '@jest/globals'
import { buildJavascriptObfuscationProfileFromSource } from '../../src/plugins/javascript-deobfuscation/tools/javascript-obfuscation-profile.js'

describe('javascript.obfuscation.profile', () => {
  test('detects JSVMP-like dispatch without executing JavaScript', () => {
    const source = `
      const bytecode = [12, 4, 91, 7, 0, 0, 1, 44, 91, 9, 2, 18, 7, 6, 5, 4, 3, 2, 1];
      const handlers = {
        12: function(state) { state.stack.push(state.regs[0]); },
        91: function(state) { state.ip = state.stack.pop(); },
        44: function(state) { state.regs[1] = state.stack.pop(); }
      };
      while (true) {
        switch (bytecode[pc++]) {
          case 12: handlers[12](vm); break;
          case 91: handlers[91](vm); break;
          case 44: handlers[44](vm); break;
          case 18: handlers[18](vm); break;
          case 7: handlers[7](vm); break;
          case 6: handlers[6](vm); break;
        }
      }
    `

    const profile = buildJavascriptObfuscationProfileFromSource(source, {
      filename: 'protected.js',
      sampleId: 'sha256:jsvmp',
    })

    expect(profile.jsvmp_assessment.suspected).toBe(true)
    expect(profile.jsvmp_assessment.score).toBeGreaterThanOrEqual(0.45)
    expect(profile.bytecode_metrics).toEqual(
      expect.objectContaining({
        numeric_array_count: expect.any(Number),
        dense_numeric_array_count: expect.any(Number),
        max_numeric_array_length: expect.any(Number),
      })
    )
    expect(profile.bytecode_metrics.numeric_array_count).toBeGreaterThanOrEqual(1)
    expect(profile.bytecode_metrics.dense_numeric_array_count).toBeGreaterThanOrEqual(1)
    expect(profile.dispatcher_model).toEqual(
      expect.objectContaining({
        model: 'loop_switch',
        confidence: expect.any(Number),
        switch_count: expect.any(Number),
      })
    )
    expect(profile.risk_tags).toEqual(
      expect.arrayContaining(['suspected_jsvmp', 'dense_numeric_bytecode_array'])
    )
    expect(profile.confidence_breakdown).toEqual(
      expect.objectContaining({
        bytecode_container: expect.any(Number),
        dispatcher: expect.any(Number),
        handler_model: expect.any(Number),
      })
    )
    expect(profile.signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining(['control-flow-dispatch', 'jsvmp-like-vm'])
    )
    expect(profile.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_interpreter_start: true,
        no_network: true,
        no_external_deobfuscator: true,
      })
    )
    expect(profile.deobfuscation_plan.status).toBe('plan_only')
    expect(profile.deobfuscation_plan.optional_tool_candidates.map((item) => item.id)).toEqual(
      expect.arrayContaining([
        'google-jsir-cascade',
        'humansecurity-restringer',
        'jsimplifier-pipeline',
        'jsvmp-handler-map',
      ])
    )
    expect(profile.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'jsvmp.bytecode.plan',
        'strings.extract',
        'yara.generate',
        'analysis.evidence.graph',
      ])
    )
  })

  test('keeps benign JavaScript below JSVMP suspicion threshold', () => {
    const source = `
      export function add(a, b) {
        const label = 'total';
        return { label, value: a + b };
      }
    `

    const profile = buildJavascriptObfuscationProfileFromSource(source, {
      filename: 'plain.js',
      sampleId: 'sha256:plain',
    })

    expect(profile.jsvmp_assessment.suspected).toBe(false)
    expect(profile.jsvmp_assessment.score).toBeLessThan(0.45)
    expect(profile.dispatcher_model.model).toBe('unknown')
    expect(profile.bytecode_metrics.numeric_array_count).toBe(0)
    expect(profile.risk_tags).not.toContain('suspected_jsvmp')
    expect(profile.recommended_next_tools).not.toContain('jsvmp.bytecode.plan')
  })
})
