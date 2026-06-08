import { describe, expect, test } from '@jest/globals'
import capstonePlugin from '../../src/plugins/capstone/index.js'
import { disasmQuickToolDefinition } from '../../src/plugins/capstone/tools/disasm-quick.js'
import { shellcodeDisasmToolDefinition } from '../../src/plugins/capstone/tools/shellcode-disasm.js'

describe('capstone disassembly adapters', () => {
  test('declares plugin-level route profile without widening the default surface', () => {
    expect(capstonePlugin.surfaceRules).toEqual(
      expect.objectContaining({
        tier: 2,
        category: 'reverse-engineering',
        activateOn: expect.objectContaining({
          fileTypes: expect.arrayContaining(['pe', 'elf', 'macho', 'shellcode']),
          findings: expect.arrayContaining(['shellcode', 'payload', 'packed']),
        }),
      })
    )
    expect(capstonePlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'bounded-disassembly',
        'function-boundary-seeding',
        'workflow-handoff',
      ])
    )
    expect(capstonePlugin.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_runtime_start', 'no_network_by_default'])
    )
  })

  test('declare passive static metadata, schemas, and evidence without requiring Capstone at discovery time', () => {
    expect(disasmQuickToolDefinition.name).toBe('disasm.quick')
    expect(disasmQuickToolDefinition.outputSchema).toBeDefined()
    expect(disasmQuickToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['pe', 'elf', 'macho']),
        execution: expect.arrayContaining(['static', 'triage']),
        safety: expect.arrayContaining(['passive', 'bounded-input', 'no_runtime_start']),
        capabilities: expect.arrayContaining([
          'bounded-disassembly',
          'function-boundary-seeding',
          'workflow-handoff',
        ]),
        evidence: expect.arrayContaining(['disassembly', 'workflow', 'provenance']),
      })
    )
    expect(disasmQuickToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
      'backend_capstone_disasm'
    )
    expect(disasmQuickToolDefinition.evidence?.map((entry) => entry.category)).toContain(
      'structure'
    )
    expect(disasmQuickToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining(['disassembly', 'workflow', 'provenance'])
    )
    expect(disasmQuickToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'capstone.quick-disassembly-handoff',
        startsWith: ['disasm.quick'],
        nextTools: expect.arrayContaining([
          'code.functions.smart_recover',
          'analysis.evidence.graph',
          'report.generate',
        ]),
        producesArtifacts: ['backend_capstone_disasm'],
        safety: expect.arrayContaining(['passive', 'no_network_by_default']),
      })
    )
    expect(disasmQuickToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: false,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
  })

  test('keeps shellcode disassembly as bounded passive output metadata', () => {
    expect(shellcodeDisasmToolDefinition.name).toBe('shellcode.disasm')
    expect(shellcodeDisasmToolDefinition.outputSchema).toBeDefined()
    expect(shellcodeDisasmToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['shellcode', 'pe'])
    )
    expect(shellcodeDisasmToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'bounded-disassembly',
        'api-dispatch-heuristic',
        'api-resolver-loop',
        'workflow-handoff',
      ])
    )
    expect(shellcodeDisasmToolDefinition.aspects?.evidence).toEqual(
      expect.arrayContaining(['shellcode', 'api-dispatch', 'workflow', 'provenance'])
    )
    expect(shellcodeDisasmToolDefinition.artifacts?.[0].type).toBe('backend_capstone_shellcode')
    expect(shellcodeDisasmToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining(['shellcode', 'api-dispatch', 'workflow', 'provenance'])
    )
    expect(shellcodeDisasmToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'capstone.shellcode-disassembly-handoff',
        startsWith: ['shellcode.disasm'],
        nextTools: expect.arrayContaining([
          'strings.extract',
          'hash.resolve',
          'analysis.evidence.graph',
          'report.generate',
        ]),
        producesArtifacts: ['backend_capstone_shellcode'],
        safety: expect.arrayContaining(['passive', 'bounded-input']),
      })
    )
    expect(shellcodeDisasmToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
  })
})
