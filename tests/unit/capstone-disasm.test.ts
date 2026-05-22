import { describe, expect, test } from '@jest/globals'
import { disasmQuickToolDefinition } from '../../src/plugins/capstone/tools/disasm-quick.js'
import { shellcodeDisasmToolDefinition } from '../../src/plugins/capstone/tools/shellcode-disasm.js'

describe('capstone disassembly adapters', () => {
  test('declare passive static metadata, schemas, and evidence without requiring Capstone at discovery time', () => {
    expect(disasmQuickToolDefinition.name).toBe('disasm.quick')
    expect(disasmQuickToolDefinition.outputSchema).toBeDefined()
    expect(disasmQuickToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['pe', 'elf', 'macho']),
        execution: expect.arrayContaining(['static', 'triage']),
        safety: expect.arrayContaining(['passive']),
      })
    )
    expect(disasmQuickToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
      'backend_capstone_disasm'
    )
    expect(disasmQuickToolDefinition.evidence?.map((entry) => entry.category)).toContain(
      'structure'
    )
  })

  test('keeps shellcode disassembly as bounded passive output metadata', () => {
    expect(shellcodeDisasmToolDefinition.name).toBe('shellcode.disasm')
    expect(shellcodeDisasmToolDefinition.outputSchema).toBeDefined()
    expect(shellcodeDisasmToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['shellcode', 'pe'])
    )
    expect(shellcodeDisasmToolDefinition.artifacts?.[0].type).toBe('backend_capstone_shellcode')
  })
})
