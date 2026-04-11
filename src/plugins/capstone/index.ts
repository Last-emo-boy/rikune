/**
 * Capstone Plugin
 *
 * Lightweight multi-architecture disassembly using the Capstone framework.
 * Does not require Ghidra or Rizin — ideal for quick shellcode/snippet analysis.
 */

import type { Plugin } from '../sdk.js'
import { disasmQuickToolDefinition, createDisasmQuickHandler } from './tools/disasm-quick.js'
import { shellcodeDisasmToolDefinition, createShellcodeDisasmHandler } from './tools/shellcode-disasm.js'

const capstonePlugin: Plugin = {
  id: 'capstone',
  name: 'Capstone Disassembly',
  surfaceRules: { tier: 2, activateOn: { findings: ['shellcode', 'suspicious_imports'] }, category: 'reverse-engineering' },
  description: 'Lightweight multi-architecture disassembly for quick analysis of code snippets and shellcode',
  version: '1.0.0',
  systemDeps: [
    {
      type: 'python',
      name: 'capstone',
      importName: 'capstone',
      required: false,
      description: 'Capstone disassembly framework',
      dockerInstall: 'pip install capstone',
      dockerFeature: 'dynamic-python',
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(disasmQuickToolDefinition, createDisasmQuickHandler(wm, db))
    server.registerTool(shellcodeDisasmToolDefinition, createShellcodeDisasmHandler(wm, db))

    return ['disasm.quick', 'shellcode.disasm']
  },
}

export default capstonePlugin
