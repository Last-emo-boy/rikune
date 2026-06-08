/**
 * Capstone Plugin
 *
 * Lightweight multi-architecture disassembly using the Capstone framework.
 * Does not require Ghidra or Rizin — ideal for quick shellcode/snippet analysis.
 */

import type { Plugin } from '../sdk.js'
import { disasmQuickToolDefinition, createDisasmQuickHandler } from './tools/disasm-quick.js'
import {
  shellcodeDisasmToolDefinition,
  createShellcodeDisasmHandler,
} from './tools/shellcode-disasm.js'
import { CAPSTONE_PASSIVE_SAFETY } from './capstone-metadata.js'

const capstonePlugin: Plugin = {
  id: 'capstone',
  name: 'Capstone Disassembly',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'shellcode', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips'],
    execution: ['static', 'triage'],
    safety: CAPSTONE_PASSIVE_SAFETY,
    capabilities: [
      'disassembly',
      'bounded-disassembly',
      'shellcode',
      'entrypoint-preview',
      'function-boundary-seeding',
      'api-dispatch-heuristic',
      'workflow-handoff',
    ],
    evidence: ['structure', 'disassembly', 'shellcode', 'symbols', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'firmware', 'shellcode'],
      findings: ['shellcode', 'suspicious_imports', 'entrypoint', 'payload', 'packed'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Lightweight multi-architecture disassembly for quick analysis of code snippets and shellcode',
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
