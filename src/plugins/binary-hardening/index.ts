/**
 * Binary Hardening Inventory Plugin
 *
 * Passive cross-platform exploit-mitigation and hardening posture inventory.
 * It reads bounded bytes only and never loads, executes, debugs, emulates,
 * rewrites, signs, queries networks, or invokes external checksec-like tools.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  binaryHardeningInventoryAspects,
  binaryHardeningInventoryToolDefinition,
  createBinaryHardeningInventoryHandler,
} from './tools/binary-hardening-inventory.js'

const binaryHardeningPlugin = definePlugin({
  id: 'binary-hardening',
  name: 'Binary Hardening Inventory',
  executionDomain: 'static',
  aspects: binaryHardeningInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'binary-hardening',
        'hardening',
        'exploit-mitigation',
        'checksec',
        'mitigation-profile',
        'elf-hardening',
        'pe-hardening',
        'macho-hardening',
        'elf',
        'elf-executable',
        'elf-so',
        'linux-binary',
        'pe',
        'pe32',
        'pe64',
        'dll',
        'exe',
        'sys',
        'macho',
        'mach-o',
        'dylib',
        'object',
        'static-lib',
        'cet',
        'ibt',
        'shstk',
        'shadow-stack',
        'pac',
        'bti',
        'mte',
        'cheri',
      ],
      findings: [
        'RELRO',
        'BIND_NOW',
        'GNU_STACK',
        '__stack_chk_fail',
        '_FORTIFY_SOURCE',
        'GNU_PROPERTY_X86_FEATURE_1_IBT',
        'GNU_PROPERTY_X86_FEATURE_1_SHSTK',
        'IMAGE_DLLCHARACTERISTICS_NX_COMPAT',
        'GUARD_CF',
        'XFG',
        'PACIASP',
        'BTI',
        'memtag',
        'CHERI',
        'purecap',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive cross-platform binary hardening inventory for ELF, PE, Mach-O, and object artifacts, covering RELRO, PIE/ASLR, NX/DEP, stack canaries, FORTIFY, CFG/XFG, CET IBT/SHSTK, PAC/BTI, MTE, CHERI, and W^X section risks.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...binaryHardeningInventoryToolDefinition,
      handler: (args, deps) => createBinaryHardeningInventoryHandler(deps)(args as never),
    }),
  ],
})

export default binaryHardeningPlugin
