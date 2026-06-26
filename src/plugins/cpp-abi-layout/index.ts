/**
 * C++ ABI Layout Plugin
 *
 * Passive Itanium/MSVC C++ ABI vtable, RTTI/typeinfo, EH personality, and
 * class-layout seed inventory. It never executes, links, loads, debugs, calls
 * external demanglers, contacts symbol/source servers, or mutates samples.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  cppAbiLayoutInventoryAspects,
  cppAbiLayoutInventoryToolDefinition,
  createCppAbiLayoutInventoryHandler,
} from './tools/cpp-abi-layout-inventory.js'

const cppAbiLayoutPlugin = definePlugin({
  id: 'cpp-abi-layout',
  name: 'C++ ABI Layout Inventory',
  executionDomain: 'static',
  aspects: cppAbiLayoutInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'cpp-abi',
        'cxx-abi',
        'itanium-abi',
        'msvc-abi',
        'rtti',
        'typeinfo',
        'vtable',
        'vftable',
        'vbtable',
        'class-layout',
        'virtual-dispatch',
        'exception-handling',
        'pe',
        'pe32',
        'pe64',
        'dll',
        'exe',
        'sys',
        'elf',
        'elf-executable',
        'elf-so',
        'elf-object',
        'linux-kernel-module',
        'macho',
        'mach-o',
        'macho-object',
        'dylib',
        'coff',
        'coff-lib',
        'object',
      ],
      findings: [
        '_ZTV',
        '_ZTI',
        '_ZTS',
        '__cxxabiv1',
        '__gxx_personality_v0',
        '__cxa_pure_virtual',
        '??_7',
        '??_R0',
        '??_R4',
        '__CxxFrameHandler3',
        '__purecall',
        'vtable',
        'RTTI',
        'typeinfo',
        'class layout',
        'virtual dispatch',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Itanium/MSVC C++ ABI layout inventory with vtable, RTTI/typeinfo, EH personality, class hierarchy seed, and virtual dispatch handoff hints.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...cppAbiLayoutInventoryToolDefinition,
      handler: (args, deps) => createCppAbiLayoutInventoryHandler(deps)(args as never),
    }),
  ],
})

export default cppAbiLayoutPlugin
