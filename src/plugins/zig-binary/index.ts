/**
 * Zig Binary Inventory Plugin
 *
 * Passive Zig language/runtime metadata inventory for native binaries and
 * object artifacts. It reads bounded bytes only and never invokes zig,
 * external demanglers, native loaders, runtimes, networks, or mutation.
 */

import { definePlugin, defineTool, type PluginToolDeps } from '../sdk.js'
import {
  createZigBinaryInventoryHandler,
  zigBinaryInventoryAspects,
  zigBinaryInventoryToolDefinition,
} from './tools/zig-binary-inventory.js'

const zigBinaryPlugin = definePlugin({
  id: 'zig-binary',
  name: 'Zig Binary Inventory',
  executionDomain: 'static',
  aspects: zigBinaryInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['zig', 'zig-binary', 'zig-archive', 'zig-object'],
      findings: [
        'zig',
        'zig.org',
        'ziglang',
        'build.zig',
        'build.zig.zon',
        '.zon',
        'std.io',
        'std.fmt',
        'std.mem',
        'std.os',
        '@import',
        '@embedFile',
        '@cImport',
        '@compileError',
        'page_allocator',
        'GeneralPurposeAllocator',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Zig binary inventory for ELF, PE, Mach-O, WASM, object, and archive artifacts, covering Zig mangled symbol candidates, zig compiler markers, build.zig.zon hints, panic/allocator/runtime markers, and target triples without demangling or execution.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...zigBinaryInventoryToolDefinition,
      handler: (args, deps) =>
        createZigBinaryInventoryHandler(deps as PluginToolDeps)(args as never) as never,
    }),
  ],
})

export default zigBinaryPlugin
