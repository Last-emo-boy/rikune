/**
 * Rust Binary Inventory Plugin
 *
 * Passive Rust language/runtime metadata inventory for native binaries and
 * object artifacts. It reads bounded bytes only and never invokes rustc,
 * cargo, external demanglers, native loaders, runtimes, networks, or mutation.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createRustBinaryInventoryHandler,
  rustBinaryInventoryAspects,
  rustBinaryInventoryToolDefinition,
} from './tools/rust-binary-inventory.js'

const rustBinaryPlugin = definePlugin({
  id: 'rust-binary',
  name: 'Rust Binary Inventory',
  executionDomain: 'static',
  aspects: rustBinaryInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'rust-binary',
        'rust',
        'rustc',
        'cargo',
        'cargo-crate',
        'rust-crate',
        'rust-mangled',
        'rust-v0-mangled',
        'rust-legacy-mangled',
        'panic-unwind',
        'panic-abort',
        'rlib',
        'rmeta',
      ],
      findings: [
        'rustc',
        'Cargo.toml',
        '.cargo/registry',
        'core::panicking',
        'std::rt::lang_start',
        '__rust_alloc',
        'rust_begin_unwind',
        'rust_eh_personality',
        'panic_unwind',
        'panic_abort',
        '_RNv',
        '_ZN4core',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Rust binary inventory for ELF, PE, Mach-O, object, rlib, and rmeta artifacts, covering Rust v0/legacy mangled symbols, rustc/Cargo/crate hints, panic/unwind profile, allocator/runtime markers, and target triples without demangling or execution.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...rustBinaryInventoryToolDefinition,
      handler: (args, deps) => createRustBinaryInventoryHandler(deps)(args as never),
    }),
  ],
})

export default rustBinaryPlugin
