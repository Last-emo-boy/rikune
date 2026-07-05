import { describe, expect, test } from '@jest/globals'
import rustBinaryPlugin from '../../src/plugins/rust-binary/index.js'
import {
  RUST_BINARY_INVENTORY_ARTIFACT_TYPE,
  buildRustBinaryInventoryFromBuffer,
  createRustBinaryInventoryHandler,
  rustBinaryInventoryToolDefinition,
} from '../../src/plugins/rust-binary/tools/rust-binary-inventory.js'

function elfRustFixture(strings: string[]): Buffer {
  const data = Buffer.alloc(0x1800, 0)
  data.write('\x7fELF', 0, 'binary')
  data[4] = 2
  data[5] = 1
  data.writeUInt16LE(3, 0x10)
  data.writeUInt16LE(62, 0x12)
  data.write(strings.join('\0'), 0x300, 'ascii')
  return data
}

function peRustFixture(strings: string[]): Buffer {
  const data = Buffer.alloc(0x1000, 0)
  data.write('MZ', 0, 'ascii')
  data.writeUInt32LE(0x80, 0x3c)
  data.write('PE\0\0', 0x80, 'ascii')
  data.writeUInt16LE(0x8664, 0x84)
  data.writeUInt16LE(0xf0, 0x94)
  data.writeUInt16LE(0x20b, 0x98)
  data.write(strings.join('\0'), 0x300, 'ascii')
  return data
}

describe('rust.binary.inventory', () => {
  test('declares passive Rust binary metadata', () => {
    expect(rustBinaryPlugin.id).toBe('rust-binary')
    expect(rustBinaryPlugin.executionDomain).toBe('static')
    expect(rustBinaryPlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining([
        'rust-binary',
        'rustc',
        'cargo-crate',
        'rust-v0-mangled',
        'panic-unwind',
      ])
    )
    expect(rustBinaryInventoryToolDefinition.name).toBe('rust.binary.inventory')
    expect(rustBinaryInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)).toEqual(
      expect.arrayContaining([RUST_BINARY_INVENTORY_ARTIFACT_TYPE])
    )
    const recipe = rustBinaryInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'rust.binary-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['rust.binary.inventory'],
        producesArtifacts: [RUST_BINARY_INVENTORY_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_rustc_invocation',
          'no_cargo_invocation',
          'no_external_demangler',
          'no_network_by_default',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'compiler.codegen.fingerprint',
        'native.debug.types.inventory',
        'sbom.provenance.graph',
      ])
    )
  })

  test('summarizes ELF Rust v0 and legacy symbols with Cargo and panic evidence', () => {
    const inventory = buildRustBinaryInventoryFromBuffer(
      elfRustFixture([
        'rustc 1.84.1',
        'x86_64-unknown-linux-gnu',
        '_RNvCs1234567890abcdef_7mycrate4main',
        '_ZN4core3fmt5write17h0123456789abcdefE',
        '/home/build/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.217/src/lib.rs',
        '/rustc/abc123/library/std/src/rt.rs',
        'std::rt::lang_start',
        'core::panicking::panic_fmt',
        'rust_begin_unwind',
        'rust_eh_personality',
        '__rust_alloc',
        'tokio::runtime::scheduler',
      ]),
      { filename: 'agent.elf', sampleId: 'sha256:rust-elf' }
    )

    expect(inventory.format).toBe('elf-rust-binary-inventory')
    expect(inventory.confidence).toBe('high')
    expect(inventory.detected_by).toEqual(
      expect.arrayContaining(['rust-v0-mangled-symbol', 'rust-legacy-mangled-symbol'])
    )
    expect(inventory.rustc_candidates).toEqual(
      expect.arrayContaining([expect.objectContaining({ version: '1.84.1' })])
    )
    expect(inventory.target_triples).toEqual(
      expect.arrayContaining([expect.objectContaining({ triple: 'x86_64-unknown-linux-gnu' })])
    )
    expect(inventory.symbol_mangling).toEqual(
      expect.objectContaining({ v0_count: 1, legacy_count: 1, demangling_performed: false })
    )
    expect(inventory.crate_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'serde', version: '1.0.217' }),
        expect.objectContaining({ name: 'core' }),
        expect.objectContaining({ name: 'tokio' }),
      ])
    )
    expect(inventory.runtime_markers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'std.lang-start' }),
        expect.objectContaining({ id: 'rust.alloc' }),
      ])
    )
    expect(inventory.panic_profile).toEqual(
      expect.objectContaining({
        unwind_candidate: true,
        abort_candidate: false,
        panic_runtime: 'panic-unwind',
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_rustc_invocation: true,
        no_cargo_invocation: true,
        no_external_demangler: true,
        no_network: true,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        sample_executed_by_tool: false,
        rustc_invoked_by_tool: false,
        external_demangler_invoked_by_tool: false,
        network_used_by_tool: false,
      })
    )
  })

  test('rejects hostile legacy mangling candidates without backtracking', () => {
    const hostile = `${'_ZN0$'.repeat(400)}rustc 1.84.1`
    const inventory = buildRustBinaryInventoryFromBuffer(elfRustFixture([hostile]), {
      filename: 'hostile.elf',
      sampleId: 'sha256:hostile-rust',
    })

    expect(inventory.symbol_mangling.legacy_count).toBe(0)
    expect(inventory.detected_by).not.toContain('rust-legacy-mangled-symbol')
    expect(inventory.rustc_candidates).toEqual(
      expect.arrayContaining([expect.objectContaining({ version: '1.84.1' })])
    )
  })

  test('summarizes Windows Rust allocator, target, ecosystem, and panic-abort hints', () => {
    const inventory = buildRustBinaryInventoryFromBuffer(
      peRustFixture([
        'x86_64-pc-windows-msvc',
        '_RNvNtCsfeedfacecafebeef_5clap7builder',
        '__rust_alloc',
        '__rust_dealloc',
        'panic_abort',
        'serde_json',
        'clap_builder',
      ]),
      { filename: 'agent.exe', sampleId: 'sha256:rust-pe' }
    )

    expect(inventory.format).toBe('pe-rust-binary-inventory')
    expect(inventory.container.kind).toBe('pe')
    expect(inventory.target_triples).toEqual(
      expect.arrayContaining([expect.objectContaining({ triple: 'x86_64-pc-windows-msvc' })])
    )
    expect(inventory.ecosystem_markers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ crate: 'serde' }),
        expect.objectContaining({ crate: 'clap' }),
      ])
    )
    expect(inventory.panic_profile).toEqual(
      expect.objectContaining({
        abort_candidate: true,
        panic_runtime: 'panic-abort',
      })
    )
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'rust.panic-abort-candidate' })])
    )
  })

  test('keeps unrelated raw input low confidence and candidate-only', () => {
    const inventory = buildRustBinaryInventoryFromBuffer(
      Buffer.from('plain C binary strings without language runtime markers', 'ascii'),
      { filename: 'plain.bin', sampleId: 'sha256:plain' }
    )

    expect(inventory.format).toBe('rust-binary-unconfirmed')
    expect(inventory.confidence).toBe('low')
    expect(inventory.symbol_mangling.total_count).toBe(0)
    expect(inventory.rustc_candidates).toHaveLength(0)
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({ candidate_only: true, total_evidence: 0 })
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createRustBinaryInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
