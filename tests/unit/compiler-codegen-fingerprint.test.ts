import { describe, expect, test } from '@jest/globals'
import compilerCodegenPlugin from '../../src/plugins/compiler-codegen/index.js'
import {
  COMPILER_CODEGEN_FINGERPRINT_ARTIFACT_TYPE,
  buildCompilerCodegenFingerprintFromBuffer,
  compilerCodegenFingerprintToolDefinition,
  createCompilerCodegenFingerprintHandler,
} from '../../src/plugins/compiler-codegen/tools/compiler-codegen-fingerprint.js'

function peFixture(strings: string[]): Buffer {
  const data = Buffer.alloc(0x800, 0)
  data.write('MZ', 0, 'ascii')
  data.writeUInt32LE(0x80, 0x3c)
  data.write('DanS', 0x40, 'ascii')
  data.write('Rich', 0x58, 'ascii')
  data.write('PE\0\0', 0x80, 'ascii')
  data.writeUInt16LE(0x8664, 0x84)
  data.writeUInt16LE(2, 0x86)
  data.writeUInt32LE(0x66112233, 0x88)
  data.writeUInt16LE(0xf0, 0x94)
  data.writeUInt16LE(0x20b, 0x98)
  data[0x9a] = 14
  data[0x9b] = 38

  const sectionTable = 0x80 + 24 + 0xf0
  data.write('.text', sectionTable, 'ascii')
  data.writeUInt32LE(0x100, sectionTable + 8)
  data.writeUInt32LE(0x1000, sectionTable + 12)
  data.writeUInt32LE(0x100, sectionTable + 16)
  data.writeUInt32LE(0x400, sectionTable + 20)
  data.write('.rdata', sectionTable + 40, 'ascii')
  data.writeUInt32LE(0x200, sectionTable + 48)
  data.writeUInt32LE(0x2000, sectionTable + 52)
  data.writeUInt32LE(0x200, sectionTable + 56)
  data.writeUInt32LE(0x500, sectionTable + 60)

  data.write(strings.join('\0'), 0x500, 'ascii')
  return data
}

describe('compiler.codegen.fingerprint', () => {
  test('declares passive compiler/codegen fingerprint metadata', () => {
    expect(compilerCodegenPlugin.id).toBe('compiler-codegen')
    expect(compilerCodegenPlugin.executionDomain).toBe('static')
    expect(compilerCodegenPlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining([
        'compiler-codegen',
        'compiler-provenance',
        'rich-header',
        'codeview',
        'pe',
        'elf',
        'macho',
      ])
    )
    expect(compilerCodegenFingerprintToolDefinition.name).toBe('compiler.codegen.fingerprint')
    expect(
      compilerCodegenFingerprintToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toEqual(expect.arrayContaining([COMPILER_CODEGEN_FINGERPRINT_ARTIFACT_TYPE]))
    const recipe = compilerCodegenFingerprintToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'compiler.codegen-fingerprint-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['compiler.codegen.fingerprint'],
        producesArtifacts: [COMPILER_CODEGEN_FINGERPRINT_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_compiler_invocation',
          'no_linker_invocation',
          'no_external_tool',
          'no_symbol_server_download',
          'no_source_fetch',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'native.debug.types.inventory',
        'windows.debug.metadata.inspect',
        'compiler.packer.detect',
        'sbom.provenance.graph',
      ])
    )
  })

  test('summarizes MSVC Rich, CodeView, runtime, and linker evidence', () => {
    const inventory = buildCompilerCodegenFingerprintFromBuffer(
      peFixture([
        'RSDS',
        'C:\\build\\widget.pdb',
        '__CxxFrameHandler4',
        '__security_cookie',
        'Microsoft (R) Incremental Linker Version 14.38',
        'vcruntime140.dll',
      ]),
      { filename: 'widget.exe', sampleId: 'sha256:msvc' }
    )

    expect(inventory.container.kind).toBe('pe')
    expect(inventory.detected_by).toEqual(
      expect.arrayContaining(['pe-rich-header', 'codeview', 'msvc-runtime'])
    )
    expect(inventory.compiler_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          family: 'msvc',
          confidence: 'high',
        }),
      ])
    )
    expect(inventory.linker_candidates).toEqual(
      expect.arrayContaining([expect.objectContaining({ family: 'ms-link' })])
    )
    expect(inventory.codegen_features).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'pe-rich-header-marker' }),
        expect.objectContaining({ name: 'pe-codeview-marker' }),
      ])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_compiler_invocation: true,
        no_linker_invocation: true,
        no_external_tool: true,
        no_network: true,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        sample_executed_by_tool: false,
        compiler_or_linker_invoked_by_tool: false,
        external_tool_invoked_by_tool: false,
        symbol_server_contacted_by_tool: false,
        network_used_by_tool: false,
      })
    )
  })

  test('summarizes GCC, Clang, LTO, and PGO evidence without packer attribution', () => {
    const inventory = buildCompilerCodegenFingerprintFromBuffer(
      Buffer.from(
        [
          'GCC: (GNU) 13.2.1',
          'clang version 18.1.8',
          '.llvm_addrsig',
          'thinlto',
          '__llvm_prf_cnts',
          '__profc_main',
          'GNU ld 2.42',
        ].join('\0'),
        'utf8'
      ),
      { filename: 'libsample.so', sampleId: 'sha256:llvm' }
    )

    expect(inventory.compiler_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ family: 'gcc' }),
        expect.objectContaining({ family: 'clang' }),
      ])
    )
    expect(inventory.linker_candidates).toEqual(
      expect.arrayContaining([expect.objectContaining({ family: 'gnu-ld' })])
    )
    expect(inventory.optimization_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'lto' }),
        expect.objectContaining({ kind: 'pgo' }),
      ])
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        packer_detector_boundary: expect.objectContaining({
          tool: 'compiler.packer.detect',
          this_tool_focus: 'code-generation and toolchain provenance evidence',
        }),
      })
    )
  })

  test('summarizes language runtime hints for Go and Rust candidates', () => {
    const inventory = buildCompilerCodegenFingerprintFromBuffer(
      Buffer.from(
        ['Go build ID: abcdef', 'runtime.goexit', 'rustc 1.78.0', 'core::panicking'].join('\0'),
        'utf8'
      ),
      { filename: 'agent.bin', sampleId: 'sha256:runtime' }
    )

    expect(inventory.language_runtime_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ family: 'go', confidence: 'high' }),
        expect.objectContaining({ family: 'rust', confidence: 'high' }),
      ])
    )
    expect(inventory.codegen_features).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'go-runtime-provenance' }),
        expect.objectContaining({ name: 'rust-runtime-provenance' }),
      ])
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createCompilerCodegenFingerprintHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
