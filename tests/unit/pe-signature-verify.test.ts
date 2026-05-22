import { describe, expect, test } from '@jest/globals'
import {
  peSignatureVerifyToolDefinition,
  peSignatureVerifyOutputSchema,
} from '../../src/plugins/pe-signature/tools/pe-signature-verify.js'
import { peCertificateExtractToolDefinition } from '../../src/plugins/pe-signature/tools/pe-certificate-extract.js'
import { buildWindowsDebugMetadataFromBuffer } from '../../src/plugins/windows-debug-symbols/tools/windows-debug-metadata-inspect.js'

describe('pe.signature.verify', () => {
  test('declares passive Authenticode schemas, aspects, artifacts, and evidence', () => {
    expect(peSignatureVerifyToolDefinition.name).toBe('pe.signature.verify')
    expect(peSignatureVerifyToolDefinition.outputSchema).toBe(peSignatureVerifyOutputSchema)
    expect(peSignatureVerifyToolDefinition.aspects).toEqual(
      expect.objectContaining({
        formats: expect.arrayContaining(['pe', 'pe-clr']),
        platforms: expect.arrayContaining(['windows']),
        execution: expect.arrayContaining(['static', 'triage']),
        safety: expect.arrayContaining(['passive', 'no_network_by_default']),
      })
    )
    expect(peSignatureVerifyToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
      'backend_pe-sig_verify'
    )
    expect(peSignatureVerifyToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining(['signatures', 'certificates'])
    )
  })

  test('declares certificate extraction output without symbol-server or network dependence', () => {
    expect(peCertificateExtractToolDefinition.name).toBe('pe.certificate.extract')
    expect(peCertificateExtractToolDefinition.outputSchema).toBeDefined()
    expect(peCertificateExtractToolDefinition.aspects?.safety).toContain('no_network_by_default')
    expect(peCertificateExtractToolDefinition.evidence?.[0].category).toBe('certificates')
  })

  test('represents PDB and COFF metadata as passive no-download inventory', () => {
    const pdb = buildWindowsDebugMetadataFromBuffer(
      Buffer.concat([Buffer.from('Microsoft C/C++ MSF 7.00\r\n', 'ascii'), Buffer.alloc(64)]),
      { filename: 'demo.pdb' }
    )
    const coff = Buffer.alloc(20)
    coff.writeUInt16LE(0x8664, 0)
    coff.writeUInt16LE(3, 2)
    coff.writeUInt32LE(0x40, 8)
    coff.writeUInt32LE(4, 12)
    const coffInventory = buildWindowsDebugMetadataFromBuffer(coff, { filename: 'demo.obj' })

    expect(pdb.format).toBe('pdb')
    expect(coffInventory.format).toBe('coff')
    expect(coffInventory.header).toEqual(
      expect.objectContaining({ architecture_hint: 'x64', section_count: 3, symbol_count: 4 })
    )
    expect([pdb, coffInventory].every((item) => item.policy.no_symbol_server_download)).toBe(true)
    expect(pdb.source_map_plan.status).toBe('plan_only')
  })
})
