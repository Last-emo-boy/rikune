import { describe, expect, test } from '@jest/globals'
import teeEnclavePlugin from '../../src/plugins/tee-enclave/index.js'
import {
  TEE_ENCLAVE_ARTIFACT_TYPE,
  buildTeeEnclaveInventoryFromBuffer,
  createTeeEnclaveInventoryHandler,
  teeEnclaveInventoryToolDefinition,
} from '../../src/plugins/tee-enclave/tools/tee-enclave-inventory.js'

function elfFixture(strings: string[]): Buffer {
  const data = Buffer.alloc(0x1000, 0)
  data.write('\x7fELF', 0, 'binary')
  data[4] = 2
  data[5] = 1
  data.write(strings.join('\0'), 0x300, 'ascii')
  return data
}

describe('tee.enclave.inventory', () => {
  test('declares passive TEE enclave inventory metadata', () => {
    expect(teeEnclavePlugin.id).toBe('tee-enclave')
    expect(teeEnclavePlugin.executionDomain).toBe('static')
    expect(teeEnclavePlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['tee-enclave', 'sgx-enclave', 'optee-ta', 'tdx', 'sev-snp'])
    )
    expect(teeEnclaveInventoryToolDefinition.name).toBe('tee.enclave.inventory')
    expect(teeEnclaveInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)).toEqual(
      expect.arrayContaining([TEE_ENCLAVE_ARTIFACT_TYPE])
    )
    const recipe = teeEnclaveInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'tee.enclave-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['tee.enclave.inventory'],
        producesArtifacts: [TEE_ENCLAVE_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_enclave_load',
          'no_attestation_request',
          'no_quote_generation',
          'no_tee_driver_call',
          'no_external_tool',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'native.object.inventory',
        'compiler.codegen.fingerprint',
        'sbom.provenance.graph',
        'analysis.evidence.graph',
      ])
    )
  })

  test('summarizes SGX metadata, manifest, and ECALL/OCALL boundary hints', () => {
    const inventory = buildTeeEnclaveInventoryFromBuffer(
      elfFixture([
        '.note.sgxmeta',
        'SIGSTRUCT',
        'MRENCLAVE',
        'MRSIGNER',
        'sgx_ecall',
        'g_ecall_table',
        'g_ocall_table',
        'Enclave.config.xml',
        'isvsvn=0',
        'debug=true',
      ]),
      { filename: 'enclave.signed.so', sampleId: 'sha256:sgx' }
    )

    expect(inventory.format).toBe('sgx-enclave-candidate')
    expect(inventory.detected_by).toEqual(expect.arrayContaining(['family:sgx']))
    expect(inventory.enclave_families).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          family: 'sgx',
          confidence: 'high',
        }),
      ])
    )
    expect(inventory.attestation_hints).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'sgx.sigstruct' })])
    )
    expect(inventory.measurement_hints).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'sgx.mrenclave' })])
    )
    expect(inventory.boundary_hints).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'sgx.ecall-table' })])
    )
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'enclave.debug-enabled-marker' }),
        expect.objectContaining({ id: 'sgx.low-isvsvn-marker' }),
      ])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_enclave_load: true,
        no_attestation_request: true,
        no_quote_generation: true,
        no_tee_driver_call: true,
        no_network: true,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        enclave_loaded_by_tool: false,
        attestation_requested_by_tool: false,
        quote_generated_by_tool: false,
      })
    )
  })

  test('summarizes OP-TEE trusted application entrypoints and UUID hints', () => {
    const inventory = buildTeeEnclaveInventoryFromBuffer(
      Buffer.from(
        [
          'OP-TEE',
          '.ta_head',
          'TA_CreateEntryPoint',
          'TA_OpenSessionEntryPoint',
          'TA_InvokeCommandEntryPoint',
          'TEE_UUID',
          '12345678-1234-5678-9abc-def012345678',
          '__utee_entry',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'f04a0fe7-1f5d-4b9b-abf7-619b85b4ce8c.ta' }
    )

    expect(inventory.format).toBe('optee-trustzone-ta')
    expect(inventory.enclave_families).toEqual(
      expect.arrayContaining([expect.objectContaining({ family: 'optee', confidence: 'high' })])
    )
    expect(inventory.entrypoint_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'optee.create-entry' }),
        expect.objectContaining({ id: 'optee.invoke-entry' }),
      ])
    )
    expect(inventory.uuids).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ value: '12345678-1234-5678-9abc-def012345678' }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['native.object.inventory', 'compiler.codegen.fingerprint'])
    )
  })

  test('summarizes TDX and SEV-SNP attestation marker candidates without verification', () => {
    const inventory = buildTeeEnclaveInventoryFromBuffer(
      Buffer.from(
        [
          'Intel TDX',
          'TDREPORT',
          'TDQUOTE',
          'MRTD',
          'RTMR0',
          'SEV-SNP',
          'SNP_REPORT',
          'REPORT_DATA',
          'MEASUREMENT',
          'VCEK',
          'AUTHOR_KEY_DIGEST',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'attestation.bin' }
    )

    expect(inventory.enclave_families).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ family: 'tdx', confidence: 'high' }),
        expect.objectContaining({ family: 'sev-snp', confidence: 'high' }),
      ])
    )
    expect(inventory.attestation_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'tdx.report' }),
        expect.objectContaining({ id: 'sev.snp-report' }),
      ])
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        attestation_boundary: expect.objectContaining({
          verified_by_this_tool: false,
        }),
      })
    )
  })

  test('handles truncated ELF candidates without throwing', () => {
    const inventory = buildTeeEnclaveInventoryFromBuffer(Buffer.from('\x7fELF', 'binary'), {
      filename: 'truncated.enclave',
    })

    expect(inventory.container).toEqual(
      expect.objectContaining({
        kind: 'elf',
        bounded_preview: true,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        truncated: false,
      })
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createTeeEnclaveInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
