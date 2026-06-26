/**
 * TEE Enclave Inventory Plugin
 *
 * Passive confidential-computing and TEE enclave artifact inventory. It reads
 * bounded bytes only and never loads an enclave, requests attestation, calls
 * TEE/kernel drivers, starts a debugger/emulator, accesses the network, or
 * mutates samples.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createTeeEnclaveInventoryHandler,
  teeEnclaveInventoryAspects,
  teeEnclaveInventoryToolDefinition,
} from './tools/tee-enclave-inventory.js'

const teeEnclavePlugin = definePlugin({
  id: 'tee-enclave',
  name: 'TEE Enclave Inventory',
  executionDomain: 'static',
  aspects: teeEnclaveInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'tee-enclave',
        'confidential-computing',
        'tee',
        'enclave',
        'sgx',
        'sgx-enclave',
        'open-enclave',
        'sgx-sigstruct',
        'sigstruct',
        'mrenclave',
        'optee',
        'optee-ta',
        'op-tee',
        'op-tee-ta',
        'tee-ta',
        'trusted-application',
        'trustlet',
        'trustzone',
        'trustzone-ta',
        'tdx',
        'tdx-module',
        'tdx-quote',
        'tdvf',
        'sev',
        'sev-snp',
        'snp-attestation',
        'keystone-enclave',
        'riscv-enclave',
        'enclave-manifest',
        'elf',
        'pe',
        'efi',
        'firmware',
      ],
      findings: [
        'SGX',
        'SIGSTRUCT',
        'MRENCLAVE',
        'MRSIGNER',
        'sgx_ecall',
        'oe_create_enclave',
        'oe_get_evidence',
        'g_ecall_table',
        'OP-TEE',
        'TA_CreateEntryPoint',
        'TA_InvokeCommandEntryPoint',
        'TEE_UUID',
        'TEEC_InvokeCommand',
        'TDREPORT',
        'TDQUOTE',
        'TDX_CMD_GET_REPORT0',
        'RTMR',
        'SEV-SNP',
        'SNP_REPORT',
        'SNP_GET_REPORT',
        'VCEK',
        'Keystone enclave',
        'PLenclave_attest',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive confidential-computing and TEE enclave inventory for SGX, OP-TEE/TrustZone TA, TDX, AMD SEV-SNP, and RISC-V enclave static evidence, attestation hints, manifest markers, and workflow routing.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...teeEnclaveInventoryToolDefinition,
      handler: (args, deps) => createTeeEnclaveInventoryHandler(deps)(args as never),
    }),
  ],
})

export default teeEnclavePlugin
