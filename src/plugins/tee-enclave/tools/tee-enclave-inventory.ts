/**
 * tee.enclave.inventory - passive TEE/confidential-computing inventory.
 *
 * This tool reads bounded bytes and summarizes static evidence for SGX, OP-TEE
 * / TrustZone trusted applications, Intel TDX, AMD SEV-SNP, and RISC-V enclave
 * ecosystems. It never loads enclaves, requests quotes, talks to TEE drivers,
 * derives keys, executes samples, invokes debuggers/emulators, accesses the
 * network, or mutates samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'tee.enclave.inventory'
export const TEE_ENCLAVE_ARTIFACT_TYPE = 'tee_enclave_inventory'

const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 8000
const MAX_EVIDENCE = 420
const MAX_UUIDS = 96

type Confidence = 'low' | 'medium' | 'high'
type Encoding = 'ascii' | 'utf16le'
type Family = 'sgx' | 'optee' | 'tdx' | 'sev-snp' | 'riscv-enclave' | 'trustzone'

interface BinaryString {
  value: string
  offset: number
  encoding: Encoding
}

type EvidenceSource = BinaryString | { value: string; offset: number; encoding: 'section' }

interface EvidenceRule {
  id: string
  family: Family
  kind:
    | 'section'
    | 'api'
    | 'entrypoint'
    | 'table'
    | 'attestation'
    | 'measurement'
    | 'manifest'
    | 'runtime'
    | 'string'
  confidence: Confidence
  pattern: RegExp
}

interface EvidenceItem {
  id: string
  family: Family
  kind: EvidenceRule['kind']
  value: string
  offset: number
  encoding: Encoding | 'section'
  confidence: Confidence
}

interface BuildOptions {
  filename?: string
  sampleId?: string
  maxReadBytes?: number
  totalSize?: number
}

const TEE_EVIDENCE = [
  'structure',
  'strings',
  'manifest',
  'attestation',
  'measurement',
  'entrypoints',
  'boundary',
  'provenance',
  'workflow',
]

const TEE_SAFETY = [
  'passive',
  'no_execute',
  'no_enclave_load',
  'no_attestation_request',
  'no_quote_generation',
  'no_tee_driver_call',
  'no_kernel_driver_call',
  'no_key_derivation',
  'no_debugger',
  'no_emulation',
  'no_external_tool',
  'no_network_by_default',
  'no_mutation',
]

const TEE_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'native.object.inventory',
  'native.debug.types.inventory',
  'compiler.codegen.fingerprint',
  'elf.structure.analyze',
  'pe.structure.analyze',
  'strings.extract',
  'sbom.provenance.graph',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const TeePolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_enclave_load: z.literal(true),
  no_attestation_request: z.literal(true),
  no_quote_generation: z.literal(true),
  no_tee_driver_call: z.literal(true),
  no_kernel_driver_call: z.literal(true),
  no_key_derivation: z.literal(true),
  no_debugger: z.literal(true),
  no_emulation: z.literal(true),
  no_external_tool: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const TeeEnclaveInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.any()),
  enclave_families: z.array(z.record(z.any())),
  attestation_hints: z.array(z.record(z.any())),
  measurement_hints: z.array(z.record(z.any())),
  entrypoint_hints: z.array(z.record(z.any())),
  manifest_hints: z.array(z.record(z.any())),
  boundary_hints: z.array(z.record(z.any())),
  uuids: z.array(z.record(z.any())),
  risk_flags: z.array(z.record(z.any())),
  runtime_risk: z.record(z.any()),
  policy: TeePolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const TeeEnclaveInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive TEE/enclave inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist TEE/enclave inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const TeeEnclaveInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: TeeEnclaveInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const teeEnclaveInventoryAspects = {
  formats: [
    'tee-enclave',
    'confidential-computing',
    'enclave',
    'sgx',
    'sgx-enclave',
    'open-enclave',
    'sigstruct',
    'mrenclave',
    'mrsigner',
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
    'tdx-quote',
    'tdreport',
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
  platforms: ['linux', 'windows', 'firmware', 'embedded', 'riscv', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'riscv'],
  execution: ['static', 'triage', 'correlation', 'trust-boundary', 'workflow-plan'],
  safety: TEE_SAFETY,
  capabilities: [
    'tee-enclave-inventory',
    'sgx-enclave-metadata-hints',
    'optee-ta-metadata-hints',
    'tdx-attestation-hints',
    'sev-snp-attestation-hints',
    'riscv-enclave-hints',
    'open-enclave-hints',
    'enclave-manifest-inventory',
    'measurement-provenance-hints',
    'enclave-boundary-risk-routing',
    'workflow-routing',
  ],
  evidence: TEE_EVIDENCE,
  route_terms: [
    'tee enclave',
    'confidential computing',
    'secure enclave',
    'sgx',
    'sigstruct',
    'mrenclave',
    'mrsigner',
    'sgx ecall ocall',
    'open enclave evidence',
    'op-tee',
    'trustzone trusted application',
    'tee uuid',
    'tdx quote',
    'tdreport',
    'rtmr',
    'sev-snp attestation report',
    'vcek',
    'keystone enclave',
    'riscv enclave',
  ],
  search: [
    'SGX enclave SIGSTRUCT MRENCLAVE static inventory',
    'OP-TEE TrustZone trusted application UUID entrypoint inventory',
    'TDX SEV-SNP attestation marker triage',
    'confidential computing enclave manifest and boundary hints',
  ],
}

const EVIDENCE_RULES: EvidenceRule[] = [
  {
    id: 'sgx.sigstruct',
    family: 'sgx',
    kind: 'attestation',
    confidence: 'high',
    pattern: /\bSIGSTRUCT\b/i,
  },
  {
    id: 'sgx.mrenclave',
    family: 'sgx',
    kind: 'measurement',
    confidence: 'high',
    pattern: /\bMRENCLAVE\b/i,
  },
  {
    id: 'sgx.mrsigner',
    family: 'sgx',
    kind: 'measurement',
    confidence: 'high',
    pattern: /\bMRSIGNER\b/i,
  },
  {
    id: 'sgx.section',
    family: 'sgx',
    kind: 'section',
    confidence: 'high',
    pattern: /\.note\.sgxmeta|\.sgxmeta/i,
  },
  {
    id: 'sgx.ecall-table',
    family: 'sgx',
    kind: 'table',
    confidence: 'high',
    pattern: /\bg_ecall_table\b|\bsgx_ecall\b/i,
  },
  {
    id: 'sgx.ocall-table',
    family: 'sgx',
    kind: 'table',
    confidence: 'medium',
    pattern: /\bg_ocall_table\b|\bsgx_ocall\b/i,
  },
  {
    id: 'sgx.host-create',
    family: 'sgx',
    kind: 'api',
    confidence: 'medium',
    pattern: /\bsgx_create_enclave\b|\bsgx_destroy_enclave\b/i,
  },
  {
    id: 'sgx.quote-api',
    family: 'sgx',
    kind: 'attestation',
    confidence: 'medium',
    pattern: /\bsgx_qe_get_quote\b|\bsgx_get_quote\b|\bsgx_quote\b/i,
  },
  {
    id: 'sgx.runtime',
    family: 'sgx',
    kind: 'runtime',
    confidence: 'medium',
    pattern: /\bsgx_(trts|urts|tstdc|tcrypto)\b/i,
  },
  {
    id: 'sgx.manifest',
    family: 'sgx',
    kind: 'manifest',
    confidence: 'medium',
    pattern: /Enclave\.config\.xml|isvsvn|prodid|heapmaxsize|stackmaxsize/i,
  },
  {
    id: 'sgx.debug-manifest',
    family: 'sgx',
    kind: 'manifest',
    confidence: 'medium',
    pattern: /debug\s*=\s*(true|1)|SGX_DEBUG_FLAG|DEBUG_ENCLAVE/i,
  },
  {
    id: 'sgx.instruction',
    family: 'sgx',
    kind: 'string',
    confidence: 'medium',
    pattern: /\bEENTER\b|\bEEXIT\b|\bEINIT\b|\bECREATE\b|\bEEXTEND\b/i,
  },
  {
    id: 'open-enclave.runtime',
    family: 'sgx',
    kind: 'runtime',
    confidence: 'medium',
    pattern:
      /\boe_create_enclave\b|\boe_get_evidence\b|\boe_verify_evidence\b|\bOE_ENCLAVE_TYPE_SGX\b/i,
  },
  {
    id: 'open-enclave.format',
    family: 'sgx',
    kind: 'attestation',
    confidence: 'medium',
    pattern: /\bOE_FORMAT_UUID_SGX_ECDSA\b|\bOE_FORMAT_UUID_SGX_LOCAL_ATTESTATION\b/i,
  },

  {
    id: 'optee.brand',
    family: 'optee',
    kind: 'string',
    confidence: 'high',
    pattern: /\bOP-TEE\b|\boptee\b/i,
  },
  {
    id: 'optee.ta-head',
    family: 'optee',
    kind: 'section',
    confidence: 'high',
    pattern: /\.ta_head|user_ta_header/i,
  },
  {
    id: 'optee.create-entry',
    family: 'optee',
    kind: 'entrypoint',
    confidence: 'high',
    pattern: /\bTA_CreateEntryPoint\b/i,
  },
  {
    id: 'optee.invoke-entry',
    family: 'optee',
    kind: 'entrypoint',
    confidence: 'high',
    pattern: /\bTA_InvokeCommandEntryPoint\b/i,
  },
  {
    id: 'optee.session-entry',
    family: 'optee',
    kind: 'entrypoint',
    confidence: 'medium',
    pattern: /\bTA_OpenSessionEntryPoint\b|\bTA_CloseSessionEntryPoint\b/i,
  },
  {
    id: 'optee.uuid',
    family: 'optee',
    kind: 'manifest',
    confidence: 'medium',
    pattern: /\bTA_UUID\b|\bTEE_UUID\b|\bGP_TA\b/i,
  },
  {
    id: 'optee.utee',
    family: 'optee',
    kind: 'api',
    confidence: 'medium',
    pattern: /\b__utee_entry\b|\but?ee_|\bTEE_InvokeTACommand\b/i,
  },
  {
    id: 'optee.ta-props',
    family: 'optee',
    kind: 'manifest',
    confidence: 'medium',
    pattern: /\bTA_FLAGS\b|\bTA_DATA_SIZE\b|\bTA_STACK_SIZE\b|\bgpd\.ta\.appID\b/i,
  },

  {
    id: 'trustzone.brand',
    family: 'trustzone',
    kind: 'string',
    confidence: 'medium',
    pattern: /\bTrustZone\b|\bTEE Client API\b|\bGlobalPlatform TEE\b/i,
  },
  {
    id: 'trustzone.client-api',
    family: 'trustzone',
    kind: 'api',
    confidence: 'medium',
    pattern: /\bTEEC_InvokeCommand\b|\bTEEC_OpenSession\b|\bTEEC_InitializeContext\b/i,
  },

  {
    id: 'tdx.brand',
    family: 'tdx',
    kind: 'string',
    confidence: 'high',
    pattern: /\bTDX\b|\bIntel TDX\b/i,
  },
  {
    id: 'tdx.report',
    family: 'tdx',
    kind: 'attestation',
    confidence: 'high',
    pattern: /\bTDREPORT\b|\bTDQUOTE\b|\bTD Quote\b/i,
  },
  {
    id: 'tdx.measurement',
    family: 'tdx',
    kind: 'measurement',
    confidence: 'high',
    pattern: /\bMRTD\b|\bMRSEAM\b|\bRTMR[0-3]?\b/i,
  },
  {
    id: 'tdx.call',
    family: 'tdx',
    kind: 'api',
    confidence: 'medium',
    pattern: /\bTDCALL\b|\bSEAMCALL\b|\bTDG\.MR\.REPORT\b/i,
  },
  {
    id: 'tdx.device',
    family: 'tdx',
    kind: 'api',
    confidence: 'medium',
    pattern: /\/dev\/tdx-guest|\bTDX_CMD_GET_REPORT0\b/i,
  },
  {
    id: 'tdx.firmware',
    family: 'tdx',
    kind: 'manifest',
    confidence: 'medium',
    pattern: /\bTDVF\b|\bOVMF\b/i,
  },

  {
    id: 'sev.snp-brand',
    family: 'sev-snp',
    kind: 'string',
    confidence: 'high',
    pattern: /\bSEV-SNP\b|\bAMD SEV\b|\bSNP\b/i,
  },
  {
    id: 'sev.snp-report',
    family: 'sev-snp',
    kind: 'attestation',
    confidence: 'high',
    pattern:
      /\bSNP_REPORT\b|\bATTESTATION_REPORT\b|\bREPORT_DATA\b|\bSNP_GET_REPORT\b|\bSNP_GET_EXT_REPORT\b/i,
  },
  {
    id: 'sev.snp-measurement',
    family: 'sev-snp',
    kind: 'measurement',
    confidence: 'high',
    pattern: /\bMEASUREMENT\b|\bHOST_DATA\b|\bID_KEY_DIGEST\b|\bAUTHOR_KEY_DIGEST\b/i,
  },
  {
    id: 'sev.snp-cert',
    family: 'sev-snp',
    kind: 'attestation',
    confidence: 'medium',
    pattern: /\bVCEK\b|\bASK\b|\bARK\b|\bchip_id\b/i,
  },
  {
    id: 'sev.snp-vmpl',
    family: 'sev-snp',
    kind: 'manifest',
    confidence: 'medium',
    pattern: /\bVMPL\b|\blaunch_digest\b|\bVMPCK\b/i,
  },
  {
    id: 'sev.snp-device',
    family: 'sev-snp',
    kind: 'api',
    confidence: 'medium',
    pattern: /\/dev\/sev-guest|\bSNP_GET_DERIVED_KEY\b|\bGHCB\b/i,
  },

  {
    id: 'riscv.keystone',
    family: 'riscv-enclave',
    kind: 'string',
    confidence: 'high',
    pattern: /\bKeystone\b|\bKeystone Enclave\b/i,
  },
  {
    id: 'riscv.keystone-entry',
    family: 'riscv-enclave',
    kind: 'entrypoint',
    confidence: 'medium',
    pattern: /\bEAPP_ENTRY\b|\bEAPP_RETURN\b|\bedge_init\b|\beyrie-rt\b/i,
  },
  {
    id: 'riscv.penglai',
    family: 'riscv-enclave',
    kind: 'string',
    confidence: 'medium',
    pattern: /\bPenglai\b|\bPENGLAI_SDK\b|\beapp\b/i,
  },
  {
    id: 'riscv.penglai-api',
    family: 'riscv-enclave',
    kind: 'api',
    confidence: 'medium',
    pattern: /\bPLenclave_(create|run|attest)\b|\benclave_args\b/i,
  },
  {
    id: 'riscv.report',
    family: 'riscv-enclave',
    kind: 'attestation',
    confidence: 'medium',
    pattern: /\bSM_REPORT\b|\battest_enclave\b/i,
  },
  {
    id: 'riscv.sbi',
    family: 'riscv-enclave',
    kind: 'api',
    confidence: 'medium',
    pattern: /\bsbi_ecall\b|\bocall\b/i,
  },
]

export const teeEnclaveInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory confidential-computing and TEE enclave evidence across SGX, OP-TEE/TrustZone TA, TDX, AMD SEV-SNP, and RISC-V enclave artifacts without enclave loading, attestation requests, driver calls, execution, emulation, or external tools.',
  inputSchema: TeeEnclaveInventoryInputSchema,
  outputSchema: TeeEnclaveInventoryOutputSchema,
  aspects: teeEnclaveInventoryAspects,
  artifacts: [
    {
      type: TEE_ENCLAVE_ARTIFACT_TYPE,
      description: 'Passive confidential-computing and TEE enclave static evidence inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: TEE_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [TEE_ENCLAVE_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'tee.enclave-static-inventory',
      title: 'TEE enclave static inventory',
      description:
        'Inventory SGX, OP-TEE/TrustZone, TDX, SEV-SNP, and RISC-V enclave static evidence before routing to object metadata, compiler provenance, evidence graph, and reporting tools.',
      startsWith: [TOOL_NAME],
      nextTools: [
        'native.object.inventory',
        'native.debug.types.inventory',
        'compiler.codegen.fingerprint',
        'strings.extract',
        'sbom.provenance.graph',
        'analysis.evidence.graph',
        'report.generate',
        'workflow.search',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [TEE_ENCLAVE_ARTIFACT_TYPE],
      evidence: TEE_EVIDENCE,
      safety: TEE_SAFETY,
    },
  ],
}

function confidenceWeight(confidence: Confidence): number {
  if (confidence === 'high') return 4
  if (confidence === 'medium') return 2
  return 1
}

function toConfidence(score: number, highEvidence: number): Confidence {
  if (score >= 8 || highEvidence >= 2) return 'high'
  if (score >= 4 || highEvidence >= 1) return 'medium'
  return 'low'
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)))
}

function extractAsciiStrings(data: Buffer): BinaryString[] {
  const results: BinaryString[] = []
  let start = -1
  for (let i = 0; i <= data.length; i += 1) {
    const byte = i < data.length ? data[i] : 0
    const printable = byte >= 0x20 && byte <= 0x7e
    if (printable && start === -1) start = i
    if ((!printable || i === data.length) && start !== -1) {
      const length = i - start
      if (length >= 4) {
        results.push({ value: data.toString('ascii', start, i), offset: start, encoding: 'ascii' })
        if (results.length >= MAX_STRINGS) return results
      }
      start = -1
    }
  }
  return results
}

function extractUtf16Strings(data: Buffer): BinaryString[] {
  const results: BinaryString[] = []
  let start = -1
  for (let i = 0; i + 1 <= data.length; i += 2) {
    const lo = data[i]
    const hi = data[i + 1]
    const printable = hi === 0 && lo >= 0x20 && lo <= 0x7e
    if (printable && start === -1) start = i
    if ((!printable || i + 1 >= data.length) && start !== -1) {
      const end = printable ? i + 2 : i
      const length = (end - start) / 2
      if (length >= 4) {
        results.push({
          value: data.toString('utf16le', start, end),
          offset: start,
          encoding: 'utf16le',
        })
        if (results.length >= Math.floor(MAX_STRINGS / 3)) return results
      }
      start = -1
    }
  }
  return results
}

function extractStrings(data: Buffer): BinaryString[] {
  return [...extractAsciiStrings(data), ...extractUtf16Strings(data)].slice(0, MAX_STRINGS)
}

function readCString(data: Buffer, offset: number, maxLength: number): string {
  let end = offset
  const limit = Math.min(data.length, offset + maxLength)
  while (end < limit && data[end] !== 0) end += 1
  return data
    .toString('ascii', offset, end)
    .replace(/[^\x20-\x7e]/g, '')
    .trim()
}

function detectContainer(data: Buffer, filename?: string): Record<string, unknown> {
  const lowerName = filename?.toLowerCase() ?? ''
  const container: Record<string, unknown> = {
    kind: 'raw',
    filename_extension: lowerName.includes('.') ? lowerName.split('.').pop() : undefined,
    sections: [],
    bounded_preview: true,
  }

  if (data.length >= 4 && data.toString('ascii', 0, 4) === '\x7fELF') {
    container.kind = 'elf'
    container.bits = data[4] === 2 ? 64 : data[4] === 1 ? 32 : 'unknown'
    container.endianness = data[5] === 2 ? 'be' : 'le'
    container.sections = extractElfSections(data)
    return container
  }

  if (data.length >= 0x40 && data.toString('ascii', 0, 2) === 'MZ') {
    container.kind = 'pe'
    const peOffset = data.readUInt32LE(0x3c)
    if (
      peOffset > 0 &&
      peOffset + 24 < data.length &&
      data.toString('ascii', peOffset, peOffset + 4) === 'PE\0\0'
    ) {
      const sections = data.readUInt16LE(peOffset + 6)
      const optSize = data.readUInt16LE(peOffset + 20)
      container.sections = extractPeSections(data, peOffset + 24 + optSize, sections)
      container.machine = `0x${data.readUInt16LE(peOffset + 4).toString(16)}`
    }
    return container
  }

  if (data.length >= 4) {
    const magic = data.readUInt32BE(0)
    if ([0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcafebabf].includes(magic)) {
      container.kind = 'macho'
      container.magic = `0x${magic.toString(16)}`
      return container
    }
  }

  if (lowerName.endsWith('.ta')) container.kind = 'optee-ta'
  if (lowerName.endsWith('.sigstruct')) container.kind = 'sgx-sigstruct'
  if (lowerName.includes('quote')) container.kind = 'attestation-quote'
  return container
}

function extractPeSections(data: Buffer, sectionTable: number, sectionCount: number): string[] {
  const sections: string[] = []
  for (let i = 0; i < Math.min(sectionCount, 96); i += 1) {
    const offset = sectionTable + i * 40
    if (offset + 40 > data.length) break
    const name = readCString(data, offset, 8)
    if (name) sections.push(name)
  }
  return uniqueStrings(sections)
}

function extractElfSections(data: Buffer): string[] {
  const is64 = data[4] === 2
  const little = data[5] !== 2
  const headerSize = is64 ? 0x40 : 0x34
  if (data.length < headerSize) return []
  if (!little) return []
  const shoff = is64 ? Number(data.readBigUInt64LE(0x28)) : data.readUInt32LE(0x20)
  const shentsize = is64 ? data.readUInt16LE(0x3a) : data.readUInt16LE(0x2e)
  const shnum = is64 ? data.readUInt16LE(0x3c) : data.readUInt16LE(0x30)
  const shstrndx = is64 ? data.readUInt16LE(0x3e) : data.readUInt16LE(0x32)
  if (!shoff || !shentsize || shnum <= 0 || shnum > 4096 || shstrndx >= shnum) return []
  const table = shoff + shstrndx * shentsize
  if (table + shentsize > data.length) return []
  const strOffset = is64
    ? Number(data.readBigUInt64LE(table + 0x18))
    : data.readUInt32LE(table + 0x10)
  const strSize = is64
    ? Number(data.readBigUInt64LE(table + 0x20))
    : data.readUInt32LE(table + 0x14)
  if (strOffset <= 0 || strSize <= 0 || strOffset + strSize > data.length) return []

  const sections: string[] = []
  for (let i = 0; i < Math.min(shnum, 256); i += 1) {
    const entry = shoff + i * shentsize
    if (entry + shentsize > data.length) break
    const nameOffset = data.readUInt32LE(entry)
    if (nameOffset < strSize) {
      const name = readCString(data, strOffset + nameOffset, 128)
      if (name) sections.push(name)
    }
  }
  return uniqueStrings(sections)
}

function collectEvidence(strings: BinaryString[], sections: string[]): EvidenceItem[] {
  const evidence: EvidenceItem[] = []
  const haystack: EvidenceSource[] = [
    ...strings,
    ...sections.map((section, index) => ({
      value: section,
      offset: index,
      encoding: 'section' as const,
    })),
  ]

  for (const item of haystack) {
    for (const rule of EVIDENCE_RULES) {
      if (rule.pattern.test(item.value)) {
        evidence.push({
          id: rule.id,
          family: rule.family,
          kind: rule.kind,
          value: item.value,
          offset: item.offset,
          encoding: item.encoding,
          confidence: rule.confidence,
        })
        break
      }
    }
    if (evidence.length >= MAX_EVIDENCE) break
  }

  return evidence
}

function scoreFamilies(evidence: EvidenceItem[]) {
  const grouped = new Map<Family, EvidenceItem[]>()
  for (const item of evidence) {
    const current = grouped.get(item.family) ?? []
    current.push(item)
    grouped.set(item.family, current)
  }

  return Array.from(grouped.entries())
    .map(([family, items]) => {
      const score = items.reduce((sum, item) => sum + confidenceWeight(item.confidence), 0)
      const highEvidence = items.filter((item) => item.confidence === 'high').length
      const kinds = uniqueStrings(items.map((item) => item.kind))
      return {
        family,
        confidence: toConfidence(score, highEvidence),
        score,
        evidence_count: items.length,
        evidence_kinds: kinds,
        matched_markers: uniqueStrings(items.map((item) => item.id)).slice(0, 18),
      }
    })
    .sort((a, b) => b.score - a.score || b.evidence_count - a.evidence_count)
}

function filterHints(
  evidence: EvidenceItem[],
  kinds: EvidenceItem['kind'][]
): Record<string, unknown>[] {
  return evidence
    .filter((item) => kinds.includes(item.kind))
    .map((item) => ({
      id: item.id,
      family: item.family,
      kind: item.kind,
      value: item.value,
      offset: item.offset,
      confidence: item.confidence,
    }))
    .slice(0, 80)
}

function extractUuids(strings: BinaryString[]): Record<string, unknown>[] {
  const uuidPattern = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi
  const seen = new Set<string>()
  const uuids: Record<string, unknown>[] = []
  for (const item of strings) {
    const matches = item.value.match(uuidPattern) ?? []
    for (const match of matches) {
      const normalized = match.toLowerCase()
      if (seen.has(normalized)) continue
      seen.add(normalized)
      uuids.push({ value: normalized, offset: item.offset, encoding: item.encoding })
      if (uuids.length >= MAX_UUIDS) return uuids
    }
  }
  return uuids
}

function buildRiskFlags(evidence: EvidenceItem[], families: ReturnType<typeof scoreFamilies>) {
  const joined = evidence.map((item) => item.value).join('\n')
  const flags: Record<string, unknown>[] = []
  if (/debug\s*=\s*(true|1)|SGX_DEBUG_FLAG|DEBUG_ENCLAVE/i.test(joined)) {
    flags.push({
      id: 'enclave.debug-enabled-marker',
      severity: 'medium',
      family: 'sgx',
      reason: 'Debug or development enclave marker was present in static strings.',
    })
  }
  if (
    evidence.some(
      (item) => item.id.includes('ocall') || /ocall|TEEC_InvokeCommand/i.test(item.value)
    )
  ) {
    flags.push({
      id: 'enclave.untrusted-boundary-calls',
      severity: 'medium',
      reason: 'ECALL/OCALL or client API boundary markers suggest host-enclave interface surface.',
    })
  }
  if (evidence.some((item) => ['attestation', 'measurement'].includes(item.kind))) {
    flags.push({
      id: 'attestation.material-present',
      severity: 'info',
      reason:
        'Measurement or attestation markers are present; this tool records them but does not verify quotes or reports.',
    })
  }
  if (/isvsvn\s*[:=]\s*0\b|ISVSVN\x00*0\b/i.test(joined)) {
    flags.push({
      id: 'sgx.low-isvsvn-marker',
      severity: 'low',
      family: 'sgx',
      reason:
        'Static manifest marker suggests ISVSVN 0; corroborate before treating as policy weakness.',
    })
  }
  if (families.some((item) => item.family === 'sev-snp') && /VCEK|ASK|ARK/i.test(joined)) {
    flags.push({
      id: 'sev-snp.certificate-chain-marker',
      severity: 'info',
      family: 'sev-snp',
      reason:
        'SEV-SNP certificate-chain terms were found; no certificate validation was attempted.',
    })
  }
  return flags
}

function detectFormat(
  filename: string | undefined,
  container: Record<string, unknown>,
  families: ReturnType<typeof scoreFamilies>
) {
  const top = families[0]
  const detectedBy = uniqueStrings([
    ...(top ? [`family:${top.family}`] : []),
    ...families.slice(0, 4).map((item) => `marker:${item.family}`),
    typeof container.kind === 'string' ? `container:${container.kind}` : 'container:raw',
  ])
  const lowerName = filename?.toLowerCase() ?? ''
  let format = top ? `${top.family}-tee-enclave-evidence` : 'tee-enclave-candidate'
  if (lowerName.endsWith('.ta') || top?.family === 'optee') format = 'optee-trustzone-ta'
  if (top?.family === 'sgx') format = 'sgx-enclave-candidate'
  if (top?.family === 'tdx') format = 'tdx-attestation-candidate'
  if (top?.family === 'sev-snp') format = 'sev-snp-attestation-candidate'
  if (top?.family === 'riscv-enclave') format = 'riscv-enclave-candidate'

  return {
    format,
    detectedBy,
    confidence: top?.confidence ?? 'low',
  }
}

function buildSummary(families: ReturnType<typeof scoreFamilies>, confidence: Confidence): string {
  if (families.length === 0) {
    return 'No strong TEE/enclave markers were found in the bounded static preview.'
  }
  const names = families
    .slice(0, 3)
    .map((item) => `${item.family} (${item.confidence})`)
    .join(', ')
  return `Passive TEE/enclave inventory found ${names}; overall confidence is ${confidence}.`
}

export function buildTeeEnclaveInventoryFromBuffer(data: Buffer, options: BuildOptions = {}) {
  const maxReadBytes = options.maxReadBytes ?? DEFAULT_MAX_READ_BYTES
  const strings = extractStrings(data)
  const container = detectContainer(data, options.filename)
  const sections = Array.isArray(container.sections) ? (container.sections as string[]) : []
  const evidence = collectEvidence(strings, sections)
  const families = scoreFamilies(evidence)
  const formatInfo = detectFormat(options.filename, container, families)
  const attestationHints = filterHints(evidence, ['attestation'])
  const measurementHints = filterHints(evidence, ['measurement'])
  const entrypointHints = filterHints(evidence, ['entrypoint'])
  const manifestHints = filterHints(evidence, ['manifest'])
  const boundaryHints = filterHints(evidence, ['api', 'table'])
  const uuids = extractUuids(strings)
  const riskFlags = buildRiskFlags(evidence, families)
  const runtimeRisk = {
    level: evidence.some((item) => ['api', 'table'].includes(item.kind)) ? 'medium' : 'low',
    live_action_required: false,
    runtime_followup_requires_opt_in: true,
    runtime_families: uniqueStrings(families.map((item) => item.family)),
  }

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: formatInfo.format,
    detected_by: formatInfo.detectedBy,
    confidence: formatInfo.confidence,
    size: options.totalSize,
    preview_size: data.length,
    container,
    enclave_families: families,
    attestation_hints: attestationHints,
    measurement_hints: measurementHints,
    entrypoint_hints: entrypointHints,
    manifest_hints: manifestHints,
    boundary_hints: boundaryHints,
    uuids,
    risk_flags: riskFlags,
    runtime_risk: runtimeRisk,
    policy: {
      passive: true,
      no_execute: true,
      no_enclave_load: true,
      no_attestation_request: true,
      no_quote_generation: true,
      no_tee_driver_call: true,
      no_kernel_driver_call: true,
      no_key_derivation: true,
      no_debugger: true,
      no_emulation: true,
      no_external_tool: true,
      no_network: true,
      no_mutation: true,
    },
    summary: buildSummary(families, formatInfo.confidence),
    recommended_next_tools: TEE_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use native.object.inventory and native.debug.types.inventory to corroborate symbols, sections, and debug/type metadata.',
      'Use compiler.codegen.fingerprint to compare enclave build provenance and hardening posture across related artifacts.',
      'Use sbom.provenance.graph and analysis.evidence.graph to relate enclave evidence to package, signer, and report context.',
      'Treat attestation markers as candidate-only until a dedicated verifier validates quotes, reports, certificate chains, and policy.',
    ],
    evidence_summary: {
      total_evidence: evidence.length,
      family_count: families.length,
      attestation_hint_count: attestationHints.length,
      measurement_hint_count: measurementHints.length,
      entrypoint_hint_count: entrypointHints.length,
      manifest_hint_count: manifestHints.length,
      boundary_hint_count: boundaryHints.length,
      uuid_count: uuids.length,
      bounded_preview: true,
      candidate_only: true,
    },
    workflow_handoff: {
      static_corroboration: [
        'native.object.inventory',
        'native.debug.types.inventory',
        'compiler.codegen.fingerprint',
        'strings.extract',
      ],
      evidence_correlation: ['sbom.provenance.graph', 'analysis.evidence.graph', 'report.generate'],
      attestation_boundary: {
        verified_by_this_tool: false,
        guidance:
          'This inventory records static quote/report/measurement markers only. Use a dedicated attestation verifier outside this passive tool when policy validation is required.',
      },
      runtime_boundary: {
        required: false,
        guidance:
          'Runtime, enclave loading, quote generation, and TEE driver interaction are outside this tool and must remain explicit opt-in workflows.',
      },
    },
    quality_gates: {
      passive_static_inventory: true,
      sample_executed_by_tool: false,
      enclave_loaded_by_tool: false,
      attestation_requested_by_tool: false,
      quote_generated_by_tool: false,
      tee_driver_called_by_tool: false,
      debugger_or_emulator_started_by_tool: false,
      external_tool_invoked_by_tool: false,
      network_used_by_tool: false,
      bounded_read_bytes: data.length,
      max_read_bytes: maxReadBytes,
      truncated: options.totalSize ? options.totalSize > data.length : false,
      candidate_only: true,
    },
  }
}

export function createTeeEnclaveInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (input: z.infer<typeof TeeEnclaveInventoryInputSchema>): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const parsed = TeeEnclaveInventoryInputSchema.parse(input)
      if (!deps.resolvePrimarySamplePath) {
        return {
          ok: false,
          errors: ['resolvePrimarySamplePath dependency is unavailable for tee.enclave.inventory'],
          metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
        }
      }

      const resolved = await deps.resolvePrimarySamplePath(deps.workspaceManager, parsed.sample_id)
      const stat = await fs.stat(resolved.samplePath)
      const maxReadBytes = Math.min(parsed.max_read_bytes, MAX_PREVIEW_BYTES)
      const file = await fs.open(resolved.samplePath, 'r')
      let data: Buffer
      try {
        const readSize = Math.max(0, Math.min(stat.size, maxReadBytes))
        data = Buffer.alloc(readSize)
        await file.read(data, 0, readSize, 0)
      } finally {
        await file.close()
      }

      const inventory = buildTeeEnclaveInventoryFromBuffer(data, {
        sampleId: parsed.sample_id,
        filename: path.basename(resolved.samplePath),
        maxReadBytes,
        totalSize: stat.size,
      })

      const artifacts: ArtifactRef[] = []
      if (parsed.persist_artifact !== false && deps.persistStaticAnalysisJsonArtifact) {
        const artifact = await deps.persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          parsed.sample_id,
          TEE_ENCLAVE_ARTIFACT_TYPE,
          'tee-enclave-inventory',
          inventory,
          parsed.session_tag ?? null
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: inventory as unknown as Record<string, unknown>,
        artifacts,
        metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
      }
    }
  }
}
