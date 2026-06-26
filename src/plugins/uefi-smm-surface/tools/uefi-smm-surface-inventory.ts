/**
 * uefi.smm.surface.inventory - passive UEFI/SMM trust-boundary inventory.
 *
 * This tool reads bounded bytes and summarizes UEFI firmware module evidence:
 * firmware volume/capsule/PE/TE hints, SMM handler registrations, SMI dispatch
 * protocols, communication buffer strings, Boot/Runtime Services callout hints,
 * NVRAM/Secure Boot variable names, flash/capsule/MMIO/MSR primitives, and
 * static workflow handoff. It never boots firmware, triggers SMI, executes SMM
 * code, writes EFI variables, applies capsules, touches SPI flash/MMIO/MSR,
 * invokes external firmware tools, accesses the network, or mutates samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'uefi.smm.surface.inventory'
export const UEFI_SMM_SURFACE_ARTIFACT_TYPE = 'uefi_smm_surface_inventory'

const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 8000
const MAX_EVIDENCE = 420
const MAX_GUIDS = 160

const UEFI_SMM_EVIDENCE = [
  'structure',
  'strings',
  'protocols',
  'guid',
  'smm',
  'variables',
  'low-level-primitives',
  'risk',
  'workflow',
]

const UEFI_SMM_SAFETY = [
  'passive',
  'no_execute',
  'no_firmware_boot',
  'no_smi_trigger',
  'no_smm_execution',
  'no_efi_variable_write',
  'no_nvram_write',
  'no_spi_flash_write',
  'no_firmware_flash_write',
  'no_capsule_apply',
  'no_mmio_or_msr_access',
  'no_emulation',
  'no_external_tool',
  'no_network_by_default',
  'no_mutation',
]

const UEFI_SMM_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'firmware.scan',
  'firmware.workflow.plan',
  'pe.structure.analyze',
  'pe.imports.extract',
  'strings.extract',
  'code.xrefs.analyze',
  'vuln.pattern.scan',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

type Confidence = 'low' | 'medium' | 'high'
type SurfaceFamily =
  | 'smm'
  | 'protocol'
  | 'boot-service'
  | 'runtime-service'
  | 'variable'
  | 'validation'
  | 'primitive'
  | 'container'

interface BinaryString {
  value: string
  offset: number
  encoding: 'ascii' | 'utf16le'
}

interface EvidenceRule {
  pattern: RegExp
  id: string
  kind: string
  family: SurfaceFamily
  confidence: Confidence
}

interface BuildOptions {
  filename?: string
  sampleId?: string
  maxReadBytes?: number
  size?: number
}

interface EvidenceItem {
  id: string
  kind: string
  family: SurfaceFamily
  value: string
  offset: number
  encoding: 'ascii' | 'utf16le'
  confidence: Confidence
}

export const uefiSmmSurfaceInventoryAspects = {
  formats: [
    'uefi',
    'efi',
    'uefi-firmware',
    'uefi-module',
    'uefi-smm',
    'smm',
    'smi',
    'te',
    'firmware-volume',
    'uefi-capsule',
    'dxe',
    'pei',
    'nvram',
  ],
  platforms: ['uefi', 'firmware', 'embedded', 'x86', 'x64', 'arm', 'arm64'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'riscv'],
  execution: ['static', 'triage', 'attack-surface', 'trust-boundary', 'workflow-plan'],
  safety: UEFI_SMM_SAFETY,
  capabilities: [
    'uefi-smm-surface-inventory',
    'smi-handler-hints',
    'smm-communication-buffer-hints',
    'uefi-protocol-service-inventory',
    'nvram-variable-surface',
    'secure-boot-variable-hints',
    'firmware-flash-capsule-primitive-inventory',
    'trust-boundary-risk-routing',
  ],
  evidence: UEFI_SMM_EVIDENCE,
  route_terms: [
    'uefi',
    'efi firmware',
    'smm',
    'smi handler',
    'smi dispatch',
    'commbuffer',
    'smram',
    'smm communication',
    'boot services',
    'runtime services',
    'nvram',
    'secure boot',
    'capsule update',
    'firmware volume',
  ],
  search: [
    'UEFI SMM trust boundary inventory',
    'SMI handler communication buffer triage',
    'UEFI NVRAM variable and Secure Boot surface',
    'firmware volume capsule static risk inventory',
  ],
}

const UefiSmmPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_firmware_boot: z.literal(true),
  no_smi_trigger: z.literal(true),
  no_smm_execution: z.literal(true),
  no_efi_variable_write: z.literal(true),
  no_nvram_write: z.literal(true),
  no_spi_flash_write: z.literal(true),
  no_firmware_flash_write: z.literal(true),
  no_capsule_apply: z.literal(true),
  no_mmio_or_msr_access: z.literal(true),
  no_emulation: z.literal(true),
  no_external_tool: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const UefiSmmSurfaceInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  platform: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.any()),
  evidence: z.array(z.record(z.any())),
  smm_surface: z.record(z.any()),
  protocol_references: z.array(z.record(z.any())),
  service_references: z.record(z.any()),
  variable_surface: z.record(z.any()),
  guid_references: z.array(z.record(z.any())),
  low_level_primitives: z.array(z.record(z.any())),
  risk_flags: z.array(z.record(z.any())),
  risk_summary: z.record(z.any()),
  policy: UefiSmmPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const UefiSmmSurfaceInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target UEFI firmware, module, or capsule sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive UEFI/SMM surface inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist UEFI/SMM surface inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const UefiSmmSurfaceInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: UefiSmmSurfaceInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const uefiSmmSurfaceInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory UEFI/SMM firmware trust-boundary evidence including SMI handlers, communication buffers, protocol/service references, NVRAM variable surface, Secure Boot hints, and flash/capsule/MMIO/MSR primitives without booting firmware, triggering SMI, executing SMM code, writing EFI variables, touching hardware, or invoking external tools.',
  inputSchema: UefiSmmSurfaceInventoryInputSchema,
  outputSchema: UefiSmmSurfaceInventoryOutputSchema,
  aspects: uefiSmmSurfaceInventoryAspects,
  artifacts: [
    {
      type: UEFI_SMM_SURFACE_ARTIFACT_TYPE,
      description: 'Passive UEFI/SMM trust-boundary surface inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: UEFI_SMM_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [UEFI_SMM_SURFACE_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'uefi.smm-surface-static-inventory',
      title: 'Passive UEFI/SMM surface inventory',
      description:
        'Inventory UEFI firmware volume/module/capsule, SMM handler, communication buffer, protocol/service, NVRAM variable, Secure Boot, and low-level primitive evidence before routing to firmware, PE, string, xref, vulnerability, evidence graph, and reporting tools.',
      startsWith: [TOOL_NAME],
      nextTools: UEFI_SMM_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [UEFI_SMM_SURFACE_ARTIFACT_TYPE],
      evidence: UEFI_SMM_EVIDENCE,
      safety: UEFI_SMM_SAFETY,
    },
  ],
}

export type UefiSmmSurfaceInventory = z.infer<typeof UefiSmmSurfaceInventorySchema>

const UEFI_EVIDENCE_RULES: EvidenceRule[] = [
  {
    pattern: /\b(?:SmiHandlerRegister|SmmRegisterProtocolNotify|SmiEntry)\b/i,
    id: 'smm.handler-register',
    kind: 'smi-handler',
    family: 'smm',
    confidence: 'high',
  },
  {
    pattern: /\b(?:EFI_SMM_SW_DISPATCH2_PROTOCOL|EFI_MM_SW_DISPATCH_PROTOCOL|SwSmiInputValue)\b/i,
    id: 'smm.sw-dispatch',
    kind: 'software-smi-dispatch',
    family: 'smm',
    confidence: 'high',
  },
  {
    pattern:
      /\b(?:EFI_SMM_COMMUNICATION_PROTOCOL|EFI_MM_COMMUNICATION_PROTOCOL|SmmCommunication|MmCommunication)\b/i,
    id: 'smm.communication-protocol',
    kind: 'smm-communication',
    family: 'protocol',
    confidence: 'high',
  },
  {
    pattern: /\b(?:CommBuffer|CommunicationBuffer|CommSize|CommunicationSize)\b/i,
    id: 'smm.communication-buffer',
    kind: 'communication-buffer',
    family: 'smm',
    confidence: 'high',
  },
  {
    pattern: /\b(?:SMRAM|Smram|SmmBase|SmmCpu|SMM_CORE_PRIVATE_DATA)\b/i,
    id: 'smm.smram-reference',
    kind: 'smram-reference',
    family: 'smm',
    confidence: 'medium',
  },
  {
    pattern:
      /\b(?:SmmIsBufferOutsideSmmValid|SmmCopyMemToSmram|SmmCopyMemFromSmram|SmmMemLib|CopyMemToSmram|CopyMemFromSmram)\b/i,
    id: 'smm.buffer-validation',
    kind: 'buffer-validation',
    family: 'validation',
    confidence: 'high',
  },
  {
    pattern:
      /\b(?:gBS|BootServices|EFI_BOOT_SERVICES|LocateProtocol|HandleProtocol|OpenProtocol|InstallProtocolInterface)\b/i,
    id: 'uefi.boot-service-reference',
    kind: 'boot-service',
    family: 'boot-service',
    confidence: 'medium',
  },
  {
    pattern:
      /\b(?:gRT|RuntimeServices|EFI_RUNTIME_SERVICES|GetVariable|SetVariable|GetNextVariableName|QueryVariableInfo)\b/i,
    id: 'uefi.runtime-service-reference',
    kind: 'runtime-service',
    family: 'runtime-service',
    confidence: 'medium',
  },
  {
    pattern:
      /\b(?:SmmGetVariable|SmmSetVariable|EFI_SMM_VARIABLE_PROTOCOL|EFI_MM_VARIABLE_PROTOCOL)\b/i,
    id: 'smm.variable-protocol',
    kind: 'smm-variable-service',
    family: 'variable',
    confidence: 'high',
  },
  {
    pattern:
      /\b(?:SecureBoot|SetupMode|AuditMode|DeployedMode|PK|KEK|dbx|db|AuthenticatedVariable|BootOrder|BootNext)\b/i,
    id: 'uefi.security-variable-name',
    kind: 'security-variable',
    family: 'variable',
    confidence: 'medium',
  },
  {
    pattern:
      /\b(?:Mmio(?:Read|Write)\d*|MemoryMappedIo|Io(?:Read|Write)\d*|Pci(?:Read|Write)\d*)\b/i,
    id: 'uefi.mmio-or-io-primitive',
    kind: 'mmio-io-primitive',
    family: 'primitive',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:Asm(?:Read|Write)Msr64|ReadMsr|WriteMsr|Rdmsr|Wrmsr)\b/i,
    id: 'uefi.msr-primitive',
    kind: 'msr-primitive',
    family: 'primitive',
    confidence: 'medium',
  },
  {
    pattern:
      /\b(?:SpiFlash|FlashWrite|FlashUpdate|FirmwareVolumeBlock|Fvb|EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL)\b/i,
    id: 'uefi.flash-primitive',
    kind: 'flash-primitive',
    family: 'primitive',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:UpdateCapsule|CapsuleUpdate|EFI_CAPSULE_HEADER|CapsuleGuid|CapsuleFlags)\b/i,
    id: 'uefi.capsule-update-primitive',
    kind: 'capsule-update',
    family: 'primitive',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:S3BootScript|BootScriptSave|EFI_S3_SAVE_STATE_PROTOCOL)\b/i,
    id: 'uefi.s3-boot-script',
    kind: 's3-boot-script',
    family: 'primitive',
    confidence: 'medium',
  },
]

function clampMaxReadBytes(value: number | undefined): number {
  if (!Number.isFinite(value ?? DEFAULT_MAX_READ_BYTES)) return DEFAULT_MAX_READ_BYTES
  return Math.max(1024, Math.min(MAX_PREVIEW_BYTES, Math.trunc(value ?? DEFAULT_MAX_READ_BYTES)))
}

function sanitizeString(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim()
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items))
}

function uniqueBy<T>(items: T[], keyer: (item: T) => string): T[] {
  const seen = new Set<string>()
  const output: T[] = []
  for (const item of items) {
    const key = keyer(item)
    if (seen.has(key)) continue
    seen.add(key)
    output.push(item)
  }
  return output
}

function extractAsciiStrings(data: Buffer): BinaryString[] {
  const strings: BinaryString[] = []
  let start = -1
  for (let i = 0; i < data.length; i += 1) {
    const byte = data[i]
    const printable = byte >= 0x20 && byte <= 0x7e
    if (printable) {
      if (start < 0) start = i
      continue
    }
    if (start >= 0 && i - start >= 4) {
      strings.push({ value: data.toString('ascii', start, i), offset: start, encoding: 'ascii' })
      if (strings.length >= MAX_STRINGS) return strings
    }
    start = -1
  }
  if (start >= 0 && data.length - start >= 4 && strings.length < MAX_STRINGS) {
    strings.push({
      value: data.toString('ascii', start, data.length),
      offset: start,
      encoding: 'ascii',
    })
  }
  return strings
}

function extractUtf16LeStrings(data: Buffer): BinaryString[] {
  const strings: BinaryString[] = []
  let start = -1
  let chars = 0
  for (let i = 0; i + 1 < data.length; i += 2) {
    const code = data.readUInt16LE(i)
    const printable = code >= 0x20 && code <= 0x7e
    if (printable) {
      if (start < 0) start = i
      chars += 1
      continue
    }
    if (start >= 0 && chars >= 4) {
      strings.push({
        value: data.toString('utf16le', start, i),
        offset: start,
        encoding: 'utf16le',
      })
      if (strings.length >= Math.floor(MAX_STRINGS / 2)) return strings
    }
    start = -1
    chars = 0
  }
  if (start >= 0 && chars >= 4 && strings.length < Math.floor(MAX_STRINGS / 2)) {
    strings.push({
      value: data.toString('utf16le', start, start + chars * 2),
      offset: start,
      encoding: 'utf16le',
    })
  }
  return strings
}

function extractBinaryStrings(data: Buffer): BinaryString[] {
  return uniqueBy([...extractAsciiStrings(data), ...extractUtf16LeStrings(data)], (item) => {
    return `${item.offset}:${item.encoding}:${item.value}`
  }).slice(0, MAX_STRINGS)
}

function detectContainer(data: Buffer, maxReadBytes: number, options: BuildOptions) {
  const filename = options.filename?.toLowerCase() ?? ''
  const extension = filename.includes('.') ? filename.slice(filename.lastIndexOf('.') + 1) : ''
  const preview = data.toString('latin1', 0, Math.min(data.length, 1024 * 1024))
  const isPe = data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a
  const isTe = data.length >= 2 && data[0] === 0x56 && data[1] === 0x5a
  const fvhOffset = preview.indexOf('_FVH')
  const hasFirmwareVolume = fvhOffset >= 0
  const hasCapsule =
    ['cap', 'capsule'].includes(extension) ||
    /\b(?:EFI_CAPSULE_HEADER|CapsuleGuid|CapsuleFlags|UpdateCapsule)\b/i.test(preview)
  const hasSmmHint = /\b(?:SmiHandlerRegister|EFI_SMM_|EFI_MM_|CommBuffer|SMRAM)\b/i.test(preview)
  const hasUefiHint =
    /\b(?:EFI_BOOT_SERVICES|EFI_RUNTIME_SERVICES|BootServices|RuntimeServices|GetVariable|SetVariable)\b/i.test(
      preview
    )

  const kind = hasFirmwareVolume
    ? 'uefi-firmware-volume-preview'
    : hasCapsule
      ? 'uefi-capsule-preview'
      : isTe
        ? 'uefi-te-module-preview'
        : isPe && ['efi', 'dxe', 'smm', 'pei'].includes(extension)
          ? 'uefi-pe-module-preview'
          : isPe && (hasSmmHint || hasUefiHint)
            ? 'uefi-pe-module-preview'
            : hasSmmHint
              ? 'uefi-smm-raw-module-preview'
              : hasUefiHint
                ? 'uefi-raw-module-preview'
                : 'raw-firmware-preview'

  const magic = isPe ? 'MZ' : isTe ? 'TE' : hasFirmwareVolume ? '_FVH' : 'unknown'
  return {
    kind,
    magic,
    filename_hint: filename || null,
    extension_hint: extension || null,
    firmware_volume_header_offset: fvhOffset >= 0 ? fvhOffset : null,
    capsule_hint: hasCapsule,
    smm_hint: hasSmmHint,
    uefi_service_hint: hasUefiHint,
    bounded_preview: {
      bytes_read: data.length,
      max_read_bytes: maxReadBytes,
      truncated: data.length >= maxReadBytes,
    },
  }
}

function collectPatternEvidence(strings: BinaryString[]): EvidenceItem[] {
  const evidence: EvidenceItem[] = []
  for (const item of strings) {
    for (const rule of UEFI_EVIDENCE_RULES) {
      if (!rule.pattern.test(item.value)) continue
      evidence.push({
        id: rule.id,
        kind: rule.kind,
        family: rule.family,
        value: sanitizeString(item.value).slice(0, 220),
        offset: item.offset,
        encoding: item.encoding,
        confidence: rule.confidence,
      })
      if (evidence.length >= MAX_EVIDENCE) {
        return uniqueBy(evidence, (entry) => `${entry.id}:${entry.offset}:${entry.value}`).slice(
          0,
          MAX_EVIDENCE
        )
      }
    }
  }
  return uniqueBy(evidence, (entry) => `${entry.id}:${entry.offset}:${entry.value}`).slice(
    0,
    MAX_EVIDENCE
  )
}

function collectProtocolReferences(
  strings: BinaryString[],
  evidence: EvidenceItem[]
): Array<Record<string, unknown>> {
  const references: Array<Record<string, unknown>> = []
  const protocolNamePattern =
    /\b(?:EFI|EDKII|AMI|INSYDE|PHOENIX)_[A-Z0-9_]*(?:PROTOCOL|PPI|GUID)\b|gEfi[A-Za-z0-9]+Guid\b/g
  for (const item of strings) {
    const matches = item.value.match(protocolNamePattern) ?? []
    for (const match of matches) {
      references.push({
        name: sanitizeString(match),
        offset: item.offset,
        encoding: item.encoding,
        source: 'string',
        confidence: /(?:PROTOCOL|PPI)/.test(match) ? 'high' : 'medium',
      })
    }
  }
  for (const item of evidence.filter((entry) => entry.family === 'protocol')) {
    references.push({
      name: item.value,
      offset: item.offset,
      encoding: item.encoding,
      source: item.id,
      confidence: item.confidence,
    })
  }
  return uniqueBy(references, (item) => `${item.name}:${item.offset}`).slice(0, 220)
}

function collectGuidReferences(strings: BinaryString[]): Array<Record<string, unknown>> {
  const references: Array<Record<string, unknown>> = []
  const guidPattern =
    /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g
  for (const item of strings) {
    const matches = item.value.match(guidPattern) ?? []
    for (const match of matches) {
      references.push({
        guid: match.toLowerCase(),
        offset: item.offset,
        encoding: item.encoding,
        source: 'text-guid',
        confidence: 'medium',
      })
    }
  }
  return uniqueBy(references, (item) => String(item.guid)).slice(0, MAX_GUIDS)
}

function buildSmmSurface(evidence: EvidenceItem[]) {
  const smmEvidence = evidence.filter((item) => item.family === 'smm')
  const validationEvidence = evidence.filter((item) => item.family === 'validation')
  const hasHandler = evidence.some((item) => item.id === 'smm.handler-register')
  const hasSwDispatch = evidence.some((item) => item.id === 'smm.sw-dispatch')
  const hasCommunication = evidence.some(
    (item) => item.id === 'smm.communication-protocol' || item.id === 'smm.communication-buffer'
  )
  return {
    present: smmEvidence.length > 0 || validationEvidence.length > 0,
    handler_registration_hint: hasHandler,
    software_smi_dispatch_hint: hasSwDispatch,
    communication_protocol_hint: evidence.some((item) => item.id === 'smm.communication-protocol'),
    communication_buffer_hint: evidence.some((item) => item.id === 'smm.communication-buffer'),
    smram_reference_hint: evidence.some((item) => item.id === 'smm.smram-reference'),
    buffer_validation_hint: validationEvidence.length > 0,
    communication_surface_present: hasCommunication,
    evidence_count: smmEvidence.length + validationEvidence.length,
  }
}

function buildServiceReferences(evidence: EvidenceItem[]) {
  const boot = evidence.filter((item) => item.family === 'boot-service')
  const runtime = evidence.filter((item) => item.family === 'runtime-service')
  return {
    boot_services: {
      present: boot.length > 0,
      count: boot.length,
      names: unique(boot.map((item) => item.value)).slice(0, 80),
    },
    runtime_services: {
      present: runtime.length > 0,
      count: runtime.length,
      names: unique(runtime.map((item) => item.value)).slice(0, 80),
    },
  }
}

function buildVariableSurface(evidence: EvidenceItem[]) {
  const variableEvidence = evidence.filter((item) => item.family === 'variable')
  const runtimeServiceEvidence = evidence.filter((item) => item.family === 'runtime-service')
  const hasSetVariable = [...variableEvidence, ...runtimeServiceEvidence].some((item) =>
    /\b(?:SetVariable|SmmSetVariable)\b/i.test(item.value)
  )
  const hasGetVariable = [...variableEvidence, ...runtimeServiceEvidence].some((item) =>
    /\b(?:GetVariable|SmmGetVariable|GetNextVariableName|QueryVariableInfo)\b/i.test(item.value)
  )
  const secureBootNames = variableEvidence
    .filter((item) =>
      /\b(?:SecureBoot|SetupMode|AuditMode|DeployedMode|PK|KEK|dbx|db|AuthenticatedVariable)\b/i.test(
        item.value
      )
    )
    .map((item) => item.value)
  return {
    present: variableEvidence.length > 0 || hasSetVariable || hasGetVariable,
    read_hint: hasGetVariable,
    write_hint: hasSetVariable,
    secure_boot_variable_hint: secureBootNames.length > 0,
    security_variable_names: unique(secureBootNames).slice(0, 80),
    evidence_count: variableEvidence.length,
  }
}

function collectLowLevelPrimitives(evidence: EvidenceItem[]): Array<Record<string, unknown>> {
  return uniqueBy(
    evidence
      .filter((item) => item.family === 'primitive')
      .map((item) => ({
        id: item.id,
        kind: item.kind,
        value: item.value,
        offset: item.offset,
        confidence: item.confidence,
        severity:
          item.id === 'uefi.flash-primitive' || item.id === 'uefi.capsule-update-primitive'
            ? 'high'
            : 'medium',
      })),
    (item) => `${item.id}:${item.offset}:${item.value}`
  ).slice(0, 160)
}

function determineFormat(
  container: Record<string, any>,
  evidence: EvidenceItem[],
  guidReferences: Array<Record<string, unknown>>
): { format: string; detectedBy: string[]; confidence: Confidence } {
  const detectedBy = new Set<string>()
  detectedBy.add(String(container.kind ?? 'raw-firmware-preview'))
  if (container.firmware_volume_header_offset !== null) detectedBy.add('firmware-volume-header')
  if (container.capsule_hint) detectedBy.add('capsule-hint')
  if (guidReferences.length > 0) detectedBy.add('text-guid')
  for (const item of evidence) detectedBy.add(`${item.family}:${item.kind}`)

  const highCount = evidence.filter((item) => item.confidence === 'high').length
  const confidence: Confidence =
    highCount >= 2 || (container.firmware_volume_header_offset !== null && evidence.length >= 2)
      ? 'high'
      : evidence.length + guidReferences.length >= 2
        ? 'medium'
        : detectedBy.size > 1
          ? 'low'
          : 'low'

  const kind = String(container.kind ?? '')
  const smmEvidence = evidence.some((item) => item.family === 'smm' || item.family === 'validation')
  const format = kind.includes('firmware-volume')
    ? smmEvidence
      ? 'uefi-firmware-volume-smm-surface'
      : 'uefi-firmware-volume-surface'
    : kind.includes('capsule')
      ? 'uefi-capsule-surface'
      : kind.includes('pe-module') || kind.includes('te-module')
        ? smmEvidence
          ? 'uefi-smm-module-surface'
          : 'uefi-module-surface'
        : smmEvidence
          ? 'uefi-smm-surface-preview'
          : 'uefi-firmware-surface-preview'

  return { format, detectedBy: Array.from(detectedBy).slice(0, 100), confidence }
}

function buildRiskFlags(
  preview: Buffer,
  maxReadBytes: number,
  smmSurface: Record<string, any>,
  serviceReferences: Record<string, any>,
  variableSurface: Record<string, any>,
  lowLevelPrimitives: Array<Record<string, any>>
) {
  const flags: Array<Record<string, unknown>> = []
  if (preview.length >= maxReadBytes) {
    flags.push({
      id: 'bounded_preview.truncated',
      severity: 'info',
      message: 'Input was scanned only up to max_read_bytes; UEFI/SMM evidence may exist later.',
    })
  }
  const smmPresent = Boolean(smmSurface.present)
  const commBuffer = Boolean(smmSurface.communication_buffer_hint)
  const validation = Boolean(smmSurface.buffer_validation_hint)
  if (smmPresent && (serviceReferences.boot_services as any)?.present === true) {
    flags.push({
      id: 'smm.callout.boot-services',
      severity: 'high',
      message:
        'SMM evidence and Boot Services references were both found; downstream xref review should rule out SMM callouts.',
    })
  }
  if (smmPresent && (serviceReferences.runtime_services as any)?.present === true) {
    flags.push({
      id: 'smm.runtime-service-access',
      severity: 'medium',
      message:
        'SMM evidence and Runtime Services references were both found; review NVRAM/service access from SMM context.',
    })
  }
  if (commBuffer) {
    flags.push({
      id: 'smm.communication-buffer',
      severity: 'high',
      message:
        'SMM communication buffer evidence was found; validate size, pointer, and SMRAM boundary checks in downstream analysis.',
    })
  }
  if (commBuffer && !validation) {
    flags.push({
      id: 'smm.comm-buffer.validation-missing-hint',
      severity: 'high',
      message:
        'CommBuffer evidence was found without nearby static validation/copy helper names; treat as a review priority, not proof of vulnerability.',
    })
  }
  if (variableSurface.write_hint === true) {
    flags.push({
      id: 'uefi.variable-write',
      severity: 'medium',
      message:
        'SetVariable/SmmSetVariable evidence was found; review authorization and attributes before trusting NVRAM state changes.',
    })
  }
  if (variableSurface.secure_boot_variable_hint === true) {
    flags.push({
      id: 'uefi.secure-boot-variable',
      severity: 'medium',
      evidence: (variableSurface.security_variable_names as string[] | undefined)?.slice(0, 8),
      message:
        'Secure Boot or authenticated variable names were found; correlate with variable access and policy logic.',
    })
  }
  for (const primitive of lowLevelPrimitives) {
    if (
      primitive.id === 'uefi.flash-primitive' ||
      primitive.id === 'uefi.capsule-update-primitive'
    ) {
      flags.push({
        id: primitive.id,
        severity: 'high',
        evidence: primitive.value,
        message:
          'Firmware flash or capsule update primitive evidence was found; keep follow-up analysis offline and non-mutating.',
      })
    }
    if (primitive.id === 'uefi.mmio-or-io-primitive' || primitive.id === 'uefi.msr-primitive') {
      flags.push({
        id: primitive.id,
        severity: 'medium',
        evidence: primitive.value,
        message:
          'MMIO, I/O port, PCI, or MSR primitive evidence was found; downstream review should bound hardware access paths statically.',
      })
    }
  }
  return uniqueBy(flags, (item) => `${item.id}:${item.evidence ?? ''}`).slice(0, 180)
}

function buildRiskSummary(riskFlags: Array<Record<string, any>>) {
  const severityRank: Record<string, number> = { info: 1, low: 2, medium: 3, high: 4, critical: 5 }
  const highest = riskFlags.reduce((current, item) => {
    return (severityRank[String(item.severity)] ?? 0) > (severityRank[current] ?? 0)
      ? String(item.severity)
      : current
  }, 'info')
  return {
    highest_severity: highest,
    risk_flag_count: riskFlags.length,
    candidate_only: true,
    needs_xref_correlation: riskFlags.length > 0,
  }
}

function buildEvidenceSummary(
  inventory: Omit<UefiSmmSurfaceInventory, 'evidence_summary' | 'workflow_handoff' | 'summary'>
) {
  return {
    schema: 'rikune.uefi_smm_surface.evidence_summary.v1',
    format: inventory.format,
    platform: inventory.platform,
    confidence: inventory.confidence,
    evidence_count: inventory.evidence.length,
    protocol_reference_count: inventory.protocol_references.length,
    guid_reference_count: inventory.guid_references.length,
    low_level_primitive_count: inventory.low_level_primitives.length,
    risk_flag_count: inventory.risk_flags.length,
    artifact_type: UEFI_SMM_SURFACE_ARTIFACT_TYPE,
  }
}

function buildWorkflowHandoff(inventory: UefiSmmSurfaceInventory): Record<string, unknown> {
  return {
    schema: 'rikune.uefi_smm_surface.workflow_handoff.v1',
    handoff_mode: 'uefi_smm_surface_inventory_to_static_firmware_xref_and_evidence_graph',
    artifact_contract: {
      consumes: ['sample'],
      produces: [UEFI_SMM_SURFACE_ARTIFACT_TYPE],
      mime: 'application/json',
      expected_consumers: UEFI_SMM_FOLLOW_UP_TOOLS,
    },
    routing: [
      {
        goal: 'correlate SMI handler, CommBuffer, service, variable, and primitive evidence with callsites',
        next_tools: ['code.xrefs.analyze', 'analysis.evidence.graph', 'artifact.read'],
      },
      {
        goal: 'review firmware volume/capsule/module structure without booting firmware',
        next_tools: ['firmware.scan', 'firmware.workflow.plan', 'pe.structure.analyze'],
      },
      {
        goal: 'extract supporting strings/imports and generate static reporting',
        next_tools: [
          'strings.extract',
          'pe.imports.extract',
          'vuln.pattern.scan',
          'report.generate',
        ],
      },
    ],
    dynamic_boundary: {
      activation_boundary: 'result-scoped',
      sample_execution_allowed: false,
      firmware_boot_allowed: false,
      smi_trigger_allowed: false,
      smm_execution_allowed: false,
      efi_variable_write_allowed: false,
      nvram_write_allowed: false,
      spi_flash_write_allowed: false,
      firmware_flash_write_allowed: false,
      capsule_apply_allowed: false,
      mmio_or_msr_access_allowed: false,
      emulation_allowed: false,
      external_tool_allowed: false,
      network_allowed: false,
      mutation_allowed: false,
      smi_triggered_by_tool: false,
      efi_variable_written_by_tool: false,
      capsule_applied_by_tool: false,
    },
    evidence_summary: inventory.evidence_summary,
  }
}

function buildSummary(
  inventory: Omit<UefiSmmSurfaceInventory, 'summary' | 'workflow_handoff'>
): string {
  const smm = inventory.smm_surface as Record<string, any>
  return `${inventory.format}: SMM=${Boolean(smm.present)}, ${inventory.protocol_references.length} protocol reference(s), ${inventory.guid_references.length} GUID reference(s), ${inventory.low_level_primitives.length} low-level primitive hint(s), ${inventory.risk_flags.length} risk flag(s).`
}

export function buildUefiSmmSurfaceInventoryFromBuffer(
  data: Buffer,
  options: BuildOptions = {}
): UefiSmmSurfaceInventory {
  const maxReadBytes = clampMaxReadBytes(options.maxReadBytes)
  const preview = data.subarray(0, Math.min(data.length, maxReadBytes))
  const container = detectContainer(preview, maxReadBytes, options)
  const strings = extractBinaryStrings(preview)
  const evidence = collectPatternEvidence(strings)
  const protocolReferences = collectProtocolReferences(strings, evidence)
  const guidReferences = collectGuidReferences(strings)
  const smmSurface = buildSmmSurface(evidence)
  const serviceReferences = buildServiceReferences(evidence)
  const variableSurface = buildVariableSurface(evidence)
  const lowLevelPrimitives = collectLowLevelPrimitives(evidence)
  const detected = determineFormat(container, evidence, guidReferences)
  const riskFlags = buildRiskFlags(
    preview,
    maxReadBytes,
    smmSurface,
    serviceReferences,
    variableSurface,
    lowLevelPrimitives
  )
  const riskSummary = buildRiskSummary(riskFlags)

  const base = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    platform: 'uefi-firmware',
    detected_by: detected.detectedBy,
    confidence: detected.confidence,
    size: options.size ?? data.length,
    preview_size: preview.length,
    container,
    evidence,
    smm_surface: smmSurface,
    protocol_references: protocolReferences,
    service_references: serviceReferences,
    variable_surface: variableSurface,
    guid_references: guidReferences,
    low_level_primitives: lowLevelPrimitives,
    risk_flags: riskFlags,
    risk_summary: riskSummary,
    policy: {
      passive: true,
      no_execute: true,
      no_firmware_boot: true,
      no_smi_trigger: true,
      no_smm_execution: true,
      no_efi_variable_write: true,
      no_nvram_write: true,
      no_spi_flash_write: true,
      no_firmware_flash_write: true,
      no_capsule_apply: true,
      no_mmio_or_msr_access: true,
      no_emulation: true,
      no_external_tool: true,
      no_network: true,
      no_mutation: true,
    },
    recommended_next_tools: UEFI_SMM_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use code.xrefs.analyze to map SMI handler, CommBuffer, service, variable, and primitive evidence to callsites.',
      'Use firmware and PE inventory tools to correlate firmware volume, capsule, PE/TE module, import, and string context offline.',
      'Keep any firmware boot, SMI triggering, variable mutation, flash access, or emulation outside this passive workflow.',
    ],
    quality_gates: {
      passive_static_inventory: true,
      sample_executed_by_tool: false,
      firmware_booted_by_tool: false,
      smi_triggered_by_tool: false,
      smm_code_executed_by_tool: false,
      efi_variable_written_by_tool: false,
      nvram_modified_by_tool: false,
      spi_flash_written_by_tool: false,
      firmware_flash_written_by_tool: false,
      capsule_applied_by_tool: false,
      mmio_or_msr_accessed_by_tool: false,
      emulator_started_by_tool: false,
      external_tool_invoked_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
  } satisfies Omit<UefiSmmSurfaceInventory, 'summary' | 'workflow_handoff' | 'evidence_summary'>

  const withEvidence = {
    ...base,
    evidence_summary: buildEvidenceSummary(base),
  } satisfies Omit<UefiSmmSurfaceInventory, 'summary' | 'workflow_handoff'>

  const inventory: UefiSmmSurfaceInventory = {
    ...withEvidence,
    summary: buildSummary(withEvidence),
    workflow_handoff: {},
  }
  inventory.workflow_handoff = buildWorkflowHandoff(inventory)
  return inventory
}

export function createUefiSmmSurfaceInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = UefiSmmSurfaceInventoryInputSchema.parse(args)
      const resolver = deps.resolvePrimarySamplePath
      if (!resolver) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is unavailable'] }
      }

      const resolved = await resolver(deps.workspaceManager, input.sample_id)
      const stat = await fs.stat(resolved.samplePath)
      const maxReadBytes = clampMaxReadBytes(input.max_read_bytes)
      const handle = await fs.open(resolved.samplePath, 'r')
      try {
        const buffer = Buffer.alloc(Math.min(stat.size, maxReadBytes))
        await handle.read(buffer, 0, buffer.length, 0)
        const inventory = buildUefiSmmSurfaceInventoryFromBuffer(buffer, {
          filename: path.basename(resolved.samplePath),
          sampleId: input.sample_id,
          maxReadBytes,
          size: stat.size,
        })

        const artifacts: ArtifactRef[] = []
        if (input.persist_artifact !== false) {
          const persist = deps.persistStaticAnalysisJsonArtifact
          if (persist) {
            artifacts.push(
              await persist(
                deps.workspaceManager,
                deps.database,
                input.sample_id,
                UEFI_SMM_SURFACE_ARTIFACT_TYPE,
                'uefi-smm-surface',
                inventory,
                input.session_tag ?? null
              )
            )
          }
        }

        return {
          ok: true,
          data: inventory,
          artifacts,
          metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
        }
      } finally {
        await handle.close()
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
