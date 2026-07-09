/**
 * pe.security.profile - passive PE hardening and exploitability posture.
 *
 * This tool reads PE metadata only. It does not load DLLs, start a Windows
 * loader, execute custom actions, query CVEs, mutate binaries, or use network.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'pe.security.profile'
const TOOL_VERSION = '1.0.0'
const DEFAULT_MAX_READ_BYTES = 32 * 1024 * 1024
const MAX_READ_BYTES = 256 * 1024 * 1024
export const PE_SECURITY_PROFILE_ARTIFACT_TYPE = 'pe_security_profile'

const IMAGE_FILE_MACHINE_NAMES: Record<number, string> = {
  0x014c: 'IMAGE_FILE_MACHINE_I386',
  0x0200: 'IMAGE_FILE_MACHINE_IA64',
  0x8664: 'IMAGE_FILE_MACHINE_AMD64',
  0x01c4: 'IMAGE_FILE_MACHINE_ARMNT',
  0xaa64: 'IMAGE_FILE_MACHINE_ARM64',
}

const DLL_CHARACTERISTIC_FLAGS: Array<[number, string]> = [
  [0x0020, 'high_entropy_va'],
  [0x0040, 'dynamic_base'],
  [0x0080, 'force_integrity'],
  [0x0100, 'nx_compat'],
  [0x0200, 'no_isolation'],
  [0x0400, 'no_seh'],
  [0x0800, 'no_bind'],
  [0x1000, 'app_container'],
  [0x2000, 'wdm_driver'],
  [0x4000, 'guard_cf'],
  [0x8000, 'terminal_server_aware'],
]

const GUARD_FLAG_NAMES: Array<[number, string]> = [
  [0x00000100, 'cf_instrumented'],
  [0x00000200, 'cfw_instrumented'],
  [0x00000400, 'cf_function_table_present'],
  [0x00000800, 'security_cookie_unused'],
  [0x00001000, 'protect_delay_load_iat'],
  [0x00002000, 'delay_load_iat_in_its_own_section'],
  [0x00004000, 'cf_export_suppression_info_present'],
  [0x00008000, 'cf_enable_export_suppression'],
  [0x00010000, 'cf_long_jump_table_present'],
  [0x00020000, 'rf_instrumented'],
  [0x00040000, 'rf_enable'],
  [0x00080000, 'rf_strict'],
  [0x00100000, 'retpoline_present'],
  [0x00200000, 'eh_continuation_table_present'],
  [0x00400000, 'xfg_enabled'],
  [0x00800000, 'castguard_present'],
  [0x01000000, 'memcpy_present'],
]

const PE_SECURITY_RECOMMENDED_NEXT_TOOLS = [
  'pe.structure.analyze',
  'pe.imports.extract',
  'pe.pdata.extract',
  'pe.signature.verify',
  'static.capability.triage',
  'compiler.packer.detect',
  'analysis.evidence.graph',
  'report.generate',
  'windows.runtime.plan',
]

const PE_SECURITY_SAFETY = [
  'passive',
  'read_only',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
  'no_loader_invocation',
]

const MitigationSchema = z.object({
  enabled: z.boolean(),
  source: z.string(),
  evidence: z.string(),
  severity_if_missing: z.enum(['info', 'low', 'medium', 'high']),
})

const SectionSchema = z.object({
  name: z.string(),
  virtual_address: z.number(),
  virtual_size: z.number(),
  raw_size: z.number(),
  raw_pointer: z.number(),
  characteristics: z.number(),
  executable: z.boolean(),
  writable: z.boolean(),
  readable: z.boolean(),
  write_execute: z.boolean(),
})

const DirectorySchema = z.object({
  rva: z.number(),
  size: z.number(),
  present: z.boolean(),
})

const PESecurityProfileDataSchema = z.object({
  schema: z.literal('rikune.pe_security_profile.v1'),
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  size: z.number().optional(),
  machine: z.number(),
  machine_name: z.string(),
  pe_kind: z.enum(['pe32', 'pe32-plus']),
  image_base: z.number(),
  entry_point_rva: z.number(),
  subsystem: z.number(),
  characteristics: z.number(),
  dll_characteristics: z.number(),
  dll_characteristics_flags: z.array(z.string()),
  mitigations: z.record(z.string(), MitigationSchema),
  data_directories: z.object({
    exception: DirectorySchema,
    security: DirectorySchema,
    load_config: DirectorySchema,
    tls: DirectorySchema,
  }),
  load_config: z.object({
    present: z.boolean(),
    parsed: z.boolean(),
    size: z.number(),
    security_cookie_va: z.number().optional(),
    seh_table_va: z.number().optional(),
    seh_count: z.number().optional(),
    guard_flags: z.number().optional(),
    guard_flags_names: z.array(z.string()),
  }),
  tls: z.object({
    present: z.boolean(),
    callback_table_va: z.number().optional(),
    callback_count: z.number(),
    callback_rvas: z.array(z.number()),
  }),
  sections: z.array(SectionSchema),
  section_risks: z.array(z.record(z.string(), z.any())),
  risk_score: z.number(),
  posture: z.enum(['low-risk', 'medium-risk', 'high-risk']),
  risk_factors: z.array(z.record(z.string(), z.any())),
  policy: z.object({
    passive: z.literal(true),
    no_execute: z.literal(true),
    no_load: z.literal(true),
    no_network: z.literal(true),
    no_mutation: z.literal(true),
  }),
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const PESecurityProfileInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_READ_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive PE security profiling.'),
  persist_artifact: z.boolean().default(true).describe('Persist PE security profile JSON.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const PESecurityProfileOutputSchema = z.object({
  ok: z.boolean(),
  data: PESecurityProfileDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const peSecurityProfileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively profile PE hardening posture from headers, DllCharacteristics, Load Config, TLS, and section flags without loading or executing the sample.',
  inputSchema: PESecurityProfileInputSchema,
  outputSchema: PESecurityProfileOutputSchema,
  aspects: {
    formats: ['pe', 'pe-clr', 'dll', 'exe', 'sys', 'efi'],
    platforms: ['windows'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage', 'workflow-handoff'],
    safety: PE_SECURITY_SAFETY,
    capabilities: [
      'security-profile',
      'hardening-assessment',
      'exploitability-posture',
      'dll-characteristics',
      'load-config-analysis',
      'tls-callback-inventory',
      'section-permission-risk',
      'workflow-handoff',
    ],
    evidence: ['structure', 'mitigations', 'sections', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: PE_SECURITY_PROFILE_ARTIFACT_TYPE,
      description: 'Passive PE mitigation, Load Config, TLS, and section-permission profile',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [PE_SECURITY_PROFILE_ARTIFACT_TYPE] },
    { category: 'mitigations', artifactTypes: [PE_SECURITY_PROFILE_ARTIFACT_TYPE] },
    { category: 'sections', artifactTypes: [PE_SECURITY_PROFILE_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [PE_SECURITY_PROFILE_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [PE_SECURITY_PROFILE_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'pe.security.hardening-profile',
      title: 'PE security hardening profile',
      description:
        'Assess PE ASLR, DEP/NX, CFG, SafeSEH/NO_SEH, Load Config, TLS callbacks, and section permission risks as passive static metadata.',
      startsWith: ['pe.security.profile', 'pe.structure.analyze'],
      nextTools: PE_SECURITY_RECOMMENDED_NEXT_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [PE_SECURITY_PROFILE_ARTIFACT_TYPE],
      evidence: ['structure', 'mitigations', 'sections', 'workflow', 'provenance'],
      safety: PE_SECURITY_SAFETY,
      runtimeBackends: ['builtin-pe-parser'],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'This tool parses PE metadata in-process and never executes or loads the sample.',
      'It does not query online CVE, reputation, or certificate services.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'builtin-pe-parser',
    backendKind: 'builtin',
    adapter: 'pe.security.profile',
    availability: 'builtin',
    supportedModes: ['profile'],
    defaultMode: 'profile',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [PE_SECURITY_PROFILE_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 120000,
      notes: ['Bounded in-process PE metadata parsing; no external backend is started.'],
    },
    readiness: {
      doesNotStartBackend: true,
      missingBackendBehavior: 'Builtin parser is always available with the Rikune server.',
    },
  },
}

type PESecurityProfile = z.infer<typeof PESecurityProfileDataSchema>

interface PESection {
  name: string
  virtualAddress: number
  virtualSize: number
  rawSize: number
  rawPointer: number
  characteristics: number
  executable: boolean
  writable: boolean
  readable: boolean
  writeExecute: boolean
}

interface ParsedPE {
  buffer: Buffer
  machine: number
  machineName: string
  peKind: 'pe32' | 'pe32-plus'
  imageBase: number
  entryPointRva: number
  subsystem: number
  characteristics: number
  dllCharacteristics: number
  sections: PESection[]
  dataDirectories: Array<{ rva: number; size: number; present: boolean }>
}

function readUInt64AsNumber(buffer: Buffer, offset: number): number {
  const low = buffer.readUInt32LE(offset)
  const high = buffer.readUInt32LE(offset + 4)
  return high * 0x1_0000_0000 + low
}

function directoryAt(parsed: ParsedPE, index: number) {
  return parsed.dataDirectories[index] ?? { rva: 0, size: 0, present: false }
}

function flagNames(value: number, flags: Array<[number, string]>): string[] {
  return flags.filter(([flag]) => (value & flag) !== 0).map(([, name]) => name)
}

function parseSections(
  buffer: Buffer,
  sectionTableOffset: number,
  numberOfSections: number
): PESection[] {
  const sections: PESection[] = []
  for (let index = 0; index < numberOfSections; index += 1) {
    const offset = sectionTableOffset + index * 40
    if (offset + 40 > buffer.length) break
    const name = buffer.toString('ascii', offset, offset + 8).replace(/\0+$/g, '')
    const virtualSize = buffer.readUInt32LE(offset + 8)
    const virtualAddress = buffer.readUInt32LE(offset + 12)
    const rawSize = buffer.readUInt32LE(offset + 16)
    const rawPointer = buffer.readUInt32LE(offset + 20)
    const characteristics = buffer.readUInt32LE(offset + 36)
    const executable = (characteristics & 0x20000000) !== 0
    const readable = (characteristics & 0x40000000) !== 0
    const writable = (characteristics & 0x80000000) !== 0
    sections.push({
      name,
      virtualAddress,
      virtualSize,
      rawSize,
      rawPointer,
      characteristics,
      executable,
      readable,
      writable,
      writeExecute: executable && writable,
    })
  }
  return sections
}

function getSectionForRva(sections: PESection[], rva: number): PESection | undefined {
  return sections.find((section) => {
    const maxSize = Math.max(section.virtualSize, section.rawSize)
    return rva >= section.virtualAddress && rva < section.virtualAddress + maxSize
  })
}

function rvaToOffset(parsed: ParsedPE, rva: number): number | undefined {
  const section = getSectionForRva(parsed.sections, rva)
  if (!section) {
    return rva < parsed.buffer.length ? rva : undefined
  }
  const delta = rva - section.virtualAddress
  if (delta < 0 || delta >= section.rawSize) return undefined
  const offset = section.rawPointer + delta
  return offset < parsed.buffer.length ? offset : undefined
}

function vaToOffset(parsed: ParsedPE, va: number): number | undefined {
  const rva = va - parsed.imageBase
  if (!Number.isFinite(rva) || rva < 0) return undefined
  return rvaToOffset(parsed, rva)
}

function parsePE(data: Buffer): ParsedPE {
  if (data.length < 0x100) throw new Error('File is too small to be a valid PE image.')
  if (data.toString('ascii', 0, 2) !== 'MZ') {
    throw new Error('File does not start with an MZ DOS header.')
  }
  const peOffset = data.readUInt32LE(0x3c)
  if (peOffset + 24 > data.length) throw new Error('PE header offset points outside the file.')
  if (data.toString('ascii', peOffset, peOffset + 4) !== 'PE\u0000\u0000') {
    throw new Error('PE signature was not found at e_lfanew.')
  }

  const fileHeaderOffset = peOffset + 4
  const machine = data.readUInt16LE(fileHeaderOffset)
  const numberOfSections = data.readUInt16LE(fileHeaderOffset + 2)
  const characteristics = data.readUInt16LE(fileHeaderOffset + 18)
  const sizeOfOptionalHeader = data.readUInt16LE(fileHeaderOffset + 16)
  const optionalHeaderOffset = fileHeaderOffset + 20
  if (optionalHeaderOffset + sizeOfOptionalHeader > data.length) {
    throw new Error('PE optional header extends outside the bounded preview.')
  }

  const optionalMagic = data.readUInt16LE(optionalHeaderOffset)
  const peKind = optionalMagic === 0x20b ? 'pe32-plus' : optionalMagic === 0x10b ? 'pe32' : null
  if (!peKind) {
    throw new Error(`Unsupported PE optional header magic: 0x${optionalMagic.toString(16)}`)
  }

  const isPe32Plus = peKind === 'pe32-plus'
  const imageBase = isPe32Plus
    ? readUInt64AsNumber(data, optionalHeaderOffset + 24)
    : data.readUInt32LE(optionalHeaderOffset + 28)
  const numberOfRvaAndSizes = data.readUInt32LE(optionalHeaderOffset + (isPe32Plus ? 108 : 92))
  const dataDirectoryStart = optionalHeaderOffset + (isPe32Plus ? 112 : 96)
  const dataDirectories = Array.from({ length: Math.min(numberOfRvaAndSizes, 16) }, (_, index) => {
    const offset = dataDirectoryStart + index * 8
    if (offset + 8 > optionalHeaderOffset + sizeOfOptionalHeader || offset + 8 > data.length) {
      return { rva: 0, size: 0, present: false }
    }
    const rva = data.readUInt32LE(offset)
    const size = data.readUInt32LE(offset + 4)
    return { rva, size, present: rva > 0 && size > 0 }
  })

  const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader
  return {
    buffer: data,
    machine,
    machineName: IMAGE_FILE_MACHINE_NAMES[machine] ?? `UNKNOWN_0x${machine.toString(16)}`,
    peKind,
    imageBase,
    entryPointRva: data.readUInt32LE(optionalHeaderOffset + 16),
    subsystem: data.readUInt16LE(optionalHeaderOffset + 68),
    characteristics,
    dllCharacteristics: data.readUInt16LE(optionalHeaderOffset + 70),
    sections: parseSections(data, sectionTableOffset, numberOfSections),
    dataDirectories,
  }
}

function parseLoadConfig(parsed: ParsedPE) {
  const directory = directoryAt(parsed, 10)
  const result = {
    present: directory.present,
    parsed: false,
    size: directory.size,
    security_cookie_va: undefined as number | undefined,
    seh_table_va: undefined as number | undefined,
    seh_count: undefined as number | undefined,
    guard_flags: undefined as number | undefined,
    guard_flags_names: [] as string[],
  }
  if (!directory.present) return result

  const offset = rvaToOffset(parsed, directory.rva)
  if (offset === undefined || offset + 4 > parsed.buffer.length) return result

  const declaredSize = parsed.buffer.readUInt32LE(offset)
  const availableSize = Math.min(directory.size || declaredSize, parsed.buffer.length - offset)
  result.size = declaredSize || directory.size
  const isPe32Plus = parsed.peKind === 'pe32-plus'
  const securityCookieOffset = offset + (isPe32Plus ? 88 : 72)
  const sehTableOffset = offset + (isPe32Plus ? 96 : 76)
  const sehCountOffset = offset + (isPe32Plus ? 104 : 80)
  const guardFlagsOffset = offset + (isPe32Plus ? 144 : 100)

  if (securityCookieOffset + (isPe32Plus ? 8 : 4) <= offset + availableSize) {
    result.security_cookie_va = isPe32Plus
      ? readUInt64AsNumber(parsed.buffer, securityCookieOffset)
      : parsed.buffer.readUInt32LE(securityCookieOffset)
  }
  if (sehTableOffset + (isPe32Plus ? 8 : 4) <= offset + availableSize) {
    result.seh_table_va = isPe32Plus
      ? readUInt64AsNumber(parsed.buffer, sehTableOffset)
      : parsed.buffer.readUInt32LE(sehTableOffset)
  }
  if (sehCountOffset + (isPe32Plus ? 8 : 4) <= offset + availableSize) {
    result.seh_count = isPe32Plus
      ? readUInt64AsNumber(parsed.buffer, sehCountOffset)
      : parsed.buffer.readUInt32LE(sehCountOffset)
  }
  if (guardFlagsOffset + 4 <= offset + availableSize) {
    result.guard_flags = parsed.buffer.readUInt32LE(guardFlagsOffset)
    result.guard_flags_names = flagNames(result.guard_flags, GUARD_FLAG_NAMES)
  }
  result.parsed = true
  return result
}

function parseTls(parsed: ParsedPE) {
  const directory = directoryAt(parsed, 9)
  const result = {
    present: directory.present,
    callback_table_va: undefined as number | undefined,
    callback_count: 0,
    callback_rvas: [] as number[],
  }
  if (!directory.present) return result
  const offset = rvaToOffset(parsed, directory.rva)
  if (offset === undefined) return result

  const isPe32Plus = parsed.peKind === 'pe32-plus'
  const callbackAddressOffset = offset + (isPe32Plus ? 24 : 12)
  const pointerSize = isPe32Plus ? 8 : 4
  if (callbackAddressOffset + pointerSize > parsed.buffer.length) return result

  const callbackTableVa = isPe32Plus
    ? readUInt64AsNumber(parsed.buffer, callbackAddressOffset)
    : parsed.buffer.readUInt32LE(callbackAddressOffset)
  result.callback_table_va = callbackTableVa || undefined
  const callbackTableOffset = callbackTableVa ? vaToOffset(parsed, callbackTableVa) : undefined
  if (callbackTableOffset === undefined) return result

  for (let index = 0; index < 64; index += 1) {
    const entryOffset = callbackTableOffset + index * pointerSize
    if (entryOffset + pointerSize > parsed.buffer.length) break
    const callbackVa = isPe32Plus
      ? readUInt64AsNumber(parsed.buffer, entryOffset)
      : parsed.buffer.readUInt32LE(entryOffset)
    if (!callbackVa) break
    const rva = callbackVa - parsed.imageBase
    if (Number.isFinite(rva) && rva >= 0) result.callback_rvas.push(rva)
  }
  result.callback_count = result.callback_rvas.length
  return result
}

function buildMitigations(parsed: ParsedPE, loadConfig: ReturnType<typeof parseLoadConfig>) {
  const dll = parsed.dllCharacteristics
  const guardFlags = loadConfig.guard_flags ?? 0
  const isX86 = parsed.machine === 0x014c
  return {
    aslr: {
      enabled: (dll & 0x0040) !== 0,
      source: 'DllCharacteristics.dynamic_base',
      evidence: 'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE',
      severity_if_missing: 'high' as const,
    },
    high_entropy_va: {
      enabled: (dll & 0x0020) !== 0,
      source: 'DllCharacteristics.high_entropy_va',
      evidence: 'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA',
      severity_if_missing: 'medium' as const,
    },
    dep_nx: {
      enabled: (dll & 0x0100) !== 0,
      source: 'DllCharacteristics.nx_compat',
      evidence: 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT',
      severity_if_missing: 'high' as const,
    },
    no_seh: {
      enabled: !isX86 || (dll & 0x0400) !== 0 || Boolean(loadConfig.seh_count),
      source: isX86 ? 'DllCharacteristics.no_seh_or_load_config.seh_count' : 'architecture',
      evidence: isX86 ? 'NO_SEH or SafeSEH table evidence' : 'SafeSEH is x86-specific',
      severity_if_missing: isX86 ? ('medium' as const) : ('info' as const),
    },
    control_flow_guard: {
      enabled: (dll & 0x4000) !== 0 || (guardFlags & 0x00000500) !== 0,
      source: 'DllCharacteristics.guard_cf_or_LoadConfig.GuardFlags',
      evidence: 'GUARD_CF or GuardFlags CF instrumentation/table',
      severity_if_missing: 'medium' as const,
    },
    force_integrity: {
      enabled: (dll & 0x0080) !== 0,
      source: 'DllCharacteristics.force_integrity',
      evidence: 'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY',
      severity_if_missing: 'low' as const,
    },
    app_container: {
      enabled: (dll & 0x1000) !== 0,
      source: 'DllCharacteristics.app_container',
      evidence: 'IMAGE_DLLCHARACTERISTICS_APPCONTAINER',
      severity_if_missing: 'info' as const,
    },
    security_cookie: {
      enabled: Boolean(loadConfig.security_cookie_va),
      source: 'LoadConfig.SecurityCookie',
      evidence: 'Load Config security cookie VA',
      severity_if_missing: 'medium' as const,
    },
    retpoline_or_xfg: {
      enabled: (guardFlags & (0x00100000 | 0x00400000)) !== 0,
      source: 'LoadConfig.GuardFlags',
      evidence: 'retpoline_present or xfg_enabled',
      severity_if_missing: 'info' as const,
    },
  }
}

function buildRiskFactors(
  parsed: ParsedPE,
  mitigations: ReturnType<typeof buildMitigations>,
  loadConfig: ReturnType<typeof parseLoadConfig>,
  tls: ReturnType<typeof parseTls>
) {
  const factors: Array<{ id: string; severity: string; score: number; detail: string }> = []
  const add = (id: string, severity: string, score: number, detail: string) =>
    factors.push({ id, severity, score, detail })

  if (!mitigations.aslr.enabled) add('missing_aslr', 'high', 20, 'DYNAMIC_BASE is not set.')
  if (!mitigations.dep_nx.enabled) add('missing_dep_nx', 'high', 25, 'NX_COMPAT is not set.')
  if (parsed.peKind === 'pe32-plus' && !mitigations.high_entropy_va.enabled) {
    add('missing_high_entropy_va', 'medium', 6, 'HIGH_ENTROPY_VA is not set on PE32+ image.')
  }
  if (!mitigations.control_flow_guard.enabled) {
    add('missing_cfg', 'medium', 10, 'No GUARD_CF or Load Config CFG table evidence found.')
  }
  if (!mitigations.security_cookie.enabled) {
    add('missing_security_cookie', 'medium', 10, 'Load Config security cookie was not found.')
  }
  if (!loadConfig.present) {
    add('missing_load_config', 'medium', 8, 'Load Config directory is absent.')
  }
  if (tls.callback_count > 0) {
    add('tls_callbacks_present', 'medium', 8, `${tls.callback_count} TLS callback(s) found.`)
  }
  for (const section of parsed.sections.filter((candidate) => candidate.writeExecute)) {
    add(
      'write_execute_section',
      'high',
      20,
      `Section ${section.name || '<unnamed>'} is both writable and executable.`
    )
  }
  return factors
}

function toDirectorySchema(directory: { rva: number; size: number; present: boolean }) {
  return { rva: directory.rva, size: directory.size, present: directory.present }
}

export function buildPESecurityProfileFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): PESecurityProfile {
  const parsed = parsePE(data)
  const loadConfig = parseLoadConfig(parsed)
  const tls = parseTls(parsed)
  const mitigations = buildMitigations(parsed, loadConfig)
  const riskFactors = buildRiskFactors(parsed, mitigations, loadConfig, tls)
  const riskScore = Math.min(
    100,
    riskFactors.reduce((sum, factor) => sum + factor.score, 0)
  )
  const posture = riskScore >= 40 ? 'high-risk' : riskScore >= 15 ? 'medium-risk' : 'low-risk'
  const sections = parsed.sections.map((section) => ({
    name: section.name,
    virtual_address: section.virtualAddress,
    virtual_size: section.virtualSize,
    raw_size: section.rawSize,
    raw_pointer: section.rawPointer,
    characteristics: section.characteristics,
    executable: section.executable,
    writable: section.writable,
    readable: section.readable,
    write_execute: section.writeExecute,
  }))
  const sectionRisks = sections
    .filter((section) => section.write_execute)
    .map((section) => ({
      type: 'write_execute_section',
      section: section.name,
      severity: 'high',
      reason: 'Writable executable section weakens W^X posture.',
    }))

  return PESecurityProfileDataSchema.parse({
    schema: 'rikune.pe_security_profile.v1',
    sample_id: options.sampleId,
    filename: options.filename,
    size: options.size ?? data.length,
    machine: parsed.machine,
    machine_name: parsed.machineName,
    pe_kind: parsed.peKind,
    image_base: parsed.imageBase,
    entry_point_rva: parsed.entryPointRva,
    subsystem: parsed.subsystem,
    characteristics: parsed.characteristics,
    dll_characteristics: parsed.dllCharacteristics,
    dll_characteristics_flags: flagNames(parsed.dllCharacteristics, DLL_CHARACTERISTIC_FLAGS),
    mitigations,
    data_directories: {
      exception: toDirectorySchema(directoryAt(parsed, 3)),
      security: toDirectorySchema(directoryAt(parsed, 4)),
      load_config: toDirectorySchema(directoryAt(parsed, 10)),
      tls: toDirectorySchema(directoryAt(parsed, 9)),
    },
    load_config: loadConfig,
    tls,
    sections,
    section_risks: sectionRisks,
    risk_score: riskScore,
    posture,
    risk_factors: riskFactors,
    policy: {
      passive: true,
      no_execute: true,
      no_load: true,
      no_network: true,
      no_mutation: true,
    },
    evidence_summary: {
      schema: 'rikune.pe_security_profile.evidence_summary.v1',
      source_tool: TOOL_NAME,
      tool_version: TOOL_VERSION,
      sample_id: options.sampleId,
      artifact_type: PE_SECURITY_PROFILE_ARTIFACT_TYPE,
      posture,
      risk_score: riskScore,
      enabled_mitigations: Object.entries(mitigations)
        .filter(([, mitigation]) => mitigation.enabled)
        .map(([name]) => name),
      missing_mitigations: Object.entries(mitigations)
        .filter(([, mitigation]) => !mitigation.enabled)
        .map(([name]) => name),
      write_execute_section_count: sectionRisks.length,
      tls_callback_count: tls.callback_count,
      static_only: true,
    },
    workflow_handoff: {
      schema: 'rikune.pe_security_profile.workflow_handoff.v1',
      handoff_mode: 'pe_security_profile_to_static_triage_and_runtime_planning',
      recommended_next_tools: PE_SECURITY_RECOMMENDED_NEXT_TOOLS,
      artifact_contract: {
        consumes: ['sample'],
        produces: [PE_SECURITY_PROFILE_ARTIFACT_TYPE],
        expected_consumers: PE_SECURITY_RECOMMENDED_NEXT_TOOLS,
      },
      routing: [
        {
          goal: 'corroborate-headers-and-sections',
          next_tools: ['pe.structure.analyze', 'pe.imports.extract'],
          priority: 'normal',
        },
        {
          goal: 'function-boundary-and-exception-review',
          next_tools: ['pe.pdata.extract'],
          priority: directoryAt(parsed, 3).present ? 'high' : 'normal',
        },
        {
          goal: 'security-reporting',
          next_tools: ['analysis.evidence.graph', 'report.generate'],
          priority: riskScore >= 40 ? 'high' : 'normal',
        },
      ],
      dynamic_boundary: {
        sample_execution_allowed: false,
        loader_invocation_allowed: false,
        network_allowed: false,
        mutation_allowed: false,
        sample_executed_by_tool: false,
        loader_invoked_by_tool: false,
        network_used_by_tool: false,
        mutation_performed: false,
      },
    },
    quality_gates: {
      schema: 'rikune.pe_security_profile.quality_gates.v1',
      passive_static_analysis: true,
      builtin_parser_only: true,
      sample_executed_by_tool: false,
      loader_invoked_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
      dll_characteristics_parsed: true,
      sections_reviewed: sections.length > 0,
      load_config_reviewed: loadConfig.present,
      tls_reviewed: true,
      analyst_review_required: riskScore >= 15 || tls.callback_count > 0,
    },
    recommended_next_tools: PE_SECURITY_RECOMMENDED_NEXT_TOOLS,
    next_actions: [
      'Review missing mitigation and section-permission risk factors before prioritizing dynamic analysis.',
      'Run pe.structure.analyze to corroborate parser output when external static backends are available.',
      'Use pe.pdata.extract when exception directory evidence can improve function boundary recovery.',
      'Keep loader behavior, exploitability testing, and runtime validation behind explicit opt-in runtime plans.',
    ],
  })
}

async function readPreview(
  filePath: string,
  maxReadBytes: number
): Promise<{ data: Buffer; size: number }> {
  const stat = await fs.stat(filePath)
  const handle = await fs.open(filePath, 'r')
  try {
    const length = Math.min(stat.size, maxReadBytes)
    const data = Buffer.alloc(length)
    await handle.read(data, 0, length, 0)
    return { data, size: stat.size }
  } finally {
    await handle.close()
  }
}

export function createPESecurityProfileHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (args: z.infer<typeof PESecurityProfileInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = PESecurityProfileInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const profile = buildPESecurityProfileFromBuffer(data, {
        filename: path.basename(samplePath),
        sampleId: input.sample_id,
        size,
      })

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
        try {
          const artifact = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            PE_SECURITY_PROFILE_ARTIFACT_TYPE,
            'pe-security-profile',
            profile,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Artifact persistence is best-effort for passive security profiling.
        }
      }

      return {
        ok: true,
        data: profile,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${error instanceof Error ? error.message : String(error)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
