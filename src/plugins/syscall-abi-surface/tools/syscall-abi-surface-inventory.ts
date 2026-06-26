/**
 * syscall.abi.surface.inventory - passive syscall ABI surface inventory.
 *
 * This tool reads bounded bytes and summarizes user-kernel boundary evidence:
 * syscall/sysenter/int/SVC/ecall instruction patterns, Windows direct syscall
 * stubs, NT API resolver strings, Linux syscall/seccomp hints, Mach trap hints,
 * anti-analysis syscall references, and static workflow handoff. It never
 * executes the sample, invokes syscalls, attaches tracers/debuggers, starts
 * emulation, invokes external tools, accesses devices, uses the network, or
 * mutates samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'syscall.abi.surface.inventory'
export const SYSCALL_ABI_SURFACE_ARTIFACT_TYPE = 'syscall_abi_surface_inventory'

const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 10000
const MAX_STRING_EVIDENCE = 420
const MAX_OPCODE_EVIDENCE = 320

const SYSCALL_ABI_EVIDENCE = [
  'structure',
  'bytecode',
  'syscalls',
  'abi',
  'strings',
  'evasion',
  'risk',
  'workflow',
  'provenance',
]

const SYSCALL_ABI_SAFETY = [
  'passive',
  'no_execute',
  'no_syscall',
  'no_ptrace',
  'no_strace',
  'no_ltrace',
  'no_debugger',
  'no_frida',
  'no_emulation',
  'no_device_open',
  'no_driver_load',
  'no_external_tool',
  'no_network_by_default',
  'no_mutation',
]

const SYSCALL_ABI_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'pe.imports.extract',
  'linux.binary.inventory',
  'native.object.inventory',
  'code.xrefs.analyze',
  'vuln.pattern.scan',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const SYSCALL_ABI_RUNTIME_HANDOFF_TOOLS = [
  'windows.runtime.plan',
  'linux.runtime.plan',
  'macos.runtime.plan',
  'debug.session.plan',
]

type Confidence = 'low' | 'medium' | 'high'
type StringEncoding = 'ascii' | 'utf16le'
type StringFamily =
  | 'windows-nt'
  | 'direct-syscall'
  | 'linux'
  | 'macos'
  | 'anti-analysis'
  | 'resolver'
  | 'wow64'
  | 'library'
  | 'abi'

interface BinaryString {
  value: string
  offset: number
  encoding: StringEncoding
}

interface StringRule {
  pattern: RegExp
  id: string
  kind: string
  family: StringFamily
  confidence: Confidence
  flags?: string[]
}

interface StringEvidence {
  id: string
  kind: string
  family: StringFamily
  value: string
  offset: number
  encoding: StringEncoding
  confidence: Confidence
  flags: string[]
}

interface OpcodeEvidence {
  offset: number
  isa: string
  mnemonic: string
  opcode_hex: string
  family: string
  mode: string
  confidence: Confidence
  syscall_number: number | null
  flags: string[]
  nearby_strings: string[]
}

interface BuildOptions {
  filename?: string
  sampleId?: string
  maxReadBytes?: number
  size?: number
}

export const syscallAbiSurfaceInventoryAspects = {
  formats: [
    'syscall',
    'syscall-stub',
    'direct-syscall',
    'raw-shellcode',
    'shellcode',
    'ntdll-stub',
    'linux-syscall',
    'mach-trap',
    'pe',
    'elf',
    'macho',
  ],
  platforms: ['windows', 'linux', 'macos', 'ios', 'android', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'riscv'],
  execution: ['static', 'triage', 'correlation'],
  safety: SYSCALL_ABI_SAFETY,
  capabilities: [
    'syscall-abi-surface-inventory',
    'direct-syscall-stub-detection',
    'nt-api-boundary-hints',
    'linux-syscall-instruction-hints',
    'mach-trap-hints',
    'svc-ecall-boundary-hints',
    'syscall-evasion-risk-routing',
  ],
  evidence: SYSCALL_ABI_EVIDENCE,
  route_terms: [
    'syscall',
    'direct syscall',
    'indirect syscall',
    'hells gate',
    'halos gate',
    'tartarusgate',
    'syswhispers',
    'ntdll syscall stub',
    'sysenter',
    'int 0x80',
    'svc',
    'ecall',
    'mach trap',
    'seccomp',
    'ptrace',
  ],
  search: [
    'direct syscall stub inventory',
    'syscall ABI surface triage',
    'user kernel boundary static inventory',
    'Hell Gate SysWhispers syscall evasion detection',
    'Linux syscall seccomp ptrace static hints',
  ],
}

const SyscallAbiPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_syscall: z.literal(true),
  no_ptrace: z.literal(true),
  no_strace: z.literal(true),
  no_ltrace: z.literal(true),
  no_debugger: z.literal(true),
  no_frida: z.literal(true),
  no_emulation: z.literal(true),
  no_device_open: z.literal(true),
  no_driver_load: z.literal(true),
  no_external_tool: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const SyscallAbiInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  platforms: z.array(z.string()),
  architectures: z.array(z.string()),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.any()),
  instruction_evidence: z.array(z.record(z.any())),
  string_evidence: z.array(z.record(z.any())),
  syscall_stubs: z.array(z.record(z.any())),
  windows_nt_surface: z.record(z.any()),
  linux_syscall_surface: z.record(z.any()),
  mach_trap_surface: z.record(z.any()),
  anti_analysis_surface: z.record(z.any()),
  risk_flags: z.array(z.record(z.any())),
  risk_summary: z.record(z.any()),
  policy: SyscallAbiPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const SyscallAbiSurfaceInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive syscall ABI surface inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist syscall ABI surface inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const SyscallAbiSurfaceInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: SyscallAbiInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const syscallAbiSurfaceInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory syscall ABI and user-kernel boundary evidence, including Windows direct syscall stubs, NT resolver strings, Linux syscall/seccomp hints, Mach traps, ARM SVC/RISC-V ecall patterns, and evasion risk handoff without executing the sample, invoking syscalls, tracing, debugging, emulating, opening devices, or using external tools.',
  inputSchema: SyscallAbiSurfaceInventoryInputSchema,
  outputSchema: SyscallAbiSurfaceInventoryOutputSchema,
  aspects: syscallAbiSurfaceInventoryAspects,
  artifacts: [
    {
      type: SYSCALL_ABI_SURFACE_ARTIFACT_TYPE,
      description: 'Passive syscall ABI and user-kernel boundary surface inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: SYSCALL_ABI_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [SYSCALL_ABI_SURFACE_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'syscall.abi-surface-static-inventory',
      title: 'Passive syscall ABI surface inventory',
      description:
        'Inventory static syscall instruction patterns, direct syscall stubs, NT/Linux/Mach boundary strings, anti-analysis syscall hints, and risk flags before routing to imports, strings, xrefs, vulnerability, evidence graph, reporting, or explicit runtime-planning tools.',
      startsWith: [TOOL_NAME],
      nextTools: SYSCALL_ABI_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [SYSCALL_ABI_SURFACE_ARTIFACT_TYPE],
      evidence: SYSCALL_ABI_EVIDENCE,
      safety: SYSCALL_ABI_SAFETY,
    },
  ],
}

export type SyscallAbiInventory = z.infer<typeof SyscallAbiInventorySchema>

const STRING_RULES: StringRule[] = [
  {
    pattern: /\b(?:Hell'?s\s*Gate|HellsGate|HalosGate|Halo'?s\s*Gate|TartarusGate)\b/i,
    id: 'direct-syscall.named-technique',
    kind: 'direct-syscall-technique',
    family: 'direct-syscall',
    confidence: 'high',
    flags: ['direct-syscall-evasion'],
  },
  {
    pattern: /\b(?:SysWhispers|SW3_GetSyscallNumber|SW3_GetRandomSyscallAddress)\b/i,
    id: 'direct-syscall.syswhispers',
    kind: 'syscall-resolver-framework',
    family: 'direct-syscall',
    confidence: 'high',
    flags: ['syswhispers'],
  },
  {
    pattern:
      /\b(?:Nt|Zw)(?:Allocate|Protect|Write|Read|Create|Open|Map|Unmap|Queue|Query|Set)[A-Za-z0-9_]*\b/,
    id: 'windows.nt-api-reference',
    kind: 'nt-api',
    family: 'windows-nt',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:ntdll\.dll|win32u\.dll|LdrGetProcedureAddress|GetProcAddress)\b/i,
    id: 'windows.ntdll-resolver',
    kind: 'ntdll-resolver',
    family: 'resolver',
    confidence: 'medium',
    flags: ['late-bound-syscall-surface'],
  },
  {
    pattern: /\b(?:wow64cpu|Wow64Transition|X86SwitchTo64BitMode|Heaven'?s\s*Gate)\b/i,
    id: 'windows.wow64-transition',
    kind: 'wow64-transition',
    family: 'wow64',
    confidence: 'medium',
    flags: ['wow64-boundary'],
  },
  {
    pattern: /\b(?:__NR_[A-Za-z0-9_]+|SYS_[A-Za-z0-9_]+|syscall\()\b/,
    id: 'linux.syscall-symbol',
    kind: 'linux-syscall-symbol',
    family: 'linux',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:seccomp|SECCOMP|prctl|PR_SET_NO_NEW_PRIVS|PR_SET_SECCOMP)\b/,
    id: 'linux.seccomp-policy',
    kind: 'seccomp',
    family: 'linux',
    confidence: 'high',
    flags: ['sandbox-policy'],
  },
  {
    pattern: /\b(?:ptrace|PTRACE_TRACEME|PTRACE_ATTACH|PTRACE_PEEK|PTRACE_POKE)\b/,
    id: 'anti-analysis.ptrace',
    kind: 'ptrace',
    family: 'anti-analysis',
    confidence: 'high',
    flags: ['anti-debug'],
  },
  {
    pattern:
      /\b(?:NtQueryInformationProcess|NtSetInformationThread|NtQuerySystemInformation|IsDebuggerPresent)\b/,
    id: 'anti-analysis.nt-query',
    kind: 'anti-debug-api',
    family: 'anti-analysis',
    confidence: 'high',
    flags: ['anti-debug'],
  },
  {
    pattern:
      /\b(?:mach_msg|mach_port|host_self_trap|thread_self_trap|task_self_trap|mach_absolute_time)\b/i,
    id: 'macos.mach-trap-reference',
    kind: 'mach-trap',
    family: 'macos',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:x0|x1|x2|x3|x8|r10|rcx|rax|eax|svc|ecall|sysenter|int\s+0x80)\b/i,
    id: 'abi.register-or-instruction-text',
    kind: 'abi-text',
    family: 'abi',
    confidence: 'low',
  },
]

const HIGH_RISK_NT_APIS = [
  'NtAllocateVirtualMemory',
  'NtProtectVirtualMemory',
  'NtWriteVirtualMemory',
  'NtReadVirtualMemory',
  'NtCreateThreadEx',
  'NtQueueApcThread',
  'NtMapViewOfSection',
  'NtUnmapViewOfSection',
  'NtOpenProcess',
  'NtOpenThread',
  'NtSetContextThread',
  'NtResumeThread',
]

function clampMaxReadBytes(value: number | undefined): number {
  if (!Number.isFinite(value ?? DEFAULT_MAX_READ_BYTES)) return DEFAULT_MAX_READ_BYTES
  return Math.max(1024, Math.min(MAX_PREVIEW_BYTES, Math.trunc(value ?? DEFAULT_MAX_READ_BYTES)))
}

function toHex(data: Buffer): string {
  return data.toString('hex')
}

function extractAsciiStrings(data: Buffer): BinaryString[] {
  const strings: BinaryString[] = []
  let start = -1
  for (let i = 0; i < data.length; i += 1) {
    const byte = data[i]
    const printable = byte >= 0x20 && byte <= 0x7e
    if (printable) {
      if (start < 0) start = i
    } else if (start >= 0) {
      if (i - start >= 4) {
        strings.push({
          value: data.subarray(start, i).toString('ascii'),
          offset: start,
          encoding: 'ascii',
        })
      }
      start = -1
    }
  }
  if (start >= 0 && data.length - start >= 4) {
    strings.push({
      value: data.subarray(start).toString('ascii'),
      offset: start,
      encoding: 'ascii',
    })
  }
  return strings
}

function extractUtf16Strings(data: Buffer): BinaryString[] {
  const strings: BinaryString[] = []
  let start = -1
  for (let i = 0; i + 1 < data.length; i += 2) {
    const byte = data[i]
    const nul = data[i + 1]
    const printable = nul === 0 && byte >= 0x20 && byte <= 0x7e
    if (printable) {
      if (start < 0) start = i
    } else if (start >= 0) {
      if (i - start >= 8) {
        strings.push({
          value: data.subarray(start, i).toString('utf16le'),
          offset: start,
          encoding: 'utf16le',
        })
      }
      start = -1
    }
  }
  if (start >= 0 && data.length - start >= 8) {
    strings.push({
      value: data.subarray(start).toString('utf16le').replace(/\0+$/u, ''),
      offset: start,
      encoding: 'utf16le',
    })
  }
  return strings
}

function extractBinaryStrings(data: Buffer): BinaryString[] {
  const all = [...extractAsciiStrings(data), ...extractUtf16Strings(data)]
  return all
    .filter((item) => item.value.trim().length >= 4)
    .sort((a, b) => a.offset - b.offset)
    .slice(0, MAX_STRINGS)
}

function collectStringEvidence(strings: BinaryString[]): StringEvidence[] {
  const evidence: StringEvidence[] = []
  const seen = new Set<string>()
  for (const item of strings) {
    for (const rule of STRING_RULES) {
      if (!rule.pattern.test(item.value)) continue
      const key = `${rule.id}:${item.offset}:${item.value}`
      if (seen.has(key)) continue
      seen.add(key)
      evidence.push({
        id: rule.id,
        kind: rule.kind,
        family: rule.family,
        value: item.value,
        offset: item.offset,
        encoding: item.encoding,
        confidence: rule.confidence,
        flags: rule.flags ?? [],
      })
      if (evidence.length >= MAX_STRING_EVIDENCE) return evidence
    }
  }
  return evidence
}

function stringsNearOffset(strings: BinaryString[], offset: number): string[] {
  return strings
    .filter((item) => Math.abs(item.offset - offset) <= 256)
    .map((item) => item.value)
    .slice(0, 8)
}

function findMovEaxImmediate(data: Buffer, syscallOffset: number): number | null {
  const start = Math.max(0, syscallOffset - 12)
  for (let i = syscallOffset - 5; i >= start; i -= 1) {
    if (i >= 0 && i + 4 < data.length && data[i] === 0xb8) {
      return data.readUInt32LE(i + 1)
    }
  }
  return null
}

function hasMovR10Rcx(data: Buffer, syscallOffset: number): boolean {
  const start = Math.max(0, syscallOffset - 12)
  for (let i = start; i + 2 < syscallOffset; i += 1) {
    if (data[i] === 0x4c && data[i + 1] === 0x8b && data[i + 2] === 0xd1) {
      return true
    }
  }
  return false
}

function hasRetAfter(data: Buffer, offset: number, size: number): boolean {
  const next = offset + size
  return next < data.length && data[next] === 0xc3
}

function pushOpcodeEvidence(evidence: OpcodeEvidence[], entry: OpcodeEvidence): boolean {
  evidence.push(entry)
  return evidence.length < MAX_OPCODE_EVIDENCE
}

function collectOpcodeEvidence(data: Buffer, strings: BinaryString[]): OpcodeEvidence[] {
  const evidence: OpcodeEvidence[] = []
  for (let i = 0; i < data.length && evidence.length < MAX_OPCODE_EVIDENCE; i += 1) {
    if (i + 1 < data.length && data[i] === 0x0f && data[i + 1] === 0x05) {
      const syscallNumber = findMovEaxImmediate(data, i)
      const movR10Rcx = hasMovR10Rcx(data, i)
      const retAfter = hasRetAfter(data, i, 2)
      const flags = ['syscall-instruction']
      if (syscallNumber !== null) flags.push('syscall-number-immediate')
      if (movR10Rcx) flags.push('windows-x64-nt-abi')
      if (retAfter) flags.push('stub-ret')
      if (
        !pushOpcodeEvidence(evidence, {
          offset: i,
          isa: 'x86-64',
          mnemonic: 'syscall',
          opcode_hex: toHex(data.subarray(i, i + 2)),
          family: movR10Rcx ? 'windows-nt-direct-syscall' : 'generic-syscall',
          mode: 'long-mode',
          confidence: movR10Rcx && syscallNumber !== null ? 'high' : 'medium',
          syscall_number: syscallNumber,
          flags,
          nearby_strings: stringsNearOffset(strings, i),
        })
      ) {
        break
      }
      i += 1
      continue
    }

    if (i + 1 < data.length && data[i] === 0x0f && data[i + 1] === 0x34) {
      if (
        !pushOpcodeEvidence(evidence, {
          offset: i,
          isa: 'x86',
          mnemonic: 'sysenter',
          opcode_hex: toHex(data.subarray(i, i + 2)),
          family: 'x86-fast-syscall',
          mode: 'protected-mode',
          confidence: 'medium',
          syscall_number: findMovEaxImmediate(data, i),
          flags: ['sysenter-instruction'],
          nearby_strings: stringsNearOffset(strings, i),
        })
      ) {
        break
      }
      i += 1
      continue
    }

    if (i + 1 < data.length && data[i] === 0xcd && data[i + 1] === 0x2e) {
      if (
        !pushOpcodeEvidence(evidence, {
          offset: i,
          isa: 'x86',
          mnemonic: 'int 0x2e',
          opcode_hex: toHex(data.subarray(i, i + 2)),
          family: 'windows-nt-legacy-syscall',
          mode: 'protected-mode',
          confidence: 'medium',
          syscall_number: findMovEaxImmediate(data, i),
          flags: ['int-2e'],
          nearby_strings: stringsNearOffset(strings, i),
        })
      ) {
        break
      }
      i += 1
      continue
    }

    if (i + 1 < data.length && data[i] === 0xcd && data[i + 1] === 0x80) {
      if (
        !pushOpcodeEvidence(evidence, {
          offset: i,
          isa: 'x86',
          mnemonic: 'int 0x80',
          opcode_hex: toHex(data.subarray(i, i + 2)),
          family: 'linux-or-bsd-syscall',
          mode: 'protected-mode',
          confidence: 'medium',
          syscall_number: findMovEaxImmediate(data, i),
          flags: ['int-80'],
          nearby_strings: stringsNearOffset(strings, i),
        })
      ) {
        break
      }
      i += 1
      continue
    }

    if (i + 3 < data.length) {
      const word = data.readUInt32LE(i)
      if ((word & 0xffe0001f) === 0xd4000001) {
        const imm = (word >>> 5) & 0xffff
        if (
          !pushOpcodeEvidence(evidence, {
            offset: i,
            isa: 'arm64',
            mnemonic: `svc #${imm}`,
            opcode_hex: toHex(data.subarray(i, i + 4)),
            family: 'arm64-supervisor-call',
            mode: 'aarch64',
            confidence: 'medium',
            syscall_number: imm,
            flags: ['svc-instruction', 'arm64-x8-syscall-abi'],
            nearby_strings: stringsNearOffset(strings, i),
          })
        ) {
          break
        }
        i += 3
        continue
      }

      if ((word & 0xff000000) === 0xef000000) {
        const imm = word & 0x00ffffff
        if (
          !pushOpcodeEvidence(evidence, {
            offset: i,
            isa: 'arm',
            mnemonic: `svc #${imm}`,
            opcode_hex: toHex(data.subarray(i, i + 4)),
            family: 'arm-supervisor-call',
            mode: 'a32',
            confidence: 'low',
            syscall_number: imm,
            flags: ['svc-instruction'],
            nearby_strings: stringsNearOffset(strings, i),
          })
        ) {
          break
        }
        i += 3
        continue
      }

      if (word === 0x00000073) {
        if (
          !pushOpcodeEvidence(evidence, {
            offset: i,
            isa: 'riscv',
            mnemonic: 'ecall',
            opcode_hex: toHex(data.subarray(i, i + 4)),
            family: 'riscv-environment-call',
            mode: 'riscv',
            confidence: 'medium',
            syscall_number: null,
            flags: ['ecall-instruction'],
            nearby_strings: stringsNearOffset(strings, i),
          })
        ) {
          break
        }
        i += 3
        continue
      }
    }

    if (i + 1 < data.length && data[i] === 0xdf) {
      const imm = data[i + 1]
      if (
        !pushOpcodeEvidence(evidence, {
          offset: i,
          isa: 'arm',
          mnemonic: `svc #${imm}`,
          opcode_hex: toHex(data.subarray(i, i + 2)),
          family: 'thumb-supervisor-call',
          mode: 'thumb',
          confidence: 'low',
          syscall_number: imm,
          flags: ['svc-instruction', 'thumb'],
          nearby_strings: stringsNearOffset(strings, i),
        })
      ) {
        break
      }
      i += 1
    }
  }
  return evidence
}

function detectContainer(preview: Buffer, maxReadBytes: number, options: BuildOptions) {
  const magic = preview.subarray(0, Math.min(preview.length, 16))
  const filename = (options.filename ?? '').toLowerCase()
  const extension = filename.includes('.') ? filename.slice(filename.lastIndexOf('.') + 1) : ''
  const container = {
    magic_hex: magic.toString('hex'),
    extension,
    bounded_read: true,
    max_read_bytes: maxReadBytes,
    truncated: typeof options.size === 'number' ? options.size > preview.length : false,
    pe: preview.length >= 2 && preview[0] === 0x4d && preview[1] === 0x5a,
    elf:
      preview.length >= 4 &&
      preview[0] === 0x7f &&
      preview[1] === 0x45 &&
      preview[2] === 0x4c &&
      preview[3] === 0x46,
    mach_o: false,
    raw_shellcode_hint: ['sc', 'shellcode', 'syscall', 'stub'].includes(extension),
  }
  if (preview.length >= 4) {
    const le = preview.readUInt32LE(0)
    const be = preview.readUInt32BE(0)
    container.mach_o =
      [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcafebabf].includes(le) ||
      [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcafebabf].includes(be)
  }
  return container
}

function detectFormat(
  container: Record<string, any>,
  instructionEvidence: OpcodeEvidence[],
  stringEvidence: StringEvidence[]
): { format: string; confidence: Confidence; detectedBy: string[] } {
  const detectedBy: string[] = []
  if (container.pe) detectedBy.push('pe-magic')
  if (container.elf) detectedBy.push('elf-magic')
  if (container.mach_o) detectedBy.push('mach-o-magic')
  if (container.raw_shellcode_hint) detectedBy.push('raw-shellcode-extension')
  if (instructionEvidence.length > 0) detectedBy.push('syscall-opcode-pattern')
  if (stringEvidence.length > 0) detectedBy.push('syscall-string-evidence')

  const hasWindowsStub = instructionEvidence.some((item) =>
    item.flags.includes('windows-x64-nt-abi')
  )
  const hasMach =
    Boolean(container.mach_o) || stringEvidence.some((item) => item.family === 'macos')
  const hasLinux =
    Boolean(container.elf) ||
    instructionEvidence.some((item) => item.family.includes('linux')) ||
    stringEvidence.some((item) => item.family === 'linux')

  if (container.pe && hasWindowsStub) {
    return { format: 'pe-windows-direct-syscall-surface', confidence: 'high', detectedBy }
  }
  if (container.pe) {
    return { format: 'pe-syscall-abi-surface', confidence: 'medium', detectedBy }
  }
  if (container.raw_shellcode_hint && hasWindowsStub) {
    return { format: 'raw-shellcode-windows-direct-syscall-stubs', confidence: 'high', detectedBy }
  }
  if (hasLinux) {
    return {
      format: container.elf ? 'elf-linux-syscall-abi-surface' : 'linux-syscall-abi-surface',
      confidence: instructionEvidence.length > 0 ? 'high' : 'medium',
      detectedBy,
    }
  }
  if (hasMach) {
    return { format: 'mach-o-syscall-trap-surface', confidence: 'medium', detectedBy }
  }
  if (instructionEvidence.length > 0) {
    return { format: 'raw-syscall-abi-surface', confidence: 'medium', detectedBy }
  }
  return { format: 'syscall-abi-surface-low-signal', confidence: 'low', detectedBy }
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)))
}

function collectArchitectures(instructionEvidence: OpcodeEvidence[]): string[] {
  const mapped = instructionEvidence.map((item) => {
    if (item.isa === 'x86-64') return 'x64'
    if (item.isa === 'riscv') return 'riscv'
    return item.isa
  })
  return uniqueStrings(mapped)
}

function collectPlatforms(
  container: Record<string, any>,
  instructionEvidence: OpcodeEvidence[],
  stringEvidence: StringEvidence[]
): string[] {
  const platforms = new Set<string>()
  if (container.pe) platforms.add('windows')
  if (container.elf) platforms.add('linux')
  if (container.mach_o) platforms.add('macos')
  for (const item of stringEvidence) {
    if (item.family === 'windows-nt' || item.family === 'wow64') platforms.add('windows')
    if (item.family === 'linux') platforms.add('linux')
    if (item.family === 'macos') platforms.add('macos')
  }
  for (const item of instructionEvidence) {
    if (item.flags.includes('windows-x64-nt-abi')) platforms.add('windows')
    if (item.family.includes('linux')) platforms.add('linux')
  }
  return Array.from(platforms)
}

function buildSyscallStubs(instructionEvidence: OpcodeEvidence[]) {
  return instructionEvidence
    .filter(
      (item) =>
        ['syscall', 'sysenter', 'int 0x2e', 'int 0x80'].includes(item.mnemonic) ||
        item.flags.some((flag) => ['svc-instruction', 'ecall-instruction'].includes(flag))
    )
    .map((item) => ({
      offset: item.offset,
      isa: item.isa,
      mnemonic: item.mnemonic,
      family: item.family,
      syscall_number: item.syscall_number,
      confidence: item.confidence,
      flags: item.flags,
      direct_windows_nt_stub: item.flags.includes('windows-x64-nt-abi'),
      nearby_strings: item.nearby_strings,
    }))
}

function buildWindowsNtSurface(
  stringEvidence: StringEvidence[],
  instructionEvidence: OpcodeEvidence[]
) {
  const ntRefs = stringEvidence.filter((item) => item.family === 'windows-nt')
  const resolverRefs = stringEvidence.filter((item) =>
    ['resolver', 'direct-syscall', 'wow64'].includes(item.family)
  )
  const directStubs = instructionEvidence.filter((item) =>
    item.flags.includes('windows-x64-nt-abi')
  )
  const highRiskApis = uniqueStrings(
    ntRefs.flatMap((item) => HIGH_RISK_NT_APIS.filter((api) => item.value.includes(api))).sort()
  )

  return {
    present: ntRefs.length > 0 || resolverRefs.length > 0 || directStubs.length > 0,
    direct_stub_count: directStubs.length,
    syscall_numbers: uniqueStrings(
      directStubs
        .map((item) =>
          item.syscall_number === null ? null : `0x${item.syscall_number.toString(16)}`
        )
        .filter((item): item is string => Boolean(item))
    ),
    nt_api_reference_count: ntRefs.length,
    resolver_reference_count: resolverRefs.length,
    high_risk_apis: highRiskApis,
    wow64_hint: resolverRefs.some((item) => item.family === 'wow64'),
    technique_hints: uniqueStrings(resolverRefs.map((item) => item.kind)),
  }
}

function buildLinuxSyscallSurface(
  stringEvidence: StringEvidence[],
  instructionEvidence: OpcodeEvidence[]
) {
  const linuxStrings = stringEvidence.filter((item) => item.family === 'linux')
  const int80 = instructionEvidence.filter((item) => item.flags.includes('int-80'))
  const syscall = instructionEvidence.filter((item) => item.mnemonic === 'syscall')
  const svc = instructionEvidence.filter((item) => item.flags.includes('svc-instruction'))
  const ecall = instructionEvidence.filter((item) => item.flags.includes('ecall-instruction'))
  return {
    present: linuxStrings.length > 0 || int80.length > 0 || syscall.length > 0 || svc.length > 0,
    syscall_instruction_count: syscall.length + int80.length + svc.length + ecall.length,
    int80_count: int80.length,
    svc_count: svc.length,
    ecall_count: ecall.length,
    seccomp_hint: linuxStrings.some((item) => item.id === 'linux.seccomp-policy'),
    ptrace_hint: stringEvidence.some((item) => item.id === 'anti-analysis.ptrace'),
    symbol_hints: uniqueStrings(linuxStrings.map((item) => item.value)).slice(0, 40),
  }
}

function buildMachTrapSurface(stringEvidence: StringEvidence[], container: Record<string, any>) {
  const machRefs = stringEvidence.filter((item) => item.family === 'macos')
  return {
    present: Boolean(container.mach_o) || machRefs.length > 0,
    mach_o_container_hint: Boolean(container.mach_o),
    trap_reference_count: machRefs.length,
    references: uniqueStrings(machRefs.map((item) => item.value)).slice(0, 40),
  }
}

function buildAntiAnalysisSurface(stringEvidence: StringEvidence[]) {
  const refs = stringEvidence.filter((item) => item.family === 'anti-analysis')
  return {
    present: refs.length > 0,
    reference_count: refs.length,
    anti_debug_hint: refs.some((item) => item.flags.includes('anti-debug')),
    references: uniqueStrings(refs.map((item) => item.value)).slice(0, 40),
  }
}

function buildRiskFlags(
  container: Record<string, any>,
  instructionEvidence: OpcodeEvidence[],
  stringEvidence: StringEvidence[],
  windowsNtSurface: Record<string, any>,
  linuxSurface: Record<string, any>,
  antiAnalysisSurface: Record<string, any>
) {
  const flags: Array<Record<string, any>> = []
  const directStubs = instructionEvidence.filter((item) =>
    item.flags.includes('windows-x64-nt-abi')
  )
  const namedTechniques = stringEvidence.filter(
    (item) => item.family === 'direct-syscall' && item.confidence === 'high'
  )

  if (directStubs.length > 0) {
    flags.push({
      id: 'windows.direct-syscall-stub',
      severity: namedTechniques.length > 0 ? 'high' : 'medium',
      confidence: directStubs.some((item) => item.syscall_number !== null) ? 'high' : 'medium',
      evidence_count: directStubs.length,
      detail: 'x64 syscall instruction with Windows NT calling convention evidence',
    })
  }

  if (namedTechniques.length > 0) {
    flags.push({
      id: 'direct-syscall.named-evasion-framework',
      severity: 'high',
      confidence: 'high',
      evidence_count: namedTechniques.length,
      detail: 'Strings reference known direct-syscall resolver/evasion frameworks.',
    })
  }

  if (
    Array.isArray(windowsNtSurface.high_risk_apis) &&
    windowsNtSurface.high_risk_apis.length > 0
  ) {
    flags.push({
      id: 'windows.nt-high-risk-api-surface',
      severity: 'high',
      confidence: 'medium',
      apis: windowsNtSurface.high_risk_apis,
      detail: 'NT API references include process memory, thread, section, or APC primitives.',
    })
  }

  if (linuxSurface.seccomp_hint || linuxSurface.ptrace_hint) {
    flags.push({
      id: 'linux.syscall-policy-or-anti-debug',
      severity: linuxSurface.ptrace_hint ? 'medium' : 'low',
      confidence: 'medium',
      detail: 'Linux syscall boundary strings include seccomp/prctl or ptrace evidence.',
    })
  }

  if (antiAnalysisSurface.present) {
    flags.push({
      id: 'syscall.anti-analysis-boundary',
      severity: 'medium',
      confidence: 'medium',
      evidence_count: antiAnalysisSurface.reference_count,
      detail: 'Anti-debug or anti-analysis APIs are present near syscall boundary evidence.',
    })
  }

  const architectures = collectArchitectures(instructionEvidence)
  if (architectures.length >= 3) {
    flags.push({
      id: 'cross-architecture-syscall-dispatch',
      severity: 'medium',
      confidence: 'low',
      architectures,
      detail:
        'Multiple syscall instruction families may indicate packed stubs or multi-arch payloads.',
    })
  }

  if (container.raw_shellcode_hint && instructionEvidence.length > 0) {
    flags.push({
      id: 'raw-shellcode-syscall-boundary',
      severity: 'high',
      confidence: 'medium',
      detail: 'Raw shellcode-like sample contains syscall boundary instruction evidence.',
    })
  }

  return flags
}

function buildRiskSummary(riskFlags: Array<Record<string, any>>) {
  const severities = riskFlags.reduce<Record<string, number>>((acc, item) => {
    const severity = String(item.severity ?? 'unknown')
    acc[severity] = (acc[severity] ?? 0) + 1
    return acc
  }, {})
  return {
    total: riskFlags.length,
    by_severity: severities,
    highest:
      riskFlags.find((item) => item.severity === 'high')?.severity ??
      riskFlags.find((item) => item.severity === 'medium')?.severity ??
      (riskFlags.length > 0 ? 'low' : 'none'),
  }
}

function buildEvidenceSummary(args: {
  instruction_evidence: OpcodeEvidence[]
  string_evidence: StringEvidence[]
  syscall_stubs: Array<Record<string, any>>
  risk_flags: Array<Record<string, any>>
}) {
  return {
    instruction_evidence_count: args.instruction_evidence.length,
    string_evidence_count: args.string_evidence.length,
    syscall_stub_count: args.syscall_stubs.length,
    risk_flag_count: args.risk_flags.length,
    evidence_kinds: SYSCALL_ABI_EVIDENCE,
    source: TOOL_NAME,
  }
}

function buildWorkflowHandoff(inventory: SyscallAbiInventory) {
  return {
    schema: 'rikune.syscall_abi_surface.workflow_handoff.v1',
    source_tool: TOOL_NAME,
    artifact_type: SYSCALL_ABI_SURFACE_ARTIFACT_TYPE,
    produces: [SYSCALL_ABI_SURFACE_ARTIFACT_TYPE],
    consumes: ['sample'],
    recommended_static_next_tools: SYSCALL_ABI_FOLLOW_UP_TOOLS,
    opt_in_runtime_next_tools: SYSCALL_ABI_RUNTIME_HANDOFF_TOOLS,
    runtime_policy: {
      runtime_not_started_by_tool: true,
      runtime_requires_explicit_opt_in: true,
      reason:
        'Syscall tracing, debugger attachment, emulation, and runtime hooks are outside this passive inventory.',
    },
    routes: [
      {
        when: 'direct Windows syscall stubs or NT resolver evidence are present',
        next_tools: ['pe.imports.extract', 'code.xrefs.analyze', 'analysis.evidence.graph'],
      },
      {
        when: 'Linux syscall/seccomp/ptrace evidence is present',
        next_tools: [
          'linux.binary.inventory',
          'native.object.inventory',
          'analysis.evidence.graph',
        ],
      },
      {
        when: 'runtime confirmation is explicitly requested',
        next_tools: SYSCALL_ABI_RUNTIME_HANDOFF_TOOLS,
        opt_in_required: true,
      },
    ],
    policy: inventory.policy,
    evidence_summary: inventory.evidence_summary,
  }
}

function buildSummary(
  inventory: Omit<SyscallAbiInventory, 'summary' | 'workflow_handoff'>
): string {
  return `${inventory.format}: ${inventory.instruction_evidence.length} syscall instruction pattern(s), ${inventory.string_evidence.length} string evidence item(s), ${inventory.syscall_stubs.length} stub candidate(s), ${inventory.risk_flags.length} risk flag(s).`
}

export function buildSyscallAbiSurfaceInventoryFromBuffer(
  data: Buffer,
  options: BuildOptions = {}
): SyscallAbiInventory {
  const maxReadBytes = clampMaxReadBytes(options.maxReadBytes)
  const preview = data.subarray(0, Math.min(data.length, maxReadBytes))
  const container = detectContainer(preview, maxReadBytes, options)
  const strings = extractBinaryStrings(preview)
  const stringEvidence = collectStringEvidence(strings)
  const instructionEvidence = collectOpcodeEvidence(preview, strings)
  const syscallStubs = buildSyscallStubs(instructionEvidence)
  const windowsNtSurface = buildWindowsNtSurface(stringEvidence, instructionEvidence)
  const linuxSyscallSurface = buildLinuxSyscallSurface(stringEvidence, instructionEvidence)
  const machTrapSurface = buildMachTrapSurface(stringEvidence, container)
  const antiAnalysisSurface = buildAntiAnalysisSurface(stringEvidence)
  const detected = detectFormat(container, instructionEvidence, stringEvidence)
  const riskFlags = buildRiskFlags(
    container,
    instructionEvidence,
    stringEvidence,
    windowsNtSurface,
    linuxSyscallSurface,
    antiAnalysisSurface
  )
  const riskSummary = buildRiskSummary(riskFlags)

  const base = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    platforms: collectPlatforms(container, instructionEvidence, stringEvidence),
    architectures: collectArchitectures(instructionEvidence),
    detected_by: detected.detectedBy,
    confidence: detected.confidence,
    size: options.size ?? data.length,
    preview_size: preview.length,
    container,
    instruction_evidence: instructionEvidence,
    string_evidence: stringEvidence,
    syscall_stubs: syscallStubs,
    windows_nt_surface: windowsNtSurface,
    linux_syscall_surface: linuxSyscallSurface,
    mach_trap_surface: machTrapSurface,
    anti_analysis_surface: antiAnalysisSurface,
    risk_flags: riskFlags,
    risk_summary: riskSummary,
    policy: {
      passive: true,
      no_execute: true,
      no_syscall: true,
      no_ptrace: true,
      no_strace: true,
      no_ltrace: true,
      no_debugger: true,
      no_frida: true,
      no_emulation: true,
      no_device_open: true,
      no_driver_load: true,
      no_external_tool: true,
      no_network: true,
      no_mutation: true,
    },
    recommended_next_tools: SYSCALL_ABI_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use code.xrefs.analyze to map syscall instruction candidates, NT resolver strings, and anti-analysis references to callsites.',
      'Use import, string, native-object, and Linux/PE inventory tools to correlate syscall boundary evidence with container metadata.',
      'Use runtime planning tools only after explicit opt-in; this passive inventory must not trace, emulate, debug, or invoke syscalls.',
    ],
    quality_gates: {
      passive_static_inventory: true,
      sample_executed_by_tool: false,
      syscall_invoked_by_tool: false,
      ptrace_started_by_tool: false,
      strace_started_by_tool: false,
      ltrace_started_by_tool: false,
      debugger_attached_by_tool: false,
      frida_started_by_tool: false,
      emulator_started_by_tool: false,
      device_opened_by_tool: false,
      driver_loaded_by_tool: false,
      external_tool_invoked_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
  } satisfies Omit<SyscallAbiInventory, 'summary' | 'workflow_handoff' | 'evidence_summary'>

  const withEvidence = {
    ...base,
    evidence_summary: buildEvidenceSummary(base),
  } satisfies Omit<SyscallAbiInventory, 'summary' | 'workflow_handoff'>

  const inventory: SyscallAbiInventory = {
    ...withEvidence,
    summary: buildSummary(withEvidence),
    workflow_handoff: {},
  }
  inventory.workflow_handoff = buildWorkflowHandoff(inventory)
  return inventory
}

export function createSyscallAbiSurfaceInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = SyscallAbiSurfaceInventoryInputSchema.parse(args)
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
        const inventory = buildSyscallAbiSurfaceInventoryFromBuffer(buffer, {
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
                SYSCALL_ABI_SURFACE_ARTIFACT_TYPE,
                'syscall-abi-surface',
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
