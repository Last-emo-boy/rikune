/**
 * ebpf.bytecode.inventory — passive eBPF bytecode inventory.
 *
 * This tool never loads BPF programs, calls the kernel verifier, creates maps,
 * attaches probes, or starts runtime telemetry.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'ebpf.bytecode.inventory'
export const EBPF_BYTECODE_ARTIFACT_TYPE = 'ebpf_bytecode_inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024
const MAX_INSTRUCTION_PREVIEW = 240
const EBPF_EVIDENCE = [
  'structure',
  'bytecode',
  'control-flow',
  'kernel-events',
  'workflow',
  'provenance',
]
const EBPF_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'native.object.inventory',
  'elf.structure.analyze',
  'analysis.evidence.graph',
  'report.generate',
]
const EBPF_RUNTIME_FOLLOW_UP_TOOLS = ['linux.runtime.plan', 'tool.readiness']
const EBPF_SAFETY = [
  'passive',
  'no_execute',
  'no_bpf_syscall',
  'no_kernel_verifier_run',
  'no_program_load',
  'no_attach',
  'no_map_create',
  'no_runtime_start',
  'no_network_by_default',
]

const EBPF_HELPERS: Record<number, { name: string; category: string; riskFlags?: string[] }> = {
  1: { name: 'map_lookup_elem', category: 'map-read' },
  2: { name: 'map_update_elem', category: 'map-write', riskFlags: ['map-write'] },
  3: { name: 'map_delete_elem', category: 'map-write', riskFlags: ['map-write'] },
  4: { name: 'probe_read', category: 'kernel-memory-read', riskFlags: ['probe-read'] },
  5: { name: 'ktime_get_ns', category: 'time' },
  6: { name: 'trace_printk', category: 'telemetry-output', riskFlags: ['perf-or-ringbuf-output'] },
  7: { name: 'get_prandom_u32', category: 'random' },
  8: { name: 'get_smp_processor_id', category: 'cpu' },
  12: { name: 'tail_call', category: 'control-transfer', riskFlags: ['tail-call'] },
  14: { name: 'get_current_pid_tgid', category: 'process' },
  15: { name: 'get_current_uid_gid', category: 'identity' },
  16: { name: 'get_current_comm', category: 'process' },
  25: {
    name: 'perf_event_output',
    category: 'telemetry-output',
    riskFlags: ['perf-or-ringbuf-output'],
  },
  28: { name: 'get_stackid', category: 'stack' },
  35: { name: 'skb_load_bytes', category: 'packet-read' },
  36: { name: 'skb_load_bytes_relative', category: 'packet-read' },
  51: { name: 'probe_read_str', category: 'kernel-memory-read', riskFlags: ['probe-read'] },
  52: { name: 'sk_redirect_map', category: 'network-routing', riskFlags: ['packet-write'] },
  58: {
    name: 'override_return',
    category: 'privileged-control',
    riskFlags: ['override-return', 'helper-privileged'],
  },
  130: {
    name: 'ringbuf_output',
    category: 'telemetry-output',
    riskFlags: ['perf-or-ringbuf-output'],
  },
  131: {
    name: 'ringbuf_reserve',
    category: 'telemetry-output',
    riskFlags: ['perf-or-ringbuf-output'],
  },
  132: {
    name: 'ringbuf_submit',
    category: 'telemetry-output',
    riskFlags: ['perf-or-ringbuf-output'],
  },
  133: {
    name: 'ringbuf_discard',
    category: 'telemetry-output',
    riskFlags: ['perf-or-ringbuf-output'],
  },
}

const EbpfPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_bpf_syscall: z.literal(true),
  no_kernel_verifier_run: z.literal(true),
  no_program_load: z.literal(true),
  no_attach: z.literal(true),
  no_map_create: z.literal(true),
  no_runtime_start: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const EbpfInstructionSchema = z.object({
  index: z.number(),
  section: z.string().optional(),
  section_offset: z.number().optional(),
  offset: z.number(),
  raw_hex: z.string(),
  opcode_hex: z.string(),
  class: z.string(),
  mode: z.string().optional(),
  size: z.string().optional(),
  op: z.string().optional(),
  src_reg: z.number(),
  dst_reg: z.number(),
  off: z.number(),
  imm: z.number(),
  mnemonic: z.string(),
  category: z.string(),
  flags: z.array(z.string()),
})

const EbpfInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  endianness: z.enum(['little', 'big']),
  decode_scope: z.string(),
  instruction_count: z.number(),
  decoded_instruction_count: z.number(),
  instruction_preview_truncated: z.boolean(),
  elf_header: z.record(z.string(), z.any()).optional(),
  sections: z.array(z.record(z.string(), z.any())),
  instructions: z.array(EbpfInstructionSchema),
  helper_calls: z.array(z.record(z.string(), z.any())),
  map_references: z.array(z.record(z.string(), z.any())),
  control_flow: z.record(z.string(), z.any()),
  verifier_precheck: z.record(z.string(), z.any()),
  risk_summary: z.record(z.string(), z.any()),
  policy: EbpfPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
})

export const EbpfBytecodeInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive eBPF bytecode inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist eBPF inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const EbpfBytecodeInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: EbpfInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const ebpfBytecodeInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory raw eBPF bytecode or ELF eBPF objects, decoding bounded instructions, helper/map hints, control-flow risk flags, and verifier-relevant prechecks without loading programs or calling the kernel verifier.',
  inputSchema: EbpfBytecodeInventoryInputSchema,
  outputSchema: EbpfBytecodeInventoryOutputSchema,
  aspects: {
    formats: ['ebpf', 'bpf', 'ebpf-bytecode', 'raw-ebpf', 'ebpf-elf', 'bpf-object'],
    platforms: ['linux'],
    architectures: ['ebpf'],
    execution: ['static', 'triage', 'workflow-plan'],
    safety: EBPF_SAFETY,
    capabilities: [
      'bytecode-inventory',
      'instruction-decode',
      'helper-call-hints',
      'map-reference-hints',
      'control-flow',
      'verifier-precheck',
      'routing',
      'workflow-plan',
    ],
    evidence: EBPF_EVIDENCE,
  },
  artifacts: [
    {
      type: EBPF_BYTECODE_ARTIFACT_TYPE,
      description:
        'Passive eBPF bytecode, helper, map, control-flow, and verifier-precheck inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [EBPF_BYTECODE_ARTIFACT_TYPE] },
    { category: 'bytecode', artifactTypes: [EBPF_BYTECODE_ARTIFACT_TYPE] },
    { category: 'control-flow', artifactTypes: [EBPF_BYTECODE_ARTIFACT_TYPE] },
    { category: 'kernel-events', artifactTypes: [EBPF_BYTECODE_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [EBPF_BYTECODE_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [EBPF_BYTECODE_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'ebpf.bytecode-static-inventory',
      title: 'eBPF bytecode static inventory handoff',
      description:
        'Decode bounded eBPF instructions, helper/map hints, control-flow risks, and passive verifier-precheck evidence, then route findings into ELF/object correlation, evidence graph, reporting, or opt-in Linux runtime planning without loading BPF programs.',
      startsWith: [TOOL_NAME],
      nextTools: [...EBPF_FOLLOW_UP_TOOLS, ...EBPF_RUNTIME_FOLLOW_UP_TOOLS],
      requiredArtifacts: ['sample'],
      producesArtifacts: [EBPF_BYTECODE_ARTIFACT_TYPE],
      evidence: EBPF_EVIDENCE,
      safety: EBPF_SAFETY,
      runtimeBackends: ['linux-runtime'],
    },
  ],
}

export type EbpfBytecodeInventory = z.infer<typeof EbpfInventorySchema>

type Endianness = 'little' | 'big'

type RawInstruction = {
  section?: string
  sectionOffset?: number
  absoluteOffset: number
  raw: Buffer
  opcode: number
  regs: number
  dstReg: number
  srcReg: number
  off: number
  imm: number
}

type ElfSection = {
  name: string
  type: number
  flags: string[]
  offset: number
  size: number
  executable: boolean
  programTypeHint?: string
}

type DecodeCandidate = {
  name?: string
  offset: number
  size: number
  programTypeHint?: string
}

type DecodedInstruction = z.infer<typeof EbpfInstructionSchema>

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function isElf(data: Buffer): boolean {
  return (
    data.length >= 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46
  )
}

function readUInt16(data: Buffer, offset: number, endian: Endianness): number {
  return endian === 'big' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
}

function readUInt32(data: Buffer, offset: number, endian: Endianness): number {
  return endian === 'big' ? data.readUInt32BE(offset) : data.readUInt32LE(offset)
}

function readBigUInt(data: Buffer, offset: number, endian: Endianness): bigint {
  return endian === 'big' ? data.readBigUInt64BE(offset) : data.readBigUInt64LE(offset)
}

function readSafeCString(data: Buffer, offset: number): string {
  if (offset < 0 || offset >= data.length) return ''
  const end = data.indexOf(0, offset)
  const slice = data.subarray(offset, end === -1 ? data.length : end)
  return slice
    .toString('utf8')
    .replace(/[^\x20-\x7e]/g, '')
    .slice(0, 160)
}

function sectionFlags(value: bigint): string[] {
  const flags: string[] = []
  if (value & 0x1n) flags.push('write')
  if (value & 0x2n) flags.push('alloc')
  if (value & 0x4n) flags.push('execinstr')
  return flags
}

function programTypeFromSection(name: string): string | undefined {
  const lower = name.toLowerCase()
  if (lower.startsWith('xdp')) return 'xdp'
  if (lower.startsWith('tc') || lower.includes('classifier')) return 'tc-bpf'
  if (lower.startsWith('kprobe') || lower.startsWith('kretprobe')) return 'kprobe-bpf'
  if (lower.startsWith('tracepoint') || lower.startsWith('tp/')) return 'tracepoint-bpf'
  if (lower.startsWith('uprobe') || lower.startsWith('uretprobe')) return 'uprobe-bpf'
  if (lower.startsWith('cgroup')) return 'cgroup-bpf'
  if (lower.includes('socket')) return 'socket-filter-bpf'
  return undefined
}

function parseElfSections(data: Buffer): {
  header?: Record<string, unknown>
  sections: ElfSection[]
  candidates: DecodeCandidate[]
  endian: Endianness
} {
  if (!isElf(data) || data.length < 20) {
    return { sections: [], candidates: [], endian: 'little' }
  }
  const elfClass = data[4] === 1 ? 32 : data[4] === 2 ? 64 : 0
  const endian: Endianness = data[5] === 2 ? 'big' : 'little'
  if (!elfClass) {
    return { sections: [], candidates: [], endian }
  }

  const type = readUInt16(data, 16, endian)
  const machine = readUInt16(data, 18, endian)
  const shoff = Number(
    elfClass === 64 ? readBigUInt(data, 40, endian) : BigInt(readUInt32(data, 32, endian))
  )
  const shentsize = readUInt16(data, elfClass === 64 ? 58 : 46, endian)
  const shnum = readUInt16(data, elfClass === 64 ? 60 : 48, endian)
  const shstrndx = readUInt16(data, elfClass === 64 ? 62 : 50, endian)
  const header = {
    class: elfClass === 64 ? 'ELF64' : 'ELF32',
    type,
    machine,
    machine_name: machine === 247 ? 'EM_BPF' : `EM_${machine}`,
    section_count: shnum,
    section_header_offset: shoff,
  }

  if (!shoff || !shentsize || shnum <= 0 || shoff + shentsize * shnum > data.length) {
    return { header, sections: [], candidates: [], endian }
  }

  const sectionHeaders: Array<Record<string, number | bigint>> = []
  for (let i = 0; i < shnum; i += 1) {
    const offset = shoff + i * shentsize
    if (elfClass === 64) {
      sectionHeaders.push({
        nameOffset: readUInt32(data, offset, endian),
        type: readUInt32(data, offset + 4, endian),
        flags: readBigUInt(data, offset + 8, endian),
        offset: Number(readBigUInt(data, offset + 24, endian)),
        size: Number(readBigUInt(data, offset + 32, endian)),
      })
    } else {
      sectionHeaders.push({
        nameOffset: readUInt32(data, offset, endian),
        type: readUInt32(data, offset + 4, endian),
        flags: BigInt(readUInt32(data, offset + 8, endian)),
        offset: readUInt32(data, offset + 16, endian),
        size: readUInt32(data, offset + 20, endian),
      })
    }
  }

  const stringHeader = sectionHeaders[shstrndx]
  const stringTableOffset = Number(stringHeader?.offset ?? 0)
  const stringTableSize = Number(stringHeader?.size ?? 0)
  const stringTable =
    stringTableOffset >= 0 && stringTableOffset + stringTableSize <= data.length
      ? data.subarray(stringTableOffset, stringTableOffset + stringTableSize)
      : Buffer.alloc(0)

  const sections = sectionHeaders.map((section) => {
    const name = readSafeCString(stringTable, Number(section.nameOffset))
    const flags = sectionFlags(BigInt(section.flags ?? 0))
    const executable = flags.includes('execinstr')
    return {
      name,
      type: Number(section.type),
      flags,
      offset: Number(section.offset),
      size: Number(section.size),
      executable,
      programTypeHint: programTypeFromSection(name),
    }
  })

  const candidates = sections
    .filter(
      (section) =>
        section.size >= 8 &&
        section.size % 8 === 0 &&
        section.offset >= 0 &&
        section.offset + section.size <= data.length &&
        (section.executable || Boolean(section.programTypeHint))
    )
    .map((section) => ({
      name: section.name,
      offset: section.offset,
      size: section.size,
      programTypeHint: section.programTypeHint,
    }))

  return { header, sections, candidates, endian }
}

function className(opcode: number): string {
  const cls = opcode & 0x07
  if (cls === 0x00) return 'ld'
  if (cls === 0x01) return 'ldx'
  if (cls === 0x02) return 'st'
  if (cls === 0x03) return 'stx'
  if (cls === 0x04) return 'alu32'
  if (cls === 0x05) return 'jmp'
  if (cls === 0x06) return 'jmp32'
  if (cls === 0x07) return 'alu64'
  return 'unknown'
}

function sizeName(opcode: number): string | undefined {
  const size = opcode & 0x18
  if (size === 0x00) return 'w'
  if (size === 0x08) return 'h'
  if (size === 0x10) return 'b'
  if (size === 0x18) return 'dw'
  return undefined
}

function modeName(opcode: number): string | undefined {
  const mode = opcode & 0xe0
  if (mode === 0x00) return 'imm'
  if (mode === 0x20) return 'abs'
  if (mode === 0x40) return 'ind'
  if (mode === 0x60) return 'mem'
  if (mode === 0x80) return 'len'
  if (mode === 0xa0) return 'msh'
  if (mode === 0xc0) return 'atomic'
  return undefined
}

function aluOpName(opcode: number): string | undefined {
  const op = opcode & 0xf0
  const names: Record<number, string> = {
    0x00: 'add',
    0x10: 'sub',
    0x20: 'mul',
    0x30: 'div',
    0x40: 'or',
    0x50: 'and',
    0x60: 'lsh',
    0x70: 'rsh',
    0x80: 'neg',
    0x90: 'mod',
    0xa0: 'xor',
    0xb0: 'mov',
    0xc0: 'arsh',
    0xd0: 'endian',
  }
  return names[op]
}

function jumpOpName(opcode: number): string | undefined {
  const op = opcode & 0xf0
  const names: Record<number, string> = {
    0x00: 'ja',
    0x10: 'jeq',
    0x20: 'jgt',
    0x30: 'jge',
    0x40: 'jset',
    0x50: 'jne',
    0x60: 'jsgt',
    0x70: 'jsge',
    0x80: 'call',
    0x90: 'exit',
    0xa0: 'jlt',
    0xb0: 'jle',
    0xc0: 'jslt',
    0xd0: 'jsle',
  }
  return names[op]
}

function isKnownOpcode(opcode: number): boolean {
  const cls = className(opcode)
  if (cls === 'unknown') return false
  if (cls === 'alu32' || cls === 'alu64') return Boolean(aluOpName(opcode))
  if (cls === 'jmp' || cls === 'jmp32') return Boolean(jumpOpName(opcode))
  if (cls === 'ld' || cls === 'ldx' || cls === 'st' || cls === 'stx')
    return Boolean(sizeName(opcode) && modeName(opcode))
  return false
}

function mnemonicFor(raw: RawInstruction, op?: string): string {
  const cls = className(raw.opcode)
  const source = raw.srcReg ? `r${raw.srcReg}` : `${raw.imm}`
  if (cls === 'alu32' || cls === 'alu64') return `${op ?? 'alu'} r${raw.dstReg}, ${source}`
  if (cls === 'jmp' || cls === 'jmp32') {
    if (op === 'call') {
      const helper = EBPF_HELPERS[raw.imm]
      return `call ${helper?.name ?? raw.imm}`
    }
    if (op === 'exit') return 'exit'
    return `${op ?? 'jmp'} r${raw.dstReg}, ${source}, ${raw.off}`
  }
  if (cls === 'ld' && raw.opcode === 0x18) return `lddw r${raw.dstReg}, ${raw.imm}`
  if (cls === 'ldx') return `ldx r${raw.dstReg}, [r${raw.srcReg}+${raw.off}]`
  if (cls === 'st') return `st [r${raw.dstReg}+${raw.off}], ${raw.imm}`
  if (cls === 'stx') return `stx [r${raw.dstReg}+${raw.off}], r${raw.srcReg}`
  return `db ${raw.raw.toString('hex')}`
}

function decodeRawInstruction(
  data: Buffer,
  offset: number,
  endian: Endianness,
  section?: string,
  sectionOffset?: number
): RawInstruction {
  const raw = data.subarray(offset, offset + 8)
  const opcode = raw[0] ?? 0
  const regs = raw[1] ?? 0
  return {
    section,
    sectionOffset,
    absoluteOffset: offset,
    raw,
    opcode,
    regs,
    dstReg: regs & 0x0f,
    srcReg: (regs >> 4) & 0x0f,
    off: endian === 'big' ? raw.readInt16BE(2) : raw.readInt16LE(2),
    imm: endian === 'big' ? raw.readInt32BE(4) : raw.readInt32LE(4),
  }
}

function decodeInstruction(raw: RawInstruction, index: number): DecodedInstruction {
  const cls = className(raw.opcode)
  const op =
    cls === 'alu32' || cls === 'alu64'
      ? aluOpName(raw.opcode)
      : cls === 'jmp' || cls === 'jmp32'
        ? jumpOpName(raw.opcode)
        : undefined
  const flags = new Set<string>()
  if (!isKnownOpcode(raw.opcode)) flags.add('unknown-opcode')
  if (raw.opcode === 0x18 && raw.srcReg > 0) flags.add('pseudo-load')
  if (op === 'call') flags.add('helper-call')
  if (op === 'exit') flags.add('exit')
  if ((cls === 'jmp' || cls === 'jmp32') && op && op !== 'call' && op !== 'exit')
    flags.add('branch')
  if ((cls === 'st' || cls === 'stx') && raw.dstReg === 1) flags.add('packet-write')
  return {
    index,
    ...(raw.section ? { section: raw.section } : {}),
    ...(raw.sectionOffset !== undefined ? { section_offset: raw.sectionOffset } : {}),
    offset: raw.absoluteOffset,
    raw_hex: raw.raw.toString('hex'),
    opcode_hex: `0x${raw.opcode.toString(16).padStart(2, '0')}`,
    class: cls,
    mode: modeName(raw.opcode),
    size: sizeName(raw.opcode),
    op,
    src_reg: raw.srcReg,
    dst_reg: raw.dstReg,
    off: raw.off,
    imm: raw.imm,
    mnemonic: mnemonicFor(raw, op),
    category: op === 'call' ? 'helper-call' : cls,
    flags: [...flags],
  }
}

function collectRawInstructions(
  data: Buffer,
  candidates: DecodeCandidate[],
  endian: Endianness
): { raw: RawInstruction[]; decodeScope: string; widthValid: boolean } {
  const raw: RawInstruction[] = []
  let widthValid = true
  const decodeCandidates =
    candidates.length > 0 ? candidates : [{ offset: 0, size: data.length, name: 'raw-ebpf' }]
  for (const candidate of decodeCandidates) {
    const alignedSize = Math.floor(candidate.size / 8) * 8
    if (candidate.size % 8 !== 0) widthValid = false
    for (let offset = 0; offset + 8 <= alignedSize; offset += 8) {
      raw.push(
        decodeRawInstruction(data, candidate.offset + offset, endian, candidate.name, offset)
      )
    }
  }
  return {
    raw,
    decodeScope:
      candidates.length > 0
        ? `elf executable sections: ${candidates.map((candidate) => candidate.name ?? 'unnamed').join(', ')}`
        : 'raw byte stream from offset 0',
    widthValid,
  }
}

function branchTarget(index: number, off: number): number {
  return index + 1 + off
}

function buildControlFlow(instructions: DecodedInstruction[]) {
  const branches = instructions.filter((ins) => ins.flags.includes('branch'))
  const targets = branches.map((ins) => ({
    from: ins.index,
    to: branchTarget(ins.index, ins.off),
    op: ins.op,
  }))
  const outOfRange = targets.filter((target) => target.to < 0 || target.to >= instructions.length)
  const backEdges = targets.filter((target) => target.to <= target.from)
  const reached = new Set<number>([0])
  for (const target of targets) {
    if (target.to >= 0 && target.to < instructions.length) reached.add(target.to)
  }
  for (const ins of instructions) {
    if (ins.index > 0) reached.add(ins.index)
  }
  return {
    entry_index: instructions.length > 0 ? 0 : null,
    exits: instructions.filter((ins) => ins.op === 'exit').map((ins) => ins.index),
    jumps: branches.length,
    calls: instructions.filter((ins) => ins.op === 'call').length,
    branch_targets: targets,
    out_of_range_jumps: outOfRange,
    back_edges: backEdges,
    unreachable_count: Math.max(0, instructions.length - reached.size),
    tail_call_sites: [] as number[],
  }
}

function buildHelperCalls(instructions: DecodedInstruction[]) {
  return instructions
    .filter((ins) => ins.op === 'call')
    .map((ins) => {
      const helper = EBPF_HELPERS[ins.imm]
      return {
        instruction_index: ins.index,
        helper_id: ins.imm,
        name: helper?.name ?? `helper_${ins.imm}`,
        category: helper?.category ?? 'unknown-helper',
        risk_flags: helper?.riskFlags ?? (helper ? [] : ['unknown-helper']),
        confidence: helper ? 'medium' : 'low',
      }
    })
}

function buildMapReferences(rawInstructions: RawInstruction[], instructions: DecodedInstruction[]) {
  const references = []
  for (let i = 0; i < rawInstructions.length; i += 1) {
    const raw = rawInstructions[i]
    if (raw.opcode !== 0x18 || raw.srcReg === 0) continue
    const pseudo =
      raw.srcReg === 1
        ? 'BPF_PSEUDO_MAP_FD'
        : raw.srcReg === 2
          ? 'BPF_PSEUDO_MAP_VALUE'
          : raw.srcReg === 3
            ? 'BPF_PSEUDO_BTF_ID'
            : `BPF_PSEUDO_${raw.srcReg}`
    references.push({
      instruction_index: i,
      pseudo_type: pseudo,
      fd_or_id: raw.imm,
      name_or_section: raw.section ?? null,
      relocation_hint:
        raw.srcReg === 1 || raw.srcReg === 2 ? 'map-like lddw pseudo load' : 'btf-like pseudo load',
      access_hint: inferMapAccessHint(instructions, i),
      confidence: raw.srcReg === 1 || raw.srcReg === 2 ? 'medium' : 'low',
    })
  }
  return references
}

function inferMapAccessHint(instructions: DecodedInstruction[], startIndex: number): string {
  const nearby = instructions.slice(startIndex, Math.min(instructions.length, startIndex + 8))
  const helperNames = nearby
    .filter((ins) => ins.op === 'call')
    .map((ins) => EBPF_HELPERS[ins.imm]?.name ?? '')
  if (helperNames.includes('map_update_elem') || helperNames.includes('map_delete_elem'))
    return 'map-write'
  if (helperNames.includes('map_lookup_elem')) return 'map-read'
  return 'map-reference'
}

function buildVerifierPrecheck(
  rawInstructions: RawInstruction[],
  instructions: DecodedInstruction[],
  widthValid: boolean,
  controlFlow: Record<string, any>
) {
  const lddwStarts = new Set<number>()
  const lddwSecondWords = new Set<number>()
  const invalidLddwPairs: number[] = []
  let reservedFieldsValid = true
  for (let i = 0; i < rawInstructions.length; i += 1) {
    const raw = rawInstructions[i]
    if (raw.opcode !== 0x18) continue
    lddwStarts.add(i)
    const next = rawInstructions[i + 1]
    if (!next) {
      invalidLddwPairs.push(i)
      continue
    }
    lddwSecondWords.add(i + 1)
    if (next.opcode !== 0 || next.regs !== 0 || next.off !== 0) {
      reservedFieldsValid = false
      invalidLddwPairs.push(i)
    }
    i += 1
  }
  const jumpTargets = (controlFlow.branch_targets ?? []) as Array<{ from: number; to: number }>
  const jumpIntoLddw = jumpTargets.filter((target) => lddwSecondWords.has(target.to))
  const invalidDivMod = instructions
    .filter((ins) => (ins.op === 'div' || ins.op === 'mod') && ins.src_reg === 0 && ins.imm === 0)
    .map((ins) => ins.index)
  const shiftWarnings = instructions
    .filter(
      (ins) =>
        ['lsh', 'rsh', 'arsh'].includes(ins.op ?? '') &&
        ins.src_reg === 0 &&
        ((ins.class === 'alu64' && ins.imm >= 64) || (ins.class === 'alu32' && ins.imm >= 32))
    )
    .map((ins) => ins.index)
  return {
    passive_precheck_only: true,
    instruction_width_valid: widthValid,
    lddw_pairs_valid: invalidLddwPairs.length === 0,
    invalid_lddw_pair_indexes: invalidLddwPairs,
    reserved_fields_zero: reservedFieldsValid,
    jump_targets_in_range: ((controlFlow.out_of_range_jumps ?? []) as unknown[]).length === 0,
    no_jump_into_lddw: jumpIntoLddw.length === 0,
    jump_into_lddw_targets: jumpIntoLddw,
    last_instruction_exit: instructions.at(-1)?.op === 'exit',
    unknown_opcode_count: instructions.filter((ins) => ins.flags.includes('unknown-opcode')).length,
    unknown_helper_count: instructions.filter((ins) => ins.op === 'call' && !EBPF_HELPERS[ins.imm])
      .length,
    invalid_imm_div_mod: invalidDivMod,
    shift_bounds_warnings: shiftWarnings,
    stack_offset_hints: instructions
      .filter((ins) => [ins.dst_reg, ins.src_reg].includes(10) && ins.off < 0)
      .map((ins) => ({ instruction_index: ins.index, offset: ins.off })),
    pointer_arithmetic_hints: instructions
      .filter((ins) => ['add', 'sub'].includes(ins.op ?? '') && ins.dst_reg > 0)
      .map((ins) => ({ instruction_index: ins.index, dst_reg: ins.dst_reg, op: ins.op })),
  }
}

function buildRiskSummary(
  instructions: DecodedInstruction[],
  helperCalls: Array<Record<string, any>>,
  mapReferences: Array<Record<string, any>>,
  controlFlow: Record<string, any>,
  verifierPrecheck: Record<string, any>
) {
  const flags = new Set<string>()
  for (const ins of instructions) {
    for (const flag of ins.flags) {
      if (flag === 'unknown-opcode' || flag === 'packet-write') flags.add(flag)
    }
  }
  for (const helper of helperCalls) {
    for (const flag of (helper.risk_flags ?? []) as string[]) flags.add(flag)
  }
  if (!verifierPrecheck.lddw_pairs_valid) flags.add('invalid-lddw-pair')
  if (!verifierPrecheck.jump_targets_in_range) flags.add('out-of-range-jump')
  if (!verifierPrecheck.no_jump_into_lddw) flags.add('jump-into-lddw')
  if (((controlFlow.back_edges ?? []) as unknown[]).length > 0) flags.add('loop-backedge')
  if (instructions.length > 4096) flags.add('instruction-limit-risk')
  if (mapReferences.some((ref) => String(ref.access_hint).includes('write'))) flags.add('map-write')
  const highFlags = [
    'unknown-opcode',
    'invalid-lddw-pair',
    'out-of-range-jump',
    'jump-into-lddw',
    'helper-privileged',
    'override-return',
  ]
  const mediumFlags = [
    'loop-backedge',
    'tail-call',
    'map-write',
    'packet-write',
    'probe-read',
    'perf-or-ringbuf-output',
  ]
  const flagList = [...flags]
  const riskLevel = flagList.some((flag) => highFlags.includes(flag))
    ? 'high'
    : flagList.some((flag) => mediumFlags.includes(flag))
      ? 'medium'
      : 'low'
  return {
    risk_level: riskLevel,
    flags: flagList,
    counts: {
      instruction_count: instructions.length,
      helper_call_count: helperCalls.length,
      map_reference_count: mapReferences.length,
      branch_count: controlFlow.jumps ?? 0,
      back_edge_count: ((controlFlow.back_edges ?? []) as unknown[]).length,
      unknown_opcode_count: verifierPrecheck.unknown_opcode_count ?? 0,
      unknown_helper_count: verifierPrecheck.unknown_helper_count ?? 0,
    },
  }
}

function detectFormat(
  data: Buffer,
  filename?: string,
  elfHeader?: Record<string, unknown>
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  const detectedBy: string[] = []
  if (elfHeader?.machine_name === 'EM_BPF') {
    detectedBy.push('ELF EM_BPF machine')
    return { format: 'ebpf-elf', detectedBy }
  }
  if (isElf(data)) {
    detectedBy.push('ELF magic')
    return { format: 'elf', detectedBy }
  }
  if (ext === 'bpf' || ext === 'ebpf') {
    detectedBy.push('filename extension')
    return { format: 'raw-ebpf', detectedBy }
  }
  if (data.length >= 8 && data.length % 8 === 0) {
    detectedBy.push('8-byte aligned raw instruction stream')
    return { format: 'raw-ebpf', detectedBy }
  }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function buildEvidenceSummary(
  inventory: Omit<EbpfBytecodeInventory, 'evidence_summary' | 'workflow_handoff' | 'quality_gates'>
) {
  return {
    schema: 'rikune.ebpf_bytecode_inventory.evidence_summary.v1',
    source_tool: TOOL_NAME,
    artifact_type: EBPF_BYTECODE_ARTIFACT_TYPE,
    format: inventory.format,
    instruction_count: inventory.instruction_count,
    helper_call_count: inventory.helper_calls.length,
    map_reference_count: inventory.map_references.length,
    risk_level: inventory.risk_summary.risk_level,
    risk_flags: inventory.risk_summary.flags,
    passive_precheck_only: true,
  }
}

function buildWorkflowHandoff(
  inventory: Omit<EbpfBytecodeInventory, 'evidence_summary' | 'workflow_handoff' | 'quality_gates'>
) {
  return {
    schema: 'rikune.ebpf_bytecode_inventory.workflow_handoff.v1',
    handoff_mode:
      'ebpf_bytecode_to_static_object_evidence_graph_reporting_and_optional_linux_runtime_plan',
    artifact_contract: {
      type: EBPF_BYTECODE_ARTIFACT_TYPE,
      read_tool: 'artifact.read',
      required_fields: [
        'instructions',
        'helper_calls',
        'map_references',
        'control_flow',
        'verifier_precheck',
      ],
    },
    recommended_next_tools: inventory.recommended_next_tools,
    optional_runtime_tools: EBPF_RUNTIME_FOLLOW_UP_TOOLS,
    routing: [
      {
        when: 'ELF eBPF object metadata is present',
        next_tools: ['elf.structure.analyze', 'native.object.inventory'],
        required_evidence: [EBPF_BYTECODE_ARTIFACT_TYPE, 'ELF EM_BPF header or eBPF section names'],
      },
      {
        when: 'helper, map, control-flow, or verifier precheck risk flags are present',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [EBPF_BYTECODE_ARTIFACT_TYPE, 'risk_summary.flags'],
      },
      {
        when: 'runtime telemetry or verifier confirmation is explicitly requested',
        next_tools: EBPF_RUNTIME_FOLLOW_UP_TOOLS,
        required_evidence: ['user opt-in', 'isolated Linux runtime plan'],
      },
    ],
    dynamic_boundary: {
      sample_execution_allowed: false,
      bpf_syscall_allowed: false,
      kernel_verifier_allowed: false,
      program_load_allowed: false,
      attach_allowed: false,
      map_create_allowed: false,
      runtime_start_allowed: false,
      network_allowed: false,
    },
  }
}

function buildQualityGates(
  inventory: Omit<EbpfBytecodeInventory, 'evidence_summary' | 'workflow_handoff' | 'quality_gates'>
) {
  return {
    schema: 'rikune.ebpf_bytecode_inventory.quality_gates.v1',
    passive_static_inventory: true,
    passive_precheck_only: true,
    sample_executed_by_tool: false,
    bpf_syscall_called_by_tool: false,
    kernel_verifier_run_by_tool: false,
    program_loaded_by_tool: false,
    probe_attached_by_tool: false,
    map_created_by_tool: false,
    runtime_started_by_tool: false,
    network_used_by_tool: false,
    mutation_performed: false,
    bounded_preview_only: inventory.size !== undefined && inventory.size > DEFAULT_MAX_READ_BYTES,
  }
}

export function buildEbpfBytecodeInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; sampleId?: string } = {}
): EbpfBytecodeInventory {
  const elf = parseElfSections(data)
  const format = detectFormat(data, options.filename, elf.header)
  const { raw, decodeScope, widthValid } = collectRawInstructions(data, elf.candidates, elf.endian)
  const instructions = raw.map((instruction, index) => decodeInstruction(instruction, index))
  const previewInstructions = instructions.slice(0, MAX_INSTRUCTION_PREVIEW)
  const helperCalls = buildHelperCalls(instructions)
  const mapReferences = buildMapReferences(raw, instructions)
  const controlFlow = buildControlFlow(instructions)
  controlFlow.tail_call_sites = helperCalls
    .filter((call) => call.name === 'tail_call')
    .map((call) => Number(call.instruction_index))
  const verifierPrecheck = buildVerifierPrecheck(raw, instructions, widthValid, controlFlow)
  const riskSummary = buildRiskSummary(
    instructions,
    helperCalls,
    mapReferences,
    controlFlow,
    verifierPrecheck
  )
  const recommendedNextTools = [...EBPF_FOLLOW_UP_TOOLS]
  if (
    (riskSummary.flags as string[]).some((flag) =>
      ['tail-call', 'helper-privileged', 'override-return', 'perf-or-ringbuf-output'].includes(flag)
    )
  ) {
    recommendedNextTools.push(...EBPF_RUNTIME_FOLLOW_UP_TOOLS)
  }

  const base: Omit<
    EbpfBytecodeInventory,
    'evidence_summary' | 'workflow_handoff' | 'quality_gates'
  > = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: format.format,
    detected_by: format.detectedBy,
    size: data.length,
    endianness: elf.endian,
    decode_scope: decodeScope,
    instruction_count: instructions.length,
    decoded_instruction_count: instructions.length,
    instruction_preview_truncated: instructions.length > previewInstructions.length,
    ...(elf.header ? { elf_header: elf.header } : {}),
    sections: elf.sections.map((section) => ({
      name: section.name,
      type: section.type,
      flags: section.flags,
      offset: section.offset,
      size: section.size,
      executable: section.executable,
      program_type_hint: section.programTypeHint,
      decoded_instruction_count: elf.candidates.some((candidate) => candidate.name === section.name)
        ? Math.floor(section.size / 8)
        : 0,
    })),
    instructions: previewInstructions,
    helper_calls: helperCalls,
    map_references: mapReferences,
    control_flow: controlFlow,
    verifier_precheck: verifierPrecheck,
    risk_summary: riskSummary,
    policy: {
      passive: true,
      no_execute: true,
      no_bpf_syscall: true,
      no_kernel_verifier_run: true,
      no_program_load: true,
      no_attach: true,
      no_map_create: true,
      no_runtime_start: true,
      no_network: true,
      no_mutation: true,
    },
    summary: `Passive eBPF inventory decoded ${instructions.length} instruction(s), ${helperCalls.length} helper call(s), ${mapReferences.length} map/BTF reference hint(s), risk=${riskSummary.risk_level}.`,
    recommended_next_tools: Array.from(new Set(recommendedNextTools)),
    next_actions: [
      'Use artifact.read to inspect the persisted ebpf_bytecode_inventory payload.',
      'Correlate ELF/object metadata before interpreting map names, program type, or relocations.',
      'Treat verifier_precheck as passive evidence only; run linux.runtime.plan only after explicit opt-in.',
    ],
  }

  return {
    ...base,
    evidence_summary: buildEvidenceSummary(base),
    workflow_handoff: buildWorkflowHandoff(base),
    quality_gates: buildQualityGates(base),
  }
}

export function createEbpfBytecodeInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = EbpfBytecodeInventoryInputSchema.parse(args)
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const handle = await fs.open(samplePath, 'r')
      let data: Buffer
      try {
        const stat = await handle.stat()
        const size = Math.min(stat.size, input.max_read_bytes)
        data = Buffer.alloc(size)
        await handle.read(data, 0, size, 0)
      } finally {
        await handle.close()
      }

      const inventory = buildEbpfBytecodeInventoryFromBuffer(data, {
        filename: path.basename(samplePath),
        sampleId: input.sample_id,
      })

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
        try {
          const artifact = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            EBPF_BYTECODE_ARTIFACT_TYPE,
            'ebpf-bytecode',
            inventory,
            input.session_tag ?? 'ebpf-bytecode'
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: the structured inventory is still returned.
        }
      }

      return {
        ok: true,
        data: inventory,
        artifacts,
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
