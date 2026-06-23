/**
 * llvm.bitcode.inventory — passive LLVM bitcode inventory.
 *
 * This tool does not call llvm-dis, opt, clang, lld, lli, a JIT, or a lifted
 * artifact. It only reads bounded bytes and summarizes the bitstream envelope.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'llvm.bitcode.inventory'
export const LLVM_BITCODE_ARTIFACT_TYPE = 'llvm_bitcode_inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const RAW_MAGIC = Buffer.from([0x42, 0x43, 0xc0, 0xde])
const WRAPPER_MAGIC = 0x0b17c0de
const MAX_BLOCKS = 96
const MAX_RECORD_SUMMARIES = 160
const MAX_STRINGS = 80
const MAX_PARSER_STEPS = 20000

const LLVM_BITCODE_EVIDENCE = ['structure', 'strings', 'metadata', 'workflow', 'provenance']
const LLVM_BITCODE_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]
const LLVM_BITCODE_SAFETY = [
  'passive',
  'no_llvm_toolchain_required',
  'no_compile',
  'no_link',
  'no_execute',
  'no_network_by_default',
]

const BLOCK_NAMES: Record<number, string> = {
  0: 'BLOCKINFO',
  8: 'MODULE',
  9: 'PARAMATTR',
  10: 'PARAMATTR_GROUP',
  11: 'CONSTANTS',
  12: 'FUNCTION',
  13: 'IDENTIFICATION',
  14: 'VALUE_SYMTAB',
  15: 'METADATA',
  16: 'METADATA_ATTACHMENT',
  17: 'TYPE',
  18: 'USELIST',
  19: 'MODULE_STRTAB',
  20: 'GLOBALVAL_SUMMARY',
  21: 'OPERAND_BUNDLE_TAGS',
  22: 'METADATA_KIND',
  23: 'STRTAB',
  24: 'FULL_LTO_GLOBALVAL_SUMMARY',
  25: 'SYMTAB',
  26: 'SYNC_SCOPE_NAMES',
}

const LlvmBitcodePolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_compile: z.literal(true),
  no_link: z.literal(true),
  no_llvm_toolchain_required: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const LlvmBitcodeInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.any()),
  bitstream: z.record(z.any()),
  llvm_ir_hints: z.record(z.any()),
  embedded_strings: z.record(z.any()),
  risk_flags: z.array(z.record(z.any())),
  risk_summary: z.record(z.any()),
  policy: LlvmBitcodePolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const LlvmBitcodeInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive LLVM bitcode inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist LLVM bitcode inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const LlvmBitcodeInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: LlvmBitcodeInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const llvmBitcodeInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory LLVM bitcode streams and wrapper files without invoking LLVM tools, compiling, linking, JITing, or executing artifacts.',
  inputSchema: LlvmBitcodeInventoryInputSchema,
  outputSchema: LlvmBitcodeInventoryOutputSchema,
  aspects: {
    formats: ['llvm-bitcode', 'llvm-bitcode-wrapper', 'llvm-bc', 'llvm-ir', 'bc', 'll'],
    platforms: ['cross-platform'],
    architectures: ['llvm-ir'],
    execution: ['static', 'triage', 'decompilation', 'correlation'],
    safety: LLVM_BITCODE_SAFETY,
    capabilities: [
      'structure',
      'strings',
      'ir-metadata',
      'bitstream-summary',
      'wrapper-inventory',
      'workflow-routing',
    ],
    evidence: LLVM_BITCODE_EVIDENCE,
  },
  artifacts: [
    {
      type: LLVM_BITCODE_ARTIFACT_TYPE,
      description: 'Passive LLVM bitcode wrapper, bitstream, metadata, and string inventory',
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [LLVM_BITCODE_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [LLVM_BITCODE_ARTIFACT_TYPE] },
    { category: 'metadata', artifactTypes: [LLVM_BITCODE_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [LLVM_BITCODE_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'llvm.bitcode-static-inventory',
      title: 'Passive LLVM bitcode IR inventory',
      description:
        'Inventory LLVM bitcode structure, wrapper metadata, block/record summaries, and string evidence before routing to static strings, evidence graph, reporting, or native-object context tools.',
      startsWith: [TOOL_NAME],
      nextTools: LLVM_BITCODE_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [LLVM_BITCODE_ARTIFACT_TYPE],
      evidence: LLVM_BITCODE_EVIDENCE,
      safety: LLVM_BITCODE_SAFETY,
    },
  ],
}

export type LlvmBitcodeInventory = z.infer<typeof LlvmBitcodeInventorySchema>

interface AbbrevLiteralOp {
  literal: true
  value: number
}

interface AbbrevEncodedOp {
  literal: false
  encoding: 'fixed' | 'vbr' | 'array' | 'char6' | 'blob' | 'unknown'
  data?: number
}

type AbbrevOp = AbbrevLiteralOp | AbbrevEncodedOp

interface AbbrevDef {
  id: number
  ops: AbbrevOp[]
}

interface BlockSummary {
  block_id: number
  name: string
  depth: number
  start_bit: number
  end_bit?: number
  declared_words?: number
  record_count: number
  subblock_count: number
  abbrev_count: number
  truncated: boolean
}

interface RecordAggregate {
  block_id: number
  block_name: string
  code: number
  count: number
  operand_count_min: number
  operand_count_max: number
  sample_operands: number[]
  string_preview?: string
}

interface BitstreamParseResult {
  decode_status: string
  stream_offset: number
  declared_size?: number
  bytes_available: number
  block_count: number
  record_count: number
  max_depth: number
  parser_warnings: string[]
  block_summaries: BlockSummary[]
  record_summaries: RecordAggregate[]
}

class BitCursor {
  readonly data: Buffer
  bit = 0

  constructor(data: Buffer, startByte = 0) {
    this.data = data
    this.bit = startByte * 8
  }

  get totalBits() {
    return this.data.length * 8
  }

  readBits(count: number): number | null {
    if (count < 0 || count > 32) return null
    if (this.bit + count > this.totalBits) return null
    let value = 0
    for (let i = 0; i < count; i++) {
      const absolute = this.bit + i
      const byte = this.data[Math.floor(absolute / 8)]
      const bitInByte = absolute % 8
      if ((byte & (1 << bitInByte)) !== 0) value |= 1 << i
    }
    this.bit += count
    return value >>> 0
  }

  readVbr(width: number): number | null {
    if (width < 2 || width > 32) return null
    const payloadBits = width - 1
    const continueBit = 1 << payloadBits
    let shift = 0
    let value = 0
    for (let i = 0; i < 12; i++) {
      const chunk = this.readBits(width)
      if (chunk === null) return null
      value += (chunk & (continueBit - 1)) * 2 ** shift
      if ((chunk & continueBit) === 0) return value
      shift += payloadBits
      if (shift > 53) return null
    }
    return null
  }

  align32() {
    const remainder = this.bit % 32
    if (remainder !== 0) this.bit += 32 - remainder
  }
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function extensionOf(filename?: string): string | null {
  if (!filename || !filename.includes('.')) return null
  return filename.slice(filename.lastIndexOf('.') + 1).toLowerCase()
}

function hasRawBitcodeMagic(data: Buffer, offset = 0): boolean {
  return data.length >= offset + RAW_MAGIC.length && data.subarray(offset, offset + 4).equals(RAW_MAGIC)
}

function hasWrapperMagic(data: Buffer): boolean {
  return data.length >= 4 && data.readUInt32LE(0) === WRAPPER_MAGIC
}

function detectFormat(data: Buffer, filename?: string) {
  const detectedBy: string[] = []
  const extension = extensionOf(filename)
  if (hasRawBitcodeMagic(data)) {
    detectedBy.push('magic:BC-c0-de')
    return { format: 'llvm-bitcode', detectedBy, confidence: 'high' as const }
  }
  if (hasWrapperMagic(data)) {
    detectedBy.push('magic:llvm-bitcode-wrapper')
    return { format: 'llvm-bitcode-wrapper', detectedBy, confidence: 'high' as const }
  }
  if (extension === 'bc') {
    detectedBy.push('extension:.bc')
    return { format: 'llvm-bitcode', detectedBy, confidence: 'medium' as const }
  }
  if (extension === 'll') {
    detectedBy.push('extension:.ll')
    return { format: 'llvm-ir-text', detectedBy, confidence: 'medium' as const }
  }
  const preview = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
  if (/\.(llvmbc|llvm\.lto)|__LLVM|target triple|source_filename/.test(preview)) {
    detectedBy.push('content:llvm-hint')
    return { format: 'llvm-bitcode-native-object-hint', detectedBy, confidence: 'low' as const }
  }
  return { format: 'unknown', detectedBy, confidence: 'low' as const }
}

function parseWrapper(data: Buffer): Record<string, unknown> {
  if (!hasWrapperMagic(data)) {
    return { kind: 'raw-bitstream', wrapper_present: false }
  }
  const version = data.length >= 8 ? data.readUInt32LE(4) : null
  const offset = data.length >= 12 ? data.readUInt32LE(8) : null
  const size = data.length >= 16 ? data.readUInt32LE(12) : null
  const cpuType = data.length >= 20 ? data.readUInt32LE(16) : null
  const declaredEnd = offset !== null && size !== null ? offset + size : null
  const boundsValid = offset !== null && size !== null && offset >= 20 && declaredEnd !== null && declaredEnd <= data.length
  const embeddedMagicValid = boundsValid && offset !== null ? hasRawBitcodeMagic(data, offset) : false
  return {
    kind: 'bitcode-wrapper',
    wrapper_present: true,
    magic: '0x0b17c0de',
    version,
    offset,
    size,
    cpu_type: cpuType,
    declared_stream_end: declaredEnd,
    bounds_valid: boundsValid,
    embedded_magic_valid: embeddedMagicValid,
    trailing_bytes: declaredEnd !== null && declaredEnd <= data.length ? data.length - declaredEnd : null,
  }
}

function getStreamBounds(data: Buffer): { offset: number; size?: number; bytesAvailable: number } {
  if (hasWrapperMagic(data) && data.length >= 20) {
    const offset = data.readUInt32LE(8)
    const declaredSize = data.readUInt32LE(12)
    if (offset >= 20 && offset < data.length) {
      const available = Math.min(declaredSize, data.length - offset)
      return { offset, size: declaredSize, bytesAvailable: available }
    }
  }
  return { offset: 0, size: data.length, bytesAvailable: data.length }
}

function blockName(blockId: number): string {
  return BLOCK_NAMES[blockId] ?? `BLOCK_${blockId}`
}

function char6(value: number): string {
  if (value < 26) return String.fromCharCode(97 + value)
  if (value < 52) return String.fromCharCode(65 + value - 26)
  if (value < 62) return String.fromCharCode(48 + value - 52)
  if (value === 62) return '.'
  if (value === 63) return '_'
  return '?'
}

function readAbbrevOp(cursor: BitCursor): AbbrevOp | null {
  const literal = cursor.readBits(1)
  if (literal === null) return null
  if (literal === 1) {
    const value = cursor.readVbr(8)
    if (value === null) return null
    return { literal: true, value }
  }
  const encodingCode = cursor.readBits(3)
  if (encodingCode === null) return null
  const encoding =
    encodingCode === 1
      ? 'fixed'
      : encodingCode === 2
        ? 'vbr'
        : encodingCode === 3
          ? 'array'
          : encodingCode === 4
            ? 'char6'
            : encodingCode === 5
              ? 'blob'
              : 'unknown'
  const needsData = encoding === 'fixed' || encoding === 'vbr'
  const data = needsData ? cursor.readVbr(5) : undefined
  if (needsData && data === null) return null
  return { literal: false, encoding, data: data ?? undefined }
}

function encodedOp(op: AbbrevOp): AbbrevEncodedOp | null {
  return 'encoding' in op ? op : null
}

function readSingleEncodedValue(
  cursor: BitCursor,
  op: AbbrevOp,
  warnings: string[]
): { value?: number; text?: string; ok: boolean } {
  if (op.literal) return { value: op.value, ok: true }
  const encoded = encodedOp(op)
  if (!encoded) return { ok: false }
  if (encoded.encoding === 'fixed') {
    const value = cursor.readBits(encoded.data ?? 1)
    return value === null ? { ok: false } : { value, ok: true }
  }
  if (encoded.encoding === 'vbr') {
    const value = cursor.readVbr(encoded.data ?? 6)
    return value === null ? { ok: false } : { value, ok: true }
  }
  if (encoded.encoding === 'char6') {
    const value = cursor.readBits(6)
    return value === null ? { ok: false } : { value, text: char6(value), ok: true }
  }
  warnings.push(`Unsupported abbrev operand encoding: ${encoded.encoding}`)
  return { ok: false }
}

function readCustomRecord(
  cursor: BitCursor,
  abbrev: AbbrevDef,
  warnings: string[]
): { operands: number[]; text?: string; ok: boolean } {
  const operands: number[] = []
  const textParts: string[] = []
  for (let i = 0; i < abbrev.ops.length; i++) {
    const op = abbrev.ops[i]
    const encoded = encodedOp(op)
    if (encoded?.encoding === 'array') {
      const elementOp = abbrev.ops[i + 1]
      if (!elementOp) return { operands, ok: false }
      const count = cursor.readVbr(6)
      if (count === null || count > 8192) return { operands, ok: false }
      operands.push(count)
      for (let j = 0; j < count; j++) {
        const item = readSingleEncodedValue(cursor, elementOp, warnings)
        if (!item.ok) return { operands, ok: false }
        if (typeof item.value === 'number') operands.push(item.value)
        if (item.text) textParts.push(item.text)
      }
      i++
      continue
    }
    if (encoded?.encoding === 'blob') {
      const length = cursor.readVbr(6)
      if (length === null || length > 1024 * 1024) return { operands, ok: false }
      cursor.align32()
      const bytes: number[] = []
      for (let j = 0; j < length; j++) {
        const value = cursor.readBits(8)
        if (value === null) return { operands, ok: false }
        if (j < 160) bytes.push(value)
      }
      cursor.align32()
      operands.push(length)
      const blobText = Buffer.from(bytes)
        .toString('utf8')
        .replace(/[^\x20-\x7e]/g, '')
        .trim()
      if (blobText) textParts.push(blobText)
      continue
    }
    const item = readSingleEncodedValue(cursor, op, warnings)
    if (!item.ok) return { operands, ok: false }
    if (typeof item.value === 'number') operands.push(item.value)
    if (item.text) textParts.push(item.text)
  }
  return { operands, text: textParts.join(''), ok: true }
}

function addRecordAggregate(
  records: Map<string, RecordAggregate>,
  blockId: number,
  code: number,
  operands: number[],
  text?: string
) {
  const key = `${blockId}:${code}`
  const existing = records.get(key)
  const block_name = blockName(blockId)
  if (existing) {
    existing.count += 1
    existing.operand_count_min = Math.min(existing.operand_count_min, operands.length)
    existing.operand_count_max = Math.max(existing.operand_count_max, operands.length)
    if (!existing.string_preview && text) existing.string_preview = text.slice(0, 160)
    return
  }
  if (records.size >= MAX_RECORD_SUMMARIES) return
  records.set(key, {
    block_id: blockId,
    block_name,
    code,
    count: 1,
    operand_count_min: operands.length,
    operand_count_max: operands.length,
    sample_operands: operands.slice(0, 12),
    string_preview: text ? text.slice(0, 160) : undefined,
  })
}

function parseBlock(params: {
  cursor: BitCursor
  blockId: number
  depth: number
  abbrevWidth: number
  endBit: number
  blocks: BlockSummary[]
  records: Map<string, RecordAggregate>
  warnings: string[]
  state: { steps: number; maxDepth: number; recordCount: number; limitHit: boolean }
}): BlockSummary {
  const { cursor, blockId, depth, endBit, blocks, records, warnings, state } = params
  const block: BlockSummary = {
    block_id: blockId,
    name: blockName(blockId),
    depth,
    start_bit: cursor.bit,
    record_count: 0,
    subblock_count: 0,
    abbrev_count: 0,
    truncated: false,
  }
  if (blocks.length < MAX_BLOCKS) blocks.push(block)
  const abbrevs = new Map<number, AbbrevDef>()
  let abbrevWidth = params.abbrevWidth
  state.maxDepth = Math.max(state.maxDepth, depth)

  while (cursor.bit < endBit && cursor.bit < cursor.totalBits) {
    if (state.steps++ > MAX_PARSER_STEPS) {
      state.limitHit = true
      warnings.push('Parser step limit reached.')
      break
    }
    const abbrevId = cursor.readBits(abbrevWidth)
    if (abbrevId === null) {
      block.truncated = true
      warnings.push(`Truncated while reading abbrev id in ${block.name}.`)
      break
    }
    if (abbrevId === 0) {
      cursor.align32()
      break
    }
    if (abbrevId === 1) {
      const subBlockId = cursor.readVbr(8)
      const newAbbrevWidth = cursor.readVbr(4)
      cursor.align32()
      const declaredWords = cursor.readBits(32)
      if (subBlockId === null || newAbbrevWidth === null || declaredWords === null) {
        block.truncated = true
        warnings.push(`Truncated ENTER_SUBBLOCK in ${block.name}.`)
        break
      }
      const subStart = cursor.bit
      const subEnd = subStart + declaredWords * 32
      block.subblock_count += 1
      if (subEnd > endBit || subEnd > cursor.totalBits) {
        warnings.push(`Subblock ${blockName(subBlockId)} length exceeds available stream.`)
      }
      const subSummary = parseBlock({
        cursor,
        blockId: subBlockId,
        depth: depth + 1,
        abbrevWidth: Math.max(2, newAbbrevWidth),
        endBit: Math.min(subEnd, endBit, cursor.totalBits),
        blocks,
        records,
        warnings,
        state,
      })
      subSummary.declared_words = declaredWords
      subSummary.end_bit = Math.min(subEnd, cursor.totalBits)
      cursor.bit = Math.min(subEnd, endBit, cursor.totalBits)
      continue
    }
    if (abbrevId === 2) {
      const opCount = cursor.readVbr(5)
      if (opCount === null || opCount > 512) {
        block.truncated = true
        warnings.push(`Invalid DEFINE_ABBREV in ${block.name}.`)
        break
      }
      const ops: AbbrevOp[] = []
      for (let i = 0; i < opCount; i++) {
        const op = readAbbrevOp(cursor)
        if (!op) {
          block.truncated = true
          warnings.push(`Truncated abbrev operand in ${block.name}.`)
          break
        }
        ops.push(op)
      }
      const id = 4 + abbrevs.size
      abbrevs.set(id, { id, ops })
      block.abbrev_count += 1
      continue
    }
    if (abbrevId === 3) {
      const code = cursor.readVbr(6)
      const opCount = cursor.readVbr(6)
      if (code === null || opCount === null || opCount > 8192) {
        block.truncated = true
        warnings.push(`Invalid UNABBREV_RECORD in ${block.name}.`)
        break
      }
      const operands: number[] = []
      for (let i = 0; i < opCount; i++) {
        const operand = cursor.readVbr(6)
        if (operand === null) {
          block.truncated = true
          break
        }
        operands.push(operand)
      }
      block.record_count += 1
      state.recordCount += 1
      addRecordAggregate(records, blockId, code, operands)
      continue
    }
    const abbrev = abbrevs.get(abbrevId)
    if (!abbrev) {
      warnings.push(`Unsupported abbreviation id ${abbrevId} in ${block.name}.`)
      block.truncated = true
      break
    }
    const record = readCustomRecord(cursor, abbrev, warnings)
    if (!record.ok) {
      block.truncated = true
      warnings.push(`Failed to parse abbreviated record ${abbrevId} in ${block.name}.`)
      break
    }
    const code = record.operands[0] ?? abbrevId
    block.record_count += 1
    state.recordCount += 1
    addRecordAggregate(records, blockId, code, record.operands.slice(1), record.text)
  }

  block.end_bit = cursor.bit
  if (cursor.bit >= cursor.totalBits && cursor.bit < endBit) block.truncated = true
  return block
}

function parseBitstream(data: Buffer, streamOffset: number, declaredSize?: number): BitstreamParseResult {
  const bytesAvailable = Math.max(0, Math.min(data.length - streamOffset, declaredSize ?? data.length))
  const parser_warnings: string[] = []
  if (bytesAvailable < 4 || !hasRawBitcodeMagic(data, streamOffset)) {
    return {
      decode_status: 'not-bitstream',
      stream_offset: streamOffset,
      declared_size: declaredSize,
      bytes_available: bytesAvailable,
      block_count: 0,
      record_count: 0,
      max_depth: 0,
      parser_warnings: ['LLVM raw bitcode magic was not found at the selected stream offset.'],
      block_summaries: [],
      record_summaries: [],
    }
  }
  const cursor = new BitCursor(data, streamOffset + 4)
  const blocks: BlockSummary[] = []
  const records = new Map<string, RecordAggregate>()
  const state = { steps: 0, maxDepth: 0, recordCount: 0, limitHit: false }
  const endBit = (streamOffset + bytesAvailable) * 8
  parseBlock({
    cursor,
    blockId: 8,
    depth: 0,
    abbrevWidth: 2,
    endBit,
    blocks,
    records,
    warnings: parser_warnings,
    state,
  })
  const truncated = bytesAvailable < (declaredSize ?? bytesAvailable)
  const partial = blocks.some((block) => block.truncated)
  const decode_status = state.limitHit
    ? 'limit-hit'
    : truncated
      ? 'truncated'
      : partial
        ? 'partial'
        : 'parsed'
  return {
    decode_status,
    stream_offset: streamOffset,
    declared_size: declaredSize,
    bytes_available: bytesAvailable,
    block_count: blocks.length,
    record_count: state.recordCount,
    max_depth: state.maxDepth,
    parser_warnings: uniqueStrings(parser_warnings).slice(0, 32),
    block_summaries: blocks,
    record_summaries: Array.from(records.values()),
  }
}

function extractAsciiStrings(data: Buffer): string[] {
  const text = data.toString('latin1')
  const matches = text.match(/[A-Za-z0-9_./:@+\\-]{4,}/g) ?? []
  return uniqueStrings(matches).slice(0, MAX_STRINGS)
}

function buildStringHints(strings: string[]) {
  const urls = strings.filter((value) => /^https?:\/\//i.test(value)).slice(0, 16)
  const paths = strings
    .filter((value) => /[A-Za-z]:\\|\/[A-Za-z0-9_.-]+\/|\\[A-Za-z0-9_.-]+\\/.test(value))
    .slice(0, 24)
  const triples = strings
    .filter((value) => /(?:x86_64|aarch64|arm|wasm32|riscv|powerpc|mips).*(?:linux|windows|darwin|apple|unknown|wasi)/i.test(value))
    .slice(0, 24)
  const toolchainMarkers = strings
    .filter((value) => /clang|llvm|rustc|swift|lto|thinlto|wasm-ld|lld/i.test(value))
    .slice(0, 24)
  return {
    ascii: strings,
    urls,
    paths,
    target_triples: triples,
    toolchain_markers: toolchainMarkers,
    truncated: strings.length >= MAX_STRINGS,
  }
}

function buildIrHints(strings: string[], bitstream: BitstreamParseResult) {
  return {
    target_triples: strings
      .filter((value) => /(?:x86_64|aarch64|arm|wasm32|riscv|powerpc|mips).*(?:linux|windows|darwin|apple|unknown|wasi)/i.test(value))
      .slice(0, 16),
    source_filenames: strings.filter((value) => /\.(c|cc|cpp|cxx|m|mm|rs|swift|ll)$/i.test(value)).slice(0, 16),
    section_name_hints: strings.filter((value) => /^(\.|__LLVM|llvmbc|llvm\.lto)/i.test(value)).slice(0, 16),
    module_block_present: bitstream.block_summaries.some((block) => block.block_id === 8),
    function_block_count_hint: bitstream.block_summaries.filter((block) => block.block_id === 12).length,
    metadata_block_count_hint: bitstream.block_summaries.filter((block) => block.block_id === 15).length,
    strtab_present: bitstream.block_summaries.some((block) => block.block_id === 23),
  }
}

function riskFlag(id: string, severity: string, category: string, evidence: string) {
  return { id, severity, category, evidence }
}

function buildRiskFlags(input: {
  format: string
  confidence: string
  container: Record<string, unknown>
  bitstream: BitstreamParseResult
  strings: ReturnType<typeof buildStringHints>
}) {
  const flags: Array<Record<string, unknown>> = []
  if (input.format === 'unknown') {
    flags.push(riskFlag('unknown-magic', 'medium', 'format', 'No LLVM bitcode magic or strong LLVM hint was found.'))
  }
  if (input.confidence === 'medium') {
    flags.push(
      riskFlag('extension-only-unverified', 'low', 'format', 'LLVM bitcode classification relies on extension fallback.')
    )
  }
  if (input.container.kind === 'bitcode-wrapper') {
    if (input.container.bounds_valid !== true) {
      flags.push(
        riskFlag('wrapper-bounds-invalid', 'high', 'structure', 'Wrapper offset/size does not fit inside the preview.')
      )
    }
    if (input.container.version !== 0) {
      flags.push(
        riskFlag('wrapper-version-unexpected', 'medium', 'structure', 'Wrapper version is not the expected value 0.')
      )
    }
    if (input.container.embedded_magic_valid !== true) {
      flags.push(
        riskFlag('wrapper-embedded-magic-missing', 'high', 'structure', 'Wrapper payload does not start with raw LLVM bitcode magic.')
      )
    }
  }
  if (input.bitstream.decode_status === 'truncated' || input.bitstream.decode_status === 'partial') {
    flags.push(
      riskFlag('parser-partial', 'medium', 'parser', `Bitstream parser status is ${input.bitstream.decode_status}.`)
    )
  }
  if (input.bitstream.decode_status === 'limit-hit') {
    flags.push(riskFlag('parser-limit-reached', 'medium', 'parser', 'Bitstream parser hit the safety step limit.'))
  }
  if (input.strings.paths.length > 0 || input.strings.urls.length > 0) {
    flags.push(
      riskFlag('embedded-path-or-url', 'low', 'privacy', 'Bitcode preview contains path or URL-like string evidence.')
    )
  }
  if (input.format === 'llvm-bitcode-native-object-hint') {
    flags.push(
      riskFlag('native-object-bitcode-hint', 'low', 'routing', 'Native object container hints should be reviewed with native.object.inventory.')
    )
  }
  return flags
}

function riskLevel(flags: Array<Record<string, unknown>>) {
  if (flags.some((flag) => flag.severity === 'high')) return 'high'
  if (flags.some((flag) => flag.severity === 'medium')) return 'medium'
  if (flags.length > 0) return 'low'
  return 'none'
}

function buildEvidenceSummary(input: {
  sampleId?: string
  filename?: string
  format: string
  bitstream: BitstreamParseResult
  riskFlags: Array<Record<string, unknown>>
}) {
  return {
    schema: 'rikune.llvm_bitcode_inventory.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: input.sampleId ?? null,
    filename: input.filename ?? null,
    artifact_type: LLVM_BITCODE_ARTIFACT_TYPE,
    format: input.format,
    route_terms: ['llvm-bitcode', 'llvm-ir', 'bitcode', 'lto', 'remill', 'decompiler-ir'],
    evidence_categories: LLVM_BITCODE_EVIDENCE,
    counts: {
      blocks: input.bitstream.block_count,
      records: input.bitstream.record_count,
      record_kinds: input.bitstream.record_summaries.length,
      risk_flags: input.riskFlags.length,
    },
    static_only: true,
  }
}

function buildWorkflowHandoff(input: { sampleId?: string; format: string }) {
  return {
    schema: 'rikune.llvm_bitcode_inventory.workflow_handoff.v1',
    handoff_mode: 'llvm_bitcode_inventory_to_static_ir_triage',
    source_tool: TOOL_NAME,
    sample_id: input.sampleId ?? null,
    artifact_type: LLVM_BITCODE_ARTIFACT_TYPE,
    format: input.format,
    recommended_next_tools: LLVM_BITCODE_FOLLOW_UP_TOOLS,
    routing: [
      {
        goal: 'string-and-toolchain-correlation',
        priority: 'normal',
        next_tools: ['strings.extract', 'metadata.extract'],
        required_evidence: [LLVM_BITCODE_ARTIFACT_TYPE, 'embedded strings'],
      },
      {
        goal: 'native-container-review',
        priority: 'conditional',
        next_tools: ['native.object.inventory'],
        required_evidence: ['native object bitcode section hints'],
      },
      {
        goal: 'lifted-ir-cross-backend-correlation',
        priority: 'normal',
        next_tools: ['workflow.search', 'analysis.evidence.graph', 'report.generate'],
        required_evidence: [LLVM_BITCODE_ARTIFACT_TYPE],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      llvm_tool_invoked_by_tool: false,
      compiled_by_tool: false,
      linked_by_tool: false,
      jit_started_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildQualityGates(input: { format: string; bitstream: BitstreamParseResult }) {
  return {
    schema: 'rikune.llvm_bitcode_inventory.quality_gates.v1',
    passive_static_inventory: true,
    format_detected: input.format !== 'unknown',
    raw_magic_valid:
      input.bitstream.decode_status === 'parsed' ||
      input.bitstream.decode_status === 'partial' ||
      input.bitstream.decode_status === 'truncated' ||
      input.bitstream.decode_status === 'limit-hit',
    llvm_tool_invoked_by_tool: false,
    sample_executed_by_tool: false,
    compiled_by_tool: false,
    linked_by_tool: false,
    jit_started_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    analyst_review_required: true,
  }
}

export function buildLlvmBitcodeInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): LlvmBitcodeInventory {
  const { format, detectedBy, confidence } = detectFormat(data, options.filename)
  const container = parseWrapper(data)
  const streamBounds = getStreamBounds(data)
  const bitstream = parseBitstream(data, streamBounds.offset, streamBounds.size)
  const stringHints = buildStringHints(extractAsciiStrings(data))
  const llvmIrHints = buildIrHints(stringHints.ascii, bitstream)
  const riskFlags = buildRiskFlags({
    format,
    confidence,
    container,
    bitstream,
    strings: stringHints,
  })
  const riskSummary = {
    risk_level: riskLevel(riskFlags),
    flags: riskFlags.map((flag) => flag.id),
    count: riskFlags.length,
  }
  const recommendedNextTools = uniqueStrings([
    ...LLVM_BITCODE_FOLLOW_UP_TOOLS,
    ...(format === 'llvm-bitcode-native-object-hint' ? ['native.object.inventory'] : []),
  ])

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format,
    detected_by: detectedBy,
    confidence,
    size: options.size ?? data.length,
    preview_size: data.length,
    container,
    bitstream,
    llvm_ir_hints: llvmIrHints,
    embedded_strings: stringHints,
    risk_flags: riskFlags,
    risk_summary: riskSummary,
    policy: {
      passive: true,
      no_execute: true,
      no_compile: true,
      no_link: true,
      no_llvm_toolchain_required: true,
      no_network: true,
      no_mutation: true,
    },
    summary: `Passive LLVM bitcode inventory detected ${format} with ${bitstream.block_count} block(s), ${bitstream.record_count} record(s), risk=${riskSummary.risk_level}.`,
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review block and record summaries before deeper IR analysis.',
      'Use strings.extract or metadata.extract for source path, target triple, and toolchain correlation.',
      'Use native.object.inventory when bitcode appears embedded in a native object container.',
    ],
    evidence_summary: buildEvidenceSummary({
      sampleId: options.sampleId,
      filename: options.filename,
      format,
      bitstream,
      riskFlags,
    }),
    workflow_handoff: buildWorkflowHandoff({ sampleId: options.sampleId, format }),
    quality_gates: buildQualityGates({ format, bitstream }),
  }
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

export function createLlvmBitcodeInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (
    args: z.infer<typeof LlvmBitcodeInventoryInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = LlvmBitcodeInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildLlvmBitcodeInventoryFromBuffer(data, {
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
            LLVM_BITCODE_ARTIFACT_TYPE,
            'llvm-bitcode',
            inventory,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: inventory can still be returned without persistence.
        }
      }

      return {
        ok: true,
        data: inventory,
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
