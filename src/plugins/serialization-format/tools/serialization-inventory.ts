/**
 * serialization.inventory - passive serialization format identification.
 *
 * Identifies and profiles binary serialization formats without deserializing
 * into language objects, executing code, or following external references.
 * Formats covered: Protocol Buffers (wire), Cap'n Proto, MessagePack,
 * FlatBuffers, Thrift (binary), Avro (object container), CBOR, BSON.
 *
 * The tool reads bounded bytes and summarizes magic signatures, structure,
 * field/type hints, and deserialization risk. It never calls into a runtime
 * deserializer or instantiates objects from untrusted data.
 */

import crypto from 'crypto'
import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'serialization.inventory'
const TOOL_VERSION = '0.1.0'
export const SERIALIZATION_INVENTORY_ARTIFACT_TYPE = 'serialization_inventory'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_STRINGS = 120
const MAX_FIELDS = 4096
const MAX_STRUCT_ENTRIES = 1024

type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
type Confidence = 'low' | 'medium' | 'high'

interface RiskSignal {
  id: string
  severity: Severity
  category: string
  evidence: string
  confidence: number
}

interface FormatDetection {
  format: string
  confidence: Confidence
  detected_by: string[]
  magic_offset: number
  magic_bytes: string
  variant?: string
}

interface FieldHint {
  field_number?: number
  wire_type?: number
  type_hint?: string
  name?: string
}

interface StructEntry {
  offset: number
  type_hint?: string
  size?: number
  label?: string
}

interface SerializationInventory {
  sample_id: string
  filename: string
  format: string
  variant?: string
  detected_by: string[]
  confidence: Confidence
  size: number
  preview_size: number
  sha256_preview: string
  detections: FormatDetection[]
  field_hints: FieldHint[]
  struct_entries: StructEntry[]
  embedded_strings: string[]
  metadata: Record<string, unknown>
  risk_signals: RiskSignal[]
  risk_level: Severity | 'none'
  follow_up_tools: string[]
  safety: string[]
}

const SERIALIZATION_EVIDENCE = [
  'structure',
  'metadata',
  'strings',
  'workflow',
  'provenance',
] as const

const SERIALIZATION_SAFETY = [
  'passive',
  'no_deserialization',
  'no_runtime_decode',
  'no_network_by_default',
  'no_mutation',
  'no_extract_to_execution_path',
] as const

const SERIALIZATION_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
] as const

// ─── Schemas ───────────────────────────────────────────────────────────────

const FieldHintSchema = z
  .object({
    field_number: z.number().int().optional(),
    wire_type: z.number().int().optional(),
    type_hint: z.string().optional(),
    name: z.string().optional(),
  })
  .passthrough()

const StructEntrySchema = z
  .object({
    offset: z.number().int(),
    type_hint: z.string().optional(),
    size: z.number().int().optional(),
    label: z.string().optional(),
  })
  .passthrough()

const FormatDetectionSchema = z
  .object({
    format: z.string(),
    confidence: z.enum(['low', 'medium', 'high']),
    detected_by: z.array(z.string()),
    magic_offset: z.number().int(),
    magic_bytes: z.string(),
    variant: z.string().optional(),
  })
  .passthrough()

const RiskSignalSchema = z
  .object({
    id: z.string(),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
    category: z.string(),
    evidence: z.string(),
    confidence: z.number().min(0).max(1),
  })
  .passthrough()

const SerializationInventorySchema = z
  .object({
    sample_id: z.string(),
    filename: z.string(),
    format: z.string(),
    variant: z.string().optional(),
    detected_by: z.array(z.string()),
    confidence: z.enum(['low', 'medium', 'high']),
    size: z.number(),
    preview_size: z.number(),
    sha256_preview: z.string(),
    detections: z.array(FormatDetectionSchema),
    field_hints: z.array(FieldHintSchema),
    struct_entries: z.array(StructEntrySchema),
    embedded_strings: z.array(z.string()),
    metadata: z.record(z.any()),
    risk_signals: z.array(RiskSignalSchema),
    risk_level: z.enum(['info', 'low', 'medium', 'high', 'critical', 'none']),
    follow_up_tools: z.array(z.string()),
    safety: z.array(z.string()),
  })
  .passthrough()

export const SerializationInventoryInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_read_bytes: z
    .number()
    .int()
    .positive()
    .max(64 * 1024 * 1024)
    .optional()
    .describe('Maximum bytes to read for passive inspection.'),
  persist_artifact: z.boolean().default(true).describe('Persist the inventory artifact.'),
  session_tag: z.string().optional().describe('Optional session tag for persisted artifacts.'),
})

export const SerializationInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: SerializationInventorySchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

// ─── Helpers ──────────────────────────────────────────────────────────────

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function riskSignal(
  id: string,
  severity: Severity,
  category: string,
  evidence: string,
  confidence = 0.8
): RiskSignal {
  return { id, severity, category, evidence, confidence }
}

function severityRank(severity: Severity): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity]
}

function riskLevel(signals: RiskSignal[]): Severity | 'none' {
  if (signals.length === 0) return 'none'
  return signals.reduce(
    (current, signal) =>
      severityRank(signal.severity) > severityRank(current) ? signal.severity : current,
    'info' as Severity
  )
}

function extractAsciiStrings(data: Buffer): string[] {
  const text = data.subarray(0, Math.min(data.length, 2 * 1024 * 1024)).toString('latin1')
  const matches = text.match(/[A-Za-z0-9_./:@+\\=${}[\],()'" -]{5,}/g) ?? []
  return unique(matches.map((item) => item.trim())).slice(0, MAX_STRINGS)
}

function toHex(data: Buffer, offset: number, length: number): string {
  const end = Math.min(offset + length, data.length)
  return data.subarray(offset, end).toString('hex')
}

// ─── Format detectors ──────────────────────────────────────────────────────

/**
 * Protocol Buffers wire format has no magic bytes, so detection is heuristic:
 * the stream must be a sequence of valid (field_number, wire_type) varint tags
 * followed by plausible payloads. We scan for runs of well-formed tag/payload
 * pairs to build confidence.
 */
function detectProtobuf(data: Buffer): FormatDetection | null {
  if (data.length < 2) return null
  let offset = 0
  let validTags = 0
  const fieldHints: FieldHint[] = []
  let cursor = 0

  while (cursor < data.length && validTags < 64) {
    const tagResult = readVarint(data, cursor)
    if (!tagResult) break
    const tag = Number(tagResult.value & 0xffffffffn)
    const fieldNumber = tag >>> 3
    const wireType = tag & 0x07
    cursor = tagResult.nextOffset

    if (fieldNumber === 0 || fieldNumber > 536870911) break
    if (wireType > 5 && wireType !== 2) break

    fieldHints.push({ field_number: fieldNumber, wire_type: wireType })

    if (wireType === 0) {
      const v = readVarint(data, cursor)
      if (!v) break
      cursor = v.nextOffset
      fieldHints[fieldHints.length - 1].type_hint = 'varint'
    } else if (wireType === 1) {
      if (cursor + 8 > data.length) break
      cursor += 8
      fieldHints[fieldHints.length - 1].type_hint = 'fixed64'
    } else if (wireType === 2) {
      const lenResult = readVarint(data, cursor)
      if (!lenResult) break
      const len = Number(lenResult.value)
      cursor = lenResult.nextOffset
      if (len < 0 || cursor + len > data.length) break
      cursor += len
      fieldHints[fieldHints.length - 1].type_hint = 'length-delimited'
    } else if (wireType === 5) {
      if (cursor + 4 > data.length) break
      cursor += 4
      fieldHints[fieldHints.length - 1].type_hint = 'fixed32'
    } else {
      break
    }
    validTags++
    offset = cursor
  }

  if (validTags < 3) return null

  return {
    format: 'protobuf',
    confidence: validTags >= 10 ? 'medium' : 'low',
    detected_by: [`wire-format-tag-sequence (${validTags} valid tags)`],
    magic_offset: 0,
    magic_bytes: toHex(data, 0, Math.min(16, data.length)),
    variant: 'wire',
  }
}

function readVarint(
  data: Buffer,
  offset: number
): { value: bigint; nextOffset: number } | null {
  if (offset >= data.length) return null
  let result = 0n
  let shift = 0n
  let cursor = offset
  while (cursor < data.length && cursor - offset < 10) {
    const byte = data[cursor]
    result |= BigInt(byte & 0x7f) << shift
    cursor++
    if ((byte & 0x80) === 0) {
      return { value: result, nextOffset: cursor }
    }
    shift += 7n
  }
  return null
}

/**
 * Cap'n Proto: 8-byte segment count (word count - 1) followed by segment sizes.
 * The first 4 bytes are (segmentCount - 1) in little-endian. We verify the
 * structure is self-consistent.
 */
function detectCapnProto(data: Buffer): FormatDetection | null {
  if (data.length < 8) return null
  const offset = scanForBytes(data, Buffer.from([0x00, 0x00, 0x00, 0x00]), 0, 256)
  if (offset === -1) return null
  if (offset + 8 > data.length) return null
  const rawSegmentCount = data.readUInt32LE(offset)
  if (rawSegmentCount > 512) return null
  const segmentCount = rawSegmentCount + 1
  const headerWords = 1 + Math.floor((segmentCount + 1) / 2)
  const headerBytes = headerWords * 8
  if (offset + headerBytes > data.length) return null
  let totalWords = 0
  for (let i = 0; i < segmentCount; i++) {
    const segOffset = offset + 4 + i * 4
    if (segOffset + 4 > data.length) return null
    totalWords += data.readUInt32LE(segOffset)
  }
  if (totalWords === 0 || totalWords > 8 * 1024 * 1024) return null
  const expectedLength = headerBytes + totalWords * 8
  if (expectedLength > data.length + 8) return null

  return {
    format: 'capn-proto',
    confidence: 'medium',
    detected_by: [
      `segment-table (${segmentCount} segments, ${totalWords} words)`,
    ],
    magic_offset: offset,
    magic_bytes: toHex(data, offset, 8),
    variant: 'binary',
  }
}

/**
 * MessagePack: detect by leading fixmap/array/str/int markers or explicit
 * magic in msgpack-coded streams. We scan for a valid top-level value.
 */
function detectMessagePack(data: Buffer): FormatDetection | null {
  if (data.length < 1) return null
  const first = data[0]
  const isFixMap = first >= 0x80 && first <= 0x8f
  const isFixArray = first >= 0x90 && first <= 0x9f
  const isFixStr = first >= 0xa0 && first <= 0xbf
  const isPosFixint = first <= 0x7f
  const isNegFixint = first >= 0xe0
  const isNil = first === 0xc0
  const isTrue = first === 0xc3
  const isFalse = first === 0xc2
  const isBin8 = first === 0xc4
  const isBin16 = first === 0xc5
  const isBin32 = first === 0xc6
  const isExt8 = first === 0xc7
  const isFloat32 = first === 0xca
  const isFloat64 = first === 0xcb
  const isUint8 = first === 0xcc
  const isUint16 = first === 0xcd
  const isUint32 = first === 0xce
  const isUint64 = first === 0xcf
  const isInt8 = first === 0xd0
  const isInt16 = first === 0xd1
  const isInt32 = first === 0xd2
  const isInt64 = first === 0xd3
  const isStr8 = first === 0xd9
  const isStr16 = first === 0xda
  const isStr32 = first === 0xdb
  const isArray16 = first === 0xdc
  const isMap16 = first === 0xde

  const isMsgpackMarker =
    isFixMap ||
    isFixArray ||
    isFixStr ||
    isPosFixint ||
    isNegFixint ||
    isNil ||
    isTrue ||
    isFalse ||
    isBin8 ||
    isBin16 ||
    isBin32 ||
    isExt8 ||
    isFloat32 ||
    isFloat64 ||
    isUint8 ||
    isUint16 ||
    isUint32 ||
    isUint64 ||
    isInt8 ||
    isInt16 ||
    isInt32 ||
    isInt64 ||
    isStr8 ||
    isStr16 ||
    isStr32 ||
    isArray16 ||
    isMap16

  if (!isMsgpackMarker) return null

  // Validate by attempting to parse the first few values.
  const parsed = parseMsgpack(data, 0, 0)
  if (!parsed || parsed.depth === 0) return null

  return {
    format: 'msgpack',
    confidence: parsed.depth >= 3 ? 'medium' : 'low',
    detected_by: [`leading-marker 0x${first.toString(16).padStart(2, '0')} (${parsed.depth} values)`],
    magic_offset: 0,
    magic_bytes: toHex(data, 0, Math.min(16, data.length)),
    variant: 'binary',
  }
}

function parseMsgpack(
  data: Buffer,
  offset: number,
  depth: number,
  maxDepth = 8
): { nextOffset: number; depth: number } | null {
  if (offset >= data.length || depth > maxDepth) return null
  const marker = data[offset]
  let next = offset + 1

  if (marker <= 0x7f || marker >= 0xe0) {
    return { nextOffset: next, depth: depth + 1 }
  }
  if (marker >= 0x80 && marker <= 0x8f) {
    const count = marker & 0x0f
    for (let i = 0; i < count && next < data.length; i++) {
      const key = parseMsgpack(data, next, depth + 1, maxDepth)
      if (!key) return null
      next = key.nextOffset
      const val = parseMsgpack(data, next, depth + 1, maxDepth)
      if (!val) return null
      next = val.nextOffset
    }
    return { nextOffset: next, depth: depth + 1 }
  }
  if (marker >= 0x90 && marker <= 0x9f) {
    const count = marker & 0x0f
    for (let i = 0; i < count && next < data.length; i++) {
      const val = parseMsgpack(data, next, depth + 1, maxDepth)
      if (!val) return null
      next = val.nextOffset
    }
    return { nextOffset: next, depth: depth + 1 }
  }
  if (marker >= 0xa0 && marker <= 0xbf) {
    const len = marker & 0x1f
    next += len
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xc0 || marker === 0xc2 || marker === 0xc3) {
    return { nextOffset: next, depth: depth + 1 }
  }
  if (marker === 0xc4 || marker === 0xc7 || marker === 0xd9) {
    if (next + 1 > data.length) return null
    const len = data[next]
    next += 1 + len
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xc5 || marker === 0xc8 || marker === 0xda) {
    if (next + 2 > data.length) return null
    const len = data.readUInt16BE(next)
    next += 2 + len
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xc6 || marker === 0xc9 || marker === 0xdb) {
    if (next + 4 > data.length) return null
    const len = data.readUInt32BE(next)
    next += 4 + len
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xca) {
    next += 4
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xcb || marker === 0xcf || marker === 0xd3) {
    next += 8
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xcc || marker === 0xd0) {
    next += 1
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xcd || marker === 0xd1) {
    next += 2
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xce || marker === 0xd2) {
    next += 4
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (marker === 0xdc) {
    if (next + 2 > data.length) return null
    const count = data.readUInt16BE(next)
    next += 2
    for (let i = 0; i < count && next < data.length; i++) {
      const val = parseMsgpack(data, next, depth + 1, maxDepth)
      if (!val) return null
      next = val.nextOffset
    }
    return { nextOffset: next, depth: depth + 1 }
  }
  if (marker === 0xde) {
    if (next + 2 > data.length) return null
    const count = data.readUInt16BE(next)
    next += 2
    for (let i = 0; i < count && next < data.length; i++) {
      const key = parseMsgpack(data, next, depth + 1, maxDepth)
      if (!key) return null
      next = key.nextOffset
      const val = parseMsgpack(data, next, depth + 1, maxDepth)
      if (!val) return null
      next = val.nextOffset
    }
    return { nextOffset: next, depth: depth + 1 }
  }

  return null
}

/**
 * FlatBuffers: root table starts with a 4-byte offset (u32 LE) to the root
 * table. The root table's first 4 bytes are a vtable offset (negative LE).
 * We verify the vtable is within bounds and self-consistent.
 */
function detectFlatBuffers(data: Buffer): FormatDetection | null {
  if (data.length < 16) return null
  const rootOffset = data.readUInt32LE(0)
  if (rootOffset === 0 || rootOffset + 8 > data.length) return null
  const vtableRel = data.readInt32LE(rootOffset)
  const vtableOffset = rootOffset - vtableRel
  if (vtableOffset < 0 || vtableOffset + 4 > data.length) return null
  const vtableSize = data.readUInt16LE(vtableOffset)
  const tableSize = data.readUInt16LE(vtableOffset + 2)
  if (vtableSize < 4 || vtableSize > 256) return null
  if (tableSize === 0 || tableSize > 1024 * 1024) return null
  // Vtable size must be even.
  if (vtableSize % 2 !== 0) return null

  return {
    format: 'flatbuffers',
    confidence: 'medium',
    detected_by: [
      `root-offset ${rootOffset} -> vtable at ${vtableOffset} (vsize=${vtableSize}, tsize=${tableSize})`,
    ],
    magic_offset: 0,
    magic_bytes: toHex(data, 0, Math.min(16, data.length)),
    variant: 'binary',
  }
}

/**
 * Thrift binary protocol: no magic, but the first message usually starts with
 * a struct field header (type byte + field id). Compact protocol starts with
 * a protocol id (0x82). We detect compact by id, binary by heuristic.
 */
function detectThrift(data: Buffer): FormatDetection | null {
  if (data.length < 4) return null
  // Compact protocol
  if (data[0] === 0x82) {
    return {
      format: 'thrift',
      confidence: 'medium',
      detected_by: ['compact-protocol-id 0x82'],
      magic_offset: 0,
      magic_bytes: toHex(data, 0, 4),
      variant: 'compact',
    }
  }
  // Binary protocol heuristic: type byte (1-12, 15) + 2-byte field id
  const typeByte = data[0]
  const validTypes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15]
  if (validTypes.includes(typeByte) && data.length >= 3) {
    return {
      format: 'thrift',
      confidence: 'low',
      detected_by: [`binary-field-header type=${typeByte}`],
      magic_offset: 0,
      magic_bytes: toHex(data, 0, 4),
      variant: 'binary',
    }
  }
  return null
}

/**
 * Avro Object Container File: magic bytes "Obj\x01".
 */
function detectAvro(data: Buffer): FormatDetection | null {
  const magic = Buffer.from([0x4f, 0x62, 0x6a, 0x01]) // "Obj\x01"
  const offset = scanForBytes(data, magic, 0, 64)
  if (offset === -1) return null
  return {
    format: 'avro',
    confidence: 'high',
    detected_by: ['object-container-magic "Obj\\x01"'],
    magic_offset: offset,
    magic_bytes: toHex(data, offset, 4),
    variant: 'object-container',
  }
}

/**
 * CBOR: major type in high 3 bits, additional info in low 5 bits.
 * Validate the first few items parse as a self-consistent structure.
 */
function detectCbor(data: Buffer): FormatDetection | null {
  if (data.length < 1) return null
  const first = data[0]
  const majorType = (first & 0xe0) >> 5
  const additional = first & 0x1f
  if (majorType > 7) return null
  if (additional === 31 && majorType !== 2 && majorType !== 3 && majorType !== 4 && majorType !== 5)
    return null

  const parsed = parseCbor(data, 0, 0)
  if (!parsed || parsed.depth === 0) return null

  return {
    format: 'cbor',
    confidence: parsed.depth >= 3 ? 'medium' : 'low',
    detected_by: [`major-type ${majorType} (${parsed.depth} values parsed)`],
    magic_offset: 0,
    magic_bytes: toHex(data, 0, Math.min(16, data.length)),
    variant: 'binary',
  }
}

function parseCbor(
  data: Buffer,
  offset: number,
  depth: number,
  maxDepth = 8
): { nextOffset: number; depth: number } | null {
  if (offset >= data.length || depth > maxDepth) return null
  const first = data[offset]
  const majorType = (first & 0xe0) >> 5
  const additional = first & 0x1f
  let next = offset + 1

  let payloadLen = -1
  let isIndefinite = false
  if (additional < 24) {
    payloadLen = additional
  } else if (additional === 24) {
    if (next + 1 > data.length) return null
    payloadLen = data[next]
    next += 1
  } else if (additional === 25) {
    if (next + 2 > data.length) return null
    payloadLen = data.readUInt16BE(next)
    next += 2
  } else if (additional === 26) {
    if (next + 4 > data.length) return null
    payloadLen = data.readUInt32BE(next)
    next += 4
  } else if (additional === 27) {
    if (next + 8 > data.length) return null
    // Read as two 32-bit parts; we only need to advance.
    next += 8
    payloadLen = 0
  } else if (additional === 31) {
    isIndefinite = true
  } else {
    return null
  }

  if (majorType === 0 || majorType === 1 || majorType === 7) {
    return { nextOffset: next, depth: depth + 1 }
  }
  if (majorType === 2 || majorType === 3) {
    if (isIndefinite) {
      // Scan for break marker (0xff).
      let cursor = next
      while (cursor < data.length && data[cursor] !== 0xff) {
        const item = parseCbor(data, cursor, depth + 1, maxDepth)
        if (!item) return null
        cursor = item.nextOffset
      }
      return cursor < data.length
        ? { nextOffset: cursor + 1, depth: depth + 1 }
        : null
    }
    next += payloadLen
    return next <= data.length ? { nextOffset: next, depth: depth + 1 } : null
  }
  if (majorType === 4) {
    if (isIndefinite) {
      let cursor = next
      while (cursor < data.length && data[cursor] !== 0xff) {
        const item = parseCbor(data, cursor, depth + 1, maxDepth)
        if (!item) return null
        cursor = item.nextOffset
      }
      return cursor < data.length
        ? { nextOffset: cursor + 1, depth: depth + 1 }
        : null
    }
    for (let i = 0; i < payloadLen && next < data.length; i++) {
      const item = parseCbor(data, next, depth + 1, maxDepth)
      if (!item) return null
      next = item.nextOffset
    }
    return { nextOffset: next, depth: depth + 1 }
  }
  if (majorType === 5) {
    if (isIndefinite) {
      let cursor = next
      while (cursor < data.length && data[cursor] !== 0xff) {
        const key = parseCbor(data, cursor, depth + 1, maxDepth)
        if (!key) return null
        cursor = key.nextOffset
        const val = parseCbor(data, cursor, depth + 1, maxDepth)
        if (!val) return null
        cursor = val.nextOffset
      }
      return cursor < data.length
        ? { nextOffset: cursor + 1, depth: depth + 1 }
        : null
    }
    for (let i = 0; i < payloadLen && next < data.length; i++) {
      const key = parseCbor(data, next, depth + 1, maxDepth)
      if (!key) return null
      next = key.nextOffset
      const val = parseCbor(data, next, depth + 1, maxDepth)
      if (!val) return null
      next = val.nextOffset
    }
    return { nextOffset: next, depth: depth + 1 }
  }
  if (majorType === 6) {
    const inner = parseCbor(data, next, depth + 1, maxDepth)
    return inner ? { nextOffset: inner.nextOffset, depth: depth + 1 } : null
  }

  return null
}

/**
 * BSON: little-endian int32 total document size at offset 0, followed by
 * elements, terminated by 0x00. We verify size consistency.
 */
function detectBson(data: Buffer): FormatDetection | null {
  if (data.length < 5) return null
  const docSize = data.readInt32LE(0)
  if (docSize < 5 || docSize > data.length) return null
  if (data[docSize - 1] !== 0x00) return null

  return {
    format: 'bson',
    confidence: 'high',
    detected_by: [`document-size ${docSize} with null terminator`],
    magic_offset: 0,
    magic_bytes: toHex(data, 0, 5),
    variant: 'document',
  }
}

function scanForBytes(
  data: Buffer,
  needle: Buffer,
  start: number,
  maxScan: number
): number {
  const limit = Math.min(start + maxScan, data.length - needle.length + 1)
  for (let i = start; i < limit; i++) {
    if (data[i] !== needle[0]) continue
    let matched = true
    for (let j = 1; j < needle.length; j++) {
      if (data[i + j] !== needle[j]) {
        matched = false
        break
      }
    }
    if (matched) return i
  }
  return -1
}

// ─── Build inventory ───────────────────────────────────────────────────────

function detectAll(data: Buffer): FormatDetection[] {
  const detectors: Array<() => FormatDetection | null> = [
    () => detectAvro(data),
    () => detectBson(data),
    () => detectFlatBuffers(data),
    () => detectCapnProto(data),
    () => detectMessagePack(data),
    () => detectCbor(data),
    () => detectThrift(data),
    () => detectProtobuf(data), // lowest confidence — heuristic
  ]
  const results: FormatDetection[] = []
  for (const detector of detectors) {
    try {
      const result = detector()
      if (result) results.push(result)
    } catch {
      // A detector throwing is treated as "not this format".
    }
  }
  return results
}

function extractProtobufFieldHints(data: Buffer): FieldHint[] {
  const hints: FieldHint[] = []
  let cursor = 0
  while (cursor < data.length && hints.length < MAX_FIELDS) {
    const tagResult = readVarint(data, cursor)
    if (!tagResult) break
    const fieldNumber = Number(tagResult.value >> 3n)
    const wireType = Number(tagResult.value & 0x7n)
    if (fieldNumber === 0 || fieldNumber > 536870911) break
    cursor = tagResult.nextOffset
    hints.push({ field_number: fieldNumber, wire_type: wireType })
    if (wireType === 0) {
      const v = readVarint(data, cursor)
      if (!v) break
      cursor = v.nextOffset
      hints[hints.length - 1].type_hint = 'varint'
    } else if (wireType === 1) {
      if (cursor + 8 > data.length) break
      cursor += 8
      hints[hints.length - 1].type_hint = 'fixed64'
    } else if (wireType === 2) {
      const lenResult = readVarint(data, cursor)
      if (!lenResult) break
      cursor = lenResult.nextOffset + Number(lenResult.value)
      hints[hints.length - 1].type_hint = 'length-delimited'
    } else if (wireType === 5) {
      if (cursor + 4 > data.length) break
      cursor += 4
      hints[hints.length - 1].type_hint = 'fixed32'
    } else {
      break
    }
  }
  return hints
}

function buildStructEntries(data: Buffer, format: string): StructEntry[] {
  const entries: StructEntry[] = []
  if (format === 'capn-proto') {
    const offset = scanForBytes(data, Buffer.from([0x00, 0x00, 0x00, 0x00]), 0, 256)
    if (offset !== -1 && offset + 8 <= data.length) {
      entries.push({
        offset,
        type_hint: 'segment-table',
        size: 8,
        label: 'capnp-header',
      })
    }
  } else if (format === 'flatbuffers') {
    if (data.length >= 4) {
      entries.push({ offset: 0, type_hint: 'u32', size: 4, label: 'root-table-offset' })
    }
  } else if (format === 'avro') {
    const magic = Buffer.from([0x4f, 0x62, 0x6a, 0x01])
    const offset = scanForBytes(data, magic, 0, 64)
    if (offset !== -1) {
      entries.push({ offset, type_hint: 'magic', size: 4, label: 'avro-magic' })
    }
  } else if (format === 'bson') {
    if (data.length >= 5) {
      entries.push({ offset: 0, type_hint: 'i32', size: 4, label: 'document-size' })
    }
  }
  return entries.slice(0, MAX_STRUCT_ENTRIES)
}

function buildRiskSignals(
  format: string,
  strings: string[],
  detections: FormatDetection[]
): RiskSignal[] {
  const signals: RiskSignal[] = []

  if (strings.some((value) => /https?:\/\//i.test(value))) {
    signals.push(
      riskSignal(
        `${format}.url_reference`,
        'low',
        'metadata',
        `${format} payload includes URL-like strings.`,
        0.7
      )
    )
  }
  if (
    strings.some((value) =>
      /(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\|\/[A-Za-z0-9_.-]+\/|\.\.\/)/.test(value)
    )
  ) {
    signals.push(
      riskSignal(
        `${format}.path_reference`,
        'medium',
        'metadata',
        `${format} payload includes path-like strings.`,
        0.7
      )
    )
  }
  if (
    strings.some((value) =>
      /(?:api[_-]?key|secret|token|password|bearer\s+[A-Za-z0-9._-]+)/i.test(value)
    )
  ) {
    signals.push(
      riskSignal(
        `${format}.secret_like_string`,
        'high',
        'secrets',
        `${format} payload includes secret-like strings.`,
        0.8
      )
    )
  }
  if (
    format === 'protobuf' &&
    detections[0] &&
    detections[0].confidence === 'low'
  ) {
    signals.push(
      riskSignal(
        'protobuf.heuristic_only',
        'info',
        'structure',
        'Protobuf detection is heuristic; the stream may be another varint-based format.',
        0.6
      )
    )
  }
  if (format === 'avro' || format === 'thrift' || format === 'protobuf') {
    signals.push(
      riskSignal(
        `${format}.schema_dependent`,
        'info',
        'structure',
        `${format} payloads may reference external schemas or type definitions.`,
        0.5
      )
    )
  }
  return signals
}

function buildInventory(
  data: Buffer,
  opts: { filename: string; sampleId: string; size: number }
): SerializationInventory {
  const detections = detectAll(data)
  const primary = detections[0]
  const format = primary?.format ?? 'unknown'
  const strings = extractAsciiStrings(data)
  const fieldHints: FieldHint[] = format === 'protobuf' ? extractProtobufFieldHints(data) : []
  const structEntries = buildStructEntries(data, format)
  const riskSignals = buildRiskSignals(format, strings, detections)
  const confidence: Confidence =
    !primary ? 'low' : detections.some((d) => d.confidence === 'high')
      ? 'high'
      : detections.some((d) => d.confidence === 'medium')
        ? 'medium'
        : 'low'

  return {
    sample_id: opts.sampleId,
    filename: opts.filename,
    format,
    variant: primary?.variant,
    detected_by: primary?.detected_by ?? ['no-match'],
    confidence,
    size: opts.size,
    preview_size: data.length,
    sha256_preview: crypto.createHash('sha256').update(data).digest('hex'),
    detections,
    field_hints: fieldHints.slice(0, MAX_FIELDS),
    struct_entries: structEntries,
    embedded_strings: strings,
    metadata: {
      tool: TOOL_NAME,
      tool_version: TOOL_VERSION,
      detection_count: detections.length,
      field_hint_count: fieldHints.length,
      struct_entry_count: structEntries.length,
    },
    risk_signals: riskSignals,
    risk_level: riskLevel(riskSignals),
    follow_up_tools: [...SERIALIZATION_FOLLOW_UP_TOOLS],
    safety: [...SERIALIZATION_SAFETY],
  }
}

// ─── Tool definition & handler ─────────────────────────────────────────────

export const serializationInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passive identification and profiling of binary serialization formats: Protocol Buffers (wire), Cap\'n Proto, MessagePack, FlatBuffers, Thrift, Avro, CBOR, and BSON. Never deserializes into runtime objects or follows external schema references.',
  inputSchema: SerializationInventoryInputSchema,
  outputSchema: SerializationInventoryOutputSchema,
  aspects: {
    formats: [
      'protobuf',
      'capn-proto',
      'msgpack',
      'flatbuffers',
      'thrift',
      'avro',
      'cbor',
      'bson',
      'serialization',
      'binary-serialization',
    ],
    platforms: ['cross-platform', 'linux', 'windows', 'macos', 'android', 'ios', 'embedded'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'wasm'],
    execution: ['static', 'triage', 'correlation', 'workflow-plan'],
    safety: [...SERIALIZATION_SAFETY],
    capabilities: [
      'serialization-format-detection',
      'wire-format-profiling',
      'field-hint-extraction',
      'schema-risk-triage',
      'external-reference-detection',
      'workflow-routing',
    ],
    evidence: [...SERIALIZATION_EVIDENCE],
  },
  artifacts: [
    {
      type: SERIALIZATION_INVENTORY_ARTIFACT_TYPE,
      description: 'Passive serialization format inventory and field hints.',
    },
  ],
  evidence: [...SERIALIZATION_EVIDENCE].map((category) => ({
    category,
    artifactTypes: [SERIALIZATION_INVENTORY_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'serialization.inventory',
      title: 'Serialization format inventory',
      description:
        'Passively identify and profile binary serialization formats without runtime deserialization.',
      startsWith: ['serialization.inventory'],
      nextTools: [...SERIALIZATION_FOLLOW_UP_TOOLS],
      requiredArtifacts: ['sample'],
      producesArtifacts: [SERIALIZATION_INVENTORY_ARTIFACT_TYPE],
      evidence: [...SERIALIZATION_EVIDENCE],
      safety: [...SERIALIZATION_SAFETY],
    },
  ],
}

export type SerializationInventoryResult = z.infer<typeof SerializationInventorySchema>

export function createSerializationInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof SerializationInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = SerializationInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const maxRead = input.max_read_bytes ?? DEFAULT_MAX_READ_BYTES
      const handle = await fs.open(samplePath, 'r')
      try {
        const stat = await handle.stat()
        const readSize = Math.min(maxRead, stat.size)
        const data = Buffer.alloc(readSize)
        await handle.read(data, 0, readSize, 0)
        const inventory = buildInventory(data, {
          filename: path.basename(samplePath),
          sampleId: input.sample_id,
          size: stat.size,
        })

        const artifacts: ArtifactRef[] = []
        if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
          try {
            const artifact = await persistStaticAnalysisJsonArtifact(
              workspaceManager,
              database,
              input.sample_id,
              SERIALIZATION_INVENTORY_ARTIFACT_TYPE,
              'serialization',
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
      } finally {
        await handle.close()
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
