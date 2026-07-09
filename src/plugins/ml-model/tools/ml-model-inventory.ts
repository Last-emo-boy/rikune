/**
 * ml.model.inventory - passive ML model artifact inventory.
 *
 * The tool never calls pickle.load, torch.load, numpy.load, ONNX Runtime,
 * TensorFlow, TFLite delegates, or any inference runtime. It reads bounded
 * bytes and summarizes format metadata, tensor declarations, and loader risks.
 */

import crypto from 'crypto'
import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'ml.model.inventory'
export const ML_MODEL_INVENTORY_ARTIFACT_TYPE = 'ml_model_inventory'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 64 * 1024 * 1024
const MAX_TENSORS = 512
const MAX_ARCHIVE_ENTRIES = 1200
const MAX_STRINGS = 120
const MAX_PROTO_FIELDS = 25000
const MAX_PICKLE_OPCODES = 25000
const SAFETENSORS_MAX_HEADER_BYTES = 100 * 1024 * 1024

const ML_MODEL_EVIDENCE = ['structure', 'metadata', 'strings', 'workflow', 'provenance']
const ML_MODEL_SAFETY = [
  'passive',
  'no_deserialization',
  'no_model_load',
  'no_inference',
  'no_ml_framework_load',
  'no_network_by_default',
  'no_mutation',
  'no_extract_to_execution_path',
]
const ML_MODEL_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

type Confidence = 'low' | 'medium' | 'high'
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

interface RiskSignal {
  id: string
  severity: Severity
  category: string
  evidence: string
  confidence: number
}

interface ZipEntry {
  path: string
  compression_method: number
  compressed_size: number
  uncompressed_size: number
  local_header_offset: number
  data_offset: number
  risk_flags: string[]
}

interface TensorPreview {
  name: string
  dtype?: string
  shape?: number[]
  declared_bytes?: number
  data_offsets?: [number, number]
  quantization_type?: string
}

const MlModelPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_deserialize: z.literal(true),
  no_model_load: z.literal(true),
  no_inference: z.literal(true),
  no_ml_framework_load: z.literal(true),
  no_network: z.literal(true),
  no_extract_to_disk: z.literal(true),
  no_tensor_payload_parse: z.literal(true),
  no_mutation: z.literal(true),
})

const MlModelInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  sha256_preview: z.string(),
  file_profile: z.record(z.string(), z.any()),
  inventory: z.record(z.string(), z.any()),
  metadata: z.record(z.string(), z.any()),
  structure: z.record(z.string(), z.any()),
  pickle_profile: z.record(z.string(), z.any()),
  risk_signals: z.array(z.record(z.string(), z.any())),
  risk_summary: z.record(z.string(), z.any()),
  policy: MlModelPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
})

export const MlModelInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive ML model artifact inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist ML model inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const MlModelInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: MlModelInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const mlModelInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory ML model artifacts (SafeTensors, GGUF/GGML, ONNX, TFLite, PyTorch/pickle checkpoints, NumPy NPY/NPZ) without deserializing, loading frameworks, running inference, extracting payloads, or using network access.',
  inputSchema: MlModelInventoryInputSchema,
  outputSchema: MlModelInventoryOutputSchema,
  aspects: {
    formats: [
      'ml-model',
      'ai-model',
      'safetensors',
      'gguf',
      'ggml',
      'onnx',
      'tflite',
      'pytorch-checkpoint',
      'torch',
      'pickle',
      'npy',
      'npz',
    ],
    platforms: ['cross-platform', 'linux', 'windows', 'macos'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'gpu'],
    execution: ['static', 'triage', 'correlation', 'workflow-plan'],
    safety: ML_MODEL_SAFETY,
    capabilities: [
      'ml-model-inventory',
      'tensor-metadata',
      'model-supply-chain',
      'pickle-risk-triage',
      'external-reference-detection',
      'workflow-routing',
    ],
    evidence: ML_MODEL_EVIDENCE,
  },
  artifacts: [
    {
      type: ML_MODEL_INVENTORY_ARTIFACT_TYPE,
      description:
        'Passive ML model artifact format, tensor, metadata, archive, and unsafe loader risk profile',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [ML_MODEL_INVENTORY_ARTIFACT_TYPE] },
    { category: 'metadata', artifactTypes: [ML_MODEL_INVENTORY_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [ML_MODEL_INVENTORY_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [ML_MODEL_INVENTORY_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [ML_MODEL_INVENTORY_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'ml.model-static-inventory',
      title: 'Passive ML model artifact inventory',
      description:
        'Inventory ML model containers, tensors, metadata, unsafe loader signals, external references, and prompt/template strings before routing to static strings, evidence graph, YARA, config carving, or reporting.',
      startsWith: [TOOL_NAME],
      nextTools: [
        ...ML_MODEL_FOLLOW_UP_TOOLS,
        'strings.extract',
        'static.config.carver',
        'yara.scan',
        'container.structure.analyze',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [ML_MODEL_INVENTORY_ARTIFACT_TYPE],
      evidence: ML_MODEL_EVIDENCE,
      safety: ML_MODEL_SAFETY,
    },
  ],
}

export type MlModelInventory = z.infer<typeof MlModelInventorySchema>

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (base.endsWith('.safetensors.index.json')) return 'safetensors.index.json'
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

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

function redactString(value: string): string {
  const trimmed = value.replace(/\s+/g, ' ').trim()
  if (/bearer\s+[A-Za-z0-9._-]+/i.test(trimmed)) return '[redacted-bearer-token]'
  if (/(?:api[_-]?key|secret|token|password)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}/i.test(trimmed)) {
    return '[redacted-secret]'
  }
  if (trimmed.length > 160) return `${trimmed.slice(0, 157)}...`
  return trimmed
}

function stringRiskSignals(strings: string[], source: string): RiskSignal[] {
  const signals: RiskSignal[] = []
  if (strings.some((value) => /https?:\/\//i.test(value))) {
    signals.push(
      riskSignal(
        `${source}.url_reference`,
        'low',
        'metadata',
        `${source} includes URL-like metadata.`
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
        `${source}.path_reference`,
        'medium',
        'metadata',
        `${source} includes path-like metadata.`
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
        `${source}.secret_like_string`,
        'high',
        'secrets',
        `${source} includes secret-like metadata.`
      )
    )
  }
  if (
    strings.some((value) => /(?:system prompt|chat_template|tool_calls|function_call)/i.test(value))
  ) {
    signals.push(
      riskSignal(
        `${source}.prompt_template`,
        'medium',
        'prompt-template',
        `${source} includes prompt/template-like text.`
      )
    )
  }
  return signals
}

function dtypeByteSize(dtype?: string): number | null {
  if (!dtype) return null
  const normalized = dtype.toUpperCase().replace(/[<>=|]/g, '')
  if (normalized === 'BOOL' || normalized === 'B1' || normalized === 'I1' || normalized === 'U1')
    return 1
  if (normalized === 'F16' || normalized === 'BF16' || normalized === 'I16' || normalized === 'U16')
    return 2
  if (normalized === 'F32' || normalized === 'I32' || normalized === 'U32') return 4
  if (normalized === 'F64' || normalized === 'I64' || normalized === 'U64' || normalized === 'C64')
    return 8
  const match = normalized.match(/[A-Z]+([0-9]+)/)
  if (!match) return null
  const parsed = Number.parseInt(match[1], 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null
}

function shapeElements(shape?: number[]): number | null {
  if (!shape || shape.length === 0) return null
  let total = 1
  for (const dim of shape) {
    if (!Number.isSafeInteger(dim) || dim < 0) return null
    total *= dim
    if (!Number.isSafeInteger(total)) return null
  }
  return total
}

function declaredBytes(dtype?: string, shape?: number[]): number | undefined {
  const elements = shapeElements(shape)
  const bytes = dtypeByteSize(dtype)
  if (elements === null || bytes === null) return undefined
  const total = elements * bytes
  return Number.isSafeInteger(total) ? total : undefined
}

function countBy(values: Array<string | undefined>): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const value of values) {
    if (!value) continue
    counts[value] = (counts[value] ?? 0) + 1
  }
  return counts
}

function isZip(data: Buffer): boolean {
  return data.length >= 4 && data.readUInt32LE(0) === 0x04034b50
}

function zipRiskFlags(
  entryPath: string,
  uncompressedSize: number,
  compressedSize: number
): string[] {
  const normalized = entryPath.replace(/\\/g, '/')
  const flags: string[] = []
  if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) flags.push('absolute-path')
  if (normalized.split('/').includes('..')) flags.push('path-traversal')
  if (compressedSize > 0 && uncompressedSize / compressedSize >= 100)
    flags.push('high-compression-ratio')
  if (uncompressedSize >= 512 * 1024 * 1024) flags.push('large-uncompressed-entry')
  return flags
}

function parseZipLocalEntries(data: Buffer): { entries: ZipEntry[]; truncated: boolean } {
  const entries: ZipEntry[] = []
  let offset = 0
  while (offset + 30 <= data.length && entries.length < MAX_ARCHIVE_ENTRIES) {
    if (data.readUInt32LE(offset) !== 0x04034b50) {
      offset += 1
      continue
    }
    const compressionMethod = data.readUInt16LE(offset + 8)
    const compressedSize = data.readUInt32LE(offset + 18)
    const uncompressedSize = data.readUInt32LE(offset + 22)
    const nameLength = data.readUInt16LE(offset + 26)
    const extraLength = data.readUInt16LE(offset + 28)
    const nameStart = offset + 30
    const nameEnd = nameStart + nameLength
    if (nameEnd > data.length) break
    const entryPath = data.subarray(nameStart, nameEnd).toString('utf8')
    const dataOffset = nameEnd + extraLength
    entries.push({
      path: entryPath,
      compression_method: compressionMethod,
      compressed_size: compressedSize,
      uncompressed_size: uncompressedSize,
      local_header_offset: offset,
      data_offset: dataOffset,
      risk_flags: zipRiskFlags(entryPath, uncompressedSize, compressedSize),
    })
    const nextOffset = dataOffset + compressedSize
    offset = nextOffset > offset && nextOffset <= data.length ? nextOffset : dataOffset
  }
  return { entries, truncated: entries.length >= MAX_ARCHIVE_ENTRIES }
}

function zipEntryData(data: Buffer, entry: ZipEntry): Buffer | undefined {
  if (entry.compression_method !== 0) return undefined
  const end = entry.data_offset + entry.compressed_size
  if (entry.data_offset < 0 || end > data.length) return undefined
  return data.subarray(entry.data_offset, end)
}

function parseNpyHeader(data: Buffer): Record<string, unknown> | null {
  if (data.length < 10 || data[0] !== 0x93 || data.subarray(1, 6).toString('ascii') !== 'NUMPY') {
    return null
  }
  const major = data[6]
  const minor = data[7]
  const headerLength = major <= 1 ? data.readUInt16LE(8) : data.readUInt32LE(8)
  const headerStart = major <= 1 ? 10 : 12
  const headerEnd = headerStart + headerLength
  if (headerEnd > data.length) {
    return {
      format: 'npy',
      version: `${major}.${minor}`,
      decode_status: 'truncated-header',
      header_length: headerLength,
    }
  }
  const header = data.subarray(headerStart, headerEnd).toString('latin1').trim()
  const descr = header.match(/['"]descr['"]\s*:\s*['"]([^'"]+)['"]/)?.[1]
  const fortranOrder = /['"]fortran_order['"]\s*:\s*True/.test(header)
  const shapeText = header.match(/['"]shape['"]\s*:\s*\(([^)]*)\)/)?.[1] ?? ''
  const shape = shapeText
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => Number.parseInt(part, 10))
    .filter((value) => Number.isFinite(value))
  const objectDtype = Boolean(descr && /(^|[<>=|])O/.test(descr))
  return {
    format: 'npy',
    version: `${major}.${minor}`,
    decode_status: 'parsed',
    header_length: headerLength,
    descr,
    fortran_order: fortranOrder,
    shape,
    object_dtype: objectDtype,
    declared_bytes: declaredBytes(descr, shape),
    header_preview: redactString(header),
  }
}

function parseSafetensors(data: Buffer, size: number): Record<string, unknown> {
  if (data.length < 8) return { decode_status: 'too-small' }
  const headerLengthBig = data.readBigUInt64LE(0)
  const headerLength =
    headerLengthBig > BigInt(Number.MAX_SAFE_INTEGER)
      ? Number.MAX_SAFE_INTEGER
      : Number(headerLengthBig)
  const signals: RiskSignal[] = []
  if (headerLength > SAFETENSORS_MAX_HEADER_BYTES) {
    signals.push(
      riskSignal(
        'safetensors.header_too_large',
        'high',
        'resource',
        'SafeTensors JSON header exceeds the 100MB format safety ceiling.'
      )
    )
  }
  if (8 + headerLength > data.length) {
    return {
      decode_status: 'truncated-header',
      header_length: headerLength,
      tensors: [],
      tensor_count: 0,
      dtype_counts: {},
      metadata: {},
      risk_signals: signals,
    }
  }

  try {
    const headerText = data.subarray(8, 8 + headerLength).toString('utf8')
    const header = JSON.parse(headerText) as Record<string, unknown>
    const tensors: TensorPreview[] = []
    const ranges: Array<{ name: string; start: number; end: number }> = []
    const metadata = (
      header.__metadata__ && typeof header.__metadata__ === 'object'
        ? (header.__metadata__ as Record<string, unknown>)
        : {}
    ) as Record<string, unknown>

    for (const [name, value] of Object.entries(header)) {
      if (name === '__metadata__') continue
      if (!value || typeof value !== 'object' || tensors.length >= MAX_TENSORS) continue
      const tensor = value as Record<string, unknown>
      const shape = Array.isArray(tensor.shape)
        ? tensor.shape.filter((item): item is number => Number.isSafeInteger(item))
        : undefined
      const offsets = Array.isArray(tensor.data_offsets)
        ? tensor.data_offsets.filter((item): item is number => Number.isSafeInteger(item))
        : []
      const preview: TensorPreview = {
        name,
        dtype: typeof tensor.dtype === 'string' ? tensor.dtype : undefined,
        shape,
        declared_bytes: declaredBytes(
          typeof tensor.dtype === 'string' ? tensor.dtype : undefined,
          shape
        ),
      }
      if (offsets.length >= 2) {
        preview.data_offsets = [offsets[0], offsets[1]]
        ranges.push({ name, start: offsets[0], end: offsets[1] })
        const absoluteEnd = 8 + headerLength + offsets[1]
        if (offsets[0] < 0 || offsets[1] < offsets[0] || absoluteEnd > size) {
          signals.push(
            riskSignal(
              'safetensors.offset_out_of_bounds',
              'high',
              'structure',
              `Tensor ${name} data_offsets do not fit inside the sample.`
            )
          )
        }
      }
      tensors.push(preview)
    }

    const sortedRanges = [...ranges].sort((a, b) => a.start - b.start)
    for (let index = 1; index < sortedRanges.length; index += 1) {
      if (sortedRanges[index].start < sortedRanges[index - 1].end) {
        signals.push(
          riskSignal(
            'safetensors.offset_overlap',
            'high',
            'structure',
            `Tensor ${sortedRanges[index].name} overlaps ${sortedRanges[index - 1].name}.`
          )
        )
        break
      }
    }

    const metadataStrings = Object.entries(metadata).map(
      ([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`
    )
    signals.push(...stringRiskSignals(metadataStrings, 'safetensors.metadata'))
    return {
      decode_status: 'parsed',
      header_length: headerLength,
      tensor_count: tensors.length,
      tensors,
      tensors_truncated:
        Object.keys(header).length - (header.__metadata__ ? 1 : 0) > tensors.length,
      dtype_counts: countBy(tensors.map((tensor) => tensor.dtype)),
      total_declared_bytes: tensors.reduce((sum, tensor) => sum + (tensor.declared_bytes ?? 0), 0),
      metadata: {
        keys: Object.keys(metadata),
        redacted_preview: Object.fromEntries(
          Object.entries(metadata)
            .slice(0, 24)
            .map(([key, value]) => [key, typeof value === 'string' ? redactString(value) : value])
        ),
      },
      bounds_validated: !signals.some((signal) => signal.category === 'structure'),
      risk_signals: signals,
    }
  } catch (error) {
    return {
      decode_status: 'invalid-json',
      header_length: headerLength,
      tensors: [],
      tensor_count: 0,
      dtype_counts: {},
      metadata: {},
      risk_signals: [
        riskSignal(
          'safetensors.invalid_header_json',
          'medium',
          'parser',
          `SafeTensors header JSON parse failed: ${error instanceof Error ? error.message : String(error)}`
        ),
      ],
    }
  }
}

function readU64Number(data: Buffer, offset: number): number | null {
  if (offset + 8 > data.length) return null
  const value = data.readBigUInt64LE(offset)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) return Number.MAX_SAFE_INTEGER
  return Number(value)
}

function readGgufString(data: Buffer, cursor: number): { value: string; next: number } | null {
  const length = readU64Number(data, cursor)
  if (length === null || length < 0 || length > 1024 * 1024) return null
  const start = cursor + 8
  const end = start + length
  if (end > data.length) return null
  return { value: data.subarray(start, end).toString('utf8'), next: end }
}

function parseGgufValue(
  data: Buffer,
  cursor: number,
  valueType: number,
  depth = 0
): { value: unknown; next: number } | null {
  if (cursor > data.length || depth > 2) return null
  switch (valueType) {
    case 0:
    case 1:
      if (cursor + 1 > data.length) return null
      return { value: data[cursor], next: cursor + 1 }
    case 2:
    case 3:
      if (cursor + 2 > data.length) return null
      return { value: data.readUInt16LE(cursor), next: cursor + 2 }
    case 4:
    case 5:
      if (cursor + 4 > data.length) return null
      return { value: data.readUInt32LE(cursor), next: cursor + 4 }
    case 6:
      if (cursor + 4 > data.length) return null
      return { value: data.readFloatLE(cursor), next: cursor + 4 }
    case 7:
      if (cursor + 1 > data.length) return null
      return { value: data[cursor] !== 0, next: cursor + 1 }
    case 8:
      return readGgufString(data, cursor)
    case 9: {
      if (cursor + 12 > data.length) return null
      const elementType = data.readUInt32LE(cursor)
      const length = readU64Number(data, cursor + 4)
      if (length === null || length > 256)
        return { value: { array_type: elementType, length }, next: cursor + 12 }
      let next = cursor + 12
      const values: unknown[] = []
      for (let i = 0; i < length; i += 1) {
        const item = parseGgufValue(data, next, elementType, depth + 1)
        if (!item) return null
        values.push(item.value)
        next = item.next
      }
      return { value: values, next }
    }
    case 10:
    case 11: {
      const value = readU64Number(data, cursor)
      return value === null ? null : { value, next: cursor + 8 }
    }
    case 12:
      if (cursor + 8 > data.length) return null
      return { value: data.readDoubleLE(cursor), next: cursor + 8 }
    default:
      return null
  }
}

const GGUF_QUANT_TYPES: Record<number, string> = {
  0: 'F32',
  1: 'F16',
  2: 'Q4_0',
  3: 'Q4_1',
  6: 'Q5_0',
  7: 'Q5_1',
  8: 'Q8_0',
  10: 'Q2_K',
  11: 'Q3_K',
  12: 'Q4_K',
  13: 'Q5_K',
  14: 'Q6_K',
  15: 'Q8_K',
  28: 'IQ2_XXS',
  30: 'IQ3_XXS',
}

function parseGguf(data: Buffer): Record<string, unknown> {
  if (data.length < 24 || data.subarray(0, 4).toString('ascii') !== 'GGUF') {
    return { decode_status: 'not-gguf' }
  }
  const version = data.readUInt32LE(4)
  const tensorCount = readU64Number(data, 8) ?? 0
  const metadataCount = readU64Number(data, 16) ?? 0
  let cursor = 24
  const metadata: Record<string, unknown> = {}
  const signals: RiskSignal[] = []

  for (let index = 0; index < metadataCount && index < 256; index += 1) {
    const key = readGgufString(data, cursor)
    if (!key || key.next + 4 > data.length) {
      signals.push(
        riskSignal('gguf.metadata_truncated', 'medium', 'parser', 'GGUF metadata is truncated.')
      )
      break
    }
    const valueType = data.readUInt32LE(key.next)
    const parsed = parseGgufValue(data, key.next + 4, valueType)
    if (!parsed) {
      signals.push(
        riskSignal(
          'gguf.metadata_value_unsupported',
          'low',
          'parser',
          `GGUF metadata value ${key.value} could not be parsed.`
        )
      )
      break
    }
    metadata[key.value] = parsed.value
    cursor = parsed.next
  }

  const tensors: TensorPreview[] = []
  for (let index = 0; index < tensorCount && index < MAX_TENSORS; index += 1) {
    const name = readGgufString(data, cursor)
    if (!name || name.next + 4 > data.length) {
      signals.push(
        riskSignal(
          'gguf.tensor_directory_truncated',
          'medium',
          'parser',
          'GGUF tensor directory is truncated.'
        )
      )
      break
    }
    cursor = name.next
    const dimensionsCount = data.readUInt32LE(cursor)
    cursor += 4
    const shape: number[] = []
    for (let dim = 0; dim < dimensionsCount && dim < 16; dim += 1) {
      const value = readU64Number(data, cursor)
      if (value === null) break
      shape.push(value)
      cursor += 8
    }
    if (cursor + 12 > data.length) break
    const quantType = data.readUInt32LE(cursor)
    const offset = readU64Number(data, cursor + 4)
    cursor += 12
    tensors.push({
      name: name.value,
      dtype: GGUF_QUANT_TYPES[quantType] ?? `GGML_TYPE_${quantType}`,
      shape,
      quantization_type: GGUF_QUANT_TYPES[quantType] ?? `GGML_TYPE_${quantType}`,
      data_offsets: typeof offset === 'number' ? [offset, offset] : undefined,
    })
  }

  const metadataStrings = Object.entries(metadata).map(([key, value]) => `${key}=${String(value)}`)
  signals.push(...stringRiskSignals(metadataStrings, 'gguf.metadata'))
  return {
    decode_status: 'parsed',
    version,
    tensor_count: tensorCount,
    metadata_kv_count: metadataCount,
    metadata_preview: Object.fromEntries(
      Object.entries(metadata)
        .slice(0, 64)
        .map(([key, value]) => [key, typeof value === 'string' ? redactString(value) : value])
    ),
    tensors,
    tensors_truncated: tensorCount > tensors.length,
    dtype_counts: countBy(tensors.map((tensor) => tensor.dtype)),
    risk_signals: signals,
  }
}

interface ProtoCursorResult {
  value: number
  next: number
}

function readVarint(data: Buffer, cursor: number, limit: number): ProtoCursorResult | null {
  let value = 0
  let shift = 0
  let next = cursor
  while (next < limit && shift <= 56) {
    const byte = data[next]
    value += (byte & 0x7f) * 2 ** shift
    next += 1
    if ((byte & 0x80) === 0) return { value, next }
    shift += 7
  }
  return null
}

function skipProtoField(
  data: Buffer,
  cursor: number,
  limit: number,
  wireType: number
): number | null {
  if (wireType === 0) return readVarint(data, cursor, limit)?.next ?? null
  if (wireType === 1) return cursor + 8 <= limit ? cursor + 8 : null
  if (wireType === 2) {
    const length = readVarint(data, cursor, limit)
    if (!length) return null
    const next = length.next + length.value
    return next <= limit ? next : null
  }
  if (wireType === 5) return cursor + 4 <= limit ? cursor + 4 : null
  return null
}

function readProtoString(
  data: Buffer,
  cursor: number,
  limit: number
): { value: string; next: number } | null {
  const length = readVarint(data, cursor, limit)
  if (!length || length.value > 1024 * 1024) return null
  const end = length.next + length.value
  if (end > limit) return null
  return { value: data.subarray(length.next, end).toString('utf8'), next: end }
}

function forEachProtoField(
  data: Buffer,
  start: number,
  end: number,
  visitor: (field: number, wireType: number, valueStart: number, fieldEnd: number) => void
) {
  let cursor = start
  let steps = 0
  while (cursor < end && steps < MAX_PROTO_FIELDS) {
    const tag = readVarint(data, cursor, end)
    if (!tag || tag.value === 0) break
    const field = tag.value >>> 3
    const wireType = tag.value & 0x7
    const fieldEnd = skipProtoField(data, tag.next, end, wireType)
    if (fieldEnd === null) break
    visitor(field, wireType, tag.next, fieldEnd)
    cursor = fieldEnd
    steps += 1
  }
}

function parseStringPair(data: Buffer, start: number, end: number): Record<string, string> {
  const pair: Record<string, string> = {}
  forEachProtoField(data, start, end, (field, wireType, valueStart) => {
    if (wireType !== 2) return
    const value = readProtoString(data, valueStart, end)?.value
    if (value === undefined) return
    if (field === 1) pair.key = value
    if (field === 2) pair.value = value
  })
  return pair
}

function parseOnnxOperatorSet(data: Buffer, start: number, end: number): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  forEachProtoField(data, start, end, (field, wireType, valueStart) => {
    if (field === 1 && wireType === 2)
      result.domain = readProtoString(data, valueStart, end)?.value ?? ''
    if (field === 2 && wireType === 0) result.version = readVarint(data, valueStart, end)?.value
  })
  return result
}

function parseOnnxTensor(data: Buffer, start: number, end: number): Record<string, unknown> {
  const tensor: Record<string, unknown> = { dims: [], external_data: [] }
  forEachProtoField(data, start, end, (field, wireType, valueStart, fieldEnd) => {
    if (field === 1 && wireType === 0)
      (tensor.dims as number[]).push(readVarint(data, valueStart, end)?.value ?? 0)
    if (field === 2 && wireType === 0) tensor.data_type = readVarint(data, valueStart, end)?.value
    if (field === 8 && wireType === 2) tensor.name = readProtoString(data, valueStart, end)?.value
    if (field === 9 && wireType === 2) tensor.raw_data_bytes = fieldEnd - valueStart
    if (field === 13 && wireType === 2) {
      const length = readVarint(data, valueStart, end)
      if (length)
        (tensor.external_data as unknown[]).push(
          parseStringPair(data, length.next, length.next + length.value)
        )
    }
  })
  return tensor
}

function parseOnnxValueInfo(data: Buffer, start: number, end: number): Record<string, unknown> {
  const valueInfo: Record<string, unknown> = {}
  forEachProtoField(data, start, end, (field, wireType, valueStart) => {
    if (field === 1 && wireType === 2)
      valueInfo.name = readProtoString(data, valueStart, end)?.value
  })
  return valueInfo
}

function parseOnnxNode(data: Buffer, start: number, end: number): Record<string, unknown> {
  const node: Record<string, unknown> = { inputs: [], outputs: [] }
  forEachProtoField(data, start, end, (field, wireType, valueStart) => {
    if (wireType !== 2) return
    const value = readProtoString(data, valueStart, end)?.value
    if (value === undefined) return
    if (field === 1) (node.inputs as string[]).push(value)
    if (field === 2) (node.outputs as string[]).push(value)
    if (field === 3) node.name = value
    if (field === 4) node.op_type = value
    if (field === 7) node.domain = value
  })
  return node
}

function parseOnnxGraph(data: Buffer, start: number, end: number): Record<string, unknown> {
  const nodes: Record<string, unknown>[] = []
  const initializers: Record<string, unknown>[] = []
  const inputs: Record<string, unknown>[] = []
  const outputs: Record<string, unknown>[] = []
  const graph: Record<string, unknown> = {}
  forEachProtoField(data, start, end, (field, wireType, valueStart) => {
    if (field === 2 && wireType === 2) graph.name = readProtoString(data, valueStart, end)?.value
    if (wireType !== 2) return
    const length = readVarint(data, valueStart, end)
    if (!length) return
    const msgStart = length.next
    const msgEnd = msgStart + length.value
    if (field === 1 && nodes.length < 256) nodes.push(parseOnnxNode(data, msgStart, msgEnd))
    if (field === 5 && initializers.length < 256)
      initializers.push(parseOnnxTensor(data, msgStart, msgEnd))
    if (field === 11 && inputs.length < 128) inputs.push(parseOnnxValueInfo(data, msgStart, msgEnd))
    if (field === 12 && outputs.length < 128)
      outputs.push(parseOnnxValueInfo(data, msgStart, msgEnd))
  })
  return {
    ...graph,
    node_count: nodes.length,
    op_type_counts: countBy(
      nodes.map((node) => (typeof node.op_type === 'string' ? node.op_type : undefined))
    ),
    custom_domains: unique(
      nodes
        .map((node) => (typeof node.domain === 'string' ? node.domain : ''))
        .filter((domain) => domain.length > 0 && domain !== 'ai.onnx' && domain !== 'ai.onnx.ml')
    ),
    node_preview: nodes.slice(0, 32),
    initializer_count: initializers.length,
    initializer_preview: initializers.slice(0, 32),
    inputs: inputs.map((item) => item.name).filter(Boolean),
    outputs: outputs.map((item) => item.name).filter(Boolean),
    external_data: initializers.flatMap((item) =>
      Array.isArray(item.external_data) ? item.external_data : []
    ),
  }
}

function parseOnnx(data: Buffer): Record<string, unknown> {
  const model: Record<string, unknown> = { opsets: [], metadata_props: [] }
  let graph: Record<string, unknown> = {}
  forEachProtoField(data, 0, data.length, (field, wireType, valueStart) => {
    if (field === 1 && wireType === 0)
      model.ir_version = readVarint(data, valueStart, data.length)?.value
    if ([2, 3, 4, 6].includes(field) && wireType === 2) {
      const value = readProtoString(data, valueStart, data.length)?.value
      if (field === 2) model.producer_name = value
      if (field === 3) model.producer_version = value
      if (field === 4) model.domain = value
      if (field === 6) model.doc_string = value ? redactString(value) : value
    }
    if (field === 5 && wireType === 0)
      model.model_version = readVarint(data, valueStart, data.length)?.value
    if (field === 8 && wireType === 2) {
      const length = readVarint(data, valueStart, data.length)
      if (length)
        (model.opsets as unknown[]).push(
          parseOnnxOperatorSet(data, length.next, length.next + length.value)
        )
    }
    if (field === 7 && wireType === 2) {
      const length = readVarint(data, valueStart, data.length)
      if (length) graph = parseOnnxGraph(data, length.next, length.next + length.value)
    }
    if (field === 14 && wireType === 2) {
      const length = readVarint(data, valueStart, data.length)
      if (length)
        (model.metadata_props as unknown[]).push(
          parseStringPair(data, length.next, length.next + length.value)
        )
    }
  })

  const signals: RiskSignal[] = []
  const customDomains = Array.isArray(graph.custom_domains) ? graph.custom_domains : []
  if (customDomains.length > 0) {
    signals.push(
      riskSignal(
        'onnx.custom_domain',
        'medium',
        'loader',
        `ONNX graph references custom domain(s): ${customDomains.join(', ')}.`
      )
    )
  }
  const externalData = Array.isArray(graph.external_data) ? graph.external_data : []
  if (externalData.length > 0) {
    signals.push(
      riskSignal(
        'onnx.external_data_reference',
        'medium',
        'external-reference',
        'ONNX initializers reference external tensor data.'
      )
    )
  }
  signals.push(
    ...stringRiskSignals(
      [
        String(model.producer_name ?? ''),
        String(model.domain ?? ''),
        String(model.doc_string ?? ''),
        ...((model.metadata_props as Array<Record<string, string>> | undefined) ?? []).map(
          (entry) => `${entry.key ?? ''}=${entry.value ?? ''}`
        ),
        ...externalData.map((entry) => JSON.stringify(entry)),
      ],
      'onnx.metadata'
    )
  )

  return {
    decode_status:
      Object.keys(model).length > 2 || Object.keys(graph).length > 0 ? 'parsed' : 'extension-only',
    model,
    graph,
    tensor_count: typeof graph.initializer_count === 'number' ? graph.initializer_count : 0,
    risk_signals: signals,
  }
}

function parsePickle(data: Buffer): Record<string, unknown> {
  const strings: string[] = []
  const globals: string[] = []
  const dangerousGlobals: string[] = []
  const signals: RiskSignal[] = []
  let opcodeCount = 0
  let reduceCount = 0
  let buildCount = 0
  let cursor = 0

  function pushString(value: string) {
    strings.push(value.slice(0, 240))
    if (strings.length > 64) strings.shift()
  }

  while (cursor < data.length && opcodeCount < MAX_PICKLE_OPCODES) {
    const opcode = data[cursor]
    opcodeCount += 1
    cursor += 1
    if (opcode === 0x2e) break
    if (opcode === 0x80) {
      cursor += 1
      continue
    }
    if (opcode === 0x63) {
      const moduleEnd = data.indexOf(0x0a, cursor)
      if (moduleEnd < 0) break
      const nameEnd = data.indexOf(0x0a, moduleEnd + 1)
      if (nameEnd < 0) break
      const moduleName = data.subarray(cursor, moduleEnd).toString('utf8')
      const name = data.subarray(moduleEnd + 1, nameEnd).toString('utf8')
      globals.push(`${moduleName}.${name}`)
      cursor = nameEnd + 1
      continue
    }
    if (opcode === 0x93) {
      const name = strings.pop()
      const moduleName = strings.pop()
      if (moduleName && name) globals.push(`${moduleName}.${name}`)
      continue
    }
    if (opcode === 0x52) {
      reduceCount += 1
      continue
    }
    if (opcode === 0x62) {
      buildCount += 1
      continue
    }
    if (opcode === 0x8c && cursor < data.length) {
      const length = data[cursor]
      cursor += 1
      if (cursor + length > data.length) break
      pushString(data.subarray(cursor, cursor + length).toString('utf8'))
      cursor += length
      continue
    }
    if (opcode === 0x58 && cursor + 4 <= data.length) {
      const length = data.readUInt32LE(cursor)
      cursor += 4
      if (length > 1024 * 1024 || cursor + length > data.length) break
      pushString(data.subarray(cursor, cursor + length).toString('utf8'))
      cursor += length
      continue
    }
    if (opcode === 0x8d && cursor + 8 <= data.length) {
      const length = readU64Number(data, cursor) ?? 0
      cursor += 8
      if (length > 1024 * 1024 || cursor + length > data.length) break
      pushString(data.subarray(cursor, cursor + length).toString('utf8'))
      cursor += length
      continue
    }
  }

  for (const globalName of unique(globals)) {
    if (
      /(^|\.)(?:os|posix|nt|subprocess|socket|requests|urllib|builtins)\.(?:system|popen|eval|exec|__import__|Popen|call|run|urlopen|Request|socket)$/i.test(
        globalName
      )
    ) {
      dangerousGlobals.push(globalName)
    }
  }
  if (globals.length > 0 || reduceCount > 0) {
    signals.push(
      riskSignal(
        'pickle.serialized_code_loader',
        'high',
        'loader',
        'Pickle opcode stream can execute constructors or reducers when deserialized.'
      )
    )
  }
  if (dangerousGlobals.length > 0) {
    signals.push(
      riskSignal(
        'pickle.dangerous_global',
        'critical',
        'execution',
        `Pickle references dangerous global(s): ${dangerousGlobals.slice(0, 8).join(', ')}.`
      )
    )
  }
  return {
    opcode_count: opcodeCount,
    global_count: unique(globals).length,
    globals: unique(globals).slice(0, 80),
    dangerous_globals: dangerousGlobals,
    reduce_count: reduceCount,
    build_count: buildCount,
    decode_status: opcodeCount >= MAX_PICKLE_OPCODES ? 'limit-hit' : 'parsed',
    risk_signals: signals,
  }
}

function detectFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[]; confidence: Confidence } {
  const ext = extensionOf(filename)
  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'GGUF') {
    return { format: 'gguf', detectedBy: ['magic:GGUF'], confidence: 'high' }
  }
  if (data.length >= 4 && data.subarray(0, 4).toString('ascii').toLowerCase() === 'ggml') {
    return { format: 'ggml', detectedBy: ['magic:GGML'], confidence: 'high' }
  }
  if (data.length >= 8 && data[0] === 0x93 && data.subarray(1, 6).toString('ascii') === 'NUMPY') {
    return { format: 'npy', detectedBy: ['magic:NUMPY'], confidence: 'high' }
  }
  if (isZip(data)) {
    const entries = parseZipLocalEntries(data).entries.map((entry) => entry.path.toLowerCase())
    if (entries.some((entry) => entry.endsWith('data.pkl') || entry === 'archive/data.pkl')) {
      return {
        format: 'pytorch-checkpoint',
        detectedBy: ['zip magic', 'pytorch data.pkl marker'],
        confidence: 'high',
      }
    }
    if (ext === 'npz' || entries.some((entry) => entry.endsWith('.npy'))) {
      return {
        format: 'npz',
        detectedBy: ['zip magic', 'npy member'],
        confidence: ext === 'npz' ? 'high' : 'medium',
      }
    }
    return {
      format:
        ext === 'pt' || ext === 'pth' || ext === 'ckpt'
          ? 'pytorch-checkpoint'
          : 'zip-model-container',
      detectedBy: ['zip magic'],
      confidence: 'medium',
    }
  }
  if (data.length >= 8) {
    const maybeLength = readU64Number(data, 0)
    if (maybeLength !== null && maybeLength > 1 && maybeLength <= Math.max(data.length - 8, 1)) {
      const first = data[8]
      if (first === 0x7b)
        return {
          format: 'safetensors',
          detectedBy: ['safetensors header length', 'json header'],
          confidence: 'high',
        }
    }
  }
  if (data.length >= 8 && data.subarray(4, 8).toString('ascii') === 'TFL3') {
    return { format: 'tflite', detectedBy: ['flatbuffer identifier:TFL3'], confidence: 'high' }
  }
  if (data.length >= 1 && data[0] === 0x80) {
    return {
      format: ext === 'pt' || ext === 'pth' || ext === 'ckpt' ? 'pytorch-pickle' : 'pickle',
      detectedBy: ['pickle protocol magic'],
      confidence: 'high',
    }
  }
  if (ext === 'safetensors')
    return { format: 'safetensors', detectedBy: ['extension:.safetensors'], confidence: 'medium' }
  if (ext === 'gguf')
    return { format: 'gguf', detectedBy: ['extension:.gguf'], confidence: 'medium' }
  if (ext === 'ggml')
    return { format: 'ggml', detectedBy: ['extension:.ggml'], confidence: 'medium' }
  if (ext === 'onnx')
    return { format: 'onnx', detectedBy: ['extension:.onnx'], confidence: 'medium' }
  if (ext === 'tflite')
    return { format: 'tflite', detectedBy: ['extension:.tflite'], confidence: 'medium' }
  if (ext === 'npy') return { format: 'npy', detectedBy: ['extension:.npy'], confidence: 'medium' }
  if (ext === 'npz') return { format: 'npz', detectedBy: ['extension:.npz'], confidence: 'medium' }
  if (['pt', 'pth', 'ckpt'].includes(ext))
    return { format: 'pytorch-checkpoint', detectedBy: ['extension'], confidence: 'medium' }
  if (['pkl', 'pickle'].includes(ext))
    return { format: 'pickle', detectedBy: ['extension'], confidence: 'medium' }
  const strings = extractAsciiStrings(data).join('\n')
  if (/ai\.onnx|onnx|opset_import/i.test(strings)) {
    return { format: 'onnx', detectedBy: ['content:onnx-string-hint'], confidence: 'low' }
  }
  return { format: 'unknown', detectedBy: [], confidence: 'low' }
}

function analyzeArchive(data: Buffer, format: string) {
  const parsed = parseZipLocalEntries(data)
  const entries = parsed.entries
  const signals: RiskSignal[] = []
  if (parsed.truncated)
    signals.push(
      riskSignal(
        'archive.entry_limit_hit',
        'medium',
        'resource',
        'Archive member listing hit the safety limit.'
      )
    )
  if (
    entries.some(
      (entry) =>
        entry.risk_flags.includes('path-traversal') || entry.risk_flags.includes('absolute-path')
    )
  ) {
    signals.push(
      riskSignal(
        'archive.unsafe_member_path',
        'high',
        'filesystem',
        'Archive contains absolute or parent traversal paths.'
      )
    )
  }
  if (
    entries.some(
      (entry) =>
        entry.risk_flags.includes('high-compression-ratio') ||
        entry.risk_flags.includes('large-uncompressed-entry')
    )
  ) {
    signals.push(
      riskSignal(
        'archive.resource_exhaustion',
        'medium',
        'resource',
        'Archive contains high-ratio or very large members.'
      )
    )
  }

  const npyMembers: Record<string, unknown>[] = []
  let pickleProfile: Record<string, unknown> = {}
  for (const entry of entries) {
    const lower = entry.path.toLowerCase()
    const member = zipEntryData(data, entry)
    if (lower.endsWith('.npy') && member) {
      const npy = parseNpyHeader(member)
      if (npy) npyMembers.push({ path: entry.path, ...npy })
    }
    if (/(^|\/)data\.pkl$|\.pkl$|\.pickle$/i.test(lower)) {
      if (member) {
        pickleProfile = parsePickle(member)
        signals.push(...((pickleProfile.risk_signals as RiskSignal[] | undefined) ?? []))
      } else {
        signals.push(
          riskSignal(
            'pickle.member_not_stored',
            'high',
            'loader',
            `Pickle member ${entry.path} is present but compressed; not deserialized or inflated.`
          )
        )
      }
    }
  }

  if (format === 'pytorch-checkpoint') {
    signals.push(
      riskSignal(
        'pytorch.pickle_checkpoint',
        'high',
        'loader',
        'PyTorch checkpoints commonly contain pickle payloads; do not torch.load untrusted files.'
      )
    )
  }
  if (npyMembers.some((member) => member.object_dtype === true)) {
    signals.push(
      riskSignal(
        'numpy.object_dtype',
        'high',
        'loader',
        'NPY/NPZ object dtype may require pickle loading.'
      )
    )
  }

  return {
    archive: {
      format: 'zip',
      entry_count: entries.length,
      entries_truncated: parsed.truncated,
      entries: entries.slice(0, 120),
      npy_members: npyMembers,
    },
    tensor_count: npyMembers.length,
    dtype_counts: countBy(
      npyMembers.map((member) => (typeof member.descr === 'string' ? member.descr : undefined))
    ),
    pickle_profile: pickleProfile,
    risk_signals: signals,
  }
}

function buildRiskSummary(signals: RiskSignal[]) {
  const bySeverity: Record<string, number> = {}
  const byCategory: Record<string, number> = {}
  for (const signal of signals) {
    bySeverity[signal.severity] = (bySeverity[signal.severity] ?? 0) + 1
    byCategory[signal.category] = (byCategory[signal.category] ?? 0) + 1
  }
  return {
    level: riskLevel(signals),
    count: signals.length,
    signal_ids: signals.map((signal) => signal.id),
    by_severity: bySeverity,
    by_category: byCategory,
  }
}

function buildEvidenceSummary(input: {
  sampleId?: string
  filename?: string
  format: string
  confidence: Confidence
  tensorCount: number
  signals: RiskSignal[]
}) {
  return {
    schema: 'rikune.ml_model_inventory.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: input.sampleId ?? null,
    filename: input.filename ?? null,
    artifact_type: ML_MODEL_INVENTORY_ARTIFACT_TYPE,
    format: input.format,
    confidence: input.confidence,
    route_terms: [
      'ml-model',
      'ai-model',
      'model-artifact',
      'safetensors',
      'onnx',
      'gguf',
      'tflite',
      'pytorch',
      'pickle',
      'numpy',
    ],
    evidence_categories: ML_MODEL_EVIDENCE,
    counts: {
      tensors: input.tensorCount,
      risk_signals: input.signals.length,
    },
    static_only: true,
  }
}

function buildWorkflowHandoff(input: {
  sampleId?: string
  format: string
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.ml_model_inventory.workflow_handoff.v1',
    handoff_mode: 'ml_model_artifact_to_static_supply_chain_and_loader_risk_triage',
    source_tool: TOOL_NAME,
    sample_id: input.sampleId ?? null,
    artifact_type: ML_MODEL_INVENTORY_ARTIFACT_TYPE,
    format: input.format,
    recommended_next_tools: input.recommendedNextTools,
    routing: [
      {
        goal: 'unsafe-loader-risk-review',
        priority: ['pickle', 'pytorch-pickle', 'pytorch-checkpoint'].includes(input.format)
          ? 'high'
          : 'normal',
        next_tools: [
          'strings.extract',
          'yara.scan',
          'static.config.carver',
          'analysis.evidence.graph',
        ],
        required_evidence: ['risk_signals', 'pickle_profile', ML_MODEL_INVENTORY_ARTIFACT_TYPE],
      },
      {
        goal: 'metadata-secret-and-template-review',
        priority: 'normal',
        next_tools: ['strings.extract', 'static.config.carver', 'report.generate'],
        required_evidence: ['metadata', 'redacted_strings'],
      },
      {
        goal: 'supply-chain-correlation',
        priority: 'normal',
        next_tools: ['metadata.extract', 'analysis.evidence.graph', 'report.generate'],
        required_evidence: ['format', 'producer', 'external_references'],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      model_loaded_by_tool: false,
      deserialized_by_tool: false,
      inference_started_by_tool: false,
      ml_framework_loaded_by_tool: false,
      archive_extracted_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

export function buildMlModelInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; sampleId?: string; size?: number } = {}
): MlModelInventory {
  const detected = detectFormat(data, options.filename)
  const strings = extractAsciiStrings(data)
  const redactedStrings = strings.map(redactString).slice(0, 64)
  const signals: RiskSignal[] = []
  let inventory: Record<string, unknown> = {
    tensor_count: 0,
    dtype_counts: {},
    total_declared_bytes: 0,
    tensor_preview: [],
  }
  let metadata: Record<string, unknown> = { redacted_strings: redactedStrings }
  let structure: Record<string, unknown> = {}
  let pickleProfile: Record<string, unknown> = {}

  if (detected.format === 'safetensors') {
    const parsed = parseSafetensors(data, options.size ?? data.length)
    signals.push(...((parsed.risk_signals as RiskSignal[] | undefined) ?? []))
    const tensors = (parsed.tensors as TensorPreview[] | undefined) ?? []
    inventory = {
      tensor_count: parsed.tensor_count ?? 0,
      dtype_counts: parsed.dtype_counts ?? {},
      total_declared_bytes: parsed.total_declared_bytes ?? 0,
      tensor_preview: tensors.slice(0, 80),
      tensors_truncated: parsed.tensors_truncated ?? false,
    }
    metadata = { ...metadata, ...(parsed.metadata as Record<string, unknown> | undefined) }
    structure = {
      safetensors: {
        decode_status: parsed.decode_status,
        header_length: parsed.header_length,
        bounds_validated: parsed.bounds_validated ?? false,
      },
    }
  } else if (detected.format === 'gguf') {
    const parsed = parseGguf(data)
    signals.push(...((parsed.risk_signals as RiskSignal[] | undefined) ?? []))
    const tensors = (parsed.tensors as TensorPreview[] | undefined) ?? []
    inventory = {
      tensor_count: parsed.tensor_count ?? 0,
      dtype_counts: parsed.dtype_counts ?? {},
      tensor_preview: tensors.slice(0, 80),
      tensors_truncated: parsed.tensors_truncated ?? false,
    }
    metadata = { ...metadata, preview: parsed.metadata_preview ?? {} }
    structure = { gguf: parsed }
  } else if (detected.format === 'npy') {
    const parsed = parseNpyHeader(data)
    if (parsed?.object_dtype)
      signals.push(
        riskSignal(
          'numpy.object_dtype',
          'high',
          'loader',
          'NPY object dtype may require pickle loading.'
        )
      )
    inventory = {
      tensor_count: parsed ? 1 : 0,
      dtype_counts: parsed?.descr ? { [String(parsed.descr)]: 1 } : {},
      total_declared_bytes: parsed?.declared_bytes ?? 0,
      tensor_preview: parsed
        ? [
            {
              name: path.basename(options.filename ?? 'array.npy'),
              dtype: parsed.descr,
              shape: parsed.shape,
              declared_bytes: parsed.declared_bytes,
            },
          ]
        : [],
    }
    structure = { npy: parsed ?? { decode_status: 'not-npy' } }
  } else if (
    detected.format === 'npz' ||
    detected.format === 'pytorch-checkpoint' ||
    detected.format === 'zip-model-container'
  ) {
    const parsed = analyzeArchive(data, detected.format)
    signals.push(...((parsed.risk_signals as RiskSignal[] | undefined) ?? []))
    inventory = {
      tensor_count: parsed.tensor_count,
      dtype_counts: parsed.dtype_counts,
      total_declared_bytes: (parsed.archive.npy_members as Record<string, unknown>[]).reduce(
        (sum, member) =>
          sum + (typeof member.declared_bytes === 'number' ? member.declared_bytes : 0),
        0
      ),
      tensor_preview: parsed.archive.npy_members.slice(0, 80),
    }
    structure = { archive: parsed.archive }
    pickleProfile = parsed.pickle_profile
  } else if (detected.format === 'pickle' || detected.format === 'pytorch-pickle') {
    pickleProfile = parsePickle(data)
    signals.push(...((pickleProfile.risk_signals as RiskSignal[] | undefined) ?? []))
    signals.push(
      riskSignal(
        'pickle.raw_model_artifact',
        'high',
        'loader',
        'Raw pickle model artifacts must not be loaded outside isolation.'
      )
    )
  } else if (detected.format === 'onnx') {
    const parsed = parseOnnx(data)
    signals.push(...((parsed.risk_signals as RiskSignal[] | undefined) ?? []))
    inventory = {
      tensor_count: parsed.tensor_count ?? 0,
      dtype_counts: {},
      total_declared_bytes: 0,
      tensor_preview:
        ((parsed.graph as Record<string, unknown> | undefined)?.initializer_preview as unknown[]) ??
        [],
    }
    metadata = { ...metadata, ...((parsed.model as Record<string, unknown> | undefined) ?? {}) }
    structure = { onnx: parsed }
  } else if (detected.format === 'tflite') {
    const identifier = data.length >= 8 ? data.subarray(4, 8).toString('ascii') : ''
    if (identifier !== 'TFL3') {
      signals.push(
        riskSignal(
          'tflite.extension_only_unverified',
          'low',
          'format',
          'TFLite classification relies on extension fallback.'
        )
      )
    }
    if (strings.some((value) => /\bCUSTOM\b|custom_code|delegate/i.test(value))) {
      signals.push(
        riskSignal(
          'tflite.custom_operator_hint',
          'medium',
          'loader',
          'TFLite preview includes custom operator or delegate hints.'
        )
      )
    }
    structure = {
      tflite: {
        decode_status: identifier === 'TFL3' ? 'identifier-valid' : 'extension-only',
        flatbuffer_identifier: identifier || null,
        root_table_offset: data.length >= 4 ? data.readUInt32LE(0) : null,
      },
    }
  } else if (detected.format === 'ggml') {
    structure = {
      ggml: {
        decode_status: 'legacy-magic-or-extension',
        note: 'Legacy GGML parsing is best-effort in this passive tool.',
      },
    }
    signals.push(
      riskSignal(
        'ggml.legacy_format',
        'low',
        'format',
        'GGML is a legacy model container; metadata is limited.'
      )
    )
  } else {
    signals.push(
      riskSignal(
        'ml_model.unknown_format',
        'medium',
        'format',
        'No supported ML model artifact signature was detected.'
      )
    )
  }

  if (detected.confidence !== 'high') {
    signals.push(
      riskSignal(
        'format.extension_or_hint_only',
        'low',
        'format',
        `Format confidence is ${detected.confidence}; classification may rely on filename extension or weak hints.`
      )
    )
  }
  signals.push(...stringRiskSignals(strings, 'preview.strings'))

  const dedupedSignals = Array.from(new Map(signals.map((signal) => [signal.id, signal])).values())
  const recommendedNextTools = unique([
    ...ML_MODEL_FOLLOW_UP_TOOLS,
    dedupedSignals.some(
      (signal) => signal.id.startsWith('pickle.') || signal.id.startsWith('pytorch.')
    )
      ? 'yara.scan'
      : '',
    dedupedSignals.some((signal) =>
      ['secrets', 'metadata', 'prompt-template'].includes(signal.category)
    )
      ? 'static.config.carver'
      : '',
    detected.format === 'zip-model-container' ||
    detected.format === 'npz' ||
    detected.format === 'pytorch-checkpoint'
      ? 'container.structure.analyze'
      : '',
  ])
  const riskSummary = buildRiskSummary(dedupedSignals)
  const tensorCount = typeof inventory.tensor_count === 'number' ? inventory.tensor_count : 0

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: detected.detectedBy,
    confidence: detected.confidence,
    size: options.size ?? data.length,
    preview_size: data.length,
    sha256_preview: crypto.createHash('sha256').update(data).digest('hex'),
    file_profile: {
      extension: extensionOf(options.filename),
      route_terms: ['ml-model', detected.format, ...detected.detectedBy],
      strings_truncated: strings.length >= MAX_STRINGS,
    },
    inventory,
    metadata,
    structure,
    pickle_profile: pickleProfile,
    risk_signals: dedupedSignals,
    risk_summary: riskSummary,
    policy: {
      passive: true,
      no_execute: true,
      no_deserialize: true,
      no_model_load: true,
      no_inference: true,
      no_ml_framework_load: true,
      no_network: true,
      no_extract_to_disk: true,
      no_tensor_payload_parse: true,
      no_mutation: true,
    },
    summary: `Passive ML model inventory detected ${detected.format} (${detected.confidence}) with ${tensorCount} tensor/member hint(s), risk=${riskSummary.level}.`,
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review risk signals before loading the model in any framework or notebook.',
      'Do not use pickle.load, torch.load, numpy.load with allow_pickle, or inference runtimes on untrusted model artifacts.',
      'Use static strings, YARA, and evidence graph tooling for loader-risk and supply-chain correlation first.',
    ],
    evidence_summary: buildEvidenceSummary({
      sampleId: options.sampleId,
      filename: options.filename,
      format: detected.format,
      confidence: detected.confidence,
      tensorCount,
      signals: dedupedSignals,
    }),
    workflow_handoff: buildWorkflowHandoff({
      sampleId: options.sampleId,
      format: detected.format,
      recommendedNextTools,
    }),
    quality_gates: {
      schema: 'rikune.ml_model_inventory.quality_gates.v1',
      passive_static_inventory: true,
      format_identified: detected.format !== 'unknown',
      bounds_validated: !dedupedSignals.some((signal) => signal.category === 'structure'),
      analyst_review_required: ['medium', 'high', 'critical'].includes(String(riskSummary.level)),
      sample_executed_by_tool: false,
      model_loaded_by_tool: false,
      deserialized_by_tool: false,
      inference_started_by_tool: false,
      ml_framework_loaded_by_tool: false,
      archive_extracted_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
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

export function createMlModelInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof MlModelInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = MlModelInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildMlModelInventoryFromBuffer(data, {
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
            ML_MODEL_INVENTORY_ARTIFACT_TYPE,
            'ml-model',
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
