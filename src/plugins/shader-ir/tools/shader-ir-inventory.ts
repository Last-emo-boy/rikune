/**
 * shader.ir.inventory - passive shader IR and GPU program inventory.
 *
 * This tool reads a bounded local preview only. It never invokes spirv-val,
 * spirv-dis, dxc, dxil.dll, Metal tooling, WebGPU runtimes, GPU drivers, or
 * samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

export const SHADER_IR_INVENTORY_ARTIFACT_TYPE = 'shader_ir_inventory'

const TOOL_NAME = 'shader.ir.inventory'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 240
const MAX_SPIRV_INSTRUCTIONS = 4000
const MAX_DX_PARTS = 96

const SHADER_IR_EVIDENCE_SUMMARY_SCHEMA = 'rikune.shader_ir_inventory.evidence_summary.v1'
const SHADER_IR_WORKFLOW_HANDOFF_SCHEMA = 'rikune.shader_ir_inventory.workflow_handoff.v1'
const SHADER_IR_QUALITY_GATES_SCHEMA = 'rikune.shader_ir_inventory.quality_gates.v1'

const SHADER_IR_POLICY = {
  passive: true,
  no_execute: true,
  no_gpu_driver: true,
  no_gpu_access: true,
  no_shader_compiler: true,
  no_validator: true,
  no_disassembler: true,
  no_external_tool: true,
  no_runtime: true,
  no_network: true,
  no_mutation: true,
} as const

const SHADER_IR_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'strings.extract',
  'metadata.extract',
  'llvm.bitcode.inventory',
  'cuda.binary.inventory',
  'culifter.gpu.plan',
  'native.object.inventory',
  'sbom.provenance.graph',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const SPIRV_MAGIC = 0x07230203
const DXBC_MAGIC = 'DXBC'

const SPIRV_CAPABILITY_NAMES: Record<number, string> = {
  0: 'Matrix',
  1: 'Shader',
  2: 'Geometry',
  3: 'Tessellation',
  6: 'Kernel',
  17: 'Addresses',
  18: 'Linkage',
  31: 'Groups',
  35: 'AtomicStorage',
  39: 'Int64',
  41: 'Int16',
  42: 'TessellationPointSize',
  49: 'Float16',
  53: 'ImageQuery',
  61: 'StorageImageExtendedFormats',
  4422: 'RayTracingKHR',
  5301: 'MeshShadingNV',
  6022: 'RayQueryKHR',
}

const SPIRV_EXECUTION_MODELS: Record<number, string> = {
  0: 'Vertex',
  1: 'TessellationControl',
  2: 'TessellationEvaluation',
  3: 'Geometry',
  4: 'Fragment',
  5: 'GLCompute',
  6: 'Kernel',
  5313: 'TaskNV',
  5314: 'MeshNV',
  5364: 'RayGenerationKHR',
  5365: 'IntersectionKHR',
  5366: 'AnyHitKHR',
  5367: 'ClosestHitKHR',
  5368: 'MissKHR',
  5369: 'CallableKHR',
}

const SPIRV_SOURCE_LANGUAGES: Record<number, string> = {
  0: 'Unknown',
  1: 'ESSL',
  2: 'GLSL',
  3: 'OpenCL_C',
  4: 'OpenCL_CPP',
  5: 'HLSL',
  6: 'CPP_for_OpenCL',
  7: 'SYCL',
  8: 'HERO_C',
  9: 'NZSL',
  10: 'WGSL',
}

const SPIRV_MEMORY_MODELS: Record<number, string> = {
  0: 'Simple',
  1: 'GLSL450',
  2: 'OpenCL',
  3: 'Vulkan',
}

const SPIRV_ADDRESSING_MODELS: Record<number, string> = {
  0: 'Logical',
  1: 'Physical32',
  2: 'Physical64',
  5348: 'PhysicalStorageBuffer64',
}

const SPIRV_EXECUTION_MODES: Record<number, string> = {
  7: 'OriginUpperLeft',
  8: 'OriginLowerLeft',
  17: 'LocalSize',
  18: 'LocalSizeHint',
  19: 'InputPoints',
  20: 'InputLines',
  21: 'InputLinesAdjacency',
  22: 'Triangles',
  23: 'InputTrianglesAdjacency',
  24: 'Quads',
  26: 'OutputVertices',
  30: 'OutputPoints',
  31: 'OutputLineStrip',
  32: 'OutputTriangleStrip',
  35: 'EarlyFragmentTests',
  4421: 'StencilRefReplacingEXT',
}

const SPIRV_DECORATIONS: Record<number, string> = {
  30: 'Location',
  33: 'Binding',
  34: 'DescriptorSet',
  35: 'Offset',
  36: 'XfbBuffer',
  37: 'XfbStride',
  43: 'BuiltIn',
  44: 'NoPerspective',
  45: 'Flat',
  46: 'Patch',
  47: 'Centroid',
  48: 'Sample',
}

const DX_PART_HINTS: Record<string, string> = {
  DXIL: 'DXIL LLVM-derived shader IR',
  SHDR: 'DXBC shader bytecode',
  SHEX: 'DXBC extended shader bytecode',
  ISGN: 'input signature',
  OSGN: 'output signature',
  OSG5: 'output signature',
  PCSG: 'patch constant signature',
  RDEF: 'resource definition',
  STAT: 'shader statistics',
  PSV0: 'pipeline state validation',
  HASH: 'shader hash',
  ILDB: 'DXIL debug data',
  ILDN: 'DXIL debug name',
  RDAT: 'runtime data',
  RTS0: 'root signature',
  SFI0: 'shader feature info',
}

const ShaderIrPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_gpu_driver: z.literal(true),
  no_gpu_access: z.literal(true),
  no_shader_compiler: z.literal(true),
  no_validator: z.literal(true),
  no_disassembler: z.literal(true),
  no_external_tool: z.literal(true),
  no_runtime: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const ShaderIrInventorySchema = z.object({
  schema: z.literal('rikune.shader_ir_inventory.v1'),
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  size: z.number().optional(),
  preview_size: z.number(),
  format: z.enum([
    'spir-v',
    'dxil-container',
    'dxbc-container',
    'dxcontainer',
    'wgsl-source',
    'metal-metallib',
    'unknown-shader-hints',
  ]),
  is_shader_candidate: z.boolean(),
  confidence: z.number().min(0).max(1),
  detected_by: z.array(z.string()),
  structure: z.record(z.any()),
  shader_stages: z.array(z.string()),
  entry_points: z.array(z.record(z.any())),
  resource_hints: z.array(z.record(z.any())),
  embedded_strings: z.record(z.any()),
  risk_flags: z.array(z.record(z.any())),
  risk_summary: z.record(z.any()),
  policy: ShaderIrPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const ShaderIrInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive shader IR inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist shader IR inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const ShaderIrInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: ShaderIrInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const shaderIrInventoryAspects = {
  formats: [
    'shader-ir',
    'spir-v',
    'spv',
    'dxil',
    'dxbc',
    'dxcontainer',
    'wgsl',
    'metal-metallib',
    'metallib',
  ],
  platforms: ['vulkan', 'directx', 'webgpu', 'metal', 'gpu', 'cross-platform'],
  execution: ['static', 'triage', 'workflow-handoff'],
  safety: [
    'passive',
    'no_execute',
    'no_gpu_driver',
    'no_gpu_access',
    'no_shader_compiler',
    'no_validator',
    'no_disassembler',
    'no_external_tool',
    'no_network_by_default',
    'no_mutation',
  ],
  capabilities: [
    'shader-ir-inventory',
    'spirv-header-summary',
    'spirv-entrypoint-reflection',
    'dxcontainer-part-inventory',
    'dxil-dxbc-routing',
    'wgsl-source-profile',
    'metal-library-detection',
    'gpu-program-triage',
    'workflow-routing',
  ],
  evidence: ['structure', 'metadata', 'strings', 'resources', 'workflow', 'provenance'],
  route_terms: [
    'shader',
    'shader-ir',
    'spir-v',
    'spv',
    'vulkan',
    'dxil',
    'dxbc',
    'directx',
    'wgsl',
    'webgpu',
    'metal',
  ],
  search: [
    'shader ir inventory',
    'spir-v reflection',
    'dxil container',
    'dxbc shader',
    'wgsl webgpu',
    'metal library',
  ],
}

export const shaderIrInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory SPIR-V, DXIL/DXBC containers, WGSL source, and Metal shader libraries without running validators, compilers, disassemblers, GPU drivers, or samples.',
  inputSchema: ShaderIrInventoryInputSchema,
  outputSchema: ShaderIrInventoryOutputSchema,
  aspects: shaderIrInventoryAspects,
  artifacts: [
    {
      type: SHADER_IR_INVENTORY_ARTIFACT_TYPE,
      description: 'Passive shader IR structure, entry point, resource, and routing inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [SHADER_IR_INVENTORY_ARTIFACT_TYPE] },
    { category: 'metadata', artifactTypes: [SHADER_IR_INVENTORY_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [SHADER_IR_INVENTORY_ARTIFACT_TYPE] },
    { category: 'resources', artifactTypes: [SHADER_IR_INVENTORY_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [SHADER_IR_INVENTORY_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [SHADER_IR_INVENTORY_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'shader.ir-static-inventory',
      title: 'Shader IR static inventory',
      description:
        'Inventory SPIR-V, DXIL/DXBC containers, WGSL source, and Metal library hints before routing to strings, GPU lift planning, LLVM bitcode, native-object, SBOM, or evidence graph tools.',
      startsWith: [TOOL_NAME],
      nextTools: [
        'artifact.read',
        'strings.extract',
        'metadata.extract',
        'llvm.bitcode.inventory',
        'cuda.binary.inventory',
        'culifter.gpu.plan',
        'native.object.inventory',
        'sbom.provenance.graph',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [SHADER_IR_INVENTORY_ARTIFACT_TYPE],
      evidence: ['structure', 'metadata', 'strings', 'resources', 'workflow', 'provenance'],
      safety: [
        'passive',
        'no_gpu_driver',
        'no_gpu_access',
        'no_shader_compiler',
        'no_validator',
        'no_disassembler',
        'no_external_tool',
        'no_live_sample_by_default',
        'no_network_by_default',
      ],
    },
  ],
}

export type ShaderIrInventory = z.infer<typeof ShaderIrInventorySchema>

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)))
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key]
  return typeof value === 'string' ? value : ''
}

function boundedText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 2 * 1024 * 1024)).toString('latin1')
}

function extractAsciiStrings(data: Buffer): string[] {
  return unique(boundedText(data).match(/[\x20-\x7e]{4,}/g) ?? []).slice(0, MAX_STRINGS)
}

function stringFromWords(words: number[], startIndex: number): string {
  const bytes: number[] = []
  for (let i = startIndex; i < words.length; i++) {
    const word = words[i]
    for (let shift = 0; shift < 32; shift += 8) {
      const value = (word >>> shift) & 0xff
      if (value === 0) {
        return Buffer.from(bytes)
          .toString('utf8')
          .replace(/[^\x20-\x7e]/g, '')
          .trim()
      }
      bytes.push(value)
    }
  }
  return Buffer.from(bytes)
    .toString('utf8')
    .replace(/[^\x20-\x7e]/g, '')
    .trim()
}

function spirvVersion(versionWord: number): string {
  const major = (versionWord >>> 16) & 0xff
  const minor = (versionWord >>> 8) & 0xff
  return `${major}.${minor}`
}

function readWord(data: Buffer, offset: number, endian: 'le' | 'be'): number {
  return endian === 'le' ? data.readUInt32LE(offset) : data.readUInt32BE(offset)
}

function parseSpirv(data: Buffer) {
  const magicLe = data.length >= 4 ? data.readUInt32LE(0) : 0
  const magicBe = data.length >= 4 ? data.readUInt32BE(0) : 0
  if (magicLe !== SPIRV_MAGIC && magicBe !== SPIRV_MAGIC) {
    return null
  }

  const endian: 'le' | 'be' = magicLe === SPIRV_MAGIC ? 'le' : 'be'
  const warnings: string[] = []
  const wordCount = Math.floor(data.length / 4)
  const read = (index: number) => readWord(data, index * 4, endian)
  const versionWord = wordCount >= 2 ? read(1) : 0
  const generator = wordCount >= 3 ? read(2) : 0
  const bound = wordCount >= 4 ? read(3) : 0
  const schema = wordCount >= 5 ? read(4) : 0
  const opCounts = new Map<number, number>()
  const capabilities: string[] = []
  const extensions: string[] = []
  const extInstImports: string[] = []
  const entryPoints: Array<Record<string, unknown>> = []
  const executionModesByEntry = new Map<number, string[]>()
  const resourceHints: Array<Record<string, unknown>> = []
  const names = new Map<number, string>()
  let sourceLanguage: string | undefined
  let sourceVersion: number | undefined
  let memoryModel: string | undefined
  let addressingModel: string | undefined
  let instructionCount = 0
  let cursor = 5

  while (cursor < wordCount && instructionCount < MAX_SPIRV_INSTRUCTIONS) {
    const instruction = read(cursor)
    const opcode = instruction & 0xffff
    const wordsInInstruction = instruction >>> 16
    if (wordsInInstruction === 0 || cursor + wordsInInstruction > wordCount) {
      warnings.push(`Invalid SPIR-V instruction length at word ${cursor}.`)
      break
    }
    const operands: number[] = []
    for (let i = 1; i < wordsInInstruction; i++) operands.push(read(cursor + i))
    opCounts.set(opcode, (opCounts.get(opcode) ?? 0) + 1)

    if (opcode === 3 && operands.length >= 2) {
      sourceLanguage = SPIRV_SOURCE_LANGUAGES[operands[0]] ?? `SourceLanguage_${operands[0]}`
      sourceVersion = operands[1]
    } else if (opcode === 5 && operands.length >= 2) {
      names.set(operands[0], stringFromWords(operands, 1))
    } else if (opcode === 10) {
      extensions.push(stringFromWords(operands, 0))
    } else if (opcode === 11 && operands.length >= 2) {
      extInstImports.push(stringFromWords(operands, 1))
    } else if (opcode === 14 && operands.length >= 2) {
      addressingModel = SPIRV_ADDRESSING_MODELS[operands[0]] ?? `AddressingModel_${operands[0]}`
      memoryModel = SPIRV_MEMORY_MODELS[operands[1]] ?? `MemoryModel_${operands[1]}`
    } else if (opcode === 15 && operands.length >= 3) {
      const executionModel = SPIRV_EXECUTION_MODELS[operands[0]] ?? `ExecutionModel_${operands[0]}`
      const entryId = operands[1]
      entryPoints.push({
        format: 'spir-v',
        stage: executionModel,
        id: entryId,
        name: stringFromWords(operands, 2),
        interface_id_count: Math.max(0, operands.length - 3),
      })
    } else if (opcode === 16 && operands.length >= 2) {
      const current = executionModesByEntry.get(operands[0]) ?? []
      current.push(SPIRV_EXECUTION_MODES[operands[1]] ?? `ExecutionMode_${operands[1]}`)
      executionModesByEntry.set(operands[0], unique(current))
    } else if (opcode === 17 && operands.length >= 1) {
      capabilities.push(SPIRV_CAPABILITY_NAMES[operands[0]] ?? `Capability_${operands[0]}`)
    } else if (opcode === 71 && operands.length >= 2) {
      resourceHints.push({
        format: 'spir-v',
        target_id: operands[0],
        target_name: names.get(operands[0]),
        decoration: SPIRV_DECORATIONS[operands[1]] ?? `Decoration_${operands[1]}`,
        values: operands.slice(2),
      })
    }

    instructionCount += 1
    cursor += wordsInInstruction
  }

  if (instructionCount >= MAX_SPIRV_INSTRUCTIONS && cursor < wordCount) {
    warnings.push('SPIR-V instruction scan limit reached.')
  }

  const entryPointsWithModes = entryPoints.map((entry) => ({
    ...entry,
    execution_modes: executionModesByEntry.get(Number(entry.id)) ?? [],
  }))

  return {
    kind: 'spir-v',
    endian,
    magic: '0x07230203',
    version: spirvVersion(versionWord),
    generator,
    bound,
    schema,
    word_count: wordCount,
    instruction_count: instructionCount,
    scan_truncated: instructionCount >= MAX_SPIRV_INSTRUCTIONS && cursor < wordCount,
    capabilities: unique(capabilities),
    extensions: unique(extensions),
    ext_inst_imports: unique(extInstImports),
    source: {
      language: sourceLanguage,
      version: sourceVersion,
    },
    memory_model: memoryModel,
    addressing_model: addressingModel,
    opcode_counts: Object.fromEntries(
      Array.from(opCounts.entries())
        .sort(([left], [right]) => left - right)
        .slice(0, 120)
        .map(([opcode, count]) => [`Op_${opcode}`, count])
    ),
    warnings: unique(warnings),
    entry_points: entryPointsWithModes,
    resource_hints: resourceHints.slice(0, 200),
  }
}

function parseDxContainer(data: Buffer) {
  if (data.length < 32 || data.subarray(0, 4).toString('ascii') !== DXBC_MAGIC) return null
  const warnings: string[] = []
  const declaredSize = data.readUInt32LE(24)
  const partCount = data.readUInt32LE(28)
  const parts: Array<Record<string, unknown>> = []
  if (partCount > MAX_DX_PARTS) {
    warnings.push(`DXContainer part count ${partCount} exceeds scan limit ${MAX_DX_PARTS}.`)
  }
  const offsetTableEnd = 32 + Math.min(partCount, MAX_DX_PARTS) * 4
  if (offsetTableEnd > data.length) warnings.push('DXContainer offset table exceeds preview size.')

  for (let i = 0; i < Math.min(partCount, MAX_DX_PARTS); i++) {
    const offsetPosition = 32 + i * 4
    if (offsetPosition + 4 > data.length) break
    const offset = data.readUInt32LE(offsetPosition)
    if (offset + 8 > data.length) {
      parts.push({
        index: i,
        offset,
        bounds_valid: false,
      })
      continue
    }
    const fourcc = data.subarray(offset, offset + 4).toString('ascii')
    const size = data.readUInt32LE(offset + 4)
    const end = offset + 8 + size
    parts.push({
      index: i,
      fourcc,
      meaning: DX_PART_HINTS[fourcc] ?? 'unknown part',
      offset,
      size,
      bounds_valid: end <= data.length,
      preview: data.subarray(offset + 8, Math.min(end, offset + 72, data.length)).toString('hex'),
    })
    if (end > data.length) warnings.push(`DXContainer part ${fourcc} exceeds preview bounds.`)
  }

  const fourccs = unique(parts.map((part) => stringField(part, 'fourcc')).filter(Boolean))
  const format = fourccs.includes('DXIL')
    ? 'dxil-container'
    : fourccs.some((part) => part === 'SHDR' || part === 'SHEX')
      ? 'dxbc-container'
      : 'dxcontainer'

  return {
    kind: 'dxcontainer',
    magic: DXBC_MAGIC,
    declared_size: declaredSize,
    declared_part_count: partCount,
    scanned_part_count: parts.length,
    declared_size_within_preview: declaredSize <= data.length,
    parts,
    part_fourccs: fourccs,
    contains_dxil: fourccs.includes('DXIL'),
    contains_dxbc_bytecode: fourccs.some((part) => part === 'SHDR' || part === 'SHEX'),
    contains_signatures: fourccs.some((part) => ['ISGN', 'OSGN', 'OSG5', 'PCSG'].includes(part)),
    contains_debug_data: fourccs.some((part) => ['ILDB', 'ILDN'].includes(part)),
    warnings: unique(warnings),
    inferred_format: format,
  }
}

function parseWgsl(text: string) {
  if (!/@(?:vertex|fragment|compute)|\bfn\s+[A-Za-z_][A-Za-z0-9_]*|var<|@group\(/.test(text)) {
    return null
  }
  const entryPoints: Array<Record<string, unknown>> = []
  const resourceHints: Array<Record<string, unknown>> = []
  for (const match of text.matchAll(/\bfn\s+([A-Za-z_][A-Za-z0-9_]*)/g)) {
    const prefix = text.slice(Math.max(0, (match.index ?? 0) - 240), match.index)
    const stages = Array.from(prefix.matchAll(/@(vertex|fragment|compute)\b/g))
    const stage = stages.at(-1)?.[1]
    if (!stage) continue
    entryPoints.push({
      format: 'wgsl',
      stage,
      name: match[1],
    })
  }
  for (const match of text.matchAll(
    /@group\((?<group>\d+)\)\s+@binding\((?<binding>\d+)\)\s+var(?:<(?<space>[^>]+)>)?\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)/g
  )) {
    resourceHints.push({
      format: 'wgsl',
      group: Number.parseInt(match.groups?.group ?? '0', 10),
      binding: Number.parseInt(match.groups?.binding ?? '0', 10),
      address_space: match.groups?.space,
      name: match.groups?.name,
    })
  }
  return {
    kind: 'wgsl-source',
    entry_points: entryPoints,
    resource_hints: resourceHints,
    stages: unique(entryPoints.map((entry) => stringField(entry, 'stage'))),
    has_structs: /\bstruct\s+[A-Za-z_][A-Za-z0-9_]*/.test(text),
    has_overrides: /\boverride\s+[A-Za-z_][A-Za-z0-9_]*/.test(text),
    has_workgroup_memory: /var<workgroup>/.test(text),
    function_count: (text.match(/\bfn\s+[A-Za-z_][A-Za-z0-9_]*/g) ?? []).length,
  }
}

function parseMetalLibrary(data: Buffer, extension: string, strings: string[]) {
  const magic = data.length >= 4 ? data.subarray(0, 4).toString('ascii') : ''
  const hasMagic = ['MTLB', 'MTLL', 'AIR\x00'].includes(magic)
  const hasExtension = extension === 'metallib'
  const hasStringHints = strings.some((value) => /metallib|air\.|metal/i.test(value))
  if (!hasMagic && !hasExtension && !hasStringHints) return null
  return {
    kind: 'metal-metallib',
    magic: hasMagic ? magic.replace(/\x00/g, '\\0') : null,
    detected_by_extension: hasExtension,
    string_hints: strings.filter((value) => /metallib|air\.|metal/i.test(value)).slice(0, 40),
    note: 'Metal library format is treated as a passive container hint; no xcrun, metal, metallib, or GPU runtime was invoked.',
  }
}

function classify(input: {
  data: Buffer
  filename?: string
  spirv: ReturnType<typeof parseSpirv>
  dx: ReturnType<typeof parseDxContainer>
  wgsl: ReturnType<typeof parseWgsl>
  metal: ReturnType<typeof parseMetalLibrary>
  strings: string[]
}) {
  const extension = extensionOf(input.filename)
  const detectedBy: string[] = []
  let score = 0

  if (input.spirv) {
    detectedBy.push('magic:spir-v')
    score += 0.8
  }
  if (['spv', 'spirv'].includes(extension)) {
    detectedBy.push(`extension:.${extension}`)
    score += 0.2
  }
  if (input.dx) {
    detectedBy.push('magic:DXBC-container')
    score += 0.75
  }
  if (['dxil', 'dxbc', 'cso'].includes(extension)) {
    detectedBy.push(`extension:.${extension}`)
    score += 0.2
  }
  if (input.wgsl) {
    detectedBy.push('content:wgsl-syntax')
    score += 0.55
  }
  if (extension === 'wgsl') {
    detectedBy.push('extension:.wgsl')
    score += 0.25
  }
  if (input.metal) {
    detectedBy.push(input.metal.magic ? 'magic:metal-library' : 'content:metal-library-hint')
    score += input.metal.magic ? 0.6 : 0.3
  }
  if (extension === 'metallib') {
    detectedBy.push('extension:.metallib')
    score += 0.25
  }

  const stringHints = input.strings.filter((value) =>
    /spir-v|spv|dxil|dxbc|hlsl|glsl|wgsl|webgpu|vulkan|directx|metallib|msl|shader/i.test(value)
  )
  if (stringHints.length > 0) {
    detectedBy.push('string:shader-ir-hints')
    score += 0.15
  }

  const format =
    input.spirv !== null
      ? 'spir-v'
      : input.dx?.inferred_format
        ? input.dx.inferred_format
        : input.wgsl !== null
          ? 'wgsl-source'
          : input.metal !== null
            ? 'metal-metallib'
            : 'unknown-shader-hints'

  return {
    format: format as ShaderIrInventory['format'],
    detectedBy: unique(detectedBy),
    confidence: Math.max(0, Math.min(1, Number(score.toFixed(2)))),
    stringHints,
  }
}

function riskFlag(id: string, severity: string, category: string, evidence: string) {
  return { id, severity, category, evidence }
}

function riskLevel(flags: Array<Record<string, unknown>>) {
  if (flags.some((flag) => flag.severity === 'high')) return 'high'
  if (flags.some((flag) => flag.severity === 'medium')) return 'medium'
  if (flags.length > 0) return 'low'
  return 'none'
}

function buildRiskFlags(input: {
  format: ShaderIrInventory['format']
  confidence: number
  spirv: ReturnType<typeof parseSpirv>
  dx: ReturnType<typeof parseDxContainer>
  wgsl: ReturnType<typeof parseWgsl>
  metal: ReturnType<typeof parseMetalLibrary>
}) {
  const flags: Array<Record<string, unknown>> = []
  if (input.confidence < 0.5) {
    flags.push(
      riskFlag(
        'weak-shader-classification',
        'medium',
        'format',
        'Shader classification relies on weak extension or string evidence.'
      )
    )
  }
  if (input.spirv?.warnings.length) {
    flags.push(
      riskFlag(
        'spirv-parser-warning',
        'medium',
        'structure',
        input.spirv.warnings.slice(0, 3).join('; ')
      )
    )
  }
  if (input.spirv?.scan_truncated) {
    flags.push(
      riskFlag(
        'spirv-scan-limit',
        'low',
        'parser',
        'SPIR-V instruction scan reached the bounded parser limit.'
      )
    )
  }
  if (input.dx && input.dx.declared_size_within_preview === false) {
    flags.push(
      riskFlag(
        'dxcontainer-size-outside-preview',
        'medium',
        'structure',
        'DXContainer declared size exceeds the bounded preview.'
      )
    )
  }
  if (input.dx?.parts.some((part) => part.bounds_valid === false)) {
    flags.push(
      riskFlag(
        'dxcontainer-part-bounds-invalid',
        'high',
        'structure',
        'At least one DXContainer part offset or size is outside the bounded preview.'
      )
    )
  }
  if (input.dx?.contains_debug_data) {
    flags.push(
      riskFlag(
        'shader-debug-data-present',
        'low',
        'privacy',
        'DirectX shader container advertises debug data parts.'
      )
    )
  }
  if (input.wgsl && input.wgsl.entry_points.length === 0) {
    flags.push(
      riskFlag(
        'wgsl-no-entrypoint',
        'low',
        'source',
        'WGSL-like source was detected but no @vertex/@fragment/@compute entry point was found.'
      )
    )
  }
  if (input.metal && input.format === 'metal-metallib') {
    flags.push(
      riskFlag(
        'metal-format-best-effort',
        'low',
        'format',
        'Metal library support is best-effort static detection without private format execution.'
      )
    )
  }
  return flags
}

function recommendedNextTools(format: ShaderIrInventory['format']) {
  const tools = ['artifact.read', 'strings.extract', 'metadata.extract', 'analysis.evidence.graph']
  if (format === 'dxil-container') {
    tools.push('llvm.bitcode.inventory', 'native.object.inventory')
  }
  if (format === 'spir-v' || format === 'dxil-container' || format === 'dxbc-container') {
    tools.push('culifter.gpu.plan')
  }
  if (format !== 'unknown-shader-hints') {
    tools.push('sbom.provenance.graph', 'report.generate', 'workflow.search')
  }
  return unique(tools).filter((tool) => SHADER_IR_FOLLOW_UP_TOOLS.includes(tool))
}

function buildEnvelope(input: {
  inventoryBase: Omit<ShaderIrInventory, 'evidence_summary' | 'workflow_handoff' | 'quality_gates'>
}) {
  const inventory = input.inventoryBase
  return {
    evidence_summary: {
      schema: SHADER_IR_EVIDENCE_SUMMARY_SCHEMA,
      source_tool: TOOL_NAME,
      sample_id: inventory.sample_id,
      filename: inventory.filename,
      artifact_type: SHADER_IR_INVENTORY_ARTIFACT_TYPE,
      format: inventory.format,
      confidence: inventory.confidence,
      route_terms: shaderIrInventoryAspects.route_terms,
      evidence_categories: shaderIrInventoryAspects.evidence,
      counts: {
        entry_points: inventory.entry_points.length,
        shader_stages: inventory.shader_stages.length,
        resource_hints: inventory.resource_hints.length,
        embedded_strings: inventory.embedded_strings.ascii_count ?? 0,
        risk_flags: inventory.risk_flags.length,
      },
      static_only: true,
    },
    workflow_handoff: {
      schema: SHADER_IR_WORKFLOW_HANDOFF_SCHEMA,
      handoff_mode: 'shader_ir_inventory_to_gpu_and_ir_correlation',
      source_tool: TOOL_NAME,
      sample_id: inventory.sample_id,
      artifact_type: SHADER_IR_INVENTORY_ARTIFACT_TYPE,
      format: inventory.format,
      recommended_next_tools: inventory.recommended_next_tools,
      artifact_contract: {
        consumes: ['sample'],
        produces: [SHADER_IR_INVENTORY_ARTIFACT_TYPE],
        mime: 'application/json',
        expected_consumers: inventory.recommended_next_tools,
      },
      dynamic_boundary: {
        sample_execution_allowed: false,
        gpu_driver_allowed: false,
        gpu_access_allowed: false,
        shader_compiler_allowed: false,
        validator_allowed: false,
        disassembler_allowed: false,
        external_tool_allowed: false,
        runtime_allowed: false,
        network_allowed: false,
        mutation_allowed: false,
      },
      routing: [
        {
          goal: 'shader-structure-and-resource-triage',
          next_tools: ['strings.extract', 'metadata.extract', 'analysis.evidence.graph'],
          conditions: ['shader candidate evidence present'],
        },
        {
          goal: 'dxil-llvm-correlation',
          next_tools: ['llvm.bitcode.inventory', 'native.object.inventory'],
          conditions: ['DXIL part detected in DirectX shader container'],
        },
        {
          goal: 'gpu-lift-planning',
          next_tools: ['culifter.gpu.plan'],
          conditions: ['SPIR-V, DXIL, or DXBC shader program detected'],
        },
      ],
    },
    quality_gates: {
      schema: SHADER_IR_QUALITY_GATES_SCHEMA,
      passive_static_inventory: true,
      bounded_preview_only: true,
      shader_candidate_detected: inventory.is_shader_candidate,
      entry_points_present: inventory.entry_points.length > 0,
      resource_hints_present: inventory.resource_hints.length > 0,
      sample_executed_by_tool: false,
      gpu_driver_used_by_tool: false,
      gpu_accessed_by_tool: false,
      shader_compiler_invoked_by_tool: false,
      validator_invoked_by_tool: false,
      disassembler_invoked_by_tool: false,
      external_tool_started_by_tool: false,
      runtime_started_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
  }
}

export function buildShaderIrInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): ShaderIrInventory {
  const extension = extensionOf(options.filename)
  const strings = extractAsciiStrings(data)
  const text = boundedText(data)
  const spirv = parseSpirv(data)
  const dx = parseDxContainer(data)
  const wgsl = parseWgsl(text)
  const metal = parseMetalLibrary(data, extension, strings)
  const detected = classify({
    data,
    filename: options.filename,
    spirv,
    dx,
    wgsl,
    metal,
    strings,
  })
  const riskFlags = buildRiskFlags({
    format: detected.format,
    confidence: detected.confidence,
    spirv,
    dx,
    wgsl,
    metal,
  })
  const nextTools = recommendedNextTools(detected.format)
  const entryPoints: Array<Record<string, unknown>> = [
    ...(spirv?.entry_points ?? []),
    ...(wgsl?.entry_points ?? []),
  ]
  const resourceHints = [...(spirv?.resource_hints ?? []), ...(wgsl?.resource_hints ?? [])]
  const shaderStages = unique(entryPoints.map((entry) => stringField(entry, 'stage')))
  const structure = {
    spirv,
    dxcontainer: dx,
    wgsl,
    metal,
  }
  const riskSummary = {
    risk_level: riskLevel(riskFlags),
    flags: riskFlags.map((flag) => flag.id),
    count: riskFlags.length,
  }

  const inventoryBase: Omit<
    ShaderIrInventory,
    'evidence_summary' | 'workflow_handoff' | 'quality_gates'
  > = {
    schema: 'rikune.shader_ir_inventory.v1',
    sample_id: options.sampleId,
    filename: options.filename,
    size: options.size ?? data.length,
    preview_size: data.length,
    format: detected.format,
    is_shader_candidate: detected.confidence >= 0.45,
    confidence: detected.confidence,
    detected_by: detected.detectedBy,
    structure,
    shader_stages: shaderStages,
    entry_points: entryPoints,
    resource_hints: resourceHints,
    embedded_strings: {
      ascii_count: strings.length,
      shader_hints: unique(detected.stringHints).slice(0, 80),
      preview: strings.slice(0, 80),
      truncated: strings.length >= MAX_STRINGS,
    },
    risk_flags: riskFlags,
    risk_summary: riskSummary,
    policy: SHADER_IR_POLICY,
    summary: `Passive shader IR inventory detected ${detected.format} with ${entryPoints.length} entry point(s), ${resourceHints.length} resource hint(s), and confidence ${detected.confidence}.`,
    recommended_next_tools: nextTools,
    next_actions: [
      'Review shader stage, entry point, resource binding, and container part evidence before deeper analysis.',
      'Use culifter.gpu.plan for bounded GPU lift planning before any shader disassembler, compiler, or validator is considered.',
      'Use llvm.bitcode.inventory when DXIL parts need passive LLVM-derived payload correlation.',
      'Keep SPIR-V validators, DXC, Metal tools, WebGPU runtimes, GPU drivers, and sample execution behind explicit readiness-gated follow-up work.',
    ],
  }

  return ShaderIrInventorySchema.parse({
    ...inventoryBase,
    ...buildEnvelope({ inventoryBase }),
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

export function createShaderIrInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof ShaderIrInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = ShaderIrInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildShaderIrInventoryFromBuffer(data, {
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
            SHADER_IR_INVENTORY_ARTIFACT_TYPE,
            'shader-ir-inventory',
            inventory,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Artifact persistence is best-effort for passive inventory.
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
