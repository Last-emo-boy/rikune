/**
 * cuda.binary.inventory - passive CUDA/PTX/CUBIN/fatbin inventory.
 *
 * This tool reads a bounded local preview only. It never runs cuobjdump,
 * nvdisasm, CUDA runtime APIs, GPU drivers, profilers, emulators, or samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

export const CUDA_BINARY_INVENTORY_ARTIFACT_TYPE = 'cuda_binary_inventory'
export const CUDA_KERNEL_SUMMARY_ARTIFACT_TYPE = 'cuda_kernel_summary'

const TOOL_NAME = 'cuda.binary.inventory'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024

const CUDA_EVIDENCE_SUMMARY_SCHEMA = 'rikune.cuda_binary_inventory.evidence_summary.v1'
const CUDA_WORKFLOW_HANDOFF_SCHEMA = 'rikune.cuda_binary_inventory.workflow_handoff.v1'
const CUDA_QUALITY_GATES_SCHEMA = 'rikune.cuda_binary_inventory.quality_gates.v1'

const CUDA_POLICY = {
  passive: true,
  no_execute: true,
  no_cuda_driver: true,
  no_gpu_access: true,
  no_external_tool: true,
  no_mutation: true,
  no_network: true,
} as const

const CUDA_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'strings.extract',
  'metadata.extract',
  'native.object.inventory',
  'linux.binary.inventory',
  'culifter.gpu.plan',
  'culifter.gpu.artifact.inventory',
  'sbom.provenance.graph',
  'analysis.evidence.graph',
]

const CUDA_HOST_REGISTRATION_MARKERS = [
  '__cudaRegisterFatBinary',
  '__cudaRegisterFunction',
  '__cudaRegisterVar',
  '__cudaUnregisterFatBinary',
  '__cudaFatCubin',
  '__cudaFatPtx',
  '__fatbinwrap',
  '__nv_relfatbin',
]

const CUDA_FATBIN_MARKERS = [
  '.nv_fatbin',
  '.nvFatBinSegment',
  '__cudaFatCubin',
  '__cudaFatPtx',
  '__fatbinwrap',
  '__nv_relfatbin',
  '__nv_module_id',
]

const SASS_HINT_RE =
  /\b(?:S2R|IMAD|IADD3|LDG(?:\.E)?|STG(?:\.E)?|BRA|BAR\.SYNC|SHFL|HMMA|MMA|ISETP|EXIT)\b/g

const CudaBinaryPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_cuda_driver: z.literal(true),
  no_gpu_access: z.literal(true),
  no_external_tool: z.literal(true),
  no_mutation: z.literal(true),
  no_network: z.literal(true),
})

const CudaTargetSchema = z.object({
  kind: z.enum(['sm', 'compute']),
  value: z.string(),
  source: z.string(),
})

const CudaKernelSchema = z.object({
  name: z.string(),
  sources: z.array(z.string()),
  visibility: z.string().optional(),
  target: z.string().optional(),
})

const CudaElfSummarySchema = z.object({
  is_elf: z.boolean(),
  elf_class: z.string().optional(),
  endian: z.string().optional(),
  type: z.string().optional(),
  machine: z.string().optional(),
  machine_id: z.number().optional(),
})

const CudaBinaryInventoryDataSchema = z.object({
  schema: z.literal('rikune.cuda_binary_inventory.v1'),
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  size: z.number().optional(),
  format: z.enum(['ptx', 'cubin-elf', 'cuda-fatbin', 'host-binary-cuda', 'unknown-cuda-hints']),
  is_cuda_candidate: z.boolean(),
  confidence: z.number().min(0).max(1),
  detected_by: z.array(z.string()),
  target_arches: z.array(CudaTargetSchema),
  ptx_versions: z.array(z.string()),
  address_sizes: z.array(z.number()),
  kernels: z.array(CudaKernelSchema),
  sections: z.array(z.string()),
  symbol_hints: z.array(z.string()),
  fatbin_markers: z.array(z.string()),
  host_registration_markers: z.array(z.string()),
  sass_hints: z.array(z.string()),
  elf: CudaElfSummarySchema,
  policy: CudaBinaryPolicySchema,
  risk_notes: z.array(z.string()),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z
    .object({
      schema: z.literal(CUDA_EVIDENCE_SUMMARY_SCHEMA),
      source_tool: z.literal(TOOL_NAME),
      artifact_type: z.literal(CUDA_BINARY_INVENTORY_ARTIFACT_TYPE),
    })
    .passthrough(),
  workflow_handoff: z
    .object({
      schema: z.literal(CUDA_WORKFLOW_HANDOFF_SCHEMA),
      handoff_mode: z.literal('cuda_binary_inventory_to_gpu_lift_and_host_correlation'),
      artifact_contract: z.record(z.string(), z.any()),
      dynamic_boundary: z.record(z.string(), z.any()),
      routing: z.array(z.record(z.string(), z.any())),
    })
    .passthrough(),
  quality_gates: z
    .object({
      schema: z.literal(CUDA_QUALITY_GATES_SCHEMA),
      passive_static_inventory: z.literal(true),
      bounded_preview_only: z.literal(true),
      sample_executed_by_tool: z.literal(false),
      cuda_driver_used_by_tool: z.literal(false),
      gpu_accessed_by_tool: z.literal(false),
      external_tool_started_by_tool: z.literal(false),
      mutation_performed: z.literal(false),
      network_used_by_tool: z.literal(false),
    })
    .passthrough(),
})

export const CudaBinaryInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive CUDA binary inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const CudaBinaryInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: CudaBinaryInventoryDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const cudaBinaryInventoryAspects = {
  formats: ['cuda', 'ptx', 'cubin', 'fatbin', 'cuda-fatbin', 'sass', 'elf'],
  platforms: ['cuda', 'linux', 'cross-platform', 'embedded'],
  execution: ['static', 'triage', 'workflow-handoff'],
  safety: [
    'passive',
    'no_execute',
    'no_cuda_driver',
    'no_gpu_access',
    'no_external_tool',
    'no_network_by_default',
    'no_mutation',
  ],
  capabilities: [
    'cuda-artifact-inventory',
    'ptx-directive-extraction',
    'cubin-elf-detection',
    'fatbin-host-correlation',
    'gpu-kernel-summary',
    'culifter-handoff',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'strings', 'artifact', 'workflow', 'provenance'],
  route_terms: ['cuda', 'ptx', 'cubin', 'fatbin', 'sass', 'gpu kernel'],
  search: ['cuda binary inventory', 'ptx', 'cubin', 'fatbin', 'gpu kernel'],
}

export const cudaBinaryInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory CUDA PTX, CUBIN ELF, fatbin, and host-embedded GPU artifact hints without running CUDA tools, drivers, profilers, or samples.',
  inputSchema: CudaBinaryInventoryInputSchema,
  outputSchema: CudaBinaryInventoryOutputSchema,
  aspects: cudaBinaryInventoryAspects,
  artifacts: [
    {
      type: CUDA_BINARY_INVENTORY_ARTIFACT_TYPE,
      description: 'Passive CUDA/PTX/CUBIN/fatbin inventory and routing hints',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
    {
      type: CUDA_KERNEL_SUMMARY_ARTIFACT_TYPE,
      description: 'GPU kernel, PTX target, and section summary',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [CUDA_BINARY_INVENTORY_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [CUDA_KERNEL_SUMMARY_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [CUDA_BINARY_INVENTORY_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [CUDA_BINARY_INVENTORY_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [CUDA_BINARY_INVENTORY_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'cuda.binary.static-inventory-handoff',
      title: 'CUDA binary static inventory handoff',
      description:
        'Route PTX, CUBIN ELF, fatbin, and host-embedded CUDA evidence into GPU lift planning and host/native correlation without GPU access.',
      startsWith: [TOOL_NAME],
      nextTools: [
        'culifter.gpu.plan',
        'culifter.gpu.artifact.inventory',
        'native.object.inventory',
        'linux.binary.inventory',
        'strings.extract',
        'sbom.provenance.graph',
        'analysis.evidence.graph',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [CUDA_BINARY_INVENTORY_ARTIFACT_TYPE, CUDA_KERNEL_SUMMARY_ARTIFACT_TYPE],
      evidence: ['structure', 'symbols', 'strings', 'workflow', 'provenance'],
      safety: [
        'passive',
        'no_cuda_driver',
        'no_gpu_access',
        'no_external_tool',
        'no_live_sample_by_default',
        'no_network_by_default',
      ],
    },
  ],
}

export type CudaBinaryInventory = z.infer<typeof CudaBinaryInventoryDataSchema>

type ElfSummary = z.infer<typeof CudaElfSummarySchema>
type CudaTarget = z.infer<typeof CudaTargetSchema>
type CudaKernel = z.infer<typeof CudaKernelSchema>

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)))
}

function boundedText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 2 * 1024 * 1024)).toString('latin1')
}

function extractAsciiStrings(data: Buffer): string[] {
  return unique(boundedText(data).match(/[\x20-\x7e]{4,}/g) ?? []).slice(0, 800)
}

function collectMatches(text: string, regex: RegExp, limit = 200): string[] {
  const values: string[] = []
  for (const match of text.matchAll(regex)) {
    const value = match[1] ?? match[0]
    if (value) values.push(value)
    if (values.length >= limit) break
  }
  return unique(values)
}

function readElfSummary(data: Buffer): ElfSummary {
  if (
    data.length < 20 ||
    data[0] !== 0x7f ||
    data[1] !== 0x45 ||
    data[2] !== 0x4c ||
    data[3] !== 0x46
  ) {
    return { is_elf: false }
  }

  const endian = data[5] === 2 ? 'be' : 'le'
  const readUInt16 = (offset: number) =>
    endian === 'be' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
  const typeId = readUInt16(16)
  const machineId = readUInt16(18)
  const type =
    typeId === 1
      ? 'relocatable'
      : typeId === 2
        ? 'executable'
        : typeId === 3
          ? 'shared-object'
          : typeId === 4
            ? 'core'
            : `elf-type-${typeId}`

  return {
    is_elf: true,
    elf_class: data[4] === 2 ? 'ELF64' : data[4] === 1 ? 'ELF32' : `ELFCLASS${data[4]}`,
    endian,
    type,
    machine: machineId === 190 ? 'cuda' : `elf-machine-${machineId}`,
    machine_id: machineId,
  }
}

function extractTargets(text: string): CudaTarget[] {
  const targets: CudaTarget[] = []
  for (const match of text.matchAll(/\b((?:sm|compute)_[0-9]{2,3}[a-z]?)\b/g)) {
    const target = match[1]
    const kindMatch = /^(sm|compute)_/.exec(target)
    targets.push({
      kind: kindMatch?.[1] === 'compute' ? 'compute' : 'sm',
      value: target,
      source: 'string-scan',
    })
    if (targets.length >= 200) break
  }

  for (const directive of collectMatches(text, /^\s*\.target\s+([^\r\n]+)/gm, 100)) {
    for (const target of directive.match(/\b(?:sm|compute)_[0-9]{2,3}[a-z]?\b/g) ?? []) {
      targets.push({
        kind: target.startsWith('compute_') ? 'compute' : 'sm',
        value: target,
        source: 'ptx-target-directive',
      })
    }
  }

  const byKey = new Map<string, CudaTarget>()
  for (const target of targets) {
    byKey.set(`${target.kind}:${target.value}`, target)
  }
  return [...byKey.values()]
}

function extractPtxKernels(text: string): CudaKernel[] {
  const kernels: CudaKernel[] = []
  for (const match of text.matchAll(/^\s*(\.visible\s+)?\.entry\s+([A-Za-z_$][A-Za-z0-9_.$]*)/gm)) {
    kernels.push({
      name: match[2],
      sources: ['ptx-entry'],
      visibility: match[1] ? 'visible' : undefined,
    })
  }

  for (const match of text.matchAll(
    /^\s*(\.visible\s+)?\.func(?:\s+\([^)]*\))?\s+([A-Za-z_$][A-Za-z0-9_.$]*)/gm
  )) {
    kernels.push({
      name: match[2],
      sources: ['ptx-func'],
      visibility: match[1] ? 'visible' : undefined,
    })
  }

  return mergeKernelHints(kernels)
}

function extractSectionHits(strings: string[]): string[] {
  const sections: string[] = []
  for (const value of strings) {
    const matches =
      value.match(
        /(?:\.nv(?:[._][A-Za-z0-9_.$-]+)+|\.text\.(?:sm_[0-9]{2,3}[a-z]?|[A-Za-z_$][A-Za-z0-9_.$-]*)|\.nvvm[A-Za-z0-9_.$-]*)/g
      ) ?? []
    sections.push(...matches)
  }
  return unique(sections).slice(0, 250)
}

function extractSectionKernels(sections: string[]): CudaKernel[] {
  const kernels: CudaKernel[] = []
  for (const section of sections) {
    const textMatch = /^\.text\.([A-Za-z_$][A-Za-z0-9_.$-]*)$/.exec(section)
    if (textMatch && !textMatch[1].startsWith('sm_')) {
      kernels.push({ name: textMatch[1], sources: ['elf-section'] })
    }
    const nvMatch = /^\.nv\.(?:shared|constant[0-9]*|info)\.([A-Za-z_$][A-Za-z0-9_.$-]*)$/.exec(
      section
    )
    if (nvMatch) {
      kernels.push({ name: nvMatch[1], sources: ['nv-section'] })
    }
  }
  return mergeKernelHints(kernels)
}

function mergeKernelHints(kernels: CudaKernel[]): CudaKernel[] {
  const byName = new Map<string, CudaKernel>()
  for (const kernel of kernels) {
    if (kernel.name.length > 160) continue
    const current = byName.get(kernel.name)
    if (!current) {
      byName.set(kernel.name, { ...kernel, sources: unique(kernel.sources) })
      continue
    }
    current.sources = unique([...current.sources, ...kernel.sources])
    current.visibility = current.visibility ?? kernel.visibility
    current.target = current.target ?? kernel.target
  }
  return [...byName.values()].slice(0, 200)
}

function detectFormat(input: {
  extension: string
  text: string
  elf: ElfSummary
  fatbinMarkers: string[]
  hostRegistrationMarkers: string[]
  ptxVersions: string[]
  kernels: CudaKernel[]
  sections: string[]
}): {
  format: CudaBinaryInventory['format']
  detectedBy: string[]
  isCudaCandidate: boolean
  confidence: number
} {
  const detectedBy: string[] = []
  let score = 0

  if (['ptx', 'cubin', 'fatbin'].includes(input.extension)) {
    detectedBy.push(`${input.extension} extension`)
    score += 0.15
  }
  if (input.ptxVersions.length > 0 || /^\s*\.(?:version|target|entry)\b/m.test(input.text)) {
    detectedBy.push('PTX directives')
    score += 0.4
  }
  if (input.elf.is_elf) {
    detectedBy.push('ELF magic')
    score += 0.1
  }
  if (input.elf.machine_id === 190) {
    detectedBy.push('ELF e_machine EM_CUDA')
    score += 0.55
  }
  if (input.sections.length > 0) {
    detectedBy.push('CUDA section strings')
    score += 0.2
  }
  if (input.fatbinMarkers.length > 0) {
    detectedBy.push('CUDA fatbin markers')
    score += 0.25
  }
  if (input.hostRegistrationMarkers.length > 0) {
    detectedBy.push('CUDA host registration markers')
    score += 0.25
  }
  if (input.kernels.length > 0) {
    detectedBy.push('GPU kernel/function hints')
    score += 0.15
  }

  let format: CudaBinaryInventory['format'] = 'unknown-cuda-hints'
  if (input.extension === 'ptx' || input.ptxVersions.length > 0) {
    format = 'ptx'
  }
  if (input.elf.machine_id === 190 || (input.extension === 'cubin' && input.elf.is_elf)) {
    format = 'cubin-elf'
  } else if (input.extension === 'fatbin' || input.fatbinMarkers.length > 0) {
    format = 'cuda-fatbin'
  } else if (input.hostRegistrationMarkers.length > 0) {
    format = 'host-binary-cuda'
  }

  const confidence = Math.max(0, Math.min(1, Number(score.toFixed(2))))
  return {
    format,
    detectedBy: unique(detectedBy),
    isCudaCandidate: confidence >= 0.3,
    confidence,
  }
}

function recommendedNextTools(format: CudaBinaryInventory['format']): string[] {
  const tools = ['artifact.read', 'strings.extract', 'metadata.extract']
  if (format === 'cubin-elf' || format === 'host-binary-cuda') {
    tools.push('native.object.inventory', 'linux.binary.inventory')
  }
  if (format !== 'unknown-cuda-hints') {
    tools.push('culifter.gpu.plan', 'culifter.gpu.artifact.inventory')
  }
  tools.push('sbom.provenance.graph', 'analysis.evidence.graph')
  return unique(tools).filter((tool) => CUDA_FOLLOW_UP_TOOLS.includes(tool))
}

function buildRiskNotes(input: {
  format: CudaBinaryInventory['format']
  kernels: CudaKernel[]
  targetArchCount: number
  hostRegistrationMarkers: string[]
  ptxVersions: string[]
  elf: ElfSummary
}): string[] {
  const notes = [
    'Inventory is static-only: no CUDA driver, GPU device, profiler, nvdisasm, cuobjdump, or sample execution was used.',
  ]
  if (input.format === 'host-binary-cuda') {
    notes.push(
      'Host binary appears to embed or register CUDA device code; correlate imports, sections, and native object inventory before GPU lifting.'
    )
  }
  if (input.format === 'cubin-elf' && input.elf.machine_id === 190) {
    notes.push(
      'CUBIN ELF uses NVIDIA CUDA e_machine metadata; downstream SASS lifting should stay bounded to selected kernels and architectures.'
    )
  }
  if (input.ptxVersions.length > 0 && input.targetArchCount === 0) {
    notes.push(
      'PTX directives were found without a concrete sm_/compute_ target in the bounded preview.'
    )
  }
  if (input.kernels.length === 0) {
    notes.push(
      'No kernel names were recovered from the bounded preview; later external disassembly should remain explicit and readiness-gated.'
    )
  }
  if (input.hostRegistrationMarkers.length > 0) {
    notes.push(
      'CUDA host registration markers can indicate embedded fatbins inside a normal host executable.'
    )
  }
  return notes
}

function buildEnvelope(
  inventory: Omit<CudaBinaryInventory, 'evidence_summary' | 'workflow_handoff' | 'quality_gates'>
) {
  return {
    evidence_summary: {
      schema: CUDA_EVIDENCE_SUMMARY_SCHEMA,
      source_tool: TOOL_NAME,
      sample_id: inventory.sample_id,
      filename: inventory.filename,
      artifact_type: CUDA_BINARY_INVENTORY_ARTIFACT_TYPE,
      format: inventory.format,
      confidence: inventory.confidence,
      static_only: true,
      counts: {
        targets: inventory.target_arches.length,
        ptx_versions: inventory.ptx_versions.length,
        kernels: inventory.kernels.length,
        sections: inventory.sections.length,
        fatbin_markers: inventory.fatbin_markers.length,
        host_registration_markers: inventory.host_registration_markers.length,
        sass_hints: inventory.sass_hints.length,
      },
    },
    workflow_handoff: {
      schema: CUDA_WORKFLOW_HANDOFF_SCHEMA,
      handoff_mode: 'cuda_binary_inventory_to_gpu_lift_and_host_correlation',
      recommended_next_tools: inventory.recommended_next_tools,
      artifact_contract: {
        consumes: ['sample'],
        produces: [CUDA_BINARY_INVENTORY_ARTIFACT_TYPE, CUDA_KERNEL_SUMMARY_ARTIFACT_TYPE],
        mime: 'application/json',
        expected_consumers: inventory.recommended_next_tools,
      },
      dynamic_boundary: {
        activation_boundary: 'result-scoped',
        sample_execution_allowed: false,
        cuda_driver_allowed: false,
        gpu_access_allowed: false,
        external_tool_allowed: false,
        mutation_allowed: false,
        network_allowed: false,
        sample_executed_by_tool: false,
        cuda_driver_used_by_tool: false,
        gpu_accessed_by_tool: false,
        external_tool_started_by_tool: false,
        mutation_performed: false,
        network_used_by_tool: false,
      },
      routing: [
        {
          goal: 'gpu-artifact-lift-planning',
          next_tools: ['culifter.gpu.plan', 'culifter.gpu.artifact.inventory'],
          conditions: [
            'cuda candidate evidence present',
            'bounded kernel/target summary available',
          ],
        },
        {
          goal: 'host-device-correlation',
          next_tools: ['native.object.inventory', 'linux.binary.inventory', 'strings.extract'],
          conditions: ['host registration markers or ELF/native wrapper evidence present'],
        },
        {
          goal: 'evidence-correlation',
          next_tools: ['sbom.provenance.graph', 'analysis.evidence.graph'],
          conditions: ['persisted CUDA inventory artifact available'],
        },
      ],
    },
    quality_gates: {
      schema: CUDA_QUALITY_GATES_SCHEMA,
      passive_static_inventory: true,
      bounded_preview_only: true,
      cuda_candidate_detected: inventory.is_cuda_candidate,
      kernel_hints_present: inventory.kernels.length > 0,
      target_arches_present: inventory.target_arches.length > 0,
      ptx_or_cubin_evidence_present:
        inventory.ptx_versions.length > 0 ||
        inventory.elf.machine_id === 190 ||
        inventory.fatbin_markers.length > 0,
      sample_executed_by_tool: false,
      cuda_driver_used_by_tool: false,
      gpu_accessed_by_tool: false,
      external_tool_started_by_tool: false,
      mutation_performed: false,
      network_used_by_tool: false,
    },
  }
}

export function buildCudaBinaryInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): CudaBinaryInventory {
  const text = boundedText(data)
  const strings = extractAsciiStrings(data)
  const combinedText = `${text}\n${strings.join('\n')}`
  const extension = extensionOf(options.filename)
  const elf = readElfSummary(data)
  const ptxVersions = collectMatches(combinedText, /^\s*\.version\s+([0-9]+(?:\.[0-9]+)?)/gm, 50)
  const addressSizes = collectMatches(combinedText, /^\s*\.address_size\s+([0-9]+)/gm, 20)
    .map((value) => Number.parseInt(value, 10))
    .filter((value) => Number.isFinite(value))
  const targetArches = extractTargets(combinedText)
  const sections = extractSectionHits(strings)
  const symbolHints = unique(
    strings.filter((value) =>
      /(?:__cuda|__nv|\.nv_|\.nv\.|_Z[A-Za-z0-9_]+|cuda[A-Z][A-Za-z0-9_]+)/.test(value)
    )
  ).slice(0, 200)
  const fatbinMarkers = CUDA_FATBIN_MARKERS.filter((marker) => combinedText.includes(marker))
  const hostRegistrationMarkers = CUDA_HOST_REGISTRATION_MARKERS.filter((marker) =>
    combinedText.includes(marker)
  )
  const sassHints = unique(combinedText.match(SASS_HINT_RE) ?? []).slice(0, 100)
  const kernels = mergeKernelHints([
    ...extractPtxKernels(combinedText),
    ...extractSectionKernels(sections),
  ])
  const detected = detectFormat({
    extension,
    text: combinedText,
    elf,
    fatbinMarkers,
    hostRegistrationMarkers,
    ptxVersions,
    kernels,
    sections,
  })
  const nextTools = recommendedNextTools(detected.format)

  const inventoryBase: Omit<
    CudaBinaryInventory,
    'evidence_summary' | 'workflow_handoff' | 'quality_gates'
  > = {
    schema: 'rikune.cuda_binary_inventory.v1',
    sample_id: options.sampleId,
    filename: options.filename,
    size: options.size ?? data.length,
    format: detected.format,
    is_cuda_candidate: detected.isCudaCandidate,
    confidence: detected.confidence,
    detected_by: detected.detectedBy,
    target_arches: targetArches,
    ptx_versions: ptxVersions,
    address_sizes: unique(addressSizes.map(String)).map((value) => Number.parseInt(value, 10)),
    kernels,
    sections,
    symbol_hints: symbolHints,
    fatbin_markers: fatbinMarkers,
    host_registration_markers: hostRegistrationMarkers,
    sass_hints: sassHints,
    elf,
    policy: CUDA_POLICY,
    risk_notes: buildRiskNotes({
      format: detected.format,
      kernels,
      targetArchCount: targetArches.length,
      hostRegistrationMarkers,
      ptxVersions,
      elf,
    }),
    summary: `Passive CUDA binary inventory detected ${detected.format} with ${targetArches.length} target hint(s), ${kernels.length} kernel/function hint(s), ${sections.length} CUDA section hit(s), and confidence ${detected.confidence}.`,
    recommended_next_tools: nextTools,
    next_actions: [
      'Review PTX directives, CUBIN ELF metadata, and fatbin markers as static evidence.',
      'Use culifter.gpu.plan for bounded GPU lift planning before any external backend is considered.',
      'Correlate host binaries with native.object.inventory or linux.binary.inventory when CUDA registration markers are present.',
      'Keep nvdisasm, cuobjdump, CUDA driver access, and GPU execution behind explicit readiness-gated follow-up work.',
    ],
  }

  return CudaBinaryInventoryDataSchema.parse({
    ...inventoryBase,
    ...buildEnvelope(inventoryBase),
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

export function createCudaBinaryInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (args: z.infer<typeof CudaBinaryInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = CudaBinaryInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildCudaBinaryInventoryFromBuffer(data, {
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
            CUDA_BINARY_INVENTORY_ARTIFACT_TYPE,
            'cuda-binary-inventory',
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
