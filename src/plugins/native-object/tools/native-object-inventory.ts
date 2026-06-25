/**
 * native.object.inventory — passive object/static-library inventory.
 *
 * This tool never links, loads, signs, strips, or executes object content. It
 * reads bounded previews and returns format, symbol, and routing hints.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'
import {
  NATIVE_OBJECT_EVIDENCE_SUMMARY_SCHEMA,
  NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE,
  NATIVE_OBJECT_QUALITY_GATES_SCHEMA,
  NATIVE_OBJECT_RUNTIME_POLICY,
  NATIVE_OBJECT_WORKFLOW_HANDOFF_SCHEMA,
  buildNativeObjectEnvelope,
  nativeObjectAspects,
  nativeObjectRecommendedNextTools,
  nativeObjectRecipe,
  type NativeObjectInventoryEnvelopeInput,
} from '../native-object-metadata.js'

const TOOL_NAME = 'native.object.inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024

const NativeObjectPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_link: z.literal(true),
  no_load: z.literal(true),
  no_strip_or_sign: z.literal(true),
  no_mutation: z.literal(true),
})

const NativeObjectInventoryDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  machine_hints: z.array(z.string()),
  member_names: z.array(z.string()),
  symbol_hints: z.array(z.string()),
  debug_metadata_candidates: z.array(z.string()),
  nested_binary_candidates: z.array(
    z.object({
      path: z.string(),
      routed_formats: z.array(z.string()),
      recommended_tools: z.array(z.string()),
    })
  ),
  policy: NativeObjectPolicySchema,
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z
    .object({
      schema: z.literal(NATIVE_OBJECT_EVIDENCE_SUMMARY_SCHEMA),
      source_tool: z.literal(TOOL_NAME),
      artifact_type: z.literal(NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE),
    })
    .passthrough()
    .optional(),
  workflow_handoff: z
    .object({
      schema: z.literal(NATIVE_OBJECT_WORKFLOW_HANDOFF_SCHEMA),
      artifact_contract: z.record(z.any()),
      dynamic_boundary: z
        .object({
          sample_execution_allowed: z.literal(false),
          link_allowed: z.literal(false),
          load_allowed: z.literal(false),
          strip_or_sign_allowed: z.literal(false),
          mutation_allowed: z.literal(false),
          network_allowed: z.literal(false),
          sample_executed_by_tool: z.literal(false),
          linked_by_tool: z.literal(false),
          loaded_by_tool: z.literal(false),
          stripped_or_signed_by_tool: z.literal(false),
          mutation_performed: z.literal(false),
          network_used_by_tool: z.literal(false),
        })
        .passthrough(),
      routing: z.array(z.record(z.any())),
    })
    .passthrough()
    .optional(),
  quality_gates: z
    .object({
      schema: z.literal(NATIVE_OBJECT_QUALITY_GATES_SCHEMA),
      passive_static_inventory: z.literal(true),
      sample_executed_by_tool: z.literal(false),
      linked_by_tool: z.literal(false),
      loaded_by_tool: z.literal(false),
      stripped_or_signed_by_tool: z.literal(false),
      mutation_performed: z.literal(false),
      network_used_by_tool: z.literal(false),
    })
    .passthrough()
    .optional(),
})

export const NativeObjectInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive object inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const NativeObjectInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: NativeObjectInventoryDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const nativeObjectInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory object files, static libraries, kernel modules, and debug bundles. Does not link, load, strip, sign, or execute content.',
  inputSchema: NativeObjectInventoryInputSchema,
  outputSchema: NativeObjectInventoryOutputSchema,
  aspects: nativeObjectAspects(),
  artifacts: [
    {
      type: NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE,
      description: 'Passive object/static-library/debug-bundle inventory and routing hints',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'symbols',
      artifactTypes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'debug-metadata',
      artifactTypes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [nativeObjectRecipe()],
  runtimePolicy: NATIVE_OBJECT_RUNTIME_POLICY,
}

export type NativeObjectInventory = z.infer<typeof NativeObjectInventoryDataSchema>
type NativeObjectInventoryBase = Omit<
  NativeObjectInventory,
  'evidence_summary' | 'workflow_handoff' | 'quality_gates'
>
type NestedBinaryCandidate = {
  path: string
  routed_formats: string[]
  recommended_tools: string[]
}

const ELF_MACHINES: Record<number, string> = {
  3: 'x86',
  8: 'mips',
  20: 'ppc',
  40: 'arm',
  62: 'x64',
  183: 'arm64',
  243: 'riscv',
}

const COFF_MACHINES: Record<number, string> = {
  0x014c: 'x86',
  0x8664: 'x64',
  0x01c0: 'arm',
  0x01c4: 'arm',
  0xaa64: 'arm64',
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (base.endsWith('.dsym')) return 'dsym'
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function previewText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
}

function readElfHeader(data: Buffer): { type?: number; machine?: string } {
  if (data.length < 20 || data.subarray(0, 4).toString('binary') !== '\x7fELF') return {}
  const endian = data[5] === 2 ? 'be' : 'le'
  const readUInt16 = (offset: number) =>
    endian === 'be' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
  return {
    type: readUInt16(16),
    machine: ELF_MACHINES[readUInt16(18)] ?? `elf-machine-${readUInt16(18)}`,
  }
}

function readMachOFileType(data: Buffer): { format?: string; machine?: string } {
  if (data.length < 16) return {}
  const magic = data.readUInt32BE(0)
  if (![0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic)) return {}
  const bigEndian = magic === 0xfeedface || magic === 0xfeedfacf
  const cpu = bigEndian ? data.readUInt32BE(4) : data.readUInt32LE(4)
  const fileType = bigEndian ? data.readUInt32BE(12) : data.readUInt32LE(12)
  const machine =
    cpu === 0x01000007
      ? 'x64'
      : cpu === 0x0100000c
        ? 'arm64'
        : cpu === 7
          ? 'x86'
          : cpu === 12
            ? 'arm'
            : `macho-cpu-${cpu}`
  return {
    format: fileType === 1 ? 'macho-object' : 'macho',
    machine,
  }
}

function parseArMembers(data: Buffer): string[] {
  if (data.length < 8 || data.subarray(0, 8).toString('ascii') !== '!<arch>\n') {
    return []
  }

  const members: string[] = []
  let offset = 8
  while (offset + 60 <= data.length && members.length < 500) {
    const header = data.subarray(offset, offset + 60).toString('latin1')
    const name = header.slice(0, 16).trim().replace(/\/$/, '')
    const size = Number.parseInt(header.slice(48, 58).trim(), 10)
    if (!name || !Number.isFinite(size) || size < 0) break
    members.push(name)
    offset += 60 + size + (size % 2)
  }
  return members
}

function detectFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[]; machineHints: string[] } {
  const ext = extensionOf(filename)
  const basename = path.posix.basename((filename ?? '').replace(/\\/g, '/')).toLowerCase()
  const detectedBy: string[] = []
  const machineHints: string[] = []
  const text = previewText(data)

  if (ext === 'dsym' || basename.endsWith('.dsym')) {
    return { format: 'dsym', detectedBy: ['filename extension'], machineHints }
  }

  const elf = readElfHeader(data)
  if (elf.type) {
    if (elf.machine) machineHints.push(elf.machine)
    if (ext === 'ko' || text.includes('vermagic=')) {
      return {
        format: 'linux-kernel-module',
        detectedBy: ['ELF magic', ext === 'ko' ? 'ko extension' : 'vermagic marker'],
        machineHints,
      }
    }
    if (elf.type === 1) {
      return { format: 'elf-object', detectedBy: ['ELF magic', 'ET_REL'], machineHints }
    }
    if (elf.type === 4) {
      return { format: 'elf-core', detectedBy: ['ELF magic', 'ET_CORE'], machineHints }
    }
    return { format: 'elf', detectedBy: ['ELF magic'], machineHints }
  }

  const macho = readMachOFileType(data)
  if (macho.format) {
    if (macho.machine) machineHints.push(macho.machine)
    return {
      format: macho.format,
      detectedBy: ['Mach-O magic', macho.format === 'macho-object' ? 'MH_OBJECT' : 'Mach-O header'],
      machineHints,
    }
  }

  if (data.length >= 8 && data.subarray(0, 8).toString('ascii') === '!<arch>\n') {
    if (ext === 'lib') {
      return { format: 'coff-lib', detectedBy: ['ar magic', 'lib extension'], machineHints }
    }
    if (ext === 'a') {
      return { format: 'ar-static-lib', detectedBy: ['ar magic', 'a extension'], machineHints }
    }
    return { format: 'ar', detectedBy: ['ar magic'], machineHints }
  }

  if (ext === 'obj' && data.length >= 2) {
    const machine = data.readUInt16LE(0)
    if (COFF_MACHINES[machine]) machineHints.push(COFF_MACHINES[machine])
    return { format: 'coff', detectedBy: ['obj extension'], machineHints }
  }

  if (ext === 'o') return { format: 'object', detectedBy: ['o extension'], machineHints }
  if (ext === 'a') return { format: 'static-lib', detectedBy: ['a extension'], machineHints }
  if (ext === 'lib') return { format: 'coff-lib', detectedBy: ['lib extension'], machineHints }
  if (ext === 'ko')
    return { format: 'linux-kernel-module', detectedBy: ['ko extension'], machineHints }

  return {
    format: ext || 'unknown',
    detectedBy: ext ? ['filename extension'] : ['unknown'],
    machineHints,
  }
}

function extractSymbolHints(data: Buffer): string[] {
  const text = previewText(data)
  const matches =
    text.match(
      /(?:_?Java_[A-Za-z0-9_]+|_?[A-Za-z][A-Za-z0-9_]{2,120}|vermagic=[A-Za-z0-9_.+\-]+)/g
    ) ?? []
  return Array.from(new Set(matches))
    .filter((value) => value.length >= 3 && !/^[0-9]+$/.test(value))
    .slice(0, 200)
}

function routeMember(memberPath: string): NestedBinaryCandidate | null {
  const lower = memberPath.toLowerCase()
  const routedFormats: string[] = []
  const recommendedTools: string[] = []

  if (/\.(?:o|obj)$/.test(lower)) {
    routedFormats.push('object')
    recommendedTools.push('native.object.inventory')
  }
  if (lower.endsWith('.ko')) {
    routedFormats.push('linux-kernel-module')
    recommendedTools.push('native.object.inventory', 'elf.structure.analyze')
  }
  if (/\.(?:so|elf)$/.test(lower)) {
    routedFormats.push('elf')
    recommendedTools.push('elf.structure.analyze')
  }
  if (/\.(?:dylib|macho)$/.test(lower)) {
    routedFormats.push('macho')
    recommendedTools.push('macho.structure.analyze')
  }
  if (lower.endsWith('.pdb') || lower.endsWith('.dsym')) {
    routedFormats.push('debug-metadata')
    recommendedTools.push(
      lower.endsWith('.pdb') ? 'windows.debug.metadata.inspect' : 'native.object.inventory'
    )
  }

  if (recommendedTools.length === 0) return null
  return {
    path: memberPath,
    routed_formats: Array.from(new Set(routedFormats)),
    recommended_tools: Array.from(new Set(recommendedTools)),
  }
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

export function buildNativeObjectInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): NativeObjectInventory {
  const detected = detectFormat(data, options.filename)
  const memberNames = parseArMembers(data)
  const symbolHints = extractSymbolHints(data)
  const debugCandidates = unique([
    ...memberNames.filter((member) => /\.(?:debug|dwo|dwp|pdb|dsym)$/i.test(member)),
    ...symbolHints.filter((symbol) => /dwarf|pdb|dsym|debug/i.test(symbol)),
  ]).slice(0, 100)
  const nested = memberNames
    .map(routeMember)
    .filter((candidate): candidate is NestedBinaryCandidate => Boolean(candidate))
    .slice(0, 200)
  const unsupported =
    detected.format === 'dsym'
      ? 'Directory bundle member listing requires ingesting the dSYM bundle or archive; this inventory keeps the default behavior passive.'
      : undefined

  const inventoryBase: NativeObjectInventoryBase = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    detected_by: detected.detectedBy,
    size: options.size ?? data.length,
    machine_hints: unique(detected.machineHints),
    member_names: memberNames,
    symbol_hints: symbolHints,
    debug_metadata_candidates: debugCandidates,
    nested_binary_candidates: nested,
    policy: {
      passive: true,
      no_execute: true,
      no_link: true,
      no_load: true,
      no_strip_or_sign: true,
      no_mutation: true,
    },
    unsupported_detail: unsupported,
    summary: `Passive native object inventory detected ${detected.format} with ${memberNames.length} archive member(s), ${symbolHints.length} symbol hint(s), and ${nested.length} nested candidate(s).`,
    recommended_next_tools: nativeObjectRecommendedNextTools({
      format: detected.format,
      symbol_hints: symbolHints,
      debug_metadata_candidates: debugCandidates,
      nested_binary_candidates: nested,
    }),
    next_actions: [
      'Review object members and symbol hints as static metadata only.',
      'Ingest relevant member binaries separately before running format-specific analyzers.',
      'Do not link, load, strip, sign, or execute object content during static triage.',
    ],
  }

  return NativeObjectInventoryDataSchema.parse({
    ...inventoryBase,
    ...buildNativeObjectEnvelope(inventoryBase as NativeObjectInventoryEnvelopeInput),
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

export function createNativeObjectInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (args: z.infer<typeof NativeObjectInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = NativeObjectInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildNativeObjectInventoryFromBuffer(data, {
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
            NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE,
            'native-object-inventory',
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
