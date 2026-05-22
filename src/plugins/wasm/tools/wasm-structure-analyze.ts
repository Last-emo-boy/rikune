/**
 * wasm.structure.analyze — passive WebAssembly module inventory.
 *
 * This tool does not instantiate modules, call wasmtime, or execute WASI code.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'wasm.structure.analyze'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024

const SECTION_NAMES: Record<number, string> = {
  0: 'custom',
  1: 'type',
  2: 'import',
  3: 'function',
  4: 'table',
  5: 'memory',
  6: 'global',
  7: 'export',
  8: 'start',
  9: 'element',
  10: 'code',
  11: 'data',
  12: 'data_count',
}

const WasmPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_runtime_start: z.literal(true),
})

const WasmStructureDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.literal('wasm'),
  valid_magic: z.boolean(),
  version: z.number().optional(),
  sections: z.array(
    z.object({
      id: z.number(),
      name: z.string(),
      offset: z.number(),
      size: z.number(),
    })
  ),
  custom_sections: z.array(z.string()),
  import_count_hint: z.number(),
  export_count_hint: z.number(),
  wasi_capability_hints: z.array(z.string()),
  runtime_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    notes: z.array(z.string()),
  }),
  policy: WasmPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const WasmStructureAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive WASM inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist WASM inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const WasmStructureAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: WasmStructureDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const wasmStructureAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively analyze WebAssembly module structure, sections, imports/exports hints, and WASI capability hints without executing the module.',
  inputSchema: WasmStructureAnalyzeInputSchema,
  outputSchema: WasmStructureAnalyzeOutputSchema,
  aspects: {
    formats: ['wasm', 'wasi'],
    platforms: ['wasm'],
    architectures: ['wasm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['structure', 'imports', 'exports', 'capabilities', 'runtime-plan'],
    evidence: ['structure', 'imports', 'exports', 'provenance'],
  },
  artifacts: [
    {
      type: 'wasm_structure',
      description: 'Passive WASM section, import/export hint, and WASI capability inventory',
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: ['wasm_structure'],
    },
  ],
}

export type WasmStructureInventory = z.infer<typeof WasmStructureDataSchema>

function readU32Leb(data: Buffer, offset: number): { value: number; next: number } | null {
  let result = 0
  let shift = 0
  let cursor = offset

  while (cursor < data.length && shift <= 28) {
    const byte = data[cursor]
    result |= (byte & 0x7f) << shift
    cursor += 1
    if ((byte & 0x80) === 0) {
      return { value: result >>> 0, next: cursor }
    }
    shift += 7
  }
  return null
}

function readName(
  data: Buffer,
  offset: number,
  limit: number
): { value: string; next: number } | null {
  const length = readU32Leb(data, offset)
  if (!length) return null
  const end = length.next + length.value
  if (end > limit || end > data.length) return null
  return { value: data.subarray(length.next, end).toString('utf8'), next: end }
}

function countVectorItems(data: Buffer, offset: number, limit: number): number {
  const count = readU32Leb(data, offset)
  if (!count || count.next > limit) return 0
  return count.value
}

function parseSections(data: Buffer): {
  sections: WasmStructureInventory['sections']
  customSections: string[]
  importCountHint: number
  exportCountHint: number
  wasiHints: string[]
} {
  const sections: WasmStructureInventory['sections'] = []
  const customSections: string[] = []
  const wasiHints = new Set<string>()
  let importCountHint = 0
  let exportCountHint = 0
  let offset = 8

  while (offset < data.length && sections.length < 200) {
    const id = data[offset]
    const size = readU32Leb(data, offset + 1)
    if (!size) break
    const payloadStart = size.next
    const payloadEnd = payloadStart + size.value
    if (payloadEnd > data.length) break

    const sectionName = SECTION_NAMES[id] ?? `section_${id}`
    sections.push({ id, name: sectionName, offset, size: size.value })

    if (id === 0) {
      const name = readName(data, payloadStart, payloadEnd)
      if (name?.value) customSections.push(name.value)
    } else if (id === 2) {
      importCountHint = countVectorItems(data, payloadStart, payloadEnd)
      const text = data.subarray(payloadStart, payloadEnd).toString('latin1')
      for (const hint of ['wasi_snapshot_preview1', 'wasi_unstable', 'fd_', 'path_', 'sock_']) {
        if (text.includes(hint)) wasiHints.add(hint)
      }
    } else if (id === 7) {
      exportCountHint = countVectorItems(data, payloadStart, payloadEnd)
    }

    offset = payloadEnd
  }

  return {
    sections,
    customSections,
    importCountHint,
    exportCountHint,
    wasiHints: Array.from(wasiHints),
  }
}

export function buildWasmStructureFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): WasmStructureInventory {
  const validMagic =
    data.length >= 8 && data[0] === 0x00 && data[1] === 0x61 && data[2] === 0x73 && data[3] === 0x6d
  const version = validMagic ? data.readUInt32LE(4) : undefined
  const parsed = validMagic
    ? parseSections(data)
    : { sections: [], customSections: [], importCountHint: 0, exportCountHint: 0, wasiHints: [] }

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: 'wasm',
    valid_magic: validMagic,
    version,
    sections: parsed.sections,
    custom_sections: parsed.customSections,
    import_count_hint: parsed.importCountHint,
    export_count_hint: parsed.exportCountHint,
    wasi_capability_hints: parsed.wasiHints,
    runtime_plan: {
      status: 'plan_only',
      recommended_tools: ['metadata.extract', 'strings.extract'],
      notes: [
        'Use a runtime-gated WASM/WASI backend only after reviewing imports and capabilities.',
        'This tool does not instantiate the module or start wasmtime.',
      ],
    },
    policy: {
      passive: true,
      no_execute: true,
      no_runtime_start: true,
    },
    summary: validMagic
      ? `Passive WASM inventory found ${parsed.sections.length} section(s), ${parsed.importCountHint} import hint(s), and ${parsed.exportCountHint} export hint(s).`
      : 'Input does not contain a valid WASM magic header in the inspected preview.',
    recommended_next_tools: ['metadata.extract', 'strings.extract'],
    next_actions: [
      'Review import and WASI capability hints before selecting a runtime backend.',
      'Do not instantiate the WASM module during static triage.',
    ],
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

export function createWasmStructureAnalyzeHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof WasmStructureAnalyzeInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = WasmStructureAnalyzeInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildWasmStructureFromBuffer(data, {
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
            'wasm_structure',
            'wasm-structure',
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
