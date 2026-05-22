/**
 * bytecode.metadata.inspect — passive script bytecode metadata inventory.
 *
 * This tool does not invoke Python, Lua, Node.js, or any bytecode decompiler.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'bytecode.metadata.inspect'
const DEFAULT_MAX_READ_BYTES = 2 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024

const BytecodePolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_interpreter_start: z.literal(true),
  no_decompiler_launch: z.literal(true),
})

const BytecodeMetadataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  header: z.record(z.any()),
  version_hints: z.array(z.string()),
  string_hints: z.array(z.string()),
  decompile_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    notes: z.array(z.string()),
  }),
  policy: BytecodePolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const BytecodeMetadataInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive bytecode metadata inspection.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist bytecode metadata JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const BytecodeMetadataInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: BytecodeMetadataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const bytecodeMetadataInspectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inspect Python PYC, Lua bytecode, and V8 cached data metadata without starting an interpreter or decompiler.',
  inputSchema: BytecodeMetadataInspectInputSchema,
  outputSchema: BytecodeMetadataInspectOutputSchema,
  aspects: {
    formats: ['pyc', 'lua-bytecode', 'v8-cache'],
    platforms: ['python', 'lua', 'node', 'cross-platform'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['metadata', 'strings', 'version-hints', 'decompile-plan', 'routing'],
    evidence: ['structure', 'strings', 'package-metadata', 'provenance'],
  },
  artifacts: [
    {
      type: 'bytecode_metadata',
      description: 'Passive script bytecode header, version hint, and string inventory',
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: ['bytecode_metadata'],
    },
    {
      category: 'strings',
      artifactTypes: ['bytecode_metadata'],
    },
  ],
}

export type BytecodeMetadataInventory = z.infer<typeof BytecodeMetadataSchema>

const KNOWN_PYC_MAGIC: Record<number, string> = {
  0x0a0d0da7: 'CPython 3.11',
  0x0a0d0d6f: 'CPython 3.10',
  0x0a0d0d61: 'CPython 3.9',
  0x0a0d0d55: 'CPython 3.8/3.12 family',
  0x0a0d0d42: 'CPython 3.7',
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function detectBytecodeFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  if (
    data.length >= 4 &&
    data[0] === 0x1b &&
    data[1] === 0x4c &&
    data[2] === 0x75 &&
    data[3] === 0x61
  ) {
    return { format: 'lua-bytecode', detectedBy: ['lua bytecode magic'] }
  }
  if (ext === 'pyc') return { format: 'pyc', detectedBy: ['filename extension'] }
  if (ext === 'luac') return { format: 'lua-bytecode', detectedBy: ['filename extension'] }
  if (ext === 'jsc' || ext === 'blob') {
    return { format: 'v8-cache', detectedBy: ['filename extension'] }
  }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function extractAsciiStringHints(data: Buffer): string[] {
  const text = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
  const matches = text.match(/[A-Za-z0-9_./:@$+-]{4,160}/g) ?? []
  const ignored = new Set(['true', 'false', 'null', 'none'])
  return Array.from(
    new Set(
      matches
        .map((item) => item.trim())
        .filter((item) => item.length >= 4 && !ignored.has(item.toLowerCase()))
    )
  ).slice(0, 100)
}

function parsePycHeader(data: Buffer): { header: Record<string, unknown>; versionHints: string[] } {
  const header: Record<string, unknown> = {}
  const versionHints: string[] = []
  if (data.length >= 4) {
    const magic = data.readUInt32LE(0)
    header.magic_hex = `0x${magic.toString(16).padStart(8, '0')}`
    const known = KNOWN_PYC_MAGIC[magic]
    if (known) versionHints.push(known)
  }
  if (data.length >= 16) {
    const flags = data.readUInt32LE(4)
    header.flags = flags
    header.hash_based = Boolean(flags & 0x01)
    if (flags & 0x01) {
      header.source_hash_hex = data.subarray(8, 16).toString('hex')
    } else {
      header.timestamp = data.readUInt32LE(8)
      header.source_size = data.readUInt32LE(12)
    }
  }
  return { header, versionHints }
}

function parseLuaHeader(data: Buffer): { header: Record<string, unknown>; versionHints: string[] } {
  const header: Record<string, unknown> = {}
  const versionHints: string[] = []
  if (data.length >= 4) header.magic = data.subarray(0, 4).toString('latin1')
  if (data.length >= 5) {
    const version = data[4]
    header.version_byte = `0x${version.toString(16).padStart(2, '0')}`
    const major = version >> 4
    const minor = version & 0x0f
    versionHints.push(`Lua ${major}.${minor}`)
  }
  if (data.length >= 6) header.format = data[5]
  if (data.length >= 12) {
    header.endianness = data[6] === 1 ? 'little' : data[6] === 0 ? 'big' : 'unknown'
    header.int_size = data[7]
    header.size_t_size = data[8]
    header.instruction_size = data[9]
    header.lua_integer_size = data[10]
    header.lua_number_size = data[11]
  }
  return { header, versionHints }
}

function parseV8Header(data: Buffer): { header: Record<string, unknown>; versionHints: string[] } {
  const header: Record<string, unknown> = {}
  if (data.length >= 4) header.magic_or_tag_hex = data.subarray(0, 4).toString('hex')
  if (data.length >= 8) header.version_or_source_hash_hex = data.subarray(4, 8).toString('hex')
  if (data.length >= 16) header.header_preview_hex = data.subarray(0, 16).toString('hex')
  return {
    header,
    versionHints: ['V8 cached data/version must be confirmed with matching runtime metadata'],
  }
}

function buildHeader(
  format: string,
  data: Buffer
): { header: Record<string, unknown>; versionHints: string[] } {
  if (format === 'pyc') return parsePycHeader(data)
  if (format === 'lua-bytecode') return parseLuaHeader(data)
  if (format === 'v8-cache') return parseV8Header(data)
  return {
    header: data.length >= 16 ? { preview_hex: data.subarray(0, 16).toString('hex') } : {},
    versionHints: [],
  }
}

function decompileToolsFor(format: string): string[] {
  if (format === 'pyc') return ['metadata.extract', 'strings.extract']
  if (format === 'lua-bytecode') return ['metadata.extract', 'strings.extract']
  if (format === 'v8-cache') return ['metadata.extract', 'strings.extract']
  return ['metadata.extract', 'strings.extract']
}

export function buildBytecodeMetadataFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): BytecodeMetadataInventory {
  const { format, detectedBy } = detectBytecodeFormat(data, options.filename)
  const { header, versionHints } = buildHeader(format, data)
  const stringHints = extractAsciiStringHints(data)
  const recommendedTools = decompileToolsFor(format)

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    header,
    version_hints: versionHints,
    string_hints: stringHints,
    decompile_plan: {
      status: 'plan_only',
      recommended_tools: recommendedTools,
      notes: [
        'Choose a bytecode-specific decompiler only after confirming runtime version and provenance.',
        'This tool does not start Python, Lua, Node.js, or any decompiler.',
      ],
    },
    policy: {
      passive: true,
      no_execute: true,
      no_interpreter_start: true,
      no_decompiler_launch: true,
    },
    summary: `Passive bytecode inventory detected ${format} with ${versionHints.length} version hint(s) and ${stringHints.length} string hint(s).`,
    recommended_next_tools: recommendedTools,
    next_actions: [
      'Review header and version hints before selecting a decompiler.',
      'Extract strings and metadata to correlate module names, paths, and constants.',
      'Do not execute bytecode or start an interpreter during static triage.',
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

export function createBytecodeMetadataInspectHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (
    args: z.infer<typeof BytecodeMetadataInspectInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = BytecodeMetadataInspectInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildBytecodeMetadataFromBuffer(data, {
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
            'bytecode_metadata',
            'bytecode-metadata',
            inventory,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: metadata can still be returned without persistence.
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
