/**
 * windows.debug.metadata.inspect — passive PDB/COFF metadata inventory.
 *
 * This tool does not contact symbol servers, download source files, or execute
 * object code.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'windows.debug.metadata.inspect'
const DEFAULT_MAX_READ_BYTES = 2 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024

const WindowsDebugPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_symbol_server_download: z.literal(true),
  no_source_fetch: z.literal(true),
})

const WindowsDebugMetadataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  header: z.record(z.any()),
  symbol_hints: z.array(z.string()),
  source_path_hints: z.array(z.string()),
  object_members: z.array(z.string()),
  source_map_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    notes: z.array(z.string()),
  }),
  policy: WindowsDebugPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const WindowsDebugMetadataInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive PDB/COFF metadata inspection.'),
  persist_artifact: z.boolean().default(true).describe('Persist debug metadata JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const WindowsDebugMetadataInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: WindowsDebugMetadataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const windowsDebugMetadataInspectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inspect PDB, COFF object, and COFF library metadata without contacting symbol servers.',
  inputSchema: WindowsDebugMetadataInspectInputSchema,
  outputSchema: WindowsDebugMetadataInspectOutputSchema,
  aspects: {
    formats: ['pdb', 'coff', 'coff-lib'],
    platforms: ['windows'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['metadata', 'symbols', 'source-map-plan', 'routing'],
    evidence: ['symbols', 'provenance'],
  },
  artifacts: [
    {
      type: 'windows_debug_metadata',
      description: 'Passive PDB/COFF metadata, symbol hint, and source-map plan inventory',
    },
  ],
  evidence: [
    {
      category: 'symbols',
      artifactTypes: ['windows_debug_metadata'],
    },
  ],
}

export type WindowsDebugMetadataInventory = z.infer<typeof WindowsDebugMetadataSchema>

const COFF_MACHINES: Record<number, string> = {
  0x014c: 'x86',
  0x8664: 'x64',
  0x01c0: 'arm',
  0xaa64: 'arm64',
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function isPdbMsf(data: Buffer): boolean {
  return (
    data.length >= 24 && data.subarray(0, 24).toString('ascii').startsWith('Microsoft C/C++ MSF')
  )
}

function isArArchive(data: Buffer): boolean {
  return data.length >= 8 && data.subarray(0, 8).toString('ascii') === '!<arch>\n'
}

function detectDebugFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  if (isPdbMsf(data)) return { format: 'pdb', detectedBy: ['PDB MSF magic'] }
  if (isArArchive(data) && ext === 'lib')
    return { format: 'coff-lib', detectedBy: ['ar magic', 'filename extension'] }
  if (ext === 'pdb') return { format: 'pdb', detectedBy: ['filename extension'] }
  if (ext === 'obj') return { format: 'coff', detectedBy: ['filename extension'] }
  if (ext === 'lib') return { format: 'coff-lib', detectedBy: ['filename extension'] }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function parseArMembers(data: Buffer): string[] {
  if (!isArArchive(data)) return []
  const members: string[] = []
  let offset = 8
  while (offset + 60 <= data.length && members.length < 300) {
    const header = data.subarray(offset, offset + 60).toString('latin1')
    const name = header.slice(0, 16).trim().replace(/\/$/, '')
    const size = Number.parseInt(header.slice(48, 58).trim(), 10)
    if (!name || !Number.isFinite(size) || size < 0) break
    members.push(name)
    offset += 60 + size + (size % 2)
  }
  return members
}

function parseHeader(format: string, data: Buffer): Record<string, unknown> {
  if (format === 'pdb') {
    const header: Record<string, unknown> = {
      magic: data.subarray(0, Math.min(32, data.length)).toString('latin1').replace(/\0/g, ''),
    }
    if (data.length >= 56 && isPdbMsf(data)) {
      header.page_size = data.readUInt32LE(32)
      header.free_page_map = data.readUInt32LE(36)
      header.page_count = data.readUInt32LE(40)
      header.directory_size = data.readUInt32LE(44)
    }
    return header
  }

  if (format === 'coff' && data.length >= 20) {
    const machine = data.readUInt16LE(0)
    return {
      machine,
      architecture_hint: COFF_MACHINES[machine] ?? 'unknown',
      section_count: data.readUInt16LE(2),
      timestamp: data.readUInt32LE(4),
      symbol_table_offset: data.readUInt32LE(8),
      symbol_count: data.readUInt32LE(12),
      optional_header_size: data.readUInt16LE(16),
      characteristics: data.readUInt16LE(18),
    }
  }

  if (format === 'coff-lib') {
    return {
      archive_magic: isArArchive(data) ? '!<arch>' : undefined,
      member_count_hint: parseArMembers(data).length,
    }
  }

  return data.length >= 16 ? { preview_hex: data.subarray(0, 16).toString('hex') } : {}
}

function extractStringHints(data: Buffer): { symbols: string[]; sources: string[] } {
  const text = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
  const matches = text.match(/[A-Za-z_?$@][A-Za-z0-9_?$@./:\\-]{3,200}/g) ?? []
  const symbols = new Set<string>()
  const sources = new Set<string>()
  for (const item of matches) {
    const lower = item.toLowerCase()
    if (/\.(?:c|cc|cpp|cxx|h|hpp|cs|pdb|obj|lib)$/.test(lower) || /[a-z]:\\/.test(lower)) {
      sources.add(item)
    } else if (
      item.includes('?') ||
      item.includes('@') ||
      item.includes('::') ||
      item.startsWith('_')
    ) {
      symbols.add(item)
    }
  }
  return {
    symbols: Array.from(symbols).slice(0, 100),
    sources: Array.from(sources).slice(0, 100),
  }
}

export function buildWindowsDebugMetadataFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): WindowsDebugMetadataInventory {
  const { format, detectedBy } = detectDebugFormat(data, options.filename)
  const header = parseHeader(format, data)
  const objectMembers = parseArMembers(data)
  const { symbols, sources } = extractStringHints(data)

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    header,
    symbol_hints: symbols,
    source_path_hints: sources,
    object_members: objectMembers,
    source_map_plan: {
      status: 'plan_only',
      recommended_tools: ['metadata.extract', 'strings.extract'],
      notes: [
        'Use explicit opt-in tooling before downloading symbols or resolving source links.',
        'This tool does not contact symbol servers or fetch source files.',
      ],
    },
    policy: {
      passive: true,
      no_execute: true,
      no_symbol_server_download: true,
      no_source_fetch: true,
    },
    summary: `Passive Windows debug metadata inventory detected ${format} with ${symbols.length} symbol hint(s), ${sources.length} source path hint(s), and ${objectMembers.length} object member hint(s).`,
    recommended_next_tools: ['metadata.extract', 'strings.extract'],
    next_actions: [
      'Review symbol and source path hints before opting into symbol server workflows.',
      'Correlate PDB/COFF metadata with PE debug directory output when available.',
      'Do not fetch symbols or source files during default static triage.',
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

export function createWindowsDebugMetadataInspectHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (
    args: z.infer<typeof WindowsDebugMetadataInspectInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = WindowsDebugMetadataInspectInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildWindowsDebugMetadataFromBuffer(data, {
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
            'windows_debug_metadata',
            'windows-debug-metadata',
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
