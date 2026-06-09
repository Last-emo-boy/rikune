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
import {
  WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE,
  WINDOWS_DEBUG_METADATA_EVIDENCE_SUMMARY_SCHEMA,
  WINDOWS_DEBUG_METADATA_QUALITY_GATES_SCHEMA,
  WINDOWS_DEBUG_METADATA_RUNTIME_POLICY,
  WINDOWS_DEBUG_METADATA_TOOL_NAME,
  WINDOWS_DEBUG_METADATA_WORKFLOW_HANDOFF_SCHEMA,
  buildWindowsDebugMetadataEnvelope,
  windowsDebugMetadataAspects,
  windowsDebugMetadataRecipe,
  windowsDebugMetadataRecommendedNextTools,
} from '../windows-debug-symbols-metadata.js'

const TOOL_NAME = WINDOWS_DEBUG_METADATA_TOOL_NAME
const DEFAULT_MAX_READ_BYTES = 2 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024

const WindowsDebugPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_network: z.literal(true),
  no_symbol_server_download: z.literal(true),
  no_source_fetch: z.literal(true),
  no_mutation: z.literal(true),
})

const PdbIdentityHintSchema = z.object({
  kind: z.enum(['RSDS', 'NB10']),
  offset: z.number(),
  age: z.number().optional(),
  guid: z.string().optional(),
  signature: z.string().optional(),
  pdb_path: z.string().optional(),
})

const CoffSymbolTableSchema = z.object({
  offset: z.number(),
  count: z.number(),
  string_table_present: z.boolean(),
  truncated: z.boolean(),
})

const SourcePathProfileSchema = z.object({
  total: z.number(),
  windows_paths: z.number(),
  unc_paths: z.number(),
  relative_paths: z.number(),
  source_index_markers: z.number(),
  possible_sensitive_paths: z.number(),
  redacted_examples: z.array(z.string()),
})

const PreviewProfileSchema = z.object({
  bytes_read: z.number(),
  size: z.number(),
  truncated: z.boolean(),
  max_read_bytes: z.number(),
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
  pdb_identity_hints: z.array(PdbIdentityHintSchema),
  codeview_markers: z.array(z.string()),
  coff_symbol_table: CoffSymbolTableSchema.optional(),
  source_path_profile: SourcePathProfileSchema,
  preview_profile: PreviewProfileSchema,
  source_map_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    notes: z.array(z.string()),
  }),
  policy: WindowsDebugPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z
    .object({
      schema: z.literal(WINDOWS_DEBUG_METADATA_EVIDENCE_SUMMARY_SCHEMA),
      source_tool: z.literal(TOOL_NAME),
      artifact_type: z.literal(WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE),
    })
    .passthrough()
    .optional(),
  workflow_handoff: z
    .object({
      schema: z.literal(WINDOWS_DEBUG_METADATA_WORKFLOW_HANDOFF_SCHEMA),
      artifact_contract: z.record(z.any()),
      dynamic_boundary: z
        .object({
          sample_execution_allowed: z.literal(false),
          symbol_server_download_allowed: z.literal(false),
          source_fetch_allowed: z.literal(false),
          network_allowed: z.literal(false),
          mutation_allowed: z.literal(false),
          sample_executed_by_tool: z.literal(false),
          symbol_server_contacted: z.literal(false),
          source_fetched: z.literal(false),
          network_used_by_tool: z.literal(false),
          mutation_performed: z.literal(false),
        })
        .passthrough(),
      routing: z.array(z.record(z.any())),
    })
    .passthrough()
    .optional(),
  quality_gates: z
    .object({
      schema: z.literal(WINDOWS_DEBUG_METADATA_QUALITY_GATES_SCHEMA),
      passive_static_inventory: z.literal(true),
      sample_executed_by_tool: z.literal(false),
      symbol_server_contacted: z.literal(false),
      source_fetched: z.literal(false),
      network_used_by_tool: z.literal(false),
      mutation_performed: z.literal(false),
    })
    .passthrough()
    .optional(),
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
    'Passively inspect PDB, COFF object/library, CodeView, DWARF sidecar, and generic debug metadata without contacting symbol servers.',
  inputSchema: WindowsDebugMetadataInspectInputSchema,
  outputSchema: WindowsDebugMetadataInspectOutputSchema,
  aspects: windowsDebugMetadataAspects(),
  artifacts: [
    {
      type: WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE,
      description:
        'Passive PDB/COFF/CodeView/debug metadata, symbol hint, source path, object member, and source-map plan inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'symbols',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'debug-metadata',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'pdb-identity',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'codeview',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'coff-symbols',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'source-map',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'source-paths',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'object-members',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [windowsDebugMetadataRecipe()],
  runtimePolicy: WINDOWS_DEBUG_METADATA_RUNTIME_POLICY,
}

export type WindowsDebugMetadataInventory = z.infer<typeof WindowsDebugMetadataSchema>
type WindowsDebugMetadataInventoryBase = Omit<
  WindowsDebugMetadataInventory,
  'evidence_summary' | 'workflow_handoff' | 'quality_gates'
>

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

function markerOffsets(data: Buffer, marker: string): number[] {
  const offsets: number[] = []
  let offset = 0
  while (offset < data.length && offsets.length < 50) {
    const found = data.indexOf(marker, offset, 'ascii')
    if (found < 0) break
    offsets.push(found)
    offset = found + marker.length
  }
  return offsets
}

function readCString(data: Buffer, offset: number, maxLength = 260): string | undefined {
  if (offset < 0 || offset >= data.length) return undefined
  const end = Math.min(data.length, offset + maxLength)
  let cursor = offset
  while (cursor < end && data[cursor] !== 0) cursor += 1
  const value = data.subarray(offset, cursor).toString('latin1').trim()
  return value.length > 0 ? value : undefined
}

function hex(value: number, width: number): string {
  return value.toString(16).padStart(width, '0')
}

function formatRsdsGuid(data: Buffer, offset: number): string | undefined {
  if (offset + 16 > data.length) return undefined
  const part1 = hex(data.readUInt32LE(offset), 8)
  const part2 = hex(data.readUInt16LE(offset + 4), 4)
  const part3 = hex(data.readUInt16LE(offset + 6), 4)
  const part4 = data.subarray(offset + 8, offset + 10).toString('hex')
  const part5 = data.subarray(offset + 10, offset + 16).toString('hex')
  return `${part1}-${part2}-${part3}-${part4}-${part5}`
}

function extractPdbIdentityHints(data: Buffer) {
  const hints: WindowsDebugMetadataInventoryBase['pdb_identity_hints'] = []

  for (const offset of markerOffsets(data, 'RSDS')) {
    if (offset + 24 > data.length) continue
    hints.push({
      kind: 'RSDS',
      offset,
      guid: formatRsdsGuid(data, offset + 4),
      age: data.readUInt32LE(offset + 20),
      pdb_path: readCString(data, offset + 24),
    })
  }

  for (const offset of markerOffsets(data, 'NB10')) {
    if (offset + 16 > data.length) continue
    hints.push({
      kind: 'NB10',
      offset,
      signature: hex(data.readUInt32LE(offset + 8), 8),
      age: data.readUInt32LE(offset + 12),
      pdb_path: readCString(data, offset + 16),
    })
  }

  return hints.slice(0, 20)
}

function extractCodeViewMarkers(data: Buffer): string[] {
  return Array.from(
    new Set([
      ...markerOffsets(data, 'RSDS').map((offset) => `RSDS@0x${offset.toString(16)}`),
      ...markerOffsets(data, 'NB10').map((offset) => `NB10@0x${offset.toString(16)}`),
    ])
  ).slice(0, 50)
}

function numberFromHeader(header: Record<string, unknown>, key: string): number | undefined {
  const value = header[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function extractCoffSymbolTable(
  format: string,
  header: Record<string, unknown>,
  data: Buffer
): WindowsDebugMetadataInventoryBase['coff_symbol_table'] {
  if (format !== 'coff') return undefined
  const offset = numberFromHeader(header, 'symbol_table_offset') ?? 0
  const count = numberFromHeader(header, 'symbol_count') ?? 0
  if (offset <= 0 || count <= 0) return undefined
  const tableEnd = offset + count * 18
  const stringTableSize = tableEnd + 4 <= data.length ? data.readUInt32LE(tableEnd) : undefined
  return {
    offset,
    count,
    string_table_present: typeof stringTableSize === 'number' && stringTableSize > 4,
    truncated: tableEnd + 4 > data.length,
  }
}

function redactSourcePath(value: string): string {
  return value
    .replace(/^([A-Za-z]:\\)(?:Users|Documents and Settings)\\[^\\]+/i, '$1Users\\<user>')
    .replace(/^\\\\[^\\]+\\[^\\]+/, '\\\\<server>\\<share>')
}

function buildSourcePathProfile(
  sourcePathHints: string[],
  data: Buffer
): WindowsDebugMetadataInventoryBase['source_path_profile'] {
  const text = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
  const windowsPaths = sourcePathHints.filter((item) => /^[A-Za-z]:\\/.test(item))
  const uncPaths = sourcePathHints.filter((item) => /^\\\\/.test(item))
  const relativePaths = sourcePathHints.filter(
    (item) => !/^[A-Za-z]:\\/.test(item) && !/^\\\\/.test(item) && /[\\/]/.test(item)
  )
  const sensitive = sourcePathHints.filter((item) =>
    /(?:\\|\/)(?:users|documents and settings|desktop|downloads)(?:\\|\/)/i.test(item)
  )

  return {
    total: sourcePathHints.length,
    windows_paths: windowsPaths.length,
    unc_paths: uncPaths.length,
    relative_paths: relativePaths.length,
    source_index_markers: (text.match(/SRCSRV|srcsrv|source server/g) ?? []).length,
    possible_sensitive_paths: sensitive.length,
    redacted_examples: sourcePathHints.slice(0, 12).map(redactSourcePath),
  }
}

export function buildWindowsDebugMetadataFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string; maxReadBytes?: number } = {}
): WindowsDebugMetadataInventory {
  const { format, detectedBy } = detectDebugFormat(data, options.filename)
  const header = parseHeader(format, data)
  const objectMembers = parseArMembers(data)
  const { symbols, sources } = extractStringHints(data)
  const pdbIdentityHints = extractPdbIdentityHints(data)
  const codeviewMarkers = extractCodeViewMarkers(data)
  const coffSymbolTable = extractCoffSymbolTable(format, header, data)
  const sourcePathProfile = buildSourcePathProfile(sources, data)
  const previewProfile = {
    bytes_read: data.length,
    size: options.size ?? data.length,
    truncated: (options.size ?? data.length) > data.length,
    max_read_bytes: options.maxReadBytes ?? data.length,
  }

  const inventoryBase: WindowsDebugMetadataInventoryBase = {
    sample_id: options.sampleId,
    filename: options.filename,
    format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    header,
    symbol_hints: symbols,
    source_path_hints: sources,
    object_members: objectMembers,
    pdb_identity_hints: pdbIdentityHints,
    codeview_markers: codeviewMarkers,
    coff_symbol_table: coffSymbolTable,
    source_path_profile: sourcePathProfile,
    preview_profile: previewProfile,
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
      no_network: true,
      no_symbol_server_download: true,
      no_source_fetch: true,
      no_mutation: true,
    },
    summary: `Passive Windows debug metadata inventory detected ${format} with ${symbols.length} symbol hint(s), ${sources.length} source path hint(s), ${objectMembers.length} object member hint(s), and ${pdbIdentityHints.length} PDB identity hint(s).`,
    recommended_next_tools: windowsDebugMetadataRecommendedNextTools({
      format,
      symbol_hints: symbols,
      source_path_hints: sources,
      object_members: objectMembers,
      pdb_identity_hints: pdbIdentityHints,
      codeview_markers: codeviewMarkers,
      coff_symbol_table: coffSymbolTable,
    }),
    next_actions: [
      'Review symbol and source path hints before opting into symbol server workflows.',
      'Correlate PDB/COFF metadata with PE debug directory output when available.',
      'Do not fetch symbols or source files during default static triage.',
    ],
  }

  return {
    ...inventoryBase,
    ...buildWindowsDebugMetadataEnvelope(inventoryBase),
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
        maxReadBytes: input.max_read_bytes,
      })

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
        try {
          const artifact = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE,
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
