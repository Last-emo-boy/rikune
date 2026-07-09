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
const BYTECODE_METADATA_ARTIFACT_TYPE = 'bytecode_metadata'
const DEFAULT_MAX_READ_BYTES = 2 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024
const BYTECODE_METADATA_EVIDENCE = [
  'structure',
  'strings',
  'package-metadata',
  'workflow',
  'provenance',
]
const BYTECODE_METADATA_FOLLOW_UP_TOOLS = [
  'metadata.extract',
  'strings.extract',
  'analysis.evidence.graph',
  'report.generate',
]
const BYTECODE_METADATA_SAFETY = [
  'passive',
  'no_interpreter_start',
  'no_decompiler_launch',
  'no_live_sample_by_default',
]

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
  header: z.record(z.string(), z.any()),
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
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
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
    capabilities: [
      'metadata',
      'strings',
      'version-hints',
      'decompile-plan',
      'routing',
      'workflow-plan',
    ],
    evidence: BYTECODE_METADATA_EVIDENCE,
  },
  artifacts: [
    {
      type: BYTECODE_METADATA_ARTIFACT_TYPE,
      description: 'Passive script bytecode header, version hint, and string inventory',
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: [BYTECODE_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'strings',
      artifactTypes: [BYTECODE_METADATA_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [BYTECODE_METADATA_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'bytecode.passive-metadata-handoff',
      title: 'Passive bytecode metadata and decompile-plan handoff',
      description:
        'Inventory script bytecode headers, version hints, and string evidence, then route passive metadata into strings, evidence graph, and reporting follow-ups without starting interpreters or decompilers.',
      startsWith: [TOOL_NAME],
      nextTools: BYTECODE_METADATA_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [BYTECODE_METADATA_ARTIFACT_TYPE],
      evidence: BYTECODE_METADATA_EVIDENCE,
      safety: BYTECODE_METADATA_SAFETY,
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

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function buildBytecodeEvidenceSummary(input: {
  sampleId?: string
  filename?: string
  format: string
  versionHintCount: number
  stringHintCount: number
}): Record<string, unknown> {
  return {
    schema: 'rikune.bytecode_metadata.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: input.sampleId ?? null,
    filename: input.filename ?? null,
    artifact_type: BYTECODE_METADATA_ARTIFACT_TYPE,
    format: input.format,
    version_hint_count: input.versionHintCount,
    string_hint_count: input.stringHintCount,
    passive_metadata_only: true,
  }
}

function buildBytecodeWorkflowHandoff(input: {
  sampleId?: string
  format: string
  recommendedTools: string[]
}): Record<string, unknown> {
  const nextTools = uniqueStrings([...input.recommendedTools, ...BYTECODE_METADATA_FOLLOW_UP_TOOLS])
  return {
    schema: 'rikune.bytecode_metadata.workflow_handoff.v1',
    handoff_mode: 'bytecode_metadata_to_static_strings_evidence_graph_and_reporting',
    source_tool: TOOL_NAME,
    sample_id: input.sampleId ?? null,
    artifact_type: BYTECODE_METADATA_ARTIFACT_TYPE,
    format: input.format,
    recommended_next_tools: nextTools,
    artifact_contract: {
      consumes: ['sample bytes'],
      produces: [BYTECODE_METADATA_ARTIFACT_TYPE],
      expected_consumers: nextTools,
    },
    routing: [
      {
        goal: 'version-and-string-correlation',
        priority: 'normal',
        next_tools: ['metadata.extract', 'strings.extract'],
        required_evidence: [BYTECODE_METADATA_ARTIFACT_TYPE, 'bytecode header/version hints'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [BYTECODE_METADATA_ARTIFACT_TYPE],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      interpreter_started_by_tool: false,
      decompiler_launched_by_tool: false,
      runtime_started_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildBytecodeQualityGates(input: {
  format: string
  versionHintCount: number
  stringHintCount: number
}): Record<string, unknown> {
  return {
    schema: 'rikune.bytecode_metadata.quality_gates.v1',
    passive_metadata_only: true,
    format_detected: input.format !== 'unknown',
    version_hints_present: input.versionHintCount > 0,
    string_hints_present: input.stringHintCount > 0,
    sample_executed_by_tool: false,
    interpreter_started_by_tool: false,
    decompiler_launched_by_tool: false,
    runtime_started_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    analyst_review_required: true,
  }
}

export function buildBytecodeMetadataFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): BytecodeMetadataInventory {
  const { format, detectedBy } = detectBytecodeFormat(data, options.filename)
  const { header, versionHints } = buildHeader(format, data)
  const stringHints = extractAsciiStringHints(data)
  const recommendedTools = decompileToolsFor(format)
  const recommendedNextTools = uniqueStrings([
    ...recommendedTools,
    'analysis.evidence.graph',
    'report.generate',
  ])

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
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review header and version hints before selecting a decompiler.',
      'Extract strings and metadata to correlate module names, paths, and constants.',
      'Route the persisted bytecode_metadata artifact into analysis.evidence.graph before report.generate.',
      'Do not execute bytecode or start an interpreter during static triage.',
    ],
    evidence_summary: buildBytecodeEvidenceSummary({
      sampleId: options.sampleId,
      filename: options.filename,
      format,
      versionHintCount: versionHints.length,
      stringHintCount: stringHints.length,
    }),
    workflow_handoff: buildBytecodeWorkflowHandoff({
      sampleId: options.sampleId,
      format,
      recommendedTools,
    }),
    quality_gates: buildBytecodeQualityGates({
      format,
      versionHintCount: versionHints.length,
      stringHintCount: stringHints.length,
    }),
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
            BYTECODE_METADATA_ARTIFACT_TYPE,
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
