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
  no_instantiation: z.literal(true),
  no_wasi_grants: z.literal(true),
  no_network: z.literal(true),
  resource_grants: z.literal('none'),
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
  imports: z.array(
    z.object({
      module: z.string(),
      name: z.string(),
      kind: z.string(),
    })
  ),
  exports: z.array(
    z.object({
      name: z.string(),
      kind: z.string(),
      index: z.number(),
    })
  ),
  memory_declarations: z.array(z.record(z.string(), z.any())),
  table_declarations: z.array(z.record(z.string(), z.any())),
  start_function_index: z.number().nullable(),
  wasi_capability_hints: z.array(z.string()),
  capability_risk_summary: z.object({
    filesystem: z.boolean(),
    environment: z.boolean(),
    args: z.boolean(),
    clocks: z.boolean(),
    random: z.boolean(),
    sockets_or_network_like: z.boolean(),
    process_exit: z.boolean(),
    risk_level: z.enum(['none', 'low', 'medium', 'high']),
  }),
  runtime_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    handoff: z.object({
      primary_tool: z.literal('wasm.runtime.plan'),
      readiness_tool: z.literal('tool.readiness'),
      evidence_tools: z.array(z.string()),
      static_evidence_artifact_type: z.literal('wasm_structure'),
      runtime_policy: z.object({
        no_instantiation: z.literal(true),
        no_wasi_grants: z.literal(true),
        no_network: z.literal(true),
        resource_grants: z.literal('none'),
      }),
    }),
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
    formats: ['wasm', 'wasi', 'wat'],
    platforms: ['wasm', 'cross-platform'],
    architectures: ['wasm', 'wasm32'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'no_live_sample_by_default',
      'no_runtime_start',
      'no_instantiation',
      'no_wasi_grants',
      'no_resource_grants',
      'no_network_by_default',
    ],
    capabilities: [
      'structure',
      'imports',
      'exports',
      'wasi-capability-review',
      'resource-grant-review',
      'preopen-policy-review',
      'network-policy-review',
      'custom-section-inventory',
      'runtime-plan',
      'runtime-handoff',
      'workflow-routing',
    ],
    evidence: [
      'structure',
      'imports',
      'exports',
      'wasi-capability',
      'resource-grant',
      'custom-section',
      'workflow',
      'provenance',
    ],
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
    {
      category: 'imports',
      artifactTypes: ['wasm_structure'],
    },
    {
      category: 'exports',
      artifactTypes: ['wasm_structure'],
    },
    {
      category: 'wasi-capability',
      artifactTypes: ['wasm_structure'],
    },
    {
      category: 'resource-grant',
      artifactTypes: ['wasm_structure'],
    },
    {
      category: 'custom-section',
      artifactTypes: ['wasm_structure'],
    },
    {
      category: 'workflow',
      artifactTypes: ['wasm_structure'],
    },
    {
      category: 'provenance',
      artifactTypes: ['wasm_structure'],
    },
  ],
  workflowRecipes: [
    {
      id: 'wasm.static.inventory',
      title: 'WASM/WASI static structure inventory',
      description:
        'Route .wasm/.wat and WASI import/export evidence into runtime planning without instantiation, WASI preopens, resource grants, or network.',
      startsWith: [TOOL_NAME],
      nextTools: [
        'wasm.runtime.plan',
        'tool.readiness',
        'analysis.evidence.graph',
        'artifact.read',
        'strings.extract',
        'sbom.generate',
        'wabt.toolchain.plan',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: ['wasm_structure'],
      evidence: [
        'structure',
        'imports',
        'exports',
        'wasi-capability',
        'resource-grant',
        'custom-section',
        'workflow',
        'provenance',
      ],
      safety: [
        'passive',
        'no_live_sample_by_default',
        'no_runtime_start',
        'no_instantiation',
        'no_wasi_grants',
        'no_resource_grants',
        'no_network_by_default',
      ],
      runtimeBackends: ['wasmtime'],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    noInstantiation: true,
    noWasiGrants: true,
    noResourceGrants: true,
    resourceGrants: 'none',
    notes: [
      'wasm.structure.analyze is a passive static parser; it never instantiates the module.',
      'No WASI preopens, filesystem grants, resource grants, or network access are created by this tool.',
    ],
  } as ToolDefinition['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
    noInstantiation: true
    noWasiGrants: true
    noResourceGrants: true
    resourceGrants: 'none'
  },
}

export type WasmStructureInventory = z.infer<typeof WasmStructureDataSchema>
type WasmImport = WasmStructureInventory['imports'][number]
type WasmExport = WasmStructureInventory['exports'][number]

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

function skipValueType(data: Buffer, offset: number, limit: number): number | null {
  return offset < limit ? offset + 1 : null
}

function skipLimits(data: Buffer, offset: number, limit: number): number | null {
  if (offset >= limit) return null
  const flags = data[offset]
  const min = readU32Leb(data, offset + 1)
  if (!min) return null
  if ((flags & 0x01) === 0) return min.next <= limit ? min.next : null
  const max = readU32Leb(data, min.next)
  return max && max.next <= limit ? max.next : null
}

function readLimits(data: Buffer, offset: number, limit: number) {
  if (offset >= limit) return null
  const flags = data[offset]
  const min = readU32Leb(data, offset + 1)
  if (!min) return null
  if ((flags & 0x01) === 0) {
    return { min: min.value, max: null, shared: Boolean(flags & 0x02), next: min.next }
  }
  const max = readU32Leb(data, min.next)
  if (!max) return null
  return { min: min.value, max: max.value, shared: Boolean(flags & 0x02), next: max.next }
}

function skipImportDescriptor(data: Buffer, offset: number, limit: number): number | null {
  if (offset >= limit) return null
  const kind = data[offset]
  let cursor = offset + 1
  if (kind === 0) {
    const typeIndex = readU32Leb(data, cursor)
    return typeIndex && typeIndex.next <= limit ? typeIndex.next : null
  }
  if (kind === 1) {
    const elemType = skipValueType(data, cursor, limit)
    return elemType === null ? null : skipLimits(data, elemType, limit)
  }
  if (kind === 2) {
    return skipLimits(data, cursor, limit)
  }
  if (kind === 3) {
    const valueType = skipValueType(data, cursor, limit)
    if (valueType === null || valueType >= limit) return null
    return valueType + 1
  }
  return null
}

function kindName(kind: number): string {
  return ['function', 'table', 'memory', 'global'][kind] ?? `kind_${kind}`
}

function parseImportSection(data: Buffer, offset: number, limit: number): WasmImport[] {
  const count = readU32Leb(data, offset)
  if (!count || count.next > limit) return []
  const imports: WasmImport[] = []
  let cursor = count.next
  for (let index = 0; index < count.value && cursor < limit && imports.length < 500; index += 1) {
    const moduleName = readName(data, cursor, limit)
    if (!moduleName) break
    const importName = readName(data, moduleName.next, limit)
    if (!importName || importName.next >= limit) break
    const kind = data[importName.next]
    const next = skipImportDescriptor(data, importName.next, limit)
    if (next === null) break
    imports.push({
      module: moduleName.value,
      name: importName.value,
      kind: kindName(kind),
    })
    cursor = next
  }
  return imports
}

function parseExportSection(data: Buffer, offset: number, limit: number): WasmExport[] {
  const count = readU32Leb(data, offset)
  if (!count || count.next > limit) return []
  const exports: WasmExport[] = []
  let cursor = count.next
  for (let index = 0; index < count.value && cursor < limit && exports.length < 500; index += 1) {
    const exportName = readName(data, cursor, limit)
    if (!exportName || exportName.next >= limit) break
    const kind = data[exportName.next]
    const itemIndex = readU32Leb(data, exportName.next + 1)
    if (!itemIndex) break
    exports.push({
      name: exportName.value,
      kind: kindName(kind),
      index: itemIndex.value,
    })
    cursor = itemIndex.next
  }
  return exports
}

function parseMemorySection(data: Buffer, offset: number, limit: number) {
  const count = readU32Leb(data, offset)
  if (!count || count.next > limit) return []
  const memories: Array<Record<string, unknown>> = []
  let cursor = count.next
  for (let index = 0; index < count.value && cursor < limit && memories.length < 100; index += 1) {
    const limits = readLimits(data, cursor, limit)
    if (!limits) break
    memories.push({ min_pages: limits.min, max_pages: limits.max, shared: limits.shared })
    cursor = limits.next
  }
  return memories
}

function parseTableSection(data: Buffer, offset: number, limit: number) {
  const count = readU32Leb(data, offset)
  if (!count || count.next > limit) return []
  const tables: Array<Record<string, unknown>> = []
  let cursor = count.next
  for (let index = 0; index < count.value && cursor < limit && tables.length < 100; index += 1) {
    if (cursor >= limit) break
    const elementType = data[cursor]
    const limits = readLimits(data, cursor + 1, limit)
    if (!limits) break
    tables.push({
      element_type: `0x${elementType.toString(16)}`,
      min: limits.min,
      max: limits.max,
      shared: limits.shared,
    })
    cursor = limits.next
  }
  return tables
}

function classifyWasiCapabilities(imports: WasmImport[], textHints: string[]): string[] {
  const hints = new Set<string>(textHints)
  for (const item of imports) {
    const name = `${item.module}.${item.name}`
    if (/wasi_snapshot_preview1|wasi_unstable/.test(item.module)) hints.add(item.module)
    if (/fd_|path_|prestat_/.test(item.name)) hints.add('filesystem')
    if (/environ/.test(item.name)) hints.add('environment')
    if (/args_/.test(item.name)) hints.add('args')
    if (/clock_/.test(item.name)) hints.add('clocks')
    if (/random_get/.test(item.name)) hints.add('random')
    if (/sock_|network|http/.test(name)) hints.add('sockets_or_network_like')
    if (/proc_exit/.test(item.name)) hints.add('process_exit')
  }
  return Array.from(hints).sort()
}

function capabilityRiskSummary(hints: string[]): WasmStructureInventory['capability_risk_summary'] {
  const has = (value: string) => hints.includes(value)
  const filesystem = has('filesystem') || hints.some((hint) => /fd_|path_|prestat_/.test(hint))
  const environment = has('environment') || hints.some((hint) => /environ/.test(hint))
  const args = has('args') || hints.some((hint) => /args_/.test(hint))
  const clocks = has('clocks') || hints.some((hint) => /clock_/.test(hint))
  const random = has('random') || hints.some((hint) => /random_get/.test(hint))
  const socketsOrNetwork =
    has('sockets_or_network_like') || hints.some((hint) => /sock_|network|http/.test(hint))
  const processExit = has('process_exit') || hints.some((hint) => /proc_exit/.test(hint))
  const score = [
    filesystem,
    environment,
    args,
    clocks,
    random,
    socketsOrNetwork,
    processExit,
  ].filter(Boolean).length
  const riskLevel =
    socketsOrNetwork || score >= 4
      ? 'high'
      : filesystem || score >= 2
        ? 'medium'
        : score > 0
          ? 'low'
          : 'none'
  return {
    filesystem,
    environment,
    args,
    clocks,
    random,
    sockets_or_network_like: socketsOrNetwork,
    process_exit: processExit,
    risk_level: riskLevel,
  }
}

function parseSections(data: Buffer): {
  sections: WasmStructureInventory['sections']
  customSections: string[]
  importCountHint: number
  exportCountHint: number
  wasiHints: string[]
  imports: WasmImport[]
  exports: WasmExport[]
  memoryDeclarations: Array<Record<string, unknown>>
  tableDeclarations: Array<Record<string, unknown>>
  startFunctionIndex: number | null
} {
  const sections: WasmStructureInventory['sections'] = []
  const customSections: string[] = []
  const wasiHints = new Set<string>()
  const imports: WasmImport[] = []
  const exports: WasmExport[] = []
  const memoryDeclarations: Array<Record<string, unknown>> = []
  const tableDeclarations: Array<Record<string, unknown>> = []
  let startFunctionIndex: number | null = null
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
      imports.push(...parseImportSection(data, payloadStart, payloadEnd))
      const text = data.subarray(payloadStart, payloadEnd).toString('latin1')
      for (const hint of ['wasi_snapshot_preview1', 'wasi_unstable', 'fd_', 'path_', 'sock_']) {
        if (text.includes(hint)) wasiHints.add(hint)
      }
    } else if (id === 4) {
      tableDeclarations.push(...parseTableSection(data, payloadStart, payloadEnd))
    } else if (id === 5) {
      memoryDeclarations.push(...parseMemorySection(data, payloadStart, payloadEnd))
    } else if (id === 7) {
      exportCountHint = countVectorItems(data, payloadStart, payloadEnd)
      exports.push(...parseExportSection(data, payloadStart, payloadEnd))
    } else if (id === 8) {
      startFunctionIndex = readU32Leb(data, payloadStart)?.value ?? null
    }

    offset = payloadEnd
  }

  return {
    sections,
    customSections,
    importCountHint,
    exportCountHint,
    wasiHints: classifyWasiCapabilities(imports, Array.from(wasiHints)),
    imports,
    exports,
    memoryDeclarations,
    tableDeclarations,
    startFunctionIndex,
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
    : {
        sections: [],
        customSections: [],
        importCountHint: 0,
        exportCountHint: 0,
        wasiHints: [],
        imports: [],
        exports: [],
        memoryDeclarations: [],
        tableDeclarations: [],
        startFunctionIndex: null,
      }
  const capabilitySummary = capabilityRiskSummary(parsed.wasiHints)

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
    imports: parsed.imports,
    exports: parsed.exports,
    memory_declarations: parsed.memoryDeclarations,
    table_declarations: parsed.tableDeclarations,
    start_function_index: parsed.startFunctionIndex,
    wasi_capability_hints: parsed.wasiHints,
    capability_risk_summary: capabilitySummary,
    runtime_plan: {
      status: 'plan_only',
      recommended_tools: [
        'wasm.runtime.plan',
        'tool.readiness',
        'analysis.evidence.graph',
        'artifact.read',
        'metadata.extract',
        'strings.extract',
        'sbom.generate',
        'wabt.toolchain.plan',
      ],
      handoff: {
        primary_tool: 'wasm.runtime.plan',
        readiness_tool: 'tool.readiness',
        evidence_tools: ['analysis.evidence.graph', 'artifact.read'],
        static_evidence_artifact_type: 'wasm_structure',
        runtime_policy: {
          no_instantiation: true,
          no_wasi_grants: true,
          no_network: true,
          resource_grants: 'none',
        },
      },
      notes: [
        'Use a runtime-gated WASM/WASI backend only after reviewing imports and capabilities.',
        'This tool does not instantiate the module or start wasmtime.',
        'No WASI preopens, filesystem grants, resource grants, or network access are created.',
        `Capability risk level: ${capabilitySummary.risk_level}.`,
      ],
    },
    policy: {
      passive: true,
      no_execute: true,
      no_runtime_start: true,
      no_instantiation: true,
      no_wasi_grants: true,
      no_network: true,
      resource_grants: 'none',
    },
    summary: validMagic
      ? `Passive WASM inventory found ${parsed.sections.length} section(s), ${parsed.importCountHint} import hint(s), ${parsed.exportCountHint} export hint(s), and ${parsed.wasiHints.length} WASI capability hint(s).`
      : 'Input does not contain a valid WASM magic header in the inspected preview.',
    recommended_next_tools: [
      'wasm.runtime.plan',
      'tool.readiness',
      'analysis.evidence.graph',
      'artifact.read',
      'metadata.extract',
      'strings.extract',
      'sbom.generate',
      'wabt.toolchain.plan',
    ],
    next_actions: [
      'Review import and WASI capability hints before selecting a runtime backend.',
      'Do not instantiate the WASM module during static triage.',
      'Keep WASI preopens, resource grants, and network disabled until an explicit runtime plan is approved.',
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
