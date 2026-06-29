/**
 * wasm.component.inventory - passive WebAssembly Component Model inventory.
 *
 * This parser only reads bounded bytes and section framing. It does not call
 * wasm-tools, instantiate components, start wasmtime, grant WASI resources, or fetch packages.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'wasm.component.inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024
const MAX_SECTIONS = 300
const MAX_IMPORT_EXPORTS = 300
const MAX_STRINGS = 600

const COMPONENT_SECTION_NAMES: Record<number, string> = {
  0: 'custom',
  1: 'core_module',
  2: 'core_instance',
  3: 'core_type',
  4: 'component',
  5: 'instance',
  6: 'alias',
  7: 'type',
  8: 'canonical',
  9: 'start',
  10: 'import',
  11: 'export',
  12: 'value',
}

const COMPONENT_SORT_NAMES: Record<number, string> = {
  1: 'func',
  2: 'value',
  3: 'type',
  4: 'component',
  5: 'instance',
}

const CORE_SORT_NAMES: Record<number, string> = {
  0: 'core:func',
  1: 'core:table',
  2: 'core:memory',
  3: 'core:global',
  4: 'core:tag',
  16: 'core:type',
  17: 'core:module',
  18: 'core:instance',
}

const WasmComponentPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_runtime_start: z.literal(true),
  no_instantiation: z.literal(true),
  no_wasi_grants: z.literal(true),
  no_external_tool: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
  resource_grants: z.literal('none'),
})

const WasmComponentInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.literal('wasm-component'),
  valid_magic: z.boolean(),
  component_preamble: z.object({
    version_field: z.number().nullable(),
    layer_field: z.number().nullable(),
    is_component: z.boolean(),
    is_core_module_layer: z.boolean(),
  }),
  sections: z.array(
    z.object({
      id: z.number(),
      name: z.string(),
      offset: z.number(),
      size: z.number(),
      count_hint: z.number().nullable(),
    })
  ),
  section_counts: z.record(z.string(), z.number()),
  custom_sections: z.array(z.string()),
  imports: z.array(
    z.object({
      name: z.string(),
      kind_hint: z.string(),
      namespace_hint: z.string().nullable(),
    })
  ),
  exports: z.array(
    z.object({
      name: z.string(),
      kind_hint: z.string(),
      index: z.number().nullable(),
      namespace_hint: z.string().nullable(),
    })
  ),
  nested_component_count: z.number(),
  embedded_core_module_count: z.number(),
  canonical_abi_definition_count: z.number(),
  start_definition_count: z.number(),
  value_definition_count: z.number(),
  wit_package_hints: z.array(z.string()),
  wasi_capability_hints: z.array(z.string()),
  component_model_hints: z.array(z.string()),
  capability_risk_summary: z.object({
    filesystem: z.boolean(),
    environment: z.boolean(),
    cli: z.boolean(),
    clocks: z.boolean(),
    random: z.boolean(),
    sockets_or_network_like: z.boolean(),
    http: z.boolean(),
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
      static_evidence_artifact_type: z.literal('wasm_component_inventory'),
      runtime_policy: z.object({
        no_instantiation: z.literal(true),
        no_wasi_grants: z.literal(true),
        no_network: z.literal(true),
        resource_grants: z.literal('none'),
      }),
    }),
    notes: z.array(z.string()),
  }),
  policy: WasmComponentPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const WasmComponentInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive component inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist component inventory JSON.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const WasmComponentInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: WasmComponentInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const wasmComponentInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory WebAssembly Component Model binaries, WIT/WASI Preview 2 hints, component imports/exports, and Canonical ABI evidence without external tools or instantiation.',
  inputSchema: WasmComponentInventoryInputSchema,
  outputSchema: WasmComponentInventoryOutputSchema,
  aspects: {
    formats: ['wasm-component', 'component-model', 'wit-component', 'wasi-preview2'],
    platforms: ['wasm', 'wasi', 'cross-platform'],
    architectures: ['wasm', 'component-model'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'no_runtime_start',
      'no_instantiation',
      'no_wasi_grants',
      'no_resource_grants',
      'no_external_tool',
      'no_network_by_default',
      'no_mutation',
    ],
    capabilities: [
      'component-model-inventory',
      'wit-interface-hints',
      'wasi-preview2-capability-review',
      'canonical-abi-summary',
      'component-section-inventory',
      'component-import-export-inventory',
      'runtime-handoff',
      'workflow-routing',
    ],
    evidence: [
      'structure',
      'imports',
      'exports',
      'wasi-capability',
      'wit-interface',
      'canonical-abi',
      'custom-section',
      'workflow',
      'provenance',
    ],
  },
  artifacts: [
    {
      type: 'wasm_component_inventory',
      description: 'Passive WebAssembly Component Model structure, WIT/WASI, and ABI inventory',
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: ['wasm_component_inventory'] },
    { category: 'imports', artifactTypes: ['wasm_component_inventory'] },
    { category: 'exports', artifactTypes: ['wasm_component_inventory'] },
    { category: 'wasi-capability', artifactTypes: ['wasm_component_inventory'] },
    { category: 'wit-interface', artifactTypes: ['wasm_component_inventory'] },
    { category: 'canonical-abi', artifactTypes: ['wasm_component_inventory'] },
    { category: 'custom-section', artifactTypes: ['wasm_component_inventory'] },
    { category: 'workflow', artifactTypes: ['wasm_component_inventory'] },
    { category: 'provenance', artifactTypes: ['wasm_component_inventory'] },
  ],
  workflowRecipes: [
    {
      id: 'wasm.component-static-inventory',
      title: 'WebAssembly Component Model static inventory',
      description:
        'Route Component Model and WIT/WASI Preview 2 evidence into runtime planning without instantiation, WASI grants, network, or external tool execution.',
      startsWith: [TOOL_NAME],
      nextTools: [
        'wasm.structure.analyze',
        'wasm.runtime.plan',
        'wabt.toolchain.plan',
        'analysis.evidence.graph',
        'artifact.read',
        'strings.extract',
        'sbom.generate',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: ['wasm_component_inventory'],
      evidence: [
        'structure',
        'imports',
        'exports',
        'wasi-capability',
        'wit-interface',
        'canonical-abi',
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
        'no_external_tool',
        'no_network_by_default',
      ],
    },
  ],
}

export type WasmComponentInventory = z.infer<typeof WasmComponentInventorySchema>
type ComponentImport = WasmComponentInventory['imports'][number]
type ComponentExport = WasmComponentInventory['exports'][number]

function readU32Leb(data: Buffer, offset: number): { value: number; next: number } | null {
  let result = 0
  let shift = 0
  let cursor = offset

  while (cursor < data.length && shift <= 28) {
    const byte = data[cursor]
    result |= (byte & 0x7f) << shift
    cursor += 1
    if ((byte & 0x80) === 0) return { value: result >>> 0, next: cursor }
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

function readExternName(
  data: Buffer,
  offset: number,
  limit: number
): { value: string; next: number; namespaceHint: string | null } | null {
  if (offset >= limit) return null
  const discriminator = data[offset]

  if (discriminator === 0 || discriminator === 1 || discriminator === 2) {
    const name = readName(data, offset + 1, limit)
    if (!name) return null
    let cursor = name.next
    if (discriminator === 2) {
      const optionCount = readU32Leb(data, cursor)
      if (!optionCount) return null
      cursor = optionCount.next
      for (let i = 0; i < optionCount.value && cursor < limit; i += 1) {
        cursor += 1
        const optionName = readName(data, cursor, limit)
        if (!optionName) return null
        cursor = optionName.next
      }
    }
    return {
      value: name.value,
      next: cursor,
      namespaceHint:
        discriminator === 0 ? 'plain' : discriminator === 1 ? 'interface' : 'annotated',
    }
  }

  const fallback = readName(data, offset, limit)
  return fallback ? { ...fallback, namespaceHint: null } : null
}

function readSortIdx(
  data: Buffer,
  offset: number,
  limit: number
): { kind: string; index: number | null; next: number } | null {
  if (offset >= limit) return null
  const sort = data[offset]
  if (sort === 0) {
    if (offset + 1 >= limit) return null
    const coreSort = data[offset + 1]
    const index = readU32Leb(data, offset + 2)
    if (!index || index.next > limit) return null
    return {
      kind: CORE_SORT_NAMES[coreSort] ?? `core:sort_${coreSort}`,
      index: index.value,
      next: index.next,
    }
  }

  const index = readU32Leb(data, offset + 1)
  if (!index || index.next > limit) return null
  return {
    kind: COMPONENT_SORT_NAMES[sort] ?? `sort_${sort}`,
    index: index.value,
    next: index.next,
  }
}

function readExternalDescHint(
  data: Buffer,
  offset: number,
  limit: number
): { kind: string; next: number } | null {
  const sort = readSortIdx(data, offset, limit)
  if (sort) return { kind: sort.kind, next: sort.next }
  if (offset >= limit) return null
  const tag = data[offset]
  const value = readU32Leb(data, offset + 1)
  if (!value || value.next > limit) return null
  return { kind: COMPONENT_SORT_NAMES[tag] ?? `descriptor_${tag}`, next: value.next }
}

function parseComponentImports(data: Buffer, offset: number, limit: number): ComponentImport[] {
  const count = readU32Leb(data, offset)
  if (!count || count.next > limit) return []
  const imports: ComponentImport[] = []
  let cursor = count.next
  for (
    let index = 0;
    index < count.value && cursor < limit && imports.length < MAX_IMPORT_EXPORTS;
    index += 1
  ) {
    const name = readExternName(data, cursor, limit)
    if (!name) break
    const desc = readExternalDescHint(data, name.next, limit)
    imports.push({
      name: name.value,
      kind_hint: desc?.kind ?? 'unknown',
      namespace_hint: name.namespaceHint,
    })
    cursor = desc?.next ?? name.next
  }
  return imports
}

function parseComponentExports(data: Buffer, offset: number, limit: number): ComponentExport[] {
  const count = readU32Leb(data, offset)
  if (!count || count.next > limit) return []
  const exports: ComponentExport[] = []
  let cursor = count.next
  for (
    let index = 0;
    index < count.value && cursor < limit && exports.length < MAX_IMPORT_EXPORTS;
    index += 1
  ) {
    const name = readExternName(data, cursor, limit)
    if (!name) break
    const sort = readSortIdx(data, name.next, limit)
    exports.push({
      name: name.value,
      kind_hint: sort?.kind ?? 'unknown',
      index: sort?.index ?? null,
      namespace_hint: name.namespaceHint,
    })
    cursor = sort?.next ?? name.next
    const optionalDesc = readExternalDescHint(data, cursor, limit)
    if (optionalDesc) cursor = optionalDesc.next
  }
  return exports
}

function readVectorCount(data: Buffer, offset: number, limit: number): number | null {
  const count = readU32Leb(data, offset)
  return count && count.next <= limit ? count.value : null
}

function addCount(target: Record<string, number>, name: string, count: number): void {
  target[name] = (target[name] ?? 0) + count
}

function extractAsciiStrings(data: Buffer): string[] {
  const strings: string[] = []
  let start = -1
  for (let i = 0; i <= data.length && strings.length < MAX_STRINGS; i += 1) {
    const byte = i < data.length ? data[i] : 0
    const printable = byte >= 0x20 && byte <= 0x7e
    if (printable && start < 0) start = i
    if ((!printable || i === data.length) && start >= 0) {
      if (i - start >= 4) strings.push(data.subarray(start, i).toString('ascii'))
      start = -1
    }
  }
  return strings
}

function collectHints(strings: string[], imports: ComponentImport[], exports: ComponentExport[]) {
  const witPackages = new Set<string>()
  const componentHints = new Set<string>()
  const wasiHints = new Set<string>()
  const allNames = [
    ...strings,
    ...imports.map((item) => item.name),
    ...exports.map((item) => item.name),
  ]

  for (const name of allNames) {
    const lower = name.toLowerCase()
    if (lower.includes('component')) componentHints.add('component-model')
    if (lower.includes('canon') || lower.includes('canonical')) componentHints.add('canonical-abi')
    if (lower.includes('wit')) componentHints.add('wit')
    if (lower.includes('wasi:') || lower.includes('wasi_') || lower.includes('wasi-')) {
      wasiHints.add('wasi')
    }
    if (lower.includes('wasi:filesystem') || lower.includes('filesystem'))
      wasiHints.add('filesystem')
    if (lower.includes('wasi:cli') || lower.includes('wasi-cli')) wasiHints.add('cli')
    if (lower.includes('wasi:io') || lower.includes('wasi-io')) wasiHints.add('io')
    if (lower.includes('wasi:clocks') || lower.includes('clock')) wasiHints.add('clocks')
    if (lower.includes('wasi:random') || lower.includes('random')) wasiHints.add('random')
    if (lower.includes('wasi:sockets') || lower.includes('socket'))
      wasiHints.add('sockets_or_network_like')
    if (lower.includes('wasi:http') || lower.includes('http')) wasiHints.add('http')
    if (lower.includes('proc_exit') || lower.includes('process-exit')) wasiHints.add('process_exit')
    if (looksLikeWitPackage(lower)) witPackages.add(name)
  }

  return {
    witPackageHints: Array.from(witPackages).sort().slice(0, 100),
    wasiCapabilityHints: Array.from(wasiHints).sort(),
    componentModelHints: Array.from(componentHints).sort(),
  }
}

function looksLikeWitPackage(value: string): boolean {
  const colon = value.indexOf(':')
  const slash = value.indexOf('/')
  if (colon <= 0 || slash <= colon + 1) return false
  const prefix = value.slice(0, colon)
  const name = value.slice(colon + 1, slash)
  return isSimpleIdent(prefix) && isSimpleIdent(name)
}

function isSimpleIdent(value: string): boolean {
  if (value.length === 0 || value.length > 80) return false
  for (const char of value) {
    const code = char.charCodeAt(0)
    const ok =
      (code >= 0x61 && code <= 0x7a) ||
      (code >= 0x30 && code <= 0x39) ||
      code === 0x2d ||
      code === 0x5f
    if (!ok) return false
  }
  return true
}

function summarizeRisk(hints: string[]): WasmComponentInventory['capability_risk_summary'] {
  const has = (value: string) => hints.includes(value)
  const filesystem = has('filesystem')
  const environment = has('environment')
  const cli = has('cli')
  const clocks = has('clocks')
  const random = has('random')
  const socketsOrNetwork = has('sockets_or_network_like')
  const http = has('http')
  const processExit = has('process_exit')
  const score = [
    filesystem,
    environment,
    cli,
    clocks,
    random,
    socketsOrNetwork,
    http,
    processExit,
  ].filter(Boolean).length
  const riskLevel =
    socketsOrNetwork || http
      ? 'high'
      : filesystem || score >= 3
        ? 'medium'
        : score > 0
          ? 'low'
          : 'none'
  return {
    filesystem,
    environment,
    cli,
    clocks,
    random,
    sockets_or_network_like: socketsOrNetwork,
    http,
    process_exit: processExit,
    risk_level: riskLevel,
  }
}

function parseComponentSections(data: Buffer) {
  const sections: WasmComponentInventory['sections'] = []
  const customSections: string[] = []
  const imports: ComponentImport[] = []
  const exports: ComponentExport[] = []
  const sectionCounts: Record<string, number> = {}
  let offset = 8

  while (offset < data.length && sections.length < MAX_SECTIONS) {
    const id = data[offset]
    const size = readU32Leb(data, offset + 1)
    if (!size) break
    const payloadStart = size.next
    const payloadEnd = payloadStart + size.value
    if (payloadEnd > data.length) break

    const name = COMPONENT_SECTION_NAMES[id] ?? `section_${id}`
    let countHint: number | null = null

    if (id === 0) {
      const customName = readName(data, payloadStart, payloadEnd)
      if (customName?.value) customSections.push(customName.value)
      countHint = null
    } else if (id === 1 || id === 4) {
      countHint = 1
    } else {
      countHint = readVectorCount(data, payloadStart, payloadEnd)
    }

    sections.push({ id, name, offset, size: size.value, count_hint: countHint })
    addCount(sectionCounts, name, countHint ?? 1)

    if (id === 10) imports.push(...parseComponentImports(data, payloadStart, payloadEnd))
    if (id === 11) exports.push(...parseComponentExports(data, payloadStart, payloadEnd))

    offset = payloadEnd
  }

  return { sections, customSections, imports, exports, sectionCounts }
}

function buildRuntimePlan(riskLevel: string): WasmComponentInventory['runtime_plan'] {
  return {
    status: 'plan_only',
    recommended_tools: [
      'wasm.runtime.plan',
      'tool.readiness',
      'wasm.structure.analyze',
      'wabt.toolchain.plan',
      'analysis.evidence.graph',
      'artifact.read',
      'strings.extract',
      'sbom.generate',
    ],
    handoff: {
      primary_tool: 'wasm.runtime.plan',
      readiness_tool: 'tool.readiness',
      evidence_tools: ['analysis.evidence.graph', 'artifact.read'],
      static_evidence_artifact_type: 'wasm_component_inventory',
      runtime_policy: {
        no_instantiation: true,
        no_wasi_grants: true,
        no_network: true,
        resource_grants: 'none',
      },
    },
    notes: [
      'Use a runtime-gated WASI Preview 2 backend only after reviewing component imports and resources.',
      'This tool does not instantiate the component or start wasmtime.',
      'No WASI preopens, filesystem grants, resource grants, package fetches, or network access are created.',
      `Capability risk level: ${riskLevel}.`,
    ],
  }
}

export function buildWasmComponentInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): WasmComponentInventory {
  const validMagic =
    data.length >= 8 && data[0] === 0x00 && data[1] === 0x61 && data[2] === 0x73 && data[3] === 0x6d
  const versionField = validMagic ? data.readUInt16LE(4) : null
  const layerField = validMagic ? data.readUInt16LE(6) : null
  const isComponent = validMagic && layerField === 1
  const isCoreModuleLayer = validMagic && layerField === 0
  const parsed = isComponent
    ? parseComponentSections(data)
    : { sections: [], customSections: [], imports: [], exports: [], sectionCounts: {} }
  const strings = extractAsciiStrings(data)
  const hints = collectHints(strings, parsed.imports, parsed.exports)
  const riskSummary = summarizeRisk(hints.wasiCapabilityHints)

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format: 'wasm-component',
    valid_magic: validMagic,
    component_preamble: {
      version_field: versionField,
      layer_field: layerField,
      is_component: isComponent,
      is_core_module_layer: isCoreModuleLayer,
    },
    sections: parsed.sections,
    section_counts: parsed.sectionCounts,
    custom_sections: parsed.customSections,
    imports: parsed.imports,
    exports: parsed.exports,
    nested_component_count: parsed.sectionCounts.component ?? 0,
    embedded_core_module_count: parsed.sectionCounts.core_module ?? 0,
    canonical_abi_definition_count: parsed.sectionCounts.canonical ?? 0,
    start_definition_count: parsed.sectionCounts.start ?? 0,
    value_definition_count: parsed.sectionCounts.value ?? 0,
    wit_package_hints: hints.witPackageHints,
    wasi_capability_hints: hints.wasiCapabilityHints,
    component_model_hints: hints.componentModelHints,
    capability_risk_summary: riskSummary,
    runtime_plan: buildRuntimePlan(riskSummary.risk_level),
    policy: {
      passive: true,
      no_execute: true,
      no_runtime_start: true,
      no_instantiation: true,
      no_wasi_grants: true,
      no_external_tool: true,
      no_network: true,
      no_mutation: true,
      resource_grants: 'none',
    },
    summary: isComponent
      ? `Passive Component Model inventory found ${parsed.sections.length} section(s), ${parsed.imports.length} import hint(s), ${parsed.exports.length} export hint(s), and ${hints.wasiCapabilityHints.length} WASI capability hint(s).`
      : validMagic
        ? 'Input has WebAssembly magic but is not a Component Model layer in the inspected preview.'
        : 'Input does not contain a valid WebAssembly magic header in the inspected preview.',
    recommended_next_tools: [
      'wasm.runtime.plan',
      'tool.readiness',
      'wasm.structure.analyze',
      'wabt.toolchain.plan',
      'analysis.evidence.graph',
      'artifact.read',
      'strings.extract',
      'sbom.generate',
    ],
    next_actions: [
      'Review component imports, WIT package hints, and WASI Preview 2 capability hints before any runtime plan.',
      'Do not instantiate the component during static triage.',
      'Keep WASI preopens, resource grants, package fetching, and network disabled until an explicit runtime plan is approved.',
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

export function createWasmComponentInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof WasmComponentInventoryInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = WasmComponentInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildWasmComponentInventoryFromBuffer(data, {
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
            'wasm_component_inventory',
            'wasm-component-inventory',
            inventory,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: callers still receive the inventory directly.
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
