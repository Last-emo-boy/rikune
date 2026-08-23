/**
 * zig.binary.inventory - passive Zig binary metadata inventory.
 *
 * This tool reads bounded bytes and summarizes static evidence for Zig
 * language/runtime provenance: Zig mangled symbol candidates, zig compiler
 * markers, build.zig/build.zig.zon hints, panic/runtime markers, allocator
 * markers, target triples, and workflow handoff. It never invokes zig,
 * external demanglers, native loaders, or runtime tools.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'zig.binary.inventory'
export const ZIG_BINARY_INVENTORY_ARTIFACT_TYPE = 'zig_binary_inventory'
const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 8000
const MAX_SYMBOLS = 180
const MAX_EVIDENCE = 300

type Confidence = 'low' | 'medium' | 'high'
type ContainerKind = 'elf' | 'pe' | 'macho' | 'archive' | 'wasm' | 'raw'

const ZIG_BINARY_EVIDENCE = [
  'symbols',
  'language-runtime',
  'provenance',
  'package-metadata',
  'panic',
  'allocator',
  'target',
  'workflow',
] as const

const ZIG_BINARY_FOLLOW_UP_TOOLS = [
  'compiler.codegen.fingerprint',
  'native.object.inventory',
  'native.debug.types.inventory',
  'strings.extract',
  'sbom.provenance.graph',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
] as const

const ZIG_BINARY_SAFETY = [
  'passive',
  'no_execute',
  'no_native_load',
  'no_zig_invocation',
  'no_external_demangler',
  'no_external_tool',
  'no_network_by_default',
  'no_mutation',
] as const

// ─── Schemas ───────────────────────────────────────────────────────────────

const ZigBinaryPolicySchema = z.object({
  passive: z.literal(true),
  read_only: z.literal(true),
  no_execute: z.literal(true),
  no_native_load: z.literal(true),
  no_zig_invocation: z.literal(true),
  no_external_demangler: z.literal(true),
  no_external_tool: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const ZigBinaryInventorySchema = z
  .object({
    sample_id: z.string(),
    filename: z.string(),
    tool: z.string(),
    tool_version: z.string(),
    container: z.enum(['elf', 'pe', 'macho', 'archive', 'wasm', 'raw']),
    confidence: z.enum(['low', 'medium', 'high']),
    detected_by: z.array(z.string()),
    size: z.number(),
    preview_size: z.number(),
    truncated: z.boolean(),
    zig_compiler_candidates: z.array(z.string()),
    build_system_markers: z.array(z.string()),
    panic_markers: z.array(z.string()),
    allocator_markers: z.array(z.string()),
    runtime_markers: z.array(z.string()),
    target_triple_candidates: z.array(z.string()),
    ecosystem_markers: z.array(z.string()),
    symbol_candidates: z.array(z.string()),
    embedded_strings: z.array(z.string()),
    evidence: z.array(z.any()),
    metadata: z.record(z.any()),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
    evidence_summary: z.record(z.any()),
    workflow_handoff: z.record(z.any()),
    quality_gates: z.record(z.any()),
  })
  .passthrough()

const ZigBinaryInventoryInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_read_bytes: z
    .number()
    .int()
    .positive()
    .max(MAX_PREVIEW_BYTES)
    .optional()
    .describe('Maximum bytes to read for passive inspection.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist normalized Zig binary inventory into reports/static_analysis'),
  session_tag: z.string().optional().describe('Optional session tag for persisted artifacts.'),
})

const ZigBinaryInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: ZigBinaryInventorySchema.optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

// ─── Helpers ──────────────────────────────────────────────────────────────

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function extractAsciiStrings(data: Buffer, maxCount: number): string[] {
  const text = data.subarray(0, Math.min(data.length, 4 * 1024 * 1024)).toString('latin1')
  const matches = text.match(/[\x20-\x7e]{4,}/g) ?? []
  return unique(matches.map((item) => item.trim())).slice(0, maxCount)
}

function detectContainer(data: Buffer): ContainerKind {
  if (data.length >= 4) {
    const magic = data.readUInt32BE(0)
    if (magic === 0x7f454c46) return 'elf'
    if (
      magic === 0xfeedface ||
      magic === 0xfeedfacf ||
      magic === 0xcefaedfe ||
      magic === 0xcffaedfe
    )
      return 'macho'
    if (magic === 0x50450000) return 'pe'
    if (data[0] === 0x21 && data.subarray(1, 9).toString('ascii') === '<arch>\n') return 'archive'
    if (data[0] === 0x00 && data[1] === 0x61 && data[2] === 0x73 && data[3] === 0x6d) return 'wasm'
  }
  return 'raw'
}

// Zig mangled symbols look like:
//   zig.org.<hash>.<name>  (newer)
//   _Z<...>                 (C++ mangling for extern)
//   zig.<module>.<name>     (legacy)
const ZIG_MANGLED_PATTERNS = [
  /zig\.org\.[A-Za-z0-9_.]+/g,
  /zig\.[A-Za-z_][A-Za-z0-9_.]+/g,
  /_Z[A-Za-z0-9_]+zig[A-Za-z0-9_]*/g,
]

// zig compiler version strings: e.g. "0.13.0", "0.14.0", "0.15.0-dev"
const ZIG_COMPILER_PATTERN = /zig[\/\-_\s]?(\d+\.\d+\.\d+(?:-[a-z0-9.]+)?)/gi

// build.zig / build.zig.zon markers
const BUILD_SYSTEM_PATTERNS = [/build\.zig/gi, /build\.zig\.zon/gi, /\.zon\b/gi]

// Zig panic markers
const PANIC_PATTERNS = [
  /panic\s*\(/gi,
  /@panic/g,
  /zig\.panic/g,
  /builtin\.panic/g,
  /panic_unwind/g,
  /panic_abort/g,
]

// Zig allocator markers
const ALLOCATOR_PATTERNS = [
  /Allocator\s*{/g,
  /page_allocator/g,
  /heap\.c_allocator/g,
  /heap\.GeneralPurposeAllocator/g,
  /heap\.ArenaAllocator/g,
  /heap\.FixedBufferAllocator/g,
  /TestingAllocator/g,
  /alloc\(/g,
  /free\(/g,
  /resize\(/g,
  /grow\(/g,
  /shrink\(/g,
]

// Zig runtime/standard library markers
const RUNTIME_PATTERNS = [
  /std\.io/g,
  /std\.fmt/g,
  /std\.mem/g,
  /std\.fs/g,
  /std\.os/g,
  /std\.net/g,
  /std\.process/g,
  /std\.time/g,
  /std\.debug/g,
  /std\.build/g,
  /std\.collections/g,
  /std\.hash/g,
  /std\.math/g,
  /std\.meta/g,
  /std\.comptime/g,
  /@import\s*\(/g,
  /@embedFile/g,
  /@cImport/g,
  /@cInclude/g,
  /@cUndef/g,
  /@compileError/g,
  /@compileLog/g,
  /@field/g,
  /@typeInfo/g,
]

// Target triple candidates: zig uses triples like "x86_64-linux-gnu"
const TARGET_TRIPLE_PATTERNS = [
  /\b(x86_64|i386|aarch64|arm|riscv64|wasm32|wasm64|mips|powerpc64)[-_](linux|macos|windows|freebsd|netbsd|openbsd|wasi|freestanding|uefi|zig)[-_]?(\w+)?\b/gi,
]

interface ZigBinaryInventory {
  sample_id: string
  filename: string
  tool: string
  tool_version: string
  container: ContainerKind
  confidence: Confidence
  detected_by: string[]
  size: number
  preview_size: number
  truncated: boolean
  zig_compiler_candidates: string[]
  build_system_markers: string[]
  panic_markers: string[]
  allocator_markers: string[]
  runtime_markers: string[]
  target_triple_candidates: string[]
  ecosystem_markers: string[]
  symbol_candidates: string[]
  embedded_strings: string[]
  evidence: Array<Record<string, unknown>>
  metadata: Record<string, unknown>
  recommended_next_tools: string[]
  next_actions: string[]
  evidence_summary: Record<string, unknown>
  workflow_handoff: Record<string, unknown>
  quality_gates: Record<string, unknown>
}

function collectMatches(text: string, patterns: RegExp[], max: number): string[] {
  const results: string[] = []
  for (const pattern of patterns) {
    pattern.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = pattern.exec(text)) !== null && results.length < max) {
      results.push(match[0])
    }
    if (results.length >= max) break
  }
  return unique(results).slice(0, max)
}

function buildInventory(
  data: Buffer,
  options: { sampleId: string; filename: string; maxReadBytes: number; totalSize: number }
): ZigBinaryInventory {
  const text = data.toString('latin1')
  const strings = extractAsciiStrings(data, MAX_STRINGS)

  const zigCompilerCandidates = collectMatches(text, [ZIG_COMPILER_PATTERN], MAX_SYMBOLS)
  const buildSystemMarkers = collectMatches(text, BUILD_SYSTEM_PATTERNS, MAX_SYMBOLS)
  const panicMarkers = collectMatches(text, PANIC_PATTERNS, MAX_SYMBOLS)
  const allocatorMarkers = collectMatches(text, ALLOCATOR_PATTERNS, MAX_SYMBOLS)
  const runtimeMarkers = collectMatches(text, RUNTIME_PATTERNS, MAX_SYMBOLS)
  const targetTriples = collectMatches(text, TARGET_TRIPLE_PATTERNS, MAX_SYMBOLS)
  const symbolCandidates = collectMatches(text, ZIG_MANGLED_PATTERNS, MAX_SYMBOLS)

  // Ecosystem markers: Zig packages, references to zig std lib, etc.
  const ecosystemPatterns = [
    /zig-std/gi,
    /ziglibc/gi,
    /ziglang/gi,
    /\.zig\b/gi,
    /zigcc/gi,
    /zig\.cc/gi,
  ]
  const ecosystemMarkers = collectMatches(text, ecosystemPatterns, MAX_SYMBOLS)

  const container = detectContainer(data)

  // Confidence: high if we find compiler candidates + runtime markers,
  // medium if either, low otherwise.
  let confidence: Confidence = 'low'
  if (zigCompilerCandidates.length > 0 && runtimeMarkers.length > 0) {
    confidence = 'high'
  } else if (zigCompilerCandidates.length > 0 || runtimeMarkers.length > 0) {
    confidence = 'medium'
  } else if (symbolCandidates.length > 0 || ecosystemMarkers.length > 0) {
    confidence = 'medium'
  }

  const detectedBy: string[] = []
  if (zigCompilerCandidates.length > 0)
    detectedBy.push(`zig-compiler-version (${zigCompilerCandidates.length})`)
  if (runtimeMarkers.length > 0)
    detectedBy.push(`zig-std-runtime-markers (${runtimeMarkers.length})`)
  if (symbolCandidates.length > 0)
    detectedBy.push(`zig-mangled-symbols (${symbolCandidates.length})`)
  if (buildSystemMarkers.length > 0)
    detectedBy.push(`build-system-markers (${buildSystemMarkers.length})`)
  if (panicMarkers.length > 0) detectedBy.push(`panic-markers (${panicMarkers.length})`)
  if (ecosystemMarkers.length > 0) detectedBy.push(`ecosystem-markers (${ecosystemMarkers.length})`)
  if (detectedBy.length === 0) detectedBy.push('no-direct-zig-evidence')

  // Build evidence list
  const evidence: Array<Record<string, unknown>> = []
  for (const sym of symbolCandidates.slice(0, MAX_EVIDENCE)) {
    evidence.push({ category: 'symbols', source: 'zig-mangled', value: sym })
  }
  for (const rt of runtimeMarkers.slice(0, MAX_EVIDENCE)) {
    evidence.push({ category: 'language-runtime', source: 'zig-std', value: rt })
  }
  for (const al of allocatorMarkers.slice(0, MAX_EVIDENCE)) {
    evidence.push({ category: 'allocator', source: 'zig-allocator', value: al })
  }
  for (const p of panicMarkers.slice(0, MAX_EVIDENCE)) {
    evidence.push({ category: 'panic', source: 'zig-panic', value: p })
  }

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    tool: TOOL_NAME,
    tool_version: '0.1.0',
    container,
    confidence,
    detected_by: detectedBy,
    size: options.totalSize,
    preview_size: data.length,
    truncated: options.totalSize > data.length,
    zig_compiler_candidates: zigCompilerCandidates,
    build_system_markers: buildSystemMarkers,
    panic_markers: panicMarkers,
    allocator_markers: allocatorMarkers,
    runtime_markers: runtimeMarkers,
    target_triple_candidates: targetTriples,
    ecosystem_markers: ecosystemMarkers,
    symbol_candidates: symbolCandidates,
    embedded_strings: strings.slice(0, MAX_SYMBOLS),
    evidence: evidence.slice(0, MAX_EVIDENCE),
    metadata: {
      container,
      zig_compiler_candidate_count: zigCompilerCandidates.length,
      build_system_marker_count: buildSystemMarkers.length,
      panic_marker_count: panicMarkers.length,
      allocator_marker_count: allocatorMarkers.length,
      runtime_marker_count: runtimeMarkers.length,
      target_triple_count: targetTriples.length,
      ecosystem_marker_count: ecosystemMarkers.length,
      symbol_candidate_count: symbolCandidates.length,
    },
    recommended_next_tools: [...ZIG_BINARY_FOLLOW_UP_TOOLS],
    next_actions: [
      'Use compiler.codegen.fingerprint to correlate Zig language-runtime hints with compiler, linker, LTO, and debug provenance.',
      'Use native.debug.types.inventory and native.object.inventory to corroborate DWARF/CodeView/object evidence when present.',
      'Use sbom.provenance.graph to compare Zig ecosystem hints across related samples.',
      'Keep demangling, execution, sandboxing, and dynamic behavior validation as explicit follow-up workflows; this tool does not invoke external demanglers or runtimes.',
    ],
    evidence_summary: {
      total_evidence: evidence.length,
      zig_compiler_candidate_count: zigCompilerCandidates.length,
      build_system_marker_count: buildSystemMarkers.length,
      crate_candidate_count: 0,
      target_triple_count: targetTriples.length,
      runtime_marker_count: runtimeMarkers.length,
      ecosystem_marker_count: ecosystemMarkers.length,
      bounded_preview: true,
      candidate_only: true,
    },
    workflow_handoff: {
      static_corroboration: [
        'compiler.codegen.fingerprint',
        'native.object.inventory',
        'native.debug.types.inventory',
        'strings.extract',
      ],
      provenance_correlation: ['sbom.provenance.graph'],
      evidence_correlation: ['analysis.evidence.graph', 'report.generate'],
      demangler_boundary: {
        external_demangler_required_for_full_names: true,
        demangling_performed_by_this_tool: false,
        disallowed_by_this_tool: ['zig', 'llvm-cxxfilt', 'c++filt'],
      },
      runtime_boundary: {
        required: false,
        guidance:
          'Runtime is not needed for this passive Zig inventory. Use workflow.search to select explicit runtime plans only when behavior validation is requested.',
      },
    },
    quality_gates: {
      passive_static_inventory: true,
      bounded_read_bytes: data.length,
      max_read_bytes: options.maxReadBytes,
      sample_executed_by_tool: false,
      native_loader_invoked_by_tool: false,
      zig_invoked_by_tool: false,
      external_demangler_invoked_by_tool: false,
      external_tool_invoked_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
      candidate_only: true,
      truncated: options.totalSize > data.length,
    },
  }
}

// ─── Tool definition & handler ─────────────────────────────────────────────

export const zigBinaryInventoryAspects = {
  formats: ['zig', 'zig-binary', 'zig-archive', 'zig-object', 'elf', 'macho', 'pe', 'wasm'],
  platforms: ['cross-platform', 'linux', 'windows', 'macos', 'wasi', 'embedded'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'riscv64', 'wasm'],
  execution: ['static', 'triage', 'correlation', 'workflow-plan'],
  safety: [...ZIG_BINARY_SAFETY],
  capabilities: [
    'zig-language-detection',
    'zig-mangled-symbol-candidates',
    'zig-compiler-provenance',
    'zig-panic-profile',
    'zig-allocator-profile',
    'zig-std-runtime-markers',
    'target-triple-candidates',
    'workflow-routing',
  ],
  evidence: [...ZIG_BINARY_EVIDENCE],
}

export const zigBinaryInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passive Zig binary inventory for ELF, PE, Mach-O, WASM, object, and archive artifacts, covering Zig mangled symbol candidates, zig compiler markers, build.zig.zon hints, panic/allocator/runtime markers, and target triples without demangling or execution.',
  inputSchema: ZigBinaryInventoryInputSchema,
  outputSchema: ZigBinaryInventoryOutputSchema,
  aspects: zigBinaryInventoryAspects,
  artifacts: [
    {
      type: ZIG_BINARY_INVENTORY_ARTIFACT_TYPE,
      description: 'Passive Zig binary metadata inventory.',
    },
  ],
  evidence: [...ZIG_BINARY_EVIDENCE].map((category) => ({
    category,
    artifactTypes: [ZIG_BINARY_INVENTORY_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'zig.binary.inventory',
      title: 'Zig binary inventory',
      description:
        'Passively inventory Zig language/runtime provenance from binary artifacts without demangling or execution.',
      startsWith: ['zig.binary.inventory'],
      nextTools: [...ZIG_BINARY_FOLLOW_UP_TOOLS],
      requiredArtifacts: ['sample'],
      producesArtifacts: [ZIG_BINARY_INVENTORY_ARTIFACT_TYPE],
      evidence: [...ZIG_BINARY_EVIDENCE],
      safety: [...ZIG_BINARY_SAFETY],
    },
  ],
}

export type ZigBinaryInventoryResult = z.infer<typeof ZigBinaryInventorySchema>

export function createZigBinaryInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (input: z.infer<typeof ZigBinaryInventoryInputSchema>): Promise<WorkerResult> => {
    const start = Date.now()
    try {
      const parsed = ZigBinaryInventoryInputSchema.parse(input)
      if (!deps.resolvePrimarySamplePath) {
        return {
          ok: false,
          errors: ['resolvePrimarySamplePath dependency is unavailable for zig.binary.inventory'],
          metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
        }
      }

      const resolved = await deps.resolvePrimarySamplePath(deps.workspaceManager, parsed.sample_id)
      const stat = await fs.stat(resolved.samplePath)
      const maxReadBytes = Math.min(
        parsed.max_read_bytes ?? DEFAULT_MAX_READ_BYTES,
        MAX_PREVIEW_BYTES
      )
      const readSize = Math.max(0, Math.min(stat.size, maxReadBytes))
      const file = await fs.open(resolved.samplePath, 'r')
      let data: Buffer
      try {
        data = Buffer.alloc(readSize)
        await file.read(data, 0, readSize, 0)
      } finally {
        await file.close()
      }

      const inventory = buildInventory(data, {
        sampleId: parsed.sample_id,
        filename: path.basename(resolved.samplePath),
        maxReadBytes,
        totalSize: stat.size,
      })

      const artifacts: ArtifactRef[] = []
      if (parsed.persist_artifact !== false && deps.persistStaticAnalysisJsonArtifact) {
        const artifact = await deps.persistStaticAnalysisJsonArtifact(
          deps.workspaceManager,
          deps.database,
          parsed.sample_id,
          ZIG_BINARY_INVENTORY_ARTIFACT_TYPE,
          'zig-binary-inventory',
          inventory,
          parsed.session_tag ?? null
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: inventory as unknown as Record<string, unknown>,
        artifacts,
        metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - start, tool: TOOL_NAME },
      }
    }
  }
}
