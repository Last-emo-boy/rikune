import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, PluginToolDeps } from '../../sdk.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from '../../../tools/cache-observability.js'
import { smartRecoverFunctionsFromPE } from '../../../pe-runtime-functions.js'
import { createStringsExtractHandler } from '../../strings/tools/strings-extract.js'
import { createRuntimeDetectHandler } from '../../static-triage/tools/runtime-detect.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import {
  demangleRustSymbol,
  normalizeSymbolList,
  type DemangledSymbol,
} from '../../../tools/rust-demangle.js'
import { CACHE_TTL_30_DAYS } from '../../../constants/cache-ttl.js'

const TOOL_NAME = 'pe.symbols.recover'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = CACHE_TTL_30_DAYS
const SYMBOLS_RECOMMENDED_NEXT_TOOLS = [
  'code.functions.define',
  'code.functions.list',
  'workflow.function_index_recover',
  'code.cross_decompiler.consensus',
  'analysis.evidence.graph',
  'artifact.read',
  'workflow.search',
]
const SYMBOLS_SAFETY = [
  'passive',
  'read_only',
  'no_live_sample_by_default',
  'no_network_by_default',
]

const cargoPathPattern =
  /(?:^|[\\/])cargo[\\/](?:registry|git)[\\/][^\\/]+[\\/](?<crate>[A-Za-z0-9_.-]+?)(?:-\d[\w.+-]*)?(?:[\\/]|$)/i

const rustMarkers = [
  'rust_panic',
  'core::panicking',
  'alloc::',
  'tokio::',
  'std::rt',
  'rustc',
  'panic_unwind',
] as const

export const peSymbolsRecoverInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_string_hints: z
    .number()
    .int()
    .min(20)
    .max(400)
    .optional()
    .default(120)
    .describe('Maximum strings inspected when deriving Rust/Go/C++ symbol hints'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
})

const recoveredSymbolSchema = z.object({
  address: z.string(),
  rva: z.number(),
  size: z.number(),
  recovered_name: z.string(),
  base_name: z.string(),
  original_candidate_name: z.string(),
  confidence: z.number(),
  language_hint: z.string().nullable(),
  name_strategy: z.string(),
  recovery_source: z.string(),
  is_entry_point: z.boolean(),
  is_exported: z.boolean(),
  export_name: z.string().optional(),
  crate_hints: z.array(z.string()),
  evidence: z.array(z.string()),
})

export const peSymbolsRecoverOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      machine: z.number(),
      machine_name: z.string(),
      image_base: z.number(),
      entry_point_rva: z.number(),
      primary_runtime: z.string().nullable(),
      runtime_hints: z.array(z.string()),
      crate_hints: z.array(z.string()),
      count: z.number(),
      symbols: z.array(recoveredSymbolSchema),
      warnings: z.array(z.string()),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
    })
    .optional(),
})

export const peSymbolsRecoverToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Recover importable symbolic function names from PE runtime metadata such as .pdata / .xdata, exports, entry point, and language/runtime hints.',
  inputSchema: peSymbolsRecoverInputSchema,
  outputSchema: peSymbolsRecoverOutputSchema,
  aspects: {
    formats: ['pe', 'pe-clr', 'sys', 'efi'],
    platforms: ['windows', 'cross-platform'],
    architectures: ['x64', 'arm64'],
    execution: ['static', 'function-recovery', 'symbol-recovery'],
    safety: SYMBOLS_SAFETY,
    capabilities: [
      'symbol-recovery',
      'function-naming',
      'runtime-hints',
      'rust-hints',
      'go-hints',
      'export-correlation',
      'workflow-handoff',
    ],
    evidence: ['symbols', 'functions', 'runtime', 'strings', 'exports', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'pe_recovered_symbols',
      description: 'Inline PE recovered symbol and runtime hint output returned by the tool',
      required: false,
    },
  ],
  evidence: [
    { category: 'symbols', artifactTypes: ['pe_recovered_symbols'] },
    { category: 'functions', artifactTypes: ['pe_recovered_symbols'] },
    { category: 'runtime', artifactTypes: ['pe_recovered_symbols'] },
    { category: 'workflow', artifactTypes: ['pe_recovered_symbols'] },
    { category: 'provenance', artifactTypes: ['pe_recovered_symbols'] },
  ],
  workflowRecipes: [
    {
      id: 'pe.symbols-function-naming-handoff',
      title: 'PE symbol recovery handoff',
      description:
        'Recover importable function names from PE runtime metadata, exports, strings, and runtime hints, then route into function definition, consensus review, evidence graph, and reconstruction workflows.',
      startsWith: [TOOL_NAME],
      nextTools: SYMBOLS_RECOMMENDED_NEXT_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: ['pe_recovered_symbols'],
      evidence: ['symbols', 'functions', 'runtime', 'strings', 'workflow', 'provenance'],
      safety: SYMBOLS_SAFETY,
      runtimeBackends: ['builtin-pe-parser'],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    maxRuntimeMs: 120000,
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'This tool parses PE metadata and consumes static strings/runtime hints; it never executes the sample.',
      'Recovered names remain evidence hints and should be reviewed before applying semantic renames.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'builtin-pe-parser',
    backendKind: 'builtin',
    adapter: 'pe.symbols.recover',
    availability: 'builtin',
    supportedModes: ['recover-symbols'],
    defaultMode: 'recover-symbols',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: ['pe_recovered_symbols'],
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 120000,
      notes: ['Bounded in-process PE metadata and static hint correlation.'],
    },
    readiness: {
      doesNotStartBackend: true,
      missingBackendBehavior: 'Builtin parser is always available with the Rikune server.',
    },
  },
}

type SymbolsRecoverData = NonNullable<z.infer<typeof peSymbolsRecoverOutputSchema>['data']>

type StringsData = {
  strings?: Array<{
    offset: number
    string: string
    encoding: string
  }>
}

type RuntimeDetectData = {
  is_dotnet?: boolean
  suspected?: Array<{
    runtime: string
    confidence: number
    evidence: string[]
  }>
}

interface SymbolRecoverDependencies {
  stringsHandler?: (args: ToolArgs) => Promise<WorkerResult>
  runtimeHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

function normalizeSymbolBase(name: string): string {
  return (
    name
      .replace(/[^A-Za-z0-9_]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .replace(/_{2,}/g, '_')
      .toLowerCase() || 'recovered_function'
  )
}

function extractCrateHints(strings: string[]): string[] {
  const crates = new Set<string>()
  for (const value of strings) {
    const cargoMatch = value.match(cargoPathPattern)
    const crate = cargoMatch?.groups?.crate?.trim()
    if (crate) {
      crates.add(crate.toLowerCase())
    }
  }
  return Array.from(crates).slice(0, 12)
}

function inferRuntimeHints(
  runtimeData: RuntimeDetectData | undefined,
  strings: string[],
  crateHints: string[]
): { primaryRuntime: string | null; runtimeHints: string[] } {
  const runtimeHints = new Set<string>()
  let primaryRuntime =
    runtimeData?.suspected?.slice().sort((left, right) => right.confidence - left.confidence)[0]
      ?.runtime || null

  for (const suspected of runtimeData?.suspected || []) {
    runtimeHints.add(suspected.runtime)
  }

  if (
    crateHints.length > 0 ||
    strings.some((value) => rustMarkers.some((marker) => value.includes(marker)))
  ) {
    runtimeHints.add('rust')
    primaryRuntime = primaryRuntime || 'rust'
  }

  if (strings.some((value) => value.includes('Go build') || value.includes('go.buildid'))) {
    runtimeHints.add('go')
    primaryRuntime = primaryRuntime || 'go'
  }

  return {
    primaryRuntime,
    runtimeHints: Array.from(runtimeHints),
  }
}

function recoverSymbolName(options: {
  originalCandidateName: string
  rva: number
  isEntryPoint: boolean
  isExported: boolean
  exportName?: string
  runtimeHints: string[]
  crateHints: string[]
  unwindFlags: string[]
}): {
  recoveredName: string
  baseName: string
  strategy: string
  confidence: number
  languageHint: string | null
  evidence: string[]
} {
  const evidence: string[] = []
  let strategy = 'pdata_generic'
  let languageHint: string | null = null
  let baseName = normalizeSymbolBase(options.originalCandidateName)
  let confidence = 0.62

  if (options.isExported && options.exportName) {
    strategy = 'export_surface'
    baseName = normalizeSymbolBase(options.exportName)
    confidence = 0.94
    evidence.push(`Matched PE export ${options.exportName}`)
  } else if (options.isEntryPoint) {
    if (options.runtimeHints.includes('rust')) {
      strategy = 'rust_entry_point'
      baseName = 'rust_entry_point'
      confidence = 0.88
      languageHint = 'rust'
    } else if (options.runtimeHints.includes('go')) {
      strategy = 'go_entry_point'
      baseName = 'go_entry_point'
      confidence = 0.84
      languageHint = 'go'
    } else {
      strategy = 'entry_point'
      baseName = 'entry_point'
      confidence = 0.8
    }
    evidence.push('Matches PE entry point RVA')
  } else if (options.runtimeHints.includes('rust')) {
    languageHint = 'rust'
    if (options.unwindFlags.includes('EHANDLER') || options.unwindFlags.includes('UHANDLER')) {
      strategy = 'rust_unwind_runtime_function'
      baseName = 'rust_unwind_runtime_function'
      confidence = 0.78
      evidence.push(`Rust unwind flags observed: ${options.unwindFlags.join('|')}`)
    } else {
      strategy = 'rust_runtime_function'
      baseName = 'rust_runtime_function'
      confidence = 0.72
    }
    if (options.crateHints.length > 0) {
      evidence.push(`Rust crate hints: ${options.crateHints.slice(0, 3).join(', ')}`)
    }
  } else if (options.runtimeHints.includes('go')) {
    strategy = 'go_runtime_function'
    baseName = 'go_runtime_function'
    confidence = 0.7
    languageHint = 'go'
  } else if (options.unwindFlags.includes('CHAININFO')) {
    strategy = 'chained_unwind_runtime_function'
    baseName = 'chained_unwind_runtime_function'
    confidence = 0.7
    evidence.push('Unwind CHAININFO flag observed')
  } else {
    evidence.push('Recovered from PE exception directory (.pdata) runtime function entry')
  }

  const recoveredName = `${baseName}_${options.rva.toString(16).padStart(8, '0')}`
  return {
    recoveredName,
    baseName,
    strategy,
    confidence,
    languageHint,
    evidence,
  }
}

function buildSymbolsEvidenceSummary(
  data: SymbolsRecoverData,
  input: z.infer<typeof peSymbolsRecoverInputSchema>
) {
  return {
    schema: 'rikune.pe_symbols.evidence_summary.v1',
    source_tool: TOOL_NAME,
    tool_version: TOOL_VERSION,
    sample_id: input.sample_id,
    machine_name: data.machine_name,
    entry_point_rva: data.entry_point_rva,
    primary_runtime: data.primary_runtime,
    runtime_hints: data.runtime_hints,
    crate_hints: data.crate_hints,
    recovered_symbol_count: data.count,
    exported_symbol_count: data.symbols.filter((symbol) => symbol.is_exported).length,
    entry_point_symbol_count: data.symbols.filter((symbol) => symbol.is_entry_point).length,
    high_confidence_symbol_count: data.symbols.filter((symbol) => symbol.confidence >= 0.8).length,
    naming_strategies: Array.from(new Set(data.symbols.map((symbol) => symbol.name_strategy))),
  }
}

function buildSymbolsWorkflowHandoff(
  data: SymbolsRecoverData,
  input: z.infer<typeof peSymbolsRecoverInputSchema>
) {
  return {
    schema: 'rikune.pe_symbols.workflow_handoff.v1',
    handoff_mode: 'pe_symbols_to_function_naming_and_consensus',
    sample_id: input.sample_id,
    recommended_next_tools: SYMBOLS_RECOMMENDED_NEXT_TOOLS,
    data_contract: {
      type: 'pe_recovered_symbols',
      recovered_symbol_count: data.count,
      primary_runtime: data.primary_runtime,
      inline_result: true,
    },
    routing: [
      {
        goal: 'apply-function-names',
        priority: data.count > 0 ? 'high' : 'low',
        next_tools: ['code.functions.define', 'code.functions.list'],
        required_evidence: ['pe_recovered_symbols', 'function_index_entries'],
      },
      {
        goal: 'cross-backend-corroboration',
        priority: 'normal',
        next_tools: ['code.cross_decompiler.consensus', 'analysis.evidence.graph'],
        required_evidence: ['pe_recovered_symbols', 'paired backend artifacts'],
      },
      {
        goal: 'recover-missing-function-index',
        priority: data.count > 0 ? 'normal' : 'high',
        next_tools: ['workflow.function_index_recover'],
        required_evidence: ['pe_pdata_runtime_functions', 'runtime hints'],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: false,
      backend_kind: 'builtin-static-parser',
      live_execution_started: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildSymbolsQualityGates(data: SymbolsRecoverData) {
  return {
    schema: 'rikune.pe_symbols.quality_gates.v1',
    passive_static_analysis: true,
    builtin_parser_only: true,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    recovered_symbols_present: data.count > 0,
    runtime_hints_present: data.runtime_hints.length > 0,
    exported_symbols_present: data.symbols.some((symbol) => symbol.is_exported),
    analyst_review_required: data.count > 0,
  }
}

function buildSymbolsNextActions(data: SymbolsRecoverData) {
  return [
    data.count > 0
      ? 'Use code.functions.define to apply high-confidence recovered names after reviewing evidence.'
      : 'Use workflow.function_index_recover or pe.pdata.extract before retrying symbol recovery.',
    'Use code.cross_decompiler.consensus to corroborate recovered names against decompiler artifacts.',
    'Use workflow.search to select a result-scoped evidence graph or reconstruction follow-up.',
  ]
}

function withSymbolsEnvelope(
  data: SymbolsRecoverData,
  input: z.infer<typeof peSymbolsRecoverInputSchema>
): SymbolsRecoverData {
  return {
    ...data,
    evidence_summary: buildSymbolsEvidenceSummary(data, input),
    workflow_handoff: buildSymbolsWorkflowHandoff(data, input),
    quality_gates: buildSymbolsQualityGates(data),
    recommended_next_tools: SYMBOLS_RECOMMENDED_NEXT_TOOLS,
    next_actions: buildSymbolsNextActions(data),
  }
}

export function createPESymbolsRecoverHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, cacheManager } = deps
  const stringsHandler =
    (deps.stringsHandler as ((args: ToolArgs) => Promise<WorkerResult>) | undefined) ||
    createStringsExtractHandler(workspaceManager, database, cacheManager)
  const runtimeHandler =
    (deps.runtimeHandler as ((args: ToolArgs) => Promise<WorkerResult>) | undefined) ||
    createRuntimeDetectHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = peSymbolsRecoverInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          max_string_hints: input.max_string_hints,
        },
      })

      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          const cachedData = cachedLookup.data as SymbolsRecoverData
          return {
            ok: true,
            data: withSymbolsEnvelope(cachedData, input),
            warnings: ['Result from cache', formatCacheWarning(cachedLookup.metadata)],
            metrics: {
              elapsed_ms: Date.now() - startTime,
              tool: TOOL_NAME,
              cached: true,
              cache_key: cachedLookup.metadata.key,
              cache_tier: cachedLookup.metadata.tier,
              cache_created_at: cachedLookup.metadata.createdAt,
              cache_expires_at: cachedLookup.metadata.expiresAt,
              cache_hit_at: cachedLookup.metadata.fetchedAt,
            },
          }
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const recovery = smartRecoverFunctionsFromPE(samplePath)

      const [stringsResult, runtimeResult] = await Promise.all([
        stringsHandler({
          sample_id: input.sample_id,
          max_strings: input.max_string_hints,
          category_filter: 'all',
        }),
        runtimeHandler({
          sample_id: input.sample_id,
        }),
      ])

      const stringsData = (stringsResult.ok ? stringsResult.data : undefined) as
        | StringsData
        | undefined
      const runtimeData = (runtimeResult.ok ? runtimeResult.data : undefined) as
        | RuntimeDetectData
        | undefined
      const rawStrings = (stringsData?.strings || []).map((item) => item.string)
      const crateHints = extractCrateHints(rawStrings)
      const { primaryRuntime, runtimeHints } = inferRuntimeHints(
        runtimeData,
        rawStrings,
        crateHints
      )

      const symbols = recovery.functions.map((item) => {
        const unwindFlags = item.unwind?.flagNames || []
        const naming = recoverSymbolName({
          originalCandidateName: item.name,
          rva: item.rva,
          isEntryPoint: item.isEntryPoint,
          isExported: item.isExported,
          exportName: item.exportName,
          runtimeHints,
          crateHints,
          unwindFlags,
        })

        return {
          address: item.address,
          rva: item.rva,
          size: item.size,
          recovered_name: naming.recoveredName,
          base_name: naming.baseName,
          original_candidate_name: item.name,
          confidence: Math.min(0.98, Math.max(item.confidence, naming.confidence)),
          language_hint: naming.languageHint,
          name_strategy: naming.strategy,
          recovery_source: item.source,
          is_entry_point: item.isEntryPoint,
          is_exported: item.isExported,
          export_name: item.exportName,
          crate_hints: crateHints,
          evidence: Array.from(new Set([...item.evidence, ...naming.evidence])),
        }
      })

      const normalized: SymbolsRecoverData = {
        machine: recovery.machine,
        machine_name: recovery.machineName,
        image_base: recovery.imageBase,
        entry_point_rva: recovery.entryPointRva,
        primary_runtime: primaryRuntime,
        runtime_hints: runtimeHints,
        crate_hints: crateHints,
        count: symbols.length,
        symbols,
        warnings: recovery.warnings,
      }

      await cacheManager.setCachedResult(cacheKey, normalized, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: withSymbolsEnvelope(normalized, input),
        warnings: recovery.warnings.length > 0 ? recovery.warnings : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
