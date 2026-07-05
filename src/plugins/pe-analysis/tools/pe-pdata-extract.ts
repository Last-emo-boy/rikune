import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, PluginToolDeps } from '../../sdk.js'
import { randomUUID } from 'crypto'
import type { Function as DbFunction } from '../../../database.js'
import { generateCacheKey } from '../../../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from '../../../tools/cache-observability.js'
import { extractPdataFromPE } from '../../../pe-runtime-functions.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import { CACHE_TTL_30_DAYS } from '../../../constants/cache-ttl.js'

const TOOL_NAME = 'pe.pdata.extract'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = CACHE_TTL_30_DAYS
const PDATA_RECOMMENDED_NEXT_TOOLS = [
  'pe.symbols.recover',
  'code.functions.list',
  'code.functions.smart_recover',
  'code.functions.define',
  'analysis.evidence.graph',
  'artifact.read',
  'workflow.search',
]
const PDATA_SAFETY = ['passive', 'read_only', 'no_live_sample_by_default', 'no_network_by_default']

export const pePdataExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache lookup and recompute from source sample'),
  materialize_functions: z
    .boolean()
    .optional()
    .default(true)
    .describe('Import .pdata runtime function boundaries into the function index'),
  replace_existing_functions: z
    .boolean()
    .optional()
    .default(false)
    .describe('Replace existing function index entries before materializing .pdata functions'),
})

export type PEPdataExtractInput = z.infer<typeof pePdataExtractInputSchema>

export const pePdataExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      machine: z.number(),
      machine_name: z.string(),
      image_base: z.number(),
      entry_point_rva: z.number(),
      exception_directory_rva: z.number(),
      exception_directory_size: z.number(),
      pdata_present: z.boolean(),
      xdata_present: z.boolean(),
      count: z.number(),
      sections: z.array(
        z.object({
          name: z.string(),
          virtual_address: z.number(),
          virtual_size: z.number(),
          raw_size: z.number(),
          raw_pointer: z.number(),
          characteristics: z.number(),
          executable: z.boolean(),
        })
      ),
      exports: z.array(
        z.object({
          rva: z.number(),
          name: z.string(),
          ordinal: z.number(),
          is_forwarder: z.boolean(),
        })
      ),
      entries: z.array(
        z.object({
          begin_rva: z.number(),
          end_rva: z.number(),
          size: z.number(),
          begin_va: z.number(),
          end_va: z.number(),
          begin_address: z.string(),
          end_address: z.string(),
          unwind_info_rva: z.number(),
          section_name: z.string().nullable(),
          executable_section: z.boolean(),
          confidence: z.number(),
          unwind: z
            .object({
              version: z.number(),
              flags: z.number(),
              flag_names: z.array(z.string()),
              prolog_size: z.number(),
              unwind_code_count: z.number(),
              frame_register: z.string().nullable(),
              frame_register_id: z.number(),
              frame_offset: z.number(),
              handler_rva: z.number().optional(),
              chained_runtime_function: z
                .object({
                  begin_rva: z.number(),
                  end_rva: z.number(),
                  unwind_info_rva: z.number(),
                })
                .optional(),
            })
            .nullable(),
        })
      ),
      warnings: z.array(z.string()),
      materialized_function_count: z.number().int().nonnegative().optional(),
      skipped_existing_function_count: z.number().int().nonnegative().optional(),
      function_index_status: z.enum(['ready', 'unchanged', 'empty', 'skipped']).optional(),
      analysis_id: z.string().optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
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
    .passthrough()
    .optional(),
})

export const pePdataExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Parse the PE exception directory / .pdata section and extract x64 RUNTIME_FUNCTION entries with unwind metadata.',
  inputSchema: pePdataExtractInputSchema,
  outputSchema: pePdataExtractOutputSchema,
  aspects: {
    formats: ['pe', 'pe-clr', 'sys', 'efi'],
    platforms: ['windows', 'cross-platform'],
    architectures: ['x64', 'arm64'],
    execution: ['static', 'function-recovery'],
    safety: PDATA_SAFETY,
    capabilities: [
      'pdata',
      'unwind-info',
      'runtime-function-table',
      'function-boundary-recovery',
      'function-index-materialization',
      'workflow-handoff',
    ],
    evidence: ['functions', 'unwind', 'symbols', 'structure', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'pe_pdata_runtime_functions',
      description: 'Inline PE .pdata runtime function and unwind metadata returned by the tool',
      required: false,
    },
    {
      type: 'function_index_entries',
      description: 'Function index entries materialized from PE runtime function metadata',
      required: false,
    },
  ],
  evidence: [
    { category: 'functions', artifactTypes: ['pe_pdata_runtime_functions'] },
    { category: 'unwind', artifactTypes: ['pe_pdata_runtime_functions'] },
    { category: 'workflow', artifactTypes: ['function_index_entries'] },
    { category: 'provenance', artifactTypes: ['pe_pdata_runtime_functions'] },
  ],
  workflowRecipes: [
    {
      id: 'pe.pdata-function-handoff',
      title: 'PE .pdata function boundary handoff',
      description:
        'Recover PE runtime function boundaries from .pdata/.xdata, optionally materialize them into the function index, then hand off to function review, naming, evidence graph, and reconstruction workflows.',
      startsWith: [TOOL_NAME],
      nextTools: PDATA_RECOMMENDED_NEXT_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: ['pe_pdata_runtime_functions', 'function_index_entries'],
      evidence: ['functions', 'unwind', 'symbols', 'workflow', 'provenance'],
      safety: PDATA_SAFETY,
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
      'This tool parses PE metadata and never executes the sample.',
      'Function materialization writes derived static evidence into Rikune function index only.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'builtin-pe-parser',
    backendKind: 'builtin',
    adapter: 'pe.pdata.extract',
    availability: 'builtin',
    supportedModes: ['extract', 'materialize-functions'],
    defaultMode: 'materialize-functions',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: ['pe_pdata_runtime_functions', 'function_index_entries'],
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 120000,
      notes: ['Bounded in-process PE metadata parsing; no external backend is started.'],
    },
    readiness: {
      doesNotStartBackend: true,
      missingBackendBehavior: 'Builtin parser is always available with the Rikune server.',
    },
  },
}

type PdataExtractData = NonNullable<z.infer<typeof pePdataExtractOutputSchema>['data']>

function normalizeAddress(address: string): string {
  return address.toLowerCase()
}

function materializePdataFunctions(
  database: PluginToolDeps['database'],
  sampleId: string,
  data: PdataExtractData,
  replaceExisting: boolean
): {
  materialized_function_count: number
  skipped_existing_function_count: number
  function_index_status: 'ready' | 'unchanged' | 'empty' | 'skipped'
  analysis_id?: string
} {
  if (!data.entries.length) {
    return {
      materialized_function_count: 0,
      skipped_existing_function_count: 0,
      function_index_status: 'empty',
    }
  }

  const db = database.getDatabase()
  if (replaceExisting) {
    db.prepare('DELETE FROM functions WHERE sample_id = ?').run(sampleId)
  }
  const existingRows = db
    .prepare('SELECT address FROM functions WHERE sample_id = ?')
    .all(sampleId) as Array<{ address: string }>
  const existingAddresses = new Set(existingRows.map((row) => normalizeAddress(row.address)))
  const exportByRva = new Map(
    data.exports
      .filter((entry) => !entry.is_forwarder)
      .map((entry) => [entry.rva, entry.name] as const)
  )
  const imported: DbFunction[] = []
  let skippedExisting = 0

  for (const entry of data.entries) {
    const address = normalizeAddress(entry.begin_address)
    if (!replaceExisting && existingAddresses.has(address)) {
      skippedExisting += 1
      continue
    }

    const exportedName = exportByRva.get(entry.begin_rva)
    const name = exportedName || `sub_${entry.begin_rva.toString(16).padStart(8, '0')}`
    const tags = [
      'source:pdata',
      'evidence:pe_exception_directory',
      ...(entry.executable_section ? ['section:executable'] : []),
      ...(entry.section_name ? [`section:${entry.section_name}`] : []),
    ]
    imported.push({
      sample_id: sampleId,
      address,
      name,
      size: entry.size > 0 ? entry.size : null,
      score: entry.confidence,
      tags: JSON.stringify(tags),
      summary: `Function boundary recovered from PE .pdata: RVA 0x${entry.begin_rva.toString(16)}-0x${entry.end_rva.toString(16)}.`,
      caller_count: 0,
      callee_count: 0,
      is_entry_point: entry.begin_rva === data.entry_point_rva ? 1 : 0,
      is_exported: exportedName ? 1 : 0,
      callees: JSON.stringify([]),
    })
    existingAddresses.add(address)
  }

  if (imported.length > 0) {
    database.insertFunctionsBatch(imported)
  }

  const analysisId = randomUUID()
  const now = new Date().toISOString()
  database.insertAnalysis({
    id: analysisId,
    sample_id: sampleId,
    stage: 'function_definition',
    backend: 'pdata',
    status: 'completed',
    started_at: now,
    finished_at: now,
    output_json: JSON.stringify({
      source: 'pdata',
      runtime_function_count: data.entries.length,
      imported_count: imported.length,
      skipped_existing_count: skippedExisting,
      replace_existing_functions: replaceExisting,
    }),
    metrics_json: JSON.stringify({
      imported_count: imported.length,
      skipped_existing_count: skippedExisting,
    }),
  })

  return {
    materialized_function_count: imported.length,
    skipped_existing_function_count: skippedExisting,
    function_index_status:
      imported.length > 0 ? 'ready' : skippedExisting > 0 ? 'unchanged' : 'empty',
    analysis_id: analysisId,
  }
}

function skippedMaterializationSummary(): {
  materialized_function_count: number
  skipped_existing_function_count: number
  function_index_status: 'skipped'
} {
  return {
    materialized_function_count: 0,
    skipped_existing_function_count: 0,
    function_index_status: 'skipped',
  }
}

function buildPdataEvidenceSummary(data: PdataExtractData, input: PEPdataExtractInput) {
  return {
    schema: 'rikune.pe_pdata.evidence_summary.v1',
    source_tool: TOOL_NAME,
    tool_version: TOOL_VERSION,
    sample_id: input.sample_id,
    machine_name: data.machine_name,
    entry_point_rva: data.entry_point_rva,
    pdata_present: data.pdata_present,
    xdata_present: data.xdata_present,
    runtime_function_count: data.count,
    executable_entry_count: data.entries.filter((entry) => entry.executable_section).length,
    unwind_entry_count: data.entries.filter((entry) => Boolean(entry.unwind)).length,
    export_count: data.exports.length,
    materialized_function_count: data.materialized_function_count ?? 0,
    skipped_existing_function_count: data.skipped_existing_function_count ?? 0,
    function_index_status: data.function_index_status ?? 'skipped',
    analysis_id: data.analysis_id ?? null,
  }
}

function buildPdataWorkflowHandoff(data: PdataExtractData, input: PEPdataExtractInput) {
  return {
    schema: 'rikune.pe_pdata.workflow_handoff.v1',
    handoff_mode: 'pe_pdata_to_function_index_and_review',
    sample_id: input.sample_id,
    recommended_next_tools: PDATA_RECOMMENDED_NEXT_TOOLS,
    data_contract: {
      type: 'pe_pdata_runtime_functions',
      runtime_function_count: data.count,
      function_index_status: data.function_index_status ?? 'skipped',
      materialized_function_count: data.materialized_function_count ?? 0,
      inline_result: true,
    },
    routing: [
      {
        goal: 'review-function-index',
        priority: data.function_index_status === 'ready' ? 'high' : 'normal',
        next_tools: ['code.functions.list', 'code.functions.smart_recover'],
        required_evidence: ['function_index_entries', 'pe_pdata_runtime_functions'],
      },
      {
        goal: 'name-recovered-functions',
        priority: data.count > 0 ? 'high' : 'low',
        next_tools: ['code.functions.define'],
        required_evidence: ['pe_pdata_runtime_functions', 'exports', 'runtime hints'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'artifact.read'],
        required_evidence: ['pe_pdata_runtime_functions', 'function_index_entries'],
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

function buildPdataQualityGates(data: PdataExtractData, input: PEPdataExtractInput) {
  return {
    schema: 'rikune.pe_pdata.quality_gates.v1',
    passive_static_analysis: true,
    builtin_parser_only: true,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    pdata_present: data.pdata_present,
    xdata_present: data.xdata_present,
    runtime_functions_recovered: data.count > 0,
    function_index_materialization_requested: input.materialize_functions,
    function_index_status: data.function_index_status ?? 'skipped',
    analyst_review_required: data.count > 0,
  }
}

function buildPdataNextActions(data: PdataExtractData) {
  return [
    data.function_index_status === 'ready'
      ? 'Use code.functions.list to review .pdata-derived function boundaries before reconstruction.'
      : 'Use code.functions.smart_recover if .pdata coverage is incomplete or materialization was skipped.',
    'Use pe.symbols.recover or code.functions.define to assign evidence-grounded names to recovered function boundaries.',
    'Use workflow.search to select a result-scoped evidence graph or reconstruction follow-up.',
  ]
}

function withPdataEnvelope(data: PdataExtractData, input: PEPdataExtractInput): PdataExtractData {
  return {
    ...data,
    evidence_summary: buildPdataEvidenceSummary(data, input),
    workflow_handoff: buildPdataWorkflowHandoff(data, input),
    quality_gates: buildPdataQualityGates(data, input),
    recommended_next_tools: PDATA_RECOMMENDED_NEXT_TOOLS,
    next_actions: buildPdataNextActions(data),
  }
}

export function createPEPdataExtractHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, cacheManager } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = pePdataExtractInputSchema.parse(args)
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
        args: {},
      })

      if (!input.force_refresh) {
        const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
        if (cachedLookup) {
          const cachedData = cachedLookup.data as PdataExtractData
          const materialization = input.materialize_functions
            ? materializePdataFunctions(
                database,
                input.sample_id,
                cachedData,
                input.replace_existing_functions
              )
            : skippedMaterializationSummary()
          return {
            ok: true,
            data: withPdataEnvelope({ ...cachedData, ...materialization }, input),
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
      const result = extractPdataFromPE(samplePath)
      const normalized: PdataExtractData = {
        machine: result.machine,
        machine_name: result.machineName,
        image_base: result.imageBase,
        entry_point_rva: result.entryPointRva,
        exception_directory_rva: result.exceptionDirectoryRva,
        exception_directory_size: result.exceptionDirectorySize,
        pdata_present: result.pdataPresent,
        xdata_present: result.xdataPresent,
        count: result.count,
        sections: result.sections.map((section) => ({
          name: section.name,
          virtual_address: section.virtualAddress,
          virtual_size: section.virtualSize,
          raw_size: section.rawSize,
          raw_pointer: section.rawPointer,
          characteristics: section.characteristics,
          executable: section.executable,
        })),
        exports: result.exports.map((record) => ({
          rva: record.rva,
          name: record.name,
          ordinal: record.ordinal,
          is_forwarder: record.isForwarder,
        })),
        entries: result.entries.map((entry) => ({
          begin_rva: entry.beginRva,
          end_rva: entry.endRva,
          size: entry.size,
          begin_va: entry.beginVa,
          end_va: entry.endVa,
          begin_address: entry.beginAddress,
          end_address: entry.endAddress,
          unwind_info_rva: entry.unwindInfoRva,
          section_name: entry.sectionName,
          executable_section: entry.executableSection,
          confidence: entry.confidence,
          unwind: entry.unwind
            ? {
                version: entry.unwind.version,
                flags: entry.unwind.flags,
                flag_names: entry.unwind.flagNames,
                prolog_size: entry.unwind.prologSize,
                unwind_code_count: entry.unwind.unwindCodeCount,
                frame_register: entry.unwind.frameRegister,
                frame_register_id: entry.unwind.frameRegisterId,
                frame_offset: entry.unwind.frameOffset,
                handler_rva: entry.unwind.handlerRva,
                chained_runtime_function: entry.unwind.chainedRuntimeFunction
                  ? {
                      begin_rva: entry.unwind.chainedRuntimeFunction.beginRva,
                      end_rva: entry.unwind.chainedRuntimeFunction.endRva,
                      unwind_info_rva: entry.unwind.chainedRuntimeFunction.unwindInfoRva,
                    }
                  : undefined,
              }
            : null,
        })),
        warnings: result.warnings,
      }

      await cacheManager.setCachedResult(cacheKey, normalized, CACHE_TTL_MS, sample.sha256)
      const materialization = input.materialize_functions
        ? materializePdataFunctions(
            database,
            input.sample_id,
            normalized,
            input.replace_existing_functions
          )
        : skippedMaterializationSummary()

      return {
        ok: true,
        data: withPdataEnvelope({ ...normalized, ...materialization }, input),
        warnings: result.warnings.length > 0 ? result.warnings : undefined,
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
