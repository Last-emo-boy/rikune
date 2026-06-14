/**
 * call.graph.cross.module MCP tool — Build a cross-module call graph
 * from multiple related binaries (EXE + DLLs, main APK + .so libs, etc.)
 * by correlating imports ↔ exports across the set.
 */

import { z } from 'zod'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
  type ArtifactRef,
  type PluginToolDeps,
} from '../../sdk.js'

const TOOL_NAME = 'call.graph.cross.module'
export const CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE = 'cross_module_graph'
export const CALL_GRAPH_CROSS_MODULE_SAFETY = [
  'passive',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
  'no_sample_execution',
]
export const CALL_GRAPH_CROSS_MODULE_EVIDENCE = [
  'imports',
  'exports',
  'symbols',
  'call-graph',
  'dependency-graph',
  'cross-module',
  'workflow',
  'provenance',
]
export const CALL_GRAPH_CROSS_MODULE_FOLLOW_UP_TOOLS = [
  'pe.imports.extract',
  'pe.exports.extract',
  'pe.symbols.recover',
  'elf.imports.extract',
  'elf.exports.extract',
  'elf.structure.analyze',
  'macho.structure.analyze',
  'native.object.inventory',
  'analysis.evidence.graph',
  'report.generate',
]
export const CALL_GRAPH_CROSS_MODULE_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'Cross-module call graph reconstruction only correlates previously collected static import/export evidence.',
    'The tool does not load, link, execute, or mutate any module while building dependency graph metadata.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}

export const CallGraphCrossModuleInputSchema = z.object({
  sample_ids: z
    .array(z.string())
    .min(2)
    .max(30)
    .describe('Array of sample IDs representing related modules (EXE + DLLs, etc.)'),
  resolve_ordinals: z
    .boolean()
    .optional()
    .default(true)
    .describe('Attempt to resolve ordinal imports'),
})

export const CallGraphCrossModuleOutputSchema = createWorkerResultOutputSchema(
  z.object({
    module_count: z.number().int().nonnegative(),
    total_edges: z.number().int().nonnegative(),
    resolved_edges: z.number().int().nonnegative(),
    unresolved_edges: z.number().int().nonnegative(),
    modules: z.array(
      z.object({
        sample_id: z.string(),
        module_name: z.string(),
        export_count: z.number().int().nonnegative(),
        import_dll_count: z.number().int().nonnegative(),
      })
    ),
    dependency_graph: z.array(
      z.object({
        module: z.string(),
        depends_on: z.array(z.string()),
      })
    ),
    edges: z.array(
      z.object({
        caller_module: z.string(),
        caller_sample_id: z.string(),
        callee_module: z.string(),
        callee_sample_id: z.string(),
        function_name: z.string(),
        resolved: z.boolean(),
      })
    ),
  })
)

export const callGraphCrossModuleToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Reconstruct a cross-module call graph by matching import entries in each binary ' +
    'to export entries in other binaries of the set. Produces a directed graph of ' +
    'inter-module dependencies with resolved function-level edges when available. Supports ' +
    'workflow.search queries for dependency graph, cross-module, imports/exports/symbols/call graph, and handoff routing.',
  inputSchema: CallGraphCrossModuleInputSchema,
  outputSchema: CallGraphCrossModuleOutputSchema,
  aspects: {
    formats: ['pe', 'dll', 'exe', 'elf', 'so', 'macho', 'dylib', 'native'],
    platforms: ['windows', 'linux', 'macos', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage', 'correlation'],
    safety: CALL_GRAPH_CROSS_MODULE_SAFETY,
    capabilities: [
      'cross-module',
      'cross-module-call-graph',
      'call-graph',
      'dependency-graph',
      'imports-exports-correlation',
      'imports/exports/symbols/call-graph',
      'symbols',
      'routing',
      'search-profile',
      'workflow-handoff',
    ],
    evidence: CALL_GRAPH_CROSS_MODULE_EVIDENCE,
  },
  artifacts: [
    {
      type: CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE,
      description:
        'Cross-module dependency graph with import/export/symbol correlation and resolved call edges',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'imports', artifactTypes: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE] },
    { category: 'exports', artifactTypes: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE] },
    { category: 'call-graph', artifactTypes: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE] },
    { category: 'dependency-graph', artifactTypes: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE] },
    { category: 'cross-module', artifactTypes: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'cross-module.call-graph-correlation-handoff',
      title: 'Cross-module call graph and dependency correlation',
      description:
        'Correlate static imports, exports, symbols, and module dependency graph evidence across PE, ELF, Mach-O, DLL, SO, and dylib sets before evidence graph and report handoff.',
      startsWith: [TOOL_NAME],
      nextTools: CALL_GRAPH_CROSS_MODULE_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample', 'static import/export evidence'],
      producesArtifacts: [CALL_GRAPH_CROSS_MODULE_ARTIFACT_TYPE],
      evidence: CALL_GRAPH_CROSS_MODULE_EVIDENCE,
      safety: CALL_GRAPH_CROSS_MODULE_SAFETY,
      handoff: {
        recommended: CALL_GRAPH_CROSS_MODULE_FOLLOW_UP_TOOLS,
        routes: ['pe', 'elf', 'macho', 'native', 'analysis.evidence.graph', 'report.generate'],
      },
    },
  ],
  runtimePolicy: CALL_GRAPH_CROSS_MODULE_RUNTIME_POLICY,
}

interface ModuleInfo {
  sample_id: string
  module_name: string
  exports: Array<{ name: string; ordinal?: number; address?: string }>
  imports: Array<{ dll: string; functions: string[] }>
}

export function createCallGraphCrossModuleHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof CallGraphCrossModuleInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const modules: ModuleInfo[] = []

      for (const sid of args.sample_ids) {
        const sample = database.findSample(sid)
        if (!sample) {
          warnings.push(`Sample not found: ${sid}, skipping`)
          continue
        }

        const moduleName = sid.replace('sha256:', '').slice(0, 12)

        const exports: ModuleInfo['exports'] = []
        const imports: ModuleInfo['imports'] = []

        const evidence = database.findAnalysisEvidenceBySample(sid)
        if (Array.isArray(evidence)) {
          for (const entry of evidence) {
            try {
              const data =
                typeof entry.result_json === 'string'
                  ? JSON.parse(entry.result_json)
                  : entry.result_json
              const family = entry.evidence_family ?? ''

              if (family === 'pe_exports' || family === 'elf_exports' || family === 'dll_exports') {
                const exps = data?.data?.exports ?? data?.exports ?? []
                for (const exp of exps) {
                  exports.push({
                    name: exp.name ?? exp.function_name ?? `ord_${exp.ordinal}`,
                    ordinal: exp.ordinal,
                    address: exp.address ?? exp.rva,
                  })
                }
              }

              if (family === 'pe_imports' || family === 'elf_imports') {
                const impDlls = data?.data?.imports ?? data?.imports ?? []
                if (Array.isArray(impDlls)) {
                  const grouped = new Map<string, string[]>()
                  for (const imp of impDlls) {
                    if (imp.dll && imp.functions) {
                      const fns = (imp.functions as Array<{ name?: string }>).map(
                        (f) => f.name ?? 'unknown'
                      )
                      const existing = grouped.get(imp.dll.toLowerCase()) ?? []
                      grouped.set(imp.dll.toLowerCase(), [...existing, ...fns])
                    } else if (imp.dll && (imp.name || imp.function_name)) {
                      const dll = imp.dll.toLowerCase()
                      const existing = grouped.get(dll) ?? []
                      existing.push(imp.name ?? imp.function_name)
                      grouped.set(dll, existing)
                    }
                  }
                  for (const [dll, fns] of grouped) {
                    imports.push({ dll, functions: fns })
                  }
                }
              }
            } catch {
              /* skip malformed */
            }
          }
        }

        modules.push({ sample_id: sid, module_name: moduleName, exports, imports })
      }

      if (modules.length < 2) {
        return { ok: false, errors: ['Need at least 2 valid modules for cross-module graph'] }
      }

      // Build export lookup: dll_name.lower() → Map<function_name, {sample_id, address}>
      const exportIndex = new Map<string, Map<string, { sample_id: string; address?: string }>>()
      for (const mod of modules) {
        const nameKey = mod.module_name.toLowerCase()
        const fnMap = new Map<string, { sample_id: string; address?: string }>()
        for (const exp of mod.exports) {
          fnMap.set(exp.name.toLowerCase(), { sample_id: mod.sample_id, address: exp.address })
        }
        exportIndex.set(nameKey, fnMap)
        const withoutExt = nameKey.replace(/\.(dll|so|dylib|exe)$/i, '')
        if (withoutExt !== nameKey) exportIndex.set(withoutExt, fnMap)
      }

      // Resolve edges
      interface CrossEdge {
        caller_module: string
        caller_sample_id: string
        callee_module: string
        callee_sample_id: string
        function_name: string
        resolved: boolean
      }
      const edges: CrossEdge[] = []
      let resolvedCount = 0

      for (const mod of modules) {
        for (const imp of mod.imports) {
          const dllKey = imp.dll.toLowerCase().replace(/\.(dll|so|dylib|exe)$/i, '')
          const expMap = exportIndex.get(imp.dll.toLowerCase()) ?? exportIndex.get(dllKey)

          for (const fn of imp.functions) {
            if (expMap) {
              const target = expMap.get(fn.toLowerCase())
              if (target) {
                edges.push({
                  caller_module: mod.module_name,
                  caller_sample_id: mod.sample_id,
                  callee_module: imp.dll,
                  callee_sample_id: target.sample_id,
                  function_name: fn,
                  resolved: true,
                })
                resolvedCount++
                continue
              }
            }
            edges.push({
              caller_module: mod.module_name,
              caller_sample_id: mod.sample_id,
              callee_module: imp.dll,
              callee_sample_id: '',
              function_name: fn,
              resolved: false,
            })
          }
        }
      }

      // Module dependency summary
      const depSummary = new Map<string, Set<string>>()
      for (const e of edges) {
        const key = e.caller_module
        if (!depSummary.has(key)) depSummary.set(key, new Set())
        depSummary.get(key).add(e.callee_module)
      }

      const resultData = {
        module_count: modules.length,
        total_edges: edges.length,
        resolved_edges: resolvedCount,
        unresolved_edges: edges.length - resolvedCount,
        modules: modules.map((m) => ({
          sample_id: m.sample_id,
          module_name: m.module_name,
          export_count: m.exports.length,
          import_dll_count: m.imports.length,
        })),
        dependency_graph: [...depSummary.entries()].map(([mod, deps]) => ({
          module: mod,
          depends_on: [...deps],
        })),
        edges: edges.slice(0, 1000),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_ids[0],
          'cross_module_graph',
          'call-graph-cross-module',
          resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        /* non-fatal */
      }

      return {
        ok: true,
        data: resultData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
