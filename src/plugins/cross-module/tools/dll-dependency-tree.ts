/**
 * dll.dependency.tree MCP tool — Build a dependency tree for a binary,
 * resolving which DLLs/SOs are in the sample set vs system/external.
 * Highlights potential DLL side-loading / hijacking opportunities.
 */

import { z } from 'zod'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
  type ArtifactRef,
  type PluginToolDeps,
} from '../../sdk.js'

const TOOL_NAME = 'dll.dependency.tree'
export const DLL_DEPENDENCY_TREE_ARTIFACT_TYPE = 'dll_dependency_tree'
export const DLL_DEPENDENCY_TREE_SAFETY = [
  'passive',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
  'no_sample_execution',
]
export const DLL_DEPENDENCY_TREE_EVIDENCE = [
  'imports',
  'dll-dependency',
  'dependency-tree',
  'dependency-graph',
  'sideload-risk',
  'cross-module',
  'workflow',
  'provenance',
]
export const DLL_DEPENDENCY_TREE_FOLLOW_UP_TOOLS = [
  'pe.imports.extract',
  'pe.exports.extract',
  'pe.structure.analyze',
  'elf.imports.extract',
  'elf.exports.extract',
  'elf.structure.analyze',
  'macho.structure.analyze',
  'native.object.inventory',
  'analysis.evidence.graph',
  'report.generate',
]
export const DLL_DEPENDENCY_TREE_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'DLL dependency tree analysis classifies static import table evidence only.',
    'The tool does not load libraries, resolve dependencies through the OS loader, execute samples, or mutate files.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}

export const DllDependencyTreeInputSchema = z.object({
  sample_id: z.string().describe('Root sample ID (format: sha256:<hex>)'),
  known_sample_ids: z
    .array(z.string())
    .optional()
    .describe('Additional sample IDs for DLLs that may be dependencies'),
})

export const DllDependencyTreeOutputSchema = createWorkerResultOutputSchema(
  z.object({
    sample_id: z.string(),
    total_dependencies: z.number().int().nonnegative(),
    system_deps: z.number().int().nonnegative(),
    known_sample_deps: z.number().int().nonnegative(),
    unknown_deps: z.number().int().nonnegative(),
    sideload_candidates: z.array(z.string()),
    dependencies: z.array(
      z.object({
        dll: z.string(),
        classification: z.enum(['system', 'known_sample', 'unknown']),
        sample_id: z.string().optional(),
        function_count: z.number().int().nonnegative(),
        sideload_risk: z.boolean(),
        functions: z.array(z.string()),
      })
    ),
  })
)

export const dllDependencyTreeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a dependency tree for a binary starting from its import table. ' +
    'Classifies each dependency as known-system, known-sample (in your collection), ' +
    'or unknown/suspicious. Flags potential DLL side-loading vectors and exposes dependency graph, cross-module, imports/exports/symbols/call graph, and DLL dependency search metadata.',
  inputSchema: DllDependencyTreeInputSchema,
  outputSchema: DllDependencyTreeOutputSchema,
  aspects: {
    formats: ['pe', 'dll', 'exe', 'elf', 'so', 'macho', 'dylib', 'native'],
    platforms: ['windows', 'linux', 'macos', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage', 'correlation'],
    safety: DLL_DEPENDENCY_TREE_SAFETY,
    capabilities: [
      'dll-dependency',
      'dependency-tree',
      'dependency-graph',
      'cross-module',
      'import-table',
      'sideload-risk',
      'routing',
      'search-profile',
      'workflow-handoff',
    ],
    evidence: DLL_DEPENDENCY_TREE_EVIDENCE,
  },
  artifacts: [
    {
      type: DLL_DEPENDENCY_TREE_ARTIFACT_TYPE,
      description:
        'Passive dependency tree with system, known-sample, unknown, and sideload-risk classifications',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'imports', artifactTypes: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE] },
    { category: 'dll-dependency', artifactTypes: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE] },
    { category: 'dependency-tree', artifactTypes: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE] },
    { category: 'dependency-graph', artifactTypes: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE] },
    { category: 'sideload-risk', artifactTypes: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE] },
    { category: 'cross-module', artifactTypes: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'cross-module.dll-dependency-handoff',
      title: 'DLL and native dependency graph handoff',
      description:
        'Classify DLL, SO, dylib, and native dependency graph evidence from import tables, then route unresolved, known-sample, and sideload-risk nodes into format-specific static analysis, evidence graph, and reporting.',
      startsWith: [TOOL_NAME],
      nextTools: DLL_DEPENDENCY_TREE_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample', 'static import evidence'],
      producesArtifacts: [DLL_DEPENDENCY_TREE_ARTIFACT_TYPE],
      evidence: DLL_DEPENDENCY_TREE_EVIDENCE,
      safety: DLL_DEPENDENCY_TREE_SAFETY,
      handoff: {
        recommended: DLL_DEPENDENCY_TREE_FOLLOW_UP_TOOLS,
        routes: ['pe', 'elf', 'macho', 'native', 'analysis.evidence.graph', 'report.generate'],
      },
    },
  ],
  runtimePolicy: DLL_DEPENDENCY_TREE_RUNTIME_POLICY,
}

const KNOWN_SYSTEM_DLLS = new Set([
  'kernel32.dll',
  'ntdll.dll',
  'user32.dll',
  'gdi32.dll',
  'advapi32.dll',
  'ole32.dll',
  'oleaut32.dll',
  'shell32.dll',
  'comctl32.dll',
  'comdlg32.dll',
  'ws2_32.dll',
  'wsock32.dll',
  'wininet.dll',
  'winhttp.dll',
  'urlmon.dll',
  'msvcrt.dll',
  'msvcr100.dll',
  'msvcr110.dll',
  'msvcr120.dll',
  'msvcr140.dll',
  'vcruntime140.dll',
  'ucrtbase.dll',
  'msvcp140.dll',
  'crypt32.dll',
  'bcrypt.dll',
  'ncrypt.dll',
  'wintrust.dll',
  'rpcrt4.dll',
  'secur32.dll',
  'shlwapi.dll',
  'version.dll',
  'iphlpapi.dll',
  'dnsapi.dll',
  'netapi32.dll',
  'psapi.dll',
  'dbghelp.dll',
  'imagehlp.dll',
  'setupapi.dll',
  'cfgmgr32.dll',
  'devobj.dll',
  'wtsapi32.dll',
  'mpr.dll',
  'userenv.dll',
  'sspicli.dll',
  'cryptbase.dll',
  'kernelbase.dll',
  'api-ms-win-core-synch-l1-1-0.dll',
  'api-ms-win-core-processthreads-l1-1-0.dll',
  'libc.so.6',
  'libm.so.6',
  'libdl.so.2',
  'libpthread.so.0',
  'librt.so.1',
  'ld-linux-x86-64.so.2',
  'libstdc++.so.6',
  'libgcc_s.so.1',
])

export function createDllDependencyTreeHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof DllDependencyTreeInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      // Build a map of known sample module names → sample_id
      const knownModules = new Map<string, string>()
      const allSampleIds = [args.sample_id, ...(args.known_sample_ids ?? [])]
      for (const sid of allSampleIds) {
        const s = database.findSample(sid)
        if (!s) continue
        const name = s.file_type ?? sid.replace('sha256:', '').slice(0, 12)
        if (name) knownModules.set(name.toLowerCase(), sid)
      }

      // Extract imports from root sample
      const imports: Array<{ dll: string; function_count: number; functions: string[] }> = []
      const evidence = database.findAnalysisEvidenceBySample(args.sample_id)
      if (Array.isArray(evidence)) {
        for (const entry of evidence) {
          try {
            const data =
              typeof entry.result_json === 'string'
                ? JSON.parse(entry.result_json)
                : entry.result_json
            const family = entry.evidence_family ?? ''

            if (family === 'pe_imports' || family === 'elf_imports') {
              const impEntries = data?.data?.imports ?? data?.imports ?? []
              const grouped = new Map<string, string[]>()
              for (const imp of impEntries) {
                if (imp.dll && imp.functions) {
                  const dll = imp.dll.toLowerCase()
                  grouped.set(
                    dll,
                    (imp.functions as Array<{ name?: string }>).map((f) => f.name ?? 'unknown')
                  )
                } else if (imp.dll && (imp.name || imp.function_name)) {
                  const dll = imp.dll.toLowerCase()
                  const existing = grouped.get(dll) ?? []
                  existing.push(imp.name ?? imp.function_name)
                  grouped.set(dll, existing)
                }
              }
              for (const [dll, fns] of grouped) {
                imports.push({ dll, function_count: fns.length, functions: fns })
              }
            }
          } catch {
            /* skip */
          }
        }
      }

      // Classify dependencies
      interface DepNode {
        dll: string
        classification: 'system' | 'known_sample' | 'unknown'
        sample_id?: string
        function_count: number
        sideload_risk: boolean
        functions: string[]
      }

      const deps_list: DepNode[] = []
      const unknownDlls: string[] = []

      for (const imp of imports) {
        const dllLower = imp.dll.toLowerCase()
        const isSystem = KNOWN_SYSTEM_DLLS.has(dllLower) || dllLower.startsWith('api-ms-win-')
        const knownSampleId = knownModules.get(dllLower)

        const classification = isSystem ? 'system' : knownSampleId ? 'known_sample' : 'unknown'

        const sideloadRisk = !isSystem && !dllLower.includes('\\') && !dllLower.includes('/')

        if (classification === 'unknown') unknownDlls.push(imp.dll)

        deps_list.push({
          dll: imp.dll,
          classification,
          sample_id: knownSampleId,
          function_count: imp.function_count,
          sideload_risk: sideloadRisk,
          functions: imp.functions.slice(0, 30),
        })
      }

      const resultData = {
        sample_id: args.sample_id,
        total_dependencies: deps_list.length,
        system_deps: deps_list.filter((d) => d.classification === 'system').length,
        known_sample_deps: deps_list.filter((d) => d.classification === 'known_sample').length,
        unknown_deps: deps_list.filter((d) => d.classification === 'unknown').length,
        sideload_candidates: deps_list.filter((d) => d.sideload_risk).map((d) => d.dll),
        dependencies: deps_list.sort((a, b) => {
          const order = { unknown: 0, known_sample: 1, system: 2 }
          return order[a.classification] - order[b.classification]
        }),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          'dll_dependency_tree',
          'dll-dependency-tree',
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
