/**
 * host.correlate MCP tool — auto-scan a directory and system artifacts
 * to correlate a DLL/EXE with its host, loader, and execution context.
 *
 * Scans for:
 *   - Co-located EXE files that may load the DLL (import table analysis)
 *   - Scheduled tasks referencing the sample path
 *   - Windows services registered with the sample
 *   - Startup folder / Run key entries
 *   - DLL sideloading configuration files (manifests, .local, .config)
 *   - COM registration entries
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'

const TOOL_NAME = 'host.correlate'
const TOOL_VERSION = '1.1.0'
export const HOST_CORRELATION_ARTIFACT_TYPE = 'host_correlation'
export const HOST_CORRELATION_FORMATS = [
  'pe',
  'dll',
  'exe',
  'windows',
  'windows-host-artifacts',
  'manifest',
  'registry',
  'scheduled-task',
  'service',
  'startup-entry',
  'com-registration',
]
export const HOST_CORRELATION_SAFETY = [
  'passive',
  'no_sample_execution',
  'no_host_mutation',
  'no_network_by_default',
  'no_live_sample_by_default',
]
export const HOST_CORRELATION_CAPABILITIES = [
  'host-correlation',
  'loader-correlation',
  'sideloading-analysis',
  'scheduled-task-correlation',
  'service-correlation',
  'startup-correlation',
  'com-correlation',
  'import-table-correlation',
  'workflow-plan',
  'workflow-handoff',
  'search-profile',
  'evidence-correlation',
]
export const HOST_CORRELATION_EVIDENCE = [
  'process',
  'filesystem',
  'registry',
  'imports',
  'manifest',
  'persistence',
  'sideloading',
  'workflow',
  'provenance',
  'search-profile',
]
export const HOST_CORRELATION_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'pe.structure.analyze',
  'dll.dependency.tree',
  'analysis.evidence.graph',
  'attack.map',
  'windows.runtime.plan',
  'report.generate',
]
export const HOST_CORRELATION_WORKFLOW_RECIPES = [
  {
    id: 'host-correlation.loader-context-handoff',
    title: 'Host loader and persistence correlation handoff',
    description:
      'Correlate PE host processes, DLL sideloading files, scheduled tasks, services, startup entries, COM registration, and import-table references into a passive evidence handoff for graphing and reporting.',
    startsWith: [TOOL_NAME],
    nextTools: HOST_CORRELATION_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [HOST_CORRELATION_ARTIFACT_TYPE],
    evidence: HOST_CORRELATION_EVIDENCE,
    safety: HOST_CORRELATION_SAFETY,
    runtimeBackends: ['local'],
  },
]
export const HOST_CORRELATION_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noSampleExecution: true,
  noHostMutation: true,
  notes: [
    'The default workflow reads local sample-adjacent files and host artifact exports only.',
    'It does not execute the sample, mutate host state, or use network access.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noSampleExecution: true
  noHostMutation: true
}

export const HostCorrelateInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  scan_directory: z
    .string()
    .optional()
    .describe('Directory to scan for co-located files (defaults to sample directory)'),
  check_scheduled_tasks: z
    .boolean()
    .default(true)
    .describe('Search scheduled tasks for references to the sample'),
  check_services: z
    .boolean()
    .default(true)
    .describe('Search Windows services for references to the sample'),
  check_startup: z
    .boolean()
    .default(true)
    .describe('Check startup folders and Run/RunOnce registry keys'),
  check_sideload: z
    .boolean()
    .default(true)
    .describe('Scan for DLL sideloading configs (.manifest, .local, .config)'),
  check_com_registration: z
    .boolean()
    .default(true)
    .describe('Search COM registration for CLSIDs pointing to the sample'),
  check_import_tables: z
    .boolean()
    .default(true)
    .describe('Analyze import tables of co-located EXEs for DLL references'),
  recursive: z.boolean().default(false).describe('Recursively scan subdirectories'),
  max_depth: z
    .number()
    .min(1)
    .max(5)
    .default(2)
    .describe('Maximum directory traversal depth when recursive is enabled'),
})

export const HostCorrelateOutputSchema = z
  .object({
    ok: z.boolean(),
    data: z.object({}).passthrough().optional(),
    artifacts: z.array(z.any()).optional(),
    errors: z.array(z.string()).optional(),
    metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).passthrough().optional(),
  })
  .passthrough()

export type HostCorrelateInput = z.infer<typeof HostCorrelateInputSchema>

export const hostCorrelateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Auto-scan directory and system artifacts to correlate a DLL/EXE with its host ' +
    'process, loader, and execution context. Checks co-located EXE import tables, ' +
    'scheduled tasks, services, startup entries, DLL sideloading configs, and COM ' +
    'registration to build a complete picture of how the sample is loaded and executed.',
  inputSchema: HostCorrelateInputSchema,
  outputSchema: HostCorrelateOutputSchema,
  aspects: {
    formats: HOST_CORRELATION_FORMATS,
    platforms: ['windows'],
    execution: ['static', 'triage', 'correlation'],
    safety: HOST_CORRELATION_SAFETY,
    capabilities: HOST_CORRELATION_CAPABILITIES,
    evidence: HOST_CORRELATION_EVIDENCE,
  },
  artifacts: [
    {
      type: HOST_CORRELATION_ARTIFACT_TYPE,
      description: 'Host process, loader, persistence, and sideloading correlation results',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'process', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
    { category: 'filesystem', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
    { category: 'registry', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
    { category: 'imports', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
    { category: 'manifest', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
    { category: 'persistence', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
    { category: 'sideloading', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE] },
  ],
  workflowRecipes: HOST_CORRELATION_WORKFLOW_RECIPES,
  runtimePolicy: HOST_CORRELATION_RUNTIME_POLICY,
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'Bundled host correlation worker',
    backendKind: 'external',
    adapter: 'builtin.host.correlation',
    availability: 'required',
    supportedModes: ['local'],
    defaultMode: 'local',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [HOST_CORRELATION_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: false,
      requiresIsolation: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 30_000,
      notes: [
        'Bundled Python worker scans local file metadata and bounded PE import tables.',
        'Worker policy forbids sample execution, host mutation, network access, and live runtime startup.',
      ],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [],
      missingBackendBehavior:
        'Host correlation is a bundled local Python worker; missing Python prevents scanning but does not trigger installation or backend startup.',
    },
    packaging: {
      installRoute: 'installed',
      installProfile: 'default',
      dockerFeature: 'host-correlation',
      notes: [
        'No external Windows service, registry writer, or network dependency is required for default passive correlation.',
      ],
    },
  },
}

async function callHostCorrelationWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath']
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath(
      'src',
      'plugins',
      'host-correlation',
      'workers',
      'host_correlation_worker.py'
    )
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => {
      stdout += d.toString()
    })
    proc.stderr.on('data', (d: Buffer) => {
      stderr += d.toString()
    })
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Host correlation worker exited ${code}: ${stderr.slice(0, 500)}`))
        return
      }
      try {
        resolve(JSON.parse(stdout.trim()))
      } catch (e) {
        reject(new Error(`Parse: ${(e as Error).message}`))
      }
    })
    proc.on('error', (e) => reject(new Error(`Spawn: ${e.message}`)))
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function countArrayField(record: Record<string, unknown>, field: string): number {
  const value = record[field]
  return Array.isArray(value) ? value.length : 0
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function buildRecommendedNextTools(counts: {
  host_exes: number
  sideloading: number
  scheduled_tasks: number
  services: number
  startup: number
  com_registration: number
}): string[] {
  return unique([
    'artifact.read',
    'analysis.evidence.graph',
    'report.generate',
    ...(counts.host_exes > 0 || counts.sideloading > 0
      ? ['pe.structure.analyze', 'dll.dependency.tree']
      : []),
    ...(counts.scheduled_tasks > 0 ||
    counts.services > 0 ||
    counts.startup > 0 ||
    counts.com_registration > 0
      ? ['attack.map', 'windows.runtime.plan']
      : []),
  ])
}

export function buildHostCorrelateCacheArgs(input: HostCorrelateInput): Record<string, unknown> {
  return {
    scan_directory: input.scan_directory ?? '',
    check_scheduled_tasks: input.check_scheduled_tasks,
    check_services: input.check_services,
    check_startup: input.check_startup,
    check_sideload: input.check_sideload,
    check_com_registration: input.check_com_registration,
    check_import_tables: input.check_import_tables,
    recursive: input.recursive,
    max_depth: input.max_depth,
  }
}

export function enrichHostCorrelationResult(
  workerResult: Record<string, unknown>,
  context: { sampleId: string; scanDirectory?: string | null }
): Record<string, unknown> {
  const workerData = isRecord(workerResult.data) ? workerResult.data : undefined
  if (!workerData) return workerResult

  const counts = {
    host_exes: countArrayField(workerData, 'host_exes'),
    sideloading: countArrayField(workerData, 'sideloading'),
    scheduled_tasks: countArrayField(workerData, 'scheduled_tasks'),
    services: countArrayField(workerData, 'services'),
    startup: countArrayField(workerData, 'startup'),
    com_registration: countArrayField(workerData, 'com_registration'),
  }
  const totalFindings =
    typeof workerData.total_findings === 'number'
      ? workerData.total_findings
      : Object.values(counts).reduce((sum, value) => sum + value, 0)
  const recommendedNextTools = buildRecommendedNextTools(counts)
  const scanDirectory =
    typeof workerData.scan_directory === 'string'
      ? workerData.scan_directory
      : (context.scanDirectory ?? null)

  return {
    ...workerResult,
    data: {
      ...workerData,
      policy: {
        passive: true,
        no_execute: true,
        no_sample_execution: true,
        no_host_mutation: true,
        no_network: true,
      },
      evidence_summary: {
        schema: 'rikune.host_correlation.evidence_summary.v1',
        source_tool: TOOL_NAME,
        artifact_type: HOST_CORRELATION_ARTIFACT_TYPE,
        sample_id: context.sampleId,
        scan_directory: scanDirectory,
        evidence_categories: HOST_CORRELATION_EVIDENCE,
        finding_counts: counts,
        total_findings: totalFindings,
        static_only: true,
        sample_executed_by_tool: false,
        host_mutated_by_tool: false,
        network_accessed_by_tool: false,
      },
      workflow_handoff: {
        schema: 'rikune.host_correlation.workflow_handoff.v1',
        handoff_mode: 'host_loader_context_to_evidence_graph_and_runtime_plan',
        artifact_type: HOST_CORRELATION_ARTIFACT_TYPE,
        recommended_next_tools: recommendedNextTools,
        artifact_contract: {
          consumes: ['sample', 'host filesystem metadata'],
          produces: [HOST_CORRELATION_ARTIFACT_TYPE],
          expected_consumers: [
            'workflow.search',
            'artifact.read',
            'analysis.evidence.graph',
            'attack.map',
            'report.generate',
          ],
        },
        routing: [
          {
            goal: 'loader-and-sideloading-static-analysis',
            priority: counts.host_exes > 0 || counts.sideloading > 0 ? 'high' : 'conditional',
            next_tools: ['pe.structure.analyze', 'dll.dependency.tree', 'analysis.evidence.graph'],
            required_evidence: ['host_exes', 'sideloading'],
            consumes: [HOST_CORRELATION_ARTIFACT_TYPE],
            produces: ['loader_context_graph'],
          },
          {
            goal: 'persistence-and-execution-context-reporting',
            priority:
              counts.scheduled_tasks > 0 ||
              counts.services > 0 ||
              counts.startup > 0 ||
              counts.com_registration > 0
                ? 'high'
                : 'conditional',
            next_tools: ['attack.map', 'windows.runtime.plan', 'report.generate'],
            required_evidence: ['scheduled_tasks', 'services', 'startup', 'com_registration'],
            consumes: [HOST_CORRELATION_ARTIFACT_TYPE],
            produces: ['host_persistence_context'],
          },
          {
            goal: 'evidence-graph-and-reporting',
            priority: 'normal',
            next_tools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
            required_evidence: [HOST_CORRELATION_ARTIFACT_TYPE],
            consumes: [HOST_CORRELATION_ARTIFACT_TYPE],
            produces: ['evidence_graph', 'analysis_report'],
          },
        ],
        dynamic_boundary: {
          sample_executed_by_tool: false,
          host_process_started_by_tool: false,
          service_modified_by_tool: false,
          scheduled_task_modified_by_tool: false,
          registry_modified_by_tool: false,
          network_accessed_by_tool: false,
          mutation_performed: false,
        },
      },
      quality_gates: {
        schema: 'rikune.host_correlation.quality_gates.v1',
        passive_correlation: true,
        sample_executed_by_tool: false,
        host_process_started_by_tool: false,
        service_modified_by_tool: false,
        scheduled_task_modified_by_tool: false,
        registry_modified_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        import_table_correlation_present: counts.host_exes > 0,
        sideloading_correlation_present: counts.sideloading > 0,
        persistence_correlation_present:
          counts.scheduled_tasks > 0 ||
          counts.services > 0 ||
          counts.startup > 0 ||
          counts.com_registration > 0,
      },
      recommended_next_tools: recommendedNextTools,
      next_actions: [
        'Review host loader, sideloading, and persistence evidence before dynamic execution.',
        'Publish host correlation evidence to the evidence graph before reporting.',
        'Use runtime planning tools only after explicit opt-in; this tool does not execute the sample or mutate the host.',
      ],
    },
  }
}

export function createHostCorrelateHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    config,
    cacheManager,
    generateCacheKey,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
    resolvePackagePath,
  } = deps
  const pythonCmd = getPythonCommand(undefined, config?.workers?.static?.pythonPath)

  return async (args: z.infer<typeof HostCorrelateInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = HostCorrelateInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: buildHostCorrelateCacheArgs(input),
      })
      const cached = await cacheManager!.getCachedResult(cacheKey)
      if (cached)
        return {
          ok: true,
          data: cached,
          metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME, cache: 'hit' },
        }

      const result = await callHostCorrelationWorker(
        {
          action: 'correlate',
          file_path: samplePath,
          scan_directory: input.scan_directory ?? null,
          check_scheduled_tasks: input.check_scheduled_tasks,
          check_services: input.check_services,
          check_startup: input.check_startup,
          check_sideload: input.check_sideload,
          check_com_registration: input.check_com_registration,
          check_import_tables: input.check_import_tables,
          recursive: input.recursive,
          max_depth: input.max_depth,
        },
        pythonCmd,
        resolvePackagePath
      )
      const enrichedResult = enrichHostCorrelationResult(result, {
        sampleId: input.sample_id,
        scanDirectory: input.scan_directory ?? null,
      })

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          HOST_CORRELATION_ARTIFACT_TYPE,
          'host-correlate',
          enrichedResult
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        /* non-fatal */
      }

      if (enrichedResult.ok)
        await cacheManager!.setCachedResult(
          cacheKey,
          enrichedResult,
          24 * 60 * 60 * 1000,
          sample.sha256
        )

      return {
        ok: Boolean(enrichedResult.ok),
        data: enrichedResult,
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
