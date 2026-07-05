/**
 * angr analyze tool - bounded angr static analysis against a sample.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from '../../docker-shared.js'
import {
  ArtifactRefSchema,
  BackendSchema,
  SharedMetricsSchema,
  normalizeError,
  runPythonJson,
  persistBackendArtifact,
  buildMetrics,
  buildStaticSetupRequired,
  resolveSampleFile,
  resolveAnalysisBackends,
} from '../../docker-shared.js'

const TOOL_NAME = 'angr.analyze'
const TOOL_VERSION = '0.2.0'
const ANGR_ANALYSES = ['cfg_fast'] as const
const ANGR_ARTIFACT_TYPE = 'backend_angr_cfg_fast'
const ANGR_RECOMMENDED_NEXT_TOOLS = ['artifact.read', 'workflow.search']
const ANGR_PROFILE_NEXT_TOOLS = [
  'code.functions.smart_recover',
  'analysis.evidence.graph',
  'report.generate',
]
const ANGR_SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]

export const angrAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  analysis: z
    .enum(ANGR_ANALYSES)
    .default('cfg_fast')
    .describe('angr analysis mode. cfg_fast is the bounded default.'),
  timeout_sec: z
    .number()
    .int()
    .min(5)
    .max(300)
    .default(60)
    .describe('angr execution timeout in seconds.'),
  max_functions: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(25)
    .describe('Maximum function previews to return.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist the angr summary JSON as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const angrAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      analysis: z.string().optional(),
      arch: z.string().nullable().optional(),
      entry: z.string().nullable().optional(),
      node_count: z.number().int().nonnegative().optional(),
      edge_count: z.number().int().nonnegative().optional(),
      function_count: z.number().int().nonnegative().optional(),
      functions: z.array(z.any()).optional(),
      raw_angr_result: z.record(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const angrAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Run bounded angr static analysis against a sample. Use this when you explicitly want angr-backed CFG recovery or function discovery instead of the default Ghidra flow.',
  inputSchema: angrAnalyzeInputSchema,
  outputSchema: angrAnalyzeOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'shellcode', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc'],
    execution: ['static', 'triage'],
    runtimes: ['angr'],
    safety: ANGR_SAFETY,
    capabilities: [
      'cfg',
      'function-discovery',
      'control-flow',
      'symbolic-execution',
      'path-exploration',
      'cross-backend-corroboration',
      'workflow-handoff',
    ],
    evidence: ['structure', 'symbols', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: ANGR_ARTIFACT_TYPE,
      description: 'Bounded angr CFGFast function and control-flow summary envelope',
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: [ANGR_ARTIFACT_TYPE],
    },
    {
      category: 'symbols',
      artifactTypes: [ANGR_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [ANGR_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [ANGR_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'angr.cfgfast-handoff',
      title: 'angr CFGFast handoff',
      description:
        'Run bounded angr CFGFast static analysis, then hand off recovered function and CFG evidence to artifact review, smart function recovery, evidence graph, and reporting.',
      startsWith: [TOOL_NAME],
      nextTools: [...ANGR_RECOMMENDED_NEXT_TOOLS, ...ANGR_PROFILE_NEXT_TOOLS],
      requiredArtifacts: ['sample'],
      producesArtifacts: [ANGR_ARTIFACT_TYPE],
      evidence: ['structure', 'symbols', 'workflow', 'provenance'],
      safety: ANGR_SAFETY,
      runtimeBackends: ['angr'],
      analyses: ANGR_ANALYSES,
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: false,
    allowedBackends: ['local'],
    maxRuntimeMs: 300000,
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'angr is used as a bounded read-only static backend and must not execute the sample.',
      'workflow.search should activate only angr.analyze for this profile before broader symbolic or cross-backend workflows.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'angr',
    backendKind: 'external',
    adapter: 'angr.cfgfast.preview',
    availability: 'optional',
    envVar: 'ANGR_PYTHON',
    commandHint: 'python -c "import angr"',
    versionHint: 'python -c "import angr; print(angr.__version__)"',
    supportedModes: [...ANGR_ANALYSES],
    defaultMode: 'cfg_fast',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [ANGR_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 60000,
      maxOutputBytes: 16 * 1024 * 1024,
      notes: ['Only CFGFast summary data is returned by this tool.'],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Set ANGR_PYTHON to a Python interpreter with angr installed, or install angr in the analyzer environment.',
      ],
      missingBackendBehavior: 'Return setup_required without importing angr or running analysis.',
    },
    packaging: {
      installRoute: 'profile-gated',
      installProfile: 'research',
      dockerFeature: 'angr',
      envVar: 'ANGR_PYTHON',
      dockerDefault: '/opt/angr/bin/python',
    },
  },
}

const ANGR_CFGFAST_SCRIPT = `
import json
import sys
import angr

payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
max_functions = int(payload.get("max_functions", 25))

project = angr.Project(sample_path, load_options={"auto_load_libs": False})
cfg = project.analyses.CFGFast(normalize=True)
functions = []
for addr, func in cfg.kb.functions.items():
    name = getattr(func, "name", None)
    if not name:
        continue
    block_count = len(getattr(func, "block_addrs", []) or [])
    functions.append({
        "address": hex(int(addr)),
        "name": name,
        "block_count": block_count,
        "returning": bool(getattr(func, "returning", False)),
        "unresolved_calls": bool(getattr(func, "has_unresolved_calls", False)),
        "unresolved_jumps": bool(getattr(func, "has_unresolved_jumps", False)),
    })

functions.sort(key=lambda item: (-item["block_count"], item["address"]))
graph = cfg.model.graph
print(json.dumps({
    "arch": str(project.arch),
    "entry": hex(int(project.entry)) if project.entry is not None else None,
    "node_count": len(graph.nodes()),
    "edge_count": len(graph.edges()),
    "function_count": len(functions),
    "functions": functions[:max_functions],
}, ensure_ascii=False))
`.trim()

function buildAngrEvidenceSummary(args: {
  sampleId: string
  analysis: z.infer<typeof angrAnalyzeInputSchema>['analysis']
  arch: string | null
  entry: string | null
  nodeCount: number
  edgeCount: number
  functionCount: number
  previewFunctionCount: number
  artifact?: ArtifactRef
  backendVersion?: string | null
}) {
  return {
    schema: 'rikune.angr_cfgfast.evidence_summary.v1',
    source_tool: TOOL_NAME,
    tool_version: TOOL_VERSION,
    artifact_type: ANGR_ARTIFACT_TYPE,
    sample_id: args.sampleId,
    analysis: args.analysis,
    arch: args.arch,
    entry: args.entry,
    node_count: args.nodeCount,
    edge_count: args.edgeCount,
    function_count: args.functionCount,
    preview_function_count: args.previewFunctionCount,
    artifact_id: args.artifact?.id ?? null,
    backend_version: args.backendVersion ?? null,
  }
}

function buildAngrQualityGates(args: {
  analysis: z.infer<typeof angrAnalyzeInputSchema>['analysis']
  functionCount: number
  nodeCount: number
  artifactPersisted: boolean
}) {
  return {
    schema: 'rikune.angr_cfgfast.quality_gates.v1',
    passive_static_analysis: true,
    read_only_backend: true,
    sample_executed_by_tool: false,
    backend_started_with_bounded_command: true,
    network_accessed_by_tool: false,
    mutation_performed: false,
    output_bounded_inline: true,
    artifact_persisted: args.artifactPersisted,
    analyst_review_required: true,
    analysis: args.analysis,
    function_count: args.functionCount,
    node_count: args.nodeCount,
  }
}

function buildAngrWorkflowHandoff(args: {
  sampleId: string
  analysis: z.infer<typeof angrAnalyzeInputSchema>['analysis']
  functionCount: number
  artifact?: ArtifactRef
}) {
  return {
    schema: 'rikune.angr_cfgfast.workflow_handoff.v1',
    handoff_mode: 'angr_cfgfast_to_function_recovery_review',
    artifact_type: ANGR_ARTIFACT_TYPE,
    sample_id: args.sampleId,
    analysis: args.analysis,
    function_count: args.functionCount,
    recommended_next_tools: ANGR_RECOMMENDED_NEXT_TOOLS,
    artifact_contract: {
      type: ANGR_ARTIFACT_TYPE,
      suggested_read_mode: 'profile',
      artifact_id: args.artifact?.id ?? null,
      content_kind: 'angr_cfgfast_function_and_cfg_summary',
    },
    routing: [
      {
        goal: 'review-angr-cfgfast-preview',
        priority: 'high',
        next_tools: ['artifact.read'],
        required_evidence: [ANGR_ARTIFACT_TYPE],
      },
      {
        goal: 'recover-and-corroborate-functions',
        priority: args.functionCount > 0 ? 'high' : 'normal',
        next_tools: ['code.functions.smart_recover', 'analysis.evidence.graph'],
        required_evidence: [ANGR_ARTIFACT_TYPE, 'paired function evidence'],
      },
      {
        goal: 'report-angr-cfg-findings',
        priority: 'normal',
        next_tools: ['report.generate'],
        required_evidence: [ANGR_ARTIFACT_TYPE],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: true,
      backend_kind: 'external-static',
      live_execution_started: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildAngrNextActions(args: { artifact?: ArtifactRef; functionCount: number }) {
  return [
    args.artifact
      ? 'Use artifact.read in profile mode to inspect the persisted angr CFGFast envelope.'
      : 'Persist an angr CFGFast artifact before relying on this result for function recovery review.',
    'Use workflow.search to select a result-scoped function recovery or evidence graph follow-up instead of exposing broad symbolic-execution tools.',
    args.functionCount > 0
      ? 'Corroborate angr function boundaries with Ghidra, Rizin, RetDec, pdata, or another backend before reconstruction.'
      : 'Run a format-specific static inventory before escalating to deeper symbolic analysis.',
  ]
}

export function createAngrAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = angrAnalyzeInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.angr
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, angrAnalyzeToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(
        backend.path,
        ANGR_CFGFAST_SCRIPT,
        {
          sample_path: samplePath,
          max_functions: input.max_functions,
        },
        input.timeout_sec * 1000
      )

      const parsed = result.parsed && typeof result.parsed === 'object' ? result.parsed : {}
      const arch = typeof parsed?.arch === 'string' ? parsed.arch : null
      const entry = typeof parsed?.entry === 'string' ? parsed.entry : null
      const nodeCount = Number(parsed?.node_count || 0)
      const edgeCount = Number(parsed?.edge_count || 0)
      const functionCount = Number(parsed?.function_count || 0)
      const functions = Array.isArray(parsed?.functions) ? parsed.functions : []
      const baseOutputData = {
        schema: 'rikune.angr_cfgfast.v1',
        tool_version: TOOL_VERSION,
        status: 'ready',
        backend,
        sample_id: input.sample_id,
        analysis: input.analysis,
        arch,
        entry,
        node_count: nodeCount,
        edge_count: edgeCount,
        function_count: functionCount,
        functions,
        raw_angr_result: parsed,
        summary: `angr CFGFast recovered ${functionCount} function(s) for ${input.sample_id}.`,
      } satisfies Record<string, unknown>

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        const artifactPayload = {
          ...baseOutputData,
          evidence_summary: buildAngrEvidenceSummary({
            sampleId: input.sample_id,
            analysis: input.analysis,
            arch,
            entry,
            nodeCount,
            edgeCount,
            functionCount,
            previewFunctionCount: functions.length,
            backendVersion: backend.version,
          }),
          workflow_handoff: buildAngrWorkflowHandoff({
            sampleId: input.sample_id,
            analysis: input.analysis,
            functionCount,
          }),
          quality_gates: buildAngrQualityGates({
            analysis: input.analysis,
            functionCount,
            nodeCount,
            artifactPersisted: true,
          }),
          recommended_next_tools: ANGR_RECOMMENDED_NEXT_TOOLS,
          next_actions: buildAngrNextActions({ functionCount }),
        }
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'angr',
          input.analysis,
          JSON.stringify(artifactPayload, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          ...baseOutputData,
          artifact,
          evidence_summary: buildAngrEvidenceSummary({
            sampleId: input.sample_id,
            analysis: input.analysis,
            arch,
            entry,
            nodeCount,
            edgeCount,
            functionCount,
            previewFunctionCount: functions.length,
            artifact,
            backendVersion: backend.version,
          }),
          workflow_handoff: buildAngrWorkflowHandoff({
            sampleId: input.sample_id,
            analysis: input.analysis,
            functionCount,
            artifact,
          }),
          quality_gates: buildAngrQualityGates({
            analysis: input.analysis,
            functionCount,
            nodeCount,
            artifactPersisted: Boolean(artifact),
          }),
          recommended_next_tools: ANGR_RECOMMENDED_NEXT_TOOLS,
          next_actions: buildAngrNextActions({ artifact, functionCount }),
        },
        artifacts,
        metrics: buildMetrics(startTime, angrAnalyzeToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, angrAnalyzeToolDefinition.name),
      }
    }
  }
}
