/**
 * sandbox.execute tool
 * Dynamic-analysis execution entrypoint supporting simulation-first and Speakeasy user-mode emulation.
 */

import { spawn } from 'child_process'
import { existsSync } from 'fs'
import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { v4 as uuidv4 } from 'uuid'
import { z } from 'zod'
import {
  PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  RuntimeDelegationFailureResultSchema,
  SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  type ToolDefinition,
  type ToolArgs,
  type WorkerResult,
  type ArtifactRef,
} from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { PolicyGuard } from '../../../policy-guard.js'
import { normalizeDynamicTraceArtifactPayload } from '../../../artifacts/dynamic-trace.js'
import { resolvePackagePath } from '../../../runtime-paths.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'

const TOOL_NAME = 'sandbox.execute'
const TOOL_VERSION = '0.1.0'
const SANDBOX_EXECUTE_ARTIFACT_TYPES = [
  SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
]
const SANDBOX_EXECUTE_SAFETY = [
  'opt_in_dynamic',
  'requires_isolation',
  'approval_required_for_live_execution',
  'no_live_sample_by_default',
  'no_network_by_default',
  'profile_gated_execution',
]
const SANDBOX_EXECUTE_RECOMMENDED_NEXT_TOOLS = [
  'artifact.read',
  'dynamic.trace.import',
  'analysis.evidence.graph',
  'sandbox.report',
  'report.generate',
  'workflow.search',
]
const SANDBOX_EXECUTE_RUNTIME_POLICY: ToolDefinition['runtimePolicy'] = {
  passiveByDefault: true,
  requiresUserOptIn: true,
  requiresIsolation: true,
  allowedBackends: ['local', 'docker', 'windows-sandbox', 'hyperv'],
  maxRuntimeMs: 180_000,
  networkPolicy: 'disabled',
  notes: [
    'sandbox.execute defaults to safe simulation and requires explicit approval before live or emulator-backed dynamic execution.',
    'Speakeasy is an emulation mode profile; allowedBackends names the isolation carrier used to run or stage dynamic tooling.',
    'Network access is disabled by default and must remain explicit when a runtime profile enables fake or live network handling.',
  ],
}

export const SandboxExecuteInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  mode: z
    .enum(['safe_simulation', 'memory_guided', 'speakeasy', 'live_local'])
    .optional()
    .default('safe_simulation')
    .describe('Dynamic analysis backend mode'),
  timeout_sec: z.number().int().min(5).max(180).optional().default(20),
  network: z
    .enum(['disabled', 'fake', 'enabled'])
    .optional()
    .default('disabled')
    .describe('Network policy for dynamic run'),
  max_scan_bytes: z
    .number()
    .int()
    .min(256 * 1024)
    .max(20 * 1024 * 1024)
    .optional()
    .default(5 * 1024 * 1024)
    .describe('Simulation scan window for fast behavioral extraction'),
  approved: z
    .boolean()
    .optional()
    .default(false)
    .describe('Explicit approval flag required by PolicyGuard'),
  require_user_approval: z
    .boolean()
    .optional()
    .default(false)
    .describe('Compatibility approval flag accepted by PolicyGuard'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist sandbox run result as report artifact'),
})

export type SandboxExecuteInput = z.infer<typeof SandboxExecuteInputSchema>

const TimelineEventSchema = z.object({
  event_type: z.string(),
  category: z.string(),
  indicator: z.string(),
  confidence: z.number(),
})

const CapabilitySchema = z.object({
  name: z.string(),
  evidence_count: z.number(),
  confidence: z.number(),
})

const MemoryRegionSchema = z.object({
  region_type: z.string(),
  purpose: z.string(),
  source: z.string(),
  confidence: z.number(),
  start_offset: z.number().int().nonnegative().optional(),
  end_offset: z.number().int().nonnegative().optional(),
  indicators: z.array(z.string()),
})

const APIResolutionSchema = z.object({
  api: z.string(),
  provenance: z.string(),
  confidence: z.number(),
  sources: z.array(z.string()),
})

const ExecutionHypothesisSchema = z.object({
  stage: z.string(),
  description: z.string(),
  source: z.string(),
  confidence: z.number(),
  indicators: z.array(z.string()),
})

const SandboxExecuteSuccessResultSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      run_id: z.string(),
      status: z.enum(['completed', 'failed', 'timeout', 'denied']),
      mode: z.string(),
      backend: z.string(),
      simulated: z.boolean(),
      timeout_sec: z.number(),
      event_count: z.number(),
      timeline: z.array(TimelineEventSchema),
      iocs: z.record(z.array(z.string())),
      capabilities: z.array(CapabilitySchema),
      memory_regions: z.array(MemoryRegionSchema).optional(),
      api_resolution: z.array(APIResolutionSchema).optional(),
      execution_hypotheses: z.array(ExecutionHypothesisSchema).optional(),
      risk: z.object({
        score: z.number(),
        level: z.enum(['clean', 'low', 'medium', 'high']),
        confidence: z.number(),
      }),
      environment: z.object({
        network_policy: z.string(),
        executed: z.boolean(),
        isolation: z.string(),
      }),
      execution_semantics: z
        .object({
          live_windows_sandbox_execution: z.boolean(),
          live_hyperv_execution: z.boolean(),
          safe_simulation: z.boolean(),
          emulation: z.boolean(),
          user_visible_sandbox_window_expected: z.boolean(),
          explanation: z.string(),
        })
        .optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      evidence: z.record(z.any()),
      inference: z.object({
        classification: z.string(),
        summary: z.string(),
      }),
    })
    .optional(),
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

export const SandboxExecuteOutputSchema = z.union([
  SandboxExecuteSuccessResultSchema,
  RuntimeDelegationFailureResultSchema,
])

export const sandboxExecuteToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Execute dynamic-analysis workflow in safe simulation mode (default), memory-guided mode, or Speakeasy user-mode emulation and return timeline/IOC/risk outputs.',
  inputSchema: SandboxExecuteInputSchema,
  outputSchema: SandboxExecuteOutputSchema,
  aspects: {
    formats: ['pe', 'dll', 'dotnet', 'elf', 'shellcode'],
    platforms: ['windows', 'linux', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['dynamic', 'emulation', 'safe_simulation', 'triage'],
    runtimes: ['safe-simulation', 'speakeasy', 'windows-sandbox', 'hyperv'],
    safety: SANDBOX_EXECUTE_SAFETY,
    capabilities: [
      'dynamic-analysis',
      'safe-simulation',
      'memory-guided-execution-profile',
      'sandbox-trace',
      'runtime-trace',
      'ioc-extraction',
      'behavior-timeline',
      'workflow-handoff',
    ],
    evidence: ['behavior', 'network', 'filesystem', 'memory', 'timeline', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
      description: 'Sandbox execution envelope with timeline, IOC, risk, and backend semantics',
      mimeTypes: ['application/json'],
    },
    {
      type: PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
      description:
        'Normalized dynamic trace artifact for trace import, evidence graph, and reports',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'behavior', artifactTypes: SANDBOX_EXECUTE_ARTIFACT_TYPES },
    { category: 'network', artifactTypes: SANDBOX_EXECUTE_ARTIFACT_TYPES },
    { category: 'filesystem', artifactTypes: SANDBOX_EXECUTE_ARTIFACT_TYPES },
    { category: 'memory', artifactTypes: SANDBOX_EXECUTE_ARTIFACT_TYPES },
    { category: 'timeline', artifactTypes: SANDBOX_EXECUTE_ARTIFACT_TYPES },
    { category: 'workflow', artifactTypes: SANDBOX_EXECUTE_ARTIFACT_TYPES },
    { category: 'provenance', artifactTypes: SANDBOX_EXECUTE_ARTIFACT_TYPES },
  ],
  workflowRecipes: [
    {
      id: 'sandbox.dynamic-execution-profile',
      title: 'Sandbox dynamic trace and evidence handoff',
      description:
        'Run an approved safe simulation, memory-guided profile, emulator-backed trace, or isolated runtime capture, then hand persisted dynamic trace artifacts to artifact review, trace import, evidence graph, sandbox reporting, and report generation.',
      startsWith: [TOOL_NAME],
      nextTools: SANDBOX_EXECUTE_RECOMMENDED_NEXT_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: SANDBOX_EXECUTE_ARTIFACT_TYPES,
      evidence: [
        'behavior',
        'network',
        'filesystem',
        'memory',
        'timeline',
        'workflow',
        'provenance',
      ],
      safety: SANDBOX_EXECUTE_SAFETY,
      runtimeBackends: ['safe-simulation', 'speakeasy', 'windows-sandbox', 'hyperv'],
      defaultMode: 'safe_simulation',
      liveExecutionRequires: ['approved=true', 'isolated runtime', 'network disabled by default'],
    },
  ],
  runtimePolicy: SANDBOX_EXECUTE_RUNTIME_POLICY,
  runtime: { type: 'inline', handler: 'executeSandboxExecute' },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'SandboxStaticWorker',
    backendKind: 'builtin',
    adapter: 'sandbox.execute.dynamic-profile',
    availability: 'builtin',
    supportedModes: ['safe_simulation', 'memory_guided', 'speakeasy', 'live_local'],
    defaultMode: 'safe_simulation',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: SANDBOX_EXECUTE_ARTIFACT_TYPES,
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: true,
      requiresIsolation: true,
      defaultTimeoutMs: 20_000,
      maxInputBytes: 20 * 1024 * 1024,
      notes: [
        'Safe simulation is the default worker mode and does not require a live sandbox backend.',
        'Live and emulator-backed modes remain approval-gated by PolicyGuard.',
      ],
    },
    readiness: {
      missingBackendBehavior: 'Return a setup error when the bundled static worker is unavailable.',
      setupActions: ['Ensure workers/static_worker.py is present in the Rikune package.'],
    },
  },
}

interface WorkerRequest {
  job_id: string
  tool: string
  sample: {
    sample_id: string
    path: string
  }
  args: Record<string, unknown>
  context: {
    request_time_utc: string
    policy: {
      allow_dynamic: boolean
      allow_network: boolean
    }
    versions: Record<string, string>
  }
}

interface WorkerResponse {
  job_id: string
  ok: boolean
  warnings: string[]
  errors: string[]
  data: unknown
  artifacts: unknown[]
  metrics: Record<string, unknown>
}

interface SandboxPayload {
  run_id: string
  status: 'completed' | 'failed' | 'timeout' | 'denied'
  mode: string
  backend: string
  simulated: boolean
  timeout_sec: number
  event_count: number
  timeline: Array<{
    event_type: string
    category: string
    indicator: string
    confidence: number
  }>
  iocs: Record<string, string[]>
  capabilities: Array<{
    name: string
    evidence_count: number
    confidence: number
  }>
  memory_regions?: Array<{
    region_type: string
    purpose: string
    source: string
    confidence: number
    start_offset?: number
    end_offset?: number
    indicators: string[]
  }>
  api_resolution?: Array<{
    api: string
    provenance: string
    confidence: number
    sources: string[]
  }>
  execution_hypotheses?: Array<{
    stage: string
    description: string
    source: string
    confidence: number
    indicators: string[]
  }>
  risk: {
    score: number
    level: 'clean' | 'low' | 'medium' | 'high'
    confidence: number
  }
  environment: {
    network_policy: string
    executed: boolean
    isolation: string
  }
  evidence: Record<string, unknown>
  inference: {
    classification: string
    summary: string
  }
  warnings?: string[]
  metrics?: Record<string, unknown>
}

interface SandboxExecuteDependencies {
  callWorker?: (request: WorkerRequest) => Promise<WorkerResponse>
}

async function callStaticWorker(request: WorkerRequest): Promise<WorkerResponse> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    const pythonCommand = getPythonCommand()
    const child = spawn(pythonCommand, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    child.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    child.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    child.on('error', (error) => {
      reject(new Error(`Failed to spawn Python worker: ${error.message}`))
    })

    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python worker exited with code ${code}. stderr: ${stderr}`))
        return
      }

      try {
        const lines = stdout.trim().split('\n')
        const lastLine = lines[lines.length - 1]
        resolve(JSON.parse(lastLine) as WorkerResponse)
      } catch (error) {
        reject(
          new Error(
            `Failed to parse worker response: ${(error as Error).message}. stdout: ${stdout}`
          )
        )
      }
    })

    try {
      child.stdin.write(JSON.stringify(request) + '\n')
      child.stdin.end()
    } catch (error) {
      reject(new Error(`Failed to write to worker stdin: ${(error as Error).message}`))
    }
  })
}

function mergeWarnings(...warningLists: Array<string[] | undefined>): string[] | undefined {
  const merged = warningLists.flatMap((list) => list || [])
  if (merged.length === 0) {
    return undefined
  }
  return Array.from(new Set(merged))
}

function enrichSandboxPayload(payload: SandboxPayload): SandboxPayload & {
  execution_semantics: {
    live_windows_sandbox_execution: boolean
    live_hyperv_execution: boolean
    safe_simulation: boolean
    emulation: boolean
    user_visible_sandbox_window_expected: boolean
    explanation: string
  }
} {
  const backend = String(payload.backend || '').toLowerCase()
  const mode = String(payload.mode || '').toLowerCase()
  const isolation = String(payload.environment?.isolation || '').toLowerCase()
  const executed = Boolean(payload.environment?.executed)
  const liveWindowsSandbox =
    executed && (backend.includes('sandbox') || isolation.includes('sandbox'))
  const liveHyperv = executed && (backend.includes('hyperv') || isolation.includes('hyperv'))
  const safeSimulation = !executed || mode === 'safe_simulation' || backend.includes('simulation')
  const emulation =
    mode === 'speakeasy' || backend.includes('speakeasy') || backend.includes('qiling')

  return {
    ...payload,
    execution_semantics: {
      live_windows_sandbox_execution: liveWindowsSandbox,
      live_hyperv_execution: liveHyperv,
      safe_simulation: safeSimulation,
      emulation,
      user_visible_sandbox_window_expected: liveWindowsSandbox,
      explanation: liveWindowsSandbox
        ? 'This run used a live Windows Sandbox runtime; a visible Sandbox window may be expected depending on the Host Agent backend.'
        : liveHyperv
          ? 'This run used a live Hyper-V runtime endpoint; Windows Sandbox UI is not expected.'
          : emulation
            ? 'This run used emulator-backed dynamic analysis, not a live Windows Sandbox session.'
            : 'This run used planning/safe simulation and did not execute the sample in a live Windows Sandbox session.',
    },
  }
}

function artifactTypesFor(artifacts: ArtifactRef[]): string[] {
  return Array.from(new Set(artifacts.map((artifact) => artifact.type)))
}

function buildSandboxExecutionEnvelope(
  payload: ReturnType<typeof enrichSandboxPayload>,
  input: SandboxExecuteInput,
  artifacts: ArtifactRef[]
) {
  const artifactTypes = artifactTypesFor(artifacts)
  const persistedArtifacts = artifacts.map((artifact) => ({
    id: artifact.id,
    type: artifact.type,
    path: artifact.path,
    mime: artifact.mime ?? 'application/json',
  }))
  const executionSemantics = payload.execution_semantics
  const liveExecution =
    executionSemantics.live_windows_sandbox_execution || executionSemantics.live_hyperv_execution

  return {
    ...payload,
    evidence_summary: {
      schema: 'rikune.sandbox_execute.evidence_summary.v1',
      source_tool: TOOL_NAME,
      run_id: payload.run_id,
      status: payload.status,
      mode: payload.mode,
      backend: payload.backend,
      simulated: payload.simulated,
      event_count: payload.event_count,
      risk: payload.risk,
      artifact_types: artifactTypes,
      persisted_artifacts: persistedArtifacts,
      evidence_categories: ['behavior', 'network', 'filesystem', 'memory', 'timeline', 'workflow'],
      execution_semantics: executionSemantics,
      recommended_next_tools: SANDBOX_EXECUTE_RECOMMENDED_NEXT_TOOLS,
    },
    workflow_handoff: {
      schema: 'rikune.sandbox_execute.workflow_handoff.v1',
      handoff_mode: 'dynamic_trace_to_evidence_graph',
      recommended_next_tools: SANDBOX_EXECUTE_RECOMMENDED_NEXT_TOOLS,
      artifact_contract: {
        consumes: ['sample'],
        produces: artifactTypes,
        expected_consumers: [
          'artifact.read',
          'dynamic.trace.import',
          'analysis.evidence.graph',
          'sandbox.report',
          'report.generate',
        ],
      },
      routing: [
        {
          goal: 'dynamic-trace-import',
          priority: artifactTypes.includes(PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE)
            ? 'high'
            : 'blocked',
          consumes: [PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE],
          next_tools: ['dynamic.trace.import', 'analysis.evidence.graph'],
        },
        {
          goal: 'sandbox-reporting',
          priority: artifactTypes.length > 0 ? 'medium' : 'blocked',
          consumes: artifactTypes,
          next_tools: ['artifact.read', 'sandbox.report', 'report.generate'],
        },
      ],
      dynamic_boundary: {
        sample_executed_by_tool: Boolean(payload.environment?.executed),
        live_execution: liveExecution,
        live_windows_sandbox_execution: executionSemantics.live_windows_sandbox_execution,
        live_hyperv_execution: executionSemantics.live_hyperv_execution,
        safe_simulation: executionSemantics.safe_simulation,
        emulation: executionSemantics.emulation,
        network_policy: input.network,
      },
    },
    quality_gates: {
      schema: 'rikune.sandbox_execute.quality_gates.v1',
      approval_required_for_live_execution: true,
      approved_execution: input.approved === true || input.require_user_approval === true,
      mode: input.mode,
      network_policy: input.network,
      network_disabled_by_default: input.network === 'disabled',
      live_execution_requires_isolation: true,
      live_execution: liveExecution,
      safe_simulation: executionSemantics.safe_simulation,
      emulation: executionSemantics.emulation,
      persisted_artifact_count: persistedArtifacts.length,
      dynamic_trace_persisted: artifactTypes.includes(PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE),
      sandbox_trace_persisted: artifactTypes.includes(SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE),
    },
    recommended_next_tools: SANDBOX_EXECUTE_RECOMMENDED_NEXT_TOOLS,
  }
}

export function createSandboxExecuteHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  policyGuard: PolicyGuard,
  dependencies?: SandboxExecuteDependencies
) {
  const runWorker = dependencies?.callWorker || callStaticWorker
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    // Backend gate
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    if (!existsSync(workerPath)) {
      return {
        ok: false,
        errors: [`Sandbox worker not found: ${workerPath}`],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }

    try {
      const input = SandboxExecuteInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const policyDecision = await policyGuard.checkPermission(
        {
          type: 'dynamic_execution',
          tool: TOOL_NAME,
          args: {
            mode: input.mode,
            network: input.network,
            approved: input.approved,
            require_user_approval: input.require_user_approval,
          },
        },
        {
          sampleId: input.sample_id,
          timestamp: new Date().toISOString(),
        }
      )

      await policyGuard.auditLog({
        timestamp: new Date().toISOString(),
        operation: TOOL_NAME,
        sampleId: input.sample_id,
        decision: policyDecision.allowed ? 'allow' : 'deny',
        reason: policyDecision.reason,
        metadata: {
          mode: input.mode,
          network: input.network,
        },
      })

      if (!policyDecision.allowed) {
        const approvalHint = policyDecision.requiresApproval
          ? 'Set `approved=true` (and run only in isolated environment) to continue.'
          : undefined
        return {
          ok: false,
          errors: [policyDecision.reason || 'Dynamic execution denied by policy guard.'],
          warnings: approvalHint ? [approvalHint] : undefined,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const workspace = await workspaceManager.getWorkspace(input.sample_id)
      const files = await fs.readdir(workspace.original)
      if (files.length === 0) {
        return {
          ok: false,
          errors: ['Sample file not found in workspace/original'],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const samplePath = path.join(workspace.original, files[0])
      const request: WorkerRequest = {
        job_id: uuidv4(),
        tool: TOOL_NAME,
        sample: {
          sample_id: input.sample_id,
          path: samplePath,
        },
        args: {
          mode: input.mode,
          timeout_sec: input.timeout_sec,
          network: input.network,
          max_scan_bytes: input.max_scan_bytes,
        },
        context: {
          request_time_utc: new Date().toISOString(),
          policy: {
            allow_dynamic: true,
            allow_network: input.network !== 'disabled',
          },
          versions: {
            tool_version: TOOL_VERSION,
          },
        },
      }

      const workerResponse = await runWorker(request)
      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
          metrics: {
            ...workerResponse.metrics,
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const payload = enrichSandboxPayload(workerResponse.data as SandboxPayload)
      const artifacts: ArtifactRef[] = Array.isArray(workerResponse.artifacts)
        ? (workerResponse.artifacts as ArtifactRef[])
        : []
      const persistedArtifacts: ArtifactRef[] = []

      if (input.persist_artifact) {
        const reportDir = path.join(workspace.reports, 'dynamic')
        await fs.mkdir(reportDir, { recursive: true })

        const persistTimestamp = Date.now()
        const fileName = `sandbox_${persistTimestamp}.json`
        const absPath = path.join(reportDir, fileName)
        const artifactId = randomUUID()
        const relativePath = `reports/dynamic/${fileName}`
        const normalizedTrace = normalizeDynamicTraceArtifactPayload(payload)
        const provisionalArtifacts: ArtifactRef[] = [
          {
            id: artifactId,
            type: SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
            path: relativePath,
            sha256: '',
            mime: 'application/json',
          },
        ]

        let normalizedArtifactId: string | undefined
        let normalizedAbsPath: string | undefined
        let normalizedRelativePath: string | undefined
        let normalizedSerialized: string | undefined
        if (normalizedTrace) {
          const normalizedFileName = `dynamic_trace_${persistTimestamp}.json`
          normalizedAbsPath = path.join(reportDir, normalizedFileName)
          normalizedSerialized = JSON.stringify(normalizedTrace, null, 2)
          normalizedArtifactId = randomUUID()
          normalizedRelativePath = `reports/dynamic/${normalizedFileName}`
          provisionalArtifacts.push({
            id: normalizedArtifactId,
            type: PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
            path: normalizedRelativePath,
            sha256: '',
            mime: 'application/json',
          })
        }

        const persistedEnvelope = buildSandboxExecutionEnvelope(payload, input, [
          ...artifacts,
          ...provisionalArtifacts,
        ])
        const serialized = JSON.stringify(persistedEnvelope, null, 2)
        await fs.writeFile(absPath, serialized, 'utf-8')

        const artifactSha256 = createHash('sha256').update(serialized).digest('hex')

        database.insertArtifact({
          id: artifactId,
          sample_id: input.sample_id,
          type: SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
          path: relativePath,
          sha256: artifactSha256,
          mime: 'application/json',
          created_at: new Date().toISOString(),
        })

        const persistedArtifact: ArtifactRef = {
          id: artifactId,
          type: SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
          path: relativePath,
          sha256: artifactSha256,
          mime: 'application/json',
        }
        persistedArtifacts.push(persistedArtifact)
        artifacts.push(persistedArtifact)

        if (
          normalizedTrace &&
          normalizedArtifactId &&
          normalizedAbsPath &&
          normalizedRelativePath &&
          normalizedSerialized
        ) {
          await fs.writeFile(normalizedAbsPath, normalizedSerialized, 'utf-8')

          const normalizedSha256 = createHash('sha256').update(normalizedSerialized).digest('hex')

          database.insertArtifact({
            id: normalizedArtifactId,
            sample_id: input.sample_id,
            type: PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
            path: normalizedRelativePath,
            sha256: normalizedSha256,
            mime: 'application/json',
            created_at: new Date().toISOString(),
          })

          const normalizedArtifact: ArtifactRef = {
            id: normalizedArtifactId,
            type: PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
            path: normalizedRelativePath,
            sha256: normalizedSha256,
            mime: 'application/json',
          }
          persistedArtifacts.push(normalizedArtifact)
          artifacts.push(normalizedArtifact)
        }
      }

      const semanticWarning = payload.execution_semantics.live_windows_sandbox_execution
        ? undefined
        : 'sandbox.execute did not perform live Windows Sandbox execution for this run; inspect data.execution_semantics for the exact backend semantics.'
      const warnings = mergeWarnings(
        workerResponse.warnings,
        payload.warnings,
        semanticWarning ? [semanticWarning] : undefined
      )
      if (persistedArtifacts.length > 0) {
        const persistedWarning = `Sandbox trace persisted as artifact(s) ${persistedArtifacts
          .map((item) => `${item.type}:${item.id}`)
          .join(', ')}`
        const merged = warnings ? [...warnings, persistedWarning] : [persistedWarning]
        const enrichedPayload = buildSandboxExecutionEnvelope(payload, input, artifacts)
        return {
          ok: true,
          data: enrichedPayload,
          warnings: Array.from(new Set(merged)),
          artifacts,
          metrics: {
            ...workerResponse.metrics,
            ...(payload.metrics || {}),
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      const enrichedPayload = buildSandboxExecutionEnvelope(payload, input, artifacts)
      return {
        ok: true,
        data: enrichedPayload,
        warnings,
        artifacts,
        metrics: {
          ...workerResponse.metrics,
          ...(payload.metrics || {}),
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
