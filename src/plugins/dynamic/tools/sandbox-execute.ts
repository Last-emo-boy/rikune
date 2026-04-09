/**
 * sandbox.execute tool
 * Dynamic-analysis execution entrypoint supporting simulation-first and Speakeasy user-mode emulation.
 */

import { spawn } from 'child_process'
import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { v4 as uuidv4 } from 'uuid'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { PolicyGuard } from '../../../policy-guard.js'
import { normalizeDynamicTraceArtifactPayload } from '../../../dynamic-trace.js'
import { resolvePackagePath } from '../../../runtime-paths.js'

const TOOL_NAME = 'sandbox.execute'
const TOOL_VERSION = '0.1.0'

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

export const SandboxExecuteOutputSchema = z.object({
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

export const sandboxExecuteToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Execute dynamic-analysis workflow in safe simulation mode (default), memory-guided mode, or Speakeasy user-mode emulation and return timeline/IOC/risk outputs.',
  inputSchema: SandboxExecuteInputSchema,
  outputSchema: SandboxExecuteOutputSchema,
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

async function callStaticWorker(request: WorkerRequest): Promise<WorkerResponse> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3'
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

export function createSandboxExecuteHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  policyGuard: PolicyGuard
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

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

      const workerResponse = await callStaticWorker(request)
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

      const payload = workerResponse.data as SandboxPayload
      const artifacts: ArtifactRef[] = workerResponse.artifacts as ArtifactRef[]
      const persistedArtifacts: ArtifactRef[] = []

      if (input.persist_artifact) {
        const reportDir = path.join(workspace.reports, 'dynamic')
        await fs.mkdir(reportDir, { recursive: true })

        const persistTimestamp = Date.now()
        const fileName = `sandbox_${persistTimestamp}.json`
        const absPath = path.join(reportDir, fileName)
        const serialized = JSON.stringify(payload, null, 2)
        await fs.writeFile(absPath, serialized, 'utf-8')

        const artifactId = randomUUID()
        const artifactSha256 = createHash('sha256').update(serialized).digest('hex')
        const relativePath = `reports/dynamic/${fileName}`

        database.insertArtifact({
          id: artifactId,
          sample_id: input.sample_id,
          type: 'sandbox_trace_json',
          path: relativePath,
          sha256: artifactSha256,
          mime: 'application/json',
          created_at: new Date().toISOString(),
        })

        const persistedArtifact: ArtifactRef = {
          id: artifactId,
          type: 'sandbox_trace_json',
          path: relativePath,
          sha256: artifactSha256,
          mime: 'application/json',
        }
        persistedArtifacts.push(persistedArtifact)
        artifacts.push(persistedArtifact)

        const normalizedTrace = normalizeDynamicTraceArtifactPayload(payload)
        if (normalizedTrace) {
          const normalizedFileName = `dynamic_trace_${persistTimestamp}.json`
          const normalizedAbsPath = path.join(reportDir, normalizedFileName)
          const normalizedSerialized = JSON.stringify(normalizedTrace, null, 2)
          await fs.writeFile(normalizedAbsPath, normalizedSerialized, 'utf-8')

          const normalizedArtifactId = randomUUID()
          const normalizedSha256 = createHash('sha256').update(normalizedSerialized).digest('hex')
          const normalizedRelativePath = `reports/dynamic/${normalizedFileName}`

          database.insertArtifact({
            id: normalizedArtifactId,
            sample_id: input.sample_id,
            type: 'dynamic_trace_json',
            path: normalizedRelativePath,
            sha256: normalizedSha256,
            mime: 'application/json',
            created_at: new Date().toISOString(),
          })

          const normalizedArtifact: ArtifactRef = {
            id: normalizedArtifactId,
            type: 'dynamic_trace_json',
            path: normalizedRelativePath,
            sha256: normalizedSha256,
            mime: 'application/json',
          }
          persistedArtifacts.push(normalizedArtifact)
          artifacts.push(normalizedArtifact)
        }
      }

      const warnings = mergeWarnings(workerResponse.warnings, payload.warnings)
      if (persistedArtifacts.length > 0) {
        const persistedWarning = `Sandbox trace persisted as artifact(s) ${persistedArtifacts
          .map((item) => `${item.type}:${item.id}`)
          .join(', ')}`
        const merged = warnings ? [...warnings, persistedWarning] : [persistedWarning]
        return {
          ok: true,
          data: payload,
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

      return {
        ok: true,
        data: payload,
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
