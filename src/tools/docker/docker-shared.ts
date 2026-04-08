/**
 * Docker Backend Shared Helpers
 *
 * Common types, schemas, and utility functions used by all Docker backend tools.
 */

import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { execFile, spawn } from 'child_process'
import { promisify } from 'util'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { DatabaseManager, Sample } from '../../database.js'
import type { WorkspaceManager } from '../../workspace-manager.js'
import type { ArtifactRef, ToolArgs, ToolDefinition, WorkerResult } from '../../types.js'
import {
  buildCoreLinuxToolchainSetupActions,
  buildDynamicDependencyRequiredUserInputs,
  buildDynamicDependencySetupActions,
  buildHeavyBackendSetupActions,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../../setup-guidance.js'
import {
  resolveAnalysisBackends,
  type ExternalExecutableResolution,
  type ToolchainBackendResolution,
} from '../../static-backend-discovery.js'
import { resolvePrimarySamplePath } from '../../sample-workspace.js'
import {
  buildEvidenceReuseWarnings,
  findCanonicalEvidence,
  persistCanonicalEvidence,
} from '../../analysis-evidence.js'
import {
  buildRizinPreviewCompatibilityKey,
  getRuntimeWorkerPool,
} from '../../runtime-worker-pool.js'
import { resolvePackagePath } from '../../runtime-paths.js'
import {
  ExplanationConfidenceStateSchema,
  ExplanationSurfaceRoleSchema,
} from '../../explanation-graphs.js'
import { ToolSurfaceRoleSchema } from '../../tool-surface-guidance.js'

export {
  fs, os, path, z, randomUUID,
  resolveAnalysisBackends,
  resolvePrimarySamplePath,
  buildEvidenceReuseWarnings,
  findCanonicalEvidence,
  persistCanonicalEvidence,
  buildRizinPreviewCompatibilityKey,
  getRuntimeWorkerPool,
  resolvePackagePath,
  ExplanationConfidenceStateSchema,
  ExplanationSurfaceRoleSchema,
  ToolSurfaceRoleSchema,
  mergeSetupActions,
  mergeRequiredUserInputs,
  buildCoreLinuxToolchainSetupActions,
  buildDynamicDependencySetupActions,
  buildDynamicDependencyRequiredUserInputs,
  buildHeavyBackendSetupActions,
}

export type {
  DatabaseManager, Sample,
  WorkspaceManager,
  ArtifactRef, ToolArgs, ToolDefinition, WorkerResult,
  ExternalExecutableResolution, ToolchainBackendResolution,
}

const execFileAsync = promisify(execFile)

// ── Shared Zod Schemas ──────────────────────────────────────────────────

export const ArtifactRefSchema = z.object({
  id: z.string(),
  type: z.string(),
  path: z.string(),
  sha256: z.string(),
  mime: z.string().optional(),
  metadata: z.record(z.any()).optional(),
})

export const BackendSchema = z.object({
  available: z.boolean(),
  source: z.string().nullable(),
  path: z.string().nullable(),
  version: z.string().nullable(),
  checked_candidates: z.array(z.string()),
  error: z.string().nullable(),
})

export const SharedMetricsSchema = z.object({
  elapsed_ms: z.number(),
  tool: z.string(),
})

// ── Shared Types ────────────────────────────────────────────────────────

export type CommandResult = {
  stdout: string
  stderr: string
  exitCode: number
  timedOut: boolean
}

export type PythonJsonResult = {
  stdout: string
  stderr: string
  parsed: any
}

export interface SharedBackendDependencies {
  resolveBackends?: () => ToolchainBackendResolution
  executeCommand?: (
    binaryPath: string,
    args: string[],
    timeoutMs: number,
    options?: { cwd?: string; env?: NodeJS.ProcessEnv }
  ) => Promise<CommandResult>
  runPythonJson?: (
    pythonPath: string,
    script: string,
    payload: unknown,
    timeoutMs: number,
    options?: { cwd?: string; env?: NodeJS.ProcessEnv }
  ) => Promise<PythonJsonResult>
}

// ── Shared Utility Functions ────────────────────────────────────────────

export function buildMetrics(startTime: number, tool: string) {
  return {
    elapsed_ms: Date.now() - startTime,
    tool,
  }
}

export function normalizeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  return String(error)
}

export function stripAnsi(text: string): string {
  return text.replace(/\x1b\[[0-9;]*m/g, '')
}

export function truncateText(text: string, maxChars: number) {
  if (text.length <= maxChars) {
    return { text, truncated: false }
  }
  return {
    text: `${text.slice(0, maxChars)}\n...[truncated ${text.length - maxChars} chars]`,
    truncated: true,
  }
}

export function safeJsonParse<T = unknown>(text: string): T | null {
  try {
    return JSON.parse(text) as T
  } catch {
    return null
  }
}

export function ensureSampleExists(database: DatabaseManager, sampleId: string) {
  const sample = database.findSample(sampleId)
  if (!sample) {
    throw new Error(`Sample not found: ${sampleId}`)
  }
  return sample
}

export function findBackendPreviewEvidence(
  database: DatabaseManager,
  sample: Pick<Sample, 'id' | 'sha256'>,
  backend: string,
  mode: string,
  args: Record<string, unknown>,
  freshnessMarker?: string | null
) {
  return findCanonicalEvidence(database, {
    sample,
    evidenceFamily: 'backend_preview',
    backend,
    mode,
    args,
    freshnessMarker,
  })
}

export function persistBackendPreviewEvidence(
  database: DatabaseManager,
  sample: Pick<Sample, 'id' | 'sha256'>,
  backend: string,
  mode: string,
  args: Record<string, unknown>,
  result: Record<string, unknown>,
  artifactRefs: ArtifactRef[],
  metadata?: Record<string, unknown>,
  freshnessMarker?: string | null
) {
  persistCanonicalEvidence(database, {
    sample,
    evidenceFamily: 'backend_preview',
    backend,
    mode,
    args,
    freshnessMarker,
    result,
    artifactRefs,
    metadata,
    provenance: {
      tool: `${backend}.${mode}`,
      precedence: ['analysis_run_stage', 'analysis_evidence', 'artifact', 'cache'],
    },
  })
}

function sanitizeSegment(value: string | undefined | null, fallback: string): string {
  const normalized = (value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return normalized.length > 0 ? normalized.slice(0, 64) : fallback
}

export async function persistBackendArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  backend: string,
  operation: string,
  content: string | Buffer,
  options: {
    extension: string
    mime: string
    sessionTag?: string | null
    metadata?: Record<string, unknown>
  }
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const sessionSegment = sanitizeSegment(options.sessionTag, 'default')
  const outputDir = path.join(workspace.reports, 'backend_tools', sessionSegment, sanitizeSegment(backend, 'backend'))
  await fs.mkdir(outputDir, { recursive: true })

  const fileName = `${sanitizeSegment(operation, 'output')}_${Date.now()}.${options.extension}`
  const absolutePath = path.join(outputDir, fileName)
  await fs.writeFile(absolutePath, content)

  const artifactId = randomUUID()
  const artifactSha256 = createHash('sha256').update(content).digest('hex')
  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const createdAt = new Date().toISOString()
  const artifactType = `backend_${sanitizeSegment(backend, 'backend')}_${sanitizeSegment(operation, 'output')}`

  database.insertArtifact({
    id: artifactId,
    sample_id: sampleId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: options.mime,
    created_at: createdAt,
  })

  return {
    id: artifactId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: options.mime,
    ...(options.metadata ? { metadata: options.metadata } : {}),
  }
}

export async function executeCommand(
  binaryPath: string,
  args: string[],
  timeoutMs: number,
  options?: { cwd?: string; env?: NodeJS.ProcessEnv }
): Promise<CommandResult> {
  try {
    const result = await execFileAsync(binaryPath, args, {
      encoding: 'utf8',
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
      cwd: options?.cwd,
      env: options?.env,
    })
    return {
      stdout: stripAnsi(result.stdout || ''),
      stderr: stripAnsi(result.stderr || ''),
      exitCode: 0,
      timedOut: false,
    }
  } catch (error) {
    const err = error as {
      stdout?: string | Buffer | null
      stderr?: string | Buffer | null
      code?: string | number
      signal?: string
      killed?: boolean
    }
    const stdout =
      typeof err.stdout === 'string'
        ? err.stdout
        : Buffer.isBuffer(err.stdout)
          ? err.stdout.toString('utf8')
          : ''
    const stderr =
      typeof err.stderr === 'string'
        ? err.stderr
        : Buffer.isBuffer(err.stderr)
          ? err.stderr.toString('utf8')
          : ''
    return {
      stdout: stripAnsi(stdout),
      stderr: stripAnsi(stderr),
      exitCode: typeof err.code === 'number' ? err.code : 1,
      timedOut: err.signal === 'SIGTERM' || err.killed === true,
    }
  }
}

export async function runPythonJson(
  pythonPath: string,
  script: string,
  payload: unknown,
  timeoutMs: number,
  options?: { cwd?: string; env?: NodeJS.ProcessEnv }
): Promise<PythonJsonResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(pythonPath, ['-c', script], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: options?.cwd,
      env: options?.env,
      windowsHide: true,
    })

    let stdout = ''
    let stderr = ''
    let settled = false

    const finish = (fn: () => void) => {
      if (settled) {
        return
      }
      settled = true
      fn()
    }

    const timer = setTimeout(() => {
      finish(() => {
        child.kill()
        reject(new Error(`Python backend timed out after ${timeoutMs}ms`))
      })
    }, timeoutMs)

    child.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    child.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    child.on('error', (error) => {
      finish(() => {
        clearTimeout(timer)
        reject(error)
      })
    })

    child.on('close', (code) => {
      finish(() => {
        clearTimeout(timer)
        if (code !== 0) {
          reject(new Error(`Python backend exited with code ${code}. stderr: ${stderr}`))
          return
        }

        const lines = stdout
          .trim()
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
        const lastLine = lines[lines.length - 1]
        if (!lastLine) {
          reject(new Error(`Python backend produced no JSON output. stderr: ${stderr}`))
          return
        }

        try {
          resolve({
            stdout,
            stderr,
            parsed: JSON.parse(lastLine),
          })
        } catch (error) {
          reject(
            new Error(
              `Failed to parse Python backend JSON output: ${normalizeError(error)}. stdout: ${stdout}`
            )
          )
        }
      })
    })

    child.stdin.write(JSON.stringify(payload))
    child.stdin.end()
  })
}

export function buildStaticSetupRequired(
  backend: ExternalExecutableResolution,
  startTime: number,
  toolName: string
): WorkerResult {
  return {
    ok: true,
    data: {
      status: 'setup_required',
      backend,
      summary: backend.error || 'Backend is unavailable.',
      recommended_next_tools: ['system.health', 'system.setup.guide', 'tool.help'],
      next_actions: [
        'Inspect setup_actions and configure the missing backend path or package.',
        'Retry the same backend-specific MCP tool after the backend becomes available.',
      ],
    },
    warnings: [backend.error || 'Backend unavailable'],
    setup_actions: mergeSetupActions(
      buildCoreLinuxToolchainSetupActions(),
      buildHeavyBackendSetupActions()
    ),
    metrics: buildMetrics(startTime, toolName),
  }
}

export function buildDynamicSetupRequired(
  backend: ExternalExecutableResolution,
  startTime: number,
  toolName: string
): WorkerResult {
  return {
    ok: true,
    data: {
      status: 'setup_required',
      backend,
      summary: backend.error || 'Backend is unavailable.',
      recommended_next_tools: ['dynamic.dependencies', 'system.health', 'system.setup.guide'],
      next_actions: [
        'Review dynamic dependency readiness and any missing rootfs or interpreter configuration.',
        'Retry this backend-specific tool after the runtime becomes available.',
      ],
    },
    warnings: [backend.error || 'Backend unavailable'],
    setup_actions: mergeSetupActions(
      buildCoreLinuxToolchainSetupActions(),
      buildDynamicDependencySetupActions()
    ),
    required_user_inputs: mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs()),
    metrics: buildMetrics(startTime, toolName),
  }
}

export async function resolveSampleFile(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string
): Promise<string> {
  ensureSampleExists(database, sampleId)
  const { samplePath } = await resolvePrimarySamplePath(workspaceManager, sampleId)
  return samplePath
}
