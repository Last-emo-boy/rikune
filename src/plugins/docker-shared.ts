/**
 * Docker Backend Shared Helpers
 *
 * Common types, schemas, and utility functions used by all Docker backend tools.
 */

import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { DatabaseManager, Sample } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { ArtifactRef, ToolArgs, ToolDefinition, WorkerResult } from '../types.js'
import {
  buildCoreLinuxToolchainSetupActions,
  buildDynamicDependencyRequiredUserInputs,
  buildDynamicDependencySetupActions,
  buildHeavyBackendSetupActions,
  mergeRequiredUserInputs,
  mergeSetupActions,
} from '../setup-guidance.js'
import {
  resolveAnalysisBackends,
  resolveExecutable,
  resolvePythonModuleBackend,
  type ExternalExecutableResolution,
  type ToolchainBackendResolution,
} from '../static-backend-discovery.js'
import { resolvePrimarySamplePath } from '../sample/sample-workspace.js'
import {
  buildEvidenceReuseWarnings,
  findCanonicalEvidence,
  persistCanonicalEvidence,
} from '../analysis/analysis-evidence.js'
import {
  buildRizinPreviewCompatibilityKey,
  getRuntimeWorkerPool,
} from '../worker/runtime-worker-pool.js'
import { resolvePackagePath } from '../runtime-paths.js'
import {
  ExplanationConfidenceStateSchema,
  ExplanationSurfaceRoleSchema,
} from '../artifacts/explanation-graphs.js'
import { ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'
import { runAbortableProcess } from '../worker/abortable-process.js'

export {
  fs,
  os,
  path,
  z,
  randomUUID,
  resolveAnalysisBackends,
  resolveExecutable,
  resolvePythonModuleBackend,
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
  DatabaseManager,
  Sample,
  WorkspaceManager,
  ArtifactRef,
  ToolArgs,
  ToolDefinition,
  WorkerResult,
  ExternalExecutableResolution,
  ToolchainBackendResolution,
}

// 鈹€鈹€ Shared Zod Schemas 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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

// 鈹€鈹€ Shared Types 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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
    options?: { cwd?: string; env?: NodeJS.ProcessEnv; abortSignal?: AbortSignal }
  ) => Promise<CommandResult>
  runPythonJson?: (
    pythonPath: string,
    script: string,
    payload: unknown,
    timeoutMs: number,
    options?: { cwd?: string; env?: NodeJS.ProcessEnv; abortSignal?: AbortSignal }
  ) => Promise<PythonJsonResult>
}

// 鈹€鈹€ Shared Utility Functions 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

export function buildMetrics(startTime: number, tool: string) {
  return {
    elapsed_ms: Date.now() - startTime,
    tool,
  }
}

import { normalizeError, sanitizePathSegment as sanitizeSegment } from '../utils/shared-helpers.js'
export { normalizeError }

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
  const outputDir = path.join(
    workspace.reports,
    'backend_tools',
    sessionSegment,
    sanitizeSegment(backend, 'backend')
  )
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
  options?: { cwd?: string; env?: NodeJS.ProcessEnv; abortSignal?: AbortSignal }
): Promise<CommandResult> {
  const result = await runAbortableProcess({
    command: binaryPath,
    args,
    cwd: options?.cwd || process.cwd(),
    env: options?.env,
    timeoutMs,
    abortSignal: options?.abortSignal,
  })
  return {
    stdout: stripAnsi(result.stdout),
    stderr: stripAnsi(result.stderr),
    exitCode: result.exitCode ?? 1,
    timedOut: result.timedOut,
  }
}

export async function runPythonJson(
  pythonPath: string,
  script: string,
  payload: unknown,
  timeoutMs: number,
  options?: { cwd?: string; env?: NodeJS.ProcessEnv; abortSignal?: AbortSignal }
): Promise<PythonJsonResult> {
  const result = await runAbortableProcess({
    command: pythonPath,
    args: ['-c', script],
    cwd: options?.cwd || process.cwd(),
    env: options?.env,
    stdin: JSON.stringify(payload),
    timeoutMs,
    abortSignal: options?.abortSignal,
  })
  if (result.timedOut) {
    throw new Error(`Python backend timed out after ${timeoutMs}ms`)
  }
  if (result.exitCode !== 0) {
    throw new Error(
      `Python backend exited with code ${result.exitCode ?? 'unknown'}. stderr: ${result.stderr}`
    )
  }

  const lines = result.stdout
    .trim()
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
  const lastLine = lines[lines.length - 1]
  if (!lastLine) {
    throw new Error(`Python backend produced no JSON output. stderr: ${result.stderr}`)
  }

  try {
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      parsed: JSON.parse(lastLine),
    }
  } catch (error) {
    throw new Error(
      `Failed to parse Python backend JSON output: ${normalizeError(error)}. stdout: ${result.stdout}`
    )
  }
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
