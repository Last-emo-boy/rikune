/**
 * dynamic.dependencies tool
 * Dynamic-analysis capability bootstrap probe (safe: no sample execution).
 */

import { spawn } from 'child_process'
import path from 'path'
import { v4 as uuidv4 } from 'uuid'
import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { resolvePackagePath } from '../runtime-paths.js'

const TOOL_NAME = 'dynamic.dependencies'
const TOOL_VERSION = '0.1.0'

export const DynamicDependenciesInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample ID; not required because this probe does not execute binaries'),
})

export const DynamicDependenciesOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'partial', 'bootstrap_required']),
      available_components: z.array(z.string()),
      components: z.record(z.any()),
      recommendations: z.array(z.string()),
      checked_at: z.string(),
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

export const dynamicDependenciesToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Probe optional dynamic-analysis components (speakeasy/frida/psutil) and return actionable setup recommendations.',
  inputSchema: DynamicDependenciesInputSchema,
  outputSchema: DynamicDependenciesOutputSchema,
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

async function callStaticWorker(request: WorkerRequest): Promise<WorkerResponse> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3'
    const pythonProcess = spawn(pythonCommand, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    pythonProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python worker exited with code ${code}. stderr: ${stderr}`))
        return
      }

      try {
        const lines = stdout.trim().split('\n')
        const lastLine = lines[lines.length - 1]
        const response: WorkerResponse = JSON.parse(lastLine)
        resolve(response)
      } catch (error) {
        reject(
          new Error(
            `Failed to parse worker response: ${(error as Error).message}. stdout: ${stdout}`
          )
        )
      }
    })

    pythonProcess.on('error', (error) => {
      reject(new Error(`Failed to spawn Python worker: ${error.message}`))
    })

    try {
      pythonProcess.stdin.write(JSON.stringify(request) + '\n')
      pythonProcess.stdin.end()
    } catch (error) {
      reject(new Error(`Failed to write to worker stdin: ${(error as Error).message}`))
    }
  })
}

export function createDynamicDependenciesHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()

    try {
      const input = DynamicDependenciesInputSchema.parse(args)

      let sampleId = input.sample_id || 'dynamic-probe'
      let samplePath = ''
      if (input.sample_id) {
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

        const workspace = await workspaceManager.getWorkspace(input.sample_id)
        const fs = await import('fs/promises')
        const files = await fs.readdir(workspace.original)
        if (files.length > 0) {
          samplePath = path.join(workspace.original, files[0])
        }
      }

      const workerRequest: WorkerRequest = {
        job_id: uuidv4(),
        tool: TOOL_NAME,
        sample: {
          sample_id: sampleId,
          path: samplePath,
        },
        args: {},
        context: {
          request_time_utc: new Date().toISOString(),
          policy: {
            allow_dynamic: false,
            allow_network: false,
          },
          versions: {
            tool_version: TOOL_VERSION,
          },
        },
      }

      const workerResponse = await callStaticWorker(workerRequest)
      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }

      return {
        ok: true,
        data: workerResponse.data,
        warnings: workerResponse.warnings,
        errors: workerResponse.errors,
        artifacts: workerResponse.artifacts as ArtifactRef[],
        metrics: {
          ...workerResponse.metrics,
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
