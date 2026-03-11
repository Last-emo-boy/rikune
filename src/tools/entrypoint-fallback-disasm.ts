/**
 * Helpers for fallback disassembly via static_worker entrypoint.disasm.
 */

import { spawn } from 'child_process'
import { v4 as uuidv4 } from 'uuid'
import { resolvePackagePath } from '../runtime-paths.js'

function getPythonCommand(): string {
  return process.platform === 'win32' ? 'python' : 'python3'
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

export interface EntrypointFallbackResult {
  function: string
  address: string
  entry_point_rva: string
  entry_section: string
  architecture: string
  backend: string
  parser: string
  instruction_count: number
  assembly: string
  bytes_window: number
  requested_address?: string | null
  requested_rva?: string | null
  resolved_from?: string
}

export interface EntrypointFallbackPayload {
  result: EntrypointFallbackResult
  warnings?: string[]
  metrics?: Record<string, unknown>
}

export async function runEntrypointFallbackDisasm(
  samplePath: string,
  options?: {
    max_instructions?: number
    max_bytes?: number
    target_address?: string
    target_symbol?: string
  }
): Promise<EntrypointFallbackPayload> {
  const request = {
    job_id: uuidv4(),
    tool: 'entrypoint.disasm',
    sample: {
      sample_id: 'sha256:fallback',
      path: samplePath,
    },
    args: {
      max_instructions: options?.max_instructions ?? 120,
      max_bytes: options?.max_bytes ?? 1024,
      target_address: options?.target_address,
      target_symbol: options?.target_symbol,
    },
    context: {
      request_time_utc: new Date().toISOString(),
      policy: {
        allow_dynamic: false,
        allow_network: false,
      },
      versions: {
        tool_version: 'fallback-0.1.0',
      },
    },
  }

  const response = await callStaticWorker(request)
  if (!response.ok) {
    throw new Error(response.errors.join('; ') || 'entrypoint.disasm failed')
  }

  const payload = response.data as {
    result?: EntrypointFallbackResult
    warnings?: string[]
    metrics?: Record<string, unknown>
  }

  if (!payload || !payload.result || !payload.result.assembly) {
    throw new Error('entrypoint.disasm returned invalid payload')
  }

  return {
    result: payload.result,
    warnings: payload.warnings || response.warnings || [],
    metrics: payload.metrics || response.metrics,
  }
}

async function callStaticWorker(request: unknown): Promise<WorkerResponse> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    const child = spawn(getPythonCommand(), [workerPath], {
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
