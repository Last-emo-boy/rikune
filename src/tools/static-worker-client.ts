import { spawn } from 'child_process'
import { v4 as uuidv4 } from 'uuid'
import { resolvePackagePath } from '../runtime-paths.js'
import { config } from '../config.js'

export interface StaticWorkerRequest {
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

export interface StaticWorkerResponse {
  job_id: string
  ok: boolean
  warnings: string[]
  errors: string[]
  data: unknown
  artifacts: unknown[]
  metrics: Record<string, unknown>
}

export function buildStaticWorkerRequest(input: {
  tool: string
  sampleId: string
  samplePath: string
  args?: Record<string, unknown>
  toolVersion: string
}): StaticWorkerRequest {
  return {
    job_id: uuidv4(),
    tool: input.tool,
    sample: {
      sample_id: input.sampleId,
      path: input.samplePath,
    },
    args: input.args || {},
    context: {
      request_time_utc: new Date().toISOString(),
      policy: {
        allow_dynamic: false,
        allow_network: false,
      },
      versions: {
        tool_version: input.toolVersion,
      },
    },
  }
}

export async function callStaticWorker(request: StaticWorkerRequest): Promise<StaticWorkerResponse> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath('workers', 'static_worker.py')
    const pythonCommand =
      config.workers.static.pythonPath ||
      (process.platform === 'win32' ? 'python' : 'python3')
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
        const response = JSON.parse(lastLine) as StaticWorkerResponse
        resolve(response)
      } catch (error) {
        reject(new Error(`Failed to parse worker response: ${(error as Error).message}. stdout: ${stdout}`))
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
