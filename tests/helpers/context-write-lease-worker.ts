import { spawn, type ChildProcessWithoutNullStreams } from 'child_process'
import fs from 'fs/promises'
import path from 'path'

export interface ContextWriteLeaseWriterConfig {
  kind: 'claim' | 'case'
  databasePath: string
  workspaceRoot: string
  sampleId: string
  caseId?: string
  suffix: string
  readyPath?: string
  releasePath?: string
}

export interface ContextWriteLeaseWriterResult {
  ok: boolean
  errors?: string[]
  data?: unknown
}

export interface RunningContextWriteLeaseWriter {
  child: ChildProcessWithoutNullStreams
  completion: Promise<ContextWriteLeaseWriterResult>
}

export function startContextWriteLeaseWriter(
  config: ContextWriteLeaseWriterConfig
): RunningContextWriteLeaseWriter {
  const fixturePath = path.resolve(process.cwd(), 'tests/fixtures/context-write-lease-writer.ts')
  const child = spawn(process.execPath, ['--import', 'tsx', fixturePath, JSON.stringify(config)], {
    cwd: process.cwd(),
    env: process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')

  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (chunk: string) => {
    stdout += chunk
  })
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk
  })

  const completion = new Promise<ContextWriteLeaseWriterResult>((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => {
      const resultLine = stdout.split(/\r?\n/).findLast((line) => line.startsWith('LEASE_RESULT:'))
      if (!resultLine) {
        reject(
          new Error(
            `Context writer exited without a result (code=${code}, signal=${signal}).\n` +
              `stdout:\n${stdout}\nstderr:\n${stderr}`
          )
        )
        return
      }

      try {
        resolve(JSON.parse(resultLine.slice('LEASE_RESULT:'.length)))
      } catch (error) {
        reject(
          new Error(
            `Could not parse context writer result: ${
              error instanceof Error ? error.message : String(error)
            }\n${resultLine}`
          )
        )
      }
    })
  })

  return { child, completion }
}

export async function waitForContextWriterReady(
  readyPath: string,
  timeoutMs = 15_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      await fs.access(readyPath)
      return
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 5))
    }
  }
  throw new Error(`Timed out waiting for context writer readiness: ${readyPath}`)
}
