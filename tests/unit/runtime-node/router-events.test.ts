/**
 * Unit tests for runtime-node SSE events endpoint
 */

import { afterEach, beforeAll, describe, expect, jest, test } from '@jest/globals'
import { createServer, request } from 'http'
import type { AddressInfo } from 'net'

jest.unstable_mockModule('../../../packages/runtime-node/src/executor.js', () => ({
  executeTask: jest.fn(async (task: { taskId: string }) => ({
    ok: true,
    taskId: task.taskId,
    logs: [],
    result: { ok: true },
  })),
}))

let createRuntimeRouter: typeof import('../../../packages/runtime-node/src/router.js').createRuntimeRouter
let cancelTask: typeof import('../../../packages/runtime-node/src/task-store.js').cancelTask
let submitTask: typeof import('../../../packages/runtime-node/src/task-store.js').submitTask

beforeAll(async () => {
  ;({ createRuntimeRouter } = await import('../../../packages/runtime-node/src/router.js'))
  ;({ cancelTask, submitTask } = await import('../../../packages/runtime-node/src/task-store.js'))
})

const activeServers = new Set<ReturnType<typeof createServer>>()

async function startRuntimeServer() {
  const router = createRuntimeRouter()
  const server = createServer((req, res) => {
    void router.handle(req, res)
  })

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve())
  })

  activeServers.add(server)
  return {
    server,
    port: (server.address() as AddressInfo).port,
  }
}

afterEach(async () => {
  await Promise.all(
    Array.from(activeServers).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve())
        }),
    ),
  )
  activeServers.clear()
})

describe('runtime-node /events SSE endpoint', () => {
  test('streams connected, snapshot, and task lifecycle events', async () => {
    const { port } = await startRuntimeServer()
    const taskId = `sse-task-${Date.now()}`

    const payload = await new Promise<string>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: `/events?taskId=${taskId}`,
          method: 'GET',
          headers: {
            Accept: 'text/event-stream',
          },
        },
        (res) => {
          try {
            expect(res.statusCode).toBe(200)
            expect(String(res.headers['content-type'] || '')).toContain('text/event-stream')
          } catch (error) {
            reject(error)
            req.destroy()
            return
          }

          let body = ''
          const timeout = setTimeout(() => {
            reject(new Error(`Timed out waiting for SSE payload. Received: ${body}`))
            res.destroy()
          }, 3000)

          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
            if (
              body.includes('event: connected')
              && body.includes('event: snapshot')
              && body.includes('event: submitted')
              && body.includes('event: cancelled')
            ) {
              clearTimeout(timeout)
              resolve(body)
              res.destroy()
            }
          })
          res.on('error', reject)

          submitTask({
            taskId,
            sampleId: 'sample-1',
            tool: 'frida.runtime.instrument',
            args: {},
            timeoutMs: 1000,
          })
          cancelTask(taskId)
        },
      )

      req.on('error', (error) => {
        if ((error as NodeJS.ErrnoException).code !== 'ECONNRESET') {
          reject(error)
        }
      })
      req.end()
    })

    expect(payload).toContain('event: connected')
    expect(payload).toContain('event: snapshot')
    expect(payload).toContain('event: submitted')
    expect(payload).toContain('event: cancelled')
    expect(payload).toContain(`"taskId":"${taskId}"`)
  })

  test('rejects invalid taskId filters', async () => {
    const { port } = await startRuntimeServer()

    const response = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/events?taskId=bad$$id',
          method: 'GET',
        },
        (res) => {
          let body = ''
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            body += chunk
          })
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body })
          })
          res.on('error', reject)
        },
      )

      req.on('error', reject)
      req.end()
    })

    expect(response.statusCode).toBe(400)
    expect(response.body).toContain('Missing or invalid taskId query parameter')
  })
})
