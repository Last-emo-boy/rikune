/**
 * Unit tests for dashboard runtime event integration.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, jest, test } from '@jest/globals'
import type { IncomingMessage, ServerResponse } from 'http'
import { eventBus } from '../../../src/api/sse-events.js'
import type { RuntimeSseEvent } from '../../../src/runtime-client/index.js'

let handleDashboardApi: typeof import('../../../src/api/routes/dashboard-api.js').handleDashboardApi
let initDashboard: typeof import('../../../src/api/routes/dashboard-api.js').initDashboard

beforeAll(async () => {
  ;({ handleDashboardApi, initDashboard } = await import('../../../src/api/routes/dashboard-api.js'))
})

type SubscribeOptions = {
  taskId?: string
  onOpen?: () => void
  onEvent: (event: RuntimeSseEvent) => void
  onError?: (error: Error) => void
}

function createResponseCapture() {
  const chunks: string[] = []
  const response = {
    writableEnded: false,
    statusCode: 0,
    headers: {} as Record<string, string>,
    writeHead: jest.fn((status: number, headers?: Record<string, string>) => {
      response.statusCode = status
      response.headers = headers ?? {}
      return response
    }),
    end: jest.fn((body?: string) => {
      if (body) chunks.push(body)
      response.writableEnded = true
      return response
    }),
  } as unknown as ServerResponse

  return {
    response,
    getJson: () => JSON.parse(chunks.join('')) as Record<string, any>,
  }
}

describe('dashboard-api runtime integration', () => {
  let subscribeOptions: SubscribeOptions | null
  let closeSubscription: jest.Mock

  beforeEach(() => {
    subscribeOptions = null
    closeSubscription = jest.fn()
    initDashboard({
      server: null,
      database: {} as any,
      getPluginStatuses: () => [
        { id: 'loaded-plugin', name: 'Loaded Plugin', status: 'loaded', tools: ['a.tool'] },
        { id: 'skipped-plugin', name: 'Skipped Plugin', status: 'skipped-check', tools: [] },
      ] as any,
      runtimeClient: {
        async health() {
          return { ok: true, role: 'runtime', isolation: 'sandbox', mode: 'remote-sandbox', pid: 4321 }
        },
        getEndpoint() {
          return 'http://127.0.0.1:18081'
        },
        subscribeEvents(options: SubscribeOptions) {
          subscribeOptions = options
          return { close: closeSubscription }
        },
      },
      jobQueue: {
        getQueueLength() {
          return 2
        },
        listStatuses() {
          return [
            {
              id: 'job-queued',
              status: 'queued',
              tool: 'workflow.analyze.start',
              sampleId: 'sample-1',
              attempts: 0,
              timeout: 1000,
              createdAt: '2026-04-16T10:00:00.000Z',
              updatedAt: '2026-04-16T10:00:00.000Z',
              args: {},
            },
            {
              id: 'job-running',
              status: 'running',
              tool: 'workflow.analyze.status',
              sampleId: 'sample-1',
              attempts: 1,
              timeout: 1000,
              createdAt: '2026-04-16T10:01:00.000Z',
              updatedAt: '2026-04-16T10:01:30.000Z',
              args: {},
            },
            {
              id: 'job-done',
              status: 'completed',
              tool: 'workflow.summarize',
              sampleId: 'sample-1',
              attempts: 1,
              timeout: 1000,
              createdAt: '2026-04-16T10:02:00.000Z',
              updatedAt: '2026-04-16T10:02:30.000Z',
              args: {},
            },
          ]
        },
      } as any,
    })
  })

  afterEach(() => {
    eventBus.removeAllListeners('event')
    eventBus.removeAllListeners('event:runtime-events')
  })

  test('subscribes to runtime events during dashboard init and closes previous subscription on re-init', () => {
    expect(subscribeOptions).not.toBeNull()

    initDashboard({
      server: null,
      database: {} as any,
      runtimeClient: {
        async health() {
          return null
        },
        getEndpoint() {
          return 'http://127.0.0.1:18082'
        },
        subscribeEvents(options: SubscribeOptions) {
          subscribeOptions = options
          return { close: jest.fn() }
        },
      },
    })

    expect(closeSubscription).toHaveBeenCalledTimes(1)
    expect(subscribeOptions).not.toBeNull()
  })

  test('exposes runtime event snapshot and queue stats in /workers response', () => {
    expect(subscribeOptions).not.toBeNull()

    const observedEvents: Array<{ type: string; payload: unknown }> = []
    eventBus.on('event:runtime-events', (evt) => {
      observedEvents.push({ type: evt.type, payload: evt.payload })
    })

    subscribeOptions?.onOpen?.()
    subscribeOptions?.onEvent({
      event: 'progress',
      id: 'task-123',
      data: { taskId: 'task-123', progressPercent: 42, status: 'running' },
    })

    const { response, getJson } = createResponseCapture()
    const handled = handleDashboardApi(
      { headers: {} } as IncomingMessage,
      response,
      '/api/v1/dashboard/workers',
      new URLSearchParams(),
    )

    expect(handled).toBe(true)
    expect(response.writeHead).toHaveBeenCalledWith(200, expect.objectContaining({ 'Content-Type': 'application/json' }))

    const body = getJson()
    expect(body.runtime.connected).toBe(true)
    expect(body.runtime.endpoint).toBe('http://127.0.0.1:18081')
    expect(body.runtime.last_event.event).toBe('progress')
    expect(body.runtime.last_event.normalized_status).toBe('active')
    expect(body.runtime.recent_events).toHaveLength(1)
    expect(body.runtime.lifecycle.persistenceScope).toBe('runtime-outbox')
    expect(body.jobs.total).toBe(3)
    expect(body.jobs.queue_depth).toBe(2)
    expect(body.jobs.queued).toBe(1)
    expect(body.jobs.running).toBe(1)
    expect(body.jobs.terminal).toBe(1)
    expect(body.jobs.by_status.pending).toBe(1)
    expect(body.jobs.by_status.active).toBe(1)
    expect(body.jobs.by_status.completed).toBe(1)
    expect(body.plugins.loaded).toBe(1)
    expect(body.plugins.completed).toBe(1)
    expect(body.plugins['skipped-check']).toBe(1)
    expect(body.plugins.failed).toBe(1)
    expect(observedEvents).toEqual([
      {
        type: 'status',
        payload: expect.objectContaining({
          event: 'progress',
          id: 'task-123',
          data: expect.objectContaining({ progressPercent: 42 }),
        }),
      },
    ])
  })

  test('captures runtime subscription errors in /workers response', () => {
    expect(subscribeOptions).not.toBeNull()

    subscribeOptions?.onError?.(new Error('stream disconnected'))

    const { response, getJson } = createResponseCapture()
    handleDashboardApi(
      { headers: {} } as IncomingMessage,
      response,
      '/api/v1/dashboard/workers',
      new URLSearchParams(),
    )

    const body = getJson()
    expect(body.runtime.connected).toBe(false)
    expect(body.runtime.last_error).toBe('stream disconnected')
  })
})
