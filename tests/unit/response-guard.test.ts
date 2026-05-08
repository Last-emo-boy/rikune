import { describe, test, expect } from '@jest/globals'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import pino from 'pino'
import { guardResponseSize } from '../../src/core/response-guard.js'

const logger = pino({ enabled: false })

describe('response guard', () => {
  test('prunes nested workflow envelopes without dropping structured content', () => {
    const payload = {
      ok: true,
      data: {
        run_id: 'run-1',
        run: {
          stages: [
            {
              stage: 'function_map',
              status: 'completed',
              result: {
                raw_results: 'x'.repeat(260 * 1024),
                compact: true,
              },
              artifact_refs: [],
            },
          ],
        },
        stage_result: {
          raw_results: 'y'.repeat(260 * 1024),
          compact: true,
        },
      },
    }
    const result: CallToolResult = {
      content: [{ type: 'text', text: JSON.stringify(payload) }],
      structuredContent: payload,
    }

    const guarded = guardResponseSize(result, logger)
    expect(guarded.structuredContent).toBeTruthy()
    const text = (guarded.content[0] as any).text as string
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(200 * 1024)
    const parsed = JSON.parse(text)
    expect(parsed.data.run.stages[0].result.raw_results).toBeUndefined()
    expect(parsed.data.stage_result.raw_results).toBeUndefined()
    expect(parsed.warnings[0]).toContain('raw_results removed')
  })
})
