/**
 * Unit tests for dynamic.behavior.capture analyzer-side definition.
 */

import { describe, test, expect } from '@jest/globals'
import {
  createDynamicBehaviorCaptureHandler,
  dynamicBehaviorCaptureToolDefinition,
} from '../../src/plugins/dynamic/tools/dynamic-behavior-capture.js'

describe('dynamic.behavior.capture tool', () => {
  test('declares Runtime Node backend support', () => {
    expect(dynamicBehaviorCaptureToolDefinition.name).toBe('dynamic.behavior.capture')
    expect(dynamicBehaviorCaptureToolDefinition.runtimeBackendHint).toEqual({
      type: 'inline',
      handler: 'executeBehaviorCapture',
    })
  })

  test('local analyzer handler refuses live execution and returns runtime guidance', async () => {
    const result = await createDynamicBehaviorCaptureHandler({} as any)({
      sample_id: `sha256:${'d'.repeat(64)}`,
    })

    expect(result.ok).toBe(false)
    expect((result.data as any).status).toBe('setup_required')
    expect((result.data as any).recommended_next_tools).toContain('dynamic.runtime.status')
    expect((result.data as any).required_runtime_backend_hint).toEqual({
      type: 'inline',
      handler: 'executeBehaviorCapture',
    })
  })
})
