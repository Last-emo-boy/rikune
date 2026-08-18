import { describe, test } from '@jest/globals'
import {
  expectFrontierWorkerTool,
  expectFrontierWorkerRejectsExternal,
} from './frontier-worker-test-utils.js'

describe('jsimplifier worker', () => {
  test('runs builtin static pipeline contract', async () => {
    await expectFrontierWorkerTool({
      pluginId: 'jsimplifier',
      toolName: 'jsimplifier.pipeline.run',
      backendName: 'JSIMPLIFIER',
      fixtureKey: 'pass_timeline',
      args: { profile: { risk_tags: ['string-array'] } },
    })
  })

  test('rejects external backend without explicit opt-in', async () => {
    await expectFrontierWorkerRejectsExternal({
      pluginId: 'jsimplifier',
      toolName: 'jsimplifier.pipeline.run',
    })
  })
})
