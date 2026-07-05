import { describe, test } from '@jest/globals'
import { expectFrontierWorkerTool } from './frontier-worker-test-utils.js'

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
})
