import { describe, test } from '@jest/globals'
import { expectFrontierWorkerTool } from './frontier-worker-test-utils.js'

describe('manifold worker', () => {
  test('runs builtin fact extraction contract', async () => {
    await expectFrontierWorkerTool({
      pluginId: 'manifold',
      toolName: 'manifold.fact.extract',
      backendName: 'Manifold',
      fixtureKey: 'agreement',
    })
  })
})
