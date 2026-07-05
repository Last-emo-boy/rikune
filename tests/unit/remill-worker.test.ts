import { describe, test } from '@jest/globals'
import { expectFrontierWorkerTool } from './frontier-worker-test-utils.js'

describe('remill worker', () => {
  test('runs builtin bounded lift contract', async () => {
    await expectFrontierWorkerTool({
      pluginId: 'remill',
      toolName: 'remill.lift.run',
      backendName: 'Remill',
      fixtureKey: 'lifted_instructions',
      args: { target: { function: 'entry' } },
    })
  }, 30_000)
})
