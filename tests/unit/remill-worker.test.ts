import { describe, test } from '@jest/globals'
import {
  expectFrontierWorkerTool,
  expectFrontierWorkerRejectsExternal,
} from './frontier-worker-test-utils.js'

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

  test('rejects external backend without explicit opt-in', async () => {
    await expectFrontierWorkerRejectsExternal({
      pluginId: 'remill',
      toolName: 'remill.lift.run',
    })
  })
})
