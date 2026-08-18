import { describe, test } from '@jest/globals'
import {
  expectFrontierWorkerTool,
  expectFrontierWorkerRejectsExternal,
} from './frontier-worker-test-utils.js'

describe('culifter worker', () => {
  test(
    'runs no-GPU artifact inventory contract',
    async () => {
      await expectFrontierWorkerTool({
        pluginId: 'culifter',
        toolName: 'culifter.gpu.artifact.inventory',
        backendName: 'CuLifter',
        fixtureKey: 'gpu_driver_required',
      })
    },
    30000
  )

  test('rejects external backend without explicit opt-in', async () => {
    await expectFrontierWorkerRejectsExternal({
      pluginId: 'culifter',
      toolName: 'culifter.gpu.artifact.inventory',
    })
  })
})
