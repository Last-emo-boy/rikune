import { describe, test } from '@jest/globals'
import { expectFrontierWorkerTool } from './frontier-worker-test-utils.js'

describe('culifter worker', () => {
  test('runs no-GPU artifact inventory contract', async () => {
    await expectFrontierWorkerTool({
      pluginId: 'culifter',
      toolName: 'culifter.gpu.artifact.inventory',
      backendName: 'CuLifter',
      fixtureKey: 'gpu_driver_required',
    })
  })
})
