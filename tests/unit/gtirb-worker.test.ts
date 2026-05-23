import { describe, test } from '@jest/globals'
import { expectFrontierWorkerTool } from './frontier-worker-test-utils.js'

describe('gtirb worker', () => {
  test('runs builtin read-only IR generation contract', async () => {
    await expectFrontierWorkerTool({
      pluginId: 'gtirb',
      toolName: 'gtirb.ir.generate',
      backendName: 'GTIRB',
      fixtureKey: 'cfg_blocks',
      args: { target: { architecture: 'x64' } },
    })
  })
})
