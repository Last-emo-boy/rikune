import { describe, test } from '@jest/globals'
import {
  expectFrontierWorkerTool,
  expectFrontierWorkerRejectsExternal,
} from './frontier-worker-test-utils.js'

describe('restringer worker', () => {
  test('runs builtin static worker contract', async () => {
    await expectFrontierWorkerTool({
      pluginId: 'restringer',
      toolName: 'restringer.deobfuscation.run',
      backendName: 'REstringer',
      fixtureKey: 'recovered_string_arrays',
    })
  })

  test('rejects external backend without explicit opt-in', async () => {
    await expectFrontierWorkerRejectsExternal({
      pluginId: 'restringer',
      toolName: 'restringer.deobfuscation.run',
    })
  })
})
