import { describe, test } from '@jest/globals'
import {
  expectFrontierWorkerTool,
  expectFrontierWorkerRejectsExternal,
} from './frontier-worker-test-utils.js'

describe('jsir-cascade worker', () => {
  test('runs builtin IR normalization contract', async () => {
    await expectFrontierWorkerTool({
      pluginId: 'jsir-cascade',
      toolName: 'jsir.cascade.normalize',
      backendName: 'JSIR/CASCADE',
      fixtureKey: 'handler_candidates',
    })
  })

  test('rejects external backend without explicit opt-in', async () => {
    await expectFrontierWorkerRejectsExternal({
      pluginId: 'jsir-cascade',
      toolName: 'jsir.cascade.normalize',
    })
  })
})
