import { afterEach } from '@jest/globals'
import { shutdownRuntimeWorkerPool } from '../src/worker/runtime-worker-pool.js'

afterEach(async () => {
  await shutdownRuntimeWorkerPool()
})
