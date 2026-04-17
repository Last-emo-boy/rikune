import { isDockerAvailable, stopAnalyzer } from './helpers/docker-lifecycle.js'

beforeAll(() => {
  if (!isDockerAvailable()) {
    // eslint-disable-next-line no-console
    console.warn('Docker is not available; E2E tests will be skipped')
  }
})

afterAll(async () => {
  if (isDockerAvailable()) {
    stopAnalyzer()
  }
})
