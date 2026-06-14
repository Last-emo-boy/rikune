import { afterEach, describe, expect, test } from '@jest/globals'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { resolveRuntimeSidecarUploads } from '../../../src/runtime-client/sidecar-staging.js'

const tempRoots: string[] = []

async function createSampleFixture() {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-sidecar-staging-'))
  tempRoots.push(tempRoot)
  const sampleDir = path.join(tempRoot, 'workspace', 'samples')
  await fs.mkdir(sampleDir, { recursive: true })
  const samplePath = path.join(sampleDir, 'sample.exe')
  await fs.writeFile(samplePath, 'sample', 'utf8')
  return { tempRoot, sampleDir, samplePath }
}

afterEach(async () => {
  await Promise.all(
    tempRoots
      .splice(0)
      .map((root) =>
        fs.rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 })
      )
  )
}, 30_000)

describe('resolveRuntimeSidecarUploads', () => {
  test('stages explicit sidecars from the sample directory', async () => {
    const { sampleDir, samplePath } = await createSampleFixture()
    const sidecarPath = path.join(sampleDir, 'sample.config')
    await fs.writeFile(sidecarPath, 'config', 'utf8')

    const result = await resolveRuntimeSidecarUploads(samplePath, {
      sidecarPaths: [sidecarPath, 'sample.config'],
    })

    expect(result.warnings).toEqual([])
    expect(result.sidecars).toEqual([
      {
        path: await fs.realpath(sidecarPath),
        name: 'sample.config',
        size: 6,
        source: 'explicit',
      },
    ])
  })

  test('rejects explicit relative traversal outside the sample directory', async () => {
    const { tempRoot, sampleDir, samplePath } = await createSampleFixture()
    const outsidePath = path.join(tempRoot, 'workspace', 'secrets.dll')
    await fs.writeFile(outsidePath, 'secret', 'utf8')

    const result = await resolveRuntimeSidecarUploads(samplePath, {
      sidecarPaths: [path.relative(sampleDir, outsidePath)],
    })

    expect(result.sidecars).toEqual([])
    expect(result.warnings).toEqual([
      expect.stringContaining('path escapes allowed sample sidecar root'),
    ])
  })

  test('rejects explicit absolute paths outside the sample directory', async () => {
    const { tempRoot, samplePath } = await createSampleFixture()
    const outsidePath = path.join(tempRoot, 'secrets.dll')
    await fs.writeFile(outsidePath, 'secret', 'utf8')

    const result = await resolveRuntimeSidecarUploads(samplePath, {
      sidecarPaths: [outsidePath],
    })

    expect(result.sidecars).toEqual([])
    expect(result.warnings).toEqual([
      expect.stringContaining('path escapes allowed sample sidecar root'),
    ])
  })
})
