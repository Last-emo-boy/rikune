import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, test } from '@jest/globals'
import { verifyStagedReleaseCandidate } from '../../scripts/verify-staged-release-candidate.mjs'

const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

function createCandidate() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-staged-candidate-'))
  temporaryDirectories.push(root)
  const packageDirectory = path.join(root, 'package')
  fs.mkdirSync(packageDirectory)
  const commit = 'a'.repeat(40)
  fs.writeFileSync(
    path.join(packageDirectory, 'package.json'),
    `${JSON.stringify({
      name: 'rikune',
      version: '1.4.0',
      gitHead: commit,
      contentPolicy: { class: 'dual-use' },
    })}\n`
  )
  fs.writeFileSync(path.join(packageDirectory, 'DISCLOSURE'), 'dual-use disclosure\n')

  const tarballPath = path.join(root, 'rikune-1.4.0.tgz')
  const tarResult = spawnSync(process.platform === 'win32' ? 'tar.exe' : 'tar', [
    '-czf',
    tarballPath,
    '-C',
    root,
    'package',
  ])
  if (tarResult.error || tarResult.status !== 0) {
    throw new Error(`Unable to create staged candidate fixture: ${tarResult.error?.message}`)
  }

  const integrity = `sha512-${createHash('sha512')
    .update(fs.readFileSync(tarballPath))
    .digest('base64')}`
  const runId = '123456789'
  const manifestPath = path.join(root, 'release-candidate-manifest.json')
  const manifest = {
    schema_version: 1,
    artifact_name: 'npm-release-candidate',
    package: 'rikune',
    version: '1.4.0',
    tag: 'v1.4.0',
    commit,
    ref: 'refs/tags/v1.4.0',
    repository: 'Last-emo-boy/rikune',
    workflow: 'Release v1.4.0',
    run_id: runId,
    run_attempt: '1',
    run_url: `https://github.com/Last-emo-boy/rikune/actions/runs/${runId}`,
    tarball: path.basename(tarballPath),
    integrity,
    static_oci_digest: `sha256:${'b'.repeat(64)}`,
    static_oci_verified: true,
  }
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)

  return { root, manifestPath, tarballPath, commit, runId, manifest }
}

describe('staged release candidate verifier', () => {
  test('binds the downloaded tarball bytes and package metadata to the official stage run', () => {
    const candidate = createCandidate()
    const result = verifyStagedReleaseCandidate({
      manifestPath: candidate.manifestPath,
      tarballPath: candidate.tarballPath,
      expectedTag: 'v1.4.0',
      expectedCommit: candidate.commit,
      expectedRunId: candidate.runId,
    })

    expect(result.version).toBe('1.4.0')
    expect(result.packageJson.gitHead).toBe(candidate.commit)
    expect(result.packageJson.contentPolicy).toEqual({ class: 'dual-use' })
  })

  test('fails before publication when the manifest does not match the actual tarball bytes', () => {
    const candidate = createCandidate()
    fs.appendFileSync(candidate.tarballPath, 'different-candidate')

    expect(() =>
      verifyStagedReleaseCandidate({
        manifestPath: candidate.manifestPath,
        tarballPath: candidate.tarballPath,
        expectedTag: 'v1.4.0',
        expectedCommit: candidate.commit,
        expectedRunId: candidate.runId,
      })
    ).toThrow('staged tarball integrity mismatch')
  })
})
