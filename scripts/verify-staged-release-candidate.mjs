#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { basename, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { listTarballEntries, verifyReleasePackage } from './verify-release-package.mjs'

const EXPECTED_ARTIFACT_NAME = 'npm-release-candidate'
const EXPECTED_PACKAGE = 'rikune'
const EXPECTED_REPOSITORY = 'Last-emo-boy/rikune'

function commandName(name) {
  return process.platform === 'win32' ? `${name}.exe` : name
}

function readTarballJson(tarballPath, entry) {
  const result = spawnSync(commandName('tar'), ['-xOf', tarballPath, entry], {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  })
  if (result.error || result.status !== 0) {
    const detail = result.error?.message ?? `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim()
    throw new Error(`Unable to read ${entry} from staged tarball: ${detail}`)
  }
  try {
    return JSON.parse(result.stdout)
  } catch (error) {
    throw new Error(
      `Invalid JSON in staged tarball entry ${entry}: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch: expected ${expected}, received ${actual}`)
  }
}

export function verifyStagedReleaseCandidate({
  manifestPath,
  tarballPath,
  expectedTag,
  expectedCommit,
  expectedRunId,
}) {
  const absoluteManifestPath = resolve(manifestPath)
  const absoluteTarballPath = resolve(tarballPath)
  if (!existsSync(absoluteManifestPath)) {
    throw new Error(`Release candidate manifest does not exist: ${absoluteManifestPath}`)
  }
  if (!existsSync(absoluteTarballPath)) {
    throw new Error(`Release candidate tarball does not exist: ${absoluteTarballPath}`)
  }
  if (!/^v\d+\.\d+\.\d+$/u.test(expectedTag)) {
    throw new Error(`Expected tag must be an exact stable version tag: ${expectedTag}`)
  }
  if (!/^[a-f0-9]{40}$/u.test(expectedCommit)) {
    throw new Error(`Expected commit must be a full Git SHA: ${expectedCommit}`)
  }
  if (!/^\d+$/u.test(String(expectedRunId))) {
    throw new Error(`Expected run ID must be numeric: ${expectedRunId}`)
  }

  const manifest = JSON.parse(readFileSync(absoluteManifestPath, 'utf8'))
  const expectedVersion = expectedTag.slice(1)
  const expectedWorkflow = `Release ${expectedTag}`
  const expectedRunUrl = `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/${expectedRunId}`

  assertEqual(manifest.schema_version, 1, 'manifest schema_version')
  assertEqual(manifest.artifact_name, EXPECTED_ARTIFACT_NAME, 'manifest artifact_name')
  assertEqual(manifest.package, EXPECTED_PACKAGE, 'manifest package')
  assertEqual(manifest.version, expectedVersion, 'manifest version')
  assertEqual(manifest.tag, expectedTag, 'manifest tag')
  assertEqual(manifest.commit, expectedCommit, 'manifest commit')
  assertEqual(manifest.ref, `refs/tags/${expectedTag}`, 'manifest ref')
  assertEqual(manifest.repository, EXPECTED_REPOSITORY, 'manifest repository')
  assertEqual(manifest.workflow, expectedWorkflow, 'manifest workflow')
  assertEqual(String(manifest.run_id), String(expectedRunId), 'manifest run_id')
  assertEqual(manifest.run_url, expectedRunUrl, 'manifest run_url')
  assertEqual(manifest.tarball, basename(absoluteTarballPath), 'manifest tarball')
  assertEqual(manifest.static_oci_verified, true, 'manifest static_oci_verified')
  if (!/^\d+$/u.test(String(manifest.run_attempt))) {
    throw new Error(`manifest run_attempt must be numeric: ${manifest.run_attempt}`)
  }
  if (!/^sha256:[a-f0-9]{64}$/u.test(manifest.static_oci_digest)) {
    throw new Error(`manifest static_oci_digest is invalid: ${manifest.static_oci_digest}`)
  }

  const tarballBytes = readFileSync(absoluteTarballPath)
  const actualIntegrity = `sha512-${createHash('sha512').update(tarballBytes).digest('base64')}`
  assertEqual(manifest.integrity, actualIntegrity, 'staged tarball integrity')

  const entries = new Set(listTarballEntries(absoluteTarballPath))
  if (!entries.has('package/DISCLOSURE')) {
    throw new Error('Staged tarball is missing package/DISCLOSURE')
  }
  const packageJson = readTarballJson(absoluteTarballPath, 'package/package.json')
  assertEqual(packageJson.name, EXPECTED_PACKAGE, 'tarball package name')
  assertEqual(packageJson.version, expectedVersion, 'tarball package version')
  assertEqual(packageJson.gitHead, expectedCommit, 'tarball package gitHead')
  assertEqual(packageJson.contentPolicy?.class, 'dual-use', 'tarball contentPolicy.class')

  return { manifest, packageJson, version: expectedVersion, integrity: actualIntegrity }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : ''
if (invokedPath === import.meta.url) {
  try {
    const [manifestPath, tarballPath, expectedTag, expectedCommit, expectedRunId] =
      process.argv.slice(2)
    const result = verifyStagedReleaseCandidate({
      manifestPath,
      tarballPath,
      expectedTag,
      expectedCommit,
      expectedRunId,
    })
    await verifyReleasePackage(tarballPath, result.version)
    console.log(
      `Verified staged ${EXPECTED_PACKAGE}@${result.version} candidate from run ${expectedRunId}: manifest, SHA-512 integrity, tar metadata, disclosure, and fresh install all match.`
    )
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  }
}
