#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const REQUIRED_BUNDLES = [
  {
    name: '@rikune/shared',
    exportName: 'createTrustedFetch',
  },
  {
    name: '@rikune/plugin-sdk',
    exportName: 'definePlugin',
  },
]

function commandName(name) {
  return process.platform === 'win32' ? `${name}.exe` : name
}

export function resolveNpmInvocation({
  platform = process.platform,
  nodeExecutable = process.execPath,
  npmExecPath = process.env.npm_execpath,
} = {}) {
  if (platform !== 'win32') {
    return { command: 'npm', prefixArgs: [] }
  }

  const candidates = [
    npmExecPath,
    join(dirname(nodeExecutable), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ].filter(Boolean)
  const npmCliPath = candidates.find((candidate) => existsSync(candidate))
  if (!npmCliPath) {
    throw new Error(
      `Unable to locate npm CLI for Windows; checked: ${candidates.join(', ') || '(none)'}`
    )
  }

  // Windows cannot execute npm.cmd directly without a shell. Running npm's
  // JavaScript entry point through the current Node binary is shell-free and
  // keeps every install argument literal.
  return { command: nodeExecutable, prefixArgs: [npmCliPath] }
}

function commandFailure(result) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim()
  return output.length > 4_000 ? output.slice(-4_000) : output
}

export function listTarballEntries(tarballPath) {
  const result = spawnSync(commandName('tar'), ['-tf', tarballPath], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  })
  if (result.error || result.status !== 0) {
    throw new Error(
      `Unable to inspect release tarball with tar: ${result.error?.message ?? commandFailure(result)}`
    )
  }
  return result.stdout
    .split(/\r?\n/u)
    .map((entry) => entry.trim().replaceAll('\\', '/'))
    .filter(Boolean)
}

export function assertBundledDependencyEntries(entries) {
  const entrySet = new Set(entries)
  for (const bridgePath of ['package/plugin-sdk.js', 'package/plugin-sdk.d.ts']) {
    if (!entrySet.has(bridgePath)) {
      throw new Error(`Release tarball is missing public SDK bridge: ${bridgePath}`)
    }
  }
  for (const bundle of REQUIRED_BUNDLES) {
    const packageRoot = `package/node_modules/${bundle.name}`
    for (const relativePath of ['package.json', 'dist/index.js', 'dist/index.d.ts']) {
      const expectedPath = `${packageRoot}/${relativePath}`
      if (!entrySet.has(expectedPath)) {
        throw new Error(`Release tarball is missing bundled file: ${expectedPath}`)
      }
    }
  }
}

export function assertPublicSdkExport(packageJson) {
  const sdkExport = packageJson.exports?.['./plugin-sdk.js']
  if (
    sdkExport?.types !== './plugin-sdk.d.ts' ||
    sdkExport?.import !== './plugin-sdk.js' ||
    sdkExport?.default !== './plugin-sdk.js'
  ) {
    throw new Error('Release package does not export rikune/plugin-sdk.js with types')
  }
}

async function assertInstalledExport(rikuneRoot, bundle) {
  const bundleRoot = join(rikuneRoot, 'node_modules', ...bundle.name.split('/'))
  const packageJsonPath = join(bundleRoot, 'package.json')
  if (!existsSync(packageJsonPath)) {
    throw new Error(`Installed release is missing bundled dependency: ${bundle.name}`)
  }

  const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'))
  const entryPath = resolve(bundleRoot, packageJson.main ?? 'dist/index.js')
  const moduleExports = await import(pathToFileURL(entryPath).href)
  if (typeof moduleExports[bundle.exportName] !== 'function') {
    throw new Error(
      `Expected ${bundle.exportName} to be importable from bundled dependency ${bundle.name}`
    )
  }
}

export async function verifyReleasePackage(tarballPath, expectedVersion) {
  const absoluteTarballPath = resolve(tarballPath)
  if (!existsSync(absoluteTarballPath)) {
    throw new Error(`Release tarball does not exist: ${absoluteTarballPath}`)
  }
  if (typeof expectedVersion !== 'string' || expectedVersion.length === 0) {
    throw new Error('Expected package version is required')
  }

  const entries = listTarballEntries(absoluteTarballPath)
  assertBundledDependencyEntries(entries)

  const installRoot = mkdtempSync(join(tmpdir(), 'rikune-release-package-'))
  try {
    writeFileSync(
      join(installRoot, 'package.json'),
      `${JSON.stringify({ name: 'rikune-release-verification', private: true }, null, 2)}\n`
    )
    // A deliberately unreachable scoped registry proves the two @rikune packages
    // came from the release tarball rather than an existing registry publication.
    writeFileSync(join(installRoot, '.npmrc'), '@rikune:registry=http://127.0.0.1:9/\n')

    const npmInvocation = resolveNpmInvocation()
    const installResult = spawnSync(
      npmInvocation.command,
      [
        ...npmInvocation.prefixArgs,
        'install',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--package-lock=false',
        absoluteTarballPath,
      ],
      {
        cwd: installRoot,
        encoding: 'utf8',
        env: process.env,
        maxBuffer: 16 * 1024 * 1024,
        timeout: 5 * 60 * 1000,
      }
    )
    if (installResult.error || installResult.status !== 0) {
      throw new Error(
        `Fresh npm install of release tarball failed: ${installResult.error?.message ?? commandFailure(installResult)}`
      )
    }

    const rikuneRoot = join(installRoot, 'node_modules', 'rikune')
    const installedPackageJson = JSON.parse(readFileSync(join(rikuneRoot, 'package.json'), 'utf8'))
    if (installedPackageJson.name !== 'rikune') {
      throw new Error(`Installed package name mismatch: ${installedPackageJson.name}`)
    }
    if (installedPackageJson.version !== expectedVersion) {
      throw new Error(
        `Installed package version mismatch: expected ${expectedVersion}, received ${installedPackageJson.version}`
      )
    }
    assertPublicSdkExport(installedPackageJson)

    for (const bundle of REQUIRED_BUNDLES) {
      await assertInstalledExport(rikuneRoot, bundle)
    }

    const consumerImportResult = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '--eval',
        "const root = await import('rikune'); if (typeof root.MCPServer !== 'function' || typeof root.startRikuneServer !== 'function') throw new Error('root API export is missing'); const sdk = await import('rikune/plugin-sdk.js'); if (typeof sdk.definePlugin !== 'function') throw new Error('definePlugin export is missing')",
      ],
      {
        cwd: installRoot,
        encoding: 'utf8',
        env: process.env,
        maxBuffer: 1024 * 1024,
        timeout: 30 * 1000,
      }
    )
    if (consumerImportResult.error || consumerImportResult.status !== 0) {
      throw new Error(
        `Consumer import of rikune and rikune/plugin-sdk.js failed: ${consumerImportResult.error?.message ?? commandFailure(consumerImportResult)}`
      )
    }
  } finally {
    rmSync(installRoot, { recursive: true, force: true })
  }

  console.log(
    `Verified rikune@${expectedVersion}: root API, bundled dependencies, and rikune/plugin-sdk.js are usable.`
  )
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : ''
if (invokedPath === import.meta.url) {
  try {
    await verifyReleasePackage(process.argv[2], process.argv[3])
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  }
}
