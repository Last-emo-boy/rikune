#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
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
const REQUIRED_CLI_ENTRIES = {
  rikune: './bin/rikune.js',
  'rikune-docker': './bin/rikune-docker.js',
  'rikune-agent': './bin/rikune-agent.js',
}
const REQUIRED_LOCK_ENTRIES = [
  'package/requirements.lock.txt',
  'package/requirements.windows.lock.txt',
  'package/workers/requirements-dynamic.lock.txt',
  'package/workers/requirements-dynamic.windows.lock.txt',
  'package/src/plugins/angr/requirements.lock.txt',
]
const REQUIRED_RUNTIME_ASSET_ENTRIES = [
  'package/dist/plugins/binary-diff/workers/rizin_diff_worker.py',
  'package/dist/plugins/kb-collaboration/data/windows-api-semantics.json',
  'package/dist/plugins/vm-analysis/workers/constraint_solver_worker.py',
  'package/dist/plugins/vuln-scanner/data/vuln-patterns.json',
]
const FORBIDDEN_GENERATED_BYTECODE_PATTERNS = [/(?:^|\/)__pycache__(?:\/|$)/iu, /\.py[co]$/iu]

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

export function resolvePythonInvocation({
  platform = process.platform,
  pythonPath = process.env.PYTHON_PATH,
  probe = (command, args) => spawnSync(command, args, { encoding: 'utf8' }),
} = {}) {
  const candidates = [
    pythonPath ? { command: pythonPath, prefixArgs: [] } : null,
    platform === 'win32' ? { command: 'python', prefixArgs: [] } : null,
    { command: 'python3', prefixArgs: [] },
    platform !== 'win32' ? { command: 'python', prefixArgs: [] } : null,
    platform === 'win32' ? { command: 'py', prefixArgs: ['-3'] } : null,
  ].filter(Boolean)
  const uniqueCandidates = candidates.filter(
    (candidate, index) =>
      candidates.findIndex(
        (other) =>
          other.command === candidate.command &&
          other.prefixArgs.join('\0') === candidate.prefixArgs.join('\0')
      ) === index
  )

  for (const candidate of uniqueCandidates) {
    const result = probe(candidate.command, [...candidate.prefixArgs, '--version'])
    if (!result.error && result.status === 0) {
      return candidate
    }
  }
  throw new Error(
    `Unable to locate Python for release verification; checked: ${uniqueCandidates
      .map(({ command, prefixArgs }) => [command, ...prefixArgs].join(' '))
      .join(', ')}`
  )
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
  const generatedBytecodeEntry = entries.find((entry) =>
    FORBIDDEN_GENERATED_BYTECODE_PATTERNS.some((pattern) => pattern.test(entry))
  )
  if (generatedBytecodeEntry) {
    throw new Error(
      `Release tarball must not contain generated Python bytecode: ${generatedBytecodeEntry}`
    )
  }

  const entrySet = new Set(entries)
  for (const relativePath of Object.values(REQUIRED_CLI_ENTRIES)) {
    const expectedPath = `package/${relativePath.replace(/^\.\//u, '')}`
    if (!entrySet.has(expectedPath)) {
      throw new Error(`Release tarball manifest is missing CLI entry: ${expectedPath}`)
    }
  }
  if (!entrySet.has('package/DISCLOSURE')) {
    throw new Error('Release tarball manifest is missing package/DISCLOSURE')
  }
  if (!entrySet.has('package/CHANGELOG.md')) {
    throw new Error('Release tarball manifest is missing package/CHANGELOG.md')
  }
  if (!entrySet.has('package/scripts/secure-fs-helper.py')) {
    throw new Error('Release tarball manifest is missing the secure filesystem helper')
  }
  for (const lockPath of REQUIRED_LOCK_ENTRIES) {
    if (!entrySet.has(lockPath)) {
      throw new Error(`Release tarball manifest is missing dependency lock: ${lockPath}`)
    }
  }
  for (const assetPath of REQUIRED_RUNTIME_ASSET_ENTRIES) {
    if (!entrySet.has(assetPath)) {
      throw new Error(`Release tarball manifest is missing runtime asset: ${assetPath}`)
    }
  }
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

function assertInstalledCliEntries(installRoot, rikuneRoot, packageJson, expectedVersion) {
  for (const [name, relativePath] of Object.entries(REQUIRED_CLI_ENTRIES)) {
    if (packageJson.bin?.[name] !== relativePath) {
      throw new Error(
        `Installed release CLI mapping mismatch for ${name}: ${packageJson.bin?.[name] ?? '(missing)'}`
      )
    }
    const targetPath = resolve(rikuneRoot, relativePath)
    if (!existsSync(targetPath) || (statSync(targetPath).mode & 0o111) === 0) {
      throw new Error(`Installed release CLI target is missing or not executable: ${name}`)
    }

    const shimPath = join(installRoot, 'node_modules', '.bin', name)
    const invocation =
      process.platform === 'win32'
        ? { command: process.execPath, args: [targetPath, '--version'] }
        : { command: shimPath, args: ['--version'] }
    if (
      process.platform !== 'win32' &&
      (!existsSync(shimPath) || (statSync(shimPath).mode & 0o111) === 0)
    ) {
      throw new Error(`Fresh install did not create an executable npm CLI shim: ${name}`)
    }
    const result = spawnSync(invocation.command, invocation.args, {
      cwd: installRoot,
      encoding: 'utf8',
      env: process.env,
      maxBuffer: 1024 * 1024,
      timeout: 30 * 1000,
    })
    if (result.error || result.status !== 0) {
      throw new Error(
        `Fresh-install invocation failed for ${name}: ${result.error?.message ?? commandFailure(result)}`
      )
    }
    if (result.stdout.trim() !== expectedVersion) {
      throw new Error(
        `Fresh-install invocation returned the wrong version for ${name}: ${result.stdout.trim()}`
      )
    }
  }
}

function assertInstalledDockerLauncher(rikuneRoot, expectedVersion) {
  const launcherEnv = { ...process.env }
  delete launcherEnv.RIKUNE_DOCKER_IMAGE
  const result = spawnSync(
    process.execPath,
    [join(rikuneRoot, 'bin', 'rikune.js'), 'docker-run', '--print-command'],
    {
      encoding: 'utf8',
      env: launcherEnv,
      maxBuffer: 1024 * 1024,
      timeout: 30 * 1000,
    }
  )
  if (result.error || result.status !== 0) {
    throw new Error(
      `Fresh-install Docker launcher check failed: ${result.error?.message ?? commandFailure(result)}`
    )
  }
  const expectedImage = `ghcr.io/last-emo-boy/rikune-analyzer-static:${expectedVersion}`
  if (!result.stdout.includes(` ${expectedImage} node dist/index.js`)) {
    throw new Error(
      `Fresh-install Docker launcher does not use the versioned release image: ${result.stdout.trim()}`
    )
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

async function assertInstalledExport(rikuneRoot, bundle, expectedVersion) {
  const bundleRoot = join(rikuneRoot, 'node_modules', ...bundle.name.split('/'))
  const packageJsonPath = join(bundleRoot, 'package.json')
  if (!existsSync(packageJsonPath)) {
    throw new Error(`Installed release is missing bundled dependency: ${bundle.name}`)
  }

  const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'))
  if (packageJson.version !== expectedVersion) {
    throw new Error(
      `Bundled dependency version mismatch for ${bundle.name}: expected ${expectedVersion}, received ${packageJson.version}`
    )
  }
  const entryPath = resolve(bundleRoot, packageJson.main ?? 'dist/index.js')
  const moduleExports = await import(pathToFileURL(entryPath).href)
  if (typeof moduleExports[bundle.exportName] !== 'function') {
    throw new Error(
      `Expected ${bundle.exportName} to be importable from bundled dependency ${bundle.name}`
    )
  }
}

async function assertInstalledRuntimeAssets(rikuneRoot) {
  for (const assetPath of REQUIRED_RUNTIME_ASSET_ENTRIES) {
    const installedPath = join(rikuneRoot, assetPath.replace(/^package\//u, ''))
    if (!existsSync(installedPath) || !statSync(installedPath).isFile()) {
      throw new Error(`Installed release is missing runtime asset: ${installedPath}`)
    }
  }

  const smtModule = await import(
    pathToFileURL(join(rikuneRoot, 'dist/plugins/vm-analysis/tools/smt-solve.js')).href
  )
  const binaryDiffModule = await import(
    pathToFileURL(join(rikuneRoot, 'dist/plugins/binary-diff/binary-diff-engine.js')).href
  )
  for (const [name, resolvedPath] of [
    ['SMT worker', smtModule.resolveSmtWorkerPath()],
    ['binary diff worker', binaryDiffModule.resolveRizinDiffWorkerPath()],
  ]) {
    if (!existsSync(resolvedPath) || !statSync(resolvedPath).isFile()) {
      throw new Error(`Installed ${name} resolver points to a missing file: ${resolvedPath}`)
    }
  }

  const vulnModule = await import(
    pathToFileURL(join(rikuneRoot, 'dist/plugins/vuln-scanner/vuln-patterns.js')).href
  )
  const patterns = await vulnModule.loadPatterns()
  if (!Array.isArray(patterns.patterns) || patterns.patterns.length === 0) {
    throw new Error('Installed vulnerability scanner loaded no default patterns')
  }

  const seedModule = await import(
    pathToFileURL(join(rikuneRoot, 'dist/plugins/kb-collaboration/kb/seed-loader.js')).href
  )
  let inserted = 0
  const result = await seedModule.loadSeedDataIfEmpty({
    queryOneSql: () => ({ count: 0 }),
    runSql: () => {
      inserted += 1
    },
  })
  if (result.loaded === 0 || result.loaded !== inserted) {
    throw new Error('Installed KB seed loader did not load its packaged seed data')
  }
}

function assertInstalledPackageRoot(installRoot, rikuneRoot) {
  const runtimePathsUrl = pathToFileURL(join(rikuneRoot, 'dist/runtime-paths.js')).href
  const pythonInvocation = resolvePythonInvocation()
  const script = `
    const { spawnSync } = await import('node:child_process');
    const fs = await import('node:fs');
    const runtimePaths = await import(process.argv[1]);
    const expectedRoot = process.argv[2];
    if (runtimePaths.getPackageRoot() !== expectedRoot) {
      throw new Error('package root mismatch: ' + runtimePaths.getPackageRoot());
    }
    const workerPath = runtimePaths.resolvePackagePath('workers', 'static_worker.py');
    if (!fs.statSync(workerPath).isFile()) throw new Error('resolved worker is missing: ' + workerPath);
    const request = {
      job_id: 'fresh-install-smoke',
      tool: '__package_root_smoke__',
      sample: { sample_id: 'sha256:' + '0'.repeat(64), path: workerPath },
      args: {},
      context: {
        request_time_utc: new Date(0).toISOString(),
        policy: { allow_dynamic: false, allow_network: false },
        versions: {},
      },
    };
    const pythonCommand = process.argv[3];
    const pythonPrefixArgs = JSON.parse(process.argv[4]);
    const result = spawnSync(pythonCommand, [...pythonPrefixArgs, workerPath], {
      input: JSON.stringify(request) + '\\n',
      encoding: 'utf8',
      timeout: 30000,
    });
    if (result.error || result.status !== 0) {
      throw new Error('fresh-install static worker failed: ' + (result.error?.message ?? result.stderr));
    }
    const response = JSON.parse(result.stdout.trim());
    if (response.ok !== false || !response.errors?.some((item) => item.includes('Unknown tool'))) {
      throw new Error('unexpected static worker response: ' + result.stdout);
    }
  `
  const result = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '--eval',
      script,
      runtimePathsUrl,
      rikuneRoot,
      pythonInvocation.command,
      JSON.stringify(pythonInvocation.prefixArgs),
    ],
    {
      cwd: installRoot,
      encoding: 'utf8',
      env: process.env,
      maxBuffer: 4 * 1024 * 1024,
      timeout: 60 * 1000,
    }
  )
  if (result.error || result.status !== 0) {
    throw new Error(
      `Fresh-install package-root worker check failed: ${result.error?.message ?? commandFailure(result)}`
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
    if (installedPackageJson.contentPolicy?.class !== 'dual-use') {
      throw new Error('Installed release is missing contentPolicy.class=dual-use')
    }
    assertPublicSdkExport(installedPackageJson)
    assertInstalledCliEntries(installRoot, rikuneRoot, installedPackageJson, expectedVersion)
    assertInstalledDockerLauncher(rikuneRoot, expectedVersion)
    assertInstalledPackageRoot(installRoot, rikuneRoot)
    await assertInstalledRuntimeAssets(rikuneRoot)

    for (const bundle of REQUIRED_BUNDLES) {
      await assertInstalledExport(rikuneRoot, bundle, expectedVersion)
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
    `Verified rikune@${expectedVersion}: root API, bundled dependencies, CLI entries, runtime assets, and rikune/plugin-sdk.js are usable.`
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
