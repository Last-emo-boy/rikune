import { describe, expect, test } from '@jest/globals'
import { execFileSync } from 'child_process'
import fs from 'fs'
import path from 'path'

const cliPath = path.resolve(process.cwd(), 'bin/rikune.js')
const analyzerEntryPath = path.resolve(process.cwd(), 'src/index.ts')
const legacyWindowsInstallerPath = path.resolve(process.cwd(), 'install-local.ps1')
const linuxInstallerPath = path.resolve(process.cwd(), 'install-local.sh')
const publicShellEntrypoints = [
  'rikune.sh',
  'install-local.sh',
  'deploy-hybrid.sh',
  'diagnose-hybrid.sh',
  'docker-entrypoint.sh',
  'scripts/setup.sh',
  'scripts/validate-docker-full-stack.sh',
]
const remoteHybridGuides = [
  'README.md',
  'README_zh.md',
  'INSTALL.md',
  'DEPLOYMENT.md',
  'docs/docker.html',
  'docs/index.html',
]

describe('rikune CLI platform contract', () => {
  test.each(publicShellEntrypoints)('tracks %s as an executable entrypoint', (relativePath) => {
    if (process.platform === 'win32') {
      const stage = execFileSync('git', ['ls-files', '--stage', '--', relativePath], {
        cwd: process.cwd(),
        encoding: 'utf8',
      })
      expect(stage.split(/\s+/u)[0]).toBe('100755')
      return
    }

    const mode = fs.statSync(path.resolve(process.cwd(), relativePath)).mode
    expect(mode & 0o111).toBe(0o111)
  })

  test.each(remoteHybridGuides)(
    'documents remote bootstrap security opt-in in %s',
    (relativePath) => {
      const lines = fs.readFileSync(path.resolve(process.cwd(), relativePath), 'utf8').split(/\r?\n/u)
      const commands = lines
        .map((line, index) => ({ line, index }))
        .filter(({ line }) =>
          line.includes('./rikune.sh install --profile hybrid --windows-host')
        )

      expect(commands.length).toBeGreaterThan(0)
      for (const { index } of commands) {
        const command = lines.slice(index, index + 4).join('\n')
        expect(command).toContain('--host-agent-endpoint https://')
        expect(command).toContain('--allow-insecure-runtime-http')
      }
    }
  )

  test('keeps control-plane subcommands available before the native Analyzer Linux guard', () => {
    const source = fs.readFileSync(cliPath, 'utf8')
    const dockerIndex = source.indexOf("subcommand === 'docker-stdio'")
    const agentIndex = source.indexOf("subcommand === 'agent'")
    const linuxGuardIndex = source.indexOf("process.platform !== 'linux'")
    const serverIndex = source.indexOf("import('../dist/index.js')")

    expect(dockerIndex).toBeGreaterThanOrEqual(0)
    expect(agentIndex).toBeGreaterThan(dockerIndex)
    expect(linuxGuardIndex).toBeGreaterThan(agentIndex)
    expect(serverIndex).toBeGreaterThan(linuxGuardIndex)
    expect(source).toContain('native Analyzer requires a Linux kernel')
    expect(source).toContain('rikune docker-stdio')
    expect(source).toContain('rikune agent')
  })

  test('keeps the legacy Windows Analyzer installer fail-closed before all legacy actions', () => {
    const source = fs.readFileSync(legacyWindowsInstallerPath, 'utf8')
    const guardIndex = source.indexOf('requires a Linux kernel')
    const exitIndex = source.indexOf('exit 1', guardIndex)
    const legacyEnvironmentIndex = source.indexOf('$explicitAnalyzerApiKey =')
    const dependencyInstallIndex = source.indexOf('npm ci --include=dev')
    const dataMutationIndex = source.indexOf('New-Item -ItemType Directory')

    expect(guardIndex).toBeGreaterThanOrEqual(0)
    expect(exitIndex).toBeGreaterThan(guardIndex)
    expect(legacyEnvironmentIndex).toBeGreaterThan(exitIndex)
    expect(dependencyInstallIndex).toBeGreaterThan(exitIndex)
    expect(dataMutationIndex).toBeGreaterThan(exitIndex)
  })

  test('verifies the final WSL data root before local installer mutations', () => {
    const source = fs.readFileSync(linuxInstallerPath, 'utf8')
    const canonicalRootIndex = source.indexOf('DATA_ROOT="$(realpath -m -- "$DATA_ROOT")"')
    const guardIndex = source.indexOf('assert_supported_wsl_data_root "$DATA_ROOT"')
    const projectDirectoryIndex = source.indexOf('cd "$PROJECT_ROOT"', guardIndex)
    const stagedEnvironmentIndex = source.indexOf('\nbegin_private_env_transaction\n', guardIndex)
    const dependencyInstallIndex = source.indexOf('npm ci --include=dev')
    const snapshotWriterIndex = source.indexOf(
      'RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN=1',
      dependencyInstallIndex
    )
    const transactionCommitIndex = source.indexOf(
      '\ncommit_private_env_transaction\n',
      snapshotWriterIndex
    )
    const dataMutationIndex = source.indexOf('mkdir -p "$DATA_ROOT/$dir"')

    expect(canonicalRootIndex).toBeGreaterThanOrEqual(0)
    expect(guardIndex).toBeGreaterThan(canonicalRootIndex)
    expect(projectDirectoryIndex).toBeGreaterThan(guardIndex)
    expect(stagedEnvironmentIndex).toBeGreaterThan(guardIndex)
    expect(dependencyInstallIndex).toBeGreaterThan(guardIndex)
    expect(snapshotWriterIndex).toBeGreaterThan(dependencyInstallIndex)
    expect(transactionCommitIndex).toBeGreaterThan(snapshotWriterIndex)
    expect(dataMutationIndex).toBeGreaterThan(guardIndex)
  })

  test('verifies every Analyzer custody root before bootstrap mutations', () => {
    const source = fs.readFileSync(analyzerEntryPath, 'utf8')
    const configLoadIndex = source.indexOf('const config = loadConfig(process.env.CONFIG_PATH)')
    const filesystemGuardIndex = source.indexOf(
      'assertSupportedAnalyzerFilesystem(getAnalyzerCustodyRoots(config))'
    )
    const firstBootstrapMutationIndex = source.indexOf(
      'prepareGhidraRuntimeDirectories(config)',
      filesystemGuardIndex
    )

    expect(configLoadIndex).toBeGreaterThanOrEqual(0)
    expect(filesystemGuardIndex).toBeGreaterThan(configLoadIndex)
    expect(firstBootstrapMutationIndex).toBeGreaterThan(filesystemGuardIndex)
    for (const rootName of [
      'workspace.root',
      'cache.root',
      'logging.auditPath',
      'api.storageRoot',
      'workers.ghidra.projectRoot',
      'workers.ghidra.logRoot',
      'database.path',
    ]) {
      expect(source).toContain(`name: '${rootName}'`)
    }
  })
})
