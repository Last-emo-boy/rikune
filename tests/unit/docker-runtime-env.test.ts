import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { afterEach, describe, expect, test } from '@jest/globals'
import {
  capturePrivateEnvSnapshot,
  decodePrivateEnvSnapshot,
  encodePrivateEnvSnapshot,
  invokeWindowsFileAcl,
  parseDockerRuntimeEnv,
  privateEnvSnapshotContent,
  removePrivateEnvForSnapshot,
  restorePrivateEnvSnapshot,
  writeDockerRuntimeEnv,
} from '../../scripts/write-docker-runtime-env.mjs'

const temporaryDirectories: string[] = []

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

function createTarget(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-docker-env-'))
  temporaryDirectories.push(directory)
  return path.join(directory, '.docker-runtime.env')
}

function write(targetPath: string, overrides: Record<string, unknown> = {}) {
  return writeDockerRuntimeEnv({
    targetPath,
    dataRoot: '/tmp/rikune-data',
    profile: 'static',
    buildNoProxy: 'localhost,127.0.0.1',
    randomBytes: () => Buffer.alloc(32, 0xab),
    ...overrides,
  })
}

function writeExecutable(filePath: string, content: string): void {
  fs.writeFileSync(filePath, content, { mode: 0o755 })
  fs.chmodSync(filePath, 0o755)
}

function createDockerInstallerFixture(): { root: string; bin: string; target: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-docker-installer-'))
  temporaryDirectories.push(root)
  const scripts = path.join(root, 'scripts')
  const bin = path.join(root, 'test-bin')
  fs.mkdirSync(scripts, { recursive: true })
  fs.mkdirSync(bin, { recursive: true })
  fs.copyFileSync(path.join(process.cwd(), 'rikune.sh'), path.join(root, 'rikune.sh'))
  fs.copyFileSync(
    path.join(process.cwd(), 'scripts', 'write-docker-runtime-env.mjs'),
    path.join(scripts, 'write-docker-runtime-env.mjs')
  )
  fs.chmodSync(path.join(root, 'rikune.sh'), 0o755)
  writeExecutable(
    path.join(bin, 'npm'),
    `#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then printf '10.0.0\\n'; exit 0; fi
if [ "\${1:-}" = "ci" ]; then exit "\${RIKUNE_TEST_NPM_EXIT:-41}"; fi
exit 0
`
  )
  writeExecutable(
    path.join(bin, 'docker'),
    `#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then printf 'Docker version 27.0.0\\n'; exit 0; fi
if [ "\${1:-}" = "info" ]; then exit 0; fi
if [ "\${1:-}" = "compose" ] && [ "\${2:-}" = "version" ]; then printf 'Docker Compose version v2.29.0\\n'; exit 0; fi
exit 0
`
  )
  return { root, bin, target: path.join(root, '.docker-runtime.env') }
}

describe('Docker runtime env writer', () => {
  test('launches the Windows ACL helper with only trusted executable search paths', () => {
    let invocation:
      | { command: string; args: string[]; options: { env: Record<string, string> } }
      | undefined
    const environment = {
      SystemRoot: 'C:\\Windows',
      HOMEDRIVE: 'C:',
      HOMEPATH: '\\Users\\analyst',
      LOGONSERVER: '\\\\TRUSTED-DC',
      PATH: 'C:\\attacker',
      TEMP: 'C:\\Users\\analyst\\AppData\\Local\\Temp',
      TMP: 'C:\\Users\\analyst\\AppData\\Local\\Temp',
      USERDOMAIN: 'TRUSTED',
      USERNAME: 'analyst',
      USERPROFILE: 'C:\\Users\\analyst',
      PSModulePath: 'C:\\attacker\\modules',
      RIKUNE_API_KEY: 'must-not-reach-child',
    }

    invokeWindowsFileAcl('C:\\secure\\.env', 'verify', {
      environment,
      powershell: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      spawn: (command: string, args: string[], options: { env: Record<string, string> }) => {
        invocation = { command, args, options }
        return { status: 0, stdout: 'RIKUNE_PRIVATE_FILE_ACL_V1', stderr: '' }
      },
    })

    expect(invocation).toBeDefined()
    const childEnvironment = invocation!.options.env
    expect(childEnvironment.PATH).toBe('C:\\Windows\\System32')
    expect(childEnvironment.PSModulePath).toBe(
      'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules'
    )
    expect(childEnvironment.SYSTEMDRIVE).toBe('C:')
    expect(childEnvironment.SYSTEMROOT).toBe('C:\\Windows')
    expect(childEnvironment.WINDIR).toBe('C:\\Windows')
    expect(childEnvironment.HOMEDRIVE).toBe('C:')
    expect(childEnvironment.HOMEPATH).toBe('\\')
    expect(childEnvironment.LOGONSERVER).toBe('')
    expect(childEnvironment.USERDOMAIN).toBe('')
    expect(childEnvironment.USERNAME).toBe('')
    expect(childEnvironment.USERPROFILE).toBe('')
    for (const requiredName of [
      'HOMEDRIVE',
      'HOMEPATH',
      'LOGONSERVER',
      'PATH',
      'SYSTEMDRIVE',
      'SYSTEMROOT',
      'TEMP',
      'USERDOMAIN',
      'USERNAME',
      'USERPROFILE',
      'WINDIR',
    ]) {
      expect(Object.hasOwn(childEnvironment, requiredName)).toBe(true)
    }
    expect(childEnvironment).not.toHaveProperty('RIKUNE_API_KEY')

    const encodedIndex = invocation!.args.indexOf('-EncodedCommand')
    const aclScript = Buffer.from(invocation!.args[encodedIndex + 1], 'base64').toString('utf16le')
    expect(aclScript.trimStart().startsWith('$env:PSModulePath = $env:SystemRoot')).toBe(true)
    expect(aclScript.indexOf('$env:PSModulePath =')).toBeLessThan(aclScript.indexOf('New-Object'))

    expect(() =>
      invokeWindowsFileAcl('C:\\secure\\.env', 'verify', {
        environment: { SystemRoot: 'C:\\Windows', windir: 'D:\\Windows' },
        powershell: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        spawn: () => ({ status: 0, stdout: 'RIKUNE_PRIVATE_FILE_ACL_V1', stderr: '' }),
      })
    ).toThrow('SystemRoot and windir')
  })

  test('generates one strong analyzer key and writes both server and client settings', () => {
    const target = createTarget()
    const result = write(target)
    const values = parseDockerRuntimeEnv(fs.readFileSync(target, 'utf8'))

    expect(result).toEqual({ analyzerApiKey: 'ab'.repeat(32), generated: true })
    expect(values.RIKUNE_API_KEY).toBe('ab'.repeat(32))
    expect(values.RIKUNE_ANALYZER_API_KEY).toBe(values.RIKUNE_API_KEY)
    if (process.platform !== 'win32') {
      expect(fs.statSync(target).mode & 0o777).toBe(0o600)
    }
  })

  test('rotates a non-empty existing key and preserves unrelated user settings', () => {
    const target = createTarget()
    const preservedKey = 'cd'.repeat(16)
    fs.writeFileSync(target, `RIKUNE_API_KEY=${preservedKey}\nCUSTOM_TOOL_PATH=/opt/custom\n`)
    fs.chmodSync(target, 0o600)

    const result = write(target)
    const values = parseDockerRuntimeEnv(fs.readFileSync(target, 'utf8'))

    expect(result).toEqual({ analyzerApiKey: 'ab'.repeat(32), generated: true })
    expect(values.RIKUNE_API_KEY).toBe('ab'.repeat(32))
    expect(values.RIKUNE_API_KEY).not.toBe(preservedKey)
    expect(values.CUSTOM_TOOL_PATH).toBe('/opt/custom')
  })

  test('round-trips an exact private snapshot and restores original bytes with mode 0600', () => {
    if (process.platform === 'win32') return
    const target = createTarget()
    const originalBytes = Buffer.from(
      `# user comment\r\nCUSTOM_FIRST=one\r\nRIKUNE_API_KEY=${'cd'.repeat(16)}\r\nCUSTOM_LAST=two\r\n`,
      'utf8'
    )
    fs.writeFileSync(target, originalBytes, { mode: 0o600 })
    fs.chmodSync(target, 0o600)

    const captured = capturePrivateEnvSnapshot({ targetPath: target, platform: 'linux' })
    const snapshot = decodePrivateEnvSnapshot(encodePrivateEnvSnapshot(captured))

    expect(snapshot.existed).toBe(true)
    expect(snapshot.originalBytes.equals(originalBytes)).toBe(true)
    expect(fs.readFileSync(target).equals(originalBytes)).toBe(true)

    removePrivateEnvForSnapshot({ targetPath: target, snapshot, platform: 'linux' })
    expect(fs.existsSync(target)).toBe(false)
    restorePrivateEnvSnapshot({ targetPath: target, snapshot, platform: 'linux' })

    expect(fs.readFileSync(target).equals(originalBytes)).toBe(true)
    expect(fs.statSync(target).mode & 0o777).toBe(0o600)
  })

  test('restores exact bytes through the Windows ACL restriction and verification hooks', () => {
    const target = createTarget()
    const originalBytes = Buffer.from(
      `# windows ordering\r\nCUSTOM_FIRST=one\r\nRIKUNE_API_KEY=${'ce'.repeat(32)}\r\n`,
      'utf8'
    )
    fs.writeFileSync(target, originalBytes)
    const verified: string[] = []
    const restricted: string[] = []
    const verifyWindowsAcl = (filePath: string) => verified.push(filePath)
    const restrictWindowsAcl = (filePath: string) => restricted.push(filePath)
    const snapshot = capturePrivateEnvSnapshot({
      targetPath: target,
      platform: 'win32',
      verifyWindowsAcl,
    })

    removePrivateEnvForSnapshot({
      targetPath: target,
      snapshot,
      platform: 'win32',
      verifyWindowsAcl,
    })
    restorePrivateEnvSnapshot({
      targetPath: target,
      snapshot,
      platform: 'win32',
      restrictWindowsAcl,
      verifyWindowsAcl,
    })

    expect(fs.readFileSync(target).equals(originalBytes)).toBe(true)
    expect(restricted.some((filePath) => filePath === target)).toBe(true)
    expect(verified.filter((filePath) => filePath === target).length).toBeGreaterThanOrEqual(2)
  })

  test('keeps the no-original state absent when a transaction fails before the writer commits', () => {
    if (process.platform === 'win32') return
    const target = createTarget()
    const snapshot = capturePrivateEnvSnapshot({ targetPath: target, platform: 'linux' })

    expect(snapshot.existed).toBe(false)
    removePrivateEnvForSnapshot({ targetPath: target, snapshot, platform: 'linux' })
    restorePrivateEnvSnapshot({ targetPath: target, snapshot, platform: 'linux' })
    expect(fs.existsSync(target)).toBe(false)
  })

  test('refuses to overwrite or delete files changed concurrently after a snapshot', () => {
    if (process.platform === 'win32') return
    const existingTarget = createTarget()
    const original = Buffer.from('CUSTOM_SETTING=original\n', 'utf8')
    const concurrent = Buffer.from('CUSTOM_SETTING=concurrent\n', 'utf8')
    fs.writeFileSync(existingTarget, original, { mode: 0o600 })
    fs.chmodSync(existingTarget, 0o600)
    const existingSnapshot = capturePrivateEnvSnapshot({
      targetPath: existingTarget,
      platform: 'linux',
    })
    fs.writeFileSync(existingTarget, concurrent, { mode: 0o600 })
    fs.chmodSync(existingTarget, 0o600)

    expect(() =>
      restorePrivateEnvSnapshot({
        targetPath: existingTarget,
        snapshot: existingSnapshot,
        platform: 'linux',
      })
    ).toThrow('refused to overwrite')
    expect(fs.readFileSync(existingTarget).equals(concurrent)).toBe(true)

    const missingTarget = createTarget()
    const missingSnapshot = capturePrivateEnvSnapshot({
      targetPath: missingTarget,
      platform: 'linux',
    })
    fs.writeFileSync(missingTarget, concurrent, { mode: 0o600 })
    fs.chmodSync(missingTarget, 0o600)
    expect(() =>
      restorePrivateEnvSnapshot({
        targetPath: missingTarget,
        snapshot: missingSnapshot,
        platform: 'linux',
      })
    ).toThrow('refused to remove')
    expect(fs.readFileSync(missingTarget).equals(concurrent)).toBe(true)
  })

  test('final transaction writer refuses a concurrent protected target without overwriting it', () => {
    if (process.platform === 'win32') return
    const target = createTarget()
    const original = Buffer.from(`RIKUNE_API_KEY=${'de'.repeat(32)}\nCUSTOM_SETTING=old\n`)
    const concurrent = Buffer.from('CUSTOM_SETTING=concurrent\n')
    fs.writeFileSync(target, original, { mode: 0o600 })
    fs.chmodSync(target, 0o600)
    const snapshot = capturePrivateEnvSnapshot({ targetPath: target, platform: 'linux' })
    removePrivateEnvForSnapshot({ targetPath: target, snapshot, platform: 'linux' })
    fs.writeFileSync(target, concurrent, { mode: 0o600 })
    fs.chmodSync(target, 0o600)

    expect(() =>
      write(target, {
        existingContent: privateEnvSnapshotContent(snapshot),
        requireAbsent: true,
      })
    ).toThrow('transaction target appeared')
    expect(fs.readFileSync(target).equals(concurrent)).toBe(true)
  })

  test('real rikune.sh dependency failure preserves exit code and restores exact old bytes', () => {
    if (process.platform === 'win32') return
    const fixture = createDockerInstallerFixture()
    const originalBytes = Buffer.from(
      `# exact docker comment\r\nCUSTOM_SETTING=preserve\r\nRIKUNE_API_KEY=${'bd'.repeat(32)}\r\n`,
      'utf8'
    )
    fs.writeFileSync(fixture.target, originalBytes, { mode: 0o600 })
    fs.chmodSync(fixture.target, 0o600)
    const environment: NodeJS.ProcessEnv = {
      ...process.env,
      PATH: `${fixture.bin}${path.delimiter}${process.env.PATH ?? ''}`,
      RIKUNE_TEST_NPM_EXIT: '41',
    }
    for (const name of [
      'RIKUNE_API_KEY',
      'RIKUNE_ANALYZER_API_KEY',
      'RUNTIME_HOST_AGENT_API_KEY',
      'RUNTIME_API_KEY',
    ]) {
      delete environment[name]
    }
    const result = spawnSync(
      'bash',
      [
        path.join(fixture.root, 'rikune.sh'),
        'install',
        '--profile',
        'static',
        '--data-root',
        path.join(fixture.root, 'data'),
      ],
      {
        cwd: fixture.root,
        env: environment,
        encoding: 'utf8',
        timeout: 15_000,
      }
    )

    expect(result.status).toBe(41)
    expect(`${result.stdout}${result.stderr}`).not.toContain('bd'.repeat(32))
    expect(fs.readFileSync(fixture.target).equals(originalBytes)).toBe(true)
    expect(fs.statSync(fixture.target).mode & 0o777).toBe(0o600)
  })

  test('real rikune.sh dependency failure leaves a previously absent env absent', () => {
    if (process.platform === 'win32') return
    const fixture = createDockerInstallerFixture()
    const environment: NodeJS.ProcessEnv = {
      ...process.env,
      PATH: `${fixture.bin}${path.delimiter}${process.env.PATH ?? ''}`,
      RIKUNE_TEST_NPM_EXIT: '42',
    }
    for (const name of [
      'RIKUNE_API_KEY',
      'RIKUNE_ANALYZER_API_KEY',
      'RUNTIME_HOST_AGENT_API_KEY',
      'RUNTIME_API_KEY',
    ]) {
      delete environment[name]
    }

    const result = spawnSync(
      'bash',
      [
        path.join(fixture.root, 'rikune.sh'),
        'install',
        '--profile',
        'static',
        '--data-root',
        path.join(fixture.root, 'data'),
      ],
      {
        cwd: fixture.root,
        env: environment,
        encoding: 'utf8',
        timeout: 15_000,
      }
    )

    expect(result.status).toBe(42)
    expect(fs.existsSync(fixture.target)).toBe(false)
  })

  test('replaces an empty existing key and carries hybrid credentials without logging', () => {
    const target = createTarget()
    fs.writeFileSync(target, 'RIKUNE_API_KEY=\n')
    fs.chmodSync(target, 0o600)

    write(target, {
      profile: 'hybrid',
      hostAgentEndpoint: 'http://host.docker.internal:18082',
      hostAgentApiKey: 'host-secret-'.repeat(3),
      runtimeApiKey: 'runtime-secret-'.repeat(3),
    })
    const values = parseDockerRuntimeEnv(fs.readFileSync(target, 'utf8'))

    expect(values.RIKUNE_API_KEY).toBe('ab'.repeat(32))
    expect(values.RUNTIME_HOST_AGENT_API_KEY).toBe('host-secret-'.repeat(3))
    expect(values.RUNTIME_API_KEY).toBe('runtime-secret-'.repeat(3))
  })

  test('rejects values that could inject another env entry', () => {
    const target = createTarget()
    expect(() => write(target, { analyzerApiKey: 'secret\nINJECTED=true' })).toThrow(
      'cannot contain line breaks'
    )
    expect(fs.existsSync(target)).toBe(false)
  })

  test('rejects weak credentials and remote plaintext runtime endpoints by default', () => {
    expect(() => write(createTarget(), { analyzerApiKey: 'too-short' })).toThrow(
      'at least 32 printable'
    )
    expect(() =>
      write(createTarget(), {
        profile: 'hybrid',
        hostAgentEndpoint: 'http://192.0.2.10:18082',
        hostAgentApiKey: 'host-secret-'.repeat(3),
        runtimeApiKey: 'runtime-secret-'.repeat(3),
      })
    ).toThrow('must use HTTPS for remote hosts')

    expect(() =>
      write(createTarget(), {
        profile: 'hybrid',
        hostAgentEndpoint: 'http://192.0.2.10:18082',
        hostAgentApiKey: 'host-secret-'.repeat(3),
        runtimeApiKey: 'runtime-secret-'.repeat(3),
        allowInsecureRuntimeHttp: true,
      })
    ).not.toThrow()
  })

  test('fails closed when required profile settings are missing', () => {
    expect(() => write(createTarget(), { dataRoot: '   ' })).toThrow('RIKUNE_DATA_ROOT is required')
    expect(() => write(createTarget(), { profile: 'unknown' })).toThrow(
      'Unsupported Docker runtime profile'
    )
    expect(() =>
      write(createTarget(), {
        profile: 'hybrid',
        hostAgentEndpoint: 'http://host.docker.internal:18082',
        hostAgentApiKey: '',
        runtimeApiKey: 'runtime-secret-'.repeat(3),
      })
    ).toThrow('RUNTIME_HOST_AGENT_API_KEY is required')
    expect(() =>
      write(createTarget(), {
        profile: 'hybrid',
        hostAgentEndpoint: 'http://host.docker.internal:18082',
        hostAgentApiKey: 'same-secret-'.repeat(3),
        runtimeApiKey: 'same-secret-'.repeat(3),
      })
    ).toThrow('must be distinct')
  })

  test('rejects planted symlinks and known-key files with unsafe permissions', () => {
    if (process.platform === 'win32') return
    const symlinkTarget = createTarget()
    const symlinkBacking = `${symlinkTarget}.backing`
    fs.writeFileSync(symlinkBacking, `RIKUNE_API_KEY=${'cd'.repeat(16)}\n`, { mode: 0o600 })
    fs.symlinkSync(symlinkBacking, symlinkTarget)
    expect(() => write(symlinkTarget)).toThrow('non-link regular file')

    const weakModeTarget = createTarget()
    fs.writeFileSync(weakModeTarget, `RIKUNE_API_KEY=${'ef'.repeat(16)}\n`, { mode: 0o644 })
    fs.chmodSync(weakModeTarget, 0o644)
    expect(() => write(weakModeTarget)).toThrow('mode 0600')
  })

  test('restricts an empty Windows temp file before writing and atomically replaces stale ACL state', () => {
    const target = createTarget()
    const oldKey = 'ef'.repeat(16)
    fs.writeFileSync(target, `RIKUNE_API_KEY=${oldKey}\n`)
    const aclSnapshots: Array<{ path: string; content: string }> = []

    write(target, {
      platform: 'win32',
      restrictWindowsAcl: (filePath: string) => {
        aclSnapshots.push({ path: filePath, content: fs.readFileSync(filePath, 'utf8') })
      },
      verifyWindowsAcl: () => undefined,
    })

    expect(aclSnapshots).toHaveLength(2)
    expect(aclSnapshots[0].path).not.toBe(target)
    expect(aclSnapshots[0].content).toBe('')
    expect(aclSnapshots[1].path).toBe(target)
    expect(aclSnapshots[1].content).toContain(`RIKUNE_API_KEY=${'ab'.repeat(32)}`)
    expect(fs.readFileSync(target, 'utf8')).not.toContain(oldKey)
  })

  test('keeps both installers on the secure writer and never logs the analyzer key', () => {
    const shellInstaller = fs.readFileSync(path.join(process.cwd(), 'rikune.sh'), 'utf8')
    const powershellInstaller = fs.readFileSync(
      path.join(process.cwd(), 'install-docker.ps1'),
      'utf8'
    )

    expect(shellInstaller).toContain('scripts/write-docker-runtime-env.mjs')
    expect(shellInstaller).toContain('chmod 600 "$env_file"')
    expect(powershellInstaller).toContain('scripts/write-docker-runtime-env.mjs')
    expect(powershellInstaller).toContain('RIKUNE_ANALYZER_API_KEY = $AnalyzerApiKey')
    expect(powershellInstaller).not.toContain('function Read-EnvFile')
    expect(powershellInstaller).not.toContain('& icacls')
    expect(powershellInstaller).toContain('RIKUNE_STAGE_DOCKER_ENV_PATH')
    expect(powershellInstaller).toContain('RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH')
    expect(powershellInstaller).toContain('RIKUNE_RESTORE_PRIVATE_ENV_PATH')
    expect(powershellInstaller).toContain('RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN')
    expect(powershellInstaller).toContain('$privateEnvTransactionCommitted = $true')
    expect(powershellInstaller).toContain('RIKUNE_NATIVE_EXIT_CODE')
    expect(powershellInstaller).toContain('exit $privateEnvFailureExitCode')
    const dependencyIndex = powershellInstaller.indexOf('& npm ci --include=dev')
    const buildIndex = powershellInstaller.indexOf('& npm run build')
    const envWriteIndex = powershellInstaller.lastIndexOf('Write-EnvFile `')
    expect(dependencyIndex).toBeGreaterThanOrEqual(0)
    expect(buildIndex).toBeGreaterThan(dependencyIndex)
    expect(envWriteIndex).toBeGreaterThan(buildIndex)
    const commitIndex = powershellInstaller.lastIndexOf('$privateEnvTransactionCommitted = $true')
    const composeIndex = powershellInstaller.indexOf('Write-Step "Docker Compose"')
    expect(commitIndex).toBeGreaterThan(envWriteIndex)
    expect(composeIndex).toBeGreaterThan(commitIndex)
    expect(
      fs.existsSync(path.join(process.cwd(), 'scripts', 'verify-powershell-installers.ps1'))
    ).toBe(true)
    expect(powershellInstaller).not.toMatch(
      /Write-(?:Host|Info|Success|Warning-Message)[^\r\n]*\$AnalyzerApiKey/u
    )
    expect(powershellInstaller).not.toMatch(
      /Write-(?:Host|Info|Success|Warning-Message)[^\r\n]*\$privateEnvSnapshot/u
    )

    expect(shellInstaller).toContain('RIKUNE_STAGE_DOCKER_ENV_PATH=')
    expect(shellInstaller).toContain('[ "$node_minor" -lt 9 ]')
    expect(shellInstaller).toContain('22.9+ is required')
    expect(shellInstaller).toContain('RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH=')
    expect(shellInstaller).toContain('RIKUNE_RESTORE_PRIVATE_ENV_PATH=')
    expect(shellInstaller).toContain('RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN=1')
    expect(shellInstaller).toContain('[ "$original_status" -ne 0 ] || original_status=1')
    const shellWriterIndex = shellInstaller.indexOf(
      'node "$PROJECT_ROOT/scripts/write-docker-runtime-env.mjs"'
    )
    const shellCommitIndex = shellInstaller.lastIndexOf('commit_private_env_transaction')
    const shellChmodIndex = shellInstaller.indexOf('chmod 600 "$env_file"')
    const shellComposeIndex = shellInstaller.indexOf('run_compose "$profile" build "$service"')
    expect(shellCommitIndex).toBeGreaterThan(shellWriterIndex)
    expect(shellChmodIndex).toBeGreaterThan(shellCommitIndex)
    expect(shellComposeIndex).toBeGreaterThan(shellCommitIndex)
  })

  test('keeps Windows and Hybrid bootstrap secrets out of child argument vectors', () => {
    const runtimeInstaller = fs.readFileSync(
      path.join(process.cwd(), 'install-runtime-windows.ps1'),
      'utf8'
    )
    const powershellWrapper = fs.readFileSync(path.join(process.cwd(), 'rikune.ps1'), 'utf8')
    const shellWrapper = fs.readFileSync(path.join(process.cwd(), 'rikune.sh'), 'utf8')
    const hybridInstaller = fs.readFileSync(path.join(process.cwd(), 'deploy-hybrid.sh'), 'utf8')
    const hybridDiagnostics = fs.readFileSync(
      path.join(process.cwd(), 'diagnose-hybrid.sh'),
      'utf8'
    )
    const manifest = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'))
    const lock = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package-lock.json'), 'utf8'))

    expect(runtimeInstaller).toContain('[string]$BindHost = "127.0.0.1"')
    expect(runtimeInstaller).toContain('RandomNumberGenerator]::GetBytes(32)')
    expect(runtimeInstaller).toContain('[switch]$ReadApiKeyFromStdin')
    expect(runtimeInstaller).toContain('[switch]$AllowInsecureRuntimeHttp')
    expect(runtimeInstaller).toContain(
      'Assert-SecureRuntimeEndpoint -Endpoint $HyperVRuntimeEndpoint'
    )
    expect(runtimeInstaller).toContain('node_modules\\.bin\\pm2.cmd')
    expect(runtimeInstaller).toContain('dist\\bootstrap.js')
    expect(runtimeInstaller).not.toContain('Get-Random')
    expect(runtimeInstaller).not.toMatch(/npm\s+install\s+-g\s+pm2/u)
    expect(runtimeInstaller).not.toMatch(/API Key:\s*\$apiKey/u)
    expect(runtimeInstaller).not.toContain('$env:HOST_AGENT_API_KEY = "$apiKey"')
    expect(runtimeInstaller).not.toContain('$env:HOST_AGENT_RUNTIME_API_KEY = "$apiKey"')

    expect(powershellWrapper).toContain('RIKUNE_HOST_AGENT_API_KEY = $HostAgentApiKey')
    expect(powershellWrapper).toContain('RIKUNE_RUNTIME_NODE_API_KEY = $RuntimeApiKey')
    expect(powershellWrapper).toContain('RUNTIME_HOST_AGENT_API_KEY = $hostKey')
    expect(powershellWrapper).toContain('if ($AllowInsecureRuntimeHttp)')
    expect(powershellWrapper).not.toMatch(/\$args\s*\+=\s*@\("-ApiKey"/u)
    expect(powershellWrapper).not.toMatch(/\$args\s*\+=\s*@\("-HostAgentApiKey"/u)
    expect(powershellWrapper).not.toMatch(/\$args\s*\+=\s*@\("-RuntimeApiKey"/u)

    expect(shellWrapper).toContain('--allow-insecure-runtime-http')
    expect(shellWrapper).not.toContain('--host-agent-api-key')
    expect(shellWrapper).not.toContain('--runtime-api-key')
    expect(shellWrapper).not.toMatch(
      /args\+=\(-[ar]\s+"\$(?:HOST_AGENT_API_KEY|RUNTIME_API_KEY)"\)/u
    )
    expect(shellWrapper).not.toMatch(/curl[^\r\n]*Authorization: Bearer \$/u)

    expect(hybridInstaller).toContain('scripts/write-docker-runtime-env.mjs')
    expect(hybridInstaller).toContain('chmod 600 "$ENV_FILE"')
    expect(hybridInstaller).toContain('pwsh -NoProfile -NonInteractive')
    expect(hybridInstaller).not.toContain('-ReadApiKeyFromStdin')
    expect(hybridInstaller).toContain('-RuntimeBindHost 0.0.0.0')
    expect(hybridInstaller).toContain('-AllowInsecureRuntimeHttp')
    expect(hybridInstaller).toContain('--exclude .env.runtime-windows')
    expect(hybridInstaller).toContain('rsync -az --delete')
    expect(hybridInstaller).toContain('Host Agent and Runtime Node API keys must be distinct')
    expect(hybridInstaller).toContain('HOST_AGENT_ENDPOINT_EXPLICIT=true')
    expect(hybridInstaller).toContain('[ "$HOST_AGENT_ENDPOINT_EXPLICIT" = false ]')
    expect(hybridInstaller).toContain(
      'export -n HOST_AGENT_API_KEY RUNTIME_API_KEY ANALYZER_API_KEY'
    )
    expect(hybridInstaller).toContain('RIKUNE_STAGE_DOCKER_ENV_PATH=')
    expect(hybridInstaller).toContain('[ "$NODE_MINOR" -lt 9 ]')
    expect(hybridInstaller).toContain('22.9+ is required')
    expect(hybridInstaller).toContain('RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH=')
    expect(hybridInstaller).toContain('RIKUNE_RESTORE_PRIVATE_ENV_PATH=')
    expect(hybridInstaller).toContain('RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN=1')
    expect(hybridInstaller).toContain('[ "$original_status" -ne 0 ] || original_status=1')
    const hybridWriterIndex = hybridInstaller.indexOf('RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN=1')
    const hybridCommitIndex = hybridInstaller.lastIndexOf('commit_private_env_transaction')
    const hybridChmodIndex = hybridInstaller.indexOf('chmod 600 "$ENV_FILE"')
    const hybridComposeIndex = hybridInstaller.indexOf(
      'docker compose --env-file .docker-runtime.env'
    )
    expect(hybridCommitIndex).toBeGreaterThan(hybridWriterIndex)
    expect(hybridChmodIndex).toBeGreaterThan(hybridCommitIndex)
    expect(hybridComposeIndex).toBeGreaterThan(hybridCommitIndex)
    expect(hybridInstaller).not.toMatch(/-ApiKey(?:\s|["'])/u)
    expect(hybridInstaller).not.toContain('cat > "$ENV_FILE"')
    expect(hybridInstaller).not.toMatch(/curl[^\r\n]*Authorization: Bearer \$/u)
    expect(hybridDiagnostics).not.toMatch(/curl[^\r\n]*Authorization: Bearer \$/u)

    expect(manifest.devDependencies.pm2).toBe('7.0.3')
    expect(lock.packages['node_modules/pm2'].version).toBe('7.0.3')
  })
})
