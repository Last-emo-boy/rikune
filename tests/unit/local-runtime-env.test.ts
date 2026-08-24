import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { afterEach, describe, expect, test } from '@jest/globals'
import {
  parseStrictLocalEnv,
  renderLocalRuntimeEnv,
  stageLocalRuntimeEnv,
  writeLocalRuntimeEnv,
} from '../../scripts/write-local-runtime-env.mjs'
import {
  capturePrivateEnvSnapshot,
  encodePrivateEnvSnapshot,
  PRIVATE_ENV_INTERNAL_CONTROL_NAMES,
  privateEnvSnapshotContent,
  removePrivateEnvForSnapshot,
} from '../../scripts/write-docker-runtime-env.mjs'

const temporaryDirectories: string[] = []
const INSTALLER_FORBIDDEN_ENV_NAMES = [
  ...PRIVATE_ENV_INTERNAL_CONTROL_NAMES,
  'RIKUNE_API_KEY',
  'RIKUNE_ANALYZER_API_KEY',
  'RUNTIME_HOST_AGENT_ENDPOINT',
  'RUNTIME_HOST_AGENT_API_KEY',
  'HOST_AGENT_API_KEY',
  'HOST_AGENT_RUNTIME_API_KEY',
  'RUNTIME_API_KEY',
  'RIKUNE_HOST_AGENT_API_KEY',
  'RIKUNE_RUNTIME_API_KEY',
  'RIKUNE_RUNTIME_NODE_API_KEY',
].join(',')
const template = `# generated
NODE_ROLE=analyzer
RUNTIME_MODE=disabled
API_ENABLED=true
API_KEY=__RIKUNE_CSPRNG_API_KEY__
`

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true })
  }
})

function createTarget(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-local-env-'))
  temporaryDirectories.push(directory)
  return path.join(directory, '.env')
}

function writeExecutable(filePath: string, content: string): void {
  fs.writeFileSync(filePath, content, { mode: 0o755 })
  fs.chmodSync(filePath, 0o755)
}

function poisonPrivateEnvControls(
  environment: NodeJS.ProcessEnv,
  targetPath: string
): NodeJS.ProcessEnv {
  for (const name of PRIVATE_ENV_INTERNAL_CONTROL_NAMES) {
    environment[name] = name.endsWith('_PATH') ? targetPath : `poison-${name.toLowerCase()}`
  }
  environment.RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN = '1'
  environment.RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN = '1'
  environment.RUNTIME_HOST_AGENT_ENDPOINT = 'https://poison.invalid'
  return environment
}

function createLocalInstallerFixture(): { root: string; bin: string; target: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-local-installer-'))
  temporaryDirectories.push(root)
  const scripts = path.join(root, 'scripts')
  const bin = path.join(root, 'test-bin')
  fs.mkdirSync(scripts, { recursive: true })
  fs.mkdirSync(bin, { recursive: true })
  fs.copyFileSync(path.join(process.cwd(), 'install-local.sh'), path.join(root, 'install-local.sh'))
  fs.copyFileSync(
    path.join(process.cwd(), 'scripts', 'write-local-runtime-env.mjs'),
    path.join(scripts, 'write-local-runtime-env.mjs')
  )
  fs.copyFileSync(
    path.join(process.cwd(), 'scripts', 'write-docker-runtime-env.mjs'),
    path.join(scripts, 'write-docker-runtime-env.mjs')
  )
  fs.chmodSync(path.join(root, 'install-local.sh'), 0o755)
  writeExecutable(
    path.join(bin, 'npm'),
    `#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then printf '10.0.0\\n'; exit 0; fi
if [ "\${1:-}" = "ci" ]; then
  if [ -n "\${RIKUNE_TEST_EXPECT_ABSENT:-}" ] && [ -e "\${RIKUNE_TEST_EXPECT_ABSENT}" ]; then exit 97; fi
  IFS=, read -r -a forbidden_names <<< "\${RIKUNE_TEST_FORBIDDEN_ENV_NAMES:-}"
  for forbidden_name in "\${forbidden_names[@]}"; do
    if [ -n "$forbidden_name" ] && [ -n "\${!forbidden_name+x}" ]; then exit 96; fi
  done
  exit "\${RIKUNE_TEST_NPM_EXIT:-37}"
fi
exit 0
`
  )
  writeExecutable(
    path.join(bin, 'python3.12'),
    `#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then printf 'Python 3.12.0\\n'; fi
exit 0
`
  )
  return { root, bin, target: path.join(root, '.env') }
}

describe('secure local runtime env writer', () => {
  test('requires exactly one local CLI operation selector without precedence', () => {
    if (process.platform === 'win32') return
    const targetPath = createTarget()
    const fakeSecret = 'local-selector-secret-'.repeat(2)
    fs.writeFileSync(targetPath, `API_KEY=${fakeSecret}\n`, { mode: 0o600 })
    fs.chmodSync(targetPath, 0o600)
    const writerPath = path.join(process.cwd(), 'scripts', 'write-local-runtime-env.mjs')
    const cleanEnvironment: NodeJS.ProcessEnv = { ...process.env }
    for (const name of PRIVATE_ENV_INTERNAL_CONTROL_NAMES) delete cleanEnvironment[name]

    const missing = spawnSync(process.execPath, [writerPath], {
      env: cleanEnvironment,
      encoding: 'utf8',
    })
    expect(missing.status).not.toBe(0)
    expect(missing.stdout).toBe('')
    expect(missing.stderr).toContain('Exactly one private environment operation selector')

    const poisoned = spawnSync(process.execPath, [writerPath], {
      env: {
        ...cleanEnvironment,
        RIKUNE_STAGE_LOCAL_ENV_PATH: targetPath,
        RIKUNE_LOCAL_ENV_PATH: targetPath,
      },
      input: template,
      encoding: 'utf8',
    })
    expect(poisoned.status).not.toBe(0)
    expect(poisoned.stdout).toBe('')
    expect(poisoned.stderr).toContain('received 2')
    expect(`${poisoned.stdout}${poisoned.stderr}`).not.toContain(fakeSecret)
    expect(fs.existsSync(targetPath)).toBe(true)

    const poisonedModifier = spawnSync(process.execPath, [writerPath], {
      env: {
        ...cleanEnvironment,
        RIKUNE_STAGE_LOCAL_ENV_PATH: targetPath,
        RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN: '1',
      },
      encoding: 'utf8',
    })
    expect(poisonedModifier.status).not.toBe(0)
    expect(poisonedModifier.stdout).toBe('')
    expect(poisonedModifier.stderr).toContain('write controls require the write operation')
    expect(`${poisonedModifier.stdout}${poisonedModifier.stderr}`).not.toContain(fakeSecret)
  })

  test('generates a strong API key and creates the file with private POSIX mode', () => {
    const targetPath = createTarget()
    const result = writeLocalRuntimeEnv({
      targetPath,
      template,
      forcedKeys: ['NODE_ROLE', 'RUNTIME_MODE', 'API_ENABLED'],
      randomBytes: () => Buffer.alloc(32, 0x12),
      platform: 'linux',
    })
    const values = parseStrictLocalEnv(fs.readFileSync(targetPath, 'utf8'))

    expect(result.apiKey).toBe('12'.repeat(32))
    expect(values.get('API_KEY')).toBe(result.apiKey)
    expect(fs.statSync(targetPath).mode & 0o777).toBe(0o600)
  })

  test('rotates the API key, preserves protected user settings, and replaces forced values', () => {
    const targetPath = createTarget()
    const key = 'ab'.repeat(16)
    fs.writeFileSync(
      targetPath,
      `NODE_ROLE=legacy\nRUNTIME_MODE=manual\nAPI_ENABLED=false\nAPI_KEY=${key}\nCUSTOM_TOOL_PATH=/opt/custom\n`
    )
    fs.chmodSync(targetPath, 0o600)

    writeLocalRuntimeEnv({
      targetPath,
      template,
      forcedKeys: ['NODE_ROLE', 'RUNTIME_MODE', 'API_ENABLED'],
      randomBytes: () => Buffer.alloc(32, 0x34),
      platform: 'linux',
    })
    const values = parseStrictLocalEnv(fs.readFileSync(targetPath, 'utf8'))

    expect(values.get('NODE_ROLE')).toBe('analyzer')
    expect(values.get('RUNTIME_MODE')).toBe('disabled')
    expect(values.get('API_ENABLED')).toBe('true')
    expect(values.get('API_KEY')).toBe('34'.repeat(32))
    expect(values.get('API_KEY')).not.toBe(key)
    expect(values.get('CUSTOM_TOOL_PATH')).toBe('/opt/custom')
  })

  test('captures exact old bytes, removes only after the snapshot is installed, and rotates safely', () => {
    const targetPath = createTarget()
    fs.writeFileSync(
      targetPath,
      `NODE_ROLE=legacy\nAPI_KEY=${'ab'.repeat(16)}\nRIKUNE_API_KEY=${'cd'.repeat(16)}\nCUSTOM_TOOL_PATH=/opt/custom\n`,
      { mode: 0o600 }
    )
    fs.chmodSync(targetPath, 0o600)

    const snapshot = stageLocalRuntimeEnv({ targetPath, platform: 'linux' })

    expect(snapshot.existed).toBe(true)
    expect(snapshot.originalBytes.equals(fs.readFileSync(targetPath))).toBe(true)
    removePrivateEnvForSnapshot({ targetPath, snapshot, platform: 'linux' })
    expect(fs.existsSync(targetPath)).toBe(false)

    writeLocalRuntimeEnv({
      targetPath,
      template,
      stagedExistingContent: privateEnvSnapshotContent(snapshot),
      forcedKeys: ['NODE_ROLE', 'RUNTIME_MODE', 'API_ENABLED'],
      randomBytes: () => Buffer.alloc(32, 0x56),
      platform: 'linux',
    })
    const values = parseStrictLocalEnv(fs.readFileSync(targetPath, 'utf8'))
    expect(values.get('API_KEY')).toBe('56'.repeat(32))
    expect(values.get('CUSTOM_TOOL_PATH')).toBe('/opt/custom')
  })

  test('real Bash installer failure preserves exit code and rolls back exact old or missing state', () => {
    if (process.platform === 'win32') return
    const originalBytes = Buffer.from(
      `# exact user comment\r\nCUSTOM_FIRST=one\r\nAPI_KEY=${'ac'.repeat(32)}\r\nCUSTOM_LAST=two\r\n`,
      'utf8'
    )

    for (const [withOriginal, exitCode] of [
      [true, 37],
      [false, 38],
    ] as const) {
      const fixture = createLocalInstallerFixture()
      if (withOriginal) {
        fs.writeFileSync(fixture.target, originalBytes, { mode: 0o600 })
        fs.chmodSync(fixture.target, 0o600)
      }
      const snapshotText = encodePrivateEnvSnapshot(
        capturePrivateEnvSnapshot({ targetPath: fixture.target, platform: 'linux' })
      )
      const explicitKey = 'de'.repeat(32)
      const environment = poisonPrivateEnvControls(
        {
          ...process.env,
          PATH: `${fixture.bin}${path.delimiter}${process.env.PATH ?? ''}`,
          RIKUNE_API_KEY: explicitKey,
          RIKUNE_TEST_NPM_EXIT: String(exitCode),
          RIKUNE_TEST_EXPECT_ABSENT: fixture.target,
          RIKUNE_TEST_FORBIDDEN_ENV_NAMES: INSTALLER_FORBIDDEN_ENV_NAMES,
        },
        fixture.target
      )
      delete environment.WSL_DISTRO_NAME
      delete environment.WSL_INTEROP
      const result = spawnSync('bash', [path.join(fixture.root, 'install-local.sh')], {
        cwd: fixture.root,
        env: environment,
        input: 'y\n\n',
        encoding: 'utf8',
        timeout: 15_000,
      })

      expect(result.status).toBe(exitCode)
      const output = `${result.stdout}${result.stderr}`
      expect(output).not.toContain('ac'.repeat(32))
      expect(output).not.toContain(explicitKey)
      expect(output).not.toContain(snapshotText)
      if (withOriginal) {
        expect(fs.readFileSync(fixture.target).equals(originalBytes)).toBe(true)
        expect(fs.statSync(fixture.target).mode & 0o777).toBe(0o600)
      } else {
        expect(fs.existsSync(fixture.target)).toBe(false)
      }
    }
  })

  test('refuses to stage planted symlinks or weakly protected files and leaves them in place', () => {
    if (process.platform === 'win32') return
    const symlinkTarget = createTarget()
    const backing = `${symlinkTarget}.backing`
    fs.writeFileSync(backing, 'CUSTOM_TOOL_PATH=/opt/custom\n', { mode: 0o600 })
    fs.symlinkSync(backing, symlinkTarget)
    expect(() => stageLocalRuntimeEnv({ targetPath: symlinkTarget, platform: 'linux' })).toThrow(
      'non-link regular file'
    )
    expect(fs.lstatSync(symlinkTarget).isSymbolicLink()).toBe(true)

    const weakModeTarget = createTarget()
    fs.writeFileSync(weakModeTarget, 'CUSTOM_TOOL_PATH=/opt/custom\n', { mode: 0o644 })
    fs.chmodSync(weakModeTarget, 0o644)
    expect(() => stageLocalRuntimeEnv({ targetPath: weakModeTarget, platform: 'linux' })).toThrow(
      'mode 0600'
    )
    expect(fs.existsSync(weakModeTarget)).toBe(true)
  })

  test('rejects duplicate entries and malformed templates', () => {
    expect(() => parseStrictLocalEnv('API_KEY=one\nAPI_KEY=two\n')).toThrow(
      'Duplicate local runtime env variable'
    )
    expect(() =>
      renderLocalRuntimeEnv({
        template: 'API_ENABLED=true\n',
      })
    ).toThrow('exactly one API_KEY=')
  })

  test('rejects planted symlinks and world-readable known-key files', () => {
    if (process.platform === 'win32') return
    const symlinkTarget = createTarget()
    const backing = `${symlinkTarget}.backing`
    fs.writeFileSync(backing, `API_KEY=${'ab'.repeat(16)}\n`, { mode: 0o600 })
    fs.symlinkSync(backing, symlinkTarget)
    expect(() => writeLocalRuntimeEnv({ targetPath: symlinkTarget, template })).toThrow(
      'non-link regular file'
    )

    const weakModeTarget = createTarget()
    fs.writeFileSync(weakModeTarget, `API_KEY=${'cd'.repeat(16)}\n`, { mode: 0o644 })
    fs.chmodSync(weakModeTarget, 0o644)
    expect(() => writeLocalRuntimeEnv({ targetPath: weakModeTarget, template })).toThrow(
      'mode 0600'
    )
  })

  test('keeps both local installers on the protected atomic writer', () => {
    const shell = fs.readFileSync(path.join(process.cwd(), 'install-local.sh'), 'utf8')
    const powershell = fs.readFileSync(path.join(process.cwd(), 'install-local.ps1'), 'utf8')

    expect(shell).toContain('scripts/write-local-runtime-env.mjs')
    expect(shell).toContain('[ "$NODE_MINOR" -lt 9 ]')
    expect(shell).toContain('need 22.9+')
    expect(shell.indexOf('RIKUNE_STAGE_LOCAL_ENV_PATH=')).toBeLessThan(shell.indexOf('npm ci'))
    expect(shell.indexOf('RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH=')).toBeLessThan(
      shell.indexOf('npm ci')
    )
    expect(shell.indexOf('RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN=1')).toBeGreaterThan(
      shell.indexOf('npm run build')
    )
    expect(shell).toContain('RIKUNE_RESTORE_PRIVATE_ENV_PATH=')
    expect(shell).toContain("trap 'rollback_private_env_transaction")
    expect(shell).toContain('[ "$original_status" -ne 0 ] || original_status=1')
    for (const name of PRIVATE_ENV_INTERNAL_CONTROL_NAMES) {
      expect(shell).toContain(name)
      expect(powershell).toContain(`"${name}"`)
    }
    const shellScrubIndex = shell.indexOf('unset RIKUNE_API_KEY RIKUNE_ANALYZER_API_KEY')
    const powershellScrubIndex = powershell.indexOf(
      ') | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }'
    )
    expect(shell.indexOf('npm ci --include=dev')).toBeGreaterThan(shellScrubIndex)
    expect(powershell.indexOf('npm ci --include=dev')).toBeGreaterThan(powershellScrubIndex)
    expect(shell.lastIndexOf('\ncommit_private_env_transaction\n')).toBeGreaterThan(
      shell.indexOf('RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN=1')
    )
    expect(shell).not.toMatch(/\bexport\s+PRIVATE_ENV_SNAPSHOT=/u)
    expect(shell).toContain('unset RIKUNE_API_KEY RIKUNE_ANALYZER_API_KEY')
    expect(shell).toContain('API_KEY=__RIKUNE_CSPRNG_API_KEY__')
    expect(shell).not.toContain('cat > "$ENV_FILE"')
    expect(shell).not.toContain('# API_KEY=your-secret-key-here')
    expect(powershell).toContain('scripts/write-local-runtime-env.mjs')
    expect(powershell).toContain('$nodeMinor -lt 9')
    expect(powershell).toContain('need 22.9+')
    expect(powershell.indexOf('"RIKUNE_STAGE_LOCAL_ENV_PATH"')).toBeLessThan(
      powershell.indexOf('npm ci')
    )
    expect(powershell.indexOf('"RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH"')).toBeLessThan(
      powershell.indexOf('npm ci')
    )
    expect(powershell.indexOf('RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN = "1"')).toBeGreaterThan(
      powershell.indexOf('npm run build')
    )
    expect(powershell).toContain('"RIKUNE_RESTORE_PRIVATE_ENV_PATH"')
    expect(powershell).toContain('$privateEnvTransactionCommitted = $true')
    expect(powershell).toContain('"RIKUNE_ANALYZER_API_KEY"')
    expect(powershell).toContain('API_KEY=__RIKUNE_CSPRNG_API_KEY__')
    expect(powershell).not.toContain('$envContent | Set-Content $envFile')
    expect(powershell).not.toContain('# API_KEY=your-secret-key-here')
  })
})
