import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, test } from '@jest/globals'
import {
  parseStrictLocalEnv,
  renderLocalRuntimeEnv,
  stageLocalRuntimeEnv,
  writeLocalRuntimeEnv,
} from '../../scripts/write-local-runtime-env.mjs'

const temporaryDirectories: string[] = []
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

describe('secure local runtime env writer', () => {
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

  test('stages only non-secret settings and removes the protected source before installation', () => {
    const targetPath = createTarget()
    fs.writeFileSync(
      targetPath,
      `NODE_ROLE=legacy\nAPI_KEY=${'ab'.repeat(16)}\nRIKUNE_API_KEY=${'cd'.repeat(16)}\nCUSTOM_TOOL_PATH=/opt/custom\n`,
      { mode: 0o600 }
    )
    fs.chmodSync(targetPath, 0o600)

    const staged = stageLocalRuntimeEnv({ targetPath, platform: 'linux' })

    expect(staged).toBe('NODE_ROLE=legacy\nCUSTOM_TOOL_PATH=/opt/custom\n')
    expect(fs.existsSync(targetPath)).toBe(false)

    writeLocalRuntimeEnv({
      targetPath,
      template,
      stagedExistingContent: staged,
      forcedKeys: ['NODE_ROLE', 'RUNTIME_MODE', 'API_ENABLED'],
      randomBytes: () => Buffer.alloc(32, 0x56),
      platform: 'linux',
    })
    const values = parseStrictLocalEnv(fs.readFileSync(targetPath, 'utf8'))
    expect(values.get('API_KEY')).toBe('56'.repeat(32))
    expect(values.get('CUSTOM_TOOL_PATH')).toBe('/opt/custom')
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
    expect(shell.indexOf('RIKUNE_STAGE_LOCAL_ENV_PATH=')).toBeLessThan(shell.indexOf('npm ci'))
    expect(shell.indexOf('RIKUNE_LOCAL_EXISTING_ENV_BASE64=')).toBeGreaterThan(
      shell.indexOf('npm run build')
    )
    expect(shell).toContain('unset RIKUNE_API_KEY RIKUNE_ANALYZER_API_KEY')
    expect(shell).toContain('API_KEY=__RIKUNE_CSPRNG_API_KEY__')
    expect(shell).not.toContain('cat > "$ENV_FILE"')
    expect(shell).not.toContain('# API_KEY=your-secret-key-here')
    expect(powershell).toContain('scripts/write-local-runtime-env.mjs')
    expect(powershell.indexOf('"RIKUNE_STAGE_LOCAL_ENV_PATH"')).toBeLessThan(
      powershell.indexOf('npm ci')
    )
    expect(powershell.indexOf('RIKUNE_LOCAL_EXISTING_ENV_BASE64 =')).toBeGreaterThan(
      powershell.indexOf('npm run build')
    )
    expect(powershell).toContain('"RIKUNE_ANALYZER_API_KEY"')
    expect(powershell).toContain('API_KEY=__RIKUNE_CSPRNG_API_KEY__')
    expect(powershell).not.toContain('$envContent | Set-Content $envFile')
    expect(powershell).not.toContain('# API_KEY=your-secret-key-here')
  })
})
