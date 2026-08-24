import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, test } from '@jest/globals'
import {
  parseDockerRuntimeEnv,
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

describe('Docker runtime env writer', () => {
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

  test('rotates a non-empty existing key across repeated installs', () => {
    const target = createTarget()
    const preservedKey = 'cd'.repeat(16)
    fs.writeFileSync(target, `RIKUNE_API_KEY=${preservedKey}\n`)
    fs.chmodSync(target, 0o600)

    const result = write(target)
    const values = parseDockerRuntimeEnv(fs.readFileSync(target, 'utf8'))

    expect(result).toEqual({ analyzerApiKey: 'ab'.repeat(32), generated: true })
    expect(values.RIKUNE_API_KEY).toBe('ab'.repeat(32))
    expect(values.RIKUNE_API_KEY).not.toBe(preservedKey)
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
    expect(powershellInstaller).toContain('RIKUNE_REMOVE_PRIVATE_ENV_PATH')
    const dependencyIndex = powershellInstaller.indexOf('& npm ci --include=dev')
    const buildIndex = powershellInstaller.indexOf('& npm run build')
    const envWriteIndex = powershellInstaller.lastIndexOf('Write-EnvFile `')
    expect(dependencyIndex).toBeGreaterThanOrEqual(0)
    expect(buildIndex).toBeGreaterThan(dependencyIndex)
    expect(envWriteIndex).toBeGreaterThan(buildIndex)
    expect(
      fs.existsSync(path.join(process.cwd(), 'scripts', 'verify-powershell-installers.ps1'))
    ).toBe(true)
    expect(powershellInstaller).not.toMatch(
      /Write-(?:Host|Info|Success|Warning-Message)[^\r\n]*\$AnalyzerApiKey/u
    )
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
    expect(hybridInstaller).not.toMatch(/-ApiKey(?:\s|["'])/u)
    expect(hybridInstaller).not.toContain('cat > "$ENV_FILE"')
    expect(hybridInstaller).not.toMatch(/curl[^\r\n]*Authorization: Bearer \$/u)
    expect(hybridDiagnostics).not.toMatch(/curl[^\r\n]*Authorization: Bearer \$/u)

    expect(manifest.devDependencies.pm2).toBe('7.0.3')
    expect(lock.packages['node_modules/pm2'].version).toBe('7.0.3')
  })
})
