import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from '@jest/globals'

const repoRoot = process.cwd()
const shellSource = fs.readFileSync(path.join(repoRoot, 'install-local.sh'), 'utf8')
const powershellSource = fs.readFileSync(path.join(repoRoot, 'install-local.ps1'), 'utf8')
const runtimePowershellSource = fs.readFileSync(
  path.join(repoRoot, 'install-runtime-windows.ps1'),
  'utf8'
)

const productionLocks = [
  'requirements.lock.txt',
  'requirements.windows.lock.txt',
  'workers/requirements-dynamic.lock.txt',
  'workers/requirements-dynamic.windows.lock.txt',
  'src/plugins/angr/requirements.lock.txt',
] as const

function assertCompleteHashLock(relativePath: string): void {
  const content = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8')
  const lines = content.split(/\r?\n/)
  const packageLine = /^[a-z0-9][a-z0-9._-]*==\S+/i
  const activeTopLevelLines = lines.filter((line) => /^[^\s#]/.test(line))
  const packageIndexes = lines.flatMap((line, index) => (packageLine.test(line) ? [index] : []))

  expect(content).toContain('--python-version 3.12')
  expect(content).toContain('--generate-hashes')
  expect(activeTopLevelLines.every((line) => packageLine.test(line))).toBe(true)
  expect(packageIndexes.length).toBeGreaterThan(0)
  for (const [position, packageIndex] of packageIndexes.entries()) {
    const nextPackageIndex = packageIndexes[position + 1] ?? lines.length
    const entry = lines.slice(packageIndex, nextPackageIndex).join('\n')
    expect(entry).toContain('--hash=sha256:')
  }
}

function activePipInstallLines(source: string): string[] {
  return source
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => !line.startsWith('#') && /-m\s+pip\s+install\b/.test(line))
}

describe('local installer Python production-lock contract', () => {
  test('keeps every selected production lock complete and hash-pinned for CPython 3.12', () => {
    for (const relativePath of productionLocks) {
      assertCompleteHashLock(relativePath)
    }
    expect(fs.readFileSync(path.join(repoRoot, 'requirements.lock.txt'), 'utf8')).toContain(
      'x86_64-manylinux_2_36'
    )
    expect(fs.readFileSync(path.join(repoRoot, 'requirements.windows.lock.txt'), 'utf8')).toContain(
      'x86_64-pc-windows-msvc'
    )
  })

  test('requires exact 64-bit CPython 3.12 for the host interpreter and reused venvs', () => {
    for (const source of [shellSource, powershellSource]) {
      expect(source.match(/sys\.version_info\[:2\] == \(3, 12\)/g)?.length).toBeGreaterThanOrEqual(
        2
      )
      expect(source).toContain("sys.implementation.name == 'cpython'")
      expect(source).toContain("struct.calcsize('P') == 8")
      expect(source).not.toContain('Python 3.11')
      expect(source).not.toContain('sys.version_info >=')
    }

    expect(shellSource).toContain('[ "$(uname -s)" = "Linux" ]')
    expect(shellSource).toContain('x86_64|amd64')
    expect(powershellSource).toContain('[System.Runtime.InteropServices.OSPlatform]::Windows')
    expect(powershellSource).toContain('[System.Runtime.InteropServices.Architecture]::X64')
    expect(powershellSource).toContain("@{ Command = 'py'; PrefixArgs = @('-3.12') }")

    expect(runtimePowershellSource).toContain('sys.version_info[:2] == (3, 12)')
    expect(runtimePowershellSource).toContain("sys.implementation.name == 'cpython'")
    expect(runtimePowershellSource).toContain("struct.calcsize('P') == 8")
    expect(runtimePowershellSource).toContain("@{ Command = 'py'; PrefixArgs = @('-3.12') }")
    expect(runtimePowershellSource).not.toContain('Python 3.11')
    expect(runtimePowershellSource).not.toContain('ms-windows-store:')
  })

  test('installs base and dynamic dependencies only from the matching platform lock', () => {
    expect(shellSource).toContain('BASE_REQUIREMENTS_LOCK="$PROJECT_ROOT/requirements.lock.txt"')
    expect(shellSource).toContain(
      'DYNAMIC_REQUIREMENTS_LOCK="$WORKERS_DIR/requirements-dynamic.lock.txt"'
    )
    expect(powershellSource).toContain(
      '$baseRequirementsLock = Join-Path $ProjectRoot "requirements.windows.lock.txt"'
    )
    expect(powershellSource).toContain(
      '$dynamicRequirementsLock = Join-Path $workersDir "requirements-dynamic.windows.lock.txt"'
    )

    const shellInstalls = activePipInstallLines(shellSource)
    const powershellInstalls = activePipInstallLines(powershellSource)
    expect(shellInstalls).toHaveLength(3)
    expect(powershellInstalls).toHaveLength(2)
    for (const command of [...shellInstalls, ...powershellInstalls]) {
      expect(command).toContain('--require-hashes')
      expect(command).toContain('--requirement')
      expect(command).toContain('--disable-pip-version-check')
      expect(command).not.toContain('|| warn')
    }
  })

  test('fails closed when a selected lock or pip installation fails', () => {
    for (const lockName of [
      'BASE_REQUIREMENTS_LOCK',
      'DYNAMIC_REQUIREMENTS_LOCK',
      'ANGR_REQUIREMENTS_LOCK',
    ]) {
      expect(shellSource).toContain(`[ -f "$${lockName}" ] ||`)
    }
    expect(shellSource).toContain('set -euo pipefail')
    expect(shellSource).not.toContain('Some dynamic packages failed')

    for (const lockName of ['$baseRequirementsLock', '$dynamicRequirementsLock']) {
      const installIndex = powershellSource.indexOf(`--require-hashes --requirement ${lockName}`)
      expect(installIndex).toBeGreaterThan(-1)
      const successIndex = powershellSource.indexOf('Write-Success', installIndex)
      const failureGate = powershellSource.slice(installIndex, successIndex)
      expect(failureGate).toContain('if ($LASTEXITCODE -ne 0)')
      expect(failureGate).toContain('exit 1')
    }
    expect(powershellSource).not.toContain('Some dynamic packages failed')
    expect(powershellSource).not.toContain('this is OK on Windows')
  })

  test('never upgrades pip online or falls back to unlocked/latest requirements', () => {
    const combinedSource = `${shellSource}\n${powershellSource}`
    expect(combinedSource).not.toMatch(/pip\s+install[^\r\n]*--upgrade\s+pip/i)
    expect(combinedSource).not.toMatch(/-m\s+ensurepip\b/i)
    expect(combinedSource).not.toMatch(/pip\s+install[^\r\n]*\sangr(?:\s|$)/i)
    expect(combinedSource).not.toContain('requirements-qiling.txt')

    for (const command of [
      ...activePipInstallLines(shellSource),
      ...activePipInstallLines(powershellSource),
    ]) {
      expect(command).not.toMatch(/requirements(?:-dynamic|-qiling)?\.txt/i)
    }
  })

  test('uses the Linux angr lock and explicitly disables profiles without production locks', () => {
    expect(shellSource).toContain(
      'ANGR_REQUIREMENTS_LOCK="$PROJECT_ROOT/src/plugins/angr/requirements.lock.txt"'
    )
    expect(shellSource).toContain(
      'Qiling installation is disabled: no hashed Linux production lock is available.'
    )
    expect(powershellSource).toContain(
      'Qiling installation is disabled: no hashed Windows production lock is available.'
    )
    expect(powershellSource).toContain(
      'angr installation is disabled on Windows: no hashed Windows production lock is available.'
    )
  })
})
