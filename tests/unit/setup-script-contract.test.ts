import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from '@jest/globals'

describe('development setup release contract', () => {
  test('scrubs credentials, refuses private env files, and uses immutable dependency locks', () => {
    const script = fs.readFileSync(path.join(process.cwd(), 'scripts/setup.sh'), 'utf8')
    const npmInstall = script.indexOf('npm ci --include=dev')
    const pythonInstall = script.indexOf('pip install --disable-pip-version-check --require-hashes')

    expect(script).toContain('set -euo pipefail')
    expect(script).toContain('unset "$name"')
    expect(script).toContain('.docker-runtime.env')
    expect(script).toContain('.env.runtime-windows')
    expect(script).toContain('requirements.lock.txt')
    expect(script).not.toMatch(/\bnpm install\b/u)
    expect(script).not.toMatch(/pip install (?![^\n]*--require-hashes)/u)
    expect(npmInstall).toBeGreaterThan(script.indexOf('unset "$name"'))
    expect(npmInstall).toBeGreaterThan(script.indexOf('private environment file exists'))
    expect(pythonInstall).toBeGreaterThan(npmInstall)
  })
})
