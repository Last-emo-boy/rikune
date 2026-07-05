import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const pluginsRoot = path.join(repoRoot, 'src', 'plugins')

function walk(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  const files: string[] = []
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...walk(fullPath))
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      files.push(fullPath)
    }
  }
  return files
}

describe('plugin domain and runtime contracts', () => {
  test('every built-in plugin declares static/dynamic/both execution domain', () => {
    const pluginDirs = fs
      .readdirSync(pluginsRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(pluginsRoot, entry.name))

    const missing = pluginDirs
      .filter((dir) => fs.existsSync(path.join(dir, 'index.ts')))
      .filter((dir) => {
        const source = fs.readFileSync(path.join(dir, 'index.ts'), 'utf8')
        return !/executionDomain:\s*['"](static|dynamic|both)['"]/.test(source)
      })
      .map((dir) => path.basename(dir))

    expect(missing).toEqual([])
  })

  test('runtime-delegated tools use runtime contracts, not backend hints', () => {
    const offenders = walk(path.join(repoRoot, 'src'))
      .filter((file) => !file.endsWith(path.join('types.ts')))
      .flatMap((file) => {
        const source = fs.readFileSync(file, 'utf8')
        const findings: string[] = []
        if (source.includes('runtimeBackendHint')) findings.push('runtimeBackendHint')
        if (/ToolRuntimeContract:\s*\{/.test(source)) findings.push('ToolRuntimeContract field')
        return findings.length > 0
          ? [`${path.relative(repoRoot, file).replace(/\\/g, '/')}: ${findings.join(', ')}`]
          : []
      })

    expect(offenders).toEqual([])
  })

  test('runtime contract literals include backend type and handler', () => {
    const malformed = walk(pluginsRoot).flatMap((file) => {
      const source = fs.readFileSync(file, 'utf8')
      const matches = source.matchAll(/runtime:\s*\{([^}]+)\}/g)
      const bad: string[] = []
      for (const match of matches) {
        const body = match[1] ?? ''
        if (!/type:\s*['"](python-worker|spawn|inline)['"]/.test(body)) {
          bad.push('missing type')
        }
        if (!/handler:\s*['"][^'"]+['"]/.test(body)) {
          bad.push('missing handler')
        }
      }
      return bad.length > 0
        ? [`${path.relative(repoRoot, file).replace(/\\/g, '/')}: ${bad.join(', ')}`]
        : []
    })

    expect(malformed).toEqual([])
  })

  test('orchestrator exposes warning-first plugin quality gates', () => {
    const orchestratorSource = fs.readFileSync(
      path.join(repoRoot, 'src/core/plugin-orchestrator.ts'),
      'utf8'
    )
    const sdkSource = fs.readFileSync(path.join(repoRoot, 'packages/plugin-sdk/src/index.ts'), 'utf8')

    expect(orchestratorSource).toContain('qualityWarnings')
    expect(orchestratorSource).toContain('auditPluginQuality')
    expect(sdkSource).toContain('missing-aspects')
    expect(sdkSource).toContain('missing-output-schema')
    expect(sdkSource).toContain('missing-runtime-policy')
  })
})
