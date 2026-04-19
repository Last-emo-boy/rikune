/**
 * Unit tests for @rikune/shared exports.
 */

import { describe, expect, test } from '@jest/globals'
import { buildWsbXml, escapeXml, getPythonCommand } from '../../../packages/shared/src/index.js'

describe('@rikune/shared', () => {
  test('getPythonCommand prefers override and platform defaults', () => {
    expect(getPythonCommand('win32')).toBe('python')
    expect(getPythonCommand('linux')).toBe('python3')
    expect(getPythonCommand('darwin', '/custom/python')).toBe('/custom/python')
  })

  test('escapeXml escapes reserved characters', () => {
    expect(escapeXml(`a&b<test>\"quote\"'single'`)).toBe('a&amp;b&lt;test&gt;&quot;quote&quot;&apos;single&apos;')
  })

  test('buildWsbXml includes mapped folders, runtime auth, and optional setup folder', () => {
    const xml = buildWsbXml({
      runtimeDirHost: 'C:\\runtime & tools',
      runtimeFileName: 'index.js',
      workersDirHost: 'C:\\workers',
      inboxDir: 'C:\\inbox',
      outboxDir: 'C:\\outbox',
      readyFileSandbox: 'C:\\rikune-outbox\\ready.json',
      runtimeApiKey: 'sandbox-secret',
      setupDirHost: 'C:\\setup',
      nodeDirHost: 'C:\\Program Files\\nodejs',
      nodeFileName: 'node.exe',
      nodeModulesDirHost: 'C:\\project\\node_modules',
      pythonDirHost: 'C:\\Python312',
      pythonFileName: 'python.exe',
    })

    expect(xml).toContain('<Configuration>')
    expect(xml).toContain('&amp;')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-runtime</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-node</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\node_modules</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-python</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-setup</SandboxFolder>')
    expect(xml).toContain('powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand')
    expect(xml).not.toContain('cmd /c')

    const encoded = xml.match(/-EncodedCommand ([A-Za-z0-9+/=]+)/)?.[1]
    expect(encoded).toBeTruthy()
    const script = Buffer.from(encoded || '', 'base64').toString('utf16le')
    expect(script).toContain("& 'C:\\rikune-setup\\setup-sandbox-env.ps1'")
    expect(script).toContain("$env:RUNTIME_API_KEY = 'sandbox-secret'")
    expect(script).toContain("$env:RUNTIME_PYTHON_PATH = 'C:\\rikune-python\\python.exe'")
    expect(script).toContain("$startupLog = 'C:\\rikune-outbox\\runtime-startup.log'")
    expect(script).toContain("$defenderExclusionPaths = @('C:\\rikune-runtime', 'C:\\rikune-workers', 'C:\\rikune-inbox', 'C:\\rikune-outbox')")
    expect(script).toContain('Add-MpPreference -ExclusionPath $defenderPath')
    expect(script).toContain("Set-Location -LiteralPath 'C:\\rikune-runtime'")
    expect(script).toContain("Start-Process -FilePath 'C:\\rikune-node\\node.exe'")
    expect(script).toContain("'index.js', '--host', '0.0.0.0', '--port', '18081'")
    expect(script).toContain("'--python-path', 'C:\\rikune-python\\python.exe'")
    expect(script).toContain("'--ready-file', 'C:\\rikune-outbox\\ready.json'")
  })
})
