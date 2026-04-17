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
      pythonDirHost: 'C:\\Python312',
      pythonFileName: 'python.exe',
    })

    expect(xml).toContain('<Configuration>')
    expect(xml).toContain('&amp;')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-runtime</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-node</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-python</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-setup</SandboxFolder>')
    expect(xml).toContain('powershell -ExecutionPolicy Bypass -File C:\\rikune-setup\\setup-sandbox-env.ps1')
    expect(xml).toContain('set &quot;RUNTIME_API_KEY=sandbox-secret&quot;')
    expect(xml).toContain('&quot;C:\\rikune-node\\node.exe&quot; &quot;index.js&quot; --host 0.0.0.0 --port 18081')
    expect(xml).toContain('--python-path &quot;C:\\rikune-python\\python.exe&quot;')
    expect(xml).toContain('--ready-file C:\\rikune-outbox\\ready.json')
  })
})
