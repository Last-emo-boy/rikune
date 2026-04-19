/**
 * Unit tests for @rikune/windows-host-agent package metadata.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import path from 'path'

const packageJsonPath = path.resolve(process.cwd(), 'packages/windows-host-agent/package.json')
const sourcePath = path.resolve(process.cwd(), 'packages/windows-host-agent/src/index.ts')

describe('@rikune/windows-host-agent package', () => {
  test('package scripts expose real lint and test commands', () => {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8')) as {
      scripts?: Record<string, string>
    }

    expect(pkg.scripts?.lint).toBeTruthy()
    expect(pkg.scripts?.lint).not.toContain('No lint configured')
    expect(pkg.scripts?.test).toBeTruthy()
    expect(pkg.scripts?.test).not.toContain('No tests yet')
  })

  test('host agent source exposes sandbox control endpoints and auth gate', () => {
    const source = fs.readFileSync(sourcePath, 'utf-8')

    expect(source).toContain("url.pathname === '/sandbox/start'")
    expect(source).toContain("url.pathname === '/sandbox/stop'")
    expect(source).toContain("url.pathname === '/sandbox/health'")
    expect(source).toContain("url.pathname === '/hyperv/status'")
    expect(source).toContain("url.pathname === '/hyperv/checkpoints'")
    expect(source).toContain("req.method === 'POST' && url.pathname === '/hyperv/checkpoints'")
    expect(source).toContain("url.pathname === '/hyperv/restore'")
    expect(source).toContain("url.pathname === '/hyperv/stop'")
    expect(source).toContain('function requireAuth')
    expect(source).toContain('buildWsbXml')
    expect(source).toContain('HOST_AGENT_NODE_PATH')
    expect(source).toContain('HOST_AGENT_PYTHON_PATH')
    expect(source).toContain('HOST_AGENT_BACKEND')
    expect(source).toContain('HOST_AGENT_HYPERV_VM_NAME')
    expect(source).toContain('HOST_AGENT_HYPERV_RUNTIME_ENDPOINT')
    expect(source).toContain('HOST_AGENT_HYPERV_RESTORE_ON_RELEASE')
    expect(source).toContain('hypervRestoreOnRelease')
    expect(source).toContain('HostAgentStartDiagnostics')
    expect(source).toContain('collectWindowsSandboxDiagnostics')
    expect(source).toContain('getHyperVRuntimeStatus')
    expect(source).toContain('restoreHyperVCheckpoint')
    expect(source).toContain('createHyperVCheckpoint')
    expect(source).toContain('listHyperVCheckpoints')
    expect(source).toContain('Get-VMSnapshot')
    expect(source).toContain('Checkpoint-VM')
    expect(source).toContain('Restore-VMSnapshot')
    expect(source).toContain('runtime-startup.log')
    expect(source).toContain('logonCommandSummary')
  })
})
