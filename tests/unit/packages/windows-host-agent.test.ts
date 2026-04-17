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
    expect(source).toContain('function requireAuth')
    expect(source).toContain('buildWsbXml')
    expect(source).toContain('HOST_AGENT_NODE_PATH')
    expect(source).toContain('HOST_AGENT_PYTHON_PATH')
  })
})
