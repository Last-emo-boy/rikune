import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from '@jest/globals'
import {
  assertBundledDependencyEntries,
  assertPublicSdkExport,
  resolveNpmInvocation,
  resolvePythonInvocation,
} from '../../scripts/verify-release-package.mjs'

const requiredEntries = [
  'package/DISCLOSURE',
  'package/CHANGELOG.md',
  'package/scripts/secure-fs-helper.py',
  'package/requirements.lock.txt',
  'package/requirements.windows.lock.txt',
  'package/workers/requirements-dynamic.lock.txt',
  'package/workers/requirements-dynamic.windows.lock.txt',
  'package/src/plugins/angr/requirements.lock.txt',
  'package/dist/plugins/binary-diff/workers/rizin_diff_worker.py',
  'package/dist/plugins/kb-collaboration/data/windows-api-semantics.json',
  'package/dist/plugins/vm-analysis/workers/constraint_solver_worker.py',
  'package/dist/plugins/vuln-scanner/data/vuln-patterns.json',
  'package/bin/rikune.js',
  'package/bin/rikune-docker.js',
  'package/bin/rikune-agent.js',
  'package/plugin-sdk.js',
  'package/plugin-sdk.d.ts',
  'package/node_modules/@rikune/shared/package.json',
  'package/node_modules/@rikune/shared/dist/index.js',
  'package/node_modules/@rikune/shared/dist/index.d.ts',
  'package/node_modules/@rikune/plugin-sdk/package.json',
  'package/node_modules/@rikune/plugin-sdk/dist/index.js',
  'package/node_modules/@rikune/plugin-sdk/dist/index.d.ts',
]

describe('release package verification', () => {
  test('keeps every workspace package and internal dependency on the release version', () => {
    const root = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'))
    const lock = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package-lock.json'), 'utf8'))
    const workspacePaths = [
      'packages/plugin-sdk',
      'packages/shared',
      'packages/runtime-node',
      'packages/windows-host-agent',
      'packages/tsconfig',
    ]

    expect(root.version).toBe('1.4.1')
    for (const workspacePath of workspacePaths) {
      const manifest = JSON.parse(
        fs.readFileSync(path.join(process.cwd(), workspacePath, 'package.json'), 'utf8')
      )
      expect(manifest.version).toBe(root.version)
      expect(lock.packages[workspacePath].version).toBe(root.version)
      if (manifest.dependencies?.['@rikune/shared']) {
        expect(manifest.dependencies['@rikune/shared']).toBe(root.version)
      }
    }
    expect(root.dependencies['@rikune/plugin-sdk']).toBe(root.version)
    expect(root.dependencies['@rikune/shared']).toBe(root.version)
  })

  test('accepts a tarball entry list containing both bundled dependencies', () => {
    expect(() => assertBundledDependencyEntries(requiredEntries)).not.toThrow()
  })

  test('rejects a tarball entry list missing a required bundled file', () => {
    const withoutSharedRuntime = requiredEntries.filter(
      (entry) => entry !== 'package/node_modules/@rikune/shared/dist/index.js'
    )

    expect(() => assertBundledDependencyEntries(withoutSharedRuntime)).toThrow(
      'Release tarball is missing bundled file: package/node_modules/@rikune/shared/dist/index.js'
    )
  })

  test('rejects a tarball entry list missing the public SDK bridge', () => {
    const withoutBridge = requiredEntries.filter((entry) => entry !== 'package/plugin-sdk.js')

    expect(() => assertBundledDependencyEntries(withoutBridge)).toThrow(
      'Release tarball is missing public SDK bridge: package/plugin-sdk.js'
    )
  })

  test('rejects a tarball manifest missing an expected CLI entry', () => {
    const withoutCli = requiredEntries.filter((entry) => entry !== 'package/bin/rikune-agent.js')

    expect(() => assertBundledDependencyEntries(withoutCli)).toThrow(
      'Release tarball manifest is missing CLI entry: package/bin/rikune-agent.js'
    )
  })

  test('rejects a tarball manifest missing a dependency lock', () => {
    const withoutWindowsLock = requiredEntries.filter(
      (entry) => entry !== 'package/requirements.windows.lock.txt'
    )

    expect(() => assertBundledDependencyEntries(withoutWindowsLock)).toThrow(
      'Release tarball manifest is missing dependency lock: package/requirements.windows.lock.txt'
    )
  })

  test('rejects generated Python bytecode from the release tarball', () => {
    expect(() =>
      assertBundledDependencyEntries([
        ...requiredEntries,
        'package/dist/resources/scripts/ghidra/__pycache__/ExtractCFG.cpython-313.pyc',
      ])
    ).toThrow(
      'Release tarball must not contain generated Python bytecode: package/dist/resources/scripts/ghidra/__pycache__/ExtractCFG.cpython-313.pyc'
    )
  })

  test('requires the public SDK bridge to be present in package exports', () => {
    expect(() =>
      assertPublicSdkExport({
        exports: {
          './plugin-sdk.js': {
            types: './plugin-sdk.d.ts',
            import: './plugin-sdk.js',
            default: './plugin-sdk.js',
          },
        },
      })
    ).not.toThrow()
    expect(() => assertPublicSdkExport({ exports: { '.': './dist/index.js' } })).toThrow(
      'Release package does not export rikune/plugin-sdk.js with types'
    )
  })

  test('uses the npm JavaScript entry point instead of npm.cmd on Windows', () => {
    const invocation = resolveNpmInvocation({
      platform: 'win32',
      nodeExecutable: process.execPath,
      npmExecPath: process.execPath,
    })

    expect(invocation).toEqual({ command: process.execPath, prefixArgs: [process.execPath] })
    expect(invocation.command).not.toMatch(/npm\.cmd$/iu)
  })

  test('prefers python3 on POSIX and supports the Windows py launcher fallback', () => {
    const posix = resolvePythonInvocation({
      platform: 'linux',
      pythonPath: '',
      probe: (command: string) => ({ status: command === 'python3' ? 0 : 1 }),
    })
    expect(posix).toEqual({ command: 'python3', prefixArgs: [] })

    const windows = resolvePythonInvocation({
      platform: 'win32',
      pythonPath: '',
      probe: (command: string) => ({ status: command === 'py' ? 0 : 1 }),
    })
    expect(windows).toEqual({ command: 'py', prefixArgs: ['-3'] })
  })
})
