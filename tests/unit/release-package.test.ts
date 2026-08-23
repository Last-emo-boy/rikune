import { describe, expect, test } from '@jest/globals'
import {
  assertBundledDependencyEntries,
  assertPublicSdkExport,
  resolveNpmInvocation,
} from '../../scripts/verify-release-package.mjs'

const requiredEntries = [
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
})
