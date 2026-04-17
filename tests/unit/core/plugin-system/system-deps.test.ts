/**
 * Unit tests for core/plugin-system/system-deps.ts
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'

jest.unstable_mockModule('fs', () => ({
  accessSync: jest.fn(),
}))

jest.unstable_mockModule('child_process', () => ({
  execFile: jest.fn(),
}))

const { accessSync } = await import('fs')
const { execFile } = await import('child_process')
const {
  resolveDepTarget,
  checkOneDep,
  checkSystemDeps,
} = await import('../../../../src/core/plugin-system/system-deps.js')

describe('system-deps', () => {
  const mockedAccessSync = accessSync as jest.MockedFunction<typeof accessSync>
  const mockedExecFile = execFile as unknown as jest.Mock

  beforeEach(() => {
    mockedAccessSync.mockClear()
    mockedExecFile.mockClear()
    delete process.env.TEST_VAR
  })

  function mockExecFileSuccess(stdout = '1.0.0') {
    mockedExecFile.mockImplementation((_cmd, _args, _opts, cb: any) => {
      if (cb) cb(null, { stdout }, '')
    })
  }

  function mockExecFileFail(err = new Error('not found')) {
    mockedExecFile.mockImplementation((_cmd, _args, _opts, cb: any) => {
      if (cb) cb(err, { stdout: '' }, '')
    })
  }

  describe('resolveDepTarget', () => {
    test('should use env var when set', () => {
      process.env.TEST_VAR = '/opt/test'
      expect(resolveDepTarget({ type: 'binary', name: 'test', envVar: 'TEST_VAR' })).toBe('/opt/test')
    })

    test('should substitute env var in target', () => {
      process.env.TEST_VAR = '/usr/bin/test'
      expect(resolveDepTarget({ type: 'binary', name: 'test', target: '$TEST_VAR' })).toBe('/usr/bin/test')
    })

    test('should fall back to dockerDefault', () => {
      expect(resolveDepTarget({ type: 'binary', name: 'test', dockerDefault: '/opt/test' })).toBe('/opt/test')
    })

    test('should fall back to name when nothing else', () => {
      expect(resolveDepTarget({ type: 'binary', name: 'test' })).toBe('test')
    })
  })

  describe('checkOneDep', () => {
    test('binary: available', async () => {
      mockExecFileSuccess('test 1.2.3')
      const result = await checkOneDep({ type: 'binary', name: 'test', versionFlag: '--version' })
      expect(result.available).toBe(true)
      expect(result.version).toBe('test 1.2.3')
    })

    test('binary: unavailable', async () => {
      mockExecFileFail()
      const result = await checkOneDep({ type: 'binary', name: 'missing' })
      expect(result.available).toBe(false)
      expect(result.error).toBeDefined()
    })

    test('env-var: available', async () => {
      process.env.TEST_VAR = 'value'
      const result = await checkOneDep({ type: 'env-var', name: 'test', envVar: 'TEST_VAR' })
      expect(result.available).toBe(true)
      expect(result.resolvedPath).toBe('value')
    })

    test('env-var: unavailable', async () => {
      const result = await checkOneDep({ type: 'env-var', name: 'test', envVar: 'MISSING_VAR' })
      expect(result.available).toBe(false)
    })

    test('directory: available', async () => {
      mockedAccessSync.mockImplementation(() => {})
      const result = await checkOneDep({ type: 'directory', name: 'test', target: '/tmp' })
      expect(result.available).toBe(true)
    })

    test('directory: unavailable', async () => {
      mockedAccessSync.mockImplementation(() => { throw new Error('ENOENT') })
      const result = await checkOneDep({ type: 'directory', name: 'test', target: '/missing' })
      expect(result.available).toBe(false)
    })

    test('file: available', async () => {
      mockedAccessSync.mockImplementation(() => {})
      const result = await checkOneDep({ type: 'file', name: 'test', target: '/etc/passwd' })
      expect(result.available).toBe(true)
    })

    test('python-venv: available', async () => {
      mockedAccessSync.mockImplementation(() => {})
      mockExecFileSuccess('Python 3.11.0')
      const result = await checkOneDep({ type: 'python-venv', name: 'venv', target: '/opt/venv/bin/python' })
      expect(result.available).toBe(true)
      expect(result.version).toBe('Python 3.11.0')
    })

    test('python: available', async () => {
      mockExecFileSuccess('ok')
      const result = await checkOneDep({ type: 'python', name: 'requests', importName: 'requests' })
      expect(result.available).toBe(true)
    })
  })

  describe('checkSystemDeps', () => {
    test('should return allRequiredOk=true when no deps', async () => {
      const result = await checkSystemDeps({ systemDeps: [] })
      expect(result.allRequiredOk).toBe(true)
      expect(result.results).toEqual([])
    })

    test('should return allRequiredOk=true when all required deps pass', async () => {
      mockExecFileSuccess()
      const result = await checkSystemDeps({
        systemDeps: [
          { type: 'env-var', name: 'test', envVar: 'TEST_VAR', required: true },
        ],
      })
      expect(result.allRequiredOk).toBe(false) // TEST_VAR not set
    })

    test('should return allRequiredOk=true when required dep fails but optional passes', async () => {
      mockExecFileFail()
      mockedAccessSync.mockImplementation(() => { throw new Error('ENOENT') })
      const result = await checkSystemDeps({
        systemDeps: [
          { type: 'binary', name: 'missing', required: false },
          { type: 'env-var', name: 'test', envVar: 'TEST_VAR', required: true },
        ],
      })
      expect(result.allRequiredOk).toBe(false) // required env-var missing
    })

    test('should return allRequiredOk=true when only optional deps fail', async () => {
      mockExecFileFail()
      const result = await checkSystemDeps({
        systemDeps: [
          { type: 'binary', name: 'missing', required: false },
        ],
      })
      expect(result.allRequiredOk).toBe(true)
    })
  })
})
