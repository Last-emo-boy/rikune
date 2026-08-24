import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { migrateLegacyGhidraSampleDirectories } from '../../src/ghidra/ghidra-config.js'

const SHA = 'abcd' + '1'.repeat(60)

describe('Ghidra canonical sample-scoped storage', () => {
  let root: string

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-ghidra-scope-'))
  })

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true })
  })

  test('enumerates and atomically migrates legacy bucketed projects to direct SHA paths', () => {
    const legacy = path.join(root, 'ab', 'cd', SHA)
    fs.mkdirSync(legacy, { recursive: true })
    fs.writeFileSync(path.join(legacy, 'project.gpr'), 'state')

    expect(migrateLegacyGhidraSampleDirectories(root)).toBe(1)
    expect(fs.readFileSync(path.join(root, SHA, 'project.gpr'), 'utf8')).toBe('state')
    expect(fs.existsSync(legacy)).toBe(false)
    expect(migrateLegacyGhidraSampleDirectories(root)).toBe(0)
  })

  test('fails closed when direct and legacy state both exist', () => {
    fs.mkdirSync(path.join(root, SHA), { recursive: true })
    fs.mkdirSync(path.join(root, 'ab', 'cd', SHA), { recursive: true })
    expect(() => migrateLegacyGhidraSampleDirectories(root)).toThrow(/both direct and legacy/i)
  })

  test('rejects a symlink masquerading as a legacy sample directory', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-ghidra-outside-'))
    try {
      fs.mkdirSync(path.join(root, 'ab', 'cd'), { recursive: true })
      fs.symlinkSync(outside, path.join(root, 'ab', 'cd', SHA))
      expect(() => migrateLegacyGhidraSampleDirectories(root)).toThrow(/trusted-root/i)
      expect(fs.existsSync(outside)).toBe(true)
    } finally {
      fs.rmSync(outside, { recursive: true, force: true })
    }
  })
})
