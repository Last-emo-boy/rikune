/**
 * Unit tests for core/plugin-system/discovery.ts
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import os from 'os'
import { discoverPluginsFromDir } from '../../../../src/core/plugin-system/discovery.js'

describe('discoverPluginsFromDir', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-discovery-test-'))
  })

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }) } catch {}
  })

  test('should return empty array for non-existent directory', async () => {
    const result = await discoverPluginsFromDir(path.join(tmpDir, 'missing'), 'test')
    expect(result).toEqual([])
  })

  test('should discover directory-based plugins with index.js', async () => {
    const pluginDir = path.join(tmpDir, 'my-plugin')
    fs.mkdirSync(pluginDir, { recursive: true })
    fs.writeFileSync(
      path.join(pluginDir, 'index.js'),
      `module.exports = { id: 'my-plugin', name: 'My Plugin', version: '1.0.0', register: () => [] };`,
      'utf-8'
    )
    const result = await discoverPluginsFromDir(tmpDir, 'test')
    expect(result.length).toBe(1)
    expect(result[0].id).toBe('my-plugin')
  })

  test('should discover flat .js plugin files', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'flat-plugin.js'),
      `module.exports = { id: 'flat-plugin', name: 'Flat', version: '1.0.0', register: () => [] };`,
      'utf-8'
    )
    const result = await discoverPluginsFromDir(tmpDir, 'test')
    expect(result.length).toBe(1)
    expect(result[0].id).toBe('flat-plugin')
  })

  test('should discover flat .mjs plugin files', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'esm-plugin.mjs'),
      `export default { id: 'esm-plugin', name: 'ESM', version: '1.0.0', register: () => [] };`,
      'utf-8'
    )
    const result = await discoverPluginsFromDir(tmpDir, 'test')
    expect(result.length).toBe(1)
    expect(result[0].id).toBe('esm-plugin')
  })

  test('should skip directories without index.js', async () => {
    fs.mkdirSync(path.join(tmpDir, 'empty-plugin'), { recursive: true })
    const result = await discoverPluginsFromDir(tmpDir, 'test')
    expect(result).toEqual([])
  })

  test('should skip invalid plugin modules', async () => {
    const pluginDir = path.join(tmpDir, 'bad-plugin')
    fs.mkdirSync(pluginDir, { recursive: true })
    fs.writeFileSync(
      path.join(pluginDir, 'index.js'),
      `module.exports = { id: 'bad-plugin', name: 'Bad' };`,
      'utf-8'
    )
    const result = await discoverPluginsFromDir(tmpDir, 'test')
    expect(result).toEqual([])
  })
})
