import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from '@jest/globals'
import { getPackageRoot, resolvePackagePath } from '../../src/runtime-paths.js'

describe('runtime package paths', () => {
  test('derive the Rikune package root from the module instead of the process cwd', () => {
    const packageRoot = getPackageRoot()
    const manifest = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'))

    expect(manifest.name).toBe('rikune')
    expect(resolvePackagePath('workers', 'static_worker.py')).toBe(
      path.join(packageRoot, 'workers', 'static_worker.py')
    )
  })
})
