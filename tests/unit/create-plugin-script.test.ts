import { describe, expect, test } from '@jest/globals'
import { execFile } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

describe('scripts/create-plugin.js', () => {
  test('scaffolds a compiled-JS plugin project shape', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-create-plugin-'))
    try {
      await execFileAsync(
        process.execPath,
        ['scripts/create-plugin.js', 'demo-plugin', '--name', 'Demo Plugin'],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            RIKUNE_PLUGIN_OUTPUT_DIR: tmpDir,
          },
        }
      )

      const pluginDir = path.join(tmpDir, 'demo-plugin')
      const indexTs = fs.readFileSync(path.join(pluginDir, 'src', 'index.ts'), 'utf8')
      const packageJson = JSON.parse(
        fs.readFileSync(path.join(pluginDir, 'package.json'), 'utf8')
      ) as Record<string, unknown>
      const manifestExample = JSON.parse(
        fs.readFileSync(path.join(pluginDir, 'plugin.json.example'), 'utf8')
      ) as Record<string, unknown>

      expect(packageJson.name).toBe('rikune-plugin-demo-plugin')
      expect(indexTs).toContain("from '@rikune/plugin-sdk'")
      expect(indexTs).toContain('definePlugin')
      expect(indexTs).toContain('defineTool')
      expect(manifestExample.id).toBe('demo-plugin')
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
