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
      expect(manifestExample).toEqual(
        expect.objectContaining({
          aspects: expect.objectContaining({
            execution: expect.arrayContaining(['static']),
          }),
          surfaceRules: expect.objectContaining({ category: 'static-analysis' }),
        })
      )
      expect((manifestExample.tools as any[])[0]).toEqual(
        expect.objectContaining({
          outputSchema: expect.any(Object),
          artifacts: expect.arrayContaining([expect.objectContaining({ type: 'demo-plugin.json' })]),
          evidence: expect.arrayContaining([expect.objectContaining({ category: 'structure' })]),
        })
      )
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test('scaffolds dynamic template with runtime policy and passive defaults', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-create-plugin-'))
    try {
      await execFileAsync(
        process.execPath,
        ['scripts/create-plugin.js', 'dynamic-demo', '--template', 'dynamic'],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            RIKUNE_PLUGIN_OUTPUT_DIR: tmpDir,
          },
        }
      )

      const pluginDir = path.join(tmpDir, 'dynamic-demo')
      const indexTs = fs.readFileSync(path.join(pluginDir, 'src', 'index.ts'), 'utf8')
      const manifestExample = JSON.parse(
        fs.readFileSync(path.join(pluginDir, 'plugin.json.example'), 'utf8')
      ) as Record<string, any>

      expect(indexTs).toContain('DynamicRuntimePolicy')
      expect(indexTs).toContain('ToolRuntimeContract')
      expect(indexTs).toContain('policy: runtimePolicy')
      expect(indexTs).toContain('live_execution: false')
      expect(manifestExample.executionDomain).toBe('dynamic')
      expect(manifestExample.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          requiresUserOptIn: true,
          requiresIsolation: true,
          allowedBackends: expect.arrayContaining([
            'windows-sandbox',
            'hyperv',
            'wine',
            'qiling',
            'gdb',
            'lldb',
            'dtrace',
            'adb',
            'android-emulator',
            'frida',
            'idevice-tools',
            'wasmtime',
          ]),
          networkPolicy: 'disabled',
        })
      )
      expect(manifestExample.aspects).toEqual(
        expect.objectContaining({
          formats: expect.arrayContaining(['pe', 'elf', 'macho', 'ipa', 'apk', 'dex', 'wasm']),
          platforms: expect.arrayContaining(['windows', 'linux', 'macos', 'ios', 'android', 'wasm']),
          runtimes: expect.arrayContaining(['windows-sandbox', 'qiling', 'lldb', 'adb', 'wasmtime']),
        })
      )
      expect(manifestExample.tools[0].runtime).toEqual(
        expect.objectContaining({
          modes: expect.arrayContaining(['plan_only', 'emulation', 'manual_runtime']),
          isolation: expect.objectContaining({
            backends: expect.arrayContaining(['windows-sandbox', 'qiling', 'lldb', 'adb', 'wasmtime']),
          }),
          policy: expect.objectContaining({
            passiveByDefault: true,
            allowedBackends: expect.arrayContaining([
              'windows-sandbox',
              'qiling',
              'frida-server',
              'idevice-tools',
              'wasmtime',
            ]),
          }),
          fallback: expect.arrayContaining([expect.objectContaining({ mode: 'plan_only' })]),
        })
      )
      expect(manifestExample.tools[0].evidence).toEqual(
        expect.arrayContaining([expect.objectContaining({ category: 'timeline' })])
      )
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test('scaffolds format-adapter and manifest-only templates', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-create-plugin-'))
    try {
      await execFileAsync(
        process.execPath,
        ['scripts/create-plugin.js', 'format-demo', '--template', 'format-adapter'],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            RIKUNE_PLUGIN_OUTPUT_DIR: tmpDir,
          },
        }
      )
      await execFileAsync(
        process.execPath,
        ['scripts/create-plugin.js', 'manifest-demo', '--template', 'manifest-only'],
        {
          cwd: process.cwd(),
          env: {
            ...process.env,
            RIKUNE_PLUGIN_OUTPUT_DIR: tmpDir,
          },
        }
      )

      const formatManifest = JSON.parse(
        fs.readFileSync(path.join(tmpDir, 'format-demo', 'plugin.json.example'), 'utf8')
      ) as Record<string, any>
      const manifestIndex = fs.readFileSync(
        path.join(tmpDir, 'manifest-demo', 'src', 'index.ts'),
        'utf8'
      )

      expect(formatManifest.surfaceRules).toEqual(
        expect.objectContaining({
          tier: 1,
          activateOn: { fileTypes: ['archive'] },
        })
      )
      expect(formatManifest.tools[0].aspects.capabilities).toEqual(
        expect.arrayContaining(['structure', 'routing'])
      )
      expect(manifestIndex).toContain('defineManifestPlugin')
      expect(manifestIndex).toContain('const manifest: PluginManifest')
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
