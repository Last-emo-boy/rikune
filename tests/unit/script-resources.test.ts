import { describe, expect, test } from '@jest/globals'
import { readFileSync } from 'fs'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import { registerScriptResources } from '../../src/core/tool-registry/script-resources.js'
import type { ResourceRegistrar } from '../../src/core/registrar.js'

describe('script MCP resources', () => {
  test('registers only readable script resources and every registered handler can be read', async () => {
    const resources: Array<{
      meta: { uri: string; name: string; description?: string; mimeType?: string }
      handler: () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>
    }> = []
    const registrar: ResourceRegistrar = {
      registerResource(meta, handler) {
        resources.push({ meta, handler })
      },
    }

    registerScriptResources(registrar)

    expect(resources.length).toBeGreaterThanOrEqual(16)
    expect(resources.map((entry) => entry.meta.uri)).toEqual(
      expect.arrayContaining([
        'script://frida/api_trace',
        'script://frida/file_registry_monitor',
        'script://frida/android_crypto_trace',
        'script://ghidra/AnalyzeCrossReferences',
        'script://ghidra/ExtractFunctions_py',
      ])
    )

    for (const resource of resources) {
      const result = await resource.handler()
      expect(result.uri).toBe(resource.meta.uri)
      expect(result.text || result.blob || '').not.toHaveLength(0)
    }
  })

  test('public docs do not advertise stale file-extension resource URIs', () => {
    const docs = ['README.md', 'README_zh.md', 'docs/ARCHITECTURE.md', 'docs/api-reference.html']
    const staleResourceUriPattern = /script:\/\/(?:frida|ghidra)\/[A-Za-z0-9_]+\.(?:js|java|py)/g

    for (const doc of docs) {
      const content = readFileSync(path.resolve(process.cwd(), doc), 'utf8')
      expect(content.match(staleResourceUriPattern) ?? []).toEqual([])
    }
  })

  test('resolves packaged dist script assets without requiring src/plugins to exist', async () => {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-script-resources-'))
    const distRoot = path.join(tempRoot, 'dist')
    await fs.mkdir(path.join(distRoot, 'resources', 'scripts', 'frida'), { recursive: true })
    await fs.writeFile(
      path.join(distRoot, 'resources', 'scripts', 'frida', 'api_trace.js'),
      '// packaged api trace\n',
      'utf8'
    )

    const resources: Array<{
      meta: { uri: string; name: string; description?: string; mimeType?: string }
      handler: () => Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }>
    }> = []
    const registrar: ResourceRegistrar = {
      registerResource(meta, handler) {
        resources.push({ meta, handler })
      },
    }

    registerScriptResources(registrar, {
      entrypointDir: distRoot,
      cwd: tempRoot,
      resourceRoot: distRoot,
    })

    const apiTrace = resources.find((entry) => entry.meta.uri === 'script://frida/api_trace')
    expect(apiTrace).toBeDefined()
    await expect(apiTrace?.handler()).resolves.toEqual(
      expect.objectContaining({
        uri: 'script://frida/api_trace',
        text: '// packaged api trace\n',
      })
    )
  })
})
