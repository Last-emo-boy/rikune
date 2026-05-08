/**
 * Unit tests for the managed fake C2 Python worker protocol boundary.
 */

import { describe, expect, test } from '@jest/globals'
import { spawnSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { getPythonCommand } from '../../packages/shared/src/index.js'

const workerPath = path.resolve(
  'src',
  'plugins',
  'managed-fake-c2',
  'workers',
  'managed_fake_c2_worker.py'
)

function runWorker(payload: unknown) {
  const result = spawnSync(getPythonCommand(process.platform), [workerPath], {
    input: `${JSON.stringify(payload)}\n`,
    encoding: 'utf-8',
  })
  expect(result.status).toBe(0)
  const lines = result.stdout.trim().split(/\r?\n/)
  return JSON.parse(lines[lines.length - 1] || '{}')
}

describe('managed fake C2 worker protocol', () => {
  test('accepts runtime-node envelope and writes a runtime artifact', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-fake-c2-'))
    const samplePath = path.join(tmpDir, 'sample.exe')
    fs.writeFileSync(samplePath, Buffer.from('MZ'))

    try {
      const result = runWorker({
        job_id: 'task-1',
        tool: 'managed.fake_c2',
        sample: { sample_id: 'sha256:abc123', path: samplePath, working_dir: tmpDir },
        args: {
          endpoints: [{ path: '/ping', response_body: '{"ok":true}' }],
          listen_port: 0,
          use_tls: false,
          timeout_seconds: 0,
        },
      })

      expect(result.ok).toBe(true)
      expect(result.data?.listen_address).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/)
      expect(result.data?.endpoints_configured).toBe(1)
      expect(result.artifacts).toEqual([
        expect.objectContaining({
          name: 'managed_fake_c2.json',
          mime: 'application/json',
        }),
      ])
      expect(fs.existsSync(result.artifacts?.[0]?.path)).toBe(true)
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  test('keeps legacy direct request compatibility', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-fake-c2-'))
    const samplePath = path.join(tmpDir, 'sample.exe')
    fs.writeFileSync(samplePath, Buffer.from('MZ'))

    try {
      const result = runWorker({
        action: 'start_fake_c2',
        file_path: samplePath,
        endpoints: [{ path: '/gate', response_body: 'ok' }],
        listen_port: 0,
        use_tls: false,
        timeout_seconds: 0,
      })

      expect(result.ok).toBe(true)
      expect(result.data?.listen_address).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/)
      expect(result.data?.endpoints_configured).toBe(1)
      expect(result.artifacts).toBeUndefined()
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
