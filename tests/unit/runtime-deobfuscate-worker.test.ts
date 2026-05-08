/**
 * Unit tests for the runtime-deobfuscate Python worker protocol boundary.
 */

import { describe, expect, test } from '@jest/globals'
import { spawnSync } from 'child_process'
import path from 'path'
import { getPythonCommand } from '../../packages/shared/src/index.js'

const workerPath = path.resolve(
  'src',
  'plugins',
  'runtime-deobfuscate',
  'workers',
  'deobfuscate_worker.py'
)

function runWorker(payload: unknown) {
  const result = spawnSync(getPythonCommand(process.platform), [workerPath], {
    input: JSON.stringify(payload),
    encoding: 'utf-8',
  })
  expect(result.status).toBe(0)
  const lines = result.stdout.trim().split(/\r?\n/)
  return JSON.parse(lines[lines.length - 1] || '{}')
}

describe('runtime-deobfuscate worker protocol', () => {
  test('accepts runtime-node envelope and maps tool names to worker commands', () => {
    const result = runWorker({
      job_id: 'task-1',
      tool: 'deobf.dotnet',
      sample: { sample_id: 'sha256:abc123', path: 'missing.exe', working_dir: '' },
      args: { timeout: 30 },
    })

    expect(result.ok).toBe(false)
    expect(result.command).toBe('dotnet_deobfuscate')
    expect(result.data?.recommended_next_tools).toEqual([
      'anti.tamper',
      'string.decrypt',
      'deobf.strings',
    ])
    expect(result.errors?.join(' ')).toMatch(/de4dot not found|execution failed/i)
  })

  test('keeps legacy direct command payload compatibility', () => {
    const result = runWorker({
      command: 'dotnet_deobfuscate',
      sample_path: 'missing.exe',
      timeout: 30,
    })

    expect(result.ok).toBe(false)
    expect(result.command).toBe('dotnet_deobfuscate')
    expect(result.data?.recommended_next_tools).toEqual([
      'anti.tamper',
      'string.decrypt',
      'deobf.strings',
    ])
    expect(result.errors?.join(' ')).toMatch(/de4dot not found|execution failed/i)
  })
})
