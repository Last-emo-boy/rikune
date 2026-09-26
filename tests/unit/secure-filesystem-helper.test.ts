import { expect, test } from '@jest/globals'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

test('secure filesystem native and ENOSYS syscall contracts', () => {
  const result = spawnSync('python3', ['-m', 'unittest', 'discover', '-s', 'tests/python', '-v'], {
    cwd: repoRoot,
    encoding: 'utf8',
  })

  if (result.error) throw result.error
  expect({ status: result.status, stderr: result.status === 0 ? '' : result.stderr }).toEqual({
    status: 0,
    stderr: '',
  })
})
