import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { runAbortableProcess } from '../../src/worker/abortable-process.js'

async function waitForFile(filePath: string, timeoutMs = 5_000): Promise<string> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      return (await fs.readFile(filePath, 'utf8')).trim()
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 20))
    }
  }
  throw new Error(`Timed out waiting for ${filePath}`)
}

async function waitForProcessExit(pid: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') return
      throw error
    }
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  throw new Error(`Process ${pid} was still alive after supervised cancellation`)
}

describe('runAbortableProcess', () => {
  test('rejects before spawning when the queued task was already cancelled', async () => {
    const controller = new AbortController()
    controller.abort(new Error('cancel before start'))

    await expect(
      runAbortableProcess({
        command: '/definitely/not/a/real/executable',
        args: [],
        cwd: process.cwd(),
        timeoutMs: 5_000,
        abortSignal: controller.signal,
      })
    ).rejects.toMatchObject({ name: 'AbortError' })
  })

  ;(process.platform === 'win32' ? test.skip : test)(
    'does not settle cancellation until a launcher and its TERM-ignoring descendant exit',
    async () => {
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'rikune-abort-tree-'))
      const descendantPidPath = path.join(tempDir, 'descendant.pid')
      let descendantPid: number | undefined

      try {
        const descendantScript = [
          "process.on('SIGTERM', () => {})",
          'setInterval(() => {}, 1000)',
        ].join(';')
        const launcherScript = [
          "const { spawn } = require('node:child_process')",
          "const { writeFileSync } = require('node:fs')",
          `const child = spawn(process.execPath, ['-e', ${JSON.stringify(descendantScript)}], { stdio: 'ignore' })`,
          `writeFileSync(${JSON.stringify(descendantPidPath)}, String(child.pid))`,
          "process.on('SIGTERM', () => {})",
          'setInterval(() => {}, 1000)',
        ].join(';')
        const controller = new AbortController()
        const execution = runAbortableProcess({
          command: process.execPath,
          args: ['-e', launcherScript],
          cwd: tempDir,
          timeoutMs: 30_000,
          abortSignal: controller.signal,
        })

        descendantPid = Number(await waitForFile(descendantPidPath))
        expect(Number.isInteger(descendantPid)).toBe(true)
        process.kill(descendantPid, 0)

        controller.abort(new Error('cancel stubborn tree'))
        await expect(execution).rejects.toMatchObject({ name: 'AbortError' })
        await waitForProcessExit(descendantPid)
      } finally {
        if (descendantPid) {
          try {
            process.kill(descendantPid, 'SIGKILL')
          } catch {
            // It is expected to have exited with the supervised process group.
          }
        }
        await fs.rm(tempDir, { recursive: true, force: true })
      }
    },
    15_000
  )
})
