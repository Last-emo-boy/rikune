/**
 * Windows Sandbox launcher for the Analyzer node.
 *
 * Generates a .wsb configuration, copies the runtime bundle, launches the
 * sandbox, and waits for the runtime node to signal readiness.
 */

import fs from 'fs/promises'
import path from 'path'
import { spawn } from 'child_process'
import { randomUUID } from 'crypto'
import { logger } from '../logger.js'
import { config } from '../config.js'
import { buildWsbXml } from '@rikune/shared'

export interface RuntimeConnection {
  endpoint: string
  sandboxDir: string
  process: ReturnType<typeof spawn>
}

export interface SandboxLauncher {
  launch(): Promise<RuntimeConnection | null>
  teardown(): Promise<void>
  startHealthCheck(options: HealthCheckOptions): void
  stopHealthCheck(): void
}

export interface HealthCheckOptions {
  intervalMs?: number
  unhealthyThreshold?: number
  onUnhealthy?: () => void | Promise<void>
}

export function createSandboxLauncher(): SandboxLauncher {
  let currentConnection: RuntimeConnection | null = null
  let healthCheckTimer: ReturnType<typeof setInterval> | null = null

  return {
    async launch(): Promise<RuntimeConnection | null> {
      const workspaceRoot = config.runtime.sandboxWorkspace
      const sandboxDir = path.join(workspaceRoot, 'sandbox', randomUUID())

      await fs.mkdir(path.join(sandboxDir, 'shared'), { recursive: true })
      await fs.mkdir(path.join(sandboxDir, 'inbox'), { recursive: true })
      await fs.mkdir(path.join(sandboxDir, 'outbox'), { recursive: true })

      const runtimeEntryHost = path.resolve(process.cwd(), 'packages', 'runtime-node', 'dist', 'index.js')
      const wsbPath = path.join(sandboxDir, 'runtime.wsb')
      await writeWsbConfig(wsbPath, sandboxDir, runtimeEntryHost)

      // Best-effort Python check: Windows Sandbox will inherit PATH from the host,
      // but if python is not installed on the host, dynamic tools will fail.
      try {
        const { execFileSync } = await import('child_process')
        const pyVer = execFileSync('python', ['--version'], { encoding: 'utf-8', timeout: 3000 }).trim()
        logger.debug({ pythonVersion: pyVer }, 'Host Python detected for sandbox runtime')
      } catch {
        logger.warn('Python was not detected on the host. Dynamic tools (Frida, Speakeasy, Qiling) inside Windows Sandbox will likely fail. Install Python and ensure it is in PATH.')
      }

      logger.info({ sandboxDir, wsbPath }, 'Launching Windows Sandbox runtime')

      const sandboxProcess = spawn('C:\\Windows\\System32\\WindowsSandbox.exe', [wsbPath], {
        detached: true,
        windowsHide: true,
        stdio: 'ignore',
      })

      const endpoint = await waitForRuntimeReady(sandboxDir, config.runtime.healthCheckTimeoutMs)
      if (!endpoint) {
        logger.warn({ sandboxDir }, 'Runtime node did not become ready within timeout')
        try {
          sandboxProcess.kill()
          await fs.rm(sandboxDir, { recursive: true, force: true })
        } catch {}
        return null
      }

      currentConnection = { endpoint, sandboxDir, process: sandboxProcess }
      logger.info({ endpoint }, 'Runtime node ready')
      return currentConnection
    },

    async teardown(): Promise<void> {
      if (!currentConnection) return
      try {
        currentConnection.process.kill()
      } catch {}
      try {
        await fs.rm(currentConnection.sandboxDir, { recursive: true, force: true })
      } catch {}
      currentConnection = null
    },

    startHealthCheck(options: HealthCheckOptions): void {
      if (healthCheckTimer) return
      const intervalMs = options.intervalMs ?? 30_000
      const unhealthyThreshold = options.unhealthyThreshold ?? 3
      let consecutiveFailures = 0

      healthCheckTimer = setInterval(async () => {
        if (!currentConnection) return
        try {
          const res = await fetch(`${currentConnection.endpoint}/health`, { signal: AbortSignal.timeout(10_000) })
          if (!res.ok) throw new Error(`HTTP ${res.status}`)
          const data = await res.json() as { ok?: boolean }
          if (!data.ok) throw new Error('Health check returned not ok')
          consecutiveFailures = 0
        } catch (err) {
          consecutiveFailures++
          logger.warn({ err, consecutiveFailures, endpoint: currentConnection?.endpoint }, 'Runtime health check failed')
          if (consecutiveFailures >= unhealthyThreshold) {
            logger.error('Runtime deemed unhealthy; triggering recovery')
            if (options.onUnhealthy) {
              try {
                await options.onUnhealthy()
              } catch (recoveryErr) {
                logger.error({ recoveryErr }, 'Recovery handler failed')
              }
            }
            consecutiveFailures = 0
          }
        }
      }, intervalMs)
    },

    stopHealthCheck(): void {
      if (healthCheckTimer) {
        clearInterval(healthCheckTimer)
        healthCheckTimer = null
      }
    },
  }
}

async function writeWsbConfig(
  wsbPath: string,
  sandboxDir: string,
  runtimeEntryHost: string,
): Promise<void> {
  const projectRoot = process.cwd()
  const stagedRuntimeEntryHost = await stageRuntimeBundle(projectRoot, sandboxDir, runtimeEntryHost)
  const inboxDir = path.join(sandboxDir, 'inbox')
  const outboxDir = path.join(sandboxDir, 'outbox')
  const runtimeDirHost = path.dirname(stagedRuntimeEntryHost)
  const runtimeFileName = path.basename(stagedRuntimeEntryHost)
  const workersDirHost = path.resolve(projectRoot, 'workers')
  const nodeModulesDirHost = path.resolve(projectRoot, 'node_modules')

  // B1.2 / B1.3: registry and filesystem decoys
  const setupDirHost = path.join(sandboxDir, 'setup')
  await fs.mkdir(setupDirHost, { recursive: true })
  const setupScriptHost = path.join(setupDirHost, 'setup-sandbox-env.ps1')
  const setupScriptContent = `
# Registry decoys to mimic a real user environment
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v ProductName /t REG_SZ /d "Windows 10 Pro" /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v EditionID /t REG_SZ /d "Professional" /f | Out-Null

# Filesystem decoys
$folders = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
foreach ($f in $folders) {
  if (!(Test-Path $f)) { New-Item -ItemType Directory -Path $f -Force | Out-Null }
  "This is a decoy file for sandbox evasion testing." | Out-File -FilePath "$f\README.txt" -Encoding utf8
  "Invoice #2024-001" | Out-File -FilePath "$f\Invoice.pdf.txt" -Encoding utf8
}
`.trim()
  await fs.writeFile(setupScriptHost, setupScriptContent, 'utf-8')

  const readyFileSandbox = 'C:\\rikune-outbox\\runtime.ready.json'

  const wsb = buildWsbXml({
    runtimeDirHost,
    runtimeFileName,
    workersDirHost,
    inboxDir,
    outboxDir,
    readyFileSandbox,
    setupDirHost,
    nodeModulesDirHost,
  })
  await fs.writeFile(wsbPath, wsb, 'utf-8')
}

async function stageRuntimeBundle(
  projectRoot: string,
  sandboxDir: string,
  runtimeEntryHost: string
): Promise<string> {
  const runtimeStageDir = path.join(sandboxDir, 'runtime')
  const sharedSourceDir = path.join(projectRoot, 'packages', 'shared')
  const sharedStageDir = path.join(runtimeStageDir, 'node_modules', '@rikune', 'shared')

  await fs.rm(runtimeStageDir, { recursive: true, force: true })
  await fs.mkdir(runtimeStageDir, { recursive: true })
  await fs.cp(path.dirname(runtimeEntryHost), runtimeStageDir, { recursive: true })
  await fs.writeFile(
    path.join(runtimeStageDir, 'package.json'),
    `${JSON.stringify({ type: 'module' }, null, 2)}\n`,
    'utf-8'
  )
  await fs.mkdir(path.dirname(sharedStageDir), { recursive: true })
  await fs.cp(path.join(sharedSourceDir, 'dist'), path.join(sharedStageDir, 'dist'), {
    recursive: true,
  })
  await fs.copyFile(
    path.join(sharedSourceDir, 'package.json'),
    path.join(sharedStageDir, 'package.json')
  )

  return path.join(runtimeStageDir, path.basename(runtimeEntryHost))
}

async function waitForRuntimeReady(sandboxDir: string, timeoutMs: number): Promise<string | null> {
  const readyFile = path.join(sandboxDir, 'outbox', 'runtime.ready.json')
  const started = Date.now()
  const interval = 1000

  while (Date.now() - started < timeoutMs) {
    try {
      const raw = await fs.readFile(readyFile, 'utf-8')
      const data = JSON.parse(raw)
      if (data.endpoint && typeof data.endpoint === 'string') {
        return data.endpoint
      }
      return 'http://127.0.0.1:18081'
    } catch {
      await new Promise((r) => setTimeout(r, interval))
    }
  }
  return null
}
