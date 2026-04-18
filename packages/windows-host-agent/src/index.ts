/**
 * Rikune Windows Host Agent
 *
 * Runs on the Windows host and exposes an HTTP API for the remote Analyzer
 * to start / stop Windows Sandbox runtimes.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'http'
import fs from 'fs/promises'
import { existsSync, realpathSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { spawn, execFile } from 'child_process'
import { randomUUID } from 'crypto'
import os from 'os'
import net from 'net'
import { logger } from './logger.js'
import { buildWsbXml } from '@rikune/shared'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const PORT = parseInt(process.env.HOST_AGENT_PORT || '18082', 10)
const API_KEY = process.env.HOST_AGENT_API_KEY || ''
const RUNTIME_INTERNAL_PORT = 18081
const LISTEN_PORT_MIN = 18081
const LISTEN_PORT_MAX = 19000
const HOST_AGENT_BACKEND = normalizeBackend(process.env.HOST_AGENT_BACKEND || process.env.HOST_AGENT_RUNTIME_BACKEND)

type HostAgentBackend = 'windows-sandbox' | 'hyperv-vm'

interface ActiveSandbox {
  backend: HostAgentBackend
  sandboxId: string
  sandboxDir?: string
  wsbPath?: string
  process?: ReturnType<typeof spawn>
  endpoint: string
  runtimeHost: string
  listenPort: number
  hypervVmName?: string
  hypervSnapshotName?: string
  hypervRestoreOnRelease?: boolean
  hypervStopOnRelease?: boolean
}

interface StartSandboxRequest {
  timeoutMs?: number
  runtimeApiKey?: string
  hypervSnapshotName?: string
  hypervRestoreOnStart?: boolean
  hypervRestoreOnRelease?: boolean
  hypervStopOnRelease?: boolean
}

interface HyperVActionRequest {
  snapshotName?: string
  start?: boolean
  waitForRuntime?: boolean
  timeoutMs?: number
  runtimeApiKey?: string
}

interface HostAgentStartDiagnostics {
  backend: HostAgentBackend
  sandboxDir?: string
  wsbPath?: string
  timeoutMs?: number
  listenPort?: number
  mappedFolders?: Array<{
    hostFolder: string
    sandboxFolder: string
    readOnly: boolean
    exists: boolean
  }>
  logonCommandSummary?: string
  windowsSandbox?: {
    executable: string
    exists: boolean
    exit?: { code: number | null; signal: NodeJS.Signals | null } | null
  }
  readyFile?: { path: string; exists: boolean; preview?: string }
  startupLog?: { path: string; exists: boolean; preview?: string }
  stdoutLog?: { path: string; exists: boolean; preview?: string }
  stderrLog?: { path: string; exists: boolean; preview?: string }
  missingPaths?: Array<{ name: string; path: string; exists: boolean }>
  hyperv?: {
    vmName?: string
    snapshotName?: string
    endpoint?: string
    restoreOnStart?: boolean
    restoreOnRelease?: boolean
    stopOnRelease?: boolean
    stdoutPreview?: string
    stderrPreview?: string
  }
}

interface StartSandboxResult {
  ok: boolean
  endpoint?: string
  sandboxId?: string
  backend?: HostAgentBackend
  hyperv?: {
    vmName?: string
    snapshotName?: string | null
    restoreOnStart?: boolean
    restoreOnRelease?: boolean
    stopOnRelease?: boolean
  }
  error?: string
  diagnostics?: HostAgentStartDiagnostics
}

const activeSandboxes = new Map<string, ActiveSandbox>()
const usedListenPorts = new Set<number>()

function normalizeBackend(raw?: string): HostAgentBackend {
  const value = (raw || '').trim().toLowerCase()
  if (value === 'hyperv' || value === 'hyper-v' || value === 'hyperv-vm' || value === 'hyper-v-vm') {
    return 'hyperv-vm'
  }
  return 'windows-sandbox'
}

function readEnvFlag(name: string, defaultValue = false): boolean {
  const value = process.env[name]
  if (value === undefined || value.trim().length === 0) {
    return defaultValue
  }
  return /^(1|true|yes|on)$/i.test(value)
}

function quotePowerShellLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

function previewText(value: string, maxChars = 4000): string {
  const normalized = value.replace(/\r\n/g, '\n')
  return normalized.length > maxChars ? `${normalized.slice(0, maxChars)}\n...[truncated]` : normalized
}

async function readFilePreview(filePath: string, maxChars = 4000): Promise<{ path: string; exists: boolean; preview?: string }> {
  if (!existsSync(filePath)) {
    return { path: filePath, exists: false }
  }
  try {
    const content = await fs.readFile(filePath, 'utf-8')
    return { path: filePath, exists: true, preview: previewText(content, maxChars) }
  } catch (err) {
    return {
      path: filePath,
      exists: true,
      preview: `Failed to read preview: ${err instanceof Error ? err.message : String(err)}`,
    }
  }
}

async function isPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = net.createServer()
    srv.once('error', () => resolve(false))
    srv.once('listening', () => {
      srv.close(() => resolve(true))
    })
    srv.listen(port)
  })
}

async function allocateListenPort(): Promise<number | null> {
  for (let p = LISTEN_PORT_MIN; p <= LISTEN_PORT_MAX; p++) {
    if (usedListenPorts.has(p)) continue
    if (await isPortAvailable(p)) {
      usedListenPorts.add(p)
      return p
    }
  }
  return null
}

function releaseListenPort(port: number): void {
  usedListenPorts.delete(port)
}

function findProjectRoot(startDir: string): string | null {
  let current = startDir
  for (let i = 0; i < 10; i++) {
    if (existsSync(path.join(current, 'workers')) && existsSync(path.join(current, 'packages'))) {
      return current
    }
    const parent = path.dirname(current)
    if (parent === current) break
    current = parent
  }
  return null
}

const projectRoot = findProjectRoot(__dirname) || process.cwd()

function getPrimaryIp(): string | null {
  const interfaces = os.networkInterfaces()
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address
      }
    }
  }
  return null
}

function existingExecutablePath(rawPath?: string): string | null {
  if (!rawPath || rawPath.trim().length === 0) {
    return null
  }
  const candidate = rawPath.trim().replace(/^"|"$/g, '')
  if (!existsSync(candidate)) {
    return null
  }
  try {
    return realpathSync(candidate)
  } catch {
    return candidate
  }
}

function findExecutableOnPath(command: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile('where.exe', [command], { windowsHide: true }, (err, stdout) => {
      if (err) {
        resolve(null)
        return
      }
      const found = stdout
        .toString()
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .filter((line) => !line.toLowerCase().includes('\\windowsapps\\'))
        .find((line) => existsSync(line))
      resolve(existingExecutablePath(found) || null)
    })
  })
}

async function resolveHostPythonPath(): Promise<string | null> {
  return (
    existingExecutablePath(process.env.HOST_AGENT_PYTHON_PATH) ||
    existingExecutablePath(process.env.RUNTIME_PYTHON_PATH) ||
    await findExecutableOnPath('python') ||
    await findExecutableOnPath('py')
  )
}

function runPowerShell(
  script: string,
  timeoutMs = 120_000
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { windowsHide: true, timeout: timeoutMs },
      (err, stdout, stderr) => {
        const result = {
          stdout: stdout?.toString() || '',
          stderr: stderr?.toString() || '',
        }
        if (err) {
          reject(Object.assign(err, result))
          return
        }
        resolve(result)
      }
    )
  })
}

async function waitForRuntimeEndpoint(
  endpoint: string,
  runtimeApiKey: string | undefined,
  timeoutMs: number
): Promise<boolean> {
  const started = Date.now()
  const interval = 2000
  const healthUrl = new URL('/health', endpoint).toString()

  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(healthUrl, {
        headers: runtimeApiKey ? { Authorization: `Bearer ${runtimeApiKey}` } : {},
        signal: AbortSignal.timeout(Math.min(interval, 5000)),
      })
      if (res.ok) {
        const data = await res.json().catch(() => ({})) as { ok?: boolean }
        if (data.ok !== false) {
          return true
        }
      }
    } catch {
      // Runtime may still be booting.
    }
    await new Promise((resolve) => setTimeout(resolve, interval))
  }
  return false
}

async function stageRuntimeBundle(
  sandboxDir: string,
  runtimeEntryHost: string
): Promise<string> {
  const runtimeStageDir = path.join(sandboxDir, 'runtime')
  const runtimeSourceDir = path.dirname(runtimeEntryHost)
  const sharedSourceDir = path.join(projectRoot, 'packages', 'shared')
  const sharedStageDir = path.join(runtimeStageDir, 'node_modules', '@rikune', 'shared')

  await fs.rm(runtimeStageDir, { recursive: true, force: true })
  await fs.mkdir(runtimeStageDir, { recursive: true })
  await fs.cp(runtimeSourceDir, runtimeStageDir, { recursive: true })
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

function requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
  if (!API_KEY) return true
  const auth = req.headers.authorization || ''
  const expected = `Bearer ${API_KEY}`
  if (auth !== expected) {
    res.writeHead(401, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: 'Unauthorized' }))
    return false
  }
  return true
}

async function readJsonBody(req: IncomingMessage, maxBytes = 10 * 1024 * 1024): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let body = ''
    let received = 0
    req.on('data', (chunk: string) => {
      received += Buffer.byteLength(chunk)
      if (received > maxBytes) {
        req.destroy()
        reject(new Error('Payload too large'))
        return
      }
      body += chunk
    })
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {})
      } catch (e) {
        reject(e)
      }
    })
    req.on('error', reject)
  })
}

interface WsbConfigDiagnostics {
  mappedFolders: NonNullable<HostAgentStartDiagnostics['mappedFolders']>
  logonCommandSummary: string
  hostNodePath?: string
  hostPythonPath?: string | null
  stagedRuntimeEntryHost: string
}

async function writeWsbConfig(
  wsbPath: string,
  sandboxDir: string,
  runtimeEntryHost: string,
  runtimeApiKey?: string,
): Promise<WsbConfigDiagnostics> {
  const inboxDir = path.join(sandboxDir, 'inbox')
  const outboxDir = path.join(sandboxDir, 'outbox')
  const stagedRuntimeEntryHost = await stageRuntimeBundle(sandboxDir, runtimeEntryHost)
  const runtimeDirHost = path.dirname(stagedRuntimeEntryHost)
  const runtimeFileName = path.basename(stagedRuntimeEntryHost)
  const workersDirHost = path.join(projectRoot, 'workers')
  const nodeModulesDirHost = path.join(projectRoot, 'node_modules')
  const readyFileSandbox = 'C:\\rikune-outbox\\runtime.ready.json'
  const hostNodePath =
    existingExecutablePath(process.env.HOST_AGENT_NODE_PATH) ||
    existingExecutablePath(process.execPath) ||
    process.execPath
  const hostPythonPath = await resolveHostPythonPath()

  if (!hostPythonPath) {
    logger.warn(
      'No host Python executable found for Windows Sandbox mapping. Runtime health checks and Python-backed dynamic tools may fail. Set HOST_AGENT_PYTHON_PATH to a real python.exe.'
    )
  }

  const wsb = buildWsbXml({
    runtimeDirHost,
    runtimeFileName,
    workersDirHost,
    inboxDir,
    outboxDir,
    readyFileSandbox,
    runtimeApiKey,
    nodeDirHost: path.dirname(hostNodePath),
    nodeFileName: path.basename(hostNodePath),
    nodeModulesDirHost,
    pythonDirHost: hostPythonPath ? path.dirname(hostPythonPath) : undefined,
    pythonFileName: hostPythonPath ? path.basename(hostPythonPath) : undefined,
  })
  await fs.writeFile(wsbPath, wsb, 'utf-8')

  const mappedFolders: NonNullable<HostAgentStartDiagnostics['mappedFolders']> = [
    { hostFolder: runtimeDirHost, sandboxFolder: 'C:\\rikune-runtime', readOnly: true, exists: existsSync(runtimeDirHost) },
    { hostFolder: workersDirHost, sandboxFolder: 'C:\\rikune-workers', readOnly: true, exists: existsSync(workersDirHost) },
    { hostFolder: inboxDir, sandboxFolder: 'C:\\rikune-inbox', readOnly: false, exists: existsSync(inboxDir) },
    { hostFolder: outboxDir, sandboxFolder: 'C:\\rikune-outbox', readOnly: false, exists: existsSync(outboxDir) },
    { hostFolder: path.dirname(hostNodePath), sandboxFolder: 'C:\\rikune-node', readOnly: true, exists: existsSync(path.dirname(hostNodePath)) },
    { hostFolder: nodeModulesDirHost, sandboxFolder: 'C:\\node_modules', readOnly: true, exists: existsSync(nodeModulesDirHost) },
  ]
  if (hostPythonPath) {
    mappedFolders.push({
      hostFolder: path.dirname(hostPythonPath),
      sandboxFolder: 'C:\\rikune-python',
      readOnly: true,
      exists: existsSync(path.dirname(hostPythonPath)),
    })
  }

  return {
    mappedFolders,
    logonCommandSummary: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <redacted>',
    hostNodePath,
    hostPythonPath,
    stagedRuntimeEntryHost,
  }
}

async function collectWindowsSandboxDiagnostics(params: {
  sandboxDir: string
  wsbPath: string
  timeoutMs: number
  listenPort: number
  wsbDiagnostics?: WsbConfigDiagnostics
  sandboxExit?: { code: number | null; signal: NodeJS.Signals | null } | null
  missingPaths?: Array<{ name: string; path: string; exists: boolean }>
}): Promise<HostAgentStartDiagnostics> {
  const windowsSandboxExecutable = 'C:\\Windows\\System32\\WindowsSandbox.exe'
  return {
    backend: 'windows-sandbox',
    sandboxDir: params.sandboxDir,
    wsbPath: params.wsbPath,
    timeoutMs: params.timeoutMs,
    listenPort: params.listenPort,
    mappedFolders: params.wsbDiagnostics?.mappedFolders,
    logonCommandSummary: params.wsbDiagnostics?.logonCommandSummary,
    windowsSandbox: {
      executable: windowsSandboxExecutable,
      exists: existsSync(windowsSandboxExecutable),
      exit: params.sandboxExit ?? null,
    },
    readyFile: await readFilePreview(path.join(params.sandboxDir, 'outbox', 'runtime.ready.json')),
    startupLog: await readFilePreview(path.join(params.sandboxDir, 'outbox', 'runtime-startup.log')),
    stdoutLog: await readFilePreview(path.join(params.sandboxDir, 'outbox', 'runtime.stdout.log')),
    stderrLog: await readFilePreview(path.join(params.sandboxDir, 'outbox', 'runtime.stderr.log')),
    missingPaths: params.missingPaths,
  }
}

function buildHyperVDiagnostics(params: {
  vmName?: string
  snapshotName?: string
  endpoint?: string
  restoreOnStart?: boolean
  restoreOnRelease?: boolean
  stopOnRelease?: boolean
  stdout?: string
  stderr?: string
}): HostAgentStartDiagnostics {
  return {
    backend: 'hyperv-vm',
    hyperv: {
      vmName: params.vmName,
      snapshotName: params.snapshotName,
      endpoint: params.endpoint,
      restoreOnStart: params.restoreOnStart,
      restoreOnRelease: params.restoreOnRelease,
      stopOnRelease: params.stopOnRelease,
      stdoutPreview: params.stdout ? previewText(params.stdout, 2000) : undefined,
      stderrPreview: params.stderr ? previewText(params.stderr, 2000) : undefined,
    },
  }
}

function getHyperVConfig(overrides: Partial<StartSandboxRequest> = {}) {
  const vmName = (process.env.HOST_AGENT_HYPERV_VM_NAME || '').trim()
  const snapshotName = typeof overrides.hypervSnapshotName === 'string'
    ? overrides.hypervSnapshotName.trim()
    : (process.env.HOST_AGENT_HYPERV_SNAPSHOT_NAME || '').trim()
  const endpoint = (process.env.HOST_AGENT_HYPERV_RUNTIME_ENDPOINT || process.env.HOST_AGENT_HYPERV_ENDPOINT || '').trim()
  const restoreOnStart = !!snapshotName && (
    typeof overrides.hypervRestoreOnStart === 'boolean'
      ? overrides.hypervRestoreOnStart
      : readEnvFlag('HOST_AGENT_HYPERV_RESTORE_ON_START', true)
  )
  const restoreOnRelease = !!snapshotName && (
    typeof overrides.hypervRestoreOnRelease === 'boolean'
      ? overrides.hypervRestoreOnRelease
      : readEnvFlag('HOST_AGENT_HYPERV_RESTORE_ON_RELEASE', false)
  )
  const stopOnRelease = typeof overrides.hypervStopOnRelease === 'boolean'
    ? overrides.hypervStopOnRelease
    : readEnvFlag('HOST_AGENT_HYPERV_STOP_ON_RELEASE', false)
  return { vmName, snapshotName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease }
}

async function getHyperVRuntimeStatus(): Promise<Record<string, unknown> | null> {
  if (HOST_AGENT_BACKEND !== 'hyperv-vm') {
    return null
  }

  const { vmName, snapshotName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease } = getHyperVConfig()

  if (!vmName || process.platform !== 'win32') {
    return {
      configured: Boolean(vmName && endpoint),
      vmName: vmName || null,
      endpoint: endpoint || null,
      snapshotName: snapshotName || null,
      restoreOnStart,
      restoreOnRelease,
      stopOnRelease,
      state: null,
      error: process.platform !== 'win32'
        ? 'Hyper-V status requires Windows platform'
        : 'HOST_AGENT_HYPERV_VM_NAME is not configured',
    }
  }

  const script = [
    `$ErrorActionPreference = 'Stop'`,
    `$vmName = ${quotePowerShellLiteral(vmName)}`,
    `$vm = Get-VM -Name $vmName -ErrorAction Stop`,
    `$snapshots = @(Get-VMSnapshot -VMName $vmName -ErrorAction SilentlyContinue | Select-Object -First 20 Name, CreationTime)`,
    `[pscustomobject]@{`,
    `  configured = $true`,
    `  vmName = $vmName`,
    `  endpoint = ${quotePowerShellLiteral(endpoint)}`,
    `  snapshotName = ${quotePowerShellLiteral(snapshotName)}`,
    `  restoreOnStart = ${restoreOnStart ? '$true' : '$false'}`,
    `  restoreOnRelease = ${restoreOnRelease ? '$true' : '$false'}`,
    `  stopOnRelease = ${stopOnRelease ? '$true' : '$false'}`,
    `  state = $vm.State.ToString()`,
    `  status = $vm.Status`,
    `  uptime = $vm.Uptime.ToString()`,
    `  snapshots = $snapshots`,
    `} | ConvertTo-Json -Depth 5`,
  ].join('\n')

  try {
    const result = await runPowerShell(script, 30_000)
    return JSON.parse(result.stdout) as Record<string, unknown>
  } catch (err) {
    return {
      configured: true,
      vmName,
      endpoint: endpoint || null,
      snapshotName: snapshotName || null,
      restoreOnStart,
      restoreOnRelease,
      stopOnRelease,
      state: null,
      error: err instanceof Error ? err.message : String(err),
    }
  }
}

async function listHyperVCheckpoints(): Promise<{ ok: boolean; backend: 'hyperv-vm'; vmName?: string; checkpoints?: unknown[]; error?: string }> {
  const { vmName } = getHyperVConfig()
  if (process.platform !== 'win32') {
    return { ok: false, backend: 'hyperv-vm', vmName, error: 'Hyper-V checkpoint listing requires Windows platform' }
  }
  if (!vmName) {
    return { ok: false, backend: 'hyperv-vm', error: 'HOST_AGENT_HYPERV_VM_NAME is not configured' }
  }

  const script = [
    `$ErrorActionPreference = 'Stop'`,
    `$vmName = ${quotePowerShellLiteral(vmName)}`,
    `Get-VMSnapshot -VMName $vmName -ErrorAction Stop | Sort-Object CreationTime -Descending | Select-Object Name, CreationTime, ParentSnapshotName, SnapshotType | ConvertTo-Json -Depth 5`,
  ].join('\n')

  try {
    const result = await runPowerShell(script, 30_000)
    const parsed = result.stdout.trim() ? JSON.parse(result.stdout) : []
    const checkpoints = Array.isArray(parsed) ? parsed : parsed ? [parsed] : []
    return { ok: true, backend: 'hyperv-vm', vmName, checkpoints }
  } catch (err) {
    return { ok: false, backend: 'hyperv-vm', vmName, error: err instanceof Error ? err.message : String(err) }
  }
}

async function createHyperVCheckpoint(body: unknown): Promise<Record<string, unknown>> {
  const request = (body && typeof body === 'object' ? body : {}) as HyperVActionRequest
  const { vmName, endpoint, stopOnRelease } = getHyperVConfig()
  const rawSnapshotName = (request.snapshotName || '').trim()
  const snapshotName = rawSnapshotName || `rikune-${new Date().toISOString().replace(/[:.]/g, '-')}`
  if (process.platform !== 'win32') {
    return { ok: false, backend: 'hyperv-vm', error: 'Hyper-V checkpoint creation requires Windows platform' }
  }
  if (!vmName) {
    return { ok: false, backend: 'hyperv-vm', error: 'HOST_AGENT_HYPERV_VM_NAME is not configured' }
  }

  const script = [
    `$ErrorActionPreference = 'Stop'`,
    `$vmName = ${quotePowerShellLiteral(vmName)}`,
    `$snapshotName = ${quotePowerShellLiteral(snapshotName)}`,
    `Checkpoint-VM -Name $vmName -SnapshotName $snapshotName | Out-Null`,
    `$snap = Get-VMSnapshot -VMName $vmName -Name $snapshotName -ErrorAction Stop`,
    `[pscustomobject]@{ name = $snap.Name; creationTime = $snap.CreationTime; parentSnapshotName = $snap.ParentSnapshotName; snapshotType = $snap.SnapshotType } | ConvertTo-Json -Depth 4`,
  ].join('\n')

  try {
    const result = await runPowerShell(script, 120_000)
    const checkpoint = result.stdout.trim() ? JSON.parse(result.stdout) : { name: snapshotName }
    const status = await getHyperVRuntimeStatus()
    return {
      ok: true,
      backend: 'hyperv-vm',
      vmName,
      snapshotName,
      checkpoint,
      endpoint: endpoint || null,
      status,
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        stopOnRelease,
        stdout: result.stdout,
        stderr: result.stderr,
      }),
    }
  } catch (err) {
    const details = err as Error & { stdout?: string; stderr?: string }
    return {
      ok: false,
      backend: 'hyperv-vm',
      vmName,
      snapshotName,
      endpoint: endpoint || null,
      error: details.message,
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        stopOnRelease,
        stdout: details.stdout,
        stderr: details.stderr,
      }),
    }
  }
}

async function restoreHyperVCheckpoint(body: unknown): Promise<Record<string, unknown>> {
  const request = (body && typeof body === 'object' ? body : {}) as HyperVActionRequest
  const { vmName, snapshotName: configuredSnapshot, endpoint, stopOnRelease } = getHyperVConfig()
  const snapshotName = (request.snapshotName || configuredSnapshot || '').trim()
  const startAfterRestore = request.start !== false
  const waitForRuntime = request.waitForRuntime !== false
  const timeoutMs = typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)
    ? Math.max(1000, request.timeoutMs)
    : parseInt(process.env.HOST_AGENT_HYPERV_WAIT_TIMEOUT_MS || '120000', 10)
  const runtimeApiKey = typeof request.runtimeApiKey === 'string' && request.runtimeApiKey.trim().length > 0
    ? request.runtimeApiKey.trim()
    : process.env.HOST_AGENT_RUNTIME_API_KEY || process.env.RUNTIME_API_KEY || API_KEY || undefined

  if (process.platform !== 'win32') {
    return { ok: false, backend: 'hyperv-vm', error: 'Hyper-V checkpoint restore requires Windows platform' }
  }
  if (!vmName) {
    return { ok: false, backend: 'hyperv-vm', error: 'HOST_AGENT_HYPERV_VM_NAME is not configured' }
  }
  if (!snapshotName) {
    return { ok: false, backend: 'hyperv-vm', vmName, error: 'No snapshot name provided. Set HOST_AGENT_HYPERV_SNAPSHOT_NAME or pass snapshotName.' }
  }

  const commands = [
    `$ErrorActionPreference = 'Stop'`,
    `$vmName = ${quotePowerShellLiteral(vmName)}`,
    `$snapshotName = ${quotePowerShellLiteral(snapshotName)}`,
    `$vm = Get-VM -Name $vmName -ErrorAction Stop`,
    `if ($vm.State -ne 'Off') { Stop-VM -Name $vmName -TurnOff -Force }`,
    `Restore-VMSnapshot -VMName $vmName -Name $snapshotName -Confirm:$false`,
    ...(startAfterRestore ? [`Start-VM -Name $vmName | Out-Null`] : []),
  ]

  try {
    const result = await runPowerShell(commands.join('\n'), timeoutMs)
    const runtimeReady = startAfterRestore && waitForRuntime && endpoint
      ? await waitForRuntimeEndpoint(endpoint, runtimeApiKey, timeoutMs)
      : null
    const status = await getHyperVRuntimeStatus()
    return {
      ok: runtimeReady === false ? false : true,
      backend: 'hyperv-vm',
      vmName,
      snapshotName,
      endpoint: endpoint || null,
      started: startAfterRestore,
      runtimeReady,
      stopOnRelease,
      status,
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        restoreOnStart: true,
        stopOnRelease,
        stdout: result.stdout,
        stderr: result.stderr,
      }),
      ...(runtimeReady === false ? { error: `Hyper-V runtime endpoint did not become healthy within timeout: ${endpoint}` } : {}),
    }
  } catch (err) {
    const details = err as Error & { stdout?: string; stderr?: string }
    return {
      ok: false,
      backend: 'hyperv-vm',
      vmName,
      snapshotName,
      endpoint: endpoint || null,
      error: details.message,
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        restoreOnStart: true,
        stopOnRelease,
        stdout: details.stdout,
        stderr: details.stderr,
      }),
    }
  }
}

async function stopHyperVRuntimeVm(): Promise<Record<string, unknown>> {
  const { vmName, snapshotName, endpoint, stopOnRelease } = getHyperVConfig()
  if (process.platform !== 'win32') {
    return { ok: false, backend: 'hyperv-vm', error: 'Hyper-V VM stop requires Windows platform' }
  }
  if (!vmName) {
    return { ok: false, backend: 'hyperv-vm', error: 'HOST_AGENT_HYPERV_VM_NAME is not configured' }
  }

  try {
    const result = await runPowerShell(
      `$ErrorActionPreference = 'Stop'\nStop-VM -Name ${quotePowerShellLiteral(vmName)} -TurnOff -Force`,
      60_000
    )
    const status = await getHyperVRuntimeStatus()
    return {
      ok: true,
      backend: 'hyperv-vm',
      vmName,
      endpoint: endpoint || null,
      status,
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        stopOnRelease,
        stdout: result.stdout,
        stderr: result.stderr,
      }),
    }
  } catch (err) {
    const details = err as Error & { stdout?: string; stderr?: string }
    return {
      ok: false,
      backend: 'hyperv-vm',
      vmName,
      endpoint: endpoint || null,
      error: details.message,
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        stopOnRelease,
        stdout: details.stdout,
        stderr: details.stderr,
      }),
    }
  }
}

async function waitForRuntimeReady(
  sandboxDir: string,
  timeoutMs: number
): Promise<{ endpoint?: string; host?: string } | null> {
  const readyFile = path.join(sandboxDir, 'outbox', 'runtime.ready.json')
  const started = Date.now()
  const interval = 1000

  while (Date.now() - started < timeoutMs) {
    try {
      const raw = await fs.readFile(readyFile, 'utf-8')
      const data = JSON.parse(raw) as { endpoint?: string; host?: string }
      if (data.endpoint && typeof data.endpoint === 'string') {
        return data
      }
      return { endpoint: 'http://127.0.0.1:18081', host: '127.0.0.1' }
    } catch {
      await new Promise((r) => setTimeout(r, interval))
    }
  }
  return null
}

async function addPortProxy(sandboxIp: string, listenPort: number): Promise<void> {
  logger.warn('netsh portproxy is binding to all interfaces. Consider restricting network access.')
  return new Promise((resolve, reject) => {
    execFile(
      'netsh',
      ['interface', 'portproxy', 'delete', 'v4tov4', `listenport=${listenPort}`],
      () => {
        execFile(
          'netsh',
          [
            'interface',
            'portproxy',
            'add',
            'v4tov4',
            `listenport=${listenPort}`,
            `connectaddress=${sandboxIp}`,
            `connectport=${RUNTIME_INTERNAL_PORT}`,
          ],
          (err) => {
            if (err) return reject(err)
            resolve()
          }
        )
      }
    )
  })
}

async function removePortProxy(listenPort: number): Promise<void> {
  return new Promise((resolve) => {
    execFile(
      'netsh',
      ['interface', 'portproxy', 'delete', 'v4tov4', `listenport=${listenPort}`],
      () => resolve()
    )
  })
}

async function removeSandboxDir(sandboxDir: string, reason: string): Promise<void> {
  if (/^(1|true|yes|on)$/i.test(process.env.HOST_AGENT_KEEP_FAILED_SANDBOX || '')) {
    logger.warn({ sandboxDir, reason }, 'Keeping failed sandbox workspace for diagnostics')
    return
  }

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await fs.rm(sandboxDir, { recursive: true, force: true })
      return
    } catch (err) {
      logger.warn({ err, sandboxDir, attempt, reason }, 'Failed to remove sandbox workspace')
      await new Promise((resolve) => setTimeout(resolve, 500 * attempt))
    }
  }
}

async function startHyperVRuntime(
  body: unknown
): Promise<StartSandboxResult> {
  if (process.platform !== 'win32') {
    return { ok: false, backend: 'hyperv-vm', error: 'Hyper-V runtime backend requires Windows platform' }
  }

  const request = (body && typeof body === 'object' ? body : {}) as StartSandboxRequest
  const timeoutMs = typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)
    ? Math.max(1000, request.timeoutMs)
    : parseInt(process.env.HOST_AGENT_HYPERV_WAIT_TIMEOUT_MS || '120000', 10)
  const runtimeApiKey = typeof request.runtimeApiKey === 'string' && request.runtimeApiKey.trim().length > 0
    ? request.runtimeApiKey.trim()
    : process.env.HOST_AGENT_RUNTIME_API_KEY || process.env.RUNTIME_API_KEY || API_KEY || undefined

  const { vmName, snapshotName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease } = getHyperVConfig(request)
  if (!vmName) {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: 'HOST_AGENT_HYPERV_VM_NAME is required for the hyperv-vm backend',
      diagnostics: buildHyperVDiagnostics({ vmName, snapshotName, endpoint }),
    }
  }
  if (!endpoint) {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: 'HOST_AGENT_HYPERV_RUNTIME_ENDPOINT is required for the hyperv-vm backend',
      diagnostics: buildHyperVDiagnostics({ vmName, snapshotName, endpoint }),
    }
  }

  const commands = [
    `$ErrorActionPreference = 'Stop'`,
    `$vmName = ${quotePowerShellLiteral(vmName)}`,
    `$vm = Get-VM -Name $vmName -ErrorAction Stop`,
  ]
  if (restoreOnStart) {
    commands.push(
      `$snapshotName = ${quotePowerShellLiteral(snapshotName)}`,
      `if ($vm.State -ne 'Off') { Stop-VM -Name $vmName -TurnOff -Force }`,
      `Restore-VMSnapshot -VMName $vmName -Name $snapshotName -Confirm:$false`,
      `$vm = Get-VM -Name $vmName -ErrorAction Stop`
    )
  }
  commands.push(`if ($vm.State -ne 'Running') { Start-VM -Name $vmName | Out-Null }`)

  try {
    const result = await runPowerShell(commands.join('\n'), timeoutMs)
    if (result.stderr.trim()) {
      logger.warn({ stderr: result.stderr.trim(), vmName }, 'Hyper-V backend command wrote to stderr')
    }
  } catch (err) {
    const details = err as Error & { stdout?: string; stderr?: string }
    return {
      ok: false,
      backend: 'hyperv-vm',
      error:
        `Failed to prepare Hyper-V VM '${vmName}': ${details.message}` +
        `${details.stderr ? ` stderr=${details.stderr.trim()}` : ''}`,
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        restoreOnStart,
        restoreOnRelease,
        stopOnRelease,
        stdout: details.stdout,
        stderr: details.stderr,
      }),
    }
  }

  const ready = await waitForRuntimeEndpoint(endpoint, runtimeApiKey, timeoutMs)
  if (!ready) {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: `Hyper-V runtime endpoint did not become healthy within timeout: ${endpoint}`,
      diagnostics: buildHyperVDiagnostics({ vmName, snapshotName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease }),
    }
  }

  const sandboxId = `hyperv-${randomUUID()}`
  const runtimeHost = (() => {
    try {
      return new URL(endpoint).hostname
    } catch {
      return endpoint
    }
  })()
  activeSandboxes.set(sandboxId, {
    backend: 'hyperv-vm',
    sandboxId,
    endpoint,
    runtimeHost,
    listenPort: 0,
    hypervVmName: vmName,
    hypervSnapshotName: snapshotName || undefined,
    hypervRestoreOnRelease: restoreOnRelease,
    hypervStopOnRelease: stopOnRelease,
  })

  logger.info({ sandboxId, vmName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease }, 'Hyper-V runtime connected')
  return {
    ok: true,
    endpoint,
    sandboxId,
    backend: 'hyperv-vm',
    hyperv: {
      vmName,
      snapshotName: snapshotName || null,
      restoreOnStart,
      restoreOnRelease,
      stopOnRelease,
    },
  }
}

async function startSandbox(
  body: unknown
): Promise<StartSandboxResult> {
  if (HOST_AGENT_BACKEND === 'hyperv-vm') {
    return startHyperVRuntime(body)
  }

  if (process.platform !== 'win32') {
    return { ok: false, error: 'Windows Host Agent requires Windows platform' }
  }

  const request = (body && typeof body === 'object' ? body : {}) as StartSandboxRequest
  const timeoutMs = typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)
    ? Math.max(1000, request.timeoutMs)
    : 60000
  const runtimeApiKey = typeof request.runtimeApiKey === 'string' && request.runtimeApiKey.trim().length > 0
    ? request.runtimeApiKey.trim()
    : process.env.HOST_AGENT_RUNTIME_API_KEY || process.env.RUNTIME_API_KEY || API_KEY || undefined
  const listenPort = await allocateListenPort()
  if (listenPort === null) {
    return { ok: false, error: 'No available listen port for new Sandbox runtime' }
  }

  const workspaceRoot =
    process.env.HOST_AGENT_WORKSPACE || path.join(os.tmpdir(), 'rikune-host-agent')
  const sandboxDir = path.join(workspaceRoot, 'sandbox', randomUUID())
  await fs.mkdir(path.join(sandboxDir, 'inbox'), { recursive: true })
  await fs.mkdir(path.join(sandboxDir, 'outbox'), { recursive: true })

  const runtimeEntryHost = path.join(projectRoot, 'packages', 'runtime-node', 'dist', 'index.js')
  const workersDirHost = path.join(projectRoot, 'workers')
  const nodeModulesDirHost = path.join(projectRoot, 'node_modules')
  const sharedDistEntryHost = path.join(projectRoot, 'packages', 'shared', 'dist', 'index.js')
  const requiredPaths = [
    { name: 'runtimeEntryHost', path: runtimeEntryHost, exists: existsSync(runtimeEntryHost) },
    { name: 'workersDirHost', path: workersDirHost, exists: existsSync(workersDirHost) },
    { name: 'nodeModulesDirHost', path: nodeModulesDirHost, exists: existsSync(nodeModulesDirHost) },
    { name: 'sharedDistEntryHost', path: sharedDistEntryHost, exists: existsSync(sharedDistEntryHost) },
  ]
  if (requiredPaths.some((entry) => !entry.exists)) {
    releaseListenPort(listenPort)
    const diagnostics = await collectWindowsSandboxDiagnostics({
      sandboxDir,
      wsbPath: path.join(sandboxDir, 'runtime.wsb'),
      timeoutMs,
      listenPort,
      missingPaths: requiredPaths,
    })
    await fs.rm(sandboxDir, { recursive: true, force: true })
    return {
      ok: false,
      error:
        'Required runtime paths are missing. ' +
        `runtimeEntryHost=${runtimeEntryHost} (exists=${existsSync(runtimeEntryHost)}), ` +
        `workersDirHost=${workersDirHost} (exists=${existsSync(workersDirHost)}), ` +
        `nodeModulesDirHost=${nodeModulesDirHost} (exists=${existsSync(nodeModulesDirHost)}), ` +
        `sharedDistEntryHost=${sharedDistEntryHost} (exists=${existsSync(sharedDistEntryHost)}). ` +
        'Ensure dependencies are installed and the project is built (npm install && npm run build:shared && npm run build:runtime).',
      diagnostics,
    }
  }

  const wsbPath = path.join(sandboxDir, 'runtime.wsb')
  const wsbDiagnostics = await writeWsbConfig(wsbPath, sandboxDir, runtimeEntryHost, runtimeApiKey)

  if (process.env.NODE_ENV === 'production' && !API_KEY) {
    logger.warn(
      'HOST_AGENT_API_KEY is not set. The sandbox runtime is exposed to all network interfaces.'
    )
  }

  logger.info({ sandboxDir, wsbPath, listenPort }, 'Launching Windows Sandbox via Host Agent')

  const sandboxProcess = spawn('C:\\Windows\\System32\\WindowsSandbox.exe', [wsbPath], {
    detached: true,
    windowsHide: true,
    stdio: 'ignore',
  })
  let sandboxExit: { code: number | null; signal: NodeJS.Signals | null } | null = null
  sandboxProcess.once('exit', (code, signal) => {
    sandboxExit = { code, signal }
    logger.warn({ sandboxDir, wsbPath, code, signal }, 'Windows Sandbox process exited before runtime readiness was confirmed')
  })

  const ready = await waitForRuntimeReady(sandboxDir, timeoutMs)
  if (!ready || !ready.host) {
    try {
      sandboxProcess.kill()
    } catch {}
    releaseListenPort(listenPort)
    const diagnostics = await collectWindowsSandboxDiagnostics({
      sandboxDir,
      wsbPath,
      timeoutMs,
      listenPort,
      wsbDiagnostics,
      sandboxExit,
    })
    await removeSandboxDir(sandboxDir, 'runtime_not_ready')
    const exitDetail = sandboxExit
      ? ` WindowsSandbox.exe exited with code=${sandboxExit.code ?? 'null'} signal=${sandboxExit.signal ?? 'null'}.`
      : ''
    return {
      ok: false,
      error:
        `Sandbox runtime did not become ready within timeout.${exitDetail} ` +
        `wsbPath=${wsbPath}`,
      diagnostics,
    }
  }

  try {
    await addPortProxy(ready.host, listenPort)
  } catch (err) {
    logger.warn(
      { err, listenPort },
      'Failed to add portproxy; external Analyzer may not reach the runtime'
    )
  }

  const hostIp = getPrimaryIp() || '127.0.0.1'
  const endpoint = `http://${hostIp}:${listenPort}`
  const sandboxId = randomUUID()

  activeSandboxes.set(sandboxId, {
    backend: 'windows-sandbox',
    sandboxId,
    sandboxDir,
    wsbPath,
    process: sandboxProcess,
    endpoint,
    runtimeHost: ready.host,
    listenPort,
  })

  logger.info(
    { sandboxId, endpoint, runtimeHost: ready.host, listenPort },
    'Sandbox started and portproxied'
  )
  return { ok: true, endpoint, sandboxId, backend: 'windows-sandbox' }
}

async function stopSandbox(sandboxId: string): Promise<{ ok: boolean; error?: string }> {
  const box = activeSandboxes.get(sandboxId)
  if (!box) {
    return { ok: false, error: 'Sandbox not found' }
  }
  if (box.backend === 'hyperv-vm') {
    const shouldRestore = Boolean(box.hypervRestoreOnRelease && box.hypervSnapshotName)
    if ((box.hypervStopOnRelease || shouldRestore) && box.hypervVmName) {
      try {
        const commands = [
          `$ErrorActionPreference = 'Stop'`,
          `$vmName = ${quotePowerShellLiteral(box.hypervVmName)}`,
          `$vm = Get-VM -Name $vmName -ErrorAction Stop`,
          `if ($vm.State -ne 'Off') { Stop-VM -Name $vmName -TurnOff -Force }`,
        ]
        if (shouldRestore && box.hypervSnapshotName) {
          commands.push(
            `$snapshotName = ${quotePowerShellLiteral(box.hypervSnapshotName)}`,
            `Restore-VMSnapshot -VMName $vmName -Name $snapshotName -Confirm:$false`
          )
        }
        await runPowerShell(commands.join('\n'), shouldRestore ? 120_000 : 60_000)
      } catch (err) {
        logger.warn(
          { err, sandboxId, vmName: box.hypervVmName, snapshotName: box.hypervSnapshotName, shouldRestore },
          'Failed to release Hyper-V VM'
        )
      }
    }
    activeSandboxes.delete(sandboxId)
    logger.info(
      {
        sandboxId,
        vmName: box.hypervVmName,
        snapshotName: box.hypervSnapshotName,
        restoreOnRelease: box.hypervRestoreOnRelease,
        stopOnRelease: box.hypervStopOnRelease,
      },
      'Hyper-V runtime released'
    )
    return { ok: true }
  }
  try {
    box.process?.kill()
  } catch {}
  try {
    if (box.listenPort > 0) {
      await removePortProxy(box.listenPort)
    }
  } catch {}
  if (box.sandboxDir) {
    try {
      await removeSandboxDir(box.sandboxDir, 'stop_sandbox')
    } catch {}
  }
  if (box.listenPort > 0) {
    releaseListenPort(box.listenPort)
  }
  activeSandboxes.delete(sandboxId)
  logger.info({ sandboxId, listenPort: box.listenPort }, 'Sandbox stopped and cleaned up')
  return { ok: true }
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host}`)

    if (req.method === 'POST' && url.pathname === '/sandbox/start') {
      if (!requireAuth(req, res)) return
      const body = await readJsonBody(req)
      const result = await startSandbox(body)
      const status = result.ok ? 200 : 500
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'POST' && url.pathname === '/sandbox/stop') {
      if (!requireAuth(req, res)) return
      const body = (await readJsonBody(req)) as { sandboxId?: string }
      const result = await stopSandbox(body.sandboxId || '')
      const status = result.ok ? 200 : 404
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'GET' && url.pathname === '/sandbox/health') {
      if (!requireAuth(req, res)) return
      const hyperv = await getHyperVRuntimeStatus()
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(
        JSON.stringify({
          ok: true,
          backend: HOST_AGENT_BACKEND,
          hyperv,
          sandboxes: Array.from(activeSandboxes.values()).map((b) => ({
            sandboxId: b.sandboxId,
            backend: b.backend,
            endpoint: b.endpoint,
            runtimeHost: b.runtimeHost,
            hypervVmName: b.hypervVmName,
          })),
        })
      )
      return
    }

    if (req.method === 'GET' && url.pathname === '/hyperv/status') {
      if (!requireAuth(req, res)) return
      const hyperv = await getHyperVRuntimeStatus()
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: true, backend: HOST_AGENT_BACKEND, hyperv }))
      return
    }

    if (req.method === 'GET' && url.pathname === '/hyperv/checkpoints') {
      if (!requireAuth(req, res)) return
      const result = await listHyperVCheckpoints()
      res.writeHead(result.ok ? 200 : 500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'POST' && url.pathname === '/hyperv/checkpoints') {
      if (!requireAuth(req, res)) return
      const body = await readJsonBody(req)
      const result = await createHyperVCheckpoint(body)
      res.writeHead(result.ok ? 200 : 500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'POST' && url.pathname === '/hyperv/restore') {
      if (!requireAuth(req, res)) return
      const body = await readJsonBody(req)
      const result = await restoreHyperVCheckpoint(body)
      res.writeHead(result.ok ? 200 : 500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'POST' && url.pathname === '/hyperv/stop') {
      if (!requireAuth(req, res)) return
      const result = await stopHyperVRuntimeVm()
      res.writeHead(result.ok ? 200 : 500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: 'Not found' }))
  } catch (err) {
    logger.error({ err }, 'Unhandled request error')
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'Internal error' }))
    }
  }
})

server.listen(PORT, () => {
  logger.info({ port: PORT, apiKeyConfigured: !!API_KEY }, 'Windows Host Agent listening')
})

process.on('SIGTERM', async () => {
  logger.info('Shutting down Windows Host Agent...')
  for (const [id] of activeSandboxes) {
    await stopSandbox(id).catch(() => {})
  }
  server.close(() => process.exit(0))
})
process.on('SIGINT', async () => {
  for (const [id] of activeSandboxes) {
    await stopSandbox(id).catch(() => {})
  }
  server.close(() => process.exit(0))
})
