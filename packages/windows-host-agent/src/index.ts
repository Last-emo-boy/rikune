/**
 * Rikune Windows Host Agent
 *
 * Runs on the Windows host and exposes an HTTP API for the remote Analyzer
 * to start / stop Windows Sandbox runtimes.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'http'
import { AsyncLocalStorage } from 'async_hooks'
import fs from 'fs/promises'
import { existsSync, realpathSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { spawn, execFile } from 'child_process'
import { randomUUID } from 'crypto'
import os from 'os'
import net from 'net'
import { logger } from './logger.js'
import {
  assertTrustedHttpEndpoint,
  buildWsbXml,
  createTrustedFetch,
  endpointUrl,
} from '@rikune/shared'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const PORT = parseInt(process.env.HOST_AGENT_PORT || '18082', 10)
const BIND_HOST = (
  process.env.HOST_AGENT_BIND_HOST ||
  process.env.HOST_AGENT_HOST ||
  '127.0.0.1'
).trim()
const API_KEY = (process.env.HOST_AGENT_API_KEY || '').trim()
const RUNTIME_PROXY_BIND_HOST = (
  process.env.HOST_AGENT_RUNTIME_BIND_HOST || (isLoopbackHost(BIND_HOST) ? '127.0.0.1' : '0.0.0.0')
).trim()
const RUNTIME_ADVERTISED_HOST = resolveRuntimeAdvertisedHost(
  RUNTIME_PROXY_BIND_HOST,
  process.env.HOST_AGENT_RUNTIME_ADVERTISED_HOST
)
const RUNTIME_INTERNAL_PORT = 18081
const LISTEN_PORT_MIN = 18081
const LISTEN_PORT_MAX = 19000
const START_REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu
const START_REQUEST_CORRELATION = 'request-id-v2'
const EXTERNAL_COMMAND_TIMEOUT_MS = 10_000
const START_CLEANUP_TIMEOUT_MS = 30_000
const DEFAULT_STOP_TIMEOUT_MS = 120_000
const MAX_OPERATION_TIMEOUT_MS = 2_147_483_647
const HOST_AGENT_BACKEND = normalizeBackend(
  process.env.HOST_AGENT_BACKEND || process.env.HOST_AGENT_RUNTIME_BACKEND
)

type HostAgentBackend = 'windows-sandbox' | 'hyperv-vm'

interface ActiveSandbox {
  backend: HostAgentBackend
  sandboxId: string
  requestId: string
  sandboxDir?: string
  wsbPath?: string
  process?: ReturnType<typeof spawn>
  endpoint: string
  runtimeHost: string
  listenPort: number
  runtimeProxyHost?: string
  hypervVmName?: string
  hypervSnapshotName?: string
  hypervRestoreOnRelease?: boolean
  hypervStopOnRelease?: boolean
}

interface StartSandboxRequest {
  requestId?: string
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
  requestId?: string
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

type WindowsCommandResult = { stdout: string; stderr: string }
export type WindowsCommandRunner = (
  command: string,
  args: string[]
) => Promise<WindowsCommandResult>

interface WindowsAclOptions {
  platform?: NodeJS.Platform
  runCommand?: WindowsCommandRunner
  currentUserSid?: string
}

interface RestrictedFileHandle {
  writeFile(data: string, options?: { encoding?: BufferEncoding } | BufferEncoding): Promise<void>
  sync(): Promise<void>
  close(): Promise<void>
}

interface FileSystemEntrySnapshot {
  isDirectory(): boolean
  isSymbolicLink(): boolean
}

export interface WindowsPathInspectionOptions extends WindowsAclOptions {
  lstat?: (targetPath: string) => Promise<FileSystemEntrySnapshot>
}

export interface SandboxWorkspaceDependencies {
  applyRestrictedAcl: (targetPath: string, isDirectory: boolean) => Promise<void>
  verifyRestrictedAcl: (targetPath: string, isDirectory: boolean) => Promise<void>
  verifyNotReparse: (targetPath: string, expectedDirectory: boolean) => Promise<void>
  mkdir: (targetPath: string, options: { recursive: false }) => Promise<string | undefined | void>
  rm: (targetPath: string, options: { recursive: true; force: true }) => Promise<void>
}

export interface UniqueSandboxWorkspaceOptions extends Partial<SandboxWorkspaceDependencies> {
  randomId?: () => string
  maxAttempts?: number
}

export interface PortProxyRow {
  listenAddress: string
  listenPort: number
  connectAddress: string
  connectPort: number
}

export type NetshCommandRunner = (args: string[]) => Promise<WindowsCommandResult>

export interface PortProxyCommandOptions {
  runNetsh?: NetshCommandRunner
  commandTimeoutMs?: number
  maxAttempts?: number
  wait?: (delayMs: number) => Promise<void>
}

export interface RestrictedWsbFileDependencies {
  applyRestrictedAcl: (targetPath: string, isDirectory: boolean) => Promise<void>
  verifyRestrictedAcl: (targetPath: string, isDirectory: boolean) => Promise<void>
  verifyParentDirectory: (targetPath: string) => Promise<void>
  open: (targetPath: string, flags: string, mode?: number) => Promise<RestrictedFileHandle>
  rename: (sourcePath: string, targetPath: string) => Promise<void>
  rm: (targetPath: string, options: { force: boolean }) => Promise<void>
  randomId: () => string
}

export interface ProtectedWsbLifecycleOptions<TPrepared, TReady, TProcess> {
  sandboxDir: string
  wsbPath: string
  verifyRestrictedAcl?: (targetPath: string, isDirectory: boolean) => Promise<void>
  verifyNotReparse?: (targetPath: string, expectedDirectory: boolean) => Promise<void>
  prepareWsb: () => Promise<TPrepared>
  spawnSandbox: (wsbPath: string) => TProcess
  waitUntilReady: (sandboxProcess: TProcess) => Promise<TReady>
  killProcess?: (sandboxProcess: TProcess) => boolean
  isProcessTerminated?: (sandboxProcess: TProcess) => boolean
}

export class ProtectedWsbLifecycleError<TProcess = unknown> extends Error {
  readonly sandboxProcess: TProcess | undefined
  readonly terminationAttempted: boolean
  readonly terminationSignalAccepted: boolean
  readonly terminationConfirmed: boolean
  readonly terminationError: Error | undefined

  constructor(params: {
    primaryError: unknown
    cleanupError?: unknown
    sandboxProcess?: TProcess
    terminationAttempted: boolean
    terminationSignalAccepted: boolean
    terminationConfirmed: boolean
    terminationError?: Error
  }) {
    const primaryMessage = formatErrorMessage(params.primaryError)
    const cleanupMessage = params.cleanupError
      ? ` Key-bearing WSB cleanup failed: ${formatErrorMessage(params.cleanupError)}.`
      : ''
    const terminationMessage = params.terminationConfirmed
      ? ''
      : ` Windows Sandbox termination was not confirmed${
          params.terminationError ? `: ${params.terminationError.message}` : '.'
        }`
    super(`${primaryMessage}.${cleanupMessage}${terminationMessage}`)
    this.name = 'ProtectedWsbLifecycleError'
    this.sandboxProcess = params.sandboxProcess
    this.terminationAttempted = params.terminationAttempted
    this.terminationSignalAccepted = params.terminationSignalAccepted
    this.terminationConfirmed = params.terminationConfirmed
    this.terminationError = params.terminationError
  }
}

interface SandboxOperationContext {
  requestId: string
  phase: 'start' | 'cleanup' | 'stop'
  deadlineAtMs: number
  controller: AbortController
}

interface PendingSandboxStart {
  requestId: string
  deadlineAtMs: number
}

const activeSandboxes = new Map<string, ActiveSandbox>()
const pendingSandboxStarts = new Map<string, PendingSandboxStart>()
const settledSandboxStarts = new Map<string, number>()
const sandboxOperationContext = new AsyncLocalStorage<SandboxOperationContext>()
const usedListenPorts = new Set<number>()
let stalePortProxyReconciliation: Promise<void> | undefined

function normalizeBackend(raw?: string): HostAgentBackend {
  const value = (raw || '').trim().toLowerCase()
  if (
    value === 'hyperv' ||
    value === 'hyper-v' ||
    value === 'hyperv-vm' ||
    value === 'hyper-v-vm'
  ) {
    return 'hyperv-vm'
  }
  return 'windows-sandbox'
}

function isLoopbackHost(host: string): boolean {
  const value = host
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
  return value === 'localhost' || value === '::1' || value.startsWith('127.')
}

function isAllInterfacesHost(host: string): boolean {
  const value = host
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
  return value === '0.0.0.0' || value === '::' || value === '*'
}

function isRfc1918Ipv4(host: string): boolean {
  if (net.isIP(host) !== 4) {
    return false
  }
  const octets = host.split('.').map(Number)
  return (
    octets[0] === 10 ||
    (octets[0] === 172 && (octets[1] || 0) >= 16 && (octets[1] || 0) <= 31) ||
    (octets[0] === 192 && octets[1] === 168)
  )
}

function isProductionEnv(): boolean {
  return (process.env.NODE_ENV || '').trim().toLowerCase() === 'production'
}

function getHostAgentAuthDefaultError(): string | null {
  if (API_KEY) {
    return null
  }
  if (isProductionEnv()) {
    return 'HOST_AGENT_API_KEY is required when NODE_ENV=production. Set HOST_AGENT_API_KEY before starting Windows Host Agent.'
  }
  if (!isLoopbackHost(BIND_HOST)) {
    return `HOST_AGENT_API_KEY is required when HOST_AGENT_BIND_HOST/HOST_AGENT_HOST binds Windows Host Agent to non-loopback address '${BIND_HOST}'. Use 127.0.0.1 for unauthenticated local development or set HOST_AGENT_API_KEY.`
  }
  return null
}

export function resolveRuntimeApiKey(
  request: { runtimeApiKey?: unknown },
  environment: NodeJS.ProcessEnv,
  hostAgentApiKey: string | undefined
): { runtimeApiKey?: string; error?: string } {
  const runtimeApiKey =
    typeof request.runtimeApiKey === 'string' && request.runtimeApiKey.trim().length > 0
      ? request.runtimeApiKey.trim()
      : environment.HOST_AGENT_RUNTIME_API_KEY || environment.RUNTIME_API_KEY || undefined

  if (runtimeApiKey && hostAgentApiKey && runtimeApiKey === hostAgentApiKey) {
    return {
      error:
        'HOST_AGENT_RUNTIME_API_KEY or RUNTIME_API_KEY must be distinct from HOST_AGENT_API_KEY.',
    }
  }
  return { runtimeApiKey }
}

export function resolveSandboxStartRequestId(value: unknown): {
  requestId?: string
  error?: string
} {
  if (value === undefined) {
    return { requestId: randomUUID() }
  }
  if (typeof value !== 'string' || !START_REQUEST_ID_PATTERN.test(value)) {
    return {
      error: 'requestId must be a canonical UUID string when provided to /sandbox/start',
    }
  }
  return { requestId: value.toLowerCase() }
}

export function normalizeServerDeadlineMs(value: unknown, fallback: number): number {
  if (value === undefined || typeof value !== 'number' || !Number.isFinite(value)) {
    return fallback
  }
  if (!Number.isSafeInteger(value) || value < 1000 || value > MAX_OPERATION_TIMEOUT_MS) {
    throw new Error(
      `Sandbox operation timeout must be an integer between 1000 and ${MAX_OPERATION_TIMEOUT_MS}`
    )
  }
  return value
}

function remainingOperationMs(label: string, maximumMs = EXTERNAL_COMMAND_TIMEOUT_MS): number {
  const context = sandboxOperationContext.getStore()
  if (!context) return maximumMs
  const remainingMs = Math.floor(context.deadlineAtMs - Date.now())
  if (context.controller.signal.aborted || remainingMs <= 0) {
    throw new Error(
      `${label} exceeded the ${context.phase} deadline for sandbox request ${context.requestId}`
    )
  }
  return Math.max(1, Math.min(maximumMs, remainingMs))
}

async function runBoundedOperation<T>(
  label: string,
  operation: () => Promise<T>,
  maximumMs = EXTERNAL_COMMAND_TIMEOUT_MS
): Promise<T> {
  const timeoutMs = remainingOperationMs(label, maximumMs)
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      operation(),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${label} timed out after ${timeoutMs}ms`)),
          timeoutMs
        )
      }),
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

async function runWithSandboxOperationDeadline<T>(
  requestId: string,
  phase: SandboxOperationContext['phase'],
  timeoutMs: number,
  operation: () => Promise<T>
): Promise<T> {
  const controller = new AbortController()
  const deadlineAtMs = Date.now() + timeoutMs
  const timer = setTimeout(
    () =>
      controller.abort(new Error(`${phase} deadline exceeded for sandbox request ${requestId}`)),
    timeoutMs
  )
  try {
    return await sandboxOperationContext.run(
      { requestId, phase, deadlineAtMs, controller },
      operation
    )
  } finally {
    clearTimeout(timer)
  }
}

async function runWithStartCleanupBudget<T>(
  requestId: string,
  operation: () => Promise<T>
): Promise<T> {
  return runWithSandboxOperationDeadline(requestId, 'cleanup', START_CLEANUP_TIMEOUT_MS, operation)
}

function assertSandboxStartCanRegister(requestId: string): void {
  const context = sandboxOperationContext.getStore()
  const pending = pendingSandboxStarts.get(requestId)
  if (
    !context ||
    context.phase !== 'start' ||
    context.requestId !== requestId ||
    context.controller.signal.aborted ||
    Date.now() >= context.deadlineAtMs ||
    pending?.requestId !== requestId
  ) {
    throw new Error(`Sandbox start request ${requestId} expired before active registration`)
  }
}

function recordSettledSandboxStart(requestId: string): void {
  settledSandboxStarts.delete(requestId)
  settledSandboxStarts.set(requestId, Date.now())
  while (settledSandboxStarts.size > 512) {
    const oldest = settledSandboxStarts.keys().next().value
    if (typeof oldest !== 'string') break
    settledSandboxStarts.delete(oldest)
  }
}

export async function runSandboxStartDeadlineGuard<T>(
  requestId: string,
  timeoutMs: number,
  operation: (assertCanRegister: () => void) => Promise<T>
): Promise<T> {
  pendingSandboxStarts.set(requestId, { requestId, deadlineAtMs: Date.now() + timeoutMs })
  try {
    return await runWithSandboxOperationDeadline(requestId, 'start', timeoutMs, () =>
      operation(() => assertSandboxStartCanRegister(requestId))
    )
  } finally {
    pendingSandboxStarts.delete(requestId)
    recordSettledSandboxStart(requestId)
  }
}

function getConfiguredRuntimeApiKey(request: StartSandboxRequest | HyperVActionRequest): {
  runtimeApiKey?: string
  error?: string
} {
  return resolveRuntimeApiKey(request, process.env, API_KEY)
}

function getSandboxRuntimeAuthDefaultError(runtimeApiKey: string | undefined): string | null {
  if (runtimeApiKey) {
    return null
  }
  return 'HOST_AGENT_RUNTIME_API_KEY or RUNTIME_API_KEY is required when Windows Host Agent launches a Sandbox Runtime Node, because the runtime binds to 0.0.0.0 inside the sandbox. Pass runtimeApiKey in /sandbox/start for controlled local development.'
}

function getRuntimeEndpointAuthDefaultError(
  runtimeApiKey: string | undefined,
  endpoint: string
): string | null {
  if (runtimeApiKey) {
    return null
  }
  if (isProductionEnv()) {
    return 'HOST_AGENT_RUNTIME_API_KEY or RUNTIME_API_KEY is required when NODE_ENV=production before connecting a Runtime Node through Windows Host Agent.'
  }
  try {
    const host = new URL(endpoint).hostname
    if (isLoopbackHost(host)) {
      return null
    }
    return `HOST_AGENT_RUNTIME_API_KEY or RUNTIME_API_KEY is required when Runtime Node endpoint '${endpoint}' is non-loopback.`
  } catch {
    return `HOST_AGENT_RUNTIME_API_KEY or RUNTIME_API_KEY is required when Runtime Node endpoint '${endpoint}' cannot be verified as loopback.`
  }
}

function getDefaultAdvertisedRuntimeHost(runtimeProxyBindHost: string): string {
  if (isAllInterfacesHost(runtimeProxyBindHost)) {
    return getPrimaryIp() || '127.0.0.1'
  }
  if (runtimeProxyBindHost.toLowerCase() === 'localhost') {
    return '127.0.0.1'
  }
  return runtimeProxyBindHost.replace(/^\[|\]$/g, '')
}

export function validateRuntimeAdvertisedHost(raw: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw !== raw.trim()) {
    throw new Error(
      'HOST_AGENT_RUNTIME_ADVERTISED_HOST must be a single hostname, IPv4 address, or IPv6 address without surrounding whitespace'
    )
  }
  if (/[\u0000-\u001f\u007f\s]/u.test(raw) || raw.includes('://') || /[\\/@?#%]/u.test(raw)) {
    throw new Error(
      'HOST_AGENT_RUNTIME_ADVERTISED_HOST must not contain a scheme, userinfo, port, path, query, fragment, whitespace, or control characters'
    )
  }

  const bracketed = raw.startsWith('[') || raw.endsWith(']')
  if (bracketed) {
    if (!(raw.startsWith('[') && raw.endsWith(']'))) {
      throw new Error('HOST_AGENT_RUNTIME_ADVERTISED_HOST contains invalid IPv6 brackets')
    }
    const ipv6 = raw.slice(1, -1)
    if (net.isIP(ipv6) !== 6) {
      throw new Error(
        'HOST_AGENT_RUNTIME_ADVERTISED_HOST brackets may only contain a single IPv6 address'
      )
    }
    return ipv6.toLowerCase()
  }

  const ipVersion = net.isIP(raw)
  if (ipVersion === 4) {
    return raw
  }
  if (ipVersion === 6) {
    return raw.toLowerCase()
  }
  if (raw.includes(':')) {
    throw new Error(
      'HOST_AGENT_RUNTIME_ADVERTISED_HOST must not include a port or scoped IPv6 zone identifier'
    )
  }
  if (raw.length > 253 || /^\d+(?:\.\d+)*$/u.test(raw)) {
    throw new Error('HOST_AGENT_RUNTIME_ADVERTISED_HOST is not a valid hostname')
  }

  const labels = raw.split('.')
  if (
    labels.some(
      (label) =>
        label.length === 0 ||
        label.length > 63 ||
        !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label)
    )
  ) {
    throw new Error('HOST_AGENT_RUNTIME_ADVERTISED_HOST is not a valid hostname')
  }
  return raw.toLowerCase()
}

export function resolveRuntimeAdvertisedHost(
  runtimeProxyBindHost: string,
  configuredHost: string | undefined
): string {
  return configuredHost === undefined
    ? validateRuntimeAdvertisedHost(getDefaultAdvertisedRuntimeHost(runtimeProxyBindHost))
    : validateRuntimeAdvertisedHost(configuredHost)
}

function formatRuntimeEndpointHost(host: string): string {
  return net.isIP(host) === 6 ? `[${host}]` : host
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
  return normalized.length > maxChars
    ? `${normalized.slice(0, maxChars)}\n...[truncated]`
    : normalized
}

function formatErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  if (typeof error === 'string') {
    return error
  }
  if (error === undefined || error === null) {
    return 'unknown error'
  }
  try {
    return JSON.stringify(error) || 'unknown error'
  } catch {
    return 'unserializable error'
  }
}

async function readFilePreview(
  filePath: string,
  maxChars = 4000
): Promise<{ path: string; exists: boolean; preview?: string }> {
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
  const timeoutMs = remainingOperationMs('where.exe command', 5_000)
  const signal = sandboxOperationContext.getStore()?.controller.signal
  return new Promise((resolve) => {
    execFile(
      'where.exe',
      [command],
      { windowsHide: true, timeout: timeoutMs, signal },
      (err, stdout) => {
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
      }
    )
  })
}

async function resolveHostPythonPath(): Promise<string | null> {
  return (
    existingExecutablePath(process.env.HOST_AGENT_PYTHON_PATH) ||
    existingExecutablePath(process.env.RUNTIME_PYTHON_PATH) ||
    (await findExecutableOnPath('python')) ||
    (await findExecutableOnPath('py'))
  )
}

function runPowerShell(
  script: string,
  timeoutMs = 120_000
): Promise<{ stdout: string; stderr: string }> {
  const boundedTimeoutMs = remainingOperationMs('PowerShell command', timeoutMs)
  const signal = sandboxOperationContext.getStore()?.controller.signal
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { windowsHide: true, timeout: boundedTimeoutMs, signal },
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
  const deadlineAtMs = Date.now() + remainingOperationMs('Runtime endpoint readiness', timeoutMs)
  const interval = 2000
  const operationSignal = sandboxOperationContext.getStore()?.controller.signal
  let healthUrl: string
  try {
    healthUrl = endpointUrl(endpoint, '/health', { label: 'Hyper-V Runtime Node endpoint' })
  } catch {
    return false
  }

  const trustedFetch = createTrustedFetch({
    allowedOrigins: [new URL(healthUrl).origin],
    label: 'Hyper-V Runtime Node endpoint',
  })
  try {
    while (Date.now() < deadlineAtMs && !operationSignal?.aborted) {
      try {
        const requestTimeoutMs = Math.max(1, Math.min(interval, deadlineAtMs - Date.now(), 5000))
        const res = await trustedFetch(healthUrl, {
          headers: runtimeApiKey ? { Authorization: `Bearer ${runtimeApiKey}` } : {},
          redirect: 'error',
          signal: operationSignal
            ? AbortSignal.any([operationSignal, AbortSignal.timeout(requestTimeoutMs)])
            : AbortSignal.timeout(requestTimeoutMs),
        })
        if (!res.ok) {
          if (res.body) {
            await res.body.cancel().catch(() => {})
          }
        } else {
          const data = (await res.json().catch(() => ({}))) as { ok?: boolean }
          if (data.ok === true) {
            return true
          }
        }
      } catch {
        // Runtime may still be booting.
      }
      const delayMs = Math.max(1, Math.min(interval, deadlineAtMs - Date.now()))
      await new Promise((resolve) => setTimeout(resolve, delayMs))
    }
    return false
  } finally {
    await trustedFetch.close().catch(() => {})
  }
}

async function stageRuntimeBundle(sandboxDir: string, runtimeEntryHost: string): Promise<string> {
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

function shouldStageWorkerPath(sourcePath: string): boolean {
  const name = path.basename(sourcePath).toLowerCase()
  return !['venv', 'qiling-venv', '__pycache__', '.pytest_cache'].includes(name)
}

async function stageRuntimeWorkers(sandboxDir: string): Promise<string> {
  const workersStageDir = path.join(sandboxDir, 'workers')
  const rootWorkersDir = path.join(projectRoot, 'workers')
  const pluginWorkersRoot = path.join(projectRoot, 'src', 'plugins')

  await fs.rm(workersStageDir, { recursive: true, force: true })
  await fs.mkdir(workersStageDir, { recursive: true })

  if (existsSync(rootWorkersDir)) {
    await fs.cp(rootWorkersDir, workersStageDir, {
      recursive: true,
      filter: (sourcePath) => shouldStageWorkerPath(sourcePath),
    })
  }

  if (existsSync(pluginWorkersRoot)) {
    const pluginEntries = await fs.readdir(pluginWorkersRoot, { withFileTypes: true })
    for (const entry of pluginEntries) {
      if (!entry.isDirectory()) continue
      const pluginWorkerDir = path.join(pluginWorkersRoot, entry.name, 'workers')
      if (!existsSync(pluginWorkerDir)) continue
      const stagedPluginWorkerDir = path.join(
        workersStageDir,
        'src',
        'plugins',
        entry.name,
        'workers'
      )
      await fs.mkdir(path.dirname(stagedPluginWorkerDir), { recursive: true })
      await fs.cp(pluginWorkerDir, stagedPluginWorkerDir, { recursive: true })
    }
  }

  return workersStageDir
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

function runWindowsCommand(command: string, args: string[]): Promise<WindowsCommandResult> {
  const timeoutMs = remainingOperationMs(command)
  const signal = sandboxOperationContext.getStore()?.controller.signal
  return new Promise((resolve, reject) => {
    execFile(
      command,
      args,
      { windowsHide: true, timeout: timeoutMs, signal },
      (err, stdout, stderr) => {
        const result = {
          stdout: stdout?.toString() || '',
          stderr: stderr?.toString() || '',
        }
        if (err) {
          reject(
            Object.assign(
              new Error(
                `${command} failed while securing Windows Sandbox files: ${result.stderr.trim() || err.message}`
              ),
              result
            )
          )
          return
        }
        resolve(result)
      }
    )
  })
}

async function resolveWindowsAclContext(options: WindowsAclOptions): Promise<{
  platform: NodeJS.Platform
  runCommand: WindowsCommandRunner
  currentUserSid: string
}> {
  const platform = options.platform || process.platform
  if (platform !== 'win32') {
    throw new Error('Restricted Windows Sandbox ACLs can only be applied on Windows')
  }

  const rawRunCommand = options.runCommand || runWindowsCommand
  const runCommand: WindowsCommandRunner = (command, args) =>
    runBoundedOperation(`${command} command`, () => rawRunCommand(command, args))
  let currentUserSid = options.currentUserSid?.trim()
  if (!currentUserSid) {
    const identity = await runCommand('whoami.exe', ['/user', '/fo', 'csv', '/nh'])
    currentUserSid = identity.stdout.match(/S-\d+(?:-\d+)+/i)?.[0]
  }
  if (!currentUserSid || !/^S-\d+(?:-\d+)+$/i.test(currentUserSid)) {
    throw new Error('Unable to resolve the current Windows user SID for Sandbox ACL hardening')
  }

  return { platform, runCommand, currentUserSid: currentUserSid.toUpperCase() }
}

export async function verifyRestrictedWindowsAcl(
  targetPath: string,
  _isDirectory: boolean,
  options: WindowsAclOptions = {}
): Promise<void> {
  const { runCommand, currentUserSid } = await resolveWindowsAclContext(options)
  const encodedTarget = Buffer.from(targetPath, 'utf8').toString('base64')
  const auditScript = [
    `$ErrorActionPreference = 'Stop'`,
    `$target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedTarget}'))`,
    `$acl = Get-Acl -LiteralPath $target`,
    `$ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value`,
    `$rules = @($acl.Access | ForEach-Object { $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; [pscustomobject]@{ Sid = $sid; Type = $_.AccessControlType.ToString(); Rights = $_.FileSystemRights.ToString(); Inherited = $_.IsInherited } })`,
    `[pscustomobject]@{ OwnerSid = $ownerSid; Protected = $acl.AreAccessRulesProtected; Rules = $rules } | ConvertTo-Json -Compress -Depth 4`,
  ].join('; ')
  const result = await runCommand('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    auditScript,
  ])

  let snapshot: {
    OwnerSid?: string
    Protected?: boolean
    Rules?: Array<{ Sid?: string; Type?: string; Rights?: string; Inherited?: boolean }>
  }
  try {
    snapshot = JSON.parse(result.stdout.trim()) as typeof snapshot
  } catch {
    throw new Error('Unable to parse the Windows Sandbox ACL verification result')
  }

  const allowedSids = new Set([currentUserSid, 'S-1-5-18', 'S-1-5-32-544'])
  const rules = Array.isArray(snapshot.Rules) ? snapshot.Rules : []
  if (
    snapshot.OwnerSid?.toUpperCase() !== currentUserSid ||
    snapshot.Protected !== true ||
    rules.length !== allowedSids.size
  ) {
    throw new Error('Windows Sandbox ACL is not an exact protected three-principal allowlist')
  }

  const observedSids = new Set<string>()
  for (const rule of rules) {
    const sid = rule.Sid?.toUpperCase() || ''
    if (
      !allowedSids.has(sid) ||
      observedSids.has(sid) ||
      rule.Type !== 'Allow' ||
      rule.Inherited !== false ||
      rule.Rights !== 'FullControl'
    ) {
      throw new Error('Windows Sandbox ACL contains a non-allowlisted or non-FullControl rule')
    }
    observedSids.add(sid)
  }
  if (observedSids.size !== allowedSids.size) {
    throw new Error('Windows Sandbox ACL is missing a required FullControl principal')
  }
}

export async function applyRestrictedWindowsAcl(
  targetPath: string,
  isDirectory: boolean,
  options: WindowsAclOptions = {}
): Promise<void> {
  const { platform, runCommand, currentUserSid } = await resolveWindowsAclContext(options)

  const permissions = isDirectory ? '(OI)(CI)F' : '(F)'
  // `/grant:r` only replaces ACEs for named principals. Reset first while the
  // directory/file is still empty or non-secret so pre-existing explicit ACEs
  // cannot survive into the protected contract.
  await runCommand('icacls.exe', [targetPath, '/setowner', `*${currentUserSid}`])
  await runCommand('icacls.exe', [targetPath, '/reset'])
  await runCommand('icacls.exe', [
    targetPath,
    '/inheritance:r',
    '/grant:r',
    `*${currentUserSid}:${permissions}`,
    `*S-1-5-18:${permissions}`,
    `*S-1-5-32-544:${permissions}`,
  ])
  await verifyRestrictedWindowsAcl(targetPath, isDirectory, {
    platform,
    runCommand,
    currentUserSid,
  })
}

export async function verifyWindowsPathNotReparse(
  targetPath: string,
  expectedDirectory: boolean,
  options: WindowsPathInspectionOptions = {}
): Promise<void> {
  const lstat = options.lstat || ((candidatePath: string) => fs.lstat(candidatePath))
  const snapshot = await lstat(targetPath)
  if (snapshot.isSymbolicLink()) {
    throw new Error(`Windows Sandbox path '${targetPath}' is a symlink or reparse point`)
  }
  if (snapshot.isDirectory() !== expectedDirectory) {
    throw new Error(
      `Windows Sandbox path '${targetPath}' is not the expected ${expectedDirectory ? 'directory' : 'file'}`
    )
  }

  const platform = options.platform || process.platform
  if (platform !== 'win32') {
    return
  }
  const runCommand = options.runCommand || runWindowsCommand
  const encodedTarget = Buffer.from(targetPath, 'utf8').toString('base64')
  const expectedAttribute = expectedDirectory ? 'Directory' : 'Normal'
  const auditScript = [
    `$ErrorActionPreference = 'Stop'`,
    `$target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedTarget}'))`,
    `$attributes = [IO.File]::GetAttributes($target)`,
    `if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'symlink or reparse point' }`,
    expectedDirectory
      ? `if (($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw 'not a directory' }`
      : `if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { throw 'not a file' }`,
    `'${expectedAttribute}:SAFE'`,
  ].join('; ')
  const result = await runCommand('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    auditScript,
  ])
  if (result.stdout.trim() !== `${expectedAttribute}:SAFE`) {
    throw new Error(`Unable to verify Windows Sandbox path attributes for '${targetPath}'`)
  }
}

function isAlreadyExistsError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as NodeJS.ErrnoException).code === 'EEXIST'
  )
}

function resolveSandboxWorkspaceDependencies(
  options: Partial<SandboxWorkspaceDependencies>
): SandboxWorkspaceDependencies {
  return {
    applyRestrictedAcl: applyRestrictedWindowsAcl,
    verifyRestrictedAcl: verifyRestrictedWindowsAcl,
    verifyNotReparse: verifyWindowsPathNotReparse,
    mkdir: (targetPath, mkdirOptions) => fs.mkdir(targetPath, mkdirOptions),
    rm: (targetPath, rmOptions) => fs.rm(targetPath, rmOptions),
    ...options,
  }
}

async function removeVerifiedNonReparseDirectory(
  targetPath: string,
  dependencies: SandboxWorkspaceDependencies
): Promise<void> {
  try {
    await dependencies.verifyNotReparse(targetPath, true)
  } catch {
    // Never issue a recursive delete against a path that is currently missing,
    // a symlink, or a Windows reparse point. Leaving an untrusted UUID behind
    // is safer than following it outside the sandbox root.
    return
  }
  await dependencies.rm(targetPath, { recursive: true, force: true }).catch(() => {})
}

async function verifyRestrictedSandboxDirectoryForSecretWrite(targetPath: string): Promise<void> {
  await verifyWindowsPathNotReparse(targetPath, true)
  if (process.platform === 'win32') {
    await verifyRestrictedWindowsAcl(targetPath, true)
  }
  await verifyWindowsPathNotReparse(targetPath, true)
}

export async function ensureRestrictedSandboxRoot(
  sandboxRoot: string,
  options: Partial<SandboxWorkspaceDependencies> = {}
): Promise<void> {
  const dependencies = resolveSandboxWorkspaceDependencies(options)
  let created = false
  try {
    await dependencies.mkdir(sandboxRoot, { recursive: false })
    created = true
  } catch (error) {
    if (!isAlreadyExistsError(error)) {
      throw error
    }
  }

  try {
    await dependencies.verifyNotReparse(sandboxRoot, true)
    // The shared sandbox root never contains a bearer key directly. Harden a
    // regular pre-existing root in place for safe upgrades, but only after the
    // lstat/Windows-attribute checks above reject junctions and reparse points.
    // UUID leaves remain exclusive-create only and are never laundered.
    await dependencies.applyRestrictedAcl(sandboxRoot, true)
    await dependencies.verifyNotReparse(sandboxRoot, true)
    await dependencies.verifyRestrictedAcl(sandboxRoot, true)
    await dependencies.verifyNotReparse(sandboxRoot, true)
  } catch (error) {
    if (created) {
      await removeVerifiedNonReparseDirectory(sandboxRoot, dependencies)
    }
    throw error
  }
}

export async function createRestrictedSandboxWorkspace(
  sandboxDir: string,
  options: Partial<SandboxWorkspaceDependencies> = {}
): Promise<void> {
  const dependencies = resolveSandboxWorkspaceDependencies(options)
  const sandboxRoot = path.dirname(sandboxDir)
  const workspaceRoot = path.dirname(sandboxRoot)

  await dependencies.verifyNotReparse(workspaceRoot, true)
  await dependencies.verifyRestrictedAcl(workspaceRoot, true)
  await dependencies.verifyNotReparse(workspaceRoot, true)
  await dependencies.verifyNotReparse(sandboxRoot, true)
  await dependencies.verifyRestrictedAcl(sandboxRoot, true)
  await dependencies.verifyNotReparse(sandboxRoot, true)

  // The UUID leaf is intentionally non-recursive and must be new. An existing
  // name is never reset, followed, or removed because it may be an attacker-
  // controlled junction created before the Host Agent selected the name.
  await dependencies.mkdir(sandboxDir, { recursive: false })

  try {
    await dependencies.verifyNotReparse(sandboxDir, true)
    await dependencies.applyRestrictedAcl(sandboxDir, true)
    await dependencies.verifyNotReparse(sandboxDir, true)
    await dependencies.verifyRestrictedAcl(sandboxDir, true)
    await dependencies.verifyNotReparse(sandboxDir, true)
    await dependencies.mkdir(path.join(sandboxDir, 'inbox'), { recursive: false })
    await dependencies.mkdir(path.join(sandboxDir, 'outbox'), { recursive: false })
    await dependencies.verifyNotReparse(sandboxDir, true)
  } catch (error) {
    await removeVerifiedNonReparseDirectory(sandboxDir, dependencies)
    throw error
  }
}

export async function createUniqueRestrictedSandboxWorkspace(
  sandboxRoot: string,
  options: UniqueSandboxWorkspaceOptions = {}
): Promise<string> {
  const {
    randomId = randomUUID,
    maxAttempts: configuredMaxAttempts = 16,
    ...workspaceOptions
  } = options
  const maxAttempts = Math.max(1, configuredMaxAttempts)

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const sandboxDir = path.join(sandboxRoot, randomId())
    try {
      await createRestrictedSandboxWorkspace(sandboxDir, workspaceOptions)
      return sandboxDir
    } catch (error) {
      if (isAlreadyExistsError(error)) {
        continue
      }
      throw error
    }
  }
  throw new Error(
    `Unable to allocate a new Windows Sandbox workspace after ${maxAttempts} attempts`
  )
}

export async function writeRestrictedWsbFile(
  wsbPath: string,
  wsb: string,
  overrides: Partial<RestrictedWsbFileDependencies> = {}
): Promise<void> {
  const dependencies: RestrictedWsbFileDependencies = {
    applyRestrictedAcl: applyRestrictedWindowsAcl,
    verifyRestrictedAcl: verifyRestrictedWindowsAcl,
    verifyParentDirectory: verifyRestrictedSandboxDirectoryForSecretWrite,
    open: (targetPath, flags, mode) => fs.open(targetPath, flags, mode),
    rename: (sourcePath, targetPath) => fs.rename(sourcePath, targetPath),
    rm: (targetPath, options) => fs.rm(targetPath, options),
    randomId: randomUUID,
    ...overrides,
  }
  const temporaryPath = path.join(
    path.dirname(wsbPath),
    `.${path.basename(wsbPath)}.${process.pid}.${dependencies.randomId()}.tmp`
  )
  let handle: RestrictedFileHandle | undefined
  let temporaryCreated = false
  let targetCreated = false

  try {
    await dependencies.verifyParentDirectory(path.dirname(wsbPath))
    handle = await dependencies.open(temporaryPath, 'wx', 0o600)
    temporaryCreated = true
    await handle.close()
    handle = undefined

    // The temporary file is empty until its ACL is restricted. This prevents a
    // key-bearing config from ever existing with inherited/default permissions.
    await dependencies.applyRestrictedAcl(temporaryPath, false)
    await dependencies.verifyParentDirectory(path.dirname(wsbPath))
    handle = await dependencies.open(temporaryPath, 'r+')
    await handle.writeFile(wsb, { encoding: 'utf8' })
    await handle.sync()
    await handle.close()
    handle = undefined

    await dependencies.verifyParentDirectory(path.dirname(wsbPath))
    await dependencies.rename(temporaryPath, wsbPath)
    temporaryCreated = false
    targetCreated = true
    // Renaming within the same directory preserves the already-restricted DACL.
    // Verify rather than reset here because the file now contains the key.
    await dependencies.verifyRestrictedAcl(wsbPath, false)
    await dependencies.verifyParentDirectory(path.dirname(wsbPath))
  } catch (error) {
    await handle?.close().catch(() => {})
    const cleanupTasks: Array<Promise<void>> = []
    if (temporaryCreated) {
      cleanupTasks.push(dependencies.rm(temporaryPath, { force: true }))
    }
    if (targetCreated) {
      cleanupTasks.push(dependencies.rm(wsbPath, { force: true }))
    }
    const cleanupResults = await Promise.allSettled(cleanupTasks)
    const cleanupFailure = cleanupResults.find(
      (result): result is PromiseRejectedResult => result.status === 'rejected'
    )
    if (cleanupFailure) {
      throw new Error(
        `Unable to clean up a key-bearing Windows Sandbox config after a secure write failure: ${formatErrorMessage(cleanupFailure.reason)}`,
        { cause: error }
      )
    }
    throw error
  }
}

export async function removeKeyBearingWsbFile(
  wsbPath: string,
  options: {
    rm?: typeof fs.rm
    exists?: (targetPath: string) => boolean
    wait?: (delayMs: number) => Promise<void>
  } = {}
): Promise<void> {
  const rm = options.rm || fs.rm.bind(fs)
  const exists = options.exists || existsSync
  const wait =
    options.wait ||
    ((delayMs: number) => new Promise<void>((resolve) => setTimeout(resolve, delayMs)))
  let lastError: unknown

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await rm(wsbPath, { force: true })
      if (!exists(wsbPath)) {
        return
      }
      lastError = new Error('file still exists after deletion')
    } catch (error) {
      lastError = error
    }
    if (attempt < 3) {
      await wait(100 * attempt)
    }
  }

  throw new Error(
    `Unable to remove key-bearing Windows Sandbox config '${wsbPath}': ${formatErrorMessage(lastError)}`
  )
}

export async function runProtectedWsbLifecycle<TPrepared, TReady, TProcess>(
  options: ProtectedWsbLifecycleOptions<TPrepared, TReady, TProcess>
): Promise<{ prepared: TPrepared; ready: TReady; process: TProcess }> {
  const verifyRestrictedAcl = options.verifyRestrictedAcl || verifyRestrictedWindowsAcl
  const verifyNotReparse = options.verifyNotReparse || verifyWindowsPathNotReparse
  let sandboxProcess: TProcess | undefined
  let result: { prepared: TPrepared; ready: TReady; process: TProcess } | undefined
  let lifecycleFailed = false
  let lifecycleError: unknown
  let cleanupError: unknown
  let terminationAttempted = false
  let terminationSignalAccepted = false
  let terminationConfirmed = false
  let terminationError: Error | undefined

  const terminateSandboxOnce = (): void => {
    if (!sandboxProcess) {
      terminationConfirmed = true
      return
    }
    if (options.isProcessTerminated?.(sandboxProcess)) {
      terminationConfirmed = true
      return
    }
    if (terminationAttempted) return
    terminationAttempted = true
    if (!options.killProcess) {
      terminationError = new Error('no Windows Sandbox termination callback was provided')
      return
    }
    try {
      terminationSignalAccepted = options.killProcess(sandboxProcess)
      if (!terminationSignalAccepted) {
        terminationError = new Error('Windows Sandbox process rejected the termination signal')
      }
    } catch (error) {
      terminationError = new Error(
        `Windows Sandbox termination callback failed: ${formatErrorMessage(error)}`
      )
    }
    terminationConfirmed = Boolean(options.isProcessTerminated?.(sandboxProcess))
  }

  try {
    // Re-verify the parent, leaf type, Windows attributes, and ACL immediately
    // before preparing the key-bearing file. None of these checks resets an ACL
    // after secret material exists.
    const sandboxRoot = path.dirname(options.sandboxDir)
    const workspaceRoot = path.dirname(sandboxRoot)
    await verifyNotReparse(workspaceRoot, true)
    await verifyRestrictedAcl(workspaceRoot, true)
    await verifyNotReparse(workspaceRoot, true)
    await verifyNotReparse(sandboxRoot, true)
    await verifyRestrictedAcl(sandboxRoot, true)
    await verifyNotReparse(sandboxRoot, true)
    await verifyNotReparse(options.sandboxDir, true)
    await verifyRestrictedAcl(options.sandboxDir, true)
    await verifyNotReparse(options.sandboxDir, true)
    const prepared = await options.prepareWsb()
    sandboxProcess = options.spawnSandbox(options.wsbPath)
    const ready = sandboxOperationContext.getStore()
      ? await runBoundedOperation(
          'Windows Sandbox lifecycle readiness',
          () => options.waitUntilReady(sandboxProcess as TProcess),
          MAX_OPERATION_TIMEOUT_MS
        )
      : await options.waitUntilReady(sandboxProcess)
    result = { prepared, ready, process: sandboxProcess }
  } catch (error) {
    lifecycleFailed = true
    lifecycleError = error
    terminateSandboxOnce()
  }

  try {
    await removeKeyBearingWsbFile(options.wsbPath)
  } catch (error) {
    cleanupError = error
    terminateSandboxOnce()
  }

  if (lifecycleFailed || cleanupError) {
    throw new ProtectedWsbLifecycleError<TProcess>({
      primaryError: lifecycleFailed ? lifecycleError : cleanupError,
      cleanupError: lifecycleFailed ? cleanupError : undefined,
      sandboxProcess,
      terminationAttempted,
      terminationSignalAccepted,
      terminationConfirmed,
      terminationError,
    })
  }
  if (!result) {
    throw new Error('Protected Windows Sandbox lifecycle completed without a result')
  }
  return result
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
  runtimeApiKey?: string
): Promise<WsbConfigDiagnostics> {
  const inboxDir = path.join(sandboxDir, 'inbox')
  const outboxDir = path.join(sandboxDir, 'outbox')
  const stagedRuntimeEntryHost = await stageRuntimeBundle(sandboxDir, runtimeEntryHost)
  const runtimeDirHost = path.dirname(stagedRuntimeEntryHost)
  const runtimeFileName = path.basename(stagedRuntimeEntryHost)
  const workersDirHost = await stageRuntimeWorkers(sandboxDir)
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
  await writeRestrictedWsbFile(wsbPath, wsb)

  const mappedFolders: NonNullable<HostAgentStartDiagnostics['mappedFolders']> = [
    {
      hostFolder: runtimeDirHost,
      sandboxFolder: 'C:\\rikune-runtime',
      readOnly: true,
      exists: existsSync(runtimeDirHost),
    },
    {
      hostFolder: workersDirHost,
      sandboxFolder: 'C:\\rikune-workers',
      readOnly: true,
      exists: existsSync(workersDirHost),
    },
    {
      hostFolder: inboxDir,
      sandboxFolder: 'C:\\rikune-inbox',
      readOnly: false,
      exists: existsSync(inboxDir),
    },
    {
      hostFolder: outboxDir,
      sandboxFolder: 'C:\\rikune-outbox',
      readOnly: false,
      exists: existsSync(outboxDir),
    },
    {
      hostFolder: path.dirname(hostNodePath),
      sandboxFolder: 'C:\\rikune-node',
      readOnly: true,
      exists: existsSync(path.dirname(hostNodePath)),
    },
    {
      hostFolder: nodeModulesDirHost,
      sandboxFolder: 'C:\\node_modules',
      readOnly: true,
      exists: existsSync(nodeModulesDirHost),
    },
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
    logonCommandSummary:
      'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <redacted>',
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
    startupLog: await readFilePreview(
      path.join(params.sandboxDir, 'outbox', 'runtime-startup.log')
    ),
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
  const snapshotName =
    typeof overrides.hypervSnapshotName === 'string'
      ? overrides.hypervSnapshotName.trim()
      : (process.env.HOST_AGENT_HYPERV_SNAPSHOT_NAME || '').trim()
  const endpoint = (
    process.env.HOST_AGENT_HYPERV_RUNTIME_ENDPOINT ||
    process.env.HOST_AGENT_HYPERV_ENDPOINT ||
    ''
  ).trim()
  const restoreOnStart =
    !!snapshotName &&
    (typeof overrides.hypervRestoreOnStart === 'boolean'
      ? overrides.hypervRestoreOnStart
      : readEnvFlag('HOST_AGENT_HYPERV_RESTORE_ON_START', true))
  const restoreOnRelease =
    !!snapshotName &&
    (typeof overrides.hypervRestoreOnRelease === 'boolean'
      ? overrides.hypervRestoreOnRelease
      : readEnvFlag('HOST_AGENT_HYPERV_RESTORE_ON_RELEASE', false))
  const stopOnRelease =
    typeof overrides.hypervStopOnRelease === 'boolean'
      ? overrides.hypervStopOnRelease
      : readEnvFlag('HOST_AGENT_HYPERV_STOP_ON_RELEASE', false)
  return { vmName, snapshotName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease }
}

async function getHyperVRuntimeStatus(): Promise<Record<string, unknown> | null> {
  if (HOST_AGENT_BACKEND !== 'hyperv-vm') {
    return null
  }

  const { vmName, snapshotName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease } =
    getHyperVConfig()

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
      error:
        process.platform !== 'win32'
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
    logger.warn({ err }, 'Failed to get Hyper-V runtime status')
    return {
      configured: true,
      vmName,
      endpoint: endpoint || null,
      snapshotName: snapshotName || null,
      restoreOnStart,
      restoreOnRelease,
      stopOnRelease,
      state: null,
      error: 'Failed to retrieve Hyper-V runtime status',
    }
  }
}

async function listHyperVCheckpoints(): Promise<{
  ok: boolean
  backend: 'hyperv-vm'
  vmName?: string
  checkpoints?: unknown[]
  error?: string
}> {
  const { vmName } = getHyperVConfig()
  if (process.platform !== 'win32') {
    return {
      ok: false,
      backend: 'hyperv-vm',
      vmName,
      error: 'Hyper-V checkpoint listing requires Windows platform',
    }
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
    logger.error(
      {
        vmName,
        error: err instanceof Error ? err.message : String(err),
      },
      'Failed to list Hyper-V checkpoints'
    )
    return {
      ok: false,
      backend: 'hyperv-vm',
      vmName,
      error: 'Failed to list Hyper-V checkpoints',
    }
  }
}

async function createHyperVCheckpoint(body: unknown): Promise<Record<string, unknown>> {
  const request = (body && typeof body === 'object' ? body : {}) as HyperVActionRequest
  const { vmName, endpoint, stopOnRelease } = getHyperVConfig()
  const rawSnapshotName = (request.snapshotName || '').trim()
  const snapshotName = rawSnapshotName || `rikune-${new Date().toISOString().replace(/[:.]/g, '-')}`
  if (process.platform !== 'win32') {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: 'Hyper-V checkpoint creation requires Windows platform',
    }
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
  const timeoutMs =
    typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)
      ? Math.max(1000, request.timeoutMs)
      : parseInt(process.env.HOST_AGENT_HYPERV_WAIT_TIMEOUT_MS || '120000', 10)
  const { runtimeApiKey, error: runtimeApiKeyConfigurationError } =
    getConfiguredRuntimeApiKey(request)

  if (process.platform !== 'win32') {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: 'Hyper-V checkpoint restore requires Windows platform',
    }
  }
  if (!vmName) {
    return { ok: false, backend: 'hyperv-vm', error: 'HOST_AGENT_HYPERV_VM_NAME is not configured' }
  }
  if (!snapshotName) {
    return {
      ok: false,
      backend: 'hyperv-vm',
      vmName,
      error: 'No snapshot name provided. Set HOST_AGENT_HYPERV_SNAPSHOT_NAME or pass snapshotName.',
    }
  }
  if (startAfterRestore && waitForRuntime && endpoint) {
    const runtimeAuthDefaultError =
      runtimeApiKeyConfigurationError || getRuntimeEndpointAuthDefaultError(runtimeApiKey, endpoint)
    if (runtimeAuthDefaultError) {
      return {
        ok: false,
        backend: 'hyperv-vm',
        vmName,
        endpoint: endpoint || null,
        error: runtimeAuthDefaultError,
      }
    }
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
    const runtimeReady =
      startAfterRestore && waitForRuntime && endpoint
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
      ...(runtimeReady === false
        ? { error: `Hyper-V runtime endpoint did not become healthy within timeout: ${endpoint}` }
        : {}),
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
  const deadlineAtMs = Date.now() + remainingOperationMs('Windows Sandbox readiness', timeoutMs)
  const operationSignal = sandboxOperationContext.getStore()?.controller.signal
  const interval = 1000

  while (Date.now() < deadlineAtMs && !operationSignal?.aborted) {
    try {
      const raw = await fs.readFile(readyFile, 'utf-8')
      const data = JSON.parse(raw) as { endpoint?: string; host?: string }
      if (data.endpoint && typeof data.endpoint === 'string') {
        return data
      }
      return { endpoint: 'http://127.0.0.1:18081', host: '127.0.0.1' }
    } catch {
      const delayMs = Math.max(1, Math.min(interval, deadlineAtMs - Date.now()))
      await new Promise((r) => setTimeout(r, delayMs))
    }
  }
  return null
}

interface WindowsSandboxTerminationAttempt {
  attempted: boolean
  signalAccepted: boolean
  error?: Error
}

function isWindowsSandboxProcessTerminated(sandboxProcess: ReturnType<typeof spawn>): boolean {
  return sandboxProcess.exitCode !== null || sandboxProcess.signalCode !== null
}

function requestWindowsSandboxTermination(
  sandboxProcess: ReturnType<typeof spawn>
): WindowsSandboxTerminationAttempt {
  if (isWindowsSandboxProcessTerminated(sandboxProcess)) {
    return { attempted: false, signalAccepted: false }
  }
  try {
    const signalAccepted = sandboxProcess.kill()
    return {
      attempted: true,
      signalAccepted,
      ...(signalAccepted
        ? {}
        : { error: new Error('Windows Sandbox process rejected the termination signal') }),
    }
  } catch (error) {
    return {
      attempted: true,
      signalAccepted: false,
      error: new Error(`Windows Sandbox termination callback failed: ${formatErrorMessage(error)}`),
    }
  }
}

async function waitForWindowsSandboxTermination(
  sandboxProcess: ReturnType<typeof spawn>
): Promise<boolean> {
  if (isWindowsSandboxProcessTerminated(sandboxProcess)) return true
  const timeoutMs = remainingOperationMs(
    'Windows Sandbox process termination',
    START_CLEANUP_TIMEOUT_MS
  )
  const operationSignal = sandboxOperationContext.getStore()?.controller.signal
  return new Promise((resolve) => {
    let settled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const finish = (confirmed: boolean): void => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      sandboxProcess.off('exit', onExit)
      operationSignal?.removeEventListener('abort', onAbort)
      resolve(confirmed)
    }
    const onExit = (): void => finish(true)
    const onAbort = (): void => finish(isWindowsSandboxProcessTerminated(sandboxProcess))
    sandboxProcess.once('exit', onExit)
    operationSignal?.addEventListener('abort', onAbort, { once: true })
    timer = setTimeout(() => finish(isWindowsSandboxProcessTerminated(sandboxProcess)), timeoutMs)
    if (isWindowsSandboxProcessTerminated(sandboxProcess)) finish(true)
  })
}

async function proveWindowsSandboxTermination(
  sandboxProcess: ReturnType<typeof spawn>,
  existingAttempt?: WindowsSandboxTerminationAttempt
): Promise<{ confirmed: boolean; error?: Error }> {
  if (isWindowsSandboxProcessTerminated(sandboxProcess)) return { confirmed: true }
  const attempt = existingAttempt || requestWindowsSandboxTermination(sandboxProcess)
  const confirmed = await waitForWindowsSandboxTermination(sandboxProcess)
  if (confirmed) return { confirmed: true }
  return {
    confirmed: false,
    error:
      attempt.error ||
      new Error(
        attempt.signalAccepted
          ? 'Windows Sandbox process did not exit after accepting the termination signal'
          : 'Windows Sandbox process termination was not confirmed'
      ),
  }
}

function runNetshCommand(args: string[]): Promise<WindowsCommandResult> {
  const timeoutMs = remainingOperationMs('netsh command')
  const signal = sandboxOperationContext.getStore()?.controller.signal
  return new Promise((resolve, reject) => {
    execFile(
      'netsh',
      args,
      { windowsHide: true, timeout: timeoutMs, signal },
      (error, stdout, stderr) => {
        const result = {
          stdout: stdout?.toString() || '',
          stderr: stderr?.toString() || '',
        }
        if (error) {
          reject(
            Object.assign(
              new Error(`netsh ${args.join(' ')} failed: ${result.stderr.trim() || error.message}`),
              result
            )
          )
          return
        }
        resolve(result)
      }
    )
  })
}

function createBoundedNetshRunner(options: PortProxyCommandOptions): NetshCommandRunner {
  const rawRunNetsh = options.runNetsh || runNetshCommand
  const commandTimeoutMs =
    typeof options.commandTimeoutMs === 'number' &&
    Number.isSafeInteger(options.commandTimeoutMs) &&
    options.commandTimeoutMs > 0
      ? options.commandTimeoutMs
      : EXTERNAL_COMMAND_TIMEOUT_MS
  return (args) =>
    runBoundedOperation(
      `netsh ${args.slice(0, 4).join(' ')} command`,
      () => rawRunNetsh(args),
      commandTimeoutMs
    )
}

function parsePortNumber(raw: string): number | null {
  if (!/^\d{1,5}$/u.test(raw)) {
    return null
  }
  const value = Number(raw)
  return Number.isInteger(value) && value >= 1 && value <= 65_535 ? value : null
}

export function parsePortProxyRows(output: string): PortProxyRow[] {
  const rows: PortProxyRow[] = []
  for (const line of output.split(/\r?\n/u)) {
    const fields = line.trim().split(/\s+/u)
    if (fields.length !== 4) {
      continue
    }
    const [listenAddress, rawListenPort, connectAddress, rawConnectPort] = fields
    const listenPort = rawListenPort ? parsePortNumber(rawListenPort) : null
    const connectPort = rawConnectPort ? parsePortNumber(rawConnectPort) : null
    if (
      !listenAddress ||
      !connectAddress ||
      net.isIP(listenAddress) !== 4 ||
      net.isIP(connectAddress) !== 4 ||
      listenPort === null ||
      connectPort === null
    ) {
      continue
    }
    rows.push({ listenAddress, listenPort, connectAddress, connectPort })
  }
  return rows
}

function parseVerifiedPortProxyRows(output: string): PortProxyRow[] {
  const rows = parsePortProxyRows(output)
  const tableSeparator = output
    .split(/\r?\n/u)
    .some((line) => /^\s*-{3,}\s+-{3,}\s+-{3,}\s+-{3,}\s*$/u.test(line))
  if (output.trim().length > 0 && rows.length === 0 && !tableSeparator) {
    throw new Error('Unable to parse netsh portproxy show v4tov4 output')
  }
  return rows
}

function matchingPortProxyListeners(
  output: string,
  listenPort: number,
  listenAddress: string
): PortProxyRow[] {
  const rows = parseVerifiedPortProxyRows(output)
  return rows.filter((row) => row.listenPort === listenPort && row.listenAddress === listenAddress)
}

export async function removePortProxy(
  listenPort: number,
  listenAddress: string,
  options: PortProxyCommandOptions = {}
): Promise<void> {
  const runNetsh = createBoundedNetshRunner(options)
  const maxAttempts = Math.max(1, options.maxAttempts || 3)
  const wait =
    options.wait ||
    ((delayMs: number) => new Promise<void>((resolve) => setTimeout(resolve, delayMs)))
  let lastError: unknown

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let deleteError: unknown
    try {
      await runNetsh([
        'interface',
        'portproxy',
        'delete',
        'v4tov4',
        `listenport=${listenPort}`,
        `listenaddress=${listenAddress}`,
      ])
    } catch (error) {
      deleteError = error
    }

    try {
      const shown = await runNetsh(['interface', 'portproxy', 'show', 'v4tov4'])
      const remaining = matchingPortProxyListeners(shown.stdout, listenPort, listenAddress)
      if (remaining.length === 0) {
        return
      }
      lastError = new Error(
        `netsh portproxy rule ${listenAddress}:${listenPort} still exists after deletion${deleteError ? ` (${formatErrorMessage(deleteError)})` : ''}`
      )
    } catch (error) {
      lastError = error
    }

    if (attempt < maxAttempts) {
      await wait(100 * attempt)
    }
  }

  throw new Error(
    `Unable to remove and verify netsh portproxy rule ${listenAddress}:${listenPort}: ${formatErrorMessage(lastError)}`
  )
}

function isSafelyAttributableStaleRikuneRule(row: PortProxyRow): boolean {
  return (
    row.listenPort >= LISTEN_PORT_MIN &&
    row.listenPort <= LISTEN_PORT_MAX &&
    row.connectPort === RUNTIME_INTERNAL_PORT &&
    isRfc1918Ipv4(row.connectAddress) &&
    (row.listenAddress === '0.0.0.0' || isLoopbackHost(row.listenAddress))
  )
}

export async function reconcileStaleRikunePortProxyRules(
  options: PortProxyCommandOptions = {}
): Promise<void> {
  const runNetsh = createBoundedNetshRunner(options)
  let shown = await runNetsh(['interface', 'portproxy', 'show', 'v4tov4'])
  const reservedRows = parseVerifiedPortProxyRows(shown.stdout).filter(
    (row) => row.listenPort >= LISTEN_PORT_MIN && row.listenPort <= LISTEN_PORT_MAX
  )
  const unknownRows = reservedRows.filter((row) => !isSafelyAttributableStaleRikuneRule(row))
  if (unknownRows.length > 0) {
    const observed = unknownRows
      .map(
        (row) => `${row.listenAddress}:${row.listenPort}->${row.connectAddress}:${row.connectPort}`
      )
      .join(', ')
    throw new Error(
      `Reserved Rikune runtime ports contain portproxy listeners of unknown ownership: ${observed}`
    )
  }

  for (const staleRule of reservedRows) {
    logger.warn(
      {
        listenPort: staleRule.listenPort,
        staleListenAddress: staleRule.listenAddress,
        connectAddress: staleRule.connectAddress,
        connectPort: staleRule.connectPort,
      },
      'Removing a stale Rikune portproxy during Host Agent startup reconciliation'
    )
    await removePortProxy(staleRule.listenPort, staleRule.listenAddress, {
      ...options,
      runNetsh,
    })
  }

  shown = await runNetsh(['interface', 'portproxy', 'show', 'v4tov4'])
  const remainingReservedRows = parseVerifiedPortProxyRows(shown.stdout).filter(
    (row) => row.listenPort >= LISTEN_PORT_MIN && row.listenPort <= LISTEN_PORT_MAX
  )
  if (remainingReservedRows.length > 0) {
    throw new Error('Reserved Rikune runtime ports still contain portproxy listeners after cleanup')
  }
}

function ensureStalePortProxyReconciliation(): Promise<void> {
  stalePortProxyReconciliation ||= reconcileStaleRikunePortProxyRules()
  return stalePortProxyReconciliation
}

export async function removePortProxyAndAuditPort(
  listenPort: number,
  listenAddress: string,
  safeConnectAddress: string | undefined,
  options: PortProxyCommandOptions = {}
): Promise<void> {
  const runNetsh = createBoundedNetshRunner(options)
  let shown = await runNetsh(['interface', 'portproxy', 'show', 'v4tov4'])
  const samePortListeners = parseVerifiedPortProxyRows(shown.stdout).filter(
    (row) => row.listenPort === listenPort
  )
  const safelyAttributableExactListeners = samePortListeners.filter(
    (row) =>
      safeConnectAddress !== undefined &&
      row.listenAddress === listenAddress &&
      row.connectAddress === safeConnectAddress &&
      row.connectPort === RUNTIME_INTERNAL_PORT
  )
  const safelyAttributableBroadListeners = samePortListeners.filter(
    (row) =>
      safeConnectAddress !== undefined &&
      isLoopbackHost(listenAddress) &&
      row.listenAddress === '0.0.0.0' &&
      row.connectAddress === safeConnectAddress &&
      row.connectPort === RUNTIME_INTERNAL_PORT
  )
  const safeListeners = new Set([
    ...safelyAttributableExactListeners,
    ...safelyAttributableBroadListeners,
  ])
  const unsafeListeners = samePortListeners.filter((row) => !safeListeners.has(row))
  if (unsafeListeners.length > 0) {
    const observed = unsafeListeners
      .map(
        (row) => `${row.listenAddress}:${row.listenPort}->${row.connectAddress}:${row.connectPort}`
      )
      .join(', ')
    throw new Error(
      `Port ${listenPort} has non-exact netsh portproxy listeners that cannot be safely attributed to Rikune: ${observed}`
    )
  }

  const safeListenAddresses = new Set(
    [...safelyAttributableExactListeners, ...safelyAttributableBroadListeners].map(
      (row) => row.listenAddress
    )
  )
  for (const staleListenAddress of safeListenAddresses) {
    logger.warn(
      {
        listenPort,
        staleListenAddress,
        connectAddress: safeConnectAddress,
        connectPort: RUNTIME_INTERNAL_PORT,
      },
      'Removing a verified Rikune portproxy before enforcing an empty-port contract'
    )
    await removePortProxy(listenPort, staleListenAddress, { ...options, runNetsh })
  }

  shown = await runNetsh(['interface', 'portproxy', 'show', 'v4tov4'])
  const remainingListeners = parseVerifiedPortProxyRows(shown.stdout).filter(
    (row) => row.listenPort === listenPort
  )
  if (remainingListeners.length > 0) {
    const observed = remainingListeners
      .map(
        (row) => `${row.listenAddress}:${row.listenPort}->${row.connectAddress}:${row.connectPort}`
      )
      .join(', ')
    throw new Error(
      `Port ${listenPort} retains non-exact netsh portproxy listeners after cleanup: ${observed}`
    )
  }
}

export async function addPortProxy(
  sandboxIp: string,
  listenPort: number,
  listenAddress: string,
  options: PortProxyCommandOptions = {}
): Promise<void> {
  if (net.isIP(sandboxIp) !== 4 || net.isIP(listenAddress) !== 4) {
    throw new Error('netsh v4tov4 requires exact IPv4 listen and connect addresses')
  }
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65_535) {
    throw new Error(`Invalid netsh portproxy listen port '${listenPort}'`)
  }
  if (!isLoopbackHost(listenAddress)) {
    logger.warn(
      { listenAddress },
      'netsh portproxy is binding to a non-loopback interface. Ensure Runtime Node API key is configured.'
    )
  }
  const runNetsh = createBoundedNetshRunner(options)

  // Remove any stale listener first, clean only broad rules that are exactly
  // attributable to this runtime target, and prove the whole port is empty.
  await removePortProxyAndAuditPort(listenPort, listenAddress, sandboxIp, {
    ...options,
    runNetsh,
  })

  try {
    await runNetsh([
      'interface',
      'portproxy',
      'add',
      'v4tov4',
      `listenport=${listenPort}`,
      `listenaddress=${listenAddress}`,
      `connectaddress=${sandboxIp}`,
      `connectport=${RUNTIME_INTERNAL_PORT}`,
    ])
    const shown = await runNetsh(['interface', 'portproxy', 'show', 'v4tov4'])
    const allListeners = parseVerifiedPortProxyRows(shown.stdout).filter(
      (row) => row.listenPort === listenPort
    )
    const listeners = allListeners.filter((row) => row.listenAddress === listenAddress)
    if (
      allListeners.length !== 1 ||
      listeners.length !== 1 ||
      listeners[0]?.connectAddress !== sandboxIp ||
      listeners[0]?.connectPort !== RUNTIME_INTERNAL_PORT
    ) {
      throw new Error(
        `netsh portproxy exact readback mismatch for ${listenAddress}:${listenPort} -> ${sandboxIp}:${RUNTIME_INTERNAL_PORT}`
      )
    }
  } catch (error) {
    const cleanupFailures: string[] = []
    try {
      // The port was proven empty immediately before this add attempt, so the
      // exact listener key is attributable to this attempt even when its
      // connect-side readback is malformed or unexpectedly changed.
      await removePortProxy(listenPort, listenAddress, { ...options, runNetsh })
    } catch (removeError) {
      cleanupFailures.push(formatErrorMessage(removeError))
    }
    try {
      await removePortProxyAndAuditPort(listenPort, listenAddress, sandboxIp, {
        ...options,
        runNetsh,
      })
    } catch (removeError) {
      cleanupFailures.push(formatErrorMessage(removeError))
    }
    throw new Error(
      `Unable to add and verify netsh portproxy rule ${listenAddress}:${listenPort}: ${formatErrorMessage(error)}${cleanupFailures.length > 0 ? `; cleanup failed: ${cleanupFailures.join('; ')}` : ''}`,
      { cause: error }
    )
  }
}

export async function removeSandboxDir(sandboxDir: string, reason: string): Promise<void> {
  const sandboxRoot = path.dirname(sandboxDir)
  const workspaceRoot = path.dirname(sandboxRoot)
  await verifyRestrictedSandboxDirectoryForSecretWrite(workspaceRoot)
  await verifyRestrictedSandboxDirectoryForSecretWrite(sandboxRoot)
  await verifyRestrictedSandboxDirectoryForSecretWrite(sandboxDir)

  const wsbPath = path.join(sandboxDir, 'runtime.wsb')
  try {
    await removeKeyBearingWsbFile(wsbPath)
  } catch (error) {
    // Diagnostics retention must never retain the bearer key. If the focused
    // delete fails, remove the whole workspace regardless of KEEP_FAILED.
    await verifyRestrictedSandboxDirectoryForSecretWrite(sandboxDir)
    await fs.rm(sandboxDir, { recursive: true, force: true }).catch(() => {})
    if (existsSync(wsbPath)) {
      throw error
    }
    return
  }

  if (/^(1|true|yes|on)$/i.test(process.env.HOST_AGENT_KEEP_FAILED_SANDBOX || '')) {
    logger.warn(
      { sandboxDir, reason },
      'Keeping failed sandbox workspace for diagnostics after removing runtime.wsb'
    )
    return
  }

  let lastError: unknown
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await verifyRestrictedSandboxDirectoryForSecretWrite(sandboxDir)
      await fs.rm(sandboxDir, { recursive: true, force: true })
      if (!existsSync(sandboxDir)) {
        return
      }
      lastError = new Error('workspace still exists after deletion')
    } catch (err) {
      lastError = err
      logger.warn({ err, sandboxDir, attempt, reason }, 'Failed to remove sandbox workspace')
    }
    if (attempt < 3) {
      await new Promise((resolve) => setTimeout(resolve, 500 * attempt))
    }
  }
  throw new Error(
    `Unable to remove Windows Sandbox workspace '${sandboxDir}' after 3 attempts: ${formatErrorMessage(lastError)}`
  )
}

async function startHyperVRuntime(body: unknown): Promise<StartSandboxResult> {
  if (process.platform !== 'win32') {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: 'Hyper-V runtime backend requires Windows platform',
    }
  }

  const request = (body && typeof body === 'object' ? body : {}) as StartSandboxRequest
  const { requestId, error: requestIdError } = resolveSandboxStartRequestId(request.requestId)
  if (requestIdError || !requestId) {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: requestIdError || 'Unable to assign a requestId to /sandbox/start',
    }
  }
  const timeoutMs =
    typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)
      ? Math.max(1000, request.timeoutMs)
      : parseInt(process.env.HOST_AGENT_HYPERV_WAIT_TIMEOUT_MS || '120000', 10)
  const { runtimeApiKey, error: runtimeApiKeyConfigurationError } =
    getConfiguredRuntimeApiKey(request)

  const { vmName, snapshotName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease } =
    getHyperVConfig(request)
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
  try {
    assertTrustedHttpEndpoint(endpoint, { label: 'HOST_AGENT_HYPERV_RUNTIME_ENDPOINT' })
  } catch (err) {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: err instanceof Error ? err.message : String(err),
      diagnostics: buildHyperVDiagnostics({ vmName, snapshotName, endpoint }),
    }
  }
  const runtimeAuthDefaultError =
    runtimeApiKeyConfigurationError || getRuntimeEndpointAuthDefaultError(runtimeApiKey, endpoint)
  if (runtimeAuthDefaultError) {
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: runtimeAuthDefaultError,
      diagnostics: buildHyperVDiagnostics({ vmName, snapshotName, endpoint }),
    }
  }

  let cleanupSandboxId: string | undefined
  const trackHyperVForCleanup = (): string => {
    if (cleanupSandboxId) return cleanupSandboxId
    cleanupSandboxId = `hyperv-${randomUUID()}`
    const runtimeHost = (() => {
      try {
        return new URL(endpoint).hostname
      } catch {
        return endpoint
      }
    })()
    activeSandboxes.set(cleanupSandboxId, {
      backend: 'hyperv-vm',
      sandboxId: cleanupSandboxId,
      requestId,
      endpoint,
      runtimeHost,
      listenPort: 0,
      hypervVmName: vmName,
      hypervSnapshotName: snapshotName || undefined,
      hypervRestoreOnRelease: restoreOnRelease,
      hypervStopOnRelease: stopOnRelease,
    })
    return cleanupSandboxId
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
      logger.warn(
        { stderr: result.stderr.trim(), vmName },
        'Hyper-V backend command wrote to stderr'
      )
    }
  } catch (err) {
    const details = err as Error & { stdout?: string; stderr?: string }
    if (restoreOnRelease || stopOnRelease) {
      trackHyperVForCleanup()
    }
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
    if (restoreOnRelease || stopOnRelease) {
      trackHyperVForCleanup()
    }
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: `Hyper-V runtime endpoint did not become healthy within timeout: ${endpoint}`,
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        restoreOnStart,
        restoreOnRelease,
        stopOnRelease,
      }),
    }
  }

  try {
    assertSandboxStartCanRegister(requestId)
  } catch (error) {
    trackHyperVForCleanup()
    return {
      ok: false,
      backend: 'hyperv-vm',
      error: formatErrorMessage(error),
      diagnostics: buildHyperVDiagnostics({
        vmName,
        snapshotName,
        endpoint,
        restoreOnStart,
        restoreOnRelease,
        stopOnRelease,
      }),
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
    requestId,
    endpoint,
    runtimeHost,
    listenPort: 0,
    hypervVmName: vmName,
    hypervSnapshotName: snapshotName || undefined,
    hypervRestoreOnRelease: restoreOnRelease,
    hypervStopOnRelease: stopOnRelease,
  })

  logger.info(
    { sandboxId, requestId, vmName, endpoint, restoreOnStart, restoreOnRelease, stopOnRelease },
    'Hyper-V runtime connected'
  )
  return {
    ok: true,
    endpoint,
    sandboxId,
    requestId,
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

async function startSandbox(body: unknown): Promise<StartSandboxResult> {
  if (HOST_AGENT_BACKEND === 'hyperv-vm') {
    return startHyperVRuntime(body)
  }

  if (process.platform !== 'win32') {
    return { ok: false, error: 'Windows Host Agent requires Windows platform' }
  }

  const request = (body && typeof body === 'object' ? body : {}) as StartSandboxRequest
  const { requestId, error: requestIdError } = resolveSandboxStartRequestId(request.requestId)
  if (requestIdError || !requestId) {
    return {
      ok: false,
      backend: 'windows-sandbox',
      error: requestIdError || 'Unable to assign a requestId to /sandbox/start',
    }
  }
  const timeoutMs =
    typeof request.timeoutMs === 'number' && Number.isFinite(request.timeoutMs)
      ? Math.max(1000, request.timeoutMs)
      : 60000
  const { runtimeApiKey, error: runtimeApiKeyConfigurationError } =
    getConfiguredRuntimeApiKey(request)
  const runtimeAuthDefaultError =
    runtimeApiKeyConfigurationError || getSandboxRuntimeAuthDefaultError(runtimeApiKey)
  if (runtimeAuthDefaultError) {
    return { ok: false, error: runtimeAuthDefaultError }
  }
  try {
    await ensureStalePortProxyReconciliation()
  } catch (error) {
    return {
      ok: false,
      backend: 'windows-sandbox',
      error: `Unable to reconcile reserved Rikune runtime portproxy rules: ${formatErrorMessage(error)}`,
    }
  }
  const listenPort = await allocateListenPort()
  if (listenPort === null) {
    return { ok: false, error: 'No available listen port for new Sandbox runtime' }
  }

  const workspaceRoot =
    process.env.HOST_AGENT_WORKSPACE || path.join(os.tmpdir(), 'rikune-host-agent')
  const sandboxRoot = path.join(workspaceRoot, 'sandbox')
  let sandboxDir: string
  try {
    await fs.mkdir(workspaceRoot, { recursive: true })
    await verifyWindowsPathNotReparse(workspaceRoot, true)
    await applyRestrictedWindowsAcl(workspaceRoot, true)
    await verifyWindowsPathNotReparse(workspaceRoot, true)
    await verifyRestrictedWindowsAcl(workspaceRoot, true)
    await ensureRestrictedSandboxRoot(sandboxRoot)
    sandboxDir = await createUniqueRestrictedSandboxWorkspace(sandboxRoot)
  } catch (error) {
    releaseListenPort(listenPort)
    return {
      ok: false,
      backend: 'windows-sandbox',
      error: `Unable to create a restricted Windows Sandbox workspace: ${(error as Error).message}`,
    }
  }

  const runtimeEntryHost = path.join(projectRoot, 'packages', 'runtime-node', 'dist', 'index.js')
  const workersDirHost = path.join(projectRoot, 'workers')
  const nodeModulesDirHost = path.join(projectRoot, 'node_modules')
  const sharedDistEntryHost = path.join(projectRoot, 'packages', 'shared', 'dist', 'index.js')
  const requiredPaths = [
    { name: 'runtimeEntryHost', path: runtimeEntryHost, exists: existsSync(runtimeEntryHost) },
    { name: 'workersDirHost', path: workersDirHost, exists: existsSync(workersDirHost) },
    {
      name: 'nodeModulesDirHost',
      path: nodeModulesDirHost,
      exists: existsSync(nodeModulesDirHost),
    },
    {
      name: 'sharedDistEntryHost',
      path: sharedDistEntryHost,
      exists: existsSync(sharedDistEntryHost),
    },
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
  let sandboxExit: { code: number | null; signal: NodeJS.Signals | null } | null = null
  let sandboxLaunchError: Error | null = null
  let cleanupSandboxId: string | undefined
  const trackWindowsSandboxForCleanup = (
    sandboxProcess: ReturnType<typeof spawn> | undefined,
    runtimeHost = '127.0.0.1'
  ): string => {
    if (cleanupSandboxId) return cleanupSandboxId
    cleanupSandboxId = randomUUID()
    activeSandboxes.set(cleanupSandboxId, {
      backend: 'windows-sandbox',
      sandboxId: cleanupSandboxId,
      requestId,
      sandboxDir,
      wsbPath,
      process: sandboxProcess,
      endpoint: `http://${formatRuntimeEndpointHost(RUNTIME_ADVERTISED_HOST)}:${listenPort}`,
      runtimeHost,
      listenPort,
      runtimeProxyHost: RUNTIME_PROXY_BIND_HOST,
    })
    return cleanupSandboxId
  }
  const cleanupFailedWindowsSandboxStart = async (params: {
    sandboxProcess?: ReturnType<typeof spawn>
    runtimeHost?: string
    terminationAttempt?: WindowsSandboxTerminationAttempt
    terminationConfirmed?: boolean
    reason: string
  }): Promise<string[]> => {
    const cleanupFailures: string[] = []
    let terminationConfirmed = Boolean(params.terminationConfirmed || !params.sandboxProcess)
    try {
      await runWithStartCleanupBudget(requestId, async () => {
        if (params.sandboxProcess && !terminationConfirmed) {
          const termination = await proveWindowsSandboxTermination(
            params.sandboxProcess,
            params.terminationAttempt
          )
          terminationConfirmed = termination.confirmed
          if (!termination.confirmed) {
            cleanupFailures.push(
              `sandbox process termination failed: ${formatErrorMessage(termination.error)}`
            )
          }
        }
        if (terminationConfirmed) {
          try {
            await removeSandboxDir(sandboxDir, params.reason)
          } catch (removeError) {
            cleanupFailures.push(`workspace cleanup failed: ${formatErrorMessage(removeError)}`)
          }
        }
      })
    } catch (cleanupError) {
      cleanupFailures.push(`cleanup deadline failed: ${formatErrorMessage(cleanupError)}`)
    }
    if (cleanupFailures.length === 0) {
      releaseListenPort(listenPort)
    } else {
      trackWindowsSandboxForCleanup(params.sandboxProcess, params.runtimeHost)
    }
    return cleanupFailures
  }
  let resolveLaunchFailure: (value: null) => void = () => {}
  const launchFailure = new Promise<null>((resolve) => {
    resolveLaunchFailure = resolve
  })
  let lifecycle: {
    prepared: WsbConfigDiagnostics
    ready: { endpoint?: string; host?: string } | null
    process: ReturnType<typeof spawn>
  }

  try {
    lifecycle = await runProtectedWsbLifecycle({
      sandboxDir,
      wsbPath,
      prepareWsb: () => writeWsbConfig(wsbPath, sandboxDir, runtimeEntryHost, runtimeApiKey),
      spawnSandbox: (protectedWsbPath) => {
        logger.info(
          { sandboxDir, wsbPath: protectedWsbPath, listenPort },
          'Launching Windows Sandbox via Host Agent'
        )
        const child = spawn('C:\\Windows\\System32\\WindowsSandbox.exe', [protectedWsbPath], {
          detached: true,
          windowsHide: true,
          stdio: 'ignore',
        })
        child.once('error', (error) => {
          sandboxLaunchError = error
          resolveLaunchFailure(null)
        })
        child.once('exit', (code, signal) => {
          sandboxExit = { code, signal }
          logger.warn(
            { sandboxDir, wsbPath: protectedWsbPath, code, signal },
            'Windows Sandbox process exited before runtime readiness was confirmed'
          )
        })
        return child
      },
      waitUntilReady: () =>
        Promise.race([waitForRuntimeReady(sandboxDir, timeoutMs), launchFailure]),
      killProcess: (child) => child.kill(),
      isProcessTerminated: isWindowsSandboxProcessTerminated,
    })
  } catch (error) {
    const protectedFailure =
      error instanceof ProtectedWsbLifecycleError
        ? (error as ProtectedWsbLifecycleError<ReturnType<typeof spawn>>)
        : undefined
    const diagnostics = await collectWindowsSandboxDiagnostics({
      sandboxDir,
      wsbPath,
      timeoutMs,
      listenPort,
      sandboxExit,
    })
    const cleanupFailures = await cleanupFailedWindowsSandboxStart({
      sandboxProcess: protectedFailure?.sandboxProcess,
      terminationConfirmed: protectedFailure?.terminationConfirmed,
      terminationAttempt: protectedFailure?.terminationAttempted
        ? {
            attempted: true,
            signalAccepted: protectedFailure.terminationSignalAccepted,
            error: protectedFailure.terminationError,
          }
        : undefined,
      reason: 'sandbox_launch_failed',
    })
    return {
      ok: false,
      backend: 'windows-sandbox',
      error:
        `Unable to launch Windows Sandbox with a protected config: ${formatErrorMessage(error)}` +
        (cleanupFailures.length > 0 ? ` Cleanup failures: ${cleanupFailures.join('; ')}` : ''),
      diagnostics,
    }
  }

  const { prepared: wsbDiagnostics, process: sandboxProcess, ready } = lifecycle
  if (!ready || !ready.host) {
    const diagnostics = await collectWindowsSandboxDiagnostics({
      sandboxDir,
      wsbPath,
      timeoutMs,
      listenPort,
      wsbDiagnostics,
      sandboxExit,
    })
    const cleanupFailures = await cleanupFailedWindowsSandboxStart({
      sandboxProcess,
      reason: 'runtime_not_ready',
    })
    const exitDetail = sandboxExit
      ? ` WindowsSandbox.exe exited with code=${sandboxExit.code ?? 'null'} signal=${sandboxExit.signal ?? 'null'}.`
      : ''
    const launchDetail = sandboxLaunchError
      ? ` WindowsSandbox.exe failed to launch: ${sandboxLaunchError.message}.`
      : ''
    return {
      ok: false,
      error:
        `Sandbox runtime did not become ready within timeout.${exitDetail}${launchDetail} ` +
        `wsbPath=${wsbPath}` +
        (cleanupFailures.length > 0 ? ` Cleanup failures: ${cleanupFailures.join('; ')}` : ''),
      diagnostics,
    }
  }

  try {
    await addPortProxy(ready.host, listenPort, RUNTIME_PROXY_BIND_HOST)
    assertSandboxStartCanRegister(requestId)
  } catch (error) {
    const cleanupFailures: string[] = []
    const diagnostics = await collectWindowsSandboxDiagnostics({
      sandboxDir,
      wsbPath,
      timeoutMs,
      listenPort,
      wsbDiagnostics,
      sandboxExit,
    })
    try {
      await runWithStartCleanupBudget(requestId, async () => {
        const termination = await proveWindowsSandboxTermination(sandboxProcess)
        if (!termination.confirmed) {
          cleanupFailures.push(
            `sandbox process termination failed: ${formatErrorMessage(termination.error)}`
          )
        }
        try {
          await removePortProxyAndAuditPort(listenPort, RUNTIME_PROXY_BIND_HOST, ready.host)
        } catch (removeError) {
          cleanupFailures.push(`portproxy cleanup failed: ${formatErrorMessage(removeError)}`)
        }
        if (termination.confirmed) {
          try {
            await removeSandboxDir(sandboxDir, 'portproxy_setup_failed')
          } catch (removeError) {
            cleanupFailures.push(`workspace cleanup failed: ${formatErrorMessage(removeError)}`)
          }
        }
      })
    } catch (cleanupError) {
      cleanupFailures.push(`cleanup deadline failed: ${formatErrorMessage(cleanupError)}`)
    }
    if (cleanupFailures.length === 0) {
      releaseListenPort(listenPort)
    } else {
      const failedSandboxId = randomUUID()
      activeSandboxes.set(failedSandboxId, {
        backend: 'windows-sandbox',
        sandboxId: failedSandboxId,
        requestId,
        sandboxDir,
        wsbPath,
        process: sandboxProcess,
        endpoint: `http://${formatRuntimeEndpointHost(RUNTIME_ADVERTISED_HOST)}:${listenPort}`,
        runtimeHost: ready.host,
        listenPort,
        runtimeProxyHost: RUNTIME_PROXY_BIND_HOST,
      })
    }
    logger.error(
      { error, cleanupFailures, listenPort, listenAddress: RUNTIME_PROXY_BIND_HOST },
      'Failed to add and verify portproxy; Sandbox start was rolled back'
    )
    return {
      ok: false,
      backend: 'windows-sandbox',
      error:
        `Unable to add and verify the Windows Sandbox portproxy: ${formatErrorMessage(error)}` +
        (cleanupFailures.length > 0 ? ` Cleanup failures: ${cleanupFailures.join('; ')}` : ''),
      diagnostics,
    }
  }

  const endpoint = `http://${formatRuntimeEndpointHost(RUNTIME_ADVERTISED_HOST)}:${listenPort}`
  const sandboxId = randomUUID()

  activeSandboxes.set(sandboxId, {
    backend: 'windows-sandbox',
    sandboxId,
    requestId,
    sandboxDir,
    wsbPath,
    process: sandboxProcess,
    endpoint,
    runtimeHost: ready.host,
    listenPort,
    runtimeProxyHost: RUNTIME_PROXY_BIND_HOST,
  })

  logger.info(
    {
      sandboxId,
      requestId,
      endpoint,
      runtimeHost: ready.host,
      listenPort,
      runtimeProxyHost: RUNTIME_PROXY_BIND_HOST,
      runtimeAdvertisedHost: RUNTIME_ADVERTISED_HOST,
    },
    'Sandbox started and portproxied'
  )
  return { ok: true, endpoint, sandboxId, requestId, backend: 'windows-sandbox' }
}

async function startSandboxWithDeadline(body: unknown): Promise<StartSandboxResult> {
  const request = (body && typeof body === 'object' ? body : {}) as StartSandboxRequest
  const { requestId, error: requestIdError } = resolveSandboxStartRequestId(request.requestId)
  if (requestIdError || !requestId) {
    return { ok: false, error: requestIdError || 'Unable to assign a requestId to /sandbox/start' }
  }
  const existing = Array.from(activeSandboxes.values()).find(
    (sandbox) => sandbox.requestId === requestId
  )
  if (existing) {
    return {
      ok: true,
      requestId,
      sandboxId: existing.sandboxId,
      endpoint: existing.endpoint,
      backend: existing.backend,
    }
  }
  if (pendingSandboxStarts.has(requestId)) {
    return { ok: false, error: `Sandbox start request ${requestId} is already pending` }
  }
  if (settledSandboxStarts.has(requestId)) {
    return { ok: false, error: `Sandbox start request ${requestId} has already settled` }
  }

  const fallbackTimeoutMs =
    HOST_AGENT_BACKEND === 'hyperv-vm'
      ? normalizeServerDeadlineMs(
          Number.parseInt(process.env.HOST_AGENT_HYPERV_WAIT_TIMEOUT_MS || '120000', 10),
          120_000
        )
      : 60_000
  const timeoutMs = normalizeServerDeadlineMs(request.timeoutMs, fallbackTimeoutMs)
  return runSandboxStartDeadlineGuard(requestId, timeoutMs, () =>
    startSandbox({ ...request, requestId, timeoutMs })
  )
}

function getSandboxStartCorrelationStatus(requestId: string): Record<string, unknown> {
  const pending = pendingSandboxStarts.get(requestId)
  if (pending) {
    return {
      ok: true,
      requestId,
      state: 'pending',
      deadlineAtMs: pending.deadlineAtMs,
    }
  }
  const active = Array.from(activeSandboxes.values()).find(
    (sandbox) => sandbox.requestId === requestId
  )
  if (active) {
    return {
      ok: true,
      requestId,
      state: 'active',
      sandboxId: active.sandboxId,
      backend: active.backend,
    }
  }
  return {
    ok: true,
    requestId,
    state: settledSandboxStarts.has(requestId) ? 'settled' : 'unknown',
  }
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
        const error = `Hyper-V cleanup failed: ${formatErrorMessage(err)}`
        logger.error(
          {
            err,
            sandboxId,
            vmName: box.hypervVmName,
            snapshotName: box.hypervSnapshotName,
            shouldRestore,
          },
          'Failed to release Hyper-V VM'
        )
        return { ok: false, error }
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
  const cleanupFailures: string[] = []
  let terminationConfirmed = !box.process
  if (box.process) {
    try {
      const termination = await proveWindowsSandboxTermination(box.process)
      terminationConfirmed = termination.confirmed
      if (!termination.confirmed) {
        cleanupFailures.push(
          `sandbox process termination failed: ${formatErrorMessage(termination.error)}`
        )
      }
    } catch (error) {
      cleanupFailures.push(`sandbox process termination check failed: ${formatErrorMessage(error)}`)
    }
  }
  if (box.listenPort > 0) {
    try {
      await removePortProxyAndAuditPort(
        box.listenPort,
        box.runtimeProxyHost || RUNTIME_PROXY_BIND_HOST,
        box.runtimeHost
      )
    } catch (error) {
      cleanupFailures.push(`portproxy removal failed: ${formatErrorMessage(error)}`)
    }
  }
  if (terminationConfirmed && box.sandboxDir && existsSync(box.sandboxDir)) {
    try {
      await removeSandboxDir(box.sandboxDir, 'stop_sandbox')
    } catch (error) {
      cleanupFailures.push(`workspace removal failed: ${formatErrorMessage(error)}`)
    }
  }
  if (cleanupFailures.length > 0) {
    const error = `Sandbox cleanup failed: ${cleanupFailures.join('; ')}`
    logger.error({ sandboxId, listenPort: box.listenPort, cleanupFailures }, error)
    return { ok: false, error }
  }
  if (box.listenPort > 0) {
    releaseListenPort(box.listenPort)
  }
  activeSandboxes.delete(sandboxId)
  logger.info({ sandboxId, listenPort: box.listenPort }, 'Sandbox stopped and cleaned up')
  return { ok: true }
}

async function stopSandboxWithDeadline(body: unknown): Promise<{ ok: boolean; error?: string }> {
  const request = (body && typeof body === 'object' ? body : {}) as {
    sandboxId?: string
    requestId?: string
    timeoutMs?: number
  }
  const sandboxId = typeof request.sandboxId === 'string' ? request.sandboxId.trim() : ''
  if (!sandboxId) return { ok: false, error: 'sandboxId is required' }
  const timeoutMs = normalizeServerDeadlineMs(request.timeoutMs, DEFAULT_STOP_TIMEOUT_MS)
  const operationId =
    typeof request.requestId === 'string' && START_REQUEST_ID_PATTERN.test(request.requestId)
      ? request.requestId.toLowerCase()
      : sandboxId
  return runWithSandboxOperationDeadline(operationId, 'stop', timeoutMs, () =>
    stopSandbox(sandboxId)
  )
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host}`)

    if (req.method === 'POST' && url.pathname === '/sandbox/start') {
      if (!requireAuth(req, res)) return
      const body = await readJsonBody(req)
      const result = await startSandboxWithDeadline(body)
      const status = result.ok ? 200 : 500
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'GET' && url.pathname === '/sandbox/start/status') {
      if (!requireAuth(req, res)) return
      const requestId = url.searchParams.get('requestId') || ''
      const resolution = resolveSandboxStartRequestId(requestId)
      if (resolution.error || !resolution.requestId) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: resolution.error || 'requestId is required' }))
        return
      }
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(getSandboxStartCorrelationStatus(resolution.requestId)))
      return
    }

    if (req.method === 'POST' && url.pathname === '/sandbox/stop') {
      if (!requireAuth(req, res)) return
      const body = await readJsonBody(req)
      const result = await stopSandboxWithDeadline(body)
      const status = result.ok ? 200 : result.error === 'Sandbox not found' ? 404 : 500
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(result))
      return
    }

    if (req.method === 'GET' && url.pathname === '/sandbox/health') {
      if (!requireAuth(req, res)) return
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(
        JSON.stringify({
          ok: true,
          backend: HOST_AGENT_BACKEND,
          sandboxStartRequestCorrelation: START_REQUEST_CORRELATION,
          sandboxStartContract: {
            timeoutScope: 'absolute-start-deadline',
            cleanupTimeoutMs: START_CLEANUP_TIMEOUT_MS,
            statusPath: '/sandbox/start/status',
          },
          sandboxStopContract: {
            timeoutScope: 'absolute-stop-deadline',
          },
          sandboxes: Array.from(activeSandboxes.values()).map((b) => ({
            sandboxId: b.sandboxId,
            requestId: b.requestId,
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

function isDirectHostAgentExecution(): boolean {
  const entryPath = process.argv[1]
  if (!entryPath) return false
  try {
    const resolvedEntry = realpathSync(entryPath)
    const resolvedModule = realpathSync(__filename)
    return process.platform === 'win32'
      ? resolvedEntry.toLowerCase() === resolvedModule.toLowerCase()
      : resolvedEntry === resolvedModule
  } catch {
    const resolvedEntry = path.resolve(entryPath)
    const resolvedModule = path.resolve(__filename)
    return process.platform === 'win32'
      ? resolvedEntry.toLowerCase() === resolvedModule.toLowerCase()
      : resolvedEntry === resolvedModule
  }
}

export function startHostAgentServer(): void {
  const hostAgentAuthDefaultError = getHostAgentAuthDefaultError()
  if (hostAgentAuthDefaultError) {
    logger.error(
      { host: BIND_HOST, port: PORT, apiKeyConfigured: false },
      hostAgentAuthDefaultError
    )
    process.exit(1)
  }

  server.listen(PORT, BIND_HOST, () => {
    logger.info(
      { host: BIND_HOST, port: PORT, apiKeyConfigured: !!API_KEY },
      'Windows Host Agent listening'
    )
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
}

if (isDirectHostAgentExecution()) {
  startHostAgentServer()
}
