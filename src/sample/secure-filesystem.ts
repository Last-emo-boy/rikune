import path from 'node:path'
import { execFile, spawn, spawnSync } from 'node:child_process'
import { promisify } from 'node:util'
import { isStaticDockerProfile } from '../core/static-profile-lock.js'
import { resolvePackagePath } from '../runtime-paths.js'

export interface SecureQuarantineRenameRequest {
  root: string
  rootDevice: number
  rootInode: number
  sourceRelative: string
  destinationRelative: string
  expectedDevice: number
  expectedInode: number
  expectedType: 'file' | 'directory'
  /** Test-only barrier reached after all relevant directory descriptors are pinned. */
  readyFile?: string
  /** Test-only continuation signal paired with readyFile. */
  continueFile?: string
}

export interface SecureQuarantineRenameResult {
  status: 'renamed' | 'already_quarantined' | 'missing'
}

interface SecureRootRequest {
  root: string
  rootDevice: number
  rootInode: number
}

export interface SecureIngestPublishRequest extends SecureRootRequest {
  directoryRelative: string
  tempName: string
  finalName: string
  expectedSha256: string
  data: Buffer
}

export interface SecureIngestPublishResult {
  status: 'published' | 'already_present'
  device: number
  inode: number
}

export interface SecureCleanupIngestTempRequest extends SecureRootRequest {
  directoryRelative: string
  tempName: string
  expectedSha256: string
  expectedSize: number
}

export interface SecureCleanupIngestTempResult {
  status: 'removed' | 'missing'
}

export interface SecureRemoveIdentityRequest extends SecureRootRequest {
  directoryRelative: string
  sourceName: string
  quarantineName: string
  expectedDevice: number
  expectedInode: number
  readyFile?: string
  continueFile?: string
}

export interface SecureRemoveIdentityResult {
  status: 'removed' | 'missing'
}

export interface SecureValidateDirectoryRequest extends SecureRootRequest {
  directoryRelative: string
}

export interface SecureFindMatchingFileRequest extends SecureValidateDirectoryRequest {
  expectedSha256: string
  expectedSize: number
}

export interface SecureFindMatchingFileResult {
  status: 'matched' | 'missing'
  name?: string
  device?: number
  inode?: number
}

export interface SecureInspectFileRequest extends SecureValidateDirectoryRequest {
  name: string
}

export interface SecureInspectFileResult {
  status: 'found' | 'missing'
  device?: number
  inode?: number
  size?: number
}

export interface SecurePurgeEntry {
  relativePath: string
  device: number
  inode: number
  type: 'file' | 'directory'
  size: number
  quarantineTarget: boolean
}

export interface SecurePurgeQuarantineRequest extends SecureRootRequest {
  directoryRelative: string
  entries: SecurePurgeEntry[]
  /** Test-only barrier reached before the first atomic basename claim. */
  readyFile?: string
  /** Test-only continuation signal paired with readyFile. */
  continueFile?: string
  /** Test-only crash injection after this many secure removals. */
  testFailAfterUnlinks?: number
  /** Test-only bound used to force multiple production-protocol chunks. */
  testChunkBytes?: number
  /** Test-only crash injection after this many committed chunks. */
  testFailAfterChunks?: number
  /** Test-only delay inside each chunk helper. */
  testDelayMs?: number
  /** Owner-fence callback run after every committed chunk and before finish. */
  onChunkCommitted?: () => void | Promise<void>
}

export interface SecurePurgeQuarantineResult {
  status: 'purged' | 'missing'
}

const execFileAsync = promisify(execFile)

function normalizeRelative(candidate: string): string {
  if (
    !candidate ||
    path.isAbsolute(candidate) ||
    candidate.includes('\0') ||
    candidate.split(/[\\/]/u).some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new Error('E_SECURE_QUARANTINE: invalid relative path')
  }
  return candidate.replaceAll('\\', '/')
}

function resolveHelperPath(): string {
  if (isStaticDockerProfile()) return '/app/scripts/secure-fs-helper.py'
  return (
    process.env.RIKUNE_SECURE_FS_HELPER_PATH || resolvePackagePath('scripts', 'secure-fs-helper.py')
  )
}

function pythonExecutable(): string {
  return isStaticDockerProfile() ? '/usr/local/bin/python3.12' : 'python3'
}

function buildPayload(request: SecureQuarantineRenameRequest): Record<string, unknown> {
  if (process.platform !== 'linux') {
    throw new Error(`E_SECURE_QUARANTINE_UNSUPPORTED: ${process.platform}`)
  }
  if (!path.isAbsolute(request.root)) {
    throw new Error('E_SECURE_QUARANTINE: trusted root must be absolute')
  }
  return {
    action: 'quarantine_rename',
    root: request.root,
    root_device: request.rootDevice,
    root_inode: request.rootInode,
    source_relative: normalizeRelative(request.sourceRelative),
    destination_relative: normalizeRelative(request.destinationRelative),
    expected_device: request.expectedDevice,
    expected_inode: request.expectedInode,
    expected_type: request.expectedType,
    ...(request.readyFile ? { ready_file: request.readyFile } : {}),
    ...(request.continueFile ? { continue_file: request.continueFile } : {}),
  }
}

function parseResult(stdout: string): SecureQuarantineRenameResult {
  let parsed: unknown
  try {
    parsed = JSON.parse(stdout.trim())
  } catch {
    throw new Error('E_SECURE_QUARANTINE: helper returned invalid JSON')
  }
  const status = (parsed as { status?: unknown })?.status
  if (!['renamed', 'already_quarantined', 'missing'].includes(String(status))) {
    throw new Error('E_SECURE_QUARANTINE: helper returned invalid status')
  }
  return { status: status as SecureQuarantineRenameResult['status'] }
}

function executeSecureHelper(
  payload: Record<string, unknown>,
  input?: Buffer,
  requestViaStdin = false
): Record<string, unknown> {
  if (requestViaStdin && input) {
    throw new Error('E_SECURE_FILESYSTEM: JSON and binary stdin modes are mutually exclusive')
  }
  const result = spawnSync(
    pythonExecutable(),
    [resolveHelperPath(), requestViaStdin ? '--json-stdin' : JSON.stringify(payload)],
    {
      encoding: 'utf8',
      input: requestViaStdin ? Buffer.from(JSON.stringify(payload), 'utf8') : input,
      timeout: 30_000,
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
    }
  )
  if (result.error || result.signal || result.status !== 0) {
    const detail = String(result.stderr || result.error?.message || 'helper failed').trim()
    throw new Error(`E_SECURE_FILESYSTEM: ${detail.slice(0, 2048)}`)
  }
  return parseHelperOutput(String(result.stdout || ''))
}

function parseHelperOutput(stdout: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(stdout.trim()) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('helper result must be an object')
    }
    return parsed as Record<string, unknown>
  } catch (error) {
    throw new Error(
      `E_SECURE_FILESYSTEM: invalid helper JSON: ${error instanceof Error ? error.message : String(error)}`
    )
  }
}

function executeSecureHelperAsync(
  payload: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8')
  if (encoded.length > 16 * 1024 * 1024) {
    return Promise.reject(new Error('E_SECURE_FILESYSTEM: JSON request exceeds 16 MiB'))
  }
  return new Promise<Record<string, unknown>>((resolve, reject) => {
    const child = spawn(pythonExecutable(), [resolveHelperPath(), '--json-stdin'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
    let stdout = ''
    let stderr = ''
    let stdoutBytes = 0
    let stderrBytes = 0
    let failure: Error | undefined
    let closed = false
    const failAndTerminate = (error: Error): void => {
      if (!failure) failure = error
      if (!closed) child.kill('SIGKILL')
    }
    const timeout = setTimeout(() => {
      failAndTerminate(new Error('secure filesystem helper timed out'))
    }, 30_000)

    child.stdout.on('data', (chunk: Buffer) => {
      stdoutBytes += chunk.length
      if (stdoutBytes > 16 * 1024 * 1024) {
        failAndTerminate(new Error('secure filesystem helper stdout exceeded 16 MiB'))
        return
      }
      stdout += chunk.toString('utf8')
    })
    child.stderr.on('data', (chunk: Buffer) => {
      stderrBytes += chunk.length
      if (stderrBytes <= 64 * 1024) stderr += chunk.toString('utf8')
    })
    child.on('error', (error) => {
      failure = failure ?? error
    })
    child.stdin.on('error', (error) => {
      failAndTerminate(error)
    })
    child.on('close', (code, signal) => {
      closed = true
      clearTimeout(timeout)
      if (failure || code !== 0 || signal) {
        const detail = String(
          stderr || failure?.message || `helper exited with ${signal || code}`
        ).trim()
        reject(new Error(`E_SECURE_FILESYSTEM: ${detail.slice(0, 2048)}`))
        return
      }
      try {
        resolve(parseHelperOutput(stdout))
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)))
      }
    })
    child.stdin.end(encoded)
  })
}

function rootPayload(request: SecureRootRequest): Record<string, unknown> {
  if (process.platform !== 'linux') {
    throw new Error(`E_SECURE_FILESYSTEM_UNSUPPORTED: ${process.platform}`)
  }
  if (!path.isAbsolute(request.root)) {
    throw new Error('E_SECURE_FILESYSTEM: trusted root must be absolute')
  }
  return {
    root: request.root,
    root_device: request.rootDevice,
    root_inode: request.rootInode,
  }
}

export function secureValidateDirectory(request: SecureValidateDirectoryRequest): void {
  const result = executeSecureHelper({
    action: 'validate_directory',
    ...rootPayload(request),
    directory_relative: normalizeRelative(request.directoryRelative),
  })
  if (result.status !== 'validated') {
    throw new Error('E_SECURE_FILESYSTEM: helper returned invalid directory status')
  }
}

export function secureFindMatchingFile(
  request: SecureFindMatchingFileRequest
): SecureFindMatchingFileResult {
  const result = executeSecureHelper({
    action: 'find_matching_file',
    ...rootPayload(request),
    directory_relative: normalizeRelative(request.directoryRelative),
    expected_sha256: request.expectedSha256,
    expected_size: request.expectedSize,
  })
  if (result.status === 'missing') return { status: 'missing' }
  if (
    result.status !== 'matched' ||
    typeof result.name !== 'string' ||
    typeof result.device !== 'number' ||
    typeof result.inode !== 'number'
  ) {
    throw new Error('E_SECURE_FILESYSTEM: helper returned invalid matching-file result')
  }
  return {
    status: 'matched',
    name: result.name,
    device: result.device,
    inode: result.inode,
  }
}

export function secureInspectFile(request: SecureInspectFileRequest): SecureInspectFileResult {
  const result = executeSecureHelper({
    action: 'inspect_file',
    ...rootPayload(request),
    directory_relative: normalizeRelative(request.directoryRelative),
    name: normalizeRelative(request.name),
  })
  if (result.status === 'missing') return { status: 'missing' }
  if (
    result.status !== 'found' ||
    typeof result.device !== 'number' ||
    typeof result.inode !== 'number' ||
    typeof result.size !== 'number'
  ) {
    throw new Error('E_SECURE_FILESYSTEM: helper returned invalid file identity')
  }
  return {
    status: 'found',
    device: result.device,
    inode: result.inode,
    size: result.size,
  }
}

function buildPurgePayload(request: SecurePurgeQuarantineRequest): Record<string, unknown> {
  return {
    action: 'purge_quarantine',
    ...rootPayload(request),
    directory_relative: normalizeRelative(request.directoryRelative),
    entries: request.entries.map((entry) => ({
      relative_path: normalizeRelative(entry.relativePath),
      device: entry.device,
      inode: entry.inode,
      type: entry.type,
      size: entry.size,
      quarantine_target: entry.quarantineTarget,
    })),
    ...(request.readyFile ? { ready_file: request.readyFile } : {}),
    ...(request.continueFile ? { continue_file: request.continueFile } : {}),
    ...(request.testFailAfterUnlinks
      ? { test_fail_after_unlinks: request.testFailAfterUnlinks }
      : {}),
  }
}

function parsePurgeResult(result: Record<string, unknown>): SecurePurgeQuarantineResult {
  if (!['purged', 'missing'].includes(String(result.status))) {
    throw new Error('E_SECURE_FILESYSTEM: helper returned invalid purge result')
  }
  return { status: result.status as SecurePurgeQuarantineResult['status'] }
}

type SecurePurgeChunkEntry =
  | {
      relative_path: string
      kind: 'exact'
      device: number
      inode: number
      type: 'file' | 'directory'
      size: number
    }
  | {
      relative_path: string
      kind: 'scaffold'
      type: 'directory'
    }

const DEFAULT_PURGE_CHUNK_BYTES = 256 * 1024
const MIN_PURGE_CHUNK_BYTES = 1024

function buildChunkedPurgeEntries(request: SecurePurgeQuarantineRequest): SecurePurgeChunkEntry[] {
  const exact = new Map<string, SecurePurgeChunkEntry>()
  const scaffolds = new Set<string>()
  for (const entry of request.entries) {
    const relative = normalizeRelative(entry.relativePath)
    if (exact.has(relative)) {
      throw new Error(`E_SECURE_FILESYSTEM: duplicate purge entry: ${relative}`)
    }
    exact.set(relative, {
      relative_path: relative,
      kind: 'exact',
      device: entry.device,
      inode: entry.inode,
      type: entry.type,
      size: entry.size,
    })
    if (entry.quarantineTarget) {
      let parent = path.posix.dirname(relative)
      while (parent !== '.') {
        scaffolds.add(parent)
        parent = path.posix.dirname(parent)
      }
    }
  }
  const entries = [
    ...exact.values(),
    ...[...scaffolds]
      .filter((relative) => !exact.has(relative))
      .map<SecurePurgeChunkEntry>((relative) => ({
        relative_path: relative,
        kind: 'scaffold',
        type: 'directory',
      })),
  ]
  return entries.sort((left, right) => {
    const depth = right.relative_path.split('/').length - left.relative_path.split('/').length
    return depth || left.relative_path.localeCompare(right.relative_path)
  })
}

function splitPurgeEntries(
  basePayload: Record<string, unknown>,
  entries: SecurePurgeChunkEntry[],
  maxBytes: number
): SecurePurgeChunkEntry[][] {
  const baseBytes = Buffer.byteLength(JSON.stringify({ ...basePayload, entries: [] }), 'utf8')
  const chunks: SecurePurgeChunkEntry[][] = []
  let current: SecurePurgeChunkEntry[] = []
  let currentBytes = baseBytes
  for (const entry of entries) {
    const entryBytes = Buffer.byteLength(JSON.stringify(entry), 'utf8') + 1
    if (baseBytes + entryBytes > maxBytes) {
      throw new Error('E_SECURE_FILESYSTEM: a purge manifest entry exceeds the bounded chunk size')
    }
    if (current.length > 0 && currentBytes + entryBytes > maxBytes) {
      chunks.push(current)
      current = []
      currentBytes = baseBytes
    }
    current.push(entry)
    currentBytes += entryBytes
  }
  if (current.length > 0) chunks.push(current)
  return chunks
}

export async function securePurgeQuarantine(
  request: SecurePurgeQuarantineRequest
): Promise<SecurePurgeQuarantineResult> {
  const chunkBytes = request.testChunkBytes ?? DEFAULT_PURGE_CHUNK_BYTES
  if (!Number.isInteger(chunkBytes) || chunkBytes < MIN_PURGE_CHUNK_BYTES) {
    throw new Error(
      `E_SECURE_FILESYSTEM: purge chunk size must be at least ${MIN_PURGE_CHUNK_BYTES}`
    )
  }
  if (
    request.testFailAfterChunks !== undefined &&
    (!Number.isInteger(request.testFailAfterChunks) || request.testFailAfterChunks < 1)
  ) {
    throw new Error('E_SECURE_FILESYSTEM: testFailAfterChunks must be a positive integer')
  }
  const basePayload = {
    ...rootPayload(request),
    directory_relative: normalizeRelative(request.directoryRelative),
  }
  const chunks = splitPurgeEntries(
    { action: 'purge_quarantine_chunk', ...basePayload },
    buildChunkedPurgeEntries(request),
    chunkBytes
  )
  for (let index = 0; index < chunks.length; index++) {
    const result = await executeSecureHelperAsync({
      action: 'purge_quarantine_chunk',
      ...basePayload,
      entries: chunks[index],
      ...(request.testDelayMs !== undefined ? { test_delay_ms: request.testDelayMs } : {}),
    })
    if (!['processed', 'missing'].includes(String(result.status))) {
      throw new Error('E_SECURE_FILESYSTEM: helper returned invalid purge chunk result')
    }
    if (request.testFailAfterChunks === index + 1) {
      throw new Error('E_SECURE_FILESYSTEM: test purge crash after committed chunk')
    }
    await request.onChunkCommitted?.()
  }
  if (chunks.length === 0) await request.onChunkCommitted?.()
  return parsePurgeResult(
    await executeSecureHelperAsync({ action: 'purge_quarantine_finish', ...basePayload })
  )
}

export async function securePurgeQuarantineForTest(
  request: SecurePurgeQuarantineRequest
): Promise<SecurePurgeQuarantineResult> {
  return await new Promise<SecurePurgeQuarantineResult>((resolve, reject) => {
    const child = spawn(pythonExecutable(), [resolveHelperPath(), '--json-stdin'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
    let stdout = ''
    let stderr = ''
    let settled = false
    const finish = (error?: unknown): void => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      if (error) {
        const detail = error instanceof Error ? error.message : String(error)
        reject(new Error(`E_SECURE_FILESYSTEM: ${detail.slice(0, 2048)}`))
        return
      }
      try {
        resolve(parsePurgeResult(JSON.parse(stdout.trim())))
      } catch (parseError) {
        reject(
          new Error(
            `E_SECURE_FILESYSTEM: ${parseError instanceof Error ? parseError.message : String(parseError)}`
          )
        )
      }
    }
    const timeout = setTimeout(() => {
      child.kill('SIGKILL')
      finish(new Error('secure purge helper timed out'))
    }, 15_000)
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk: string) => {
      stdout = (stdout + chunk).slice(0, 16 * 1024 * 1024)
    })
    child.stderr.on('data', (chunk: string) => {
      stderr = (stderr + chunk).slice(0, 64 * 1024)
    })
    child.on('error', finish)
    child.on('close', (code, signal) => {
      if (code !== 0 || signal) {
        finish(new Error(stderr.trim() || `helper exited with ${signal || code}`))
      } else {
        finish()
      }
    })
    child.stdin.end(JSON.stringify(buildPurgePayload(request)))
  })
}

export function secureIngestPublish(
  request: SecureIngestPublishRequest
): SecureIngestPublishResult {
  const result = executeSecureHelper(
    {
      action: 'ingest_publish',
      ...rootPayload(request),
      directory_relative: normalizeRelative(request.directoryRelative),
      temp_name: normalizeRelative(request.tempName),
      final_name: normalizeRelative(request.finalName),
      expected_sha256: request.expectedSha256,
      expected_size: request.data.length,
    },
    request.data
  )
  if (
    !['published', 'already_present'].includes(String(result.status)) ||
    typeof result.device !== 'number' ||
    typeof result.inode !== 'number'
  ) {
    throw new Error('E_SECURE_FILESYSTEM: helper returned invalid ingest result')
  }
  return {
    status: result.status as SecureIngestPublishResult['status'],
    device: result.device,
    inode: result.inode,
  }
}

export function secureCleanupIngestTemp(
  request: SecureCleanupIngestTempRequest
): SecureCleanupIngestTempResult {
  const result = executeSecureHelper({
    action: 'cleanup_ingest_temp',
    ...rootPayload(request),
    directory_relative: normalizeRelative(request.directoryRelative),
    temp_name: normalizeRelative(request.tempName),
    expected_sha256: request.expectedSha256,
    expected_size: request.expectedSize,
  })
  if (!['removed', 'missing'].includes(String(result.status))) {
    throw new Error('E_SECURE_FILESYSTEM: helper returned invalid ingest cleanup result')
  }
  return { status: result.status as SecureCleanupIngestTempResult['status'] }
}

function buildRemovePayload(request: SecureRemoveIdentityRequest): Record<string, unknown> {
  return {
    action: 'remove_identity',
    ...rootPayload(request),
    directory_relative: normalizeRelative(request.directoryRelative),
    source_name: normalizeRelative(request.sourceName),
    quarantine_name: normalizeRelative(request.quarantineName),
    expected_device: request.expectedDevice,
    expected_inode: request.expectedInode,
    ...(request.readyFile ? { ready_file: request.readyFile } : {}),
    ...(request.continueFile ? { continue_file: request.continueFile } : {}),
  }
}

function parseRemoveResult(result: Record<string, unknown>): SecureRemoveIdentityResult {
  if (!['removed', 'missing'].includes(String(result.status))) {
    throw new Error('E_SECURE_FILESYSTEM: helper returned invalid remove result')
  }
  return { status: result.status as SecureRemoveIdentityResult['status'] }
}

export function secureRemoveIdentity(
  request: SecureRemoveIdentityRequest
): SecureRemoveIdentityResult {
  return parseRemoveResult(executeSecureHelper(buildRemovePayload(request)))
}

export async function secureRemoveIdentityForTest(
  request: SecureRemoveIdentityRequest
): Promise<SecureRemoveIdentityResult> {
  try {
    const result = await execFileAsync(
      pythonExecutable(),
      [resolveHelperPath(), JSON.stringify(buildRemovePayload(request))],
      { encoding: 'utf8', timeout: 15_000, maxBuffer: 64 * 1024, windowsHide: true }
    )
    return parseRemoveResult(JSON.parse(String(result.stdout || '').trim()))
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(`E_SECURE_FILESYSTEM: ${detail.slice(0, 2048)}`)
  }
}

export function secureQuarantineRename(
  request: SecureQuarantineRenameRequest
): SecureQuarantineRenameResult {
  const payload = JSON.stringify(buildPayload(request))
  const result = spawnSync(pythonExecutable(), [resolveHelperPath(), payload], {
    encoding: 'utf8',
    timeout: 15_000,
    maxBuffer: 64 * 1024,
    windowsHide: true,
  })
  if (result.error || result.signal || result.status !== 0) {
    const detail = String(result.stderr || result.error?.message || 'helper failed').trim()
    throw new Error(`E_SECURE_QUARANTINE: ${detail.slice(0, 2048)}`)
  }
  return parseResult(String(result.stdout || ''))
}

/** Async variant used only to coordinate deterministic ancestor-swap tests. */
export async function secureQuarantineRenameForTest(
  request: SecureQuarantineRenameRequest
): Promise<SecureQuarantineRenameResult> {
  const payload = JSON.stringify(buildPayload(request))
  try {
    const result = await execFileAsync(pythonExecutable(), [resolveHelperPath(), payload], {
      encoding: 'utf8',
      timeout: 15_000,
      maxBuffer: 64 * 1024,
      windowsHide: true,
    })
    return parseResult(String(result.stdout || ''))
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(`E_SECURE_QUARANTINE: ${detail.slice(0, 2048)}`)
  }
}
