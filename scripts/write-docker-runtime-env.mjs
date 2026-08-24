#!/usr/bin/env node

import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const PRIVATE_ENV_INTERNAL_CONTROL_NAMES = Object.freeze([
  'RIKUNE_VERIFY_PRIVATE_ENV_PATH',
  'RIKUNE_STAGE_DOCKER_ENV_PATH',
  'RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH',
  'RIKUNE_RESTORE_PRIVATE_ENV_PATH',
  'RIKUNE_REMOVE_PRIVATE_ENV_PATH',
  'RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN',
  'RIKUNE_DOCKER_ENV_PATH',
  'RIKUNE_DOCKER_ENV_DATA_ROOT',
  'RIKUNE_DOCKER_ENV_PROFILE',
  'RIKUNE_BUILD_HTTP_PROXY',
  'RIKUNE_BUILD_HTTPS_PROXY',
  'RIKUNE_BUILD_NO_PROXY',
  'RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP',
  'RIKUNE_STAGE_LOCAL_ENV_PATH',
  'RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN',
  'RIKUNE_LOCAL_EXISTING_ENV_BASE64',
  'RIKUNE_LOCAL_ENV_PATH',
  'RIKUNE_LOCAL_ENV_FORCE_KEYS',
  'RIKUNE_PRIVATE_ENV_PATH',
  'RIKUNE_PRIVATE_ENV_ACL_MODE',
  'STAGED_LOCAL_ENV_BASE64',
])

export function selectExactlyOnePrivateEnvOperation(environment, operationSelectors) {
  const selected = Object.entries(operationSelectors).filter(([, selector]) =>
    Object.hasOwn(environment, selector)
  )
  if (selected.length !== 1) {
    throw new Error(
      `Exactly one private environment operation selector is required; received ${selected.length}`
    )
  }
  return selected[0][0]
}

function assertPrivateEnvControlsAllowed(environment, operation, allowedOperation, controls) {
  if (operation === allowedOperation) return
  const unexpected = controls.filter((name) => Object.hasOwn(environment, name))
  if (unexpected.length > 0) {
    throw new Error(
      `Private environment controls are not valid for the selected ${operation} operation: ${unexpected.join(', ')}`
    )
  }
}

function assertEnvValue(name, value) {
  const normalized = String(value ?? '')
  if (/[\r\n\0]/u.test(normalized)) {
    throw new Error(`${name} cannot contain line breaks or NUL bytes`)
  }
  return normalized
}

function requireEnvValue(name, value) {
  const normalized = assertEnvValue(name, value)
  if (normalized.trim().length === 0) {
    throw new Error(`${name} is required`)
  }
  return normalized
}

function requireStrongApiKey(name, value) {
  const normalized = requireEnvValue(name, value).trim()
  if (!/^[\x21-\x7e]{32,}$/u.test(normalized)) {
    throw new Error(`${name} must contain at least 32 printable non-space ASCII characters`)
  }
  return normalized
}

function requireSecureRuntimeEndpoint(name, value, allowInsecureRuntimeHttp) {
  const normalized = requireEnvValue(name, value).trim()
  let endpoint
  try {
    endpoint = new URL(normalized)
  } catch {
    throw new Error(`${name} must be an absolute HTTP(S) URL`)
  }
  if (endpoint.username || endpoint.password) {
    throw new Error(`${name} must not contain URL userinfo credentials`)
  }
  if (endpoint.protocol === 'https:') return normalized
  const localHosts = new Set(['localhost', '127.0.0.1', '[::1]', 'host.docker.internal'])
  if (endpoint.protocol === 'http:' && localHosts.has(endpoint.hostname)) return normalized
  if (endpoint.protocol === 'http:' && allowInsecureRuntimeHttp) return normalized
  throw new Error(
    `${name} must use HTTPS for remote hosts; plaintext HTTP requires explicit isolated-network opt-in`
  )
}

function commandFailure(result) {
  return `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim()
}

const WINDOWS_PRIVATE_FILE_ACL_MARKER = 'RIKUNE_PRIVATE_FILE_ACL_V1'
const WINDOWS_PRIVATE_FILE_ACL_FAILURE_PREFIX = 'RIKUNE_PRIVATE_FILE_ACL_FAILURE='
const WINDOWS_PRIVATE_FILE_ACL_ASSERTION_EXIT_CODE = 86
const WINDOWS_PRIVATE_FILE_ACL_FAILURE_REASONS = new Set([
  'missing-target',
  'not-file',
  'reparse',
  'sid',
  'invalid-operation',
  'inheritance',
  'owner',
  'entry-count',
  'rule',
  'attributes-read',
  'identity-read',
  'descriptor-build',
  'rule-build',
  'acl-write',
  'acl-read',
  'owner-read',
  'rules-read',
  'rule-inspect',
  'marker-write',
])
const WINDOWS_PRIVATE_FILE_ACL_FAILURE_PHASES = new Set([
  'capture',
  'snapshot-match',
  'pre-unlink',
  'unscoped',
])
const WINDOWS_PRIVATE_FILE_ACL_SCRIPT = String.raw`
$env:PSModulePath = $env:SystemRoot + '\System32\WindowsPowerShell\v1.0\Modules'
$ErrorActionPreference = 'Stop'
$targetPath = $env:RIKUNE_PRIVATE_ENV_PATH
$mode = $env:RIKUNE_PRIVATE_ENV_ACL_MODE
function Fail-PrivateFileAcl {
    param([string]$Reason)
    [Console]::Error.Write('${WINDOWS_PRIVATE_FILE_ACL_FAILURE_PREFIX}' + $Reason)
    exit ${WINDOWS_PRIVATE_FILE_ACL_ASSERTION_EXIT_CODE}
}
if ([string]::IsNullOrWhiteSpace($targetPath)) { Fail-PrivateFileAcl 'missing-target' }

try {
    $attributes = [System.IO.File]::GetAttributes($targetPath)
} catch {
    Fail-PrivateFileAcl 'attributes-read'
}
if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
    Fail-PrivateFileAcl 'not-file'
}
if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail-PrivateFileAcl 'reparse'
}

try {
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $currentSidValue = $currentSid.Value
} catch {
    Fail-PrivateFileAcl 'identity-read'
}
if ($null -eq $currentSid) { Fail-PrivateFileAcl 'sid' }
if ($mode -eq 'set') {
    try {
        $security = New-Object System.Security.AccessControl.FileSecurity
        $security.SetOwner($currentSid)
        $security.SetAccessRuleProtection($true, $false)
    } catch {
        Fail-PrivateFileAcl 'descriptor-build'
    }
    try {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $security.SetAccessRule($rule)
    } catch {
        Fail-PrivateFileAcl 'rule-build'
    }
    try {
        [System.IO.File]::SetAccessControl($targetPath, $security)
    } catch {
        Fail-PrivateFileAcl 'acl-write'
    }
} elseif ($mode -ne 'verify') {
    Fail-PrivateFileAcl 'invalid-operation'
}

try {
    $acl = [System.IO.File]::GetAccessControl($targetPath)
    $accessRulesProtected = $acl.AreAccessRulesProtected
} catch {
    Fail-PrivateFileAcl 'acl-read'
}
if (-not $accessRulesProtected) { Fail-PrivateFileAcl 'inheritance' }
try {
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    $ownerSidValue = $ownerSid.Value
} catch {
    Fail-PrivateFileAcl 'owner-read'
}
if ($ownerSidValue -ne $currentSidValue) { Fail-PrivateFileAcl 'owner' }
try {
    $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
} catch {
    Fail-PrivateFileAcl 'rules-read'
}
if ($rules.Count -ne 1) { Fail-PrivateFileAcl 'entry-count' }
try {
    $actual = $rules[0]
    $ruleMismatch = (
        $actual.IsInherited -or
        $actual.IdentityReference.Value -ne $currentSidValue -or
        $actual.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        $actual.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
        $actual.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or
        $actual.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
    )
} catch {
    Fail-PrivateFileAcl 'rule-inspect'
}
if ($ruleMismatch) { Fail-PrivateFileAcl 'rule' }
try {
    [Console]::Out.Write('${WINDOWS_PRIVATE_FILE_ACL_MARKER}')
} catch {
    Fail-PrivateFileAcl 'marker-write'
}
`

function normalizeWindowsAclFailurePhase(value) {
  const phase = String(value ?? '')
  return WINDOWS_PRIVATE_FILE_ACL_FAILURE_PHASES.has(phase) ? phase : 'unscoped'
}

function windowsAclChildFailureReason(result) {
  if (result.status !== WINDOWS_PRIVATE_FILE_ACL_ASSERTION_EXIT_CODE) return 'child-exit'
  const output = commandFailure(result)
  const marker = new RegExp(`^${WINDOWS_PRIVATE_FILE_ACL_FAILURE_PREFIX}([a-z0-9-]+)$`, 'u').exec(
    output
  )
  return marker && WINDOWS_PRIVATE_FILE_ACL_FAILURE_REASONS.has(marker[1])
    ? marker[1]
    : 'child-exit'
}

function windowsAclFailure(mode, phase, reason) {
  const action = mode === 'set' ? 'restrict' : 'verify'
  const category = `acl-${normalizeWindowsAclFailurePhase(phase)}-${reason}`
  return new Error(`RIKUNE_PRIVATE_ENV_FAILURE=${category}: Unable to ${action} Windows ACL`)
}

function readWindowsEnvironmentValue(environment, name) {
  const matchedName = Object.keys(environment).find(
    (candidate) => candidate.toUpperCase() === name.toUpperCase()
  )
  const value = matchedName === undefined ? '' : String(environment[matchedName] ?? '')
  if (/[\r\n\0]/u.test(value)) {
    throw new Error(`Unsafe Windows child environment value: ${name}`)
  }
  return value
}

function resolveTrustedWindowsSystemRoot(environment) {
  const configuredSystemRoot = readWindowsEnvironmentValue(environment, 'SYSTEMROOT')
  const configuredWindowsDirectory = readWindowsEnvironmentValue(environment, 'WINDIR')
  if (
    configuredSystemRoot &&
    configuredWindowsDirectory &&
    path.win32.resolve(configuredSystemRoot).toLowerCase() !==
      path.win32.resolve(configuredWindowsDirectory).toLowerCase()
  ) {
    throw new Error('SystemRoot and windir must resolve to the same Windows directory')
  }

  const systemRoot = configuredSystemRoot || configuredWindowsDirectory
  if (!/^[A-Za-z]:[\\/]/u.test(systemRoot) || !path.win32.isAbsolute(systemRoot)) {
    throw new Error('Unable to resolve a trusted drive-qualified Windows SystemRoot')
  }
  return path.win32.resolve(systemRoot)
}

export function resolveTrustedWindowsPowerShell(environment = process.env) {
  const systemRoot = resolveTrustedWindowsSystemRoot(environment)
  const powershell = path.win32.join(
    systemRoot,
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe'
  )
  const executableStat = fs.lstatSync(powershell)
  if (!executableStat.isFile() || executableStat.isSymbolicLink()) {
    throw new Error('Trusted Windows PowerShell executable is not a regular file')
  }
  return powershell
}

export function invokeWindowsFileAcl(filePath, mode, options = {}) {
  const environment = options.environment || process.env
  const runCommand = options.spawn || spawnSync
  const powershell = options.powershell || resolveTrustedWindowsPowerShell(environment)
  const encodedCommand = Buffer.from(WINDOWS_PRIVATE_FILE_ACL_SCRIPT, 'utf16le').toString('base64')
  const systemRoot = resolveTrustedWindowsSystemRoot(environment)
  const system32 = path.win32.join(systemRoot, 'System32')
  const trustedPowerShellModules = path.win32.join(system32, 'WindowsPowerShell', 'v1.0', 'Modules')
  const systemDrive = path.win32.parse(systemRoot).root.replace(/[\\/]$/u, '')
  const configuredTemp = readWindowsEnvironmentValue(environment, 'TEMP')
  const configuredTmp = readWindowsEnvironmentValue(environment, 'TMP')
  const temp = configuredTemp || configuredTmp
  const tmp = configuredTmp || temp
  const childEnvironment = {
    HOMEDRIVE: systemDrive,
    HOMEPATH: '\\',
    LOGONSERVER: '',
    PATH: system32,
    SYSTEMDRIVE: systemDrive,
    SYSTEMROOT: systemRoot,
    TEMP: temp,
    TMP: tmp,
    USERDOMAIN: '',
    USERNAME: '',
    USERPROFILE: '',
    WINDIR: systemRoot,
    PSModulePath: trustedPowerShellModules,
    RIKUNE_PRIVATE_ENV_PATH: path.resolve(filePath),
    RIKUNE_PRIVATE_ENV_ACL_MODE: mode,
  }
  const result = runCommand(
    powershell,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodedCommand],
    { encoding: 'utf8', windowsHide: true, env: childEnvironment }
  )
  if (result.error) {
    throw windowsAclFailure(mode, options.failurePhase, 'spawn')
  }
  if (result.status !== 0) {
    throw windowsAclFailure(mode, options.failurePhase, windowsAclChildFailureReason(result))
  }
  if (String(result.stdout || '').trim() !== WINDOWS_PRIVATE_FILE_ACL_MARKER) {
    throw windowsAclFailure(mode, options.failurePhase, 'marker')
  }
}

export function restrictWindowsFileAcl(filePath, options = {}) {
  invokeWindowsFileAcl(filePath, 'set', options)
}

export function verifyWindowsFileAcl(filePath, options = {}) {
  invokeWindowsFileAcl(filePath, 'verify', options)
}

function isSameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

export function pathEntryExists(targetPath) {
  try {
    fs.lstatSync(targetPath)
    return true
  } catch (error) {
    if (error?.code === 'ENOENT') return false
    throw error
  }
}

export function assertProtectedExistingFile({
  targetPath,
  platform = process.platform,
  verifyWindowsAcl = verifyWindowsFileAcl,
  maxBytes = 64 * 1024,
  aclFailurePhase = 'unscoped',
}) {
  const absoluteTarget = path.resolve(requireEnvValue('targetPath', targetPath))
  const initial = fs.lstatSync(absoluteTarget)
  if (!initial.isFile() || initial.isSymbolicLink()) {
    throw new Error(
      `Existing private environment target must be a non-link regular file: ${absoluteTarget}`
    )
  }
  if (initial.nlink !== 1) {
    throw new Error(
      `Existing private environment target must have exactly one hard link: ${absoluteTarget}`
    )
  }
  if (initial.size > maxBytes) {
    throw new Error(
      `Existing private environment target exceeds ${maxBytes} bytes: ${absoluteTarget}`
    )
  }
  if (platform === 'win32') {
    verifyWindowsAcl(absoluteTarget, { failurePhase: aclFailurePhase })
  } else {
    if (typeof process.getuid !== 'function' || initial.uid !== process.getuid()) {
      throw new Error(
        `Existing private environment target must be owned by the current user: ${absoluteTarget}`
      )
    }
    if ((initial.mode & 0o777) !== 0o600) {
      throw new Error(`Existing private environment target must have mode 0600: ${absoluteTarget}`)
    }
  }
  return { absoluteTarget, initial }
}

export function readPrivateUtf8File({
  targetPath,
  platform = process.platform,
  verifyWindowsAcl = verifyWindowsFileAcl,
  maxBytes = 64 * 1024,
  aclFailurePhase = 'unscoped',
}) {
  return new TextDecoder('utf-8', { fatal: true }).decode(
    readPrivateUtf8Bytes({
      targetPath,
      platform,
      verifyWindowsAcl,
      maxBytes,
      aclFailurePhase,
    })
  )
}

export function readPrivateUtf8Bytes({
  targetPath,
  platform = process.platform,
  verifyWindowsAcl = verifyWindowsFileAcl,
  maxBytes = 64 * 1024,
  aclFailurePhase = 'unscoped',
}) {
  const { absoluteTarget, initial } = assertProtectedExistingFile({
    targetPath,
    platform,
    verifyWindowsAcl,
    maxBytes,
    aclFailurePhase,
  })
  const noFollow = fs.constants.O_NOFOLLOW || 0
  const closeOnExec = fs.constants.O_CLOEXEC || 0
  const descriptor = fs.openSync(absoluteTarget, fs.constants.O_RDONLY | noFollow | closeOnExec)
  let bytes
  try {
    const opened = fs.fstatSync(descriptor)
    if (!isSameFile(initial, opened) || opened.size !== initial.size) {
      throw new Error(`Private environment target changed during validation: ${absoluteTarget}`)
    }
    bytes = fs.readFileSync(descriptor)
    const completed = fs.fstatSync(descriptor)
    if (
      !isSameFile(opened, completed) ||
      completed.size !== opened.size ||
      bytes.length !== opened.size
    ) {
      throw new Error(`Private environment target changed while reading: ${absoluteTarget}`)
    }
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    } catch {
      throw new Error(`Private environment target must contain valid UTF-8: ${absoluteTarget}`)
    }
  } finally {
    fs.closeSync(descriptor)
  }
  const final = fs.lstatSync(absoluteTarget)
  if (!isSameFile(initial, final) || final.size !== initial.size) {
    throw new Error(`Private environment target changed after reading: ${absoluteTarget}`)
  }
  return bytes
}

const PRIVATE_ENV_SNAPSHOT_VERSION = 1

function assertCanonicalBase64(name, value, maxBytes = 128 * 1024) {
  const normalized = String(value ?? '').trim()
  if (
    normalized.length > maxBytes * 2 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(normalized)
  ) {
    throw new Error(`${name} must contain canonical base64`)
  }
  const bytes = Buffer.from(normalized, 'base64')
  if (bytes.toString('base64') !== normalized || bytes.length > maxBytes) {
    throw new Error(`${name} must contain canonical base64`)
  }
  return bytes
}

function assertSnapshotTarget(snapshot, targetPath) {
  const absoluteTarget = path.resolve(requireEnvValue('targetPath', targetPath))
  if (snapshot.targetPath !== absoluteTarget) {
    throw new Error('Private environment snapshot target does not match the requested target')
  }
  return absoluteTarget
}

export function capturePrivateEnvSnapshot({
  targetPath,
  platform = process.platform,
  verifyWindowsAcl = verifyWindowsFileAcl,
}) {
  const absoluteTarget = path.resolve(requireEnvValue('targetPath', targetPath))
  if (!pathEntryExists(absoluteTarget)) {
    return { targetPath: absoluteTarget, existed: false, originalBytes: Buffer.alloc(0) }
  }
  const originalBytes = readPrivateUtf8Bytes({
    targetPath: absoluteTarget,
    platform,
    verifyWindowsAcl,
    aclFailurePhase: 'capture',
  })
  if (originalBytes.includes(0)) {
    throw new Error(`Private environment target must not contain NUL bytes: ${absoluteTarget}`)
  }
  return {
    targetPath: absoluteTarget,
    existed: true,
    originalBytes,
  }
}

export function encodePrivateEnvSnapshot(snapshot) {
  const originalBytes = Buffer.from(snapshot?.originalBytes ?? [])
  const payload = {
    version: PRIVATE_ENV_SNAPSHOT_VERSION,
    targetPath: String(snapshot?.targetPath ?? ''),
    existed: snapshot?.existed === true,
    originalBase64: originalBytes.toString('base64'),
  }
  if (!path.isAbsolute(payload.targetPath) || /[\r\n\0]/u.test(payload.targetPath)) {
    throw new Error('Private environment snapshot target must be an absolute path')
  }
  if (!payload.existed && originalBytes.length !== 0) {
    throw new Error('A missing private environment snapshot cannot contain original bytes')
  }
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64')
}

export function decodePrivateEnvSnapshot(encoded) {
  const serialized = assertCanonicalBase64('Private environment snapshot', encoded)
  let payload
  try {
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(serialized))
  } catch {
    throw new Error('Private environment snapshot must contain valid UTF-8 JSON')
  }
  if (
    payload?.version !== PRIVATE_ENV_SNAPSHOT_VERSION ||
    typeof payload.targetPath !== 'string' ||
    !path.isAbsolute(payload.targetPath) ||
    /[\r\n\0]/u.test(payload.targetPath) ||
    typeof payload.existed !== 'boolean' ||
    typeof payload.originalBase64 !== 'string'
  ) {
    throw new Error('Private environment snapshot has an invalid schema')
  }
  const originalBytes = assertCanonicalBase64(
    'Private environment snapshot original bytes',
    payload.originalBase64,
    64 * 1024
  )
  if (!payload.existed && originalBytes.length !== 0) {
    throw new Error('A missing private environment snapshot cannot contain original bytes')
  }
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(originalBytes)
  } catch {
    throw new Error('Private environment snapshot original bytes must contain valid UTF-8')
  }
  if (originalBytes.includes(0)) {
    throw new Error('Private environment snapshot original bytes must not contain NUL bytes')
  }
  return {
    targetPath: payload.targetPath,
    existed: payload.existed,
    originalBytes,
  }
}

export function privateEnvSnapshotContent(snapshot) {
  if (!snapshot.existed) return ''
  return new TextDecoder('utf-8', { fatal: true }).decode(snapshot.originalBytes)
}

function snapshotMatchesCurrentFile(snapshot, options) {
  if (!snapshot.existed || !pathEntryExists(snapshot.targetPath)) return false
  const currentBytes = readPrivateUtf8Bytes({ targetPath: snapshot.targetPath, ...options })
  return (
    currentBytes.length === snapshot.originalBytes.length &&
    crypto.timingSafeEqual(currentBytes, snapshot.originalBytes)
  )
}

export function removePrivateEnvForSnapshot({
  targetPath,
  snapshot,
  platform = process.platform,
  verifyWindowsAcl = verifyWindowsFileAcl,
}) {
  const absoluteTarget = assertSnapshotTarget(snapshot, targetPath)
  if (!snapshot.existed) {
    if (pathEntryExists(absoluteTarget)) {
      throw new Error('Private environment target appeared after the missing-file snapshot')
    }
    return false
  }
  if (
    !snapshotMatchesCurrentFile(snapshot, {
      platform,
      verifyWindowsAcl,
      aclFailurePhase: 'snapshot-match',
    })
  ) {
    throw new Error('Private environment target changed after the transaction snapshot')
  }
  return removeProtectedExistingFile({
    targetPath: absoluteTarget,
    platform,
    verifyWindowsAcl,
    aclFailurePhase: 'pre-unlink',
  })
}

export function restorePrivateEnvSnapshot({
  targetPath,
  snapshot,
  platform = process.platform,
  restrictWindowsAcl = restrictWindowsFileAcl,
  verifyWindowsAcl = verifyWindowsFileAcl,
}) {
  const absoluteTarget = assertSnapshotTarget(snapshot, targetPath)
  if (!snapshot.existed) {
    if (pathEntryExists(absoluteTarget)) {
      throw new Error(
        'Private environment rollback refused to remove a file created after the missing-file snapshot'
      )
    }
    return
  }

  if (pathEntryExists(absoluteTarget)) {
    if (snapshotMatchesCurrentFile(snapshot, { platform, verifyWindowsAcl })) return
    throw new Error(
      'Private environment rollback refused to overwrite bytes changed after the transaction snapshot'
    )
  }

  writePrivateUtf8File({
    targetPath: absoluteTarget,
    content: snapshot.originalBytes,
    platform,
    restrictWindowsAcl,
    verifyWindowsAcl,
    requireAbsent: true,
  })
  if (!snapshotMatchesCurrentFile(snapshot, { platform, verifyWindowsAcl })) {
    throw new Error('Private environment rollback did not restore the original bytes')
  }
}

export function removeProtectedExistingFile({
  targetPath,
  platform = process.platform,
  verifyWindowsAcl = verifyWindowsFileAcl,
  aclFailurePhase = 'unscoped',
}) {
  const absoluteTarget = path.resolve(requireEnvValue('targetPath', targetPath))
  if (!pathEntryExists(absoluteTarget)) return false
  const { initial } = assertProtectedExistingFile({
    targetPath: absoluteTarget,
    platform,
    verifyWindowsAcl,
    aclFailurePhase,
  })
  fs.unlinkSync(absoluteTarget)
  if (pathEntryExists(absoluteTarget)) {
    throw new Error(`Unable to remove stale private environment target: ${absoluteTarget}`)
  }
  if (!initial.isFile()) {
    throw new Error(`Refusing to remove a non-file private environment target: ${absoluteTarget}`)
  }
  return true
}

export function parseDockerRuntimeEnv(content) {
  const values = {}
  for (const line of String(content ?? '').split(/\r?\n/u)) {
    const trimmed = line.trim()
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue
    const separator = trimmed.indexOf('=')
    if (separator <= 0) continue
    values[trimmed.slice(0, separator).trim()] = trimmed.slice(separator + 1).trim()
  }
  return values
}

export function resolveAnalyzerApiKey({ explicitKey, randomBytes = crypto.randomBytes }) {
  const explicit = assertEnvValue('RIKUNE_API_KEY', explicitKey).trim()
  if (explicit.length > 0) {
    return { key: requireStrongApiKey('RIKUNE_API_KEY', explicit), generated: false }
  }

  const generated = randomBytes(32).toString('hex')
  if (!/^[a-f0-9]{64}$/u.test(generated)) {
    throw new Error('Cryptographic API key generation returned an invalid value')
  }
  return { key: generated, generated: true }
}

export function writePrivateUtf8File({
  targetPath,
  content,
  platform = process.platform,
  restrictWindowsAcl = restrictWindowsFileAcl,
  verifyWindowsAcl = verifyWindowsFileAcl,
  requireAbsent = false,
}) {
  const absoluteTarget = path.resolve(requireEnvValue('targetPath', targetPath))
  const normalizedContent = Buffer.isBuffer(content)
    ? Buffer.from(content)
    : Buffer.from(String(content ?? ''), 'utf8')
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(normalizedContent)
  } catch {
    throw new Error('content must contain valid UTF-8')
  }
  if (normalizedContent.includes(0)) {
    throw new Error('content cannot contain NUL bytes')
  }
  if (pathEntryExists(absoluteTarget)) {
    if (requireAbsent) {
      throw new Error(
        'Private environment transaction target appeared before the atomic replacement'
      )
    }
    assertProtectedExistingFile({ targetPath: absoluteTarget, platform, verifyWindowsAcl })
  }
  fs.mkdirSync(path.dirname(absoluteTarget), { recursive: true })
  const temporaryPath = `${absoluteTarget}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`
  let descriptor
  let renamed = false
  let replacementIdentity

  try {
    descriptor = fs.openSync(temporaryPath, 'wx', 0o600)
    if (platform === 'win32') {
      fs.closeSync(descriptor)
      descriptor = undefined
      restrictWindowsAcl(temporaryPath)
      descriptor = fs.openSync(temporaryPath, 'r+')
    } else {
      fs.fchmodSync(descriptor, 0o600)
    }

    fs.writeFileSync(descriptor, normalizedContent)
    fs.fsyncSync(descriptor)
    fs.closeSync(descriptor)
    descriptor = undefined
    replacementIdentity = fs.lstatSync(temporaryPath)

    if (requireAbsent) {
      fs.linkSync(temporaryPath, absoluteTarget)
      renamed = true
      fs.unlinkSync(temporaryPath)
    } else {
      fs.renameSync(temporaryPath, absoluteTarget)
      renamed = true
    }
    if (platform === 'win32') {
      restrictWindowsAcl(absoluteTarget)
    } else {
      fs.chmodSync(absoluteTarget, 0o600)
    }
    const { initial: installedIdentity } = assertProtectedExistingFile({
      targetPath: absoluteTarget,
      platform,
      verifyWindowsAcl,
    })
    if (!isSameFile(replacementIdentity, installedIdentity)) {
      throw new Error(
        `Private environment target changed during atomic replacement: ${absoluteTarget}`
      )
    }
    const writtenBytes = readPrivateUtf8Bytes({
      targetPath: absoluteTarget,
      platform,
      verifyWindowsAcl,
    })
    if (
      writtenBytes.length !== normalizedContent.length ||
      !crypto.timingSafeEqual(writtenBytes, normalizedContent)
    ) {
      throw new Error(
        `Private environment target bytes did not verify after replacement: ${absoluteTarget}`
      )
    }
  } catch (error) {
    if (renamed && pathEntryExists(absoluteTarget)) {
      try {
        const currentIdentity = fs.lstatSync(absoluteTarget)
        if (!replacementIdentity || !isSameFile(replacementIdentity, currentIdentity)) {
          throw new Error(
            `Refusing to remove a private environment target changed after replacement: ${absoluteTarget}`
          )
        }
        fs.unlinkSync(absoluteTarget)
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          `Unable to clean up private file after secure replacement failed: ${absoluteTarget}`
        )
      }
    }
    throw error
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
    fs.rmSync(temporaryPath, { force: true })
  }
}

export function writeDockerRuntimeEnv({
  targetPath,
  dataRoot,
  profile,
  buildHttpProxy = '',
  buildHttpsProxy = '',
  buildNoProxy = '',
  analyzerApiKey = '',
  hostAgentEndpoint = '',
  hostAgentApiKey = '',
  runtimeApiKey = '',
  allowInsecureRuntimeHttp = false,
  existingContent,
  randomBytes = crypto.randomBytes,
  platform = process.platform,
  restrictWindowsAcl = restrictWindowsFileAcl,
  verifyWindowsAcl = verifyWindowsFileAcl,
  requireAbsent = false,
}) {
  const normalizedTarget = assertEnvValue('targetPath', targetPath).trim()
  if (normalizedTarget.length === 0) {
    throw new Error('RIKUNE_DOCKER_ENV_PATH is required')
  }
  const normalizedDataRoot = requireEnvValue('RIKUNE_DATA_ROOT', dataRoot)
  if (!['static', 'full', 'hybrid'].includes(profile)) {
    throw new Error(`Unsupported Docker runtime profile: ${profile}`)
  }
  const normalizedHybridCredentials =
    profile === 'hybrid'
      ? {
          endpoint: requireSecureRuntimeEndpoint(
            'RUNTIME_HOST_AGENT_ENDPOINT',
            hostAgentEndpoint,
            allowInsecureRuntimeHttp
          ),
          hostKey: requireStrongApiKey('RUNTIME_HOST_AGENT_API_KEY', hostAgentApiKey),
          runtimeKey: requireStrongApiKey('RUNTIME_API_KEY', runtimeApiKey),
        }
      : null
  if (
    normalizedHybridCredentials &&
    normalizedHybridCredentials.hostKey === normalizedHybridCredentials.runtimeKey
  ) {
    throw new Error('RUNTIME_HOST_AGENT_API_KEY and RUNTIME_API_KEY must be distinct')
  }
  const absoluteTarget = path.resolve(normalizedTarget)
  if (requireAbsent && pathEntryExists(absoluteTarget)) {
    throw new Error('Private environment transaction target appeared before the final writer')
  }
  const resolvedKey = resolveAnalyzerApiKey({
    explicitKey: analyzerApiKey,
    randomBytes,
  })

  const lines = [
    '# Rikune Docker runtime environment - generated securely',
    `RIKUNE_DATA_ROOT=${normalizedDataRoot}`,
    `RIKUNE_BUILD_HTTP_PROXY=${assertEnvValue('RIKUNE_BUILD_HTTP_PROXY', buildHttpProxy)}`,
    `RIKUNE_BUILD_HTTPS_PROXY=${assertEnvValue('RIKUNE_BUILD_HTTPS_PROXY', buildHttpsProxy)}`,
    `RIKUNE_BUILD_NO_PROXY=${assertEnvValue('RIKUNE_BUILD_NO_PROXY', buildNoProxy)}`,
    `RIKUNE_API_KEY=${resolvedKey.key}`,
    `RIKUNE_ANALYZER_API_KEY=${resolvedKey.key}`,
  ]

  if (profile === 'hybrid') {
    lines.push(
      `RUNTIME_HOST_AGENT_ENDPOINT=${normalizedHybridCredentials.endpoint}`,
      `RUNTIME_HOST_AGENT_API_KEY=${normalizedHybridCredentials.hostKey}`,
      `RUNTIME_API_KEY=${normalizedHybridCredentials.runtimeKey}`,
      `RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP=${allowInsecureRuntimeHttp ? 'true' : 'false'}`
    )
  }

  const existing = parseDockerRuntimeEnv(
    existingContent === undefined && pathEntryExists(absoluteTarget)
      ? readPrivateUtf8File({ targetPath: absoluteTarget, platform, verifyWindowsAcl })
      : existingContent || ''
  )
  const managedKeys = new Set([
    'RIKUNE_DATA_ROOT',
    'RIKUNE_BUILD_HTTP_PROXY',
    'RIKUNE_BUILD_HTTPS_PROXY',
    'RIKUNE_BUILD_NO_PROXY',
    'RIKUNE_API_KEY',
    'RIKUNE_ANALYZER_API_KEY',
    'RUNTIME_HOST_AGENT_ENDPOINT',
    'RUNTIME_HOST_AGENT_API_KEY',
    'RUNTIME_API_KEY',
    'RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP',
  ])
  const preserved = Object.entries(existing)
    .filter(([name]) => !managedKeys.has(name))
    .map(([name, value]) => `${name}=${value}`)
  if (preserved.length > 0) {
    lines.push('', '# Existing user settings preserved by secure installer', ...preserved)
  }

  const content = `${lines.join('\n')}\n`
  writePrivateUtf8File({
    targetPath: absoluteTarget,
    content,
    platform,
    restrictWindowsAcl,
    verifyWindowsAcl,
    requireAbsent,
  })

  return { analyzerApiKey: resolvedKey.key, generated: resolvedKey.generated }
}

async function readStandardInput() {
  let content = ''
  process.stdin.setEncoding('utf8')
  for await (const chunk of process.stdin) content += chunk
  return content
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : ''
if (invokedPath === fileURLToPath(import.meta.url)) {
  const operation = selectExactlyOnePrivateEnvOperation(process.env, {
    verify: 'RIKUNE_VERIFY_PRIVATE_ENV_PATH',
    stageDocker: 'RIKUNE_STAGE_DOCKER_ENV_PATH',
    removeSnapshot: 'RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH',
    restoreSnapshot: 'RIKUNE_RESTORE_PRIVATE_ENV_PATH',
    removeLegacy: 'RIKUNE_REMOVE_PRIVATE_ENV_PATH',
    writeDocker: 'RIKUNE_DOCKER_ENV_PATH',
  })
  assertPrivateEnvControlsAllowed(process.env, operation, 'writeDocker', [
    'RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN',
    'RIKUNE_DOCKER_ENV_DATA_ROOT',
    'RIKUNE_DOCKER_ENV_PROFILE',
    'RIKUNE_BUILD_HTTP_PROXY',
    'RIKUNE_BUILD_HTTPS_PROXY',
    'RIKUNE_BUILD_NO_PROXY',
    'RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP',
  ])

  switch (operation) {
    case 'verify':
      assertProtectedExistingFile({ targetPath: process.env.RIKUNE_VERIFY_PRIVATE_ENV_PATH })
      break
    case 'stageDocker': {
      const snapshot = capturePrivateEnvSnapshot({
        targetPath: process.env.RIKUNE_STAGE_DOCKER_ENV_PATH,
      })
      process.stdout.write(encodePrivateEnvSnapshot(snapshot))
      break
    }
    case 'removeSnapshot': {
      const snapshot = decodePrivateEnvSnapshot(await readStandardInput())
      removePrivateEnvForSnapshot({
        targetPath: process.env.RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH,
        snapshot,
      })
      break
    }
    case 'restoreSnapshot': {
      const snapshot = decodePrivateEnvSnapshot(await readStandardInput())
      restorePrivateEnvSnapshot({
        targetPath: process.env.RIKUNE_RESTORE_PRIVATE_ENV_PATH,
        snapshot,
      })
      break
    }
    case 'removeLegacy':
      removeProtectedExistingFile({ targetPath: process.env.RIKUNE_REMOVE_PRIVATE_ENV_PATH })
      break
    case 'writeDocker': {
      const snapshot = process.env.RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN
        ? decodePrivateEnvSnapshot(await readStandardInput())
        : undefined
      if (snapshot) assertSnapshotTarget(snapshot, process.env.RIKUNE_DOCKER_ENV_PATH)
      writeDockerRuntimeEnv({
        targetPath: process.env.RIKUNE_DOCKER_ENV_PATH,
        dataRoot: process.env.RIKUNE_DOCKER_ENV_DATA_ROOT,
        profile: process.env.RIKUNE_DOCKER_ENV_PROFILE,
        buildHttpProxy: process.env.RIKUNE_BUILD_HTTP_PROXY,
        buildHttpsProxy: process.env.RIKUNE_BUILD_HTTPS_PROXY,
        buildNoProxy: process.env.RIKUNE_BUILD_NO_PROXY,
        analyzerApiKey: process.env.RIKUNE_API_KEY || process.env.RIKUNE_ANALYZER_API_KEY,
        hostAgentEndpoint: process.env.RUNTIME_HOST_AGENT_ENDPOINT,
        hostAgentApiKey: process.env.RUNTIME_HOST_AGENT_API_KEY,
        runtimeApiKey: process.env.RUNTIME_API_KEY,
        allowInsecureRuntimeHttp: /^(1|true|yes|on)$/iu.test(
          process.env.RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP || ''
        ),
        existingContent: snapshot ? privateEnvSnapshotContent(snapshot) : undefined,
        requireAbsent: snapshot !== undefined,
      })
      break
    }
  }
}
