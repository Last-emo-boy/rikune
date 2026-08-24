#!/usr/bin/env node

import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

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
const WINDOWS_PRIVATE_FILE_ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$targetPath = $env:RIKUNE_PRIVATE_ENV_PATH
$mode = $env:RIKUNE_PRIVATE_ENV_ACL_MODE
if ([string]::IsNullOrWhiteSpace($targetPath)) { throw 'Missing private file path' }

$attributes = [System.IO.File]::GetAttributes($targetPath)
if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
    throw 'Private environment path must be a regular file'
}
if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Private environment file must not be a reparse point'
}

$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($null -eq $currentSid) { throw 'Unable to resolve current Windows SID' }
if ($mode -eq 'set') {
    $security = New-Object System.Security.AccessControl.FileSecurity
    $security.SetOwner($currentSid)
    $security.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $currentSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $security.SetAccessRule($rule)
    [System.IO.File]::SetAccessControl($targetPath, $security)
} elseif ($mode -ne 'verify') {
    throw 'Invalid private file ACL operation'
}

$acl = [System.IO.File]::GetAccessControl($targetPath)
if (-not $acl.AreAccessRulesProtected) { throw 'Private file ACL inheritance is enabled' }
$ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
if ($ownerSid.Value -ne $currentSid.Value) { throw 'Private file has an unexpected owner' }
$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
if ($rules.Count -ne 1) { throw 'Private file must have exactly one ACL entry' }
$actual = $rules[0]
if (
    $actual.IsInherited -or
    $actual.IdentityReference.Value -ne $currentSid.Value -or
    $actual.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
    $actual.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
    $actual.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or
    $actual.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
) { throw 'Private file ACL is not exact current-user FullControl' }
[Console]::Out.Write('${WINDOWS_PRIVATE_FILE_ACL_MARKER}')
`

function resolveTrustedWindowsPowerShell(environment = process.env) {
  const systemRoot = String(environment.SystemRoot || environment.windir || '')
  if (!path.win32.isAbsolute(systemRoot) || /[\r\n\0]/u.test(systemRoot)) {
    throw new Error('Unable to resolve a trusted Windows SystemRoot')
  }
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

function invokeWindowsFileAcl(filePath, mode, options = {}) {
  const environment = options.environment || process.env
  const runCommand = options.spawn || spawnSync
  const powershell = options.powershell || resolveTrustedWindowsPowerShell(environment)
  const encodedCommand = Buffer.from(WINDOWS_PRIVATE_FILE_ACL_SCRIPT, 'utf16le').toString('base64')
  const childEnvironment = {
    SystemRoot: environment.SystemRoot,
    TEMP: environment.TEMP,
    TMP: environment.TMP,
    windir: environment.windir,
    RIKUNE_PRIVATE_ENV_PATH: path.resolve(filePath),
    RIKUNE_PRIVATE_ENV_ACL_MODE: mode,
  }
  for (const key of Object.keys(childEnvironment)) {
    if (childEnvironment[key] === undefined) delete childEnvironment[key]
  }
  const result = runCommand(
    powershell,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodedCommand],
    { encoding: 'utf8', windowsHide: true, env: childEnvironment }
  )
  if (
    result.error ||
    result.status !== 0 ||
    String(result.stdout || '').trim() !== WINDOWS_PRIVATE_FILE_ACL_MARKER
  ) {
    throw new Error(
      `Unable to ${mode === 'set' ? 'restrict' : 'verify'} Windows ACL on ${filePath}: ${result.error?.message ?? commandFailure(result)}`
    )
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
}) {
  const absoluteTarget = path.resolve(requireEnvValue('targetPath', targetPath))
  const initial = fs.lstatSync(absoluteTarget)
  if (!initial.isFile() || initial.isSymbolicLink()) {
    throw new Error(`Existing private environment target must be a non-link regular file: ${absoluteTarget}`)
  }
  if (initial.nlink !== 1) {
    throw new Error(`Existing private environment target must have exactly one hard link: ${absoluteTarget}`)
  }
  if (initial.size > maxBytes) {
    throw new Error(`Existing private environment target exceeds ${maxBytes} bytes: ${absoluteTarget}`)
  }
  if (platform === 'win32') {
    verifyWindowsAcl(absoluteTarget)
  } else {
    if (typeof process.getuid !== 'function' || initial.uid !== process.getuid()) {
      throw new Error(`Existing private environment target must be owned by the current user: ${absoluteTarget}`)
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
}) {
  const { absoluteTarget, initial } = assertProtectedExistingFile({
    targetPath,
    platform,
    verifyWindowsAcl,
    maxBytes,
  })
  const noFollow = fs.constants.O_NOFOLLOW || 0
  const closeOnExec = fs.constants.O_CLOEXEC || 0
  const descriptor = fs.openSync(absoluteTarget, fs.constants.O_RDONLY | noFollow | closeOnExec)
  let content
  try {
    const opened = fs.fstatSync(descriptor)
    if (!isSameFile(initial, opened) || opened.size !== initial.size) {
      throw new Error(`Private environment target changed during validation: ${absoluteTarget}`)
    }
    const bytes = fs.readFileSync(descriptor)
    const completed = fs.fstatSync(descriptor)
    if (
      !isSameFile(opened, completed) ||
      completed.size !== opened.size ||
      bytes.length !== opened.size
    ) {
      throw new Error(`Private environment target changed while reading: ${absoluteTarget}`)
    }
    try {
      content = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
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
  return content
}

export function removeProtectedExistingFile({
  targetPath,
  platform = process.platform,
  verifyWindowsAcl = verifyWindowsFileAcl,
}) {
  const absoluteTarget = path.resolve(requireEnvValue('targetPath', targetPath))
  if (!pathEntryExists(absoluteTarget)) return false
  const { initial } = assertProtectedExistingFile({
    targetPath: absoluteTarget,
    platform,
    verifyWindowsAcl,
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

export function resolveAnalyzerApiKey({
  explicitKey,
  randomBytes = crypto.randomBytes,
}) {
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
}) {
  const absoluteTarget = path.resolve(requireEnvValue('targetPath', targetPath))
  const normalizedContent = String(content ?? '')
  if (normalizedContent.includes('\0')) {
    throw new Error('content cannot contain NUL bytes')
  }
  if (pathEntryExists(absoluteTarget)) {
    assertProtectedExistingFile({ targetPath: absoluteTarget, platform, verifyWindowsAcl })
  }
  fs.mkdirSync(path.dirname(absoluteTarget), { recursive: true })
  const temporaryPath = `${absoluteTarget}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`
  let descriptor
  let renamed = false

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

    fs.writeFileSync(descriptor, normalizedContent, { encoding: 'utf8' })
    fs.fsyncSync(descriptor)
    fs.closeSync(descriptor)
    descriptor = undefined

    fs.renameSync(temporaryPath, absoluteTarget)
    renamed = true
    if (platform === 'win32') {
      restrictWindowsAcl(absoluteTarget)
    } else {
      fs.chmodSync(absoluteTarget, 0o600)
      assertProtectedExistingFile({ targetPath: absoluteTarget, platform })
    }
  } catch (error) {
    if (renamed) {
      try {
        fs.rmSync(absoluteTarget, { force: true })
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
  randomBytes = crypto.randomBytes,
  platform = process.platform,
  restrictWindowsAcl = restrictWindowsFileAcl,
  verifyWindowsAcl = verifyWindowsFileAcl,
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

  const content = `${lines.join('\n')}\n`
  writePrivateUtf8File({
    targetPath: absoluteTarget,
    content,
    platform,
    restrictWindowsAcl,
    verifyWindowsAcl,
  })

  return { analyzerApiKey: resolvedKey.key, generated: resolvedKey.generated }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : ''
if (invokedPath === fileURLToPath(import.meta.url)) {
  if (process.env.RIKUNE_VERIFY_PRIVATE_ENV_PATH) {
    assertProtectedExistingFile({ targetPath: process.env.RIKUNE_VERIFY_PRIVATE_ENV_PATH })
  } else if (process.env.RIKUNE_REMOVE_PRIVATE_ENV_PATH) {
    removeProtectedExistingFile({ targetPath: process.env.RIKUNE_REMOVE_PRIVATE_ENV_PATH })
  } else {
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
    })
  }
}
