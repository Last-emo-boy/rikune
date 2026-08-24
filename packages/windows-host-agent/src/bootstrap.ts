/**
 * Security bootstrap for the Windows Host Agent.
 *
 * Installer-managed environment values are loaded from the protected project
 * root file before importing index.js, whose module-level constants read them.
 */

import { execFile } from 'child_process'
import { createHash } from 'crypto'
import fs from 'fs/promises'
import { realpathSync, type Stats } from 'fs'
import path from 'path'
import { TextDecoder } from 'util'
import { fileURLToPath } from 'url'
import {
  encodeTrustedWindowsPowerShellScript,
  resolveTrustedWindowsCommand,
} from './windows-child-process.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

export const RUNTIME_WINDOWS_ENV_FILE = '.env.runtime-windows'
export const INSTALLER_MANAGED_ENV_KEYS = [
  'HOST_AGENT_PORT',
  'HOST_AGENT_BIND_HOST',
  'HOST_AGENT_RUNTIME_BIND_HOST',
  'HOST_AGENT_RUNTIME_ADVERTISED_HOST',
  'HOST_AGENT_API_KEY',
  'HOST_AGENT_RUNTIME_API_KEY',
  'HOST_AGENT_WORKSPACE',
  'HOST_AGENT_NODE_PATH',
  'HOST_AGENT_PYTHON_PATH',
  'HOST_AGENT_BACKEND',
  'HOST_AGENT_HYPERV_VM_NAME',
  'HOST_AGENT_HYPERV_SNAPSHOT_NAME',
  'HOST_AGENT_HYPERV_RUNTIME_ENDPOINT',
  'HOST_AGENT_HYPERV_RESTORE_ON_RELEASE',
  'HOST_AGENT_HYPERV_STOP_ON_RELEASE',
] as const

const INSTALLER_MANAGED_ENV_KEY_SET = new Set<string>(INSTALLER_MANAGED_ENV_KEYS)
const MAX_RUNTIME_ENV_FILE_BYTES = 64 * 1024
const ACL_EVIDENCE_MARKER = 'RIKUNE_WINDOWS_RUNTIME_ENV_ACL_V1'

const WINDOWS_ACL_VERIFIER_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$stream = $null
$sha256 = $null
try {
    $targetPath = $env:RIKUNE_HOST_AGENT_ENV_PATH
    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        throw 'The runtime environment path was not supplied'
    }

    $stream = [System.IO.File]::Open(
        $targetPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    $attributes = [System.IO.File]::GetAttributes($targetPath)
    if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        throw 'The runtime environment path is not a regular file'
    }
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The runtime environment file must not be a reparse point'
    }

    $acl = [System.IO.File]::GetAccessControl($targetPath)
    if (-not $acl.AreAccessRulesProtected) {
        throw 'The runtime environment file must have ACL inheritance disabled'
    }

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([string]::IsNullOrWhiteSpace($currentSid)) {
        throw 'Unable to resolve the current Windows user SID'
    }
    $allowedSids = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')
    $ownerSid = $acl.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    if ($allowedSids -notcontains $ownerSid) {
        throw 'A trusted Windows identity must own the runtime environment file'
    }

    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    ))
    $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $hasCurrentUserFullControl = $false

    foreach ($rule in $rules) {
        if ($rule.IsInherited) {
            throw 'The runtime environment file must not contain inherited ACL entries'
        }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            throw 'The runtime environment file ACL must contain only allow entries'
        }

        $ruleSid = $rule.IdentityReference.Value
        if ($allowedSids -notcontains $ruleSid) {
            throw "The runtime environment file grants access to an unexpected SID: $ruleSid"
        }
        if (
            $ruleSid -eq $currentSid -and
            (($rule.FileSystemRights -band $fullControl) -eq $fullControl)
        ) {
            $hasCurrentUserFullControl = $true
        }
    }

    if (-not $hasCurrentUserFullControl) {
        throw 'The runtime environment file must grant FullControl to the current Windows user'
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $digest = $sha256.ComputeHash($stream)
    $digestHex = ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    [Console]::Out.WriteLine((
        '{{"marker":"${ACL_EVIDENCE_MARKER}","sha256":"{0}","size":{1}}}' -f
        $digestHex,
        $stream.Length
    ))
} catch {
    [Console]::Error.WriteLine(
        'Windows runtime environment ACL verification failed: {0}',
        $_.Exception.Message
    )
    exit 1
} finally {
    if ($null -ne $sha256) { $sha256.Dispose() }
    if ($null -ne $stream) { $stream.Dispose() }
}
`

export interface RuntimeEnvironmentAclEvidence {
  sha256: string
  size: number
}

export type RuntimeEnvironmentAclVerifier = (
  targetPath: string
) => Promise<RuntimeEnvironmentAclEvidence | void>

interface WindowsCommandOptions {
  env: NodeJS.ProcessEnv
  maxBuffer: number
  windowsHide: boolean
}

export type WindowsBootstrapCommandRunner = (
  command: string,
  args: string[],
  options: WindowsCommandOptions
) => Promise<{ stdout: string; stderr: string }>

export interface LoadRuntimeWindowsEnvironmentOptions {
  projectRoot?: string
  verifyAcl?: RuntimeEnvironmentAclVerifier
}

export interface WindowsHostAgentBootstrapOptions extends LoadRuntimeWindowsEnvironmentOptions {
  processEnvironment?: NodeJS.ProcessEnv
  importHostAgent?: () => Promise<{ startHostAgentServer: () => void }>
}

function runWindowsCommand(
  command: string,
  args: string[],
  options: WindowsCommandOptions
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(command, args, options, (error, stdout, stderr) => {
      const result = {
        stdout: stdout?.toString() || '',
        stderr: stderr?.toString() || '',
      }
      if (error) {
        reject(
          new Error(
            `Windows runtime environment ACL verification command failed: ${
              result.stderr.trim() || error.message
            }`
          )
        )
        return
      }
      resolve(result)
    })
  })
}

export async function verifyWindowsRuntimeEnvAcl(
  targetPath: string,
  options: {
    platform?: NodeJS.Platform
    environment?: NodeJS.ProcessEnv
    runCommand?: WindowsBootstrapCommandRunner
  } = {}
): Promise<RuntimeEnvironmentAclEvidence> {
  const platform = options.platform || process.platform
  if (platform !== 'win32') {
    throw new Error('Windows runtime environment ACLs can only be verified on Windows')
  }

  const environment = options.environment || process.env
  const trustedCommand = resolveTrustedWindowsCommand('powershell.exe', environment, {
    RIKUNE_HOST_AGENT_ENV_PATH: targetPath,
  })
  const encodedScript = encodeTrustedWindowsPowerShellScript(WINDOWS_ACL_VERIFIER_SCRIPT)
  const args = ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodedScript]
  const result = await (options.runCommand || runWindowsCommand)(trustedCommand.command, args, {
    env: trustedCommand.env,
    maxBuffer: 64 * 1024,
    windowsHide: true,
  })

  let evidence: unknown
  try {
    evidence = JSON.parse(result.stdout.trim())
  } catch {
    throw new Error('Windows runtime environment ACL verifier returned invalid evidence')
  }
  if (
    !evidence ||
    typeof evidence !== 'object' ||
    (evidence as { marker?: unknown }).marker !== ACL_EVIDENCE_MARKER ||
    typeof (evidence as { sha256?: unknown }).sha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test((evidence as { sha256: string }).sha256) ||
    typeof (evidence as { size?: unknown }).size !== 'number' ||
    !Number.isSafeInteger((evidence as { size: number }).size) ||
    (evidence as { size: number }).size < 0
  ) {
    throw new Error('Windows runtime environment ACL verifier returned invalid evidence')
  }

  return {
    sha256: (evidence as { sha256: string }).sha256,
    size: (evidence as { size: number }).size,
  }
}

export function assertRegularRuntimeEnvironmentFile(
  stat: Pick<Stats, 'isFile' | 'isSymbolicLink'>
): void {
  if (stat.isSymbolicLink()) {
    throw new Error('The Windows runtime environment file must not be a symlink or reparse point')
  }
  if (!stat.isFile()) {
    throw new Error('The Windows runtime environment path must be a regular file')
  }
}

function isSameFile(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino
}

function assertBoundedRuntimeEnvironmentFileSize(size: number): void {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_RUNTIME_ENV_FILE_BYTES) {
    throw new Error('The Windows runtime environment file exceeds the maximum allowed size')
  }
}

async function readBoundedRuntimeEnvironmentFile(
  handle: Awaited<ReturnType<typeof fs.open>>,
  expectedSize: number
): Promise<Buffer> {
  const content = Buffer.allocUnsafe(expectedSize)
  let offset = 0
  while (offset < expectedSize) {
    const { bytesRead } = await handle.read(content, offset, expectedSize - offset, offset)
    if (bytesRead === 0) {
      throw new Error('The Windows runtime environment file changed while it was being read')
    }
    offset += bytesRead
  }

  const overflow = Buffer.allocUnsafe(1)
  const { bytesRead: overflowBytesRead } = await handle.read(overflow, 0, 1, expectedSize)
  if (overflowBytesRead !== 0) {
    throw new Error('The Windows runtime environment file exceeds the maximum allowed size')
  }
  return content
}

function decodeRuntimeEnvironmentFile(content: Buffer): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(content)
  } catch {
    throw new Error('The Windows runtime environment file must contain valid UTF-8')
  }
}

export function parseRuntimeWindowsEnvironment(content: string): Record<string, string> {
  if (content.includes('\0')) {
    throw new Error('The Windows runtime environment file must not contain NUL characters')
  }
  if (content.includes('\r')) {
    throw new Error('The Windows runtime environment file must use LF-only line endings')
  }

  const values: Record<string, string> = {}
  const seenKeys = new Set<string>()
  for (const [index, line] of content.split('\n').entries()) {
    const lineNumber = index + 1
    if (line.length === 0 || line.startsWith('#')) {
      continue
    }

    const separatorIndex = line.indexOf('=')
    if (separatorIndex <= 0) {
      throw new Error(`Invalid runtime environment entry on line ${lineNumber}`)
    }
    const key = line.slice(0, separatorIndex)
    const value = line.slice(separatorIndex + 1)
    if (!/^[A-Z][A-Z0-9_]*$/.test(key)) {
      throw new Error(`Invalid runtime environment key on line ${lineNumber}`)
    }
    if (!INSTALLER_MANAGED_ENV_KEY_SET.has(key)) {
      throw new Error(`Unknown installer-managed runtime environment key: ${key}`)
    }
    if (seenKeys.has(key)) {
      throw new Error(`Duplicate installer-managed runtime environment key: ${key}`)
    }
    seenKeys.add(key)
    values[key] = value
  }

  const hostAgentApiKey = values.HOST_AGENT_API_KEY
  if (!hostAgentApiKey || !/^[\x21-\x7e]{32,}$/.test(hostAgentApiKey)) {
    throw new Error(
      'HOST_AGENT_API_KEY must contain at least 32 printable non-space ASCII characters'
    )
  }
  const runtimeApiKey = values.HOST_AGENT_RUNTIME_API_KEY
  if (!runtimeApiKey || !/^[\x21-\x7e]{32,}$/.test(runtimeApiKey)) {
    throw new Error(
      'HOST_AGENT_RUNTIME_API_KEY must contain at least 32 printable non-space ASCII characters'
    )
  }
  if (runtimeApiKey === hostAgentApiKey) {
    throw new Error('HOST_AGENT_API_KEY and HOST_AGENT_RUNTIME_API_KEY must be distinct')
  }
  return values
}

export function resolveProjectRoot(): string {
  return path.resolve(__dirname, '../../..')
}

export async function loadRuntimeWindowsEnvironment(
  options: LoadRuntimeWindowsEnvironmentOptions = {}
): Promise<Record<string, string>> {
  const projectRoot = path.resolve(options.projectRoot || resolveProjectRoot())
  const runtimeEnvironmentPath = path.join(projectRoot, RUNTIME_WINDOWS_ENV_FILE)
  const initialStat = await fs.lstat(runtimeEnvironmentPath)
  assertRegularRuntimeEnvironmentFile(initialStat)
  assertBoundedRuntimeEnvironmentFileSize(initialStat.size)

  const verifyAcl = options.verifyAcl || verifyWindowsRuntimeEnvAcl
  const aclEvidence = await verifyAcl(runtimeEnvironmentPath)
  if (aclEvidence) {
    assertBoundedRuntimeEnvironmentFileSize(aclEvidence.size)
  }
  const handle = await fs.open(runtimeEnvironmentPath, 'r')
  let openedStat: Stats
  let content: Buffer
  try {
    openedStat = await handle.stat()
    assertRegularRuntimeEnvironmentFile(openedStat)
    assertBoundedRuntimeEnvironmentFileSize(openedStat.size)
    if (!isSameFile(initialStat, openedStat) || initialStat.size !== openedStat.size) {
      throw new Error('The Windows runtime environment file changed during verification')
    }
    if (aclEvidence && aclEvidence.size !== openedStat.size) {
      throw new Error('The Windows runtime environment file changed after ACL verification')
    }
    content = await readBoundedRuntimeEnvironmentFile(handle, openedStat.size)
    const completedStat = await handle.stat()
    if (
      !isSameFile(openedStat, completedStat) ||
      completedStat.size !== openedStat.size ||
      completedStat.size !== content.length
    ) {
      throw new Error('The Windows runtime environment file changed while it was being read')
    }
  } finally {
    await handle.close()
  }

  const finalStat = await fs.lstat(runtimeEnvironmentPath)
  assertRegularRuntimeEnvironmentFile(finalStat)
  if (!isSameFile(openedStat, finalStat) || finalStat.size !== openedStat.size) {
    throw new Error('The Windows runtime environment file changed after it was read')
  }
  if (aclEvidence) {
    const digest = createHash('sha256').update(content).digest('hex')
    if (aclEvidence.size !== content.length || aclEvidence.sha256 !== digest) {
      throw new Error('The Windows runtime environment file changed after ACL verification')
    }
  }

  return parseRuntimeWindowsEnvironment(decodeRuntimeEnvironmentFile(content))
}

export function applyRuntimeWindowsEnvironment(
  values: Record<string, string>,
  environment: NodeJS.ProcessEnv = process.env
): void {
  for (const key of Object.keys(values)) {
    if (!INSTALLER_MANAGED_ENV_KEY_SET.has(key)) {
      throw new Error(`Unknown installer-managed runtime environment key: ${key}`)
    }
  }

  const previousValues = new Map<string, string | undefined>()
  for (const key of INSTALLER_MANAGED_ENV_KEYS) {
    previousValues.set(key, environment[key])
  }
  try {
    for (const key of INSTALLER_MANAGED_ENV_KEYS) {
      if (Object.prototype.hasOwnProperty.call(values, key)) {
        environment[key] = values[key]
      } else {
        delete environment[key]
      }
    }
  } catch (error) {
    for (const [key, previousValue] of previousValues) {
      if (previousValue === undefined) {
        delete environment[key]
      } else {
        environment[key] = previousValue
      }
    }
    throw error
  }
}

export async function startWindowsHostAgentBootstrap(
  options: WindowsHostAgentBootstrapOptions = {}
): Promise<void> {
  const values = await loadRuntimeWindowsEnvironment(options)
  const environment = options.processEnvironment || process.env
  applyRuntimeWindowsEnvironment(values, environment)

  const hostAgent = await (options.importHostAgent || (() => import('./index.js')))()
  hostAgent.startHostAgentServer()
}

function isDirectBootstrapExecution(): boolean {
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

if (isDirectBootstrapExecution()) {
  void startWindowsHostAgentBootstrap().catch((error) => {
    const message = error instanceof Error ? error.message : String(error)
    console.error(`Windows Host Agent secure bootstrap failed: ${message}`)
    process.exitCode = 1
  })
}
