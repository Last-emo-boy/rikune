import path from 'path'
export {
  buildTrustedWindowsPowerShellScript,
  encodeTrustedWindowsPowerShellScript,
  TRUSTED_WINDOWS_POWERSHELL_MODULE_PATH_PRELUDE,
} from '@rikune/shared'

const WINDOWS_DRIVE_QUALIFIED_ROOT = /^[A-Za-z]:[\\/]/u

// Node 22's bundled libuv restores these variables from the parent process
// when they are absent from an explicitly supplied child environment. Keep
// every key present (Windows matches names case-insensitively) so no parent
// search path or account profile leaks back in.
export const LIBUV_WINDOWS_REQUIRED_ENV_KEYS = [
  'HOMEDRIVE',
  'HOMEPATH',
  'LOGONSERVER',
  'PATH',
  'SYSTEMDRIVE',
  'SYSTEMROOT',
  'TEMP',
  'USERDOMAIN',
  'USERNAME',
  'USERPROFILE',
  'WINDIR',
] as const

const TRUSTED_SYSTEM32_COMMANDS = new Map<string, string>([
  ['icacls.exe', 'icacls.exe'],
  ['netsh', 'netsh.exe'],
  ['netsh.exe', 'netsh.exe'],
  ['where.exe', 'where.exe'],
  ['whoami.exe', 'whoami.exe'],
  ['windowssandbox.exe', 'WindowsSandbox.exe'],
])

export function findWindowsEnvironmentValue(
  environment: NodeJS.ProcessEnv,
  name: string
): string | undefined {
  const entry = Object.entries(environment).find(
    ([key, value]) => key.toLowerCase() === name.toLowerCase() && value !== undefined
  )
  return entry?.[1]
}

export function resolveTrustedWindowsSystemRoot(environment: NodeJS.ProcessEnv): string {
  const configuredSystemRoot = findWindowsEnvironmentValue(environment, 'SystemRoot')
  const configuredWindowsDirectory = findWindowsEnvironmentValue(environment, 'windir')
  if (
    configuredSystemRoot &&
    configuredWindowsDirectory &&
    path.win32.resolve(configuredSystemRoot).toLowerCase() !==
      path.win32.resolve(configuredWindowsDirectory).toLowerCase()
  ) {
    throw new Error('SystemRoot and windir must resolve to the same Windows directory')
  }

  const systemRoot = configuredSystemRoot || configuredWindowsDirectory
  if (
    !systemRoot ||
    /[\r\n\0]/u.test(systemRoot) ||
    !WINDOWS_DRIVE_QUALIFIED_ROOT.test(systemRoot) ||
    !path.win32.isAbsolute(systemRoot)
  ) {
    throw new Error('A trusted drive-qualified local Windows SystemRoot is required')
  }
  return path.win32.resolve(systemRoot)
}

export function buildTrustedWindowsChildEnvironment(
  environment: NodeJS.ProcessEnv,
  systemRoot: string,
  additionalEnvironment: Readonly<Record<string, string>> = {}
): NodeJS.ProcessEnv {
  const trustedSystemRoot = resolveTrustedWindowsSystemRoot({
    SystemRoot: systemRoot,
    windir: systemRoot,
  })
  const trustedSystem32 = path.win32.join(trustedSystemRoot, 'System32')
  const trustedPowerShellModules = path.win32.join(
    trustedSystem32,
    'WindowsPowerShell',
    'v1.0',
    'Modules'
  )
  const systemDrive = path.win32.parse(trustedSystemRoot).root.replace(/[\\/]$/u, '')
  const configuredTemp = findWindowsEnvironmentValue(environment, 'TEMP')
  const configuredTmp = findWindowsEnvironmentValue(environment, 'TMP')
  const temp = configuredTemp ?? configuredTmp ?? ''
  const tmp = configuredTmp ?? temp

  const childEnvironment: NodeJS.ProcessEnv = {
    HOMEDRIVE: systemDrive,
    HOMEPATH: '\\',
    LOGONSERVER: '',
    PATH: trustedSystem32,
    PSModulePath: trustedPowerShellModules,
    SYSTEMDRIVE: systemDrive,
    SystemRoot: trustedSystemRoot,
    TEMP: temp,
    TMP: tmp,
    USERDOMAIN: '',
    USERNAME: '',
    USERPROFILE: '',
    windir: trustedSystemRoot,
  }

  const reservedKeys = new Set(Object.keys(childEnvironment).map((key) => key.toLowerCase()))
  for (const [key, value] of Object.entries(additionalEnvironment)) {
    if (reservedKeys.has(key.toLowerCase())) {
      throw new Error(`Additional Windows child environment may not override ${key}`)
    }
    childEnvironment[key] = value
  }
  return childEnvironment
}

export function resolveTrustedWindowsCommand(
  command: string,
  environment: NodeJS.ProcessEnv,
  additionalEnvironment: Readonly<Record<string, string>> = {}
): { command: string; env: NodeJS.ProcessEnv } {
  const systemRoot = resolveTrustedWindowsSystemRoot(environment)
  const normalizedCommand = command.toLowerCase()
  let commandPath: string
  if (normalizedCommand === 'powershell.exe') {
    commandPath = path.win32.join(
      systemRoot,
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe'
    )
  } else {
    const executable = TRUSTED_SYSTEM32_COMMANDS.get(normalizedCommand)
    if (!executable) {
      throw new Error(`Unsupported trusted Windows command: ${command}`)
    }
    commandPath = path.win32.join(systemRoot, 'System32', executable)
  }

  return {
    command: commandPath,
    env: buildTrustedWindowsChildEnvironment(environment, systemRoot, additionalEnvironment),
  }
}
