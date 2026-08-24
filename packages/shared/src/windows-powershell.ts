export const TRUSTED_WINDOWS_POWERSHELL_MODULE_PATH_PRELUDE = String.raw`$env:PSModulePath = $env:SystemRoot + '\System32\WindowsPowerShell\v1.0\Modules'`

export function buildTrustedWindowsPowerShellScript(script: string): string {
  if (script.includes('\0')) {
    throw new Error('Trusted Windows PowerShell script cannot contain NUL bytes')
  }
  return `${TRUSTED_WINDOWS_POWERSHELL_MODULE_PATH_PRELUDE}\r\n${script}`
}

export function encodeTrustedWindowsPowerShellScript(script: string): string {
  return Buffer.from(buildTrustedWindowsPowerShellScript(script), 'utf16le').toString('base64')
}
