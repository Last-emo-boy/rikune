export { buildWsbXml, escapeXml, type WsbConfig } from './wsb-builder.js'
export {
  buildTrustedWindowsPowerShellScript,
  encodeTrustedWindowsPowerShellScript,
  TRUSTED_WINDOWS_POWERSHELL_MODULE_PATH_PRELUDE,
} from './windows-powershell.js'
export * from './runtime-contract.js'
export * from './runtime-control-plane.js'
export * from './network-endpoint-policy.js'
export * from './trusted-fetch.js'

export function getPythonCommand(
  platform: NodeJS.Platform = process.platform,
  overridePath?: string
): string {
  if (overridePath) return overridePath
  if (platform === 'win32') {
    return 'python'
  }
  return 'python3'
}
