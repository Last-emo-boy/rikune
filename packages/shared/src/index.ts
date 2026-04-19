export { buildWsbXml, escapeXml, type WsbConfig } from './wsb-builder.js'

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
