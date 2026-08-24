export const ANALYZER_PLATFORM_ERROR =
  'Rikune v1.4.0 Analyzer requires a Linux kernel for fail-closed sample custody.'

export function assertSupportedAnalyzerPlatform(platform: NodeJS.Platform): void {
  if (platform !== 'linux') {
    throw new Error(`${ANALYZER_PLATFORM_ERROR} Received: ${platform}`)
  }
}
