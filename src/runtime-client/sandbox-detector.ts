/**
 * Detect whether Windows Sandbox is available on this machine.
 */

import fs from 'fs'
import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

let cachedAvailability: boolean | null = null

export async function isWindowsSandboxAvailable(): Promise<boolean> {
  if (cachedAvailability !== null) return cachedAvailability

  // Level 1: executable exists
  const exePath = 'C:\\Windows\\System32\\WindowsSandbox.exe'
  if (!fs.existsSync(exePath)) {
    cachedAvailability = false
    return false
  }

  // Level 2: optional feature check (best-effort, non-blocking)
  try {
    const { stdout } = await execFileAsync(
      'dism',
      ['/Online', '/Get-FeatureInfo', '/FeatureName:Containers-DisposableClientVM'],
      { timeout: 10000, windowsHide: true },
    )
    const enabled = stdout.includes('State : Enabled')
    cachedAvailability = enabled
    return enabled
  } catch {
    // If DISM fails, assume available because executable exists
    cachedAvailability = true
    return true
  }
}
