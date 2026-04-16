/**
 * Detect whether the runtime is running inside an isolated environment.
 * Primarily targets Windows Sandbox.
 */

import fs from 'fs'
import os from 'os'

let cachedIsolated: boolean | null = null

export async function isIsolatedEnvironment(): Promise<boolean> {
  if (cachedIsolated !== null) return cachedIsolated

  const checks: (() => number)[] = [
    // Windows Sandbox uses WDAGUtilityAccount as the default user (strong signal)
    () => (os.userInfo().username === 'WDAGUtilityAccount' ? 2 : 0),
    // Windows Sandbox desktop path contains specific markers (strong signal)
    () => {
      try {
        const desktop = p('C:\\Users\\WDAGUtilityAccount\\Desktop')
        return fs.existsSync(desktop) ? 2 : 0
      } catch {
        return 0
      }
    },
    // Exact hostname match for WDAG (weak signal)
    () => (os.hostname().toLowerCase().startsWith('wdagutilityaccount') ? 1 : 0),
    // Generic sandbox in hostname (very weak, only contributory)
    () => (os.hostname().toLowerCase().includes('sandbox') ? 1 : 0),
    // Registry key often present in Sandbox (best-effort via environment proxies)
    () => (process.env.WDAG_ENABLED === '1' ? 1 : 0),
  ]

  const score = checks.reduce((sum, c) => sum + c(), 0)
  cachedIsolated = score >= 2
  return cachedIsolated
}

function p(pathStr: string): string {
  return pathStr
}
