/**
 * System Dependency Checker
 *
 * Auto-validates plugin runtime requirements.
 */

import { accessSync } from 'fs'
import { execFile } from 'child_process'
import { promisify } from 'util'
import type { PluginSystemDep, DepCheckResult } from '../../plugins/sdk.js'
import { getPythonCommand } from '../../utils/shared-helpers.js'

const execFileAsync = promisify(execFile)

/**
 * Python imports are module paths, not arbitrary code. Keep the value
 * constrained to dotted identifiers before interpolating it into `python -c`.
 */
export function isValidPythonImportName(value: unknown): value is string {
  return (
    typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(value)
  )
}

/**
 * Resolve the effective target path for a dependency, substituting `$ENV_VAR`
 * references and falling back to dockerDefault or the bare name.
 */
export function resolveDepTarget(dep: PluginSystemDep): string {
  if (dep.envVar && process.env[dep.envVar]) return process.env[dep.envVar]
  if (dep.target) {
    // Substitute $ENV_VAR references in target
    const substituted = dep.target.replace(/\$([A-Z_][A-Z0-9_]*)/g, (_m, v) => process.env[v] ?? '')
    if (substituted.trim().length > 0) {
      return substituted
    }
    if (dep.dockerDefault) {
      return dep.dockerDefault
    }
  }
  return dep.dockerDefault ?? dep.name
}

/**
 * Check a single system dependency. Returns a structured result.
 */
export async function checkOneDep(dep: PluginSystemDep): Promise<DepCheckResult> {
  const result: DepCheckResult = { dep, available: false }
  try {
    switch (dep.type) {
      case 'binary': {
        const target = resolveDepTarget(dep)
        result.resolvedPath = target
        const vFlag = dep.versionFlag ?? '--version'
        const { stdout } = await execFileAsync(target, [vFlag], { timeout: 5000 })
        result.version = stdout.toString().trim().split('\n')[0]?.slice(0, 120)
        result.available = true
        break
      }
      case 'python': {
        const mod = dep.importName ?? dep.name
        if (!isValidPythonImportName(mod)) {
          throw new Error(`Invalid Python import name: ${String(mod)}`)
        }
        // `target` is the pip package name for Python deps. Interpreter
        // selection is controlled by envVar/dockerDefault, then the platform
        // default, so package metadata is never executed as a command.
        const target = resolveDepTarget({ ...dep, name: getPythonCommand(), target: undefined })
        result.resolvedPath = target
        await execFileAsync(
          target,
          ['-c', `import ${mod}; print(getattr(${mod}, '__version__', 'ok'))`],
          { timeout: 10000 }
        )
        result.available = true
        break
      }
      case 'python-venv': {
        const target = resolveDepTarget(dep)
        result.resolvedPath = target
        accessSync(target)
        const { stdout } = await execFileAsync(target, ['--version'], { timeout: 5000 })
        result.version = stdout.toString().trim()
        result.available = true
        break
      }
      case 'env-var': {
        const envName = dep.envVar ?? dep.target ?? dep.name
        const val = process.env[envName]
        result.available = val !== undefined && val !== ''
        if (val) result.resolvedPath = val
        break
      }
      case 'directory': {
        const target = resolveDepTarget(dep)
        result.resolvedPath = target
        accessSync(target)
        result.available = true
        break
      }
      case 'file': {
        const target = resolveDepTarget(dep)
        result.resolvedPath = target
        accessSync(target)
        result.available = true
        break
      }
    }
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err)
  }
  return result
}

/**
 * Check all system dependencies declared by a plugin.
 * Returns an array of results + a boolean indicating whether all required deps passed.
 */
export async function checkSystemDeps(plugin: {
  systemDeps?: PluginSystemDep[]
}): Promise<{ results: DepCheckResult[]; allRequiredOk: boolean }> {
  if (!plugin.systemDeps || plugin.systemDeps.length === 0) {
    return { results: [], allRequiredOk: true }
  }
  const results = await Promise.all(plugin.systemDeps.map(checkOneDep))
  const allRequiredOk = results.every((r) => r.available || !r.dep.required)
  return { results, allRequiredOk }
}
