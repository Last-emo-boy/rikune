import fs from 'fs'
import path from 'path'
import type { Config } from './index.js'

export interface ValidationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
}

export function validateEnvironment(config: Config): ValidationResult {
  const errors: string[] = []
  const warnings: string[] = []

  // Node.js version check
  const nodeVersion = parseInt(process.versions.node.split('.')[0], 10)
  if (nodeVersion < 18) {
    errors.push(`Node.js version ${process.versions.node} is not supported. Minimum required: 18`)
  }

  // Workspace validation
  const workspaceRoot = config.workspace.root
  if (!fs.existsSync(workspaceRoot)) {
    try {
      fs.mkdirSync(workspaceRoot, { recursive: true })
      warnings.push(`Created workspace directory: ${workspaceRoot}`)
    } catch (err) {
      errors.push(`Failed to create workspace directory: ${workspaceRoot}`)
    }
  }

  // Database validation
  if (config.database.type === 'postgresql') {
    if (!config.database.host || !config.database.database) {
      errors.push('PostgreSQL configuration requires host and database name')
    }
  } else if (config.database.type === 'sqlite') {
    if (config.database.path) {
      const dbDir = path.dirname(config.database.path)
      if (!fs.existsSync(dbDir)) {
        try {
          fs.mkdirSync(dbDir, { recursive: true })
          warnings.push(`Created database directory: ${dbDir}`)
        } catch (err) {
          errors.push(`Failed to create database directory: ${dbDir}`)
        }
      }
    }
  }

  // Ghidra worker validation
  if (config.workers.ghidra.enabled) {
    const ghidraPath = config.workers.ghidra.path || process.env.GHIDRA_PATH
    if (!ghidraPath) {
      errors.push('Ghidra worker is enabled but GHIDRA_PATH is not configured')
    } else if (!fs.existsSync(ghidraPath)) {
      errors.push(`Ghidra path does not exist: ${ghidraPath}`)
    }
  }

  // Python/static worker validation
  if (config.workers.static.enabled && config.workers.static.pythonPath) {
    // Just validate not crashing - actual python check is best-effort
    warnings.push(`Python worker configured with path: ${config.workers.static.pythonPath}`)
  }

  // .NET worker validation
  if (config.workers.dotnet.enabled) {
    const ilspyPath = config.workers.dotnet.ilspyPath
    if (!ilspyPath) {
      errors.push('.NET worker is enabled but ilspyPath is not configured')
    } else if (!fs.existsSync(ilspyPath)) {
      errors.push(`ILSpy path does not exist: ${ilspyPath}`)
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  }
}
