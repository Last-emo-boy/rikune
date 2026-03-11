/**
 * Configuration management for MCP Server
 * Handles loading and validating configuration from files and environment variables
 */

import { z } from 'zod'
import fs from 'fs'

// Configuration schema using Zod
export const ConfigSchema = z.object({
  server: z.object({
    port: z.number().int().min(1).max(65535).default(3000),
    host: z.string().default('localhost'),
  }).default({}),
  database: z.object({
    type: z.enum(['sqlite', 'postgresql']).default('sqlite'),
    path: z.string().optional(),
    host: z.string().optional(),
    port: z.number().int().optional(),
    database: z.string().optional(),
    user: z.string().optional(),
    password: z.string().optional(),
  }).default({}),
  workspace: z.object({
    root: z.string().default('./workspaces'),
    maxSampleSize: z.number().int().min(1).default(500 * 1024 * 1024), // 500MB
  }).default({}),
  workers: z.object({
    ghidra: z.object({
      enabled: z.boolean().default(false),
      path: z.string().optional(),
      maxConcurrent: z.number().int().min(1).max(16).default(4),
      timeout: z.number().int().min(1).default(300),
    }).default({}),
    static: z.object({
      enabled: z.boolean().default(true),
      pythonPath: z.string().optional(),
      timeout: z.number().int().min(1).default(60),
    }).default({}),
    dotnet: z.object({
      enabled: z.boolean().default(false),
      ilspyPath: z.string().optional(),
      timeout: z.number().int().min(1).default(60),
    }).default({}),
    sandbox: z.object({
      enabled: z.boolean().default(false),
      timeout: z.number().int().min(1).default(120),
    }).default({}),
  }).default({}),
  cache: z.object({
    enabled: z.boolean().default(true),
    ttl: z.number().int().min(0).default(30 * 24 * 60 * 60), // 30 days
  }).default({}),
  logging: z.object({
    level: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),
    pretty: z.boolean().default(false),
  }).default({}),
})

export type Config = z.infer<typeof ConfigSchema>

/**
 * Load configuration from a JSON file
 */
export function loadConfigFromFile(filePath: string): Partial<Config> {
  try {
    const content = fs.readFileSync(filePath, 'utf-8')
    return JSON.parse(content)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return {}
    }
    throw new Error(`Failed to load config from ${filePath}: ${(error as Error).message}`)
  }
}

/**
 * Load configuration from environment variables
 */
export function loadConfigFromEnv(): Record<string, any> {
  const config: Record<string, any> = {}

  // Server configuration
  if (process.env.SERVER_PORT) {
    if (!config.server) config.server = {}
    config.server.port = parseInt(process.env.SERVER_PORT, 10)
  }
  if (process.env.SERVER_HOST) {
    if (!config.server) config.server = {}
    config.server.host = process.env.SERVER_HOST
  }

  // Database configuration
  if (process.env.DB_TYPE) {
    if (!config.database) config.database = {}
    config.database.type = process.env.DB_TYPE
  }
  if (process.env.DB_PATH) {
    if (!config.database) config.database = {}
    config.database.path = process.env.DB_PATH
  }
  if (process.env.DB_HOST) {
    if (!config.database) config.database = {}
    config.database.host = process.env.DB_HOST
  }
  if (process.env.DB_PORT) {
    if (!config.database) config.database = {}
    config.database.port = parseInt(process.env.DB_PORT, 10)
  }

  // Workspace configuration
  if (process.env.WORKSPACE_ROOT) {
    if (!config.workspace) config.workspace = {}
    config.workspace.root = process.env.WORKSPACE_ROOT
  }
  if (process.env.MAX_SAMPLE_SIZE) {
    if (!config.workspace) config.workspace = {}
    config.workspace.maxSampleSize = parseInt(process.env.MAX_SAMPLE_SIZE, 10)
  }

  // Worker configuration
  if (process.env.GHIDRA_PATH || process.env.GHIDRA_INSTALL_DIR) {
    if (!config.workers) config.workers = {}
    if (!config.workers.ghidra) config.workers.ghidra = {}
    config.workers.ghidra.path = process.env.GHIDRA_PATH || process.env.GHIDRA_INSTALL_DIR
    config.workers.ghidra.enabled = true
  }
  if (process.env.PYTHON_PATH) {
    if (!config.workers) config.workers = {}
    if (!config.workers.static) config.workers.static = {}
    config.workers.static.pythonPath = process.env.PYTHON_PATH
  }

  // Logging configuration
  if (process.env.LOG_LEVEL) {
    if (!config.logging) config.logging = {}
    config.logging.level = process.env.LOG_LEVEL
  }

  return config
}

/**
 * Deep merge helper function
 */
function deepMerge(target: any, source: any): any {
  const output = { ...target }
  
  if (isObject(target) && isObject(source)) {
    Object.keys(source).forEach(key => {
      if (isObject(source[key])) {
        if (!(key in target)) {
          output[key] = source[key]
        } else {
          output[key] = deepMerge(target[key], source[key])
        }
      } else {
        output[key] = source[key]
      }
    })
  }
  
  return output
}

function isObject(item: any): boolean {
  return item && typeof item === 'object' && !Array.isArray(item)
}

/**
 * Merge multiple configuration sources with priority: env > file > defaults
 */
export function mergeConfigs(...configs: any[]): any {
  return configs.reduce((acc, config) => deepMerge(acc, config), {})
}

/**
 * Load and validate configuration from all sources
 */
export function loadConfig(configPath?: string): Config {
  const fileConfig = configPath ? loadConfigFromFile(configPath) : {}
  const envConfig = loadConfigFromEnv()
  const mergedConfig = mergeConfigs(fileConfig, envConfig)

  const result = ConfigSchema.safeParse(mergedConfig)
  if (!result.success) {
    throw new Error(`Configuration validation failed: ${result.error.message}`)
  }

  return result.data
}

/**
 * Default configuration instance
 * Loads configuration from environment variables and default config file
 */
export const config = loadConfig()
