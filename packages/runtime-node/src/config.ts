/**
 * Minimal configuration for the runtime node.
 */

import { z } from 'zod'

export const ConfigSchema = z.object({
  server: z.object({
    port: z.number().int().min(1).max(65535).default(18081),
    host: z.string().default('0.0.0.0'),
  }).default({}),
  runtime: z.object({
    mode: z.enum(['sandbox', 'manual', 'disabled']).default('sandbox'),
    inbox: z.string().default('C:\\rikune-inbox'),
    outbox: z.string().default('C:\\rikune-outbox'),
    apiKey: z.string().optional(),
    readyFile: z.string().optional(),
    corsOrigin: z.string().optional(),
    pythonPath: z.string().default('python'),
    maxRssBytes: z.number().default(2 * 1024 * 1024 * 1024),
    minDiskSpaceBytes: z.number().default(5 * 1024 * 1024 * 1024),
  }).default({}),
  logging: z.object({
    level: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),
  }).default({}),
})

export type Config = z.infer<typeof ConfigSchema>

export interface RuntimeConfigLoadOptions {
  argv?: string[]
  env?: NodeJS.ProcessEnv
}

function ensureNestedObject(root: Record<string, any>, key: string): Record<string, any> {
  if (!root[key]) {
    root[key] = {}
  }
  return root[key] as Record<string, any>
}

function parseInteger(rawValue: string, flagName: string): number {
  const parsed = Number.parseInt(rawValue, 10)
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid numeric value for ${flagName}: ${rawValue}`)
  }
  return parsed
}

function normalizeCliFlag(flag: string): string | null {
  switch (flag) {
    case '--port':
    case '--host':
    case '--mode':
    case '--inbox':
    case '--outbox':
    case '--api-key':
    case '--ready-file':
    case '--cors-origin':
    case '--python-path':
    case '--max-rss-bytes':
    case '--min-disk-space-bytes':
    case '--log-level':
      return flag
    default:
      return null
  }
}

export function loadConfigFromCliArgs(argv: string[] = process.argv.slice(2)): Record<string, any> {
  const cfg: Record<string, any> = {}

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index]
    if (!current.startsWith('--')) {
      continue
    }

    const [rawFlag, inlineValue] = current.split(/=(.*)/s, 2)
    const flag = normalizeCliFlag(rawFlag)
    if (!flag) {
      continue
    }

    const value = inlineValue ?? argv[index + 1]
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`Missing value for ${flag}`)
    }
    if (inlineValue === undefined) {
      index += 1
    }

    switch (flag) {
      case '--port':
        ensureNestedObject(cfg, 'server').port = parseInteger(value, flag)
        break
      case '--host':
        ensureNestedObject(cfg, 'server').host = value
        break
      case '--mode':
        ensureNestedObject(cfg, 'runtime').mode = value
        break
      case '--inbox':
        ensureNestedObject(cfg, 'runtime').inbox = value
        break
      case '--outbox':
        ensureNestedObject(cfg, 'runtime').outbox = value
        break
      case '--api-key':
        ensureNestedObject(cfg, 'runtime').apiKey = value
        break
      case '--ready-file':
        ensureNestedObject(cfg, 'runtime').readyFile = value
        break
      case '--cors-origin':
        ensureNestedObject(cfg, 'runtime').corsOrigin = value
        break
      case '--python-path':
        ensureNestedObject(cfg, 'runtime').pythonPath = value
        break
      case '--max-rss-bytes':
        ensureNestedObject(cfg, 'runtime').maxRssBytes = parseInteger(value, flag)
        break
      case '--min-disk-space-bytes':
        ensureNestedObject(cfg, 'runtime').minDiskSpaceBytes = parseInteger(value, flag)
        break
      case '--log-level':
        ensureNestedObject(cfg, 'logging').level = value
        break
    }
  }

  return cfg
}

export function loadConfigFromEnv(env: NodeJS.ProcessEnv = process.env): Record<string, any> {
  const cfg: Record<string, any> = {}
  if (env.RUNTIME_PORT) {
    ensureNestedObject(cfg, 'server').port = parseInt(env.RUNTIME_PORT, 10)
  }
  if (env.RUNTIME_HOST) {
    ensureNestedObject(cfg, 'server').host = env.RUNTIME_HOST
  }
  if (env.RUNTIME_MODE) {
    ensureNestedObject(cfg, 'runtime').mode = env.RUNTIME_MODE
  }
  if (env.RUNTIME_INBOX) {
    ensureNestedObject(cfg, 'runtime').inbox = env.RUNTIME_INBOX
  }
  if (env.RUNTIME_OUTBOX) {
    ensureNestedObject(cfg, 'runtime').outbox = env.RUNTIME_OUTBOX
  }
  if (env.RUNTIME_API_KEY) {
    ensureNestedObject(cfg, 'runtime').apiKey = env.RUNTIME_API_KEY
  }
  if (env.RUNTIME_READY_FILE) {
    ensureNestedObject(cfg, 'runtime').readyFile = env.RUNTIME_READY_FILE
  }
  if (env.RUNTIME_CORS_ORIGIN) {
    ensureNestedObject(cfg, 'runtime').corsOrigin = env.RUNTIME_CORS_ORIGIN
  }
  if (env.RUNTIME_PYTHON_PATH) {
    ensureNestedObject(cfg, 'runtime').pythonPath = env.RUNTIME_PYTHON_PATH
  }
  if (env.RUNTIME_MAX_RSS_BYTES) {
    ensureNestedObject(cfg, 'runtime').maxRssBytes = parseInt(env.RUNTIME_MAX_RSS_BYTES, 10)
  }
  if (env.RUNTIME_MIN_DISK_SPACE_BYTES) {
    ensureNestedObject(cfg, 'runtime').minDiskSpaceBytes = parseInt(env.RUNTIME_MIN_DISK_SPACE_BYTES, 10)
  }
  if (env.LOG_LEVEL) {
    ensureNestedObject(cfg, 'logging').level = env.LOG_LEVEL
  }
  return cfg
}

function mergeConfigLayers(baseConfig: Record<string, any>, overrideConfig: Record<string, any>): Record<string, any> {
  const merged: Record<string, any> = {
    ...baseConfig,
  }

  for (const [key, value] of Object.entries(overrideConfig)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      merged[key] = mergeConfigLayers((baseConfig[key] as Record<string, any>) ?? {}, value as Record<string, any>)
      continue
    }
    merged[key] = value
  }

  return merged
}

export function loadConfig(options: RuntimeConfigLoadOptions = {}): Config {
  const envConfig = loadConfigFromEnv(options.env)
  const cliConfig = loadConfigFromCliArgs(options.argv)
  const mergedConfig = mergeConfigLayers(envConfig, cliConfig)
  const result = ConfigSchema.safeParse(mergedConfig)
  if (!result.success) {
    throw new Error(`Runtime config validation failed: ${result.error.message}`)
  }
  return result.data
}

export const config = loadConfig()
