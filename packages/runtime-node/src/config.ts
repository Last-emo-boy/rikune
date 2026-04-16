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

function loadConfigFromEnv(): Record<string, any> {
  const cfg: Record<string, any> = {}
  if (process.env.RUNTIME_PORT) {
    if (!cfg.server) cfg.server = {}
    cfg.server.port = parseInt(process.env.RUNTIME_PORT, 10)
  }
  if (process.env.RUNTIME_HOST) {
    if (!cfg.server) cfg.server = {}
    cfg.server.host = process.env.RUNTIME_HOST
  }
  if (process.env.RUNTIME_MODE) {
    if (!cfg.runtime) cfg.runtime = {}
    cfg.runtime.mode = process.env.RUNTIME_MODE
  }
  if (process.env.RUNTIME_INBOX) {
    if (!cfg.runtime) cfg.runtime = {}
    cfg.runtime.inbox = process.env.RUNTIME_INBOX
  }
  if (process.env.RUNTIME_OUTBOX) {
    if (!cfg.runtime) cfg.runtime = {}
    cfg.runtime.outbox = process.env.RUNTIME_OUTBOX
  }
  if (process.env.RUNTIME_API_KEY) {
    if (!cfg.runtime) cfg.runtime = {}
    cfg.runtime.apiKey = process.env.RUNTIME_API_KEY
  }
  if (process.env.RUNTIME_READY_FILE) {
    if (!cfg.runtime) cfg.runtime = {}
    cfg.runtime.readyFile = process.env.RUNTIME_READY_FILE
  }
  if (process.env.RUNTIME_CORS_ORIGIN) {
    if (!cfg.runtime) cfg.runtime = {}
    cfg.runtime.corsOrigin = process.env.RUNTIME_CORS_ORIGIN
  }
  if (process.env.LOG_LEVEL) {
    if (!cfg.logging) cfg.logging = {}
    cfg.logging.level = process.env.LOG_LEVEL
  }
  return cfg
}

export function loadConfig(): Config {
  const envConfig = loadConfigFromEnv()
  const result = ConfigSchema.safeParse(envConfig)
  if (!result.success) {
    throw new Error(`Runtime config validation failed: ${result.error.message}`)
  }
  return result.data
}

export const config = loadConfig()
