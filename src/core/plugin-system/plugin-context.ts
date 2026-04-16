/**
 * Plugin Context Factory
 *
 * Builds scoped PluginContext objects for plugin registration.
 */

import path from 'path'
import { fileURLToPath } from 'url'
import type { Plugin, PluginContext } from '../../plugins/sdk.js'
import { logger } from '../../logger.js'

/**
 * Create a scoped PluginContext for a plugin.
 * Provides a logger prefixed with the plugin ID and a type-safe config reader.
 */
export function createPluginContext(plugin: Plugin): PluginContext {
  const prefix = `[plugin:${plugin.id}]`
  const pluginLogger = {
    info:  (msg: string, data?: Record<string, unknown>) => logger.info(data ?? {}, `${prefix} ${msg}`),
    warn:  (msg: string, data?: Record<string, unknown>) => logger.warn(data ?? {}, `${prefix} ${msg}`),
    error: (msg: string, data?: Record<string, unknown>) => logger.error(data ?? {}, `${prefix} ${msg}`),
    debug: (msg: string, data?: Record<string, unknown>) => logger.debug(data ?? {}, `${prefix} ${msg}`),
  }

  // Build config lookup from declared configSchema
  const configMap = new Map<string, string>()
  if (plugin.configSchema) {
    for (const field of plugin.configSchema) {
      const val = process.env[field.envVar] ?? field.defaultValue
      if (val !== undefined) configMap.set(field.envVar, val)
    }
  }

  return {
    pluginId: plugin.id,
    logger: pluginLogger,
    getConfig: (envVar: string) => configMap.get(envVar),
    getRequiredConfig: (envVar: string) => {
      const val = configMap.get(envVar)
      if (val === undefined) throw new Error(`Plugin '${plugin.id}': required config '${envVar}' is not set`)
      return val
    },
    dataDir: path.join(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..'), 'data', 'plugins', plugin.id),
  }
}
