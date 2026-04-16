/**
 * Plugin Auto-Discovery
 *
 * Scans built-in and external plugin directories.
 */

import fs from 'fs/promises'
import path from 'path'
import { pathToFileURL, fileURLToPath } from 'url'
import type { Plugin } from '../../plugins/sdk.js'
import { logger } from '../../logger.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = path.resolve(__dirname, '../..')

/**
 * Discover built-in plugins from `src/plugins/` (compiled to `dist/plugins/`).
 * Each subdirectory with an `index.js` entry point is loaded as a plugin.
 */
export async function discoverBuiltInPlugins(): Promise<Plugin[]> {
  const pluginsDir = path.join(__dirname, '../plugins')
  return discoverPluginsFromDir(pluginsDir, 'built-in')
}

/**
 * Discover external plugins from `plugins/` at project root.
 * Supports both directory-based (with index.js) and flat .js/.mjs files.
 */
export async function discoverExternalPlugins(): Promise<Plugin[]> {
  const pluginsDir = path.join(PROJECT_ROOT, 'plugins')
  return discoverPluginsFromDir(pluginsDir, 'external')
}

/**
 * Scan a directory for plugin modules.
 * - Subdirectories with `index.js` → loaded as directory-based plugins
 * - Flat `.js`/`.mjs` files → loaded as single-file plugins
 */
export async function discoverPluginsFromDir(pluginsDir: string, source: string): Promise<Plugin[]> {
  try {
    await fs.access(pluginsDir)
  } catch {
    return []  // directory doesn't exist — that's fine
  }

  const entries = await fs.readdir(pluginsDir, { withFileTypes: true })
  const discovered: Plugin[] = []

  // Scan subdirectories for index.js entry points
  for (const entry of entries) {
    if (entry.isDirectory()) {
      const indexPath = path.join(pluginsDir, entry.name, 'index.js')
      try {
        await fs.access(indexPath)
        const mod = await import(pathToFileURL(indexPath).href)
        const plugin: Plugin | undefined = mod.default ?? mod.plugin
        if (plugin && typeof plugin.id === 'string' && typeof plugin.register === 'function') {
          discovered.push(plugin)
          logger.info({ dir: entry.name, plugin: plugin.id, source }, `Discovered ${source} plugin: ${plugin.name}`)
        }
      } catch (err) {
        logger.warn({ dir: entry.name, err, source }, `Failed to load ${source} plugin from directory`)
      }
    }
  }

  // Also scan flat .js/.mjs files (backward compat for external plugins)
  const jsFiles = entries
    .filter(e => e.isFile() && (e.name.endsWith('.js') || e.name.endsWith('.mjs')))
    .map(e => path.join(pluginsDir, e.name))

  for (const file of jsFiles) {
    try {
      const mod = await import(pathToFileURL(file).href)
      const plugin: Plugin | undefined = mod.default ?? mod.plugin
      if (plugin && typeof plugin.id === 'string' && typeof plugin.register === 'function') {
        discovered.push(plugin)
        logger.info({ file: path.basename(file), plugin: plugin.id, source }, `Discovered ${source} plugin: ${plugin.name}`)
      }
    } catch (err) {
      logger.warn({ file: path.basename(file), err, source }, `Failed to load ${source} plugin file`)
    }
  }

  return discovered
}
