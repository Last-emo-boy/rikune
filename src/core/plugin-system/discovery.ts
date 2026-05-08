/**
 * Plugin Auto-Discovery
 *
 * Scans built-in and external plugin directories.
 */

import fs from 'fs/promises'
import path from 'path'
import { pathToFileURL, fileURLToPath } from 'url'
import type { ManifestHandlers, Plugin, PluginManifest } from '../../plugins/sdk.js'
import { defineManifestPlugin, validatePlugin } from '../../plugins/sdk.js'
import { logger } from '../../logger.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const RUNTIME_ROOT = path.resolve(__dirname, '../..')
const PROJECT_ROOT = path.resolve(RUNTIME_ROOT, '..')

function isPluginCandidate(value: unknown): value is Plugin {
  if (!value || typeof value !== 'object') {
    return false
  }
  const candidate = value as Partial<Plugin>
  return (
    typeof candidate.id === 'string' &&
    (typeof candidate.register === 'function' || Array.isArray(candidate.tools))
  )
}

function isValidPlugin(value: unknown): value is Plugin {
  return isPluginCandidate(value) && validatePlugin(value).ok
}

function resolveHandlers(mod: Record<string, unknown>): ManifestHandlers {
  const defaultExport = mod.default
  if (
    defaultExport &&
    typeof defaultExport === 'object' &&
    'handlers' in defaultExport &&
    typeof (defaultExport as { handlers?: unknown }).handlers === 'object'
  ) {
    return (defaultExport as { handlers: ManifestHandlers }).handlers
  }
  if (mod.handlers && typeof mod.handlers === 'object') {
    return mod.handlers as ManifestHandlers
  }
  if (defaultExport && typeof defaultExport === 'object') {
    return defaultExport as ManifestHandlers
  }
  return mod as ManifestHandlers
}

async function loadPluginFromDirectory(
  indexPath: string,
  manifestPath: string
): Promise<Plugin | null> {
  const mod = (await import(pathToFileURL(indexPath).href)) as Record<string, unknown>
  const directPlugin = mod.default ?? mod.plugin
  if (isValidPlugin(directPlugin)) {
    return directPlugin
  }

  try {
    await fs.access(manifestPath)
  } catch {
    return null
  }

  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8')) as PluginManifest
  return defineManifestPlugin(manifest, resolveHandlers(mod))
}

async function resolveDirectoryEntrypoint(pluginDir: string): Promise<string | null> {
  for (const fileName of ['index.js', 'index.mjs', 'index.ts']) {
    const candidate = path.join(pluginDir, fileName)
    try {
      await fs.access(candidate)
      return candidate
    } catch {
      // Try the next supported entrypoint.
    }
  }
  return null
}

/**
 * Discover built-in plugins from `src/plugins/` (compiled to `dist/plugins/`).
 * Each subdirectory with an `index.js` entry point is loaded as a plugin.
 */
export async function discoverBuiltInPlugins(): Promise<Plugin[]> {
  for (const pluginsDir of [
    path.join(RUNTIME_ROOT, 'plugins'),
    path.join(PROJECT_ROOT, 'dist', 'plugins'),
    path.join(PROJECT_ROOT, 'src', 'plugins'),
  ]) {
    try {
      await fs.access(pluginsDir)
      return discoverPluginsFromDir(pluginsDir, 'built-in', { scanFlatFiles: false })
    } catch {
      // Try the next runtime layout.
    }
  }
  return []
}

/**
 * Discover external plugins from `plugins/` at project root.
 * Supports both directory-based (with index.js) and flat .js/.mjs files.
 */
export async function discoverExternalPlugins(): Promise<Plugin[]> {
  const pluginsDir = path.join(PROJECT_ROOT, 'plugins')
  return discoverPluginsFromDir(pluginsDir, 'external', { scanFlatFiles: true })
}

/**
 * Scan a directory for plugin modules.
 * - Subdirectories with `index.js` → loaded as directory-based plugins
 * - Flat `.js`/`.mjs` files → loaded as single-file plugins
 */
export async function discoverPluginsFromDir(
  pluginsDir: string,
  source: string,
  options: {
    scanFlatFiles?: boolean
  } = {}
): Promise<Plugin[]> {
  try {
    await fs.access(pluginsDir)
  } catch {
    return [] // directory doesn't exist — that's fine
  }

  const entries = await fs.readdir(pluginsDir, { withFileTypes: true })
  const discovered: Plugin[] = []

  // Scan subdirectories for index.js entry points
  for (const entry of entries) {
    if (entry.isDirectory()) {
      const pluginDir = path.join(pluginsDir, entry.name)
      const indexPath = await resolveDirectoryEntrypoint(pluginDir)
      const manifestPath = path.join(pluginsDir, entry.name, 'plugin.json')
      if (!indexPath) {
        continue
      }
      try {
        const plugin = await loadPluginFromDirectory(indexPath, manifestPath)
        if (plugin) {
          discovered.push(plugin)
          logger.info(
            { dir: entry.name, plugin: plugin.id, source },
            `Discovered ${source} plugin: ${plugin.name}`
          )
        }
      } catch (err) {
        logger.warn(
          { dir: entry.name, err, source },
          `Failed to load ${source} plugin from directory`
        )
      }
    }
  }

  // Also scan flat .js/.mjs files (backward compat for external plugins)
  if (options.scanFlatFiles) {
    const jsFiles = entries
      .filter((e) => e.isFile() && (e.name.endsWith('.js') || e.name.endsWith('.mjs')))
      .map((e) => path.join(pluginsDir, e.name))

    for (const file of jsFiles) {
      try {
        const mod = await import(pathToFileURL(file).href)
        const plugin: Plugin | undefined = mod.default ?? mod.plugin
        if (isValidPlugin(plugin)) {
          discovered.push(plugin)
          logger.info(
            { file: path.basename(file), plugin: plugin.id, source },
            `Discovered ${source} plugin: ${plugin.name}`
          )
        }
      } catch (err) {
        logger.warn(
          { file: path.basename(file), err, source },
          `Failed to load ${source} plugin file`
        )
      }
    }
  }

  return discovered
}
