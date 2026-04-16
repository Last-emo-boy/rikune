/**
 * Plugin Orchestrator — discovery, loading, sorting, and lifecycle management.
 */

import type { ToolDeps } from './tool-registry.js'
import type { ToolRegistrar, PromptRegistrar, ResourceRegistrar, SamplingClient } from './registrar.js'
import { logger } from '../logger.js'
import { config } from '../config.js'
import { getToolSurfaceManager } from './tool-surface-manager.js'
import { PluginRuntimeBridge } from './plugin-runtime-bridge.js'
import { createPluginContext } from './plugin-system/plugin-context.js'
import { checkSystemDeps } from './plugin-system/system-deps.js'
import { discoverBuiltInPlugins, discoverExternalPlugins } from './plugin-system/discovery.js'
import type { Plugin, PluginStatus } from '../plugins/sdk.js'

type PluginServer = ToolRegistrar & PromptRegistrar & ResourceRegistrar & SamplingClient

export class PluginOrchestrator {
  private plugins: PluginStatus[] = []
  private loadedPlugins = new Map<string, Plugin>()
  private pluginToolMap = new Map<string, string>() // toolName → pluginId
  private discoveredPlugins: Plugin[] = []
  private server: PluginServer | null = null
  private deps: ToolDeps | null = null

  /** Get status of all known plugins. */
  getStatuses(): PluginStatus[] { return [...this.plugins] }

  /** Get the Plugin definition for a loaded plugin. */
  getPlugin(id: string): Plugin | undefined { return this.loadedPlugins.get(id) }

  /** Find which plugin owns a given tool name. */
  getPluginForTool(toolName: string): string | undefined { return this.pluginToolMap.get(toolName) }

  /** Check if a specific plugin is loaded. */
  isLoaded(id: string): boolean { return this.loadedPlugins.has(id) }

  /** Get all discovered plugin definitions (loaded or not). */
  getDiscoveredPlugins(): Plugin[] { return [...this.discoveredPlugins] }

  getPluginToolMap(): ReadonlyMap<string, string> { return this.pluginToolMap }
  getLoadedPlugins(): ReadonlyMap<string, Plugin> { return this.loadedPlugins }

  /**
   * Resolve which plugins are enabled via `PLUGINS` env var.
   * - `*` or empty → all
   * - `android,malware` → only those
   * - `-dynamic` → all except
   */
  resolveEnabledPlugins(plugins: Plugin[]): Plugin[] {
    const envVal = (process.env.PLUGINS ?? '*').trim()
    if (envVal === '*' || envVal === '') return plugins

    const tokens = envVal.split(',').map(t => t.trim()).filter(Boolean)
    const excluded = new Set(tokens.filter(t => t.startsWith('-')).map(t => t.slice(1)))
    const included = new Set(tokens.filter(t => !t.startsWith('-')))

    if (included.size > 0) return plugins.filter(p => included.has(p.id))
    return plugins.filter(p => !excluded.has(p.id))
  }

  /**
   * Filter plugins by executionDomain based on the current node role.
   * - analyzer: skip executionDomain === 'dynamic'
   * - runtime: skip executionDomain === 'static'
   * - hybrid: keep all
   */
  resolvePluginsByRole(plugins: Plugin[]): Plugin[] {
    const role = config.node.role
    if (role === 'hybrid') return plugins
    return plugins.filter(p => {
      const domain = p.executionDomain ?? 'both'
      if (domain === 'both') return true
      // analyzer keeps dynamic plugins so we can register delegated handlers
      if (role === 'analyzer' && domain === 'dynamic') return true
      if (role === 'runtime' && domain === 'static') return false
      return true
    })
  }

  /**
   * Topologically sort plugins by their `dependencies` arrays.
   * Throws if a cycle is detected.
   */
  topoSort(plugins: Plugin[]): Plugin[] {
    const idMap = new Map(plugins.map(p => [p.id, p]))
    const visited = new Set<string>()
    const visiting = new Set<string>()
    const visitStack: string[] = []
    const sorted: Plugin[] = []

    const visit = (id: string) => {
      if (visited.has(id)) return
      if (visiting.has(id)) {
        // Build cycle path for user-friendly error
        const cycleStart = visitStack.indexOf(id)
        const cyclePath = [...visitStack.slice(cycleStart), id].join(' → ')
        throw new Error(`Plugin dependency cycle detected: ${cyclePath}`)
      }
      visiting.add(id)
      visitStack.push(id)
      const plugin = idMap.get(id)
      if (plugin?.dependencies) {
        for (const dep of plugin.dependencies) {
          if (idMap.has(dep)) visit(dep)
        }
      }
      visiting.delete(id)
      visitStack.pop()
      visited.add(id)
      if (plugin) sorted.push(plugin)
    }

    for (const p of plugins) visit(p.id)
    return sorted
  }

  /**
   * Load all enabled plugins in dependency order.
   * Discovers plugins from `src/plugins/` directories and external `plugins/` dir.
   */
  async loadAll(
    server: PluginServer,
    deps: ToolDeps,
    extraPlugins: Plugin[] = [],
  ): Promise<PluginStatus[]> {
    this.server = server
    this.deps = deps

    // Discover all plugins from filesystem
    const builtInPlugins = await discoverBuiltInPlugins()
    const externalPlugins = await discoverExternalPlugins()
    const allPlugins = [...builtInPlugins, ...externalPlugins, ...extraPlugins]

    // Deduplicate by id (first occurrence wins — built-in takes priority)
    const seen = new Set<string>()
    const uniquePlugins: Plugin[] = []
    for (const p of allPlugins) {
      if (!seen.has(p.id)) {
        seen.add(p.id)
        uniquePlugins.push(p)
      }
    }

    this.discoveredPlugins = uniquePlugins
    const enabled = this.resolveEnabledPlugins(uniquePlugins)
    const roleFiltered = this.resolvePluginsByRole(enabled)
    const enabledIds = new Set(enabled.map(p => p.id))
    const roleAllowedIds = new Set(roleFiltered.map(p => p.id))
    const sorted = this.topoSort(roleFiltered)

    // Record disabled plugins
    for (const p of uniquePlugins) {
      if (!enabledIds.has(p.id)) {
        this.plugins.push({
          id: p.id, name: p.name, description: p.description,
          version: p.version, status: 'skipped-disabled', tools: [],
          configFields: p.configSchema,
        })
      } else if (!roleAllowedIds.has(p.id)) {
        this.plugins.push({
          id: p.id, name: p.name, description: p.description,
          version: p.version, status: 'skipped-disabled', tools: [],
          configFields: p.configSchema,
          error: `Skipped because executionDomain ('${p.executionDomain ?? 'both'}') is incompatible with node role '${config.node.role}'`,
        })
      }
    }

    // Load in topological order
    for (const plugin of sorted) {
      await this.loadOne(plugin, server, deps)
    }

    logger.info(
      { total: uniquePlugins.length, loaded: this.loadedPlugins.size },
      `Plugin discovery complete: ${this.loadedPlugins.size}/${uniquePlugins.length} plugins loaded`,
    )

    // Log aggregated dependency health report
    this.logDependencyHealth()

    return this.plugins
  }

  /**
   * Log a structured dependency health report across all plugins.
   */
  private logDependencyHealth(): void {
    const allChecks: Array<{ plugin: string; dep: string; type: string; required: boolean; available: boolean; path?: string; error?: string }> = []
    for (const s of this.plugins) {
      if (s.depChecks) {
        for (const r of s.depChecks) {
          allChecks.push({
            plugin: s.id, dep: r.dep.name, type: r.dep.type,
            required: r.dep.required, available: r.available,
            path: r.resolvedPath, error: r.error,
          })
        }
      }
    }
    if (allChecks.length === 0) return

    const ok = allChecks.filter(c => c.available).length
    const missing = allChecks.filter(c => !c.available && c.required)
    const optional = allChecks.filter(c => !c.available && !c.required)

    logger.info(
      { total: allChecks.length, ok, missingRequired: missing.length, missingOptional: optional.length },
      `System dependency health: ${ok}/${allChecks.length} available` +
      (missing.length > 0 ? ` — ${missing.length} required deps MISSING` : '') +
      (optional.length > 0 ? ` — ${optional.length} optional deps not found` : ''),
    )

    if (missing.length > 0) {
      for (const m of missing) {
        logger.warn({ plugin: m.plugin, dep: m.dep, type: m.type }, `  MISSING: ${m.dep} (required by ${m.plugin})`)
      }
    }
  }

  /**
   * Load a single plugin. Used internally and for hot-load.
   */
  async loadOne(plugin: Plugin, server: PluginServer, deps: ToolDeps): Promise<PluginStatus> {
    const isAnalyzerDynamic = config.node.role === 'analyzer' && plugin.executionDomain === 'dynamic'
    const status: PluginStatus = {
      id: plugin.id, name: plugin.name, description: plugin.description,
      version: plugin.version, status: 'loaded', tools: [],
      configFields: plugin.configSchema,
    }

    // Check dependencies are loaded
    if (plugin.dependencies) {
      for (const dep of plugin.dependencies) {
        if (!this.loadedPlugins.has(dep)) {
          status.status = 'skipped-deps'
          status.error = `Required dependency '${dep}' is not loaded`
          this.plugins.push(status)
          logger.info({ plugin: plugin.id, dep }, `Plugin skipped (dependency not loaded): ${plugin.name}`)
          return status
        }
      }
    }

    // Run prerequisite check
    if (plugin.check) {
      try {
        const ok = await plugin.check()
        if (!ok) {
          if (isAnalyzerDynamic) {
            logger.debug({ plugin: plugin.id }, `Plugin check failed but loading anyway for delegation: ${plugin.name}`)
          } else {
            status.status = 'skipped-check'
            status.error = 'Prerequisite check returned false'
            this.plugins.push(status)
            logger.info({ plugin: plugin.id }, `Plugin skipped (prerequisites not met): ${plugin.name}`)
            return status
          }
        }
      } catch (err) {
        if (isAnalyzerDynamic) {
          logger.debug({ plugin: plugin.id, err }, `Plugin check error but loading anyway for delegation: ${plugin.name}`)
        } else {
          status.status = 'skipped-check'
          status.error = `Prerequisite check threw: ${err}`
          this.plugins.push(status)
          logger.warn({ plugin: plugin.id, err }, `Plugin skipped (check error): ${plugin.name}`)
          return status
        }
      }
    }

    // Auto-check system dependencies (runs even if plugin has a manual check)
    if (plugin.systemDeps && plugin.systemDeps.length > 0) {
      const { results, allRequiredOk } = await checkSystemDeps(plugin)
      status.depChecks = results

      // Log each dependency result
      for (const r of results) {
        if (r.available) {
          logger.debug({ plugin: plugin.id, dep: r.dep.name, path: r.resolvedPath, version: r.version }, `  ✓ ${r.dep.name}`)
        } else if (r.dep.required) {
          logger.warn({ plugin: plugin.id, dep: r.dep.name, error: r.error }, `  ✗ ${r.dep.name} (required, missing)`)
        } else {
          logger.debug({ plugin: plugin.id, dep: r.dep.name }, `  ○ ${r.dep.name} (optional, not found)`)
        }
      }

      // If plugin has no manual check() and required deps are missing, skip it
      // Exception: analyzer node loading dynamic plugins — we still register them
      // so their tools can be delegated to the runtime sandbox.
      if (!plugin.check && !allRequiredOk && !isAnalyzerDynamic) {
        const missing = results.filter(r => !r.available && r.dep.required).map(r => r.dep.name)
        status.status = 'skipped-check'
        status.error = `Missing required system deps: ${missing.join(', ')}`
        this.plugins.push(status)
        logger.info({ plugin: plugin.id, missing }, `Plugin skipped (system deps not met): ${plugin.name}`)
        return status
      }
    }

    // Register tools
    try {
      // Create scoped PluginContext for this plugin
      const ctx = createPluginContext(plugin)

      // Validate required config fields from configSchema
      if (plugin.configSchema) {
        const missing = plugin.configSchema
          .filter(f => f.required && !process.env[f.envVar] && !f.defaultValue)
          .map(f => f.envVar)
        if (missing.length > 0) {
          logger.warn(
            { plugin: plugin.id, missing },
            `Plugin ${plugin.name}: missing required config: ${missing.join(', ')} — loading anyway`,
          )
        }
      }

      const bridge = new PluginRuntimeBridge(deps)
      const targetServer = bridge.createServerForPlugin(server, plugin.id, plugin.executionDomain)

      const toolNames = plugin.register(targetServer, deps, ctx)
      const names: string[] = Array.isArray(toolNames) ? toolNames : []
      status.tools = names
      for (const t of names) this.pluginToolMap.set(t, plugin.id)
      this.loadedPlugins.set(plugin.id, plugin)
      this.plugins.push(status)

      // Register plugin with progressive surface manager
      getToolSurfaceManager().registerPlugin(plugin, names)

      // Fire onActivate hook
      if (plugin.hooks?.onActivate) {
        try { await plugin.hooks.onActivate() } catch (e) {
          logger.warn({ plugin: plugin.id, err: e }, 'Plugin onActivate hook threw — swallowed')
        }
      }

      logger.info({ plugin: plugin.id, tools: names.length }, `Plugin loaded: ${plugin.name}`)
    } catch (err) {
      status.status = 'error'
      status.error = `Registration failed: ${err}`
      this.plugins.push(status)
      logger.error({ plugin: plugin.id, err }, `Plugin failed to load: ${plugin.name}`)
    }

    return status
  }

  /**
   * Hot-load a plugin at runtime (after server has started).
   * Returns the status of the newly loaded plugin.
   */
  async hotLoad(plugin: Plugin): Promise<PluginStatus> {
    if (!this.server || !this.deps) throw new Error('PluginManager not initialized — call loadAll first')
    if (this.loadedPlugins.has(plugin.id)) throw new Error(`Plugin '${plugin.id}' is already loaded`)
    return this.loadOne(plugin, this.server, this.deps)
  }

  /**
   * Unload a plugin at runtime — tears down and unregisters its tools.
   */
  async unload(pluginId: string): Promise<void> {
    const plugin = this.loadedPlugins.get(pluginId)
    if (!plugin) throw new Error(`Plugin '${pluginId}' is not loaded`)
    if (!this.server) throw new Error('PluginManager not initialized')

    // Fire onDeactivate hook
    if (plugin.hooks?.onDeactivate) {
      try { await plugin.hooks.onDeactivate() } catch (e) {
        logger.warn({ plugin: pluginId, err: e }, 'Plugin onDeactivate hook threw — swallowed')
      }
    }

    // Run teardown if defined
    if (plugin.teardown) {
      await plugin.teardown()
    }

    // Find and unregister tools
    const status = this.plugins.find(s => s.id === pluginId)
    if (status) {
      for (const toolName of status.tools) {
        this.server.unregisterTool(toolName)
        this.pluginToolMap.delete(toolName)
      }
      status.status = 'skipped-disabled'
      status.tools = []
    }

    this.loadedPlugins.delete(pluginId)
    logger.info({ plugin: pluginId }, `Plugin unloaded: ${plugin.name}`)
  }
}
