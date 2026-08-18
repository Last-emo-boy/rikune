/**
 * Plugin Orchestrator — discovery, loading, sorting, and lifecycle management.
 */

import type { ToolDeps } from './tool-registry.js'
import type {
  ToolRegistrar,
  PromptRegistrar,
  ResourceRegistrar,
  SamplingClient,
} from './registrar.js'
import { logger } from '../logger.js'
import { config } from '../config.js'
import { getToolSurfaceManager } from './tool-surface-manager.js'
import { PluginRuntimeBridge } from './plugin-runtime-bridge.js'
import { createPluginContext } from './plugin-system/plugin-context.js'
import { checkSystemDeps } from './plugin-system/system-deps.js'
import { discoverBuiltInPlugins, discoverExternalPlugins } from './plugin-system/discovery.js'
import type {
  Plugin,
  PluginContext,
  PluginServerInterface,
  PluginStatus,
  PluginSystemDep,
} from '../plugins/sdk.js'
import { auditPluginQuality, validatePlugin } from '../plugins/sdk.js'

type PluginServer = ToolRegistrar & PromptRegistrar & ResourceRegistrar & SamplingClient

type PluginDepsWithServices = ToolDeps & {
  services?: {
    platform?: Record<string, unknown>
    [key: string]: unknown
  }
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    value !== null &&
    (typeof value === 'object' || typeof value === 'function') &&
    typeof (value as { then?: unknown }).then === 'function'
  )
}

/**
 * Plugins that need sampling or internal tool calls receive a narrow facade,
 * not the mutable MCPServer instance. Registration remains available only
 * through the scoped `server` argument supplied to register().
 */
function createPluginPlatformServerFacade(server: PluginServer): Readonly<Record<string, unknown>> {
  const facade: Record<string, unknown> = {}
  for (const methodName of ['getClientCapabilities', 'getClientVersion', 'createMessage']) {
    const method = (server as unknown as Record<string, unknown>)[methodName]
    if (typeof method === 'function') {
      facade[methodName] = method.bind(server)
    }
  }
  const callTool = (server as unknown as { callTool?: (...args: unknown[]) => unknown }).callTool
  if (typeof callTool === 'function') {
    const boundCallTool = callTool.bind(server)
    const blockedTools = new Set([
      'plugin.enable',
      'plugin_enable',
      'plugin.disable',
      'plugin_disable',
    ])
    facade.callToolInternal = async (...args: unknown[]) => {
      const toolName = args[0]
      const normalizedToolName =
        typeof toolName === 'string'
          ? toolName.replace(/[^A-Za-z0-9_-]/g, '_').replace(/_+/g, '_')
          : null
      if (
        typeof toolName === 'string' &&
        (blockedTools.has(toolName) ||
          (normalizedToolName !== null && blockedTools.has(normalizedToolName)))
      ) {
        throw new Error(`Plugin dependency facade cannot invoke control-plane tool '${toolName}'`)
      }
      return boundCallTool(...args)
    }
  }
  return Object.freeze(facade)
}

function createScopedPluginDeps(deps: ToolDeps, server: PluginServer): ToolDeps {
  const source = deps as PluginDepsWithServices
  const platformServer = createPluginPlatformServerFacade(server)
  const services = source.services
    ? {
        ...source.services,
        platform: {
          ...(source.services.platform ?? {}),
          server: platformServer,
        },
      }
    : undefined

  return {
    ...source,
    server: platformServer as unknown as ToolDeps['server'],
    ...(services ? { services } : {}),
  } as ToolDeps
}

const DELEGATED_EXECUTION_DOCKER_FEATURES = new Set([
  'dynamic-python',
  'frida',
  'gdb',
  'qiling',
  'wine',
  'de4dot',
])

function isRemoteRuntimeAnalyzer(): boolean {
  const runtimeMode = config.runtime?.mode ?? 'disabled'
  return (
    config.node.role === 'analyzer' &&
    ['remote-sandbox', 'manual', 'auto-sandbox'].includes(runtimeMode)
  )
}

function localSystemDepsForNode(plugin: Plugin): PluginSystemDep[] {
  const deps = plugin.systemDeps ?? []
  if (!isRemoteRuntimeAnalyzer()) {
    return deps
  }

  if (plugin.executionDomain === 'dynamic') {
    return []
  }

  return deps.filter((dep) => {
    if (
      !dep.required &&
      dep.dockerFeature &&
      DELEGATED_EXECUTION_DOCKER_FEATURES.has(dep.dockerFeature)
    ) {
      return false
    }
    return true
  })
}

export class PluginOrchestrator {
  private plugins: PluginStatus[] = []
  private loadedPlugins = new Map<string, Plugin>()
  private pluginToolMap = new Map<string, string>() // toolName → pluginId
  private discoveredPlugins: Plugin[] = []
  private server: PluginServer | null = null
  private deps: ToolDeps | null = null

  /** Get status of all known plugins. */
  getStatuses(): PluginStatus[] {
    return [...this.plugins]
  }

  /** Get the Plugin definition for a loaded plugin. */
  getPlugin(id: string): Plugin | undefined {
    return this.loadedPlugins.get(id)
  }

  /** Find which plugin owns a given tool name. */
  getPluginForTool(toolName: string): string | undefined {
    return this.pluginToolMap.get(toolName)
  }

  /** Check if a specific plugin is loaded. */
  isLoaded(id: string): boolean {
    return this.loadedPlugins.has(id)
  }

  /** Get all discovered plugin definitions (loaded or not). */
  getDiscoveredPlugins(): Plugin[] {
    return [...this.discoveredPlugins]
  }

  getPluginToolMap(): ReadonlyMap<string, string> {
    return this.pluginToolMap
  }
  getLoadedPlugins(): ReadonlyMap<string, Plugin> {
    return this.loadedPlugins
  }

  /**
   * Resolve which plugins are enabled via `PLUGINS` env var.
   * - `*` or empty → all
   * - `android,malware` → only those
   * - `-dynamic` → all except
   */
  resolveEnabledPlugins(plugins: Plugin[]): Plugin[] {
    const envVal = (process.env.PLUGINS ?? '*').trim()
    if (envVal === '*' || envVal === '') return plugins

    const tokens = envVal
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean)
    const excluded = new Set(tokens.filter((t) => t.startsWith('-')).map((t) => t.slice(1)))
    const included = new Set(tokens.filter((t) => !t.startsWith('-')))

    if (included.size > 0) return plugins.filter((p) => included.has(p.id))
    return plugins.filter((p) => !excluded.has(p.id))
  }

  /**
   * Filter plugins by executionDomain based on the current node role.
   * - analyzer: keep all (static runs locally, dynamic gets delegated)
   * - runtime: keep only dynamic and both (static analysis does not run on runtime)
   * - hybrid: keep all
   */
  resolvePluginsByRole(plugins: Plugin[]): Plugin[] {
    const role = config.node.role
    if (role === 'hybrid') return plugins
    return plugins.filter((p) => {
      const domain = p.executionDomain ?? 'both'
      if (domain === 'both') return true
      if (role === 'analyzer') {
        // analyzer runs static locally and delegates dynamic to runtime
        return true
      }
      if (role === 'runtime') {
        // runtime only executes dynamic analysis inside the sandbox
        return domain === 'dynamic'
      }
      return true
    })
  }

  /**
   * Topologically sort plugins by their `dependencies` arrays.
   * Throws if a cycle is detected.
   */
  topoSort(plugins: Plugin[]): Plugin[] {
    const idMap = new Map(plugins.map((p) => [p.id, p]))
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
    extraPlugins: Plugin[] = []
  ): Promise<PluginStatus[]> {
    this.server = server
    this.deps = deps

    // Discover all plugins from filesystem
    const builtInPlugins = await discoverBuiltInPlugins()
    const externalPlugins = await discoverExternalPlugins()
    const allPlugins = [...builtInPlugins, ...externalPlugins, ...extraPlugins]

    // Keep built-in-first precedence, but surface every rejected duplicate so
    // discovery order never changes plugin ownership silently.
    const seen = new Map<string, Plugin>()
    const uniquePlugins: Plugin[] = []
    const duplicatePlugins: Array<{ plugin: Plugin; retained: Plugin }> = []
    for (const p of allPlugins) {
      const retained = seen.get(p.id)
      if (!retained) {
        seen.set(p.id, p)
        uniquePlugins.push(p)
      } else {
        duplicatePlugins.push({ plugin: p, retained })
      }
    }

    this.discoveredPlugins = uniquePlugins
    const enabled = this.resolveEnabledPlugins(uniquePlugins)
    const roleFiltered = this.resolvePluginsByRole(enabled)
    const enabledIds = new Set(enabled.map((p) => p.id))
    const roleAllowedIds = new Set(roleFiltered.map((p) => p.id))
    const sorted = this.topoSort(roleFiltered)

    // Record disabled plugins
    for (const p of uniquePlugins) {
      if (!enabledIds.has(p.id)) {
        this.plugins.push({
          id: p.id,
          name: p.name,
          description: p.description,
          version: p.version,
          executionDomain: p.executionDomain ?? 'both',
          status: 'skipped-disabled',
          tools: [],
          configFields: p.configSchema,
          reasonCode: 'disabled-by-config',
          statusDetail: 'Plugin disabled by PLUGINS selection',
          controlPlaneStatus: 'cancelled',
        })
      } else if (!roleAllowedIds.has(p.id)) {
        this.plugins.push({
          id: p.id,
          name: p.name,
          description: p.description,
          version: p.version,
          executionDomain: p.executionDomain ?? 'both',
          status: 'skipped-disabled',
          tools: [],
          configFields: p.configSchema,
          reasonCode: 'role-incompatible',
          statusDetail: `Plugin executionDomain '${p.executionDomain ?? 'both'}' is incompatible with node role '${config.node.role}'`,
          controlPlaneStatus: 'cancelled',
          error: `Skipped because executionDomain ('${p.executionDomain ?? 'both'}') is incompatible with node role '${config.node.role}'`,
        })
      }
    }

    // Load in topological order
    for (const plugin of sorted) {
      await this.loadOne(plugin, server, deps)
    }

    // Append rejected duplicates after the retained definitions have reached
    // their terminal status. Consumers that select the first status by ID then
    // observe the retained plugin's outcome instead of its duplicate warning.
    for (const { plugin, retained } of duplicatePlugins) {
      const statusDetail =
        `Duplicate plugin ID '${plugin.id}' rejected; ` +
        `the first discovered definition '${retained.name}' was retained`
      this.plugins.push({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        version: plugin.version,
        executionDomain: plugin.executionDomain ?? 'both',
        status: 'error',
        tools: [],
        configFields: plugin.configSchema,
        reasonCode: 'duplicate-plugin-id',
        statusDetail,
        controlPlaneStatus: 'failed',
        error: statusDetail,
      })
      logger.warn(
        { plugin: plugin.id, retainedPluginName: retained.name },
        'Duplicate plugin ID rejected during discovery'
      )
    }

    logger.info(
      { total: uniquePlugins.length, loaded: this.loadedPlugins.size },
      `Plugin discovery complete: ${this.loadedPlugins.size}/${uniquePlugins.length} plugins loaded`
    )

    // Log aggregated dependency health report
    this.logDependencyHealth()

    return this.plugins
  }

  /**
   * Log a structured dependency health report across all plugins.
   */
  private logDependencyHealth(): void {
    const allChecks: Array<{
      plugin: string
      dep: string
      type: string
      required: boolean
      available: boolean
      path?: string
      error?: string
    }> = []
    for (const s of this.plugins) {
      if (s.depChecks) {
        for (const r of s.depChecks) {
          allChecks.push({
            plugin: s.id,
            dep: r.dep.name,
            type: r.dep.type,
            required: r.dep.required,
            available: r.available,
            path: r.resolvedPath,
            error: r.error,
          })
        }
      }
    }
    if (allChecks.length === 0) return

    const ok = allChecks.filter((c) => c.available).length
    const missing = allChecks.filter((c) => !c.available && c.required)
    const optional = allChecks.filter((c) => !c.available && !c.required)

    logger.info(
      {
        total: allChecks.length,
        ok,
        missingRequired: missing.length,
        missingOptional: optional.length,
      },
      `System dependency health: ${ok}/${allChecks.length} available` +
        (missing.length > 0 ? ` — ${missing.length} required deps MISSING` : '') +
        (optional.length > 0 ? ` — ${optional.length} optional deps not found` : '')
    )

    if (missing.length > 0) {
      for (const m of missing) {
        logger.warn(
          { plugin: m.plugin, dep: m.dep, type: m.type },
          `  MISSING: ${m.dep} (required by ${m.plugin})`
        )
      }
    }
  }

  /**
   * Load a single plugin. Used internally and for hot-load.
   */
  async loadOne(plugin: Plugin, server: PluginServer, deps: ToolDeps): Promise<PluginStatus> {
    const pluginReceiver = plugin
    const pluginId = plugin.id
    // Keep validation and ownership on an immutable descriptor snapshot while
    // lifecycle methods retain the original object as their `this` receiver.
    plugin = Object.freeze({ ...plugin, id: pluginId })
    if (this.loadedPlugins.has(pluginId)) {
      throw new Error(`Plugin '${pluginId}' is already loaded`)
    }
    const isAnalyzerDynamic =
      config.node.role === 'analyzer' && plugin.executionDomain === 'dynamic'
    const status: PluginStatus = {
      id: pluginId,
      name: plugin.name,
      description: plugin.description,
      version: plugin.version,
      executionDomain: plugin.executionDomain ?? 'both',
      status: 'loaded',
      tools: [],
      configFields: plugin.configSchema,
      qualityWarnings: auditPluginQuality(plugin),
      controlPlaneStatus: 'completed',
      statusDetail: 'Plugin loaded successfully',
    }

    const pluginValidation = validatePlugin(plugin)
    if (!pluginValidation.ok) {
      status.status = 'error'
      status.reasonCode = 'registration-failed'
      status.controlPlaneStatus = 'failed'
      status.statusDetail = `Invalid plugin contract: ${pluginValidation.errors.join('; ')}`
      status.error = status.statusDetail
      this.plugins.push(status)
      logger.error(
        { plugin: pluginId, errors: pluginValidation.errors },
        `Plugin failed validation: ${plugin.name}`
      )
      return status
    }

    // Check dependencies are loaded
    if (plugin.dependencies) {
      for (const dep of plugin.dependencies) {
        if (!this.loadedPlugins.has(dep)) {
          status.status = 'skipped-deps'
          status.reasonCode = 'missing-dependency'
          status.controlPlaneStatus = 'failed'
          status.statusDetail = `Required dependency '${dep}' is not loaded`
          status.error = `Required dependency '${dep}' is not loaded`
          this.plugins.push(status)
          logger.info(
            { plugin: pluginId, dep },
            `Plugin skipped (dependency not loaded): ${plugin.name}`
          )
          return status
        }
      }
    }

    // Run prerequisite check
    if (plugin.check) {
      try {
        const ok = await plugin.check.call(pluginReceiver)
        if (!ok) {
          if (isAnalyzerDynamic) {
            logger.debug(
              { plugin: pluginId },
              `Plugin check failed but loading anyway for delegation: ${plugin.name}`
            )
          } else {
            status.status = 'skipped-check'
            status.reasonCode = 'prerequisite-check-failed'
            status.controlPlaneStatus = 'failed'
            status.statusDetail = 'Prerequisite check returned false'
            status.error = 'Prerequisite check returned false'
            this.plugins.push(status)
            logger.info(
              { plugin: pluginId },
              `Plugin skipped (prerequisites not met): ${plugin.name}`
            )
            return status
          }
        }
      } catch (err) {
        if (isAnalyzerDynamic) {
          logger.debug(
            { plugin: pluginId, err },
            `Plugin check error but loading anyway for delegation: ${plugin.name}`
          )
        } else {
          status.status = 'skipped-check'
          status.reasonCode = 'prerequisite-check-failed'
          status.controlPlaneStatus = 'failed'
          status.statusDetail = `Prerequisite check threw: ${err}`
          status.error = `Prerequisite check threw: ${err}`
          this.plugins.push(status)
          logger.warn({ plugin: pluginId, err }, `Plugin skipped (check error): ${plugin.name}`)
          return status
        }
      }
    }

    // Auto-check system dependencies (runs even if plugin has a manual check)
    const localSystemDeps = localSystemDepsForNode(plugin)
    if (localSystemDeps.length > 0) {
      const { results, allRequiredOk } = await checkSystemDeps({ systemDeps: localSystemDeps })
      status.depChecks = results

      // Log each dependency result
      for (const r of results) {
        if (r.available) {
          logger.debug(
            { plugin: pluginId, dep: r.dep.name, path: r.resolvedPath, version: r.version },
            `  ✓ ${r.dep.name}`
          )
        } else if (r.dep.required) {
          logger.warn(
            { plugin: pluginId, dep: r.dep.name, error: r.error },
            `  ✗ ${r.dep.name} (required, missing)`
          )
        } else {
          logger.debug(
            { plugin: pluginId, dep: r.dep.name },
            `  ○ ${r.dep.name} (optional, not found)`
          )
        }
      }

      // If plugin has no manual check() and required deps are missing, skip it
      // Exception: analyzer node loading dynamic plugins — we still register them
      // so their tools can be delegated to the runtime sandbox.
      if (!plugin.check && !allRequiredOk && !isAnalyzerDynamic) {
        const missing = results.filter((r) => !r.available && r.dep.required).map((r) => r.dep.name)
        status.status = 'skipped-check'
        status.reasonCode = 'system-deps-missing'
        status.controlPlaneStatus = 'failed'
        status.statusDetail = `Missing required system deps: ${missing.join(', ')}`
        status.error = `Missing required system deps: ${missing.join(', ')}`
        this.plugins.push(status)
        logger.info(
          { plugin: pluginId, missing },
          `Plugin skipped (system deps not met): ${plugin.name}`
        )
        return status
      }
    } else if (plugin.systemDeps && plugin.systemDeps.length > 0 && isRemoteRuntimeAnalyzer()) {
      status.statusDetail = 'Plugin loaded for remote runtime delegation'
      logger.debug(
        { plugin: pluginId },
        `Plugin system dependency checks delegated to runtime: ${plugin.name}`
      )
    }

    // Register tools
    const registeredDuringLoad = new Set<string>()
    let registrationActive = true
    let targetServer: PluginServerInterface | null = null
    try {
      // Create scoped PluginContext for this plugin
      const ctx = createPluginContext(plugin)

      // Validate required config fields from configSchema
      if (plugin.configSchema) {
        const missing = plugin.configSchema
          .filter((f) => f.required && !process.env[f.envVar] && !f.defaultValue)
          .map((f) => f.envVar)
        if (missing.length > 0) {
          logger.warn(
            { plugin: pluginId, missing },
            `Plugin ${plugin.name}: missing required config: ${missing.join(', ')} — loading anyway`
          )
        }
      }

      const bridge = new PluginRuntimeBridge(deps)
      const pluginServer = bridge.createServerForPlugin(server, pluginId, plugin.executionDomain)
      targetServer = pluginServer
      const ownerForTool = (canonicalName: string) => this.pluginToolMap.get(canonicalName)
      const assertRegistrationActive = () => {
        if (!registrationActive) {
          throw new Error(`Plugin '${pluginId}' registration server is no longer active`)
        }
      }
      const throwToolOwnershipError = (canonicalName: string): never => {
        throw new Error(
          `Plugin '${pluginId}' cannot unregister tool '${canonicalName}' owned by another plugin or the core`
        )
      }
      const registrationServer: PluginServerInterface = Object.freeze({
        registerTool(definition, handler) {
          assertRegistrationActive()
          pluginServer.registerTool(definition, handler)
          registeredDuringLoad.add(definition.name)
        },
        unregisterTool(canonicalName) {
          const owner = ownerForTool(canonicalName)
          if (owner !== undefined && owner !== pluginId) {
            throwToolOwnershipError(canonicalName)
          }
          assertRegistrationActive()
          if (!registeredDuringLoad.has(canonicalName) && owner !== pluginId) {
            throwToolOwnershipError(canonicalName)
          }
          pluginServer.unregisterTool(canonicalName)
          registeredDuringLoad.delete(canonicalName)
        },
      })
      const scopedDeps = createScopedPluginDeps(deps, server)

      let toolNames: unknown
      try {
        const registrationResult: unknown = this.registerPlugin(
          plugin,
          registrationServer,
          scopedDeps,
          ctx,
          pluginReceiver
        )
        toolNames = isPromiseLike(registrationResult)
          ? await registrationResult
          : registrationResult
      } finally {
        registrationActive = false
      }
      if (toolNames !== undefined && !Array.isArray(toolNames)) {
        throw new Error(
          `Plugin '${pluginId}' register() must return an array of registered tool names or void`
        )
      }
      const declaredNames: string[] = Array.isArray(toolNames) ? toolNames : []
      const unregisteredNames = declaredNames.filter(
        (toolName) => typeof toolName !== 'string' || !registeredDuringLoad.has(toolName)
      )
      if (unregisteredNames.length > 0) {
        throw new Error(
          `Plugin '${pluginId}' declared tools that were not registered during load: ${unregisteredNames.join(', ')}`
        )
      }
      const names: string[] = [...new Set([...declaredNames, ...registeredDuringLoad])]
      const conflictingOwners = names.filter((toolName) => {
        const owner = this.pluginToolMap.get(toolName)
        return owner !== undefined && owner !== pluginId
      })
      if (conflictingOwners.length > 0) {
        throw new Error(
          `Plugin '${pluginId}' attempted to claim tools owned by another plugin: ${conflictingOwners.join(', ')}`
        )
      }
      status.tools = names
      status.controlPlaneStatus = 'completed'
      status.statusDetail =
        names.length > 0
          ? `Plugin loaded with ${names.length} tool${names.length === 1 ? '' : 's'}`
          : 'Plugin loaded without registering tools'
      for (const t of names) this.pluginToolMap.set(t, pluginId)
      this.loadedPlugins.set(pluginId, plugin)
      this.plugins.push(status)

      // Register plugin with progressive surface manager
      getToolSurfaceManager().registerPlugin(plugin, names)

      // Fire onActivate hook
      if (plugin.hooks?.onActivate) {
        try {
          await plugin.hooks.onActivate()
        } catch (e) {
          logger.warn({ plugin: pluginId, err: e }, 'Plugin onActivate hook threw — swallowed')
        }
      }

      logger.info({ plugin: pluginId, tools: names.length }, `Plugin loaded: ${plugin.name}`)
    } catch (err) {
      const cleanupNames = new Set(registeredDuringLoad)
      for (const [toolName, ownerPluginId] of this.pluginToolMap) {
        if (ownerPluginId === pluginId) cleanupNames.add(toolName)
      }
      for (const toolName of cleanupNames) {
        try {
          targetServer?.unregisterTool(toolName)
        } catch (rollbackError) {
          logger.warn(
            { plugin: pluginId, tool: toolName, err: rollbackError },
            'Plugin registration rollback failed'
          )
        }
        if (this.pluginToolMap.get(toolName) === pluginId) {
          this.pluginToolMap.delete(toolName)
        }
      }
      if (this.loadedPlugins.delete(pluginId)) {
        getToolSurfaceManager().unregisterPlugin(pluginId)
      }
      status.status = 'error'
      status.reasonCode = 'registration-failed'
      status.controlPlaneStatus = 'failed'
      status.statusDetail = `Registration failed: ${err}`
      status.error = `Registration failed: ${err}`
      if (!this.plugins.includes(status)) {
        this.plugins.push(status)
      }
      logger.error({ plugin: pluginId, err }, `Plugin failed to load: ${plugin.name}`)
    }

    return status
  }

  private registerPlugin(
    plugin: Plugin,
    targetServer: PluginServerInterface,
    deps: ToolDeps,
    ctx: PluginContext,
    pluginReceiver: Plugin
  ): string[] | void | Promise<string[] | void> {
    if (plugin.register) {
      return plugin.register.call(pluginReceiver, targetServer, deps, ctx)
    }

    const names: string[] = []
    for (const tool of plugin.tools ?? []) {
      targetServer.registerTool(tool.definition, async (args: unknown) =>
        tool.handler(args as never, deps, ctx)
      )
      names.push(tool.definition.name)
    }
    return names
  }

  /**
   * Hot-load a plugin at runtime (after server has started).
   * Returns the status of the newly loaded plugin.
   */
  async hotLoad(plugin: Plugin): Promise<PluginStatus> {
    if (!this.server || !this.deps)
      throw new Error('PluginManager not initialized — call loadAll first')
    if (this.loadedPlugins.has(plugin.id))
      throw new Error(`Plugin '${plugin.id}' is already loaded`)
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
      try {
        await plugin.hooks.onDeactivate()
      } catch (e) {
        logger.warn({ plugin: pluginId, err: e }, 'Plugin onDeactivate hook threw — swallowed')
      }
    }

    // Run teardown if defined
    if (plugin.teardown) {
      await plugin.teardown()
    }

    // Find and unregister tools
    const status = this.plugins.find((s) => s.id === pluginId)
    const ownedTools = Array.from(this.pluginToolMap.entries())
      .filter(([, ownerPluginId]) => ownerPluginId === pluginId)
      .map(([toolName]) => toolName)
    const statusTools = (status?.tools ?? []).filter((toolName) => {
      const ownerPluginId = this.pluginToolMap.get(toolName)
      return ownerPluginId === undefined || ownerPluginId === pluginId
    })
    const toolNames = [...new Set([...statusTools, ...ownedTools])]

    for (const toolName of toolNames) {
      this.server.unregisterTool(toolName)
      if (this.pluginToolMap.get(toolName) === pluginId) {
        this.pluginToolMap.delete(toolName)
      }
    }

    if (status) {
      status.status = 'skipped-disabled'
      status.reasonCode = 'manually-unloaded'
      status.controlPlaneStatus = 'cancelled'
      status.statusDetail = 'Plugin unloaded at runtime'
      status.tools = []
    }

    getToolSurfaceManager().unregisterPlugin(pluginId)
    this.loadedPlugins.delete(pluginId)
    logger.info({ plugin: pluginId }, `Plugin unloaded: ${plugin.name}`)
  }
}
