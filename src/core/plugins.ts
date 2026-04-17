/**
 * Plugin System — extensible plugin framework for the MCP server.
 *
 * Plugins are self-contained tool modules that can be enabled, disabled,
 * discovered, and (optionally) hot-loaded at runtime.
 *
 * Architecture:
 *   - All plugins live in `src/plugins/<id>/index.ts` directories
 *   - Plugins are auto-discovered at startup by scanning the plugins directory
 *   - No manual registration needed — just create a directory with an index.ts
 *   - External plugins can also be placed in `plugins/` at project root
 *   - Plugin SDK types are in `src/plugins/sdk.ts` — the single contract
 *
 * Public entry points:
 *   - `loadPlugins()` — called from tool-registry.ts
 *   - `getPluginManager()` — singleton accessor
 */

import type { ToolDeps } from './tool-registry.js'
import type { ToolRegistrar, PromptRegistrar, ResourceRegistrar, SamplingClient } from './registrar.js'

// Re-export SDK types so existing consumers don't break
export type {
  Plugin,
  PluginConfigField,
  PluginContext,
  PluginHooks,
  PluginLogger,
  PluginStatus,
  PluginServerInterface,
  PluginToolDeps,
  PluginSystemDep,
  DepCheckResult,
  ToolDefinition,
  WorkerResult,
  ArtifactRef,
} from '../plugins/sdk.js'

import type { Plugin, PluginStatus } from '../plugins/sdk.js'
import { PluginOrchestrator } from './plugin-orchestrator.js'
import { PluginRuntime } from './plugin-runtime.js'

// ═══════════════════════════════════════════════════════════════════════════
// Plugin Manager — facade that composes orchestration and runtime
// ═══════════════════════════════════════════════════════════════════════════

export type PluginServer = ToolRegistrar & PromptRegistrar & ResourceRegistrar & SamplingClient

export class PluginManager {
  private orchestrator: PluginOrchestrator
  private runtime: PluginRuntime

  constructor() {
    this.orchestrator = new PluginOrchestrator()
    this.runtime = new PluginRuntime()
  }

  private syncRuntimeMaps(): void {
    this.runtime.setMaps(
      new Map(this.orchestrator.getPluginToolMap()),
      new Map(this.orchestrator.getLoadedPlugins()),
    )
  }

  /** Get status of all known plugins. */
  getStatuses(): PluginStatus[] { return this.orchestrator.getStatuses() }

  /** Get the Plugin definition for a loaded plugin. */
  getPlugin(id: string): Plugin | undefined { return this.orchestrator.getPlugin(id) }

  /** Find which plugin owns a given tool name. */
  getPluginForTool(toolName: string): string | undefined { return this.orchestrator.getPluginForTool(toolName) }

  /** Check if a specific plugin is loaded. */
  isLoaded(id: string): boolean { return this.orchestrator.isLoaded(id) }

  /** Get all discovered plugin definitions (loaded or not). */
  getDiscoveredPlugins(): Plugin[] { return this.orchestrator.getDiscoveredPlugins() }

  /**
   * Resolve which plugins are enabled via `PLUGINS` env var.
   */
  resolveEnabledPlugins(plugins: Plugin[]): Plugin[] {
    return this.orchestrator.resolveEnabledPlugins(plugins)
  }

  /**
   * Filter plugins by executionDomain based on the current node role.
   */
  resolvePluginsByRole(plugins: Plugin[]): Plugin[] {
    return this.orchestrator.resolvePluginsByRole(plugins)
  }

  /**
   * Topologically sort plugins by their `dependencies` arrays.
   */
  topoSort(plugins: Plugin[]): Plugin[] {
    return this.orchestrator.topoSort(plugins)
  }

  /**
   * Load all enabled plugins in dependency order.
   */
  async loadAll(
    server: PluginServer,
    deps: ToolDeps,
    extraPlugins: Plugin[] = [],
  ): Promise<PluginStatus[]> {
    const result = await this.orchestrator.loadAll(server, deps, extraPlugins)
    this.syncRuntimeMaps()
    return result
  }

  /**
   * Hot-load a plugin at runtime (after server has started).
   */
  async hotLoad(plugin: Plugin): Promise<PluginStatus> {
    const result = await this.orchestrator.hotLoad(plugin)
    this.syncRuntimeMaps()
    return result
  }

  /**
   * Unload a plugin at runtime — tears down and unregisters its tools.
   */
  async unload(pluginId: string): Promise<void> {
    await this.orchestrator.unload(pluginId)
    this.syncRuntimeMaps()
  }

  /**
   * Execute a hook phase for a given tool invocation.
   * Fires on: (1) the plugin owning the tool, and (2) all global observers.
   */
  async fireHook(
    phase: 'before' | 'after' | 'error',
    toolName: string,
    args: Record<string, unknown>,
    extra?: { elapsedMs?: number; error?: unknown },
  ): Promise<void> {
    return this.runtime.fireHook(phase, toolName, args, extra)
  }
}

// Singleton
let pluginManagerInstance: PluginManager | null = null

export function getPluginManager(): PluginManager {
  if (!pluginManagerInstance) pluginManagerInstance = new PluginManager()
  return pluginManagerInstance
}

// ═══════════════════════════════════════════════════════════════════════════
// Public entry point — called from tool-registry.ts
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Load all enabled plugins (built-in + external) through the PluginManager.
 * Plugins are automatically discovered from the filesystem — no hardcoded list.
 */
export async function loadPlugins(
  server: PluginServer,
  deps: ToolDeps,
  extraPlugins: Plugin[] = [],
): Promise<string[]> {
  const mgr = getPluginManager()
  const statuses = await mgr.loadAll(server, deps, extraPlugins)
  return statuses.filter(s => s.status === 'loaded').map(s => s.id)
}
