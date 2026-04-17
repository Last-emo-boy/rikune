/**
 * Plugin Runtime — hook execution at tool invocation time.
 */

import { logger } from '../logger.js'
import type { Plugin } from '../plugins/sdk.js'

export class PluginRuntime {
  private pluginToolMap = new Map<string, string>()
  private loadedPlugins = new Map<string, Plugin>()

  setMaps(pluginToolMap: Map<string, string>, loadedPlugins: Map<string, Plugin>): void {
    this.pluginToolMap = pluginToolMap
    this.loadedPlugins = loadedPlugins
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
    const targets: Plugin[] = []

    // Owner plugin
    const pluginId = this.pluginToolMap.get(toolName)
    if (pluginId) {
      const owner = this.loadedPlugins.get(pluginId)
      if (owner?.hooks) targets.push(owner)
    }

    // Global observers (plugins with globalHooks: true)
    for (const [id, plugin] of this.loadedPlugins) {
      if (id !== pluginId && plugin.globalHooks && plugin.hooks) {
        targets.push(plugin)
      }
    }

    for (const plugin of targets) {
      try {
        if (phase === 'before' && plugin.hooks?.onBeforeToolCall) {
          await plugin.hooks.onBeforeToolCall(toolName, args)
        } else if (phase === 'after' && plugin.hooks?.onAfterToolCall) {
          await plugin.hooks.onAfterToolCall(toolName, args, extra?.elapsedMs ?? 0)
        } else if (phase === 'error' && plugin.hooks?.onToolError) {
          await plugin.hooks.onToolError(toolName, extra?.error)
        }
      } catch (hookErr) {
        logger.warn({ plugin: plugin.id, phase, toolName, hookErr }, 'Plugin hook threw — swallowed')
      }
    }
  }
}
