/**
 * plugin.list — MCP tool that returns the status of all known plugins.
 *
 * Provides self-introspection so LLM clients can discover which capability
 * modules are loaded, skipped, or failed, along with the tools each plugin owns.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolResult } from '../types.js'
import { getPluginManager } from '../plugins.js'
import type { ToolRegistrar } from '../core/registrar.js'
import { getToolSurfaceManager } from '../core/tool-surface-manager.js'
import {
  buildPluginAspectMatrix,
  buildPluginMatrixSources,
  buildToolAspectSummary,
  describeAspectCoverage,
  normalizeAspects,
} from './tool-aspect-matrix.js'

// ── Schema ──────────────────────────────────────────────────────────────────

const inputSchema = z.object({
  /** Optional: filter to a specific plugin ID. */
  plugin_id: z.string().optional(),
  /** Optional: filter plugins by execution domain. */
  execution_domain: z.enum(['static', 'dynamic', 'both']).optional(),
  /** If true, include config schema details for each plugin. */
  include_config: z.boolean().optional(),
})

export const pluginListToolDefinition: ToolDefinition = {
  name: 'plugin.list',
  description:
    'List all known plugins and their status (loaded, skipped, error). ' +
    'Shows which MCP tools each plugin provides and optional config fields. ' +
    'Use this to discover available capabilities and diagnose missing tools.',
  inputSchema: inputSchema as any,
}

// ── Handler ─────────────────────────────────────────────────────────────────

export function createPluginListHandler(_server: ToolRegistrar) {
  return async (args: z.infer<typeof inputSchema>): Promise<ToolResult> => {
    const mgr = getPluginManager()
    let statuses = mgr.getStatuses()
    const allPlugins = mgr.getDiscoveredPlugins()

    if (args.plugin_id) {
      statuses = statuses.filter((s) => s.id === args.plugin_id)
      if (statuses.length === 0) {
        return {
          content: [{ type: 'text', text: `No plugin found with id '${args.plugin_id}'` }],
          isError: true,
        }
      }
    }

    if (args.execution_domain) {
      statuses = statuses.filter((s) => (s.executionDomain ?? 'both') === args.execution_domain)
    }

    const statusIds = new Set(statuses.map((s) => s.id))
    const filteredPlugins = allPlugins.filter((plugin) => statusIds.has(plugin.id))
    const pluginById = new Map(filteredPlugins.map((plugin) => [plugin.id, plugin]))
    const surfacePluginIndex = new Map(
      allPlugins.map((plugin) => [
        plugin.id,
        { name: plugin.name, description: plugin.description },
      ])
    )
    for (const status of mgr.getStatuses()) {
      surfacePluginIndex.set(status.id, { name: status.name, description: status.description })
    }
    const surfaceCategories = getToolSurfaceManager().listCategories(surfacePluginIndex)
    const activatedByPlugin = new Map<string, boolean>()
    const toolNamesByPlugin = new Map<string, string[]>()
    for (const category of surfaceCategories) {
      for (const plugin of category.plugins) {
        activatedByPlugin.set(plugin.id, plugin.activated)
        toolNamesByPlugin.set(plugin.id, plugin.tools)
      }
    }
    const toolNameLookup = new Map(
      filteredPlugins.flatMap((plugin) =>
        (plugin.tools ?? []).map((tool) => [tool.definition.name, tool.definition] as const)
      )
    )
    const matrixSources = buildPluginMatrixSources({
      statuses,
      plugins: filteredPlugins,
      toolNameLookup,
      activatedByPlugin,
      toolNamesByPlugin,
    })
    const pluginMatrix = buildPluginAspectMatrix(matrixSources)

    const summary = {
      total: statuses.length,
      loaded: statuses.filter((s) => s.status === 'loaded').length,
      skipped: statuses.filter((s) => s.status.startsWith('skipped')).length,
      errored: statuses.filter((s) => s.status === 'error').length,
      quality_warning_count: statuses.reduce((sum, s) => sum + (s.qualityWarnings?.length ?? 0), 0),
      by_execution_domain: {
        static: statuses.filter((s) => (s.executionDomain ?? 'both') === 'static').length,
        dynamic: statuses.filter((s) => (s.executionDomain ?? 'both') === 'dynamic').length,
        both: statuses.filter((s) => (s.executionDomain ?? 'both') === 'both').length,
      },
      plugin_matrix: pluginMatrix,
      plugins: statuses.map((s) => {
        const plugin = pluginById.get(s.id)
        const pluginAspects = normalizeAspects(plugin?.aspects)
        const pluginAspectPayload = Object.keys(pluginAspects).length > 0 ? pluginAspects : null
        const source = matrixSources.find((candidate) => candidate.id === s.id)
        const matrix = source ? buildPluginAspectMatrix([source]) : null
        const entry: Record<string, unknown> = {
          id: s.id,
          name: s.name,
          execution_domain: s.executionDomain ?? 'both',
          status: s.status,
          version: s.version ?? null,
          description: s.description ?? null,
          tools: s.tools,
          tool_count: s.tools.length,
          activated: activatedByPlugin.get(s.id) ?? null,
          aspects: pluginAspectPayload,
          aspect_coverage: describeAspectCoverage(pluginAspectPayload),
          runtime_policy: plugin?.runtimePolicy ?? null,
          format_matrix: matrix?.by_format ?? {},
          plugin_matrix: matrix,
          artifact_declarations: (plugin?.tools ?? [])
            .filter((tool) => s.tools.includes(tool.definition.name))
            .flatMap((tool) => tool.definition.artifacts ?? []),
          evidence_declarations: (plugin?.tools ?? [])
            .filter((tool) => s.tools.includes(tool.definition.name))
            .flatMap((tool) => tool.definition.evidence ?? []),
          tool_metadata: (plugin?.tools ?? [])
            .filter((tool) => s.tools.includes(tool.definition.name))
            .map((tool) => ({
              name: tool.definition.name,
              ...buildToolAspectSummary(tool.definition, {
                pluginAspects: plugin?.aspects,
                pluginRuntimePolicy: plugin?.runtimePolicy,
              }),
            })),
          quality_warning_count: s.qualityWarnings?.length ?? 0,
          quality_warnings: s.qualityWarnings ?? [],
        }
        if (s.error) entry.error = s.error
        if (args.include_config && s.configFields) {
          entry.config = s.configFields.map((f) => ({
            env_var: f.envVar,
            description: f.description,
            required: f.required,
            default: f.defaultValue ?? null,
            current_value: process.env[f.envVar] ? '(set)' : '(unset)',
          }))
        }
        return entry
      }),
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }],
      structuredContent: summary,
    }
  }
}

// ── plugin.enable / plugin.disable — hot-load & unload tools ────────────────

const enableSchema = z.object({
  plugin_id: z.string().describe('The ID of the plugin to enable'),
})

export const pluginEnableToolDefinition: ToolDefinition = {
  name: 'plugin.enable',
  description:
    'Hot-load a plugin at runtime without restarting the server. ' +
    'The plugin must be known (built-in or discovered) but currently not loaded.',
  inputSchema: enableSchema as any,
}

export function createPluginEnableHandler(server: ToolRegistrar) {
  return async (args: z.infer<typeof enableSchema>): Promise<ToolResult> => {
    const mgr = getPluginManager()

    if (mgr.isLoaded(args.plugin_id)) {
      return {
        content: [{ type: 'text', text: `Plugin '${args.plugin_id}' is already loaded` }],
        isError: true,
      }
    }

    // Find the plugin definition in discovered plugins
    const allPlugins = mgr.getDiscoveredPlugins()
    const pluginDef = allPlugins.find((p) => p.id === args.plugin_id)
    if (!pluginDef) {
      return {
        content: [{ type: 'text', text: `Unknown plugin id: '${args.plugin_id}'` }],
        isError: true,
      }
    }

    try {
      const status = await mgr.hotLoad(pluginDef)
      return {
        content: [
          {
            type: 'text',
            text: `Plugin '${args.plugin_id}' loaded: ${status.tools.length} tools registered`,
          },
        ],
        structuredContent: { ...status } as Record<string, unknown>,
      }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Failed to enable plugin: ${err}` }],
        isError: true,
      }
    }
  }
}

const disableSchema = z.object({
  plugin_id: z.string().describe('The ID of the plugin to disable'),
})

export const pluginDisableToolDefinition: ToolDefinition = {
  name: 'plugin.disable',
  description:
    'Unload a plugin at runtime — its tools become unavailable until re-enabled. ' +
    'Core plugins cannot be disabled.',
  inputSchema: disableSchema as any,
}

// Core plugins that cannot be disabled at runtime
const CORE_PLUGIN_IDS = new Set<string>([])

export function createPluginDisableHandler(server: ToolRegistrar) {
  return async (args: z.infer<typeof disableSchema>): Promise<ToolResult> => {
    if (CORE_PLUGIN_IDS.has(args.plugin_id)) {
      return {
        content: [
          {
            type: 'text',
            text: `Plugin '${args.plugin_id}' is a core plugin and cannot be disabled`,
          },
        ],
        isError: true,
      }
    }

    const mgr = getPluginManager()
    if (!mgr.isLoaded(args.plugin_id)) {
      return {
        content: [{ type: 'text', text: `Plugin '${args.plugin_id}' is not currently loaded` }],
        isError: true,
      }
    }

    try {
      await mgr.unload(args.plugin_id)
      return {
        content: [{ type: 'text', text: `Plugin '${args.plugin_id}' unloaded successfully` }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Failed to disable plugin: ${err}` }],
        isError: true,
      }
    }
  }
}
