/**
 * tools.discover — Progressive tool discovery meta-tool.
 *
 * Lets the AI explore and activate analysis capabilities on demand.
 * When the progressive surface is enabled, this is one of the ~15
 * always-visible Gateway tools.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import { getToolSurfaceManager } from '../tool-surface-manager.js'
import type { PluginManager } from '../plugins.js'

// ═══════════════════════════════════════════════════════════════════════════
// Schema
// ═══════════════════════════════════════════════════════════════════════════

export const toolsDiscoverInputSchema = z.object({
  action: z.enum(['status', 'list', 'activate']).default('list').describe(
    'Action to perform.\n' +
    '- `status`: Show surface state (how many tools visible vs total).\n' +
    '- `list`: List available categories and plugins that can be activated.\n' +
    '- `activate`: Activate a specific category or plugin.',
  ),
  category: z.string().optional().describe(
    'Category to activate (with action=activate) or filter by (with action=list).\n' +
    'Standard categories: reverse-engineering, dynamic-analysis, symbolic-execution, ' +
    'memory-forensics, network-analysis, malware-analysis, vulnerability-research, ' +
    'static-analysis, unpacking, dotnet-analysis, go-analysis, android-analysis.',
  ),
  plugin_id: z.string().optional().describe(
    'Specific plugin ID to activate (with action=activate). Use action=list to see available IDs.',
  ),
  finding: z.string().optional().describe(
    'Finding/signal tag to activate matching plugins (with action=activate).\n' +
    'Tags: packed, dotnet, go, signed, obfuscated, vba_macros, crypto, c2, shellcode, firmware.',
  ),
  file_type: z.string().optional().describe(
    'File type tag to activate matching plugins (with action=activate).\n' +
    'Tags: pe, elf, macho, apk, office, pcap, jar, pdf.',
  ),
})

export const toolsDiscoverOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    action: z.string(),
    status: z.object({
      enabled: z.boolean(),
      total_plugins: z.number(),
      activated_plugins: z.number(),
      total_tools: z.number(),
      visible_tools: z.number(),
    }).optional(),
    categories: z.array(z.object({
      category: z.string(),
      plugins: z.array(z.object({
        id: z.string(),
        name: z.string(),
        description: z.string().optional(),
        tool_count: z.number(),
        tier: z.number(),
        activated: z.boolean(),
      })),
    })).optional(),
    activated: z.array(z.string()).optional(),
    activated_tools: z.array(z.string()).optional(),
    message: z.string(),
  }),
})

export const toolsDiscoverToolDefinition: ToolDefinition = {
  name: 'tools.discover',
  description:
    'Discover and activate analysis capabilities progressively. ' +
    'Use `action=status` to see how many tools are visible. ' +
    'Use `action=list` to browse available categories. ' +
    'Use `action=activate` with a category, plugin_id, finding, or file_type to unlock tools. ' +
    'Tools are automatically activated during analysis (e.g., PE tools appear when a PE file is loaded), ' +
    'but you can also manually activate expert tools here.',
  inputSchema: toolsDiscoverInputSchema,
  outputSchema: toolsDiscoverOutputSchema,
}

// ═══════════════════════════════════════════════════════════════════════════
// Handler
// ═══════════════════════════════════════════════════════════════════════════

export function createToolsDiscoverHandler(pluginManager: PluginManager) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = toolsDiscoverInputSchema.parse(args)
    const surface = getToolSurfaceManager()

    // Build a plugin index for name/description lookups
    const pluginIndex = new Map<string, { name: string; description?: string }>()
    for (const p of pluginManager.getStatuses()) {
      pluginIndex.set(p.id, { name: p.name, description: p.description })
    }

    switch (input.action) {
      case 'status': {
        const status = surface.getSurfaceStatus()
        return {
          ok: true,
          data: {
            action: 'status',
            status: {
              enabled: status.enabled,
              total_plugins: status.totalPlugins,
              activated_plugins: status.activatedPlugins,
              total_tools: status.totalTools,
              visible_tools: status.visibleTools,
            },
            message: status.enabled
              ? `Progressive surface active: ${status.visibleTools}/${status.totalTools} tools visible from ${status.activatedPlugins}/${status.totalPlugins} plugins. ` +
                `Tier 0: ${status.tiers[0].activated}/${status.tiers[0].total}, ` +
                `Tier 1: ${status.tiers[1].activated}/${status.tiers[1].total}, ` +
                `Tier 2: ${status.tiers[2].activated}/${status.tiers[2].total}, ` +
                `Tier 3: ${status.tiers[3].activated}/${status.tiers[3].total}. ` +
                'Use action=list to browse categories, or action=activate to unlock more tools.'
              : `Progressive surface is disabled — all ${status.totalTools} tools are visible.`,
          },
        }
      }

      case 'list': {
        const allCategories = surface.listCategories(pluginIndex)
        const filtered = input.category
          ? allCategories.filter(c => c.category.toLowerCase().includes(input.category!.toLowerCase()))
          : allCategories

        return {
          ok: true,
          data: {
            action: 'list',
            categories: filtered.map(c => ({
              category: c.category,
              plugins: c.plugins.map(p => ({
                id: p.id,
                name: p.name,
                description: p.description,
                tool_count: p.tools.length,
                tier: p.tier,
                activated: p.activated,
              })),
            })),
            message: `Found ${filtered.length} categories with ${filtered.reduce((sum, c) => sum + c.plugins.length, 0)} plugins. ` +
              'Use action=activate with category=<name> or plugin_id=<id> to unlock tools.',
          },
        }
      }

      case 'activate': {
        const activated: string[] = []

        if (input.plugin_id) {
          activated.push(...surface.activatePlugins([input.plugin_id]))
        }
        if (input.category) {
          activated.push(...surface.activateByCategory(input.category))
        }
        if (input.finding) {
          activated.push(...surface.activateByFinding(input.finding))
        }
        if (input.file_type) {
          activated.push(...surface.activateByFileType(input.file_type))
        }

        const unique = [...new Set(activated)]

        // Collect activated tool names for display
        const activatedTools: string[] = []
        for (const pid of unique) {
          const categories = surface.listCategories(pluginIndex)
          for (const c of categories) {
            const p = c.plugins.find(p => p.id === pid)
            if (p) activatedTools.push(...p.tools)
          }
        }

        if (unique.length === 0) {
          return {
            ok: true,
            data: {
              action: 'activate',
              activated: [],
              activated_tools: [],
              message: 'No new plugins were activated. They may already be active, or no matching plugins were found. ' +
                'Use action=list to see available categories and plugins.',
            },
          }
        }

        return {
          ok: true,
          data: {
            action: 'activate',
            activated: unique,
            activated_tools: activatedTools,
            message: `Activated ${unique.length} plugin(s): ${unique.join(', ')}. ` +
              `${activatedTools.length} new tools are now available.`,
          },
        }
      }

      default:
        return { ok: false, errors: [`Unknown action: ${input.action}`] }
    }
  }
}
