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
import type { Plugin, PluginQualityWarning } from '../plugins/sdk.js'
import { buildToolSurfaceGuidance, ToolSurfaceRoleSchema } from '../tool-surface-guidance.js'
import {
  buildPluginAspectMatrix,
  buildPluginMatrixSources,
  buildToolAspectSummary,
  describeAspectCoverage,
  normalizeAspects,
  normalizeFileTypeTags,
  type ToolAspectSource,
} from './tool-aspect-matrix.js'

// ═══════════════════════════════════════════════════════════════════════════
// Schema
// ═══════════════════════════════════════════════════════════════════════════

export const toolsDiscoverInputSchema = z.object({
  action: z
    .enum(['status', 'list', 'activate'])
    .default('list')
    .describe(
      'Action to perform.\n' +
        '- `status`: Show surface state (how many tools visible vs total).\n' +
        '- `list`: List available categories and plugins that can be activated.\n' +
        '- `activate`: Activate a specific category or plugin.'
    ),
  category: z
    .string()
    .optional()
    .describe(
      'Category to activate (with action=activate) or filter by (with action=list).\n' +
        'Standard categories: reverse-engineering, dynamic-analysis, symbolic-execution, ' +
        'memory-forensics, network-analysis, malware-analysis, vulnerability-research, ' +
        'static-analysis, unpacking, dotnet-analysis, go-analysis, android-analysis.'
    ),
  plugin_id: z
    .string()
    .optional()
    .describe(
      'Specific plugin ID to activate (with action=activate). Use action=list to see available IDs.'
    ),
  finding: z
    .string()
    .optional()
    .describe(
      'Finding/signal tag to activate matching plugins (with action=activate).\n' +
        'Tags: packed, dotnet, go, signed, obfuscated, vba_macros, crypto, c2, shellcode, firmware.'
    ),
  file_type: z
    .string()
    .optional()
    .describe(
      'File type tag to activate matching plugins (with action=activate).\n' +
        'Tags: pe, elf, macho, apk, office, pcap, jar, pdf.'
    ),
})

export const toolsDiscoverOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    action: z.string(),
    status: z
      .object({
        enabled: z.boolean(),
        total_plugins: z.number(),
        activated_plugins: z.number(),
        total_tools: z.number(),
        visible_tools: z.number(),
      })
      .optional(),
    categories: z
      .array(
        z.object({
          category: z.string(),
          plugins: z.array(
            z.object({
              id: z.string(),
              name: z.string(),
              description: z.string().optional(),
              tool_count: z.number(),
              tier: z.number(),
              activated: z.boolean(),
              tool_surface_role: ToolSurfaceRoleSchema,
              preferred_primary_tools: z.array(z.string()),
              aspects: z.record(z.array(z.string())).nullable().optional(),
              aspect_coverage: z.array(z.string()).optional(),
              format_matrix: z.record(z.any()).optional(),
              runtime_policy: z.any().nullable().optional(),
              runtime_contract: z.any().nullable().optional(),
              artifact_declarations: z.array(z.any()).optional(),
              evidence_declarations: z.array(z.any()).optional(),
              workflow_recipes: z.array(z.any()).optional(),
              recommended_tools: z.array(z.string()).optional(),
              available_tools: z.array(z.string()).optional(),
              blocked_tools: z.array(z.string()).optional(),
              missing_deps: z.array(z.string()).optional(),
              next_actions: z.array(z.string()).optional(),
              quality_warnings: z.array(z.any()).optional(),
            })
          ),
          plugin_matrix: z.any().optional(),
          format_matrix: z.any().optional(),
          recommended_tools: z.array(z.string()).optional(),
          available_tools: z.array(z.string()).optional(),
          blocked_tools: z.array(z.string()).optional(),
          missing_deps: z.array(z.string()).optional(),
          next_actions: z.array(z.string()).optional(),
        })
      )
      .optional(),
    activated: z.array(z.string()).optional(),
    activated_tools: z.array(z.string()).optional(),
    target_file_type_tags: z.array(z.string()).optional(),
    matched_plugins: z.array(z.string()).optional(),
    matched_tools: z.array(z.string()).optional(),
    plugin_matrix: z.any().optional(),
    format_matrix: z.any().optional(),
    recommended_tools: z.array(z.string()).optional(),
    available_tools: z.array(z.string()).optional(),
    blocked_tools: z.array(z.string()).optional(),
    missing_deps: z.array(z.string()).optional(),
    next_actions: z.array(z.string()).optional(),
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

type DiscoverPluginMetadata = Pick<
  Plugin,
  'id' | 'name' | 'description' | 'aspects' | 'runtimePolicy' | 'tools'
>

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function collectToolDeclarations(
  plugin: DiscoverPluginMetadata | undefined,
  toolNames: string[]
): {
  artifact_declarations: unknown[]
  evidence_declarations: unknown[]
  workflow_recipes: unknown[]
} {
  const toolNameSet = new Set(toolNames)
  const definitions = (plugin?.tools ?? [])
    .map((tool) => tool.definition)
    .filter((definition) => toolNameSet.has(definition.name))

  return {
    artifact_declarations: definitions.flatMap((definition) => definition.artifacts ?? []),
    evidence_declarations: definitions.flatMap((definition) => definition.evidence ?? []),
    workflow_recipes: definitions.flatMap((definition) => definition.workflowRecipes ?? []),
  }
}

function buildPluginMetadataIndex(
  pluginManager: PluginManager
): Map<string, DiscoverPluginMetadata> {
  const manager = pluginManager as PluginManager & {
    getDiscoveredPlugins?: () => Plugin[]
    getPlugin?: (id: string) => Plugin | undefined
  }
  const index = new Map<string, DiscoverPluginMetadata>()
  for (const plugin of manager.getDiscoveredPlugins?.() ?? []) {
    index.set(plugin.id, plugin)
  }
  for (const status of pluginManager.getStatuses()) {
    const loadedPlugin = manager.getPlugin?.(status.id)
    if (loadedPlugin) {
      index.set(status.id, loadedPlugin)
    }
  }
  return index
}

function collectSurfaceMaps(
  categories: ReturnType<ReturnType<typeof getToolSurfaceManager>['listCategories']>
): {
  activatedByPlugin: Map<string, boolean>
  toolNamesByPlugin: Map<string, string[]>
} {
  const activatedByPlugin = new Map<string, boolean>()
  const toolNamesByPlugin = new Map<string, string[]>()
  for (const category of categories) {
    for (const plugin of category.plugins) {
      activatedByPlugin.set(plugin.id, plugin.activated)
      toolNamesByPlugin.set(plugin.id, uniqueStrings(plugin.tools))
    }
  }
  return { activatedByPlugin, toolNamesByPlugin }
}

function buildToolNameLookup(plugins: DiscoverPluginMetadata[]): Map<string, ToolAspectSource> {
  const lookup = new Map<string, ToolAspectSource>()
  for (const plugin of plugins) {
    for (const tool of plugin.tools ?? []) {
      lookup.set(tool.definition.name, tool.definition)
    }
  }
  return lookup
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
    const pluginMetadataIndex = buildPluginMetadataIndex(pluginManager)
    for (const plugin of pluginMetadataIndex.values()) {
      pluginIndex.set(plugin.id, { name: plugin.name, description: plugin.description })
    }
    const pluginStatusIndex = new Map<string, { qualityWarnings?: PluginQualityWarning[] }>()
    for (const p of pluginManager.getStatuses()) {
      pluginIndex.set(p.id, { name: p.name, description: p.description })
      pluginStatusIndex.set(p.id, { qualityWarnings: p.qualityWarnings })
    }
    const allCategories = surface.listCategories(pluginIndex)
    const surfaceMaps = collectSurfaceMaps(allCategories)
    const matrixSources = buildPluginMatrixSources({
      statuses: pluginManager.getStatuses(),
      plugins: [...pluginMetadataIndex.values()],
      toolNameLookup: buildToolNameLookup([...pluginMetadataIndex.values()]),
      activatedByPlugin: surfaceMaps.activatedByPlugin,
      toolNamesByPlugin: surfaceMaps.toolNamesByPlugin,
    })
    const fileTypeTags = normalizeFileTypeTags(input.file_type)
    const pluginMatrix = buildPluginAspectMatrix(matrixSources, { targetTags: fileTypeTags })

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
        const filtered = input.category
          ? allCategories.filter((c) =>
              c.category.toLowerCase().includes(input.category.toLowerCase())
            )
          : allCategories

        return {
          ok: true,
          data: {
            action: 'list',
            categories: filtered.map((c) => ({
              category: c.category,
              ...(() => {
                const categorySources = matrixSources.filter((source) =>
                  c.plugins.some((plugin) => plugin.id === source.id)
                )
                const categoryMatrix = buildPluginAspectMatrix(categorySources, {
                  targetTags: fileTypeTags,
                })
                return {
                  plugin_matrix: categoryMatrix,
                  format_matrix: categoryMatrix.by_format,
                  recommended_tools: categoryMatrix.target?.recommended_tools.length
                    ? categoryMatrix.target.recommended_tools
                    : categoryMatrix.recommended_tools,
                  available_tools: categoryMatrix.available_tools,
                  blocked_tools: categoryMatrix.blocked_tools,
                  missing_deps: categoryMatrix.missing_deps,
                  next_actions: categoryMatrix.target?.next_actions.length
                    ? uniqueStrings([
                        ...categoryMatrix.target.next_actions,
                        ...categoryMatrix.next_actions,
                      ])
                    : categoryMatrix.next_actions,
                }
              })(),
              plugins: c.plugins.map((p) => {
                const plugin = pluginMetadataIndex.get(p.id)
                const pluginSource = matrixSources.find((source) => source.id === p.id)
                const perPluginMatrix = pluginSource
                  ? buildPluginAspectMatrix([pluginSource], { targetTags: fileTypeTags })
                  : null
                const normalizedAspects = normalizeAspects(plugin?.aspects)
                const aspects = Object.keys(normalizedAspects).length > 0 ? normalizedAspects : null
                const toolSummaries = (plugin?.tools ?? [])
                  .filter((tool) => p.tools.includes(tool.definition.name))
                  .map((tool) =>
                    buildToolAspectSummary(tool.definition, {
                      pluginAspects: plugin?.aspects,
                      pluginRuntimePolicy: plugin?.runtimePolicy,
                    })
                  )
                return {
                  id: p.id,
                  name: p.name,
                  description: p.description,
                  tool_count: p.tools.length,
                  tier: p.tier,
                  activated: p.activated,
                  tool_surface_role: p.tools.some(
                    (tool) => buildToolSurfaceGuidance(tool).tool_surface_role === 'runtime_gated'
                  )
                    ? 'runtime_gated'
                    : p.tier === 3
                      ? 'expert'
                      : p.tools.some(
                            (tool) =>
                              buildToolSurfaceGuidance(tool).tool_surface_role === 'specialist'
                          )
                        ? 'specialist'
                        : 'primary',
                  preferred_primary_tools: Array.from(
                    new Set(
                      p.tools.flatMap(
                        (tool) => buildToolSurfaceGuidance(tool).preferred_primary_tools
                      )
                    )
                  ),
                  aspects,
                  aspect_coverage: describeAspectCoverage(aspects),
                  format_matrix: perPluginMatrix?.by_format ?? {},
                  runtime_policy: plugin?.runtimePolicy ?? null,
                  runtime_contract:
                    toolSummaries.find((summary) => summary.runtime_contract)?.runtime_contract ??
                    null,
                  ...collectToolDeclarations(plugin, p.tools),
                  recommended_tools: perPluginMatrix?.target?.recommended_tools.length
                    ? perPluginMatrix.target.recommended_tools
                    : (perPluginMatrix?.recommended_tools ?? []),
                  available_tools: perPluginMatrix?.available_tools ?? [],
                  blocked_tools: perPluginMatrix?.blocked_tools ?? [],
                  missing_deps: perPluginMatrix?.missing_deps ?? [],
                  next_actions: perPluginMatrix?.target?.next_actions.length
                    ? uniqueStrings([
                        ...perPluginMatrix.target.next_actions,
                        ...perPluginMatrix.next_actions,
                      ])
                    : (perPluginMatrix?.next_actions ?? []),
                  quality_warnings: pluginStatusIndex.get(p.id)?.qualityWarnings ?? [],
                }
              }),
            })),
            target_file_type_tags: fileTypeTags.length > 0 ? fileTypeTags : undefined,
            plugin_matrix: pluginMatrix,
            format_matrix: pluginMatrix.by_format,
            recommended_tools: pluginMatrix.target?.recommended_tools.length
              ? pluginMatrix.target.recommended_tools
              : pluginMatrix.recommended_tools,
            available_tools: pluginMatrix.available_tools,
            blocked_tools: pluginMatrix.blocked_tools,
            missing_deps: pluginMatrix.missing_deps,
            next_actions: pluginMatrix.target?.next_actions.length
              ? uniqueStrings([...pluginMatrix.target.next_actions, ...pluginMatrix.next_actions])
              : pluginMatrix.next_actions,
            message:
              `Found ${filtered.length} categories with ${filtered.reduce((sum, c) => sum + c.plugins.length, 0)} plugins. ` +
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
          const updatedCategories = surface.listCategories(pluginIndex)
          for (const c of updatedCategories) {
            const p = c.plugins.find((p) => p.id === pid)
            if (p) activatedTools.push(...p.tools)
          }
        }
        const updatedCategories = surface.listCategories(pluginIndex)
        const updatedSurfaceMaps = collectSurfaceMaps(updatedCategories)
        const updatedMatrixSources = buildPluginMatrixSources({
          statuses: pluginManager.getStatuses(),
          plugins: [...pluginMetadataIndex.values()],
          toolNameLookup: buildToolNameLookup([...pluginMetadataIndex.values()]),
          activatedByPlugin: updatedSurfaceMaps.activatedByPlugin,
          toolNamesByPlugin: updatedSurfaceMaps.toolNamesByPlugin,
        })
        const updatedPluginMatrix = buildPluginAspectMatrix(updatedMatrixSources, {
          targetTags: fileTypeTags,
        })

        if (unique.length === 0) {
          return {
            ok: true,
            data: {
              action: 'activate',
              activated: [],
              activated_tools: [],
              target_file_type_tags: fileTypeTags.length > 0 ? fileTypeTags : undefined,
              matched_plugins: updatedPluginMatrix.target?.matched_plugins ?? [],
              matched_tools: updatedPluginMatrix.target?.matched_tools ?? [],
              plugin_matrix: updatedPluginMatrix,
              format_matrix: updatedPluginMatrix.by_format,
              recommended_tools: updatedPluginMatrix.target?.recommended_tools.length
                ? updatedPluginMatrix.target.recommended_tools
                : updatedPluginMatrix.recommended_tools,
              available_tools: updatedPluginMatrix.available_tools,
              blocked_tools: updatedPluginMatrix.blocked_tools,
              missing_deps: updatedPluginMatrix.missing_deps,
              next_actions: updatedPluginMatrix.target?.next_actions.length
                ? uniqueStrings([
                    ...updatedPluginMatrix.target.next_actions,
                    ...updatedPluginMatrix.next_actions,
                  ])
                : updatedPluginMatrix.next_actions,
              message:
                'No new plugins were activated. They may already be active, or no matching plugins were found. ' +
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
            target_file_type_tags: fileTypeTags.length > 0 ? fileTypeTags : undefined,
            matched_plugins: updatedPluginMatrix.target?.matched_plugins ?? unique,
            matched_tools: updatedPluginMatrix.target?.matched_tools ?? activatedTools,
            plugin_matrix: updatedPluginMatrix,
            format_matrix: updatedPluginMatrix.by_format,
            recommended_tools: updatedPluginMatrix.target?.recommended_tools.length
              ? updatedPluginMatrix.target.recommended_tools
              : updatedPluginMatrix.recommended_tools,
            available_tools: updatedPluginMatrix.available_tools,
            blocked_tools: updatedPluginMatrix.blocked_tools,
            missing_deps: updatedPluginMatrix.missing_deps,
            next_actions: updatedPluginMatrix.target?.next_actions.length
              ? uniqueStrings([
                  ...updatedPluginMatrix.target.next_actions,
                  ...updatedPluginMatrix.next_actions,
                ])
              : updatedPluginMatrix.next_actions,
            message:
              `Activated ${unique.length} plugin(s): ${unique.join(', ')}. ` +
              `${activatedTools.length} new tools are now available.`,
          },
        }
      }

      default:
        return { ok: false, errors: [`Unknown action: ${input.action}`] }
    }
  }
}
