/**
 * Tool Surface Manager — Progressive Tool Visibility
 *
 * Controls which tools are visible to the AI at any given moment.
 * Instead of exposing all ~270 tools, the AI starts with ~15 Gateway tools
 * and discovers more as analysis progresses.
 *
 * Architecture:
 *   - Each plugin declares `surfaceRules` (tier + activation conditions)
 *   - ToolSurfaceManager reads these at startup
 *   - `listVisibleTools()` returns only currently active tool names
 *   - `processToolResult()` checks results for activation signals
 *   - MCP `notifications/tools/list_changed` notifies clients on change
 *
 * Tiers:
 *   0 — Gateway-capable: discoverable immediately, but not necessarily listed
 *       in the initial gateway unless explicitly configured.
 *   1 — Context-activated: appear when sample file type matches
 *   2 — Finding-activated: appear when analysis findings match
 *   3 — Expert: manual activation only through the workflow.search activation gateway
 */

import pino from 'pino'
import type { Plugin, SurfaceRules, SurfaceTier } from '../plugins/sdk.js'
import { SURFACE_FILE_TYPE_TAGS } from '../plugins/sdk.js'
import { toTransportToolName } from './tool-name-normalization.js'

// MCP stdio reserves stdout for JSON-RPC frames. Send surface logs to stderr.
const logger = pino(
  { name: 'tool-surface-manager', level: process.env.LOG_LEVEL || 'info' },
  pino.destination({ dest: 2, sync: false })
)

const SURFACE_EXPANSION_EXCLUDED_TOOLS = new Set(['workflow.search', 'workflow.run'])

// ═══════════════════════════════════════════════════════════════════════════
// File-type normalization (delegates to SDK vocabulary)
// ═══════════════════════════════════════════════════════════════════════════

function normalizeFileTypeTags(rawType: string): string[] {
  const lower = rawType.toLowerCase().trim()
  if (SURFACE_FILE_TYPE_TAGS[lower]) return SURFACE_FILE_TYPE_TAGS[lower]
  // Extension-based fallback
  const extension = lower.includes('.') ? lower.slice(lower.lastIndexOf('.') + 1) : lower
  if (extension && SURFACE_FILE_TYPE_TAGS[extension]) return SURFACE_FILE_TYPE_TAGS[extension]
  return [lower]
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin surface entry
// ═══════════════════════════════════════════════════════════════════════════

interface PluginSurfaceEntry {
  pluginId: string
  tools: string[]
  rules: SurfaceRules
  activated: boolean
}

// ═══════════════════════════════════════════════════════════════════════════
// Surface categories for workflow.search/tools.discover
// ═══════════════════════════════════════════════════════════════════════════

export interface DiscoverableCategory {
  category: string
  plugins: Array<{
    id: string
    name: string
    description?: string
    tools: string[]
    tier: SurfaceTier
    activated: boolean
  }>
}

export interface DiscoverableCoreTool {
  name: string
  transportName: string
  visible: boolean
}

// ═══════════════════════════════════════════════════════════════════════════
// ToolSurfaceManager
// ═══════════════════════════════════════════════════════════════════════════

export class ToolSurfaceManager {
  private entries: Map<string, PluginSurfaceEntry> = new Map()
  /** All registered core tool names (not from plugins). */
  private coreTools: Set<string> = new Set()
  /** Core tool names exposed in the initial gateway surface. */
  private visibleCoreTools: Set<string> = new Set()
  /** Callback to send MCP notification. */
  private notifyListChanged: (() => void) | null = null
  /** Whether progressive surface is enabled (can be disabled via env). */
  private enabled: boolean
  /** Preserve legacy behavior by making tier-0 plugins visible at startup. */
  private autoActivateTier0Plugins: boolean

  constructor() {
    // Allow full surface via env var for backward compatibility
    this.enabled = (process.env.SURFACE_PROGRESSIVE ?? '1') !== '0'
    this.autoActivateTier0Plugins = process.env.SURFACE_AUTO_ACTIVATE_TIER0 === '1'
  }

  // ── Setup ────────────────────────────────────────────────────────────────

  /**
   * Set the MCP notification callback. Called by server.ts after init.
   */
  setNotifyCallback(cb: () => void): void {
    this.notifyListChanged = cb
  }

  /**
   * Register core tools (non-plugin tools registered in tool-registry.ts).
   * These remain registered and callable by name, but are not necessarily
   * listed in the initial gateway surface.
   */
  registerCoreTools(toolNames: string[]): void {
    for (const name of toolNames) this.coreTools.add(name)
  }

  /**
   * Register the intentionally small core gateway surface.
   * These tools are visible before sample context or discovery expansion.
   */
  registerGatewayCoreTools(toolNames: string[]): void {
    for (const name of toolNames) {
      this.coreTools.add(name)
      this.visibleCoreTools.add(name)
    }
  }

  /**
   * Register a plugin and its tools with their surface rules.
   * Called during plugin loading.
   */
  registerPlugin(plugin: Plugin, toolNames: string[]): void {
    const rules = plugin.surfaceRules ?? { tier: 0 as const }
    const activated = this.autoActivateTier0Plugins && rules.tier === 0
    this.entries.set(plugin.id, {
      pluginId: plugin.id,
      tools: toolNames,
      rules,
      activated,
    })
  }

  /**
   * Remove a plugin and all of its progressive-surface state.
   * Used by plugin hot-unload so hidden discovery metadata, activation state,
   * and signal rules do not survive after the plugin's tools are unregistered.
   *
   * @returns tool names that were owned by the removed plugin
   */
  unregisterPlugin(pluginId: string): string[] {
    const entry = this.entries.get(pluginId)
    if (!entry) return []

    this.entries.delete(pluginId)
    if (this.notifyListChanged) {
      this.notifyListChanged()
    }

    logger.info(
      { plugin: pluginId, tools: entry.tools.length },
      `Surface unregistered: ${pluginId} (-${entry.tools.length} tools)`
    )

    return [...entry.tools]
  }

  // ── Visibility queries ─────────────────────────────────────────────────

  /**
   * Get the set of tool names currently visible to the AI.
   * Used by server.ts in `listTools()`.
   */
  getVisibleToolNames(): Set<string> {
    // When disabled, everything is visible
    if (!this.enabled) return new Set<string>() // empty = no filtering

    const visible = new Set<string>(this.visibleCoreTools)
    for (const entry of this.entries.values()) {
      if (entry.activated) {
        for (const tool of entry.tools) visible.add(tool)
      }
    }
    return visible
  }

  /**
   * Whether surface filtering is active.
   */
  isEnabled(): boolean {
    return this.enabled
  }

  /**
   * Check if a specific tool is currently visible.
   */
  isToolVisible(toolName: string): boolean {
    if (!this.enabled) return true
    if (this.visibleCoreTools.has(toolName)) return true
    for (const entry of this.entries.values()) {
      if (entry.activated && entry.tools.includes(toolName)) return true
    }
    return false
  }

  // ── Activation ─────────────────────────────────────────────────────────

  /**
   * Activate plugins matching a file type.
   * Called when a sample is ingested or when triage identifies the file type.
   * By default only tier-1 format tools are auto-opened. The discovery portal
   * can opt into tier-2 format tools when the AI explicitly activates by type.
   *
   * @returns list of newly activated plugin IDs
   */
  activateByFileType(
    rawFileType: string,
    options: { includeTier2?: boolean; includeExpert?: boolean } = {}
  ): string[] {
    const tags = normalizeFileTypeTags(rawFileType)
    return this.activateMatching((entry) => {
      if (
        entry.rules.tier !== 1 &&
        !(options.includeTier2 && entry.rules.tier === 2) &&
        !(options.includeExpert && entry.rules.tier === 3)
      ) {
        return false
      }
      const fileTypes = entry.rules.activateOn?.fileTypes
      if (!fileTypes) return false
      return fileTypes.some((ft) => tags.includes(ft.toLowerCase()))
    })
  }

  /**
   * Activate plugins matching a finding/signal (tier 2 activation).
   * Called when a tool result contains findings that match plugin rules.
   *
   * @returns list of newly activated plugin IDs
   */
  activateByFinding(finding: string): string[] {
    const lower = finding.toLowerCase()
    return this.activateMatching((entry) => {
      if (entry.rules.tier !== 2) return false
      const findings = entry.rules.activateOn?.findings
      if (!findings) return false
      return findings.some((f) => lower.includes(f.toLowerCase()))
    })
  }

  /**
   * Activate plugins matching a discovery category (tier 3 or any tier).
   * Called by the progressive activation gateway.
   *
   * @returns list of newly activated plugin IDs
   */
  activateByCategory(category: string): string[] {
    const lower = category.toLowerCase()
    return this.activateMatching((entry) => {
      return entry.rules.category?.toLowerCase() === lower
    })
  }

  /**
   * Activate specific plugins by ID.
   * Called by the progressive activation gateway when targeting specific plugins.
   *
   * @returns list of newly activated plugin IDs
   */
  activatePlugins(pluginIds: string[]): string[] {
    return this.activateMatching((entry) => pluginIds.includes(entry.pluginId))
  }

  /**
   * Expose already registered core tools in the gateway list.
   * Used by the discovery portal and by recommended_next_tools expansion.
   */
  activateCoreTools(toolNames: string[]): string[] {
    if (!this.enabled) return []
    const newlyVisible: string[] = []
    for (const name of toolNames) {
      const canonicalName = Array.from(this.coreTools).find(
        (tool) => tool === name || toTransportToolName(tool) === name
      )
      if (!canonicalName || this.visibleCoreTools.has(canonicalName)) continue
      this.visibleCoreTools.add(canonicalName)
      newlyVisible.push(canonicalName)
    }
    if (newlyVisible.length > 0 && this.notifyListChanged) {
      this.notifyListChanged()
    }
    return newlyVisible
  }

  /**
   * Process a tool result for automatic surface expansion.
   *
   * Extracts signals from the result:
   *   - `data.file_type` → tier 1 file-type activation
   *   - `data.recommended_next_tools` → activate plugins owning those tools
   *   - Structured finding flags → tier 2 finding activation
   *
   * @returns list of newly activated plugin IDs (empty if no change)
   */
  processToolResult(toolName: string, result: unknown): string[] {
    if (!this.enabled || !result || typeof result !== 'object') return []
    if (SURFACE_EXPANSION_EXCLUDED_TOOLS.has(toolName)) return []

    const activated: string[] = []
    const data = (result as Record<string, unknown>).data as Record<string, unknown> | undefined

    if (!data || typeof data !== 'object') return []

    // 1. File-type activation (tier 1)
    const fileType = data.file_type as string | undefined
    if (fileType && typeof fileType === 'string') {
      activated.push(...this.activateByFileType(fileType))
    }

    // 2. Recommended next tools → activate owning plugins
    const nextTools = data.recommended_next_tools as string[] | undefined
    if (Array.isArray(nextTools)) {
      for (const nextTool of nextTools) {
        if (typeof nextTool !== 'string') continue
        this.activateCoreTools([nextTool])
        // Find which plugin owns this tool and activate it
        for (const entry of this.entries.values()) {
          if (
            !entry.activated &&
            entry.tools.some((t) => t === nextTool || nextTool.startsWith(t.split('.')[0] + '.'))
          ) {
            activated.push(...this.activatePlugins([entry.pluginId]))
          }
        }
      }
    }

    // 3. Structured finding signals (tier 2)
    const findingSignals = this.extractFindingSignals(data)
    for (const signal of findingSignals) {
      activated.push(...this.activateByFinding(signal))
    }

    return [...new Set(activated)]
  }

  // ── Discovery ──────────────────────────────────────────────────────────

  /**
   * List all discoverable categories with their plugins and activation status.
   * Used by workflow.search and the compatibility tools.discover meta-tool.
   */
  listCategories(
    pluginIndex: Map<string, { name: string; description?: string }>
  ): DiscoverableCategory[] {
    const catMap = new Map<string, DiscoverableCategory['plugins']>()

    for (const entry of this.entries.values()) {
      const cat = entry.rules.category || this.inferCategory(entry.rules)
      const meta = pluginIndex.get(entry.pluginId)
      const pluginEntry = {
        id: entry.pluginId,
        name: meta?.name ?? entry.pluginId,
        description: meta?.description,
        tools: entry.tools,
        tier: entry.rules.tier,
        activated: entry.activated,
      }

      const existing = catMap.get(cat)
      if (existing) {
        existing.push(pluginEntry)
      } else {
        catMap.set(cat, [pluginEntry])
      }
    }

    return Array.from(catMap.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([category, plugins]) => ({ category, plugins }))
  }

  /**
   * List registered core tools and whether they are currently exposed.
   * Used by the discovery portal to search the hidden core tool surface.
   */
  listCoreTools(): DiscoverableCoreTool[] {
    return Array.from(this.coreTools)
      .sort((a, b) => a.localeCompare(b))
      .map((name) => ({
        name,
        transportName: toTransportToolName(name),
        visible: this.visibleCoreTools.has(name),
      }))
  }

  /**
   * Get a summary of the current surface state.
   */
  getSurfaceStatus(): {
    enabled: boolean
    totalPlugins: number
    activatedPlugins: number
    totalTools: number
    visibleTools: number
    tiers: Record<SurfaceTier, { total: number; activated: number }>
  } {
    const tiers: Record<SurfaceTier, { total: number; activated: number }> = {
      0: { total: 0, activated: 0 },
      1: { total: 0, activated: 0 },
      2: { total: 0, activated: 0 },
      3: { total: 0, activated: 0 },
    }

    let totalTools = this.coreTools.size
    let visibleTools = this.visibleCoreTools.size

    for (const entry of this.entries.values()) {
      tiers[entry.rules.tier].total++
      if (entry.activated) tiers[entry.rules.tier].activated++
      totalTools += entry.tools.length
      if (entry.activated) visibleTools += entry.tools.length
    }

    return {
      enabled: this.enabled,
      totalPlugins: this.entries.size,
      activatedPlugins: [...this.entries.values()].filter((e) => e.activated).length,
      totalTools,
      visibleTools,
      tiers,
    }
  }

  // ── Internal helpers ───────────────────────────────────────────────────

  private activateMatching(predicate: (entry: PluginSurfaceEntry) => boolean): string[] {
    const newlyActivated: string[] = []
    for (const entry of this.entries.values()) {
      if (entry.activated) continue
      if (predicate(entry)) {
        entry.activated = true
        newlyActivated.push(entry.pluginId)
        logger.info(
          { plugin: entry.pluginId, tier: entry.rules.tier, tools: entry.tools.length },
          `Surface activated: ${entry.pluginId} (+${entry.tools.length} tools)`
        )
      }
    }
    if (newlyActivated.length > 0 && this.notifyListChanged) {
      this.notifyListChanged()
    }
    return newlyActivated
  }

  /**
   * Extract finding signals from tool result data using plugin-declared
   * signalMaps and extractSignals functions. No hardcoded field checks.
   */
  private extractFindingSignals(data: Record<string, unknown>): string[] {
    const signals: string[] = []

    for (const entry of this.entries.values()) {
      const rules = entry.rules

      // 1. Declarative signalMap: check each field → emit tags
      if (rules.signalMap) {
        for (const [field, tags] of Object.entries(rules.signalMap)) {
          if (data[field]) {
            const tagArr = Array.isArray(tags) ? tags : [tags]
            signals.push(...tagArr)
          }
        }
      }

      // 2. Custom extractSignals function for complex structures
      if (rules.extractSignals) {
        try {
          const extracted = rules.extractSignals(data)
          if (Array.isArray(extracted)) signals.push(...extracted)
        } catch {
          // Signal extraction is best-effort
        }
      }
    }

    return [...new Set(signals)]
  }

  /**
   * Fallback category when none is declared (should be rare — all plugins
   * now declare `category` in surfaceRules).
   */
  private inferCategory(_rules: SurfaceRules): string {
    return 'analysis'
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Singleton instance
// ═══════════════════════════════════════════════════════════════════════════

let instance: ToolSurfaceManager | null = null

export function getToolSurfaceManager(): ToolSurfaceManager {
  if (!instance) instance = new ToolSurfaceManager()
  return instance
}
