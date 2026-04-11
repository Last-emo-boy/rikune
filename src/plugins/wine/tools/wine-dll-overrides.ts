/**
 * wine.dll_overrides — Configure DLL override behaviour for Wine analysis.
 *
 * Allows setting which DLLs use native vs built-in mode in a Wine prefix.
 * Essential for malware analysis: override specific DLLs to intercept
 * API calls, bypass anti-analysis DLL checks, or force specific behaviours.
 */

import { z } from 'zod'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs'
import { join, basename } from 'path'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  SharedMetricsSchema,
  normalizeError, buildMetrics,
} from '../../docker-shared.js'

const overrideMode = z.enum(['native', 'builtin', 'native,builtin', 'builtin,native', 'disabled', ''])
  .describe('native = use Windows DLL; builtin = use Wine DLL; disabled = DLL not loaded; empty = remove override')

const inputSchema = z.object({
  action: z.enum(['set', 'get', 'list']).describe(
    'set: apply DLL overrides; get: read current override for specific DLLs; list: show all overrides'
  ),
  prefix_name: z.string().describe('Wine prefix name (must exist under .wine-prefixes/).'),
  overrides: z.record(z.string(), overrideMode).optional().describe(
    'Map of DLL name → override mode. Required for action=set. Example: {"kernel32": "native", "ntdll": "builtin"}'
  ),
  dlls: z.array(z.string()).optional().describe('DLL names to query. Used with action=get.'),
})

export const wineDllOverridesToolDefinition: ToolDefinition = {
  name: 'wine.dll_overrides',
  description:
    'Configure DLL load-order overrides in a Wine prefix. ' +
    'Set native/builtin/disabled per DLL — useful for hooking, anti-analysis bypass, or forcing specific API implementations.',
  inputSchema: inputSchema,
}

function getPrefixRoot(wm: WorkspaceManager): string {
  return join((wm as any).workspaceRoot ?? '/tmp', '.wine-prefixes')
}

/** Read user.reg from a Wine prefix and extract DLL overrides section */
function readDllOverrides(prefixPath: string): Record<string, string> {
  const userReg = join(prefixPath, 'user.reg')
  if (!existsSync(userReg)) return {}

  const content = readFileSync(userReg, 'utf-8')
  const overrides: Record<string, string> = {}
  const sectionMatch = content.match(/\[Software\\\\Wine\\\\DllOverrides\][^\[]*/)
  if (!sectionMatch) return overrides

  const lines = sectionMatch[0].split('\n')
  for (const line of lines) {
    const m = line.match(/^"([^"]+)"="([^"]*)"/)
    if (m) overrides[m[1]] = m[2]
  }
  return overrides
}

export function createWineDllOverridesHandler(wm: WorkspaceManager, _db: DatabaseManager) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = inputSchema.parse(args)
      const prefixRoot = getPrefixRoot(wm)
      const safeName = basename(input.prefix_name).replace(/[^a-zA-Z0-9_\-\.]/g, '_')
      const prefixPath = join(prefixRoot, safeName)

      if (!existsSync(prefixPath)) {
        return { ok: false, errors: [`Prefix '${safeName}' does not exist. Create it first with wine.env`], metrics: buildMetrics(startTime, 'wine.dll_overrides') }
      }

      if (input.action === 'list') {
        const overrides = readDllOverrides(prefixPath)
        return {
          ok: true,
          data: { prefix: safeName, overrides, count: Object.keys(overrides).length },
          metrics: buildMetrics(startTime, 'wine.dll_overrides'),
        }
      }

      if (input.action === 'get') {
        const all = readDllOverrides(prefixPath)
        const result: Record<string, string | null> = {}
        for (const dll of (input.dlls ?? [])) {
          result[dll] = all[dll] ?? null
        }
        return {
          ok: true,
          data: { prefix: safeName, overrides: result },
          metrics: buildMetrics(startTime, 'wine.dll_overrides'),
        }
      }

      if (input.action === 'set') {
        if (!input.overrides || Object.keys(input.overrides).length === 0) {
          return { ok: false, errors: ['overrides map is required for action=set'], metrics: buildMetrics(startTime, 'wine.dll_overrides') }
        }

        // Build WINEDLLOVERRIDES env format: "dll1=mode;dll2=mode"
        const envOverrides = Object.entries(input.overrides)
          .map(([dll, mode]) => `${dll}=${mode}`)
          .join(';')

        // Also write a .wine-dll-overrides file for reference
        const overridePath = join(prefixPath, '.wine-dll-overrides')
        writeFileSync(overridePath, JSON.stringify(input.overrides, null, 2), 'utf-8')

        return {
          ok: true,
          data: {
            prefix: safeName,
            applied: input.overrides,
            env_string: envOverrides,
            hint: `Set WINEDLLOVERRIDES="${envOverrides}" when running wine.run against this prefix.`,
          },
          metrics: buildMetrics(startTime, 'wine.dll_overrides'),
        }
      }

      return { ok: false, errors: ['Unknown action'], metrics: buildMetrics(startTime, 'wine.dll_overrides') }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, 'wine.dll_overrides') }
    }
  }
}
