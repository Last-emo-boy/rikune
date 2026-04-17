/**
 * wine.env — Manage Wine prefixes for isolated analysis environments.
 *
 * Each prefix is a self-contained Windows filesystem that can be created,
 * inspected, or cleaned up. Useful for running samples in clean environments
 * or preserving state across analysis steps.
 */

import { z } from 'zod'
import { existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'fs'
import { join, basename } from 'path'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  SharedMetricsSchema,
  executeCommand, normalizeError, buildMetrics, buildDynamicSetupRequired,
  resolveAnalysisBackends,
} from '../../docker-shared.js'

const inputSchema = z.object({
  action: z.enum(['create', 'inspect', 'list', 'remove']).describe(
    'create: initialise a new WINEPREFIX; inspect: show details of an existing prefix; list: list all prefixes; remove: delete a prefix'
  ),
  prefix_name: z.string().optional().describe(
    'Name for the Wine prefix directory. Required for create/inspect/remove.'
  ),
  arch: z.enum(['win32', 'win64']).default('win64').describe(
    'Architecture for new prefix (WINEARCH). win32 = 32-bit, win64 = 64-bit.'
  ),
  timeout_sec: z.number().int().min(5).max(120).default(60).describe('Timeout for wineboot initialisation.'),
})

export const wineEnvToolDefinition: ToolDefinition = {
  name: 'wine.env',
  description:
    'Manage Wine prefixes — create isolated environments, inspect existing ones, list all, or remove. ' +
    'Each prefix is a separate Windows filesystem for clean analysis.',
  inputSchema: inputSchema,
  runtimeBackendHint: { type: 'inline', handler: 'executeWineEnv' },
}

function getPrefixRoot(wm: WorkspaceManager): string {
  const root = join((wm as any).workspaceRoot ?? '/tmp', '.wine-prefixes')
  if (!existsSync(root)) mkdirSync(root, { recursive: true })
  return root
}

export function createWineEnvHandler(wm: WorkspaceManager, _db: DatabaseManager) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = inputSchema.parse(args)
      const backends = resolveAnalysisBackends()
      const wine = backends.wine
      if (!wine.available || !wine.path) {
        return buildDynamicSetupRequired(wine, startTime, 'wine.env')
      }

      const prefixRoot = getPrefixRoot(wm)

      if (input.action === 'list') {
        const entries = existsSync(prefixRoot)
          ? readdirSync(prefixRoot).filter(e => statSync(join(prefixRoot, e)).isDirectory())
          : []
        return {
          ok: true,
          data: {
            prefixes: entries,
            count: entries.length,
            root: prefixRoot,
          },
          metrics: buildMetrics(startTime, 'wine.env'),
        }
      }

      if (!input.prefix_name) {
        return { ok: false, errors: ['prefix_name is required for create/inspect/remove'], metrics: buildMetrics(startTime, 'wine.env') }
      }

      // Sanitize prefix name to prevent path traversal
      const safeName = basename(input.prefix_name).replace(/[^a-zA-Z0-9_\-\.]/g, '_')
      const prefixPath = join(prefixRoot, safeName)

      if (input.action === 'create') {
        if (existsSync(prefixPath)) {
          return { ok: false, errors: [`Prefix '${safeName}' already exists at ${prefixPath}`], metrics: buildMetrics(startTime, 'wine.env') }
        }
        mkdirSync(prefixPath, { recursive: true })
        const result = await executeCommand(
          wine.path,
          ['wineboot', '--init'],
          input.timeout_sec * 1000,
          { env: { ...process.env, WINEPREFIX: prefixPath, WINEARCH: input.arch, WINEDEBUG: '-all' } }
        )
        return {
          ok: result.exitCode === 0,
          data: {
            prefix: safeName,
            path: prefixPath,
            arch: input.arch,
            initialised: result.exitCode === 0,
          },
          warnings: result.timedOut ? ['wineboot timed out — prefix may be incomplete'] : undefined,
          errors: result.exitCode !== 0 ? [`wineboot exited ${result.exitCode}`] : undefined,
          metrics: buildMetrics(startTime, 'wine.env'),
        }
      }

      if (input.action === 'inspect') {
        if (!existsSync(prefixPath)) {
          return { ok: false, errors: [`Prefix '${safeName}' does not exist`], metrics: buildMetrics(startTime, 'wine.env') }
        }
        const stat = statSync(prefixPath)
        const driveC = join(prefixPath, 'drive_c')
        const hasDriveC = existsSync(driveC)
        return {
          ok: true,
          data: {
            prefix: safeName,
            path: prefixPath,
            created: stat.birthtime.toISOString(),
            modified: stat.mtime.toISOString(),
            has_drive_c: hasDriveC,
            size_hint: hasDriveC ? 'use du for accurate size' : 'uninitialised',
          },
          metrics: buildMetrics(startTime, 'wine.env'),
        }
      }

      if (input.action === 'remove') {
        if (!existsSync(prefixPath)) {
          return { ok: false, errors: [`Prefix '${safeName}' does not exist`], metrics: buildMetrics(startTime, 'wine.env') }
        }
        rmSync(prefixPath, { recursive: true, force: true })
        return {
          ok: true,
          data: { prefix: safeName, removed: true },
          metrics: buildMetrics(startTime, 'wine.env'),
        }
      }

      return { ok: false, errors: ['Unknown action'], metrics: buildMetrics(startTime, 'wine.env') }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, 'wine.env') }
    }
  }
}
