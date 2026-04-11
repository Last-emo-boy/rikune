/**
 * wine.reg — Query and set Wine registry keys.
 *
 * Many malware samples check Windows registry for environment detection
 * (VM checks, locale, installed software). This tool lets you pre-populate
 * or inspect registry state in a Wine prefix before/after execution.
 */

import { z } from 'zod'
import { existsSync } from 'fs'
import { join, basename } from 'path'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  SharedMetricsSchema,
  executeCommand, normalizeError, truncateText, buildMetrics,
  buildDynamicSetupRequired, resolveAnalysisBackends,
  persistBackendArtifact,
} from '../../docker-shared.js'
import type { ArtifactRef } from '../../../types.js'

const inputSchema = z.object({
  action: z.enum(['query', 'add', 'export']).describe(
    'query: read a key/value; add: set a registry value; export: dump a registry subtree'
  ),
  prefix_name: z.string().describe('Wine prefix name.'),
  key: z.string().describe(
    'Registry key path, e.g. "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"'
  ),
  value_name: z.string().optional().describe('Value name under the key (for query/add).'),
  value_data: z.string().optional().describe('Data to set (for action=add).'),
  value_type: z.enum(['REG_SZ', 'REG_DWORD', 'REG_BINARY', 'REG_EXPAND_SZ', 'REG_MULTI_SZ'])
    .default('REG_SZ').describe('Registry value type (for action=add).'),
  sample_id: z.string().optional().describe('Sample ID to attach exported registry as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
  timeout_sec: z.number().int().min(5).max(60).default(15).describe('Timeout.'),
})

export const wineRegToolDefinition: ToolDefinition = {
  name: 'wine.reg',
  description:
    'Query, set, or export Wine registry keys in a prefix. ' +
    'Useful for pre-populating environment data (anti-VM bypass) or inspecting registry changes after execution.',
  inputSchema: inputSchema,
}

function getPrefixRoot(wm: WorkspaceManager): string {
  return join((wm as any).workspaceRoot ?? '/tmp', '.wine-prefixes')
}

export function createWineRegHandler(wm: WorkspaceManager, db: DatabaseManager) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = inputSchema.parse(args)
      const backends = resolveAnalysisBackends()
      const wine = backends.wine
      if (!wine.available || !wine.path) {
        return buildDynamicSetupRequired(wine, startTime, 'wine.reg')
      }

      const prefixRoot = getPrefixRoot(wm)
      const safeName = basename(input.prefix_name).replace(/[^a-zA-Z0-9_\-\.]/g, '_')
      const prefixPath = join(prefixRoot, safeName)

      if (!existsSync(prefixPath)) {
        return { ok: false, errors: [`Prefix '${safeName}' does not exist. Create it first with wine.env`], metrics: buildMetrics(startTime, 'wine.reg') }
      }

      const env = { ...process.env, WINEPREFIX: prefixPath, WINEDEBUG: '-all' }

      if (input.action === 'query') {
        const cmdArgs = ['reg', 'query', input.key]
        if (input.value_name) cmdArgs.push('/v', input.value_name)
        const result = await executeCommand(wine.path, cmdArgs, input.timeout_sec * 1000, { env })
        const preview = truncateText(result.stdout, 4000)
        return {
          ok: result.exitCode === 0,
          data: {
            key: input.key,
            output: preview.text,
          },
          errors: result.exitCode !== 0 ? [`reg query exited ${result.exitCode}: ${result.stderr}`] : undefined,
          metrics: buildMetrics(startTime, 'wine.reg'),
        }
      }

      if (input.action === 'add') {
        if (!input.value_name || !input.value_data) {
          return { ok: false, errors: ['value_name and value_data are required for action=add'], metrics: buildMetrics(startTime, 'wine.reg') }
        }
        const cmdArgs = ['reg', 'add', input.key, '/v', input.value_name, '/t', input.value_type, '/d', input.value_data, '/f']
        const result = await executeCommand(wine.path, cmdArgs, input.timeout_sec * 1000, { env })
        return {
          ok: result.exitCode === 0,
          data: {
            key: input.key,
            value_name: input.value_name,
            value_data: input.value_data,
            value_type: input.value_type,
            written: result.exitCode === 0,
          },
          errors: result.exitCode !== 0 ? [`reg add exited ${result.exitCode}: ${result.stderr}`] : undefined,
          metrics: buildMetrics(startTime, 'wine.reg'),
        }
      }

      if (input.action === 'export') {
        const cmdArgs = ['reg', 'export', input.key, '/dev/stdout']
        const result = await executeCommand(wine.path, cmdArgs, input.timeout_sec * 1000, { env })

        const artifacts: ArtifactRef[] = []
        if (result.exitCode === 0 && input.sample_id) {
          const artifact = await persistBackendArtifact(
            wm, db, input.sample_id, 'wine-reg', 'export',
            result.stdout,
            { extension: 'reg', mime: 'text/plain', sessionTag: input.session_tag }
          )
          artifacts.push(artifact)
        }

        const preview = truncateText(result.stdout, 4000)
        return {
          ok: result.exitCode === 0,
          data: {
            key: input.key,
            output: preview.text,
          },
          artifacts: artifacts.length > 0 ? artifacts : undefined,
          errors: result.exitCode !== 0 ? [`reg export exited ${result.exitCode}: ${result.stderr}`] : undefined,
          metrics: buildMetrics(startTime, 'wine.reg'),
        }
      }

      return { ok: false, errors: ['Unknown action'], metrics: buildMetrics(startTime, 'wine.reg') }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, 'wine.reg') }
    }
  }
}
