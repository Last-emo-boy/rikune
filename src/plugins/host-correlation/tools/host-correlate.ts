/**
 * host.correlate MCP tool — auto-scan a directory and system artifacts
 * to correlate a DLL/EXE with its host, loader, and execution context.
 *
 * Scans for:
 *   - Co-located EXE files that may load the DLL (import table analysis)
 *   - Scheduled tasks referencing the sample path
 *   - Windows services registered with the sample
 *   - Startup folder / Run key entries
 *   - DLL sideloading configuration files (manifests, .local, .config)
 *   - COM registration entries
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'

const TOOL_NAME = 'host.correlate'

export const HostCorrelateInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  scan_directory: z.string().optional()
    .describe('Directory to scan for co-located files (defaults to sample directory)'),
  check_scheduled_tasks: z.boolean().default(true)
    .describe('Search scheduled tasks for references to the sample'),
  check_services: z.boolean().default(true)
    .describe('Search Windows services for references to the sample'),
  check_startup: z.boolean().default(true)
    .describe('Check startup folders and Run/RunOnce registry keys'),
  check_sideload: z.boolean().default(true)
    .describe('Scan for DLL sideloading configs (.manifest, .local, .config)'),
  check_com_registration: z.boolean().default(true)
    .describe('Search COM registration for CLSIDs pointing to the sample'),
  check_import_tables: z.boolean().default(true)
    .describe('Analyze import tables of co-located EXEs for DLL references'),
  recursive: z.boolean().default(false)
    .describe('Recursively scan subdirectories'),
  max_depth: z.number().min(1).max(5).default(2)
    .describe('Maximum directory traversal depth when recursive is enabled'),
})

export const hostCorrelateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Auto-scan directory and system artifacts to correlate a DLL/EXE with its host ' +
    'process, loader, and execution context. Checks co-located EXE import tables, ' +
    'scheduled tasks, services, startup entries, DLL sideloading configs, and COM ' +
    'registration to build a complete picture of how the sample is loaded and executed.',
  inputSchema: HostCorrelateInputSchema,
}

async function callHostCorrelationWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath'],
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath!('src', 'plugins', 'host-correlation', 'workers', 'host_correlation_worker.py')
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Host correlation worker exited ${code}: ${stderr.slice(0, 500)}`))
        return
      }
      try { resolve(JSON.parse(stdout.trim())) }
      catch (e) { reject(new Error(`Parse: ${(e as Error).message}`)) }
    })
    proc.on('error', (e) => reject(new Error(`Spawn: ${e.message}`)))
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

export function createHostCorrelateHandler(deps: PluginToolDeps) {
  const {
    workspaceManager, database, config, cacheManager, generateCacheKey,
    resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath,
  } = deps
  const pythonCmd = getPythonCommand(undefined, config?.workers?.static?.pythonPath)

  return async (args: z.infer<typeof HostCorrelateInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      const cacheKey = generateCacheKey!({
        sampleSha256: sample.sha256, toolName: TOOL_NAME, toolVersion: '1.0.0',
        args: { scan_directory: args.scan_directory ?? '' },
      })
      const cached = await cacheManager!.getCachedResult(cacheKey)
      if (cached) return { ok: true, data: cached, metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME, cache: 'hit' } }

      const result = await callHostCorrelationWorker({
        action: 'correlate',
        file_path: samplePath,
        scan_directory: args.scan_directory ?? null,
        check_scheduled_tasks: args.check_scheduled_tasks,
        check_services: args.check_services,
        check_startup: args.check_startup,
        check_sideload: args.check_sideload,
        check_com_registration: args.check_com_registration,
        check_import_tables: args.check_import_tables,
        recursive: args.recursive,
        max_depth: args.max_depth,
      }, pythonCmd, resolvePackagePath)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'host_correlation', 'host-correlate', result,
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      if (result.ok) await cacheManager!.setCachedResult(cacheKey, result, 24 * 60 * 60 * 1000, sample.sha256)

      return {
        ok: Boolean(result.ok),
        data: result,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
