/**
 * reactor.resource_export MCP tool — extract and export embedded resource
 * assemblies from .NET Reactor-protected binaries.
 *
 * .NET Reactor commonly packs satellite assemblies, dependencies, or payload
 * assemblies as encrypted/compressed resources. This tool identifies, decrypts,
 * and exports them.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'

const TOOL_NAME = 'reactor.resource_export'

export const ResourceExportInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  resource_name: z.string().optional().describe('Specific resource name to export (exports all if omitted)'),
  attempt_decrypt: z.boolean().default(true).describe('Attempt to decrypt encrypted resources'),
  attempt_decompress: z.boolean().default(true).describe('Attempt to decompress packed resources'),
  save_to_workspace: z.boolean().default(true).describe('Save exported assemblies to the sample workspace'),
})

export const resourceExportToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract and export embedded resource assemblies from .NET Reactor-protected ' +
    'binaries. Identifies encrypted/compressed satellite assemblies, payload DLLs, ' +
    'and packed dependencies. Attempts decryption and decompression, then saves ' +
    'recovered assemblies to the workspace for further analysis.',
  inputSchema: ResourceExportInputSchema,
}

async function callReactorWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath'],
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath!('src', 'plugins', 'dotnet-reactor', 'workers', 'dotnet_reactor_worker.py')
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Reactor worker exited ${code}: ${stderr.slice(0, 500)}`))
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

export function createResourceExportHandler(deps: PluginToolDeps) {
  const {
    workspaceManager, database, config, cacheManager, generateCacheKey,
    resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath,
  } = deps
  const pythonCmd = getPythonCommand(undefined, config?.workers?.static?.pythonPath)

  return async (args: z.infer<typeof ResourceExportInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const cacheKey = generateCacheKey!({
        sampleSha256: sample.sha256, toolName: TOOL_NAME, toolVersion: '1.0.0',
        args: { resource_name: args.resource_name ?? '' },
      })
      const cached = await cacheManager!.getCachedResult(cacheKey)
      if (cached) return { ok: true, data: cached, metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME, cache: 'hit' } }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      const result = await callReactorWorker({
        action: 'resource_export',
        file_path: samplePath,
        resource_name: args.resource_name ?? null,
        attempt_decrypt: args.attempt_decrypt,
        attempt_decompress: args.attempt_decompress,
        save_to_workspace: args.save_to_workspace,
      }, pythonCmd, resolvePackagePath)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'reactor_resources', 'reactor-resource-export', result,
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

      if (result.ok) await cacheManager!.setCachedResult(cacheKey, result, 30 * 24 * 60 * 60 * 1000, sample.sha256)

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
