/**
 * managed.il_xrefs MCP tool — IL-level cross-reference analysis.
 *
 * Given a field, method, or type token, scans all method bodies for
 * stfld/stsfld/ldfld/ldsfld/call/callvirt/newobj/ldtoken references.
 * Handles generic instantiation contexts (e.g. List<T>.Add vs List<int>.Add).
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'

const TOOL_NAME = 'managed.il_xrefs'

export const IlXrefsInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  token: z.string().describe('Metadata token in hex (e.g. 0x04000012) or fully-qualified member name'),
  token_type: z.enum(['field', 'method', 'type']).describe('Kind of token being queried'),
  include_generic_instantiations: z.boolean().default(true).describe('Resolve generic instantiation contexts'),
  max_results: z.number().min(1).max(5000).default(500).describe('Maximum cross-references to return'),
})

export const ilXrefsToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Scan all IL method bodies for cross-references to a given field, method, or type token. ' +
    'Reports stfld/stsfld/ldfld/ldsfld (fields), call/callvirt/newobj (methods), ' +
    'ldtoken/typeof (types). Handles generic context resolution.',
  inputSchema: IlXrefsInputSchema,
}

async function callIlXrefsWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath'],
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath!('src', 'plugins', 'managed-il-xrefs', 'workers', 'managed_il_xrefs_worker.py')
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`IL xrefs worker exited ${code}: ${stderr.slice(0, 500)}`))
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

export function createIlXrefsHandler(deps: PluginToolDeps) {
  const {
    workspaceManager, database, config, cacheManager, generateCacheKey,
    resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath,
  } = deps
  const pythonCmd = getPythonCommand(undefined, config?.workers?.static?.pythonPath)

  return async (args: z.infer<typeof IlXrefsInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const cacheKey = generateCacheKey!({
        sampleSha256: sample.sha256, toolName: TOOL_NAME, toolVersion: '1.0.0',
        args: { token: args.token, token_type: args.token_type, generic: args.include_generic_instantiations },
      })
      const cached = await cacheManager!.getCachedResult(cacheKey)
      if (cached) return { ok: true, data: cached, metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME, cache: 'hit' } }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      const result = await callIlXrefsWorker({
        action: 'il_xrefs',
        file_path: samplePath,
        token: args.token,
        token_type: args.token_type,
        include_generic_instantiations: args.include_generic_instantiations,
        max_results: args.max_results,
      }, pythonCmd, resolvePackagePath)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'il_xrefs', 'managed-il-xrefs', result,
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
