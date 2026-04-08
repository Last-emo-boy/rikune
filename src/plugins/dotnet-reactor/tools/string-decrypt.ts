/**
 * reactor.string_decrypt MCP tool — track and decrypt .NET Reactor
 * encrypted strings.
 *
 * Identifies string decryption delegate calls, proxy methods, and
 * encrypted string tables. Supports static pattern matching and
 * dynamic decryption via sandbox execution.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'reactor.string_decrypt'

export const StringDecryptInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  method_token: z.string().optional().describe('Specific method token to analyze (analyzes all if omitted)'),
  mode: z.enum(['static', 'dynamic', 'both']).default('static')
    .describe('Decryption approach: static pattern matching, dynamic execution, or both'),
  max_strings: z.number().min(1).max(10000).default(2000).describe('Maximum strings to decrypt'),
})

export const stringDecryptToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Track and decrypt .NET Reactor encrypted strings. Identifies delegate-based ' +
    'decryption proxies, resolves encrypted string tables, and decrypts via ' +
    'static pattern matching or dynamic sandbox execution. Returns original and ' +
    'decrypted string pairs with call-site locations.',
  inputSchema: StringDecryptInputSchema,
}

async function callReactorWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath'],
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath!('workers', 'dotnet_reactor_worker.py')
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

export function createStringDecryptHandler(deps: PluginToolDeps) {
  const {
    workspaceManager, database, config, cacheManager, generateCacheKey,
    resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath,
  } = deps
  const pythonCmd = config?.workers?.static?.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')

  return async (args: z.infer<typeof StringDecryptInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const cacheKey = generateCacheKey!({
        sampleSha256: sample.sha256, toolName: TOOL_NAME, toolVersion: '1.0.0',
        args: { method_token: args.method_token ?? '', mode: args.mode },
      })
      const cached = await cacheManager!.getCachedResult(cacheKey)
      if (cached) return { ok: true, data: cached, metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME, cache: 'hit' } }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      const result = await callReactorWorker({
        action: 'string_decrypt',
        file_path: samplePath,
        method_token: args.method_token ?? null,
        mode: args.mode,
        max_strings: args.max_strings,
      }, pythonCmd, resolvePackagePath)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'reactor_strings', 'reactor-string-decrypt', result,
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
