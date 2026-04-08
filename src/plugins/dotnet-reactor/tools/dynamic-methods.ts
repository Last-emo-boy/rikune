/**
 * reactor.dynamic_methods MCP tool — recover DynamicMethod / MethodBuilder
 * bodies created by .NET Reactor at runtime.
 *
 * Uses a combination of static IL analysis (detecting DynamicMethod.CreateDelegate,
 * MethodBuilder patterns) and optional sandbox execution to capture method
 * bodies that are generated dynamically.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'reactor.dynamic_methods'

export const DynamicMethodsInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  use_sandbox: z.boolean().default(false)
    .describe('Execute in sandbox to capture runtime-generated method bodies'),
  include_il_bytes: z.boolean().default(true)
    .describe('Include raw IL bytes for recovered methods'),
  decompile: z.boolean().default(true)
    .describe('Attempt to decompile recovered IL back to C#'),
  timeout_seconds: z.number().min(5).max(120).default(30)
    .describe('Sandbox execution timeout if use_sandbox is enabled'),
})

export const dynamicMethodsToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Recover DynamicMethod and MethodBuilder bodies created by .NET Reactor ' +
    'at runtime. Combines static IL analysis with optional sandbox execution. ' +
    'Returns recovered method signatures, IL disassembly, and decompiled C# where possible.',
  inputSchema: DynamicMethodsInputSchema,
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

export function createDynamicMethodsHandler(deps: PluginToolDeps) {
  const {
    workspaceManager, database, config, cacheManager, generateCacheKey,
    resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath,
  } = deps
  const pythonCmd = config?.workers?.static?.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')

  return async (args: z.infer<typeof DynamicMethodsInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const cacheKey = generateCacheKey!({
        sampleSha256: sample.sha256, toolName: TOOL_NAME, toolVersion: '1.0.0',
        args: { use_sandbox: args.use_sandbox },
      })
      const cached = await cacheManager!.getCachedResult(cacheKey)
      if (cached) return { ok: true, data: cached, metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME, cache: 'hit' } }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      const result = await callReactorWorker({
        action: 'dynamic_methods',
        file_path: samplePath,
        use_sandbox: args.use_sandbox,
        include_il_bytes: args.include_il_bytes,
        decompile: args.decompile,
        timeout_seconds: args.timeout_seconds,
      }, pythonCmd, resolvePackagePath)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'reactor_dynamic_methods', 'reactor-dynamic-methods', result,
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
