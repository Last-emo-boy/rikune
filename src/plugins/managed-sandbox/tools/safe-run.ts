/**
 * managed.safe_run MCP tool — execute a .NET assembly in an isolated sandbox
 * environment with network sinkholing and CLR hook capture.
 *
 * Capabilities:
 *   - Default network disabled — redirects HttpClient, WebRequest, Socket,
 *     WinHTTP, and WinINet calls to a local sinkhole
 *   - Hooks Assembly.Load(byte[]), AppDomain.ResourceResolve,
 *     CreateDecryptor, MethodInfo.Invoke to capture dynamic loading
 *   - Configurable timeout, memory limit, and sinkhole response body
 *   - Returns captured network requests, loaded assemblies, decryption calls,
 *     and invoked methods as structured data
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'
import { resolveExecutable } from '../../../static-backend-discovery.js'
import { buildDynamicSetupRequired } from '../../docker-shared.js'

const TOOL_NAME = 'managed.safe_run'

/* ── Input schema ──────────────────────────────────────────────────────── */

export const SafeRunInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  entry_class: z.string().optional().describe('Fully-qualified class name to invoke (auto-detected if omitted)'),
  entry_method: z.string().optional().describe('Method name to invoke (defaults to Main / EntryPoint)'),
  args: z.array(z.string()).optional().describe('Command-line arguments to pass to the assembly'),
  timeout_seconds: z.number().min(1).max(300).default(60).describe('Maximum execution time in seconds'),
  memory_limit_mb: z.number().min(32).max(2048).default(512).describe('Maximum memory in MB'),
  enable_network_sinkhole: z.boolean().default(true).describe('Redirect all network calls to local sinkhole'),
  sinkhole_response_body: z.string().optional().describe('Custom HTTP response body returned by the sinkhole'),
  hook_assembly_load: z.boolean().default(true).describe('Hook Assembly.Load(byte[]) and log payloads'),
  hook_resource_resolve: z.boolean().default(true).describe('Hook AppDomain.ResourceResolve events'),
  hook_create_decryptor: z.boolean().default(true).describe('Hook SymmetricAlgorithm.CreateDecryptor calls'),
  hook_method_invoke: z.boolean().default(true).describe('Hook MethodInfo.Invoke calls'),
  dump_loaded_assemblies: z.boolean().default(true).describe('Dump dynamically loaded assemblies to workspace'),
})

export const safeRunToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Execute a managed .NET assembly in an isolated sandbox with network ' +
    'sinkholing and CLR runtime hooks. Captures dynamically loaded assemblies, ' +
    'decryption calls, reflective invocations, and all outbound network requests. ' +
    'Supports configurable timeout, memory limit, and custom sinkhole responses.',
  inputSchema: SafeRunInputSchema,
  runtimeBackendHint: { type: 'inline', handler: 'executeManagedSafeRun' },
}

/* ── Worker bridge ─────────────────────────────────────────────────────── */

async function callSandboxWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath'],
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath!('src', 'plugins', 'managed-sandbox', 'workers', 'managed_sandbox_worker.py')
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Sandbox worker exited ${code}: ${stderr.slice(0, 500)}`))
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

/* ── Handler ───────────────────────────────────────────────────────────── */

export function createSafeRunHandler(deps: PluginToolDeps) {
  const {
    workspaceManager, database, config, cacheManager, generateCacheKey,
    resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath,
  } = deps
  const pythonCmd = config?.workers?.static?.pythonPath || (process.platform === 'win32' ? 'python' : 'python3')

  return async (args: z.infer<typeof SafeRunInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    // Backend gate
    const pythonBackend = resolveExecutable({ pathCandidates: [pythonCmd, 'python3', 'python'], versionArgSets: [['--version']] })
    if (!pythonBackend.available) {
      return buildDynamicSetupRequired(pythonBackend as any, t0, TOOL_NAME)
    }
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      // No caching for sandbox runs — each execution may produce different results

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      const result = await callSandboxWorker({
        action: 'safe_run',
        file_path: samplePath,
        entry_class: args.entry_class ?? null,
        entry_method: args.entry_method ?? null,
        args: args.args ?? [],
        timeout_seconds: args.timeout_seconds,
        memory_limit_mb: args.memory_limit_mb,
        enable_network_sinkhole: args.enable_network_sinkhole,
        sinkhole_response_body: args.sinkhole_response_body ?? null,
        hook_assembly_load: args.hook_assembly_load,
        hook_resource_resolve: args.hook_resource_resolve,
        hook_create_decryptor: args.hook_create_decryptor,
        hook_method_invoke: args.hook_method_invoke,
        dump_loaded_assemblies: args.dump_loaded_assemblies,
      }, pythonCmd, resolvePackagePath)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'sandbox_run', 'managed-safe-run', result,
        )
        if (artRef) artifacts.push(artRef)
      } catch { /* non-fatal */ }

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
