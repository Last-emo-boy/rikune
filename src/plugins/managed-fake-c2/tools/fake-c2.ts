/**
 * managed.fake_c2 MCP tool — configurable fake C2 server for driving
 * deeper sample logic during sandbox execution.
 *
 * Allows the analyst to configure custom responses for specific endpoints
 * (e.g. /plugin, /ping, /gate, /task) so that the sample continues past
 * initial C2 connectivity checks and enters operational command handling.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef, PluginToolDeps } from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'

const TOOL_NAME = 'managed.fake_c2'

/* ── Input schema ──────────────────────────────────────────────────────── */

const EndpointConfigSchema = z.object({
  path: z.string().describe('URL path to match (e.g. /plugin, /ping, /gate)'),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'ANY']).default('ANY').describe('HTTP method to match'),
  status_code: z.number().min(100).max(599).default(200).describe('HTTP status code to return'),
  response_body: z.string().describe('Response body to return (plain text or JSON string)'),
  content_type: z.string().default('application/json').describe('Content-Type header value'),
  delay_ms: z.number().min(0).max(10000).default(0).describe('Artificial response delay in milliseconds'),
})

export const FakeC2InputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  endpoints: z.array(EndpointConfigSchema).min(1).describe('List of endpoint configurations for the fake C2'),
  listen_port: z.number().min(1024).max(65535).default(8443).describe('Port for the fake C2 HTTPS listener'),
  use_tls: z.boolean().default(true).describe('Enable TLS with self-signed certificate'),
  capture_requests: z.boolean().default(true).describe('Log all incoming requests for analysis'),
  default_response: z.string().default('{"status":"ok"}').describe('Default response for unmatched endpoints'),
  timeout_seconds: z.number().min(10).max(600).default(120).describe('Maximum runtime for the fake C2 server'),
  auto_run_sample: z.boolean().default(false)
    .describe('Automatically launch the sample in sandbox with C2 pointing to the fake server'),
  dns_redirect: z.array(z.string()).optional()
    .describe('Domain names to redirect to the fake C2 (via hosts-file patching in sandbox)'),
})

export const fakeC2ToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Start a configurable fake C2 server with custom endpoint responses. ' +
    'Configure responses for /plugin, /ping, /gate, /task, etc. to drive ' +
    'the sample into deeper operational logic. Captures all incoming requests ' +
    'for analysis. Supports TLS, response delays, and DNS redirection in sandbox.',
  inputSchema: FakeC2InputSchema,
}

/* ── Worker bridge ─────────────────────────────────────────────────────── */

async function callFakeC2Worker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath'],
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath!('src', 'plugins', 'managed-fake-c2', 'workers', 'managed_fake_c2_worker.py')
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Fake C2 worker exited ${code}: ${stderr.slice(0, 500)}`))
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

export function createFakeC2Handler(deps: PluginToolDeps) {
  const {
    workspaceManager, database, config,
    resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, resolvePackagePath,
  } = deps
  const pythonCmd = getPythonCommand(undefined, config?.workers?.static?.pythonPath)

  return async (args: z.infer<typeof FakeC2InputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const { samplePath } = await resolvePrimarySamplePath!(workspaceManager, args.sample_id)

      // No caching — each C2 session is unique
      const result = await callFakeC2Worker({
        action: 'start_fake_c2',
        file_path: samplePath,
        endpoints: args.endpoints,
        listen_port: args.listen_port,
        use_tls: args.use_tls,
        capture_requests: args.capture_requests,
        default_response: args.default_response,
        timeout_seconds: args.timeout_seconds,
        auto_run_sample: args.auto_run_sample,
        dns_redirect: args.dns_redirect ?? [],
      }, pythonCmd, resolvePackagePath)

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact!(
          workspaceManager, database, args.sample_id,
          'fake_c2_session', 'managed-fake-c2', result,
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
