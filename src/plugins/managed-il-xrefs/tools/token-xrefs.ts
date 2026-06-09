/**
 * managed.token_xrefs MCP tool — metadata token dependency graph.
 *
 * Given a metadata token, builds a bidirectional reference graph showing
 * what references the token and what the token references.
 * Useful for understanding field usage, call chains, and type hierarchies.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
  type ArtifactRef,
  type PluginToolDeps,
} from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'
import {
  MANAGED_IL_XREFS_ARTIFACT_TYPES,
  MANAGED_IL_XREFS_RUNTIME_POLICY,
  MANAGED_IL_XREFS_TOOL_VERSION,
  MANAGED_IL_XREFS_WORKER_TIMEOUT_MS,
  buildManagedIlXrefsEnvelope,
  managedIlXrefsAspects,
  managedIlXrefsRecipe,
  managedIlXrefsWorkerBackend,
} from '../managed-il-xrefs-metadata.js'

const TOOL_NAME = 'managed.token_xrefs'

export const TokenXrefsInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  token: z
    .string()
    .describe('Metadata token in hex (e.g. 0x06000042) or fully-qualified member name'),
  depth: z
    .number()
    .min(1)
    .max(5)
    .default(1)
    .describe('How many levels of transitive references to follow'),
  direction: z
    .enum(['both', 'incoming', 'outgoing'])
    .default('both')
    .describe('Reference direction to trace'),
  include_system_refs: z
    .boolean()
    .default(false)
    .describe('Include references to/from System.* types'),
  max_nodes: z.number().min(1).max(2000).default(500).describe('Maximum graph nodes to return'),
})

export const TokenXrefsOutputSchema = createWorkerResultOutputSchema(z.record(z.any()))

export const tokenXrefsToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a bidirectional cross-reference graph around a metadata token. ' +
    'Shows what references the token (incoming) and what the token references (outgoing). ' +
    'Supports transitive traversal up to 5 levels. Useful for call-chain analysis, ' +
    'field usage tracking, and type dependency mapping.',
  inputSchema: TokenXrefsInputSchema,
  outputSchema: TokenXrefsOutputSchema,
  aspects: managedIlXrefsAspects([
    'token-graph',
    'managed-xrefs',
    'bidirectional-reference-graph',
    'call-chain-analysis',
    'workflow-handoff',
    'quality-gates',
  ]),
  artifacts: [
    {
      type: MANAGED_IL_XREFS_ARTIFACT_TYPES.token,
      description: 'Managed metadata token dependency graph with incoming/outgoing references',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'managed-metadata', artifactTypes: [MANAGED_IL_XREFS_ARTIFACT_TYPES.token] },
    { category: 'il-references', artifactTypes: [MANAGED_IL_XREFS_ARTIFACT_TYPES.token] },
    { category: 'callgraph', artifactTypes: [MANAGED_IL_XREFS_ARTIFACT_TYPES.token] },
    { category: 'workflow', artifactTypes: [MANAGED_IL_XREFS_ARTIFACT_TYPES.token] },
    { category: 'provenance', artifactTypes: [MANAGED_IL_XREFS_ARTIFACT_TYPES.token] },
  ],
  workflowRecipes: [
    managedIlXrefsRecipe({
      id: 'managed-il-xrefs.token-graph-handoff',
      title: 'Managed metadata token graph handoff',
      startsWith: TOOL_NAME,
      artifactType: MANAGED_IL_XREFS_ARTIFACT_TYPES.token,
      focus: 'token-graph',
    }),
  ],
  runtimePolicy: MANAGED_IL_XREFS_RUNTIME_POLICY,
  workerBackend: managedIlXrefsWorkerBackend(MANAGED_IL_XREFS_ARTIFACT_TYPES.token),
}

async function callTokenXrefsWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath']
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath(
      'src',
      'plugins',
      'managed-il-xrefs',
      'workers',
      'managed_il_xrefs_worker.py'
    )
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    let settled = false
    const timeout = setTimeout(() => {
      if (settled) return
      settled = true
      proc.kill()
      reject(
        new Error(`Token xrefs worker timed out after ${MANAGED_IL_XREFS_WORKER_TIMEOUT_MS}ms`)
      )
    }, MANAGED_IL_XREFS_WORKER_TIMEOUT_MS)
    proc.stdout.on('data', (d: Buffer) => {
      stdout += d.toString()
    })
    proc.stderr.on('data', (d: Buffer) => {
      stderr += d.toString()
    })
    proc.on('close', (code) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Token xrefs worker exited ${code}: ${stderr.slice(0, 500)}`))
        return
      }
      try {
        resolve(JSON.parse(stdout.trim()))
      } catch (e) {
        reject(new Error(`Parse: ${(e as Error).message}`))
      }
    })
    proc.on('error', (e) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      reject(new Error(`Spawn: ${e.message}`))
    })
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

export function createTokenXrefsHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    config,
    cacheManager,
    generateCacheKey,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
    resolvePackagePath,
  } = deps
  const pythonCmd = getPythonCommand(undefined, config?.workers?.static?.pythonPath)

  return async (args: z.infer<typeof TokenXrefsInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: MANAGED_IL_XREFS_TOOL_VERSION,
        args: {
          token: args.token,
          depth: args.depth,
          direction: args.direction,
          include_system_refs: args.include_system_refs,
          max_nodes: args.max_nodes,
        },
      })
      const cached = await cacheManager!.getCachedResult(cacheKey)
      if (cached)
        return {
          ok: true,
          data: cached,
          metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME, cache: 'hit' },
        }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)

      const result = await callTokenXrefsWorker(
        {
          action: 'token_xrefs',
          file_path: samplePath,
          token: args.token,
          depth: args.depth,
          direction: args.direction,
          include_system_refs: args.include_system_refs,
          max_nodes: args.max_nodes,
        },
        pythonCmd,
        resolvePackagePath
      )
      const enrichedResult = {
        ...result,
        ...buildManagedIlXrefsEnvelope({
          toolName: TOOL_NAME,
          artifactType: MANAGED_IL_XREFS_ARTIFACT_TYPES.token,
          sampleId: args.sample_id,
          focus: 'token-graph',
          query: {
            token: args.token,
            depth: args.depth,
            direction: args.direction,
            include_system_refs: args.include_system_refs,
            max_nodes: args.max_nodes,
          },
          result,
        }),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          'token_xrefs',
          'managed-token-xrefs',
          enrichedResult
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        /* non-fatal */
      }

      if (result.ok)
        await cacheManager!.setCachedResult(
          cacheKey,
          enrichedResult,
          30 * 24 * 60 * 60 * 1000,
          sample.sha256
        )

      return {
        ok: Boolean(result.ok),
        data: enrichedResult,
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
