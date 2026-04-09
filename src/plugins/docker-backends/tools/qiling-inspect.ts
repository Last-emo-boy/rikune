/**
 * Qiling inspect tool — inspect Qiling readiness and rootfs state.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from './docker-shared.js'
import {
  BackendSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson, buildMetrics, buildDynamicSetupRequired,
  resolveAnalysisBackends,
  mergeSetupActions, mergeRequiredUserInputs,
  buildDynamicDependencySetupActions, buildDynamicDependencyRequiredUserInputs,
} from './docker-shared.js'

export const qilingInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  operation: z
    .enum(['preflight', 'rootfs_probe'])
    .default('preflight')
    .describe('Qiling readiness inspection mode.'),
  timeout_sec: z.number().int().min(1).max(60).default(20).describe('Backend probe timeout in seconds.'),
})

export const qilingInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      operation: z.string().optional(),
      rootfs_configured: z.boolean().optional(),
      rootfs_exists: z.boolean().optional(),
      rootfs_path: z.string().nullable().optional(),
      details: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const qilingInspectToolDefinition: ToolDefinition = {
  name: 'qiling.inspect',
  description:
    'Inspect Qiling readiness, configured rootfs state, and emulation prerequisites for a sample. Use this when you explicitly request Qiling-backed automation or need to verify rootfs prerequisites before emulation.',
  inputSchema: qilingInspectInputSchema,
  outputSchema: qilingInspectOutputSchema,
}

const QILING_INSPECT_SCRIPT = `
import json
import pathlib
import sys
import qiling

payload = json.loads(sys.stdin.read())
rootfs = payload.get("rootfs")
rootfs_exists = bool(rootfs and pathlib.Path(rootfs).exists())
windows_dir = None
kernel32_present = False
if rootfs_exists:
    windows_candidate = pathlib.Path(rootfs) / "Windows" / "System32"
    windows_dir = str(windows_candidate)
    kernel32_present = (windows_candidate / "kernel32.dll").exists()

print(json.dumps({
    "qiling_version": getattr(qiling, "__version__", None),
    "rootfs_configured": bool(rootfs),
    "rootfs_exists": rootfs_exists,
    "rootfs_path": rootfs,
    "system32_path": windows_dir,
    "kernel32_present": kernel32_present,
}, ensure_ascii=False))
`.trim()

export function createQilingInspectHandler(
  _workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = qilingInspectInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.qiling
      if (!backend.available || !backend.path) {
        return buildDynamicSetupRequired(backend, startTime, qilingInspectToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(
        backend.path,
        QILING_INSPECT_SCRIPT,
        {
          rootfs: process.env.QILING_ROOTFS || null,
        },
        input.timeout_sec * 1000
      )

      const rootfsConfigured = Boolean(result.parsed?.rootfs_configured)
      const rootfsExists = Boolean(result.parsed?.rootfs_exists)
      const warnings: string[] = []
      if (!rootfsConfigured) {
        warnings.push('QILING_ROOTFS is not configured.')
      } else if (!rootfsExists) {
        warnings.push('Configured QILING_ROOTFS does not exist.')
      }

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id,
          operation: input.operation,
          rootfs_configured: rootfsConfigured,
          rootfs_exists: rootfsExists,
          rootfs_path:
            typeof result.parsed?.rootfs_path === 'string' ? result.parsed.rootfs_path : null,
          details: result.parsed,
          summary: rootfsConfigured && rootfsExists
            ? 'Qiling runtime is available and a rootfs is configured.'
            : 'Qiling runtime is available, but the Windows rootfs still needs attention before useful emulation.',
          recommended_next_tools: ['dynamic.dependencies', 'sandbox.execute', 'tool.help'],
          next_actions: rootfsConfigured && rootfsExists
            ? ['Use sandbox.execute or future Qiling-backed workflows when you need controlled emulation.']
            : ['Set QILING_ROOTFS to a mounted Windows rootfs before attempting Qiling-backed emulation.'],
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        required_user_inputs: !rootfsConfigured || !rootfsExists
          ? mergeRequiredUserInputs(buildDynamicDependencyRequiredUserInputs())
          : undefined,
        setup_actions: !rootfsConfigured || !rootfsExists
          ? mergeSetupActions(buildDynamicDependencySetupActions())
          : undefined,
        metrics: buildMetrics(startTime, qilingInspectToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, qilingInspectToolDefinition.name),
      }
    }
  }
}
