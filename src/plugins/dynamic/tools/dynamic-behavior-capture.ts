/**
 * dynamic.behavior.capture tool.
 *
 * The analyzer-side definition delegates live behavior capture to Runtime Node.
 * The local handler is intentionally non-executing so an analyzer-only process
 * never starts malware locally.
 */

import { z } from 'zod'
import type { PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'dynamic.behavior.capture'

export const DynamicBehaviorCaptureInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  timeout_sec: z.number().int().min(5).max(300).optional().default(30),
  arguments: z.array(z.string()).optional().default([]).describe('Optional command-line arguments passed to the sample.'),
  sidecar_paths: z
    .array(z.string())
    .optional()
    .default([])
    .describe('Optional local sidecar files, such as DLLs or config files, to stage next to the sample inside the Runtime Node.'),
  auto_stage_sidecars: z
    .boolean()
    .optional()
    .default(true)
    .describe('Best-effort scan of the sample directory for common sidecar files (.dll, .config, .json, .dat, etc.) before upload.'),
  max_sidecars: z.number().int().min(0).max(256).optional().default(32),
  sidecar_max_total_bytes: z.number().int().min(0).max(1024 * 1024 * 1024).optional().default(128 * 1024 * 1024),
  network_sinkhole: z
    .boolean()
    .optional()
    .default(true)
    .describe('Best-effort runtime network sinkhole via proxy environment variables.'),
  capture_process_tree: z.boolean().optional().default(true),
  capture_modules: z.boolean().optional().default(true),
  capture_file_snapshot: z.boolean().optional().default(true),
  max_events: z.number().int().min(10).max(5000).optional().default(500),
})

const DynamicBehaviorCaptureOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const dynamicBehaviorCaptureToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Execute a sample inside the configured Runtime Node and collect coarse behavior evidence: process observations, module loads, file snapshot deltas, stdout/stderr, and normalized runtime artifacts. Requires Sandbox, Hyper-V VM, or another Runtime Node backend.',
  inputSchema: DynamicBehaviorCaptureInputSchema,
  outputSchema: DynamicBehaviorCaptureOutputSchema,
  runtimeBackendHint: { type: 'inline', handler: 'executeBehaviorCapture' },
}

export function createDynamicBehaviorCaptureHandler(_deps: PluginToolDeps) {
  return async (_args: z.infer<typeof DynamicBehaviorCaptureInputSchema>): Promise<WorkerResult> => ({
    ok: false,
    data: {
      status: 'setup_required',
      failure_category: 'runtime_required',
      summary: 'dynamic.behavior.capture must run inside a Runtime Node. Configure Docker + Windows Host Agent + Sandbox/Hyper-V, or attach a manual Runtime Node endpoint.',
      recommended_next_tools: ['dynamic.runtime.status', 'runtime.debug.session.start', 'sandbox.execute'],
      next_actions: [
        'Call dynamic.runtime.status to verify Runtime Node capabilities.',
        'Use runtime.debug.session.start to launch or attach to Sandbox/Hyper-V before behavior capture.',
      ],
      required_runtime_backend_hint: { type: 'inline', handler: 'executeBehaviorCapture' },
    },
    errors: ['Runtime Node is required for dynamic.behavior.capture.'],
    metrics: { elapsed_ms: 0, tool: TOOL_NAME },
  })
}
