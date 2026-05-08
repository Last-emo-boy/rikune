import { z } from 'zod'

export const RuntimeTaskStatusSchema = z.enum([
  'queued',
  'running',
  'completed',
  'failed',
  'cancelled',
])
export type RuntimeTaskStatus = z.infer<typeof RuntimeTaskStatusSchema>

export const RuntimeTaskLifecycleEventTypeSchema = z.enum([
  'submitted',
  'started',
  'progress',
  'log',
  'completed',
  'failed',
  'cancelled',
])
export type RuntimeTaskLifecycleEventType = z.infer<typeof RuntimeTaskLifecycleEventTypeSchema>

export const RuntimeTaskArtifactRefSchema = z.object({
  name: z.string(),
  path: z.string(),
})
export type RuntimeTaskArtifactRef = z.infer<typeof RuntimeTaskArtifactRefSchema>

export interface RuntimeTaskResult {
  ok: boolean
  taskId: string
  result?: unknown
  logs: string[]
  errors?: string[]
  artifactRefs?: RuntimeTaskArtifactRef[]
}

export const RuntimeTaskResultSchema = z.object({
  ok: z.boolean(),
  taskId: z.string(),
  result: z.unknown().optional(),
  logs: z.array(z.string()),
  errors: z.array(z.string()).optional(),
  artifactRefs: z.array(RuntimeTaskArtifactRefSchema).optional(),
})

export interface RuntimeTaskSnapshot {
  taskId: string
  status: RuntimeTaskStatus
  submittedAt: number
  startedAt?: number
  completedAt?: number
  progressPercent?: number
  lastMessage?: string
  result?: RuntimeTaskResult
}

export const RuntimeTaskSnapshotSchema = z.object({
  taskId: z.string(),
  status: RuntimeTaskStatusSchema,
  submittedAt: z.number(),
  startedAt: z.number().optional(),
  completedAt: z.number().optional(),
  progressPercent: z.number().finite().optional(),
  lastMessage: z.string().optional(),
  result: RuntimeTaskResultSchema.optional(),
})

export interface RuntimeTaskEvent extends RuntimeTaskSnapshot {
  id: number
  type: RuntimeTaskLifecycleEventType
  timestamp: number
  log?: string
}

export const RuntimeTaskEventSchema = RuntimeTaskSnapshotSchema.extend({
  id: z.number().int().nonnegative(),
  type: RuntimeTaskLifecycleEventTypeSchema,
  timestamp: z.number(),
  log: z.string().optional(),
})

export interface RuntimeConnectedEventData {
  ok: boolean
  subscribedAt: number
  taskId: string | null
}

export const RuntimeConnectedEventDataSchema = z.object({
  ok: z.boolean(),
  subscribedAt: z.number(),
  taskId: z.string().nullable(),
})

export interface RuntimeSnapshotEventData {
  tasks: RuntimeTaskSnapshot[]
}

export const RuntimeSnapshotEventDataSchema = z.object({
  tasks: z.array(RuntimeTaskSnapshotSchema),
})

export interface RuntimeSseEvent<T = unknown> {
  event: string
  id?: string
  data: T
}

export const RuntimeSseEventSchema = z.object({
  event: z.string(),
  id: z.string().optional(),
  data: z.unknown(),
})

export type RuntimeConnectedSseEvent = RuntimeSseEvent<RuntimeConnectedEventData> & {
  event: 'connected'
}
export type RuntimeSnapshotSseEvent = RuntimeSseEvent<RuntimeSnapshotEventData> & {
  event: 'snapshot'
}
export type RuntimeTaskLifecycleSseEvent = RuntimeSseEvent<RuntimeTaskEvent> & {
  event: RuntimeTaskLifecycleEventType
}
export type RuntimeControlPlaneEvent =
  | RuntimeConnectedSseEvent
  | RuntimeSnapshotSseEvent
  | RuntimeTaskLifecycleSseEvent

export const PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE = 'dynamic_trace_json' as const
export const SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE = 'sandbox_trace_json' as const
export const RuntimeDynamicArtifactTypeSchema = z.enum([
  PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  'runtime_debug_artifact',
  'runtime_analysis',
])
export type RuntimeDynamicArtifactType = z.infer<typeof RuntimeDynamicArtifactTypeSchema>

export const RuntimeDynamicArtifactFamilySchema = z.enum([
  'dynamic_trace',
  'sandbox_trace',
  'runtime_debug',
  'runtime_analysis',
])
export type RuntimeDynamicArtifactFamily = z.infer<typeof RuntimeDynamicArtifactFamilySchema>
export const RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPES = [
  PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
] as const
export type RuntimeDynamicTraceArtifactType = (typeof RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPES)[number]

export function listRuntimeDynamicTraceArtifactTypes(): RuntimeDynamicTraceArtifactType[] {
  return [...RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPES]
}

export const RuntimeArtifactControlPlaneMetadataSchema = z
  .object({
    runtime_schema: z.literal('rikune.runtime_artifact.v1'),
    artifact_family: RuntimeDynamicArtifactFamilySchema,
    source_runtime_tool: z.string().optional(),
    effective_runtime_tool: z.string().optional(),
    runtime_tool: z.string().optional(),
    runtime_task_id: z.string().optional(),
    runtime_debug_session_id: z.string().optional(),
  })
  .passthrough()
export type RuntimeArtifactControlPlaneMetadata = z.infer<
  typeof RuntimeArtifactControlPlaneMetadataSchema
>

export function isRuntimeTaskStatus(value: unknown): value is RuntimeTaskStatus {
  return RuntimeTaskStatusSchema.safeParse(value).success
}

export function extractRuntimeTaskStatusFromEvent(
  event: RuntimeSseEvent | null | undefined
): RuntimeTaskStatus | undefined {
  const status = (event?.data as { status?: unknown } | undefined)?.status
  return isRuntimeTaskStatus(status) ? status : undefined
}

export function inferRuntimeArtifactFamily(
  artifactType: string
): RuntimeDynamicArtifactFamily | undefined {
  switch (artifactType) {
    case PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE:
      return 'dynamic_trace'
    case SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE:
      return 'sandbox_trace'
    case 'runtime_debug_artifact':
      return 'runtime_debug'
    case 'runtime_analysis':
      return 'runtime_analysis'
    default:
      return undefined
  }
}

export function inferRuntimeArtifactType(
  toolName: string,
  filename: string
): RuntimeDynamicArtifactType {
  const lowerName = filename.toLowerCase()
  if (
    (toolName === 'dynamic.behavior.capture' || toolName === 'frida.runtime.instrument') &&
    lowerName.endsWith('.json')
  ) {
    return PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE
  }
  if (toolName === 'sandbox.execute' && lowerName.endsWith('.json')) {
    if (lowerName.includes('behavior_capture')) {
      return PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE
    }
    return SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE
  }
  if (
    toolName.startsWith('debug.session.') ||
    toolName === 'debug.procdump.capture' ||
    toolName === 'debug.telemetry.capture' ||
    toolName === 'dynamic.memory_dump' ||
    toolName === 'managed.safe_run'
  ) {
    return 'runtime_debug_artifact'
  }
  return 'runtime_analysis'
}

export function buildRuntimeArtifactControlPlaneMetadata(input: {
  artifactType: string
  sourceRuntimeTool?: string
  effectiveRuntimeTool?: string
  runtimeTool?: string
  runtimeTaskId?: string
  runtimeDebugSessionId?: string
  extra?: Record<string, unknown>
}): RuntimeArtifactControlPlaneMetadata {
  return {
    runtime_schema: 'rikune.runtime_artifact.v1',
    artifact_family: inferRuntimeArtifactFamily(input.artifactType) ?? 'runtime_analysis',
    ...(input.sourceRuntimeTool ? { source_runtime_tool: input.sourceRuntimeTool } : {}),
    ...(input.effectiveRuntimeTool ? { effective_runtime_tool: input.effectiveRuntimeTool } : {}),
    ...(input.runtimeTool ? { runtime_tool: input.runtimeTool } : {}),
    ...(input.runtimeTaskId ? { runtime_task_id: input.runtimeTaskId } : {}),
    ...(input.runtimeDebugSessionId
      ? { runtime_debug_session_id: input.runtimeDebugSessionId }
      : {}),
    ...(input.extra || {}),
  }
}
