import { randomUUID } from 'crypto'
import { existsSync, statSync } from 'fs'
import type {
  ArtifactRef,
  BackendWorkerContract,
  BackendWorkerPolicy,
  WorkerResult,
} from '../types.js'

export interface BackendWorkerRequest {
  job_id: string
  tool: string
  backend: BackendWorkerContract
  input: Record<string, unknown>
  context: {
    request_time_utc: string
    policy: Required<
      Pick<
        BackendWorkerPolicy,
        | 'passiveByDefault'
        | 'requiresUserOptIn'
        | 'requiresIsolation'
        | 'noNetwork'
        | 'noMutation'
        | 'noLiveExecution'
      >
    > &
      BackendWorkerPolicy
    versions: Record<string, string>
  }
}

export interface BackendWorkerRunOptions {
  mode?: string
  timeoutMs?: number
  backendPath?: string
  allowExternalBackend?: boolean
  requireOptIn?: boolean
  approved?: boolean
  fixtureData?: Record<string, unknown>
}

export interface BackendWorkerReadiness {
  status: 'ready' | 'backend_missing' | 'policy_denied' | 'runtime_not_started'
  backend_name: string
  backend_kind: BackendWorkerContract['backendKind']
  adapter: string
  mode: string
  env_var: string | null
  backend_path: string | null
  does_not_start_backend: true
  setup_actions: string[]
  reasons: string[]
}

function firstString(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) return value.trim()
  }
  return null
}

function defaultPolicy(
  policy: BackendWorkerPolicy | undefined
): BackendWorkerRequest['context']['policy'] {
  return {
    passiveByDefault: policy?.passiveByDefault ?? true,
    requiresUserOptIn: policy?.requiresUserOptIn ?? false,
    requiresIsolation: policy?.requiresIsolation ?? false,
    noNetwork: policy?.noNetwork ?? true,
    noMutation: policy?.noMutation ?? true,
    noLiveExecution: policy?.noLiveExecution ?? true,
    ...policy,
  }
}

export function buildBackendWorkerRequest(input: {
  tool: string
  backend: BackendWorkerContract
  args?: Record<string, unknown>
  backendVersion?: string | null
}): BackendWorkerRequest {
  return {
    job_id: randomUUID(),
    tool: input.tool,
    backend: input.backend,
    input: input.args ?? {},
    context: {
      request_time_utc: new Date().toISOString(),
      policy: defaultPolicy(input.backend.policy),
      versions: {
        contract: input.backend.version ?? 'backend-worker.v1',
        backend_version: input.backendVersion ?? input.backend.versionHint ?? 'unknown',
      },
    },
  }
}

export function checkBackendWorkerReadiness(
  backend: BackendWorkerContract,
  options: BackendWorkerRunOptions = {}
): BackendWorkerReadiness {
  const mode = options.mode ?? backend.defaultMode ?? 'builtin'
  const envPath = backend.envVar ? firstString(process.env[backend.envVar]) : null
  const backendPath = firstString(options.backendPath, envPath, backend.commandHint)
  const setupActions = backend.readiness?.setupActions ?? []
  const reasons: string[] = []

  if (backend.policy?.requiresUserOptIn && !options.approved) {
    reasons.push('explicit_opt_in_required')
  }

  if (backend.backendKind === 'delegated-runtime') {
    reasons.push('delegated_runtime_required')
    return {
      status: options.approved ? 'runtime_not_started' : 'policy_denied',
      backend_name: backend.backendName,
      backend_kind: backend.backendKind,
      adapter: backend.adapter,
      mode,
      env_var: backend.envVar ?? null,
      backend_path: backendPath,
      does_not_start_backend: true,
      setup_actions: setupActions,
      reasons,
    }
  }

  if (mode !== 'builtin' && backend.backendKind === 'external') {
    if (!backendPath || !existsSync(backendPath)) {
      reasons.push('backend_path_missing')
      return {
        status: 'backend_missing',
        backend_name: backend.backendName,
        backend_kind: backend.backendKind,
        adapter: backend.adapter,
        mode,
        env_var: backend.envVar ?? null,
        backend_path: backendPath,
        does_not_start_backend: true,
        setup_actions: setupActions,
        reasons,
      }
    }
  }

  return {
    status: reasons.includes('explicit_opt_in_required') ? 'policy_denied' : 'ready',
    backend_name: backend.backendName,
    backend_kind: backend.backendKind,
    adapter: backend.adapter,
    mode,
    env_var: backend.envVar ?? null,
    backend_path: backendPath,
    does_not_start_backend: true,
    setup_actions: setupActions,
    reasons,
  }
}

function localArtifact(pathValue: unknown, fallbackType: string): ArtifactRef | null {
  if (typeof pathValue !== 'string' || pathValue.trim().length === 0) return null
  const path = pathValue.trim()
  let size = 0
  try {
    size = existsSync(path) ? statSync(path).size : 0
  } catch {
    size = 0
  }
  return {
    id: `artifact:${fallbackType}:${randomUUID()}`,
    type: fallbackType,
    path,
    sha256: 'not-computed',
    metadata: {
      size,
      generated_by: 'backend-worker-client',
    },
  }
}

function buildBuiltinData(
  request: BackendWorkerRequest,
  options: BackendWorkerRunOptions
): Record<string, unknown> {
  const inputPath = firstString(
    request.input.path,
    request.input.source_path,
    request.input.sample_path
  )
  return {
    backend: request.backend.backendName,
    adapter: request.backend.adapter,
    mode: options.mode ?? request.backend.defaultMode ?? 'builtin',
    input_path: inputPath,
    preview: request.input.preview ?? true,
    policy: request.context.policy,
    ...options.fixtureData,
  }
}

export async function runBackendWorker(
  request: BackendWorkerRequest,
  options: BackendWorkerRunOptions = {}
): Promise<WorkerResult> {
  const readiness = checkBackendWorkerReadiness(request.backend, options)
  if (readiness.status !== 'ready') {
    return {
      ok: false,
      errors: readiness.reasons,
      data: {
        readiness,
        policy: request.context.policy,
      },
      metrics: {
        elapsed_ms: 0,
        tool: request.tool,
      },
    }
  }

  const mode = options.mode ?? request.backend.defaultMode ?? 'builtin'
  if (mode !== 'builtin' && !options.allowExternalBackend) {
    return {
      ok: false,
      errors: ['external_backend_execution_not_enabled'],
      data: {
        readiness,
        policy: request.context.policy,
      },
      metrics: {
        elapsed_ms: 0,
        tool: request.tool,
      },
    }
  }

  const outputType =
    request.backend.outputArtifactTypes?.[0] ?? `${request.tool.replace(/\W+/g, '_')}_artifact`
  const artifact = localArtifact(request.input.output_path, outputType)
  const data = buildBuiltinData(request, options)

  return {
    ok: true,
    data: {
      ...data,
      readiness,
      execution_semantics: {
        requested_mode: mode,
        actual_mode: 'worker_builtin',
        backend: request.backend.backendName,
        adapter: request.backend.adapter,
        live_execution: false,
        no_network: request.context.policy.noNetwork,
        no_mutation: request.context.policy.noMutation,
      },
    },
    artifacts: artifact ? [artifact] : [],
    evidence: [
      {
        id: `${request.tool}:${request.job_id}`,
        category: 'provenance',
        source: request.backend.backendName,
        toolName: request.tool,
        artifactRefs: artifact ? [artifact] : [],
        confidence: 0.85,
        metadata: {
          worker_contract: request.backend.version ?? 'backend-worker.v1',
          backend_kind: request.backend.backendKind,
          adapter: request.backend.adapter,
        },
      },
    ],
    metrics: {
      elapsed_ms: 0,
      tool: request.tool,
      backend_worker: {
        contract: request.backend.version ?? 'backend-worker.v1',
        mode,
        adapter: request.backend.adapter,
      },
    },
  }
}
