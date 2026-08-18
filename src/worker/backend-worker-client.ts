import { randomUUID } from 'crypto'
import { spawn } from 'child_process'
import { existsSync, statSync } from 'fs'
import path from 'path'
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

interface ExternalWorkerResult {
  result: WorkerResult
  stderr: string
  elapsedMs: number
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

const SHELL_CONTROL_TOKENS = new Set(['&&', '||', ';', '|', '&', '<', '>'])
const SHELL_LAUNCHERS = new Set([
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
  'bash',
  'bash.exe',
  'sh',
])

function firstString(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) return value.trim()
  }
  return null
}

function maxOutputBytes(policy: BackendWorkerPolicy | undefined): number {
  return policy?.maxOutputBytes ?? 10 * 1024 * 1024
}

function timeoutMs(request: BackendWorkerRequest, options: BackendWorkerRunOptions): number {
  return options.timeoutMs ?? request.backend.policy?.defaultTimeoutMs ?? 30_000
}

function parseCommandLine(commandLine: string): { command: string; args: string[] } {
  const parts = commandLine.match(/"[^"]+"|'[^']+'|\S+/g) ?? []
  const cleaned = parts.map((part) => part.replace(/^["']|["']$/g, ''))
  return { command: cleaned[0] ?? commandLine, args: cleaned.slice(1) }
}

function commandBaseName(command: string): string {
  return command.split(/[\\/]/).pop()?.toLowerCase() ?? command.toLowerCase()
}

function validateCommandLine(commandLine: string): {
  command: string
  args: string[]
  reasons: string[]
} {
  const parsed = parseCommandLine(commandLine)
  const tokens = [parsed.command, ...parsed.args]
  const reasons: string[] = []

  if (!parsed.command.trim()) {
    reasons.push('backend_command_empty')
  }

  if (SHELL_LAUNCHERS.has(commandBaseName(parsed.command))) {
    reasons.push('backend_shell_launcher_rejected')
  }

  if (
    tokens.some(
      (token) =>
        SHELL_CONTROL_TOKENS.has(token) ||
        token.includes('`') ||
        token.includes('$(') ||
        token.includes('\n') ||
        token.includes('\r')
    )
  ) {
    reasons.push('backend_shell_metacharacter_rejected')
  }

  return { ...parsed, reasons }
}

function redactPathToken(token: string): string {
  if (!token) return token
  if (token.includes('/') || token.includes('\\') || /^[a-z]:/i.test(token)) {
    return `<path:${path.basename(token)}>`
  }
  return token
}

function redactCommandLine(commandLine: string | null): string | null {
  if (!commandLine) return null
  const parsed = parseCommandLine(commandLine)
  return [redactPathToken(parsed.command), ...parsed.args.map(redactPathToken)].join(' ')
}

function redactDiagnosticText(value: string): string {
  let redacted = value
    .replace(/[A-Za-z]:\\[^\s"'<>|]+/g, '<path>')
    .replace(/\/(?:[^/\s"'<>|]+\/){1,}[^\s"'<>|]+/g, '<path>')
    .replace(
      /\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASS|KEY|AUTH)[A-Z0-9_]*)=([^\s]+)/gi,
      '$1=<redacted>'
    )

  for (const envValue of Object.values(process.env)) {
    if (typeof envValue === 'string' && envValue.length >= 16 && redacted.includes(envValue)) {
      redacted = redacted.split(envValue).join('<redacted-env>')
    }
  }

  return redacted
}

function truncateDiagnostic(value: string, limit = 4096): string {
  return redactDiagnosticText(value).slice(0, limit)
}

function inputByteLength(input: Record<string, unknown>): number {
  try {
    return Buffer.byteLength(JSON.stringify(input), 'utf8')
  } catch {
    return Number.POSITIVE_INFINITY
  }
}

function backendPathExists(backendPath: string): boolean {
  const parsed = validateCommandLine(backendPath)
  if (parsed.reasons.length > 0) return false
  if (parsed.command.includes('/') || parsed.command.includes('\\')) {
    return existsSync(parsed.command)
  }
  return true
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
      backend_path: redactCommandLine(backendPath),
      does_not_start_backend: true,
      setup_actions: setupActions,
      reasons,
    }
  }

  if (mode !== 'builtin' && backend.backendKind === 'external') {
    if (backendPath) {
      const commandValidation = validateCommandLine(backendPath)
      if (commandValidation.reasons.length > 0) {
        reasons.push(...commandValidation.reasons)
        return {
          status: 'policy_denied',
          backend_name: backend.backendName,
          backend_kind: backend.backendKind,
          adapter: backend.adapter,
          mode,
          env_var: backend.envVar ?? null,
          backend_path: redactCommandLine(backendPath),
          does_not_start_backend: true,
          setup_actions: setupActions,
          reasons,
        }
      }
    }

    if (!backendPath || !backendPathExists(backendPath)) {
      reasons.push('backend_path_missing')
      return {
        status: 'backend_missing',
        backend_name: backend.backendName,
        backend_kind: backend.backendKind,
        adapter: backend.adapter,
        mode,
        env_var: backend.envVar ?? null,
        backend_path: redactCommandLine(backendPath),
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
    backend_path: redactCommandLine(backendPath),
    does_not_start_backend: true,
    setup_actions: setupActions,
    reasons,
  }
}

function isPathAllowed(pathValue: string, allowedRoots: string[] | undefined): boolean {
  if (!allowedRoots || allowedRoots.length === 0) return true
  const resolvedPath = path.resolve(pathValue)

  return allowedRoots.some((root) => {
    const resolvedRoot = path.resolve(root)
    const relative = path.relative(resolvedRoot, resolvedPath)
    return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))
  })
}

function localArtifact(
  pathValue: unknown,
  fallbackType: string,
  policy: BackendWorkerPolicy | undefined
): { artifact: ArtifactRef | null; error?: string } {
  if (typeof pathValue !== 'string' || pathValue.trim().length === 0) {
    return { artifact: null }
  }
  const artifactPath = pathValue.trim()
  if (!isPathAllowed(artifactPath, policy?.allowedRoots)) {
    return { artifact: null, error: 'artifact_path_outside_allowed_roots' }
  }
  let size = 0
  try {
    size = existsSync(artifactPath) ? statSync(artifactPath).size : 0
  } catch {
    size = 0
  }
  return {
    artifact: {
      id: `artifact:${fallbackType}:${randomUUID()}`,
      type: fallbackType,
      path: artifactPath,
      sha256: 'not-computed',
      metadata: {
        size,
        generated_by: 'backend-worker-client',
        passthrough: true,
        data_provenance: 'fixture',
      },
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

function runExternalWorker(
  backendPath: string,
  request: BackendWorkerRequest,
  options: BackendWorkerRunOptions
): Promise<ExternalWorkerResult> {
  return new Promise((resolve) => {
    const started = Date.now()
    const limit = maxOutputBytes(request.backend.policy)
    const timeout = timeoutMs(request, options)
    const commandLine = parseCommandLine(backendPath)
    const child = spawn(commandLine.command, commandLine.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })

    let stdout = ''
    let stderr = ''
    let settled = false
    let exceeded = false
    const finish = (result: WorkerResult) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ result, stderr, elapsedMs: Date.now() - started })
    }
    const timer = setTimeout(() => {
      finish({
        ok: false,
        errors: ['external_backend_timeout'],
        data: {
          timeout_ms: timeout,
          backend: request.backend.backendName,
          adapter: request.backend.adapter,
        },
      })
      child.kill()
    }, timeout)

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
      if (Buffer.byteLength(stdout, 'utf8') > limit) {
        exceeded = true
        finish({
          ok: false,
          errors: ['external_backend_output_limit_exceeded'],
          data: {
            max_output_bytes: limit,
            backend: request.backend.backendName,
            adapter: request.backend.adapter,
          },
        })
        child.kill()
      }
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })
    child.on('error', (err) => {
      finish({
        ok: false,
        errors: ['external_backend_spawn_failed', truncateDiagnostic(err.message)],
        data: {
          backend: request.backend.backendName,
          adapter: request.backend.adapter,
        },
      })
    })
    child.on('close', (code) => {
      if (settled || exceeded) return
      if (code !== 0) {
        finish({
          ok: false,
          errors: ['external_backend_failed'],
          data: {
            exit_code: code,
            stderr: truncateDiagnostic(stderr),
            backend: request.backend.backendName,
            adapter: request.backend.adapter,
          },
        })
        return
      }
      try {
        const lines = stdout.trim().split('\n').filter(Boolean)
        const parsed = JSON.parse(lines[lines.length - 1] ?? '{}') as WorkerResult
        finish(parsed)
      } catch (err) {
        finish({
          ok: false,
          errors: [
            'external_backend_malformed_output',
            truncateDiagnostic(err instanceof Error ? err.message : String(err)),
          ],
          data: {
            stdout: truncateDiagnostic(stdout),
            stderr: truncateDiagnostic(stderr),
            backend: request.backend.backendName,
            adapter: request.backend.adapter,
          },
        })
      }
    })

    child.stdin.write(JSON.stringify(request) + '\n')
    child.stdin.end()
  })
}

export async function runBackendWorker(
  request: BackendWorkerRequest,
  options: BackendWorkerRunOptions = {}
): Promise<WorkerResult> {
  const maxInputBytes = request.context.policy.maxInputBytes
  const actualInputBytes = inputByteLength(request.input)
  if (maxInputBytes && actualInputBytes > maxInputBytes) {
    return {
      ok: false,
      errors: ['backend_worker_input_limit_exceeded'],
      data: {
        max_input_bytes: maxInputBytes,
        input_bytes: Number.isFinite(actualInputBytes) ? actualInputBytes : null,
        backend: request.backend.backendName,
        adapter: request.backend.adapter,
      },
      metrics: {
        elapsed_ms: 0,
        tool: request.tool,
      },
    }
  }

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

  if (mode === 'external') {
    const backendPath = firstString(
      options.backendPath,
      request.backend.envVar ? process.env[request.backend.envVar] : null,
      request.backend.commandHint
    )
    if (!backendPath) {
      return {
        ok: false,
        errors: ['backend_path_missing'],
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
    const commandValidation = validateCommandLine(backendPath)
    if (commandValidation.reasons.length > 0) {
      return {
        ok: false,
        errors: commandValidation.reasons,
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
    const external = await runExternalWorker(backendPath, request, options)
    const resultData =
      external.result.data && typeof external.result.data === 'object'
        ? (external.result.data as Record<string, unknown>)
        : {}
    return {
      ...external.result,
      data: {
        ...resultData,
        readiness,
        execution_semantics: {
          requested_mode: mode,
          actual_mode: 'worker_external',
          backend: request.backend.backendName,
          adapter: request.backend.adapter,
          live_execution: !request.context.policy.noLiveExecution,
          no_network: request.context.policy.noNetwork,
          no_mutation: request.context.policy.noMutation,
          data_provenance: 'analysis',
        },
        stderr: external.stderr ? truncateDiagnostic(external.stderr) : undefined,
      },
      metrics: {
        ...(external.result.metrics ?? {}),
        elapsed_ms: external.elapsedMs,
        tool: request.tool,
        backend_worker: {
          contract: request.backend.version ?? 'backend-worker.v1',
          mode,
          adapter: request.backend.adapter,
        },
      },
    }
  }

  const outputType =
    request.backend.outputArtifactTypes?.[0] ?? `${request.tool.replace(/\W+/g, '_')}_artifact`
  const artifactResult = localArtifact(
    request.input.output_path,
    outputType,
    request.context.policy
  )
  if (artifactResult.error) {
    return {
      ok: false,
      errors: [artifactResult.error],
      data: {
        backend: request.backend.backendName,
        adapter: request.backend.adapter,
        policy: request.context.policy,
      },
      metrics: {
        elapsed_ms: 0,
        tool: request.tool,
      },
    }
  }
  const artifact = artifactResult.artifact
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
        data_provenance: 'fixture',
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
