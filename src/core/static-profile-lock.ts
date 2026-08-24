import fs from 'fs'
import path from 'path'
import { createHash } from 'crypto'
import { spawnSync } from 'child_process'
import { z } from 'zod'
import type { AnalysisPipelineStage } from '../analysis/analysis-run-state.js'

const STATIC_PLUGIN_COUNT = 100
export const STATIC_IMAGE_MARKER_PATH = '/app/.rikune-static-profile'
export const STATIC_IMAGE_LOCK_PATH = '/app/static-profile.lock.json'
/**
 * Ordered analysis DAG for an already-ingested sample: fast_profile establishes
 * the bounded baseline, enrich_static adds read-only static evidence, and
 * function_map builds the final function index. These are domain stage IDs,
 * not generic release phases such as ingest/analyze/package.
 */
export const STATIC_WORKFLOW_STAGE_IDS = [
  'fast_profile',
  'enrich_static',
  'function_map',
] as const satisfies readonly AnalysisPipelineStage[]
export const STATIC_ANALYSIS_STAGE_JOB_TOOL = 'workflow.analyze.stage'
export const STATIC_PUBLIC_WORKFLOW_TOOL_IDS = ['workflow.search', 'workflow.run'] as const
export const STATIC_PUBLIC_TOOL_IDS = [
  ...STATIC_PUBLIC_WORKFLOW_TOOL_IDS,
  'sample.ingest',
  'sample.request_upload',
  'sample.delete',
  'artifact.read',
  'analysis.case.checkpoint',
  'analysis.context.pack',
  'task.status',
  'task.cancel',
  'plugin.list',
  'system.health',
  'system.setup.guide',
] as const
export const STATIC_STAGE_ONLY_TOOL_IDS = [
  'ghidra.analyze',
  'strings.extract',
  'strings.floss.decode',
  'binary.role.profile',
  'analysis.context.link',
  'crypto.identify',
  'attack.map',
] as const
export const STATIC_FORBIDDEN_CONTROL_TOOL_IDS = ['plugin.enable', 'plugin.disable'] as const

const BackendEnvironmentSchema = z.union([
  z
    .object({
      name: z.string().regex(/^[A-Z][A-Z0-9_]*$/),
      value: z.string().startsWith('/'),
      required: z.boolean(),
    })
    .strict(),
  z
    .object({
      name: z.string().regex(/^[A-Z][A-Z0-9_]*$/),
      must_be_unset: z.literal(true),
    })
    .strict(),
])

const RequiredBackendSchema = z
  .object({
    name: z.string().min(1),
    path: z.string().startsWith('/'),
    environment: z.array(BackendEnvironmentSchema).min(1).max(16),
    version_args: z.array(z.string()).max(8),
    allowed_exit_codes: z.array(z.number().int().min(0).max(255)).min(1).max(8),
    version_file: z.string().startsWith('/').optional(),
    version_pattern: z.string().min(1).max(512),
  })
  .strict()

export const StaticProfileLockSchema = z
  .object({
    schema_version: z.literal(1),
    profile: z.literal('static'),
    plugins: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)).length(STATIC_PLUGIN_COUNT),
    ordered_csv_sha256: z.string().regex(/^[a-f0-9]{64}$/),
    static_workflow_stages: z.tuple([
      z.literal('fast_profile'),
      z.literal('enrich_static'),
      z.literal('function_map'),
    ]),
    required_backends: z.array(RequiredBackendSchema).min(3).max(32),
    generated_by: z.literal('scripts/generate-docker.mjs'),
    generator_version: z.literal(1),
  })
  .strict()

export type StaticProfileLock = z.infer<typeof StaticProfileLockSchema>

function fail(message: string): never {
  throw new Error(`E_STATIC_PROFILE_CONTRACT: ${message}`)
}

function hasTrustedStaticImageMarker(markerPath: string): boolean {
  let stat: fs.Stats
  try {
    stat = fs.lstatSync(markerPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false
    fail(
      `cannot stat static image marker ${markerPath}: ${error instanceof Error ? error.message : String(error)}`
    )
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 64) {
    fail(`static image marker is not a bounded single-link regular file: ${markerPath}`)
  }
  if (fs.readFileSync(markerPath, 'utf8') !== 'static\n') {
    fail(`static image marker has invalid content: ${markerPath}`)
  }
  return true
}

/**
 * Image identity wins over mutable container environment. A baked static
 * marker therefore cannot be downgraded to another profile at `docker run`.
 */
export function isStaticDockerProfile(markerPath = STATIC_IMAGE_MARKER_PATH): boolean {
  const hasImageMarker = hasTrustedStaticImageMarker(markerPath)
  if (hasImageMarker && process.env.RIKUNE_DOCKER_PROFILE !== 'static') {
    fail('baked static image identity requires RIKUNE_DOCKER_PROFILE=static')
  }
  if (hasImageMarker && markerPath === STATIC_IMAGE_MARKER_PATH) {
    const configuredLockPath = process.env.RIKUNE_STATIC_PROFILE_LOCK_PATH
    if (configuredLockPath && path.resolve(configuredLockPath) !== STATIC_IMAGE_LOCK_PATH) {
      fail(`baked static image lock path must remain ${STATIC_IMAGE_LOCK_PATH}`)
    }
  }
  return hasImageMarker || process.env.RIKUNE_DOCKER_PROFILE === 'static'
}

export function defaultStaticProfileLockPath(markerPath = STATIC_IMAGE_MARKER_PATH): string {
  // The static OCI contract fixes WORKDIR=/app and copies the lock beside the
  // application. Keeping the default relative to cwd also makes the loader
  // usable from both native ESM and the Jest CJS transform without import.meta.
  if (hasTrustedStaticImageMarker(markerPath) && markerPath === STATIC_IMAGE_MARKER_PATH) {
    return STATIC_IMAGE_LOCK_PATH
  }
  return (
    process.env.RIKUNE_STATIC_PROFILE_LOCK_PATH ||
    path.resolve(process.cwd(), 'static-profile.lock.json')
  )
}

export function loadStaticProfileLock(
  lockPath = defaultStaticProfileLockPath()
): StaticProfileLock {
  let raw: unknown
  try {
    raw = JSON.parse(fs.readFileSync(lockPath, 'utf8'))
  } catch (error) {
    fail(`cannot read ${lockPath}: ${error instanceof Error ? error.message : String(error)}`)
  }
  const parsed = StaticProfileLockSchema.safeParse(raw)
  if (!parsed.success) fail(`invalid lock schema: ${parsed.error.message}`)
  const lock = parsed.data
  if (new Set(lock.plugins).size !== lock.plugins.length) fail('plugin list contains duplicates')
  const digest = createHash('sha256').update(lock.plugins.join(','), 'utf8').digest('hex')
  if (digest !== lock.ordered_csv_sha256) fail('ordered plugin CSV digest mismatch')
  const backendNames = lock.required_backends.map((backend) => backend.name)
  if (new Set(backendNames).size !== backendNames.length)
    fail('required backend names contain duplicates')
  for (const backend of lock.required_backends) {
    if (new Set(backend.allowed_exit_codes).size !== backend.allowed_exit_codes.length) {
      fail(`backend ${backend.name} has duplicate allowed_exit_codes`)
    }
    try {
      new RegExp(backend.version_pattern)
    } catch {
      fail(`backend ${backend.name} has an invalid version_pattern`)
    }
    const bindingNames = backend.environment.map((binding) => binding.name)
    if (new Set(bindingNames).size !== bindingNames.length) {
      fail(`backend ${backend.name} has duplicate environment bindings`)
    }
  }
  return lock
}

function assertTrustedBackendFile(candidate: string, maxBytes: number): fs.Stats {
  let stat: fs.Stats
  try {
    stat = fs.lstatSync(candidate)
  } catch (error) {
    fail(
      `cannot stat required backend file ${candidate}: ${error instanceof Error ? error.message : String(error)}`
    )
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maxBytes) {
    fail(`required backend file is not a bounded single-link regular file: ${candidate}`)
  }
  return stat
}

/** Validate exact executable identity, exit contract, and version evidence. */
export function validateStaticRequiredBackends(lock: StaticProfileLock): void {
  for (const backend of lock.required_backends) {
    const executable = assertTrustedBackendFile(backend.path, 64 * 1024 * 1024)
    if ((executable.mode & 0o111) === 0) {
      fail(`required backend is not executable: ${backend.name}`)
    }
    const result = spawnSync(backend.path, backend.version_args, {
      encoding: 'utf8',
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    })
    if (result.error || result.signal || result.status === null) {
      fail(`required backend ${backend.name} could not complete its version probe`)
    }
    if (!backend.allowed_exit_codes.includes(result.status)) {
      fail(`required backend ${backend.name} returned disallowed exit code ${result.status}`)
    }
    let versionFile = ''
    if (backend.version_file) {
      assertTrustedBackendFile(backend.version_file, 64 * 1024)
      versionFile = `\n${fs.readFileSync(backend.version_file, 'utf8')}`
    }
    const evidence = `${result.stdout || ''}\n${result.stderr || ''}${versionFile}`
    if (!new RegExp(backend.version_pattern).test(evidence)) {
      fail(`required backend ${backend.name} version evidence did not match the lock`)
    }
  }
}

function assertExactOrdered(
  label: string,
  actual: readonly string[],
  expected: readonly string[]
): void {
  if (new Set(actual).size !== actual.length) fail(`${label} contains duplicate IDs`)
  if (
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    fail(`${label} does not exactly match the versioned lock`)
  }
}

export function validateStaticStartupEnvironment(lock: StaticProfileLock): void {
  const configuredPlugins = (process.env.PLUGINS ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
  assertExactOrdered('PLUGINS', configuredPlugins, lock.plugins)
  const configuredStages = (process.env.STATIC_WORKFLOW_STAGES ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
  assertExactOrdered(
    'STATIC_WORKFLOW_STAGES',
    configuredStages,
    Array.from(lock.static_workflow_stages, (stage) => String(stage))
  )
  if ((process.env.RUNTIME_MODE ?? 'disabled') !== 'disabled') {
    fail('RUNTIME_MODE must be disabled')
  }
  for (const backend of lock.required_backends) {
    for (const binding of backend.environment) {
      const actual = process.env[binding.name]
      if (!('value' in binding)) {
        if (actual !== undefined) {
          fail(`backend ${backend.name} requires ${binding.name} to remain unset`)
        }
        continue
      }
      if (
        (binding.required && actual !== binding.value) ||
        (!binding.required && actual !== undefined && actual !== binding.value)
      ) {
        fail(
          `backend ${backend.name} requires ${binding.name}=${binding.value}; received ${actual ?? '(unset)'}`
        )
      }
    }
  }
  const defaultConfigPath = path.join(process.env.HOME || '', '.rikune', 'config.json')
  if (fs.existsSync(defaultConfigPath)) {
    fail(`static profile forbids mutable file configuration: ${defaultConfigPath}`)
  }
}

/**
 * Entrypoint-safe validation performed before any requested container command.
 * Plugin discovery repeats this contract and additionally validates exact
 * discovered/enabled/loaded sets plus backend executable identities.
 */
export function assertStaticImageStartupContract(
  options: {
    markerPath?: string
    lockPath?: string
    /** Unit fixtures may validate schema/environment without host OCI backends. */
    validateBackends?: boolean
  } = {}
): StaticProfileLock | null {
  const markerPath = options.markerPath ?? STATIC_IMAGE_MARKER_PATH
  if (!isStaticDockerProfile(markerPath)) return null
  const lock = loadStaticProfileLock(options.lockPath ?? defaultStaticProfileLockPath(markerPath))
  validateStaticStartupEnvironment(lock)
  if (options.validateBackends !== false) validateStaticRequiredBackends(lock)
  return lock
}

export function assertStaticPluginSets(params: {
  lock: StaticProfileLock
  discovered: readonly string[]
  enabled: readonly string[]
  loaded: readonly string[]
}): void {
  assertExactOrdered(
    'discovered plugins',
    [...params.discovered].sort(),
    [...params.lock.plugins].sort()
  )
  assertExactOrdered('enabled plugins', params.enabled, params.lock.plugins)
  assertExactOrdered('loaded plugins', [...params.loaded].sort(), [...params.lock.plugins].sort())
}

export function assertStaticWorkflowStage(stage: AnalysisPipelineStage): void {
  if (!STATIC_WORKFLOW_STAGE_IDS.includes(stage as (typeof STATIC_WORKFLOW_STAGE_IDS)[number])) {
    fail(`stage '${stage}' is not allowed by STATIC_WORKFLOW_STAGES`)
  }
}

/** Block direct surfaces that can escape the exact three-stage static DAG. */
export function assertStaticToolAllowed(toolName: string): void {
  const publicTools = STATIC_PUBLIC_TOOL_IDS as readonly string[]
  if (!publicTools.includes(toolName)) {
    fail(`tool '${toolName}' is not callable outside the exact static workflow DAG`)
  }
}

/** Validate persisted/queued work before it can enter the static runner. */
export function assertStaticQueuedJob(toolName: string, args: Record<string, unknown>): void {
  if (toolName !== STATIC_ANALYSIS_STAGE_JOB_TOOL) {
    fail(`queued tool '${toolName}' is not allowed by the exact static workflow DAG`)
  }
  if (typeof args.stage !== 'string') {
    fail('queued static analysis stage is missing a stage ID')
  }
  assertStaticWorkflowStage(args.stage as AnalysisPipelineStage)
}

interface StaticAnalysisRunLike {
  id: string
  sample_id: string
  goal: string
  stage_plan_json: string | null
  metadata_json: string | null
}

/**
 * Validate the persisted run behind an internal static-stage job. This is
 * intentionally DB-agnostic so enqueue, recovery, runner admission, and the
 * stage executor can all apply the same mutation-before gate.
 */
export function assertStaticAnalysisRunContract(params: {
  run: StaticAnalysisRunLike | undefined
  stage: AnalysisPipelineStage
  jobSampleId: string
  getStageStatus: (stage: AnalysisPipelineStage) => string | null | undefined
}): void {
  const { run, stage, jobSampleId, getStageStatus } = params
  assertStaticWorkflowStage(stage)
  if (!run) fail('queued static analysis run does not exist')
  if (run.sample_id !== jobSampleId) {
    fail(`queued sample '${jobSampleId}' does not match run sample '${run.sample_id}'`)
  }
  if (run.goal !== 'static') fail(`queued static analysis run has forbidden goal '${run.goal}'`)

  let stagePlan: unknown
  let metadata: unknown
  try {
    stagePlan = JSON.parse(run.stage_plan_json || 'null')
    metadata = JSON.parse(run.metadata_json || 'null')
  } catch {
    fail('queued static analysis run contains invalid JSON')
  }
  if (!Array.isArray(stagePlan)) fail('queued static analysis run is missing its exact stage plan')
  assertExactOrdered(
    'persisted static stage plan',
    stagePlan.map((value) => String(value)),
    STATIC_WORKFLOW_STAGE_IDS
  )
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    fail('queued static analysis run is missing its execution policy')
  }
  const policy = metadata as Record<string, unknown>
  if (policy.allow_transformations !== false || policy.allow_live_execution !== false) {
    fail('queued static analysis run must freeze transformation and live execution flags to false')
  }

  const stageIndex = STATIC_WORKFLOW_STAGE_IDS.indexOf(
    stage as (typeof STATIC_WORKFLOW_STAGE_IDS)[number]
  )
  if (stageIndex < 0) fail(`stage '${stage}' is absent from the exact static plan`)
  for (const predecessor of STATIC_WORKFLOW_STAGE_IDS.slice(0, stageIndex)) {
    const status = getStageStatus(predecessor)
    if (status !== 'completed') {
      fail(
        `stage '${stage}' requires predecessor '${predecessor}' to be completed; received ${status ?? 'missing'}`
      )
    }
  }
}
