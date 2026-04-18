/**
 * Runtime execution engine.
 *
 * Dispatches dynamic tool requests to the actual backend processes.
 * Runs inside the isolated Runtime node (e.g., Windows Sandbox).
 */

import { spawn } from 'child_process'
import fs from 'fs'
import path from 'path'
import { logger } from './logger.js'
import { config } from './config.js'
import { registerProcess } from './process-registry.js'
import { getPythonCommand } from '@rikune/shared'

const originalSpawn = spawn
let spawnProcess: typeof spawn = originalSpawn

export function setSpawnImplementationForTests(mockSpawn?: typeof spawn): void {
  spawnProcess = mockSpawn ?? originalSpawn
}

const moduleDirname = typeof __dirname === 'string' ? __dirname : process.cwd()

export type RuntimeBackendType = 'python-worker' | 'spawn' | 'inline'

export interface RuntimeBackendHint {
  type: RuntimeBackendType
  handler: string
}

export interface ExecuteTask {
  taskId: string
  sampleId: string
  tool: string
  args: Record<string, unknown>
  timeoutMs: number
  runtimeBackendHint?: RuntimeBackendHint
}

function resolveBackendHint(task: ExecuteTask): RuntimeBackendHint | undefined {
  if (task.runtimeBackendHint) {
    return task.runtimeBackendHint
  }
  // Fallback prefix heuristics for backward compatibility
  if (task.tool.startsWith('frida.')) {
    return { type: 'python-worker', handler: 'frida_worker.py' }
  }
  return undefined
}

export interface ExecuteResult {
  ok: boolean
  taskId: string
  result?: {
    ok: boolean
    data?: unknown
    errors?: string[]
    warnings?: string[]
    artifacts?: unknown[]
    metrics?: Record<string, unknown>
  }
  logs: string[]
  errors?: string[]
  artifactRefs?: { name: string; path: string }[]
}

const pythonCommand = getPythonCommand(process.platform, config.runtime.pythonPath)
const TASK_UPLOAD_MANIFEST = 'upload-manifest.json'

interface TaskUploadManifest {
  schema?: string
  taskId?: string
  primary?: string | null
  files?: Array<{
    name?: string
    role?: string
    size?: number
    uploadedAt?: string
  }>
}

interface ResolvedTaskSample {
  samplePath: string
  workingDir: string
  sidecars: Array<{ name: string; path: string; size?: number }>
  manifestPath?: string
}

function sanitizeManifestFilename(value: string, fallback: string): string {
  const basename = path
    .basename(String(value || fallback).replace(/\\/g, '/'))
    .replace(/[<>:"|?*\x00-\x1f]/g, '_')
    .replace(/^\.+$/, '')
    .slice(0, 160)
  return basename || fallback
}

function resolveTaskSample(taskId: string): ResolvedTaskSample {
  const taskInboxDir = path.join(config.runtime.inbox, taskId)
  const manifestPath = path.join(taskInboxDir, TASK_UPLOAD_MANIFEST)

  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as TaskUploadManifest
    const primaryName = typeof manifest.primary === 'string'
      ? sanitizeManifestFilename(manifest.primary, `${taskId}.sample`)
      : `${taskId}.sample`
    const primaryPath = path.join(taskInboxDir, primaryName)
    if (fs.existsSync(primaryPath)) {
      const sidecars = Array.isArray(manifest.files)
        ? manifest.files
            .filter((entry) => entry?.role === 'sidecar' && typeof entry.name === 'string')
            .map((entry) => {
              const name = sanitizeManifestFilename(entry.name!, 'sidecar.bin')
              return {
                name,
                path: path.join(taskInboxDir, name),
                size: typeof entry.size === 'number' ? entry.size : undefined,
              }
            })
            .filter((entry) => fs.existsSync(entry.path))
        : []
      return {
        samplePath: primaryPath,
        workingDir: taskInboxDir,
        sidecars,
        manifestPath,
      }
    }
  } catch {
    // Fall through to the legacy single-file runtime inbox contract.
  }

  const legacyPath = path.join(config.runtime.inbox, `${taskId}.sample`)
  return {
    samplePath: legacyPath,
    workingDir: path.dirname(legacyPath),
    sidecars: [],
  }
}

function resolveTaskSamplePath(taskId: string): string {
  return resolveTaskSample(taskId).samplePath
}

export async function executeTask(
  task: ExecuteTask,
  onLog?: (msg: string) => void,
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const logs: string[] = []
  const log = (msg: string) => {
    logs.push(msg)
    logger.debug({ taskId: task.taskId, tool: task.tool }, msg)
    onLog?.(msg)
  }

  log(`Received execution request for tool: ${task.tool}`)

  const spec = resolveBackendHint(task)
  if (!spec) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Unknown tool: ${task.tool}. No runtimeBackendHint provided and no fallback heuristic matched.`],
      logs,
    }
  }

  switch (spec.type) {
    case 'python-worker':
      return executePythonWorker(task, spec.handler, log, logs, onProgress)
    case 'inline': {
      const handler = inlineHandlers[spec.handler]
      if (!handler) {
        return {
          ok: false,
          taskId: task.taskId,
          errors: [`Inline handler '${spec.handler}' is not implemented.`],
          logs,
        }
      }
      return handler(task, log, logs, onProgress)
    }
    case 'spawn':
      return executeSpawnBackend(task, spec.handler, log, logs, onProgress)
    default:
      return {
        ok: false,
        taskId: task.taskId,
        errors: [`Unrecognized execution type: ${String(spec.type)}`],
        logs,
      }
  }
}

function buildAntiDebugScript(): string {
  return `
    const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
    if (IsDebuggerPresent) {
      Interceptor.attach(IsDebuggerPresent, { onLeave: function(retval) { retval.replace(0); } });
    }
    const CheckRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
    if (CheckRemoteDebuggerPresent) {
      Interceptor.attach(CheckRemoteDebuggerPresent, {
        onEnter: function(args) { this.pbDebuggerPresent = args[1]; },
        onLeave: function(retval) {
          retval.replace(0);
          if (this.pbDebuggerPresent) Memory.writeU32(this.pbDebuggerPresent, 0);
        }
      });
    }
    const NtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
    if (NtQueryInformationProcess) {
      Interceptor.attach(NtQueryInformationProcess, {
        onEnter: function(args) {
          this.processInformationClass = args[1].toInt32();
          this.processInformation = args[2];
        },
        onLeave: function(retval) {
          var patched = false;
          if (this.processInformationClass === 7 && this.processInformation) { Memory.writeU32(this.processInformation, 0); patched = true; }
          if (this.processInformationClass === 0x1F && this.processInformation) { Memory.writeU32(this.processInformation, 1); patched = true; }
          if (this.processInformationClass === 0 && this.processInformation) { Memory.writeU8(this.processInformation.add(0x02), 0); patched = true; }
          if (patched) retval.replace(0);
        }
      });
    }
    const NtSetInformationThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
    if (NtSetInformationThread) {
      Interceptor.attach(NtSetInformationThread, { onLeave: function(retval) { retval.replace(0); } });
    }
    const NtClose = Module.findExportByName('ntdll.dll', 'NtClose');
    if (NtClose) {
      Interceptor.attach(NtClose, { onLeave: function(retval) { if (retval.toInt32() === -1073741816) retval.replace(0); } });
    }
  `.trim()
}

function buildTimeBypassScript(speedFactor: number): string {
  return `
    var speedFactor = ${speedFactor};
    var startReal = Date.now();
    var startFake = Date.now();
    function getFakeTick() {
      var elapsedReal = Date.now() - startReal;
      return startFake + (elapsedReal * speedFactor);
    }
    const GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
    if (GetTickCount) {
      Interceptor.attach(GetTickCount, { onLeave: function(retval) { retval.replace(getFakeTick() % 0xFFFFFFFF); } });
    }
    const GetTickCount64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
    if (GetTickCount64) {
      Interceptor.attach(GetTickCount64, { onLeave: function(retval) { retval.replace(ptr(getFakeTick().toString())); } });
    }
    const timeGetTime = Module.findExportByName('winmm.dll', 'timeGetTime');
    if (timeGetTime) {
      Interceptor.attach(timeGetTime, { onLeave: function(retval) { retval.replace(getFakeTick() % 0xFFFFFFFF); } });
    }
    const QueryPerformanceCounter = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
    if (QueryPerformanceCounter) {
      Interceptor.attach(QueryPerformanceCounter, {
        onEnter: function(args) { this.lpPerformanceCount = args[0]; },
        onLeave: function(retval) {
          if (this.lpPerformanceCount) Memory.writeU64(this.lpPerformanceCount, getFakeTick() * 10000);
          retval.replace(0);
        }
      });
    }
    const Sleep = Module.findExportByName('kernel32.dll', 'Sleep');
    if (Sleep) {
      Interceptor.attach(Sleep, {
        onEnter: function(args) {
          var originalMs = args[0].toUInt32();
          var reducedMs = Math.max(1, Math.floor(originalMs / speedFactor));
          args[0] = ptr(reducedMs);
        }
      });
    }
    const NtDelayExecution = Module.findExportByName('ntdll.dll', 'NtDelayExecution');
    if (NtDelayExecution) {
      Interceptor.attach(NtDelayExecution, {
        onEnter: function(args) {
          var pLi = args[1];
          if (pLi) {
            var interval = Memory.readS64(pLi);
            var reduced = Math.max(-1, Math.floor(interval / speedFactor));
            Memory.writeS64(pLi, reduced);
          }
        }
      });
    }
  `.trim()
}

function buildEvasionScoreScript(): string {
  return `
    var evasionCounters = {};
    function countApi(module, name) {
      var addr = Module.findExportByName(module, name);
      if (addr) {
        Interceptor.attach(addr, {
          onEnter: function() {
            evasionCounters[name] = (evasionCounters[name] || 0) + 1;
            send({ type: 'evasion_api_call', api: name });
          }
        });
      }
    }
    ['IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess','NtSetInformationThread','NtClose','OutputDebugStringA','OutputDebugStringW']
    .forEach(function(name) { countApi('kernel32.dll', name) || countApi('ntdll.dll', name); });
    ['IsProcessorFeaturePresent','GetSystemFirmwareTable','CheckTokenMembership','EnumWindows','GetCursorPos','GetTickCount','GetTickCount64','QueryPerformanceCounter','GetAdaptersInfo','WNetGetProviderNameA']
    .forEach(function(name) { countApi('kernel32.dll', name) || countApi('user32.dll', name) || countApi('advapi32.dll', name) || countApi('iphlpapi.dll', name) || countApi('mpr.dll', name); });
  `.trim()
}

const inlineHandlers: Record<string, (task: ExecuteTask, log: (msg: string) => void, logs: string[], onProgress?: (progress: number, message?: string) => void) => Promise<ExecuteResult>> = {
  executeSandboxExecute,
  executeSpeakeasyEmulate,
  executeSpeakeasyShellcode,
  executeSpeakeasyApiTrace,
  executeWineRun,
  executeWineEnv,
  executeWineDllOverrides,
  executeWineReg,
  executeDynamicMemoryDump,
  executeProcDumpCapture,
  executeTelemetryCapture,
  executeBehaviorCapture,
  executeQilingInspect,
  executePandaInspect,
  executeManagedSafeRun,
  executeDebugSession,
  executeRuntimeToolProbe,
}

const pythonWorkerHandlers: Record<string, { description: string }> = {
  'frida_worker.py': {
    description: 'Execute Frida-backed runtime instrumentation through the Python worker bridge.',
  },
}

const inlineHandlerMetadata: Record<string, { description: string; requiresSample?: boolean }> = {
  executeSandboxExecute: { description: 'Run the sandbox.execute dynamic workflow inline inside the runtime node.' },
  executeSpeakeasyEmulate: { description: 'Run Speakeasy user-mode emulation inline inside the runtime node.' },
  executeSpeakeasyShellcode: { description: 'Run Speakeasy shellcode emulation inline inside the runtime node.' },
  executeSpeakeasyApiTrace: { description: 'Collect API traces from Speakeasy inline execution.' },
  executeWineRun: { description: 'Run or preflight Wine execution inline inside the runtime node.' },
  executeWineEnv: { description: 'Inspect or prepare Wine environment state inline inside the runtime node.' },
  executeWineDllOverrides: { description: 'Configure Wine DLL override behavior inline inside the runtime node.' },
  executeWineReg: { description: 'Read or write Wine registry values inline inside the runtime node.' },
  executeDynamicMemoryDump: { description: 'Capture dynamic memory dumps inline inside the runtime node.' },
  executeProcDumpCapture: {
    description: 'Capture crash, timeout, launch, or PID-triggered dumps with Sysinternals ProcDump inside the runtime node.',
    requiresSample: false,
  },
  executeTelemetryCapture: {
    description: 'Capture ProcMon, Sysmon, ETW, or PowerShell event-log telemetry inside the runtime node.',
    requiresSample: false,
  },
  executeBehaviorCapture: { description: 'Run a bounded Windows behavior capture inside the runtime node and persist process/module/file observations.' },
  executeQilingInspect: { description: 'Run Qiling-backed inspection inline inside the runtime node.' },
  executePandaInspect: { description: 'Run PANDA-backed inspection inline inside the runtime node.' },
  executeManagedSafeRun: { description: 'Run managed sandbox analysis inline inside the runtime node.' },
  executeDebugSession: { description: 'Handle debug-session lifecycle and inspection requests inline inside the runtime node.' },
  executeRuntimeToolProbe: {
    description: 'Inspect runtime-side debugger, dump, telemetry, network, and manual GUI tool availability without executing a sample.',
    requiresSample: false,
  },
}

interface SpawnExecutionPlan {
  command: string
  args: string[]
  cwd?: string
  env?: NodeJS.ProcessEnv
}

interface SpawnBackendHandler {
  description: string
  requiresSample?: boolean
  preflight?: () => Promise<string | undefined>
  buildPlan: (task: ExecuteTask, samplePath?: string) => SpawnExecutionPlan
}

const spawnHandlers: Record<string, SpawnBackendHandler> = {
  'native.sample.execute': {
    description: 'Execute the uploaded sample directly as a child process.',
    requiresSample: true,
    buildPlan(task, samplePath) {
      return {
        command: samplePath!,
        args: readStringArrayArg(task.args, 'arguments', 'args'),
      }
    },
  },
  'wine.sample.run': {
    description: 'Execute the uploaded sample under Wine as a spawned process.',
    requiresSample: true,
    preflight: async () => {
      if (await checkCommandAvailable('wine')) return undefined
      return 'Wine is not available in the runtime environment.'
    },
    buildPlan(task, samplePath) {
      return {
        command: 'wine',
        args: [samplePath!, ...readStringArrayArg(task.args, 'arguments', 'args')],
      }
    },
  },
  'winedbg.sample.run': {
    description: 'Execute the uploaded sample under winedbg as a spawned process.',
    requiresSample: true,
    preflight: async () => {
      if (await checkCommandAvailable('winedbg')) return undefined
      return 'winedbg is not available in the runtime environment.'
    },
    buildPlan(task, samplePath) {
      return {
        command: 'winedbg',
        args: [samplePath!, ...readStringArrayArg(task.args, 'arguments', 'args')],
      }
    },
  },
  'dotnet.sample.run': {
    description: 'Execute the uploaded sample through dotnet as a spawned process.',
    requiresSample: true,
    preflight: async () => {
      if (await checkCommandAvailable('dotnet')) return undefined
      return 'dotnet CLI is not available in the runtime environment.'
    },
    buildPlan(task, samplePath) {
      return {
        command: 'dotnet',
        args: [samplePath!, ...readStringArrayArg(task.args, 'arguments', 'args')],
      }
    },
  },
}

export interface RuntimeBackendCapability {
  type: RuntimeBackendType
  handler: string
  description: string
  requiresSample: boolean
}

interface RuntimeBackendCapabilityDetails extends RuntimeBackendCapability {
  key: string
}

function getRuntimeBackendCapabilityKey(type: RuntimeBackendType, handler: string): string {
  return `${type}:${handler}`
}

const runtimeBackendCapabilityRegistry: RuntimeBackendCapabilityDetails[] = [
  ...Object.entries(pythonWorkerHandlers).map(([handler, definition]) => ({
    key: getRuntimeBackendCapabilityKey('python-worker', handler),
    type: 'python-worker' as const,
    handler,
    description: definition.description,
    requiresSample: true,
  })),
  ...Object.entries(spawnHandlers).map(([handler, definition]) => ({
    key: getRuntimeBackendCapabilityKey('spawn', handler),
    type: 'spawn' as const,
    handler,
    description: definition.description,
    requiresSample: definition.requiresSample !== false,
  })),
  ...Object.entries(inlineHandlerMetadata).map(([handler, definition]) => ({
    key: getRuntimeBackendCapabilityKey('inline', handler),
    type: 'inline' as const,
    handler,
    description: definition.description,
    requiresSample: definition.requiresSample !== false,
  })),
]

const runtimeBackendCapabilityIndex = new Map(
  runtimeBackendCapabilityRegistry.map((entry) => [entry.key, entry] satisfies [string, RuntimeBackendCapabilityDetails]),
)

export function listRuntimeBackendCapabilities(): RuntimeBackendCapability[] {
  return runtimeBackendCapabilityRegistry.map(({ key: _key, ...capability }) => ({ ...capability }))
}

export function getRuntimeBackendCapability(hint: RuntimeBackendHint): RuntimeBackendCapability | undefined {
  const capability = runtimeBackendCapabilityIndex.get(getRuntimeBackendCapabilityKey(hint.type, hint.handler))
  if (!capability) {
    return undefined
  }
  const { key: _key, ...result } = capability
  return { ...result }
}

export function isRuntimeBackendHintSupported(hint: RuntimeBackendHint): boolean {
  return getRuntimeBackendCapability(hint) !== undefined
}

function readStringArrayArg(args: Record<string, unknown>, ...keys: string[]): string[] {
  for (const key of keys) {
    const value = args[key]
    if (Array.isArray(value) && value.every((entry) => typeof entry === 'string')) {
      return [...value]
    }
  }
  return []
}

function tryParseStructuredSpawnResult(stdout: string): ExecuteResult['result'] | undefined {
  const trimmed = stdout.trim()
  if (!trimmed) {
    return undefined
  }

  const candidates = [trimmed, trimmed.split(/\r?\n/).filter(Boolean).slice(-1)[0]].filter(Boolean) as string[]
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate)
      if (!parsed || typeof parsed !== 'object') {
        continue
      }
      const payload = parsed as Record<string, unknown>
      return {
        ok: typeof payload.ok === 'boolean' ? payload.ok : true,
        data: 'data' in payload ? payload.data : payload,
        errors: Array.isArray(payload.errors) ? payload.errors.filter((entry): entry is string => typeof entry === 'string') : undefined,
        warnings: Array.isArray(payload.warnings) ? payload.warnings.filter((entry): entry is string => typeof entry === 'string') : undefined,
        artifacts: Array.isArray(payload.artifacts) ? payload.artifacts : undefined,
        metrics: payload.metrics && typeof payload.metrics === 'object' ? payload.metrics as Record<string, unknown> : undefined,
      }
    } catch {
      // fall through and keep treating stdout as plain text
    }
  }

  return undefined
}

async function executeSpawnBackend(
  task: ExecuteTask,
  handlerName: string,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const handler = spawnHandlers[handlerName]
  if (!handler) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Spawn handler '${handlerName}' is not registered.`],
      logs,
    }
  }

  const samplePath = handler.requiresSample === false
    ? undefined
    : resolveTaskSamplePath(task.taskId)
  const sampleWorkingDir = samplePath ? path.dirname(samplePath) : undefined

  if (samplePath && !fs.existsSync(samplePath)) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Sample file not found in runtime inbox: ${samplePath}`],
      logs,
    }
  }

  const preflightError = await handler.preflight?.()
  if (preflightError) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [preflightError],
      logs,
    }
  }

  const plan = handler.buildPlan(task, samplePath)
  log(`Spawning command backend '${handlerName}': ${plan.command} ${plan.args.join(' ')}`.trim())
  onProgress?.(0.05, `Spawn backend '${handlerName}' started`)

  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(plan.command, plan.args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: task.timeoutMs,
      cwd: plan.cwd ?? sampleWorkingDir,
      env: {
        ...process.env,
        ...plan.env,
      },
      windowsHide: true,
    })
    registerProcess(task.taskId, child)

    let stdout = ''
    let stderr = ''

    child.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    child.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    child.on('error', (error) => {
      resolve({
        ok: false,
        taskId: task.taskId,
        errors: [`Failed to spawn backend '${handlerName}': ${error.message}`],
        logs: [...logs, stderr].filter(Boolean),
      })
    })

    child.on('close', (code, signal) => {
      onProgress?.(1, code === 0 ? `Spawn backend '${handlerName}' completed` : `Spawn backend '${handlerName}' failed`)

      const parsedResult = tryParseStructuredSpawnResult(stdout)
      const stagedArtifacts = stageArtifactsToOutbox(task.taskId, parsedResult?.artifacts, log)
      const defaultData = {
        backend: handlerName,
        command: plan.command,
        args: plan.args,
        exitCode: code,
        signal: signal ?? null,
        stdout,
        stderr,
        samplePath,
      }
      const result = parsedResult
        ? {
            ...parsedResult,
            data: parsedResult.data ?? defaultData,
            artifacts: parsedResult.artifacts,
          }
        : {
            ok: code === 0,
            data: defaultData,
            errors: code === 0 ? undefined : [`Spawn backend '${handlerName}' exited with code ${code}${signal ? ` (signal ${signal})` : ''}.`],
            warnings: undefined,
            artifacts: undefined,
            metrics: undefined,
          }

      resolve({
        ok: code === 0 && (parsedResult?.ok ?? true),
        taskId: task.taskId,
        result,
        logs: [...logs, stderr].filter(Boolean),
        errors: code === 0 ? undefined : [`Spawn backend '${handlerName}' exited with code ${code}${signal ? ` (signal ${signal})` : ''}.`],
        artifactRefs: stagedArtifacts,
      })
    })
  })
}

function resolveWorkerPath(workerName: string): string | null {
  const mappedWorkersDir = 'C:\\rikune-workers'
  const candidates = [
    path.join(mappedWorkersDir, workerName),
    path.join(moduleDirname, '..', '..', '..', 'workers', workerName),
    path.join(moduleDirname, '..', '..', '..', '..', 'workers', workerName),
  ]
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate
    }
  }
  return null
}

function stageArtifactsToOutbox(
  taskId: string,
  artifacts: unknown[] | undefined,
  log: (msg: string) => void,
): { name: string; path: string }[] {
  const staged: { name: string; path: string }[] = []
  if (!artifacts || artifacts.length === 0) {
    return staged
  }

  const outboxDir = path.join(config.runtime.outbox, taskId)
  if (!fs.existsSync(outboxDir)) {
    fs.mkdirSync(outboxDir, { recursive: true })
  }

  for (const art of artifacts) {
    if (!art || typeof art !== 'object') continue
    const artPath = (art as any).path as string | undefined
    if (!artPath || !fs.existsSync(artPath)) continue

    const basename = path.basename(artPath)
    const destPath = path.join(outboxDir, basename)
    try {
      fs.copyFileSync(artPath, destPath)
      staged.push({ name: basename, path: destPath })
      log(`Staged artifact to outbox: ${basename}`)
    } catch (err) {
      log(`Failed to stage artifact ${basename}: ${err}`)
    }
  }

  return staged
}

async function checkPythonAvailable(): Promise<boolean> {
  try {
    const pythonCheck = spawnProcess(pythonCommand, ['--version'], { stdio: 'ignore' })
    await new Promise<void>((resolve, reject) => {
      pythonCheck.on('close', (code) => (code === 0 ? resolve() : reject(new Error('Python not available'))))
      pythonCheck.on('error', reject)
    })
    return true
  } catch {
    return false
  }
}

async function checkPythonModuleAvailable(moduleName: string): Promise<boolean> {
  try {
    const check = spawnProcess(pythonCommand, ['-c', `import ${moduleName}`], { stdio: 'ignore' })
    await new Promise<void>((resolve, reject) => {
      check.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`Module ${moduleName} not available`))))
      check.on('error', reject)
    })
    return true
  } catch {
    return false
  }
}

async function checkCommandAvailable(cmd: string): Promise<boolean> {
  try {
    const check = spawnProcess(cmd, ['--version'], { stdio: 'ignore' })
    await new Promise<void>((resolve, reject) => {
      check.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} not available`))))
      check.on('error', reject)
    })
    return true
  } catch {
    return false
  }
}

export async function executePythonWorker(
  task: ExecuteTask,
  workerName: string,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const uploadedSample = resolveTaskSample(task.taskId)
  const samplePath = uploadedSample.samplePath
  if (!fs.existsSync(samplePath)) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Sample file not found in runtime inbox: ${samplePath}`],
      logs,
    }
  }

  const workerPath = resolveWorkerPath(workerName)
  if (!workerPath) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`${workerName} not found. Ensure workers/ directory is mapped into the runtime environment.`],
      logs,
    }
  }

  if (!(await checkPythonAvailable())) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Python (${pythonCommand}) is not available in the runtime environment.`],
      logs,
    }
  }

  const requestPayload = {
    job_id: task.taskId,
    tool: task.tool,
    sample: {
      sample_id: task.sampleId,
      path: samplePath,
      working_dir: uploadedSample.workingDir,
      sidecars: uploadedSample.sidecars,
    },
    args: task.args,
    context: {
      request_time_utc: new Date().toISOString(),
      policy: {
        allow_dynamic: true,
        allow_network: task.args.network === 'enabled',
      },
      versions: {},
    },
  }

  log(`Spawning worker: ${workerPath} for tool ${task.tool}`)

  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(pythonCommand, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: task.timeoutMs,
    })
    registerProcess(task.taskId, child)

    let stdout = ''
    let stdoutBuffer = ''
    let stderr = ''

    child.stdout.on('data', (data) => {
      stdoutBuffer += data.toString()
      const lines = stdoutBuffer.split('\n')
      stdoutBuffer = lines.pop() ?? ''
      for (const line of lines) {
        const trimmed = line.trim()
        if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
          try {
            const parsed = JSON.parse(trimmed)
            if (typeof parsed.progress === 'number') {
              onProgress?.(parsed.progress, parsed.message)
              continue
            }
          } catch {
            // not a progress line
          }
        }
        stdout += line + '\n'
      }
    })

    child.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    child.on('error', (error) => {
      resolve({
        ok: false,
        taskId: task.taskId,
        errors: [`Failed to spawn Python worker: ${error.message}`],
        logs: [...logs, stderr],
      })
    })

    child.on('close', (code) => {
      if (code !== 0) {
        resolve({
          ok: false,
          taskId: task.taskId,
          errors: [`Python worker exited with code ${code}. stderr: ${stderr}`],
          logs,
        })
        return
      }

      try {
        const lines = stdout.trim().split('\n')
        const lastLine = lines[lines.length - 1]
        const workerResponse = JSON.parse(lastLine)
        const artifacts = workerResponse.artifacts || []
        const artifactRefs = stageArtifactsToOutbox(task.taskId, artifacts, log)
        resolve({
          ok: workerResponse.ok ?? true,
          taskId: task.taskId,
          result: {
            ok: workerResponse.ok ?? true,
            data: workerResponse.data,
            errors: workerResponse.errors,
            warnings: workerResponse.warnings,
            artifacts,
            metrics: workerResponse.metrics,
          },
          logs: [...logs, stderr].filter(Boolean),
          artifactRefs,
        })
      } catch (error) {
        resolve({
          ok: false,
          taskId: task.taskId,
          errors: [`Failed to parse worker response: ${(error as Error).message}. stdout: ${stdout}`],
          logs,
        })
      }
    })

    try {
      child.stdin.write(JSON.stringify(requestPayload) + '\n')
      child.stdin.end()
    } catch (error) {
      resolve({
        ok: false,
        taskId: task.taskId,
        errors: [`Failed to write to worker stdin: ${(error as Error).message}`],
        logs,
      })
    }
  })
}

async function runPythonInline(
  script: string,
  args: string[],
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
  requiredModule?: string,
): Promise<ExecuteResult> {
  if (!(await checkPythonAvailable())) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Python (${pythonCommand}) is not available in the runtime environment.`],
      logs,
    }
  }
  if (requiredModule && !(await checkPythonModuleAvailable(requiredModule))) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Python module '${requiredModule}' is not installed in the runtime environment.`],
      logs,
    }
  }

  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(pythonCommand, ['-c', script, ...args], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: task.timeoutMs + 10000,
    })
    registerProcess(task.taskId, child)

    let stdout = ''
    let stdoutBuffer = ''
    let stderr = ''

    child.stdout.on('data', (data) => {
      stdoutBuffer += data.toString()
      const lines = stdoutBuffer.split('\n')
      stdoutBuffer = lines.pop() ?? ''
      for (const line of lines) {
        const trimmed = line.trim()
        if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
          try {
            const parsed = JSON.parse(trimmed)
            if (typeof parsed.progress === 'number') {
              onProgress?.(parsed.progress, parsed.message)
              continue
            }
          } catch {
            // not a progress line
          }
        }
        stdout += line + '\n'
      }
    })

    child.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    child.on('error', (error) => {
      resolve({
        ok: false,
        taskId: task.taskId,
        errors: [`Failed to spawn inline Python: ${error.message}`],
        logs: [...logs, stderr],
      })
    })

    child.on('close', (code) => {
      try {
        const lines = stdout.trim().split('\n')
        const jsonLines = lines.filter((l) => l.trim().startsWith('{'))
        const lastLine = jsonLines[jsonLines.length - 1] || lines[lines.length - 1] || '{}'
        const workerResponse = JSON.parse(lastLine)
        const artifacts = workerResponse.artifacts || []
        const artifactRefs = stageArtifactsToOutbox(task.taskId, artifacts, log)
        resolve({
          ok: workerResponse.ok ?? true,
          taskId: task.taskId,
          result: {
            ok: workerResponse.ok ?? true,
            data: workerResponse.data,
            errors: workerResponse.errors,
            warnings: workerResponse.warnings,
            artifacts,
            metrics: workerResponse.metrics || { elapsed_ms: task.timeoutMs },
          },
          logs: [...logs, stderr].filter(Boolean),
          artifactRefs,
        })
      } catch (error) {
        resolve({
          ok: false,
          taskId: task.taskId,
          errors: [`Failed to parse inline Python response: ${(error as Error).message}. stdout: ${stdout}`],
          logs,
        })
      }
    })
  })
}

function buildFridaDumpScript(trigger: string, _delayMs: number, maxDumps: number): string {
  return `
var dumpCount = 0;
var maxDumps = ${maxDumps};
var trigger = '${trigger}';

function dumpRegion(base, size, reason) {
    if (dumpCount >= maxDumps) return;
    try {
        var data = base.readByteArray(Math.min(size, 0x100000));
        send({ type: 'memory_dump', reason: reason, base: base.toString(),
               size: size, dump_index: dumpCount }, data);
        dumpCount++;
    } catch(e) {
        send({ type: 'dump_error', reason: reason, base: base.toString(), error: e.toString() });
    }
}

if (trigger === 'alloc_rwx' || trigger === 'protect_rx') {
    var pVA = Module.getExportByName('kernel32.dll', 'VirtualAlloc');
    if (pVA) {
        Interceptor.attach(pVA, {
            onEnter: function(args) {
                this.size = args[1].toInt32();
                this.protect = args[3].toInt32();
            },
            onLeave: function(retval) {
                if (!retval.isNull() && trigger === 'alloc_rwx') {
                    if (this.protect === 0x40 || this.protect === 0x10) {
                        send({ type: 'alloc_detected', base: retval.toString(),
                               size: this.size, protect: this.protect });
                        var base = retval; var size = this.size;
                        setTimeout(function() { dumpRegion(base, size, 'alloc_rwx'); }, 500);
                    }
                }
            }
        });
    }

    var pVP = Module.getExportByName('kernel32.dll', 'VirtualProtect');
    if (pVP) {
        Interceptor.attach(pVP, {
            onEnter: function(args) {
                this.addr = args[0];
                this.size = args[1].toInt32();
                this.newProtect = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (trigger === 'protect_rx' && retval.toInt32() !== 0) {
                    if (this.newProtect === 0x20 || this.newProtect === 0x10 || this.newProtect === 0x40) {
                        send({ type: 'protect_detected', base: this.addr.toString(),
                               size: this.size, new_protect: this.newProtect });
                        dumpRegion(this.addr, this.size, 'protect_change_rx');
                    }
                }
            }
        });
    }
}

if (trigger === 'timed') {
    setTimeout(function() {
        Process.enumerateRanges('r-x').forEach(function(range) {
            if (range.size > 0x1000 && range.size < 0x1000000) {
                dumpRegion(ptr(range.base), range.size, 'timed_rx_region');
            }
        });
    }, ${_delayMs});
}

send({ type: 'dump_hooks_installed', trigger: trigger, max_dumps: maxDumps });
`.trim()
}

export async function executeDynamicMemoryDump(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Sample file not found in runtime inbox: ${samplePath}`],
      logs,
    }
  }

  const trigger = String(task.args.trigger || 'alloc_rwx')
  const delayMs = Number(task.args.delay_ms || 3000)
  const maxDumps = Number(task.args.max_dumps || 5)
  const timeoutSec = Number(task.args.timeout_sec || 30)

  const fridaScript = buildFridaDumpScript(trigger, delayMs, maxDumps)
  const outboxTaskDir = path.join(config.runtime.outbox, task.taskId)
  fs.mkdirSync(outboxTaskDir, { recursive: true })
  const scriptPath = path.join(outboxTaskDir, 'memory_dump_hook.js')
  fs.writeFileSync(scriptPath, fridaScript, 'utf-8')

  const pyScript = `
import frida, sys, json, os, time
sample_path = sys.argv[1]
script_path = sys.argv[2]
timeout_sec = int(sys.argv[3])
outbox = sys.argv[4]
dumps = []

def on_message(message, data):
    if message.get('type') == 'send':
        payload = message.get('payload', {})
        if payload.get('type') == 'memory_dump' and data:
            idx = payload.get('dump_index', 0)
            reason = payload.get('reason', 'unknown')
            dump_path = os.path.join(outbox, 'memory_dump_{}_{}.bin'.format(idx, reason))
            with open(dump_path, 'wb') as f:
                f.write(data)
            dumps.append({"index": idx, "reason": reason, "path": dump_path, "size": len(data)})
        elif payload.get('type') in ('alloc_detected', 'protect_detected', 'dump_hooks_installed'):
            print(json.dumps({"log": str(payload)}), flush=True)

try:
    device = frida.get_local_device()
    pid = device.spawn([sample_path])
    session = device.attach(pid)
    with open(script_path, 'r', encoding='utf-8') as f:
        script_content = f.read()
    script = session.create_script(script_content)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    time.sleep(timeout_sec)
    session.detach()
    result = {"ok": True, "dumps": dumps, "trigger": "${trigger}", "timeout_sec": timeout_sec}
except Exception as e:
    result = {"ok": False, "error": str(e)}
print(json.dumps(result))
`

  log(`Spawning Frida memory dump for ${samplePath} trigger=${trigger}`)
  return runPythonInline(pyScript, [samplePath, scriptPath, String(timeoutSec), outboxTaskDir], task, log, logs, onProgress, 'frida')
}

export async function executeSandboxExecute(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return { ok: false, taskId: task.taskId, errors: [`Sample file not found: ${samplePath}`], logs }
  }

  const antiDebug = Boolean(task.args.anti_debug)
  const timeDilation = Boolean(task.args.time_dilation)
  const speedFactor = Number(task.args.speed_factor || 100)
  const timeoutMs = task.timeoutMs

  if (process.platform !== 'win32') {
    log(`Falling back to static_worker.py for sandbox.execute on ${process.platform}`)
    return executePythonWorker(task, 'static_worker.py', log, logs, onProgress)
  }

  const { isIsolatedEnvironment } = await import('./isolation.js')
  const isolated = await isIsolatedEnvironment()
  if (!isolated) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: ['Direct PE execution is only allowed inside an isolated environment (Windows Sandbox).'],
      logs,
    }
  }

  if (antiDebug || timeDilation) {
    const outboxTaskDir = path.join(config.runtime.outbox, task.taskId)
    fs.mkdirSync(outboxTaskDir, { recursive: true })
    const scriptPath = path.join(outboxTaskDir, 'evasion_hook.js')
    let script = ''
    if (antiDebug) script += buildAntiDebugScript() + '\n'
    if (timeDilation) script += buildTimeBypassScript(speedFactor) + '\n'
    script += buildEvasionScoreScript() + '\n'
    fs.writeFileSync(scriptPath, script, 'utf-8')

    const pyScript = `
import frida, sys, json, os, time
sample_path = sys.argv[1]
script_path = sys.argv[2]
timeout_sec = int(sys.argv[3])
traces = []
start_time = time.time()

def on_message(message, data):
    if message.get('type') == 'send':
        payload = message.get('payload', {})
        traces.append(payload)
        if payload.get('type') == 'time_bypass':
            print(json.dumps({"progress": 0.5, "message": "time bypass active"}), flush=True)

try:
    device = frida.get_local_device()
    pid = device.spawn([sample_path])
    session = device.attach(pid)
    with open(script_path, 'r', encoding='utf-8') as f:
        script_content = f.read()
    frida_script = session.create_script(script_content)
    frida_script.on('message', on_message)
    frida_script.load()
    device.resume(pid)
    elapsed = 0
    while elapsed < timeout_sec:
        time.sleep(1)
        elapsed = time.time() - start_time
        try:
            device.get_process(os.path.basename(sample_path))
        except frida.ProcessNotFoundError:
            break
    session.detach()
    evasion_counts = {}
    time_bypass_count = 0
    for t in traces:
        if t.get('type') == 'evasion_api_call':
            api = t.get('api')
            evasion_counts[api] = evasion_counts.get(api, 0) + 1
        elif t.get('type') == 'time_bypass':
            time_bypass_count += 1
    evasion_score = time_bypass_count + sum(evasion_counts.values()) * 2
    result = {"ok": True, "pid": pid, "traces": traces, "elapsed_sec": elapsed,
              "evasion_score": evasion_score, "evasion_counts": evasion_counts,
              "time_bypass_count": time_bypass_count}
except Exception as e:
    result = {"ok": False, "error": str(e)}
print(json.dumps(result))
`.trim()

    log(`Spawning sandbox.execute with Frida evasion for ${samplePath}`)
    return runPythonInline(pyScript, [samplePath, scriptPath, String(Math.floor(timeoutMs / 1000))], task, log, logs, onProgress, 'frida')
  }

  log(`Spawning sandbox.execute directly for ${samplePath}`)
  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(samplePath, [String(task.args.command_line_args || '')], {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs,
      cwd: path.dirname(samplePath),
      windowsHide: true,
    })
    registerProcess(task.taskId, child)
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += d.toString() })
    child.stderr.on('data', (d) => { stderr += d.toString() })
    child.on('error', (e) => resolve({ ok: false, taskId: task.taskId, errors: [e.message], logs }))
    child.on('close', (code) => {
      resolve({
        ok: true,
        taskId: task.taskId,
        result: {
          ok: true,
          data: { exit_code: code, stdout: stdout.slice(0, 20000), stderr: stderr.slice(0, 10000) },
          metrics: { tool: 'sandbox.execute' },
        },
        logs,
      })
    })
  })
}

function buildSpeakeasyScript(mode: 'module' | 'shellcode' | 'api_trace'): string {
  const isShellcode = mode === 'shellcode'
  const runCall = isShellcode
    ? 'sc_addr = se.load_shellcode(sample_path, arch=arch); se.run_shellcode(sc_addr, timeout=timeout_sec)'
    : 'module = se.load_module(sample_path); se.run_module(module, timeout=timeout_sec)'
  const reportGet = 'se.get_report()'

  return `
import json, sys, os, traceback, warnings

sample_path = sys.argv[1]
mode = sys.argv[2]
timeout_sec = int(sys.argv[3])
max_api = int(sys.argv[4])
outbox = sys.argv[5]
arch = sys.argv[6] if len(sys.argv) > 6 else 'x64'

payload = {"ok": False, "warnings": [], "errors": [], "data": {}}

try:
    worker_dir = os.path.dirname(os.path.abspath(__file__)) if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "speakeasy_compat.py")) else os.path.dirname(sample_path)
    if worker_dir and worker_dir not in sys.path:
        sys.path.insert(0, worker_dir)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        from speakeasy_compat import load_speakeasy_module
        speakeasy, compat_info = load_speakeasy_module()

    payload["warnings"] = [str(item.message) for item in caught]
    if not hasattr(speakeasy, "Speakeasy"):
        raise RuntimeError("Imported speakeasy module does not expose Speakeasy emulator API")

    se = speakeasy.Speakeasy()
    if mode == 'shellcode':
        sc_addr = se.load_shellcode(sample_path, arch=arch)
        se.run_shellcode(sc_addr, timeout=timeout_sec)
    else:
        module = se.load_module(sample_path)
        se.run_module(module, timeout=timeout_sec)
    report = se.get_report()
    entry_points = report.get("entry_points", [])
    all_apis = []
    file_activity = set()
    registry_activity = set()
    network_activity = set()

    for ep in entry_points:
        for api_call in ep.get("apis_called", [])[:max_api]:
            all_apis.append({
                "api_name": api_call.get("api_name", ""),
                "module": api_call.get("module", ""),
                "args": [str(a)[:200] for a in api_call.get("args", [])[:8]],
                "ret_val": str(api_call.get("ret_val", ""))[:100],
            })
            api_name = api_call.get("api_name", "").lower()
            args_str = " ".join(str(a) for a in api_call.get("args", []))
            if any(k in api_name for k in ("createfile", "writefile", "deletefile", "copyfile", "movefile")):
                file_activity.add(args_str[:300])
            if any(k in api_name for k in ("regopen", "regset", "regcreate", "regdelete", "regquery")):
                registry_activity.add(args_str[:300])
            if any(k in api_name for k in ("connect", "send", "recv", "socket", "inet", "gethost", "urldownload", "winhttp", "internetopen")):
                network_activity.add(args_str[:300])

    data = {
        "mode": mode,
        "entry_points_count": len(entry_points),
        "entry_points_summary": [{"ep_type": ep.get("ep_type",""), "api_count": len(ep.get("apis_called",[]))} for ep in entry_points][:20],
        "api_call_count": len(all_apis),
        "api_calls_preview": all_apis[:50],
        "file_activity": sorted(file_activity)[:50],
        "registry_activity": sorted(registry_activity)[:50],
        "network_activity": sorted(network_activity)[:50],
    }

    if outbox:
        os.makedirs(outbox, exist_ok=True)
        report_path = os.path.join(outbox, "speakeasy_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        payload["artifacts"] = [{"id": "speakeasy_report", "type": "emulation_report", "path": report_path, "sha256": "", "mime": "application/json"}]

    payload["ok"] = True
    payload["data"] = data
except Exception as exc:
    payload["errors"].append(str(exc))
    payload["traceback"] = traceback.format_exc(limit=10)

print(json.dumps(payload))
`
}

export async function executeSpeakeasyEmulate(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Sample file not found in runtime inbox: ${samplePath}`],
      logs,
    }
  }
  const timeoutSec = Number(task.args.timeout_sec || 60)
  const maxApi = Number(task.args.max_api_count || 10000)
  const outboxTaskDir = path.join(config.runtime.outbox, task.taskId)
  log(`Spawning speakeasy emulate for ${samplePath}`)
  return runPythonInline(buildSpeakeasyScript('module'), [samplePath, 'module', String(timeoutSec), String(maxApi), outboxTaskDir], task, log, logs, onProgress, 'speakeasy')
}

export async function executeSpeakeasyShellcode(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return { ok: false, taskId: task.taskId, errors: [`Sample file not found: ${samplePath}`], logs }
  }
  const timeoutSec = Number(task.args.timeout_sec || 60)
  const maxApi = Number(task.args.max_api_count || 10000)
  const arch = String(task.args.arch || 'x64')
  const outboxTaskDir = path.join(config.runtime.outbox, task.taskId)
  log(`Spawning speakeasy shellcode for ${samplePath} arch=${arch}`)
  return runPythonInline(buildSpeakeasyScript('shellcode'), [samplePath, 'shellcode', String(timeoutSec), String(maxApi), outboxTaskDir, arch], task, log, logs, onProgress, 'speakeasy')
}

export async function executeSpeakeasyApiTrace(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return { ok: false, taskId: task.taskId, errors: [`Sample file not found: ${samplePath}`], logs }
  }
  const timeoutSec = Number(task.args.timeout_sec || 60)
  const maxApi = Number(task.args.max_api_count || 10000)
  const outboxTaskDir = path.join(config.runtime.outbox, task.taskId)
  log(`Spawning speakeasy api_trace for ${samplePath}`)
  return runPythonInline(buildSpeakeasyScript('api_trace'), [samplePath, 'api_trace', String(timeoutSec), String(maxApi), outboxTaskDir], task, log, logs, onProgress, 'speakeasy')
}

export async function executeWineRun(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Sample file not found in runtime inbox: ${samplePath}`],
      logs,
    }
  }

  if (process.platform !== 'win32' && !(await checkCommandAvailable('wine'))) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: ['Wine is not available in the runtime environment. Install Wine to run Windows PE samples on Linux.'],
      logs,
    }
  }

  const wineCmd = process.platform === 'win32' ? samplePath : 'wine'
  const wineArgs = process.platform === 'win32'
    ? [String(task.args.command_line_args || '')]
    : [samplePath, String(task.args.command_line_args || '')]

  if (process.platform === 'win32') {
    const { isIsolatedEnvironment } = await import('./isolation.js')
    const isolated = await isIsolatedEnvironment()
    if (!isolated) {
      return {
        ok: false,
        taskId: task.taskId,
        errors: ['Direct PE execution is only allowed inside an isolated environment (Windows Sandbox).'],
        logs,
      }
    }
  }

  log(`Spawning wine run: ${wineCmd} ${wineArgs.join(' ')}`)

  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(wineCmd, wineArgs, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: task.timeoutMs,
      cwd: path.dirname(samplePath),
      windowsHide: true,
    })
    registerProcess(task.taskId, child)

    let stdout = ''
    let stderr = ''

    child.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    child.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    child.on('error', (error) => {
      resolve({
        ok: false,
        taskId: task.taskId,
        errors: [`Failed to spawn wine: ${error.message}`],
        logs: [...logs, stderr],
      })
    })

    child.on('close', (code) => {
      resolve({
        ok: true,
        taskId: task.taskId,
        result: {
          ok: true,
          data: {
            exit_code: code,
            stdout: stdout.slice(0, 20000),
            stderr: stderr.slice(0, 10000),
          },
          metrics: { tool: 'wine.run' },
        },
        logs: [...logs, `wine exited with code ${code}`].filter(Boolean),
      })
    })
  })
}

export async function executeWineEnv(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  if (process.platform !== 'win32' && !(await checkCommandAvailable('wine'))) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: ['Wine is not available in the runtime environment. Install Wine to query Windows PE environment on Linux.'],
      logs,
    }
  }
  const wineCmd = process.platform === 'win32' ? 'cmd.exe' : 'wine'
  const wineArgs = process.platform === 'win32' ? ['/c', 'set'] : ['cmd', '/c', 'set']
  log(`Querying wine environment`)
  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(wineCmd, wineArgs, { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, windowsHide: true })
    registerProcess(task.taskId, child)
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += d.toString() })
    child.stderr.on('data', (d) => { stderr += d.toString() })
    child.on('error', (e) => resolve({ ok: false, taskId: task.taskId, errors: [e.message], logs }))
    child.on('close', (code) => {
      const envVars: Record<string, string> = {}
      for (const line of stdout.split('\n')) {
        const idx = line.indexOf('=')
        if (idx > 0) envVars[line.slice(0, idx)] = line.slice(idx + 1)
      }
      resolve({ ok: true, taskId: task.taskId, result: { ok: true, data: { env_vars: envVars, exit_code: code }, metrics: { tool: 'wine.env' } }, logs: [...logs, stdout, stderr].filter(Boolean) })
    })
  })
}

export async function executeWineDllOverrides(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const overrides = task.args.overrides as Record<string, string> | undefined
  if (process.platform === 'win32') {
    return { ok: true, taskId: task.taskId, result: { ok: true, data: { overrides: overrides || {}, note: 'DLL overrides are managed via registry on native Windows.' }, metrics: { tool: 'wine.dll_overrides' } }, logs }
  }
  if (!(await checkCommandAvailable('wine'))) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: ['Wine is not available in the runtime environment. Install Wine to configure DLL overrides on Linux.'],
      logs,
    }
  }
  const wineCmd = 'wine'
  const env = { ...process.env, WINEDLLOVERRIDES: Object.entries(overrides || {}).map(([k, v]) => `${k}=${v}`).join(';') }
  log(`Setting WINEDLLOVERRIDES`)
  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(wineCmd, ['regedit', '/?'], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, env, windowsHide: true })
    registerProcess(task.taskId, child)
    let stdout = ''
    child.stdout.on('data', (d) => { stdout += d.toString() })
    child.on('error', (e) => resolve({ ok: false, taskId: task.taskId, errors: [e.message], logs }))
    child.on('close', () => {
      resolve({ ok: true, taskId: task.taskId, result: { ok: true, data: { overrides: overrides || {}, note: 'WINEDLLOVERRIDES updated' }, metrics: { tool: 'wine.dll_overrides' } }, logs: [...logs, stdout].filter(Boolean) })
    })
  })
}

export async function executeWineReg(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const operation = String(task.args.operation || 'read')
  const keyPath = String(task.args.key_path || '')
  const valueName = String(task.args.value_name || '')
  const valueData = task.args.value_data as string | undefined

  if (process.platform !== 'win32' && !(await checkCommandAvailable('wine'))) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: ['Wine is not available in the runtime environment. Install Wine to manipulate registry on Linux.'],
      logs,
    }
  }

  const wineCmd = process.platform === 'win32' ? 'reg.exe' : 'wine'
  let wineArgs: string[]
  if (process.platform === 'win32') {
    if (operation === 'read') wineArgs = ['query', keyPath, '/v', valueName]
    else if (operation === 'add') wineArgs = ['add', keyPath, '/v', valueName, '/d', valueData || '', '/f']
    else if (operation === 'delete') wineArgs = ['delete', keyPath, '/v', valueName, '/f']
    else wineArgs = ['query', keyPath]
  } else {
    if (operation === 'read') wineArgs = ['regedit', '/E', '-', keyPath]
    else wineArgs = ['regedit', '/?']
  }

  log(`Spawning wine reg: ${wineCmd} ${wineArgs.join(' ')}`)
  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(wineCmd, wineArgs, { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, windowsHide: true })
    registerProcess(task.taskId, child)
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += d.toString() })
    child.stderr.on('data', (d) => { stderr += d.toString() })
    child.on('error', (e) => resolve({ ok: false, taskId: task.taskId, errors: [e.message], logs }))
    child.on('close', (code) => {
      resolve({ ok: code === 0, taskId: task.taskId, result: { ok: code === 0, data: { operation, stdout: stdout.slice(0, 5000), stderr: stderr.slice(0, 5000) }, metrics: { tool: 'wine.reg' } }, logs: [...logs, stdout, stderr].filter(Boolean) })
    })
  })
}

export async function executeQilingInspect(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return { ok: false, taskId: task.taskId, errors: [`Sample file not found: ${samplePath}`], logs }
  }
  const timeoutSec = Number(task.args.timeout_sec || 60)
  const outboxTaskDir = path.join(config.runtime.outbox, task.taskId)

  const script = `
import json, sys, os, traceback
try:
    from qiling import Qiling
    from qiling.const import QL_VERBOSE
    QILING_AVAILABLE = True
except Exception as e:
    QILING_AVAILABLE = False
    QILING_ERROR = str(e)

sample_path = sys.argv[1]
outbox = sys.argv[2]
timeout_sec = int(sys.argv[3])

payload = {"ok": False, "errors": [], "data": {}}
if not QILING_AVAILABLE:
    payload["errors"].append("Qiling is not installed: " + QILING_ERROR)
    print(json.dumps(payload))
    sys.exit(0)

try:
    # Use default rootfs heuristic: same dir as sample, or common paths
    rootfs_candidates = [
        os.path.join(os.path.dirname(sample_path), "rootfs"),
        "/opt/qiling-rootfs",
        "C:\\\\qiling-rootfs",
    ]
    rootfs = None
    for cand in rootfs_candidates:
        if os.path.isdir(cand):
            rootfs = cand
            break
    if not rootfs:
        raise RuntimeError("Qiling rootfs not found. Searched: " + str(rootfs_candidates))

    ql = Qiling([sample_path], rootfs, verbose=QL_VERBOSE.OFF)
    # Run briefly
    import threading
    def timeout_stop():
        ql.emu_stop()
    t = threading.Timer(timeout_sec, timeout_stop)
    t.start()
    try:
        ql.run()
    finally:
        t.cancel()

    mem_map = []
    for m in ql.mem.get_mapinfo():
        mem_map.append({"start": hex(m[0]), "end": hex(m[1]), "perm": m[2], "label": m[3]})

    data = {
        "rootfs": rootfs,
        "arch": ql.archtype.name if hasattr(ql.archtype, "name") else str(ql.archtype),
        "os": ql.ostype.name if hasattr(ql.ostype, "name") else str(ql.ostype),
        "memory_map": mem_map,
    }
    payload["ok"] = True
    payload["data"] = data
except Exception as exc:
    payload["errors"].append(str(exc))
    payload["traceback"] = traceback.format_exc(limit=10)

print(json.dumps(payload))
`
  log(`Spawning qiling inspect for ${samplePath}`)
  return runPythonInline(script, [samplePath, outboxTaskDir, String(timeoutSec)], task, log, logs, onProgress, 'qiling')
}

export async function executePandaInspect(
  _task: ExecuteTask,
  _log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  return {
    ok: false,
    taskId: _task.taskId,
    errors: [`PANDA record/replay is not supported in the Windows Sandbox runtime. Consider using the Linux analyzer node for PANDA analysis.`],
    logs,
  }
}

export async function executeManagedSafeRun(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return { ok: false, taskId: task.taskId, errors: [`Sample file not found: ${samplePath}`], logs }
  }
  if (process.platform !== 'win32' && !(await checkCommandAvailable('dotnet'))) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: ['dotnet CLI is not available in the runtime environment. Install .NET SDK to run managed sandbox analysis on Linux.'],
      logs,
    }
  }
  const timeoutSec = Number(task.args.timeout_sec || 60)
  const memoryMb = Number(task.args.memory_mb || 512)
  const networkSinkhole = Boolean(task.args.network_sinkhole ?? true)
  const outboxTaskDir = path.join(config.runtime.outbox, task.taskId)

  const script = `
import json, sys, os, subprocess, traceback, time

sample_path = sys.argv[1]
timeout_sec = int(sys.argv[2])
memory_mb = int(sys.argv[3])
network_sinkhole = sys.argv[4].lower() == 'true'
outbox = sys.argv[5]

payload = {"ok": False, "errors": [], "data": {}}

try:
    # Best-effort managed sandbox: run under dotnet with AppDomain isolation
    # or direct process spawn with constrained job object on Windows.
    cmd = []
    if os.name == 'nt' and sample_path.lower().endswith('.exe'):
        # Use direct execution with timeout (Windows Sandbox isolates the process)
        cmd = [sample_path]
    else:
        cmd = ['dotnet', sample_path]

    env = os.environ.copy()
    if network_sinkhole:
        # Best-effort: point common proxy vars at non-routable address
        env['HTTP_PROXY'] = 'http://127.0.0.1:9'
        env['HTTPS_PROXY'] = 'http://127.0.0.1:9'

    start = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=os.path.dirname(sample_path))
    try:
        outs, errs = proc.communicate(timeout=timeout_sec)
        elapsed = time.time() - start
        payload["ok"] = True
        payload["data"] = {
            "exit_code": proc.returncode,
            "stdout": outs.decode('utf-8', errors='replace')[:10000],
            "stderr": errs.decode('utf-8', errors='replace')[:5000],
            "elapsed_sec": round(elapsed, 2),
            "network_sinkhole": network_sinkhole,
            "memory_limit_mb": memory_mb,
        }
    except subprocess.TimeoutExpired:
        proc.kill()
        outs, errs = proc.communicate()
        payload["ok"] = True
        payload["data"] = {
            "exit_code": None,
            "timed_out": True,
            "stdout": outs.decode('utf-8', errors='replace')[:5000],
            "stderr": errs.decode('utf-8', errors='replace')[:5000],
        }
except Exception as exc:
    payload["errors"].append(str(exc))
    payload["traceback"] = traceback.format_exc(limit=10)

print(json.dumps(payload))
`
  log(`Spawning managed safe run for ${samplePath} timeout=${timeoutSec}s memory=${memoryMb}MB`)
  return runPythonInline(script, [samplePath, String(timeoutSec), String(memoryMb), String(networkSinkhole), outboxTaskDir], task, log, logs, onProgress)
}

function quotePowerShellSingle(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

function parsePowerShellJsonArray(value: string): any[] {
  const trimmed = value.trim()
  if (!trimmed) {
    return []
  }
  try {
    const parsed = JSON.parse(trimmed)
    if (Array.isArray(parsed)) {
      return parsed
    }
    return parsed && typeof parsed === 'object' ? [parsed] : []
  } catch {
    return []
  }
}

async function runPowerShellJsonArray(taskId: string, script: string, timeoutMs = 10_000): Promise<any[]> {
  return new Promise<any[]>((resolve) => {
    const child = spawnProcess(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { stdio: ['ignore', 'pipe', 'pipe'], timeout: timeoutMs }
    )
    registerProcess(taskId, child)
    let stdout = ''
    child.stdout.on('data', (data) => {
      stdout += data.toString()
      if (stdout.length > 1_000_000) {
        stdout = stdout.slice(-1_000_000)
      }
    })
    child.on('error', () => resolve([]))
    child.on('close', () => resolve(parsePowerShellJsonArray(stdout)))
  })
}

function buildProcessSnapshotScript(): string {
  return [
    '$ErrorActionPreference = "SilentlyContinue"',
    'Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate | ConvertTo-Json -Depth 4 -Compress',
  ].join('; ')
}

function buildModuleSnapshotScript(pid: number): string {
  return [
    '$ErrorActionPreference = "SilentlyContinue"',
    `$p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue`,
    'if ($p) { $p.Modules | Select-Object ModuleName, FileName, BaseAddress, ModuleMemorySize | ConvertTo-Json -Depth 4 -Compress } else { @() | ConvertTo-Json -Compress }',
  ].join('; ')
}

function buildTcpConnectionSnapshotScript(pid: number): string {
  return [
    '$ErrorActionPreference = "SilentlyContinue"',
    `$rootPid = ${pid}`,
    '$processes = @(Get-CimInstance Win32_Process)',
    '$pids = @($rootPid)',
    'for ($i = 0; $i -lt 4; $i++) { $children = @($processes | Where-Object { $pids -contains ([int]$_.ParentProcessId) } | ForEach-Object { [int]$_.ProcessId }); $pids = @($pids + $children); $pids = @($pids | Select-Object -Unique) }',
    '$connections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $pids -contains ([int]$_.OwningProcess) } | Select-Object OwningProcess, State, LocalAddress, LocalPort, RemoteAddress, RemotePort, CreationTime)',
    '$connections | ConvertTo-Json -Depth 4 -Compress',
  ].join('; ')
}

function buildRecentFileSnapshotScript(paths: string[], startIso: string, maxEvents: number): string {
  const pathArray = paths.map(quotePowerShellSingle).join(', ')
  return [
    '$ErrorActionPreference = "SilentlyContinue"',
    `$start = [DateTime]::Parse(${quotePowerShellSingle(startIso)}).ToUniversalTime()`,
    `$roots = @(${pathArray}) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }`,
    '$items = foreach ($root in $roots) { Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -ge $start } | Select-Object FullName, Length, LastWriteTimeUtc }',
    `$items | Select-Object -First ${maxEvents} | ConvertTo-Json -Depth 4 -Compress`,
  ].join('; ')
}

function appendCapped(current: string, data: Buffer, limit: number): string {
  if (current.length >= limit) {
    return current
  }
  const next = current + data.toString()
  return next.length > limit ? next.slice(0, limit) : next
}

function normalizeProcessRow(row: any): Record<string, unknown> {
  return {
    pid: Number(row?.ProcessId ?? row?.process_id ?? row?.Id ?? 0) || null,
    parent_pid: Number(row?.ParentProcessId ?? row?.parent_pid ?? 0) || null,
    name: typeof row?.Name === 'string' ? row.Name : row?.ProcessName ?? null,
    image_path: typeof row?.ExecutablePath === 'string' ? row.ExecutablePath : row?.Path ?? null,
    command_line: typeof row?.CommandLine === 'string' ? row.CommandLine : null,
    creation_date: typeof row?.CreationDate === 'string' ? row.CreationDate : null,
  }
}

function normalizeModuleRow(row: any): Record<string, unknown> {
  return {
    module_name: typeof row?.ModuleName === 'string' ? row.ModuleName : null,
    path: typeof row?.FileName === 'string' ? row.FileName : null,
    base_address: row?.BaseAddress ? String(row.BaseAddress) : null,
    size: Number(row?.ModuleMemorySize ?? 0) || null,
  }
}

function normalizeFileRow(row: any): Record<string, unknown> {
  return {
    path: typeof row?.FullName === 'string' ? row.FullName : null,
    size: Number(row?.Length ?? 0) || 0,
    last_write_time_utc: typeof row?.LastWriteTimeUtc === 'string' ? row.LastWriteTimeUtc : row?.LastWriteTimeUtc ?? null,
  }
}

function normalizeNetworkRow(row: any): Record<string, unknown> {
  return {
    protocol: 'tcp',
    pid: Number(row?.OwningProcess ?? row?.pid ?? 0) || null,
    state: typeof row?.State === 'string' ? row.State : row?.State ? String(row.State) : null,
    local_address: typeof row?.LocalAddress === 'string' ? row.LocalAddress : null,
    local_port: Number(row?.LocalPort ?? 0) || null,
    remote_address: typeof row?.RemoteAddress === 'string' ? row.RemoteAddress : null,
    remote_port: Number(row?.RemotePort ?? 0) || null,
    creation_time: typeof row?.CreationTime === 'string' ? row.CreationTime : row?.CreationTime ?? null,
  }
}

function buildBehaviorCaptureTrace(payload: Record<string, any>): Record<string, unknown> {
  const modules = Array.isArray(payload.module_loads)
    ? payload.module_loads.map((entry: any) => entry.module_name || entry.path || '').filter(Boolean)
    : []
  const fileIndicators = Array.isArray(payload.file_events)
    ? payload.file_events.map((entry: any) => entry.path || '').filter(Boolean)
    : []
  const processIndicators = Array.isArray(payload.process_observations)
    ? payload.process_observations.map((entry: any) => entry.name || entry.image_path || '').filter(Boolean)
    : []
  const networkIndicators = Array.isArray(payload.network_events)
    ? payload.network_events
        .flatMap((entry: any) => [entry.remote_address, entry.remote_port ? `${entry.remote_address || ''}:${entry.remote_port}` : ''])
        .filter(Boolean)
    : []
  const stages = ['process_execution']
  if (fileIndicators.length > 0) stages.push('file_operations')
  if (modules.length > 0) stages.push('module_load_observation')
  if (networkIndicators.length > 0) stages.push('network_activity')
  if (payload.status === 'timeout') stages.push('long_running_or_stalled_execution')

  return {
    schema_version: '0.1.0',
    source_format: 'sandbox_trace',
    evidence_kind: 'trace',
    source_name: payload.task_id,
    source_mode: 'live_behavior_capture',
    imported_at: new Date().toISOString(),
    executed: payload.status === 'completed' || payload.status === 'timeout',
    raw_event_count:
      (Array.isArray(payload.process_observations) ? payload.process_observations.length : 0) +
      (Array.isArray(payload.file_events) ? payload.file_events.length : 0) +
      (Array.isArray(payload.module_loads) ? payload.module_loads.length : 0) +
      (Array.isArray(payload.network_events) ? payload.network_events.length : 0),
    api_calls: [],
    memory_regions: [],
    modules: Array.from(new Set(modules)).slice(0, 200),
    strings: Array.from(new Set([...fileIndicators, ...processIndicators, ...networkIndicators])).slice(0, 200),
    stages: Array.from(new Set(stages)),
    risk_hints: payload.status === 'timeout'
      ? ['The sample did not exit before the behavior-capture timeout.']
      : [],
    notes: [
      'Coarse behavior capture records process, module, file, network, stdout, and stderr observations. It is not a full ETW/Sysmon trace.',
    ],
  }
}

function writeBehaviorCaptureArtifact(task: ExecuteTask, payload: Record<string, unknown>): { name: string; path: string } | null {
  try {
    const outboxDir = ensureTaskOutboxDir(task.taskId)
    const artifactPath = path.join(outboxDir, 'behavior_capture.json')
    fs.writeFileSync(artifactPath, JSON.stringify(payload, null, 2), 'utf8')
    return { name: 'behavior_capture.json', path: artifactPath }
  } catch (err) {
    logger.warn({ err, taskId: task.taskId }, 'Failed to write behavior capture artifact')
    return null
  }
}

export type RuntimeToolCategory =
  | 'debugger'
  | 'dump'
  | 'telemetry'
  | 'network'
  | 'managed'
  | 'instrumentation'
  | 'manual-gui'
  | 'runtime'

interface RuntimeToolSpec {
  id: string
  displayName: string
  category: RuntimeToolCategory
  role: string
  filenames: string[]
  relativePaths: string[]
  installHint: string
  profiles: string[]
}

export interface RuntimeToolStatus {
  id: string
  displayName: string
  category: RuntimeToolCategory
  role: string
  available: boolean
  path: string | null
  source: string | null
  installHint: string
  profiles: string[]
}

export interface RuntimeToolProfile {
  id: string
  status: 'ready' | 'partial' | 'missing'
  requiredTools: string[]
  optionalTools: string[]
  availableTools: string[]
  missingTools: string[]
  recommendedTools: string[]
}

export interface RuntimeToolInventory {
  schema: 'rikune.runtime_tool_inventory.v1'
  generatedAt: string
  runtime: {
    platform: NodeJS.Platform
    mode: string
    toolSearchRoots: string[]
    pathEntries: string[]
  }
  tools: RuntimeToolStatus[]
  profiles: RuntimeToolProfile[]
  summary: {
    availableToolCount: number
    missingToolCount: number
    readyProfiles: string[]
    partialProfiles: string[]
    missingProfiles: string[]
  }
}

const RUNTIME_TOOL_SPECS: RuntimeToolSpec[] = [
  {
    id: 'cdb',
    displayName: 'CDB / Windows Debugger',
    category: 'debugger',
    role: 'Automated breakpoints, register/stack inspection, dumps on debugger events.',
    filenames: ['cdb.exe'],
    relativePaths: [
      'debuggers\\x64\\cdb.exe',
      'debuggers\\x86\\cdb.exe',
      'Windows Kits\\10\\Debuggers\\x64\\cdb.exe',
      'Windows Kits\\11\\Debuggers\\x64\\cdb.exe',
      'cdb.exe',
    ],
    installHint: 'Install Windows SDK Debugging Tools or mount cdb.exe under C:\\rikune-tools\\debuggers\\x64.',
    profiles: ['debugger_cdb', 'ttd_recording', 'memory_dump'],
  },
  {
    id: 'windbg',
    displayName: 'WinDbg',
    category: 'debugger',
    role: 'Manual debugger fallback and postmortem dump review.',
    filenames: ['windbg.exe', 'WinDbgX.exe'],
    relativePaths: [
      'debuggers\\x64\\windbg.exe',
      'Windows Kits\\10\\Debuggers\\x64\\windbg.exe',
      'Windows Kits\\11\\Debuggers\\x64\\windbg.exe',
      'windbg.exe',
      'WinDbgX.exe',
    ],
    installHint: 'Install WinDbg from Windows SDK or Microsoft Store, then expose it inside the runtime tool cache.',
    profiles: ['manual_gui_debug', 'memory_dump'],
  },
  {
    id: 'procdump',
    displayName: 'ProcDump',
    category: 'dump',
    role: 'Crash, timeout, and breakpoint-adjacent memory dump capture.',
    filenames: ['procdump64.exe', 'procdump.exe'],
    relativePaths: ['Sysinternals\\procdump64.exe', 'Sysinternals\\procdump.exe', 'procdump64.exe', 'procdump.exe'],
    installHint: 'Download Sysinternals ProcDump and place procdump64.exe in C:\\rikune-tools\\Sysinternals.',
    profiles: ['memory_dump', 'debugger_cdb'],
  },
  {
    id: 'procmon',
    displayName: 'Process Monitor',
    category: 'telemetry',
    role: 'File, registry, process, and network activity capture for ProcMon-grade traces.',
    filenames: ['Procmon64.exe', 'Procmon.exe'],
    relativePaths: ['Sysinternals\\Procmon64.exe', 'Sysinternals\\Procmon.exe', 'Procmon64.exe', 'Procmon.exe'],
    installHint: 'Download Sysinternals Process Monitor and place Procmon64.exe in C:\\rikune-tools\\Sysinternals.',
    profiles: ['procmon_capture', 'behavior_capture'],
  },
  {
    id: 'sysmon',
    displayName: 'Sysmon',
    category: 'telemetry',
    role: 'Process, network, image-load, registry, and file-create event telemetry.',
    filenames: ['Sysmon64.exe', 'Sysmon.exe'],
    relativePaths: ['Sysinternals\\Sysmon64.exe', 'Sysinternals\\Sysmon.exe', 'Sysmon64.exe', 'Sysmon.exe'],
    installHint: 'Download Sysinternals Sysmon and provide a sandbox-safe config before enabling service-backed capture.',
    profiles: ['sysmon_capture', 'behavior_capture'],
  },
  {
    id: 'ttd',
    displayName: 'Time Travel Debugging',
    category: 'debugger',
    role: 'Record/replay execution for deep manual debugging and branch replay.',
    filenames: ['TTD.exe', 'TTTracer.exe', 'TTDRecord.exe'],
    relativePaths: [
      'debuggers\\x64\\TTD.exe',
      'debuggers\\x64\\TTTracer.exe',
      'debuggers\\x64\\TTDRecord.exe',
      'TTD\\TTD.exe',
      'TTD\\TTTracer.exe',
      'TTD.exe',
    ],
    installHint: 'Install WinDbg Preview / Debugging Tools with TTD support or mount TTD tooling in C:\\rikune-tools.',
    profiles: ['ttd_recording'],
  },
  {
    id: 'x64dbg',
    displayName: 'x64dbg',
    category: 'manual-gui',
    role: 'Manual GUI debugger for retained Hyper-V or visible Sandbox review.',
    filenames: ['x64dbg.exe', 'x96dbg.exe'],
    relativePaths: ['x64dbg\\release\\x64\\x64dbg.exe', 'x64dbg\\x64dbg.exe', 'x96dbg.exe', 'x64dbg.exe'],
    installHint: 'Place x64dbg in the runtime tool cache when manual GUI debugging profiles are needed.',
    profiles: ['manual_gui_debug', 'anti_evasion'],
  },
  {
    id: 'dnspy',
    displayName: 'dnSpyEx',
    category: 'manual-gui',
    role: '.NET assembly inspection, edit-and-continue style manual debugging, and resource review.',
    filenames: ['dnSpy.exe', 'dnSpy.Console.exe'],
    relativePaths: ['dnSpy\\dnSpy.exe', 'dnSpyEx\\dnSpy.exe', 'dnSpy.exe'],
    installHint: 'Place dnSpyEx in the runtime tool cache for manual .NET debugging and resource review.',
    profiles: ['dotnet_runtime', 'manual_gui_debug'],
  },
  {
    id: 'frida',
    displayName: 'Frida CLI',
    category: 'instrumentation',
    role: 'Runtime API tracing, anti-analysis bypass hooks, and decrypted string capture.',
    filenames: ['frida.exe', 'frida-trace.exe', 'frida-ps.exe', 'frida'],
    relativePaths: ['frida\\frida.exe', 'frida\\frida-trace.exe', 'frida.exe', 'frida-trace.exe', 'frida'],
    installHint: 'Install frida-tools in the runtime Python environment or mount standalone Frida CLI binaries.',
    profiles: ['frida_runtime', 'anti_evasion', 'network_lab'],
  },
  {
    id: 'dotnet',
    displayName: '.NET SDK / Runtime',
    category: 'managed',
    role: 'Managed sample execution, .NET runtime inspection, and future CLRMD/dotnet-dump flows.',
    filenames: ['dotnet.exe', 'dotnet'],
    relativePaths: ['dotnet\\dotnet.exe', 'dotnet.exe', 'dotnet'],
    installHint: 'Install the .NET runtime/SDK in the Runtime Node when managed samples need native execution.',
    profiles: ['dotnet_runtime'],
  },
  {
    id: 'fakenet',
    displayName: 'FakeNet-NG',
    category: 'network',
    role: 'Network service emulation, DNS/HTTP capture, and malware traffic sinkholing.',
    filenames: ['fakenet.exe', 'fakenet.py', 'FakeNet-NG.exe'],
    relativePaths: ['FakeNet-NG\\fakenet.py', 'FakeNet-NG\\fakenet.exe', 'FakeNet-NG.exe', 'fakenet.py'],
    installHint: 'Install FakeNet-NG or expose a compatible fake-service harness in the runtime tool cache.',
    profiles: ['network_lab'],
  },
]

const RUNTIME_TOOL_PROFILE_DEFINITIONS: Array<{
  id: string
  requiredTools: string[]
  optionalTools: string[]
  recommendedTools: string[]
}> = [
  {
    id: 'behavior_capture',
    requiredTools: [],
    optionalTools: ['procmon', 'sysmon', 'frida', 'fakenet'],
    recommendedTools: ['dynamic.behavior.capture', 'dynamic.toolkit.status', 'dynamic.trace.import'],
  },
  {
    id: 'debugger_cdb',
    requiredTools: ['cdb'],
    optionalTools: ['procdump', 'windbg'],
    recommendedTools: ['runtime.debug.command', 'debug.session.inspect', 'debug.session.breakpoint', 'debug.session.snapshot'],
  },
  {
    id: 'memory_dump',
    requiredTools: [],
    optionalTools: ['procdump', 'cdb', 'windbg'],
    recommendedTools: ['dynamic.memory_dump', 'runtime.debug.command'],
  },
  {
    id: 'procmon_capture',
    requiredTools: ['procmon'],
    optionalTools: [],
    recommendedTools: ['dynamic.behavior.capture'],
  },
  {
    id: 'sysmon_capture',
    requiredTools: ['sysmon'],
    optionalTools: [],
    recommendedTools: ['dynamic.behavior.capture'],
  },
  {
    id: 'ttd_recording',
    requiredTools: ['cdb', 'ttd'],
    optionalTools: ['windbg'],
    recommendedTools: ['runtime.debug.command'],
  },
  {
    id: 'network_lab',
    requiredTools: [],
    optionalTools: ['fakenet', 'frida'],
    recommendedTools: ['debug.network.plan', 'dynamic.behavior.capture', 'debug.telemetry.plan', 'dynamic.trace.import'],
  },
  {
    id: 'dotnet_runtime',
    requiredTools: ['dotnet'],
    optionalTools: ['dnspy'],
    recommendedTools: ['debug.managed.plan', 'runtime.debug.command', 'managed.safe_run', 'debug.gui.handoff'],
  },
  {
    id: 'manual_gui_debug',
    requiredTools: [],
    optionalTools: ['x64dbg', 'dnspy', 'windbg'],
    recommendedTools: ['debug.gui.handoff', 'runtime.debug.session.start', 'runtime.hyperv.control'],
  },
  {
    id: 'anti_evasion',
    requiredTools: [],
    optionalTools: ['frida', 'x64dbg'],
    recommendedTools: ['dynamic.auto_hook', 'frida.script.generate', 'runtime.debug.command'],
  },
]

function splitEnvList(value: string | undefined): string[] {
  if (!value) {
    return []
  }
  const separator = process.platform === 'win32' ? /[;\n\r]+/u : /[:;\n\r]+/u
  return value
    .split(separator)
    .map((entry) => entry.trim())
    .filter(Boolean)
}

function runtimeToolSearchRoots(): string[] {
  const roots = [
    ...splitEnvList(process.env.RUNTIME_TOOL_DIRS),
    process.env.RUNTIME_TOOL_CACHE_DIR,
    process.env.RIKUNE_RUNTIME_TOOLS,
    process.env.RIKUNE_TOOL_CACHE_DIR,
    'C:\\rikune-tools',
    'C:\\Tools',
    'C:\\ProgramData\\Rikune\\tools',
    'C:\\Program Files',
    'C:\\Program Files (x86)',
    path.join(process.cwd(), 'tools'),
    '/opt/rikune-tools',
    '/usr/local/rikune-tools',
  ].filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
  return Array.from(new Set(roots.map((entry) => path.resolve(entry))))
}

function runtimePathEntries(): string[] {
  return (process.env.PATH || '')
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean)
}

function findExecutableOnPath(filenames: string[]): { path: string; source: string } | null {
  for (const dir of runtimePathEntries()) {
    for (const filename of filenames) {
      const candidate = path.join(dir, filename)
      if (fs.existsSync(candidate)) {
        return { path: candidate, source: 'PATH' }
      }
    }
  }
  return null
}

function findRuntimeTool(spec: RuntimeToolSpec): { path: string; source: string } | null {
  for (const root of runtimeToolSearchRoots()) {
    for (const relativePath of spec.relativePaths) {
      const candidate = path.join(root, relativePath)
      if (fs.existsSync(candidate)) {
        return { path: candidate, source: root }
      }
    }
  }

  const pathMatch = findExecutableOnPath(spec.filenames)
  if (pathMatch) {
    return pathMatch
  }

  if (spec.id === 'python') {
    const pythonPath = config.runtime.pythonPath
    if (pythonPath && fs.existsSync(pythonPath)) {
      return { path: pythonPath, source: 'runtime.pythonPath' }
    }
  }
  return null
}

function buildRuntimeToolProfiles(tools: RuntimeToolStatus[]): RuntimeToolProfile[] {
  const available = new Set(tools.filter((tool) => tool.available).map((tool) => tool.id))
  return RUNTIME_TOOL_PROFILE_DEFINITIONS.map((profile) => {
    const requiredAvailable = profile.requiredTools.filter((tool) => available.has(tool))
    const optionalAvailable = profile.optionalTools.filter((tool) => available.has(tool))
    const missingTools = [...profile.requiredTools, ...profile.optionalTools].filter((tool) => !available.has(tool))
    let status: RuntimeToolProfile['status'] = 'missing'
    if (profile.requiredTools.length === 0) {
      status = optionalAvailable.length > 0 || profile.optionalTools.length === 0 ? 'ready' : 'partial'
    } else if (requiredAvailable.length === profile.requiredTools.length) {
      status = 'ready'
    } else if (requiredAvailable.length > 0 || optionalAvailable.length > 0) {
      status = 'partial'
    }

    return {
      id: profile.id,
      status,
      requiredTools: profile.requiredTools,
      optionalTools: profile.optionalTools,
      availableTools: [...requiredAvailable, ...optionalAvailable],
      missingTools,
      recommendedTools: profile.recommendedTools,
    }
  })
}

export function buildRuntimeToolInventory(): RuntimeToolInventory {
  const tools = RUNTIME_TOOL_SPECS.map((spec): RuntimeToolStatus => {
    const match = findRuntimeTool(spec)
    return {
      id: spec.id,
      displayName: spec.displayName,
      category: spec.category,
      role: spec.role,
      available: Boolean(match),
      path: match?.path ?? null,
      source: match?.source ?? null,
      installHint: spec.installHint,
      profiles: spec.profiles,
    }
  })
  const profiles = buildRuntimeToolProfiles(tools)
  return {
    schema: 'rikune.runtime_tool_inventory.v1',
    generatedAt: new Date().toISOString(),
    runtime: {
      platform: process.platform,
      mode: config.runtime.mode,
      toolSearchRoots: runtimeToolSearchRoots(),
      pathEntries: runtimePathEntries(),
    },
    tools,
    profiles,
    summary: {
      availableToolCount: tools.filter((tool) => tool.available).length,
      missingToolCount: tools.filter((tool) => !tool.available).length,
      readyProfiles: profiles.filter((profile) => profile.status === 'ready').map((profile) => profile.id),
      partialProfiles: profiles.filter((profile) => profile.status === 'partial').map((profile) => profile.id),
      missingProfiles: profiles.filter((profile) => profile.status === 'missing').map((profile) => profile.id),
    },
  }
}

export async function executeRuntimeToolProbe(
  task: ExecuteTask,
  _log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  onProgress?.(0.2, 'Inspecting runtime tool cache')
  const inventory = buildRuntimeToolInventory()
  onProgress?.(1, 'Runtime tool probe completed')
  const artifact = writeRuntimeToolInventoryArtifact(task, inventory)
  return {
    ok: true,
    taskId: task.taskId,
    result: {
      ok: true,
      data: inventory,
      artifacts: artifact ? [artifact] : undefined,
      metrics: { tool: task.tool },
    },
    logs,
    artifactRefs: artifact ? [artifact] : undefined,
  }
}

function writeRuntimeToolInventoryArtifact(
  task: ExecuteTask,
  inventory: RuntimeToolInventory
): { name: string; path: string } | null {
  try {
    const outboxDir = ensureTaskOutboxDir(task.taskId)
    const inventoryPath = path.join(outboxDir, 'runtime_tool_inventory.json')
    fs.writeFileSync(inventoryPath, JSON.stringify(inventory, null, 2), 'utf8')
    return { name: 'runtime_tool_inventory.json', path: inventoryPath }
  } catch (err) {
    logger.warn({ err, taskId: task.taskId }, 'Failed to write runtime tool inventory artifact')
    return null
  }
}

export async function executeBehaviorCapture(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const uploadedSample = resolveTaskSample(task.taskId)
  const samplePath = uploadedSample.samplePath
  if (!fs.existsSync(samplePath)) {
    return { ok: false, taskId: task.taskId, errors: [`Sample file not found: ${samplePath}`], logs }
  }

  const timeoutSec = Math.max(5, Math.min(Number(task.args.timeout_sec || 30), 300))
  const timeoutMs = timeoutSec * 1000
  const commandArgs = readStringArrayArg(task.args, 'arguments', 'args')
  const networkSinkhole = Boolean(task.args.network_sinkhole ?? true)
  const captureModules = task.args.capture_modules !== false
  const captureFileSnapshot = task.args.capture_file_snapshot !== false
  const captureNetworkSnapshot = task.args.capture_network_snapshot !== false
  const maxEvents = Math.max(10, Math.min(Number(task.args.max_events || 500), 5000))
  const startedAt = new Date().toISOString()

  if (process.platform !== 'win32') {
    const payload: Record<string, unknown> = {
      schema: 'rikune.behavior_capture.v1',
      task_id: task.taskId,
      sample_id: task.sampleId,
      tool: task.tool,
      status: 'unsupported',
      backend: process.platform,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      errors: ['dynamic.behavior.capture currently requires a Windows Runtime Node such as Windows Sandbox or Hyper-V VM.'],
    }
    const artifact = writeBehaviorCaptureArtifact(task, payload)
    return {
      ok: false,
      taskId: task.taskId,
      result: {
        ok: false,
        data: payload,
        errors: payload.errors as string[],
        artifacts: artifact ? [artifact] : undefined,
        metrics: { elapsed_ms: 0, tool: task.tool },
      },
      logs,
      errors: payload.errors as string[],
      artifactRefs: artifact ? [artifact] : undefined,
    }
  }

  onProgress?.(0.05, 'Capturing baseline process snapshot')
  const beforeProcesses = await runPowerShellJsonArray(task.taskId, buildProcessSnapshotScript())
  const beforePidSet = new Set(
    beforeProcesses
      .map((row) => Number(row?.ProcessId ?? 0))
      .filter((pid) => Number.isFinite(pid) && pid > 0)
  )
  const env = { ...process.env }
  if (networkSinkhole) {
    env.HTTP_PROXY = 'http://127.0.0.1:9'
    env.HTTPS_PROXY = 'http://127.0.0.1:9'
  }

  let stdout = ''
  let stderr = ''
  let exitCode: number | null = null
  let signal: NodeJS.Signals | null = null
  let timedOut = false
  let spawnError: string | null = null
  let childPid: number | null = null
  let moduleRows: any[] = []
  let networkRows: any[] = []

  log(`Starting behavior capture for ${samplePath} timeout=${timeoutSec}s`)
  if (uploadedSample.sidecars.length > 0) {
    log(`Staged ${uploadedSample.sidecars.length} sidecar file(s): ${uploadedSample.sidecars.map((entry) => entry.name).join(', ')}`)
  }
  onProgress?.(0.2, 'Launching sample inside runtime node')

  const child = spawnProcess(samplePath, commandArgs, {
    cwd: path.dirname(samplePath),
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  registerProcess(task.taskId, child)
  childPid = child.pid ?? null
  child.stdout.on('data', (data: Buffer) => { stdout = appendCapped(stdout, data, 20_000) })
  child.stderr.on('data', (data: Buffer) => { stderr = appendCapped(stderr, data, 10_000) })

  const childClosed = new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      timedOut = true
      if (childPid) {
        const killer = spawnProcess('taskkill.exe', ['/PID', String(childPid), '/T', '/F'], { stdio: 'ignore' })
        registerProcess(task.taskId, killer)
      }
      child.kill('SIGKILL')
    }, timeoutMs)

    child.once('error', (error) => {
      spawnError = error.message
      clearTimeout(timer)
      resolve()
    })
    child.once('close', (code, childSignal) => {
      clearTimeout(timer)
      exitCode = code
      signal = childSignal
      resolve()
    })
  })

  if (captureModules && childPid) {
    await new Promise((resolve) => setTimeout(resolve, Math.min(1500, Math.max(250, timeoutMs / 5))))
    onProgress?.(0.45, 'Capturing module snapshot')
    moduleRows = await runPowerShellJsonArray(task.taskId, buildModuleSnapshotScript(childPid), 10_000)
  }
  if (captureNetworkSnapshot && childPid) {
    onProgress?.(0.55, 'Capturing TCP connection snapshot')
    networkRows = await runPowerShellJsonArray(task.taskId, buildTcpConnectionSnapshotScript(childPid), 10_000)
  }

  await childClosed

  onProgress?.(0.75, 'Capturing final process and file observations')
  const afterProcesses = await runPowerShellJsonArray(task.taskId, buildProcessSnapshotScript())
  const newProcesses = afterProcesses
    .filter((row) => {
      const pid = Number(row?.ProcessId ?? 0)
      return Number.isFinite(pid) && pid > 0 && !beforePidSet.has(pid)
    })
    .slice(0, maxEvents)
    .map(normalizeProcessRow)

  const fileRows = captureFileSnapshot
    ? await runPowerShellJsonArray(
        task.taskId,
        buildRecentFileSnapshotScript(
          Array.from(new Set([
            path.dirname(samplePath),
            ensureTaskOutboxDir(task.taskId),
            process.env.TEMP || '',
          ].filter(Boolean))),
          startedAt,
          maxEvents
        ),
        20_000
      )
    : []

  const finishedAt = new Date().toISOString()
  const payload: Record<string, any> = {
    schema: 'rikune.behavior_capture.v1',
    task_id: task.taskId,
    sample_id: task.sampleId,
    tool: task.tool,
    status: spawnError ? 'failed' : timedOut ? 'timeout' : 'completed',
    backend: 'windows-runtime-node',
    started_at: startedAt,
    finished_at: finishedAt,
    timeout_sec: timeoutSec,
    command: {
      executable: samplePath,
      working_directory: uploadedSample.workingDir,
      arguments: commandArgs,
      pid: childPid,
      exit_code: exitCode,
      signal,
      timed_out: timedOut,
      network_sinkhole: networkSinkhole,
    },
    sidecars: uploadedSample.sidecars.map((entry) => ({
      name: entry.name,
      path: entry.path,
      size: entry.size ?? null,
    })),
    stdout,
    stderr,
    process_observations: newProcesses,
    module_loads: moduleRows.slice(0, maxEvents).map(normalizeModuleRow),
    file_events: fileRows.slice(0, maxEvents).map(normalizeFileRow),
    registry_events: [],
    network_events: [
      ...networkRows.slice(0, maxEvents).map(normalizeNetworkRow),
      ...(networkSinkhole
        ? [{ policy: 'sinkhole', note: 'HTTP_PROXY/HTTPS_PROXY pointed at 127.0.0.1:9 for this process.' }]
        : []),
    ],
    summary: {
      process_count: newProcesses.length,
      module_count: moduleRows.length,
      file_event_count: fileRows.length,
      registry_event_count: 0,
      network_event_count: networkRows.length + (networkSinkhole ? 1 : 0),
    },
    warnings: [
      'Behavior capture is coarse and best-effort. Use Frida, ProcMon/ETW, or a debugger for complete API-level evidence.',
    ],
    errors: spawnError ? [spawnError] : [],
  }
  payload.normalized_trace = buildBehaviorCaptureTrace(payload)

  const artifact = writeBehaviorCaptureArtifact(task, payload)
  onProgress?.(1, 'Behavior capture completed')

  return {
    ok: !spawnError,
    taskId: task.taskId,
    result: {
      ok: !spawnError,
      data: payload,
      errors: spawnError ? [spawnError] : undefined,
      warnings: payload.warnings,
      artifacts: artifact ? [artifact] : undefined,
      metrics: {
        elapsed_ms: new Date(finishedAt).getTime() - new Date(startedAt).getTime(),
        tool: task.tool,
      },
    },
    logs,
    errors: spawnError ? [spawnError] : undefined,
    artifactRefs: artifact ? [artifact] : undefined,
  }
}

function findCdbPath(): string | null {
  const toolCacheMatch = findRuntimeTool(RUNTIME_TOOL_SPECS.find((spec) => spec.id === 'cdb')!)
  if (toolCacheMatch) {
    return toolCacheMatch.path
  }
  const candidates = [
    'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe',
    'C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe',
    'C:\\Program Files (x86)\\Windows Kits\\11\\Debuggers\\x64\\cdb.exe',
    'C:\\Program Files\\Windows Kits\\11\\Debuggers\\x64\\cdb.exe',
  ]
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  return null
}

function findProcDumpPath(): string | null {
  const toolCacheMatch = findRuntimeTool(RUNTIME_TOOL_SPECS.find((spec) => spec.id === 'procdump')!)
  if (toolCacheMatch) {
    return toolCacheMatch.path
  }
  return null
}

function findProcMonPath(): string | null {
  const toolCacheMatch = findRuntimeTool(RUNTIME_TOOL_SPECS.find((spec) => spec.id === 'procmon')!)
  return toolCacheMatch?.path ?? null
}

function findSysmonPath(): string | null {
  const toolCacheMatch = findRuntimeTool(RUNTIME_TOOL_SPECS.find((spec) => spec.id === 'sysmon')!)
  return toolCacheMatch?.path ?? null
}

const DEBUG_STDOUT_LIMIT = 20_000
const DEBUG_STDERR_LIMIT = 5_000

function ensureTaskOutboxDir(taskId: string): string {
  const outboxDir = path.join(config.runtime.outbox, taskId)
  if (!fs.existsSync(outboxDir)) {
    fs.mkdirSync(outboxDir, { recursive: true })
  }
  return outboxDir
}

function writeDebugSessionTranscript(
  task: ExecuteTask,
  payload: Record<string, unknown>
): { name: string; path: string } | null {
  try {
    const outboxDir = ensureTaskOutboxDir(task.taskId)
    const transcriptPath = path.join(outboxDir, 'debug_session_trace.json')
    fs.writeFileSync(
      transcriptPath,
      JSON.stringify(
        {
          schema: 'rikune.debug_session_trace.v1',
          task_id: task.taskId,
          sample_id: task.sampleId,
          tool: task.tool,
          created_at: new Date().toISOString(),
          ...payload,
        },
        null,
        2
      ),
      'utf8'
    )
    return { name: 'debug_session_trace.json', path: transcriptPath }
  } catch (err) {
    logger.warn({ err, taskId: task.taskId }, 'Failed to write debug-session transcript')
    return null
  }
}

function collectDebugSessionArtifactRefs(taskId: string, refs: Array<{ name: string; path: string } | null>): { name: string; path: string }[] {
  const outboxDir = ensureTaskOutboxDir(taskId)
  const collected = refs.filter((entry): entry is { name: string; path: string } => Boolean(entry))
  const snapshotDump = path.join(outboxDir, 'debug_snapshot.dmp')
  if (fs.existsSync(snapshotDump)) {
    collected.push({ name: 'debug_snapshot.dmp', path: snapshotDump })
  }
  return collected
}

function readCdbCommandBatch(args: Record<string, unknown>): string[] {
  const rawCommands = readStringArrayArg(args, 'commands', 'cdb_commands')
  const fallbackCommand = typeof args.command === 'string' && args.command.trim().length > 0
    ? [args.command]
    : []
  const commands = (rawCommands.length > 0 ? rawCommands : fallbackCommand)
    .map((command) => command.replace(/\0/g, '').trim())
    .filter((command) => command.length > 0)
    .slice(0, 64)
    .map((command) => command.slice(0, 600))

  if (commands.length === 0) {
    return ['q']
  }
  const hasQuit = commands.some((command) => /^q(?:uit)?\b/i.test(command))
  return hasQuit ? commands : [...commands, 'q']
}

function readNumberArg(args: Record<string, unknown>, key: string, fallback: number): number {
  const value = args[key]
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value
  }
  if (typeof value === 'string') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) {
      return parsed
    }
  }
  return fallback
}

function safeDumpFilename(value: unknown, fallback: string): string {
  const raw = typeof value === 'string' && value.trim().length > 0 ? value.trim() : fallback
  const basename = path.basename(raw.replace(/\\/g, '/')).replace(/[<>:"|?*\x00-\x1f]/g, '_')
  return basename.toLowerCase().endsWith('.dmp') ? basename : `${basename || fallback}.dmp`
}

function writeProcDumpCaptureArtifact(
  task: ExecuteTask,
  payload: Record<string, unknown>
): { name: string; path: string } | null {
  try {
    const outboxDir = ensureTaskOutboxDir(task.taskId)
    const artifactPath = path.join(outboxDir, 'procdump_capture.json')
    fs.writeFileSync(
      artifactPath,
      JSON.stringify(
        {
          schema: 'rikune.procdump_capture.v1',
          task_id: task.taskId,
          sample_id: task.sampleId,
          tool: task.tool,
          created_at: new Date().toISOString(),
          ...payload,
        },
        null,
        2
      ),
      'utf8'
    )
    return { name: 'procdump_capture.json', path: artifactPath }
  } catch (err) {
    logger.warn({ err, taskId: task.taskId }, 'Failed to write ProcDump capture artifact')
    return null
  }
}

function collectProcDumpArtifactRefs(
  taskId: string,
  refs: Array<{ name: string; path: string } | null>
): { name: string; path: string }[] {
  const outboxDir = ensureTaskOutboxDir(taskId)
  const collected = refs.filter((entry): entry is { name: string; path: string } => Boolean(entry))
  try {
    const existing = new Set(collected.map((entry) => path.resolve(entry.path)))
    for (const entry of fs.readdirSync(outboxDir)) {
      if (!entry.toLowerCase().endsWith('.dmp')) {
        continue
      }
      const dumpPath = path.join(outboxDir, entry)
      const key = path.resolve(dumpPath)
      if (!existing.has(key)) {
        existing.add(key)
        collected.push({ name: entry, path: dumpPath })
      }
    }
  } catch {
    // Best-effort artifact discovery.
  }
  return collected
}

function writeTelemetryCaptureArtifact(
  task: ExecuteTask,
  payload: Record<string, unknown>
): { name: string; path: string } | null {
  try {
    const outboxDir = ensureTaskOutboxDir(task.taskId)
    const artifactPath = path.join(outboxDir, 'telemetry_capture.json')
    fs.writeFileSync(
      artifactPath,
      JSON.stringify(
        {
          schema: 'rikune.telemetry_capture.v1',
          task_id: task.taskId,
          sample_id: task.sampleId,
          tool: task.tool,
          created_at: new Date().toISOString(),
          ...payload,
        },
        null,
        2
      ),
      'utf8'
    )
    return { name: 'telemetry_capture.json', path: artifactPath }
  } catch (err) {
    logger.warn({ err, taskId: task.taskId }, 'Failed to write telemetry capture artifact')
    return null
  }
}

function collectTelemetryArtifactRefs(
  taskId: string,
  refs: Array<{ name: string; path: string } | null>
): { name: string; path: string }[] {
  const outboxDir = ensureTaskOutboxDir(taskId)
  const collected = refs.filter((entry): entry is { name: string; path: string } => Boolean(entry))
  const seen = new Set(collected.map((entry) => path.resolve(entry.path)))
  try {
    for (const entry of fs.readdirSync(outboxDir)) {
      if (!/\.(pml|etl|json|xml|csv)$/i.test(entry)) {
        continue
      }
      const artifactPath = path.join(outboxDir, entry)
      const key = path.resolve(artifactPath)
      if (seen.has(key)) {
        continue
      }
      seen.add(key)
      collected.push({ name: entry, path: artifactPath })
    }
  } catch {
    // Best-effort artifact discovery.
  }
  return collected
}

function readTelemetryProfiles(args: Record<string, unknown>): string[] {
  const raw = readStringArrayArg(args, 'profiles', 'telemetry_profiles')
  const profiles = raw.length > 0 ? raw : ['powershell_eventlog']
  const expanded = profiles.includes('all')
    ? ['procmon', 'sysmon', 'etw_process', 'etw_dns', 'powershell_eventlog']
    : profiles
  return Array.from(new Set(expanded.map((profile) => profile.trim()).filter(Boolean)))
}

function buildEventLogSnapshotScript(startedAt: string, outputPath: string, maxEvents: number): string {
  const logs = [
    'System',
    'Application',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
  ]
  return [
    '$ErrorActionPreference = "SilentlyContinue"',
    `$start = [DateTime]::Parse(${quotePowerShellSingle(startedAt)})`,
    `$logs = @(${logs.map(quotePowerShellSingle).join(', ')})`,
    '$events = foreach ($log in $logs) {',
    '  Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$start} -ErrorAction SilentlyContinue |',
    `    Select-Object -First ${Math.max(1, maxEvents)} LogName, Id, ProviderName, LevelDisplayName, TimeCreated, Message`,
    '}',
    `$events | Select-Object -First ${Math.max(1, maxEvents)} | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath ${quotePowerShellSingle(outputPath)} -Encoding UTF8`,
  ].join('; ')
}

function runRuntimeCommand(taskId: string, command: string, args: string[], timeoutMs: number, cwd?: string): Promise<{ code: number | null; stdout: string; stderr: string; error?: string }> {
  return new Promise((resolve) => {
    const child = spawnProcess(command, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs,
      cwd,
      windowsHide: true,
    })
    registerProcess(taskId, child)
    let stdout = ''
    let stderr = ''
    let settled = false
    const finish = (result: { code: number | null; stdout: string; stderr: string; error?: string }) => {
      if (settled) return
      settled = true
      resolve(result)
    }
    child.stdout.on('data', (data) => { stdout = appendCapped(stdout, data, DEBUG_STDOUT_LIMIT) })
    child.stderr.on('data', (data) => { stderr = appendCapped(stderr, data, DEBUG_STDERR_LIMIT) })
    child.on('error', (error) => finish({ code: null, stdout, stderr, error: error.message }))
    child.on('close', (code) => finish({ code, stdout, stderr }))
  })
}

async function runTelemetrySampleWindow(task: ExecuteTask, timeoutSec: number): Promise<Record<string, unknown> | null> {
  const samplePath = resolveTaskSamplePath(task.taskId)
  const hasSample = fs.existsSync(samplePath)
  if (!hasSample) {
    if (timeoutSec > 0) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(timeoutSec * 1000, 5000)))
    }
    return null
  }
  const commandArgs = readStringArrayArg(task.args, 'arguments', 'args', 'sample_args')
  const result = await runRuntimeCommand(task.taskId, samplePath, commandArgs, Math.max(1000, timeoutSec * 1000), path.dirname(samplePath))
  return {
    executable: samplePath,
    arguments: commandArgs,
    exit_code: result.code,
    stdout: result.stdout,
    stderr: result.stderr,
    error: result.error || null,
  }
}

function buildProcDumpArgs(
  task: ExecuteTask,
  outboxDir: string
): { args: string[]; samplePath?: string; mode: string; dumpPath?: string; cwd?: string; error?: string } {
  const mode = String(task.args.mode || 'launch_crash')
  const dumpType = String(task.args.dump_type || 'full') === 'mini' ? '-mm' : '-ma'
  const extraArgs = readStringArrayArg(task.args, 'arguments', 'sample_args')

  if (mode === 'pid_snapshot') {
    const pid = readNumberArg(task.args, 'pid', 0)
    if (!pid || pid < 1) {
      return { args: [], mode, error: 'pid_snapshot mode requires args.pid.' }
    }
    const dumpPath = path.join(outboxDir, safeDumpFilename(task.args.dump_name, `procdump_pid_${pid}.dmp`))
    return {
      args: ['-accepteula', dumpType, String(Math.trunc(pid)), dumpPath],
      mode,
      dumpPath,
    }
  }

  const samplePath = resolveTaskSamplePath(task.taskId)
  if (!fs.existsSync(samplePath)) {
    return { args: [], mode, error: `Sample file not found: ${samplePath}` }
  }

  const args = ['-accepteula', dumpType]
  if (mode === 'launch_crash') {
    args.push('-e')
  } else if (mode === 'launch_first_chance') {
    args.push('-e', '1')
  } else if (mode === 'launch_timeout') {
    const seconds = Math.max(1, Math.min(3600, Math.trunc(readNumberArg(task.args, 'seconds', 30))))
    const dumpCount = Math.max(1, Math.min(64, Math.trunc(readNumberArg(task.args, 'max_dumps', 1))))
    args.push('-s', String(seconds), '-n', String(dumpCount))
  }
  args.push('-x', outboxDir, samplePath, ...extraArgs)
  return {
    args,
    samplePath,
    mode,
    cwd: path.dirname(samplePath),
  }
}

export async function executeProcDumpCapture(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const procdumpPath = findProcDumpPath()
  if (!procdumpPath) {
    const artifact = writeProcDumpCaptureArtifact(task, {
      status: 'setup_required',
      failure_category: 'missing_procdump',
      errors: ['Sysinternals ProcDump was not found in the runtime environment.'],
      install_hint: 'Place procdump64.exe or procdump.exe in C:\\rikune-tools\\Sysinternals or another configured runtime tool cache path.',
    })
    return {
      ok: false,
      taskId: task.taskId,
      errors: ['ProcDump was not found in the runtime environment.'],
      logs,
      artifactRefs: collectProcDumpArtifactRefs(task.taskId, [artifact]),
    }
  }

  const outboxDir = ensureTaskOutboxDir(task.taskId)
  const plan = buildProcDumpArgs(task, outboxDir)
  if (plan.error) {
    const artifact = writeProcDumpCaptureArtifact(task, {
      status: 'failed',
      failure_category: 'invalid_request',
      mode: plan.mode,
      errors: [plan.error],
    })
    return {
      ok: false,
      taskId: task.taskId,
      errors: [plan.error],
      logs,
      artifactRefs: collectProcDumpArtifactRefs(task.taskId, [artifact]),
    }
  }

  onProgress?.(0.2, 'Starting ProcDump capture')
  log(`Spawning ProcDump mode=${plan.mode}`)

  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(procdumpPath, plan.args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: task.timeoutMs,
      cwd: plan.cwd,
      windowsHide: true,
    })
    registerProcess(task.taskId, child)
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (data) => { stdout = appendCapped(stdout, data, DEBUG_STDOUT_LIMIT) })
    child.stderr.on('data', (data) => { stderr = appendCapped(stderr, data, DEBUG_STDERR_LIMIT) })
    child.on('error', (error) => {
      const artifact = writeProcDumpCaptureArtifact(task, {
        status: 'failed',
        failure_category: 'process_error',
        mode: plan.mode,
        procdump_path: procdumpPath,
        procdump_args: plan.args,
        errors: [error.message],
      })
      resolve({
        ok: false,
        taskId: task.taskId,
        errors: [error.message],
        logs,
        artifactRefs: collectProcDumpArtifactRefs(task.taskId, [artifact]),
      })
    })
    child.on('close', (code) => {
      onProgress?.(1, 'ProcDump capture completed')
      const dumpRefs = collectProcDumpArtifactRefs(task.taskId, [])
      const dumpFiles = dumpRefs
        .filter((entry) => entry.name.toLowerCase().endsWith('.dmp'))
        .map((entry) => ({
          name: entry.name,
          path: entry.path,
          size: fs.existsSync(entry.path) ? fs.statSync(entry.path).size : null,
        }))
      const artifact = writeProcDumpCaptureArtifact(task, {
        status: code === 0 || dumpFiles.length > 0 ? 'completed' : 'failed',
        mode: plan.mode,
        sample_path: plan.samplePath || null,
        dump_path: plan.dumpPath || null,
        procdump_path: procdumpPath,
        procdump_args: plan.args,
        exit_code: code,
        stdout,
        stderr,
        dump_files: dumpFiles,
        safety_budgets: {
          timeout_ms: task.timeoutMs,
          stdout_limit: DEBUG_STDOUT_LIMIT,
          stderr_limit: DEBUG_STDERR_LIMIT,
        },
      })
      const artifactRefs = collectProcDumpArtifactRefs(task.taskId, [artifact])
      const ok = code === 0 || dumpFiles.length > 0
      resolve({
        ok,
        taskId: task.taskId,
        result: {
          ok,
          data: {
            status: ok ? 'completed' : 'failed',
            mode: plan.mode,
            dump_files: dumpFiles,
            stdout,
            stderr,
            exit_code: code,
            metadata_artifact: artifact,
          },
          artifacts: artifactRefs,
          metrics: { tool: task.tool },
        },
        errors: ok ? undefined : [`ProcDump exited with code ${code} and no dump files were found.`],
        logs: [...logs, stdout, stderr].filter(Boolean),
        artifactRefs,
      })
    })
  })
}

export async function executeTelemetryCapture(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const startedAt = new Date().toISOString()
  const outboxDir = ensureTaskOutboxDir(task.taskId)
  const profiles = readTelemetryProfiles(task.args)
  const timeoutSec = Math.max(0, Math.min(3600, Math.trunc(readNumberArg(task.args, 'capture_seconds', 30))))
  const maxEvents = Math.max(1, Math.min(20_000, Math.trunc(readNumberArg(task.args, 'max_events', 1000))))
  const includeCleanup = task.args.include_cleanup !== false

  if (process.platform !== 'win32') {
    const artifact = writeTelemetryCaptureArtifact(task, {
      status: 'unsupported',
      backend: process.platform,
      profiles,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      errors: ['debug.telemetry.capture currently requires a Windows Runtime Node.'],
    })
    return {
      ok: false,
      taskId: task.taskId,
      errors: ['debug.telemetry.capture currently requires a Windows Runtime Node.'],
      logs,
      artifactRefs: collectTelemetryArtifactRefs(task.taskId, [artifact]),
    }
  }

  const profileResults: Record<string, unknown>[] = []
  const errors: string[] = []
  const warnings: string[] = []
  const cleanupCommands: Array<() => Promise<Record<string, unknown>>> = []

  onProgress?.(0.1, 'Preparing telemetry collectors')

  for (const profile of profiles) {
    if (profile === 'procmon') {
      const procmonPath = findProcMonPath()
      if (!procmonPath) {
        warnings.push('ProcMon was requested but Procmon64.exe/Procmon.exe was not found in the runtime tool cache.')
        profileResults.push({ profile, status: 'setup_required', missing_tool: 'procmon' })
        continue
      }
      const pmlPath = path.join(outboxDir, 'procmon_capture.pml')
      const start = await runRuntimeCommand(
        task.taskId,
        procmonPath,
        ['/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', pmlPath],
        15_000,
        outboxDir
      )
      profileResults.push({ profile, status: start.code === 0 ? 'started' : 'start_submitted', artifact: pmlPath, start })
      cleanupCommands.push(async () => {
        const stop = await runRuntimeCommand(task.taskId, procmonPath, ['/AcceptEula', '/Terminate'], 20_000, outboxDir)
        return { profile, action: 'terminate', result: stop }
      })
      continue
    }

    if (profile === 'sysmon') {
      const sysmonPath = findSysmonPath()
      if (!sysmonPath) {
        warnings.push('Sysmon was requested but Sysmon64.exe/Sysmon.exe was not found in the runtime tool cache.')
        profileResults.push({ profile, status: 'setup_required', missing_tool: 'sysmon' })
        continue
      }
      const install = await runRuntimeCommand(task.taskId, sysmonPath, ['-accepteula', '-i'], 30_000, outboxDir)
      profileResults.push({ profile, status: install.code === 0 ? 'started' : 'start_failed', install })
      if (install.error || (install.code !== 0 && install.stderr)) {
        warnings.push('Sysmon install may have failed; see telemetry_capture.json for command output.')
      }
      cleanupCommands.push(async () => {
        const uninstall = await runRuntimeCommand(task.taskId, sysmonPath, ['-u', 'force'], 30_000, outboxDir)
        return { profile, action: 'uninstall', result: uninstall }
      })
      continue
    }

    if (profile === 'etw_process' || profile === 'etw_dns') {
      const sessionName = `Rikune_${profile}_${task.taskId.replace(/[^A-Za-z0-9]/g, '').slice(0, 16)}`
      const etlPath = path.join(outboxDir, `${profile}.etl`)
      const provider = profile === 'etw_dns'
        ? 'Microsoft-Windows-DNS-Client'
        : 'Microsoft-Windows-Kernel-Process'
      const start = await runRuntimeCommand(
        task.taskId,
        'logman.exe',
        ['start', sessionName, '-p', provider, '-o', etlPath, '-ets'],
        15_000,
        outboxDir
      )
      profileResults.push({ profile, status: start.code === 0 ? 'started' : 'start_failed', provider, session_name: sessionName, artifact: etlPath, start })
      if (start.error || start.code !== 0) {
        warnings.push(`${profile} logman start failed or is unavailable; see telemetry_capture.json for command output.`)
      }
      cleanupCommands.push(async () => {
        const stop = await runRuntimeCommand(task.taskId, 'logman.exe', ['stop', sessionName, '-ets'], 15_000, outboxDir)
        return { profile, action: 'logman_stop', result: stop }
      })
      continue
    }

    if (profile === 'powershell_eventlog') {
      profileResults.push({ profile, status: 'scheduled', artifact: path.join(outboxDir, 'eventlog_snapshot.json') })
      continue
    }

    warnings.push(`Unknown telemetry profile ignored: ${profile}`)
    profileResults.push({ profile, status: 'ignored' })
  }

  onProgress?.(0.35, 'Running telemetry sample window')
  const sampleRun = await runTelemetrySampleWindow(task, timeoutSec)

  onProgress?.(0.7, 'Stopping telemetry collectors')
  const cleanupResults: Record<string, unknown>[] = []
  if (includeCleanup) {
    for (const cleanup of cleanupCommands.reverse()) {
      cleanupResults.push(await cleanup())
    }
  } else if (cleanupCommands.length > 0) {
    warnings.push('Telemetry cleanup was disabled; collector state may remain dirty until runtime rollback or manual cleanup.')
  }

  if (profiles.includes('powershell_eventlog') || profiles.includes('sysmon')) {
    const eventLogPath = path.join(outboxDir, 'eventlog_snapshot.json')
    const script = buildEventLogSnapshotScript(startedAt, eventLogPath, maxEvents)
    const eventLogExport = await runRuntimeCommand(
      task.taskId,
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script],
      30_000,
      outboxDir
    )
    profileResults.push({
      profile: 'powershell_eventlog_export',
      status: eventLogExport.code === 0 ? 'completed' : 'failed',
      artifact: eventLogPath,
      result: eventLogExport,
    })
  }

  const finishedAt = new Date().toISOString()
  const payload = {
    status: errors.length > 0 ? 'partial' : 'completed',
    backend: 'windows-runtime-node',
    profiles,
    started_at: startedAt,
    finished_at: finishedAt,
    capture_seconds: timeoutSec,
    max_events: maxEvents,
    include_cleanup: includeCleanup,
    sample_run: sampleRun,
    profile_results: profileResults,
    cleanup_results: cleanupResults,
    warnings,
    errors,
    safety_budgets: {
      timeout_ms: task.timeoutMs,
      stdout_limit: DEBUG_STDOUT_LIMIT,
      stderr_limit: DEBUG_STDERR_LIMIT,
    },
  }
  const artifact = writeTelemetryCaptureArtifact(task, payload)
  const artifactRefs = collectTelemetryArtifactRefs(task.taskId, [artifact])
  onProgress?.(1, 'Telemetry capture completed')

  return {
    ok: errors.length === 0,
    taskId: task.taskId,
    result: {
      ok: errors.length === 0,
      data: payload,
      errors: errors.length > 0 ? errors : undefined,
      warnings,
      artifacts: artifactRefs,
      metrics: {
        elapsed_ms: new Date(finishedAt).getTime() - new Date(startedAt).getTime(),
        tool: task.tool,
      },
    },
    logs,
    errors: errors.length > 0 ? errors : undefined,
    artifactRefs,
  }
}

export async function executeDebugSession(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const cdbPath = findCdbPath()
  if (!cdbPath) {
    const transcript = writeDebugSessionTranscript(task, {
      status: 'failed',
      failure_category: 'missing_debugger',
      errors: ['Windows Debugger (cdb.exe) was not found in the runtime environment.'],
      safety_budgets: {
        timeout_ms: task.timeoutMs,
        stdout_limit: DEBUG_STDOUT_LIMIT,
        stderr_limit: DEBUG_STDERR_LIMIT,
      },
    })
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Debug session tools require Windows Debugger (cdb.exe), which was not found in the runtime environment.`],
      logs,
      artifactRefs: collectDebugSessionArtifactRefs(task.taskId, [transcript]),
    }
  }

  const samplePath = resolveTaskSamplePath(task.taskId)
  const sessionId = String(task.args.session_id || '')
  const command = String(task.args.command || '')
  const address = String(task.args.address || '')
  const expression = String(task.args.expression || '')

  let cdbArgs: string[] = []

  switch (task.tool) {
    case 'debug.session.start':
      cdbArgs = ['-g', '-G', '-c', 'g', samplePath]
      break
    case 'debug.session.breakpoint':
      cdbArgs = ['-c', `bp ${address}; g`, '-c', 'q', samplePath]
      break
    case 'debug.session.continue':
      cdbArgs = ['-c', 'g', '-c', 'q', samplePath]
      break
    case 'debug.session.step':
      cdbArgs = ['-c', 'p', '-c', 'q', samplePath]
      break
    case 'debug.session.inspect':
      cdbArgs = ['-c', 'r', '-c', 'u', '-c', 'q', samplePath]
      break
    case 'debug.session.end':
      cdbArgs = ['-c', 'q', samplePath]
      break
    case 'debug.session.smart_breakpoint':
      cdbArgs = ['-c', `bm ${address}; g`, '-c', 'q', samplePath]
      break
    case 'debug.session.snapshot':
      cdbArgs = ['-c', `.dump /ma \"${path.join(config.runtime.outbox, task.taskId, 'debug_snapshot.dmp')}\"`, '-c', 'q', samplePath]
      break
    case 'debug.session.watch':
      cdbArgs = ['-c', `ba r4 ${expression}; g`, '-c', 'q', samplePath]
      break
    case 'debug.session.command_batch':
    case 'debug.session.cdb_script':
      cdbArgs = ['-c', readCdbCommandBatch(task.args).join('; '), samplePath]
      break
    default:
      cdbArgs = ['-c', 'q', samplePath]
  }

  log(`Spawning debug session tool=${task.tool} with cdb`)

  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(cdbPath, cdbArgs, { stdio: ['ignore', 'pipe', 'pipe'], timeout: task.timeoutMs, cwd: path.dirname(samplePath), windowsHide: true })
    registerProcess(task.taskId, child)
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += d.toString() })
    child.stderr.on('data', (d) => { stderr += d.toString() })
    child.on('error', (e) => {
      const transcript = writeDebugSessionTranscript(task, {
        status: 'failed',
        failure_category: 'process_error',
        session_id: sessionId || task.taskId,
        command,
        cdb_path: cdbPath,
        cdb_args: cdbArgs,
        errors: [e.message],
        safety_budgets: {
          timeout_ms: task.timeoutMs,
          stdout_limit: DEBUG_STDOUT_LIMIT,
          stderr_limit: DEBUG_STDERR_LIMIT,
        },
      })
      resolve({
        ok: false,
        taskId: task.taskId,
        errors: [e.message],
        logs,
        artifactRefs: collectDebugSessionArtifactRefs(task.taskId, [transcript]),
      })
    })
    child.on('close', (code) => {
      const stdoutPreview = stdout.slice(0, DEBUG_STDOUT_LIMIT)
      const stderrPreview = stderr.slice(0, DEBUG_STDERR_LIMIT)
      const transcript = writeDebugSessionTranscript(task, {
        status: 'completed',
        session_id: sessionId || task.taskId,
        command,
        address: address || null,
        expression: expression || null,
        cdb_path: cdbPath,
        cdb_args: cdbArgs,
        exit_code: code,
        stdout: stdoutPreview,
        stderr: stderrPreview,
        safety_budgets: {
          timeout_ms: task.timeoutMs,
          stdout_limit: DEBUG_STDOUT_LIMIT,
          stderr_limit: DEBUG_STDERR_LIMIT,
        },
      })
      const artifactRefs = collectDebugSessionArtifactRefs(task.taskId, [transcript])
      resolve({
        ok: true,
        taskId: task.taskId,
        result: {
          ok: true,
          data: {
            session_id: sessionId || task.taskId,
            tool: task.tool,
            stdout: stdoutPreview,
            stderr: stderrPreview,
            exit_code: code,
            transcript_artifact: transcript,
          },
          artifacts: artifactRefs,
          metrics: { tool: task.tool },
        },
        logs: [...logs, stdout, stderr].filter(Boolean),
        artifactRefs,
      })
    })
  })
}
