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
  executeQilingInspect,
  executePandaInspect,
  executeManagedSafeRun,
  executeDebugSession,
}

const pythonWorkerHandlers: Record<string, { description: string }> = {
  'frida_worker.py': {
    description: 'Execute Frida-backed runtime instrumentation through the Python worker bridge.',
  },
}

const inlineHandlerDescriptions: Record<string, string> = {
  executeSandboxExecute: 'Run the sandbox.execute dynamic workflow inline inside the runtime node.',
  executeSpeakeasyEmulate: 'Run Speakeasy user-mode emulation inline inside the runtime node.',
  executeSpeakeasyShellcode: 'Run Speakeasy shellcode emulation inline inside the runtime node.',
  executeSpeakeasyApiTrace: 'Collect API traces from Speakeasy inline execution.',
  executeWineRun: 'Run or preflight Wine execution inline inside the runtime node.',
  executeWineEnv: 'Inspect or prepare Wine environment state inline inside the runtime node.',
  executeWineDllOverrides: 'Configure Wine DLL override behavior inline inside the runtime node.',
  executeWineReg: 'Read or write Wine registry values inline inside the runtime node.',
  executeDynamicMemoryDump: 'Capture dynamic memory dumps inline inside the runtime node.',
  executeQilingInspect: 'Run Qiling-backed inspection inline inside the runtime node.',
  executePandaInspect: 'Run PANDA-backed inspection inline inside the runtime node.',
  executeManagedSafeRun: 'Run managed sandbox analysis inline inside the runtime node.',
  executeDebugSession: 'Handle debug-session lifecycle and inspection requests inline inside the runtime node.',
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
  ...Object.entries(inlineHandlerDescriptions).map(([handler, description]) => ({
    key: getRuntimeBackendCapabilityKey('inline', handler),
    type: 'inline' as const,
    handler,
    description,
    requiresSample: true,
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
    : path.join(config.runtime.inbox, `${task.taskId}.sample`)

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
      cwd: plan.cwd,
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
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

function findCdbPath(): string | null {
  const candidates = [
    'C:\\\\Program Files (x86)\\\\Windows Kits\\\\10\\\\Debuggers\\\\x64\\\\cdb.exe',
    'C:\\\\Program Files\\\\Windows Kits\\\\10\\\\Debuggers\\\\x64\\\\cdb.exe',
    'C:\\\\Program Files (x86)\\\\Windows Kits\\\\11\\\\Debuggers\\\\x64\\\\cdb.exe',
    'C:\\\\Program Files\\\\Windows Kits\\\\11\\\\Debuggers\\\\x64\\\\cdb.exe',
  ]
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  return null
}

export async function executeDebugSession(
  task: ExecuteTask,
  log: (msg: string) => void,
  logs: string[],
  onProgress?: (progress: number, message?: string) => void,
): Promise<ExecuteResult> {
  const cdbPath = findCdbPath()
  if (!cdbPath) {
    return {
      ok: false,
      taskId: task.taskId,
      errors: [`Debug session tools require Windows Debugger (cdb.exe), which was not found in the runtime environment.`],
      logs,
    }
  }

  const samplePath = path.join(config.runtime.inbox, `${task.taskId}.sample`)
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
    default:
      cdbArgs = ['-c', 'q', samplePath]
  }

  log(`Spawning debug session tool=${task.tool} with cdb`)

  return new Promise<ExecuteResult>((resolve) => {
    const child = spawnProcess(cdbPath, cdbArgs, { stdio: ['ignore', 'pipe', 'pipe'], timeout: task.timeoutMs, windowsHide: true })
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
          data: { session_id: sessionId || task.taskId, tool: task.tool, stdout: stdout.slice(0, 20000), stderr: stderr.slice(0, 5000), exit_code: code },
          metrics: { tool: task.tool },
        },
        logs: [...logs, stdout, stderr].filter(Boolean),
      })
    })
  })
}
