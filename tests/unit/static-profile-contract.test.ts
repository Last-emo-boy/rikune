import { DATABASE_FIXTURE_CAPABILITY } from '../../src/database.js'
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import { execFileSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { CacheManager } from '../../src/cache-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { JobPriority, JobQueue } from '../../src/job-queue.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import {
  assertStaticImageStartupContract,
  assertStaticQueuedJob,
  isStaticDockerProfile,
  STATIC_WORKFLOW_STAGE_IDS,
  StaticProfileLockSchema,
  loadStaticProfileLock,
  validateStaticRequiredBackends,
} from '../../src/core/static-profile-lock.js'
import {
  createOrReuseAnalysisRun,
  upsertAnalysisRunStage,
  type AnalysisPipelineStage,
} from '../../src/analysis/analysis-run-state.js'
import {
  createAnalyzePipelineStageContext,
  createAnalyzeWorkflowPromoteHandler,
  executeQueuedAnalysisStage,
} from '../../src/workflows/analyze-pipeline.js'
import { registerWorkflowTools } from '../../src/core/tool-registry/workflow-tools.js'
import { getPythonCommand } from '../../src/utils/shared-helpers.js'

const SAMPLE_ID = `sha256:${'a'.repeat(64)}`
const FORBIDDEN_STAGES: AnalysisPipelineStage[] = [
  'reconstruct',
  'semantic_name_review',
  'semantic_explain_review',
  'semantic_module_review',
  'dynamic_plan',
  'dynamic_execute',
  'summarize',
]
const FORBIDDEN_DEPENDENCIES = [
  'dynamicDependencies',
  'dynamicDeepPlan',
  'breakpointSmart',
  'traceCondition',
  'sandboxExecute',
  'workflowSummarize',
  'reconstructWorkflow',
  'semanticNameReviewWorkflow',
  'functionExplanationReviewWorkflow',
  'moduleReconstructionReviewWorkflow',
  'qilingInspect',
  'pandaInspect',
  'angrAnalyze',
  'retdecDecompile',
]
const FORBIDDEN_PLUGIN_IDS = [
  'android-runtime',
  'behavior-first',
  'debug-session',
  'dynamic',
  'frida',
  'ios-runtime',
  'linux-runtime',
  'macos-runtime',
  'managed-fake-c2',
  'managed-sandbox',
  'panda',
  'qiling',
  'runtime-deobfuscate',
  'speakeasy',
  'wasm-runtime',
  'windows-runtime',
  'wine',
]

describe('static profile release contract', () => {
  let testDir: string
  let database: DatabaseManager
  let workspaceManager: WorkspaceManager
  let cacheManager: CacheManager
  let policyGuard: PolicyGuard
  let jobQueue: JobQueue

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-static-profile-'))
    database = new DatabaseManager(path.join(testDir, 'database.db'))
    workspaceManager = new WorkspaceManager(path.join(testDir, 'workspaces'))
    cacheManager = new CacheManager(path.join(testDir, 'cache'), database)
    policyGuard = new PolicyGuard(path.join(testDir, 'audit.log'))
    jobQueue = new JobQueue(database)
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: 'a'.repeat(64),
      md5: 'b'.repeat(32),
      size: 1024,
      file_type: 'PE',
      created_at: new Date('2026-08-23T00:00:00.000Z').toISOString(),
      source: 'static-profile-test',
    })
  })

  afterEach(() => {
    jobQueue.close()
    database.close()
    fs.rmSync(testDir, { recursive: true, force: true })
  })

  test('locks the generator-derived exact 100-plugin static profile', () => {
    const lock = loadStaticProfileLock(path.join(process.cwd(), 'static-profile.lock.json'))
    expect(StaticProfileLockSchema.safeParse(lock).success).toBe(true)
    expect(lock.plugins).toHaveLength(100)
    expect(new Set(lock.plugins).size).toBe(100)
    expect(lock.static_workflow_stages).toEqual(STATIC_WORKFLOW_STAGE_IDS)
    expect(lock.required_backends.map((backend) => backend.name)).toEqual([
      'java',
      'ghidra-analyze-headless',
      'rizin',
      'capa',
      'detect-it-easy',
      'upx',
      'flare-floss',
      'yara-x-python',
    ])
    expect(lock.required_backends[1]).toEqual(
      expect.objectContaining({
        version_args: [],
        allowed_exit_codes: [1],
        version_file: '/opt/ghidra/Ghidra/application.properties',
        version_pattern: expect.stringContaining('12\\.1\\.3'),
      })
    )

    const generatedDir = path.join(testDir, 'generated-static-profile')
    const output = execFileSync(
      process.execPath,
      ['scripts/generate-docker.mjs', '--profile=static', `--output=${generatedDir}`],
      { cwd: process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
    )
    const match = output.match(/Build plugins \(100\): ([^\n]+)/)
    expect(match?.[1]?.split(', ')).toEqual(lock.plugins)

    const generatedLock = loadStaticProfileLock(path.join(generatedDir, 'static-profile.lock.json'))
    expect(generatedLock).toEqual(lock)
    for (const backend of generatedLock.required_backends) {
      expect(() => new RegExp(backend.version_pattern)).not.toThrow()
      expect(backend.version_pattern).not.toMatch(/\(\?[ims-]+:/)
    }

    const rizin = generatedLock.required_backends.find((backend) => backend.name === 'rizin')
    expect(rizin).toEqual(expect.objectContaining({ version_args: ['-v'] }))
    const rizinPattern = new RegExp(rizin!.version_pattern)
    for (const evidence of [
      'rizin 0.8.2',
      'Rizin v0.8.2',
      'RIZIN version 0.8.2\n',
      'rizin 0.8.2 @ linux-x86-64\ncommit: 5a611eee2999d312317ff90d600e37dde0f58992',
    ]) {
      expect(rizinPattern.test(evidence)).toBe(true)
    }
    for (const evidence of ['rizin 0.8.3', 'rizin 0.8.20', 'rizin 10.8.2', 'cutter 0.8.2']) {
      expect(rizinPattern.test(evidence)).toBe(false)
    }

    const capa = generatedLock.required_backends.find((backend) => backend.name === 'capa')
    expect(capa).toEqual(expect.objectContaining({ version_args: ['--version'] }))
    const capaPattern = new RegExp(capa!.version_pattern)
    for (const evidence of ['main.py 9.3.1', 'capa 9.3.1', 'CAPA v9.3.1\n']) {
      expect(capaPattern.test(evidence)).toBe(true)
    }
    for (const evidence of ['main.py 9.3.2', 'main.py 9.3.10', 'capa 19.3.1', 'other.py 9.3.1']) {
      expect(capaPattern.test(evidence)).toBe(false)
    }

    const allPluginIds = fs
      .readdirSync(path.join(process.cwd(), 'src', 'plugins'), { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && !entry.name.startsWith('.'))
      .map((entry) => entry.name)
      .sort()
    expect(allPluginIds.filter((id) => !lock.plugins.includes(id))).toEqual(FORBIDDEN_PLUGIN_IDS)
    expect(lock.plugins.some((id) => FORBIDDEN_PLUGIN_IDS.includes(id))).toBe(false)

    const dockerfile = fs.readFileSync(
      path.join(process.cwd(), 'docker', 'Dockerfile.analyzer'),
      'utf8'
    )
    expect(dockerfile).toContain('COPY static-profile.lock.json /app/static-profile.lock.json')
    expect(dockerfile).toContain('ENV RIKUNE_DOCKER_PROFILE=static')
    expect(dockerfile).toContain('API_ENABLED=false')
    expect(dockerfile).toContain('npm_config_build_from_source=true')
    expect(dockerfile).toContain('npm_config_nodedir=/usr/local')
    expect(dockerfile).toContain("const Database=require('better-sqlite3')")
    expect(dockerfile).toContain('RIKUNE_STATIC_PROFILE_LOCK_PATH=/app/static-profile.lock.json')
    expect(dockerfile).toContain("RUN printf 'static\\n' > /app/.rikune-static-profile")
    expect(dockerfile).toContain(
      'chmod 0444 /app/.rikune-static-profile /app/static-profile.lock.json'
    )
    expect(dockerfile).toContain('USER 1000:1000')
    expect(dockerfile).toContain('-xdev -exec chown -h root:root {} +')
    expect(dockerfile).toContain('-xdev ! -type l -exec chmod go-w {} +')
    expect(dockerfile).toContain('chown root:root /docker-entrypoint.sh')
    expect(dockerfile).toContain('chmod 0555 /docker-entrypoint.sh')
    expect(dockerfile).toContain(
      'COPY scripts/secure-fs-helper.py scripts/verify-hybrid-runtime.mjs ./scripts/'
    )
    expect(dockerfile).toContain('COPY LICENSE DISCLOSURE ./')
    expect(dockerfile).toContain('chmod 0444 /app/LICENSE /app/DISCLOSURE')
    expect(dockerfile).toContain('chmod 0555 ./scripts/secure-fs-helper.py')
    const dockerignore = fs.readFileSync(path.join(process.cwd(), '.dockerignore'), 'utf8')
    expect(dockerignore).toContain('!scripts/secure-fs-helper.py')
    expect(dockerignore).toContain('!scripts/verify-hybrid-runtime.mjs')
    expect(dockerignore).toContain('!LICENSE')
    expect(dockerignore).toContain('!DISCLOSURE')
    expect(dockerfile).not.toContain('chown -R appuser:appuser /app &&')
    expect(dockerfile).toContain('STATIC_WORKFLOW_STAGES=fast_profile,enrich_static,function_map')
    expect(dockerfile).not.toContain('src/plugins/frida/scripts')

    const compose = fs.readFileSync(path.join(process.cwd(), 'docker-compose.analyzer.yml'), 'utf8')
    expect(compose).toContain('STATIC_WORKFLOW_STAGES=fast_profile,enrich_static,function_map')
    expect(compose).toContain('user: "1000:1000"')
    expect(compose).toContain('read_only: true')
    expect(compose).toContain('mem_limit: 8g')
    expect(compose).toContain('pids_limit: 512')
    expect(compose).toContain("cpus: '2'\n          pids: 512")
    expect(compose).toContain('deployment admission is the trust boundary')
    expect(compose).toContain(
      'API_KEY=${RIKUNE_API_KEY:?RIKUNE_API_KEY_required_when_API_ENABLED_true}'
    )
    expect(compose).toContain('127.0.0.1:${RIKUNE_API_PORT:-18080}:18080')
    expect(compose).not.toContain('- "18080:18080"')
    const developmentCompose = fs.readFileSync(
      path.join(process.cwd(), 'docker-compose.dev.yml'),
      'utf8'
    )
    expect(developmentCompose).not.toContain('ports:')
    expect(developmentCompose).toContain('loopback-only dashboard/API port is inherited')
    const entrypoint = fs.readFileSync(path.join(process.cwd(), 'docker-entrypoint.sh'), 'utf8')
    expect(entrypoint).toContain('assertStaticImageStartupContract')
    expect(entrypoint).not.toContain('chown -R appuser:appuser /app')
  })

  test('executes FLOSS, capa, and the Rizin helper through locked absolute paths', () => {
    const rulesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-capa-rules-'))
    const previousProfile = process.env.RIKUNE_DOCKER_PROFILE
    const previousPython = process.env.PYTHON_PATH
    try {
      const probe = execFileSync(
        'python3',
        [
          '-c',
          [
            'import json, os, sys',
            'sys.path.insert(0, os.path.join(os.getcwd(), "workers"))',
            'import static_worker as module',
            'commands = []',
            'executed = []',
            'class Completed:',
            '    def __init__(self, stdout):',
            '        self.returncode = 0',
            '        self.stdout = stdout',
            '        self.stderr = ""',
            'def fake_run(command, **_kwargs):',
            '    commands.append(command)',
            '    if command[-1] == "--help":',
            '        return Completed("--json --no-static-strings --no-stack-strings --no-tight-strings --no-decoded-strings")',
            '    return Completed("floss 3.1.1" if command[0] == os.environ["FLOSS_PATH"] else "capa v9.3.1")',
            'def forbidden_which(name):',
            '    raise AssertionError(f"PATH lookup forbidden in static profile: {name}")',
            'module.subprocess.run = fake_run',
            'module.shutil.which = forbidden_which',
            'worker = module.StaticWorker()',
            'floss = worker._discover_floss_cli()',
            'capa = worker._discover_capa_backend()',
            'def fake_external(command, _timeout):',
            '    executed.append(command)',
            '    return (0, "{\\"strings\\": {}}", "", False)',
            'worker._run_external_command_to_files = fake_external',
            'worker.floss_decode("/sample", {"timeout": 1})',
            'print(json.dumps({"floss": floss["command"], "capa": capa["command"], "executed": executed, "probes": commands}))',
          ].join('\n'),
        ],
        {
          cwd: process.cwd(),
          encoding: 'utf8',
          env: {
            ...process.env,
            RIKUNE_DOCKER_PROFILE: 'static',
            FLOSS_PATH: '/locked/floss',
            CAPA_PATH: '/locked/capa',
            CAPA_RULES_PATH: rulesDir,
          },
        }
      )
      const result = JSON.parse(probe)
      expect(result.floss).toEqual(['/locked/floss'])
      expect(result.capa).toEqual(['/locked/capa'])
      expect(result.executed[0][0]).toBe('/locked/floss')
      expect(result.probes.every((command: string[]) => command[0].startsWith('/locked/'))).toBe(
        true
      )

      process.env.RIKUNE_DOCKER_PROFILE = 'static'
      process.env.PYTHON_PATH = '/locked/python3.12'
      expect(getPythonCommand('linux')).toBe('/locked/python3.12')
      const secureFilesystemSource = fs.readFileSync(
        path.join(process.cwd(), 'src/sample/secure-filesystem.ts'),
        'utf8'
      )
      expect(secureFilesystemSource).toContain("'/usr/local/bin/python3.12'")
      expect(secureFilesystemSource).not.toContain("'/usr/local/bin/python3.11'")
      const rizinSource = fs.readFileSync(
        path.join(process.cwd(), 'src/plugins/rizin/tools/rizin-analyze.ts'),
        'utf8'
      )
      expect(rizinSource).toContain('command: getPythonCommand()')
      expect(rizinSource).not.toContain(
        "command: process.platform === 'win32' ? 'python' : 'python3'"
      )
    } finally {
      fs.rmSync(rulesDir, { recursive: true, force: true })
      if (previousProfile === undefined) delete process.env.RIKUNE_DOCKER_PROFILE
      else process.env.RIKUNE_DOCKER_PROFILE = previousProfile
      if (previousPython === undefined) delete process.env.PYTHON_PATH
      else process.env.PYTHON_PATH = previousPython
    }
  })

  test('baked marker activates the bare-image startup contract and cannot be downgraded', () => {
    const lockPath = path.join(process.cwd(), 'static-profile.lock.json')
    const lock = loadStaticProfileLock(lockPath)
    const markerPath = path.join(testDir, '.rikune-static-profile')
    fs.writeFileSync(markerPath, 'static\n', { mode: 0o444 })
    expect(fs.statSync(markerPath).mode & 0o777).toBe(0o444)
    const previous = {
      profile: process.env.RIKUNE_DOCKER_PROFILE,
      plugins: process.env.PLUGINS,
      stages: process.env.STATIC_WORKFLOW_STAGES,
      runtime: process.env.RUNTIME_MODE,
      backendEnvironment: new Map(
        lock.required_backends.flatMap((backend) =>
          backend.environment.map((binding) => [binding.name, process.env[binding.name]] as const)
        )
      ),
    }
    try {
      process.env.RIKUNE_DOCKER_PROFILE = 'static'
      process.env.PLUGINS = lock.plugins.join(',')
      process.env.STATIC_WORKFLOW_STAGES = lock.static_workflow_stages.join(',')
      process.env.RUNTIME_MODE = 'disabled'
      for (const backend of lock.required_backends) {
        for (const binding of backend.environment) {
          if (binding.required) process.env[binding.name] = binding.value
          else delete process.env[binding.name]
        }
      }
      expect(isStaticDockerProfile(markerPath)).toBe(true)
      expect(
        assertStaticImageStartupContract({ markerPath, lockPath, validateBackends: false })
      ).toEqual(lock)

      process.env.RIZIN_PATH = '/tmp/unlocked-rizin'
      expect(() =>
        assertStaticImageStartupContract({ markerPath, lockPath, validateBackends: false })
      ).toThrow(/requires RIZIN_PATH=\/opt\/rizin\/bin\/rizin/i)
      process.env.RIZIN_PATH = '/opt/rizin/bin/rizin'

      process.env.GHIDRA_PATH = '/tmp/unlocked-ghidra'
      expect(() =>
        assertStaticImageStartupContract({ markerPath, lockPath, validateBackends: false })
      ).toThrow(/requires GHIDRA_PATH=\/opt\/ghidra/i)
      delete process.env.GHIDRA_PATH

      process.env.RIKUNE_DOCKER_PROFILE = 'full'
      expect(() => isStaticDockerProfile(markerPath)).toThrow(
        /baked static image identity requires RIKUNE_DOCKER_PROFILE=static/i
      )

      process.env.RIKUNE_DOCKER_PROFILE = 'static'
      fs.chmodSync(markerPath, 0o644)
      fs.writeFileSync(markerPath, 'hybrid\n')
      fs.chmodSync(markerPath, 0o444)
      expect(fs.statSync(markerPath).mode & 0o777).toBe(0o444)
      expect(() => isStaticDockerProfile(markerPath)).toThrow(/marker has invalid content/i)
    } finally {
      for (const [key, value] of [
        ['RIKUNE_DOCKER_PROFILE', previous.profile],
        ['PLUGINS', previous.plugins],
        ['STATIC_WORKFLOW_STAGES', previous.stages],
        ['RUNTIME_MODE', previous.runtime],
      ] as const) {
        if (value === undefined) delete process.env[key]
        else process.env[key] = value
      }
      for (const [key, value] of previous.backendEnvironment) {
        if (value === undefined) delete process.env[key]
        else process.env[key] = value
      }
    }
  })

  test('validates backend executable, exit-code, and version evidence fail closed', () => {
    const lock = loadStaticProfileLock(path.join(process.cwd(), 'static-profile.lock.json'))
    const probe = path.join(testDir, 'backend-probe.sh')
    fs.writeFileSync(probe, '#!/bin/sh\nprintf "backend-%s\\n" "$1"\nexit 0\n')
    fs.chmodSync(probe, 0o755)
    const required_backends = lock.required_backends.map((original, index) => {
      const { version_file: _versionFile, ...backend } = original
      return {
        ...backend,
        path: probe,
        version_args: [String(index)],
        allowed_exit_codes: [0],
        version_pattern: `^backend-${index}(?:\\r?\\n|$)`,
      }
    })
    const fixture = { ...lock, required_backends }
    expect(() => validateStaticRequiredBackends(fixture)).not.toThrow()

    fixture.required_backends[0] = {
      ...fixture.required_backends[0],
      allowed_exit_codes: [7],
    }
    expect(() => validateStaticRequiredBackends(fixture)).toThrow(/disallowed exit code/i)
  })

  test('rejects malformed backend version patterns while loading the lock', () => {
    const lock = loadStaticProfileLock(path.join(process.cwd(), 'static-profile.lock.json'))
    const malformedPath = path.join(testDir, 'malformed-static-profile.lock.json')
    fs.writeFileSync(
      malformedPath,
      `${JSON.stringify(
        {
          ...lock,
          required_backends: lock.required_backends.map((backend) =>
            backend.name === 'rizin' ? { ...backend, version_pattern: '(?<' } : backend
          ),
        },
        null,
        2
      )}\n`
    )

    expect(() => loadStaticProfileLock(malformedPath)).toThrow(
      /E_STATIC_PROFILE_CONTRACT: backend rizin has an invalid version_pattern/
    )
  })

  test('omits non-static handler dependencies from the static pipeline graph', () => {
    const context = createAnalyzePipelineStageContext(
      workspaceManager,
      database,
      cacheManager,
      policyGuard,
      undefined,
      { staticOnly: true },
      jobQueue
    )
    expect(context.dependencies.staticOnly).toBe(true)
    for (const dependency of FORBIDDEN_DEPENDENCIES) {
      expect(context.dependencies).not.toHaveProperty(dependency)
    }
  })

  test('cannot downgrade static stage gates with false or omitted caller flags', async () => {
    const previousProfile = process.env.RIKUNE_DOCKER_PROFILE
    process.env.RIKUNE_DOCKER_PROFILE = 'static'
    try {
      for (const dependencies of [{ staticOnly: false }, {}]) {
        const context = createAnalyzePipelineStageContext(
          workspaceManager,
          database,
          cacheManager,
          policyGuard,
          undefined,
          dependencies,
          jobQueue
        )
        expect(context.dependencies.staticOnly).toBe(true)
        await expect(
          executeQueuedAnalysisStage(context, {
            run_id: 'missing-run',
            stage: 'reconstruct',
          })
        ).rejects.toThrow('E_STATIC_PROFILE_CONTRACT')
        expect(database.findAnalysisRunStage('missing-run', 'reconstruct')).toBeUndefined()
        expect(jobQueue.listQueuedJobs()).toHaveLength(0)
      }
    } finally {
      if (previousProfile === undefined) delete process.env.RIKUNE_DOCKER_PROFILE
      else process.env.RIKUNE_DOCKER_PROFILE = previousProfile
    }
  })

  test('queued static allowlist permits only workflow.analyze.stage and exact stage literals', () => {
    // The ordered domain DAG starts after ingest: bounded baseline, static
    // enrichment, then function-index construction.
    expect(STATIC_WORKFLOW_STAGE_IDS).toEqual(['fast_profile', 'enrich_static', 'function_map'])
    for (const stage of STATIC_WORKFLOW_STAGE_IDS) {
      expect(() =>
        assertStaticQueuedJob('workflow.analyze.stage', { run_id: 'run', stage })
      ).not.toThrow()
    }
    expect(() => assertStaticQueuedJob('ghidra.analyze', { stage: 'function_map' })).toThrow(
      /queued tool 'ghidra\.analyze' is not allowed/i
    )
    expect(() => assertStaticQueuedJob('workflow.analyze.stage', { stage: 'reconstruct' })).toThrow(
      /stage 'reconstruct' is not allowed/i
    )
  })

  test('startup recovery interrupts persisted forbidden static jobs and their stages', () => {
    const previousProfile = process.env.RIKUNE_DOCKER_PROFILE
    const sample = database.findSample(SAMPLE_ID)!
    const { run } = createOrReuseAnalysisRun(database, {
      sample,
      goal: 'static',
      depth: 'balanced',
      backendPolicy: 'auto',
      stagePlan: [...STATIC_WORKFLOW_STAGE_IDS],
    })
    upsertAnalysisRunStage(database, {
      runId: run.id,
      stage: 'fast_profile',
      status: 'completed',
      executionState: 'completed',
      tool: 'workflow.analyze.stage',
    })
    database.createJob({
      id: 'valid-static-job',
      type: 'static',
      tool: 'workflow.analyze.stage',
      sampleId: SAMPLE_ID,
      args: { run_id: run.id, stage: 'enrich_static' },
      priority: JobPriority.NORMAL,
      timeout: 5_000,
    })
    database.createJob({
      id: 'forbidden-ghidra-job',
      type: 'static',
      tool: 'ghidra.analyze',
      sampleId: SAMPLE_ID,
      args: { run_id: run.id, stage: 'reconstruct' },
      priority: JobPriority.NORMAL,
      timeout: 5_000,
    })
    upsertAnalysisRunStage(database, {
      runId: run.id,
      stage: 'reconstruct',
      status: 'queued',
      executionState: 'queued',
      tool: 'ghidra.analyze',
      jobId: 'forbidden-ghidra-job',
    })

    const restoredQueue = new JobQueue(database)
    process.env.RIKUNE_DOCKER_PROFILE = 'static'
    try {
      expect(restoredQueue.restoreFromDatabase()).toEqual({ restored: 2, interrupted: 1 })
      expect(restoredQueue.listQueuedJobs().map((job) => job.id)).toEqual(['valid-static-job'])
      expect(restoredQueue.getStatus('forbidden-ghidra-job')?.status).toBe('interrupted')
      expect(database.findAnalysisRunStage(run.id, 'reconstruct')?.status).toBe('interrupted')
    } finally {
      restoredQueue.close()
      if (previousProfile === undefined) delete process.env.RIKUNE_DOCKER_PROFILE
      else process.env.RIKUNE_DOCKER_PROFILE = previousProfile
    }
  })

  test('registers only workflow.run from the workflow registry in the static profile', async () => {
    const previousProfile = process.env.RIKUNE_DOCKER_PROFILE
    const registered: string[] = []
    const server = {
      registerTool: (definition: { name: string }) => registered.push(definition.name),
    }
    process.env.RIKUNE_DOCKER_PROFILE = 'static'
    try {
      await registerWorkflowTools(
        server as any,
        {
          workspaceManager,
          database,
          cacheManager,
          policyGuard,
          jobQueue,
          config: { api: { port: 18080, publicBaseUrl: undefined } },
        } as any
      )
      expect(registered).toEqual(['workflow.run'])
      expect(jobQueue.listQueuedJobs()).toHaveLength(0)
    } finally {
      if (previousProfile === undefined) delete process.env.RIKUNE_DOCKER_PROFILE
      else process.env.RIKUNE_DOCKER_PROFILE = previousProfile
    }
  })

  test.each(FORBIDDEN_STAGES)(
    'rejects prohibited stage %s before enqueue or stage mutation',
    async (stage) => {
      const sample = database.findSample(SAMPLE_ID)!
      const { run } = createOrReuseAnalysisRun(database, {
        sample,
        goal: 'static',
        depth: 'balanced',
        backendPolicy: 'auto',
        stagePlan: [...STATIC_WORKFLOW_STAGE_IDS],
      })
      upsertAnalysisRunStage(database, {
        runId: run.id,
        stage: 'fast_profile',
        status: 'completed',
        executionState: 'completed',
        result: { stage: 'fast_profile', status: 'ready' },
      })
      const promote = createAnalyzeWorkflowPromoteHandler(
        workspaceManager,
        database,
        cacheManager,
        policyGuard,
        undefined,
        { staticOnly: true },
        jobQueue
      )

      const result = await promote({ run_id: run.id, through_stage: stage })

      expect(result.ok).toBe(false)
      expect(result.errors?.[0]).toContain('E_STATIC_PROFILE_CONTRACT')
      expect(jobQueue.listQueuedJobs()).toHaveLength(0)
      expect(database.findAnalysisRunStage(run.id, stage)).toBeUndefined()

      const context = createAnalyzePipelineStageContext(
        workspaceManager,
        database,
        cacheManager,
        policyGuard,
        undefined,
        { staticOnly: true },
        jobQueue
      )
      await expect(executeQueuedAnalysisStage(context, { run_id: run.id, stage })).rejects.toThrow(
        'E_STATIC_PROFILE_CONTRACT'
      )
      expect(database.findAnalysisRunStage(run.id, stage)).toBeUndefined()
    }
  )
})
