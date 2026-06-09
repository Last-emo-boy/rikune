/**
 * managed.fake_c2 MCP tool — configurable fake C2 server for driving
 * deeper sample logic during sandbox execution.
 *
 * Allows the analyst to configure custom responses for specific endpoints
 * (e.g. /plugin, /ping, /gate, /task) so that the sample continues past
 * initial C2 connectivity checks and enters operational command handling.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
  type ArtifactRef,
  type PluginToolDeps,
  type BackendWorkerContract,
} from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'
import {
  MANAGED_FAKE_C2_ARTIFACT_TYPES,
  MANAGED_FAKE_C2_FOLLOW_UP_TOOLS,
  MANAGED_FAKE_C2_TOOL_NAME,
  buildManagedFakeC2Envelope,
  managedFakeC2Aspects,
} from '../managed-fake-c2-metadata.js'

const TOOL_NAME = MANAGED_FAKE_C2_TOOL_NAME
const WORKER_HANDLER = 'src/plugins/managed-fake-c2/workers/managed_fake_c2_worker.py'

export const FAKE_C2_ARTIFACT_TYPES = MANAGED_FAKE_C2_ARTIFACT_TYPES

type FakeC2RuntimePolicy = NonNullable<ToolDefinition['runtimePolicy']> & {
  sinkholedOnly: true
  noArbitraryOutboundNetwork: true
  validationPlannerRequired: true
  workflowSearchAutoRun: false
}

/* ── Input schema ──────────────────────────────────────────────────────── */

const EndpointConfigSchema = z.object({
  path: z.string().describe('URL path to match (e.g. /plugin, /ping, /gate)'),
  method: z
    .enum(['GET', 'POST', 'PUT', 'DELETE', 'ANY'])
    .default('ANY')
    .describe('HTTP method to match'),
  status_code: z.number().min(100).max(599).default(200).describe('HTTP status code to return'),
  response_body: z.string().describe('Response body to return (plain text or JSON string)'),
  content_type: z.string().default('application/json').describe('Content-Type header value'),
  delay_ms: z
    .number()
    .min(0)
    .max(10000)
    .default(0)
    .describe('Artificial response delay in milliseconds'),
})

export const FakeC2InputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  endpoints: z
    .array(EndpointConfigSchema)
    .min(1)
    .describe('List of endpoint configurations for the fake C2'),
  listen_port: z
    .number()
    .min(1024)
    .max(65535)
    .default(8443)
    .describe('Port for the fake C2 HTTPS listener'),
  use_tls: z.boolean().default(true).describe('Enable TLS with self-signed certificate'),
  capture_requests: z.boolean().default(true).describe('Log all incoming requests for analysis'),
  default_response: z
    .string()
    .default('{"status":"ok"}')
    .describe('Default response for unmatched endpoints'),
  timeout_seconds: z
    .number()
    .min(10)
    .max(600)
    .default(120)
    .describe('Maximum runtime for the fake C2 server'),
  auto_run_sample: z
    .boolean()
    .default(false)
    .describe('Automatically launch the sample in sandbox with C2 pointing to the fake server'),
  dns_redirect: z
    .array(z.string())
    .optional()
    .describe('Domain names to redirect to the fake C2 (via hosts-file patching in sandbox)'),
})

export const FakeC2OutputSchema = createWorkerResultOutputSchema(z.record(z.any()))

export const FAKE_C2_RUNTIME_POLICY: FakeC2RuntimePolicy = {
  passiveByDefault: true,
  requiresUserOptIn: true,
  requiresIsolation: true,
  allowedBackends: ['docker', 'windows-sandbox', 'hyperv', 'windows-host-agent'],
  maxRuntimeMs: 300_000,
  networkPolicy: 'restricted',
  sinkholedOnly: true,
  noArbitraryOutboundNetwork: true,
  validationPlannerRequired: true,
  workflowSearchAutoRun: false,
  notes: [
    'managed.fake_c2 starts a loopback Fake C2 listener and must be run only after explicit analyst opt-in.',
    'Use an isolated runtime with sinkholed or record-only routing; do not permit arbitrary outbound network from the sample.',
    'Run debug.network.plan, dynamic.runtime.status, and tool.readiness as the validation planner before enabling auto_run_sample or DNS redirects.',
    'workflow.search may recommend or activate this tool but must not start the listener, execute the sample, or mutate DNS/network state.',
  ],
}

export const FAKE_C2_WORKER_BACKEND: BackendWorkerContract = {
  version: 'backend-worker.v1',
  backendName: 'Managed Fake C2 Runtime Worker',
  backendKind: 'delegated-runtime',
  adapter: 'managed-fake-c2.python-worker',
  availability: 'required',
  supportedModes: ['live_sandbox', 'manual_runtime'],
  defaultMode: 'live_sandbox',
  inputArtifactTypes: ['sample', 'static_config_carver', 'c2_extraction', 'debug_network_plan'],
  outputArtifactTypes: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
  policy: {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: true,
    noMutation: true,
    defaultTimeoutMs: 300_000,
    notes: [
      'Readiness checks describe the worker contract only; they do not start the listener.',
      'The worker binds the Fake C2 listener to 127.0.0.1 and expects runtime routing to be isolated and sinkholed.',
      'auto_run_sample remains false by default and requires a separate explicit opt-in inside a managed sandbox.',
      'No arbitrary outbound network is allowed; route sample traffic to the loopback sinkhole or record-only runtime capture.',
    ],
    sinkholedOnly: true,
    noArbitraryOutboundNetwork: true,
    bindsLoopbackOnly: true,
    autoRunSampleDefault: false,
  },
  readiness: {
    doesNotStartBackend: true,
    setupActions: [
      'Run tool.readiness for managed.fake_c2 and confirm the runtime advertises the python-worker contract.',
      'Use debug.network.plan as the validation planner for DNS, hosts, proxy, or sinkhole routing before execution.',
      'Keep the runtime isolated and sinkholed; block arbitrary outbound network from the sample.',
      'Install openssl or set use_tls=false for HTTP-only validation sessions.',
      'Install dotnet or mono only when auto_run_sample=true has been explicitly approved in an isolated runtime.',
    ],
    missingBackendBehavior:
      'Search and readiness remain metadata-only; managed.fake_c2 must not start from workflow.search and execution is blocked until the delegated runtime worker is available.',
    qualityContract: {
      schema: 'rikune.managed_fake_c2.quality_contract.v1',
      requiredBeforeExecution: [
        'explicit-opt-in',
        'isolated-runtime-selected',
        'sinkholed-network-policy-confirmed',
        'validation-planner-reviewed',
      ],
      forbiddenAutomation: [
        'workflow.search must not invoke managed.fake_c2 automatically',
        'no arbitrary outbound network from the sample',
        'no DNS or hosts mutation outside the isolated runtime',
      ],
    },
    handoffContract: {
      schema: 'rikune.managed_fake_c2.handoff_contract.v1',
      producedArtifacts: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
      expectedConsumers: [
        'dynamic.behavior.capture',
        'malware.intel.loop',
        'analysis.evidence.graph',
        'report.generate',
      ],
    },
  },
}

export const fakeC2ToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Start an explicit opt-in, isolated Fake C2 / FakeNet-style HTTP sinkhole with custom endpoint responses. ' +
    'Configure responses for /plugin, /ping, /gate, /task, beacon gate, tasking endpoint, and C2 emulation paths ' +
    'to drive the sample into deeper operational logic inside a managed sandbox. Captures incoming requests ' +
    'for analysis. Supports TLS self-signed certificates, response delays, DNS hosts redirect handoff notes, ' +
    'and validation-planner handoff. workflow.search may recommend this tool but must not run it automatically.',
  inputSchema: FakeC2InputSchema,
  outputSchema: FakeC2OutputSchema,
  aspects: managedFakeC2Aspects(),
  artifacts: [
    {
      type: FAKE_C2_ARTIFACT_TYPES.session,
      description:
        'Persisted Fake C2 session JSON containing listener metadata, endpoint configuration, captured HTTP requests, DNS redirect handoff notes, and provenance.',
      mime: 'application/json',
      required: true,
    },
    {
      type: FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope,
      description:
        'Runtime-node worker artifact managed_fake_c2.json written inside the isolated runtime working directory.',
      mime: 'application/json',
      required: false,
    },
  ],
  evidence: [
    {
      category: 'network',
      artifactTypes: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
      description: 'Loopback sinkhole listener metadata and captured network requests.',
    },
    {
      category: 'http',
      artifactTypes: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
      description: 'HTTP method, path, headers, body preview, and body hash request evidence.',
    },
    {
      category: 'c2',
      artifactTypes: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
      description: 'C2 beacon gate, tasking endpoint, and response emulation evidence.',
    },
    {
      category: 'timeline',
      artifactTypes: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
      description: 'Request timestamps suitable for behavior timeline and evidence graph handoff.',
    },
    {
      category: 'provenance',
      artifactTypes: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
      description:
        'Runtime policy, explicit opt-in, sinkhole boundary, and worker provenance notes.',
    },
    {
      category: 'workflow',
      artifactTypes: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
      description:
        'Validation planner, dynamic behavior capture, evidence graph, and report handoff.',
    },
  ],
  workflowRecipes: [
    {
      id: 'managed-fake-c2.c2-emulation-validation',
      title: 'Fake C2 sinkhole validation lab',
      description:
        'Route static C2 indicators through a validation planner into an explicit opt-in isolated Fake C2 sinkhole, then hand captured requests to behavior capture, malware intel, evidence graph, and reporting.',
      startsWith: [
        'static.config.carver',
        'c2.extract',
        'debug.network.plan',
        'tool.readiness',
        TOOL_NAME,
      ],
      nextTools: MANAGED_FAKE_C2_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['static_config_carver', 'c2_extraction', 'debug_network_plan'],
      producesArtifacts: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
      evidence: ['network', 'http', 'c2', 'timeline', 'behavior', 'workflow', 'provenance'],
      safety: [
        'explicit-opt-in',
        'isolated-runtime',
        'sinkholed-network-only',
        'no-arbitrary-outbound-network',
        'validation-planner-required',
        'workflow-search-does-not-run',
      ],
      runtimeBackends: ['python-worker', 'managed-sandbox', 'windows-sandbox', 'hyperv'],
      searchTags: [
        'fake c2',
        'fakenet',
        'fakenet-style',
        'http beacon',
        'beacon gate',
        'network_ioc',
        'network-ioc',
        'sinkhole',
        'c2 emulation',
        'dns redirect',
        'tls self-signed',
        'tasking endpoint',
        'validation planner',
      ],
      quality: {
        schema: 'rikune.managed_fake_c2.workflow_quality.v1',
        gates: [
          'Explicit analyst opt-in is required before managed.fake_c2 execution.',
          'Runtime must be isolated and sinkholed with no arbitrary outbound network.',
          'debug.network.plan and tool.readiness should be reviewed as the validation planner.',
          'Captured request evidence should be handed to analysis.evidence.graph or report.generate.',
        ],
      },
      handoff: {
        contract: 'rikune.managed_fake_c2.handoff_contract.v1',
        mode: 'static-c2-indicators-to-isolated-sinkhole-validation',
        expectedInputs: ['sample_id', 'endpoints', 'explicit opt-in', 'isolated runtime'],
        producedArtifacts: [FAKE_C2_ARTIFACT_TYPES.session, FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope],
        consumers: [
          'dynamic.behavior.capture',
          'malware.intel.loop',
          'analysis.evidence.graph',
          'report.generate',
        ],
        forbiddenAutomation: [
          'workflow.search must not run managed.fake_c2 automatically',
          'no arbitrary outbound network',
        ],
      },
    },
  ],
  runtimePolicy: FAKE_C2_RUNTIME_POLICY,
  runtime: {
    type: 'python-worker',
    handler: WORKER_HANDLER,
  },
  workerBackend: FAKE_C2_WORKER_BACKEND,
}

/* ── Worker bridge ─────────────────────────────────────────────────────── */

async function callFakeC2Worker(
  request: Record<string, unknown>,
  pythonCmd: string,
  resolvePackagePath: PluginToolDeps['resolvePackagePath']
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath(
      'src',
      'plugins',
      'managed-fake-c2',
      'workers',
      'managed_fake_c2_worker.py'
    )
    const proc = spawn(pythonCmd, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    proc.stdout.on('data', (d: Buffer) => {
      stdout += d.toString()
    })
    proc.stderr.on('data', (d: Buffer) => {
      stderr += d.toString()
    })
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`Fake C2 worker exited ${code}: ${stderr.slice(0, 500)}`))
        return
      }
      try {
        resolve(JSON.parse(stdout.trim()))
      } catch (e) {
        reject(new Error(`Parse: ${(e as Error).message}`))
      }
    })
    proc.on('error', (e) => reject(new Error(`Spawn: ${e.message}`)))
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

/* ── Handler ───────────────────────────────────────────────────────────── */

export function createFakeC2Handler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    config,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
    resolvePackagePath,
  } = deps
  const pythonCmd = getPythonCommand(undefined, config?.workers?.static?.pythonPath)

  return async (args: z.infer<typeof FakeC2InputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)

      // No caching — each C2 session is unique
      const result = await callFakeC2Worker(
        {
          action: 'start_fake_c2',
          file_path: samplePath,
          endpoints: args.endpoints,
          listen_port: args.listen_port,
          use_tls: args.use_tls,
          capture_requests: args.capture_requests,
          default_response: args.default_response,
          timeout_seconds: args.timeout_seconds,
          auto_run_sample: args.auto_run_sample,
          dns_redirect: args.dns_redirect ?? [],
        },
        pythonCmd,
        resolvePackagePath
      )
      const enrichedResult = {
        ...result,
        ...buildManagedFakeC2Envelope({
          sample_id: args.sample_id,
          endpoint_count: args.endpoints.length,
          dns_redirect_count: args.dns_redirect?.length ?? 0,
          capture_requests: args.capture_requests,
          use_tls: args.use_tls,
          auto_run_sample: args.auto_run_sample,
          listen_port: args.listen_port,
          timeout_seconds: args.timeout_seconds,
          worker_result: result,
        }),
      }

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          FAKE_C2_ARTIFACT_TYPES.session,
          'managed-fake-c2',
          enrichedResult
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        /* non-fatal */
      }

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
