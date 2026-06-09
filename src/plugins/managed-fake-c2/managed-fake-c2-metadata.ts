export const MANAGED_FAKE_C2_TOOL_NAME = 'managed.fake_c2'
export const MANAGED_FAKE_C2_TOOL_VERSION = '1.1.0'

export const MANAGED_FAKE_C2_ARTIFACT_TYPES = {
  session: 'fake_c2_session',
  runtimeEnvelope: 'managed_fake_c2',
} as const

export const MANAGED_FAKE_C2_FORMATS = ['pe', 'dll', 'dotnet', 'pe-clr']
export const MANAGED_FAKE_C2_PLATFORMS = ['windows']
export const MANAGED_FAKE_C2_ARCHITECTURES = ['x86', 'x64', 'cil']
export const MANAGED_FAKE_C2_EXECUTION = [
  'dynamic',
  'runtime-validation',
  'explicit-opt-in',
  'workflow-handoff',
]
export const MANAGED_FAKE_C2_RUNTIMES = [
  'managed-sandbox',
  'fake-c2',
  'runtime-node',
  'python-worker',
]

export const MANAGED_FAKE_C2_SAFETY = [
  'explicit-opt-in',
  'opt_in_dynamic',
  'requires-isolation',
  'requires_isolation',
  'isolated-sinkhole',
  'sinkholed-only',
  'no-arbitrary-outbound-network',
  'workflow-search-does-not-run',
  'validation-planner-required',
  'no_live_sample_by_default',
]

export const MANAGED_FAKE_C2_CAPABILITIES = [
  'fake-c2',
  'c2-emulation',
  'http-sinkhole',
  'network-sinkhole',
  'beacon-gate',
  'request-capture',
  'c2-capture',
  'dns-redirect-handoff',
  'runtime-handoff',
  'validation-planner',
  'sandbox-support',
  'fakenet-style',
  'workflow-handoff',
  'quality-gates',
  'search-profile',
]

export const MANAGED_FAKE_C2_EVIDENCE = [
  'network',
  'c2',
  'timeline',
  'http',
  'behavior',
  'request',
  'workflow',
  'provenance',
  'runtime-boundary',
]

export const MANAGED_FAKE_C2_SEARCH_TERMS = [
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
  'managed sandbox',
]

export const MANAGED_FAKE_C2_PROFILE_TERMS = [
  'managed-fake-c2',
  'fake-c2-sinkhole',
  'fakenet-style-profile',
  'explicit-opt-in-runtime',
  'isolated-sinkhole-runtime',
  'network-ioc-validation',
  'beacon-gate-validation',
  'request-capture-profile',
]

export const MANAGED_FAKE_C2_ROUTE_TERMS = [
  'managed_fake_c2_profile',
  'static_c2_to_sinkhole_validation',
  'fake_c2_request_capture_handoff',
  'dns_redirect_handoff',
  'beacon_gate_validation',
  'approval_gated_fake_c2',
  'loopback_sinkhole_listener',
  'ephemeral_tls_certificate',
  'dns_redirect_isolated_runtime_only',
  'managed_sandbox_fake_c2',
  'isolated_runtime_required',
  'workflow_search_does_not_run',
  'no_arbitrary_outbound_network',
]

export const MANAGED_FAKE_C2_EVIDENCE_SUMMARY_SCHEMA = 'rikune.managed_fake_c2.evidence_summary.v1'
export const MANAGED_FAKE_C2_WORKFLOW_HANDOFF_SCHEMA = 'rikune.managed_fake_c2.workflow_handoff.v1'
export const MANAGED_FAKE_C2_QUALITY_GATES_SCHEMA = 'rikune.managed_fake_c2.quality_gates.v1'
export const MANAGED_FAKE_C2_RUNTIME_READINESS_SCHEMA =
  'rikune.managed_fake_c2.runtime_readiness.v1'
export const MANAGED_FAKE_C2_EXECUTION_PROFILE_SCHEMA =
  'rikune.managed_fake_c2.execution_profile.v1'

export const MANAGED_FAKE_C2_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'dynamic.behavior.capture',
  'malware.intel.loop',
  'analysis.evidence.graph',
  'report.generate',
]

export function managedFakeC2Aspects(capabilities: string[] = MANAGED_FAKE_C2_CAPABILITIES) {
  return {
    formats: MANAGED_FAKE_C2_FORMATS,
    platforms: MANAGED_FAKE_C2_PLATFORMS,
    architectures: MANAGED_FAKE_C2_ARCHITECTURES,
    execution: MANAGED_FAKE_C2_EXECUTION,
    runtimes: MANAGED_FAKE_C2_RUNTIMES,
    safety: MANAGED_FAKE_C2_SAFETY,
    capabilities,
    evidence: MANAGED_FAKE_C2_EVIDENCE,
    search: MANAGED_FAKE_C2_SEARCH_TERMS,
    profile: MANAGED_FAKE_C2_PROFILE_TERMS,
    route_terms: MANAGED_FAKE_C2_ROUTE_TERMS,
  }
}

export type ManagedFakeC2EnvelopeInput = {
  sample_id: string
  endpoint_count: number
  dns_redirect_count: number
  capture_requests: boolean
  use_tls: boolean
  auto_run_sample: boolean
  listen_port: number
  timeout_seconds: number
  worker_result: Record<string, unknown>
}

function nestedData(result: Record<string, unknown>): Record<string, unknown> {
  const data = result.data
  return data && typeof data === 'object' && !Array.isArray(data)
    ? (data as Record<string, unknown>)
    : result
}

function requestCount(result: Record<string, unknown>): number {
  const data = nestedData(result)
  const explicit = data.total_requests_captured
  if (typeof explicit === 'number' && Number.isFinite(explicit)) return explicit
  const requests = data.requests
  return Array.isArray(requests) ? requests.length : 0
}

function sampleExecutionPresent(result: Record<string, unknown>): boolean {
  const data = nestedData(result)
  return data.sample_execution !== null && data.sample_execution !== undefined
}

export function buildManagedFakeC2Envelope(input: ManagedFakeC2EnvelopeInput) {
  const capturedRequests = requestCount(input.worker_result)
  const listenerStarted = Boolean(input.worker_result.ok)
  const sampleExecution = sampleExecutionPresent(input.worker_result)
  const executionMode = input.auto_run_sample ? 'listener-plus-sample-run' : 'listener-only'
  const evidenceConfidence =
    capturedRequests > 0
      ? 'observed-request-evidence'
      : listenerStarted
        ? 'listener-only'
        : 'not-started'

  return {
    recommended_next_tools: MANAGED_FAKE_C2_FOLLOW_UP_TOOLS,
    runtime_readiness: {
      schema: MANAGED_FAKE_C2_RUNTIME_READINESS_SCHEMA,
      source_tool: MANAGED_FAKE_C2_TOOL_NAME,
      status:
        input.auto_run_sample || input.dns_redirect_count > 0 ? 'approval_gated' : 'listener_ready',
      listener: {
        bind_host: '127.0.0.1',
        binds_loopback_only: true,
        listen_port: input.listen_port,
        tls_enabled: input.use_tls,
        tls_certificate: input.use_tls ? 'ephemeral-self-signed' : 'not-used',
        timeout_seconds: input.timeout_seconds,
      },
      required_before_execution: [
        'explicit analyst opt-in',
        'isolated runtime selected',
        'sinkholed network policy confirmed',
        'debug.network.plan reviewed',
        'tool.readiness reviewed',
      ],
      network_boundary: {
        allowed_scope: 'loopback-sinkhole-only',
        arbitrary_outbound_network_allowed: false,
        dns_redirect_requested: input.dns_redirect_count > 0,
        dns_redirect_requires_isolated_runtime: input.dns_redirect_count > 0,
        host_dns_or_hosts_mutation_allowed: false,
      },
      sample_execution: {
        requested: input.auto_run_sample,
        result_present: sampleExecution,
        allowed_without_explicit_approval: false,
        runtime_dependency_profile: input.auto_run_sample ? ['dotnet', 'mono'] : [],
      },
    },
    execution_profile: {
      schema: MANAGED_FAKE_C2_EXECUTION_PROFILE_SCHEMA,
      source_tool: MANAGED_FAKE_C2_TOOL_NAME,
      mode: executionMode,
      confidence: evidenceConfidence,
      evidence_strength:
        capturedRequests > 0
          ? 'runtime-observed-network'
          : listenerStarted
            ? 'listener-configured-no-traffic'
            : 'metadata-only',
      route_terms: [
        'approval_gated_fake_c2',
        'loopback_sinkhole_listener',
        ...(input.use_tls ? ['ephemeral_tls_certificate'] : []),
        ...(input.dns_redirect_count > 0 ? ['dns_redirect_isolated_runtime_only'] : []),
        ...(input.auto_run_sample ? ['managed_sandbox_fake_c2'] : []),
      ],
      counts: {
        endpoints_configured: input.endpoint_count,
        dns_redirects: input.dns_redirect_count,
        requests_captured: capturedRequests,
      },
    },
    evidence_summary: {
      schema: MANAGED_FAKE_C2_EVIDENCE_SUMMARY_SCHEMA,
      source_tool: MANAGED_FAKE_C2_TOOL_NAME,
      sample_id: input.sample_id,
      artifact_type: MANAGED_FAKE_C2_ARTIFACT_TYPES.session,
      route_terms: MANAGED_FAKE_C2_ROUTE_TERMS,
      evidence_categories: MANAGED_FAKE_C2_EVIDENCE,
      confidence: evidenceConfidence,
      counts: {
        endpoints_configured: input.endpoint_count,
        dns_redirects: input.dns_redirect_count,
        requests_captured: capturedRequests,
      },
      runtime_profile: {
        listen_port: input.listen_port,
        timeout_seconds: input.timeout_seconds,
        tls_enabled: input.use_tls,
        capture_requests: input.capture_requests,
        auto_run_sample_requested: input.auto_run_sample,
      },
      dynamic_only_after_opt_in: true,
      backend_semantics: {
        listener_started: listenerStarted,
        sample_execution_requested: input.auto_run_sample,
        sample_execution_result_present: sampleExecution,
        workflow_search_started_listener: false,
        arbitrary_outbound_network_allowed: false,
      },
    },
    workflow_handoff: {
      schema: MANAGED_FAKE_C2_WORKFLOW_HANDOFF_SCHEMA,
      handoff_mode: 'static_c2_indicators_to_isolated_sinkhole_validation',
      source_tool: MANAGED_FAKE_C2_TOOL_NAME,
      sample_id: input.sample_id,
      recommended_next_tools: MANAGED_FAKE_C2_FOLLOW_UP_TOOLS,
      artifact_contract: {
        consumes: ['sample', 'static_config_carver', 'c2_extraction', 'debug_network_plan'],
        produces: [
          MANAGED_FAKE_C2_ARTIFACT_TYPES.session,
          MANAGED_FAKE_C2_ARTIFACT_TYPES.runtimeEnvelope,
        ],
        mime: 'application/json',
        expected_consumers: MANAGED_FAKE_C2_FOLLOW_UP_TOOLS,
      },
      dynamic_boundary: {
        activation_boundary: 'result-scoped',
        explicit_opt_in_required: true,
        isolated_runtime_required: true,
        validation_planner_required: true,
        approval_gate: 'external-policy-guard-or-runtime-profile',
        allowed_network_scope: 'loopback-sinkhole-only',
        workflow_search_can_start_listener: false,
        workflow_search_can_execute_sample: false,
        arbitrary_outbound_network_allowed: false,
        dns_or_hosts_mutation_outside_runtime_allowed: false,
        dns_redirect_requires_isolated_runtime: input.dns_redirect_count > 0,
        auto_run_sample_requested: input.auto_run_sample,
        sample_execution_result_present: sampleExecution,
      },
      routing: [
        {
          goal: 'behavior-capture-correlation',
          priority: capturedRequests > 0 ? 'high' : 'medium',
          route_terms: ['fake_c2_request_capture_handoff', 'beacon_gate_validation'],
          next_tools: ['dynamic.behavior.capture', 'analysis.evidence.graph'],
          consumes: [MANAGED_FAKE_C2_ARTIFACT_TYPES.session],
          produces: ['behavior_timeline', 'evidence_graph'],
        },
        {
          goal: 'malware-intel-loop',
          priority: capturedRequests > 0 ? 'medium' : 'low',
          route_terms: ['static_c2_to_sinkhole_validation'],
          next_tools: ['malware.intel.loop'],
          consumes: [MANAGED_FAKE_C2_ARTIFACT_TYPES.session],
          produces: ['malware_intel_loop'],
        },
        {
          goal: 'dns-redirect-review',
          priority: input.dns_redirect_count > 0 ? 'medium' : 'low',
          route_terms: ['dns_redirect_handoff', 'isolated_runtime_required'],
          next_tools: ['artifact.read', 'report.generate'],
          consumes: [MANAGED_FAKE_C2_ARTIFACT_TYPES.session],
          produces: ['report'],
          blocking_conditions: [
            'Apply DNS or hosts redirects only inside the isolated runtime; do not mutate the analyst host.',
          ],
        },
        {
          goal: 'evidence-and-reporting',
          priority: 'medium',
          route_terms: ['managed_fake_c2_profile', 'no_arbitrary_outbound_network'],
          next_tools: ['analysis.evidence.graph', 'artifact.read', 'report.generate'],
          consumes: [MANAGED_FAKE_C2_ARTIFACT_TYPES.session],
          produces: ['evidence_graph', 'report'],
        },
      ],
      quality_gates_schema: MANAGED_FAKE_C2_QUALITY_GATES_SCHEMA,
    },
    quality_gates: {
      schema: MANAGED_FAKE_C2_QUALITY_GATES_SCHEMA,
      explicit_opt_in_required: true,
      isolated_runtime_required: true,
      validation_planner_required: true,
      sinkholed_network_only: true,
      listener_bound_loopback_only: true,
      tls_certificate_ephemeral: input.use_tls,
      workflow_search_auto_run: false,
      workflow_search_started_listener: false,
      arbitrary_outbound_network_allowed: false,
      dns_or_hosts_mutation_outside_runtime_allowed: false,
      dns_redirect_requires_isolated_runtime: input.dns_redirect_count > 0,
      endpoint_config_present: input.endpoint_count > 0,
      request_capture_enabled: input.capture_requests,
      requests_captured: capturedRequests > 0,
      auto_run_sample_requested: input.auto_run_sample,
      sample_execution_result_present: sampleExecution,
    },
  }
}
