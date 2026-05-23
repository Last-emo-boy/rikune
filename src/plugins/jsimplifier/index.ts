import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'
import {
  createFrontierWorkerHandler,
  createFrontierWorkerToolDefinition,
  type FrontierWorkerToolSpec,
} from '../frontier-worker-tools.js'

const spec: BackendPlanSpec = {
  pluginId: 'jsimplifier',
  toolName: 'jsimplifier.pipeline.plan',
  title: 'JSIMPLIFIER deobfuscation pipeline plan',
  description:
    'Build a passive JSIMPLIFIER-style JavaScript deobfuscation plan without dynamic tracing, LLM calls, network access, Node/V8 startup, or source evaluation.',
  backendName: 'JSIMPLIFIER',
  formats: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html'],
  platforms: ['node', 'browser', 'cross-platform'],
  architectures: ['js-vm', 'v8'],
  capabilities: [
    'javascript-deobfuscation-pipeline',
    'ast-static-analysis-plan',
    'dynamic-trace-gate',
    'identifier-renaming-plan',
    'benchmark-routing',
    'workflow-routing',
  ],
  evidence: ['structure', 'strings', 'behavior', 'artifact'],
  artifactType: 'jsimplifier_pipeline_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'jsimplifier.javascript.pipeline-plan',
    title: 'JSIMPLIFIER JavaScript deobfuscation planning',
    description:
      'Plan a JSIMPLIFIER-style staged pipeline with preprocessing, AST/static analysis, optional trace gates, and readability-oriented identifier recovery.',
    startsWith: ['javascript.obfuscation.profile', 'jsimplifier.pipeline.plan'],
    nextTools: [
      'restringer.deobfuscation.plan',
      'jsir.cascade.plan',
      'jsvmp.bytecode.plan',
      'analysis.evidence.graph',
    ],
    requiredArtifacts: ['javascript_obfuscation_profile', 'enriched_string_analysis'],
    producesArtifacts: [
      'jsimplifier_pipeline_plan',
      'javascript_static_pass_plan',
      'javascript_identifier_recovery_plan',
    ],
    evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'preprocess-scope',
      title: 'Preprocessing scope',
      purpose:
        'Map input format, parser tolerance needs, string-array signals, control-flow flattening, and source-map hints.',
      inputs: [
        'javascript_obfuscation_profile',
        'source_map_inventory',
        'enriched_string_analysis',
      ],
      outputs: ['javascript_preprocess_plan'],
      safety: ['metadata_only'],
    },
    {
      id: 'static-pipeline',
      title: 'AST/static pipeline plan',
      purpose:
        'Plan static AST passes, control/data-flow simplification, entropy metrics, and readability checks without executing JavaScript.',
      inputs: ['javascript_preprocess_plan'],
      outputs: ['javascript_static_pass_plan', 'javascript_readability_metric_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'dynamic-llm-gates',
      title: 'Dynamic and LLM gate plan',
      purpose:
        'Mark dynamic trace and LLM identifier-renaming stages as separately gated future workers, not default plugin behavior.',
      inputs: ['javascript_static_pass_plan'],
      outputs: ['javascript_identifier_recovery_plan', 'javascript_dynamic_trace_gate'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'jsimplifier-paper',
      name: 'JSIMPLIFIER',
      source: 'https://arxiv.org/abs/2512.14070',
      role: 'Recent staged JavaScript deobfuscation pipeline blueprint covering preprocessing, AST analysis, trace gates, and identifier recovery.',
      readiness: 'future_worker',
      notes: [
        'Use the paper as a benchmark and worker-design target, not as a default runtime dependency.',
        'Keep dynamic tracing and LLM-assisted naming behind explicit opt-in and offline fixture tests.',
      ],
    },
  ],
  recommendedNextTools: [
    'javascript.obfuscation.profile',
    'restringer.deobfuscation.plan',
    'jsir.cascade.plan',
    'analysis.evidence.graph',
  ],
  safetyNotes: [
    'JSIMPLIFIER planning does not execute JavaScript, start interpreters, run dynamic traces, call LLMs, or use network access.',
    'Future workers must separate safe static passes from dynamic/LLM stages with explicit policy gates.',
  ],
}

const workerSpec: FrontierWorkerToolSpec = {
  pluginId: 'jsimplifier',
  toolName: 'jsimplifier.pipeline.run',
  description:
    'Run a bounded JSIMPLIFIER-style static deobfuscation pipeline worker on local JavaScript artifacts without executing JavaScript.',
  backendName: 'JSIMPLIFIER',
  adapter: 'jsimplifier.static.pipeline',
  envVar: 'JSIMPLIFIER_WORKER_PATH',
  dockerFeature: 'jsimplifier',
  dockerDefault: '/opt/rikune-backends/jsimplifier/bin/jsimplifier-worker.js',
  installRoute: 'installed',
  installProfile: 'default',
  aspects: buildBackendPlanAspects(spec),
  artifacts: [
    { type: 'jsimplifier_pipeline_result', description: 'JSIMPLIFIER static pipeline output' },
    { type: 'javascript_static_pass_report', description: 'Static pass timeline and metrics' },
  ],
  evidence: [
    { category: 'structure', artifactTypes: ['javascript_static_pass_report'] },
    { category: 'provenance', artifactTypes: ['jsimplifier_pipeline_result'] },
  ],
  workflowRecipe: {
    id: 'jsimplifier.javascript.pipeline-worker',
    title: 'JSIMPLIFIER static pipeline worker',
    startsWith: ['javascript.obfuscation.profile', 'jsimplifier.pipeline.run'],
    nextTools: [
      'restringer.deobfuscation.run',
      'jsir.cascade.normalize',
      'analysis.evidence.graph',
    ],
    producesArtifacts: ['jsimplifier_pipeline_result', 'javascript_static_pass_report'],
    evidence: ['structure', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  readinessSetupActions: [
    'Set JSIMPLIFIER_WORKER_PATH to a pinned local worker for external mode.',
  ],
  fixtureData: {
    pass_timeline: ['parse', 'constant-fold', 'dead-branch-prune', 'identifier-score'],
    confidence_breakdown: {
      syntax: 0.9,
      string_recovery: 0.75,
      control_flow: 0.65,
    },
    static_only: true,
  },
  recommendedNextTools: ['restringer.deobfuscation.run', 'jsir.cascade.normalize'],
}

const jsimplifierPlugin = definePlugin({
  id: 'jsimplifier',
  name: 'JSIMPLIFIER Pipeline Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html'],
      findings: ['obfuscated', 'packed', 'control-flow-flattening', 'string-array', 'jsvmp'],
    },
    category: 'reverse-engineering',
  },
  description: 'Passive JSIMPLIFIER-style JavaScript deobfuscation pipeline planning.',
  version: '1.0.0',
  resources: { workers: 'workers' },
  configSchema: [
    {
      envVar: 'JSIMPLIFIER_WORKER_PATH',
      description: 'Optional future JSIMPLIFIER worker path',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'jsimplifier-worker',
      target: '$JSIMPLIFIER_WORKER_PATH',
      envVar: 'JSIMPLIFIER_WORKER_PATH',
      dockerDefault: '/opt/rikune-backends/jsimplifier/bin/jsimplifier-worker.js',
      required: false,
      description: 'Optional future JSIMPLIFIER static worker',
      dockerInstall: 'Install Rikune static JSIMPLIFIER-style worker',
      dockerFeature: 'jsimplifier',
      dockerValidation: [
        'node /opt/rikune-backends/jsimplifier/bin/jsimplifier-worker.js --self-test',
      ],
      dockerInstallRoute: 'installed',
      dockerInstallProfile: 'default',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
    defineTool({
      ...createFrontierWorkerToolDefinition(workerSpec),
      handler: createFrontierWorkerHandler(workerSpec),
    }),
  ],
})

export default jsimplifierPlugin
