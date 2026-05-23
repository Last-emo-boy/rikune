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
  pluginId: 'restringer',
  toolName: 'restringer.deobfuscation.plan',
  title: 'REstringer JavaScript deobfuscation plan',
  description:
    'Build a passive REstringer integration plan for JavaScript string-array and expression deobfuscation without evaluating JavaScript or invoking the external tool.',
  backendName: 'REstringer',
  formats: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'html'],
  platforms: ['node', 'browser', 'cross-platform'],
  architectures: ['js-vm', 'v8'],
  capabilities: [
    'string-array-recovery',
    'javascript-expression-simplification',
    'eval-preflight',
    'jsvmp-preprocessing',
    'workflow-routing',
  ],
  evidence: ['structure', 'strings', 'behavior', 'artifact'],
  artifactType: 'restringer_deobfuscation_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'restringer.javascript.preprocess-plan',
    title: 'REstringer JavaScript preprocessing planning',
    description:
      'Plan a REstringer-style string and expression deobfuscation pass before deeper JSVMP or JSIR analysis.',
    startsWith: ['javascript.obfuscation.profile', 'restringer.deobfuscation.plan'],
    nextTools: ['jsir.cascade.plan', 'jsvmp.bytecode.plan', 'strings.extract', 'yara.generate'],
    requiredArtifacts: ['javascript_obfuscation_profile', 'enriched_string_analysis'],
    producesArtifacts: [
      'restringer_deobfuscation_plan',
      'javascript_string_array_plan',
      'javascript_expression_simplification_plan',
    ],
    evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'string-array-scope',
      title: 'String-array scope',
      purpose:
        'Identify string-array, decoder-function, and eval/codegen hints from passive JavaScript profile evidence.',
      inputs: ['javascript_obfuscation_profile', 'enriched_string_analysis'],
      outputs: ['javascript_string_array_plan'],
      safety: ['metadata_only'],
    },
    {
      id: 'expression-plan',
      title: 'Expression simplification plan',
      purpose:
        'Plan constant expression, decoder call, dead expression, and folded literal recovery without executing source.',
      inputs: ['javascript_string_array_plan'],
      outputs: ['javascript_expression_simplification_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'downstream-handoff',
      title: 'Downstream deobfuscation handoff',
      purpose:
        'Route simplified output expectations to JSIR/CASCADE or JSVMP bytecode recovery workers after fixture validation.',
      inputs: ['javascript_expression_simplification_plan'],
      outputs: ['javascript_deobfuscation_handoff_plan'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'humansecurity-restringer',
      name: 'HumanSecurity/REstringer',
      source: 'https://github.com/HumanSecurity/restringer',
      role: 'JavaScript deobfuscator candidate for recovering string and expression obfuscation before VM analysis.',
      readiness: 'optional_external',
      notes: [
        'Keep optional and pinned; default planner does not invoke the CLI or import its runtime.',
        'Run only on local source through a future worker with strict timeout and output schema.',
      ],
    },
  ],
  recommendedNextTools: [
    'javascript.obfuscation.profile',
    'jsir.cascade.plan',
    'jsvmp.bytecode.plan',
    'strings.extract',
  ],
  safetyNotes: [
    'REstringer planning never evaluates JavaScript, starts Node/V8, or invokes an external deobfuscator.',
    'Future workers must preserve original source, emit diff artifacts, and refuse network access.',
  ],
}

const workerSpec: FrontierWorkerToolSpec = {
  pluginId: 'restringer',
  toolName: 'restringer.deobfuscation.run',
  description:
    'Run a bounded REstringer-style static JavaScript preprocessing worker on local artifacts. Builtin mode uses safe deterministic fixture logic; external mode requires RESTRINGER_PATH.',
  backendName: 'REstringer',
  adapter: 'restringer.static.preprocess',
  envVar: 'RESTRINGER_PATH',
  aspects: buildBackendPlanAspects(spec),
  artifacts: [
    {
      type: 'restringer_deobfuscation_result',
      description: 'REstringer static deobfuscation result',
    },
    { type: 'javascript_string_array_recovery', description: 'Recovered string-array metadata' },
  ],
  evidence: [
    { category: 'strings', artifactTypes: ['javascript_string_array_recovery'] },
    { category: 'provenance', artifactTypes: ['restringer_deobfuscation_result'] },
  ],
  workflowRecipe: {
    id: 'restringer.javascript.preprocess-worker',
    title: 'REstringer static preprocessing worker',
    startsWith: ['javascript.obfuscation.profile', 'restringer.deobfuscation.run'],
    nextTools: ['jsimplifier.pipeline.run', 'jsir.cascade.normalize', 'jsvmp.bytecode.plan'],
    producesArtifacts: ['restringer_deobfuscation_result', 'javascript_string_array_recovery'],
    evidence: ['strings', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  readinessSetupActions: ['Set RESTRINGER_PATH to a pinned REstringer wrapper for external mode.'],
  fixtureData: {
    recovered_string_arrays: 1,
    simplified_expressions: 2,
    static_only: true,
  },
  recommendedNextTools: [
    'jsimplifier.pipeline.run',
    'jsir.cascade.normalize',
    'jsvmp.bytecode.plan',
  ],
}

const restringerPlugin = definePlugin({
  id: 'restringer',
  name: 'REstringer Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'html'],
      findings: ['obfuscated', 'string-array', 'eval', 'packed', 'jsvmp'],
    },
    category: 'reverse-engineering',
  },
  description: 'Passive REstringer JavaScript string-array and expression deobfuscation planning.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'RESTRINGER_PATH',
      description: 'Optional REstringer path for a future bounded static worker',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'restringer',
      target: '$RESTRINGER_PATH',
      envVar: 'RESTRINGER_PATH',
      required: false,
      description: 'Optional REstringer checkout or wrapper',
      dockerInstall: 'Provide a pinned REstringer checkout; not installed by default',
      dockerFeature: 'restringer',
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

export default restringerPlugin
