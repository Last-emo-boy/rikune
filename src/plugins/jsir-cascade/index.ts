import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'jsir-cascade',
  toolName: 'jsir.cascade.plan',
  title: 'JSIR/CASCADE JavaScript IR plan',
  description:
    'Build a passive JSIR/CASCADE-style JavaScript normalization and deobfuscation plan without evaluating source, starting Node/V8, or invoking an external deobfuscator.',
  backendName: 'JSIR/CASCADE',
  formats: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html'],
  platforms: ['node', 'browser', 'cross-platform'],
  architectures: ['js-vm', 'v8'],
  capabilities: [
    'javascript-ir-normalization',
    'ast-deobfuscation-plan',
    'constant-folding-plan',
    'control-flow-structuring',
    'jsvmp-preprocessing',
    'workflow-routing',
  ],
  evidence: ['structure', 'strings', 'behavior', 'artifact'],
  artifactType: 'jsir_cascade_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'jsir.cascade.normalization-plan',
    title: 'JSIR/CASCADE normalization planning',
    description:
      'Plan JavaScript IR normalization, constant folding, control-flow cleanup, and JSVMP preprocessing from passive JavaScript obfuscation profiles.',
    startsWith: ['javascript.obfuscation.profile', 'jsir.cascade.plan'],
    nextTools: [
      'jsvmp.bytecode.plan',
      'strings.extract',
      'yara.generate',
      'analysis.evidence.graph',
    ],
    requiredArtifacts: ['javascript_obfuscation_profile', 'enriched_string_analysis'],
    producesArtifacts: ['jsir_cascade_plan', 'javascript_ir_plan', 'deobfuscation_pass_plan'],
    evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'profile-to-ir',
      title: 'Profile to IR scope',
      purpose:
        'Map JavaScript obfuscation signals, source-map hints, and string-array evidence into candidate IR normalization scopes.',
      inputs: [
        'javascript_obfuscation_profile',
        'source_map_inventory',
        'enriched_string_analysis',
      ],
      outputs: ['javascript_ir_scope'],
      safety: ['metadata_only'],
    },
    {
      id: 'static-passes',
      title: 'Static pass plan',
      purpose:
        'Plan AST parsing, constant folding, string-array recovery, dead-branch cleanup, and control-flow structuring without executing JavaScript.',
      inputs: ['javascript_ir_scope'],
      outputs: ['deobfuscation_pass_plan', 'javascript_ir_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'vm-preprocess',
      title: 'JSVMP preprocessing handoff',
      purpose:
        'Prepare normalized source/IR artifacts that can feed bytecode-container and handler-map recovery later.',
      inputs: ['javascript_ir_plan', 'deobfuscation_pass_plan'],
      outputs: ['jsvmp_preprocessing_plan'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'google-jsir',
      name: 'google/jsir',
      source: 'local-roadmap',
      role: 'JavaScript IR and analysis framework used as a design target for normalization and deobfuscation passes.',
      readiness: 'optional_external',
      notes: [
        'Treat as an optional pinned backend; never fetch or execute code during default triage.',
        'Use source-local parsing only through a future bounded static worker.',
      ],
    },
    {
      id: 'cascade-pipeline',
      name: 'CASCADE-style deobfuscation pipeline',
      source: 'local-roadmap',
      role: 'Layer IR normalization, simplification, and JSVMP preprocessing as a staged worker contract.',
      readiness: 'future_worker',
      notes: [
        'Start with deterministic AST fixtures before adding any interpreter-assisted normalization.',
        'Expose every pass as structured artifacts so downstream JSVMP plans do not parse prose.',
      ],
    },
  ],
  recommendedNextTools: [
    'javascript.obfuscation.profile',
    'jsvmp.bytecode.plan',
    'strings.extract',
    'analysis.evidence.graph',
  ],
  safetyNotes: [
    'JSIR/CASCADE planning never evaluates JavaScript or starts Node, V8, browser automation, or external deobfuscators.',
    'Future workers must enforce source-size, parse-time, pass-count, and artifact budgets.',
  ],
}

const jsirCascadePlugin = definePlugin({
  id: 'jsir-cascade',
  name: 'JSIR/CASCADE Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html'],
      findings: ['obfuscated', 'jsvmp', 'eval', 'packed', 'string-array'],
    },
    category: 'reverse-engineering',
  },
  description: 'Passive JSIR/CASCADE-style JavaScript IR normalization and deobfuscation planning.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'JSIR_WORKER_PATH',
      description: 'Optional future JSIR/CASCADE static worker path',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'jsir-worker',
      target: '$JSIR_WORKER_PATH',
      envVar: 'JSIR_WORKER_PATH',
      required: false,
      description: 'Optional local JSIR/CASCADE static worker',
      dockerInstall: 'Provide a pinned local JSIR/CASCADE worker; not installed by default',
      dockerFeature: 'jsir-cascade',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default jsirCascadePlugin
