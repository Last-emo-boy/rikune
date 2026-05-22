import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'jsvmp-analysis',
  toolName: 'jsvmp.bytecode.plan',
  title: 'JSVMP bytecode and handler recovery plan',
  description:
    'Build a passive JSVMP bytecode, dispatcher, handler-map, and semantics recovery plan without evaluating JavaScript or starting Node, V8, browser automation, or external deobfuscators.',
  backendName: 'JSVMP Analysis',
  formats: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html', 'v8-cache'],
  platforms: ['node', 'browser', 'cross-platform'],
  architectures: ['js-vm', 'v8'],
  capabilities: [
    'jsvmp-bytecode-recovery',
    'handler-map-recovery',
    'vm-dispatch-analysis',
    'stack-register-modeling',
    'javascript-deobfuscation',
    'workflow-routing',
  ],
  evidence: ['structure', 'strings', 'behavior', 'artifact'],
  artifactType: 'jsvmp_bytecode_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'jsvmp.bytecode.recovery-plan',
    title: 'JSVMP bytecode recovery planning',
    description:
      'Plan a passive JSVMP workflow from JavaScript obfuscation profiles, strings, source-map hints, and VM-dispatch evidence before optional JSIR/CASCADE or local handler-map workers.',
    startsWith: ['javascript.obfuscation.profile', 'jsvmp.bytecode.plan'],
    nextTools: ['strings.extract', 'yara.generate', 'analysis.evidence.graph', 'report.generate'],
    requiredArtifacts: ['javascript_obfuscation_profile', 'enriched_string_analysis'],
    producesArtifacts: ['jsvmp_bytecode_plan', 'jsvmp_handler_map', 'jsvmp_semantics_model'],
    evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'profile-correlation',
      title: 'Profile correlation',
      purpose:
        'Correlate JavaScript obfuscation profile signals with strings, source-map references, eval-like call sites, and VM-dispatch hints.',
      inputs: [
        'javascript_obfuscation_profile',
        'enriched_string_analysis',
        'source_map_inventory',
      ],
      outputs: ['jsvmp_candidate_regions'],
      safety: ['metadata_only'],
    },
    {
      id: 'bytecode-container',
      title: 'Bytecode container plan',
      purpose:
        'Identify likely bytecode arrays, encoded opcode streams, constant pools, and state variables without executing the VM.',
      inputs: ['jsvmp_candidate_regions'],
      outputs: ['jsvmp_bytecode_plan', 'jsvmp_constant_pool_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'handler-map',
      title: 'Handler-map recovery plan',
      purpose:
        'Plan dispatcher loop, opcode handler, stack/register model, and control-transfer recovery for a future bounded parser worker.',
      inputs: ['jsvmp_bytecode_plan', 'jsvmp_constant_pool_plan'],
      outputs: ['jsvmp_handler_map', 'jsvmp_semantics_model'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'google-jsir-cascade',
      name: 'Google JSIR / CASCADE',
      source: 'local-roadmap',
      role: 'Normalize JavaScript into IR and support structured deobfuscation passes after passive VM triage.',
      readiness: 'optional_external',
      notes: [
        'Use only through a future bounded static worker with pinned checkout metadata.',
        'Do not execute protected JavaScript while converting source to an analysis IR.',
      ],
    },
    {
      id: 'humansecurity-restringer',
      name: 'REstringer',
      source: 'https://github.com/HumanSecurity/restringer',
      role: 'Recover string-array and expression obfuscation before handler-map recovery.',
      readiness: 'optional_external',
      notes: [
        'Treat as a preprocessing candidate, not as a default plugin startup dependency.',
        'Keep source-local and offline; no network lookup is needed for the plan.',
      ],
    },
    {
      id: 'local-jsvmp-parser-worker',
      name: 'Local JSVMP parser worker',
      source: 'local-roadmap',
      role: 'Recover bytecode containers, dispatch loops, opcode handlers, and stack/register semantics from parsed source.',
      readiness: 'future_worker',
      notes: [
        'Implement as AST/static parsing first, with fixtures for known VM-dispatch patterns.',
        'Require explicit analyst opt-in before using any interpreter-assisted normalization.',
      ],
    },
  ],
  recommendedNextTools: [
    'javascript.obfuscation.profile',
    'strings.extract',
    'yara.generate',
    'analysis.evidence.graph',
  ],
  safetyNotes: [
    'JSVMP plans are static metadata; the protected JavaScript VM is never executed.',
    'Future workers must parse local source and enforce source-size, timeout, and artifact budgets.',
  ],
}

const jsvmpAnalysisPlugin = definePlugin({
  id: 'jsvmp-analysis',
  name: 'JSVMP Analysis Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html', 'v8-cache'],
      findings: ['jsvmp', 'vm_detect', 'obfuscated', 'eval', 'packed'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive JSVMP bytecode, dispatcher, handler-map, and semantics recovery planning for obfuscated JavaScript.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'JSVMP_WORKER_PATH',
      description: 'Optional future local JSVMP parser worker path',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'jsvmp-worker',
      target: '$JSVMP_WORKER_PATH',
      envVar: 'JSVMP_WORKER_PATH',
      required: false,
      description: 'Optional local JSVMP static parser worker',
      dockerInstall: 'Provide a pinned local worker; not installed by default',
      dockerFeature: 'jsvmp-analysis',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default jsvmpAnalysisPlugin
