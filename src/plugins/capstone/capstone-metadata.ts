import type { ToolDefinition } from '../../types.js'

export const CAPSTONE_DISASM_ARTIFACT_TYPE = 'backend_capstone_disasm'
export const CAPSTONE_SHELLCODE_ARTIFACT_TYPE = 'backend_capstone_shellcode'

export const CAPSTONE_PASSIVE_SAFETY = [
  'passive',
  'bounded-input',
  'no_live_sample_by_default',
  'no_runtime_start',
  'no_network_by_default',
  'no_mutation',
]

export const CAPSTONE_QUICK_EVIDENCE = [
  'structure',
  'disassembly',
  'instructions',
  'workflow',
  'provenance',
]

export const CAPSTONE_SHELLCODE_EVIDENCE = [
  'structure',
  'shellcode',
  'api-dispatch',
  'workflow',
  'provenance',
]

export const CAPSTONE_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  maxRuntimeMs: 30_000,
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'Capstone tools read bounded local sample bytes and never execute, emulate, or debug the sample.',
    'The optional Python Capstone backend is used only for passive disassembly previews.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}

export const CAPSTONE_QUICK_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'code.function.decompile',
  'code.function.cfg',
  'code.functions.smart_recover',
  'pe.pdata.extract',
  'analysis.evidence.graph',
  'report.generate',
]

export const CAPSTONE_SHELLCODE_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'strings.extract',
  'hash.resolve',
  'hash.resolver.plan',
  'speakeasy.shellcode',
  'analysis.evidence.graph',
  'report.generate',
]

export const CAPSTONE_QUICK_WORKFLOW_RECIPES: NonNullable<ToolDefinition['workflowRecipes']> = [
  {
    id: 'capstone.quick-disassembly-handoff',
    title: 'Capstone bounded disassembly handoff',
    description:
      'Disassemble a bounded entrypoint, function seed, or payload preview and hand the passive instruction evidence to recovery, CFG, evidence graph, and reporting workflows.',
    startsWith: ['disasm.quick'],
    nextTools: CAPSTONE_QUICK_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [CAPSTONE_DISASM_ARTIFACT_TYPE],
    evidence: CAPSTONE_QUICK_EVIDENCE,
    safety: CAPSTONE_PASSIVE_SAFETY,
  },
]

export const CAPSTONE_SHELLCODE_WORKFLOW_RECIPES: NonNullable<ToolDefinition['workflowRecipes']> = [
  {
    id: 'capstone.shellcode-disassembly-handoff',
    title: 'Capstone shellcode triage handoff',
    description:
      'Disassemble bounded shellcode bytes, surface API-dispatch heuristics, and route static evidence into string, API-hash, emulation, evidence graph, and reporting workflows.',
    startsWith: ['shellcode.disasm'],
    nextTools: CAPSTONE_SHELLCODE_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [CAPSTONE_SHELLCODE_ARTIFACT_TYPE],
    evidence: CAPSTONE_SHELLCODE_EVIDENCE,
    safety: CAPSTONE_PASSIVE_SAFETY,
  },
]
