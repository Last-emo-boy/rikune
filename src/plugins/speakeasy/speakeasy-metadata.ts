import type { ToolDefinition } from '../../types.js'

export const SPEAKEASY_FORMATS = ['pe', 'dll', 'shellcode']
export const SPEAKEASY_PLATFORMS = ['windows']
export const SPEAKEASY_ARCHITECTURES = ['x86', 'x64']
export const SPEAKEASY_RUNTIME_BACKENDS = ['speakeasy']

export const SPEAKEASY_SAFETY = [
  'passive',
  'opt_in_dynamic',
  'requires_isolation',
  'no_live_sample_by_default',
  'no_network_by_default',
]

export const SPEAKEASY_CAPABILITIES = [
  'api-trace',
  'shellcode-emulation',
  'behavior-hints',
  'unsupported-summary',
  'workflow-handoff',
]

export const SPEAKEASY_EVIDENCE = [
  'api-calls',
  'memory',
  'process',
  'filesystem',
  'registry',
  'network',
  'timeline',
  'workflow',
  'provenance',
]

export const SPEAKEASY_RUNTIME_POLICY: ToolDefinition['runtimePolicy'] = {
  passiveByDefault: true,
  requiresUserOptIn: true,
  requiresIsolation: true,
  allowedBackends: ['docker'],
  maxRuntimeMs: 120_000,
  networkPolicy: 'disabled',
  notes: [
    'Speakeasy is the emulation backend profile, while allowedBackends names the isolation carrier used to run Python tooling.',
    'Speakeasy emulation is coverage-limited and should emit backend confidence with behavior evidence.',
    'Readiness checks must not emulate payloads by default.',
  ],
}

export const SPEAKEASY_SYSTEM_DEP = {
  type: 'python' as const,
  name: 'speakeasy-emulator',
  importName: 'speakeasy',
  required: false,
  description: 'Mandiant Speakeasy Windows emulator',
  dockerInstall: 'pip install speakeasy-emulator',
  dockerFeature: 'dynamic-python',
}

export const SPEAKEASY_EMULATE_ARTIFACT_TYPE = 'backend_speakeasy_emulate'
export const SPEAKEASY_SHELLCODE_ARTIFACT_TYPE = 'backend_speakeasy_shellcode'
export const SPEAKEASY_API_TRACE_ARTIFACT_TYPE = 'backend_speakeasy_api_trace'

export const SPEAKEASY_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'attack.map',
  'malware.classify',
  'malware.config.extract',
  'analysis.evidence.graph',
]

export const SPEAKEASY_EMULATE_WORKFLOW_RECIPE = {
  id: 'speakeasy.pe-emulation-handoff',
  title: 'Speakeasy PE emulation evidence handoff',
  description:
    'Run opt-in Speakeasy PE emulation and hand API, filesystem, registry, network, and timeline evidence to behavior mapping and reporting.',
  startsWith: ['speakeasy.emulate'],
  nextTools: SPEAKEASY_FOLLOW_UP_TOOLS,
  requiredArtifacts: ['sample'],
  producesArtifacts: [SPEAKEASY_EMULATE_ARTIFACT_TYPE],
  evidence: ['api-calls', 'filesystem', 'registry', 'network', 'timeline', 'workflow'],
  safety: SPEAKEASY_SAFETY,
  runtimeBackends: SPEAKEASY_RUNTIME_BACKENDS,
}

export const SPEAKEASY_SHELLCODE_WORKFLOW_RECIPE = {
  id: 'speakeasy.shellcode-emulation-handoff',
  title: 'Speakeasy shellcode emulation evidence handoff',
  description:
    'Run opt-in Speakeasy shellcode emulation and hand API and memory behavior evidence to disassembly and C2/config extraction.',
  startsWith: ['speakeasy.shellcode'],
  nextTools: ['artifact.read', 'disasm.quick', 'c2.extract', 'analysis.evidence.graph'],
  requiredArtifacts: ['sample'],
  producesArtifacts: [SPEAKEASY_SHELLCODE_ARTIFACT_TYPE],
  evidence: ['api-calls', 'memory', 'timeline', 'workflow'],
  safety: SPEAKEASY_SAFETY,
  runtimeBackends: SPEAKEASY_RUNTIME_BACKENDS,
}

export const SPEAKEASY_API_TRACE_WORKFLOW_RECIPE = {
  id: 'speakeasy.api-trace-handoff',
  title: 'Speakeasy focused API trace evidence handoff',
  description:
    'Run opt-in Speakeasy API trace extraction and hand filtered behavior evidence to ATT&CK mapping and report generation.',
  startsWith: ['speakeasy.api_trace'],
  nextTools: ['artifact.read', 'attack.map', 'malware.classify', 'analysis.evidence.graph'],
  requiredArtifacts: ['sample'],
  producesArtifacts: [SPEAKEASY_API_TRACE_ARTIFACT_TYPE],
  evidence: ['api-calls', 'process', 'timeline', 'workflow'],
  safety: SPEAKEASY_SAFETY,
  runtimeBackends: SPEAKEASY_RUNTIME_BACKENDS,
}
