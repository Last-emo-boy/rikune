import type { ArtifactRef, ToolDefinition } from '../../types.js'

export const OFFICE_ANALYSIS_FORMATS = [
  'office',
  'doc',
  'docx',
  'docm',
  'xls',
  'xlsx',
  'xlsm',
  'ppt',
  'pptx',
  'pptm',
  'rtf',
  'ole',
  'ole2',
  'ooxml',
]

export const OFFICE_ANALYSIS_PLATFORMS = ['windows', 'macos', 'cross-platform']

export const OFFICE_ANALYSIS_SAFETY = [
  'passive',
  'static-only',
  'external_static_backend',
  'no_live_sample_by_default',
  'no_live_execution',
  'no_network',
  'no_network_by_default',
  'no_mutation',
  'no_office_automation',
  'no_macro_execution',
]

export const OFFICE_ANALYSIS_EVIDENCE = [
  'structure',
  'strings',
  'macro-source',
  'behavior',
  'network',
  'filesystem',
  'registry',
  'ioc',
  'workflow',
  'provenance',
]

export const OFFICE_ANALYSIS_CAPABILITIES = [
  'office-analysis',
  'office-document-triage',
  'malicious-document-triage',
  'malicious-document-detection',
  'macro-analysis',
  'vba-macro-analysis',
  'vba-extraction',
  'excel-macro-analysis',
  'excel-vba-macro',
  'xlm-macro-triage',
  'ole-structure',
  'ole2-structure',
  'ooxml-structure',
  'embedded-object-detect',
  'rtf-object-detect',
  'ioc-extraction',
  'behavior-profile',
  'static-only-profile',
  'workflow-handoff',
  'evidence-correlation',
]

export const OFFICE_ANALYSIS_SEARCH_TERMS = [
  'office',
  'office-document',
  'malicious-document',
  'malicious document',
  'vba',
  'vba-macro',
  'vba macro',
  'macro',
  'macros',
  'excel',
  'excel-macro',
  'excel macro',
  'xlm',
  'ole',
  'ole2',
  'ole-object',
  'ooxml',
  'rtf',
  'behavior-profile',
  'behavior profile',
  'static-only',
  'static only',
  'oletools',
  'olevba',
  'mraptor',
  'oleobj',
  'rtfobj',
]

export const OFFICE_ANALYSIS_PROFILE_TAGS = [
  'office-static-profile',
  'office-search-profile',
  'malicious-document-profile',
  'macro-behavior-profile',
  'static-only-profile',
  'artifact-handoff',
  'evidence-summary',
  'quality-gates',
]

export const OFFICE_ANALYSIS_PLUGIN_ASPECTS = {
  formats: OFFICE_ANALYSIS_FORMATS,
  platforms: OFFICE_ANALYSIS_PLATFORMS,
  execution: ['static', 'triage', 'correlation', 'workflow-handoff'],
  safety: OFFICE_ANALYSIS_SAFETY,
  capabilities: OFFICE_ANALYSIS_CAPABILITIES,
  evidence: OFFICE_ANALYSIS_EVIDENCE,
  search: OFFICE_ANALYSIS_SEARCH_TERMS,
  profile: OFFICE_ANALYSIS_PROFILE_TAGS,
}

export const OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE = 'office_behavior_profile'

export const OFFICE_ANALYSIS_FOLLOW_UP_TOOLS = [
  'workflow.search',
  'artifact.read',
  'office.ole.analyze',
  'office.macro.detect',
  'office.vba.extract',
  'office.behavior.profile',
  'strings.extract',
  'ioc.export',
  'yara.scan',
  'yara.generate',
  'sigma.rule.generate',
  'analysis.evidence.graph',
  'report.generate',
]

export const OFFICE_VBA_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'office.macro.detect',
  'office.behavior.profile',
  'strings.extract',
  'ioc.export',
  'yara.scan',
  'yara.generate',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

export const OFFICE_MACRO_FOLLOW_UP_TOOLS = [
  'office.vba.extract',
  'office.ole.analyze',
  'office.behavior.profile',
  'yara.scan',
  'ioc.export',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

export const OFFICE_OLE_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'office.vba.extract',
  'office.macro.detect',
  'office.behavior.profile',
  'strings.extract',
  'yara.scan',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

export const OFFICE_BEHAVIOR_FOLLOW_UP_TOOLS = [
  'ioc.export',
  'yara.generate',
  'sigma.rule.generate',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

export const OFFICE_OLETOOLS_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  maxRuntimeMs: 120_000,
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noOfficeAutomation: true,
  noMacroExecution: true,
  notes: [
    'Office analysis tools use passive oletools/olefile parsing only.',
    'No Microsoft Office automation, macro execution, document preview, network access, or sample mutation is performed.',
    'Missing Python backends return setup guidance instead of falling back to live Office execution.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noOfficeAutomation: true
  noMacroExecution: true
}

export const OFFICE_PROFILE_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noOfficeAutomation: true,
  noMacroExecution: true,
  notes: [
    'office.behavior.profile correlates caller-provided static evidence only.',
    'The profile builder does not read the sample, start Office, execute macros, or perform network lookups.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noOfficeAutomation: true
  noMacroExecution: true
}

export const OFFICE_STATIC_DYNAMIC_BOUNDARY = {
  status: 'static_only',
  sample_executed_by_tool: false,
  macros_executed_by_tool: false,
  office_automation_used: false,
  document_previewed_by_tool: false,
  embedded_content_executed_by_tool: false,
  network_accessed_by_tool: false,
  mutation_performed: false,
}

type ArtifactSelector = {
  artifact_id?: string
  artifact_type: string
  path?: string
  mime?: string
}

function artifactSelector(
  artifact: ArtifactRef | undefined,
  artifactType: string
): ArtifactSelector {
  return artifact
    ? {
        artifact_id: artifact.id,
        artifact_type: artifact.type,
        path: artifact.path,
        mime: artifact.mime,
      }
    : { artifact_type: artifactType }
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

export function buildOfficeEvidenceSummary(args: {
  schema: string
  sourceTool: string
  sampleId?: string
  artifactType: string
  evidenceKind: string
  evidenceCategories: string[]
  counts?: Record<string, unknown>
  highlights?: Record<string, unknown>
  artifact?: ArtifactRef
}) {
  return {
    schema: args.schema,
    source_tool: args.sourceTool,
    sample_id: args.sampleId ?? null,
    artifact_type: args.artifactType,
    artifact: artifactSelector(args.artifact, args.artifactType),
    evidence_kind: args.evidenceKind,
    evidence_categories: unique(args.evidenceCategories),
    counts: args.counts ?? {},
    highlights: args.highlights ?? {},
    static_only: true,
    backend_semantics: {
      backend_family:
        args.sourceTool === 'office.behavior.profile' ? 'local-correlation' : 'oletools',
      no_office_automation: true,
      no_macro_execution: true,
      no_network: true,
      no_mutation: true,
    },
  }
}

export function buildOfficeWorkflowHandoff(args: {
  schema: string
  sourceTool: string
  sampleId?: string
  producesArtifacts: string[]
  recommendedNextTools: string[]
  routing: Array<Record<string, unknown>>
  artifact?: ArtifactRef
  primaryArtifactType?: string
  consumesArtifacts?: string[]
}) {
  const primaryArtifactType = args.primaryArtifactType ?? args.producesArtifacts[0]
  return {
    schema: args.schema,
    handoff_mode: 'office_static_document_analysis',
    source_tool: args.sourceTool,
    sample_id: args.sampleId ?? null,
    artifact_contract: {
      consumes: args.consumesArtifacts ?? ['sample'],
      produces: args.producesArtifacts,
      primary: artifactSelector(args.artifact, primaryArtifactType),
      expected_consumers: unique(args.recommendedNextTools),
    },
    routing: args.routing,
    dynamic_boundary: OFFICE_STATIC_DYNAMIC_BOUNDARY,
    recommended_next_tools: unique(args.recommendedNextTools),
  }
}

export function buildOfficeQualityGates(args: {
  schema: string
  sourceTool: string
  artifact?: ArtifactRef
  backend?: string
  checks?: Record<string, unknown>
}) {
  return {
    schema: args.schema,
    source_tool: args.sourceTool,
    passive_static_analysis: true,
    static_only: true,
    backend: args.backend ?? 'oletools',
    backend_read_only: true,
    no_office_automation: true,
    macros_executed: false,
    document_previewed: false,
    embedded_content_executed: false,
    no_live_sample_execution: true,
    no_network: true,
    no_mutation: true,
    artifact_persisted: Boolean(args.artifact),
    ...(args.checks ?? {}),
  }
}
