import type { ToolDefinition } from '../../types.js'

export const WINDOWS_DEBUG_METADATA_TOOL_NAME = 'windows.debug.metadata.inspect'
export const WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE = 'windows_debug_metadata'
export const WINDOWS_DEBUG_METADATA_TOOL_VERSION = '1.1.0'

export const WINDOWS_DEBUG_METADATA_FORMATS = [
  'pdb',
  'obj',
  'lib',
  'coff',
  'coff-object',
  'coff-lib',
  'codeview',
  'codeview-records',
  'pdb-codeview',
  'dwarf',
  'dwo',
  'dwp',
  'debug',
  'debug-file',
  'debug-section',
  'debug-symbols',
  'debug-info',
  'debug-metadata',
]

export const WINDOWS_DEBUG_METADATA_PLATFORMS = ['windows', 'cross-platform']
export const WINDOWS_DEBUG_METADATA_ARCHITECTURES = ['x86', 'x64', 'arm64', 'arm']
export const WINDOWS_DEBUG_METADATA_EXECUTION = ['static', 'triage', 'workflow-handoff']

export const WINDOWS_DEBUG_METADATA_SAFETY = [
  'passive',
  'no_execute',
  'no_network',
  'no_network_by_default',
  'no_symbol_server_network_by_default',
  'no_symbol_server_download',
  'no_source_fetch',
  'no_mutation',
  'no_live_sample_by_default',
]

export const WINDOWS_DEBUG_METADATA_CAPABILITIES = [
  'metadata',
  'symbols',
  'debug-symbols',
  'debug-metadata',
  'search-profile',
  'source-map-plan',
  'routing',
  'workflow-plan',
  'workflow-handoff',
  'metadata-only-handoff',
  'symbol-handoff',
  'debug-metadata-handoff',
  'function-boundary-handoff',
  'pdb-identity',
  'codeview-metadata',
  'coff-symbols',
  'source-path-profile',
]

export const WINDOWS_DEBUG_METADATA_EVIDENCE = [
  'structure',
  'symbols',
  'debug-metadata',
  'pdb-identity',
  'codeview',
  'coff-symbols',
  'source-map',
  'source-paths',
  'object-members',
  'workflow',
  'provenance',
  'search-profile',
]

export const WINDOWS_DEBUG_METADATA_SEARCH_TERMS = [
  'windows debug symbols',
  'pdb',
  'program database',
  'codeview',
  'rsds',
  'nb10',
  'coff symbols',
  'symbol table',
  'source map',
  'source path',
  'debug metadata',
  'function boundary',
  'symbol recovery',
]

export const WINDOWS_DEBUG_METADATA_PROFILE_TERMS = [
  'windows-debug-metadata',
  'debug-symbols-inventory',
  'pdb-identity-profile',
  'codeview-profile',
  'coff-symbol-table-profile',
  'source-map-profile',
  'bounded-preview',
  'passive-profile',
  'symbol-handoff',
  'function-boundary-handoff',
]

export const WINDOWS_DEBUG_METADATA_ROUTE_TERMS = [
  'windows_debug_metadata_profile',
  'pdb_identity_handoff',
  'codeview_metadata_handoff',
  'coff_symbol_table_handoff',
  'source_map_review',
  'symbol_handoff',
  'function_boundary_handoff',
  'bounded_preview_static_analysis',
  'no_symbol_server_download',
  'no_source_fetch',
]

export const WINDOWS_DEBUG_METADATA_EVIDENCE_SUMMARY_SCHEMA =
  'rikune.windows_debug_metadata.evidence_summary.v1'
export const WINDOWS_DEBUG_METADATA_WORKFLOW_HANDOFF_SCHEMA =
  'rikune.windows_debug_metadata.workflow_handoff.v1'
export const WINDOWS_DEBUG_METADATA_QUALITY_GATES_SCHEMA =
  'rikune.windows_debug_metadata.quality_gates.v1'

export const WINDOWS_DEBUG_METADATA_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'pe.structure.analyze',
  'native.object.inventory',
  'code.functions.smart_recover',
  'code.functions.define',
  'analysis.evidence.graph',
  'report.generate',
]

export const WINDOWS_DEBUG_METADATA_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noSymbolServerDownload: true,
  noSourceFetch: true,
  notes: [
    'windows.debug.metadata.inspect reads only bounded local sample bytes for debug metadata hints.',
    'Symbol server downloads, source fetching, mutation, and live sample execution are outside the default passive profile.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noSymbolServerDownload: true
  noSourceFetch: true
}

export function windowsDebugMetadataAspects(
  capabilities: string[] = WINDOWS_DEBUG_METADATA_CAPABILITIES
) {
  return {
    formats: WINDOWS_DEBUG_METADATA_FORMATS,
    platforms: WINDOWS_DEBUG_METADATA_PLATFORMS,
    architectures: WINDOWS_DEBUG_METADATA_ARCHITECTURES,
    execution: WINDOWS_DEBUG_METADATA_EXECUTION,
    safety: WINDOWS_DEBUG_METADATA_SAFETY,
    capabilities,
    evidence: WINDOWS_DEBUG_METADATA_EVIDENCE,
    search: WINDOWS_DEBUG_METADATA_SEARCH_TERMS,
    profile: WINDOWS_DEBUG_METADATA_PROFILE_TERMS,
    route_terms: WINDOWS_DEBUG_METADATA_ROUTE_TERMS,
  }
}

export function windowsDebugMetadataRecipe() {
  return {
    id: 'windows-debug-symbols.passive-metadata-handoff',
    title: 'Windows debug symbols passive metadata handoff',
    description:
      'Profile PDB, COFF object/library, CodeView, DWARF sidecar, and generic debug metadata signals, then hand off symbol and function-boundary evidence without symbol-server network access, source fetch, mutation, or live sample execution.',
    startsWith: [WINDOWS_DEBUG_METADATA_TOOL_NAME],
    nextTools: WINDOWS_DEBUG_METADATA_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
    evidence: WINDOWS_DEBUG_METADATA_EVIDENCE,
    safety: WINDOWS_DEBUG_METADATA_SAFETY,
  }
}

export type WindowsDebugPdbIdentityHint = {
  kind: 'RSDS' | 'NB10'
  offset: number
  age?: number
  guid?: string
  signature?: string
  pdb_path?: string
}

export type WindowsDebugCoffSymbolTable = {
  offset: number
  count: number
  string_table_present: boolean
  truncated: boolean
}

export type WindowsDebugSourcePathProfile = {
  total: number
  windows_paths: number
  unc_paths: number
  relative_paths: number
  source_index_markers: number
  possible_sensitive_paths: number
  redacted_examples: string[]
}

export type WindowsDebugPreviewProfile = {
  bytes_read: number
  size: number
  truncated: boolean
  max_read_bytes: number
}

export type WindowsDebugMetadataEnvelopeInput = {
  sample_id?: string
  format: string
  detected_by: string[]
  size?: number
  symbol_hints: string[]
  source_path_hints: string[]
  object_members: string[]
  pdb_identity_hints: WindowsDebugPdbIdentityHint[]
  codeview_markers: string[]
  coff_symbol_table?: WindowsDebugCoffSymbolTable
  source_path_profile: WindowsDebugSourcePathProfile
  preview_profile: WindowsDebugPreviewProfile
  recommended_next_tools: string[]
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function hasPdbIdentity(inventory: Pick<WindowsDebugMetadataEnvelopeInput, 'pdb_identity_hints'>) {
  return inventory.pdb_identity_hints.length > 0
}

function hasCodeView(inventory: Pick<WindowsDebugMetadataEnvelopeInput, 'codeview_markers'>) {
  return inventory.codeview_markers.length > 0
}

function hasCoffSymbolTable(
  inventory: Pick<WindowsDebugMetadataEnvelopeInput, 'format' | 'coff_symbol_table'>
) {
  return Boolean(inventory.coff_symbol_table) || inventory.format === 'coff'
}

export function windowsDebugMetadataRecommendedNextTools(
  inventory: Pick<
    WindowsDebugMetadataEnvelopeInput,
    | 'format'
    | 'symbol_hints'
    | 'source_path_hints'
    | 'object_members'
    | 'pdb_identity_hints'
    | 'codeview_markers'
    | 'coff_symbol_table'
  >
): string[] {
  return unique([
    'artifact.read',
    'metadata.extract',
    'strings.extract',
    'analysis.evidence.graph',
    ...(hasPdbIdentity(inventory) || hasCodeView(inventory) ? ['pe.structure.analyze'] : []),
    ...(hasCoffSymbolTable(inventory) || inventory.object_members.length > 0
      ? ['native.object.inventory']
      : []),
    ...(inventory.symbol_hints.length > 0 || hasCoffSymbolTable(inventory)
      ? ['code.functions.smart_recover', 'code.functions.define']
      : []),
  ])
}

export function buildWindowsDebugMetadataEnvelope(inventory: WindowsDebugMetadataEnvelopeInput) {
  const pdbTools =
    hasPdbIdentity(inventory) || hasCodeView(inventory)
      ? ['pe.structure.analyze', 'analysis.evidence.graph']
      : []
  const coffTools = hasCoffSymbolTable(inventory)
    ? ['native.object.inventory', 'code.functions.define']
    : []
  const functionBoundaryTools =
    inventory.symbol_hints.length > 0 || hasCoffSymbolTable(inventory)
      ? ['code.functions.smart_recover', 'code.functions.define']
      : []

  return {
    evidence_summary: {
      schema: WINDOWS_DEBUG_METADATA_EVIDENCE_SUMMARY_SCHEMA,
      source_tool: WINDOWS_DEBUG_METADATA_TOOL_NAME,
      sample_id: inventory.sample_id ?? null,
      format: inventory.format,
      detected_by: inventory.detected_by,
      artifact_type: WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE,
      route_terms: WINDOWS_DEBUG_METADATA_ROUTE_TERMS,
      evidence_categories: WINDOWS_DEBUG_METADATA_EVIDENCE,
      counts: {
        symbol_hints: inventory.symbol_hints.length,
        source_path_hints: inventory.source_path_hints.length,
        object_members: inventory.object_members.length,
        pdb_identity_hints: inventory.pdb_identity_hints.length,
        codeview_markers: inventory.codeview_markers.length,
        coff_symbol_tables: inventory.coff_symbol_table ? 1 : 0,
      },
      highlights: {
        symbols: inventory.symbol_hints.slice(0, 12),
        source_paths: inventory.source_path_hints.slice(0, 12),
        object_members: inventory.object_members.slice(0, 12),
        pdb_identities: inventory.pdb_identity_hints.slice(0, 12),
        codeview_markers: inventory.codeview_markers.slice(0, 12),
      },
      static_only: true,
      backend_semantics: {
        bounded_preview_only: true,
        symbol_server_contacted: false,
        source_fetched: false,
        sample_executed: false,
        network_used: false,
        mutation_performed: false,
      },
    },
    workflow_handoff: {
      schema: WINDOWS_DEBUG_METADATA_WORKFLOW_HANDOFF_SCHEMA,
      handoff_mode: 'windows_debug_metadata_to_symbol_source_and_function_boundary_analysis',
      source_tool: WINDOWS_DEBUG_METADATA_TOOL_NAME,
      sample_id: inventory.sample_id ?? null,
      recommended_next_tools: inventory.recommended_next_tools,
      artifact_contract: {
        consumes: ['sample'],
        produces: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
        mime: 'application/json',
        expected_consumers: WINDOWS_DEBUG_METADATA_FOLLOW_UP_TOOLS,
      },
      dynamic_boundary: {
        activation_boundary: 'result-scoped',
        sample_execution_allowed: false,
        symbol_server_download_allowed: false,
        source_fetch_allowed: false,
        network_allowed: false,
        mutation_allowed: false,
        sample_executed_by_tool: false,
        symbol_server_contacted: false,
        source_fetched: false,
        network_used_by_tool: false,
        mutation_performed: false,
      },
      routing: [
        {
          goal: 'pdb-identity-correlation',
          priority: pdbTools.length > 0 ? 'high' : 'low',
          route_terms: ['pdb_identity_handoff', 'codeview_metadata_handoff'],
          next_tools: pdbTools,
          consumes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
          produces: ['pe_structure', 'evidence_graph'],
          blocking_conditions:
            pdbTools.length > 0
              ? []
              : ['No RSDS/NB10 or CodeView identity marker was detected in this bounded preview.'],
        },
        {
          goal: 'source-map-review',
          priority: inventory.source_path_hints.length > 0 ? 'medium' : 'low',
          route_terms: ['source_map_review', 'no_source_fetch'],
          next_tools: ['artifact.read', 'report.generate'],
          consumes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
          produces: ['report'],
          blocking_conditions: [
            'Review source path hints as metadata only; do not fetch source files from this route.',
          ],
        },
        {
          goal: 'coff-symbol-review',
          priority: coffTools.length > 0 ? 'high' : 'low',
          route_terms: ['coff_symbol_table_handoff', 'symbol_handoff'],
          next_tools: coffTools,
          consumes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
          produces: ['native_object_inventory', 'function_index'],
          blocking_conditions:
            coffTools.length > 0
              ? []
              : ['No COFF symbol table was detected in this bounded preview.'],
        },
        {
          goal: 'function-boundary-recovery',
          priority: functionBoundaryTools.length > 0 ? 'medium' : 'low',
          route_terms: ['symbol_handoff', 'function_boundary_handoff'],
          next_tools: functionBoundaryTools,
          consumes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
          produces: ['function_index'],
          blocking_conditions:
            functionBoundaryTools.length > 0
              ? []
              : ['No symbol hints were detected for function-boundary recovery.'],
        },
        {
          goal: 'evidence-and-reporting',
          priority: 'medium',
          route_terms: ['windows_debug_metadata_profile', 'bounded_preview_static_analysis'],
          next_tools: ['analysis.evidence.graph', 'artifact.read', 'report.generate'],
          consumes: [WINDOWS_DEBUG_METADATA_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'report'],
        },
      ],
      quality_gates_schema: WINDOWS_DEBUG_METADATA_QUALITY_GATES_SCHEMA,
    },
    quality_gates: {
      schema: WINDOWS_DEBUG_METADATA_QUALITY_GATES_SCHEMA,
      passive_static_inventory: true,
      bounded_preview_only: true,
      format_detected: inventory.format !== 'unknown',
      debug_metadata_format: WINDOWS_DEBUG_METADATA_FORMATS.includes(inventory.format),
      pdb_identity_present: inventory.pdb_identity_hints.length > 0,
      codeview_markers_present: inventory.codeview_markers.length > 0,
      source_path_hints_present: inventory.source_path_hints.length > 0,
      coff_symbol_table_present: Boolean(inventory.coff_symbol_table),
      object_members_present: inventory.object_members.length > 0,
      sample_executed_by_tool: false,
      symbol_server_contacted: false,
      source_fetched: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
  }
}
