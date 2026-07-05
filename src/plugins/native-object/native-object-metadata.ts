import type { ToolDefinition } from '../../types.js'

export const NATIVE_OBJECT_FORMATS = [
  'object',
  'static-lib',
  'ar',
  'ar-static-lib',
  'coff',
  'coff-lib',
  'elf-object',
  'linux-kernel-module',
  'macho-object',
  'dsym',
  'dwarf',
  'dwo',
  'dwp',
  'debug-metadata',
]

export const NATIVE_OBJECT_PLATFORMS = [
  'windows',
  'linux',
  'macos',
  'ios',
  'embedded',
  'cross-platform',
]

export const NATIVE_OBJECT_ARCHITECTURES = [
  'x86',
  'x64',
  'arm',
  'arm64',
  'mips',
  'mipsel',
  'ppc',
  'riscv',
]

export const NATIVE_OBJECT_EXECUTION = ['static', 'triage', 'workflow-handoff']

export const NATIVE_OBJECT_SAFETY = [
  'passive',
  'no_execute',
  'no_link',
  'no_load',
  'no_strip_or_sign',
  'no_mutation',
  'no_network',
  'no_live_sample_by_default',
]

export const NATIVE_OBJECT_CAPABILITIES = [
  'inventory',
  'symbols',
  'debug-metadata',
  'nested-binaries',
  'routing',
  'workflow-plan',
  'workflow-handoff',
  'symbol-handoff',
  'debug-metadata-handoff',
  'function-boundary-handoff',
  'search-profile',
]

export const NATIVE_OBJECT_EVIDENCE = [
  'structure',
  'symbols',
  'debug-metadata',
  'package-metadata',
  'nested-binaries',
  'workflow',
  'provenance',
]

export const NATIVE_OBJECT_SEARCH_TERMS = [
  'native object',
  'object file',
  'static library',
  'ar archive',
  'coff object',
  'coff lib',
  'elf relocatable',
  'kernel module',
  'mach-o object',
  'dwarf',
  'dwp',
  'dwo',
  'dsym',
  'pdb handoff',
  'symbol recovery',
  'function boundary',
]

export const NATIVE_OBJECT_PROFILE_TERMS = [
  'native-object-inventory',
  'object-inventory',
  'static-lib-inventory',
  'debug-metadata-inventory',
  'bounded-preview',
  'passive-profile',
  'symbol-handoff',
  'function-boundary-handoff',
]

export const NATIVE_OBJECT_ROUTE_TERMS = [
  'native_object_inventory_profile',
  'object_static_library_handoff',
  'debug_metadata_handoff',
  'symbol_handoff',
  'function_boundary_handoff',
  'nested_native_member_handoff',
  'bounded_preview_static_analysis',
  'no_link',
  'no_load',
  'no_strip_or_sign',
]

export const NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE = 'native_object_inventory'
export const NATIVE_OBJECT_TOOL_VERSION = '1.1.0'

export const NATIVE_OBJECT_EVIDENCE_SUMMARY_SCHEMA =
  'rikune.native_object_inventory.evidence_summary.v1'
export const NATIVE_OBJECT_WORKFLOW_HANDOFF_SCHEMA =
  'rikune.native_object_inventory.workflow_handoff.v1'
export const NATIVE_OBJECT_QUALITY_GATES_SCHEMA = 'rikune.native_object_inventory.quality_gates.v1'

export const NATIVE_OBJECT_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'elf.structure.analyze',
  'macho.structure.analyze',
  'windows.debug.metadata.inspect',
  'code.functions.smart_recover',
  'code.functions.define',
  'analysis.evidence.graph',
  'report.generate',
]

export const NATIVE_OBJECT_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noLink: true,
  noLoad: true,
  noStripOrSign: true,
  notes: [
    'native.object.inventory reads a bounded preview of object/static-library/debug metadata content.',
    'It does not link, load, execute, strip, sign, mutate, or contact symbol servers.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noLink: true
  noLoad: true
  noStripOrSign: true
}

export function nativeObjectAspects(capabilities: string[] = NATIVE_OBJECT_CAPABILITIES) {
  return {
    formats: NATIVE_OBJECT_FORMATS,
    platforms: NATIVE_OBJECT_PLATFORMS,
    architectures: NATIVE_OBJECT_ARCHITECTURES,
    execution: NATIVE_OBJECT_EXECUTION,
    safety: NATIVE_OBJECT_SAFETY,
    capabilities,
    evidence: NATIVE_OBJECT_EVIDENCE,
    search: NATIVE_OBJECT_SEARCH_TERMS,
    profile: NATIVE_OBJECT_PROFILE_TERMS,
    route_terms: NATIVE_OBJECT_ROUTE_TERMS,
  }
}

export function nativeObjectRecipe() {
  return {
    id: 'native-object.passive-inventory-handoff',
    title: 'Passive native object and debug metadata inventory',
    description:
      'Inventory object files, static libraries, kernel modules, and debug bundles, then route symbols, debug metadata, and nested native members without linking, loading, stripping, signing, mutating, or executing content.',
    startsWith: ['native.object.inventory'],
    nextTools: NATIVE_OBJECT_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
    evidence: NATIVE_OBJECT_EVIDENCE,
    safety: NATIVE_OBJECT_SAFETY,
  }
}

type NestedNativeMember = {
  path: string
  routed_formats: string[]
  recommended_tools: string[]
}

export type NativeObjectInventoryEnvelopeInput = {
  sample_id?: string
  format: string
  detected_by: string[]
  machine_hints: string[]
  member_names: string[]
  symbol_hints: string[]
  debug_metadata_candidates: string[]
  nested_binary_candidates: NestedNativeMember[]
  recommended_next_tools: string[]
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function formatSpecificStructureTools(format: string): string[] {
  if (format.startsWith('elf') || format === 'linux-kernel-module') return ['elf.structure.analyze']
  if (format.startsWith('macho')) return ['macho.structure.analyze']
  return []
}

function hasWindowsDebugMetadata(
  inventory: Pick<
    NativeObjectInventoryEnvelopeInput,
    'format' | 'debug_metadata_candidates' | 'nested_binary_candidates'
  >
): boolean {
  return (
    inventory.format === 'coff' ||
    inventory.format === 'coff-lib' ||
    inventory.debug_metadata_candidates.some((candidate) => /\.pdb$/i.test(candidate)) ||
    inventory.nested_binary_candidates.some((candidate) => /\.pdb$/i.test(candidate.path))
  )
}

export function nativeObjectRecommendedNextTools(
  inventory: Pick<
    NativeObjectInventoryEnvelopeInput,
    'format' | 'symbol_hints' | 'debug_metadata_candidates' | 'nested_binary_candidates'
  >
): string[] {
  return unique([
    'artifact.read',
    'metadata.extract',
    'strings.extract',
    'analysis.evidence.graph',
    ...formatSpecificStructureTools(inventory.format),
    ...(hasWindowsDebugMetadata(inventory) ? ['windows.debug.metadata.inspect'] : []),
    ...(inventory.symbol_hints.length > 0
      ? ['code.functions.smart_recover', 'code.functions.define']
      : []),
    ...inventory.nested_binary_candidates.flatMap((candidate) => candidate.recommended_tools),
  ])
}

export function buildNativeObjectEnvelope(inventory: NativeObjectInventoryEnvelopeInput) {
  const formatTools = formatSpecificStructureTools(inventory.format)
  const debugTools = hasWindowsDebugMetadata(inventory) ? ['windows.debug.metadata.inspect'] : []
  const functionBoundaryTools =
    inventory.symbol_hints.length > 0
      ? ['code.functions.smart_recover', 'code.functions.define']
      : []
  const nestedTools = unique(
    inventory.nested_binary_candidates.flatMap((candidate) => candidate.recommended_tools)
  )

  return {
    evidence_summary: {
      schema: NATIVE_OBJECT_EVIDENCE_SUMMARY_SCHEMA as typeof NATIVE_OBJECT_EVIDENCE_SUMMARY_SCHEMA,
      source_tool: 'native.object.inventory' as const,
      sample_id: inventory.sample_id ?? null,
      format: inventory.format,
      detected_by: inventory.detected_by,
      artifact_type:
        NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE as typeof NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE,
      route_terms: NATIVE_OBJECT_ROUTE_TERMS,
      evidence_categories: NATIVE_OBJECT_EVIDENCE,
      counts: {
        machine_hints: inventory.machine_hints.length,
        members: inventory.member_names.length,
        symbol_hints: inventory.symbol_hints.length,
        debug_metadata_candidates: inventory.debug_metadata_candidates.length,
        nested_binary_candidates: inventory.nested_binary_candidates.length,
      },
      highlights: {
        machines: inventory.machine_hints.slice(0, 12),
        members: inventory.member_names.slice(0, 12),
        symbols: inventory.symbol_hints.slice(0, 12),
        debug_metadata: inventory.debug_metadata_candidates.slice(0, 12),
        nested_members: inventory.nested_binary_candidates.slice(0, 12).map((candidate) => ({
          path: candidate.path,
          routed_formats: candidate.routed_formats,
          recommended_tools: candidate.recommended_tools,
        })),
      },
      static_only: true,
      backend_semantics: {
        bounded_preview_only: true,
        linked: false,
        loaded: false,
        executed: false,
        stripped_or_signed: false,
        network_used: false,
      },
    },
    workflow_handoff: {
      schema: NATIVE_OBJECT_WORKFLOW_HANDOFF_SCHEMA as typeof NATIVE_OBJECT_WORKFLOW_HANDOFF_SCHEMA,
      handoff_mode: 'native_object_inventory_to_symbol_and_debug_analysis',
      source_tool: 'native.object.inventory',
      sample_id: inventory.sample_id ?? null,
      recommended_next_tools: inventory.recommended_next_tools,
      artifact_contract: {
        consumes: ['sample'],
        produces: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
        mime: 'application/json',
        expected_consumers: NATIVE_OBJECT_FOLLOW_UP_TOOLS,
      },
      dynamic_boundary: {
        activation_boundary: 'result-scoped',
        sample_execution_allowed: false,
        link_allowed: false,
        load_allowed: false,
        strip_or_sign_allowed: false,
        mutation_allowed: false,
        network_allowed: false,
        sample_executed_by_tool: false,
        linked_by_tool: false,
        loaded_by_tool: false,
        stripped_or_signed_by_tool: false,
        mutation_performed: false,
        network_used_by_tool: false,
      },
      routing: [
        {
          goal: 'format-specific-structure-review',
          priority: formatTools.length > 0 ? 'high' : 'low',
          route_terms: ['object_static_library_handoff', 'bounded_preview_static_analysis'],
          next_tools: formatTools,
          consumes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
          produces: ['elf_structure', 'macho_structure'],
          blocking_conditions:
            formatTools.length > 0
              ? []
              : ['No ELF or Mach-O object format was detected in this bounded preview.'],
        },
        {
          goal: 'debug-metadata-review',
          priority: debugTools.length > 0 ? 'high' : 'low',
          route_terms: ['debug_metadata_handoff', 'symbol_handoff'],
          next_tools: debugTools,
          consumes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
          produces: ['windows_debug_metadata'],
          blocking_conditions:
            debugTools.length > 0
              ? []
              : ['No PDB/COFF debug metadata route was detected in this bounded preview.'],
        },
        {
          goal: 'function-boundary-recovery',
          priority: inventory.symbol_hints.length > 0 ? 'medium' : 'low',
          route_terms: ['symbol_handoff', 'function_boundary_handoff'],
          next_tools: functionBoundaryTools,
          consumes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
          produces: ['function_index'],
          blocking_conditions:
            functionBoundaryTools.length > 0
              ? []
              : ['No symbol hints were detected for function-boundary recovery.'],
        },
        {
          goal: 'nested-native-member-routing',
          priority: inventory.nested_binary_candidates.length > 0 ? 'high' : 'low',
          route_terms: ['nested_native_member_handoff'],
          next_tools: nestedTools,
          consumes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
          produces: ['nested_native_inventory'],
          blocking_conditions: [
            'Ingest relevant member binaries separately before activating format-specific analyzers.',
          ],
        },
        {
          goal: 'evidence-and-reporting',
          priority: 'medium',
          route_terms: ['symbol_handoff', 'debug_metadata_handoff'],
          next_tools: ['analysis.evidence.graph', 'artifact.read', 'report.generate'],
          consumes: [NATIVE_OBJECT_INVENTORY_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'report'],
        },
      ],
      quality_gates_schema: NATIVE_OBJECT_QUALITY_GATES_SCHEMA,
    },
    quality_gates: {
      schema: NATIVE_OBJECT_QUALITY_GATES_SCHEMA as typeof NATIVE_OBJECT_QUALITY_GATES_SCHEMA,
      passive_static_inventory: true,
      bounded_preview_only: true,
      format_detected: inventory.format !== 'unknown',
      native_object_or_debug_format: NATIVE_OBJECT_FORMATS.includes(inventory.format),
      machine_hints_present: inventory.machine_hints.length > 0,
      symbol_hints_present: inventory.symbol_hints.length > 0,
      debug_metadata_candidates_present: inventory.debug_metadata_candidates.length > 0,
      nested_binary_candidates_present: inventory.nested_binary_candidates.length > 0,
      sample_executed_by_tool: false,
      linked_by_tool: false,
      loaded_by_tool: false,
      stripped_or_signed_by_tool: false,
      mutation_performed: false,
      network_used_by_tool: false,
    },
  }
}
