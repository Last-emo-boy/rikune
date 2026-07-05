import type { ToolDefinition } from '../../types.js'

export const ELF_STRUCTURE_ARTIFACT_TYPE = 'elf_structure'
export const MACHO_STRUCTURE_ARTIFACT_TYPE = 'macho_structure'
export const ELF_IMPORTS_ARTIFACT_TYPE = 'elf_imports'
export const ELF_EXPORTS_ARTIFACT_TYPE = 'elf_exports'

export const ELF_MACHO_SAFETY = [
  'passive',
  'no_sample_execution',
  'no_runtime_start',
  'no_native_load',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
]

export const ELF_MACHO_CAPABILITIES = [
  'structure',
  'imports',
  'exports',
  'symbols',
  'loader-metadata',
  'dynamic-table',
  'search-profile',
  'workflow-plan',
  'workflow-handoff',
  'evidence-correlation',
]

export const ELF_MACHO_EVIDENCE = [
  'structure',
  'imports',
  'exports',
  'symbols',
  'loader',
  'workflow',
  'provenance',
  'search-profile',
]

export const ELF_STRUCTURE_FOLLOW_UP_TOOLS = [
  'elf.imports.extract',
  'elf.exports.extract',
  'linux.binary.inventory',
  'strings.extract',
  'sbom.generate',
  'analysis.evidence.graph',
  'artifact.read',
  'report.generate',
]

export const MACHO_STRUCTURE_FOLLOW_UP_TOOLS = [
  'apple.container.inventory',
  'apple.signing.inspect',
  'strings.extract',
  'sbom.generate',
  'analysis.evidence.graph',
  'artifact.read',
  'report.generate',
]

export const ELF_IMPORTS_FOLLOW_UP_TOOLS = [
  'linux.binary.inventory',
  'strings.extract',
  'sbom.generate',
  'analysis.evidence.graph',
  'artifact.read',
  'report.generate',
]

export const ELF_EXPORTS_FOLLOW_UP_TOOLS = [
  'linux.binary.inventory',
  'strings.extract',
  'analysis.evidence.graph',
  'artifact.read',
  'report.generate',
]

export const ELF_MACHO_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noSampleExecution: true,
  noRuntimeStart: true,
  noNativeLoad: true,
  notes: [
    'The default ELF/Mach-O workflow reads local sample bytes through a bundled parser only.',
    'It does not execute samples, load native libraries, start runtimes, mutate files, or access the network.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noSampleExecution: true
  noRuntimeStart: true
  noNativeLoad: true
}

export const ELF_STRUCTURE_WORKFLOW_RECIPES: NonNullable<ToolDefinition['workflowRecipes']> = [
  {
    id: 'elf.passive-structure-handoff',
    title: 'ELF passive structure handoff',
    description:
      'Parse ELF headers, sections, segments, symbols, and dynamic loader metadata for static routing into imports, exports, Linux inventory, evidence graph, SBOM, and reporting workflows.',
    startsWith: ['elf.structure.analyze'],
    nextTools: ELF_STRUCTURE_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [ELF_STRUCTURE_ARTIFACT_TYPE],
    evidence: ELF_MACHO_EVIDENCE,
    safety: ELF_MACHO_SAFETY,
    runtimeBackends: ['local'],
  },
]

export const MACHO_STRUCTURE_WORKFLOW_RECIPES: NonNullable<ToolDefinition['workflowRecipes']> = [
  {
    id: 'macho.passive-structure-handoff',
    title: 'Mach-O passive structure handoff',
    description:
      'Parse Mach-O load commands, sections, symbols, and universal slices for static routing into Apple container, signing, evidence graph, SBOM, and reporting workflows.',
    startsWith: ['macho.structure.analyze'],
    nextTools: MACHO_STRUCTURE_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [MACHO_STRUCTURE_ARTIFACT_TYPE],
    evidence: ELF_MACHO_EVIDENCE,
    safety: ELF_MACHO_SAFETY,
    runtimeBackends: ['local'],
  },
]

export const ELF_IMPORTS_WORKFLOW_RECIPES: NonNullable<ToolDefinition['workflowRecipes']> = [
  {
    id: 'elf.imports.passive-handoff',
    title: 'ELF import and dependency handoff',
    description:
      'Extract DT_NEEDED libraries and imported dynamic symbols for Linux binary inventory, SBOM, evidence graph, and reporting workflows without loading the binary.',
    startsWith: ['elf.imports.extract'],
    nextTools: ELF_IMPORTS_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [ELF_IMPORTS_ARTIFACT_TYPE],
    evidence: ['imports', 'symbols', 'loader', 'workflow', 'provenance'],
    safety: ELF_MACHO_SAFETY,
    runtimeBackends: ['local'],
  },
]

export const ELF_EXPORTS_WORKFLOW_RECIPES: NonNullable<ToolDefinition['workflowRecipes']> = [
  {
    id: 'elf.exports.passive-handoff',
    title: 'ELF export symbol handoff',
    description:
      'Extract globally visible ELF symbols for Linux inventory, cross-module review, evidence graph, and reporting workflows without loading the binary.',
    startsWith: ['elf.exports.extract'],
    nextTools: ELF_EXPORTS_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [ELF_EXPORTS_ARTIFACT_TYPE],
    evidence: ['exports', 'symbols', 'workflow', 'provenance'],
    safety: ELF_MACHO_SAFETY,
    runtimeBackends: ['local'],
  },
]

export function buildElfMachoWorkerBackend(
  outputArtifactTypes: string[]
): NonNullable<ToolDefinition['workerBackend']> {
  return {
    version: 'backend-worker.v1',
    backendName: 'Bundled ELF/Mach-O parser worker',
    backendKind: 'external',
    adapter: 'builtin.elf_macho.parser',
    availability: 'required',
    supportedModes: ['local'],
    defaultMode: 'local',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes,
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: false,
      requiresIsolation: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 30_000,
      notes: [
        'Bundled Python worker parses bytes with the standard library struct module.',
        'Worker policy forbids sample execution, native loading, runtime startup, mutation, and network access.',
      ],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [],
      missingBackendBehavior:
        'ELF/Mach-O parsing uses a bundled local Python worker; missing Python prevents parsing but does not trigger installation or backend startup.',
    },
    packaging: {
      installRoute: 'installed',
      installProfile: 'default',
      dockerFeature: 'elf-macho',
      notes: ['No external native parser, runtime backend, or network service is required.'],
    },
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function countArrayField(record: Record<string, unknown>, field: string): number {
  const value = record[field]
  return Array.isArray(value) ? value.length : 0
}

function dynamicTags(data: Record<string, unknown>): string[] {
  const dynamic = data.dynamic
  if (!Array.isArray(dynamic)) return []
  return Array.from(
    new Set(
      dynamic
        .map((entry) => (isRecord(entry) && typeof entry.tag === 'string' ? entry.tag : ''))
        .filter(Boolean)
    )
  )
}

function machoLoadCommandNames(data: Record<string, unknown>): string[] {
  const loadCommands = data.load_commands
  if (!Array.isArray(loadCommands)) return []
  return Array.from(
    new Set(
      loadCommands
        .map((entry) => (isRecord(entry) && typeof entry.cmd === 'string' ? entry.cmd : ''))
        .filter(Boolean)
    )
  )
}

function passivePolicy() {
  return {
    passive: true,
    no_execute: true,
    no_sample_execution: true,
    no_runtime_start: true,
    no_native_load: true,
    no_network: true,
    no_mutation: true,
  }
}

function dynamicBoundary() {
  return {
    sample_executed_by_tool: false,
    runtime_started_by_tool: false,
    native_library_loaded_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
  }
}

function baseQualityGates(schema: string) {
  return {
    schema,
    passive_static_analysis: true,
    sample_executed_by_tool: false,
    runtime_started_by_tool: false,
    native_library_loaded_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
  }
}

export function enrichElfStructureResult(
  result: Record<string, unknown>,
  context: { sampleId: string }
): Record<string, unknown> {
  const counts = {
    sections: countArrayField(result, 'sections'),
    segments: countArrayField(result, 'segments'),
    symbols: countArrayField(result, 'symbols'),
    dynamic_entries: countArrayField(result, 'dynamic'),
  }

  return {
    ...result,
    policy: passivePolicy(),
    workflowRecipes: ELF_STRUCTURE_WORKFLOW_RECIPES,
    evidence_summary: {
      schema: 'rikune.elf_structure.evidence_summary.v1',
      source_tool: 'elf.structure.analyze',
      artifact_type: ELF_STRUCTURE_ARTIFACT_TYPE,
      sample_id: context.sampleId,
      format: result.format ?? 'ELF',
      machine: result.machine ?? null,
      class: result.class ?? null,
      endian: result.endian ?? null,
      evidence_categories: ELF_MACHO_EVIDENCE,
      counts,
      dynamic_tags: dynamicTags(result),
      static_only: true,
      sample_executed_by_tool: false,
      native_library_loaded_by_tool: false,
      network_accessed_by_tool: false,
    },
    workflow_handoff: {
      schema: 'rikune.elf_structure.workflow_handoff.v1',
      handoff_mode: 'elf_structure_to_static_inventory_and_evidence_graph',
      artifact_type: ELF_STRUCTURE_ARTIFACT_TYPE,
      recommended_next_tools: ELF_STRUCTURE_FOLLOW_UP_TOOLS,
      artifact_contract: {
        consumes: ['sample'],
        produces: [ELF_STRUCTURE_ARTIFACT_TYPE],
        expected_consumers: [
          'workflow.search',
          'artifact.read',
          'elf.imports.extract',
          'elf.exports.extract',
          'linux.binary.inventory',
          'analysis.evidence.graph',
          'report.generate',
        ],
      },
      routing: [
        {
          goal: 'elf-loader-and-dependency-static-analysis',
          priority: counts.dynamic_entries > 0 ? 'high' : 'conditional',
          next_tools: ['elf.imports.extract', 'linux.binary.inventory', 'sbom.generate'],
          required_evidence: ['dynamic', 'symbols'],
          consumes: [ELF_STRUCTURE_ARTIFACT_TYPE],
          produces: [ELF_IMPORTS_ARTIFACT_TYPE, 'linux_binary_inventory'],
        },
        {
          goal: 'elf-export-and-symbol-review',
          priority: counts.symbols > 0 ? 'high' : 'conditional',
          next_tools: ['elf.exports.extract', 'analysis.evidence.graph'],
          required_evidence: ['symbols'],
          consumes: [ELF_STRUCTURE_ARTIFACT_TYPE],
          produces: [ELF_EXPORTS_ARTIFACT_TYPE],
        },
        {
          goal: 'evidence-graph-and-reporting',
          priority: 'normal',
          next_tools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: [ELF_STRUCTURE_ARTIFACT_TYPE],
          consumes: [ELF_STRUCTURE_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'analysis_report'],
        },
      ],
      dynamic_boundary: dynamicBoundary(),
    },
    quality_gates: {
      ...baseQualityGates('rikune.elf_structure.quality_gates.v1'),
      sections_present: counts.sections > 0,
      segments_present: counts.segments > 0,
      dynamic_entries_present: counts.dynamic_entries > 0,
      symbols_present: counts.symbols > 0,
    },
    recommended_next_tools: ELF_STRUCTURE_FOLLOW_UP_TOOLS,
    next_actions: [
      'Route the persisted ELF structure artifact through analysis.evidence.graph before reporting.',
      'Use elf.imports.extract and elf.exports.extract when loader or symbol evidence is needed.',
      'Use runtime planning only after explicit opt-in; this tool never executes or loads the sample.',
    ],
  }
}

export function enrichMachoStructureResult(
  result: Record<string, unknown>,
  context: { sampleId: string }
): Record<string, unknown> {
  const counts = {
    load_commands: countArrayField(result, 'load_commands'),
    sections: countArrayField(result, 'sections'),
    symbols: countArrayField(result, 'symbols'),
    fat_architectures: countArrayField(result, 'fat_architectures'),
  }

  return {
    ...result,
    policy: passivePolicy(),
    workflowRecipes: MACHO_STRUCTURE_WORKFLOW_RECIPES,
    evidence_summary: {
      schema: 'rikune.macho_structure.evidence_summary.v1',
      source_tool: 'macho.structure.analyze',
      artifact_type: MACHO_STRUCTURE_ARTIFACT_TYPE,
      sample_id: context.sampleId,
      format: result.format ?? 'MachO',
      cputype: result.cputype ?? null,
      filetype: result.filetype ?? null,
      is_fat: result.is_fat ?? false,
      evidence_categories: ELF_MACHO_EVIDENCE,
      counts,
      load_commands: machoLoadCommandNames(result),
      static_only: true,
      sample_executed_by_tool: false,
      native_library_loaded_by_tool: false,
      network_accessed_by_tool: false,
    },
    workflow_handoff: {
      schema: 'rikune.macho_structure.workflow_handoff.v1',
      handoff_mode: 'macho_structure_to_apple_container_signing_and_evidence_graph',
      artifact_type: MACHO_STRUCTURE_ARTIFACT_TYPE,
      recommended_next_tools: MACHO_STRUCTURE_FOLLOW_UP_TOOLS,
      artifact_contract: {
        consumes: ['sample'],
        produces: [MACHO_STRUCTURE_ARTIFACT_TYPE],
        expected_consumers: [
          'workflow.search',
          'artifact.read',
          'apple.container.inventory',
          'apple.signing.inspect',
          'analysis.evidence.graph',
          'report.generate',
        ],
      },
      routing: [
        {
          goal: 'apple-container-and-signing-static-analysis',
          priority: 'high',
          next_tools: ['apple.container.inventory', 'apple.signing.inspect'],
          required_evidence: ['load_commands', 'symbols'],
          consumes: [MACHO_STRUCTURE_ARTIFACT_TYPE],
          produces: ['apple_container_inventory', 'apple_signing_profile'],
        },
        {
          goal: 'macho-symbol-and-slice-reporting',
          priority: counts.symbols > 0 || counts.fat_architectures > 0 ? 'high' : 'normal',
          next_tools: ['analysis.evidence.graph', 'report.generate'],
          required_evidence: ['symbols', 'fat_architectures'],
          consumes: [MACHO_STRUCTURE_ARTIFACT_TYPE],
          produces: ['macho_structure_graph'],
        },
        {
          goal: 'evidence-graph-and-reporting',
          priority: 'normal',
          next_tools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: [MACHO_STRUCTURE_ARTIFACT_TYPE],
          consumes: [MACHO_STRUCTURE_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'analysis_report'],
        },
      ],
      dynamic_boundary: dynamicBoundary(),
    },
    quality_gates: {
      ...baseQualityGates('rikune.macho_structure.quality_gates.v1'),
      load_commands_present: counts.load_commands > 0,
      sections_present: counts.sections > 0,
      symbols_present: counts.symbols > 0,
      universal_slices_present: counts.fat_architectures > 0,
    },
    recommended_next_tools: MACHO_STRUCTURE_FOLLOW_UP_TOOLS,
    next_actions: [
      'Route the persisted Mach-O structure artifact through analysis.evidence.graph before reporting.',
      'Use Apple container and signing tools to correlate load commands, entitlements, and packaging evidence.',
      'Use runtime planning only after explicit opt-in; this tool never executes or loads the sample.',
    ],
  }
}

export function enrichElfImportsResult(
  result: Record<string, unknown>,
  context: { sampleId: string }
): Record<string, unknown> {
  const counts = {
    needed_libraries: countArrayField(result, 'needed_libraries'),
    imported_symbols: countArrayField(result, 'imported_symbols'),
  }

  return {
    ...result,
    policy: passivePolicy(),
    workflowRecipes: ELF_IMPORTS_WORKFLOW_RECIPES,
    evidence_summary: {
      schema: 'rikune.elf_imports.evidence_summary.v1',
      source_tool: 'elf.imports.extract',
      artifact_type: ELF_IMPORTS_ARTIFACT_TYPE,
      sample_id: context.sampleId,
      evidence_categories: ['imports', 'symbols', 'loader', 'workflow', 'provenance'],
      counts,
      static_only: true,
      sample_executed_by_tool: false,
      native_library_loaded_by_tool: false,
      network_accessed_by_tool: false,
    },
    workflow_handoff: {
      schema: 'rikune.elf_imports.workflow_handoff.v1',
      handoff_mode: 'elf_imports_to_dependency_inventory_sbom_and_evidence_graph',
      artifact_type: ELF_IMPORTS_ARTIFACT_TYPE,
      recommended_next_tools: ELF_IMPORTS_FOLLOW_UP_TOOLS,
      artifact_contract: {
        consumes: ['sample'],
        produces: [ELF_IMPORTS_ARTIFACT_TYPE],
        expected_consumers: [
          'workflow.search',
          'artifact.read',
          'linux.binary.inventory',
          'sbom.generate',
          'analysis.evidence.graph',
          'report.generate',
        ],
      },
      routing: [
        {
          goal: 'elf-shared-library-dependency-review',
          priority: counts.needed_libraries > 0 ? 'high' : 'conditional',
          next_tools: ['linux.binary.inventory', 'sbom.generate'],
          required_evidence: ['needed_libraries'],
          consumes: [ELF_IMPORTS_ARTIFACT_TYPE],
          produces: ['linux_dependency_inventory', 'sbom'],
        },
        {
          goal: 'evidence-graph-and-reporting',
          priority: 'normal',
          next_tools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: [ELF_IMPORTS_ARTIFACT_TYPE],
          consumes: [ELF_IMPORTS_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'analysis_report'],
        },
      ],
      dynamic_boundary: dynamicBoundary(),
    },
    quality_gates: {
      ...baseQualityGates('rikune.elf_imports.quality_gates.v1'),
      needed_libraries_present: counts.needed_libraries > 0,
      imported_symbols_present: counts.imported_symbols > 0,
    },
    recommended_next_tools: ELF_IMPORTS_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use linux.binary.inventory or sbom.generate to preserve dependency context.',
      'Route ELF import evidence into analysis.evidence.graph before reporting.',
    ],
  }
}

export function enrichElfExportsResult(
  result: Record<string, unknown>,
  context: { sampleId: string }
): Record<string, unknown> {
  const counts = {
    exported_symbols: countArrayField(result, 'exported_symbols'),
  }

  return {
    ...result,
    policy: passivePolicy(),
    workflowRecipes: ELF_EXPORTS_WORKFLOW_RECIPES,
    evidence_summary: {
      schema: 'rikune.elf_exports.evidence_summary.v1',
      source_tool: 'elf.exports.extract',
      artifact_type: ELF_EXPORTS_ARTIFACT_TYPE,
      sample_id: context.sampleId,
      evidence_categories: ['exports', 'symbols', 'workflow', 'provenance'],
      counts,
      static_only: true,
      sample_executed_by_tool: false,
      native_library_loaded_by_tool: false,
      network_accessed_by_tool: false,
    },
    workflow_handoff: {
      schema: 'rikune.elf_exports.workflow_handoff.v1',
      handoff_mode: 'elf_exports_to_symbol_review_and_evidence_graph',
      artifact_type: ELF_EXPORTS_ARTIFACT_TYPE,
      recommended_next_tools: ELF_EXPORTS_FOLLOW_UP_TOOLS,
      artifact_contract: {
        consumes: ['sample'],
        produces: [ELF_EXPORTS_ARTIFACT_TYPE],
        expected_consumers: [
          'workflow.search',
          'artifact.read',
          'linux.binary.inventory',
          'analysis.evidence.graph',
          'report.generate',
        ],
      },
      routing: [
        {
          goal: 'elf-exported-symbol-review',
          priority: counts.exported_symbols > 0 ? 'high' : 'conditional',
          next_tools: ['linux.binary.inventory', 'analysis.evidence.graph'],
          required_evidence: ['exported_symbols'],
          consumes: [ELF_EXPORTS_ARTIFACT_TYPE],
          produces: ['symbol_inventory'],
        },
        {
          goal: 'evidence-graph-and-reporting',
          priority: 'normal',
          next_tools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: [ELF_EXPORTS_ARTIFACT_TYPE],
          consumes: [ELF_EXPORTS_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'analysis_report'],
        },
      ],
      dynamic_boundary: dynamicBoundary(),
    },
    quality_gates: {
      ...baseQualityGates('rikune.elf_exports.quality_gates.v1'),
      exported_symbols_present: counts.exported_symbols > 0,
    },
    recommended_next_tools: ELF_EXPORTS_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use linux.binary.inventory to correlate exported symbol evidence with loader metadata.',
      'Route ELF export evidence into analysis.evidence.graph before reporting.',
    ],
  }
}
