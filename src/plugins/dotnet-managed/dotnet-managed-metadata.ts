import type { ToolDefinition } from '../../types.js'

export const DOTNET_MANAGED_FORMATS = ['dotnet', 'pe-clr', 'nupkg', 'mono', 'winmd']
export const DOTNET_MANAGED_PLATFORMS = ['dotnet', 'windows', 'linux', 'macos']
export const DOTNET_MANAGED_ARCHITECTURES = ['x86', 'x64', 'arm64', 'arm']
export const DOTNET_MANAGED_EXECUTION = ['static', 'triage', 'workflow-handoff']

export const DOTNET_MANAGED_SAFETY = [
  'passive',
  'no_execute',
  'no_runtime_start',
  'no_package_restore',
  'no_decompiler_launch',
  'no_network',
  'no_mutation',
]

export const DOTNET_MANAGED_EVIDENCE = [
  'manifest',
  'resources',
  'package-metadata',
  'managed-metadata',
  'dependency-hints',
  'pinvoke-hints',
  'workflow',
  'provenance',
]

export const DOTNET_MANAGED_CAPABILITIES = [
  'assembly-metadata',
  'managed-metadata',
  'resources',
  'dependencies',
  'target-framework-profile',
  'pinvoke-profile',
  'decompile-plan',
  'managed-xref-handoff',
  'workflow-handoff',
  'artifact-handoff',
  'routing',
]

export const DOTNET_MANAGED_SEARCH_TERMS = [
  'dotnet',
  'managed',
  'pe-clr',
  'clr-metadata',
  'nupkg',
  'winmd',
  'mono',
  'target-framework',
  'assembly-reference',
  'pinvoke',
  'managed-xref',
  'decompile-plan',
  'workflow-handoff',
  'artifact-handoff',
  'quality-gates',
]

export const DOTNET_MANAGED_PROFILE_TERMS = [
  'managed-inventory',
  'bounded-preview',
  'passive-profile',
  'metadata-only-handoff',
  'no-clr-start',
  'no-package-restore',
  'no-decompiler-launch',
]

export const DOTNET_MANAGED_ROUTE_TERMS = [
  'dotnet_inventory_profile',
  'clr_metadata_handoff',
  'bounded_preview_static_analysis',
  'managed_metadata_confirmation',
  'managed_xref_handoff',
  'dotnet_type_inventory',
  'no_clr_start',
  'no_package_restore',
  'no_decompiler_launch',
]

export const DOTNET_ASSEMBLY_ARTIFACT_TYPE = 'dotnet_assembly_inventory'
export const DOTNET_MANAGED_TOOL_VERSION = '1.1.0'

export const DOTNET_ASSEMBLY_EVIDENCE_SUMMARY_SCHEMA =
  'rikune.dotnet_assembly_inventory.evidence_summary.v1'
export const DOTNET_ASSEMBLY_WORKFLOW_HANDOFF_SCHEMA =
  'rikune.dotnet_assembly_inventory.workflow_handoff.v1'
export const DOTNET_ASSEMBLY_QUALITY_GATES_SCHEMA =
  'rikune.dotnet_assembly_inventory.quality_gates.v1'

export const DOTNET_MANAGED_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'dotnet.metadata.extract',
  'dotnet.types.list',
  'managed.il_xrefs',
  'managed.token_xrefs',
  'analysis.evidence.graph',
  'report.generate',
]

export const DOTNET_MANAGED_DECOMPILATION_ROUTE_TOOLS = ['dotnet.decompile.type']

export const DOTNET_MANAGED_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noClrStart: true,
  noPackageRestore: true,
  noDecompilerLaunch: true,
  notes: [
    'dotnet.assembly.inspect reads only a bounded preview of the sample and does not start the CLR.',
    'NuGet package restore, managed code execution, and ILSpy/decompiler launch are explicitly out of scope for this passive inventory.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noClrStart: true
  noPackageRestore: true
  noDecompilerLaunch: true
}

export function dotnetManagedAspects(capabilities: string[] = DOTNET_MANAGED_CAPABILITIES) {
  return {
    formats: DOTNET_MANAGED_FORMATS,
    platforms: DOTNET_MANAGED_PLATFORMS,
    architectures: DOTNET_MANAGED_ARCHITECTURES,
    execution: DOTNET_MANAGED_EXECUTION,
    safety: DOTNET_MANAGED_SAFETY,
    capabilities,
    evidence: DOTNET_MANAGED_EVIDENCE,
    search: DOTNET_MANAGED_SEARCH_TERMS,
    profile: DOTNET_MANAGED_PROFILE_TERMS,
    route_terms: DOTNET_MANAGED_ROUTE_TERMS,
  }
}

export function dotnetManagedRecipe() {
  return {
    id: 'dotnet-managed.passive-inventory-handoff',
    title: '.NET managed passive inventory handoff',
    description:
      'Extract bounded .NET, NuGet, Mono, and WinMD metadata hints without CLR execution, package restore, or decompiler launch, then hand off to managed metadata, type listing, IL xrefs, evidence graph, artifact read, or reporting tools.',
    startsWith: ['dotnet.assembly.inspect'],
    nextTools: DOTNET_MANAGED_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample'],
    producesArtifacts: [DOTNET_ASSEMBLY_ARTIFACT_TYPE],
    evidence: DOTNET_MANAGED_EVIDENCE,
    safety: DOTNET_MANAGED_SAFETY,
  }
}

export type DotnetAssemblyInventoryEnvelopeInput = {
  sample_id?: string
  format: string
  detected_by: string[]
  archive_members: string[]
  assembly_hints: string[]
  target_framework_hints: string[]
  dependency_hints: string[]
  resource_hints: string[]
  pinvoke_hints: string[]
  recommended_next_tools: string[]
}

export function buildDotnetManagedEnvelope(inventory: DotnetAssemblyInventoryEnvelopeInput) {
  return {
    evidence_summary: {
      schema: DOTNET_ASSEMBLY_EVIDENCE_SUMMARY_SCHEMA,
      source_tool: 'dotnet.assembly.inspect',
      sample_id: inventory.sample_id ?? null,
      format: inventory.format,
      detected_by: inventory.detected_by,
      artifact_type: DOTNET_ASSEMBLY_ARTIFACT_TYPE,
      route_terms: DOTNET_MANAGED_ROUTE_TERMS,
      evidence_categories: DOTNET_MANAGED_EVIDENCE,
      counts: {
        archive_members: inventory.archive_members.length,
        assembly_hints: inventory.assembly_hints.length,
        target_framework_hints: inventory.target_framework_hints.length,
        dependency_hints: inventory.dependency_hints.length,
        resource_hints: inventory.resource_hints.length,
        pinvoke_hints: inventory.pinvoke_hints.length,
      },
      highlights: {
        assemblies: inventory.assembly_hints.slice(0, 12),
        target_frameworks: inventory.target_framework_hints.slice(0, 12),
        dependencies: inventory.dependency_hints.slice(0, 12),
        resources: inventory.resource_hints.slice(0, 12),
        pinvoke: inventory.pinvoke_hints.slice(0, 12),
      },
      static_only: true,
      backend_semantics: {
        bounded_preview_only: true,
        clr_started: false,
        package_restore_performed: false,
        decompiler_launched: false,
        network_used: false,
      },
    },
    workflow_handoff: {
      schema: DOTNET_ASSEMBLY_WORKFLOW_HANDOFF_SCHEMA,
      handoff_mode: 'dotnet_passive_inventory_to_managed_analysis',
      source_tool: 'dotnet.assembly.inspect',
      sample_id: inventory.sample_id ?? null,
      recommended_next_tools: inventory.recommended_next_tools,
      artifact_contract: {
        consumes: ['sample'],
        produces: [DOTNET_ASSEMBLY_ARTIFACT_TYPE],
        mime: 'application/json',
        expected_consumers: DOTNET_MANAGED_FOLLOW_UP_TOOLS,
      },
      dynamic_boundary: {
        activation_boundary: 'result-scoped',
        sample_execution_allowed: false,
        clr_start_allowed: false,
        package_restore_allowed: false,
        decompiler_launch_allowed: false,
        network_allowed: false,
        mutation_allowed: false,
        sample_executed_by_tool: false,
        clr_started_by_tool: false,
        package_restored_by_tool: false,
        decompiler_launched_by_tool: false,
        network_used_by_tool: false,
      },
      routing: [
        {
          goal: 'managed-metadata-confirmation',
          priority: 'high',
          route_terms: ['managed_metadata_confirmation', 'clr_metadata_handoff'],
          next_tools: ['dotnet.metadata.extract', 'dotnet.types.list'],
          consumes: [DOTNET_ASSEMBLY_ARTIFACT_TYPE],
          produces: ['dotnet_metadata', 'dotnet_type_index'],
        },
        {
          goal: 'managed-cross-reference-review',
          priority: inventory.assembly_hints.length > 0 ? 'medium' : 'low',
          route_terms: ['managed_xref_handoff', 'dotnet_type_inventory'],
          next_tools: ['managed.il_xrefs', 'managed.token_xrefs'],
          consumes: ['dotnet_metadata', DOTNET_ASSEMBLY_ARTIFACT_TYPE],
          produces: ['managed_il_xrefs', 'managed_token_xrefs'],
        },
        {
          goal: 'bounded-decompilation-planning',
          priority: 'medium',
          route_terms: ['decompile-plan', 'dotnet_type_inventory'],
          next_tools: DOTNET_MANAGED_DECOMPILATION_ROUTE_TOOLS,
          consumes: ['dotnet_type_index'],
          produces: ['dotnet_type_decompile'],
          blocking_conditions: [
            'Do not run whole-assembly decompilation from this passive inventory route.',
            'Select a specific managed type from dotnet.types.list before activating dotnet.decompile.type.',
          ],
        },
        {
          goal: 'evidence-and-reporting',
          priority: 'medium',
          route_terms: ['artifact-handoff', 'quality-gates'],
          next_tools: ['analysis.evidence.graph', 'artifact.read', 'report.generate'],
          consumes: [DOTNET_ASSEMBLY_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'report'],
        },
      ],
      quality_gates_schema: DOTNET_ASSEMBLY_QUALITY_GATES_SCHEMA,
    },
    quality_gates: {
      schema: DOTNET_ASSEMBLY_QUALITY_GATES_SCHEMA,
      passive_static_inventory: true,
      bounded_preview_only: true,
      format_detected: inventory.format !== 'unknown',
      managed_or_package_format: DOTNET_MANAGED_FORMATS.includes(inventory.format),
      assembly_hints_present: inventory.assembly_hints.length > 0,
      target_framework_hints_present: inventory.target_framework_hints.length > 0,
      dependency_hints_present: inventory.dependency_hints.length > 0,
      resource_hints_present: inventory.resource_hints.length > 0,
      pinvoke_hints_present: inventory.pinvoke_hints.length > 0,
      sample_executed_by_tool: false,
      clr_started_by_tool: false,
      package_restored_by_tool: false,
      decompiler_launched_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
  }
}
