import type { ToolDefinition } from '../../../types.js'

type CodeAnalysisToolMetadata = Pick<
  ToolDefinition,
  'aspects' | 'artifacts' | 'evidence' | 'workflowRecipes' | 'runtimePolicy'
>

const CODE_ANALYSIS_FORMATS = [
  'pe',
  'exe',
  'dll',
  'elf',
  'so',
  'macho',
  'dylib',
  'dotnet',
  'native-binary',
  'firmware',
  'object',
  'static-lib',
]

const CODE_ANALYSIS_PLATFORMS = ['windows', 'linux', 'macos', 'cross-platform']

const CODE_ANALYSIS_ARCHITECTURES = ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc', 'riscv', 'wasm32']

export const CODE_ANALYSIS_SAFETY = [
  'passive',
  'artifact_first',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
  'no_sample_execution',
]

export const CODE_ANALYSIS_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'Code-analysis tools are passive static-analysis workflows and must not execute the analyzed sample.',
    'Decompiler, graph, build, and export helpers are tool backends or recipe runtimeBackends, not runtime isolation backends.',
    'Workflow recipes prefer artifact-first handoffs through artifact.read, analysis.evidence.graph, and report.generate.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}

export const CODE_CROSS_DECOMPILER_CONSENSUS_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noBackendStart: true,
  notes: [
    'code.cross_decompiler.consensus compares already produced decompiler, disassembler, and IR artifacts only.',
    'It must not launch Ghidra, RetDec, Rizin, radare2, Angr, rev.ng, Remill, GTIRB, or any other backend.',
    'Use missing_backend_gaps and workflow recipes to choose follow-up backend collection explicitly.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noBackendStart: true
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function buildCodeAnalysisAspects(params: {
  capabilities: string[]
  evidence: string[]
  formats?: string[]
  platforms?: string[]
  architectures?: string[]
  execution?: string[]
  safety?: string[]
}) {
  return {
    formats: uniqueStrings([...(params.formats ?? []), ...CODE_ANALYSIS_FORMATS]),
    platforms: uniqueStrings([...(params.platforms ?? []), ...CODE_ANALYSIS_PLATFORMS]),
    architectures: uniqueStrings([...(params.architectures ?? []), ...CODE_ANALYSIS_ARCHITECTURES]),
    execution: uniqueStrings([
      ...(params.execution ?? []),
      'static',
      'decompilation',
      'function-recovery',
      'workflow-handoff',
    ]),
    safety: uniqueStrings([...(params.safety ?? []), ...CODE_ANALYSIS_SAFETY]),
    capabilities: uniqueStrings([
      ...params.capabilities,
      'reverse-engineering',
      'function-analysis',
      'function-recovery',
      'function-index',
      'function-search',
      'decompile',
      'decompilation',
      'disassembly',
      'cfg',
      'control-flow-graph',
      'xref',
      'xrefs',
      'cross-reference',
      'reconstruct',
      'source-reconstruction',
      'workflow-handoff',
      'search-profile',
    ]),
    evidence: uniqueStrings([
      ...params.evidence,
      'functions',
      'function-index',
      'symbols',
      'cfg',
      'xrefs',
      'decompiled-code',
      'disassembly',
      'workflow',
      'provenance',
    ]),
  }
}

function artifact(
  type: string,
  description: string
): NonNullable<ToolDefinition['artifacts']>[number] {
  return {
    type,
    description,
    mime: 'application/json',
  }
}

function evidenceSpecs(
  categories: string[],
  artifactTypes: string[]
): NonNullable<ToolDefinition['evidence']> {
  return uniqueStrings(categories).map((category) => ({
    category,
    artifactTypes,
  }))
}

function buildMetadata(params: {
  capabilities: string[]
  evidence: string[]
  artifacts: NonNullable<ToolDefinition['artifacts']>
  workflowRecipes: NonNullable<ToolDefinition['workflowRecipes']>
  execution?: string[]
  formats?: string[]
  runtimePolicy?: ToolDefinition['runtimePolicy']
}): CodeAnalysisToolMetadata {
  const artifactTypes = params.artifacts.map((item) => item.type)
  return {
    aspects: buildCodeAnalysisAspects({
      capabilities: params.capabilities,
      evidence: params.evidence,
      execution: params.execution,
      formats: params.formats,
    }),
    artifacts: params.artifacts,
    evidence: evidenceSpecs(params.evidence, artifactTypes),
    workflowRecipes: params.workflowRecipes,
    runtimePolicy: params.runtimePolicy ?? CODE_ANALYSIS_RUNTIME_POLICY,
  }
}

const FUNCTION_RECOVERY_TOOLS = [
  'code.functions.smart_recover',
  'code.functions.define',
  'code.functions.list',
  'code.functions.rank',
  'code.functions.search',
  'code.xrefs.analyze',
  'code.functions.reconstruct',
]

const FUNCTION_NAVIGATION_TOOLS = [
  'code.functions.search',
  'code.xrefs.analyze',
  'code.function.decompile',
  'code.function.disassemble',
  'code.function.cfg',
  'code.functions.reconstruct',
]

const RECONSTRUCT_EXPORT_TOOLS = [
  'code.reconstruct.plan',
  'code.functions.reconstruct',
  'code.reconstruct.export',
  'dotnet.reconstruct.export',
  'code.module.review.prepare',
  'analysis.evidence.graph',
  'report.generate',
  'artifact.read',
]

export const CODE_FUNCTIONS_LIST_METADATA = buildMetadata({
  capabilities: ['function-list', 'function-inventory', 'function-map', 'function-index-query'],
  evidence: ['functions', 'function-index', 'symbols', 'function-map'],
  artifacts: [
    artifact(
      'function_index',
      'Function index view with names, addresses, caller counts, and callee counts'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-list-profile',
      title: 'Function list and recovery profile',
      description:
        'List recovered functions after Ghidra analysis, metadata-only function recovery, manual definitions, or native export/import handoff.',
      startsWith: ['code.functions.list'],
      nextTools: FUNCTION_RECOVERY_TOOLS,
      requiredArtifacts: ['sample', 'ghidra-analysis-or-recovered-function-index'],
      producesArtifacts: ['function_index'],
      evidence: ['functions', 'function-index', 'symbols', 'function-recovery', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      searchTerms: ['function recovery', 'function list', 'function map', 'native export'],
    },
  ],
})

export const CODE_FUNCTIONS_RANK_METADATA = buildMetadata({
  capabilities: [
    'function-ranking',
    'function-prioritization',
    'sensitive-api-ranking',
    'xref-prioritization',
  ],
  evidence: ['functions', 'function-rank', 'sensitive-apis', 'xrefs', 'vulnerability-risk'],
  artifacts: [
    artifact(
      'function_rank_profile',
      'Ranked function profile for prioritizing decompile, CFG, xref, and reconstruction work'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-prioritization',
      title: 'Function prioritization for reverse engineering',
      description:
        'Rank high-value functions before decompile, CFG, xref analysis, source reconstruction, or native export.',
      startsWith: ['code.functions.rank'],
      nextTools: FUNCTION_NAVIGATION_TOOLS,
      requiredArtifacts: ['function_index'],
      producesArtifacts: ['function_rank_profile'],
      evidence: ['functions', 'function-rank', 'xrefs', 'sensitive-apis', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      searchTerms: ['function recovery', 'function ranking', 'decompile', 'cfg', 'xref'],
    },
  ],
})

export const CODE_FUNCTIONS_SMART_RECOVER_METADATA = buildMetadata({
  capabilities: [
    'function-boundary-recovery',
    'pdata-function-recovery',
    'export-function-recovery',
    'entry-point-recovery',
    'metadata-only-handoff',
  ],
  evidence: ['function-recovery', 'function-boundaries', 'pdata', 'exports', 'entry-point'],
  artifacts: [
    artifact(
      'function_recovery_candidates',
      'Metadata-only function recovery candidates from .pdata, exports, and entry-point evidence'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-recovery',
      title: 'Metadata-only function recovery',
      description:
        'Recover PE function boundaries from .pdata/runtime metadata, exports, and entry point when decompiler function recovery is empty or incomplete.',
      startsWith: ['code.functions.smart_recover'],
      nextTools: [
        'code.functions.define',
        'code.functions.list',
        'code.functions.rank',
        'code.functions.reconstruct',
        'analysis.evidence.graph',
      ],
      requiredArtifacts: ['sample', 'pe-runtime-metadata', 'exports', 'entry-point'],
      producesArtifacts: ['function_recovery_candidates', 'function_index'],
      evidence: ['function-recovery', 'function-boundaries', 'pdata', 'exports', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      searchTerms: ['function recovery', 'metadata-only', 'pdata', 'native export'],
    },
  ],
})

export const CODE_FUNCTIONS_DEFINE_METADATA = buildMetadata({
  capabilities: [
    'function-index-import',
    'manual-function-definition',
    'metadata-only-handoff',
    'recovered-function-import',
  ],
  evidence: ['function-definitions', 'function-index', 'function-recovery', 'provenance'],
  artifacts: [
    artifact(
      'function_definition_import',
      'Imported function definitions with provenance for later list, rank, search, and reconstruction'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-definition-import',
      title: 'Import recovered function definitions',
      description:
        'Promote smart-recovered, symbol-recovered, external, or manual function boundaries into the function index for search, CFG, xref, decompile, and reconstruct workflows.',
      startsWith: ['code.functions.define'],
      nextTools: [
        'code.functions.list',
        'code.functions.rank',
        'code.functions.search',
        'code.functions.reconstruct',
        'analysis.evidence.graph',
      ],
      requiredArtifacts: ['function_recovery_candidates-or-external-function-map'],
      producesArtifacts: ['function_definition_import', 'function_index'],
      evidence: ['function-definitions', 'function-index', 'function-recovery', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      searchTerms: ['function recovery', 'function index', 'reconstruct'],
    },
  ],
})

export const CODE_FUNCTIONS_SEARCH_METADATA = buildMetadata({
  capabilities: [
    'function-search',
    'api-search',
    'string-to-function-search',
    'xref-discovery',
    'indicator-to-function',
  ],
  evidence: ['function-search', 'api-references', 'string-references', 'xrefs', 'functions'],
  artifacts: [
    artifact(
      'function_search_results',
      'Function search matches for API and string reference queries'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-search-xrefs',
      title: 'Function search and xref pivot',
      description:
        'Search functions by API or string, then pivot to xref, decompile, CFG, reconstruct, native export, or evidence graph workflows.',
      startsWith: ['code.functions.search'],
      nextTools: [
        'code.xrefs.analyze',
        'code.function.decompile',
        'code.function.cfg',
        'code.functions.reconstruct',
        'analysis.evidence.graph',
      ],
      requiredArtifacts: ['function_index', 'strings-or-import-evidence'],
      producesArtifacts: ['function_search_results'],
      evidence: ['function-search', 'api-references', 'string-references', 'xrefs', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      searchTerms: ['function search', 'xref', 'xrefs', 'decompile', 'reconstruct'],
    },
  ],
})

export const CODE_XREFS_ANALYZE_METADATA = buildMetadata({
  capabilities: [
    'xref-analysis',
    'cross-reference-analysis',
    'caller-callee-navigation',
    'indicator-to-function',
    'bounded-graph-preview',
  ],
  evidence: ['xrefs', 'cross-references', 'callers', 'callees', 'api-references', 'strings'],
  artifacts: [
    artifact(
      'xref_analysis',
      'Bounded cross-reference snapshot for function, API, string, or data targets'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.xref-navigation',
      title: 'Xref navigation before decompile or CFG',
      description:
        'Analyze bounded inbound/outbound xrefs for functions, APIs, strings, or data before decompile, CFG, reconstruction, or cross-decompiler consensus.',
      startsWith: ['code.xrefs.analyze'],
      nextTools: [
        'code.functions.search',
        'code.function.decompile',
        'code.function.cfg',
        'code.functions.reconstruct',
        'code.cross_decompiler.consensus',
        'analysis.evidence.graph',
      ],
      requiredArtifacts: ['function_index', 'string-or-api-target'],
      producesArtifacts: ['xref_analysis'],
      evidence: ['xrefs', 'cross-references', 'callers', 'callees', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      searchTerms: ['xref', 'xrefs', 'cross reference', 'function recovery', 'cfg'],
    },
  ],
})

export const CODE_FUNCTION_DECOMPILE_METADATA = buildMetadata({
  capabilities: ['function-decompile', 'pseudocode', 'decompiler-output', 'xrefs-on-decompile'],
  evidence: ['decompiled-code', 'pseudocode', 'functions', 'callers', 'callees', 'xrefs'],
  artifacts: [
    artifact(
      'function_decompile',
      'Function pseudocode with optional caller, callee, and xref context'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-decompile',
      title: 'Function decompile and semantic review',
      description:
        'Decompile one function to pseudocode, optionally include xrefs, then continue with CFG, reconstruct, native export, or cross-decompiler consensus.',
      startsWith: ['code.function.decompile'],
      nextTools: [
        'code.function.cfg',
        'code.function.disassemble',
        'code.xrefs.analyze',
        'code.functions.reconstruct',
        'code.cross_decompiler.consensus',
      ],
      requiredArtifacts: ['ghidra-analysis', 'function_index'],
      producesArtifacts: ['function_decompile'],
      evidence: ['decompiled-code', 'pseudocode', 'functions', 'xrefs', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      runtimeBackends: ['ghidra'],
      searchTerms: ['decompile', 'function recovery', 'xref', 'cfg', 'reconstruct'],
    },
  ],
})

export const CODE_FUNCTION_DISASSEMBLE_METADATA = buildMetadata({
  capabilities: ['function-disassembly', 'assembly', 'entrypoint-fallback-disasm'],
  evidence: ['disassembly', 'instructions', 'functions', 'entry-point', 'provenance'],
  artifacts: [
    artifact(
      'function_disassembly',
      'Function assembly listing or bounded entry-point fallback disassembly'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-disassembly',
      title: 'Function disassembly fallback',
      description:
        'Inspect function assembly when decompile is unavailable, then pivot to CFG, xref analysis, reconstruction, or cross-decompiler consensus.',
      startsWith: ['code.function.disassemble'],
      nextTools: [
        'code.function.cfg',
        'code.xrefs.analyze',
        'code.function.decompile',
        'code.functions.reconstruct',
        'analysis.evidence.graph',
      ],
      requiredArtifacts: ['sample-or-ghidra-analysis'],
      producesArtifacts: ['function_disassembly'],
      evidence: ['disassembly', 'instructions', 'functions', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      runtimeBackends: ['ghidra', 'entrypoint-fallback'],
      searchTerms: ['disassemble', 'decompile', 'cfg', 'function recovery'],
    },
  ],
})

export const CODE_FUNCTION_CFG_METADATA = buildMetadata({
  capabilities: [
    'function-cfg',
    'cfg-export',
    'control-flow-graph',
    'dot-export',
    'mermaid-export',
    'graphviz-render',
    'local-call-relationships',
  ],
  evidence: ['cfg', 'control-flow', 'basic-blocks', 'call-relationships', 'xrefs'],
  artifacts: [
    artifact(
      'function_cfg_graph',
      'Function CFG graph export in JSON, DOT, Mermaid, SVG, or PNG artifact-first form'
    ),
    artifact(
      'local_call_relationship_graph',
      'Bounded local caller/callee graph around the selected function'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-cfg-export',
      title: 'Function CFG graph export',
      description:
        'Export control-flow graph (CFG), DOT, Mermaid, or Graphviz-rendered artifacts before decompile, xref review, reconstruct, report, or native export.',
      startsWith: ['code.function.cfg'],
      nextTools: [
        'artifact.read',
        'graphviz.render',
        'code.function.decompile',
        'code.xrefs.analyze',
        'code.functions.reconstruct',
        'report.generate',
      ],
      requiredArtifacts: ['ghidra-analysis', 'function_index'],
      producesArtifacts: ['function_cfg_graph', 'local_call_relationship_graph'],
      evidence: ['cfg', 'control-flow', 'basic-blocks', 'call-relationships', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      runtimeBackends: ['ghidra', 'graphviz'],
      searchTerms: ['CFG', 'control flow graph', 'xref', 'decompile', 'reconstruct'],
    },
  ],
})

export const CODE_FUNCTIONS_RECONSTRUCT_METADATA = buildMetadata({
  capabilities: [
    'function-reconstruction',
    'semantic-reconstruction',
    'source-like-reconstruction',
    'xref-aware-reconstruction',
    'cfg-aware-reconstruction',
  ],
  evidence: [
    'function-reconstruction',
    'decompiled-code',
    'cfg',
    'disassembly',
    'xrefs',
    'runtime-evidence',
    'semantic-evidence',
  ],
  artifacts: [
    artifact(
      'function_reconstruction',
      'Function-level source-like reconstruction with confidence, gaps, CFG shape, xrefs, and evidence'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.function-reconstruct',
      title: 'Function semantic reconstruction',
      description:
        'Reconstruct source-like function semantics by combining decompile, CFG, assembly, xref, runtime, and semantic review evidence.',
      startsWith: ['code.functions.reconstruct'],
      nextTools: [
        'code.reconstruct.export',
        'dotnet.reconstruct.export',
        'code.function.explain.prepare',
        'code.function.rename.prepare',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['function_index', 'decompiled-code', 'cfg-or-disassembly'],
      producesArtifacts: ['function_reconstruction'],
      evidence: [
        'function-reconstruction',
        'decompiled-code',
        'cfg',
        'disassembly',
        'xrefs',
        'semantic-evidence',
        'provenance',
      ],
      safety: CODE_ANALYSIS_SAFETY,
      runtimeBackends: ['ghidra'],
      searchTerms: ['function recovery', 'reconstruct', 'decompile', 'cfg', 'xref'],
    },
  ],
})

export const CODE_RECONSTRUCT_PLAN_METADATA = buildMetadata({
  capabilities: [
    'reconstruction-planning',
    'source-reconstruction-plan',
    'function-recovery-routing',
    'dotnet-routing',
    'native-routing',
  ],
  evidence: ['reconstruction-plan', 'runtime-detection', 'packing', 'function-recovery'],
  artifacts: [
    artifact('reconstruction_plan', 'Source reconstruction feasibility and phased workflow plan'),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.reconstruct-plan',
      title: 'Source reconstruction planning',
      description:
        'Plan native export, dotnet export, decompile, CFG, xref, and function recovery phases from current static and decompiler signals.',
      startsWith: ['code.reconstruct.plan'],
      nextTools: RECONSTRUCT_EXPORT_TOOLS,
      requiredArtifacts: ['sample', 'runtime-profile', 'packer-profile', 'function_index'],
      producesArtifacts: ['reconstruction_plan'],
      evidence: ['reconstruction-plan', 'runtime-detection', 'packing', 'provenance'],
      safety: CODE_ANALYSIS_SAFETY,
      searchTerms: ['reconstruct', 'function recovery', 'dotnet export', 'native export'],
    },
  ],
})

export const CODE_RECONSTRUCT_EXPORT_METADATA = buildMetadata({
  capabilities: [
    'native-export',
    'native-reconstruct-export',
    'source-skeleton-export',
    'module-reconstruction',
    'build-validation',
  ],
  evidence: [
    'native-export',
    'source-reconstruction',
    'function-reconstruction',
    'modules',
    'imports',
    'strings',
    'xrefs',
  ],
  artifacts: [
    artifact(
      'native_reconstruction_export',
      'Native C/C++-style source skeleton export with manifest, modules, notes, gaps, and validation logs'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.native-reconstruct-export',
      title: 'Native source reconstruction export',
      description:
        'Export a native source-like project skeleton from reconstructed functions, CFG, xrefs, imports, strings, and module grouping evidence.',
      startsWith: ['code.reconstruct.export'],
      nextTools: [
        'code.module.review.prepare',
        'code.module.review.apply',
        'artifact.read',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['function_reconstruction', 'imports', 'strings', 'function_index'],
      producesArtifacts: ['native_reconstruction_export'],
      evidence: [
        'native-export',
        'source-reconstruction',
        'function-reconstruction',
        'modules',
        'provenance',
      ],
      safety: CODE_ANALYSIS_SAFETY,
      runtimeBackends: ['ghidra', 'clang'],
      searchTerms: ['native export', 'reconstruct', 'function recovery', 'cfg', 'xref'],
    },
  ],
})

export const DOTNET_RECONSTRUCT_EXPORT_METADATA = buildMetadata({
  capabilities: [
    'dotnet-export',
    'dotnet-reconstruct-export',
    'managed-source-export',
    'csharp-skeleton-export',
    'clr-metadata-reconstruction',
  ],
  formats: ['dotnet', 'clr', 'managed', 'csharp'],
  evidence: [
    'dotnet-export',
    'managed-metadata',
    'clr-metadata',
    'source-reconstruction',
    'function-reconstruction',
  ],
  artifacts: [
    artifact(
      'dotnet_reconstruction_export',
      '.NET C# source skeleton export with CLR metadata types, project files, and fallback notes'
    ),
  ],
  workflowRecipes: [
    {
      id: 'code-analysis.dotnet-reconstruct-export',
      title: '.NET source reconstruction export',
      description:
        'Export a dotnet/C# reconstruction skeleton from CLR metadata, decompile output, function recovery, and native fallback evidence.',
      startsWith: ['dotnet.reconstruct.export'],
      nextTools: [
        'artifact.read',
        'dotnet.metadata.extract',
        'code.reconstruct.export',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['dotnet-metadata', 'function_reconstruction-or-native-export'],
      producesArtifacts: ['dotnet_reconstruction_export'],
      evidence: [
        'dotnet-export',
        'managed-metadata',
        'clr-metadata',
        'source-reconstruction',
        'provenance',
      ],
      safety: CODE_ANALYSIS_SAFETY,
      runtimeBackends: ['dotnet', 'ghidra'],
      searchTerms: ['dotnet export', 'managed export', 'reconstruct', 'decompile'],
    },
  ],
})
