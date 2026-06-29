/**
 * code.cross_decompiler.consensus
 *
 * Compares already-produced decompiler, disassembler, and IR-lifter artifacts.
 * This tool is intentionally fixture-safe: it never starts Ghidra, RetDec,
 * radare2, Rizin, Angr, rev.ng, Remill, GTIRB, or any other backend.
 */

import { z } from 'zod'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
} from '../../sdk.js'
import { CODE_CROSS_DECOMPILER_CONSENSUS_RUNTIME_POLICY } from './code-analysis-metadata.js'

const TOOL_NAME = 'code.cross_decompiler.consensus'
const TOOL_VERSION = '0.1.0'

const DEFAULT_EXPECTED_BACKENDS = [
  'ghidra',
  'retdec',
  'rizin',
  'radare2',
  'angr',
  'revng',
  'remill',
  'gtirb',
]

const BACKEND_NEXT_TOOLS: Record<string, string[]> = {
  ghidra: ['ghidra.analyze'],
  retdec: ['retdec.decompile'],
  rizin: ['rizin.analyze'],
  radare2: ['radare2.pipeline.run', 'radare2.pipeline.plan'],
  angr: ['angr.analyze'],
  revng: ['revng.pipeline.plan'],
  remill: ['remill.lift.run', 'remill.lift.plan'],
  gtirb: ['gtirb.ir.generate', 'gtirb.ir.plan'],
}

export const CrossDecompilerFunctionFactSchema = z
  .object({
    address: z.string().optional(),
    range: z
      .object({
        start: z.string(),
        end: z.string().optional(),
      })
      .optional(),
    name: z.string().optional(),
    signature: z.string().optional(),
    calls: z.array(z.string()).optional().default([]),
    xrefs: z.array(z.string()).optional().default([]),
    strings: z.array(z.string()).optional().default([]),
    constants: z
      .array(z.union([z.string(), z.number()]))
      .optional()
      .default([]),
    cfg_shape: z
      .object({
        blocks: z.number().int().nonnegative().optional(),
        edges: z.number().int().nonnegative().optional(),
        loops: z.number().int().nonnegative().optional(),
        cyclomatic: z.number().int().nonnegative().optional(),
      })
      .passthrough()
      .optional(),
    decompiled_text_hash: z.string().optional(),
    ir_fact_hash: z.string().optional(),
    confidence: z.number().min(0).max(1).optional().default(0.5),
  })
  .passthrough()

export const CrossDecompilerArtifactSchema = z
  .object({
    backend: z.string().min(1),
    tool_name: z.string().optional(),
    backend_version: z.string().optional(),
    artifact_type: z.string().optional(),
    artifact_id: z.string().optional(),
    confidence: z.number().min(0).max(1).optional().default(0.5),
    functions: z.array(CrossDecompilerFunctionFactSchema).min(1),
    provenance: z
      .object({
        source: z.string().optional(),
        produced_at: z.string().optional(),
        fixture: z.boolean().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough()

export const CrossDecompilerConsensusInputSchema = z.object({
  sample_id: z.string().optional(),
  artifacts: z
    .array(CrossDecompilerArtifactSchema)
    .min(2)
    .describe('Fixture-safe decompiler/disassembler/IR artifacts from at least two backends.'),
  expected_backends: z.array(z.string()).optional().default(DEFAULT_EXPECTED_BACKENDS),
  min_agreeing_backends: z.number().int().min(2).max(8).optional().default(2),
  include_evidence_graph: z.boolean().optional().default(true),
})

export type CrossDecompilerConsensusInput = z.infer<typeof CrossDecompilerConsensusInputSchema>
type CrossDecompilerArtifact = z.infer<typeof CrossDecompilerArtifactSchema>
type FunctionFact = z.infer<typeof CrossDecompilerFunctionFactSchema>

const ConsensusFunctionSchema = z.object({
  key: z.string(),
  backends: z.array(z.string()),
  addresses: z.array(z.string()),
  names: z.array(z.string()),
  signatures: z.array(z.string()),
  shared_calls: z.array(z.string()),
  shared_strings: z.array(z.string()),
  shared_constants: z.array(z.string()),
  cfg_shapes: z.array(z.any()),
  decompiled_text_hashes: z.array(z.string()),
  ir_fact_hashes: z.array(z.string()),
  confidence: z.number().min(0).max(1),
  reasons: z.array(z.string()),
})

const DisagreementFunctionSchema = z.object({
  key: z.string(),
  backends: z.array(z.string()),
  conflicts: z.array(
    z.object({
      field: z.string(),
      values: z.array(z.object({ backend: z.string(), value: z.any() })),
    })
  ),
  severity: z.enum(['low', 'medium', 'high']),
  recommended_follow_up: z.array(z.string()),
})

type ConsensusFunction = z.infer<typeof ConsensusFunctionSchema>
type DisagreementFunction = z.infer<typeof DisagreementFunctionSchema>

export const CrossDecompilerConsensusOutputSchema = createWorkerResultOutputSchema(
  z.object({
    schema: z.literal('rikune.cross_decompiler_consensus.v1'),
    tool_version: z.string(),
    sample_id: z.string().nullable(),
    execution_semantics: z.object({
      actual_mode: z.literal('static_fixture_consensus'),
      live_execution: z.literal(false),
      backend_process_started: z.literal(false),
      network_access: z.literal(false),
      mutation: z.literal(false),
    }),
    policy: z.object({
      passive: z.literal(true),
      no_backend_start: z.literal(true),
      no_live_sample_execution: z.literal(true),
      no_network: z.literal(true),
      read_only: z.literal(true),
    }),
    artifact_summary: z.object({
      artifact_count: z.number().int().nonnegative(),
      backend_count: z.number().int().nonnegative(),
      backends_present: z.array(z.string()),
      expected_backends: z.array(z.string()),
    }),
    agreement: z.object({
      score: z.number().min(0).max(1),
      functions: z.array(ConsensusFunctionSchema),
      stable_facts: z.array(z.string()),
    }),
    disagreement: z.object({
      count: z.number().int().nonnegative(),
      functions: z.array(DisagreementFunctionSchema),
    }),
    missing_backend_gaps: z.array(
      z.object({
        backend: z.string(),
        impact: z.string(),
        recommended_tools: z.array(z.string()),
      })
    ),
    backend_coverage: z.record(z.string(), z.any()),
    evidence_summary: z.record(z.string(), z.any()),
    function_evidence_handoff: z.record(z.string(), z.any()),
    evidence_graph: z
      .object({
        nodes: z.array(z.object({ id: z.string(), type: z.string(), label: z.string() })),
        edges: z.array(
          z.object({ from: z.string(), to: z.string(), label: z.string(), confidence: z.number() })
        ),
      })
      .optional(),
    quality_gates: z.record(z.string(), z.any()),
    follow_up_recommendations: z.array(z.string()),
  })
)

function normalizeBackend(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, '-')
}

function normalizeText(value: string | undefined): string | null {
  const normalized = value?.trim().toLowerCase()
  return normalized ? normalized : null
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value))))
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000
}

function factAddress(fact: FunctionFact): string | null {
  return normalizeText(fact.address ?? fact.range?.start)
}

function factKey(fact: FunctionFact): string {
  const address = factAddress(fact)
  if (address) return `addr:${address}`
  const irHash = normalizeText(fact.ir_fact_hash)
  if (irHash) return `ir:${irHash}`
  const textHash = normalizeText(fact.decompiled_text_hash)
  if (textHash) return `text:${textHash}`
  const name = normalizeText(fact.name)
  if (name) return `name:${name}`
  const signature = normalizeText(fact.signature)
  if (signature) return `sig:${signature}`
  return 'unknown:function'
}

function normalizedArray(values: unknown[] | undefined): string[] {
  return uniqueStrings((values ?? []).map((value) => normalizeText(String(value))))
}

function intersection(values: string[][]): string[] {
  if (values.length === 0) return []
  const [first, ...rest] = values.map((items) => new Set(items))
  return Array.from(first).filter((item) => rest.every((set) => set.has(item)))
}

function valuesByBackend(
  records: Array<{ backend: string; fact: FunctionFact }>,
  pick: (fact: FunctionFact) => unknown
): Array<{ backend: string; value: unknown }> {
  return records
    .map((record) => ({ backend: record.backend, value: pick(record.fact) }))
    .filter((entry) => {
      if (entry.value == null) return false
      if (typeof entry.value === 'string') return entry.value.trim().length > 0
      if (Array.isArray(entry.value)) return entry.value.length > 0
      return true
    })
}

function hasConflict(values: Array<{ value: unknown }>): boolean {
  const normalized = values.map((entry) => JSON.stringify(entry.value)).filter(Boolean)
  return new Set(normalized).size > 1
}

function averageConfidence(
  records: Array<{ artifact: CrossDecompilerArtifact; fact: FunctionFact }>
) {
  if (records.length === 0) return 0
  const total = records.reduce(
    (sum, record) => sum + (record.fact.confidence ?? 0.5) * (record.artifact.confidence ?? 0.5),
    0
  )
  return round(total / records.length)
}

function buildConsensus(input: CrossDecompilerConsensusInput) {
  const grouped = new Map<
    string,
    Array<{ backend: string; artifact: CrossDecompilerArtifact; fact: FunctionFact }>
  >()
  const backendsPresent = uniqueStrings(
    input.artifacts.map((artifact) => normalizeBackend(artifact.backend))
  )

  for (const artifact of input.artifacts) {
    const backend = normalizeBackend(artifact.backend)
    for (const fact of artifact.functions) {
      const key = factKey(fact)
      const records = grouped.get(key) ?? []
      records.push({ backend, artifact, fact })
      grouped.set(key, records)
    }
  }

  const agreements: z.infer<typeof ConsensusFunctionSchema>[] = []
  const disagreements: z.infer<typeof DisagreementFunctionSchema>[] = []

  for (const [key, records] of grouped.entries()) {
    const backends = uniqueStrings(records.map((record) => record.backend))
    const addresses = uniqueStrings(records.map((record) => factAddress(record.fact)))
    const names = uniqueStrings(records.map((record) => record.fact.name))
    const signatures = uniqueStrings(records.map((record) => record.fact.signature))
    const callsByRecord = records.map((record) => normalizedArray(record.fact.calls))
    const stringsByRecord = records.map((record) => normalizedArray(record.fact.strings))
    const constantsByRecord = records.map((record) => normalizedArray(record.fact.constants))
    const decompiledTextHashes = uniqueStrings(
      records.map((record) => normalizeText(record.fact.decompiled_text_hash))
    )
    const irFactHashes = uniqueStrings(
      records.map((record) => normalizeText(record.fact.ir_fact_hash))
    )
    const cfgShapes = records
      .map((record) => record.fact.cfg_shape)
      .filter((shape): shape is NonNullable<FunctionFact['cfg_shape']> => Boolean(shape))

    const reasons: string[] = []
    if (backends.length >= input.min_agreeing_backends) {
      reasons.push(`Recovered by ${backends.length} backend(s).`)
    }
    if (addresses.length === 1) reasons.push('Function address/range agrees.')
    if (names.length === 1 && names[0]) reasons.push('Function name agrees.')
    if (signatures.length === 1 && signatures[0]) reasons.push('Function signature agrees.')
    if (decompiledTextHashes.length === 1 && decompiledTextHashes[0]) {
      reasons.push('Decompiler text hash agrees.')
    }
    if (irFactHashes.length === 1 && irFactHashes[0]) reasons.push('IR fact hash agrees.')

    if (backends.length >= input.min_agreeing_backends) {
      agreements.push({
        key,
        backends,
        addresses,
        names,
        signatures,
        shared_calls: intersection(callsByRecord),
        shared_strings: intersection(stringsByRecord),
        shared_constants: intersection(constantsByRecord),
        cfg_shapes: cfgShapes,
        decompiled_text_hashes: decompiledTextHashes,
        ir_fact_hashes: irFactHashes,
        confidence: averageConfidence(records),
        reasons: reasons.length > 0 ? reasons : ['Backend records were correlated by key.'],
      })
    }

    const conflictCandidates = [
      { field: 'name', values: valuesByBackend(records, (fact) => fact.name) },
      { field: 'signature', values: valuesByBackend(records, (fact) => fact.signature) },
      {
        field: 'decompiled_text_hash',
        values: valuesByBackend(records, (fact) => fact.decompiled_text_hash),
      },
      { field: 'ir_fact_hash', values: valuesByBackend(records, (fact) => fact.ir_fact_hash) },
      { field: 'cfg_shape', values: valuesByBackend(records, (fact) => fact.cfg_shape) },
    ]
    const conflicts = conflictCandidates
      .filter((candidate) => candidate.values.length >= 2 && hasConflict(candidate.values))
      .map((candidate) => ({ field: candidate.field, values: candidate.values }))

    if (conflicts.length > 0) {
      const highSignalFields = new Set(['signature', 'ir_fact_hash', 'cfg_shape'])
      const severity = conflicts.some((conflict) => highSignalFields.has(conflict.field))
        ? 'high'
        : conflicts.length >= 2
          ? 'medium'
          : 'low'
      disagreements.push({
        key,
        backends,
        conflicts,
        severity,
        recommended_follow_up: uniqueStrings([
          'code.function.disassemble',
          'code.function.cfg',
          'analysis.evidence.graph',
          ...(severity === 'high' ? ['remill.lift.run', 'gtirb.ir.generate'] : []),
        ]),
      })
    }
  }

  const stableFacts = uniqueStrings(
    agreements.flatMap((agreement) => [
      agreement.addresses.length === 1 ? `stable_address:${agreement.addresses[0]}` : null,
      agreement.names.length === 1 ? `stable_name:${agreement.names[0]}` : null,
      agreement.signatures.length === 1 ? `stable_signature:${agreement.signatures[0]}` : null,
      agreement.ir_fact_hashes.length === 1 ? `stable_ir:${agreement.ir_fact_hashes[0]}` : null,
    ])
  )

  const denominator = Math.max(grouped.size, 1)
  const score = round(
    Math.max(
      0,
      Math.min(
        1,
        agreements.reduce((sum, agreement) => sum + agreement.confidence, 0) / denominator -
          disagreements.length * 0.05
      )
    )
  )

  return {
    grouped,
    backendsPresent,
    agreements,
    disagreements,
    stableFacts,
    score,
  }
}

function buildMissingBackendGaps(expectedBackends: string[], presentBackends: string[]) {
  const present = new Set(presentBackends)
  return uniqueStrings(expectedBackends.map(normalizeBackend))
    .filter((backend) => !present.has(backend))
    .map((backend) => ({
      backend,
      impact: `No ${backend} artifact was provided, so consensus cannot compare that backend's recovery view.`,
      recommended_tools: BACKEND_NEXT_TOOLS[backend] ?? [`${backend}.analyze`],
    }))
}

function buildBackendCoverage(
  input: CrossDecompilerConsensusInput,
  presentBackends: string[],
  missingBackendGaps: Array<{ backend: string; impact: string; recommended_tools: string[] }>
) {
  const expectedBackends = uniqueStrings(input.expected_backends.map(normalizeBackend))
  const expected = new Set(expectedBackends)
  const presentExpected = presentBackends.filter((backend) => expected.has(backend))
  const artifactsByBackend = presentBackends
    .map((backend) => {
      const artifacts = input.artifacts.filter(
        (artifact) => normalizeBackend(artifact.backend) === backend
      )
      return {
        backend,
        artifact_count: artifacts.length,
        function_fact_count: artifacts.reduce(
          (sum, artifact) => sum + artifact.functions.length,
          0
        ),
        artifact_types: uniqueStrings(artifacts.map((artifact) => artifact.artifact_type)),
        tool_names: uniqueStrings(artifacts.map((artifact) => artifact.tool_name)),
      }
    })
    .sort((left, right) => left.backend.localeCompare(right.backend))

  return {
    schema: 'rikune.cross_decompiler.backend_coverage.v1',
    expected_backends: expectedBackends,
    present_backends: presentBackends,
    missing_backends: missingBackendGaps.map((gap) => gap.backend),
    unexpected_backends: presentBackends.filter((backend) => !expected.has(backend)),
    coverage_score:
      expectedBackends.length > 0 ? round(presentExpected.length / expectedBackends.length) : 1,
    minimum_backend_count_met: presentBackends.length >= input.min_agreeing_backends,
    artifacts_by_backend: artifactsByBackend,
    coverage_gaps: missingBackendGaps,
  }
}

function buildEvidenceSummary(params: {
  input: CrossDecompilerConsensusInput
  agreements: ConsensusFunction[]
  disagreements: DisagreementFunction[]
  stableFacts: string[]
  groupedSize: number
  missingBackendGaps: Array<{ backend: string }>
  evidenceGraph?: ReturnType<typeof buildEvidenceGraph>
}) {
  return {
    schema: 'rikune.cross_decompiler.evidence_summary.v1',
    sample_id: params.input.sample_id ?? null,
    source_tool: TOOL_NAME,
    artifact_count: params.input.artifacts.length,
    backend_count: uniqueStrings(params.input.artifacts.map((artifact) => artifact.backend)).length,
    function_key_count: params.groupedSize,
    agreement_count: params.agreements.length,
    disagreement_count: params.disagreements.length,
    high_severity_disagreement_count: params.disagreements.filter(
      (disagreement) => disagreement.severity === 'high'
    ).length,
    stable_fact_count: params.stableFacts.length,
    missing_backend_count: params.missingBackendGaps.length,
    artifact_types: uniqueStrings(params.input.artifacts.map((artifact) => artifact.artifact_type)),
    graph_node_count: params.evidenceGraph?.nodes.length ?? 0,
    graph_edge_count: params.evidenceGraph?.edges.length ?? 0,
  }
}

function severityRank(value: DisagreementFunction['severity']): number {
  return { low: 1, medium: 2, high: 3 }[value]
}

function buildFunctionEvidenceHandoff(params: {
  agreements: ConsensusFunction[]
  disagreements: DisagreementFunction[]
  missingBackendGaps: Array<{ backend: string; recommended_tools: string[] }>
}) {
  const disagreementByKey = new Map(
    params.disagreements.map((disagreement) => [disagreement.key, disagreement])
  )
  const stableFunctions = params.agreements
    .filter((agreement) => !disagreementByKey.has(agreement.key))
    .sort((left, right) => right.confidence - left.confidence)
    .slice(0, 24)
    .map((agreement) => ({
      key: agreement.key,
      confidence: agreement.confidence,
      backends: agreement.backends,
      addresses: agreement.addresses,
      names: agreement.names,
      signatures: agreement.signatures,
      stable_facts: uniqueStrings([
        agreement.addresses.length === 1 ? `address:${agreement.addresses[0]}` : null,
        agreement.names.length === 1 ? `name:${agreement.names[0]}` : null,
        agreement.signatures.length === 1 ? `signature:${agreement.signatures[0]}` : null,
        agreement.ir_fact_hashes.length === 1 ? `ir:${agreement.ir_fact_hashes[0]}` : null,
      ]),
      recommended_tools: ['code.functions.reconstruct', 'code.function.explain.prepare'],
    }))

  const disputedFunctions = params.disagreements
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))
    .slice(0, 24)
    .map((disagreement) => ({
      key: disagreement.key,
      severity: disagreement.severity,
      backends: disagreement.backends,
      conflict_fields: disagreement.conflicts.map((conflict) => conflict.field),
      recommended_tools: disagreement.recommended_follow_up,
    }))

  return {
    schema: 'rikune.cross_decompiler.function_evidence_handoff.v1',
    handoff_mode: 'function_evidence_consensus',
    stable_functions: stableFunctions,
    disputed_functions: disputedFunctions,
    routing: [
      {
        goal: 'promote-stable-function-facts',
        priority: stableFunctions.length > 0 ? 'normal' : 'low',
        next_tools: ['code.functions.reconstruct', 'code.function.explain.prepare'],
        required_evidence: ['stable function identity', 'shared backend facts'],
      },
      {
        goal: 'resolve-decompiler-disagreements',
        priority: disputedFunctions.length > 0 ? 'high' : 'low',
        next_tools: ['code.function.disassemble', 'code.function.cfg', 'analysis.evidence.graph'],
        required_evidence: ['disagreement conflicts', 'backend provenance'],
      },
      {
        goal: 'fill-backend-coverage-gaps',
        priority: params.missingBackendGaps.length > 0 ? 'normal' : 'low',
        next_tools: uniqueStrings(
          params.missingBackendGaps.flatMap((gap) => gap.recommended_tools)
        ),
        required_evidence: ['missing backend list', 'expected backend policy'],
      },
    ],
    downstream_artifacts: [
      'analysis_evidence_graph',
      'function_reconstruction',
      'module_review_plan',
      'analysis_report',
    ],
  }
}

function buildQualityGates(params: {
  input: CrossDecompilerConsensusInput
  agreementCount: number
  disagreements: DisagreementFunction[]
  missingBackendGaps: Array<{ backend: string }>
  evidenceGraph?: ReturnType<typeof buildEvidenceGraph>
}) {
  return {
    passive_fixture_only: true,
    backend_process_started: false,
    sample_executed: false,
    network_accessed: false,
    mutation_performed: false,
    minimum_backend_count_met:
      uniqueStrings(params.input.artifacts.map((artifact) => artifact.backend)).length >=
      params.input.min_agreeing_backends,
    minimum_agreement_met: params.agreementCount > 0,
    expected_backend_coverage_met: params.missingBackendGaps.length === 0,
    evidence_graph_built: Boolean(params.evidenceGraph),
    analyst_review_required:
      params.disagreements.length > 0 || params.missingBackendGaps.length > 0,
    high_severity_disagreement_present: params.disagreements.some(
      (disagreement) => disagreement.severity === 'high'
    ),
  }
}

function buildEvidenceGraph(params: {
  grouped: Map<
    string,
    Array<{ backend: string; artifact: CrossDecompilerArtifact; fact: FunctionFact }>
  >
  agreements: z.infer<typeof ConsensusFunctionSchema>[]
  disagreements: z.infer<typeof DisagreementFunctionSchema>[]
}) {
  const nodes: Array<{ id: string; type: string; label: string }> = []
  const edges: Array<{ from: string; to: string; label: string; confidence: number }> = []
  const added = new Set<string>()

  function addNode(id: string, type: string, label: string) {
    if (added.has(id)) return
    nodes.push({ id, type, label })
    added.add(id)
  }

  addNode('consensus', 'workflow', 'Cross-decompiler consensus')
  for (const [key, records] of params.grouped.entries()) {
    addNode(key, 'function', key)
    edges.push({ from: 'consensus', to: key, label: 'correlates', confidence: 1 })
    for (const record of records) {
      const backendId = `backend:${record.backend}`
      addNode(backendId, 'backend', record.backend)
      edges.push({
        from: backendId,
        to: key,
        label: 'reported',
        confidence: round(record.fact.confidence ?? record.artifact.confidence ?? 0.5),
      })
    }
  }
  for (const agreement of params.agreements) {
    edges.push({
      from: agreement.key,
      to: 'consensus',
      label: 'agrees',
      confidence: agreement.confidence,
    })
  }
  for (const disagreement of params.disagreements) {
    edges.push({
      from: disagreement.key,
      to: 'consensus',
      label: `disagrees:${disagreement.severity}`,
      confidence: disagreement.severity === 'high' ? 0.9 : 0.6,
    })
  }

  return { nodes, edges }
}

export const crossDecompilerConsensusToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Compare fixture-safe outputs from multiple decompilers, disassemblers, and IR lifters to find stable facts, disagreements, backend coverage gaps, function evidence handoffs, and follow-up tools. Does not start external backends or execute samples.',
  inputSchema: CrossDecompilerConsensusInputSchema,
  outputSchema: CrossDecompilerConsensusOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib'],
    platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm32'],
    execution: ['static', 'decompilation', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'cross-decompiler-consensus',
      'cross-decompiler',
      'function-recovery-consensus',
      'decompile-consensus',
      'cfg-consensus',
      'xref-consensus',
      'ir-comparison',
      'decompiler-diffing',
      'evidence-correlation',
      'workflow-routing',
    ],
    evidence: [
      'functions',
      'function-recovery',
      'cfg',
      'xrefs',
      'symbols',
      'decompiled-code',
      'artifact',
      'workflow',
      'provenance',
    ],
  },
  artifacts: [
    {
      type: 'cross_decompiler_consensus',
      description: 'Consensus and disagreement report across decompiler/IR artifacts',
      mime: 'application/json',
    },
    {
      type: 'function_evidence_handoff',
      description:
        'Stable and disputed function facts routed to reconstruction, CFG, and reporting tools',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'functions', artifactTypes: ['cross_decompiler_consensus'] },
    { category: 'cfg', artifactTypes: ['cross_decompiler_consensus'] },
    { category: 'artifact', artifactTypes: ['cross_decompiler_consensus'] },
    { category: 'workflow', artifactTypes: ['cross_decompiler_consensus'] },
    { category: 'correlation-graph', artifactTypes: ['function_evidence_handoff'] },
    { category: 'provenance', artifactTypes: ['cross_decompiler_consensus'] },
  ],
  workflowRecipes: [
    {
      id: 'reverse.cross-decompiler.consensus',
      title: 'Cross-decompiler IR consensus',
      description:
        'Compare Ghidra, RetDec, Rizin/radare2, Angr, rev.ng, Remill, GTIRB, and bridge-imported artifacts before trusting recovered function semantics, decompile output, CFG shape, xref evidence, or source reconstruction.',
      startsWith: [
        'code.cross_decompiler.consensus',
        'ghidra.analyze',
        'retdec.decompile',
        'rizin.analyze',
      ],
      nextTools: [
        'ghidra.analyze',
        'retdec.decompile',
        'rizin.analyze',
        'radare2.pipeline.run',
        'remill.lift.run',
        'gtirb.ir.generate',
        'code.functions.reconstruct',
        'code.function.explain.prepare',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: [
        'ghidra_analysis',
        'backend_retdec_decompile_json-human',
        'backend_rizin_functions',
        'radare2_function_index',
        'gtirb_ir_artifact',
        'llvm_bitcode_lift_artifact',
      ],
      producesArtifacts: ['cross_decompiler_consensus', 'function_evidence_handoff'],
      evidence: [
        'functions',
        'cfg',
        'symbols',
        'artifact',
        'workflow',
        'correlation-graph',
        'provenance',
      ],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      runtimeBackends: ['ghidra', 'retdec', 'rizin', 'radare2', 'angr', 'revng', 'remill', 'gtirb'],
    },
  ],
  runtimePolicy: CODE_CROSS_DECOMPILER_CONSENSUS_RUNTIME_POLICY,
}

export function createCrossDecompilerConsensusHandler() {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = CrossDecompilerConsensusInputSchema.parse(args || {})
      const consensus = buildConsensus(input)
      const missingBackendGaps = buildMissingBackendGaps(
        input.expected_backends,
        consensus.backendsPresent
      )
      const evidenceGraph = input.include_evidence_graph
        ? buildEvidenceGraph({
            grouped: consensus.grouped,
            agreements: consensus.agreements,
            disagreements: consensus.disagreements,
          })
        : undefined
      const backendCoverage = buildBackendCoverage(
        input,
        consensus.backendsPresent,
        missingBackendGaps
      )
      const evidenceSummary = buildEvidenceSummary({
        input,
        agreements: consensus.agreements,
        disagreements: consensus.disagreements,
        stableFacts: consensus.stableFacts,
        groupedSize: consensus.grouped.size,
        missingBackendGaps,
        evidenceGraph,
      })
      const functionEvidenceHandoff = buildFunctionEvidenceHandoff({
        agreements: consensus.agreements,
        disagreements: consensus.disagreements,
        missingBackendGaps,
      })
      const qualityGates = buildQualityGates({
        input,
        agreementCount: consensus.agreements.length,
        disagreements: consensus.disagreements,
        missingBackendGaps,
        evidenceGraph,
      })
      const followUpRecommendations = uniqueStrings([
        ...(consensus.disagreements.length > 0
          ? ['code.function.disassemble', 'code.function.cfg']
          : []),
        ...(missingBackendGaps.length > 0
          ? missingBackendGaps.flatMap((gap) => gap.recommended_tools).slice(0, 8)
          : []),
        'analysis.evidence.graph',
      ])

      const data = {
        schema: 'rikune.cross_decompiler_consensus.v1' as const,
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id ?? null,
        execution_semantics: {
          actual_mode: 'static_fixture_consensus' as const,
          live_execution: false as const,
          backend_process_started: false as const,
          network_access: false as const,
          mutation: false as const,
        },
        policy: {
          passive: true as const,
          no_backend_start: true as const,
          no_live_sample_execution: true as const,
          no_network: true as const,
          read_only: true as const,
        },
        artifact_summary: {
          artifact_count: input.artifacts.length,
          backend_count: consensus.backendsPresent.length,
          backends_present: consensus.backendsPresent,
          expected_backends: uniqueStrings(input.expected_backends.map(normalizeBackend)),
        },
        agreement: {
          score: consensus.score,
          functions: consensus.agreements,
          stable_facts: consensus.stableFacts,
        },
        disagreement: {
          count: consensus.disagreements.length,
          functions: consensus.disagreements,
        },
        missing_backend_gaps: missingBackendGaps,
        backend_coverage: backendCoverage,
        evidence_summary: evidenceSummary,
        function_evidence_handoff: functionEvidenceHandoff,
        evidence_graph: evidenceGraph,
        quality_gates: qualityGates,
        follow_up_recommendations: followUpRecommendations,
      }

      return {
        ok: true,
        data,
        warnings:
          missingBackendGaps.length > 0
            ? [`Missing ${missingBackendGaps.length} expected backend artifact(s).`]
            : undefined,
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
