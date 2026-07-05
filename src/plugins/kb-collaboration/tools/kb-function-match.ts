/**
 * kb.function.match MCP tool — Match function signatures across samples
 * to find reused code, shared libraries, and known function patterns.
 * Leverages the knowledge base to propagate names/annotations.
 */

import { z } from 'zod'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
  type ArtifactRef,
  type PluginToolDeps,
} from '../../sdk.js'

const TOOL_NAME = 'kb.function.match'
export const KB_FUNCTION_MATCH_ARTIFACT_TYPE = 'function_match'
export const KB_FUNCTION_MATCH_FORMATS = [
  'artifact',
  'analysis-evidence',
  'function',
  'function-index',
  'function-signature',
  'code-reuse',
  'knowledge-base',
  'rule',
]
export const KB_COLLABORATION_PLATFORMS = ['cross-platform']
export const KB_COLLABORATION_SAFETY = [
  'passive',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
]
export const KB_FUNCTION_MATCH_CAPABILITIES = [
  'analysis-memory',
  'knowledge-reuse',
  'function-matching',
  'function-signature-correlation',
  'code-reuse-detection',
  'annotation-propagation',
  'workflow-plan',
  'workflow-handoff',
  'search-profile',
  'evidence-correlation',
]
export const KB_FUNCTION_MATCH_EVIDENCE = [
  'analysis-memory',
  'functions',
  'symbols',
  'api-calls',
  'code-reuse',
  'workflow',
  'provenance',
  'search-profile',
]
export const KB_FUNCTION_MATCH_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'analysis.evidence.graph',
  'analysis.notes',
  'rule.library',
  'kb.context.suggest',
  'kb.export',
  'report.generate',
]
export const KB_FUNCTION_MATCH_WORKFLOW_RECIPES = [
  {
    id: 'kb.function-match.reuse-handoff',
    title: 'Knowledge-base function reuse handoff',
    description:
      'Compare function signatures against curated local sample evidence, surface exact and high-confidence reuse, and hand off annotation, evidence-graph, notes, and export follow-ups without network access or sample execution.',
    startsWith: [TOOL_NAME],
    nextTools: KB_FUNCTION_MATCH_FOLLOW_UP_TOOLS,
    requiredArtifacts: ['sample', 'analysis_evidence', 'function_index'],
    producesArtifacts: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
    evidence: KB_FUNCTION_MATCH_EVIDENCE,
    safety: KB_COLLABORATION_SAFETY,
    runtimeBackends: ['local'],
  },
]
export const KB_COLLABORATION_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noSampleExecution: true,
  notes: [
    'Knowledge-base collaboration uses local database evidence and workspace artifacts only.',
    'Function matching does not execute samples, mutate binaries, or use network access.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noSampleExecution: true
}

export const KbFunctionMatchInputSchema = z.object({
  sample_id: z.string().describe('Target sample ID to match functions for'),
  match_against: z
    .array(z.string())
    .optional()
    .describe('Specific sample IDs to match against (or all KB entries if omitted)'),
  min_confidence: z
    .number()
    .optional()
    .default(0.7)
    .describe('Minimum similarity score to report a match (0.0-1.0)'),
  max_matches: z.number().optional().default(100).describe('Maximum matches to return'),
})

export const KbFunctionMatchOutputSchema = createWorkerResultOutputSchema(
  z.object({
    sample_id: z.string(),
    target_function_count: z.number().int().nonnegative(),
    reference_function_count: z.number().int().nonnegative(),
    match_count: z.number().int().nonnegative(),
    exact_matches: z.number().int().nonnegative(),
    high_confidence_matches: z.number().int().nonnegative(),
    workflowRecipes: z.array(z.any()).optional(),
    formats: z.array(z.string()).optional(),
    evidence: z.array(z.string()).optional(),
    policy: z.record(z.any()).optional(),
    evidence_summary: z.record(z.any()).optional(),
    workflow_handoff: z.record(z.any()).optional(),
    quality_gates: z.record(z.any()).optional(),
    recommended_next_tools: z.array(z.string()).optional(),
    next_actions: z.array(z.string()).optional(),
    matches: z.array(
      z.object({
        target_function: z.string(),
        target_address: z.string(),
        matched_function: z.string(),
        matched_sample_id: z.string(),
        matched_address: z.string(),
        confidence: z.number(),
      })
    ),
  })
)

export const kbFunctionMatchToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Match function signatures from a sample against the knowledge base and other ' +
    'analyzed samples. Uses byte-pattern hashing and API-call fingerprinting to ' +
    'find reused code and propagate function names and annotations.',
  inputSchema: KbFunctionMatchInputSchema,
  outputSchema: KbFunctionMatchOutputSchema,
  aspects: {
    formats: KB_FUNCTION_MATCH_FORMATS,
    platforms: KB_COLLABORATION_PLATFORMS,
    execution: ['static', 'correlation'],
    safety: KB_COLLABORATION_SAFETY,
    capabilities: KB_FUNCTION_MATCH_CAPABILITIES,
    evidence: KB_FUNCTION_MATCH_EVIDENCE,
  },
  artifacts: [
    {
      type: KB_FUNCTION_MATCH_ARTIFACT_TYPE,
      description:
        'Function signature reuse, exact/high-confidence matches, and analysis-memory handoff',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'analysis-memory', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'functions', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'api-calls', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'code-reuse', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE] },
  ],
  workflowRecipes: KB_FUNCTION_MATCH_WORKFLOW_RECIPES,
  runtimePolicy: KB_COLLABORATION_RUNTIME_POLICY,
}

interface FunctionSig {
  sample_id: string
  address: string
  name: string
  hash?: string
  size?: number
  api_calls?: string[]
}

export interface FunctionMatchEntry {
  target_function: string
  target_address: string
  matched_function: string
  matched_sample_id: string
  matched_address: string
  confidence: number
}

function signatureOverlap(a: FunctionSig, b: FunctionSig): number {
  // Hash match = high confidence
  if (a.hash && b.hash && a.hash === b.hash) return 1.0

  // API call overlap
  if (a.api_calls?.length && b.api_calls?.length) {
    const setA = new Set(a.api_calls)
    const setB = new Set(b.api_calls)
    const intersection = [...setA].filter((x) => setB.has(x))
    const union = new Set([...setA, ...setB])
    const jaccard = union.size > 0 ? intersection.length / union.size : 0

    // Size similarity bonus
    let sizeBonus = 0
    if (a.size && b.size) {
      const ratio = Math.min(a.size, b.size) / Math.max(a.size, b.size)
      sizeBonus = ratio * 0.2
    }

    return Math.min(1.0, jaccard * 0.8 + sizeBonus)
  }

  // Size-only comparison (weak)
  if (a.size && b.size) {
    const ratio = Math.min(a.size, b.size) / Math.max(a.size, b.size)
    return ratio > 0.95 ? 0.5 : 0
  }

  return 0
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function buildRecommendedNextTools(input: {
  exact_matches: number
  high_confidence_matches: number
  match_count: number
}): string[] {
  return uniqueStrings([
    'artifact.read',
    'kb.context.suggest',
    'analysis.notes',
    ...(input.match_count > 0 ? ['analysis.evidence.graph', 'report.generate'] : []),
    ...(input.exact_matches > 0 || input.high_confidence_matches > 0
      ? ['rule.library', 'kb.export']
      : []),
  ])
}

export function enrichKbFunctionMatchResultData(resultData: {
  sample_id: string
  target_function_count: number
  reference_function_count: number
  match_count: number
  exact_matches: number
  high_confidence_matches: number
  matches: FunctionMatchEntry[]
  min_confidence?: number
  match_against?: string[]
}) {
  const recommendedNextTools = buildRecommendedNextTools(resultData)
  const matchAgainst = resultData.match_against ?? []

  return {
    sample_id: resultData.sample_id,
    target_function_count: resultData.target_function_count,
    reference_function_count: resultData.reference_function_count,
    match_count: resultData.match_count,
    exact_matches: resultData.exact_matches,
    high_confidence_matches: resultData.high_confidence_matches,
    workflowRecipes: KB_FUNCTION_MATCH_WORKFLOW_RECIPES,
    formats: KB_FUNCTION_MATCH_FORMATS,
    evidence: KB_FUNCTION_MATCH_EVIDENCE,
    policy: {
      passive: true,
      no_execute: true,
      no_network: true,
      no_mutation: true,
      no_sample_execution: true,
      no_live_sample: true,
    },
    evidence_summary: {
      schema: 'rikune.kb_function_match.evidence_summary.v1',
      source_tool: TOOL_NAME,
      artifact_type: KB_FUNCTION_MATCH_ARTIFACT_TYPE,
      sample_id: resultData.sample_id,
      evidence_categories: KB_FUNCTION_MATCH_EVIDENCE,
      function_counts: {
        target_functions: resultData.target_function_count,
        reference_functions: resultData.reference_function_count,
        matches: resultData.match_count,
        exact_matches: resultData.exact_matches,
        high_confidence_matches: resultData.high_confidence_matches,
      },
      match_scope: {
        match_against: matchAgainst,
        all_kb_entries_requested: matchAgainst.length === 0,
        min_confidence: resultData.min_confidence ?? null,
      },
      static_only: true,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
    workflow_handoff: {
      schema: 'rikune.kb_function_match.workflow_handoff.v1',
      handoff_mode: 'function_reuse_to_analysis_memory_and_evidence_graph',
      artifact_type: KB_FUNCTION_MATCH_ARTIFACT_TYPE,
      recommended_next_tools: recommendedNextTools,
      artifact_contract: {
        consumes: ['analysis_evidence', 'function_index'],
        produces: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
        expected_consumers: [
          'workflow.search',
          'artifact.read',
          'kb.context.suggest',
          'analysis.evidence.graph',
          'report.generate',
        ],
      },
      routing: [
        {
          goal: 'exact-and-high-confidence-function-reuse',
          priority:
            resultData.exact_matches > 0 || resultData.high_confidence_matches > 0
              ? 'high'
              : 'conditional',
          next_tools: ['analysis.evidence.graph', 'analysis.notes', 'rule.library'],
          required_evidence: ['function signatures', 'matched sample IDs', 'confidence scores'],
          consumes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          produces: ['function_reuse_evidence'],
        },
        {
          goal: 'analysis-memory-context-refresh',
          priority: 'normal',
          next_tools: ['kb.context.suggest', 'analysis.notes', 'kb.export'],
          required_evidence: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          consumes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          produces: ['analysis_memory'],
        },
        {
          goal: 'evidence-graph-and-reporting',
          priority: resultData.match_count > 0 ? 'normal' : 'low',
          next_tools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          consumes: [KB_FUNCTION_MATCH_ARTIFACT_TYPE],
          produces: ['evidence_graph', 'analysis_report'],
        },
      ],
      dynamic_boundary: {
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        binary_modified_by_tool: false,
      },
    },
    quality_gates: {
      schema: 'rikune.kb_function_match.quality_gates.v1',
      passive_local_kb_match: true,
      target_functions_present: resultData.target_function_count > 0,
      reference_functions_present: resultData.reference_function_count > 0,
      matches_present: resultData.match_count > 0,
      exact_or_high_confidence_matches_present:
        resultData.exact_matches > 0 || resultData.high_confidence_matches > 0,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
      binary_modified_by_tool: false,
    },
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review exact and high-confidence matches before propagating names or annotations.',
      'Publish function reuse evidence to analysis.evidence.graph when matches are present.',
      'Capture reusable analyst notes before exporting curated knowledge.',
    ],
    matches: resultData.matches,
  }
}

export function createKbFunctionMatchHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, persistStaticAnalysisJsonArtifact } = deps

  return async (args: z.infer<typeof KbFunctionMatchInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }

      // Collect functions from target sample
      const targetFunctions: FunctionSig[] = []
      const targetEvidence = database.findAnalysisEvidenceBySample(args.sample_id)
      if (Array.isArray(targetEvidence)) {
        for (const entry of targetEvidence) {
          try {
            const data =
              typeof entry.result_json === 'string'
                ? JSON.parse(entry.result_json)
                : entry.result_json
            const family = entry.evidence_family ?? ''

            if (
              family === 'function_index' ||
              family === 'function_list' ||
              family === 'ghidra_functions'
            ) {
              const funcs = data?.data?.functions ?? data?.functions ?? []
              for (const f of funcs) {
                targetFunctions.push({
                  sample_id: args.sample_id,
                  address: f.address ?? f.entry ?? f.offset ?? '0x0',
                  name: f.name ?? `sub_${f.address ?? 'unknown'}`,
                  hash: f.hash ?? f.byte_hash,
                  size: f.size ?? f.length,
                  api_calls: f.api_calls ?? f.imports ?? f.calls,
                })
              }
            }
          } catch {
            /* skip */
          }
        }
      }

      if (targetFunctions.length === 0) {
        return {
          ok: false,
          errors: ['No function data found for target sample. Run function analysis first.'],
        }
      }

      // Collect reference functions from other samples
      const referenceFunctions: FunctionSig[] = []
      const matchSampleIds = args.match_against ?? []

      // If no specific samples, search all KB entries
      if (matchSampleIds.length === 0) {
        warnings.push('No match_against samples provided; specify sample IDs to match against')
      }

      // Also gather from specified sample IDs
      for (const sid of matchSampleIds) {
        if (sid === args.sample_id) continue
        const evidence = database.findAnalysisEvidenceBySample(sid)
        if (Array.isArray(evidence)) {
          for (const entry of evidence) {
            try {
              const data =
                typeof entry.result_json === 'string'
                  ? JSON.parse(entry.result_json)
                  : entry.result_json
              const family = entry.evidence_family ?? ''

              if (
                family === 'function_index' ||
                family === 'function_list' ||
                family === 'ghidra_functions'
              ) {
                const funcs = data?.data?.functions ?? data?.functions ?? []
                for (const f of funcs) {
                  referenceFunctions.push({
                    sample_id: sid,
                    address: f.address ?? f.entry ?? '0x0',
                    name: f.name ?? `sub_${f.address ?? 'unknown'}`,
                    hash: f.hash ?? f.byte_hash,
                    size: f.size ?? f.length,
                    api_calls: f.api_calls ?? f.imports ?? f.calls,
                  })
                }
              }
            } catch {
              /* skip */
            }
          }
        }
      }

      if (referenceFunctions.length === 0) {
        warnings.push(
          'No reference functions found. Provide match_against sample IDs or build KB first.'
        )
      }

      // Match functions
      const matches: FunctionMatchEntry[] = []
      for (const target of targetFunctions) {
        let bestMatch: FunctionMatchEntry | null = null
        let bestScore = 0

        for (const ref of referenceFunctions) {
          const score = signatureOverlap(target, ref)
          if (score >= args.min_confidence && score > bestScore) {
            bestScore = score
            bestMatch = {
              target_function: target.name,
              target_address: target.address,
              matched_function: ref.name,
              matched_sample_id: ref.sample_id,
              matched_address: ref.address,
              confidence: Math.round(score * 1000) / 1000,
            }
          }
        }

        if (bestMatch) matches.push(bestMatch)
      }

      matches.sort((a, b) => b.confidence - a.confidence)
      const topMatches = matches.slice(0, args.max_matches)

      const resultData = enrichKbFunctionMatchResultData({
        sample_id: args.sample_id,
        target_function_count: targetFunctions.length,
        reference_function_count: referenceFunctions.length,
        match_count: topMatches.length,
        exact_matches: topMatches.filter((m) => m.confidence >= 0.99).length,
        high_confidence_matches: topMatches.filter(
          (m) => m.confidence >= 0.8 && m.confidence < 0.99
        ).length,
        min_confidence: args.min_confidence,
        match_against: args.match_against ?? [],
        matches: topMatches,
      })

      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          KB_FUNCTION_MATCH_ARTIFACT_TYPE,
          'kb-function-match',
          resultData
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        /* non-fatal */
      }

      return {
        ok: true,
        data: resultData,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
