import { z } from 'zod'
import {
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
  type PluginToolDeps,
} from '../../sdk.js'
import { KB_COLLABORATION_RUNTIME_POLICY } from './kb-function-match.js'

const TOOL_NAME = 'kb.context.suggest'

export const KbContextSuggestInputSchema = z.object({
  sample_id: z.string().describe('Sample ID to build reusable analysis-memory context for'),
  goal: z.string().optional().describe('Optional analyst goal or workflow focus'),
  evidence_tags: z.array(z.string()).optional().default([]),
  max_recommendations: z.number().int().min(1).max(50).optional().default(12),
})

export const KbContextSuggestOutputSchema = createWorkerResultOutputSchema(
  z.object({
    result_mode: z.literal('kb_context_suggest'),
    sample_id: z.string(),
    analysis_memory: z.record(z.string(), z.any()),
    recommendations: z.array(z.record(z.string(), z.any())),
    provenance: z.array(z.record(z.string(), z.any())),
    recommended_next_tools: z.array(z.string()),
  })
)

export const kbContextSuggestToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Suggest local analysis-memory context for a sample: reusable function knowledge, notes, rule-library actions, and import/export follow-ups based on existing evidence tags. No network access is performed.',
  inputSchema: KbContextSuggestInputSchema,
  outputSchema: KbContextSuggestOutputSchema,
  aspects: {
    formats: ['artifact', 'analysis-evidence', 'function', 'rule'],
    platforms: ['cross-platform'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['analysis-memory', 'knowledge-reuse', 'workflow-recommendation'],
    evidence: ['analysis-memory', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'analysis_memory',
      description: 'Reusable local analysis-memory recommendations',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'analysis-memory', artifactTypes: ['analysis_memory'] },
    { category: 'workflow', artifactTypes: ['analysis_memory'] },
    { category: 'provenance', artifactTypes: ['analysis_memory'] },
  ],
  workflowRecipes: [
    {
      id: 'kb.analysis-memory.reuse',
      title: 'Analysis memory reuse',
      startsWith: ['kb.context.suggest', 'analysis.notes'],
      nextTools: ['kb.function.match', 'analysis.notes', 'rule.library', 'kb.export'],
      requiredArtifacts: ['analysis_evidence'],
      producesArtifacts: ['analysis_memory'],
      evidence: ['analysis-memory', 'workflow', 'provenance'],
      safety: ['passive', 'no_network_by_default'],
      runtimeBackends: ['local'],
    },
  ],
  runtimePolicy: KB_COLLABORATION_RUNTIME_POLICY,
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function safeArray<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : []
}

export function createKbContextSuggestHandler(deps: PluginToolDeps) {
  const { database } = deps

  return async (args: z.infer<typeof KbContextSuggestInputSchema>): Promise<WorkerResult> => {
    const input = KbContextSuggestInputSchema.parse(args)
    const sample = database.findSample?.(input.sample_id)
    if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }

    const evidence = safeArray<Record<string, unknown>>(
      database.findAnalysisEvidenceBySample?.(input.sample_id)
    )
    const artifacts = safeArray<Record<string, unknown>>(database.listArtifacts?.(input.sample_id))
    const evidenceFamilies = uniqueStrings(
      evidence.map((entry) => String(entry.evidence_family ?? '')).filter(Boolean)
    )
    const artifactTypes = uniqueStrings(
      artifacts.map((artifact) => String(artifact.type ?? '')).filter(Boolean)
    )
    const tags = uniqueStrings([...input.evidence_tags, ...evidenceFamilies, ...artifactTypes])

    const recommendations = [
      {
        tool: 'kb.function.match',
        reason: 'Compare current function evidence against known local samples.',
        confidence: tags.some((tag) => /function|ghidra|decomp/i.test(tag)) ? 0.9 : 0.65,
      },
      {
        tool: 'analysis.notes',
        reason: 'Capture analyst findings, hypotheses, verdicts, and reusable tags.',
        confidence: 0.8,
      },
      {
        tool: 'rule.library',
        reason: 'Review generated YARA/Sigma artifacts and attach status labels.',
        confidence: tags.some((tag) => /yara|sigma|rule/i.test(tag)) ? 0.9 : 0.55,
      },
      {
        tool: 'kb.export',
        reason: 'Export curated local knowledge for reuse after review.',
        confidence: 0.6,
      },
    ]
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, input.max_recommendations)

    return {
      ok: true,
      data: {
        result_mode: 'kb_context_suggest',
        sample_id: input.sample_id,
        analysis_memory: {
          goal: input.goal ?? null,
          evidence_tags: tags,
          evidence_count: evidence.length,
          artifact_count: artifacts.length,
          stale_data_caveat:
            'Suggestions are based on local evidence and artifacts only; refresh sample analyses if the workspace changed.',
        },
        recommendations,
        provenance: [
          ...evidenceFamilies.map((family) => ({ source: 'analysis_evidence', family })),
          ...artifactTypes.map((type) => ({ source: 'artifact', type })),
        ],
        recommended_next_tools: recommendations.map((item) => item.tool),
      },
      metrics: { elapsed_ms: 0, tool: TOOL_NAME },
    }
  }
}
