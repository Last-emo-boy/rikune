import { z } from 'zod'
import { ArtifactSelectionProvenanceSchema } from './analysis-provenance.js'

export const ArtifactSelectionDiffSchema = z.object({
  label: z.enum(['runtime', 'semantic_names', 'semantic_explanations']),
  current: ArtifactSelectionProvenanceSchema,
  baseline: ArtifactSelectionProvenanceSchema,
  added_artifact_ids: z.array(z.string()),
  removed_artifact_ids: z.array(z.string()),
  added_session_tags: z.array(z.string()),
  removed_session_tags: z.array(z.string()),
  artifact_count_delta: z.number().int(),
  summary: z.string(),
})

export const AnalysisSelectionDiffSchema = z.object({
  runtime: ArtifactSelectionDiffSchema.optional(),
  semantic_names: ArtifactSelectionDiffSchema.optional(),
  semantic_explanations: ArtifactSelectionDiffSchema.optional(),
})

export type ArtifactSelectionDiff = z.infer<typeof ArtifactSelectionDiffSchema>

function diffStrings(current: string[], baseline: string[]) {
  const currentSet = new Set(current)
  const baselineSet = new Set(baseline)
  return {
    added: current.filter((item) => !baselineSet.has(item)),
    removed: baseline.filter((item) => !currentSet.has(item)),
  }
}

export function buildArtifactSelectionDiff(
  label: 'runtime' | 'semantic_names' | 'semantic_explanations',
  current: z.infer<typeof ArtifactSelectionProvenanceSchema>,
  baseline: z.infer<typeof ArtifactSelectionProvenanceSchema>
): ArtifactSelectionDiff {
  const artifactDiff = diffStrings(current.artifact_ids, baseline.artifact_ids)
  const sessionDiff = diffStrings(current.session_tags, baseline.session_tags)
  const artifactCountDelta = current.artifact_count - baseline.artifact_count
  const targetLabel =
    label === 'runtime'
      ? 'runtime selection'
      : label === 'semantic_names'
        ? 'semantic naming selection'
        : 'semantic explanation selection'
  const summary =
    `Compared ${targetLabel} against baseline scope=${baseline.scope}` +
    `${baseline.session_selector ? ` selector=${baseline.session_selector}` : ''}: ` +
    `artifact_delta=${artifactCountDelta >= 0 ? '+' : ''}${artifactCountDelta}, ` +
    `added=${artifactDiff.added.length}, removed=${artifactDiff.removed.length}, ` +
    `session_tag_delta=${sessionDiff.added.length}/${sessionDiff.removed.length}.`

  return {
    label,
    current,
    baseline,
    added_artifact_ids: artifactDiff.added,
    removed_artifact_ids: artifactDiff.removed,
    added_session_tags: sessionDiff.added,
    removed_session_tags: sessionDiff.removed,
    artifact_count_delta: artifactCountDelta,
    summary,
  }
}
