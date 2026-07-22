/**
 * Artifact families that may inform analyst context but must never be promoted
 * to primary or derived Claim evidence.
 *
 * Keep this policy centralized so Claim validation and report lineage apply the
 * same trust boundary. Do not classify every `*_report` artifact as context:
 * deterministic analyzer outputs such as `strings_report` may still be valid
 * evidence.
 */
const CONTEXT_ONLY_ARTIFACT_TYPES: ReadonlySet<string> = new Set([
  'analysis_claim_set',
  'analysis_case_state',
  'workflow_summary',
  'summary_triage_digest',
  'summary_static_digest',
  'summary_deep_digest',
  'summary_final_digest',
  'report_summary',
  'analysis_report',
  'html_report',
  'report',
])

export function isContextOnlyArtifactType(artifactType: string): boolean {
  const normalized = artifactType.trim().toLowerCase()
  return CONTEXT_ONLY_ARTIFACT_TYPES.has(normalized) || normalized.startsWith('report_')
}
