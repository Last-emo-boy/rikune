/**
 * YARA-X scan tool — scan a sample with YARA-X rules.
 */

import { createHash } from 'crypto'
import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import type { SharedBackendDependencies } from './docker-shared.js'
import {
  fs,
  ArtifactRefSchema, BackendSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson,
  persistBackendArtifact, buildMetrics, buildStaticSetupRequired,
  findBackendPreviewEvidence, persistBackendPreviewEvidence, buildEvidenceReuseWarnings,
  resolveSampleFile, resolveAnalysisBackends,
} from './docker-shared.js'

export const yaraXScanInputSchema = z
  .object({
    sample_id: z.string().describe('Target sample identifier.'),
    rules_text: z.string().optional().describe('Inline YARA-X source text.'),
    rules_path: z.string().optional().describe('Absolute path to a YARA or YARA-X rules file.'),
    timeout_sec: z.number().int().min(1).max(180).default(30).describe('YARA-X scan timeout in seconds.'),
    max_matches_per_pattern: z
      .number()
      .int()
      .min(1)
      .max(5000)
      .default(250)
      .describe('Maximum matches per pattern for the scanner.'),
    persist_artifact: z.boolean().default(true).describe('Persist the JSON scan result as an artifact.'),
    session_tag: z.string().optional().describe('Optional artifact session tag.'),
  })
  .superRefine((data, ctx) => {
    if (!data.rules_text && !data.rules_path) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['rules_text'],
        message: 'Either rules_text or rules_path must be provided',
      })
    }
  })

export const yaraXScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      match_count: z.number().int().nonnegative().optional(),
      matches: z.array(z.any()).optional(),
      module_outputs: z.record(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const yaraXScanToolDefinition: ToolDefinition = {
  name: 'yara_x.scan',
  description:
    'Scan a sample with YARA-X using inline rules or a rules file. Use this when you explicitly want the newer YARA-X engine instead of the legacy yara.scan path.',
  inputSchema: yaraXScanInputSchema,
  outputSchema: yaraXScanOutputSchema,
}

const YARAX_SCAN_SCRIPT = `
import json
import pathlib
import sys
import yara_x

payload = json.loads(sys.stdin.read())
sample_path = payload["sample_path"]
rules_text = payload.get("rules_text")
rules_path = payload.get("rules_path")
max_matches = int(payload.get("max_matches_per_pattern", 250))
timeout_sec = int(payload.get("timeout_sec", 30))

if not rules_text and rules_path:
    rules_text = pathlib.Path(rules_path).read_text(encoding="utf-8")

rules = yara_x.compile(rules_text)
scanner = yara_x.Scanner(rules)
scanner.set_timeout(timeout_sec)
scanner.max_matches_per_pattern(max_matches)

data = pathlib.Path(sample_path).read_bytes()
results = scanner.scan(data)

matching_rules = []
for rule in getattr(results, "matching_rules", []):
    patterns = []
    for pattern in getattr(rule, "patterns", []):
        matches = []
        for match in getattr(pattern, "matches", []):
            matches.append({
                "offset": int(getattr(match, "offset", 0)),
                "length": int(getattr(match, "length", 0)),
            })
        patterns.append({
            "identifier": getattr(pattern, "identifier", ""),
            "matches": matches,
        })
    matching_rules.append({
        "identifier": getattr(rule, "identifier", ""),
        "namespace": getattr(rule, "namespace", ""),
        "patterns": patterns,
    })

print(json.dumps({
    "match_count": len(matching_rules),
    "matching_rules": matching_rules,
    "module_outputs": getattr(results, "module_outputs", {}) or {},
}, ensure_ascii=False))
`.trim()

export function createYaraXScanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = yaraXScanInputSchema.parse(args)
      const sample = ensureSampleExists(database, input.sample_id)
      let rulesDigest: string | null = null
      if (input.rules_text) {
        rulesDigest = createHash('sha256').update(input.rules_text).digest('hex')
      } else if (input.rules_path) {
        try {
          const rulesContent = await fs.readFile(input.rules_path, 'utf8')
          rulesDigest = createHash('sha256').update(rulesContent).digest('hex')
        } catch {
          rulesDigest = createHash('sha256').update(input.rules_path).digest('hex')
        }
      }
      const evidenceArgs = {
        rules_digest: rulesDigest,
        max_matches_per_pattern: input.max_matches_per_pattern,
      }
      const reused = findBackendPreviewEvidence(
        database,
        sample,
        'yara_x',
        'scan',
        evidenceArgs
      )
      if (reused) {
        return {
          ok: true,
          data: reused.result as Record<string, unknown>,
          warnings: buildEvidenceReuseWarnings({
            source: 'analysis_evidence',
            record: reused,
          }),
          artifacts: reused.artifact_refs,
          metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
        }
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.yara_x
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, yaraXScanToolDefinition.name)
      }

      const runPythonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonImpl(
        backend.path,
        YARAX_SCAN_SCRIPT,
        {
          sample_path: samplePath,
          rules_text: input.rules_text,
          rules_path: input.rules_path,
          max_matches_per_pattern: input.max_matches_per_pattern,
          timeout_sec: input.timeout_sec,
        },
        input.timeout_sec * 1000 + 5000
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'yara_x',
          'scan',
          JSON.stringify(result.parsed, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      const matchingRules = Array.isArray(result.parsed?.matching_rules) ? result.parsed.matching_rules : []
      const outputData = {
        status: 'ready',
        backend,
        sample_id: input.sample_id,
        match_count: Number(result.parsed?.match_count || matchingRules.length || 0),
        matches: matchingRules.slice(0, 25),
        module_outputs: result.parsed?.module_outputs || {},
        artifact,
        summary: `YARA-X scanned ${input.sample_id} and produced ${matchingRules.length} matching rule(s).`,
        recommended_next_tools: ['artifact.read', 'yara.scan', 'workflow.analyze.start'],
        next_actions: [
          'Use artifact.read for the full rule match payload when you need all pattern offsets.',
          'Compare with yara.scan if you want legacy-rule behavior, then continue with workflow.analyze.start or workflow.analyze.promote instead of restarting older synchronous facades.',
        ],
      } satisfies Record<string, unknown>

      persistBackendPreviewEvidence(
        database,
        sample,
        'yara_x',
        'scan',
        evidenceArgs,
        outputData,
        artifacts,
        {
          backend_version: backend.version,
          rules_path: input.rules_path || null,
        }
      )

      return {
        ok: true,
        data: outputData,
        artifacts,
        metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, yaraXScanToolDefinition.name),
      }
    }
  }
}
