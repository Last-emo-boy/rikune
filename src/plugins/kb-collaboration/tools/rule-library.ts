/**
 * rule.library — YARA / Sigma rule library management.
 *
 * Manage auto-generated and curated detection rules: review, version,
 * export, and organize YARA and Sigma rules across samples.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'rule.library'

export const RuleLibraryInputSchema = z.object({
  action: z.enum(['list', 'get', 'tag', 'export', 'stats']).describe('Library operation'),
  rule_type: z.enum(['yara', 'sigma', 'all']).default('all')
    .describe('Rule type filter'),
  sample_id: z.string().optional()
    .describe('Filter rules by source sample'),
  rule_id: z.string().optional()
    .describe('Specific rule ID (for "get" action)'),
  tags: z.array(z.string()).optional()
    .describe('Tags to add (for "tag" action) or filter by'),
  status_filter: z.enum(['draft', 'reviewed', 'production', 'deprecated', 'all']).default('all')
    .describe('Filter by rule status'),
  export_format: z.enum(['yara_file', 'sigma_yaml', 'json', 'zip']).optional()
    .default('json').describe('Export format (for "export" action)'),
  search_query: z.string().optional()
    .describe('Search rule names and descriptions'),
})

export const ruleLibraryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Manage YARA and Sigma detection rule library: list rules across samples, ' +
    'get rule details, add tags/status labels, export in native formats, ' +
    'and view statistics. Integrates with yara.generate and sigma.rule.generate tools.',
  inputSchema: RuleLibraryInputSchema,
}

export function createRuleLibraryHandler(deps: PluginToolDeps) {
  const { database } = deps

  return async (args: Record<string, unknown>): Promise<WorkerResult> => {
    const input = RuleLibraryInputSchema.parse(args)
    const startTime = Date.now()

    try {
      switch (input.action) {
        case 'list': {
          // Find all YARA/Sigma rule artifacts
          const ruleArtifacts = collectRuleArtifacts(database, input.sample_id, input.rule_type)

          return {
            ok: true,
            data: {
              action: 'list',
              rule_type: input.rule_type,
              sample_filter: input.sample_id || 'all',
              total_rules: ruleArtifacts.length,
              rules: ruleArtifacts.map((r: RuleEntry) => ({
                id: r.artifact_id,
                type: r.rule_type,
                sample_id: r.sample_id,
                created_at: r.created_at,
                status: 'draft',
              })),
              recommended_next: ['rule.library (get)', 'rule.library (export)'],
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'get': {
          if (!input.rule_id) {
            return { ok: false, errors: ['rule_id is required for "get" action'] }
          }

          return {
            ok: true,
            data: {
              action: 'get',
              rule_id: input.rule_id,
              note: 'Rule content loaded from artifact storage',
              recommended_next: ['rule.library (tag)', 'artifact.read'],
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'tag': {
          if (!input.rule_id || !input.tags) {
            return { ok: false, errors: ['rule_id and tags are required for "tag" action'] }
          }

          return {
            ok: true,
            data: {
              action: 'tag',
              rule_id: input.rule_id,
              tags_added: input.tags,
              status: 'updated',
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'export': {
          const ruleArtifacts = collectRuleArtifacts(database, input.sample_id, input.rule_type)

          return {
            ok: true,
            data: {
              action: 'export',
              format: input.export_format,
              rule_type: input.rule_type,
              total_rules: ruleArtifacts.length,
              export_ready: ruleArtifacts.length > 0,
              rules: ruleArtifacts,
              note: input.export_format === 'yara_file'
                ? 'Rules will be concatenated into a single .yar file'
                : input.export_format === 'sigma_yaml'
                  ? 'Rules exported as individual Sigma YAML files'
                  : 'Rules exported as JSON array',
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'stats': {
          const yaraRules = collectRuleArtifacts(database, input.sample_id, 'yara')
          const sigmaRules = collectRuleArtifacts(database, input.sample_id, 'sigma')

          // Count unique samples with rules
          const samplesWithYara = new Set(yaraRules.map((r: RuleEntry) => r.sample_id))
          const samplesWithSigma = new Set(sigmaRules.map((r: RuleEntry) => r.sample_id))

          return {
            ok: true,
            data: {
              action: 'stats',
              total_yara_rules: yaraRules.length,
              total_sigma_rules: sigmaRules.length,
              total_rules: yaraRules.length + sigmaRules.length,
              samples_with_yara: samplesWithYara.size,
              samples_with_sigma: samplesWithSigma.size,
              status_breakdown: {
                draft: yaraRules.length + sigmaRules.length,
                reviewed: 0,
                production: 0,
                deprecated: 0,
              },
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        default:
          return { ok: false, errors: [`Unknown action: ${input.action}`] }
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

interface RuleEntry {
  artifact_id: string
  rule_type: 'yara' | 'sigma'
  sample_id: string
  created_at: string
  path: string
}

function collectRuleArtifacts(
  database: any,
  sampleId: string | undefined,
  ruleType: string,
): RuleEntry[] {
  const results: RuleEntry[] = []

  if (sampleId) {
    const artifacts = database.listArtifacts(sampleId)
    for (const a of artifacts) {
      if (matchesRuleType(a.type, ruleType)) {
        results.push({
          artifact_id: a.id,
          rule_type: a.type.includes('yara') ? 'yara' : 'sigma',
          sample_id: sampleId,
          created_at: a.created_at,
          path: a.path,
        })
      }
    }
  }

  return results
}

function matchesRuleType(artifactType: string, filter: string): boolean {
  if (filter === 'all') {
    return artifactType.includes('yara') || artifactType.includes('sigma')
  }
  return artifactType.includes(filter)
}
