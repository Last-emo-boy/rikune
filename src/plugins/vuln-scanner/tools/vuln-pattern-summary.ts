/**
 * vuln.pattern.summary MCP tool - aggregate vulnerability scan findings into a concise summary.
 */

import { z } from 'zod'
import fs from 'fs/promises'
import type { ToolDefinition, ToolArgs, WorkerResult, PluginToolDeps } from '../../sdk.js'
import type { VulnScanResult, VulnFinding } from '../vuln-patterns.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'vuln.pattern.summary'
const VULN_PATTERN_SCAN_ARTIFACT_TYPE = 'vuln_pattern_scan'
const VULN_PATTERN_SUMMARY_SAFETY = [
  'passive',
  'static',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
  'no_live_execution',
]
const VULN_PATTERN_SUMMARY_EVIDENCE = [
  'vulnerabilities',
  'cwe',
  'risk-summary',
  'workflow',
  'provenance',
]
const VULN_PATTERN_SUMMARY_NEXT_TOOLS = [
  'artifact.read',
  'code.functions.rank',
  'code.function.explain.prepare',
  'analysis.evidence.graph',
  'report.generate',
]

export const VulnPatternSummaryInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  top_n_functions: z
    .number()
    .int()
    .min(1)
    .max(50)
    .optional()
    .default(10)
    .describe('Number of most vulnerable functions to include'),
})

export const VulnPatternSummaryOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vulnPatternSummaryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Summarize vulnerability scan findings: aggregate by CWE, rank most vulnerable functions, compute severity distribution.',
  inputSchema: VulnPatternSummaryInputSchema,
  outputSchema: VulnPatternSummaryOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'jar', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'jvm', 'dotnet', 'wasm', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'correlation'],
    safety: VULN_PATTERN_SUMMARY_SAFETY,
    capabilities: [
      'cwe-patterns',
      'risk-summary',
      'function-risk-ranking',
      'audit-prioritization',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: VULN_PATTERN_SUMMARY_EVIDENCE,
    search: [
      'vulnerability-summary',
      'cwe-summary',
      'function-risk',
      'audit-prioritization',
      'risk-report',
    ],
  },
  evidence: [
    {
      category: 'vulnerabilities',
      artifactTypes: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      description: 'Summarized CWE and severity evidence from vuln.pattern.scan artifacts',
    },
    {
      category: 'workflow',
      artifactTypes: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      description: 'Function review and reporting handoff derived from vulnerability scan results',
    },
    {
      category: 'provenance',
      artifactTypes: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'vuln-scanner.pattern-summary-handoff',
      title: 'Vulnerability pattern summary to review and reporting',
      description:
        'Summarize persisted CWE pattern findings into a compact risk profile, then route high-risk functions into ranking, explanation, evidence graph, and reporting workflows without executing the sample.',
      startsWith: [TOOL_NAME, 'vuln.pattern.scan'],
      nextTools: VULN_PATTERN_SUMMARY_NEXT_TOOLS,
      requiredArtifacts: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      evidence: VULN_PATTERN_SUMMARY_EVIDENCE,
      safety: VULN_PATTERN_SUMMARY_SAFETY,
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'vuln.pattern.summary reads a local vuln_pattern_scan artifact and does not execute the sample.',
      'Risk summaries are prioritization aids and still require analyst validation.',
    ],
  } as ToolDefinition['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
  },
}

// ============================================================================
// Handler
// ============================================================================

function buildSummary(scanResult: VulnScanResult, topN: number): Record<string, unknown> {
  // CWE breakdown
  const cweBreakdown = Object.entries(scanResult.cwe_counts)
    .sort((a, b) => b[1] - a[1])
    .map(([cwe, count]) => ({ cwe, count }))

  // Severity distribution
  const severityDist = {
    critical: scanResult.severity_counts['critical'] ?? 0,
    high: scanResult.severity_counts['high'] ?? 0,
    medium: scanResult.severity_counts['medium'] ?? 0,
    low: scanResult.severity_counts['low'] ?? 0,
  }

  // Most vulnerable functions
  const functionRisk = new Map<
    string,
    { name: string; address: string; findings: VulnFinding[]; risk_score: number }
  >()
  for (const f of scanResult.findings) {
    const key = f.function_address
    if (!functionRisk.has(key)) {
      functionRisk.set(key, {
        name: f.function_name,
        address: f.function_address,
        findings: [],
        risk_score: 0,
      })
    }
    const entry = functionRisk.get(key)
    entry.findings.push(f)
    const severityWeight: Record<string, number> = { critical: 10, high: 5, medium: 2, low: 1 }
    entry.risk_score += (severityWeight[f.severity] ?? 1) * f.confidence
  }

  const topFunctions = [...functionRisk.values()]
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, topN)
    .map((f) => ({
      function_name: f.name,
      function_address: f.address,
      risk_score: Math.round(f.risk_score * 100) / 100,
      finding_count: f.findings.length,
      cwe_list: [...new Set(f.findings.map((x) => x.cwe))],
      top_severity: f.findings.reduce((worst, cur) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
        return (order[cur.severity] ?? 4) < (order[worst] ?? 4) ? cur.severity : worst
      }, 'low' as string),
    }))

  // Overall risk assessment
  const totalRisk = [...functionRisk.values()].reduce((sum, f) => sum + f.risk_score, 0)
  let riskLevel: string
  if (severityDist.critical > 0 || totalRisk > 50) riskLevel = 'critical'
  else if (severityDist.high > 2 || totalRisk > 20) riskLevel = 'high'
  else if (severityDist.high > 0 || totalRisk > 5) riskLevel = 'medium'
  else riskLevel = 'low'

  return {
    overall_risk_level: riskLevel,
    total_findings: scanResult.total_findings,
    functions_scanned: scanResult.functions_scanned,
    functions_with_findings: functionRisk.size,
    severity_distribution: severityDist,
    cwe_breakdown: cweBreakdown,
    top_vulnerable_functions: topFunctions,
    total_risk_score: Math.round(totalRisk * 100) / 100,
  }
}

function buildSummaryEvidenceSummary(summary: Record<string, unknown>, sampleId: string) {
  return {
    schema: 'rikune.vuln_pattern_summary.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: sampleId,
    source_artifact_type: VULN_PATTERN_SCAN_ARTIFACT_TYPE,
    overall_risk_level: summary.overall_risk_level,
    total_findings: summary.total_findings,
    functions_scanned: summary.functions_scanned,
    functions_with_findings: summary.functions_with_findings,
    cwe_count: Array.isArray(summary.cwe_breakdown) ? summary.cwe_breakdown.length : 0,
    top_function_count: Array.isArray(summary.top_vulnerable_functions)
      ? summary.top_vulnerable_functions.length
      : 0,
  }
}

function buildSummaryWorkflowHandoff(summary: Record<string, unknown>, sampleId: string) {
  return {
    schema: 'rikune.vuln_pattern_summary.workflow_handoff.v1',
    handoff_mode: 'vulnerability_summary_to_function_review_and_reporting',
    source_tool: TOOL_NAME,
    sample_id: sampleId,
    recommended_next_tools: VULN_PATTERN_SUMMARY_NEXT_TOOLS,
    artifact_contract: {
      consumes: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      produces: ['inline_vuln_pattern_summary'],
      expected_consumers: ['code.functions.rank', 'analysis.evidence.graph', 'report.generate'],
    },
    routing: [
      {
        goal: 'high-risk-function-review',
        next_tools: ['code.functions.rank', 'code.function.explain.prepare'],
        required_evidence: ['top_vulnerable_functions', 'cwe_breakdown'],
      },
      {
        goal: 'reporting',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: ['severity_distribution', 'overall_risk_level'],
      },
    ],
    dynamic_boundary: {
      passive_static_only: true,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

export function createVulnPatternSummaryHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = VulnPatternSummaryInputSchema.parse(args)

    // Find scan artifact
    const artifacts = database.findArtifactsByType(input.sample_id, 'vuln_pattern_scan')
    const scanArtifact = artifacts[0]

    if (!scanArtifact) {
      return {
        ok: false,
        errors: [
          `No vulnerability scan results found for ${input.sample_id}. Run vuln.pattern.scan first.`,
        ],
      }
    }

    let scanResult: VulnScanResult
    try {
      const workspace = await workspaceManager.getWorkspace(input.sample_id)
      const artifactPath = workspaceManager.normalizePath(workspace.root, scanArtifact.path)
      const content = await fs.readFile(artifactPath, 'utf8')
      scanResult = JSON.parse(content) as VulnScanResult
    } catch {
      return { ok: false, errors: ['Failed to parse scan artifact'] }
    }

    const summary = buildSummary(scanResult, input.top_n_functions)
    const data = {
      ...summary,
      schema: 'rikune.vuln_pattern_summary.v1',
      sample_id: input.sample_id,
      evidence_summary: buildSummaryEvidenceSummary(summary, input.sample_id),
      workflow_handoff: buildSummaryWorkflowHandoff(summary, input.sample_id),
      quality_gates: {
        schema: 'rikune.vuln_pattern_summary.quality_gates.v1',
        passive_static_only: true,
        source_artifact_available: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        analyst_review_required: Number(summary.total_findings ?? 0) > 0,
      },
      recommended_next_tools: VULN_PATTERN_SUMMARY_NEXT_TOOLS,
      next_actions: [
        'Use code.functions.rank to prioritize vulnerable functions for review.',
        'Use artifact.read on the source vuln_pattern_scan artifact for finding-level detail.',
        'Use report.generate only after reviewing high-risk function evidence.',
      ],
    }

    return {
      ok: true,
      data,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
