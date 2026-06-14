/**
 * vuln.pattern.scan MCP tool — scan decompiled functions for CWE vulnerability patterns.
 */

import { z } from 'zod'
import type {
  ToolDefinition,
  ToolArgs,
  WorkerResult,
  ArtifactRef,
  PluginToolDeps,
} from '../../sdk.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import { loadPatterns, scanAllFunctions, type VulnScanResult } from '../vuln-patterns.js'

// ============================================================================
// Schemas
// ============================================================================

const TOOL_NAME = 'vuln.pattern.scan'
const TOOL_VERSION = '1.1.0'
const VULN_PATTERN_SCAN_ARTIFACT_TYPE = 'vuln_pattern_scan'
const VULN_PATTERN_SAFETY = [
  'passive',
  'static',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
  'no_live_execution',
]
const VULN_PATTERN_EVIDENCE = [
  'vulnerabilities',
  'functions',
  'decompiled-code',
  'cwe',
  'risk-ranking',
  'workflow',
  'provenance',
]
const VULN_PATTERN_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'vuln.pattern.summary',
  'code.functions.rank',
  'code.function.explain.prepare',
  'analysis.evidence.graph',
  'report.generate',
]

export const VulnPatternScanInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  min_confidence: z
    .number()
    .min(0)
    .max(1)
    .optional()
    .default(0.3)
    .describe('Minimum confidence threshold for findings'),
  max_findings: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(100)
    .describe('Maximum number of findings to return'),
})

export const VulnPatternScanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vulnPatternScanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Scan decompiled functions for CWE vulnerability patterns (buffer overflow, format string, command injection, DLL hijacking, integer overflow, use-after-free).',
  inputSchema: VulnPatternScanInputSchema,
  outputSchema: VulnPatternScanOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'jar', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'jvm', 'dotnet', 'wasm', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'correlation'],
    safety: VULN_PATTERN_SAFETY,
    capabilities: [
      'cwe-patterns',
      'decompiled-code-scan',
      'function-risk-ranking',
      'audit-prioritization',
      'risk-summary',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: VULN_PATTERN_EVIDENCE,
    search: [
      'vulnerability',
      'cwe',
      'buffer-overflow',
      'format-string',
      'command-injection',
      'dll-hijacking',
      'integer-overflow',
      'use-after-free',
      'function-risk',
    ],
  },
  artifacts: [
    {
      type: VULN_PATTERN_SCAN_ARTIFACT_TYPE,
      description:
        'CWE vulnerability findings, function risk ranking, workflow handoff, and quality gates over decompiled functions',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'vulnerabilities',
      artifactTypes: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      description: 'CWE-pattern findings over recovered decompiled functions',
    },
    {
      category: 'functions',
      artifactTypes: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      description: 'Function-level risk evidence for later ranking and review',
    },
    {
      category: 'workflow',
      artifactTypes: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      description: 'Audit handoff into function ranking, evidence graph, and report generation',
    },
    {
      category: 'provenance',
      artifactTypes: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      description: 'Pattern database version and scan threshold provenance',
    },
  ],
  workflowRecipes: [
    {
      id: 'vuln-scanner.pattern-risk-handoff',
      title: 'CWE pattern scan to function risk review',
      description:
        'Scan recovered decompiled functions with curated CWE patterns, persist function-level risk evidence, then route high-risk functions into ranking, explanation, evidence graph, and reporting workflows without executing the sample.',
      startsWith: [TOOL_NAME, 'code.functions.reconstruct', 'code.function.decompile'],
      nextTools: VULN_PATTERN_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['analysis_evidence', 'decompiled_functions'],
      producesArtifacts: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      evidence: VULN_PATTERN_EVIDENCE,
      safety: VULN_PATTERN_SAFETY,
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
      'vuln.pattern.scan reads decompiled function evidence from the local database and never executes the sample.',
      'Findings are pattern-based audit candidates and require analyst review before vulnerability claims.',
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

function extractDecompiledFunctions(
  database: any,
  sampleId: string
): Array<{ name: string; address: string; decompiled_code: string }> {
  const functions: Array<{ name: string; address: string; decompiled_code: string }> = []

  // Try loading from analysis_evidence (function_map stage)
  const evidence = database.findAnalysisEvidenceBySample(sampleId)
  if (Array.isArray(evidence)) {
    for (const entry of evidence) {
      const family = entry.evidence_family ?? ''
      if (family === 'function_map' || family === 'decompilation' || family === 'functions') {
        const data =
          typeof entry.result_json === 'string' ? JSON.parse(entry.result_json) : entry.result_json
        if (!data) continue

        // Extract functions array
        const fnList =
          (data as Record<string, unknown>).functions ??
          (data as Record<string, unknown>).decompiled_functions ??
          []
        if (Array.isArray(fnList)) {
          for (const fn of fnList) {
            if (fn && typeof fn === 'object') {
              const obj = fn as Record<string, unknown>
              const code = String(obj.decompiled ?? obj.code ?? obj.decompiled_code ?? '')
              if (code) {
                functions.push({
                  name: String(obj.name ?? obj.function_name ?? 'unknown'),
                  address: String(obj.address ?? obj.offset ?? obj.addr ?? '0x0'),
                  decompiled_code: code,
                })
              }
            }
          }
        }
      }
    }
  }

  return functions
}

function buildEvidenceSummary(args: {
  sampleId: string
  input: z.infer<typeof VulnPatternScanInputSchema>
  patternVersion: string
  result: VulnScanResult
}) {
  const highRiskFindings = args.result.findings.filter((finding) =>
    ['critical', 'high'].includes(finding.severity)
  )
  return {
    schema: 'rikune.vuln_pattern_scan.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: VULN_PATTERN_SCAN_ARTIFACT_TYPE,
    pattern_db_version: args.patternVersion,
    min_confidence: args.input.min_confidence,
    max_findings: args.input.max_findings,
    functions_scanned: args.result.functions_scanned,
    total_findings: args.result.total_findings,
    returned_findings: args.result.findings.length,
    high_risk_finding_count: highRiskFindings.length,
    severity_counts: args.result.severity_counts,
    cwe_counts: args.result.cwe_counts,
    top_function_risk: args.result.findings.slice(0, 12).map((finding) => ({
      function_name: finding.function_name,
      function_address: finding.function_address,
      cwe: finding.cwe,
      severity: finding.severity,
      confidence: finding.confidence,
    })),
    evidence_sources: ['analysis_evidence.function_map', 'curated_cwe_pattern_database'],
  }
}

function buildWorkflowHandoff(args: {
  sampleId: string
  result: VulnScanResult
  recommendedNextTools: string[]
}) {
  const highRisk = args.result.findings.some((finding) =>
    ['critical', 'high'].includes(finding.severity)
  )
  return {
    schema: 'rikune.vuln_pattern_scan.workflow_handoff.v1',
    handoff_mode: 'vulnerability_pattern_scan_to_function_review',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    recommended_next_tools: args.recommendedNextTools,
    artifact_contract: {
      consumes: ['analysis_evidence.function_map', 'decompiled_functions'],
      produces: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
      expected_consumers: ['vuln.pattern.summary', 'code.functions.rank', 'analysis.evidence.graph'],
    },
    routing: [
      {
        goal: 'function-risk-ranking',
        next_tools: ['code.functions.rank', 'code.function.explain.prepare'],
        required_evidence: ['vuln_pattern_scan', 'function_addresses'],
        priority: highRisk ? 'high' : 'normal',
      },
      {
        goal: 'vulnerability-summary-and-reporting',
        next_tools: ['vuln.pattern.summary', 'analysis.evidence.graph', 'report.generate'],
        required_evidence: ['cwe_counts', 'severity_counts', 'top_function_risk'],
      },
      {
        goal: 'artifact-review',
        next_tools: ['artifact.read'],
        required_evidence: [VULN_PATTERN_SCAN_ARTIFACT_TYPE],
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

function buildQualityGates(args: { result: VulnScanResult; artifactPersisted: boolean }) {
  return {
    schema: 'rikune.vuln_pattern_scan.quality_gates.v1',
    passive_static_only: true,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    decompiled_functions_available: args.result.functions_scanned > 0,
    pattern_scan_completed: true,
    artifact_persisted: args.artifactPersisted,
    finding_count_bounded: true,
    analyst_review_required: args.result.total_findings > 0,
  }
}

function buildNextActions(result: VulnScanResult): string[] {
  if (result.findings.length === 0) {
    return [
      'No CWE pattern findings met the confidence threshold; use artifact.read only if you need audit provenance.',
      'Run code.functions.rank or deeper reconstruction if vulnerability review remains in scope.',
    ]
  }
  return [
    'Use vuln.pattern.summary for a compact risk overview.',
    'Use code.functions.rank with vulnerability risk enabled to prioritize functions for review.',
    'Use artifact.read on the vuln_pattern_scan artifact before citing specific findings.',
    'Use analysis.evidence.graph or report.generate to publish corroborated findings.',
  ]
}

export function createVulnPatternScanHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = VulnPatternScanInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Load vulnerability patterns
    const patternDB = await loadPatterns()

    // Extract decompiled functions
    const functions = extractDecompiledFunctions(database, input.sample_id)
    if (functions.length === 0) {
      return {
        ok: false,
        errors: [
          'No decompiled functions found. Run function_map stage or code.functions.reconstruct first.',
        ],
      }
    }

    // Scan
    const scanResult = scanAllFunctions(functions, patternDB.patterns, input.min_confidence)

    // Truncate findings
    scanResult.findings = scanResult.findings
      .sort((a, b) => {
        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
        const diff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)
        if (diff !== 0) return diff
        return b.confidence - a.confidence
      })
      .slice(0, input.max_findings)

    const recommendedNextTools = VULN_PATTERN_FOLLOW_UP_TOOLS
    let outputData: Record<string, unknown> = {
      ...scanResult,
      schema: 'rikune.vuln_pattern_scan.v1',
      tool_version: TOOL_VERSION,
      sample_id: input.sample_id,
      pattern_db_version: patternDB.version,
      min_confidence: input.min_confidence,
      max_findings: input.max_findings,
      evidence_summary: buildEvidenceSummary({
        sampleId: input.sample_id,
        input,
        patternVersion: patternDB.version,
        result: scanResult,
      }),
      workflow_handoff: buildWorkflowHandoff({
        sampleId: input.sample_id,
        result: scanResult,
        recommendedNextTools,
      }),
      quality_gates: buildQualityGates({ result: scanResult, artifactPersisted: true }),
      recommended_next_tools: recommendedNextTools,
      next_actions: buildNextActions(scanResult),
    }

    // Persist artifact
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager,
        database,
        input.sample_id,
        VULN_PATTERN_SCAN_ARTIFACT_TYPE,
        'vuln_findings',
        outputData
      )
      artifacts.push(ref)
      outputData = {
        ...outputData,
        artifact: ref,
      }
    } catch {
      warnings.push('Failed to persist vulnerability scan artifact')
      outputData = {
        ...outputData,
        quality_gates: buildQualityGates({ result: scanResult, artifactPersisted: false }),
      }
    }

    return {
      ok: true,
      data: outputData,
      warnings: warnings.length > 0 ? warnings : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
