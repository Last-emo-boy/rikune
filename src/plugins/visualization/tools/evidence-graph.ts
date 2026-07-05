/**
 * analysis.evidence.graph tool.
 *
 * Correlates specialist static artifacts and runtime trace artifacts into a
 * compact evidence graph for reports, dashboard navigation, and AI grounding.
 */

import { z } from 'zod'
import {
  getDatabase,
  getWorkspaceServices,
  createWorkerResultOutputSchema,
  type ArtifactRef,
  type PluginToolDeps,
  type ToolDefinition,
  type WorkerResult,
} from '../../sdk.js'
import {
  buildEvidenceGraph,
  loadCorrelationEvidence,
  type EvidenceGraph,
  type EvidenceGraphNode,
  type PluginEvidence,
} from '../../../artifacts/evidence-correlation.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'analysis.evidence.graph'
const TOOL_VERSION = '0.1.0'

export const EvidenceGraphInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  evidence_scope: z.enum(['all', 'latest', 'session']).optional().default('all'),
  evidence_session_tag: z.string().optional(),
  max_static_artifacts: z.number().int().min(1).max(100).optional().default(20),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

export const EvidenceGraphOutputSchema = createWorkerResultOutputSchema(
  z
    .object({
      schema: z.string(),
      tool_version: z.string(),
      sample_id: z.string(),
      evidence_scope: z.enum(['all', 'latest', 'session']),
      evidence_session_tag: z.string().nullable(),
      summary: z.object({
        static_artifact_count: z.number().int().nonnegative(),
        dynamic_artifact_count: z.number().int().nonnegative(),
        dynamic_executed: z.boolean(),
        expectation_count: z.number().int().nonnegative(),
        observation_count: z.number().int().nonnegative(),
        plugin_evidence_count: z.number().int().nonnegative(),
        function_handoff_count: z.number().int().nonnegative(),
        node_count: z.number().int().nonnegative(),
        edge_count: z.number().int().nonnegative(),
        corroboration_edge_count: z.number().int().nonnegative(),
      }),
      plugin_evidence_summary: z.record(z.any()),
      reporting_handoff: z.record(z.any()),
      quality_gates: z.record(z.any()),
      dynamic_summary: z.any().nullable(),
      graph: z.any(),
      warnings: z.array(z.string()),
      recommended_next_tools: z.array(z.string()),
    })
    .passthrough()
)

export const evidenceGraphToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a compact evidence graph that links specialist static artifacts, plugin evidence handoffs, static expectations, dynamic trace observations, reporting handoffs, and corroboration edges. Does not execute the sample.',
  inputSchema: EvidenceGraphInputSchema,
  outputSchema: EvidenceGraphOutputSchema,
  aspects: {
    formats: ['artifact', 'analysis-evidence', 'runtime-trace'],
    platforms: ['all', 'cross-platform'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default'],
    evidence: ['provenance', 'timeline', 'behavior', 'network', 'memory', 'artifact', 'workflow'],
  },
  artifacts: [
    {
      type: 'analysis_evidence_graph',
      description:
        'Correlated evidence graph across static artifacts, plugin evidence handoffs, and imported runtime traces',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'provenance', artifactTypes: ['analysis_evidence_graph'] },
    { category: 'timeline', artifactTypes: ['analysis_evidence_graph'] },
    { category: 'behavior', artifactTypes: ['analysis_evidence_graph'] },
    { category: 'workflow', artifactTypes: ['analysis_evidence_graph'] },
  ],
  workflowRecipes: [
    {
      id: 'visualization.plugin-evidence-reporting',
      title: 'Plugin evidence graph to reporting',
      description:
        'Fold malware intel, static-triage correlation bundles, cross-decompiler consensus, and function evidence handoffs into one passive evidence graph before final reporting.',
      startsWith: [
        'analysis.evidence.graph',
        'malware.intel.loop',
        'static.capability.triage',
        'code.cross_decompiler.consensus',
      ],
      nextTools: ['workflow.summarize', 'report.summarize', 'report.generate', 'artifact.read'],
      requiredArtifacts: [
        'malware_intel_loop',
        'static_triage_correlation_bundle',
        'cross_decompiler_consensus',
        'function_evidence_handoff',
      ],
      producesArtifacts: ['analysis_evidence_graph'],
      evidence: ['provenance', 'behavior', 'network', 'functions', 'workflow', 'correlation-graph'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

function uniqueStrings(values: Array<string | null | undefined>, limit?: number): string[] {
  const unique = Array.from(new Set(values.filter((value): value is string => Boolean(value))))
  return typeof limit === 'number' ? unique.slice(0, limit) : unique
}

function countBy<T extends string>(values: T[]): Record<string, number> {
  return values.reduce<Record<string, number>>((counts, value) => {
    counts[value] = (counts[value] || 0) + 1
    return counts
  }, {})
}

function topEvidenceItems(pluginEvidence: PluginEvidence[]) {
  return [...pluginEvidence]
    .sort((left, right) => right.confidence - left.confidence)
    .slice(0, 16)
    .map((item) => ({
      kind: item.kind,
      category: item.category,
      label: item.label,
      value: item.value,
      confidence: item.confidence,
      source_artifact_type: item.source_artifact_type,
      recommended_tools: item.recommended_tools || [],
    }))
}

function buildPluginEvidenceSummary(pluginEvidence: PluginEvidence[]) {
  const functionHandoffKinds = new Set(['stable_function', 'disputed_function'])
  const byKind = countBy(pluginEvidence.map((item) => item.kind))

  return {
    schema: 'rikune.analysis_evidence_graph.plugin_evidence_summary.v1',
    source_tool: TOOL_NAME,
    plugin_evidence_count: pluginEvidence.length,
    function_handoff_count: pluginEvidence.filter((item) => functionHandoffKinds.has(item.kind))
      .length,
    ioc_count: byKind.ioc || 0,
    triage_signal_count: byKind.triage_signal || 0,
    workflow_route_count: byKind.workflow_route || 0,
    backend_gap_count: byKind.backend_gap || 0,
    disputed_function_count: byKind.disputed_function || 0,
    evidence_by_kind: byKind,
    evidence_by_category: countBy(pluginEvidence.map((item) => item.category)),
    evidence_by_source_artifact_type: countBy(
      pluginEvidence.map((item) => item.source_artifact_type)
    ),
    high_confidence_count: pluginEvidence.filter((item) => item.confidence >= 0.75).length,
    recommended_tools: uniqueStrings(
      pluginEvidence.flatMap((item) => item.recommended_tools || []),
      24
    ),
    top_report_evidence: topEvidenceItems(pluginEvidence),
  }
}

function reportSectionsFor(pluginEvidence: PluginEvidence[], graph: EvidenceGraph): string[] {
  const kinds = new Set(pluginEvidence.map((item) => item.kind))
  const categories = new Set(pluginEvidence.map((item) => item.category))
  return uniqueStrings([
    'evidence_graph_overview',
    kinds.has('ioc') ? 'ioc_summary' : null,
    kinds.has('triage_signal') || kinds.has('capability') ? 'capability_correlation' : null,
    kinds.has('stable_function') || kinds.has('disputed_function') ? 'function_consensus' : null,
    categories.has('workflow') ? 'workflow_routes' : null,
    graph.edges.some((edge) => edge.label === 'corroborated_by')
      ? 'static_dynamic_corroboration'
      : null,
    graph.nodes.some((node) => node.kind === 'observation') ? 'runtime_observations' : null,
  ])
}

function preferredEvidenceNodes(nodes: EvidenceGraphNode[]) {
  return nodes
    .filter((node) => node.kind === 'plugin_evidence' || node.kind === 'function_handoff')
    .sort((left, right) => (right.confidence || 0) - (left.confidence || 0))
    .slice(0, 12)
    .map((node) => ({
      id: node.id,
      kind: node.kind,
      category: node.category || null,
      label: node.label,
      confidence: node.confidence || 0,
      source: node.source || null,
    }))
}

function buildReportingHandoff(args: {
  sampleId: string
  pluginEvidence: PluginEvidence[]
  graph: EvidenceGraph
  dynamicEvidencePresent: boolean
}) {
  const pluginRecommended = args.pluginEvidence.flatMap((item) => item.recommended_tools || [])
  const reportSections = reportSectionsFor(args.pluginEvidence, args.graph)

  return {
    schema: 'rikune.analysis_evidence_graph.reporting_handoff.v1',
    handoff_mode: 'plugin_evidence_to_reporting',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    recommended_next_tools: uniqueStrings([
      'workflow.summarize',
      'report.summarize',
      'report.generate',
      'artifact.read',
      ...pluginRecommended,
    ]),
    report_sections: reportSections,
    graph_snapshot: {
      node_count: args.graph.nodes.length,
      edge_count: args.graph.edges.length,
      plugin_evidence_node_count: args.graph.nodes.filter(
        (node) => node.kind === 'plugin_evidence' || node.kind === 'function_handoff'
      ).length,
      corroboration_edge_count: args.graph.edges.filter((edge) => edge.label === 'corroborated_by')
        .length,
      preferred_evidence_nodes: preferredEvidenceNodes(args.graph.nodes),
    },
    routing: [
      {
        goal: 'staged-analyst-summary',
        priority: args.pluginEvidence.length > 0 ? 'high' : 'normal',
        next_tools: ['workflow.summarize', 'artifact.read'],
        required_evidence: ['analysis_evidence_graph'],
      },
      {
        goal: 'archival-report-export',
        priority: 'normal',
        next_tools: ['report.generate'],
        required_evidence: ['analysis_evidence_graph', ...reportSections],
      },
      {
        goal: 'compact-compatibility-summary',
        priority: 'normal',
        next_tools: ['report.summarize'],
        required_evidence: ['persisted analysis artifacts'],
      },
    ],
    artifact_contract: {
      consumes: [
        'static_config_carver',
        'static_resource_graph',
        'malware_intel_loop',
        'static_capability_triage',
        'static_triage_correlation_bundle',
        'cross_decompiler_consensus',
        'function_evidence_handoff',
        'backend_die_scan',
        'backend_upx_list',
        'backend_upx_test',
        'dynamic_trace_json',
      ],
      produces: ['analysis_evidence_graph'],
      expected_consumers: ['workflow.summarize', 'report.summarize', 'report.generate'],
    },
    dynamic_boundary: {
      runtime_started_by_tool: false,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      dynamic_evidence_present: args.dynamicEvidencePresent,
    },
  }
}

function buildQualityGates(args: {
  pluginEvidence: PluginEvidence[]
  graph: EvidenceGraph
  dynamicEvidencePresent: boolean
  staticExpectationCount: number
  warnings: string[]
}) {
  const disputedFunctionCount = args.pluginEvidence.filter(
    (item) => item.kind === 'disputed_function'
  ).length
  const backendGapCount = args.pluginEvidence.filter((item) => item.kind === 'backend_gap').length

  return {
    passive_correlation_only: true,
    backend_started: false,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    plugin_evidence_present: args.pluginEvidence.length > 0,
    static_expectations_present: args.staticExpectationCount > 0,
    dynamic_evidence_present: args.dynamicEvidencePresent,
    report_handoff_ready: args.graph.nodes.length > 1,
    graph_nonempty: args.graph.nodes.length > 0 && args.graph.edges.length > 0,
    function_handoff_present: args.pluginEvidence.some((item) =>
      ['stable_function', 'disputed_function'].includes(item.kind)
    ),
    analyst_review_required:
      args.warnings.length > 0 || disputedFunctionCount > 0 || backendGapCount > 0,
    warning_count: args.warnings.length,
    disputed_function_count: disputedFunctionCount,
    backend_gap_count: backendGapCount,
  }
}

export function createEvidenceGraphHandler(deps: PluginToolDeps) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = EvidenceGraphInputSchema.parse(args || {})
      const db = getDatabase(deps)
      const workspace = getWorkspaceServices(deps)
      const sample = db.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
        }
      }

      const bundle = await loadCorrelationEvidence(workspace.manager, db, input.sample_id, {
        evidenceScope: input.evidence_scope,
        sessionTag: input.evidence_session_tag,
        maxStaticArtifacts: input.max_static_artifacts,
      })
      const graph = buildEvidenceGraph(bundle)
      const pluginEvidence = bundle.plugin_evidence ?? []
      const pluginEvidenceSummary = buildPluginEvidenceSummary(pluginEvidence)
      const reportingHandoff = buildReportingHandoff({
        sampleId: input.sample_id,
        pluginEvidence,
        graph,
        dynamicEvidencePresent: Boolean(bundle.dynamic_summary),
      })
      const qualityGates = buildQualityGates({
        pluginEvidence,
        graph,
        dynamicEvidencePresent: Boolean(bundle.dynamic_summary),
        staticExpectationCount: bundle.expectations.length,
        warnings: bundle.warnings,
      })
      const data = {
        schema: 'rikune.analysis_evidence_graph.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        evidence_scope: input.evidence_scope,
        evidence_session_tag: input.evidence_session_tag || null,
        summary: {
          static_artifact_count: bundle.static_artifacts.length,
          dynamic_artifact_count: bundle.dynamic_summary?.artifact_count || 0,
          dynamic_executed: Boolean(bundle.dynamic_summary?.executed),
          expectation_count: bundle.expectations.length,
          observation_count: bundle.observations.length,
          plugin_evidence_count: pluginEvidence.length,
          function_handoff_count: pluginEvidence.filter((item) =>
            ['stable_function', 'disputed_function'].includes(item.kind)
          ).length,
          node_count: graph.nodes.length,
          edge_count: graph.edges.length,
          corroboration_edge_count: graph.edges.filter((edge) => edge.label === 'corroborated_by')
            .length,
        },
        plugin_evidence_summary: pluginEvidenceSummary,
        reporting_handoff: reportingHandoff,
        quality_gates: qualityGates,
        dynamic_summary: bundle.dynamic_summary
          ? {
              artifact_count: bundle.dynamic_summary.artifact_count,
              artifact_types: bundle.dynamic_summary.artifact_types || [],
              artifact_families: bundle.dynamic_summary.artifact_families || [],
              executed: bundle.dynamic_summary.executed,
              scope_note: bundle.dynamic_summary.scope_note,
            }
          : null,
        graph,
        warnings: bundle.warnings,
        recommended_next_tools: [
          'static.config.carver',
          'static.resource.graph',
          'malware.intel.loop',
          'code.cross_decompiler.consensus',
          'workflow.summarize',
          'report.summarize',
          'report.generate',
          'dynamic.behavior.diff',
          'dynamic.persona.plan',
          'dynamic.behavior.capture',
        ],
      }

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        artifacts.push(
          await persistStaticAnalysisJsonArtifact(
            workspace.manager,
            db,
            input.sample_id,
            'analysis_evidence_graph',
            'evidence_graph',
            data,
            input.session_tag
          )
        )
      }

      return {
        ok: true,
        data,
        warnings: bundle.warnings.length > 0 ? bundle.warnings : undefined,
        artifacts,
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
