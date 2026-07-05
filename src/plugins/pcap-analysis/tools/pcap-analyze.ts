/**
 * pcap.analyze — Analyze a PCAP file and extract conversation summaries.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  normalizeError,
  executeCommand,
  persistBackendArtifact,
  buildMetrics,
  resolveSampleFile,
  resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'
import {
  buildPcapWorkflowEnvelope,
  PCAP_NETWORK_EVIDENCE,
  PCAP_NETWORK_WORKFLOW_RECIPES,
} from '../pcap-workflow-metadata.js'

const TOOL_NAME = 'pcap.analyze'

export const pcapAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the PCAP file.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('Analysis timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist analysis as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const pcapAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      packet_count: z.number().optional(),
      protocol_hierarchy: z.string().optional(),
      conversations: z.string().optional(),
      endpoints: z.string().optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const pcapAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Analyze a PCAP file: protocol hierarchy, conversations, endpoints, packet count.',
  inputSchema: pcapAnalyzeInputSchema,
  outputSchema: pcapAnalyzeOutputSchema,
  aspects: {
    formats: ['pcap', 'pcapng', 'network-capture'],
    platforms: ['cross-platform'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['packet-analysis', 'network-triage', 'workflow-handoff', 'evidence-correlation'],
    evidence: ['network', 'timeline', 'artifact', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'pcap_analysis',
      description: 'Protocol hierarchy, conversations, endpoint, and packet-count summary',
      mime: 'text/plain',
    },
  ],
  evidence: [
    { category: 'network', artifactTypes: ['pcap_analysis'] },
    { category: 'timeline', artifactTypes: ['pcap_analysis'] },
    { category: 'workflow', artifactTypes: ['pcap_analysis'] },
  ],
  workflowRecipes: PCAP_NETWORK_WORKFLOW_RECIPES,
}

export function createPcapAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = pcapAnalyzeInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({
        envPath: process.env.TSHARK_PATH,
        pathCandidates: ['tshark'],
        versionArgSets: [['--version']],
      })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(
          backend ||
            ({
              name: 'tshark',
              available: false,
              error: 'tshark not installed. apt-get install tshark',
            } as any),
          startTime,
          TOOL_NAME
        )
      }

      // Get stats
      const [statsResult, convResult, protoResult] = await Promise.all([
        executeCommand(
          backend.path,
          ['-r', samplePath, '-q', '-z', 'io,stat,0'],
          input.timeout_sec * 1000
        ),
        executeCommand(
          backend.path,
          ['-r', samplePath, '-q', '-z', 'conv,tcp'],
          input.timeout_sec * 1000
        ),
        executeCommand(
          backend.path,
          ['-r', samplePath, '-q', '-z', 'io,phs'],
          input.timeout_sec * 1000
        ),
      ])

      // Count packets
      const countResult = await executeCommand(
        backend.path,
        ['-r', samplePath, '-T', 'fields', '-e', 'frame.number'],
        input.timeout_sec * 1000
      )
      const packetCount = countResult.stdout.trim().split(/\r?\n/).filter(Boolean).length

      const analysisText = [
        '=== Protocol Hierarchy ===',
        protoResult.stdout,
        '=== TCP Conversations ===',
        convResult.stdout,
        '=== I/O Statistics ===',
        statsResult.stdout,
      ].join('\n\n')

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'pcap',
          'analysis',
          analysisText,
          { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }
      const recommendedNextTools = [
        'artifact.read',
        'pcap.dns.list',
        'pcap.extract.streams',
        'ioc.export',
        'analysis.evidence.graph',
        'report.generate',
      ]
      const envelope = buildPcapWorkflowEnvelope({
        sourceTool: TOOL_NAME,
        sampleId: input.sample_id,
        artifactType: 'pcap_analysis',
        artifact,
        summary: `PCAP analysis: ${packetCount} packets captured.`,
        evidenceCounts: {
          packet_count: packetCount,
          protocol_hierarchy_available: protoResult.stdout.trim().length > 0,
          conversation_summary_available: convResult.stdout.trim().length > 0,
          io_statistics_available: statsResult.stdout.trim().length > 0,
          evidence_family_count: PCAP_NETWORK_EVIDENCE.length,
        },
        recommendedNextTools,
      })

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          packet_count: packetCount,
          protocol_hierarchy: protoResult.stdout.slice(0, 2000),
          conversations: convResult.stdout.slice(0, 2000),
          endpoints: statsResult.stdout.slice(0, 1000),
          artifact,
          ...envelope,
          summary: `PCAP analysis: ${packetCount} packets captured.`,
          recommended_next_tools: recommendedNextTools,
          next_actions: [
            'Use pcap.dns.list for DNS query/response analysis.',
            'Use pcap.extract.streams for TCP stream reassembly.',
            'Route the persisted artifact into analysis.evidence.graph before report.generate.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    }
  }
}
