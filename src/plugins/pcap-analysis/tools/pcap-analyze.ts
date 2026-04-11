/**
 * pcap.analyze — Analyze a PCAP file and extract conversation summaries.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'pcap.analyze'

export const pcapAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the PCAP file.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('Analysis timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist analysis as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const pcapAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    packet_count: z.number().optional(),
    protocol_hierarchy: z.string().optional(),
    conversations: z.string().optional(),
    endpoints: z.string().optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const pcapAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze a PCAP file: protocol hierarchy, conversations, endpoints, packet count.',
  inputSchema: pcapAnalyzeInputSchema,
  outputSchema: pcapAnalyzeOutputSchema,
}

export function createPcapAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = pcapAnalyzeInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.TSHARK_PATH, pathCandidates: ['tshark'], versionArgSets: [['--version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'tshark', available: false, error: 'tshark not installed. apt-get install tshark' } as any, startTime, TOOL_NAME)
      }

      // Get stats
      const [statsResult, convResult, protoResult] = await Promise.all([
        executeCommand(backend.path, ['-r', samplePath, '-q', '-z', 'io,stat,0'], input.timeout_sec * 1000),
        executeCommand(backend.path, ['-r', samplePath, '-q', '-z', 'conv,tcp'], input.timeout_sec * 1000),
        executeCommand(backend.path, ['-r', samplePath, '-q', '-z', 'io,phs'], input.timeout_sec * 1000),
      ])

      // Count packets
      const countResult = await executeCommand(backend.path, ['-r', samplePath, '-T', 'fields', '-e', 'frame.number'], input.timeout_sec * 1000)
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
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'pcap', 'analysis', analysisText, { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          packet_count: packetCount,
          protocol_hierarchy: protoResult.stdout.slice(0, 2000),
          conversations: convResult.stdout.slice(0, 2000),
          endpoints: statsResult.stdout.slice(0, 1000),
          artifact,
          summary: `PCAP analysis: ${packetCount} packets captured.`,
          recommended_next_tools: ['pcap.dns.list', 'pcap.extract.streams', 'behavior.network', 'ioc.export'],
          next_actions: [
            'Use pcap.dns.list for DNS query/response analysis.',
            'Use pcap.extract.streams for TCP stream reassembly.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
