/**
 * pcap.extract.streams — Reassemble and extract TCP/UDP streams from PCAP.
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

const TOOL_NAME = 'pcap.extract.streams'

export const pcapExtractStreamsInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the PCAP file.'),
  stream_index: z.number().int().min(0).optional().describe('Specific TCP stream index to extract. Omit for summary of all streams.'),
  protocol: z.enum(['tcp', 'udp']).default('tcp').describe('Stream protocol to extract.'),
  max_bytes: z.number().int().min(256).max(65536).default(8192).describe('Max bytes per stream.'),
  timeout_sec: z.number().int().min(5).max(60).default(20).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist extracted stream data.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const pcapExtractStreamsOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    protocol: z.string().optional(),
    stream_count: z.number().optional(),
    streams: z.array(z.object({
      index: z.number(),
      src: z.string().optional(),
      dst: z.string().optional(),
      bytes: z.number().optional(),
      preview: z.string().optional(),
    })).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const pcapExtractStreamsToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Reassemble and extract TCP/UDP streams from a PCAP file.',
  inputSchema: pcapExtractStreamsInputSchema,
  outputSchema: pcapExtractStreamsOutputSchema,
}

export function createPcapExtractStreamsHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = pcapExtractStreamsInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.TSHARK_PATH, pathCandidates: ['tshark'], versionArgSets: [['--version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'tshark', available: false, error: 'tshark not installed' } as any, startTime, TOOL_NAME)
      }

      if (input.stream_index !== undefined) {
        // Extract specific stream
        const filter = `${input.protocol}.stream eq ${input.stream_index}`
        const result = await executeCommand(
          backend.path,
          ['-r', samplePath, '-qz', `follow,${input.protocol},ascii,${input.stream_index}`],
          input.timeout_sec * 1000,
        )
        const preview = result.stdout.slice(0, input.max_bytes)
        const artifacts: ArtifactRef[] = []
        let artifact: ArtifactRef | undefined
        if (input.persist_artifact && result.stdout.length > 0) {
          artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'pcap', `stream-${input.protocol}-${input.stream_index}`, preview, { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag })
          artifacts.push(artifact)
        }
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            protocol: input.protocol,
            stream_count: 1,
            streams: [{ index: input.stream_index, bytes: result.stdout.length, preview: preview.slice(0, 2048) }],
            artifact,
            summary: `Extracted ${input.protocol} stream #${input.stream_index} (${result.stdout.length} bytes).`,
            recommended_next_tools: ['pcap.dns.list', 'pcap.analyze', 'string.extract'],
            next_actions: [
              'Look for embedded payloads or C2 commands in the stream.',
              'Carve out any transferred files.',
            ],
          },
          artifacts,
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      } else {
        // List all streams with endpoints
        const result = await executeCommand(
          backend.path,
          ['-r', samplePath, '-q', '-z', `conv,${input.protocol}`],
          input.timeout_sec * 1000,
        )
        const lines = result.stdout.trim().split(/\r?\n/)
        const streams: Array<{ index: number; src: string; dst: string; bytes: number }> = []
        let idx = 0
        for (const line of lines) {
          // Format: addr:port <-> addr:port  frames  bytes  frames  bytes  frames  bytes
          const m = line.match(/^([\d.:[\]a-fA-F]+)\s+<->\s+([\d.:[\]a-fA-F]+)\s+\d+\s+(\d+)\s+\d+\s+(\d+)\s+\d+\s+(\d+)/)
          if (m) {
            streams.push({ index: idx++, src: m[1], dst: m[2], bytes: parseInt(m[5], 10) })
          }
        }

        const artifacts: ArtifactRef[] = []
        let artifact: ArtifactRef | undefined
        if (input.persist_artifact && streams.length > 0) {
          artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'pcap', `streams-${input.protocol}`, JSON.stringify(streams, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
          artifacts.push(artifact)
        }

        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            protocol: input.protocol,
            stream_count: streams.length,
            streams: streams.slice(0, 50),
            artifact,
            summary: `Found ${streams.length} ${input.protocol} streams.`,
            recommended_next_tools: ['pcap.extract.streams', 'pcap.dns.list', 'pcap.analyze'],
            next_actions: [
              'Extract a specific stream by index for full content.',
              'Look for large streams that may contain file transfers.',
            ],
          },
          artifacts,
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
