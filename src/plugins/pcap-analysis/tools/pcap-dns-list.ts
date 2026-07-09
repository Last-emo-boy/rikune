/**
 * pcap.dns.list — Extract DNS queries and responses from a PCAP.
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
  PCAP_NETWORK_WORKFLOW_RECIPES,
} from '../pcap-workflow-metadata.js'

const TOOL_NAME = 'pcap.dns.list'

export const pcapDnsListInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the PCAP file.'),
  timeout_sec: z.number().int().min(5).max(60).default(15).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist DNS list as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const pcapDnsListOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      query_count: z.number().optional(),
      unique_domains: z.array(z.string()).optional(),
      dns_entries: z
        .array(
          z.object({
            query: z.string(),
            type: z.string().optional(),
            response: z.string().optional(),
          })
        )
        .optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const pcapDnsListToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Extract DNS queries and responses from a PCAP file.',
  inputSchema: pcapDnsListInputSchema,
  outputSchema: pcapDnsListOutputSchema,
  aspects: {
    formats: ['pcap', 'pcapng', 'network-capture'],
    platforms: ['cross-platform'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['dns-analysis', 'ioc-routing', 'workflow-handoff', 'evidence-correlation'],
    evidence: ['network', 'dns', 'artifact', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'pcap_dns_records',
      description: 'Extracted DNS query and response records',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'network', artifactTypes: ['pcap_dns_records'] },
    { category: 'workflow', artifactTypes: ['pcap_dns_records'] },
  ],
  workflowRecipes: PCAP_NETWORK_WORKFLOW_RECIPES,
}

export function createPcapDnsListHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = pcapDnsListInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({
        envPath: process.env.TSHARK_PATH,
        pathCandidates: ['tshark'],
        versionArgSets: [['--version']],
      })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(
          backend || ({ name: 'tshark', available: false, error: 'tshark not installed' } as any),
          startTime,
          TOOL_NAME
        )
      }

      const result = await executeCommand(
        backend.path,
        [
          '-r',
          samplePath,
          '-Y',
          'dns',
          '-T',
          'fields',
          '-e',
          'dns.qry.name',
          '-e',
          'dns.qry.type',
          '-e',
          'dns.a',
          '-E',
          'separator=|',
          '-E',
          'occurrence=f',
        ],
        input.timeout_sec * 1000
      )

      const lines = result.stdout.trim().split(/\r?\n/).filter(Boolean)
      const dnsEntries: Array<{ query: string; type: string; response: string }> = []
      const domains = new Set<string>()

      for (const line of lines) {
        const [query, type, response] = line.split('|')
        if (query) {
          dnsEntries.push({ query, type: type || '', response: response || '' })
          domains.add(query)
        }
      }

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact && dnsEntries.length > 0) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'pcap',
          'dns',
          JSON.stringify(dnsEntries, null, 2),
          { extension: 'json', mime: 'application/json', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }
      const recommendedNextTools = [
        'artifact.read',
        'pcap.analyze',
        'pcap.extract.streams',
        'ioc.export',
        'analysis.evidence.graph',
        'report.generate',
      ]
      const envelope = buildPcapWorkflowEnvelope({
        sourceTool: TOOL_NAME,
        sampleId: input.sample_id,
        artifactType: 'pcap_dns_records',
        artifact,
        summary: `${dnsEntries.length} DNS queries, ${domains.size} unique domains.`,
        evidenceCounts: {
          dns_query_count: dnsEntries.length,
          unique_domain_count: domains.size,
          response_count: dnsEntries.filter((entry) => entry.response).length,
        },
        recommendedNextTools,
      })

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          query_count: dnsEntries.length,
          unique_domains: [...domains].sort().slice(0, 100),
          dns_entries: dnsEntries.slice(0, 50),
          artifact,
          ...envelope,
          summary: `${dnsEntries.length} DNS queries, ${domains.size} unique domains.`,
          recommended_next_tools: recommendedNextTools,
          next_actions: [
            'Review domains for known C2 infrastructure.',
            'Route DNS records into analysis.evidence.graph for correlation.',
            'Export reviewed IOCs with ioc.export.',
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
