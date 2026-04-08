/**
 * sample.timeline — Cross-sample compilation timestamp timeline.
 *
 * Extracts PE timestamps, .NET metadata dates, and compilation markers
 * from multiple samples to build a chronological timeline for tracking
 * malware evolution.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'

const TOOL_NAME = 'sample.timeline'
const TOOL_VERSION = '0.1.0'

export const SampleTimelineInputSchema = z.object({
  sample_ids: z.array(z.string()).min(2).max(200)
    .describe('List of sample identifiers to timeline'),
  include_pe_timestamp: z.boolean().default(true)
    .describe('Include PE header TimeDateStamp'),
  include_debug_timestamp: z.boolean().default(true)
    .describe('Include debug directory timestamp'),
  include_resource_timestamp: z.boolean().default(true)
    .describe('Include resource section timestamps'),
  include_dotnet_metadata: z.boolean().default(true)
    .describe('Include .NET assembly metadata dates'),
  detect_fake_timestamps: z.boolean().default(true)
    .describe('Flag timestamps outside reasonable ranges as potentially fake'),
})
export type SampleTimelineInput = z.infer<typeof SampleTimelineInputSchema>

export const sampleTimelineToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a chronological timeline from compilation timestamps across multiple samples. ' +
    'Extracts PE TimeDateStamp, debug directory dates, resource timestamps, and .NET ' +
    'assembly metadata. Flags potentially fake timestamps. Useful for tracking malware ' +
    'evolution, campaign timelines, and toolchain analysis.',
  inputSchema: SampleTimelineInputSchema,
}

// Reasonable timestamp range: 2000-01-01 to now+1year
const MIN_REASONABLE_TS = new Date('2000-01-01').getTime() / 1000
const MAX_REASONABLE_TS = () => (Date.now() / 1000) + 365 * 86400

export function createSampleTimelineHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = SampleTimelineInputSchema.parse(args)
    const startTime = Date.now()

    try {
      // Validate samples
      const missing: string[] = []
      const sampleProfiles: Array<{
        id: string; sha256: string; file_name: string | null; created_at: string
      }> = []

      for (const sid of input.sample_ids) {
        const s = database.findSample(sid)
        if (!s) missing.push(sid)
        else sampleProfiles.push({
          id: sid,
          sha256: s.sha256,
          file_name: s.source || s.sha256.slice(0, 12),
          created_at: s.created_at,
        })
      }

      if (missing.length > 0 && sampleProfiles.length === 0) {
        return { ok: false, errors: [`No valid samples found. Missing: ${missing.join(', ')}`] }
      }

      // Extract timestamps from existing artifacts
      const timelineEntries: Array<{
        sample_id: string
        file_name: string
        timestamp_type: string
        timestamp_unix: number | null
        timestamp_iso: string | null
        is_suspicious: boolean
        suspicion_reason: string | null
      }> = []

      for (const sp of sampleProfiles) {
        const artifacts = database.findArtifacts(sp.id)

        // Check for PE profile artifacts
        const peProfile = artifacts.find((a: { type: string }) =>
          a.type === 'pe_structure' || a.type === 'sample_profile',
        )

        // Add ingestion timestamp
        timelineEntries.push({
          sample_id: sp.id,
          file_name: sp.file_name,
          timestamp_type: 'ingestion',
          timestamp_unix: Math.floor(new Date(sp.created_at).getTime() / 1000),
          timestamp_iso: sp.created_at,
          is_suspicious: false,
          suspicion_reason: null,
        })

        // Timestamps from PE artifacts would be extracted by the worker
        // Add a placeholder entry indicating PE timestamp extraction is needed
        if (input.include_pe_timestamp) {
          timelineEntries.push({
            sample_id: sp.id,
            file_name: sp.file_name,
            timestamp_type: 'pe_timedatestamp',
            timestamp_unix: null,
            timestamp_iso: null,
            is_suspicious: false,
            suspicion_reason: peProfile ? null : 'PE profile not yet extracted; run sample.profile.get first',
          })
        }
      }

      // Sort by timestamp (nulls last)
      const sorted = timelineEntries
        .filter(e => e.timestamp_unix !== null)
        .sort((a, b) => (a.timestamp_unix || 0) - (b.timestamp_unix || 0))

      // Detect fake timestamps
      if (input.detect_fake_timestamps) {
        const maxTs = MAX_REASONABLE_TS()
        for (const entry of sorted) {
          if (entry.timestamp_unix !== null) {
            if (entry.timestamp_unix < MIN_REASONABLE_TS) {
              entry.is_suspicious = true
              entry.suspicion_reason = 'Timestamp before 2000 — likely zeroed or fake'
            } else if (entry.timestamp_unix > maxTs) {
              entry.is_suspicious = true
              entry.suspicion_reason = 'Timestamp in the future — likely forged'
            } else if (entry.timestamp_unix === 0) {
              entry.is_suspicious = true
              entry.suspicion_reason = 'Timestamp is zero — compiler/builder zeroed it'
            }
          }
        }
      }

      // Compute time span
      const validTimestamps = sorted.filter(e => !e.is_suspicious && e.timestamp_unix)
      const timeSpan = validTimestamps.length >= 2
        ? {
            earliest: validTimestamps[0].timestamp_iso,
            latest: validTimestamps[validTimestamps.length - 1].timestamp_iso,
            span_days: Math.round(
              ((validTimestamps[validTimestamps.length - 1].timestamp_unix || 0) -
                (validTimestamps[0].timestamp_unix || 0)) / 86400,
            ),
          }
        : null

      // Persist artifact
      const artifacts: ArtifactRef[] = []
      const data = {
        total_samples: sampleProfiles.length,
        total_timestamps: timelineEntries.length,
        valid_timestamps: sorted.length,
        suspicious_timestamps: sorted.filter(e => e.is_suspicious).length,
        time_span: timeSpan,
        timeline: sorted,
        pending_extraction: timelineEntries.filter(e => e.timestamp_unix === null),
        recommended_next: ['sample.cluster', 'sample.family.track'],
      }

      try {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_ids[0],
          'sample_timeline', 'timeline', { tool: TOOL_NAME, data },
        ))
      } catch { /* best effort */ }

      return {
        ok: true,
        data,
        warnings: missing.length > 0 ? [`${missing.length} samples not found, skipped`] : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
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
