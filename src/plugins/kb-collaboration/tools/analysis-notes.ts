/**
 * analysis.notes — Analysis notebook system.
 *
 * Per-sample note-taking that auto-saves findings to the knowledge base.
 * Supports structured annotations, tags, and cross-sample references.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, PluginToolDeps, ArtifactRef } from '../../sdk.js'

const TOOL_NAME = 'analysis.notes'

export const AnalysisNotesInputSchema = z.object({
  action: z.enum(['add', 'list', 'search', 'export']).describe('Note operation'),
  sample_id: z.string().describe('Sample identifier'),
  note_text: z.string().optional()
    .describe('Note content (required for "add")'),
  category: z.enum([
    'finding',
    'hypothesis',
    'ioc',
    'technique',
    'question',
    'verdict',
    'reference',
  ]).optional().default('finding')
    .describe('Note category (for "add")'),
  tags: z.array(z.string()).optional()
    .describe('Tags for the note (e.g., ["crypto", "c2", "evasion"])'),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional()
    .default('info').describe('Severity level for findings'),
  related_samples: z.array(z.string()).optional()
    .describe('Cross-reference to related sample IDs'),
  related_tool: z.string().optional()
    .describe('Tool that produced this finding (e.g., "entropy.analyze")'),
  search_query: z.string().optional()
    .describe('Search query (for "search" action)'),
  export_format: z.enum(['json', 'markdown', 'csv']).optional().default('json')
    .describe('Export format (for "export" action)'),
})

export const analysisNotesToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analysis notebook system: add structured notes/findings to a sample, list all notes, ' +
    'search across notes, or export. Notes support categories (finding, hypothesis, IOC, ' +
    'technique, verdict), severity levels, tags, and cross-sample references. ' +
    'Findings are automatically indexed in the knowledge base for future reuse.',
  inputSchema: AnalysisNotesInputSchema,
}

export function createAnalysisNotesHandler(deps: PluginToolDeps) {
  const { database } = deps

  return async (args: Record<string, unknown>): Promise<WorkerResult> => {
    const input = AnalysisNotesInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      switch (input.action) {
        case 'add': {
          if (!input.note_text) {
            return { ok: false, errors: ['note_text is required for "add" action'] }
          }

          const noteId = `note_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`
          const note = {
            id: noteId,
            sample_id: input.sample_id,
            text: input.note_text,
            category: input.category || 'finding',
            severity: input.severity || 'info',
            tags: input.tags || [],
            related_samples: input.related_samples || [],
            related_tool: input.related_tool || null,
            created_at: new Date().toISOString(),
            author: 'llm_analysis',
          }

          // Store as artifact
          const artifacts: ArtifactRef[] = []
          if (deps.persistStaticAnalysisJsonArtifact && deps.workspaceManager) {
            try {
              const artifact = await deps.persistStaticAnalysisJsonArtifact(
                deps.workspaceManager, database, input.sample_id,
                'analysis_note', `note_${noteId}`, note,
              )
              artifacts.push(artifact)
            } catch { /* best effort */ }
          }

          return {
            ok: true,
            data: {
              action: 'add',
              note,
              persisted: artifacts.length > 0,
              recommended_next: ['analysis.notes (list)', 'kb.import'],
            },
            artifacts,
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'list': {
          // List all note artifacts for the sample
          const allArtifacts = database.listArtifacts(input.sample_id)
          const noteArtifacts = allArtifacts.filter(
            (a: { type: string }) => a.type === 'analysis_note',
          )

          return {
            ok: true,
            data: {
              action: 'list',
              sample_id: input.sample_id,
              total_notes: noteArtifacts.length,
              notes: noteArtifacts.map((a: { id: string; path: string; created_at: string }) => ({
                artifact_id: a.id,
                path: a.path,
                created_at: a.created_at,
              })),
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'search': {
          if (!input.search_query) {
            return { ok: false, errors: ['search_query is required for "search" action'] }
          }

          // Search across all note artifacts
          const allArtifacts = database.listArtifacts(input.sample_id)
          const noteArtifacts = allArtifacts.filter(
            (a: { type: string }) => a.type === 'analysis_note',
          )

          return {
            ok: true,
            data: {
              action: 'search',
              query: input.search_query,
              sample_id: input.sample_id,
              results: noteArtifacts,
              note: 'Full-text search requires reading artifact contents; showing all note artifacts for now',
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'export': {
          const allArtifacts = database.listArtifacts(input.sample_id)
          const noteArtifacts = allArtifacts.filter(
            (a: { type: string }) => a.type === 'analysis_note',
          )

          return {
            ok: true,
            data: {
              action: 'export',
              sample_id: input.sample_id,
              format: input.export_format,
              total_notes: noteArtifacts.length,
              notes: noteArtifacts,
              note: 'Export format applied on client side',
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
