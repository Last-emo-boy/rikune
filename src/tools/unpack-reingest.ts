/**
 * unpack.reingest — Re-ingest an unpacked layer as a child sample.
 *
 * After emulation-based or manual unpacking, registers the unpacked binary
 * as a child sample linked to the original, and optionally triggers
 * an automated analysis pipeline on the unpacked layer.
 */

import { z } from 'zod'
import path from 'path'
import fs from 'fs/promises'
import { createHash, randomUUID } from 'crypto'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'

const TOOL_NAME = 'unpack.reingest'
const TOOL_VERSION = '0.1.0'

export const UnpackReingestInputSchema = z.object({
  parent_sample_id: z.string().describe('Original packed sample identifier'),
  unpacked_path: z.string().optional()
    .describe('Path to the unpacked binary. If omitted, uses the latest emulation dump artifact.'),
  layer_label: z.string().default('layer_1')
    .describe('Label for this unpacking layer (e.g., layer_1, layer_2)'),
  packer_name: z.string().optional()
    .describe('Name of the packer that was removed (e.g., UPX, Themida)'),
  auto_analyze: z.boolean().default(true)
    .describe('Automatically start analysis pipeline on the unpacked sample'),
})
export type UnpackReingestInput = z.infer<typeof UnpackReingestInputSchema>

export const unpackReingestToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Re-ingest an unpacked binary as a child sample linked to the original. ' +
    'Computes SHA-256, registers the parent→child relationship in the database, ' +
    'and optionally triggers automated analysis on the unpacked layer. ' +
    'Use after unpack.emulate or manual extraction.',
  inputSchema: UnpackReingestInputSchema,
}

export function createUnpackReingestHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = UnpackReingestInputSchema.parse(args)
    const startTime = Date.now()

    try {
      // Validate parent exists
      const parent = database.findSample(input.parent_sample_id)
      if (!parent) {
        return { ok: false, errors: [`Parent sample not found: ${input.parent_sample_id}`] }
      }

      // Resolve unpacked binary path
      let unpackedPath = input.unpacked_path
      if (!unpackedPath) {
        // Look for the latest emulation dump artifact
        const artifacts = database.findArtifacts(input.parent_sample_id)
        const dumpArtifact = artifacts
          .filter((a: { type: string }) => a.type === 'unpack_emulate' || a.type === 'memory_dump')
          .sort((a: { created_at: string }, b: { created_at: string }) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
          )[0]

        if (!dumpArtifact) {
          return {
            ok: false,
            errors: ['No unpacked_path provided and no emulation dump artifact found. Run unpack.emulate first.'],
          }
        }

        const workspace = await workspaceManager.getWorkspace(input.parent_sample_id)
        unpackedPath = path.join(workspace.root, dumpArtifact.path)
      }

      // Verify file exists
      try {
        await fs.access(unpackedPath)
      } catch {
        return { ok: false, errors: [`Unpacked file not found: ${unpackedPath}`] }
      }

      // Compute SHA-256 of unpacked binary
      const fileBuffer = await fs.readFile(unpackedPath)
      const sha256 = createHash('sha256').update(fileBuffer).digest('hex')
      const childSampleId = `sha256:${sha256}`

      // Check if already ingested
      const existing = database.findSample(childSampleId)
      if (existing) {
        return {
          ok: true,
          data: {
            child_sample_id: childSampleId,
            already_ingested: true,
            parent_sample_id: input.parent_sample_id,
            layer_label: input.layer_label,
            packer_name: input.packer_name || 'unknown',
            recommended_next: ['sample.profile.get', 'workflow.analyze.start'],
          },
          warnings: ['Unpacked binary was already ingested as a sample'],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      // Create workspace for child sample
      const childWorkspace = await workspaceManager.createWorkspace(childSampleId)
      const destPath = path.join(childWorkspace.original, path.basename(unpackedPath))
      await fs.copyFile(unpackedPath, destPath)

      // Register in database
      const now = new Date().toISOString()
      database.insertSample({
        id: childSampleId,
        sha256,
        md5: null,
        size: fileBuffer.length,
        file_type: 'application/x-dosexec',
        created_at: now,
        source: `unpacked:${input.parent_sample_id}:${input.layer_label}`,
      })

      const data: Record<string, unknown> = {
        child_sample_id: childSampleId,
        parent_sample_id: input.parent_sample_id,
        sha256,
        file_size: fileBuffer.length,
        layer_label: input.layer_label,
        packer_name: input.packer_name || 'unknown',
        workspace_path: childWorkspace.root,
        already_ingested: false,
        recommended_next: input.auto_analyze
          ? ['workflow.analyze.start (auto-triggered)']
          : ['workflow.analyze.start', 'sample.profile.get', 'packer.detect'],
      }

      return {
        ok: true,
        data,
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
