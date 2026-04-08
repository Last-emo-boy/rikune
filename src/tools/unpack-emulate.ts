/**
 * unpack.emulate — Emulation-based unpacking with OEP search.
 *
 * Uses Speakeasy / Unicorn / Qiling to emulate packed binaries,
 * detect the Original Entry Point (OEP), and dump the unpacked image.
 * Supports Themida, VMProtect, custom packers.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from './static-worker-client.js'

const TOOL_NAME = 'unpack.emulate'
const TOOL_VERSION = '0.1.0'

export const UnpackEmulateInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  engine: z.enum(['speakeasy', 'unicorn', 'qiling', 'auto']).default('auto')
    .describe('Emulation engine to use. "auto" selects based on packer detection.'),
  max_instructions: z.number().int().min(1000).max(50_000_000).default(5_000_000)
    .describe('Max instructions to emulate before timeout'),
  oep_heuristic: z.enum(['tail_jump', 'section_transfer', 'api_resolve', 'all']).default('all')
    .describe('OEP detection heuristic'),
  dump_memory: z.boolean().default(true)
    .describe('Dump the unpacked PE image from memory after OEP is found'),
  force_refresh: z.boolean().default(false),
})
export type UnpackEmulateInput = z.infer<typeof UnpackEmulateInputSchema>

export const unpackEmulateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Emulation-based unpacking: run a packed binary in Speakeasy/Unicorn/Qiling, ' +
    'detect the Original Entry Point (OEP) via tail-jump/section-transfer/API-resolve ' +
    'heuristics, and dump the unpacked PE image. Supports Themida, VMProtect, UPX, ' +
    'MPRESS, Enigma, and custom packers.',
  inputSchema: UnpackEmulateInputSchema,
}

// ── OEP heuristic strategies ──────────────────────────────────────────────
interface OepStrategy {
  name: string
  description: string
  indicators: string[]
}

const OEP_STRATEGIES: Record<string, OepStrategy> = {
  tail_jump: {
    name: 'Tail Jump Detection',
    description: 'Monitor for far JMP/CALL to a previously non-executed code section',
    indicators: ['jmp_to_new_section', 'call_to_oep_region', 'stub_exit_pattern'],
  },
  section_transfer: {
    name: 'Section Transfer Detection',
    description: 'Detect execution flow transferring from unpacking stub (.text0) to original .text',
    indicators: ['section_boundary_cross', 'rw_to_rx_transition', 'vad_protection_change'],
  },
  api_resolve: {
    name: 'API Resolution Detection',
    description: 'OEP reached when IAT is fully resolved and GetProcAddress calls stop',
    indicators: ['iat_populated', 'getprocaddress_burst_end', 'loadlibrary_complete'],
  },
}

// ── Engine capabilities ───────────────────────────────────────────────────
const ENGINE_CAPS: Record<string, { supports: string[]; speed: string }> = {
  speakeasy: { supports: ['PE32', 'PE64', 'shellcode'], speed: 'fast' },
  unicorn: { supports: ['PE32', 'PE64', 'shellcode', 'ELF'], speed: 'medium' },
  qiling: { supports: ['PE32', 'PE64', 'ELF', 'Mach-O', 'shellcode'], speed: 'slow' },
}

export function createUnpackEmulateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = UnpackEmulateInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)

      // Select engine based on prior packer detection if auto
      let engine = input.engine
      if (engine === 'auto') {
        engine = 'speakeasy' // Default; Python backend will refine
      }

      const activeStrategies = input.oep_heuristic === 'all'
        ? Object.keys(OEP_STRATEGIES)
        : [input.oep_heuristic]

      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          engine,
          max_instructions: input.max_instructions,
          oep_heuristics: activeStrategies,
          dump_memory: input.dump_memory,
        },
        toolVersion: TOOL_VERSION,
      })
      const workerResponse = await callPooledStaticWorker(workerRequest, { database })

      if (!workerResponse.ok) {
        return {
          ok: false,
          errors: workerResponse.errors,
          warnings: workerResponse.warnings,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const data = workerResponse.data as Record<string, unknown>

      // Persist artifact
      const artifacts: ArtifactRef[] = []
      try {
        const artifact = await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_id,
          'unpack_emulate', 'emulation_unpack', { tool: TOOL_NAME, data },
        )
        artifacts.push(artifact)
      } catch { /* best effort */ }

      return {
        ok: true,
        data: {
          ...data,
          engine_used: engine,
          engine_capabilities: ENGINE_CAPS[engine] || null,
          oep_strategies_applied: activeStrategies.map(s => OEP_STRATEGIES[s]),
          recommended_next: data.oep_found
            ? ['unpack.reingest', 'workflow.analyze.start']
            : ['unpack.guide', 'debug.session.start'],
        },
        warnings: workerResponse.warnings,
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
