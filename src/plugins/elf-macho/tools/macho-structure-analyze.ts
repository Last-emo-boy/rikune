/**
 * macho.structure.analyze MCP tool — analyze Mach-O binary structure.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type { ToolDefinition, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import { resolvePackagePath } from '../../../runtime-paths.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'
import {
  ELF_MACHO_CAPABILITIES,
  ELF_MACHO_EVIDENCE,
  ELF_MACHO_RUNTIME_POLICY,
  ELF_MACHO_SAFETY,
  MACHO_STRUCTURE_ARTIFACT_TYPE,
  MACHO_STRUCTURE_WORKFLOW_RECIPES,
  buildElfMachoWorkerBackend,
  enrichMachoStructureResult,
} from '../elf-macho-metadata.js'

const TOOL_NAME = 'macho.structure.analyze'

export const MachoStructureAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
})

export const MachoStructureAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const machoStructureAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze Mach-O binary structure: load commands, sections, symbols. Handles fat (universal) binaries by listing all architectures.',
  inputSchema: MachoStructureAnalyzeInputSchema,
  outputSchema: MachoStructureAnalyzeOutputSchema,
  aspects: {
    formats: [
      'macho',
      'fat',
      'universal',
      'macho-object',
      'dylib',
      'framework',
      'app-bundle',
      'dsym',
    ],
    platforms: ['macos', 'ios'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage'],
    safety: ELF_MACHO_SAFETY,
    capabilities: ELF_MACHO_CAPABILITIES,
    evidence: ELF_MACHO_EVIDENCE,
  },
  artifacts: [
    {
      type: MACHO_STRUCTURE_ARTIFACT_TYPE,
      description: 'Mach-O load commands, segments, sections, symbols, and universal slices',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [MACHO_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [MACHO_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'imports', artifactTypes: [MACHO_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'exports', artifactTypes: [MACHO_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [MACHO_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [MACHO_STRUCTURE_ARTIFACT_TYPE] },
  ],
  workflowRecipes: MACHO_STRUCTURE_WORKFLOW_RECIPES,
  runtimePolicy: ELF_MACHO_RUNTIME_POLICY,
  workerBackend: buildElfMachoWorkerBackend([MACHO_STRUCTURE_ARTIFACT_TYPE]),
}

export function createMachoStructureAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: z.infer<typeof MachoStructureAnalyzeInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)

      const result = await callElfMachoWorker({ action: 'parse_macho', file_path: samplePath })

      if (!result.ok) {
        return { ok: false, errors: [String(result.error || 'Mach-O parsing failed')] }
      }

      const enriched = enrichMachoStructureResult(result, { sampleId: args.sample_id })
      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          MACHO_STRUCTURE_ARTIFACT_TYPE,
          'macho-structure',
          enriched
        )
        if (artRef) artifacts.push(artRef)
      } catch {
        // non-fatal
      }

      return {
        ok: true,
        data: enriched,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}

async function callElfMachoWorker(
  request: Record<string, unknown>
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const workerPath = resolvePackagePath(
      'src',
      'plugins',
      'elf-macho',
      'workers',
      'elf_macho_worker.py'
    )
    const pythonCommand = getPythonCommand()
    const proc = spawn(pythonCommand, [workerPath], { stdio: ['pipe', 'pipe', 'pipe'] })

    let stdout = ''
    let stderr = ''

    proc.stdout.on('data', (d) => {
      stdout += d.toString()
    })
    proc.stderr.on('data', (d) => {
      stderr += d.toString()
    })

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`ELF/Mach-O worker exited with code ${code}: ${stderr}`))
        return
      }
      try {
        const lines = stdout.trim().split('\n')
        resolve(JSON.parse(lines[lines.length - 1]))
      } catch (e) {
        reject(new Error(`Failed to parse worker response: ${(e as Error).message}`))
      }
    })

    proc.on('error', (e) => reject(new Error(`Failed to spawn worker: ${e.message}`)))

    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}
