/**
 * macho.structure.analyze MCP tool — analyze Mach-O binary structure.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import { resolvePackagePath } from '../../../runtime-paths.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'
import { runAbortableProcess } from '../../../worker/abortable-process.js'
import { throwIfAnalysisAborted } from '../../../analysis/analysis-cancellation.js'
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

interface MachoStructureAnalyzeDependencies {
  runProcess?: typeof runAbortableProcess
}

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
  database: DatabaseManager,
  dependencies: MachoStructureAnalyzeDependencies = {}
) {
  return async (
    args: z.infer<typeof MachoStructureAnalyzeInputSchema>,
    abortSignal?: AbortSignal
  ): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      throwIfAnalysisAborted(abortSignal)
      const sample = database.findSample(args.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)
      throwIfAnalysisAborted(abortSignal)

      const result = await callElfMachoWorker(
        { action: 'parse_macho', file_path: samplePath },
        abortSignal,
        dependencies.runProcess
      )
      throwIfAnalysisAborted(abortSignal)

      if (!result.ok) {
        return { ok: false, errors: [String(result.error || 'Mach-O parsing failed')] }
      }

      const enriched = enrichMachoStructureResult(result, { sampleId: args.sample_id })
      const artifacts: ArtifactRef[] = []
      try {
        throwIfAnalysisAborted(abortSignal)
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          MACHO_STRUCTURE_ARTIFACT_TYPE,
          'macho-structure',
          enriched
        )
        throwIfAnalysisAborted(abortSignal)
        if (artRef) artifacts.push(artRef)
      } catch {
        throwIfAnalysisAborted(abortSignal)
        // non-fatal
      }

      return {
        ok: true,
        data: enriched,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      throwIfAnalysisAborted(abortSignal)
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}

async function callElfMachoWorker(
  request: Record<string, unknown>,
  abortSignal?: AbortSignal,
  runProcess: typeof runAbortableProcess = runAbortableProcess
): Promise<Record<string, unknown>> {
  const workerPath = resolvePackagePath(
    'src',
    'plugins',
    'elf-macho',
    'workers',
    'elf_macho_worker.py'
  )
  const result = await runProcess({
    command: getPythonCommand(),
    args: [workerPath],
    cwd: process.cwd(),
    stdin: `${JSON.stringify(request)}\n`,
    timeoutMs: 120_000,
    abortSignal,
  })
  if (result.timedOut) {
    throw new Error('ELF/Mach-O worker timed out')
  }
  if (result.exitCode !== 0) {
    throw new Error(
      `ELF/Mach-O worker exited with code ${result.exitCode ?? 'unknown'}: ${result.stderr}`
    )
  }
  try {
    const lines = result.stdout.trim().split('\n')
    return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>
  } catch (error) {
    throw new Error(`Failed to parse worker response: ${(error as Error).message}`)
  }
}
