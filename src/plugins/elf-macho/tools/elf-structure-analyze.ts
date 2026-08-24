/**
 * elf.structure.analyze MCP tool — analyze ELF binary structure.
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
  ELF_STRUCTURE_ARTIFACT_TYPE,
  ELF_STRUCTURE_WORKFLOW_RECIPES,
  buildElfMachoWorkerBackend,
  enrichElfStructureResult,
} from '../elf-macho-metadata.js'

const TOOL_NAME = 'elf.structure.analyze'

interface ElfStructureAnalyzeDependencies {
  runProcess?: typeof runAbortableProcess
}

export const ElfStructureAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
})

export const ElfStructureAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const elfStructureAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze ELF binary structure: headers, sections, segments, symbols, dynamic entries.',
  inputSchema: ElfStructureAnalyzeInputSchema,
  outputSchema: ElfStructureAnalyzeOutputSchema,
  aspects: {
    formats: ['elf', 'so', 'core', 'elf-core', 'elf-object', 'linux-kernel-module', 'dwarf'],
    platforms: ['linux'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    safety: ELF_MACHO_SAFETY,
    capabilities: ELF_MACHO_CAPABILITIES,
    evidence: ELF_MACHO_EVIDENCE,
  },
  artifacts: [
    {
      type: ELF_STRUCTURE_ARTIFACT_TYPE,
      description: 'ELF headers, sections, segments, symbols, dynamic entries, and notes',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [ELF_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'symbols', artifactTypes: [ELF_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'imports', artifactTypes: [ELF_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'exports', artifactTypes: [ELF_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [ELF_STRUCTURE_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [ELF_STRUCTURE_ARTIFACT_TYPE] },
  ],
  workflowRecipes: ELF_STRUCTURE_WORKFLOW_RECIPES,
  runtimePolicy: ELF_MACHO_RUNTIME_POLICY,
  workerBackend: buildElfMachoWorkerBackend([ELF_STRUCTURE_ARTIFACT_TYPE]),
}

export function createElfStructureAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies: ElfStructureAnalyzeDependencies = {}
) {
  return async (
    args: z.infer<typeof ElfStructureAnalyzeInputSchema>,
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
        { action: 'parse_elf', file_path: samplePath },
        abortSignal,
        dependencies.runProcess
      )
      throwIfAnalysisAborted(abortSignal)

      if (!result.ok) {
        return { ok: false, errors: [String(result.error || 'ELF parsing failed')] }
      }

      const enriched = enrichElfStructureResult(result, { sampleId: args.sample_id })
      const artifacts: ArtifactRef[] = []
      try {
        throwIfAnalysisAborted(abortSignal)
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          ELF_STRUCTURE_ARTIFACT_TYPE,
          'elf-structure',
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
