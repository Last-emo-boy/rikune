/**
 * elf.structure.analyze MCP tool — analyze ELF binary structure.
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
  ELF_STRUCTURE_ARTIFACT_TYPE,
  ELF_STRUCTURE_WORKFLOW_RECIPES,
  buildElfMachoWorkerBackend,
  enrichElfStructureResult,
} from '../elf-macho-metadata.js'

const TOOL_NAME = 'elf.structure.analyze'

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
  database: DatabaseManager
) {
  return async (args: z.infer<typeof ElfStructureAnalyzeInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()

    try {
      const sample = database.findSample(args.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${args.sample_id}`] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, args.sample_id)

      const result = await callElfMachoWorker({ action: 'parse_elf', file_path: samplePath })

      if (!result.ok) {
        return { ok: false, errors: [String(result.error || 'ELF parsing failed')] }
      }

      const enriched = enrichElfStructureResult(result, { sampleId: args.sample_id })
      const artifacts: ArtifactRef[] = []
      try {
        const artRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          args.sample_id,
          ELF_STRUCTURE_ARTIFACT_TYPE,
          'elf-structure',
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
