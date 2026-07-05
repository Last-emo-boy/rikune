/**
 * vm.opcode.extract MCP tool — extract opcode table from VM dispatch function.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'
import { buildOpcodeTable } from '../vm/opcode-extractor.js'
import {
  codeFromFunctionRecord,
  functionRecordsFromPayload,
  normalizeAddress,
  parseJsonLike,
} from './vm-function-evidence.js'

const TOOL_NAME = 'vm.opcode.extract'

export const vmOpcodeExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  function_name: z
    .string()
    .optional()
    .describe('Name of the VM dispatcher function to analyze (auto-detected if omitted)'),
  function_address: z.string().optional().describe('Address of the VM dispatcher function'),
  decompiled_code: z
    .string()
    .optional()
    .describe('Optional decompiled dispatcher code when the function body is not persisted yet'),
})

export const vmOpcodeExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.any().optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const vmOpcodeExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract the opcode table from a VM dispatch function. Parses switch/case handlers, classifies semantic categories (arithmetic, logic, memory, control flow), and detects instruction formats.',
  inputSchema: vmOpcodeExtractInputSchema,
  outputSchema: vmOpcodeExtractOutputSchema,
}

export function createVmOpcodeExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const input = vmOpcodeExtractInputSchema.parse(args)
    const warnings: string[] = []

    const sample = database.findSample(input.sample_id)
    if (!sample) {
      return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
    }

    // Find the dispatcher function from analysis evidence
    const evidence = database.findAnalysisEvidenceBySample(input.sample_id)
    let dispatcherCode = input.decompiled_code ?? ''
    let dispatcherName = input.function_name ?? ''
    const requestedAddress = normalizeAddress(input.function_address)

    if (Array.isArray(evidence)) {
      // First try VM detection results for auto-detected dispatcher
      for (const entry of evidence) {
        if (entry.evidence_family === 'vm_detection') {
          const data = parseJsonLike(entry.result_json) as
            | { candidates?: Array<{ function?: string }> }
            | undefined
          if (data?.candidates?.length && !input.function_name) {
            dispatcherName = data.candidates[0]?.function ?? ''
          }
        }
      }

      // Then find the decompiled code for that function
      for (const entry of evidence) {
        const family = entry.evidence_family ?? ''
        if (
          family === 'function_map' ||
          family === 'decompilation' ||
          family === 'functions' ||
          family === 'function_decompile'
        ) {
          const data = parseJsonLike(entry.result_json)
          if (!data) continue

          for (const obj of functionRecordsFromPayload(data)) {
            const name = String(obj.name ?? obj.function_name ?? obj.function ?? '')
            const addr = normalizeAddress(obj.address ?? obj.offset ?? obj.addr)

            if (
              (input.function_name && name === input.function_name) ||
              (requestedAddress && addr === requestedAddress) ||
              (dispatcherName && name === dispatcherName)
            ) {
              dispatcherCode = codeFromFunctionRecord(obj)
              if (!dispatcherName) dispatcherName = name
              break
            }
          }
        }
        if (dispatcherCode) break
      }
    }

    if (!dispatcherCode) {
      if (requestedAddress && typeof database.findFunctions === 'function') {
        const indexed = database
          .findFunctions(input.sample_id)
          .find((fn) => normalizeAddress(fn.address) === requestedAddress)
        if (indexed?.name && !dispatcherName) {
          dispatcherName = indexed.name
        }
      }
      return {
        ok: false,
        errors: [
          `Could not find decompiled dispatcher function${dispatcherName ? ` '${dispatcherName}'` : ''}. Run vm.detect/code.function.decompile first, specify function_name/function_address, or pass decompiled_code directly.`,
        ],
      }
    }

    const opcodeTable = buildOpcodeTable(dispatcherCode)

    const result = {
      dispatcher_function: dispatcherName,
      opcode_table: opcodeTable,
      entry_count: opcodeTable.length,
      semantic_categories: Object.fromEntries(
        opcodeTable.reduce((acc, e) => {
          acc.set(e.semanticCategory, (acc.get(e.semanticCategory) ?? 0) + 1)
          return acc
        }, new Map<string, number>())
      ),
    }

    // Persist
    const artifacts: ArtifactRef[] = []
    try {
      const ref = await persistStaticAnalysisJsonArtifact(
        workspaceManager,
        database,
        input.sample_id,
        'vm_opcode_table',
        'opcode_table',
        result
      )
      artifacts.push(ref)
    } catch {
      warnings.push('Failed to persist opcode table artifact')
    }

    return {
      ok: true,
      data: result,
      warnings: warnings.length > 0 ? warnings : undefined,
      artifacts,
      metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
    }
  }
}
