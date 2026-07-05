/**
 * code.function.disassemble MCP Tool
 *
 * Returns assembly code for a function
 */

import { z } from 'zod'
import fs from 'fs/promises'
import path from 'path'
import type { ToolDefinition, ToolHandler, ToolResult } from '../../../types.js'
import type { DatabaseManager } from '../../../database.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import {
  DecompilerWorker,
  getGhidraDiagnostics,
  normalizeGhidraError,
} from '../../../worker/decompiler-worker.js'
import { runEntrypointFallbackDisasm } from '../../../tools/entrypoint-fallback-disasm.js'
import { logger } from '../../../logger.js'
import { CODE_FUNCTION_DISASSEMBLE_METADATA } from './code-analysis-metadata.js'

/**
 * Input schema for code.function.disassemble tool
 */
export const codeFunctionDisassembleInputSchema = z
  .object({
    sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
    address: z.string().optional().describe('Function address (hex string)'),
    symbol: z.string().optional().describe('Function symbol name'),
  })
  .refine((data) => data.address || data.symbol, {
    message: 'Either address or symbol must be provided',
  })

export type CodeFunctionDisassembleInput = z.infer<typeof codeFunctionDisassembleInputSchema>

export const codeFunctionDisassembleOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      function: z.string(),
      address: z.string(),
      assembly: z.string(),
      fallback: z.boolean(),
      fallback_metadata: z
        .object({
          backend: z.string(),
          parser: z.string(),
          entry_section: z.string(),
          resolved_from: z.string().optional(),
          requested_address: z.string().nullable().optional(),
        })
        .passthrough()
        .optional(),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  diagnostics: z.any().optional(),
  normalized_error: z.any().optional(),
})

/**
 * Tool definition for code.function.disassemble
 */
export const codeFunctionDisassembleToolDefinition: ToolDefinition = {
  name: 'code.function.disassemble',
  description:
    'Get assembly code for a function. Requires prior Ghidra analysis. Provide either address or symbol name.',
  inputSchema: codeFunctionDisassembleInputSchema,
  outputSchema: codeFunctionDisassembleOutputSchema,
  ...CODE_FUNCTION_DISASSEMBLE_METADATA,
}

function normalizeAddress(address: string | undefined): string | undefined {
  if (!address) {
    return undefined
  }
  const trimmed = address.trim()
  if (!trimmed) {
    return undefined
  }
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    return `0x${trimmed.slice(2).toLowerCase()}`
  }
  if (/^[0-9a-fA-F]+$/.test(trimmed)) {
    return `0x${trimmed.toLowerCase()}`
  }
  return undefined
}

function hasOperandPoorDisassembly(assembly: string): boolean {
  const lines = assembly
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith(';'))

  if (lines.length < 8) {
    return false
  }

  const binaryOperandMnemonics = new Set([
    'adc',
    'add',
    'and',
    'cmp',
    'imul',
    'lea',
    'mov',
    'or',
    'sbb',
    'sub',
    'test',
    'xor',
  ])

  let suspectBinaryOperands = 0
  for (const line of lines) {
    const [mnemonic, ...operands] = line.split(/\s+/)
    if (!mnemonic || !binaryOperandMnemonics.has(mnemonic.toLowerCase())) {
      continue
    }
    if (!operands.join(' ').includes(',')) {
      suspectBinaryOperands += 1
    }
  }

  return suspectBinaryOperands >= 4 && suspectBinaryOperands / lines.length >= 0.25
}

async function resolveSamplePath(originalDir: string): Promise<string> {
  const entries = await fs.readdir(originalDir, { withFileTypes: true })
  const files = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort((a, b) => a.localeCompare(b))

  if (files.length === 0) {
    throw new Error(`Sample file not found in workspace: ${originalDir}`)
  }

  return path.join(originalDir, files[0])
}

/**
 * Create handler for code.function.disassemble tool
 */
export function createCodeFunctionDisassembleHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = codeFunctionDisassembleInputSchema.parse(args)

      const addressOrSymbol = input.address || input.symbol

      logger.info(
        {
          sample_id: input.sample_id,
          address_or_symbol: addressOrSymbol,
        },
        'code.function.disassemble tool called'
      )

      // Check if sample exists
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ok: false,
                  errors: [`Sample not found: ${input.sample_id}`],
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        }
      }

      // For now, return a placeholder indicating this feature uses CFG
      // In a full implementation, this would extract assembly from Ghidra
      const decompilerWorker = new DecompilerWorker(database, workspaceManager)

      let functionName = ''
      let functionAddress = ''
      let assemblyText = ''
      let warnings: string[] | undefined
      let requestedAddress = normalizeAddress(input.address)
      if (!requestedAddress && input.symbol && typeof database.findFunctions === 'function') {
        const matched = database
          .findFunctions(input.sample_id)
          .find((item) => item.name?.toLowerCase() === input.symbol?.toLowerCase())
        if (matched?.address) {
          requestedAddress = normalizeAddress(matched.address) || matched.address
        }
      }
      let fallbackMetadata:
        | {
            backend: string
            parser: string
            entry_section: string
            resolved_from?: string
            requested_address?: string | null
          }
        | undefined

      const runFallback = async (reason: string) => {
        const workspace = await workspaceManager.getWorkspace(input.sample_id)
        const samplePath = await resolveSamplePath(workspace.original)
        const fallback = await runEntrypointFallbackDisasm(samplePath, {
          max_instructions: 140,
          max_bytes: 1536,
          target_address: requestedAddress,
          target_symbol: input.symbol,
        })
        functionName = fallback.result.function
        functionAddress = fallback.result.address
        assemblyText = fallback.result.assembly
        fallbackMetadata = {
          backend: fallback.result.backend,
          parser: fallback.result.parser,
          entry_section: fallback.result.entry_section,
          resolved_from: fallback.result.resolved_from,
          requested_address: fallback.result.requested_address,
        }
        warnings = [reason, ...(fallback.warnings || [])]
      }

      try {
        // Primary path: use CFG generated by Ghidra
        const cfg = await decompilerWorker.getFunctionCFG(input.sample_id, addressOrSymbol)
        const assembly: string[] = []
        for (const node of cfg.nodes) {
          assembly.push(`; Block ${node.id} (${node.type})`)
          assembly.push(...node.instructions)
          assembly.push('')
        }
        functionName = cfg.function
        functionAddress = cfg.address
        assemblyText = assembly.join('\n')
        if (hasOperandPoorDisassembly(assemblyText)) {
          await runFallback(
            'Ghidra CFG disassembly appears to omit operands; static fallback used for operand-complete listing.'
          )
        }
      } catch (primaryError) {
        // Secondary path: fallback disassembly around PE entrypoint
        await runFallback(
          `Ghidra disassembly unavailable, fallback used: ${
            primaryError instanceof Error ? primaryError.message : String(primaryError)
          }`
        )
      }

      logger.info(
        {
          sample_id: input.sample_id,
          function: functionName,
          instruction_count: assemblyText.split('\n').filter((line) => line.length > 0).length,
          fallback: Boolean(fallbackMetadata),
        },
        'Function disassembled successfully'
      )

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: true,
                data: {
                  function: functionName,
                  address: functionAddress,
                  assembly: assemblyText,
                  fallback: Boolean(fallbackMetadata),
                  fallback_metadata: fallbackMetadata,
                },
                warnings,
              },
              null,
              2
            ),
          },
        ],
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      const diagnostics = getGhidraDiagnostics(error)
      const normalizedError = normalizeGhidraError(error, 'code.function.disassemble')
      logger.error(
        {
          error: errorMessage,
          ghidra_diagnostics: diagnostics,
          normalized_error: normalizedError,
        },
        'code.function.disassemble tool failed'
      )

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ok: false,
                errors: [errorMessage],
                diagnostics,
                normalized_error: normalizedError,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      }
    }
  }
}
