/**
 * code.function.decompile MCP Tool
 * 
 * Requirements: 10.1, 10.2, 10.3, 10.4
 * 
 * Decompiles a specific function to pseudocode
 */

import { z } from 'zod';
import type { ToolDefinition, ToolHandler, ToolResult } from '../../../types.js';
import type { DatabaseManager } from '../../../database.js';
import type { WorkspaceManager } from '../../../workspace-manager.js';
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError } from '../../../worker/decompiler-worker.js';
import { logger } from '../../../logger.js';

/**
 * Input schema for code.function.decompile tool
 */
export const codeFunctionDecompileInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  address: z.string().optional().describe('Function address (hex string, e.g., "0x00401000")'),
  symbol: z.string().optional().describe('Function symbol name'),
  include_xrefs: z.boolean().optional().describe('Include cross-references (default: false)'),
  timeout: z.number().optional().describe('Timeout in seconds (default: 30)')
}).refine(data => data.address || data.symbol, {
  message: 'Either address or symbol must be provided'
});

export type CodeFunctionDecompileInput = z.infer<typeof codeFunctionDecompileInputSchema>;

/**
 * Tool definition for code.function.decompile
 */
export const codeFunctionDecompileToolDefinition: ToolDefinition = {
  name: 'code.function.decompile',
  description: 'Decompile a specific function to pseudocode. Requires prior Ghidra analysis. Provide either address or symbol name.',
  inputSchema: codeFunctionDecompileInputSchema
};

/**
 * Create handler for code.function.decompile tool
 */
export function createCodeFunctionDecompileHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = codeFunctionDecompileInputSchema.parse(args);

      const addressOrSymbol = input.address || input.symbol!;

      logger.info({
        sample_id: input.sample_id,
        address_or_symbol: addressOrSymbol,
        include_xrefs: input.include_xrefs
      }, 'code.function.decompile tool called');

      // Check if sample exists
      const sample = database.findSample(input.sample_id);
      if (!sample) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: false,
              errors: [`Sample not found: ${input.sample_id}`]
            }, null, 2)
          }],
          isError: true
        };
      }

      // Create decompiler worker
      const decompilerWorker = new DecompilerWorker(database, workspaceManager);

      // Convert timeout from seconds to milliseconds
      const timeoutMs = (input.timeout || 30) * 1000;

      // Decompile function
      const result = await decompilerWorker.decompileFunction(
        input.sample_id,
        addressOrSymbol,
        input.include_xrefs || false,
        timeoutMs
      );

      logger.info({
        sample_id: input.sample_id,
        function: result.function,
        address: result.address
      }, 'Function decompiled successfully');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            data: result
          }, null, 2)
        }]
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const diagnostics = getGhidraDiagnostics(error);
      const normalizedError = normalizeGhidraError(error, 'code.function.decompile');
      logger.error({
        error: errorMessage,
        ghidra_diagnostics: diagnostics,
        normalized_error: normalizedError,
      }, 'code.function.decompile tool failed');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: false,
            errors: [errorMessage],
            diagnostics,
            normalized_error: normalizedError,
          }, null, 2)
        }],
        isError: true
      };
    }
  };
}
