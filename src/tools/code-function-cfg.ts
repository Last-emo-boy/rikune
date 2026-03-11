/**
 * code.function.cfg MCP Tool
 * 
 * Requirements: 11.1, 11.2, 11.3, 11.4
 * 
 * Extracts control flow graph for a function
 */

import { z } from 'zod';
import type { ToolDefinition, ToolResult, ToolHandler } from '../types.js';
import type { DatabaseManager } from '../database.js';
import type { WorkspaceManager } from '../workspace-manager.js';
import { DecompilerWorker, getGhidraDiagnostics, normalizeGhidraError } from '../decompiler-worker.js';
import { logger } from '../logger.js';

/**
 * Input schema for code.function.cfg tool
 */
export const codeFunctionCFGInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  address: z.string().optional().describe('Function address (hex string)'),
  symbol: z.string().optional().describe('Function symbol name'),
  timeout: z.number().optional().describe('Timeout in seconds (default: 30)')
}).refine(data => data.address || data.symbol, {
  message: 'Either address or symbol must be provided'
});

export type CodeFunctionCFGInput = z.infer<typeof codeFunctionCFGInputSchema>;

/**
 * Tool definition for code.function.cfg
 */
export const codeFunctionCFGToolDefinition: ToolDefinition = {
  name: 'code.function.cfg',
  description: 'Extract control flow graph (CFG) for a function. Returns nodes (basic blocks) and edges (control flow). Requires prior Ghidra analysis.',
  inputSchema: codeFunctionCFGInputSchema
};

/**
 * Create handler for code.function.cfg tool
 */
export function createCodeFunctionCFGHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
): ToolHandler {
  return async (args: unknown): Promise<ToolResult> => {
    try {
      const input = codeFunctionCFGInputSchema.parse(args);

      const addressOrSymbol = input.address || input.symbol!;

      logger.info({
        sample_id: input.sample_id,
        address_or_symbol: addressOrSymbol
      }, 'code.function.cfg tool called');

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

      // Extract CFG
      const cfg = await decompilerWorker.getFunctionCFG(
        input.sample_id,
        addressOrSymbol,
        timeoutMs
      );

      logger.info({
        sample_id: input.sample_id,
        function: cfg.function,
        node_count: cfg.nodes.length,
        edge_count: cfg.edges.length
      }, 'Function CFG extracted successfully');

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            ok: true,
            data: cfg
          }, null, 2)
        }]
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const diagnostics = getGhidraDiagnostics(error);
      const normalizedError = normalizeGhidraError(error, 'code.function.cfg');
      logger.error({
        error: errorMessage,
        ghidra_diagnostics: diagnostics,
        normalized_error: normalizedError,
      }, 'code.function.cfg tool failed');

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
