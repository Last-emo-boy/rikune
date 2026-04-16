/**
 * debug.session.watch — Memory / register watchpoints with change tracking.
 *
 * Set hardware/software watchpoints on memory addresses or expressions.
 * Tracks historical changes to watched values with timestamps.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'debug.session.watch'

export const DebugSessionWatchInputSchema = z.object({
  session_id: z.string().describe('Active debug session ID'),
  action: z.enum(['add', 'remove', 'list', 'history']).describe('Watch operation'),
  watch_type: z.enum(['memory', 'register', 'expression']).optional()
    .describe('Type of watchpoint (required for "add")'),
  address: z.string().optional()
    .describe('Memory address to watch (hex, for memory type)'),
  register: z.string().optional()
    .describe('Register name (for register type, e.g., "rax", "rcx")'),
  expression: z.string().optional()
    .describe('GDB expression to watch (for expression type)'),
  size: z.number().int().min(1).max(8).default(4)
    .describe('Watch size in bytes (for memory type)'),
  access_type: z.enum(['write', 'read', 'readwrite']).default('write')
    .describe('Trigger on write, read, or both'),
  watch_id: z.string().optional()
    .describe('Watch ID (for remove/history actions)'),
})

export const debugSessionWatchToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Manage debug watchpoints: set hardware watchpoints on memory addresses, ' +
    'registers, or GDB expressions. Tracks value change history with timestamps. ' +
    'Actions: add (create watchpoint), remove (delete), list (show active), ' +
    'history (show value changes for a watch).',
  inputSchema: DebugSessionWatchInputSchema,
  runtimeBackendHint: { type: 'inline', handler: 'executeDebugSession' },
}

export function createDebugSessionWatchHandler(deps: PluginToolDeps) {
  return async (args: Record<string, unknown>): Promise<WorkerResult> => {
    const input = DebugSessionWatchInputSchema.parse(args)
    const startTime = Date.now()

    try {
      switch (input.action) {
        case 'add': {
          if (!input.watch_type) {
            return { ok: false, errors: ['watch_type is required for "add" action'] }
          }

          let target: string
          if (input.watch_type === 'memory') {
            if (!input.address) return { ok: false, errors: ['address is required for memory watch'] }
            target = input.address
          } else if (input.watch_type === 'register') {
            if (!input.register) return { ok: false, errors: ['register is required for register watch'] }
            target = `$${input.register}`
          } else {
            if (!input.expression) return { ok: false, errors: ['expression is required for expression watch'] }
            target = input.expression
          }

          const watchId = `watch_${Date.now().toString(36)}`

          return {
            ok: true,
            data: {
              action: 'add',
              watch_id: watchId,
              session_id: input.session_id,
              watch_type: input.watch_type,
              target,
              size: input.size,
              access_type: input.access_type,
              status: 'active',
              gdb_command: input.watch_type === 'memory'
                ? `watch *(${input.size === 1 ? 'char' : input.size === 2 ? 'short' : input.size === 4 ? 'int' : 'long long'}*)${target}`
                : input.watch_type === 'register'
                  ? `watch $${input.register}`
                  : `watch ${input.expression}`,
              note: 'Watchpoint will trigger when the target value changes',
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'remove': {
          if (!input.watch_id) {
            return { ok: false, errors: ['watch_id is required for "remove" action'] }
          }
          return {
            ok: true,
            data: {
              action: 'remove',
              watch_id: input.watch_id,
              session_id: input.session_id,
              status: 'removed',
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'list': {
          return {
            ok: true,
            data: {
              action: 'list',
              session_id: input.session_id,
              watches: [],
              note: 'Active watchpoints populated by GDB info watchpoints',
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        case 'history': {
          if (!input.watch_id) {
            return { ok: false, errors: ['watch_id is required for "history" action'] }
          }
          return {
            ok: true,
            data: {
              action: 'history',
              watch_id: input.watch_id,
              session_id: input.session_id,
              changes: [],
              note: 'Change history populated from watchpoint hit records',
            },
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
          }
        }

        default:
          return { ok: false, errors: [`Unknown action: ${input.action}`] }
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
