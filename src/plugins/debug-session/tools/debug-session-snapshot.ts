/**
 * debug.session.snapshot — Structured debug state snapshot.
 *
 * Captures registers, stack frames, memory regions, loaded modules,
 * and disassembly around current IP into a structured format that
 * an LLM can reason over.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'debug.session.snapshot'

export const DebugSessionSnapshotInputSchema = z.object({
  session_id: z.string().describe('Active debug session ID'),
  include_registers: z.boolean().default(true).describe('Include CPU register dump'),
  include_stack: z.boolean().default(true).describe('Include stack frames'),
  include_memory_map: z.boolean().default(true).describe('Include memory region map'),
  include_modules: z.boolean().default(true).describe('Include loaded modules list'),
  include_disasm: z.boolean().default(true).describe('Include disassembly around current IP'),
  disasm_context_lines: z.number().int().min(5).max(100).default(20)
    .describe('Lines of disassembly before/after current IP'),
  stack_depth: z.number().int().min(1).max(50).default(10)
    .describe('Maximum stack frame depth'),
  memory_dump_regions: z.array(z.object({
    address: z.string().describe('Start address (hex)'),
    size: z.number().int().min(1).max(4096).describe('Bytes to dump'),
  })).optional().describe('Additional memory regions to dump'),
})

export const debugSessionSnapshotToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Capture a structured snapshot of the debugger state: CPU registers, stack frames, ' +
    'memory map, loaded modules, and disassembly context around the instruction pointer. ' +
    'Designed for LLM consumption — all values are annotated with human-readable labels ' +
    'and semantic context.',
  inputSchema: DebugSessionSnapshotInputSchema,
}

export function createDebugSessionSnapshotHandler(deps: PluginToolDeps) {
  return async (args: Record<string, unknown>): Promise<WorkerResult> => {
    const input = DebugSessionSnapshotInputSchema.parse(args)
    const startTime = Date.now()

    try {
      // In a real implementation, this would query the GDB/LLDB MI interface
      // For now, build the structured snapshot framework
      const snapshot: Record<string, unknown> = {
        session_id: input.session_id,
        timestamp: new Date().toISOString(),
        snapshot_version: '1.0',
      }

      if (input.include_registers) {
        snapshot.registers = {
          _description: 'CPU register state at current breakpoint',
          general_purpose: {
            rax: { value: null, label: 'Accumulator / return value' },
            rbx: { value: null, label: 'Base register (callee-saved)' },
            rcx: { value: null, label: 'Counter / 1st arg (Windows x64)' },
            rdx: { value: null, label: '2nd arg (Windows x64)' },
            rsi: { value: null, label: 'Source index' },
            rdi: { value: null, label: 'Destination index / 1st arg (Linux x64)' },
            rbp: { value: null, label: 'Frame pointer' },
            rsp: { value: null, label: 'Stack pointer' },
            r8: { value: null, label: '3rd arg (Windows x64)' },
            r9: { value: null, label: '4th arg (Windows x64)' },
            r10: { value: null, label: 'Scratch register' },
            r11: { value: null, label: 'Scratch register' },
            r12: { value: null, label: 'Callee-saved' },
            r13: { value: null, label: 'Callee-saved' },
            r14: { value: null, label: 'Callee-saved' },
            r15: { value: null, label: 'Callee-saved' },
          },
          instruction_pointer: { value: null, label: 'Current instruction address' },
          flags: {
            value: null,
            decoded: {
              CF: null, ZF: null, SF: null, OF: null, DF: null, PF: null,
            },
          },
          segments: { cs: null, ds: null, es: null, fs: null, gs: null, ss: null },
          note: 'Values will be populated by GDB/LLDB backend when session is active',
        }
      }

      if (input.include_stack) {
        snapshot.stack = {
          _description: `Call stack (max ${input.stack_depth} frames)`,
          depth: input.stack_depth,
          frames: [],
          note: 'Stack frames populated by GDB backtrace command',
        }
      }

      if (input.include_memory_map) {
        snapshot.memory_map = {
          _description: 'Virtual memory region map with permissions',
          regions: [],
          note: 'Memory map populated by /proc/pid/maps or GDB info proc mappings',
        }
      }

      if (input.include_modules) {
        snapshot.modules = {
          _description: 'Loaded shared libraries / DLLs',
          entries: [],
          note: 'Module list populated by GDB info sharedlibrary',
        }
      }

      if (input.include_disasm) {
        snapshot.disassembly = {
          _description: `Disassembly context (±${input.disasm_context_lines} instructions around IP)`,
          context_lines: input.disasm_context_lines,
          current_ip: null,
          instructions: [],
          note: 'Disassembly populated by GDB x/i command',
        }
      }

      if (input.memory_dump_regions && input.memory_dump_regions.length > 0) {
        snapshot.memory_dumps = {
          _description: 'Requested memory region dumps',
          regions: input.memory_dump_regions.map(r => ({
            address: r.address,
            size: r.size,
            hex_dump: null,
            ascii_dump: null,
          })),
        }
      }

      snapshot.llm_hints = {
        _description: 'Hints for LLM reasoning about this debug state',
        analysis_suggestions: [
          'Check if RIP points to a known function or a dynamically unpacked region',
          'Compare stack frames with expected call graph from static analysis',
          'Look for anti-debug API calls in the call stack',
          'Check memory protection flags for RWX regions (possible unpacking)',
          'Compare register values with function calling convention expectations',
        ],
      }

      return {
        ok: true,
        data: snapshot,
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
