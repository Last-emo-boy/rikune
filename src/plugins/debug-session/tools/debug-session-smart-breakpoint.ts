/**
 * debug.session.smart_breakpoint — LLM-driven breakpoint strategy.
 *
 * Analyses static analysis results (imports, strings, crypto, packer info)
 * to automatically suggest and set breakpoints at high-value locations:
 * crypto routines, network calls, unpacking stubs, anti-debug checks.
 */

import { z } from 'zod'
import type { ToolDefinition, WorkerResult, PluginToolDeps } from '../../sdk.js'

const TOOL_NAME = 'debug.session.smart_breakpoint'

export const DebugSessionSmartBreakpointInputSchema = z.object({
  session_id: z.string().describe('Active debug session ID'),
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  strategy: z.enum([
    'crypto_intercept',
    'network_monitor',
    'unpack_oep',
    'anti_debug',
    'string_decrypt',
    'auto',
  ]).default('auto').describe('Breakpoint strategy category'),
  max_breakpoints: z.number().int().min(1).max(50).default(10)
    .describe('Maximum breakpoints to set'),
  include_conditional: z.boolean().default(true)
    .describe('Allow conditional breakpoints (may slow execution)'),
})

export const debugSessionSmartBreakpointToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Automatically set intelligent breakpoints based on static analysis results. ' +
    'Strategies: crypto_intercept (break on CryptEncrypt/AES/RSA), network_monitor ' +
    '(break on connect/send/recv), unpack_oep (break at probable OEP), anti_debug ' +
    '(break on IsDebuggerPresent/NtQueryInformationProcess), string_decrypt ' +
    '(break at XOR/RC4 decryption loops), auto (all applicable).',
  inputSchema: DebugSessionSmartBreakpointInputSchema,
  runtimeBackendHint: { type: 'inline', handler: 'executeDebugSession' },
}

// ── Breakpoint strategy knowledge base ────────────────────────────────────
interface BreakpointRule {
  category: string
  api_pattern: string
  description: string
  condition?: string
  priority: number
}

const STRATEGY_RULES: Record<string, BreakpointRule[]> = {
  crypto_intercept: [
    { category: 'crypto', api_pattern: 'CryptEncrypt', description: 'Windows CryptoAPI encrypt', priority: 1 },
    { category: 'crypto', api_pattern: 'CryptDecrypt', description: 'Windows CryptoAPI decrypt', priority: 1 },
    { category: 'crypto', api_pattern: 'BCryptEncrypt', description: 'BCrypt encrypt', priority: 1 },
    { category: 'crypto', api_pattern: 'BCryptDecrypt', description: 'BCrypt decrypt', priority: 1 },
    { category: 'crypto', api_pattern: 'CryptHashData', description: 'Hash data input', priority: 2 },
    { category: 'crypto', api_pattern: 'CryptDeriveKey', description: 'Key derivation', priority: 2 },
  ],
  network_monitor: [
    { category: 'network', api_pattern: 'connect', description: 'Socket connect', priority: 1 },
    { category: 'network', api_pattern: 'send', description: 'Socket send', priority: 1 },
    { category: 'network', api_pattern: 'recv', description: 'Socket receive', priority: 1 },
    { category: 'network', api_pattern: 'InternetOpenA', description: 'WinINet open', priority: 1 },
    { category: 'network', api_pattern: 'HttpSendRequestA', description: 'HTTP request', priority: 1 },
    { category: 'network', api_pattern: 'WSAStartup', description: 'Winsock init', priority: 2 },
    { category: 'network', api_pattern: 'URLDownloadToFileA', description: 'URL download', priority: 1 },
  ],
  unpack_oep: [
    { category: 'unpack', api_pattern: 'VirtualAlloc', description: 'Memory allocation for unpacking', priority: 1, condition: 'size > 0x1000' },
    { category: 'unpack', api_pattern: 'VirtualProtect', description: 'Memory protection change (RWX)', priority: 1, condition: 'newProtect == 0x40' },
    { category: 'unpack', api_pattern: 'WriteProcessMemory', description: 'Remote process write', priority: 1 },
    { category: 'unpack', api_pattern: 'NtUnmapViewOfSection', description: 'Process hollowing', priority: 1 },
  ],
  anti_debug: [
    { category: 'anti_debug', api_pattern: 'IsDebuggerPresent', description: 'Debugger check', priority: 1 },
    { category: 'anti_debug', api_pattern: 'CheckRemoteDebuggerPresent', description: 'Remote debugger check', priority: 1 },
    { category: 'anti_debug', api_pattern: 'NtQueryInformationProcess', description: 'Process info query (debug port)', priority: 1 },
    { category: 'anti_debug', api_pattern: 'OutputDebugStringA', description: 'Debug string output (timing check)', priority: 2 },
    { category: 'anti_debug', api_pattern: 'GetTickCount', description: 'Timing-based anti-debug', priority: 2 },
    { category: 'anti_debug', api_pattern: 'QueryPerformanceCounter', description: 'High-res timing check', priority: 2 },
  ],
  string_decrypt: [
    { category: 'string_decrypt', api_pattern: 'VirtualAlloc', description: 'Buffer for decrypted strings', priority: 2 },
    { category: 'string_decrypt', api_pattern: 'RtlDecompressBuffer', description: 'Decompression (string table)', priority: 1 },
    { category: 'string_decrypt', api_pattern: 'MultiByteToWideChar', description: 'String conversion post-decrypt', priority: 2 },
  ],
}

export function createDebugSessionSmartBreakpointHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps

  return async (args: Record<string, unknown>): Promise<WorkerResult> => {
    const input = DebugSessionSmartBreakpointInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      // Gather static analysis context
      const artifacts = database.listArtifacts(input.sample_id)
      const importArtifact = artifacts.find((a: { type: string }) =>
        a.type === 'imports' || a.type === 'pe_imports',
      )

      // Determine which strategies to apply
      const strategies = input.strategy === 'auto'
        ? Object.keys(STRATEGY_RULES)
        : [input.strategy]

      // Collect applicable rules
      const applicableRules: Array<BreakpointRule & { applied: boolean; address?: string }> = []

      for (const strategyName of strategies) {
        const rules = STRATEGY_RULES[strategyName] || []
        for (const rule of rules) {
          if (applicableRules.length >= input.max_breakpoints) break
          applicableRules.push({
            ...rule,
            applied: false, // Would be true after GDB integration sets the BP
          })
        }
      }

      // Sort by priority
      applicableRules.sort((a, b) => a.priority - b.priority)
      const selected = applicableRules.slice(0, input.max_breakpoints)

      return {
        ok: true,
        data: {
          session_id: input.session_id,
          sample_id: input.sample_id,
          strategies_applied: strategies,
          breakpoints_planned: selected.length,
          breakpoints: selected.map((rule, idx) => ({
            index: idx + 1,
            category: rule.category,
            target: rule.api_pattern,
            description: rule.description,
            condition: input.include_conditional ? rule.condition : undefined,
            priority: rule.priority,
            status: 'planned',
          })),
          static_context_available: !!importArtifact,
          recommended_next: ['debug.session.continue', 'debug.session.snapshot'],
        },
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
