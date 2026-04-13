/**
 * shellcode.disasm — Disassemble raw shellcode bytes from a sample.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolvePythonModuleBackend,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'shellcode.disasm'

export const shellcodeDisasmInputSchema = z.object({
  sample_id: z.string().describe('Sample containing shellcode.'),
  arch: z.enum(['x86', 'x64']).default('x86').describe('Shellcode architecture.'),
  offset: z.number().int().min(0).default(0).describe('Starting byte offset.'),
  max_bytes: z.number().int().min(1).max(65536).default(4096).describe('Maximum bytes to disassemble.'),
  persist_artifact: z.boolean().default(true).describe('Persist disassembly as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const shellcodeDisasmOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    arch: z.string().optional(),
    shellcode_size: z.number().optional(),
    instruction_count: z.number().optional(),
    disassembly: z.string().optional(),
    api_calls_heuristic: z.array(z.string()).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const shellcodeDisasmToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Disassemble raw shellcode from a sample using Capstone. Includes heuristic API call detection from call/jmp patterns.',
  inputSchema: shellcodeDisasmInputSchema,
  outputSchema: shellcodeDisasmOutputSchema,
}

const SHELLCODE_DISASM_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
file_path = payload["sample_path"]
arch_str = payload.get("arch", "x86")
offset = int(payload.get("offset", 0))
max_bytes = int(payload.get("max_bytes", 4096))

with open(file_path, "rb") as f:
    f.seek(offset)
    code = f.read(max_bytes)

import capstone

if arch_str == "x64":
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
else:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

instructions = []
text_lines = []
api_heuristic = []
for insn in md.disasm(code, 0):
    hex_bytes = " ".join(f"{b:02x}" for b in insn.bytes)
    text_lines.append(f"0x{insn.address:08x}:  {hex_bytes:<24s}  {insn.mnemonic}  {insn.op_str}")
    instructions.append({
        "address": f"0x{insn.address:x}",
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
    })
    # Heuristic: look for call/jmp with register operands (likely API dispatch)
    if insn.mnemonic in ("call", "jmp") and insn.op_str.startswith(("e", "r", "dword")):
        api_heuristic.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

print(json.dumps({
    "shellcode_size": len(code),
    "instruction_count": len(instructions),
    "disassembly": "\\n".join(text_lines[:1000]),
    "instructions": instructions[:500],
    "api_calls_heuristic": api_heuristic[:50],
}, ensure_ascii=False))
`.trim()

export function createShellcodeDisasmHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = shellcodeDisasmInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.CAPSTONE_PYTHON, moduleNames: ['capstone'], distributionNames: ['capstone'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'capstone', available: false, error: 'capstone not installed' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(
        backend.path,
        SHELLCODE_DISASM_SCRIPT,
        { sample_path: samplePath, arch: input.arch, offset: input.offset, max_bytes: input.max_bytes },
        30_000,
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'capstone', 'shellcode', result.parsed?.disassembly || '', { extension: 'asm', mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      const count = result.parsed?.instruction_count || 0
      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          arch: input.arch,
          shellcode_size: result.parsed?.shellcode_size || 0,
          instruction_count: count,
          disassembly: (result.parsed?.disassembly || '').slice(0, 5000),
          api_calls_heuristic: result.parsed?.api_calls_heuristic || [],
          artifact,
          summary: `Shellcode (${input.arch}, ${result.parsed?.shellcode_size || 0} bytes): ${count} instructions, ${(result.parsed?.api_calls_heuristic || []).length} potential API dispatch points.`,
          recommended_next_tools: ['artifact.read', 'speakeasy.shellcode', 'hash.resolve', 'strings.extract'],
          next_actions: [
            'Use speakeasy.shellcode to emulate the shellcode and trace API calls.',
            'Use hash.resolve if you see API hash constants.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
