/**
 * disasm.quick — Disassemble bytes at a given offset from a sample.
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

const TOOL_NAME = 'disasm.quick'

export const disasmQuickInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  offset: z.number().int().min(0).describe('Byte offset to start disassembly.'),
  length: z.number().int().min(1).max(65536).default(256).describe('Number of bytes to disassemble.'),
  arch: z.enum(['x86', 'x64', 'arm', 'arm64', 'mips']).default('x86').describe('Target architecture.'),
  base_address: z.number().int().min(0).optional().describe('Virtual base address for display (defaults to offset).'),
  persist_artifact: z.boolean().default(false).describe('Persist disassembly as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const disasmQuickOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    arch: z.string().optional(),
    offset: z.number().optional(),
    instruction_count: z.number().optional(),
    disassembly: z.string().optional(),
    instructions: z.array(z.object({
      address: z.string(),
      mnemonic: z.string(),
      op_str: z.string(),
      bytes: z.string(),
    })).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const disasmQuickToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Quickly disassemble bytes from a sample at a given offset. Uses Capstone — no Ghidra/Rizin needed. Ideal for entrypoints, shellcode snippets, and quick inspection.',
  inputSchema: disasmQuickInputSchema,
  outputSchema: disasmQuickOutputSchema,
}

const CAPSTONE_DISASM_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
file_path = payload["sample_path"]
offset = int(payload["offset"])
length = int(payload.get("length", 256))
arch_str = payload.get("arch", "x86")
base = int(payload.get("base_address", offset))

with open(file_path, "rb") as f:
    f.seek(offset)
    code = f.read(length)

import capstone

ARCH_MAP = {
    "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN),
}

cs_arch, cs_mode = ARCH_MAP.get(arch_str, ARCH_MAP["x86"])
md = capstone.Cs(cs_arch, cs_mode)
md.detail = False

instructions = []
text_lines = []
for insn in md.disasm(code, base):
    hex_bytes = " ".join(f"{b:02x}" for b in insn.bytes)
    instructions.append({
        "address": f"0x{insn.address:x}",
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "bytes": hex_bytes,
    })
    text_lines.append(f"0x{insn.address:08x}:  {hex_bytes:<24s}  {insn.mnemonic}  {insn.op_str}")

print(json.dumps({
    "instruction_count": len(instructions),
    "instructions": instructions[:500],
    "disassembly": "\\n".join(text_lines[:500]),
}, ensure_ascii=False))
`.trim()

export function createDisasmQuickHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = disasmQuickInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.CAPSTONE_PYTHON, moduleNames: ['capstone'], distributionNames: ['capstone'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'capstone', available: false, error: 'Python capstone not installed. pip install capstone' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(
        backend.path,
        CAPSTONE_DISASM_SCRIPT,
        { sample_path: samplePath, offset: input.offset, length: input.length, arch: input.arch, base_address: input.base_address ?? input.offset },
        30_000,
      )

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'capstone', 'disasm', result.parsed?.disassembly || '', { extension: 'asm', mime: 'text/plain', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      const count = result.parsed?.instruction_count || 0
      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          arch: input.arch,
          offset: input.offset,
          instruction_count: count,
          disassembly: (result.parsed?.disassembly || '').slice(0, 5000),
          instructions: (result.parsed?.instructions || []).slice(0, 50),
          artifact,
          summary: `Disassembled ${count} ${input.arch} instructions at offset 0x${input.offset.toString(16)}.`,
          recommended_next_tools: ['artifact.read', 'code.function.decompile', 'shellcode.disasm', 'pe.pdata.extract'],
          next_actions: [
            'Use code.function.decompile for full function analysis via Ghidra.',
            'Use shellcode.disasm for raw shellcode analysis.',
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
