/**
 * python.decompile — Decompile Python bytecode (.pyc) to source / disassembly.
 *
 * Loads a CPython .pyc file's marshalled code object and either recovers
 * source via decompyle3/uncompyle6 (when installed and version-compatible)
 * or falls back to a bounded disassembly (dis.dis) which always works.
 * Recovers code object metadata: names, constants, varnames, arg count.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type {
  WorkerResult,
  ToolDefinition,
  ToolArgs,
  ArtifactRef,
  PluginToolDeps,
} from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'
import {
  ArtifactRefSchema,
  SharedMetricsSchema,
  normalizeError,
  persistBackendArtifact,
  buildMetrics,
  resolveSampleFile,
} from '../../docker-shared.js'

const TOOL_NAME = 'python.decompile'
const TOOL_VERSION = '0.1.0'
const ARTIFACT_TYPE = 'python_decompiled_source'
const RECOMMENDED_NEXT_TOOLS = [
  'bytecode.metadata.inspect',
  'strings.extract',
  'artifact.read',
  'workflow.search',
]

const SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]

export const pythonDecompileInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier (sha256:<hex>) of a .pyc file.'),
  mode: z
    .enum(['auto', 'source', 'disasm'])
    .optional()
    .default('auto')
    .describe(
      'auto: try source recovery, fall back to disasm. ' +
        'source: only attempt decompyle3/uncompyle6. ' +
        'disasm: only produce dis.dis output.'
    ),
  max_source_chars: z
    .number()
    .int()
    .min(256)
    .max(1_000_000)
    .optional()
    .default(64_000)
    .describe('Maximum recovered source characters to return inline.'),
  max_disasm_lines: z
    .number()
    .int()
    .min(50)
    .max(20_000)
    .optional()
    .default(2_000)
    .describe('Maximum disassembly lines to return inline.'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist the decompiled output as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

const CodeObjectMetaSchema = z.object({
  magic_hex: z.string().optional(),
  magic_int: z.number().int().optional(),
  python_version: z.string().nullable().optional(),
  co_name: z.string().nullable().optional(),
  co_argcount: z.number().int().optional(),
  co_nlocals: z.number().int().optional(),
  co_stacksize: z.number().int().optional(),
  co_flags: z.number().int().optional(),
  co_names: z.array(z.string()).optional(),
  co_varnames: z.array(z.string()).optional(),
  co_freevars: z.array(z.string()).optional(),
  co_cellvars: z.array(z.string()).optional(),
  co_consts: z.array(z.any()).optional(),
  error: z.string().optional(),
})

export const pythonDecompileOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum([
        'ready',
        'source_recovered',
        'disasm_only',
        'unsupported_version',
        'setup_required',
        'invalid_pyc',
      ]),
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      mode: z.string().optional(),
      decompiler_used: z.string().nullable().optional(),
      python_version: z.string().nullable().optional(),
      source: z.string().nullable().optional(),
      disassembly: z.string().nullable().optional(),
      source_truncated: z.boolean().optional(),
      disasm_truncated: z.boolean().optional(),
      code_object: CodeObjectMetaSchema.optional(),
      summary: z.string().optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      artifact: ArtifactRefSchema.nullable().optional(),
    })
    .passthrough()
    .optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  errors: z.array(z.string()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const pythonDecompileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decompile Python bytecode (.pyc) to source code or a bounded disassembly. ' +
    'Recovers source via decompyle3 (3.7-3.8) or uncompyle6 (2.7, 3.5-3.8) when ' +
    'installed; otherwise produces a dis.dis disassembly that always works. ' +
    'Also returns code object metadata (names, constants, varnames). ' +
    'Useful for PyInstaller payloads, supply-chain packages, and source-less ' +
    'Python applications. Never imports or executes the code object bytecode.',
  inputSchema: pythonDecompileInputSchema,
  outputSchema: pythonDecompileOutputSchema,
  aspects: {
    formats: ['pyc', 'pyo', 'python', 'python-bytecode'],
    platforms: ['python', 'cross-platform'],
    execution: ['static', 'decompilation'],
    safety: SAFETY,
    capabilities: [
      'python-decompilation',
      'bytecode-disassembly',
      'code-object-recovery',
      'source-recovery',
      'workflow-handoff',
    ],
    evidence: ['source', 'disassembly', 'strings', 'provenance'],
  },
  artifacts: [
    {
      type: ARTIFACT_TYPE,
      description: 'Decompiled Python source or disassembly with code object metadata',
    },
  ],
  evidence: [
    {
      category: 'source',
      artifactTypes: [ARTIFACT_TYPE],
    },
    {
      category: 'disassembly',
      artifactTypes: [ARTIFACT_TYPE],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    noMutation: true,
    noLiveExecution: true,
    noNetwork: true,
    notes: [
      'marshal.loads loads the code object but never executes its bytecode.',
      'dis.dis produces a read-only disassembly; no interpreter state is mutated.',
      'Source recovery degrades gracefully to disassembly when no compatible decompiler is installed.',
    ],
  },
}

async function callPycWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  workerPath: string,
  timeoutMs: number
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const proc = spawn(pythonCmd, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
      proc.kill()
      reject(new Error(`Python worker timed out after ${timeoutMs}ms`))
    }, timeoutMs)
    proc.stdout.on('data', (d: Buffer) => {
      stdout += d.toString()
    })
    proc.stderr.on('data', (d: Buffer) => {
      stderr += d.toString()
    })
    proc.on('close', (code) => {
      clearTimeout(timer)
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`PYC worker exited ${code}: ${stderr.slice(0, 500)}`))
        return
      }
      try {
        resolve(JSON.parse(stdout.trim()))
      } catch (e) {
        reject(new Error(`Parse error: ${(e as Error).message}; stderr=${stderr.slice(0, 200)}`))
      }
    })
    proc.on('error', (e) => {
      clearTimeout(timer)
      reject(new Error(`Spawn error: ${e.message}`))
    })
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

export function createPythonDecompileHandler(deps: PluginToolDeps) {
  const { workspaceManager, database, config, resolvePackagePath } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = pythonDecompileInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const pythonCmd = getPythonCommand(undefined, config?.workers?.static?.pythonPath)
      const workerPath = resolvePackagePath(
        'src',
        'plugins',
        'python-decompile',
        'workers',
        'pyc_decompile_worker.py'
      )

      const workerResult = await callPycWorker(
        {
          sample_path: samplePath,
          mode: input.mode,
          max_source_chars: input.max_source_chars,
          max_disasm_lines: input.max_disasm_lines,
        },
        pythonCmd,
        workerPath,
        120_000
      )

      const status = (workerResult.status as string) ?? 'setup_required'
      const pythonVersion =
        typeof workerResult.python_version === 'string' ? workerResult.python_version : null
      const decompilerUsed =
        typeof workerResult.decompiler_used === 'string' ? workerResult.decompiler_used : null
      const source = typeof workerResult.source === 'string' ? workerResult.source : null
      const disassembly =
        typeof workerResult.disassembly === 'string' ? workerResult.disassembly : null

      const baseOutputData = {
        schema: `rikune.${ARTIFACT_TYPE}`,
        tool_version: TOOL_VERSION,
        status,
        sample_id: input.sample_id,
        mode: input.mode,
        decompiler_used: decompilerUsed,
        python_version: pythonVersion,
        source,
        disassembly,
        source_truncated: Boolean(workerResult.source_truncated),
        disasm_truncated: Boolean(workerResult.disasm_truncated),
        code_object: workerResult.code_object ?? null,
        summary: buildSummary(status, pythonVersion, decompilerUsed, input.mode),
        recommended_next_tools: RECOMMENDED_NEXT_TOOLS,
      } satisfies Record<string, unknown>

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'python-decompile',
          'decompile',
          JSON.stringify(baseOutputData, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          ...baseOutputData,
          artifact,
          recommended_next_tools: RECOMMENDED_NEXT_TOOLS,
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    }
  }
}

function buildSummary(
  status: string,
  pythonVersion: string | null,
  decompiler: string | null,
  mode: string
): string {
  switch (status) {
    case 'source_recovered':
      return `Recovered Python source via ${decompiler} for ${pythonVersion ?? 'unknown'} bytecode.`
    case 'disasm_only':
      return `No source recovery (mode=${mode}); produced bounded disassembly for ${pythonVersion ?? 'unknown'} bytecode.`
    case 'unsupported_version':
      return `Bytecode is ${pythonVersion ?? 'unknown'} which has no compatible decompiler; disassembly produced instead.`
    case 'invalid_pyc':
      return 'Sample is not a valid CPython .pyc file.'
    case 'setup_required':
      return `Source recovery requested (mode=${mode}) but no compatible decompiler is installed.`
    default:
      return `python.decompile completed with status ${status}.`
  }
}
