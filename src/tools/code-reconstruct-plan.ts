/**
 * code.reconstruct.plan tool implementation
 * Builds a practical source-reconstruction plan from current static/decompiler signals.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import { clamp } from '../utils/shared-helpers.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { createRuntimeDetectHandler } from './runtime-detect.js'
import { createPackerDetectHandler } from './packer-detect.js'
import { CACHE_TTL_7_DAYS } from '../constants/cache-ttl.js'

const TOOL_NAME = 'code.reconstruct.plan'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = CACHE_TTL_7_DAYS

export const CodeReconstructPlanInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  target_language: z
    .enum(['auto', 'csharp', 'c', 'cpp', 'rust', 'go'])
    .default('auto')
    .describe('Preferred reconstruction language'),
  depth: z
    .enum(['quick', 'standard', 'deep'])
    .default('standard')
    .describe('Planning depth'),
  include_decompiler: z
    .boolean()
    .default(true)
    .describe('Whether to include decompiler-based phases'),
  include_strings: z
    .boolean()
    .default(true)
    .describe('Whether to include string/IOC enrichment phases'),
})

export type CodeReconstructPlanInput = z.infer<typeof CodeReconstructPlanInputSchema>

const ReconstructionPhaseSchema = z.object({
  phase: z.string(),
  title: z.string(),
  objective: z.string(),
  actions: z.array(z.string()),
  estimated_effort: z.enum(['low', 'medium', 'high']),
  confidence: z.number().min(0).max(1),
})

export const CodeReconstructPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      feasibility: z.enum(['high', 'medium', 'low']),
      confidence: z.number().min(0).max(1),
      restoration_expectation: z.string(),
      runtime_summary: z.object({
        primary_runtime: z.string(),
        suspected: z.array(
          z.object({
            runtime: z.string(),
            confidence: z.number(),
            evidence: z.array(z.string()),
          })
        ),
      }),
      packing_summary: z.object({
        packed: z.boolean(),
        confidence: z.number(),
      }),
      blockers: z.array(z.string()),
      recommendations: z.array(z.string()),
      phases: z.array(ReconstructionPhaseSchema),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z
    .object({
      elapsed_ms: z.number(),
      tool: z.string(),
      cached: z.boolean().optional(),
      cache_key: z.string().optional(),
      cache_tier: z.string().optional(),
      cache_created_at: z.string().optional(),
      cache_expires_at: z.string().optional(),
      cache_hit_at: z.string().optional(),
    })
    .optional(),
})

export type CodeReconstructPlanOutput = z.infer<typeof CodeReconstructPlanOutputSchema>

export const codeReconstructPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Assess source-reconstruction feasibility and produce a phased reverse-engineering plan with confidence.',
  inputSchema: CodeReconstructPlanInputSchema,
  outputSchema: CodeReconstructPlanOutputSchema,
}

interface RuntimeDetectData {
  is_dotnet?: boolean
  suspected?: Array<{ runtime: string; confidence: number; evidence: string[] }>
}

interface PackerDetectData {
  packed?: boolean
  confidence?: number
}

interface ReconstructPlanDependencies {
  runtimeDetectHandler?: (args: ToolArgs) => Promise<WorkerResult>
  packerDetectHandler?: (args: ToolArgs) => Promise<WorkerResult>
}

function pickPrimaryRuntime(runtimeData?: RuntimeDetectData): string {
  const suspected = runtimeData?.suspected || []
  if (suspected.length === 0) {
    return 'unknown'
  }
  const sorted = [...suspected].sort((a, b) => b.confidence - a.confidence)
  return sorted[0].runtime || 'unknown'
}

function assessReconstructability(
  runtimeData: RuntimeDetectData | undefined,
  packerData: PackerDetectData | undefined
): {
  feasibility: 'high' | 'medium' | 'low'
  confidence: number
  restorationExpectation: string
  blockers: string[]
} {
  const primaryRuntime = pickPrimaryRuntime(runtimeData).toLowerCase()
  const isDotNet = runtimeData?.is_dotnet === true || primaryRuntime.includes('dotnet')
  const packed = packerData?.packed === true
  const packingConfidence = clamp(packerData?.confidence ?? 0, 0, 1)

  let score = 0.5
  const blockers: string[] = []

  if (isDotNet) {
    score += 0.3
  } else if (primaryRuntime.includes('rust')) {
    score -= 0.15
  } else if (primaryRuntime.includes('go')) {
    score -= 0.1
  } else if (primaryRuntime.includes('c++') || primaryRuntime.includes('cpp')) {
    score -= 0.05
  }

  if (packed) {
    score -= 0.35 * (packingConfidence || 0.8)
    blockers.push('Sample appears packed/obfuscated; unpacking is needed before reliable reconstruction.')
  }

  if (primaryRuntime === 'unknown') {
    score -= 0.2
    blockers.push('Primary runtime is uncertain; detection confidence is currently low.')
  }

  const confidenceSignals =
    (runtimeData ? 1 : 0) + (packerData ? 1 : 0) + ((runtimeData?.suspected?.length || 0) > 0 ? 1 : 0)
  const confidence = clamp(0.35 + confidenceSignals * 0.2, 0.35, 0.95)
  score = clamp(score, 0, 1)

  let feasibility: 'high' | 'medium' | 'low' = 'low'
  if (score >= 0.75) {
    feasibility = 'high'
  } else if (score >= 0.5) {
    feasibility = 'medium'
  }

  let restorationExpectation =
    'Behavioral reconstruction is possible; exact original source text is not recoverable.'
  if (isDotNet && !packed) {
    restorationExpectation =
      'High-confidence C# structural restoration is feasible, but comments/symbol intent still requires manual review.'
  } else if (isDotNet && packed) {
    restorationExpectation =
      'Partial C# restoration is feasible after unpacking/deobfuscation; fidelity depends on recovered metadata.'
  } else if (!isDotNet) {
    restorationExpectation =
      'Native binaries support semantic reconstruction (C-like pseudocode), not exact original source restoration.'
  }

  return {
    feasibility,
    confidence,
    restorationExpectation,
    blockers,
  }
}

function buildPhases(
  input: CodeReconstructPlanInput,
  runtimeData: RuntimeDetectData | undefined,
  packerData: PackerDetectData | undefined,
  confidence: number
) {
  const primaryRuntime = pickPrimaryRuntime(runtimeData).toLowerCase()
  const isDotNet = runtimeData?.is_dotnet === true || primaryRuntime.includes('dotnet')
  const packed = packerData?.packed === true

  const phases: Array<z.infer<typeof ReconstructionPhaseSchema>> = [
    {
      phase: 'phase_1',
      title: 'Assess & Baseline',
      objective: 'Establish runtime profile, packing state, and reconstruction boundary.',
      actions: [
        'Run runtime.detect and packer.detect with evidence capture.',
        'Lock sample hash and workspace snapshot for reproducibility.',
        'Define target output: semantic reconstruction vs source-like project.',
      ],
      estimated_effort: 'low',
      confidence: clamp(confidence, 0.3, 0.95),
    },
  ]

  if (packed) {
    phases.push({
      phase: 'phase_2',
      title: 'Unpack & Normalize',
      objective: 'Remove packing/obfuscation artifacts before deep reconstruction.',
      actions: [
        'Correlate packer signatures with imports/calls to reduce false positives.',
        'Extract clean image and rerun static fingerprinting.',
        'Rebuild string corpus with IOC-priority filtering.',
      ],
      estimated_effort: 'high',
      confidence: clamp(confidence - 0.1, 0.2, 0.85),
    })
  }

  if (input.include_decompiler) {
    phases.push({
      phase: packed ? 'phase_3' : 'phase_2',
      title: 'Function Recovery',
      objective: 'Recover function-level semantics and prioritize high-value logic.',
      actions: [
        'Run ghidra.analyze and build per-function confidence map.',
        'Use code.functions.rank to focus on entry points and sensitive APIs.',
        'Pair code.function.decompile with disassembly for mismatch review.',
      ],
      estimated_effort: input.depth === 'deep' ? 'high' : 'medium',
      confidence: clamp(confidence - (packed ? 0.15 : 0.05), 0.2, 0.9),
    })
  }

  phases.push({
    phase: packed ? (input.include_decompiler ? 'phase_4' : 'phase_3') : (input.include_decompiler ? 'phase_3' : 'phase_2'),
    title: isDotNet ? '.NET Structure Rebuild' : 'Module Recomposition',
    objective: isDotNet
      ? 'Recover assembly/type/method structure and generate maintainable C# project skeleton.'
      : 'Cluster functions into modules and produce source-like pseudocode packages.',
    actions: isDotNet
      ? [
          'Extract namespace/type graph and identify business-critical methods.',
          'Reconstruct method bodies with IL fallback when C# decompilation is uncertain.',
          'Export project skeleton with unresolved gaps documented.',
        ]
      : [
          'Group functions by call graph and shared constants/strings.',
          'Promote stable symbols and infer interfaces/data structures.',
          'Export source-like files with confidence annotations and TODO gaps.',
        ],
    estimated_effort: 'high',
    confidence: clamp(confidence - 0.1, 0.2, 0.85),
  })

  return phases
}

export function createCodeReconstructPlanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
  dependencies?: ReconstructPlanDependencies
) {
  const runtimeDetectHandler =
    dependencies?.runtimeDetectHandler ||
    createRuntimeDetectHandler(workspaceManager, database, cacheManager)
  const packerDetectHandler =
    dependencies?.packerDetectHandler ||
    createPackerDetectHandler(workspaceManager, database, cacheManager)

  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as CodeReconstructPlanInput
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }

      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          target_language: input.target_language,
          depth: input.depth,
          include_decompiler: input.include_decompiler,
          include_strings: input.include_strings,
        },
      })

      const cachedLookup = await lookupCachedResult(cacheManager, cacheKey)
      if (cachedLookup) {
        return {
          ok: true,
          data: cachedLookup.data,
          warnings: ['Result from cache', formatCacheWarning(cachedLookup.metadata)],
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
            cached: true,
            cache_key: cachedLookup.metadata.key,
            cache_tier: cachedLookup.metadata.tier,
            cache_created_at: cachedLookup.metadata.createdAt,
            cache_expires_at: cachedLookup.metadata.expiresAt,
            cache_hit_at: cachedLookup.metadata.fetchedAt,
          },
        }
      }

      const warnings: string[] = []

      const runtimeResult = await runtimeDetectHandler({ sample_id: input.sample_id })
      let runtimeData: RuntimeDetectData | undefined
      if (runtimeResult.ok && runtimeResult.data) {
        runtimeData = runtimeResult.data as RuntimeDetectData
      } else {
        warnings.push(
          `runtime.detect unavailable: ${(runtimeResult.errors || ['unknown error']).join('; ')}`
        )
      }

      const packerResult = await packerDetectHandler({
        sample_id: input.sample_id,
        engines: ['yara', 'entropy', 'entrypoint'],
      })
      let packerData: PackerDetectData | undefined
      if (packerResult.ok && packerResult.data) {
        packerData = packerResult.data as PackerDetectData
      } else {
        warnings.push(
          `packer.detect unavailable: ${(packerResult.errors || ['unknown error']).join('; ')}`
        )
      }

      const assessment = assessReconstructability(runtimeData, packerData)
      const phases = buildPhases(input, runtimeData, packerData, assessment.confidence)

      const recommendations: string[] = [
        'Treat reconstruction as semantic recovery, not literal source restoration.',
        'Prioritize top-ranked functions and entry points before broad decompilation.',
        'Keep a confidence map and flag low-confidence blocks for manual review.',
      ]

      const primaryRuntime = pickPrimaryRuntime(runtimeData).toLowerCase()
      if (primaryRuntime.includes('dotnet') || runtimeData?.is_dotnet) {
        recommendations.push(
          'Use .NET-oriented extraction first (types/method metadata) to maximize readable source output.'
        )
      } else {
        recommendations.push(
          'For native binaries, export C-like pseudocode modules with explicit TODOs for unresolved semantics.'
        )
      }

      if (packerData?.packed) {
        recommendations.push('Complete unpacking/deobfuscation before claiming source-level conclusions.')
      }

      const outputData = {
        feasibility: assessment.feasibility,
        confidence: assessment.confidence,
        restoration_expectation: assessment.restorationExpectation,
        runtime_summary: {
          primary_runtime: pickPrimaryRuntime(runtimeData),
          suspected: runtimeData?.suspected || [],
        },
        packing_summary: {
          packed: packerData?.packed === true,
          confidence: clamp(packerData?.confidence ?? 0, 0, 1),
        },
        blockers: assessment.blockers,
        recommendations,
        phases,
      }

      await cacheManager.setCachedResult(cacheKey, outputData, CACHE_TTL_MS, sample.sha256)

      return {
        ok: true,
        data: outputData,
        warnings: warnings.length > 0 ? warnings : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}

