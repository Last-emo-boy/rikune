/**
 * javascript.obfuscation.profile - passive JavaScript obfuscation and JSVMP triage.
 *
 * The tool reads source text only. It does not evaluate JavaScript, instantiate V8, call Node,
 * fetch source maps, or run an external deobfuscator.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'javascript.obfuscation.profile'
const DEFAULT_MAX_READ_BYTES = 2 * 1024 * 1024
const MAX_READ_BYTES = 16 * 1024 * 1024

const JavascriptPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_interpreter_start: z.literal(true),
  no_network: z.literal(true),
  no_external_deobfuscator: z.literal(true),
})

const JavascriptSignalSchema = z.object({
  id: z.string(),
  label: z.string(),
  confidence: z.number(),
  indicators: z.array(z.string()),
})

const JavascriptToolCandidateSchema = z.object({
  id: z.string(),
  name: z.string(),
  source: z.string(),
  role: z.string(),
  readiness: z.enum(['metadata_only', 'optional_external', 'future_worker']),
  notes: z.array(z.string()),
})

const JavascriptProfileSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  size: z.number().optional(),
  source_preview_bytes: z.number(),
  lexical_summary: z.object({
    line_count: z.number(),
    char_count: z.number(),
    minified_line_ratio: z.number(),
    long_identifier_count: z.number(),
    short_identifier_ratio: z.number(),
    string_literal_count: z.number(),
    numeric_literal_count: z.number(),
    large_array_count: z.number(),
    switch_case_count: z.number(),
    eval_like_call_count: z.number(),
  }),
  signals: z.array(JavascriptSignalSchema),
  jsvmp_assessment: z.object({
    suspected: z.boolean(),
    score: z.number(),
    handler_hints: z.array(z.string()),
    bytecode_container_hints: z.array(z.string()),
    dispatch_hints: z.array(z.string()),
  }),
  deobfuscation_plan: z.object({
    status: z.literal('plan_only'),
    stages: z.array(z.string()),
    optional_tool_candidates: z.array(JavascriptToolCandidateSchema),
    recommended_next_tools: z.array(z.string()),
  }),
  policy: JavascriptPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const JavascriptObfuscationProfileInputSchema = z.object({
  sample_id: z.string().describe('Target JavaScript, HTML, source-map, or V8-cache sample ID.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_READ_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive JavaScript triage.'),
  persist_artifact: z.boolean().default(true).describe('Persist the profile JSON artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const JavascriptObfuscationProfileOutputSchema = z.object({
  ok: z.boolean(),
  data: JavascriptProfileSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  warnings: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const javascriptObfuscationProfileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively profile JavaScript obfuscation, VM-style dispatch, and JSVMP-like bytecode containers without evaluating the script or invoking Node/V8.',
  inputSchema: JavascriptObfuscationProfileInputSchema,
  outputSchema: JavascriptObfuscationProfileOutputSchema,
  aspects: {
    formats: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html', 'v8-cache'],
    platforms: ['node', 'browser', 'cross-platform'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'javascript-deobfuscation',
      'jsvmp-triage',
      'vm-dispatch-detection',
      'jsir-plan',
      'routing',
    ],
    evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'javascript_obfuscation_profile',
      description: 'Passive JavaScript obfuscation, JSVMP, and deobfuscation planning profile',
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: ['javascript_obfuscation_profile'] },
    { category: 'strings', artifactTypes: ['javascript_obfuscation_profile'] },
    { category: 'behavior', artifactTypes: ['javascript_obfuscation_profile'] },
    { category: 'workflow', artifactTypes: ['javascript_obfuscation_profile'] },
  ],
  workflowRecipes: [
    {
      id: 'javascript.deobfuscation.jsvmp-triage',
      title: 'JavaScript and JSVMP passive deobfuscation triage',
      description:
        'Profile obfuscated JavaScript, identify VM-dispatch and bytecode container hints, then route to optional JSIR/CASCADE, REstringer, strings, YARA, and reporting work without executing the script.',
      startsWith: ['javascript.obfuscation.profile', 'strings.extract'],
      nextTools: ['strings.extract', 'yara.generate', 'analysis.evidence.graph', 'report.generate'],
      producesArtifacts: ['javascript_obfuscation_profile'],
      evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

export type JavascriptObfuscationProfile = z.infer<typeof JavascriptProfileSchema>

function clampRatio(value: number): number {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(1, Number(value.toFixed(3))))
}

function countMatches(source: string, pattern: RegExp): number {
  return source.match(pattern)?.length ?? 0
}

function uniqueStrings(values: string[], limit = 20): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0))).slice(0, limit)
}

function regexHints(source: string, pattern: RegExp, limit = 20): string[] {
  const hints: string[] = []
  for (const match of source.matchAll(pattern)) {
    hints.push(match[0].slice(0, 160))
    if (hints.length >= limit) break
  }
  return uniqueStrings(hints, limit)
}

function buildSignal(
  id: string,
  label: string,
  confidence: number,
  indicators: string[]
): z.infer<typeof JavascriptSignalSchema> | null {
  const normalized = uniqueStrings(indicators)
  if (normalized.length === 0) return null
  return {
    id,
    label,
    confidence: clampRatio(confidence),
    indicators: normalized,
  }
}

function buildToolCandidates(): z.infer<typeof JavascriptToolCandidateSchema>[] {
  return [
    {
      id: 'google-jsir-cascade',
      name: 'Google JSIR / CASCADE pipeline',
      source: 'https://github.com/google/jsir',
      role: 'Normalize JavaScript into an IR suitable for structured deobfuscation passes.',
      readiness: 'optional_external',
      notes: [
        'Treat as an optional external backend until a local worker contract is implemented.',
        'Use only on analyst-provided local source; no network lookup is required by this planner.',
      ],
    },
    {
      id: 'humansecurity-restringer',
      name: 'REstringer',
      source: 'https://github.com/HumanSecurity/restringer',
      role: 'Recover common string and expression obfuscation patterns before deeper VM triage.',
      readiness: 'optional_external',
      notes: [
        'Best used after passive profile confirms string-array or eval-like obfuscation.',
        'Keep execution disabled; integrate through a bounded static worker first.',
      ],
    },
    {
      id: 'jsimplifier-pipeline',
      name: 'JSIMPLIFIER-style pipeline',
      source: 'https://arxiv.org/abs/2512.14070',
      role: 'Use a staged AST/static-analysis, tracing, and identifier-recovery blueprint for future JavaScript deobfuscation workers.',
      readiness: 'future_worker',
      notes: [
        'Treat the paper as a design target for local fixtures and benchmarks, not as a default runtime dependency.',
        'Keep any dynamic trace stage outside the default passive profile path.',
      ],
    },
    {
      id: 'jsvmp-handler-map',
      name: 'JSVMP handler-map recovery',
      source: 'local-analysis-pattern',
      role: 'Recover bytecode arrays, dispatch loops, opcode handlers, and stack/register semantics.',
      readiness: 'future_worker',
      notes: [
        'Implement as local parser plus IR extraction before any interpreter-assisted workflow.',
        'Never execute the protected JavaScript VM during default analysis.',
      ],
    },
  ]
}

export function buildJavascriptObfuscationProfileFromSource(
  source: string,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): JavascriptObfuscationProfile {
  const lines = source.length > 0 ? source.split(/\r?\n/) : []
  const nonEmptyLines = lines.filter((line) => line.trim().length > 0)
  const longLines = nonEmptyLines.filter((line) => line.length > 500).length
  const identifiers = source.match(/\b[$A-Za-z_][$\w]{0,80}\b/g) ?? []
  const shortIdentifiers = identifiers.filter((id) => id.length <= 2).length
  const longIdentifierCount = identifiers.filter((id) => id.length >= 40).length
  const stringLiteralCount = countMatches(source, /(["'`])(?:\\.|(?!\1)[\s\S]){0,200}\1/g)
  const numericLiteralCount = countMatches(source, /\b(?:0x[0-9a-fA-F]+|\d{2,})\b/g)
  const largeArrayCount = countMatches(source, /\[[\s\S]{120,}?\]/g)
  const switchCaseCount = countMatches(
    source,
    /\bcase\s+(?:0x[0-9a-fA-F]+|\d+|["'][^"']+["'])\s*:/g
  )
  const evalLikeCallCount = countMatches(
    source,
    /\b(?:eval|Function|setTimeout|setInterval|atob|btoa|unescape)\s*\(/g
  )
  const whileTrueCount = countMatches(source, /\bwhile\s*\(\s*(?:true|!!\[\]|1)\s*\)/g)
  const dispatchHints = regexHints(
    source,
    /\b(?:while\s*\(\s*(?:true|!!\[\]|1)\s*\)|switch\s*\([^)]+\)|case\s+(?:0x[0-9a-fA-F]+|\d+)\s*:)/g,
    12
  )
  const bytecodeContainerHints = regexHints(
    source,
    /\b(?:bytecode|opcodes?|handlers?|virtual(?:Machine)?|vm|dispatch|pc|ip|stack|regs?)\b|(?:\[[\d,\s]{120,}\])/gi,
    16
  )
  const handlerHints = regexHints(
    source,
    /\b(?:handlers?|opcodes?|dispatch|stack|registers?|pc|ip)\b|(?:function\s+[$A-Za-z_][$\w]*\s*\([^)]{0,80}\)\s*\{)/gi,
    16
  )

  const signals = [
    buildSignal(
      'minified-source',
      'Minified or packed source',
      longLines / Math.max(nonEmptyLines.length, 1),
      [longLines > 0 ? `${longLines} line(s) longer than 500 characters` : '']
    ),
    buildSignal(
      'string-array-obfuscation',
      'String array or literal-heavy obfuscation',
      largeArrayCount > 0 ? 0.72 : 0,
      [
        largeArrayCount > 0 ? `${largeArrayCount} large array literal(s)` : '',
        stringLiteralCount > 100 ? `${stringLiteralCount} string literal(s)` : '',
      ]
    ),
    buildSignal(
      'eval-like-codegen',
      'Eval-like code generation',
      evalLikeCallCount > 0 ? 0.78 : 0,
      [evalLikeCallCount > 0 ? `${evalLikeCallCount} eval/codegen-like call(s)` : '']
    ),
    buildSignal(
      'control-flow-dispatch',
      'Switch/loop dispatch pattern',
      switchCaseCount > 4 || whileTrueCount > 0 ? 0.81 : 0,
      [
        switchCaseCount > 0 ? `${switchCaseCount} switch case label(s)` : '',
        whileTrueCount > 0 ? `${whileTrueCount} while(true)-style loop(s)` : '',
      ]
    ),
    buildSignal(
      'jsvmp-like-vm',
      'JSVMP-like VM structure',
      bytecodeContainerHints.length >= 3 && dispatchHints.length >= 2 ? 0.86 : 0,
      [...bytecodeContainerHints.slice(0, 6), ...dispatchHints.slice(0, 6)]
    ),
  ].filter((signal): signal is z.infer<typeof JavascriptSignalSchema> => Boolean(signal))

  const jsvmpScore = clampRatio(
    Math.min(
      1,
      switchCaseCount * 0.025 +
        whileTrueCount * 0.15 +
        bytecodeContainerHints.length * 0.04 +
        handlerHints.length * 0.025 +
        largeArrayCount * 0.08
    )
  )
  const suspectedJsvmp = jsvmpScore >= 0.45
  const optionalToolCandidates = buildToolCandidates()
  const recommendedNextTools = suspectedJsvmp
    ? ['strings.extract', 'yara.generate', 'analysis.evidence.graph', 'report.generate']
    : ['strings.extract', 'yara.generate', 'report.generate']

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    size: options.size ?? Buffer.byteLength(source, 'utf8'),
    source_preview_bytes: Buffer.byteLength(source, 'utf8'),
    lexical_summary: {
      line_count: lines.length,
      char_count: source.length,
      minified_line_ratio: clampRatio(longLines / Math.max(nonEmptyLines.length, 1)),
      long_identifier_count: longIdentifierCount,
      short_identifier_ratio: clampRatio(shortIdentifiers / Math.max(identifiers.length, 1)),
      string_literal_count: stringLiteralCount,
      numeric_literal_count: numericLiteralCount,
      large_array_count: largeArrayCount,
      switch_case_count: switchCaseCount,
      eval_like_call_count: evalLikeCallCount,
    },
    signals,
    jsvmp_assessment: {
      suspected: suspectedJsvmp,
      score: jsvmpScore,
      handler_hints: handlerHints,
      bytecode_container_hints: bytecodeContainerHints,
      dispatch_hints: dispatchHints,
    },
    deobfuscation_plan: {
      status: 'plan_only',
      stages: [
        'Collect passive strings and source-map hints.',
        'Recover string-array transforms and constant folding opportunities.',
        'Use JSIMPLIFIER-style staged AST analysis as a benchmark target before adding dynamic traces.',
        'Identify VM bytecode containers, dispatch loop, opcode handlers, and state model.',
        'Export normalized IR or handler map only after analyst opt-in to an external backend.',
      ],
      optional_tool_candidates: optionalToolCandidates,
      recommended_next_tools: recommendedNextTools,
    },
    policy: {
      passive: true,
      no_execute: true,
      no_interpreter_start: true,
      no_network: true,
      no_external_deobfuscator: true,
    },
    summary: `Passive JavaScript profile found ${signals.length} obfuscation signal(s); JSVMP suspicion score ${jsvmpScore}.`,
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Use strings.extract to collect IOC and string-array evidence before any deobfuscation attempt.',
      'If JSVMP is suspected, recover bytecode arrays and handler tables before selecting an external backend.',
      'Keep JSIR/CASCADE and REstringer integration as explicit optional backend work until a bounded worker is added.',
    ],
  }
}

async function readPreview(
  filePath: string,
  maxReadBytes: number
): Promise<{ source: string; size: number; truncated: boolean }> {
  const stat = await fs.stat(filePath)
  const handle = await fs.open(filePath, 'r')
  try {
    const length = Math.min(stat.size, maxReadBytes)
    const data = Buffer.alloc(length)
    await handle.read(data, 0, length, 0)
    return {
      source: data.toString('utf8'),
      size: stat.size,
      truncated: stat.size > length,
    }
  } finally {
    await handle.close()
  }
}

export function createJavascriptObfuscationProfileHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps

  return async (
    args: z.infer<typeof JavascriptObfuscationProfileInputSchema>
  ): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = JavascriptObfuscationProfileInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const preview = await readPreview(samplePath, input.max_read_bytes)
      const profile = buildJavascriptObfuscationProfileFromSource(preview.source, {
        filename: path.basename(samplePath),
        sampleId: input.sample_id,
        size: preview.size,
      })

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
        try {
          const artifact = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'javascript_obfuscation_profile',
            'javascript-obfuscation-profile',
            profile,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: the profile remains useful without persistence.
        }
      }

      return {
        ok: true,
        data: profile,
        warnings: preview.truncated
          ? [`Source preview truncated to ${input.max_read_bytes} byte(s).`]
          : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${error instanceof Error ? error.message : String(error)}`],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
