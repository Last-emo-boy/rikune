/**
 * hash.resolver.plan tool.
 *
 * Scans the sample prefix for API resolver signals and hash-like constants,
 * then produces a bounded plan for hash.identify / hash.resolve and runtime
 * breakpoint follow-up. This is static planning only; it never executes the sample.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'hash.resolver.plan'
const TOOL_VERSION = '0.1.0'

interface ExtractedString {
  value: string
  offset: number
}

interface ResolverIndicator {
  indicator: string
  category: string
  confidence: number
  offset?: number
  evidence: string[]
}

interface HashCandidate {
  value: string
  normalized: string
  source: 'string_hex' | 'raw_dword_le' | 'raw_dword_be'
  offset?: number
  confidence: number
  evidence: string[]
}

const RESOLVER_PATTERNS: Array<{
  pattern: RegExp
  indicator: string
  category: string
  confidence: number
  evidence: string
}> = [
  {
    pattern: /\bGetProcAddress\b/i,
    indicator: 'GetProcAddress',
    category: 'dynamic_api_resolution',
    confidence: 0.92,
    evidence: 'resolver_api_string',
  },
  {
    pattern: /\bLoadLibrary(?:A|W|ExA|ExW)?\b/i,
    indicator: 'LoadLibrary',
    category: 'dynamic_api_resolution',
    confidence: 0.9,
    evidence: 'loader_api_string',
  },
  {
    pattern: /\bLdrGetProcedureAddress\b/i,
    indicator: 'LdrGetProcedureAddress',
    category: 'native_dynamic_resolution',
    confidence: 0.92,
    evidence: 'native_resolver_api_string',
  },
  {
    pattern: /\bLdrLoadDll\b/i,
    indicator: 'LdrLoadDll',
    category: 'native_dynamic_resolution',
    confidence: 0.9,
    evidence: 'native_loader_api_string',
  },
  {
    pattern: /\bPEB\b|\bInMemoryOrderModuleList\b|\bLDR_DATA_TABLE_ENTRY\b/i,
    indicator: 'PEB module walk',
    category: 'manual_module_walk',
    confidence: 0.78,
    evidence: 'peb_walk_string',
  },
  {
    pattern: /\bkernel32\.dll\b/i,
    indicator: 'kernel32.dll',
    category: 'resolver_module',
    confidence: 0.74,
    evidence: 'resolver_module_string',
  },
  {
    pattern: /\bntdll\.dll\b/i,
    indicator: 'ntdll.dll',
    category: 'resolver_module',
    confidence: 0.72,
    evidence: 'native_module_string',
  },
]

const LOW_VALUE_DWORDS = new Set([
  0x00000000, 0xffffffff, 0xcccccccc, 0x90909090, 0x41414141, 0x42424242, 0xdeadbeef,
])

export const hashResolverPlanInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_candidates: z.number().int().min(1).max(256).optional().default(64),
  max_scan_bytes: z
    .number()
    .int()
    .min(4096)
    .max(16 * 1024 * 1024)
    .optional()
    .default(2 * 1024 * 1024),
  include_raw_dwords: z.boolean().optional().default(true),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

export const hashResolverPlanOutputSchema = z
  .object({
    ok: z.boolean(),
    data: z
      .object({
        schema: z.string(),
        tool_version: z.string(),
        sample_id: z.string(),
        source: z.object({
          file_name: z.string(),
          total_size: z.number().int().nonnegative(),
          scanned_bytes: z.number().int().nonnegative(),
          truncated: z.boolean(),
        }),
        resolver_indicators: z.array(z.any()),
        hash_candidates: z.array(z.any()),
        recommended_hashes: z.array(z.string()),
        algorithm_hints: z.array(z.any()),
        confidence_summary: z.object({}).passthrough(),
        evidence_summary: z.object({}).passthrough(),
        workflow_handoff: z.object({}).passthrough(),
        quality_gates: z.object({}).passthrough(),
        recommended_next_tools: z.array(z.string()),
        next_actions: z.array(z.string()),
        warnings: z.array(z.string()),
      })
      .passthrough()
      .optional(),
    warnings: z.array(z.string()).optional(),
    errors: z.array(z.string()).optional(),
    artifacts: z.array(z.any()).optional(),
    metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
  })
  .passthrough()

export const hashResolverPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Statically scan a sample for API resolver strings, PEB/module-walk hints, and hash-like constants, then produce a bounded resolver plan for hash.identify/hash.resolve and runtime breakpoint follow-up. Does not execute the sample.',
  inputSchema: hashResolverPlanInputSchema,
  outputSchema: hashResolverPlanOutputSchema,
  aspects: {
    formats: ['pe', 'shellcode', 'raw-bytes'],
    platforms: ['windows'],
    architectures: ['x86', 'x64'],
    execution: ['static', 'triage', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'api-hash-resolution',
      'shellcode-analysis',
      'imports',
      'deobfuscation',
      'workflow-plan',
      'evidence-handoff',
    ],
    evidence: ['imports', 'strings', 'shellcode', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'api_hash_resolver_plan',
      description:
        'Static API resolver indicators, hash candidates, resolution workflow handoff, and passive quality gates',
      mime: 'application/json',
    },
  ],
  evidence: [
    { category: 'imports', artifactTypes: ['api_hash_resolver_plan'] },
    { category: 'strings', artifactTypes: ['api_hash_resolver_plan'] },
    { category: 'shellcode', artifactTypes: ['api_hash_resolver_plan'] },
    { category: 'workflow', artifactTypes: ['api_hash_resolver_plan'] },
    { category: 'provenance', artifactTypes: ['api_hash_resolver_plan'] },
  ],
  workflowRecipes: [
    {
      id: 'api-hash.resolver-recovery',
      title: 'API hash resolver recovery',
      description:
        'Use passive resolver indicators and hash-like constants to identify algorithms, resolve API names, publish evidence graph nodes, and gate any runtime breakpoint follow-up behind explicit opt-in.',
      startsWith: ['hash.resolver.plan', 'strings.extract', 'static.behavior.classify'],
      nextTools: [
        'hash.identify',
        'hash.resolve',
        'analysis.evidence.graph',
        'report.generate',
        'breakpoint.smart',
        'trace.condition',
      ],
      requiredArtifacts: [],
      producesArtifacts: ['api_hash_resolver_plan'],
      evidence: ['imports', 'strings', 'shellcode', 'workflow', 'provenance'],
      safety: ['passive', 'opt_in_dynamic', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

async function readSamplePrefix(
  samplePath: string,
  maxBytes: number
): Promise<{
  buffer: Buffer
  totalSize: number
  scannedBytes: number
  truncated: boolean
}> {
  const handle = await fs.open(samplePath, 'r')
  try {
    const stat = await handle.stat()
    const scannedBytes = Math.min(stat.size, maxBytes)
    const buffer = Buffer.alloc(scannedBytes)
    await handle.read(buffer, 0, scannedBytes, 0)
    return {
      buffer,
      totalSize: stat.size,
      scannedBytes,
      truncated: stat.size > scannedBytes,
    }
  } finally {
    await handle.close()
  }
}

function extractAsciiStrings(buffer: Buffer, maxStrings = 1500): ExtractedString[] {
  const strings: ExtractedString[] = []
  let start = -1
  let chars: number[] = []

  function flush(endOffset: number) {
    if (chars.length >= 4 && strings.length < maxStrings) {
      strings.push({
        value: Buffer.from(chars).toString('ascii'),
        offset: start >= 0 ? start : endOffset - chars.length,
      })
    }
    start = -1
    chars = []
  }

  for (let offset = 0; offset < buffer.length; offset += 1) {
    const value = buffer[offset]
    if (value >= 0x20 && value <= 0x7e) {
      if (start < 0) {
        start = offset
      }
      chars.push(value)
      if (chars.length > 512) {
        flush(offset)
      }
    } else {
      flush(offset)
    }
  }
  flush(buffer.length)

  return strings
}

function normalizeHashToken(value: string): string | null {
  const trimmed = value.trim().replace(/^0x/i, '')
  if (!/^[a-f0-9]{8}$/i.test(trimmed)) {
    return null
  }
  return `0x${trimmed.toLowerCase()}`
}

function isPlausibleHashDword(value: number): boolean {
  if (!Number.isFinite(value) || value < 0x10000) {
    return false
  }
  if (LOW_VALUE_DWORDS.has(value >>> 0)) {
    return false
  }
  const bytes = [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]
  const printable = bytes.filter((item) => item >= 0x20 && item <= 0x7e).length
  return printable < 4
}

function collectResolverIndicators(strings: ExtractedString[]): ResolverIndicator[] {
  const indicators = new Map<string, ResolverIndicator>()
  for (const item of strings) {
    for (const rule of RESOLVER_PATTERNS) {
      if (!rule.pattern.test(item.value)) {
        continue
      }
      const existing = indicators.get(rule.indicator)
      indicators.set(rule.indicator, {
        indicator: rule.indicator,
        category: rule.category,
        confidence: Math.max(existing?.confidence || 0, rule.confidence),
        offset: existing?.offset ?? item.offset,
        evidence: Array.from(new Set([...(existing?.evidence || []), rule.evidence])),
      })
    }
  }
  return Array.from(indicators.values()).sort((left, right) => right.confidence - left.confidence)
}

function collectHashCandidates(
  strings: ExtractedString[],
  buffer: Buffer,
  indicators: ResolverIndicator[],
  options: { includeRawDwords: boolean; maxCandidates: number }
): HashCandidate[] {
  const candidates = new Map<string, HashCandidate>()
  const indicatorOffsets = indicators
    .map((item) => item.offset)
    .filter((item): item is number => typeof item === 'number')

  function nearResolver(offset: number): boolean {
    return indicatorOffsets.some((indicatorOffset) => Math.abs(indicatorOffset - offset) <= 2048)
  }

  function upsert(candidate: HashCandidate) {
    const existing = candidates.get(candidate.normalized)
    if (!existing || candidate.confidence > existing.confidence) {
      candidates.set(candidate.normalized, candidate)
      return
    }
    existing.evidence = Array.from(new Set([...existing.evidence, ...candidate.evidence]))
  }

  for (const item of strings) {
    const matches = item.value.matchAll(/\b(?:0x)?[a-f0-9]{8}\b/gi)
    for (const match of matches) {
      const normalized = normalizeHashToken(match[0])
      if (!normalized) {
        continue
      }
      const offset = item.offset + (match.index || 0)
      upsert({
        value: match[0],
        normalized,
        source: 'string_hex',
        offset,
        confidence: nearResolver(offset) ? 0.84 : 0.68,
        evidence: [nearResolver(offset) ? 'hex_token_near_resolver_string' : 'hex_token_string'],
      })
    }
  }

  if (options.includeRawDwords) {
    for (
      let offset = 0;
      offset + 4 <= buffer.length && candidates.size < options.maxCandidates * 4;
      offset += 4
    ) {
      const le = buffer.readUInt32LE(offset)
      if (isPlausibleHashDword(le)) {
        const normalized = `0x${le.toString(16).padStart(8, '0')}`
        const nearby = nearResolver(offset)
        upsert({
          value: normalized,
          normalized,
          source: 'raw_dword_le',
          offset,
          confidence: nearby ? 0.62 : 0.34,
          evidence: [nearby ? 'raw_dword_near_resolver_string' : 'raw_dword_sample_prefix'],
        })
      }
      const be = buffer.readUInt32BE(offset)
      if (be !== le && isPlausibleHashDword(be)) {
        const normalized = `0x${be.toString(16).padStart(8, '0')}`
        const nearby = nearResolver(offset)
        upsert({
          value: normalized,
          normalized,
          source: 'raw_dword_be',
          offset,
          confidence: nearby ? 0.56 : 0.3,
          evidence: [nearby ? 'raw_dword_be_near_resolver_string' : 'raw_dword_be_sample_prefix'],
        })
      }
    }
  }

  return Array.from(candidates.values())
    .sort((left, right) => {
      if (right.confidence !== left.confidence) {
        return right.confidence - left.confidence
      }
      return (left.offset || 0) - (right.offset || 0)
    })
    .slice(0, options.maxCandidates)
}

function buildAlgorithmHints(indicators: ResolverIndicator[], candidates: HashCandidate[]) {
  const hasResolver = indicators.some(
    (item) => item.category.includes('resolution') || item.category.includes('walk')
  )
  const candidateCount = candidates.length
  const baseConfidence = hasResolver ? 0.76 : candidateCount >= 8 ? 0.58 : 0.42

  return [
    {
      algorithm: 'ror13',
      confidence: Math.min(0.95, baseConfidence + 0.1),
      rationale: [
        'Common shellcode API hashing algorithm.',
        hasResolver
          ? 'Resolver or module-walk indicators were found.'
          : 'Use as first-pass fallback.',
      ].filter(Boolean),
    },
    {
      algorithm: 'ror13_additive',
      confidence: Math.min(0.9, baseConfidence + 0.06),
      rationale: [
        'Common DLL+API additive hash variant.',
        hasResolver
          ? 'Loader/resolver strings support DLL-aware matching.'
          : 'Useful when API-only hashes do not match.',
      ].filter(Boolean),
    },
    {
      algorithm: 'crc32',
      confidence: Math.min(0.82, baseConfidence),
      rationale: ['Common compact resolver hash family.'],
    },
    {
      algorithm: 'djb2',
      confidence: Math.min(0.72, baseConfidence - 0.04),
      rationale: ['Common malware string/API hash fallback.'],
    },
    {
      algorithm: 'fnv1a',
      confidence: Math.min(0.68, baseConfidence - 0.08),
      rationale: ['Useful when rotate/additive and CRC families do not resolve.'],
    },
  ].filter((item) => item.confidence > 0.2)
}

function countHighConfidence<T extends { confidence: number }>(
  items: T[],
  threshold: number
): number {
  return items.filter((item) => item.confidence >= threshold).length
}

function summarizeResolverIndicators(indicators: ResolverIndicator[]) {
  return indicators.slice(0, 8).map((item) => ({
    indicator: item.indicator,
    category: item.category,
    confidence: item.confidence,
    offset: item.offset ?? null,
    evidence: item.evidence,
  }))
}

function summarizeHashCandidates(candidates: HashCandidate[]) {
  return candidates.slice(0, 12).map((item) => ({
    value: item.normalized,
    source: item.source,
    confidence: item.confidence,
    offset: item.offset ?? null,
    evidence: item.evidence,
  }))
}

function buildEvidenceSummary(args: {
  source: { fileName: string; totalSize: number; scannedBytes: number; truncated: boolean }
  resolverIndicators: ResolverIndicator[]
  hashCandidates: HashCandidate[]
  recommendedHashes: string[]
  algorithmHints: Array<{ algorithm: string; confidence: number; rationale: string[] }>
  includeRawDwords: boolean
  warnings: string[]
}) {
  return {
    schema: 'rikune.api_hash.resolver_evidence_summary.v1',
    source_tool: TOOL_NAME,
    source: {
      file_name: args.source.fileName,
      total_size: args.source.totalSize,
      scanned_bytes: args.source.scannedBytes,
      truncated: args.source.truncated,
    },
    resolver_indicator_count: args.resolverIndicators.length,
    high_confidence_resolver_indicator_count: countHighConfidence(args.resolverIndicators, 0.75),
    hash_candidate_count: args.hashCandidates.length,
    high_confidence_hash_candidate_count: countHighConfidence(args.hashCandidates, 0.5),
    recommended_hash_count: args.recommendedHashes.length,
    algorithm_hint_count: args.algorithmHints.length,
    raw_dword_scan_enabled: args.includeRawDwords,
    warnings: args.warnings,
    warning_count: args.warnings.length,
    top_resolver_indicators: summarizeResolverIndicators(args.resolverIndicators),
    top_hash_candidates: summarizeHashCandidates(args.hashCandidates),
    top_algorithm_hints: args.algorithmHints.slice(0, 5).map((item) => ({
      algorithm: item.algorithm,
      confidence: item.confidence,
      rationale: item.rationale,
    })),
  }
}

function buildWorkflowHandoff(args: {
  sampleId: string
  resolverIndicators: ResolverIndicator[]
  hashCandidates: HashCandidate[]
  recommendedHashes: string[]
  algorithmHints: Array<{ algorithm: string; confidence: number; rationale: string[] }>
  warnings: string[]
}) {
  const hasRecommendedHashes = args.recommendedHashes.length > 0
  const algorithmNames = args.algorithmHints.map((item) => item.algorithm)

  return {
    schema: 'rikune.api_hash.resolver_workflow_handoff.v1',
    handoff_mode: 'api_hash_resolver_to_resolution',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    recommended_next_tools: [
      'hash.identify',
      'hash.resolve',
      'analysis.evidence.graph',
      'report.generate',
      'breakpoint.smart',
      'trace.condition',
    ],
    resolver_context: {
      resolver_indicators: summarizeResolverIndicators(args.resolverIndicators),
      recommended_hashes: args.recommendedHashes.slice(0, 24),
      algorithm_candidates: algorithmNames.slice(0, 8),
      candidate_preview: summarizeHashCandidates(args.hashCandidates),
    },
    routing: [
      {
        goal: 'hash-algorithm-identification',
        priority: hasRecommendedHashes ? 'high' : 'normal',
        next_tools: ['hash.identify'],
        required_evidence: ['recommended_hashes', 'algorithm_hints'],
      },
      {
        goal: 'api-name-resolution',
        priority: hasRecommendedHashes ? 'high' : 'blocked-until-hash-candidates',
        next_tools: ['hash.resolve'],
        required_evidence: ['hash.identify result', 'api_hash_resolver_plan'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'normal',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: ['api_hash_resolver_plan'],
      },
      {
        goal: 'runtime-resolver-capture',
        priority: 'optional-opt-in',
        next_tools: ['breakpoint.smart', 'trace.condition'],
        required_evidence: ['explicit analyst opt-in', 'isolated runtime plan'],
      },
    ],
    artifact_contract: {
      consumes: ['sample prefix bytes', 'ascii strings', 'hash-like constants'],
      produces: ['api_hash_resolver_plan'],
      expected_consumers: [
        'hash.identify',
        'hash.resolve',
        'analysis.evidence.graph',
        'report.generate',
      ],
    },
    dynamic_boundary: {
      runtime_started_by_tool: false,
      sample_executed_by_tool: false,
      network_accessed_by_tool: false,
      runtime_followup_requires_opt_in: true,
    },
    warnings: args.warnings,
  }
}

function buildQualityGates(args: {
  resolverIndicators: ResolverIndicator[]
  hashCandidates: HashCandidate[]
  recommendedHashes: string[]
  warnings: string[]
}) {
  return {
    passive_static_only: true,
    sample_executed: false,
    backend_started: false,
    network_accessed: false,
    mutation_performed: false,
    resolver_evidence_present: args.resolverIndicators.length > 0,
    hash_candidates_present: args.hashCandidates.length > 0,
    recommended_hashes_present: args.recommendedHashes.length > 0,
    evidence_graph_handoff_ready:
      args.resolverIndicators.length > 0 || args.hashCandidates.length > 0,
    runtime_followup_requires_opt_in: true,
    analyst_review_required:
      args.warnings.length > 0 ||
      args.resolverIndicators.length === 0 ||
      args.recommendedHashes.length === 0,
    warning_count: args.warnings.length,
  }
}

export function createHashResolverPlanHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = hashResolverPlanInputSchema.parse(args || {})
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { buffer, totalSize, scannedBytes, truncated } = await readSamplePrefix(
        samplePath,
        input.max_scan_bytes
      )
      const strings = extractAsciiStrings(buffer)
      const resolverIndicators = collectResolverIndicators(strings)
      const hashCandidates = collectHashCandidates(strings, buffer, resolverIndicators, {
        includeRawDwords: input.include_raw_dwords,
        maxCandidates: input.max_candidates,
      })
      const recommendedHashes = hashCandidates
        .filter((item) => item.confidence >= 0.5)
        .slice(0, 24)
        .map((item) => item.normalized)
      const algorithmHints = buildAlgorithmHints(resolverIndicators, hashCandidates)
      const warnings: string[] = []

      if (truncated) {
        warnings.push(
          `Only scanned the first ${scannedBytes} of ${totalSize} bytes. Increase max_scan_bytes for a deeper resolver sweep.`
        )
      }
      if (resolverIndicators.length === 0) {
        warnings.push(
          'No explicit dynamic resolver strings were found in the scanned sample prefix.'
        )
      }
      if (recommendedHashes.length === 0) {
        warnings.push(
          'No high-confidence hash constants were found; raw DWORD candidates may be noisy.'
        )
      }
      const evidenceSummary = buildEvidenceSummary({
        source: {
          fileName: path.basename(samplePath),
          totalSize,
          scannedBytes,
          truncated,
        },
        resolverIndicators,
        hashCandidates,
        recommendedHashes,
        algorithmHints,
        includeRawDwords: input.include_raw_dwords,
        warnings,
      })
      const workflowHandoff = buildWorkflowHandoff({
        sampleId: input.sample_id,
        resolverIndicators,
        hashCandidates,
        recommendedHashes,
        algorithmHints,
        warnings,
      })
      const qualityGates = buildQualityGates({
        resolverIndicators,
        hashCandidates,
        recommendedHashes,
        warnings,
      })

      const data = {
        schema: 'rikune.api_hash_resolver_plan.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        source: {
          file_name: path.basename(samplePath),
          total_size: totalSize,
          scanned_bytes: scannedBytes,
          truncated,
        },
        resolver_indicators: resolverIndicators,
        hash_candidates: hashCandidates,
        recommended_hashes: recommendedHashes,
        algorithm_hints: algorithmHints,
        confidence_summary: {
          resolver_indicator_count: resolverIndicators.length,
          hash_candidate_count: hashCandidates.length,
          high_confidence_hash_count: recommendedHashes.length,
          raw_dword_scan_enabled: input.include_raw_dwords,
        },
        evidence_summary: evidenceSummary,
        workflow_handoff: workflowHandoff,
        quality_gates: qualityGates,
        recommended_next_tools: [
          'hash.identify',
          'hash.resolve',
          'analysis.evidence.graph',
          'report.generate',
          'breakpoint.smart',
          'trace.condition',
          'dynamic.behavior.diff',
        ],
        next_actions:
          recommendedHashes.length > 0
            ? [
                `Run hash.identify with hashes=${JSON.stringify(recommendedHashes.slice(0, 12))}.`,
                'Use hash.resolve with the best-matching algorithm to recover API names.',
                'If runtime is available, convert resolver APIs into breakpoint.smart / trace.condition capture points.',
              ]
            : [
                'Run static.config.carver and strings.extract(mode=full) to collect more resolver context.',
                'If runtime is available, trace GetProcAddress/LdrGetProcedureAddress hits before attempting custom hash recovery.',
              ],
        warnings,
      }

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        artifacts.push(
          await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'api_hash_resolver_plan',
            'hash_resolver_plan',
            data,
            input.session_tag
          )
        )
      }

      return {
        ok: true,
        data,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
