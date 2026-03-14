/**
 * Triage workflow implementation
 * Quick threat assessment workflow that completes within 5 minutes
 * Requirements: 15.1, 15.2, 15.4, 15.5
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { createPEFingerprintHandler } from '../tools/pe-fingerprint.js'
import { createRuntimeDetectHandler } from '../tools/runtime-detect.js'
import { createPEImportsExtractHandler } from '../tools/pe-imports-extract.js'
import { createStringsExtractHandler } from '../tools/strings-extract.js'
import { createYaraScanHandler } from '../tools/yara-scan.js'
import { createStaticCapabilityTriageHandler } from '../tools/static-capability-triage.js'
import { createPEStructureAnalyzeHandler } from '../tools/pe-structure-analyze.js'
import { createCompilerPackerDetectHandler } from '../tools/compiler-packer-detect.js'

// ============================================================================
// Constants
// ============================================================================

const TOOL_NAME = 'workflow.triage'

// Suspicious API patterns for IOC detection
const HIGH_RISK_APIS = [
  'CreateRemoteThread',
  'VirtualAllocEx',
  'WriteProcessMemory',
  'SetWindowsHookEx',
]

const CONTEXT_DEPENDENT_APIS = [
  'GetAsyncKeyState',
  'InternetOpen',
  'InternetConnect',
  'HttpSendRequest',
  'URLDownloadToFile',
  'WinExec',
  'ShellExecute',
  'CreateProcess',
  'RegSetValue',
  'RegCreateKey',
  'CryptEncrypt',
  'CryptDecrypt',
]

const SUSPICIOUS_APIS = [...new Set([...HIGH_RISK_APIS, ...CONTEXT_DEPENDENT_APIS])]

const LibraryProfileSchema = z.object({
  ecosystems: z.array(z.string()),
  top_crates: z.array(z.string()),
  notable_libraries: z.array(z.string()),
  evidence: z.array(z.string()),
})

const NOTABLE_LIBRARY_HINTS: Array<{ name: string; patterns: RegExp[] }> = [
  { name: 'tokio', patterns: [/\btokio\b/i] },
  { name: 'goblin', patterns: [/\bgoblin\b/i] },
  { name: 'iced-x86', patterns: [/\biced[-_]?x86\b/i] },
  { name: 'clap', patterns: [/\bclap\b/i] },
  { name: 'sysinfo', patterns: [/\bsysinfo\b/i] },
  { name: 'reqwest', patterns: [/\breqwest\b/i] },
  { name: 'serde', patterns: [/\bserde\b/i] },
  { name: 'mio', patterns: [/\bmio\b/i] },
  { name: 'pelite', patterns: [/\bpelite\b/i] },
  { name: 'object', patterns: [/\bobject\b/i] },
  { name: 'winapi', patterns: [/\bwinapi\b/i] },
  { name: 'ntapi', patterns: [/\bntapi\b/i] },
  { name: 'windows-sys', patterns: [/\bwindows[-_]?sys\b/i] },
]

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for triage workflow
 * Requirements: 15.1
 */
export const TriageWorkflowInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  force_refresh: z
    .boolean()
    .optional()
    .default(false)
    .describe('Bypass cache in dependent static tools'),
})

export type TriageWorkflowInput = z.infer<typeof TriageWorkflowInputSchema>

/**
 * IOC (Indicators of Compromise) structure
 * Requirements: 15.2, 15.5
 */
const IOCSchema = z.object({
  suspicious_imports: z.array(z.string()).describe('Suspicious imported functions'),
  suspicious_strings: z.array(z.string()).describe('Suspicious strings found'),
  yara_matches: z.array(z.string()).describe('YARA rule matches'),
  yara_low_confidence: z.array(z.string()).optional().describe('YARA matches downgraded due to weak evidence'),
  urls: z.array(z.string()).optional().describe('URLs found in strings'),
  ip_addresses: z.array(z.string()).optional().describe('IP addresses found'),
  file_paths: z.array(z.string()).optional().describe('File paths found'),
  registry_keys: z.array(z.string()).optional().describe('Registry keys found'),
  high_value_iocs: z
    .object({
      suspicious_apis: z.array(z.string()).optional(),
      commands: z.array(z.string()).optional(),
      pipes: z.array(z.string()).optional(),
      urls: z.array(z.string()).optional(),
      network: z.array(z.string()).optional(),
    })
    .optional()
    .describe('Layered high-value IOC view'),
  compiler_artifacts: z
    .object({
      cargo_paths: z.array(z.string()).optional(),
      rust_markers: z.array(z.string()).optional(),
      library_profile: LibraryProfileSchema.optional(),
    })
    .optional()
    .describe('Build/toolchain breadcrumbs separated from high-risk IOC signals'),
})

const IntentAssessmentSchema = z.object({
  label: z.enum(['dual_use_tool', 'operator_utility', 'malware_like_payload', 'unknown']),
  confidence: z.number().min(0).max(1),
  evidence: z.array(z.string()),
  counter_evidence: z.array(z.string()),
})

const ToolingAssessmentSchema = z.object({
  help_text_detected: z.boolean(),
  cli_surface_detected: z.boolean(),
  framework_hints: z.array(z.string()),
  toolchain_markers: z.array(z.string()),
  library_profile: LibraryProfileSchema.optional(),
})

/**
 * Output schema for triage workflow
 * Requirements: 15.2, 15.4, 15.5
 */
export const TriageWorkflowOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    summary: z.string().describe('Natural language summary of the analysis'),
    confidence: z.number().min(0).max(1).describe('Confidence score (0-1)'),
    threat_level: z.enum(['clean', 'suspicious', 'malicious', 'unknown']).describe('Assessed threat level'),
    iocs: IOCSchema.describe('Indicators of Compromise'),
    evidence: z.array(z.string()).describe('Evidence supporting the assessment'),
    evidence_weights: z
      .object({
        import: z.number().min(0).max(1),
        string: z.number().min(0).max(1),
        runtime: z.number().min(0).max(1),
      })
      .describe('Relative evidence contribution weights for this conclusion'),
    inference: z
      .object({
        classification: z.enum(['benign', 'suspicious', 'malicious', 'unknown']),
        hypotheses: z.array(z.string()),
        false_positive_risks: z.array(z.string()),
        intent_assessment: IntentAssessmentSchema.optional(),
        tooling_assessment: ToolingAssessmentSchema.optional(),
      })
      .optional()
      .describe('Inference layer derived from evidence, separated for auditability'),
    recommendation: z.string().describe('Recommended next steps'),
    raw_results: z.object({
      fingerprint: z.any().optional(),
      runtime: z.any().optional(),
      imports: z.any().optional(),
      strings: z.any().optional(),
      yara: z.any().optional(),
      static_capability: z.any().optional(),
      pe_structure: z.any().optional(),
      compiler_packer: z.any().optional(),
    }).describe('Raw results from individual tools'),
  }).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({
    elapsed_ms: z.number(),
    tool: z.string(),
  }).optional(),
})

export type TriageWorkflowOutput = z.infer<typeof TriageWorkflowOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for triage workflow
 */
export const triageWorkflowToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: '快速画像工作流：在 5 分钟内完成基础威胁评估，包括 PE 指纹、运行时检测、导入表分析、字符串提取和 YARA 扫描',
  inputSchema: TriageWorkflowInputSchema,
  outputSchema: TriageWorkflowOutputSchema,
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Analyze imports for suspicious APIs
 * Requirements: 15.5
 */
function analyzeSuspiciousImports(imports: Record<string, string[]>): string[] {
  const suspicious: string[] = []
  
  try {
    for (const [dll, functions] of Object.entries(imports)) {
      // Ensure functions is an array
      if (!Array.isArray(functions)) {
        continue
      }
      
      for (const func of functions) {
        if (typeof func === 'string' && SUSPICIOUS_APIS.some(api => func.toLowerCase().includes(api.toLowerCase()))) {
          suspicious.push(`${dll}!${func}`)
        }
      }
    }
  } catch (error) {
    // Silently handle errors to prevent workflow failure
    console.error('Error analyzing suspicious imports:', error)
  }
  
  return suspicious
}

function summarizeStaticCapabilityResult(data: Record<string, unknown> | null | undefined) {
  if (!data || data.status !== 'ready') {
    return {
      summary: null as string | null,
      evidence: [] as string[],
      recommendation: null as string | null,
      threat_hint: false,
    }
  }

  const capabilityCount = Number(data.capability_count || 0)
  const capabilityGroups =
    data.capability_groups && typeof data.capability_groups === 'object'
      ? Object.entries(data.capability_groups as Record<string, unknown>)
          .map(([key, value]) => ({ key, count: Number(value) || 0 }))
          .sort((left, right) => right.count - left.count)
      : []
  const topGroups = capabilityGroups.slice(0, 4).map((item) => item.key)
  const threatHint = topGroups.some((item) =>
    ['persistence', 'execution', 'injection', 'command-and-control', 'c2', 'network', 'service'].includes(
      item.toLowerCase()
    )
  )

  return {
    summary:
      capabilityCount > 0
        ? `Static capability triage matched ${capabilityCount} capability finding(s)${
            topGroups.length > 0 ? ` across ${topGroups.join(', ')}` : ''
          }.`
        : null,
    evidence:
      capabilityCount > 0
        ? [
            `Static capability triage matched ${capabilityCount} capability finding(s).`,
            ...(topGroups.length > 0
              ? [`Capability groups: ${topGroups.join(', ')}.`]
              : []),
          ]
        : [],
    recommendation:
      capabilityCount > 0
        ? 'Map the recovered capability groups to concrete functions with code.functions.search, code.functions.reconstruct, or workflow.reconstruct.'
        : null,
    threat_hint: threatHint,
  }
}

function summarizePeStructureResult(data: Record<string, unknown> | null | undefined) {
  if (!data || (data.status !== 'ready' && data.status !== 'partial')) {
    return {
      summary: null as string | null,
      evidence: [] as string[],
      recommendation: null as string | null,
      packer_hint: false,
    }
  }

  const summary =
    data.summary && typeof data.summary === 'object' ? (data.summary as Record<string, unknown>) : {}
  const overlayPresent = Boolean(summary.overlay_present)
  const sectionCount = Number(summary.section_count || 0)
  const resourceCount = Number(summary.resource_count || 0)
  const forwarderCount = Number(summary.forwarder_count || 0)
  const parserPreference = typeof summary.parser_preference === 'string' ? summary.parser_preference : 'unknown'

  const evidence = [
    `PE structure analysis used parser preference ${parserPreference}.`,
    `PE sections=${sectionCount}, resources=${resourceCount}, forwarders=${forwarderCount}.`,
    ...(overlayPresent ? ['PE overlay detected.'] : []),
  ]

  return {
    summary:
      sectionCount > 0
        ? `PE structure analysis recovered ${sectionCount} section(s)${
            overlayPresent ? ' and detected an overlay.' : '.'
          }`
        : null,
    evidence,
    recommendation:
      overlayPresent || resourceCount > 0
        ? 'Inspect recovered resources and any detected overlay before assuming the file layout is benign or complete.'
        : null,
    packer_hint: overlayPresent,
  }
}

function summarizeCompilerPackerResult(data: Record<string, unknown> | null | undefined) {
  if (!data || data.status !== 'ready') {
    return {
      summary: null as string | null,
      evidence: [] as string[],
      recommendation: null as string | null,
      packer_hint: false,
    }
  }

  const summary =
    data.summary && typeof data.summary === 'object' ? (data.summary as Record<string, unknown>) : {}
  const compilerCount = Number(summary.compiler_count || 0)
  const packerCount = Number(summary.packer_count || 0)
  const protectorCount = Number(summary.protector_count || 0)
  const primaryFileType =
    typeof summary.likely_primary_file_type === 'string' ? summary.likely_primary_file_type : null

  const findingsByCategory = (field: string) =>
    Array.isArray(data[field]) ? (data[field] as Array<Record<string, unknown>>) : []
  const compilerNames = findingsByCategory('compiler_findings')
    .slice(0, 3)
    .map((item) => String(item.name))
  const packerNames = [
    ...findingsByCategory('packer_findings').slice(0, 3),
    ...findingsByCategory('protector_findings').slice(0, 3),
  ].map((item) => String(item.name))

  return {
    summary:
      compilerCount + packerCount + protectorCount > 0
        ? `Toolchain attribution suggests ${
            packerNames.length > 0
              ? `packer/protector signals (${packerNames.join(', ')})`
              : compilerNames.length > 0
                ? `compiler signals (${compilerNames.join(', ')})`
                : 'additional toolchain hints'
          }.`
        : null,
    evidence: [
      `Compiler/packer attribution found compiler=${compilerCount}, packer=${packerCount}, protector=${protectorCount}.`,
      ...(primaryFileType ? [`Primary file type attribution: ${primaryFileType}.`] : []),
    ],
    recommendation:
      packerCount > 0 || protectorCount > 0
        ? 'Treat this sample as packed or protected until deeper static analysis or runtime evidence disproves it.'
        : null,
    packer_hint: packerCount > 0 || protectorCount > 0,
  }
}

/**
 * Analyze strings for suspicious patterns
 * Requirements: 15.5
 */
function normalizeStringEntry(entry: unknown): string | null {
  if (typeof entry === 'string') {
    return entry
  }

  if (
    entry &&
    typeof entry === 'object' &&
    'string' in entry &&
    typeof (entry as { string?: unknown }).string === 'string'
  ) {
    return (entry as { string: string }).string
  }

  return null
}

export function extractCrateNameFromCargoPath(input: string): string | null {
  const normalized = input.replace(/\//g, '\\')
  const match = normalized.match(
    /cargo\\(?:registry\\src|git\\checkouts)\\[^\\]+\\([^\\]+)(?:\\|$)/i
  )
  if (!match?.[1]) {
    return null
  }

  const rawCrate = match[1].trim()
  if (!rawCrate) {
    return null
  }

  const versionMatch = rawCrate.match(/^(.*)-\d[\w.+-]*$/)
  const crateName = versionMatch?.[1] || rawCrate
  return crateName.trim() || null
}

function detectLibraryHints(str: string): string[] {
  return NOTABLE_LIBRARY_HINTS
    .filter((hint) => hint.patterns.some((pattern) => pattern.test(str)))
    .map((hint) => hint.name)
}

function analyzeSuspiciousStrings(strings: unknown[]): {
  suspicious: string[]
  urls: string[]
  ips: string[]
  paths: string[]
  registry: string[]
  commands: string[]
  pipes: string[]
  cargoPaths: string[]
  rustMarkers: string[]
  crateNames: string[]
  libraryHints: string[]
} {
  const suspicious: string[] = []
  const urls: string[] = []
  const ips: string[] = []
  const paths: string[] = []
  const registry: string[] = []
  const commands: string[] = []
  const pipes: string[] = []
  const cargoPaths: string[] = []
  const rustMarkers: string[] = []
  const crateNames: string[] = []
  const libraryHints: string[] = []
  
  for (const rawEntry of strings) {
    const str = normalizeStringEntry(rawEntry)
    if (!str) {
      continue
    }

    // Check for URLs
    const urlMatch = str.match(/https?:\/\/[^\s]+/i)
    if (urlMatch) {
      urls.push(urlMatch[0])
      suspicious.push(str)
    }
    
    // Check for IP addresses
    const ipMatch = str.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
    if (ipMatch) {
      ips.push(ipMatch[0])
      suspicious.push(str)
    }
    
    // Check for file paths
    const pathMatch = str.match(/[A-Za-z]:\\[^\s]+/)
    if (pathMatch) {
      paths.push(pathMatch[0])
      if (pathMatch[0].toLowerCase().includes('temp') || 
          pathMatch[0].toLowerCase().includes('appdata')) {
        suspicious.push(str)
      }
    }
    
    // Check for registry keys
    const regMatch = str.match(/HKEY_[A-Z_]+\\[^\s]+/i)
    if (regMatch) {
      registry.push(regMatch[0])
      suspicious.push(str)
    }
    
    // Check for shell executables
    if (/cmd\.exe|powershell\.exe|wscript\.exe/i.test(str)) {
      suspicious.push(str)
      commands.push(str)
    }

    // Check for named pipes / IPC
    const pipeMatch = str.match(/\\\\\.\\pipe\\[^\s]+|\\\\pipe\\[^\s]+/i)
    if (pipeMatch) {
      pipes.push(pipeMatch[0])
      suspicious.push(str)
    }

    // Split compiler/toolchain artifacts from high-value IOC
    const cargoMatch = str.match(/cargo\\registry\\src\\[^\s]+/i)
    if (cargoMatch) {
      cargoPaths.push(cargoMatch[0])
      const crateName = extractCrateNameFromCargoPath(cargoMatch[0])
      if (crateName) {
        crateNames.push(crateName)
      }
    }

    if (/rust_panic|core::panicking|\\src\\main\.rs|\\src\\lib\.rs/i.test(str)) {
      rustMarkers.push(str)
    }

    libraryHints.push(...detectLibraryHints(str))
  }
  
  return {
    suspicious: [...new Set(suspicious)],  // Remove duplicates
    urls: [...new Set(urls)],
    ips: [...new Set(ips)],
    paths: [...new Set(paths)],
    registry: [...new Set(registry)],
    commands: [...new Set(commands)],
    pipes: [...new Set(pipes)],
    cargoPaths: [...new Set(cargoPaths)],
    rustMarkers: [...new Set(rustMarkers)],
    crateNames: [...new Set(crateNames)],
    libraryHints: [...new Set(libraryHints)],
  }
}

interface YaraSignal {
  rule: string
  level: 'low' | 'medium' | 'high' | 'unknown'
  score: number
  stringOnly: boolean
  generic: boolean
}

interface IntentAssessment {
  label: 'dual_use_tool' | 'operator_utility' | 'malware_like_payload' | 'unknown'
  confidence: number
  evidence: string[]
  counter_evidence: string[]
}

export interface LibraryProfile {
  ecosystems: string[]
  top_crates: string[]
  notable_libraries: string[]
  evidence: string[]
}

interface ToolingAssessment {
  help_text_detected: boolean
  cli_surface_detected: boolean
  framework_hints: string[]
  toolchain_markers: string[]
  library_profile?: LibraryProfile
}

function normalizeEcosystemLabel(value: string): string | null {
  const lowered = value.toLowerCase()
  if (lowered.includes('rust')) {
    return 'rust'
  }
  if (lowered.includes('dotnet') || lowered.includes('.net') || lowered.includes('clr')) {
    return '.net'
  }
  if (lowered.includes('go')) {
    return 'go'
  }
  if (lowered.includes('native') || lowered.includes('c++') || lowered.includes('pe')) {
    return 'native'
  }
  return null
}

export function buildLibraryProfile(
  stringAnalysis: Pick<
    ReturnType<typeof analyzeSuspiciousStrings>,
    'cargoPaths' | 'crateNames' | 'libraryHints' | 'rustMarkers'
  >,
  runtime: any
): LibraryProfile | undefined {
  const ecosystems = new Set<string>()
  const crateCounts = new Map<string, number>()

  for (const runtimeHint of Array.isArray(runtime?.suspected) ? runtime.suspected : []) {
    const runtimeName = typeof runtimeHint?.runtime === 'string' ? runtimeHint.runtime : ''
    const ecosystem = normalizeEcosystemLabel(runtimeName)
    if (ecosystem) {
      ecosystems.add(ecosystem)
    }
  }

  if (
    stringAnalysis.cargoPaths.length > 0 ||
    stringAnalysis.rustMarkers.length > 0 ||
    stringAnalysis.crateNames.length > 0
  ) {
    ecosystems.add('rust')
  }

  for (const crateName of [...stringAnalysis.crateNames, ...stringAnalysis.libraryHints]) {
    const normalized = crateName.trim().toLowerCase()
    if (!normalized) {
      continue
    }
    crateCounts.set(normalized, (crateCounts.get(normalized) || 0) + 1)
  }

  const rankedCrates = Array.from(crateCounts.entries())
    .sort((left, right) => {
      if (right[1] !== left[1]) {
        return right[1] - left[1]
      }
      return left[0].localeCompare(right[0])
    })
    .map(([crate]) => crate)

  const topCrates = rankedCrates.slice(0, 8)
  const notableLibraries = Array.from(
    new Set(
      rankedCrates.filter((crate) =>
        NOTABLE_LIBRARY_HINTS.some((hint) => hint.name.toLowerCase() === crate)
      )
    )
  ).slice(0, 8)

  const evidence: string[] = []
  if (topCrates.length > 0) {
    evidence.push(`Cargo/library references observed: ${topCrates.slice(0, 5).join(', ')}`)
  }
  if (stringAnalysis.cargoPaths.length > 0) {
    evidence.push(
      `Cargo registry paths observed: ${stringAnalysis.cargoPaths.slice(0, 2).join(' | ')}`
    )
  }
  if (stringAnalysis.rustMarkers.length > 0) {
    evidence.push(
      `Rust toolchain markers observed: ${stringAnalysis.rustMarkers.slice(0, 2).join(' | ')}`
    )
  }
  if (ecosystems.size > 0) {
    evidence.push(`Ecosystem hints: ${Array.from(ecosystems).join(', ')}`)
  }

  if (ecosystems.size === 0 && topCrates.length === 0 && notableLibraries.length === 0) {
    return undefined
  }

  return {
    ecosystems: Array.from(ecosystems),
    top_crates: topCrates,
    notable_libraries: notableLibraries,
    evidence: Array.from(new Set(evidence)),
  }
}

function summarizeLibraryProfile(profile?: LibraryProfile): string {
  if (!profile) {
    return ''
  }

  const libraries = profile.notable_libraries.length > 0
    ? profile.notable_libraries
    : profile.top_crates
  if (libraries.length === 0) {
    return profile.ecosystems.join(', ')
  }

  return libraries.slice(0, 3).join(' + ')
}

function downgradeYaraLevel(level: YaraSignal['level']): YaraSignal['level'] {
  if (level === 'high') {
    return 'medium'
  }
  if (level === 'medium') {
    return 'low'
  }
  return 'low'
}

function normalizeYaraSignals(matches: unknown[]): YaraSignal[] {
  if (!Array.isArray(matches)) {
    return []
  }

  return matches
    .map((match) => {
      const rule = typeof (match as { rule?: unknown })?.rule === 'string'
        ? String((match as { rule: string }).rule)
        : ''
      if (!rule) {
        return null
      }

      const levelRaw = typeof (match as { confidence?: { level?: unknown } })?.confidence?.level === 'string'
        ? String((match as { confidence?: { level?: string } }).confidence?.level).toLowerCase()
        : 'unknown'
      const level: YaraSignal['level'] =
        levelRaw === 'high' || levelRaw === 'medium' || levelRaw === 'low'
          ? levelRaw
          : 'unknown'
      const numericScore = Number((match as { confidence?: { score?: unknown } })?.confidence?.score || 0)
      const stringOnly = Boolean((match as { evidence?: { string_only?: unknown } })?.evidence?.string_only)
      const loweredRule = rule.toLowerCase()

      return {
        rule,
        level,
        score: Number.isFinite(numericScore) ? numericScore : 0,
        stringOnly,
        generic:
          loweredRule.includes('generic') ||
          (loweredRule.includes('trojan') && !loweredRule.includes('downloader') && !loweredRule.includes('backdoor')),
      } satisfies YaraSignal
    })
    .filter((item): item is YaraSignal => Boolean(item))
}

function assessIntentAndTooling(
  stringsSummary: any,
  suspiciousImports: string[],
  stringAnalysis: ReturnType<typeof analyzeSuspiciousStrings>,
  yaraSignals: YaraSignal[],
  runtime: any
): { intent: IntentAssessment; tooling: ToolingAssessment } {
  const contextWindows = Array.isArray(stringsSummary?.context_windows)
    ? stringsSummary.context_windows
    : []
  const windowTexts = contextWindows.map((window: any) =>
    Array.isArray(window?.strings)
      ? window.strings
          .map((entry: any) => String(entry?.string || ''))
          .filter((item: string) => item.length > 0)
          .join('\n')
      : ''
  )
  const joinedWindows = windowTexts.join('\n').toLowerCase()
  const helpTextDetected = /usage:|options?:|examples?:|--help\b|-h\b|commands?:|syntax:/.test(
    joinedWindows
  )
  const cliSurfaceDetected =
    /--[a-z0-9_-]+|-[a-z0-9]\b/.test(joinedWindows) ||
    /\b(pid|process|thread|target|list|inject|suspend|resume|kill|dump)\b/.test(joinedWindows)

  const importApis = suspiciousImports.map((item) => (item.split('!').pop() || item).toLowerCase())
  const processOpsCount = importApis.filter((api) =>
    [
      'openprocess',
      'writeprocessmemory',
      'createremotethread',
      'virtualallocex',
      'suspendthread',
      'resumethread',
      'terminatethread',
      'terminateprocess',
    ].some((needle) => api.includes(needle))
  ).length

  const malwareSpecificYara = yaraSignals.some((signal) =>
    /ransomware|backdoor|downloader|keylogger/.test(signal.rule.toLowerCase()) &&
    signal.level !== 'low'
  )
  const networkBehavior = stringAnalysis.urls.length > 0 || stringAnalysis.ips.length > 0
  const persistenceBehavior = stringAnalysis.registry.length > 0
  const suspectedRuntimes: string[] = Array.isArray(runtime?.suspected)
    ? runtime.suspected
        .map((item: any) => String(item?.runtime || '').trim())
        .filter((item: string) => item.length > 0)
    : []
  const toolchainMarkers: string[] = [
    ...(
      Array.isArray(runtime?.suspected)
        ? runtime.suspected
            .map((item: any) =>
              `${String(item?.runtime || '').trim()}${
                typeof item?.confidence === 'number' ? `(${item.confidence.toFixed(2)})` : ''
              }`
            )
            .filter((item: string) => item.length > 0)
        : []
    ),
    ...stringAnalysis.cargoPaths.slice(0, 5),
    ...stringAnalysis.rustMarkers.slice(0, 5),
  ]

  const libraryProfile = buildLibraryProfile(stringAnalysis, runtime)
  const frameworkHints: string[] = Array.from(
    new Set([
      ...suspectedRuntimes,
      ...(libraryProfile?.ecosystems || []),
      ...(libraryProfile?.notable_libraries.slice(0, 3) || []),
    ])
  )

  if (
    helpTextDetected &&
    cliSurfaceDetected &&
    processOpsCount > 0 &&
    !malwareSpecificYara &&
    !networkBehavior &&
    !persistenceBehavior
  ) {
    return {
      intent: {
        label: 'dual_use_tool',
        confidence: 0.78,
        evidence: [
          'Long-form help/usage text grouped in nearby string windows.',
          'CLI-style options and operator verbs are present.',
          'Process-operation APIs are present without stronger malware-specific corroboration.',
        ],
        counter_evidence: [
          'Static evidence alone cannot rule out malicious repurposing of the tool.',
        ],
      },
      tooling: {
        help_text_detected: helpTextDetected,
        cli_surface_detected: cliSurfaceDetected,
        framework_hints: frameworkHints,
        toolchain_markers: toolchainMarkers.slice(0, 10),
        library_profile: libraryProfile,
      },
    }
  }

  if (helpTextDetected || cliSurfaceDetected) {
    return {
      intent: {
        label: 'operator_utility',
        confidence: 0.62,
        evidence: [
          'Operator-facing help or CLI surface detected in grouped string windows.',
        ],
        counter_evidence: malwareSpecificYara
          ? ['Malware-specific YARA evidence is also present; treat as suspicious until validated.']
          : [],
      },
      tooling: {
        help_text_detected: helpTextDetected,
        cli_surface_detected: cliSurfaceDetected,
        framework_hints: frameworkHints,
        toolchain_markers: toolchainMarkers.slice(0, 10),
        library_profile: libraryProfile,
      },
    }
  }

  if (malwareSpecificYara) {
    return {
      intent: {
        label: 'malware_like_payload',
        confidence: 0.74,
        evidence: ['Malware-family-like YARA evidence is present.'],
        counter_evidence: [],
      },
      tooling: {
        help_text_detected: helpTextDetected,
        cli_surface_detected: cliSurfaceDetected,
        framework_hints: frameworkHints,
        toolchain_markers: toolchainMarkers.slice(0, 10),
        library_profile: libraryProfile,
      },
    }
  }

  return {
    intent: {
      label: 'unknown',
      confidence: 0.35,
      evidence: [],
      counter_evidence: [],
    },
    tooling: {
      help_text_detected: helpTextDetected,
      cli_surface_detected: cliSurfaceDetected,
      framework_hints: frameworkHints,
      toolchain_markers: toolchainMarkers.slice(0, 10),
      library_profile: libraryProfile,
    },
  }
}

export function applyIntentAwareYaraAdjustments(
  yaraSignals: YaraSignal[],
  intentAssessment: IntentAssessment
): YaraSignal[] {
  if (
    !Array.isArray(yaraSignals) ||
    yaraSignals.length === 0 ||
    !['dual_use_tool', 'operator_utility'].includes(intentAssessment.label) ||
    intentAssessment.confidence < 0.55
  ) {
    return yaraSignals
  }

  return yaraSignals.map((signal) => {
    if (!signal.generic || hasMalwareSpecificSignal(signal)) {
      return signal
    }

    const dualUse = intentAssessment.label === 'dual_use_tool'
    const adjustedLevel = dualUse ? 'low' : downgradeYaraLevel(signal.level)
    const adjustedScore = Number((Math.max(0, signal.score) * (dualUse ? 0.45 : 0.7)).toFixed(2))

    return {
      ...signal,
      level: adjustedLevel,
      score: adjustedScore,
    }
  })
}

/**
 * Calculate threat level based on IOCs
 * Requirements: 15.2, 15.4
 */
function calculateThreatLevel(
  yaraMatches: string[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  lowConfidenceYaraCount: number = 0
): { level: 'clean' | 'suspicious' | 'malicious' | 'unknown'; confidence: number } {
  let score = 0
  let maxScore = 0
  
  // YARA matches (highest weight)
  maxScore += 50
  if (yaraMatches.length > 0) {
    // Check for malware family matches
    const hasMalwareMatch = yaraMatches.some(rule => 
      rule.toLowerCase().includes('trojan') ||
      rule.toLowerCase().includes('ransomware') ||
      rule.toLowerCase().includes('backdoor') ||
      rule.toLowerCase().includes('malware')
    )
    
    if (hasMalwareMatch) {
      score += 50
    } else {
      // Packer or other matches
      score += 20
    }
  } else if (lowConfidenceYaraCount > 0) {
    // Weak YARA-only signal: keep as low weight to reduce false positives.
    score += Math.min(lowConfidenceYaraCount * 2, 6)
  }
  
  // Suspicious imports (context-aware weighting to reduce false positives)
  maxScore += 30
  if (suspiciousImports.length > 0) {
    const importApis = suspiciousImports
      .map((item) => item.split('!').pop() || item)
      .map((item) => item.toLowerCase())

    const highRiskCount = importApis.filter((name) =>
      HIGH_RISK_APIS.some((api) => name.includes(api.toLowerCase()))
    ).length

    const contextDependentCount = importApis.filter((name) =>
      CONTEXT_DEPENDENT_APIS.some((api) => name.includes(api.toLowerCase()))
    ).length

    let importScore = 0

    // High-risk primitives (injection/hooking) are strong signals.
    importScore += Math.min(highRiskCount * 8, 22)
    // Context-dependent APIs are weaker alone (debuggers/installers use them too).
    importScore += Math.min(contextDependentCount * 2, 8)

    const hasWriteProcessMemory = importApis.some((name) => name.includes('writeprocessmemory'))
    const hasCreateRemoteThread = importApis.some((name) => name.includes('createremotethread'))
    const hasVirtualAllocEx = importApis.some((name) => name.includes('virtualallocex'))
    if (hasWriteProcessMemory && (hasCreateRemoteThread || hasVirtualAllocEx)) {
      importScore += 6
    }

    score += Math.min(importScore, 30)
  }
  
  // Suspicious strings (lower weight)
  maxScore += 20
  if (suspiciousStrings.length > 0) {
    score += Math.min(suspiciousStrings.length * 2, 20)
  }
  
  // Calculate confidence
  const confidence = maxScore > 0 ? score / maxScore : 0
  
  // Determine threat level
  let level: 'clean' | 'suspicious' | 'malicious' | 'unknown'
  if (score >= 40) {
    level = 'malicious'
  } else if (score >= 15) {
    level = 'suspicious'
  } else if (score > 0) {
    level = 'suspicious'
  } else {
    level = 'clean'
  }
  
  return { level, confidence }
}

/**
 * Generate evidence list
 * Requirements: 15.2
 */
function generateEvidence(
  yaraMatches: string[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  runtime: any
): string[] {
  const evidence: string[] = []
  
  if (yaraMatches.length > 0) {
    evidence.push(`YARA 规则匹配: ${yaraMatches.join(', ')}`)
  }
  
  if (suspiciousImports.length > 0) {
    evidence.push(`检测到 ${suspiciousImports.length} 个可疑导入函数`)
    if (suspiciousImports.length <= 5) {
      evidence.push(`可疑导入: ${suspiciousImports.join(', ')}`)
    }
  }
  
  if (suspiciousStrings.length > 0) {
    evidence.push(`检测到 ${suspiciousStrings.length} 个可疑字符串`)
  }
  
  if (runtime?.is_dotnet) {
    evidence.push(`.NET 程序 (${runtime.dotnet_version || 'unknown version'})`)
  }
  
  if (runtime?.suspected && runtime.suspected.length > 0) {
    const runtimes = runtime.suspected.map((s: any) => s.runtime).join(', ')
    evidence.push(`检测到运行时: ${runtimes}`)
  }
  
  return evidence
}

/**
 * Generate summary and recommendation
 * Requirements: 15.2
 */
function generateSummaryAndRecommendation(
  threatLevel: string,
  yaraMatches: string[],
  runtime: any
): { summary: string; recommendation: string } {
  let summary = ''
  let recommendation = ''
  
  // Generate summary based on threat level
  if (threatLevel === 'malicious') {
    const malwareTypes = yaraMatches
      .filter(rule => 
        rule.toLowerCase().includes('trojan') ||
        rule.toLowerCase().includes('ransomware') ||
        rule.toLowerCase().includes('backdoor')
      )
      .map(rule => rule.split('_')[0])
    
    if (malwareTypes.length > 0) {
      summary = `检测到恶意软件: ${malwareTypes.join(', ')}`
    } else {
      summary = '检测到高度可疑的恶意行为特征'
    }
    
    recommendation = '强烈建议在隔离环境中进行深度分析，不要在生产环境执行此文件'
  } else if (threatLevel === 'suspicious') {
    const packerMatches = yaraMatches.filter(rule => 
      rule.toLowerCase().includes('upx') ||
      rule.toLowerCase().includes('packer') ||
      rule.toLowerCase().includes('themida') ||
      rule.toLowerCase().includes('vmprotect')
    )
    
    if (packerMatches.length > 0) {
      summary = `检测到加壳器: ${packerMatches.join(', ')}`
      recommendation = '建议进行脱壳分析或深度静态分析以了解真实行为'
    } else {
      summary = '检测到可疑行为特征，需要进一步分析'
      recommendation = '建议进行深度静态分析或在隔离环境中进行动态分析'
    }
  } else if (threatLevel === 'clean') {
    summary = '未检测到明显的恶意行为特征'
    recommendation = '样本看起来相对安全，但建议根据具体使用场景进行进一步验证'
  } else {
    summary = '无法确定威胁等级，需要更多信息'
    recommendation = '建议进行深度静态分析以获取更多信息'
  }
  
  // Add runtime info to summary
  if (runtime?.is_dotnet) {
    summary += ` (.NET 程序)`
  }
  
  return { summary, recommendation }
}

function calculateEvidenceWeights(
  suspiciousImports: string[],
  suspiciousStrings: string[],
  runtime: any,
  yaraMatches: string[],
  yaraLowConfidenceMatches: string[]
): { import: number; string: number; runtime: number } {
  let importWeight = Math.min(0.9, suspiciousImports.length * 0.06)
  let stringWeight =
    Math.min(0.8, suspiciousStrings.length * 0.03) +
    Math.min(0.35, yaraMatches.length * 0.09 + yaraLowConfidenceMatches.length * 0.03)
  let runtimeWeight = 0.05

  if (runtime?.is_dotnet) {
    runtimeWeight += 0.25
  }
  if (Array.isArray(runtime?.suspected) && runtime.suspected.length > 0) {
    const topConfidence = Number(runtime.suspected[0]?.confidence || 0)
    runtimeWeight += Math.min(0.45, Math.max(0, topConfidence) * 0.5)
  }

  const total = importWeight + stringWeight + runtimeWeight
  if (total <= 0) {
    return { import: 0.34, string: 0.33, runtime: 0.33 }
  }

  return {
    import: Number((importWeight / total).toFixed(2)),
    string: Number((stringWeight / total).toFixed(2)),
    runtime: Number((runtimeWeight / total).toFixed(2)),
  }
}

function buildInferenceLayer(
  threatLevel: 'clean' | 'suspicious' | 'malicious' | 'unknown',
  yaraMatches: string[],
  yaraLowConfidenceMatches: string[],
  suspiciousImports: string[],
  suspiciousStrings: string[]
): {
  classification: 'benign' | 'suspicious' | 'malicious' | 'unknown'
  hypotheses: string[]
  false_positive_risks: string[]
} {
  const hypotheses: string[] = []
  const falsePositiveRisks: string[] = []

  if (yaraMatches.length > 0) {
    hypotheses.push(`YARA medium/high confidence match: ${yaraMatches.slice(0, 5).join(', ')}`)
  }
  if (yaraLowConfidenceMatches.length > 0) {
    hypotheses.push(
      `YARA low-confidence hints: ${yaraLowConfidenceMatches.slice(0, 5).join(', ')}`
    )
    falsePositiveRisks.push(
      'Low-confidence YARA hits may be string overlap without strong import/API corroboration.'
    )
  }
  if (suspiciousImports.length > 0) {
    hypotheses.push(`Suspicious API imports observed: ${Math.min(suspiciousImports.length, 10)}`)
    const hasOnlyContextDependentAPIs =
      suspiciousImports.every((item) =>
        CONTEXT_DEPENDENT_APIS.some((api) =>
          (item.split('!').pop() || item).toLowerCase().includes(api.toLowerCase())
        )
      ) && suspiciousImports.length > 0
    if (hasOnlyContextDependentAPIs) {
      falsePositiveRisks.push(
        'Import evidence is mostly context-dependent APIs (debuggers/installers may also use them).'
      )
    }
  }
  if (suspiciousStrings.length > 0) {
    hypotheses.push(`Behavior-related strings observed: ${Math.min(suspiciousStrings.length, 20)}`)
  }

  let classification: 'benign' | 'suspicious' | 'malicious' | 'unknown' = 'unknown'
  if (threatLevel === 'clean') {
    classification = 'benign'
  } else if (threatLevel === 'malicious') {
    classification = 'malicious'
  } else if (threatLevel === 'suspicious') {
    classification = 'suspicious'
  }

  if (hypotheses.length === 0) {
    hypotheses.push('Insufficient evidence to build high-confidence behavioral inference.')
  }

  return {
    classification,
    hypotheses,
    false_positive_risks: falsePositiveRisks,
  }
}

void [
  calculateThreatLevel,
  generateEvidence,
  generateSummaryAndRecommendation,
  calculateEvidenceWeights,
  buildInferenceLayer,
]

function hasMalwareSpecificSignal(signal: YaraSignal): boolean {
  return /ransomware|backdoor|downloader|keylogger|stealer|rat|loader/.test(
    signal.rule.toLowerCase()
  )
}

export function calculateThreatLevelV2(
  yaraSignals: YaraSignal[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  intentAssessment: IntentAssessment
): { level: 'clean' | 'suspicious' | 'malicious' | 'unknown'; confidence: number } {
  let score = 0
  const maxScore = 90

  let yaraScore = 0
  for (const signal of yaraSignals) {
    const levelWeight =
      signal.level === 'high'
        ? 16
        : signal.level === 'medium'
          ? 10
          : signal.level === 'low'
            ? 4
            : 6
    let signalScore = levelWeight + Math.min(4, Math.max(0, signal.score) * 3)

    if (signal.stringOnly) {
      signalScore *= 0.35
    }
    if (signal.generic) {
      signalScore *= 0.55
    }
    if (
      (intentAssessment.label === 'dual_use_tool' ||
        intentAssessment.label === 'operator_utility') &&
      signal.generic
    ) {
      signalScore *= 0.55
    }
    if (
      intentAssessment.label === 'dual_use_tool' &&
      signal.stringOnly &&
      !hasMalwareSpecificSignal(signal)
    ) {
      signalScore *= 0.7
    }

    yaraScore += signalScore
  }
  score += Math.min(36, yaraScore)

  if (suspiciousImports.length > 0) {
    const importApis = suspiciousImports
      .map((item) => item.split('!').pop() || item)
      .map((item) => item.toLowerCase())

    const highRiskCount = importApis.filter((name) =>
      HIGH_RISK_APIS.some((api) => name.includes(api.toLowerCase()))
    ).length
    const contextDependentCount = importApis.filter((name) =>
      CONTEXT_DEPENDENT_APIS.some((api) => name.includes(api.toLowerCase()))
    ).length
    const hasWriteProcessMemory = importApis.some((name) => name.includes('writeprocessmemory'))
    const hasCreateRemoteThread = importApis.some((name) => name.includes('createremotethread'))
    const hasVirtualAllocEx = importApis.some((name) => name.includes('virtualallocex'))

    let importScore = Math.min(highRiskCount * 7, 22) + Math.min(contextDependentCount * 2, 8)
    if (hasWriteProcessMemory && (hasCreateRemoteThread || hasVirtualAllocEx)) {
      importScore += 6
    }

    if (intentAssessment.label === 'dual_use_tool') {
      importScore *= 0.8
    } else if (intentAssessment.label === 'operator_utility') {
      importScore *= 0.9
    }

    score += Math.min(28, importScore)
  }

  let stringScore = Math.min(suspiciousStrings.length * 1.4, 18)
  if (intentAssessment.label === 'dual_use_tool') {
    stringScore *= 0.7
  } else if (intentAssessment.label === 'operator_utility') {
    stringScore *= 0.85
  }
  score += Math.min(18, stringScore)

  if (intentAssessment.label === 'malware_like_payload') {
    score += 8
  } else if (intentAssessment.label === 'dual_use_tool') {
    score -= 4
  }

  const boundedScore = Math.max(0, score)
  const confidence = Number(Math.max(0, Math.min(1, boundedScore / maxScore)).toFixed(2))
  const strongMalwareYara = yaraSignals.some(
    (signal) =>
      !signal.generic &&
      !signal.stringOnly &&
      hasMalwareSpecificSignal(signal) &&
      signal.level !== 'low'
  )

  let level: 'clean' | 'suspicious' | 'malicious' | 'unknown' = 'clean'
  if (strongMalwareYara && boundedScore >= 34 && intentAssessment.label !== 'dual_use_tool') {
    level = 'malicious'
  } else if (boundedScore >= 44 && intentAssessment.label !== 'dual_use_tool') {
    level = 'malicious'
  } else if (boundedScore >= 12) {
    level = 'suspicious'
  }

  const hasMeaningfulStaticCapability =
    suspiciousImports.length > 0 || suspiciousStrings.length > 0 || yaraSignals.length > 0
  if (
    level === 'clean' &&
    hasMeaningfulStaticCapability &&
    (intentAssessment.label === 'dual_use_tool' || intentAssessment.label === 'operator_utility')
  ) {
    level = 'suspicious'
  }

  return { level, confidence }
}

function generateEvidenceV2(
  yaraSignals: YaraSignal[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  runtime: any,
  intentAssessment: IntentAssessment,
  toolingAssessment: ToolingAssessment
): string[] {
  const evidence: string[] = []
  const strongSignals = yaraSignals
    .filter((signal) => signal.level !== 'low')
    .map((signal) =>
      `${signal.rule}${signal.stringOnly ? ' [string-only]' : ''}${signal.generic ? ' [generic]' : ''}`
    )
  const downgradedSignals = yaraSignals
    .filter((signal) => signal.level === 'low')
    .map((signal) => signal.rule)

  if (strongSignals.length > 0) {
    evidence.push(`YARA medium/high confidence matches: ${strongSignals.slice(0, 6).join(', ')}`)
  }
  if (downgradedSignals.length > 0) {
    evidence.push(`YARA low-confidence hints: ${downgradedSignals.slice(0, 6).join(', ')}`)
  }
  if (suspiciousImports.length > 0) {
    evidence.push(`Suspicious imports observed: ${suspiciousImports.length}`)
    if (suspiciousImports.length <= 5) {
      evidence.push(`Import details: ${suspiciousImports.join(', ')}`)
    }
  }
  if (suspiciousStrings.length > 0) {
    evidence.push(`Behavior-related strings observed: ${suspiciousStrings.length}`)
  }
  if (toolingAssessment.help_text_detected || toolingAssessment.cli_surface_detected) {
    evidence.push('Grouped strings indicate operator-facing help text or CLI options.')
  }
  if (toolingAssessment.library_profile) {
    const librarySummary = summarizeLibraryProfile(toolingAssessment.library_profile)
    if (librarySummary) {
      evidence.push(`Library/crate profile: ${librarySummary}`)
    }
    evidence.push(...toolingAssessment.library_profile.evidence.slice(0, 2))
  }
  if (intentAssessment.evidence.length > 0) {
    evidence.push(...intentAssessment.evidence.slice(0, 2))
  }
  if (runtime?.is_dotnet) {
    evidence.push(`.NET program detected (${runtime.dotnet_version || 'unknown version'})`)
  }
  if (Array.isArray(runtime?.suspected) && runtime.suspected.length > 0) {
    const runtimes = runtime.suspected
      .map((item: any) => String(item?.runtime || '').trim())
      .filter((item: string) => item.length > 0)
    if (runtimes.length > 0) {
      evidence.push(`Runtime hints: ${Array.from(new Set(runtimes)).join(', ')}`)
    }
  }

  return Array.from(new Set(evidence))
}

function generateSummaryAndRecommendationV2(
  threatLevel: string,
  yaraSignals: YaraSignal[],
  runtime: any,
  intentAssessment: IntentAssessment,
  toolingAssessment: ToolingAssessment
): { summary: string; recommendation: string } {
  const strongRules = yaraSignals
    .filter((signal) => signal.level !== 'low')
    .map((signal) => signal.rule)
  const packerMatches = strongRules.filter((rule) => /upx|packer|themida|vmprotect/i.test(rule))
  const runtimeSuffix = runtime?.is_dotnet ? ' (.NET)' : ''
  const librarySuffix = summarizeLibraryProfile(toolingAssessment.library_profile)
    ? ` Tooling stack hints: ${summarizeLibraryProfile(toolingAssessment.library_profile)}.`
    : ''

  if (intentAssessment.label === 'dual_use_tool') {
    return {
      summary:
        'Static evidence is more consistent with a dual-use operator utility than a pure malware payload.' +
        runtimeSuffix +
        librarySuffix,
      recommendation:
        'Validate provenance, operator workflow, and deployment context before labeling it malicious. ' +
        'Treat generic or string-only YARA hits as weak until dynamic or function-level evidence confirms abuse.',
    }
  }

  if (intentAssessment.label === 'operator_utility') {
    return {
      summary:
        'The sample exposes an operator-facing CLI/help surface and should be treated as a suspicious utility pending validation.' +
        runtimeSuffix +
        librarySuffix,
      recommendation:
        'Correlate with execution context, parent process, and any dropped artifacts before concluding malicious intent.',
    }
  }

  if (threatLevel === 'malicious') {
    const malwareRules = strongRules.filter((rule) =>
      /trojan|ransomware|backdoor|loader|stealer/i.test(rule)
    )
    return {
      summary:
        malwareRules.length > 0
          ? `Static evidence aligns with malware-like behavior: ${malwareRules.slice(0, 4).join(', ')}${runtimeSuffix}${librarySuffix}`
          : `Static evidence indicates a high-risk malicious payload${runtimeSuffix}${librarySuffix}`,
      recommendation:
        'Handle the sample in an isolated environment and collect dynamic evidence before any operational use.',
    }
  }

  if (threatLevel === 'suspicious') {
    if (packerMatches.length > 0) {
      return {
        summary: `Packed or protected traits detected: ${packerMatches.slice(0, 4).join(', ')}${runtimeSuffix}${librarySuffix}`,
        recommendation:
          'Unpack or deepen static analysis before making a final malware classification.',
      }
    }

    return {
      summary:
        toolingAssessment.help_text_detected || toolingAssessment.cli_surface_detected
          ? `Suspicious capability set detected, but the sample also exposes an operator-facing surface${runtimeSuffix}${librarySuffix}`
          : `Suspicious static behavior detected${runtimeSuffix}${librarySuffix}`,
      recommendation:
        'Escalate to deeper static analysis or controlled dynamic execution to resolve intent and capability.',
    }
  }

  if (threatLevel === 'clean') {
    return {
      summary: `No strong malicious indicators were confirmed from current static evidence${runtimeSuffix}${librarySuffix}`,
      recommendation:
        'Retain the sample for context-aware review if provenance is unknown, but current evidence alone is weak.',
    }
  }

  return {
    summary: `Threat level could not be determined with current evidence${runtimeSuffix}${librarySuffix}`,
    recommendation:
      'Collect additional static or dynamic evidence before drawing behavioral conclusions.',
  }
}

function calculateEvidenceWeightsV2(
  suspiciousImports: string[],
  suspiciousStrings: string[],
  runtime: any,
  yaraSignals: YaraSignal[],
  intentAssessment: IntentAssessment
): { import: number; string: number; runtime: number } {
  let importWeight = Math.min(0.9, suspiciousImports.length * 0.06)
  const strongYara = yaraSignals.filter((signal) => signal.level !== 'low').length
  const weakYara = yaraSignals.length - strongYara
  let stringWeight =
    Math.min(0.8, suspiciousStrings.length * 0.03) +
    Math.min(0.28, strongYara * 0.07 + weakYara * 0.02)
  let runtimeWeight = 0.05

  if (runtime?.is_dotnet) {
    runtimeWeight += 0.25
  }
  if (Array.isArray(runtime?.suspected) && runtime.suspected.length > 0) {
    const topConfidence = Number(runtime.suspected[0]?.confidence || 0)
    runtimeWeight += Math.min(0.45, Math.max(0, topConfidence) * 0.5)
  }
  if (intentAssessment.label === 'dual_use_tool') {
    stringWeight *= 0.85
  }

  const total = importWeight + stringWeight + runtimeWeight
  if (total <= 0) {
    return { import: 0.34, string: 0.33, runtime: 0.33 }
  }

  return {
    import: Number((importWeight / total).toFixed(2)),
    string: Number((stringWeight / total).toFixed(2)),
    runtime: Number((runtimeWeight / total).toFixed(2)),
  }
}

function buildInferenceLayerV2(
  threatLevel: 'clean' | 'suspicious' | 'malicious' | 'unknown',
  yaraSignals: YaraSignal[],
  suspiciousImports: string[],
  suspiciousStrings: string[],
  intentAssessment: IntentAssessment,
  toolingAssessment: ToolingAssessment
): {
  classification: 'benign' | 'suspicious' | 'malicious' | 'unknown'
  hypotheses: string[]
  false_positive_risks: string[]
  intent_assessment: IntentAssessment
  tooling_assessment: ToolingAssessment
} {
  const hypotheses: string[] = []
  const falsePositiveRisks: string[] = []
  const strongYara = yaraSignals.filter((signal) => signal.level !== 'low')
  const weakYara = yaraSignals.filter((signal) => signal.level === 'low')

  if (strongYara.length > 0) {
    hypotheses.push(
      `YARA medium/high confidence match: ${strongYara
        .map((signal) => signal.rule)
        .slice(0, 5)
        .join(', ')}`
    )
  }
  if (weakYara.length > 0) {
    hypotheses.push(
      `YARA low-confidence hints: ${weakYara
        .map((signal) => signal.rule)
        .slice(0, 5)
        .join(', ')}`
    )
    falsePositiveRisks.push(
      'Low-confidence YARA hits may be string overlap without strong import/API corroboration.'
    )
  }
  if (strongYara.some((signal) => signal.stringOnly)) {
    falsePositiveRisks.push(
      'Some medium/high YARA hits remain string-heavy and should not be treated as execution proof.'
    )
  }
  if (strongYara.some((signal) => signal.generic)) {
    falsePositiveRisks.push(
      'Generic malware-family YARA matches can overlap with dual-use process tooling.'
    )
  }
  if (suspiciousImports.length > 0) {
    hypotheses.push(`Suspicious API imports observed: ${Math.min(suspiciousImports.length, 10)}`)
  }
  if (suspiciousStrings.length > 0) {
    hypotheses.push(`Behavior-related strings observed: ${Math.min(suspiciousStrings.length, 20)}`)
  }
  if (intentAssessment.evidence.length > 0) {
    hypotheses.push(...intentAssessment.evidence.slice(0, 2))
  }
  if (toolingAssessment.library_profile) {
    const librarySummary = summarizeLibraryProfile(toolingAssessment.library_profile)
    if (librarySummary) {
      hypotheses.push(`Observed crate/library profile: ${librarySummary}`)
    }
  }
  falsePositiveRisks.push(...intentAssessment.counter_evidence)

  let classification: 'benign' | 'suspicious' | 'malicious' | 'unknown' = 'unknown'
  if (threatLevel === 'clean') {
    classification = 'benign'
  } else if (threatLevel === 'malicious') {
    classification = 'malicious'
  } else if (threatLevel === 'suspicious') {
    classification = 'suspicious'
  }

  if (hypotheses.length === 0) {
    hypotheses.push('Insufficient evidence to build high-confidence behavioral inference.')
  }

  return {
    classification,
    hypotheses: Array.from(new Set(hypotheses)),
    false_positive_risks: Array.from(new Set(falsePositiveRisks)),
    intent_assessment: intentAssessment,
    tooling_assessment: toolingAssessment,
  }
}

// ============================================================================
// Standalone Workflow Function
// ============================================================================

/**
 * Execute triage workflow
 * Requirements: 15.1, 15.2, 15.4, 15.5
 * 
 * This is a standalone function that can be called by other workflows
 */
export async function triageWorkflow(
  sampleId: string,
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
): Promise<TriageWorkflowOutput> {
  const handler = createTriageWorkflowHandler(workspaceManager, database, cacheManager);
  const result = await handler({ sample_id: sampleId });
  
  // Convert WorkerResult to TriageWorkflowOutput
  return {
    ok: result.ok,
    data: result.data as any,
    errors: result.errors,
    warnings: result.warnings
  };
}

// ============================================================================
// Workflow Handler
// ============================================================================

/**
 * Create triage workflow handler
 * Requirements: 15.1, 15.2, 15.4, 15.5
 */
export function createTriageWorkflowHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager
) {
  // Create tool handlers
  const peFingerprintHandler = createPEFingerprintHandler(workspaceManager, database, cacheManager)
  const runtimeDetectHandler = createRuntimeDetectHandler(workspaceManager, database, cacheManager)
  const peImportsExtractHandler = createPEImportsExtractHandler(workspaceManager, database, cacheManager)
  const stringsExtractHandler = createStringsExtractHandler(workspaceManager, database, cacheManager)
  const yaraScanHandler = createYaraScanHandler(workspaceManager, database, cacheManager)
  const staticCapabilityTriageHandler = createStaticCapabilityTriageHandler(workspaceManager, database)
  const peStructureAnalyzeHandler = createPEStructureAnalyzeHandler(workspaceManager, database)
  const compilerPackerDetectHandler = createCompilerPackerDetectHandler(workspaceManager, database)
  
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as TriageWorkflowInput
    const startTime = Date.now()
    const warnings: string[] = []
    const errors: string[] = []
    
    try {
      // Verify sample exists
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
        }
      }
      
      // Step 1: PE Fingerprint (fast mode)
      // Requirement: 15.1
      const fingerprintResult = await peFingerprintHandler({ 
        sample_id: input.sample_id, 
        fast: true,
        force_refresh: input.force_refresh,
      })
      
      if (!fingerprintResult.ok) {
        errors.push('PE fingerprint extraction failed')
      }
      if (fingerprintResult.warnings) {
        warnings.push(...fingerprintResult.warnings)
      }
      
      // Step 2: Runtime Detection
      // Requirement: 15.1
      const runtimeResult = await runtimeDetectHandler({ 
        sample_id: input.sample_id,
        force_refresh: input.force_refresh,
      })
      
      if (!runtimeResult.ok) {
        errors.push('Runtime detection failed')
      }
      if (runtimeResult.warnings) {
        warnings.push(...runtimeResult.warnings)
      }
      
      // Step 3: Import Table Extraction
      // Requirement: 15.1
      const importsResult = await peImportsExtractHandler({ 
        sample_id: input.sample_id,
        group_by_dll: true,
        force_refresh: input.force_refresh,
      })
      
      if (!importsResult.ok) {
        errors.push('Import table extraction failed')
      }
      if (importsResult.warnings) {
        warnings.push(...importsResult.warnings)
      }
      
      // Step 4: String Extraction
      // Requirement: 15.1
      const stringsResult = await stringsExtractHandler({ 
        sample_id: input.sample_id,
        min_len: 6,
        encoding: 'all',
        force_refresh: input.force_refresh,
      })
      
      if (!stringsResult.ok) {
        errors.push('String extraction failed')
      }
      if (stringsResult.warnings) {
        warnings.push(...stringsResult.warnings)
      }
      
      // Step 5: YARA Scan
      // Requirement: 15.1
      const yaraResult = await yaraScanHandler({ 
        sample_id: input.sample_id,
        rule_set: 'malware_families',
        rule_tier: 'production',
        force_refresh: input.force_refresh,
      })
      
      if (!yaraResult.ok) {
        errors.push('YARA scan failed')
      }
      if (yaraResult.warnings) {
        warnings.push(...yaraResult.warnings)
      }

      // Step 6: Static capability triage
      const staticCapabilityResult = await staticCapabilityTriageHandler({
        sample_id: input.sample_id,
      })
      if (!staticCapabilityResult.ok) {
        errors.push('Static capability triage failed')
      }
      if (staticCapabilityResult.warnings) {
        warnings.push(...staticCapabilityResult.warnings)
      }

      // Step 7: Canonical PE structure analysis
      const peStructureResult = await peStructureAnalyzeHandler({
        sample_id: input.sample_id,
      })
      if (!peStructureResult.ok) {
        errors.push('PE structure analysis failed')
      }
      if (peStructureResult.warnings) {
        warnings.push(...peStructureResult.warnings)
      }

      // Step 8: Compiler / packer attribution
      const compilerPackerResult = await compilerPackerDetectHandler({
        sample_id: input.sample_id,
      })
      if (!compilerPackerResult.ok) {
        errors.push('Compiler/packer attribution failed')
      }
      if (compilerPackerResult.warnings) {
        warnings.push(...compilerPackerResult.warnings)
      }
      
      // If all tools failed, return error
      if (errors.length >= 8) {
        return {
          ok: false,
          errors: ['All analysis tools failed', ...errors],
          warnings,
          metrics: {
            elapsed_ms: Date.now() - startTime,
            tool: TOOL_NAME,
          },
        }
      }
      
      // Step 9: Aggregate results and generate structured summary
      // Requirements: 15.2, 15.4, 15.5
      
      // Extract YARA matches
      let yaraSignals: YaraSignal[] = []
      if (yaraResult.ok && yaraResult.data) {
        const yaraData = yaraResult.data as any
        if (yaraData.matches && Array.isArray(yaraData.matches)) {
          yaraSignals = normalizeYaraSignals(yaraData.matches)
        }
      }
      
      // Analyze imports for suspicious APIs
      const suspiciousImports: string[] = []
      if (importsResult.ok && importsResult.data) {
        const importsData = importsResult.data as any
        if (importsData.imports && typeof importsData.imports === 'object') {
          suspiciousImports.push(...analyzeSuspiciousImports(importsData.imports))
        }
      }
      
      // Analyze strings for suspicious patterns
      const stringAnalysis = {
        suspicious: [] as string[],
        urls: [] as string[],
        ips: [] as string[],
        paths: [] as string[],
        registry: [] as string[],
        commands: [] as string[],
        pipes: [] as string[],
        cargoPaths: [] as string[],
        rustMarkers: [] as string[],
        crateNames: [] as string[],
        libraryHints: [] as string[],
      }
      if (stringsResult.ok && stringsResult.data) {
        const stringsData = stringsResult.data as any
        if (stringsData.strings && Array.isArray(stringsData.strings)) {
          const analysis = analyzeSuspiciousStrings(stringsData.strings)
          stringAnalysis.suspicious = analysis.suspicious
          stringAnalysis.urls = analysis.urls
          stringAnalysis.ips = analysis.ips
          stringAnalysis.paths = analysis.paths
          stringAnalysis.registry = analysis.registry
          stringAnalysis.commands = analysis.commands
          stringAnalysis.pipes = analysis.pipes
          stringAnalysis.cargoPaths = analysis.cargoPaths
          stringAnalysis.rustMarkers = analysis.rustMarkers
          stringAnalysis.crateNames = analysis.crateNames
          stringAnalysis.libraryHints = analysis.libraryHints
        }
      }

      const stringsSummary = (stringsResult.data as any)?.summary
      const { intent, tooling } = assessIntentAndTooling(
        stringsSummary,
        suspiciousImports,
        stringAnalysis,
        yaraSignals,
        runtimeResult.data
      )
      yaraSignals = applyIntentAwareYaraAdjustments(yaraSignals, intent)

      const yaraMatches = Array.from(
        new Set(
          yaraSignals
            .filter((signal) => signal.level !== 'low')
            .map((signal) => signal.rule)
        )
      )
      const yaraLowConfidenceMatches = Array.from(
        new Set(
          yaraSignals
            .filter((signal) => signal.level === 'low')
            .map((signal) => signal.rule)
        )
      )
      
      // Calculate threat level and confidence
      const { level: threatLevel, confidence } = calculateThreatLevelV2(
        yaraSignals,
        suspiciousImports,
        stringAnalysis.suspicious,
        intent
      )
      
      // Generate evidence
      const evidence = generateEvidenceV2(
        yaraSignals,
        suspiciousImports,
        stringAnalysis.suspicious,
        runtimeResult.data,
        intent,
        tooling
      )
      if (yaraLowConfidenceMatches.length > 0) {
        evidence.push(
          `YARA low-confidence matches (downgraded): ${yaraLowConfidenceMatches.join(', ')}`
        )
      }
      
      // Generate summary and recommendation
      let { summary, recommendation } = generateSummaryAndRecommendationV2(
        threatLevel,
        yaraSignals,
        runtimeResult.data,
        intent,
        tooling
      )
      const inference = buildInferenceLayerV2(
        threatLevel,
        yaraSignals,
        suspiciousImports,
        stringAnalysis.suspicious,
        intent,
        tooling
      )
      const evidenceWeights = calculateEvidenceWeightsV2(
        suspiciousImports,
        stringAnalysis.suspicious,
        runtimeResult.data,
        yaraSignals,
        intent
      )

      const highValueIocs = {
        suspicious_apis:
          suspiciousImports.length > 0 ? suspiciousImports.slice(0, 20) : undefined,
        commands: stringAnalysis.commands.length > 0 ? stringAnalysis.commands.slice(0, 15) : undefined,
        pipes: stringAnalysis.pipes.length > 0 ? stringAnalysis.pipes.slice(0, 15) : undefined,
        urls: stringAnalysis.urls.length > 0 ? stringAnalysis.urls.slice(0, 15) : undefined,
        network:
          stringAnalysis.ips.length > 0 ? stringAnalysis.ips.slice(0, 15) : undefined,
      }

      const compilerArtifacts = {
        cargo_paths:
          stringAnalysis.cargoPaths.length > 0 ? stringAnalysis.cargoPaths.slice(0, 10) : undefined,
        rust_markers:
          stringAnalysis.rustMarkers.length > 0 ? stringAnalysis.rustMarkers.slice(0, 10) : undefined,
        library_profile: tooling.library_profile,
      }

      const hasHighValue =
        Boolean(highValueIocs.suspicious_apis?.length) ||
        Boolean(highValueIocs.commands?.length) ||
        Boolean(highValueIocs.pipes?.length) ||
        Boolean(highValueIocs.urls?.length) ||
        Boolean(highValueIocs.network?.length)
      const hasCompilerArtifacts =
        Boolean(compilerArtifacts.cargo_paths?.length) ||
        Boolean(compilerArtifacts.rust_markers?.length) ||
        Boolean(compilerArtifacts.library_profile)
      
      // Build IOCs
      const iocs = {
        suspicious_imports: suspiciousImports,
        suspicious_strings: stringAnalysis.suspicious.slice(0, 20),  // Limit to top 20
        yara_matches: yaraMatches,
        yara_low_confidence:
          yaraLowConfidenceMatches.length > 0 ? yaraLowConfidenceMatches : undefined,
        urls: stringAnalysis.urls.length > 0 ? stringAnalysis.urls : undefined,
        ip_addresses: stringAnalysis.ips.length > 0 ? stringAnalysis.ips : undefined,
        file_paths: stringAnalysis.paths.length > 0 ? stringAnalysis.paths.slice(0, 10) : undefined,
        registry_keys: stringAnalysis.registry.length > 0 ? stringAnalysis.registry.slice(0, 10) : undefined,
        high_value_iocs: hasHighValue ? highValueIocs : undefined,
        compiler_artifacts: hasCompilerArtifacts ? compilerArtifacts : undefined,
      }

      const staticCapabilityInsights = summarizeStaticCapabilityResult(
        staticCapabilityResult.ok && staticCapabilityResult.data
          ? (staticCapabilityResult.data as Record<string, unknown>)
          : null
      )
      const peStructureInsights = summarizePeStructureResult(
        peStructureResult.ok && peStructureResult.data
          ? (peStructureResult.data as Record<string, unknown>)
          : null
      )
      const compilerPackerInsights = summarizeCompilerPackerResult(
        compilerPackerResult.ok && compilerPackerResult.data
          ? (compilerPackerResult.data as Record<string, unknown>)
          : null
      )

      if (staticCapabilityInsights.summary || peStructureInsights.summary || compilerPackerInsights.summary) {
        summary = [
          summary,
          staticCapabilityInsights.summary,
          peStructureInsights.summary,
          compilerPackerInsights.summary,
        ]
          .filter((item): item is string => Boolean(item && item.trim().length > 0))
          .join(' ')
      }

      const recommendationAddenda = [
        staticCapabilityInsights.recommendation,
        peStructureInsights.recommendation,
        compilerPackerInsights.recommendation,
      ].filter((item): item is string => Boolean(item && item.trim().length > 0))
      if (recommendationAddenda.length > 0) {
        recommendation = `${recommendation} ${Array.from(new Set(recommendationAddenda)).join(' ')}`
      }

      evidence.push(
        ...[
          ...staticCapabilityInsights.evidence,
          ...peStructureInsights.evidence,
          ...compilerPackerInsights.evidence,
        ].filter((item) => item.trim().length > 0)
      )

      let adjustedThreatLevel = threatLevel
      let adjustedConfidence = confidence
      if (
        adjustedThreatLevel === 'clean' &&
        (staticCapabilityInsights.threat_hint ||
          peStructureInsights.packer_hint ||
          compilerPackerInsights.packer_hint)
      ) {
        adjustedThreatLevel = 'suspicious'
        adjustedConfidence = Math.max(adjustedConfidence, 0.58)
      }
      
      // Return structured result
      return {
        ok: true,
        data: {
          summary,
          confidence: adjustedConfidence,
          threat_level: adjustedThreatLevel,
          iocs,
          evidence: Array.from(new Set(evidence)),
          evidence_weights: evidenceWeights,
          inference,
          recommendation,
          raw_results: {
            fingerprint: fingerprintResult.data || null,
            runtime: runtimeResult.data || null,
            imports: importsResult.data || null,
            strings: stringsResult.data || null,
            yara: yaraResult.data || null,
            static_capability: staticCapabilityResult.data || null,
            pe_structure: peStructureResult.data || null,
            compiler_packer: compilerPackerResult.data || null,
          },
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        errors: errors.length > 0 ? errors : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message, ...errors],
        warnings: warnings.length > 0 ? warnings : undefined,
        metrics: {
          elapsed_ms: Date.now() - startTime,
          tool: TOOL_NAME,
        },
      }
    }
  }
}
