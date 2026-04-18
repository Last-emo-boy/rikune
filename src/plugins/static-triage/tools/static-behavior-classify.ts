/**
 * static.behavior.classify tool.
 *
 * Classifies persistence and process-injection behavior from strings, generic
 * config artifacts, and optional imported dynamic evidence. Static planning
 * only; it never executes the sample.
 */

import fs from 'fs/promises'
import { createHash } from 'crypto'
import { z } from 'zod'
import type { ArtifactRef, ToolArgs, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import {
  loadStaticAnalysisArtifactSelection,
  persistStaticAnalysisJsonArtifact,
  type StaticArtifactScope,
} from '../../../artifacts/static-analysis-artifacts.js'
import { loadDynamicTraceEvidence, type DynamicEvidenceScope } from '../../../artifacts/dynamic-trace.js'
import { dedupeStrings } from '../../../utils/shared-helpers.js'

const TOOL_NAME = 'static.behavior.classify'
const TOOL_VERSION = '0.1.0'

type BehaviorCategory = 'persistence' | 'injection' | 'anti_analysis' | 'execution'
type EvidenceSource = 'string' | 'config_artifact' | 'dynamic_trace'

interface ExtractedString {
  value: string
  offset: number
  encoding: 'ascii' | 'utf16le'
}

interface BehaviorEvidence {
  source: EvidenceSource
  kind: string
  value: string
  confidence: number
  location?: string
}

interface BehaviorRule {
  id: string
  category: BehaviorCategory
  technique: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  baseConfidence: number
  apiPatterns: RegExp[]
  stringPatterns: RegExp[]
  configKinds?: string[]
  rationale: string
  nextTools: string[]
}

interface StaticConfigCarverPayload {
  candidates?: Array<{ kind?: string; value?: string; confidence?: number; evidence?: string[] }>
}

export const StaticBehaviorClassifyInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_strings: z.number().int().min(50).max(5000).optional().default(1500),
  min_string_length: z.number().int().min(4).max(32).optional().default(5),
  static_artifact_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  static_artifact_session_tag: z.string().optional(),
  include_dynamic_evidence: z.boolean().optional().default(true),
  runtime_evidence_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  runtime_evidence_session_tag: z.string().optional(),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

export const staticBehaviorClassifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Classify static persistence, service install, scheduled task, WMI, process injection, DLL injection, APC injection, and hollowing indicators from strings, config artifacts, and optional imported runtime evidence. Does not execute the sample.',
  inputSchema: StaticBehaviorClassifyInputSchema,
}

const RULES: BehaviorRule[] = [
  {
    id: 'persistence.run_key',
    category: 'persistence',
    technique: 'Registry Run key persistence',
    severity: 'high',
    baseConfidence: 0.72,
    apiPatterns: [/^Reg(Open|Create|Set|Query)Key/i, /^RegSetValueEx/i],
    stringPatterns: [/\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?/i, /HKEY_(CURRENT_USER|LOCAL_MACHINE).*\\Run/i],
    configKinds: ['registry_path'],
    rationale: 'Registry autostart locations and registry write APIs indicate possible Run key persistence.',
    nextTools: ['dynamic.behavior.capture', 'dynamic.behavior.diff', 'analysis.evidence.graph'],
  },
  {
    id: 'persistence.service_install',
    category: 'persistence',
    technique: 'Windows service installation',
    severity: 'high',
    baseConfidence: 0.7,
    apiPatterns: [/^OpenSCManager/i, /^CreateService/i, /^StartService/i, /^ChangeServiceConfig/i],
    stringPatterns: [/\bSERVICE_AUTO_START\b/i, /\bsc\.exe\s+create\b/i, /\bCreateService[AW]?\b/i],
    rationale: 'Service-control APIs and service-install strings indicate durable service persistence.',
    nextTools: ['dynamic.behavior.capture', 'dynamic.deep_plan', 'runtime.debug.session.start'],
  },
  {
    id: 'persistence.scheduled_task',
    category: 'persistence',
    technique: 'Scheduled task persistence',
    severity: 'medium',
    baseConfidence: 0.66,
    apiPatterns: [/^CoCreateInstance/i],
    stringPatterns: [/\bschtasks(?:\.exe)?\b/i, /\bTaskScheduler\b/i, /\bITaskService\b/i, /\\Microsoft\\Windows\\TaskScheduler/i],
    rationale: 'Task Scheduler COM strings or schtasks usage indicate scheduled execution persistence.',
    nextTools: ['dynamic.persona.plan', 'dynamic.behavior.capture'],
  },
  {
    id: 'persistence.wmi_event',
    category: 'persistence',
    technique: 'WMI event subscription persistence',
    severity: 'high',
    baseConfidence: 0.68,
    apiPatterns: [/^CoCreateInstance/i],
    stringPatterns: [/\bIWbemServices\b/i, /\b__EventFilter\b/i, /\bCommandLineEventConsumer\b/i, /\bWin32_StartupCommand\b/i, /\broot\\subscription\b/i],
    rationale: 'WMI subscription strings indicate possible event-consumer persistence.',
    nextTools: ['dynamic.behavior.capture', 'dynamic.deep_plan'],
  },
  {
    id: 'persistence.startup_folder',
    category: 'persistence',
    technique: 'Startup folder persistence',
    severity: 'medium',
    baseConfidence: 0.62,
    apiPatterns: [/^SHGetFolderPath/i, /^SHGetKnownFolderPath/i, /^CreateFile/i, /^CopyFile/i],
    stringPatterns: [/\\Start Menu\\Programs\\Startup/i, /\bStartup\\[^\\]+\.lnk\b/i, /\bCSIDL_STARTUP\b/i],
    rationale: 'Startup-folder paths and file-copy APIs indicate possible user-logon persistence.',
    nextTools: ['dynamic.persona.plan', 'dynamic.behavior.capture'],
  },
  {
    id: 'persistence.ifeo_debugger',
    category: 'persistence',
    technique: 'Image File Execution Options debugger persistence',
    severity: 'high',
    baseConfidence: 0.72,
    apiPatterns: [/^RegSetValueEx/i],
    stringPatterns: [/Image File Execution Options/i, /\\Debugger\b/i, /\\SilentProcessExit/i],
    configKinds: ['registry_path'],
    rationale: 'IFEO Debugger/SilentProcessExit registry paths are common persistence and execution hijack locations.',
    nextTools: ['static.config.carver', 'dynamic.behavior.capture'],
  },
  {
    id: 'injection.remote_thread',
    category: 'injection',
    technique: 'Remote thread process injection',
    severity: 'critical',
    baseConfidence: 0.76,
    apiPatterns: [/^OpenProcess$/i, /^VirtualAllocEx$/i, /^WriteProcessMemory$/i, /^CreateRemoteThread$/i, /^NtCreateThreadEx$/i],
    stringPatterns: [/\bVirtualAllocEx\b/i, /\bWriteProcessMemory\b/i, /\bCreateRemoteThread\b/i, /\bNtCreateThreadEx\b/i],
    rationale: 'OpenProcess, remote allocation/write, and remote thread APIs indicate classic process injection.',
    nextTools: ['breakpoint.smart', 'trace.condition', 'runtime.debug.session.start', 'dynamic.behavior.capture'],
  },
  {
    id: 'injection.process_hollowing',
    category: 'injection',
    technique: 'Process hollowing',
    severity: 'critical',
    baseConfidence: 0.78,
    apiPatterns: [/^CreateProcess[AW]?$/i, /^Zw?UnmapViewOfSection$/i, /^SetThreadContext$/i, /^ResumeThread$/i, /^WriteProcessMemory$/i],
    stringPatterns: [/\bCREATE_SUSPENDED\b/i, /\bUnmapViewOfSection\b/i, /\bSetThreadContext\b/i, /\bResumeThread\b/i],
    rationale: 'Suspended process creation, section unmapping, context writes, and resume APIs indicate process hollowing.',
    nextTools: ['dynamic.deep_plan', 'runtime.debug.session.start', 'dynamic.behavior.capture'],
  },
  {
    id: 'injection.apc',
    category: 'injection',
    technique: 'APC injection',
    severity: 'high',
    baseConfidence: 0.7,
    apiPatterns: [/^QueueUserAPC$/i, /^NtQueueApcThread$/i, /^OpenThread$/i],
    stringPatterns: [/\bQueueUserAPC\b/i, /\bNtQueueApcThread\b/i],
    rationale: 'APC queueing APIs indicate APC-based injection or async execution.',
    nextTools: ['breakpoint.smart', 'trace.condition', 'runtime.debug.session.start'],
  },
  {
    id: 'injection.dll_load',
    category: 'injection',
    technique: 'DLL injection through remote LoadLibrary',
    severity: 'high',
    baseConfidence: 0.68,
    apiPatterns: [/^LoadLibrary[AW]?$/i, /^GetProcAddress$/i, /^CreateRemoteThread$/i, /^WriteProcessMemory$/i],
    stringPatterns: [/\bLoadLibrary[AW]?\b/i, /\.dll\b/i, /\bCreateRemoteThread\b/i],
    rationale: 'LoadLibrary plus remote thread/write APIs can indicate DLL injection.',
    nextTools: ['hash.resolver.plan', 'breakpoint.smart', 'dynamic.behavior.capture'],
  },
  {
    id: 'injection.thread_hijack',
    category: 'injection',
    technique: 'Thread context hijacking',
    severity: 'high',
    baseConfidence: 0.7,
    apiPatterns: [/^SuspendThread$/i, /^GetThreadContext$/i, /^SetThreadContext$/i, /^ResumeThread$/i],
    stringPatterns: [/\bSuspendThread\b/i, /\bGetThreadContext\b/i, /\bSetThreadContext\b/i],
    rationale: 'Thread suspend/context APIs indicate thread hijacking or hollowing support.',
    nextTools: ['runtime.debug.session.start', 'trace.condition'],
  },
  {
    id: 'anti_analysis.debug_probe',
    category: 'anti_analysis',
    technique: 'Debugger and environment checks',
    severity: 'medium',
    baseConfidence: 0.6,
    apiPatterns: [/^IsDebuggerPresent$/i, /^CheckRemoteDebuggerPresent$/i, /^NtQueryInformationProcess$/i, /^NtQuerySystemInformation$/i],
    stringPatterns: [/\bIsDebuggerPresent\b/i, /\bCheckRemoteDebuggerPresent\b/i, /\bNtQueryInformationProcess\b/i],
    rationale: 'Debugger and system-query APIs can affect runtime behavior and require a persona/debug plan.',
    nextTools: ['dynamic.persona.plan', 'dynamic.deep_plan'],
  },
]

function extractAsciiStrings(buffer: Buffer, minLength: number, maxStrings: number): ExtractedString[] {
  const strings: ExtractedString[] = []
  let start = -1
  let chars: number[] = []

  function flush(endOffset: number) {
    if (chars.length >= minLength && strings.length < maxStrings) {
      strings.push({ value: Buffer.from(chars).toString('ascii'), offset: start, encoding: 'ascii' })
    }
    start = -1
    chars = []
  }

  for (let offset = 0; offset < buffer.length; offset += 1) {
    const byte = buffer[offset]
    if (byte >= 0x20 && byte <= 0x7e) {
      if (start < 0) start = offset
      chars.push(byte)
      if (chars.length >= 240) flush(offset)
    } else {
      flush(offset)
    }
  }
  flush(buffer.length)
  return strings
}

function extractUtf16Strings(buffer: Buffer, minLength: number, maxStrings: number): ExtractedString[] {
  const strings: ExtractedString[] = []
  let start = -1
  let value = ''
  for (let offset = 0; offset + 1 < buffer.length; offset += 2) {
    const lo = buffer[offset]
    const hi = buffer[offset + 1]
    if (hi === 0 && lo >= 0x20 && lo <= 0x7e) {
      if (start < 0) start = offset
      value += String.fromCharCode(lo)
      if (value.length >= 240) {
        strings.push({ value, offset: start, encoding: 'utf16le' })
        start = -1
        value = ''
      }
      continue
    }
    if (value.length >= minLength && strings.length < maxStrings) {
      strings.push({ value, offset: start, encoding: 'utf16le' })
    }
    start = -1
    value = ''
    if (strings.length >= maxStrings) break
  }
  if (value.length >= minLength && strings.length < maxStrings) {
    strings.push({ value, offset: start, encoding: 'utf16le' })
  }
  return strings
}

function dedupeExtractedStrings(strings: ExtractedString[]): ExtractedString[] {
  const seen = new Set<string>()
  const output: ExtractedString[] = []
  for (const item of strings) {
    const key = `${item.encoding}:${item.value}`
    if (seen.has(key)) continue
    seen.add(key)
    output.push(item)
  }
  return output
}

function normalizeApi(value: string): string {
  return value.trim().replace(/\(.*/, '').replace(/^.*!/, '')
}

function collectStringEvidence(rule: BehaviorRule, strings: ExtractedString[]): BehaviorEvidence[] {
  const evidence: BehaviorEvidence[] = []
  for (const item of strings) {
    for (const pattern of rule.stringPatterns) {
      if (!pattern.test(item.value)) {
        continue
      }
      evidence.push({
        source: 'string',
        kind: 'string_match',
        value: item.value.slice(0, 240),
        confidence: 0.64,
        location: `${item.encoding}:0x${item.offset.toString(16)}`,
      })
      break
    }
  }
  return evidence.slice(0, 16)
}

function collectApiEvidence(rule: BehaviorRule, apis: string[], source: EvidenceSource): BehaviorEvidence[] {
  const evidence: BehaviorEvidence[] = []
  for (const api of apis) {
    const normalized = normalizeApi(api)
    if (rule.apiPatterns.some((pattern) => pattern.test(normalized))) {
      evidence.push({
        source,
        kind: 'api_match',
        value: normalized,
        confidence: source === 'dynamic_trace' ? 0.86 : 0.68,
      })
    }
  }
  return evidence
}

function collectConfigEvidence(rule: BehaviorRule, payloads: StaticConfigCarverPayload[]): BehaviorEvidence[] {
  const acceptedKinds = new Set(rule.configKinds || [])
  const evidence: BehaviorEvidence[] = []
  for (const payload of payloads) {
    for (const candidate of payload.candidates || []) {
      const kind = candidate.kind || 'unknown'
      const value = candidate.value || ''
      if (!value) continue
      const kindMatches = acceptedKinds.size > 0 && acceptedKinds.has(kind)
      const stringMatches = rule.stringPatterns.some((pattern) => pattern.test(value))
      if (!kindMatches && !stringMatches) continue
      evidence.push({
        source: 'config_artifact',
        kind,
        value: value.slice(0, 240),
        confidence: Math.max(0.58, Math.min(0.9, candidate.confidence || 0.58)),
      })
    }
  }
  return evidence.slice(0, 16)
}

function scoreFinding(rule: BehaviorRule, evidence: BehaviorEvidence[]): number {
  const sourceCount = new Set(evidence.map((item) => item.source)).size
  const apiCount = evidence.filter((item) => item.kind === 'api_match').length
  const dynamicBoost = evidence.some((item) => item.source === 'dynamic_trace') ? 0.12 : 0
  const score = rule.baseConfidence + Math.min(0.18, evidence.length * 0.035) + Math.min(0.1, apiCount * 0.02) + sourceCount * 0.025 + dynamicBoost
  return Number(Math.min(0.98, score).toFixed(3))
}

function severityRank(value: BehaviorRule['severity']): number {
  return { low: 1, medium: 2, high: 3, critical: 4 }[value]
}

function summarizeFindings(findings: Array<{ category: BehaviorCategory; severity: string; confidence: number }>) {
  const byCategory: Record<string, number> = {}
  const bySeverity: Record<string, number> = {}
  for (const finding of findings) {
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1
  }
  return {
    finding_count: findings.length,
    high_or_critical_count: findings.filter((item) => item.severity === 'high' || item.severity === 'critical').length,
    by_category: byCategory,
    by_severity: bySeverity,
    max_confidence: findings.reduce((max, item) => Math.max(max, item.confidence), 0),
  }
}

export function createStaticBehaviorClassifyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = StaticBehaviorClassifyInputSchema.parse(args || {})
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const buffer = await fs.readFile(samplePath)
      const strings = dedupeExtractedStrings([
        ...extractAsciiStrings(buffer, input.min_string_length, input.max_strings),
        ...extractUtf16Strings(buffer, input.min_string_length, Math.floor(input.max_strings / 2)),
      ])
      const stringCorpusApis = dedupeStrings(
        RULES.flatMap((rule) =>
          strings.flatMap((item) =>
            rule.apiPatterns
              .filter((pattern) => pattern.test(item.value))
              .map(() => item.value.match(/[A-Za-z][A-Za-z0-9_]{2,80}/)?.[0] || item.value)
          )
        )
      )

      const configSelection = await loadStaticAnalysisArtifactSelection<StaticConfigCarverPayload>(
        workspaceManager,
        database,
        input.sample_id,
        'static_config_carver',
        {
          scope: input.static_artifact_scope as StaticArtifactScope,
          sessionTag: input.static_artifact_session_tag,
        }
      )
      const configPayloads = configSelection.artifacts.map((item) => item.payload)
      const dynamicSummary = input.include_dynamic_evidence
        ? await loadDynamicTraceEvidence(workspaceManager, database, input.sample_id, {
            evidenceScope: input.runtime_evidence_scope as DynamicEvidenceScope,
            sessionTag: input.runtime_evidence_session_tag,
          })
        : null

      const findings = RULES.map((rule) => {
        const evidence = [
          ...collectStringEvidence(rule, strings),
          ...collectApiEvidence(rule, stringCorpusApis, 'string'),
          ...collectConfigEvidence(rule, configPayloads),
          ...collectApiEvidence(rule, dynamicSummary?.observed_apis || [], 'dynamic_trace'),
        ]
        const dedupedEvidence = Array.from(
          new Map(evidence.map((item) => [`${item.source}:${item.kind}:${item.value}:${item.location || ''}`, item])).values()
        )
        if (dedupedEvidence.length === 0) {
          return null
        }
        return {
          id: rule.id,
          category: rule.category,
          technique: rule.technique,
          severity: rule.severity,
          confidence: scoreFinding(rule, dedupedEvidence),
          evidence: dedupedEvidence.sort((left, right) => right.confidence - left.confidence).slice(0, 20),
          rationale: rule.rationale,
          recommended_next_tools: rule.nextTools,
        }
      })
        .filter((item): item is NonNullable<typeof item> => Boolean(item))
        .sort((left, right) => {
          const severityDiff = severityRank(right.severity) - severityRank(left.severity)
          return severityDiff !== 0 ? severityDiff : right.confidence - left.confidence
        })

      const recommendedTools = dedupeStrings([
        ...findings.flatMap((finding) => finding.recommended_next_tools),
        'dynamic.behavior.diff',
        'analysis.evidence.graph',
        'dynamic.deep_plan',
      ], 12)
      const warnings: string[] = []
      if (configSelection.artifacts.length === 0) {
        warnings.push('No static_config_carver artifacts were selected; run static.config.carver for richer registry/config evidence.')
      }
      if (input.include_dynamic_evidence && !dynamicSummary) {
        warnings.push('No dynamic trace evidence was selected; classification is static-only.')
      }

      const data = {
        schema: 'rikune.static_behavior_classifier.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        source: {
          file_size: buffer.length,
          sha256: createHash('sha256').update(buffer).digest('hex'),
          string_count: strings.length,
        },
        evidence_sources: {
          config_artifacts: configSelection.artifact_ids,
          config_scope_note: configSelection.scope_note,
          dynamic_artifacts: dynamicSummary?.artifact_ids || [],
          dynamic_scope_note: dynamicSummary?.scope_note || null,
        },
        summary: summarizeFindings(findings),
        findings,
        dynamic_summary: dynamicSummary
          ? {
              artifact_count: dynamicSummary.artifact_count,
              executed: dynamicSummary.executed,
              observed_apis: dynamicSummary.observed_apis,
              stages: dynamicSummary.stages,
            }
          : null,
        recommended_next_tools: recommendedTools,
        next_actions: findings.length > 0
          ? [
              'Use dynamic.deep_plan to choose a bounded behavior/debugger profile for high-risk persistence or injection findings.',
              'Use breakpoint.smart and trace.condition for injection or API-resolution findings that need runtime capture.',
              'Use dynamic.behavior.diff after runtime import to compare these static expectations with observed behavior.',
            ]
          : [
              'No persistence or injection indicators were found in the selected evidence. Continue with workflow.analyze.promote or broader string extraction if suspicion remains.',
            ],
        warnings,
      }

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'static_behavior_classifier',
          'behavior_classifier',
          data,
          input.session_tag
        ))
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
