import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'office.behavior.profile'

export const OfficeBehaviorProfileInputSchema = z
  .object({
    sample_id: z.string().optional(),
    macro_detection: z.any().optional(),
    ole_analysis: z.any().optional(),
    vba_sources: z.any().optional(),
    strings: z.any().optional(),
    findings: z.array(z.string()).optional().default([]),
  })
  .passthrough()

export const OfficeBehaviorProfileOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const officeBehaviorProfileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a passive Office document behavior profile from OLE/OOXML structure, VBA/XLM macro text, macro detector flags, static strings, and IOC-like evidence without automating Office or executing macros.',
  inputSchema: OfficeBehaviorProfileInputSchema,
  outputSchema: OfficeBehaviorProfileOutputSchema,
  aspects: {
    formats: ['office', 'doc', 'docm', 'xls', 'xlsm', 'ppt', 'pptm', 'ole', 'ooxml'],
    platforms: ['windows', 'macos', 'cross-platform'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['macro-analysis', 'ioc-extraction', 'behavior-profile', 'workflow-plan'],
    evidence: ['structure', 'strings', 'behavior', 'network', 'filesystem', 'provenance'],
  },
  artifacts: [
    {
      type: 'office_behavior_profile',
      description: 'Passive Office macro behavior profile with IOC and rule-generation handoffs',
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: ['office_behavior_profile'] },
    { category: 'strings', artifactTypes: ['office_behavior_profile'] },
    { category: 'behavior', artifactTypes: ['office_behavior_profile'] },
    { category: 'network', artifactTypes: ['office_behavior_profile'] },
  ],
  workflowRecipes: [
    {
      id: 'office.macro.static-profile',
      title: 'Office macro static behavior profile',
      startsWith: [
        'office.ole.analyze',
        'office.macro.detect',
        'office.vba.extract',
        'office.behavior.profile',
      ],
      nextTools: ['ioc.export', 'yara.generate', 'sigma.rule.generate', 'report.generate'],
      requiredArtifacts: ['office_ole_analysis', 'office_macro_detection', 'office_vba_source'],
      producesArtifacts: ['office_behavior_profile'],
      evidence: ['structure', 'strings', 'behavior', 'network', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default'],
    },
  ],
}

function stringify(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(stringify).join('\n')
  if (value && typeof value === 'object') return JSON.stringify(value)
  return ''
}

function uniqueMatches(text: string, pattern: RegExp): string[] {
  return Array.from(new Set(Array.from(text.matchAll(pattern)).map((match) => match[0]))).sort()
}

function flagFromObject(value: unknown, name: string): boolean {
  if (!value || typeof value !== 'object') return false
  const obj = value as Record<string, any>
  return Boolean(obj?.flags?.[name] ?? obj?.data?.flags?.[name] ?? obj?.[name])
}

function behaviorSignals(text: string, macroDetection: unknown) {
  const autoExec = uniqueMatches(
    text,
    /\b(?:Auto_Open|AutoOpen|Workbook_Open|Document_Open|Auto_Close|Document_Close)\b/gi
  )
  if (flagFromObject(macroDetection, 'auto_exec') && !autoExec.includes('auto_exec')) {
    autoExec.push('auto_exec')
  }

  const network = uniqueMatches(
    text,
    /\b(?:WinHttpRequest|MSXML2\.XMLHTTP|MSXML2\.ServerXMLHTTP|URLDownloadToFile|InternetOpen|ShellExecute|XMLHTTP)\b/gi
  )
  const filesystem = uniqueMatches(
    text,
    /\b(?:FileSystemObject|ADODB\.Stream|OpenTextFile|WriteLine|SaveToFile|CreateTextFile|Kill)\b/gi
  )
  const process = uniqueMatches(
    text,
    /\b(?:Shell|WScript\.Shell|CreateObject|powershell|cmd\.exe|rundll32|regsvr32|wscript|cscript)\b/gi
  )
  const registry = uniqueMatches(text, /\b(?:RegRead|RegWrite|RegDelete|HKEY_[A-Z_]+)\b/gi)
  const obfuscation = uniqueMatches(
    text,
    /\b(?:ChrW?|AscW?|StrReverse|Replace|Split|Join|Execute|Eval|Base64|FromBase64String)\b/gi
  )
  return { auto_exec: autoExec, network, filesystem, process, registry, obfuscation }
}

function iocCandidates(text: string) {
  const urls = uniqueMatches(text, /\bhttps?:\/\/[^\s"'<>]+/gi)
  const ips = uniqueMatches(
    text,
    /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b/g
  )
  const domains = uniqueMatches(
    text,
    /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|biz|info|ru|cn|top|xyz|io)\b/gi
  ).filter((domain) => !urls.some((url) => url.includes(domain)))
  return [
    ...urls.map((value) => ({ type: 'url', value, source: TOOL_NAME, confidence: 0.8 })),
    ...ips.map((value) => ({ type: 'ip', value, source: TOOL_NAME, confidence: 0.75 })),
    ...domains.map((value) => ({ type: 'domain', value, source: TOOL_NAME, confidence: 0.55 })),
  ]
}

function riskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 8) return 'critical'
  if (score >= 5) return 'high'
  if (score >= 2) return 'medium'
  return 'low'
}

export function buildOfficeBehaviorProfile(rawInput: unknown) {
  const input = OfficeBehaviorProfileInputSchema.parse(rawInput)
  const text = [
    stringify(input.macro_detection),
    stringify(input.ole_analysis),
    stringify(input.vba_sources),
    stringify(input.strings),
    input.findings.join('\n'),
  ].join('\n')
  const signals = behaviorSignals(text, input.macro_detection)
  const iocs = iocCandidates(text)
  const structureHints = uniqueMatches(
    text,
    /\b(?:VBA|dir|project|Macros|xlm|Excel 4\.0|OLE|OOXML|word\/vbaProject\.bin)\b/gi
  )
  const score =
    signals.auto_exec.length * 2 +
    signals.network.length * 2 +
    signals.process.length * 2 +
    signals.filesystem.length +
    signals.registry.length +
    signals.obfuscation.length +
    iocs.length

  return {
    result_mode: 'office_behavior_profile',
    sample_id: input.sample_id ?? null,
    passive_findings: {
      structure_hints: structureHints,
      macro_triggers: signals.auto_exec,
      suspicious_api_hints: {
        network: signals.network,
        filesystem: signals.filesystem,
        process: signals.process,
        registry: signals.registry,
        obfuscation: signals.obfuscation,
      },
    },
    ioc_candidates: iocs,
    rule_generation_handoff: {
      yara: {
        tool: 'yara.generate',
        confidence: iocs.length || signals.obfuscation.length ? 0.7 : 0.45,
        evidence: ['macro_triggers', 'suspicious_api_hints', 'ioc_candidates'],
      },
      sigma: {
        tool: 'sigma.rule.generate',
        confidence: signals.process.length || signals.registry.length ? 0.65 : 0.4,
        evidence: ['process', 'registry', 'network'],
      },
    },
    risk_summary: {
      score,
      risk_level: riskLevel(score),
      macro_execution_required: false,
      office_automation_used: false,
    },
    recommended_next_tools: [
      'office.vba.extract',
      'ioc.export',
      'yara.generate',
      'sigma.rule.generate',
    ],
    safety_notes: [
      'No Microsoft Office automation, macro execution, document preview, or network lookup is performed.',
    ],
  }
}

export function createOfficeBehaviorProfileHandler() {
  return async (args: unknown): Promise<WorkerResult> => ({
    ok: true,
    data: buildOfficeBehaviorProfile(args),
    metrics: { elapsed_ms: 0, tool: TOOL_NAME },
  })
}
