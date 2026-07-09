import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../../sdk.js'
import { OFFICE_MACRO_DETECTION_ARTIFACT_TYPE } from './office-macro-detect.js'
import { OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE } from './office-ole-analyze.js'
import { OFFICE_VBA_EXTRACT_ARTIFACT_TYPE } from './office-vba-extract.js'
import {
  OFFICE_ANALYSIS_FORMATS,
  OFFICE_ANALYSIS_PLATFORMS,
  OFFICE_ANALYSIS_PROFILE_TAGS,
  OFFICE_ANALYSIS_SEARCH_TERMS,
  OFFICE_ANALYSIS_SAFETY,
  OFFICE_BEHAVIOR_FOLLOW_UP_TOOLS,
  OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE,
  OFFICE_PROFILE_RUNTIME_POLICY,
  buildOfficeEvidenceSummary,
  buildOfficeQualityGates,
  buildOfficeWorkflowHandoff,
} from '../office-analysis-metadata.js'

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
  data: z.record(z.string(), z.any()).optional(),
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
    formats: OFFICE_ANALYSIS_FORMATS,
    platforms: OFFICE_ANALYSIS_PLATFORMS,
    execution: ['static', 'correlation', 'workflow-handoff'],
    safety: OFFICE_ANALYSIS_SAFETY,
    capabilities: [
      'macro-analysis',
      'vba-macro-analysis',
      'excel-macro-analysis',
      'ioc-extraction',
      'behavior-profile',
      'malicious-document-triage',
      'static-only-profile',
      'workflow-plan',
      'workflow-handoff',
    ],
    evidence: [
      'structure',
      'strings',
      'behavior',
      'network',
      'filesystem',
      'registry',
      'ioc',
      'workflow',
      'provenance',
    ],
    search: OFFICE_ANALYSIS_SEARCH_TERMS,
    profile: OFFICE_ANALYSIS_PROFILE_TAGS,
  },
  artifacts: [
    {
      type: OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE,
      description:
        'Passive Office macro behavior profile contract with IOC, rule-generation, evidence graph, reporting handoffs, and static-only quality gates',
      required: false,
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
    { category: 'behavior', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
    { category: 'network', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
    { category: 'filesystem', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
    { category: 'registry', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
    { category: 'ioc', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE] },
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
      nextTools: OFFICE_BEHAVIOR_FOLLOW_UP_TOOLS,
      requiredArtifacts: [
        OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE,
        OFFICE_MACRO_DETECTION_ARTIFACT_TYPE,
        OFFICE_VBA_EXTRACT_ARTIFACT_TYPE,
      ],
      producesArtifacts: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE],
      evidence: [
        'structure',
        'strings',
        'behavior',
        'network',
        'filesystem',
        'registry',
        'ioc',
        'workflow',
        'provenance',
      ],
      safety: OFFICE_ANALYSIS_SAFETY,
      runtimeBackends: ['local-correlation'],
    },
  ],
  runtimePolicy: OFFICE_PROFILE_RUNTIME_POLICY,
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
  const signalCounts = {
    structure_hints: structureHints.length,
    macro_triggers: signals.auto_exec.length,
    network: signals.network.length,
    filesystem: signals.filesystem.length,
    process: signals.process.length,
    registry: signals.registry.length,
    obfuscation: signals.obfuscation.length,
    ioc_candidates: iocs.length,
  }
  const evidenceSummary = buildOfficeEvidenceSummary({
    schema: 'rikune.office_behavior_profile.evidence_summary.v1',
    sourceTool: TOOL_NAME,
    sampleId: input.sample_id,
    artifactType: OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE,
    evidenceKind: 'office-behavior-profile',
    evidenceCategories: [
      'structure',
      'strings',
      'behavior',
      'network',
      'filesystem',
      'registry',
      'ioc',
      'workflow',
      'provenance',
    ],
    counts: signalCounts,
    highlights: {
      risk_level: riskLevel(score),
      macro_triggers: signals.auto_exec.slice(0, 20),
      network_hints: signals.network.slice(0, 20),
      process_hints: signals.process.slice(0, 20),
      ioc_candidates: iocs.slice(0, 20),
    },
  })
  const workflowHandoff = buildOfficeWorkflowHandoff({
    schema: 'rikune.office_behavior_profile.workflow_handoff.v1',
    sourceTool: TOOL_NAME,
    sampleId: input.sample_id,
    producesArtifacts: [OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE],
    consumesArtifacts: [
      OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE,
      OFFICE_MACRO_DETECTION_ARTIFACT_TYPE,
      OFFICE_VBA_EXTRACT_ARTIFACT_TYPE,
      'strings',
      'analysis_findings',
    ],
    primaryArtifactType: OFFICE_BEHAVIOR_PROFILE_ARTIFACT_TYPE,
    recommendedNextTools: OFFICE_BEHAVIOR_FOLLOW_UP_TOOLS,
    routing: [
      {
        goal: 'ioc-export',
        next_tools: ['ioc.export', 'analysis.evidence.graph'],
        evidence: ['ioc_candidates', 'network', 'filesystem'],
      },
      {
        goal: 'rule-generation',
        next_tools: ['yara.generate', 'sigma.rule.generate'],
        evidence: ['macro_triggers', 'suspicious_api_hints', 'ioc_candidates'],
      },
      {
        goal: 'malicious-document-reporting',
        next_tools: ['report.generate', 'workflow.search'],
        evidence: ['risk_summary', 'passive_findings', 'quality_gates'],
      },
    ],
  })
  const qualityGates = buildOfficeQualityGates({
    schema: 'rikune.office_behavior_profile.quality_gates.v1',
    sourceTool: TOOL_NAME,
    backend: 'local-correlation',
    checks: {
      behavior_profile_ready: true,
      has_behavior_signal: score > 0,
      ioc_candidates_present: iocs.length > 0,
      macro_trigger_count: signals.auto_exec.length,
      static_evidence_only: true,
    },
  })

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
    evidence_summary: evidenceSummary,
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
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
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
      'analysis.evidence.graph',
      'report.generate',
      'workflow.search',
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
