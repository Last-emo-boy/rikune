/**
 * sigma.rule.generate tool implementation
 * Auto-generate Sigma detection rules from sample analysis evidence.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'sigma.rule.generate'
const TOOL_VERSION = '0.1.0'
const SIGMA_RULES_ARTIFACT_TYPE = 'sigma_rules'

const GeneratedSigmaRuleSchema = z.object({
  type: z.string(),
  title: z.string(),
  rule_yaml: z.string(),
  indicator_count: z.number(),
})

export const SigmaRuleGenerateInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  rule_types: z
    .array(
      z.enum([
        'process_creation',
        'file_event',
        'registry_event',
        'network_connection',
        'dns_query',
        'image_load',
      ])
    )
    .optional()
    .default(['process_creation', 'file_event', 'network_connection'])
    .describe('Sigma rule categories to generate'),
  level: z
    .enum(['low', 'medium', 'high', 'critical'])
    .default('high')
    .describe('Detection rule severity level'),
  deploy: z.boolean().default(false).describe('Save generated rules to workspace'),
})

export type SigmaRuleGenerateInput = z.infer<typeof SigmaRuleGenerateInputSchema>

export const SigmaRuleGenerateOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      level: z.enum(['low', 'medium', 'high', 'critical']).optional(),
      deploy_requested: z.boolean().optional(),
      requested_rule_types: z.array(z.string()).optional(),
      rules: z.array(GeneratedSigmaRuleSchema).optional(),
      total_rules: z.number().optional(),
      total_indicators: z.number().optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      next_actions: z.array(z.string()).optional(),
    })
    .passthrough()
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const sigmaRuleGenerateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Auto-generate Sigma detection rules from sample analysis evidence. Creates rules for process creation, ' +
    'file events, registry modifications, network connections, DNS queries, and DLL loads. ' +
    'Uses strings, imports, and behavioral evidence to build detection logic.',
  inputSchema: SigmaRuleGenerateInputSchema,
  outputSchema: SigmaRuleGenerateOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'apk', 'jar', 'firmware'],
    platforms: [
      'windows',
      'linux',
      'macos',
      'android',
      'jvm',
      'dotnet',
      'embedded',
      'cross-platform',
    ],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_network_by_default', 'no_live_sample_by_default'],
    capabilities: [
      'sigma-generation',
      'ioc',
      'detection-rule-generation',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: [
      'behavior',
      'network',
      'filesystem',
      'registry',
      'strings',
      'imports',
      'workflow',
      'provenance',
    ],
  },
  artifacts: [
    {
      type: SIGMA_RULES_ARTIFACT_TYPE,
      description:
        'Generated Sigma rules with evidence summary, workflow handoff, and quality gates',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'behavior',
      artifactTypes: [SIGMA_RULES_ARTIFACT_TYPE],
    },
    {
      category: 'network',
      artifactTypes: [SIGMA_RULES_ARTIFACT_TYPE],
    },
    {
      category: 'registry',
      artifactTypes: [SIGMA_RULES_ARTIFACT_TYPE],
    },
    {
      category: 'strings',
      artifactTypes: [SIGMA_RULES_ARTIFACT_TYPE],
    },
    {
      category: 'imports',
      artifactTypes: [SIGMA_RULES_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [SIGMA_RULES_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [SIGMA_RULES_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'threat-intel.sigma-rule-generation-handoff',
      title: 'Sigma rule generation to validation and reporting',
      description:
        'Convert static behavior, string, import, network, and registry evidence into generated Sigma rules with quality gates, evidence graph routing, ATT&CK feedback, and reporting handoff.',
      startsWith: ['sigma.rule.generate', 'strings.extract', 'ioc.export'],
      nextTools: [
        'analysis.evidence.graph',
        'attack.map',
        'ioc.export',
        'yara.generate',
        'report.generate',
        'artifact.read',
      ],
      requiredArtifacts: ['analysis_evidence'],
      producesArtifacts: [SIGMA_RULES_ARTIFACT_TYPE],
      evidence: ['behavior', 'network', 'registry', 'strings', 'imports', 'workflow', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

// --------------------------------------------------------------------------
// Evidence extraction
// --------------------------------------------------------------------------

interface SigmaEvidence {
  strings: string[]
  imports: Array<{ dll: string; functions: string[] }>
  mutexes: string[]
  urls: string[]
  ips: string[]
  domains: string[]
  filePaths: string[]
  registryKeys: string[]
  processNames: string[]
  sha256: string
}

type GeneratedSigmaRule = z.infer<typeof GeneratedSigmaRuleSchema>

function extractSigmaEvidence(database: DatabaseManager, sampleId: string): SigmaEvidence {
  const evidence: SigmaEvidence = {
    strings: [],
    imports: [],
    mutexes: [],
    urls: [],
    ips: [],
    domains: [],
    filePaths: [],
    registryKeys: [],
    processNames: [],
    sha256: sampleId.startsWith('sha256:') ? sampleId.slice(7) : sampleId,
  }

  const allEvidence = database.findAnalysisEvidenceBySample(sampleId)
  if (!Array.isArray(allEvidence)) return evidence

  for (const entry of allEvidence) {
    let data: Record<string, unknown>
    try {
      data =
        typeof entry.result_json === 'string'
          ? JSON.parse(entry.result_json)
          : (entry.result_json as Record<string, unknown>)
    } catch {
      continue
    }
    if (!data || typeof data !== 'object') continue

    // Extract strings
    if (Array.isArray(data.strings)) {
      for (const s of data.strings) {
        const str =
          typeof s === 'string'
            ? s
            : (s as { value?: string; string?: string })?.value ||
              (s as { string?: string })?.string
        if (str && str.length >= 6 && str.length <= 200) {
          evidence.strings.push(str)
        }
      }
    }

    // Extract imports
    if (Array.isArray(data.imports)) {
      for (const imp of data.imports as Array<{ dll?: string; functions?: string[] }>) {
        if (imp.dll) {
          evidence.imports.push({
            dll: imp.dll,
            functions: Array.isArray(imp.functions)
              ? imp.functions
                  .map((f: unknown) =>
                    typeof f === 'string' ? f : (f as { name?: string })?.name || ''
                  )
                  .filter(Boolean)
              : [],
          })
        }
      }
    }

    // Extract URLs, IPs, domains from strings
    for (const str of evidence.strings) {
      if (/^https?:\/\//i.test(str)) evidence.urls.push(str)
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(str)) evidence.ips.push(str)
      if (
        /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/i.test(str)
      ) {
        evidence.domains.push(str)
      }
      // Mutex patterns
      if (/^(Global\\|Local\\)/i.test(str) || /Mutex/i.test(str)) {
        evidence.mutexes.push(str)
      }
      // File system paths
      if (/^[A-Z]:\\/i.test(str) || /\\(Users|Windows|Temp|AppData|ProgramData)\\/i.test(str)) {
        evidence.filePaths.push(str)
      }
      // Registry keys
      if (/^(HKLM|HKCU|HKEY_)/i.test(str) || /\\(Software|CurrentVersion|Run)\\/i.test(str)) {
        evidence.registryKeys.push(str)
      }
    }

    // Extract process/service names from strings
    for (const str of evidence.strings) {
      if (/\.(exe|dll|sys|bat|cmd|ps1|vbs|js)$/i.test(str) && str.length < 100) {
        evidence.processNames.push(str)
      }
    }
  }

  // Deduplicate
  evidence.strings = [...new Set(evidence.strings)]
  evidence.urls = [...new Set(evidence.urls)]
  evidence.ips = [...new Set(evidence.ips)]
  evidence.domains = [...new Set(evidence.domains)]
  evidence.mutexes = [...new Set(evidence.mutexes)]
  evidence.filePaths = [...new Set(evidence.filePaths)]
  evidence.registryKeys = [...new Set(evidence.registryKeys)]
  evidence.processNames = [...new Set(evidence.processNames)]

  return evidence
}

// --------------------------------------------------------------------------
// Sigma YAML generation
// --------------------------------------------------------------------------

function yamlEscape(s: string): string {
  if (/[:\-#\[\]{}|>!&*?,'"%@`]/.test(s) || s.includes('\n')) {
    return `'${s.replace(/'/g, "''")}'`
  }
  return s
}

function generateProcessCreationRule(
  evidence: SigmaEvidence,
  level: string,
  sampleId: string
): string | null {
  const indicators: string[] = []

  // Suspicious imports that suggest process manipulation
  const suspiciousApis = [
    'CreateProcessW',
    'CreateProcessA',
    'ShellExecuteW',
    'ShellExecuteA',
    'WinExec',
    'CreateRemoteThread',
  ]
  const hasProcManip = evidence.imports.some((imp) =>
    imp.functions.some((f) => suspiciousApis.includes(f))
  )

  if (evidence.processNames.length > 0) {
    indicators.push(...evidence.processNames.slice(0, 10))
  }

  if (indicators.length === 0 && !hasProcManip) return null

  let yaml = `title: 'Suspicious Process Creation - ${evidence.sha256.slice(0, 8)}'\n`
  yaml += `id: ${generateUUID(sampleId + 'process_creation')}\n`
  yaml += `status: experimental\n`
  yaml += `description: 'Auto-generated Sigma rule for process creation indicators from sample ${evidence.sha256.slice(0, 16)}'\n`
  yaml += `references:\n  - 'Internal analysis'\n`
  yaml += `author: Rikune Auto-Generator\n`
  yaml += `date: ${new Date().toISOString().slice(0, 10)}\n`
  yaml += `tags:\n  - attack.execution\n  - attack.t1059\n`
  yaml += `logsource:\n  category: process_creation\n  product: windows\n`
  yaml += `detection:\n`

  if (indicators.length > 0) {
    yaml += `  selection:\n`
    yaml += `    Image|endswith:\n`
    for (const proc of indicators.slice(0, 10)) {
      yaml += `      - ${yamlEscape('\\' + proc)}\n`
    }
  }

  if (evidence.strings.length > 0) {
    yaml += `  selection_cmdline:\n`
    yaml += `    CommandLine|contains:\n`
    const cmdIndicators = evidence.strings
      .filter((s) => s.length >= 8 && s.length <= 100 && !/^[A-Z]:\\/i.test(s))
      .slice(0, 5)
    for (const s of cmdIndicators) {
      yaml += `      - ${yamlEscape(s)}\n`
    }
  }

  yaml += `  condition: selection or selection_cmdline\n`
  yaml += `level: ${level}\n`
  yaml += `falsepositives:\n  - Unknown\n`

  return yaml
}

function generateFileEventRule(
  evidence: SigmaEvidence,
  level: string,
  sampleId: string
): string | null {
  if (evidence.filePaths.length === 0 && evidence.processNames.length === 0) return null

  let yaml = `title: 'Suspicious File Activity - ${evidence.sha256.slice(0, 8)}'\n`
  yaml += `id: ${generateUUID(sampleId + 'file_event')}\n`
  yaml += `status: experimental\n`
  yaml += `description: 'Auto-generated Sigma rule for file event indicators from sample ${evidence.sha256.slice(0, 16)}'\n`
  yaml += `references:\n  - 'Internal analysis'\n`
  yaml += `author: Rikune Auto-Generator\n`
  yaml += `date: ${new Date().toISOString().slice(0, 10)}\n`
  yaml += `tags:\n  - attack.persistence\n  - attack.t1547\n`
  yaml += `logsource:\n  category: file_event\n  product: windows\n`
  yaml += `detection:\n`
  yaml += `  selection:\n`
  yaml += `    TargetFilename|contains:\n`

  const fileIndicators = [...evidence.filePaths, ...evidence.processNames].slice(0, 10)
  for (const f of fileIndicators) {
    yaml += `      - ${yamlEscape(f)}\n`
  }

  yaml += `  condition: selection\n`
  yaml += `level: ${level}\n`
  yaml += `falsepositives:\n  - Legitimate software with similar paths\n`

  return yaml
}

function generateRegistryEventRule(
  evidence: SigmaEvidence,
  level: string,
  sampleId: string
): string | null {
  if (evidence.registryKeys.length === 0) return null

  let yaml = `title: 'Suspicious Registry Modification - ${evidence.sha256.slice(0, 8)}'\n`
  yaml += `id: ${generateUUID(sampleId + 'registry_event')}\n`
  yaml += `status: experimental\n`
  yaml += `description: 'Auto-generated Sigma rule for registry indicators from sample ${evidence.sha256.slice(0, 16)}'\n`
  yaml += `references:\n  - 'Internal analysis'\n`
  yaml += `author: Rikune Auto-Generator\n`
  yaml += `date: ${new Date().toISOString().slice(0, 10)}\n`
  yaml += `tags:\n  - attack.persistence\n  - attack.t1547.001\n`
  yaml += `logsource:\n  category: registry_event\n  product: windows\n`
  yaml += `detection:\n`
  yaml += `  selection:\n`
  yaml += `    TargetObject|contains:\n`

  for (const key of evidence.registryKeys.slice(0, 10)) {
    yaml += `      - ${yamlEscape(key)}\n`
  }

  yaml += `  condition: selection\n`
  yaml += `level: ${level}\n`
  yaml += `falsepositives:\n  - Legitimate software\n`

  return yaml
}

function generateNetworkConnectionRule(
  evidence: SigmaEvidence,
  level: string,
  sampleId: string
): string | null {
  if (evidence.ips.length === 0 && evidence.domains.length === 0) return null

  let yaml = `title: 'Suspicious Network Connection - ${evidence.sha256.slice(0, 8)}'\n`
  yaml += `id: ${generateUUID(sampleId + 'network_connection')}\n`
  yaml += `status: experimental\n`
  yaml += `description: 'Auto-generated Sigma rule for network indicators from sample ${evidence.sha256.slice(0, 16)}'\n`
  yaml += `references:\n  - 'Internal analysis'\n`
  yaml += `author: Rikune Auto-Generator\n`
  yaml += `date: ${new Date().toISOString().slice(0, 10)}\n`
  yaml += `tags:\n  - attack.command_and_control\n  - attack.t1071\n`
  yaml += `logsource:\n  category: network_connection\n  product: windows\n`
  yaml += `detection:\n`

  if (evidence.ips.length > 0) {
    yaml += `  selection_ip:\n`
    yaml += `    DestinationIp:\n`
    for (const ip of evidence.ips.slice(0, 20)) {
      yaml += `      - ${yamlEscape(ip)}\n`
    }
  }

  if (evidence.domains.length > 0) {
    yaml += `  selection_host:\n`
    yaml += `    DestinationHostname|contains:\n`
    for (const domain of evidence.domains.slice(0, 20)) {
      yaml += `      - ${yamlEscape(domain)}\n`
    }
  }

  const conditions: string[] = []
  if (evidence.ips.length > 0) conditions.push('selection_ip')
  if (evidence.domains.length > 0) conditions.push('selection_host')
  yaml += `  condition: ${conditions.join(' or ')}\n`
  yaml += `level: ${level}\n`
  yaml += `falsepositives:\n  - Legitimate connections to these hosts\n`

  return yaml
}

function generateDnsQueryRule(
  evidence: SigmaEvidence,
  level: string,
  sampleId: string
): string | null {
  if (evidence.domains.length === 0) return null

  let yaml = `title: 'Suspicious DNS Query - ${evidence.sha256.slice(0, 8)}'\n`
  yaml += `id: ${generateUUID(sampleId + 'dns_query')}\n`
  yaml += `status: experimental\n`
  yaml += `description: 'Auto-generated Sigma rule for DNS query indicators from sample ${evidence.sha256.slice(0, 16)}'\n`
  yaml += `references:\n  - 'Internal analysis'\n`
  yaml += `author: Rikune Auto-Generator\n`
  yaml += `date: ${new Date().toISOString().slice(0, 10)}\n`
  yaml += `tags:\n  - attack.command_and_control\n  - attack.t1071.004\n`
  yaml += `logsource:\n  category: dns_query\n  product: windows\n`
  yaml += `detection:\n`
  yaml += `  selection:\n`
  yaml += `    QueryName|contains:\n`

  for (const domain of evidence.domains.slice(0, 20)) {
    yaml += `      - ${yamlEscape(domain)}\n`
  }

  yaml += `  condition: selection\n`
  yaml += `level: ${level}\n`
  yaml += `falsepositives:\n  - Legitimate DNS queries\n`

  return yaml
}

function generateImageLoadRule(
  evidence: SigmaEvidence,
  level: string,
  sampleId: string
): string | null {
  const suspiciousDlls = evidence.imports
    .map((imp) => imp.dll)
    .filter((dll) => {
      const lower = dll.toLowerCase()
      return (
        lower.includes('crypt') ||
        lower === 'winhttp.dll' ||
        lower === 'wininet.dll' ||
        lower === 'ws2_32.dll' ||
        lower === 'dnsapi.dll' ||
        lower === 'amsi.dll'
      )
    })

  if (suspiciousDlls.length === 0) return null

  let yaml = `title: 'Suspicious DLL Load - ${evidence.sha256.slice(0, 8)}'\n`
  yaml += `id: ${generateUUID(sampleId + 'image_load')}\n`
  yaml += `status: experimental\n`
  yaml += `description: 'Auto-generated Sigma rule for image load indicators from sample ${evidence.sha256.slice(0, 16)}'\n`
  yaml += `references:\n  - 'Internal analysis'\n`
  yaml += `author: Rikune Auto-Generator\n`
  yaml += `date: ${new Date().toISOString().slice(0, 10)}\n`
  yaml += `tags:\n  - attack.defense_evasion\n  - attack.t1574\n`
  yaml += `logsource:\n  category: image_load\n  product: windows\n`
  yaml += `detection:\n`
  yaml += `  selection:\n`
  yaml += `    ImageLoaded|endswith:\n`

  for (const dll of suspiciousDlls.slice(0, 10)) {
    yaml += `      - ${yamlEscape('\\' + dll)}\n`
  }

  yaml += `  filter:\n`
  yaml += `    Image|startswith:\n`
  yaml += `      - 'C:\\Windows\\'\n`
  yaml += `  condition: selection and not filter\n`
  yaml += `level: ${level}\n`
  yaml += `falsepositives:\n  - Legitimate applications loading these DLLs\n`

  return yaml
}

function generateUUID(seed: string): string {
  let hash = 0
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 5) - hash + seed.charCodeAt(i)) | 0
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0')
  return `${hex.slice(0, 8)}-${hex.slice(0, 4)}-4${hex.slice(1, 4)}-a${hex.slice(0, 3)}-${hex.padEnd(12, '0').slice(0, 12)}`
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

const RULE_GENERATORS: Record<
  string,
  (evidence: SigmaEvidence, level: string, sampleId: string) => string | null
> = {
  process_creation: generateProcessCreationRule,
  file_event: generateFileEventRule,
  registry_event: generateRegistryEventRule,
  network_connection: generateNetworkConnectionRule,
  dns_query: generateDnsQueryRule,
  image_load: generateImageLoadRule,
}

function countImportedFunctions(evidence: SigmaEvidence): number {
  return evidence.imports.reduce((sum, item) => sum + item.functions.length, 0)
}

function buildEvidenceSummary(args: {
  sampleId: string
  input: SigmaRuleGenerateInput
  evidence: SigmaEvidence
  rules: GeneratedSigmaRule[]
  warnings: string[]
}) {
  return {
    schema: 'rikune.sigma_rule_generation.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: SIGMA_RULES_ARTIFACT_TYPE,
    level: args.input.level,
    deploy_requested: args.input.deploy,
    requested_rule_types: args.input.rule_types,
    generated_rule_types: args.rules.map((rule) => rule.type),
    rules_generated: args.rules.length,
    total_indicators: args.rules.reduce((sum, rule) => sum + rule.indicator_count, 0),
    warning_count: args.warnings.length,
    warnings: args.warnings,
    evidence_counts: {
      strings: args.evidence.strings.length,
      imports: args.evidence.imports.length,
      imported_functions: countImportedFunctions(args.evidence),
      mutexes: args.evidence.mutexes.length,
      urls: args.evidence.urls.length,
      ips: args.evidence.ips.length,
      domains: args.evidence.domains.length,
      file_paths: args.evidence.filePaths.length,
      registry_keys: args.evidence.registryKeys.length,
      process_names: args.evidence.processNames.length,
    },
    evidence_sources: ['analysis_evidence', 'sample_metadata'],
  }
}

function buildRecommendedNextTools(): string[] {
  return [
    'analysis.evidence.graph',
    'attack.map',
    'ioc.export',
    'yara.generate',
    'report.generate',
    'artifact.read',
  ]
}

function buildNextActions(args: {
  input: SigmaRuleGenerateInput
  rules: GeneratedSigmaRule[]
  totalIndicators: number
  warnings: string[]
}): string[] {
  const actions = [
    'Review generated Sigma selections for over-broad strings, hostnames, paths, and registry keys before SIEM use.',
    'Load the persisted sigma_rules artifact through analysis.evidence.graph and report.generate for analyst reporting.',
    'Use attack.map, ioc.export, and yara.generate to correlate Sigma coverage with ATT&CK, IOC, and YARA evidence.',
  ]

  if (args.totalIndicators < 3) {
    actions.unshift(
      'Gather richer strings, imports, registry, file, or network evidence before promoting these rules.'
    )
  }

  if (args.rules.length < args.input.rule_types.length) {
    actions.unshift(
      'Review warnings for requested rule types that could not be generated from the available evidence.'
    )
  }

  if (args.input.deploy) {
    actions.unshift(
      'Treat deploy=true as a deployment request only; review and export the generated YAML before any external SIEM mutation.'
    )
  }

  if (args.warnings.length > 0) {
    actions.unshift('Resolve insufficient-evidence warnings if the missing rule categories matter.')
  }

  return actions
}

function buildQualityGates(args: {
  input: SigmaRuleGenerateInput
  rules: GeneratedSigmaRule[]
  totalIndicators: number
  evidence: SigmaEvidence
}) {
  const generatedRuleTypes = new Set(args.rules.map((rule) => rule.type))
  const missingRuleTypes = args.input.rule_types.filter(
    (ruleType) => !generatedRuleTypes.has(ruleType)
  )

  return {
    schema: 'rikune.sigma_rule_generation.quality_gates.v1',
    passive_generation_only: true,
    sample_executed_by_tool: false,
    backend_started: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    deploy_requested: args.input.deploy,
    deployment_mutation_requested: args.input.deploy,
    deployment_performed_by_tool: false,
    generated_rule_count: args.rules.length,
    requested_rule_count: args.input.rule_types.length,
    missing_requested_rule_types: missingRuleTypes,
    total_indicators: args.totalIndicators,
    rule_floor_met: args.rules.length > 0,
    indicator_floor_met: args.totalIndicators > 0,
    network_rule_present: args.rules.some((rule) =>
      ['network_connection', 'dns_query'].includes(rule.type)
    ),
    registry_rule_present: args.rules.some((rule) => rule.type === 'registry_event'),
    process_or_file_rule_present: args.rules.some((rule) =>
      ['process_creation', 'file_event', 'image_load'].includes(rule.type)
    ),
    false_positive_review_required: true,
    siem_validation_required: true,
    analyst_review_required: true,
    evidence_floor: {
      strings: args.evidence.strings.length,
      imports: args.evidence.imports.length,
      network_indicators:
        args.evidence.urls.length + args.evidence.ips.length + args.evidence.domains.length,
      registry_keys: args.evidence.registryKeys.length,
      file_or_process_indicators:
        args.evidence.filePaths.length + args.evidence.processNames.length,
    },
  }
}

function buildWorkflowHandoff(args: {
  sampleId: string
  input: SigmaRuleGenerateInput
  rules: GeneratedSigmaRule[]
  totalIndicators: number
  recommendedNextTools: string[]
}) {
  const generatedRuleTypes = args.rules.map((rule) => rule.type)

  return {
    schema: 'rikune.sigma_rule_generation.workflow_handoff.v1',
    handoff_mode: 'sigma_rule_generation_to_validation_attack_mapping_and_reporting',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: SIGMA_RULES_ARTIFACT_TYPE,
    level: args.input.level,
    deploy_requested: args.input.deploy,
    requested_rule_types: args.input.rule_types,
    generated_rule_types: generatedRuleTypes,
    generated_rule_count: args.rules.length,
    total_indicators: args.totalIndicators,
    recommended_next_tools: args.recommendedNextTools,
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: false,
      network_accessed_by_tool: false,
      live_lookup_started: false,
      siem_deployment_performed: false,
      deployment_mutation_requested: args.input.deploy,
    },
    routing: [
      {
        goal: 'rule-validation-and-false-positive-review',
        priority: 'high',
        next_tools: ['artifact.read', 'report.generate'],
        required_evidence: [SIGMA_RULES_ARTIFACT_TYPE, 'SIEM field mapping', 'benign event corpus'],
      },
      {
        goal: 'evidence-graph-and-reporting',
        priority: 'high',
        next_tools: ['analysis.evidence.graph', 'report.generate'],
        required_evidence: [SIGMA_RULES_ARTIFACT_TYPE],
      },
      {
        goal: 'attack-and-ioc-feedback-loop',
        priority: args.totalIndicators > 0 ? 'normal' : 'low',
        next_tools: ['attack.map', 'ioc.export', 'yara.generate'],
        required_evidence: ['generated Sigma rules', 'analysis evidence'],
      },
    ],
  }
}

function buildStructuredResult(args: {
  sampleId: string
  input: SigmaRuleGenerateInput
  evidence: SigmaEvidence
  rules: GeneratedSigmaRule[]
  warnings: string[]
}) {
  const totalIndicators = args.rules.reduce((sum, rule) => sum + rule.indicator_count, 0)
  const recommendedNextTools = buildRecommendedNextTools()
  const evidenceSummary = buildEvidenceSummary(args)
  const qualityGates = buildQualityGates({
    input: args.input,
    rules: args.rules,
    totalIndicators,
    evidence: args.evidence,
  })
  const workflowHandoff = buildWorkflowHandoff({
    sampleId: args.sampleId,
    input: args.input,
    rules: args.rules,
    totalIndicators,
    recommendedNextTools,
  })
  const nextActions = buildNextActions({
    input: args.input,
    rules: args.rules,
    totalIndicators,
    warnings: args.warnings,
  })

  return {
    schema: 'rikune.sigma_rule_generation.v1',
    tool_version: TOOL_VERSION,
    sample_id: args.sampleId,
    level: args.input.level,
    deploy_requested: args.input.deploy,
    requested_rule_types: args.input.rule_types,
    rules: args.rules,
    total_rules: args.rules.length,
    total_indicators: totalIndicators,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
    recommended_next_tools: recommendedNextTools,
    next_actions: nextActions,
  }
}

export function createSigmaRuleGenerateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = SigmaRuleGenerateInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      const evidence = extractSigmaEvidence(database, input.sample_id)
      const warnings: string[] = []
      const rules: GeneratedSigmaRule[] = []

      for (const ruleType of input.rule_types) {
        const generator = RULE_GENERATORS[ruleType]
        if (!generator) {
          warnings.push(`Unknown rule type: ${ruleType}`)
          continue
        }

        const ruleYaml = generator(evidence, input.level, input.sample_id)
        if (!ruleYaml) {
          warnings.push(`Insufficient evidence for ${ruleType} rule`)
          continue
        }

        // Count indicators in the rule
        const indicatorCount = (ruleYaml.match(/^\s+-\s/gm) || []).length

        rules.push({
          type: ruleType,
          title: ruleYaml.match(/title:\s*'([^']+)'/)?.[1] || `${ruleType} rule`,
          rule_yaml: ruleYaml,
          indicator_count: indicatorCount,
        })
      }

      if (rules.length === 0) {
        return {
          ok: false,
          errors: [
            'Insufficient analysis evidence to generate Sigma rules. Run strings.extract and pe.imports.extract first.',
          ],
          warnings,
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const data = buildStructuredResult({
        sampleId: input.sample_id,
        input,
        evidence,
        rules,
        warnings,
      })

      const artifacts: ArtifactRef[] = []
      try {
        const artifactRef = await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          SIGMA_RULES_ARTIFACT_TYPE,
          'sigma',
          data
        )
        artifacts.push(artifactRef)
      } catch {
        warnings.push('Failed to persist Sigma rule artifact')
      }

      return {
        ok: true,
        data,
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts: artifacts.length > 0 ? artifacts : undefined,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
