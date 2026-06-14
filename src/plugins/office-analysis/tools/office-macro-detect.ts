/**
 * office.macro.detect — Detect and classify malicious macros using mraptor.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  normalizeError,
  runPythonJson,
  persistBackendArtifact,
  buildMetrics,
  resolveSampleFile,
  resolvePythonModuleBackend,
  buildStaticSetupRequired,
} from '../../docker-shared.js'
import {
  OFFICE_ANALYSIS_FORMATS,
  OFFICE_ANALYSIS_PLATFORMS,
  OFFICE_ANALYSIS_PROFILE_TAGS,
  OFFICE_ANALYSIS_SEARCH_TERMS,
  OFFICE_ANALYSIS_SAFETY,
  OFFICE_MACRO_FOLLOW_UP_TOOLS,
  OFFICE_OLETOOLS_RUNTIME_POLICY,
  buildOfficeEvidenceSummary,
  buildOfficeQualityGates,
  buildOfficeWorkflowHandoff,
} from '../office-analysis-metadata.js'

const TOOL_NAME = 'office.macro.detect'
export const OFFICE_MACRO_DETECTION_ARTIFACT_TYPE = 'backend_office_macro_detection'

export const officeMacroDetectInputSchema = z.object({
  sample_id: z.string().describe('Target Office document sample identifier.'),
  timeout_sec: z.number().int().min(5).max(60).default(15).describe('Detection timeout.'),
  persist_artifact: z
    .boolean()
    .default(false)
    .describe(
      'Persist macro detection JSON as an artifact. Default preserves legacy no-artifact behavior.'
    ),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const officeMacroDetectOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      has_macros: z.boolean().optional(),
      is_suspicious: z.boolean().optional(),
      flags: z
        .object({
          auto_exec: z.boolean().optional(),
          suspicious: z.boolean().optional(),
          ioc: z.boolean().optional(),
          hex_strings: z.boolean().optional(),
          base64_strings: z.boolean().optional(),
          dridex_strings: z.boolean().optional(),
          vba_stomping: z.boolean().optional(),
        })
        .optional(),
      risk_level: z.enum(['safe', 'low', 'medium', 'high']).optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const officeMacroDetectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Detect and classify malicious macros in Office documents. Returns risk level and specific threat indicators.',
  inputSchema: officeMacroDetectInputSchema,
  outputSchema: officeMacroDetectOutputSchema,
  aspects: {
    formats: OFFICE_ANALYSIS_FORMATS,
    platforms: OFFICE_ANALYSIS_PLATFORMS,
    execution: ['static', 'triage', 'workflow-handoff'],
    safety: OFFICE_ANALYSIS_SAFETY,
    capabilities: [
      'macro-analysis',
      'vba-macro-analysis',
      'excel-macro-analysis',
      'malicious-macro-detect',
      'malicious-document-detection',
      'ioc-extraction',
      'behavior-profile-handoff',
      'static-only-profile',
      'workflow-handoff',
    ],
    evidence: ['behavior', 'strings', 'network', 'filesystem', 'workflow', 'provenance'],
    search: OFFICE_ANALYSIS_SEARCH_TERMS,
    profile: OFFICE_ANALYSIS_PROFILE_TAGS,
  },
  artifacts: [
    {
      type: OFFICE_MACRO_DETECTION_ARTIFACT_TYPE,
      description:
        'Optional Office macro detector JSON with flags, risk level, malicious document evidence summary, workflow handoff, and static-only quality gates',
      mimeTypes: ['application/json'],
      required: false,
    },
  ],
  evidence: [
    { category: 'behavior', artifactTypes: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE] },
    { category: 'network', artifactTypes: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE] },
    { category: 'filesystem', artifactTypes: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'office.macro.detect-and-triage',
      title: 'Office macro detection triage',
      description:
        'Classify passive VBA/Excel macro detector flags for malicious document triage and hand suspicious static-only evidence to VBA extraction, OLE structure review, signature scanning, and behavior profiling.',
      startsWith: ['office.macro.detect'],
      nextTools: OFFICE_MACRO_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE],
      evidence: ['behavior', 'strings', 'network', 'filesystem', 'workflow', 'provenance'],
      safety: OFFICE_ANALYSIS_SAFETY,
      runtimeBackends: ['static-python', 'oletools'],
    },
  ],
  runtimePolicy: OFFICE_OLETOOLS_RUNTIME_POLICY,
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'oletools macro detection worker',
    backendKind: 'external',
    adapter: 'static_python.office.macro.detect',
    availability: 'optional',
    envVar: 'OLETOOLS_PYTHON',
    supportedModes: ['external'],
    defaultMode: 'external',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: false,
      requiresIsolation: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      maxInputBytes: 128 * 1024 * 1024,
      maxOutputBytes: 4 * 1024 * 1024,
      defaultTimeoutMs: 15_000,
      notes: [
        'Worker performs read-only macro flag classification through oletools olevba.',
        'Detector output is static evidence only and does not execute document code.',
      ],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Install oletools into the configured static Python worker environment.',
        'Set OLETOOLS_PYTHON when the oletools interpreter is not on PATH.',
      ],
      missingBackendBehavior:
        'Return setup_required guidance; do not automate Office or execute document macros.',
    },
    packaging: {
      installRoute: 'installed',
      installProfile: 'default',
      dockerFeature: 'dynamic-python',
      envVar: 'OLETOOLS_PYTHON',
      dockerDefault: 'python3',
      notes: ['Requires the Python oletools package in the static worker environment.'],
    },
  },
}

const MACRO_DETECT_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
file_path = payload["sample_path"]

from oletools.olevba import VBA_Parser

vba_parser = VBA_Parser(file_path)
has_macros = vba_parser.detect_vba_macros()

flags = {
    "auto_exec": False,
    "suspicious": False,
    "ioc": False,
    "hex_strings": False,
    "base64_strings": False,
    "dridex_strings": False,
    "vba_stomping": False,
}

if has_macros:
    for kw_type, keyword, description in vba_parser.analyze_macros():
        if kw_type == "AutoExec":
            flags["auto_exec"] = True
        elif kw_type == "Suspicious":
            flags["suspicious"] = True
        elif kw_type == "IOC":
            flags["ioc"] = True
        elif kw_type == "Hex String":
            flags["hex_strings"] = True
        elif kw_type == "Base64 String":
            flags["base64_strings"] = True
        elif kw_type == "Dridex String":
            flags["dridex_strings"] = True
        elif kw_type == "VBA Stomping":
            flags["vba_stomping"] = True

vba_parser.close()

risk_count = sum(1 for v in flags.values() if v)
if risk_count == 0:
    risk = "safe" if not has_macros else "low"
elif risk_count <= 2:
    risk = "medium"
else:
    risk = "high"

print(json.dumps({
    "has_macros": has_macros,
    "is_suspicious": flags["suspicious"] or flags["auto_exec"],
    "flags": flags,
    "risk_level": risk,
}, ensure_ascii=False))
`.trim()

export function createOfficeMacroDetectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = officeMacroDetectInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({
        envPythonPath: process.env.OLETOOLS_PYTHON,
        moduleNames: ['oletools'],
        distributionNames: ['oletools'],
      })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(
          backend ||
            ({
              name: 'oletools',
              available: false,
              error: 'oletools Python module not available',
            } as any),
          startTime,
          TOOL_NAME
        )
      }

      const result = await runPythonJson(
        backend.path,
        MACRO_DETECT_SCRIPT,
        { sample_path: samplePath },
        input.timeout_sec * 1000
      )

      const risk = result.parsed?.risk_level || 'safe'
      const hasMacros = result.parsed?.has_macros || false
      const flags = result.parsed?.flags || {}
      const enabledFlags = Object.entries(flags)
        .filter(([, value]) => Boolean(value))
        .map(([name]) => name)
      const isSuspicious = result.parsed?.is_suspicious || false

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      const buildHandoffBundle = (currentArtifact?: ArtifactRef) => {
        const evidenceSummary = buildOfficeEvidenceSummary({
          schema: 'rikune.office_macro_detect.evidence_summary.v1',
          sourceTool: TOOL_NAME,
          sampleId: input.sample_id,
          artifactType: OFFICE_MACRO_DETECTION_ARTIFACT_TYPE,
          artifact: currentArtifact,
          evidenceKind: 'macro-detection',
          evidenceCategories: [
            'behavior',
            'strings',
            'network',
            'filesystem',
            'workflow',
            'provenance',
          ],
          counts: {
            enabled_flags: enabledFlags.length,
            has_macros: hasMacros ? 1 : 0,
          },
          highlights: {
            risk_level: risk,
            has_macros: hasMacros,
            is_suspicious: isSuspicious,
            enabled_flags: enabledFlags,
          },
        })
        const workflowHandoff = buildOfficeWorkflowHandoff({
          schema: 'rikune.office_macro_detect.workflow_handoff.v1',
          sourceTool: TOOL_NAME,
          sampleId: input.sample_id,
          artifact: currentArtifact,
          producesArtifacts: [OFFICE_MACRO_DETECTION_ARTIFACT_TYPE],
          recommendedNextTools: OFFICE_MACRO_FOLLOW_UP_TOOLS,
          routing: [
            {
              goal: 'vba-source-review',
              next_tools: ['office.vba.extract', 'office.behavior.profile', 'artifact.read'],
              evidence: ['has_macros', 'auto_exec', 'suspicious', 'ioc'],
            },
            {
              goal: 'ole-structure-review',
              next_tools: ['office.ole.analyze', 'analysis.evidence.graph'],
              evidence: ['macro_detection_flags', 'malicious_document_triage'],
            },
            {
              goal: 'signature-and-reporting',
              next_tools: ['yara.scan', 'ioc.export', 'report.generate'],
              evidence: ['risk_level', 'enabled_flags'],
            },
          ],
        })
        const qualityGates = buildOfficeQualityGates({
          schema: 'rikune.office_macro_detect.quality_gates.v1',
          sourceTool: TOOL_NAME,
          artifact: currentArtifact,
          backend: 'oletools.olevba',
          checks: {
            macro_detection_available: true,
            has_macros: hasMacros,
            suspicious_flags_present: enabledFlags.length > 0,
            risk_level: risk,
            optional_artifact_requested: input.persist_artifact,
          },
        })
        return { evidenceSummary, workflowHandoff, qualityGates }
      }
      let { evidenceSummary, workflowHandoff, qualityGates } = buildHandoffBundle()

      if (input.persist_artifact) {
        const payload = {
          sample_id: input.sample_id,
          has_macros: hasMacros,
          is_suspicious: isSuspicious,
          flags,
          risk_level: risk,
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
        }
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'office',
          'macro_detection',
          JSON.stringify(payload, null, 2),
          { extension: 'json', mime: 'application/json', sessionTag: input.session_tag }
        )
        const persistedBundle = buildHandoffBundle(artifact)
        evidenceSummary = persistedBundle.evidenceSummary
        workflowHandoff = persistedBundle.workflowHandoff
        qualityGates = persistedBundle.qualityGates
        artifact.metadata = {
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
        }
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          has_macros: hasMacros,
          is_suspicious: isSuspicious,
          flags,
          risk_level: risk,
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
          artifact,
          summary: hasMacros
            ? `Macros detected — risk: ${risk.toUpperCase()}. ${isSuspicious ? 'SUSPICIOUS indicators found.' : 'No suspicious patterns.'}`
            : 'No macros detected.',
          recommended_next_tools: hasMacros
            ? OFFICE_MACRO_FOLLOW_UP_TOOLS
            : ['office.ole.analyze', 'metadata.extract', 'workflow.search'],
          next_actions: hasMacros
            ? [
                'Extract macro source with office.vba.extract for manual review.',
                'Scan with YARA rules for known malware patterns.',
                'Build a static-only behavior handoff with office.behavior.profile.',
              ]
            : [
                'No macro execution evidence was found; continue with OLE/OOXML structure and metadata review if the document remains suspicious.',
              ],
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
