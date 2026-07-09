/**
 * office.vba.extract — Extract VBA macro source code from Office documents.
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
  truncateText,
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
  OFFICE_OLETOOLS_RUNTIME_POLICY,
  OFFICE_VBA_FOLLOW_UP_TOOLS,
  buildOfficeEvidenceSummary,
  buildOfficeQualityGates,
  buildOfficeWorkflowHandoff,
} from '../office-analysis-metadata.js'

const TOOL_NAME = 'office.vba.extract'
export const OFFICE_VBA_EXTRACT_ARTIFACT_TYPE = 'backend_office_vba_extract'

export const officeVbaExtractInputSchema = z.object({
  sample_id: z.string().describe('Target Office document sample identifier.'),
  timeout_sec: z.number().int().min(5).max(120).default(30).describe('Extraction timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist VBA source as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const officeVbaExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      macro_count: z.number().optional(),
      macros: z
        .array(
          z.object({
            filename: z.string(),
            stream_path: z.string(),
            vba_code: z.string(),
          })
        )
        .optional(),
      suspicious_keywords: z.array(z.string()).optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
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

export const officeVbaExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Extract VBA macro source code from Office documents (.doc, .xls, .docm, .xlsm, etc.) using olevba.',
  inputSchema: officeVbaExtractInputSchema,
  outputSchema: officeVbaExtractOutputSchema,
  aspects: {
    formats: OFFICE_ANALYSIS_FORMATS,
    platforms: OFFICE_ANALYSIS_PLATFORMS,
    execution: ['static', 'triage', 'workflow-handoff'],
    safety: OFFICE_ANALYSIS_SAFETY,
    capabilities: [
      'macro-analysis',
      'vba-macro-analysis',
      'vba-extraction',
      'excel-macro-analysis',
      'ioc-extraction',
      'behavior-profile-handoff',
      'static-only-profile',
      'workflow-handoff',
    ],
    evidence: [
      'macro-source',
      'strings',
      'behavior',
      'network',
      'filesystem',
      'workflow',
      'provenance',
    ],
    search: OFFICE_ANALYSIS_SEARCH_TERMS,
    profile: OFFICE_ANALYSIS_PROFILE_TAGS,
  },
  artifacts: [
    {
      type: OFFICE_VBA_EXTRACT_ARTIFACT_TYPE,
      description:
        'Extracted Office VBA macro source text with stream provenance, evidence summary, behavior profile handoff, and static-only quality gates',
      mimeTypes: ['text/plain'],
    },
  ],
  evidence: [
    { category: 'macro-source', artifactTypes: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE] },
    { category: 'strings', artifactTypes: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE] },
    { category: 'behavior', artifactTypes: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE] },
    { category: 'network', artifactTypes: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE] },
    { category: 'filesystem', artifactTypes: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'office.vba.extract-and-profile',
      title: 'Office VBA macro extraction and behavior profile',
      description:
        'Extract passive VBA macro and Excel macro source evidence for malicious document triage, IOC extraction, YARA generation, behavior profile correlation, and static-only workflow handoff.',
      startsWith: ['office.vba.extract'],
      nextTools: OFFICE_VBA_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE],
      evidence: [
        'macro-source',
        'strings',
        'behavior',
        'network',
        'filesystem',
        'workflow',
        'provenance',
      ],
      safety: OFFICE_ANALYSIS_SAFETY,
      runtimeBackends: ['static-python', 'oletools'],
    },
  ],
  runtimePolicy: OFFICE_OLETOOLS_RUNTIME_POLICY,
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'oletools VBA extraction worker',
    backendKind: 'external',
    adapter: 'static_python.office.vba.extract',
    availability: 'optional',
    envVar: 'OLETOOLS_PYTHON',
    supportedModes: ['external'],
    defaultMode: 'external',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: false,
      requiresIsolation: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      maxInputBytes: 128 * 1024 * 1024,
      maxOutputBytes: 16 * 1024 * 1024,
      defaultTimeoutMs: 30_000,
      notes: [
        'Worker performs read-only VBA extraction through oletools olevba.',
        'Missing oletools backends must return setup guidance; macros are never executed.',
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

const VBA_EXTRACT_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
file_path = payload["sample_path"]

from oletools.olevba import VBA_Parser

vba_parser = VBA_Parser(file_path)
macros = []
suspicious = set()

if vba_parser.detect_vba_macros():
    for filename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
        macros.append({
            "filename": str(vba_filename or filename or ""),
            "stream_path": str(stream_path or ""),
            "vba_code": str(vba_code or "")[:10000],
        })
    for kw_type, keyword, description in vba_parser.analyze_macros():
        if kw_type in ("Suspicious", "IOC", "AutoExec"):
            suspicious.add(f"{kw_type}: {keyword} — {description}")

vba_parser.close()

print(json.dumps({
    "macro_count": len(macros),
    "macros": macros[:20],
    "suspicious_keywords": sorted(suspicious)[:30],
}, ensure_ascii=False))
`.trim()

export function createOfficeVbaExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = officeVbaExtractInputSchema.parse(args)
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
        VBA_EXTRACT_SCRIPT,
        { sample_path: samplePath },
        input.timeout_sec * 1000
      )

      const macros = result.parsed?.macros || []
      const suspicious = result.parsed?.suspicious_keywords || []

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact && macros.length > 0) {
        const vbaText = macros
          .map((m: any) => `' ===== ${m.filename} (${m.stream_path}) =====\n${m.vba_code}`)
          .join('\n\n')
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'office',
          'vba_extract',
          vbaText,
          { extension: 'vba', mime: 'text/plain', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }
      const evidenceSummary = buildOfficeEvidenceSummary({
        schema: 'rikune.office_vba_extract.evidence_summary.v1',
        sourceTool: TOOL_NAME,
        sampleId: input.sample_id,
        artifactType: OFFICE_VBA_EXTRACT_ARTIFACT_TYPE,
        artifact,
        evidenceKind: 'vba-macro-source',
        evidenceCategories: [
          'macro-source',
          'strings',
          'behavior',
          'network',
          'filesystem',
          'provenance',
        ],
        counts: {
          macros: macros.length,
          suspicious_keywords: suspicious.length,
        },
        highlights: {
          macro_streams: macros
            .slice(0, 20)
            .map((macro: any) => `${macro.filename || 'macro'}:${macro.stream_path || 'stream'}`),
          suspicious_keywords: suspicious.slice(0, 20),
        },
      })
      const workflowHandoff = buildOfficeWorkflowHandoff({
        schema: 'rikune.office_vba_extract.workflow_handoff.v1',
        sourceTool: TOOL_NAME,
        sampleId: input.sample_id,
        artifact,
        producesArtifacts: [OFFICE_VBA_EXTRACT_ARTIFACT_TYPE],
        recommendedNextTools: OFFICE_VBA_FOLLOW_UP_TOOLS,
        routing: [
          {
            goal: 'malicious-document-triage',
            next_tools: ['office.macro.detect', 'office.behavior.profile', 'yara.scan'],
            evidence: ['macro-source', 'suspicious_keywords'],
          },
          {
            goal: 'ioc-extraction',
            next_tools: ['office.behavior.profile', 'ioc.export', 'analysis.evidence.graph'],
            evidence: ['network', 'filesystem', 'strings'],
          },
          {
            goal: 'rule-generation',
            next_tools: ['yara.generate', 'sigma.rule.generate', 'report.generate'],
            evidence: ['macro-source', 'behavior', 'ioc'],
          },
        ],
      })
      const qualityGates = buildOfficeQualityGates({
        schema: 'rikune.office_vba_extract.quality_gates.v1',
        sourceTool: TOOL_NAME,
        artifact,
        backend: 'oletools.olevba',
        checks: {
          macro_source_available: macros.length > 0,
          suspicious_keywords_present: suspicious.length > 0,
          truncated_preview_returned: macros.some(
            (macro: any) => String(macro.vba_code || '').length > 2000
          ),
          full_source_artifact_available: Boolean(artifact),
        },
      })
      if (artifact) {
        artifact.metadata = {
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
        }
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          macro_count: macros.length,
          macros: macros
            .slice(0, 5)
            .map((m: any) => ({ ...m, vba_code: truncateText(m.vba_code, 2000) })),
          suspicious_keywords: suspicious,
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
          artifact,
          summary: `Extracted ${macros.length} VBA macro(s), ${suspicious.length} suspicious keyword(s).`,
          recommended_next_tools: OFFICE_VBA_FOLLOW_UP_TOOLS,
          next_actions: [
            'Use artifact.read for full untruncated macro source.',
            'Use office.macro.detect for maliciousness assessment.',
            'Use office.behavior.profile to convert VBA, IOC, and static strings into workflow handoff evidence.',
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
