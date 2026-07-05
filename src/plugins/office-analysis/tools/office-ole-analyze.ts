/**
 * office.ole.analyze — Analyze OLE2 structure and embedded objects.
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
  OFFICE_OLE_FOLLOW_UP_TOOLS,
  OFFICE_OLETOOLS_RUNTIME_POLICY,
  buildOfficeEvidenceSummary,
  buildOfficeQualityGates,
  buildOfficeWorkflowHandoff,
} from '../office-analysis-metadata.js'

const TOOL_NAME = 'office.ole.analyze'
export const OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE = 'backend_office_ole_analysis'

export const officeOleAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target Office/OLE document sample identifier.'),
  timeout_sec: z.number().int().min(5).max(60).default(20).describe('Analysis timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist OLE analysis as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const officeOleAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      is_ole2: z.boolean().optional(),
      streams: z
        .array(
          z.object({
            name: z.string(),
            size: z.number(),
          })
        )
        .optional(),
      embedded_objects: z
        .array(
          z.object({
            type: z.string(),
            indicator: z.string().optional(),
          })
        )
        .optional(),
      rtf_objects: z.array(z.any()).optional(),
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

export const officeOleAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Analyze OLE2 compound document structure: streams, embedded objects, ActiveX, and RTF objects.',
  inputSchema: officeOleAnalyzeInputSchema,
  outputSchema: officeOleAnalyzeOutputSchema,
  aspects: {
    formats: OFFICE_ANALYSIS_FORMATS,
    platforms: OFFICE_ANALYSIS_PLATFORMS,
    execution: ['static', 'triage', 'workflow-handoff'],
    safety: OFFICE_ANALYSIS_SAFETY,
    capabilities: [
      'ole-structure',
      'ole2-structure',
      'ooxml-structure',
      'embedded-object-detect',
      'rtf-object-detect',
      'malicious-document-triage',
      'behavior-profile-handoff',
      'static-only-profile',
      'workflow-handoff',
    ],
    evidence: ['structure', 'filesystem', 'workflow', 'provenance'],
    search: OFFICE_ANALYSIS_SEARCH_TERMS,
    profile: OFFICE_ANALYSIS_PROFILE_TAGS,
  },
  artifacts: [
    {
      type: OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE,
      description:
        'Office OLE/RTF structure, stream, embedded object inventory, evidence summary, workflow handoff, and static-only quality gates',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: [
    { category: 'structure', artifactTypes: [OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE] },
    { category: 'filesystem', artifactTypes: [OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE] },
    { category: 'workflow', artifactTypes: [OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE] },
    { category: 'provenance', artifactTypes: [OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE] },
  ],
  workflowRecipes: [
    {
      id: 'office.ole.structure-profile',
      title: 'Office OLE structure profile',
      description:
        'Inventory Office OLE, OOXML-adjacent, embedded object, and RTF evidence for malicious document triage before macro extraction, behavior profiling, and static-only workflow handoff.',
      startsWith: ['office.ole.analyze'],
      nextTools: OFFICE_OLE_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE],
      evidence: ['structure', 'filesystem', 'workflow', 'provenance'],
      safety: OFFICE_ANALYSIS_SAFETY,
      runtimeBackends: ['static-python', 'oletools', 'olefile'],
    },
  ],
  runtimePolicy: OFFICE_OLETOOLS_RUNTIME_POLICY,
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'oletools OLE structure worker',
    backendKind: 'external',
    adapter: 'static_python.office.ole.analyze',
    availability: 'optional',
    envVar: 'OLETOOLS_PYTHON',
    supportedModes: ['external'],
    defaultMode: 'external',
    inputArtifactTypes: ['sample'],
    outputArtifactTypes: [OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: false,
      requiresIsolation: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      maxInputBytes: 128 * 1024 * 1024,
      maxOutputBytes: 8 * 1024 * 1024,
      defaultTimeoutMs: 20_000,
      notes: [
        'Worker performs read-only OLE, embedded object, and RTF object parsing.',
        'Structure analysis must not preview documents, automate Office, or execute embedded content.',
      ],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Install oletools and olefile into the configured static Python worker environment.',
        'Set OLETOOLS_PYTHON when the oletools interpreter is not on PATH.',
      ],
      missingBackendBehavior:
        'Return setup_required guidance or partial static evidence; do not open or execute embedded content.',
    },
    packaging: {
      installRoute: 'installed',
      installProfile: 'default',
      dockerFeature: 'dynamic-python',
      envVar: 'OLETOOLS_PYTHON',
      dockerDefault: 'python3',
      notes: ['Requires Python packages oletools and olefile in the static worker environment.'],
    },
  },
}

const OLE_ANALYZE_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
file_path = payload["sample_path"]

result = {"is_ole2": False, "streams": [], "embedded_objects": [], "rtf_objects": []}

# Try OLE2 analysis
try:
    import olefile
    if olefile.isOleFile(file_path):
        result["is_ole2"] = True
        ole = olefile.OleFileIO(file_path)
        for stream in ole.listdir():
            path = "/".join(stream)
            try:
                size = ole.get_size(path)
            except:
                size = 0
            result["streams"].append({"name": path, "size": size})
        ole.close()
except ImportError:
    pass

# Try oleobj for embedded objects
try:
    from oletools import oleobj
    for index, data in enumerate(oleobj.find_ole(file_path)):
        if hasattr(data, 'format_id'):
            result["embedded_objects"].append({
                "type": "OLE_OBJECT",
                "indicator": str(getattr(data, 'filename', ''))[:200],
            })
except Exception:
    pass

# Try rtfobj
try:
    from oletools import rtfobj
    rtf_parser = rtfobj.RtfObjParser(open(file_path, "rb").read())
    rtf_parser.parse()
    for obj in rtf_parser.objects:
        result["rtf_objects"].append({
            "format_id": getattr(obj, "format_id", None),
            "class_name": str(getattr(obj, "class_name", ""))[:100],
            "is_package": getattr(obj, "is_package", False),
            "filename": str(getattr(obj, "filename", ""))[:200],
        })
except Exception:
    pass

print(json.dumps(result, ensure_ascii=False))
`.trim()

export function createOfficeOleAnalyzeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = officeOleAnalyzeInputSchema.parse(args)
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
        OLE_ANALYZE_SCRIPT,
        { sample_path: samplePath },
        input.timeout_sec * 1000
      )

      const streams = result.parsed?.streams || []
      const embeds = result.parsed?.embedded_objects || []
      const rtfObjs = result.parsed?.rtf_objects || []

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'office',
          'ole_analysis',
          JSON.stringify(result.parsed, null, 2),
          { extension: 'json', mime: 'application/json', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }
      const evidenceSummary = buildOfficeEvidenceSummary({
        schema: 'rikune.office_ole_analyze.evidence_summary.v1',
        sourceTool: TOOL_NAME,
        sampleId: input.sample_id,
        artifactType: OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE,
        artifact,
        evidenceKind: 'ole-structure',
        evidenceCategories: ['structure', 'filesystem', 'workflow', 'provenance'],
        counts: {
          streams: streams.length,
          embedded_objects: embeds.length,
          rtf_objects: rtfObjs.length,
          is_ole2: result.parsed?.is_ole2 ? 1 : 0,
        },
        highlights: {
          stream_names: streams
            .slice(0, 20)
            .map((stream: any) => stream.name)
            .filter(Boolean),
          embedded_object_indicators: embeds
            .slice(0, 20)
            .map((embed: any) => embed.indicator || embed.type)
            .filter(Boolean),
          rtf_object_filenames: rtfObjs
            .slice(0, 20)
            .map((obj: any) => obj.filename || obj.class_name)
            .filter(Boolean),
        },
      })
      const workflowHandoff = buildOfficeWorkflowHandoff({
        schema: 'rikune.office_ole_analyze.workflow_handoff.v1',
        sourceTool: TOOL_NAME,
        sampleId: input.sample_id,
        artifact,
        producesArtifacts: [OFFICE_OLE_ANALYSIS_ARTIFACT_TYPE],
        recommendedNextTools: OFFICE_OLE_FOLLOW_UP_TOOLS,
        routing: [
          {
            goal: 'macro-and-vba-review',
            next_tools: ['office.macro.detect', 'office.vba.extract', 'office.behavior.profile'],
            evidence: ['streams', 'vba_project', 'ole_structure'],
          },
          {
            goal: 'embedded-object-triage',
            next_tools: [
              'artifact.read',
              'strings.extract',
              'yara.scan',
              'analysis.evidence.graph',
            ],
            evidence: ['embedded_objects', 'rtf_objects', 'stream_inventory'],
          },
          {
            goal: 'malicious-document-reporting',
            next_tools: ['office.behavior.profile', 'report.generate'],
            evidence: ['structure', 'filesystem', 'provenance'],
          },
        ],
      })
      const qualityGates = buildOfficeQualityGates({
        schema: 'rikune.office_ole_analyze.quality_gates.v1',
        sourceTool: TOOL_NAME,
        artifact,
        backend: 'oletools.olefile',
        checks: {
          ole_structure_available: streams.length > 0 || Boolean(result.parsed?.is_ole2),
          embedded_objects_present: embeds.length > 0,
          rtf_objects_present: rtfObjs.length > 0,
          stream_inventory_count: streams.length,
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
          is_ole2: result.parsed?.is_ole2 || false,
          streams: streams.slice(0, 30),
          embedded_objects: embeds.slice(0, 20),
          rtf_objects: rtfObjs.slice(0, 10),
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
          artifact,
          summary: `OLE analysis: ${streams.length} streams, ${embeds.length} embedded objects, ${rtfObjs.length} RTF objects. OLE2: ${result.parsed?.is_ole2 ? 'yes' : 'no'}.`,
          recommended_next_tools: OFFICE_OLE_FOLLOW_UP_TOOLS,
          next_actions: [
            'Check embedded objects for executable payloads.',
            'Extract VBA macros with office.vba.extract.',
            'Use office.behavior.profile to correlate OLE structure with macro and IOC evidence.',
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
