/**
 * apk.resources.decode — Decode and list APK resources via apktool.
 */

import { z } from 'zod'
import nodeFs from 'node:fs'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  os,
  path,
  ArtifactRefSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  normalizeError,
  executeCommand,
  persistBackendArtifact,
  buildMetrics,
  resolveSampleFile,
  resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'apk.resources.decode'
const APK_RESOURCES_ARTIFACT_TYPE = 'backend_apk_resources-listing'
const APK_RESOURCES_SAFETY = [
  'passive',
  'static',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
  'no_live_execution',
]
const APK_RESOURCES_EVIDENCE = ['resources', 'strings', 'filesystem', 'workflow', 'provenance']
const APK_RESOURCES_NEXT_TOOLS = [
  'apk.manifest.parse',
  'apk.disassemble',
  'strings.extract',
  'analysis.evidence.graph',
  'artifact.read',
]

export const apkResourcesDecodeInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the APK file.'),
  resource_filter: z
    .string()
    .optional()
    .describe('Regex filter for resource paths (e.g. "values/strings").'),
  max_files: z.number().int().min(1).max(200).default(50).describe('Max resource files to return.'),
  timeout_sec: z.number().int().min(10).max(120).default(60).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist resource listing as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const apkResourcesDecodeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      total_resources: z.number().optional(),
      returned_files: z.number().optional(),
      resource_files: z
        .array(
          z.object({
            path: z.string(),
            size_bytes: z.number(),
            preview: z.string().optional(),
          })
        )
        .optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const apkResourcesDecodeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Decode and list resources from an APK (layouts, strings, drawables, etc.).',
  inputSchema: apkResourcesDecodeInputSchema,
  outputSchema: apkResourcesDecodeOutputSchema,
  aspects: {
    formats: ['apk', 'aab', 'apks', 'xapk', 'split-apk', 'aar'],
    platforms: ['android'],
    execution: ['static', 'triage'],
    safety: APK_RESOURCES_SAFETY,
    capabilities: ['resources', 'strings', 'layouts', 'assets', 'manifest', 'workflow-handoff'],
    evidence: APK_RESOURCES_EVIDENCE,
    search: ['resources', 'strings.xml', 'layouts', 'drawables', 'assets', 'apktool'],
  },
  artifacts: [
    {
      type: APK_RESOURCES_ARTIFACT_TYPE,
      description: 'APK resource listing generated from APKTool output',
      mime: 'text/plain',
    },
  ],
  evidence: [
    {
      category: 'resources',
      artifactTypes: [APK_RESOURCES_ARTIFACT_TYPE],
    },
    {
      category: 'strings',
      artifactTypes: [APK_RESOURCES_ARTIFACT_TYPE],
    },
    {
      category: 'filesystem',
      artifactTypes: [APK_RESOURCES_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [APK_RESOURCES_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [APK_RESOURCES_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'apk-smali.resource-string-profile',
      title: 'APK resources and string profile',
      description:
        'Decode APK resources with apktool, list resource and text previews, then route manifest, Smali, string extraction, evidence graph, and artifact review without executing Android bytecode.',
      startsWith: [TOOL_NAME, 'android.package.inventory'],
      nextTools: APK_RESOURCES_NEXT_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [APK_RESOURCES_ARTIFACT_TYPE],
      evidence: APK_RESOURCES_EVIDENCE,
      safety: APK_RESOURCES_SAFETY,
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'apk.resources.decode decodes local APK resources with apktool and never executes Android bytecode.',
    ],
  } as ToolDefinition['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
  },
}

function collectResourceFiles(
  dir: string,
  base: string,
  filter?: RegExp
): Array<{ rel: string; abs: string; size: number }> {
  const results: Array<{ rel: string; abs: string; size: number }> = []
  if (!nodeFs.existsSync(dir)) return results
  const entries = nodeFs.readdirSync(dir, { withFileTypes: true })
  for (const entry of entries) {
    const abs = path.join(dir, entry.name)
    const rel = path.join(base, entry.name)
    if (entry.isDirectory()) {
      results.push(...collectResourceFiles(abs, rel, filter))
    } else {
      if (filter && !filter.test(rel)) continue
      const stat = nodeFs.statSync(abs)
      results.push({ rel, abs, size: stat.size })
    }
  }
  return results
}

function buildResourceEvidenceSummary(args: {
  input: z.infer<typeof apkResourcesDecodeInputSchema>
  totalResources: number
  returnedFiles: number
  files: Array<{ path: string; size_bytes: number; preview?: string }>
}) {
  const pathBuckets = args.files.reduce<Record<string, number>>((acc, file) => {
    const bucket = file.path.split('/')[0] || 'root'
    acc[bucket] = (acc[bucket] ?? 0) + 1
    return acc
  }, {})
  return {
    schema: 'rikune.apk_resources_decode.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.input.sample_id,
    artifact_type: APK_RESOURCES_ARTIFACT_TYPE,
    resource_filter: args.input.resource_filter ?? null,
    total_resources: args.totalResources,
    returned_files: args.returnedFiles,
    previewed_text_resource_count: args.files.filter((file) => file.preview).length,
    top_resource_buckets: pathBuckets,
    evidence_sources: ['apktool decoded res directory'],
  }
}

function buildResourceWorkflowHandoff(args: {
  input: z.infer<typeof apkResourcesDecodeInputSchema>
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.apk_resources_decode.workflow_handoff.v1',
    handoff_mode: 'apk_resources_to_strings_manifest_and_smali_review',
    source_tool: TOOL_NAME,
    sample_id: args.input.sample_id,
    recommended_next_tools: args.recommendedNextTools,
    artifact_contract: {
      consumes: ['sample'],
      produces: [APK_RESOURCES_ARTIFACT_TYPE],
      expected_consumers: ['strings.extract', 'apk.manifest.parse', 'analysis.evidence.graph'],
    },
    routing: [
      {
        goal: 'resource-string-review',
        next_tools: ['strings.extract', 'artifact.read'],
        required_evidence: ['resources', 'strings.xml', 'assets'],
      },
      {
        goal: 'manifest-and-smali-correlation',
        next_tools: ['apk.manifest.parse', 'apk.disassemble', 'analysis.evidence.graph'],
        required_evidence: ['resource_listing'],
      },
    ],
    dynamic_boundary: {
      passive_static_only: true,
      android_bytecode_executed_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

export function createApkResourcesDecodeHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const tmpDir = path.join(os.tmpdir(), `apk-res-${Date.now()}`)
    try {
      const input = apkResourcesDecodeInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({
        envPath: process.env.APKTOOL_PATH,
        pathCandidates: ['apktool'],
        versionArgSets: [['--version'], ['-version']],
      })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(
          backend || ({ name: 'apktool', available: false, error: 'apktool not installed' } as any),
          startTime,
          TOOL_NAME
        )
      }

      nodeFs.mkdirSync(tmpDir, { recursive: true })
      await executeCommand(
        backend.path,
        ['d', '-f', '-s', '-o', tmpDir, samplePath],
        input.timeout_sec * 1000
      )

      const resDir = path.join(tmpDir, 'res')
      const filter = input.resource_filter ? new RegExp(input.resource_filter, 'i') : undefined
      const allFiles = collectResourceFiles(resDir, '', filter)
      allFiles.sort((a, b) => b.size - a.size)

      const textExtensions = new Set(['.xml', '.json', '.txt', '.html', '.properties'])
      const resourceFiles = allFiles.slice(0, input.max_files).map((f) => {
        let preview = ''
        const ext = path.extname(f.abs).toLowerCase()
        if (textExtensions.has(ext) && f.size < 4096) {
          try {
            preview = nodeFs.readFileSync(f.abs, 'utf-8').slice(0, 512)
          } catch {}
        }
        return {
          path: f.rel.replace(/\\/g, '/'),
          size_bytes: f.size,
          preview: preview || undefined,
        }
      })

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        const listing = allFiles.map((f) => `${f.rel.replace(/\\/g, '/')} (${f.size}B)`).join('\n')
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'apk',
          'resources-listing',
          listing,
          { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }
      const recommendedNextTools = APK_RESOURCES_NEXT_TOOLS
      const evidenceSummary = buildResourceEvidenceSummary({
        input,
        totalResources: allFiles.length,
        returnedFiles: resourceFiles.length,
        files: resourceFiles,
      })
      const workflowHandoff = buildResourceWorkflowHandoff({
        input,
        recommendedNextTools,
      })

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          total_resources: allFiles.length,
          returned_files: resourceFiles.length,
          resource_files: resourceFiles,
          artifact,
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: {
            schema: 'rikune.apk_resources_decode.quality_gates.v1',
            passive_static_only: true,
            resources_decoded: true,
            resource_listing_present: allFiles.length > 0,
            artifact_persisted: Boolean(artifact),
            android_bytecode_executed_by_tool: false,
            network_accessed_by_tool: false,
          },
          summary: `Decoded ${allFiles.length} resource files${filter ? ' (filtered)' : ''}.`,
          recommended_next_tools: recommendedNextTools,
          next_actions: [
            'Look for suspicious URL strings in values/strings.xml.',
            'Check layouts for overlay attack indicators.',
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
    } finally {
      try {
        nodeFs.rmSync(tmpDir, { recursive: true, force: true })
      } catch {}
    }
  }
}
