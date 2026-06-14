/**
 * apk.manifest.parse — Parse AndroidManifest.xml from an APK.
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

const TOOL_NAME = 'apk.manifest.parse'
const APK_MANIFEST_ARTIFACT_TYPE = 'backend_apk_manifest'
const APK_MANIFEST_SAFETY = [
  'passive',
  'static',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
  'no_live_execution',
]
const APK_MANIFEST_EVIDENCE = [
  'manifest',
  'permissions',
  'android-components',
  'package-metadata',
  'workflow',
  'provenance',
]
const APK_MANIFEST_NEXT_TOOLS = [
  'apk.disassemble',
  'apk.resources.decode',
  'android.behavior.graph',
  'strings.extract',
  'analysis.evidence.graph',
  'artifact.read',
]

export const apkManifestParseInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the APK file.'),
  timeout_sec: z.number().int().min(5).max(60).default(30).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist decoded manifest as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const apkManifestParseOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      package_name: z.string().optional(),
      version_name: z.string().optional(),
      version_code: z.string().optional(),
      min_sdk: z.string().optional(),
      target_sdk: z.string().optional(),
      permissions: z.array(z.string()).optional(),
      activities: z.array(z.string()).optional(),
      services: z.array(z.string()).optional(),
      receivers: z.array(z.string()).optional(),
      providers: z.array(z.string()).optional(),
      manifest_xml: z.string().optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const apkManifestParseToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Parse and decode AndroidManifest.xml from an APK, extracting permissions, components, and metadata.',
  inputSchema: apkManifestParseInputSchema,
  outputSchema: apkManifestParseOutputSchema,
  aspects: {
    formats: ['apk', 'aab', 'apks', 'xapk', 'split-apk', 'aar'],
    platforms: ['android'],
    execution: ['static', 'triage'],
    safety: APK_MANIFEST_SAFETY,
    capabilities: [
      'manifest',
      'permissions',
      'android-components',
      'package-metadata',
      'routing',
      'workflow-handoff',
    ],
    evidence: APK_MANIFEST_EVIDENCE,
    search: [
      'androidmanifest',
      'permissions',
      'activities',
      'services',
      'receivers',
      'providers',
      'package-name',
      'target-sdk',
    ],
  },
  artifacts: [
    {
      type: APK_MANIFEST_ARTIFACT_TYPE,
      description: 'Decoded AndroidManifest.xml and extracted component metadata',
      mime: 'application/xml',
    },
  ],
  evidence: [
    {
      category: 'manifest',
      artifactTypes: [APK_MANIFEST_ARTIFACT_TYPE],
    },
    {
      category: 'permissions',
      artifactTypes: [APK_MANIFEST_ARTIFACT_TYPE],
    },
    {
      category: 'android-components',
      artifactTypes: [APK_MANIFEST_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [APK_MANIFEST_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [APK_MANIFEST_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'apk-smali.manifest-component-profile',
      title: 'Android manifest permissions and component profile',
      description:
        'Decode AndroidManifest.xml with apktool, extract permissions and exported component evidence, then route Smali, resources, behavior graph, strings, and evidence graph follow-ups without executing the APK.',
      startsWith: [TOOL_NAME, 'android.package.inventory'],
      nextTools: APK_MANIFEST_NEXT_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [APK_MANIFEST_ARTIFACT_TYPE],
      evidence: APK_MANIFEST_EVIDENCE,
      safety: APK_MANIFEST_SAFETY,
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
      'apk.manifest.parse decodes local APK metadata with apktool and never executes Android code.',
    ],
  } as ToolDefinition['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
  },
}

function buildManifestEvidenceSummary(args: {
  sampleId: string
  packageName: string
  permissions: string[]
  dangerousPermissions: string[]
  activities: string[]
  services: string[]
  receivers: string[]
  providers: string[]
}) {
  return {
    schema: 'rikune.apk_manifest_parse.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    artifact_type: APK_MANIFEST_ARTIFACT_TYPE,
    package_name: args.packageName || null,
    permission_count: args.permissions.length,
    dangerous_permission_count: args.dangerousPermissions.length,
    component_counts: {
      activities: args.activities.length,
      services: args.services.length,
      receivers: args.receivers.length,
      providers: args.providers.length,
    },
    dangerous_permissions: args.dangerousPermissions.slice(0, 24),
    evidence_sources: ['apktool decoded AndroidManifest.xml'],
  }
}

function buildManifestWorkflowHandoff(args: {
  sampleId: string
  dangerousPermissions: string[]
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.apk_manifest_parse.workflow_handoff.v1',
    handoff_mode: 'apk_manifest_to_smali_resources_behavior_profile',
    source_tool: TOOL_NAME,
    sample_id: args.sampleId,
    recommended_next_tools: args.recommendedNextTools,
    artifact_contract: {
      consumes: ['sample'],
      produces: [APK_MANIFEST_ARTIFACT_TYPE],
      expected_consumers: ['apk.disassemble', 'android.behavior.graph', 'analysis.evidence.graph'],
    },
    routing: [
      {
        goal: 'entrypoint-and-component-review',
        next_tools: ['apk.disassemble', 'android.behavior.graph'],
        required_evidence: ['activities', 'services', 'receivers', 'providers'],
      },
      {
        goal: 'permission-risk-review',
        next_tools: ['apk.resources.decode', 'strings.extract', 'analysis.evidence.graph'],
        required_evidence: args.dangerousPermissions,
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

export function createApkManifestParseHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const tmpDir = path.join(os.tmpdir(), `apk-manifest-${Date.now()}`)
    try {
      const input = apkManifestParseInputSchema.parse(args)
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
      // Only decode resources, skip sources to be fast
      await executeCommand(
        backend.path,
        ['d', '-f', '-s', '-o', tmpDir, samplePath],
        input.timeout_sec * 1000
      )

      const manifestPath = path.join(tmpDir, 'AndroidManifest.xml')
      if (!nodeFs.existsSync(manifestPath)) {
        return {
          ok: false,
          errors: ['AndroidManifest.xml not found after decoding.'],
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }

      const xml = nodeFs.readFileSync(manifestPath, 'utf-8')

      // Simple regex extraction from decoded XML
      const pkg = xml.match(/package="([^"]+)"/)?.[1] || ''
      const versionName = xml.match(/android:versionName="([^"]+)"/)?.[1] || ''
      const versionCode = xml.match(/android:versionCode="([^"]+)"/)?.[1] || ''
      const minSdk = xml.match(/android:minSdkVersion="([^"]+)"/)?.[1] || ''
      const targetSdk = xml.match(/android:targetSdkVersion="([^"]+)"/)?.[1] || ''

      const permissions = [...xml.matchAll(/android:name="(android\.permission\.[^"]+)"/g)].map(
        (m) => m[1]
      )
      const activities = [...xml.matchAll(/<activity[^>]+android:name="([^"]+)"/g)].map((m) => m[1])
      const services = [...xml.matchAll(/<service[^>]+android:name="([^"]+)"/g)].map((m) => m[1])
      const receivers = [...xml.matchAll(/<receiver[^>]+android:name="([^"]+)"/g)].map((m) => m[1])
      const providers = [...xml.matchAll(/<provider[^>]+android:name="([^"]+)"/g)].map((m) => m[1])

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'apk',
          'manifest',
          xml.slice(0, 32768),
          { extension: 'xml', mime: 'application/xml', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }

      const dangerousPerms = permissions.filter((p) =>
        /INTERNET|SEND_SMS|READ_CONTACTS|CAMERA|RECORD_AUDIO|READ_PHONE|WRITE_EXTERNAL|INSTALL_PACKAGES|RECEIVE_BOOT/i.test(
          p
        )
      )
      const uniquePermissions = [...new Set(permissions)]
      const recommendedNextTools = APK_MANIFEST_NEXT_TOOLS
      const evidenceSummary = buildManifestEvidenceSummary({
        sampleId: input.sample_id,
        packageName: pkg,
        permissions: uniquePermissions,
        dangerousPermissions: dangerousPerms,
        activities,
        services,
        receivers,
        providers,
      })
      const workflowHandoff = buildManifestWorkflowHandoff({
        sampleId: input.sample_id,
        dangerousPermissions: dangerousPerms,
        recommendedNextTools,
      })

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          package_name: pkg,
          version_name: versionName,
          version_code: versionCode,
          min_sdk: minSdk,
          target_sdk: targetSdk,
          permissions: uniquePermissions,
          activities: activities.slice(0, 30),
          services: services.slice(0, 20),
          receivers: receivers.slice(0, 20),
          providers: providers.slice(0, 10),
          manifest_xml: xml.slice(0, 4096),
          artifact,
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: {
            schema: 'rikune.apk_manifest_parse.quality_gates.v1',
            passive_static_only: true,
            manifest_decoded: true,
            package_name_present: Boolean(pkg),
            component_profile_present:
              activities.length + services.length + receivers.length + providers.length > 0,
            artifact_persisted: Boolean(artifact),
            android_bytecode_executed_by_tool: false,
            network_accessed_by_tool: false,
          },
          summary: `Package: ${pkg}, ${permissions.length} permissions (${dangerousPerms.length} dangerous), ${activities.length} activities, ${services.length} services, ${receivers.length} receivers.`,
          recommended_next_tools: recommendedNextTools,
          next_actions: [
            dangerousPerms.length > 0
              ? `Review dangerous permissions: ${dangerousPerms.slice(0, 5).join(', ')}.`
              : 'No dangerous permissions found.',
            'Disassemble to Smali to inspect entry-point activities.',
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
