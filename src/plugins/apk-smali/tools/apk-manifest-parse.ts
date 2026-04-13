/**
 * apk.manifest.parse — Parse AndroidManifest.xml from an APK.
 */

import { z } from 'zod'
import nodeFs from 'node:fs'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  os, path,
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'apk.manifest.parse'

export const apkManifestParseInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the APK file.'),
  timeout_sec: z.number().int().min(5).max(60).default(30).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist decoded manifest as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const apkManifestParseOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
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
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const apkManifestParseToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Parse and decode AndroidManifest.xml from an APK, extracting permissions, components, and metadata.',
  inputSchema: apkManifestParseInputSchema,
  outputSchema: apkManifestParseOutputSchema,
}

export function createApkManifestParseHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const tmpDir = path.join(os.tmpdir(), `apk-manifest-${Date.now()}`)
    try {
      const input = apkManifestParseInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.APKTOOL_PATH, pathCandidates: ['apktool'], versionArgSets: [['--version'], ['-version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'apktool', available: false, error: 'apktool not installed' } as any, startTime, TOOL_NAME)
      }

      nodeFs.mkdirSync(tmpDir, { recursive: true })
      // Only decode resources, skip sources to be fast
      await executeCommand(
        backend.path,
        ['d', '-f', '-s', '-o', tmpDir, samplePath],
        input.timeout_sec * 1000,
      )

      const manifestPath = path.join(tmpDir, 'AndroidManifest.xml')
      if (!nodeFs.existsSync(manifestPath)) {
        return { ok: false, errors: ['AndroidManifest.xml not found after decoding.'], metrics: buildMetrics(startTime, TOOL_NAME) }
      }

      const xml = nodeFs.readFileSync(manifestPath, 'utf-8')

      // Simple regex extraction from decoded XML
      const pkg = xml.match(/package="([^"]+)"/)?.[1] || ''
      const versionName = xml.match(/android:versionName="([^"]+)"/)?.[1] || ''
      const versionCode = xml.match(/android:versionCode="([^"]+)"/)?.[1] || ''
      const minSdk = xml.match(/android:minSdkVersion="([^"]+)"/)?.[1] || ''
      const targetSdk = xml.match(/android:targetSdkVersion="([^"]+)"/)?.[1] || ''

      const permissions = [...xml.matchAll(/android:name="(android\.permission\.[^"]+)"/g)].map(m => m[1])
      const activities = [...xml.matchAll(/<activity[^>]+android:name="([^"]+)"/g)].map(m => m[1])
      const services = [...xml.matchAll(/<service[^>]+android:name="([^"]+)"/g)].map(m => m[1])
      const receivers = [...xml.matchAll(/<receiver[^>]+android:name="([^"]+)"/g)].map(m => m[1])
      const providers = [...xml.matchAll(/<provider[^>]+android:name="([^"]+)"/g)].map(m => m[1])

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'apk', 'manifest', xml.slice(0, 32768), { extension: 'xml', mime: 'application/xml', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      const dangerousPerms = permissions.filter(p =>
        /INTERNET|SEND_SMS|READ_CONTACTS|CAMERA|RECORD_AUDIO|READ_PHONE|WRITE_EXTERNAL|INSTALL_PACKAGES|RECEIVE_BOOT/i.test(p)
      )

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          package_name: pkg,
          version_name: versionName,
          version_code: versionCode,
          min_sdk: minSdk,
          target_sdk: targetSdk,
          permissions: [...new Set(permissions)],
          activities: activities.slice(0, 30),
          services: services.slice(0, 20),
          receivers: receivers.slice(0, 20),
          providers: providers.slice(0, 10),
          manifest_xml: xml.slice(0, 4096),
          artifact,
          summary: `Package: ${pkg}, ${permissions.length} permissions (${dangerousPerms.length} dangerous), ${activities.length} activities, ${services.length} services, ${receivers.length} receivers.`,
          recommended_next_tools: ['apk.disassemble', 'apk.resources.decode', 'string.extract'],
          next_actions: [
            dangerousPerms.length > 0 ? `Review dangerous permissions: ${dangerousPerms.slice(0, 5).join(', ')}.` : 'No dangerous permissions found.',
            'Disassemble to Smali to inspect entry-point activities.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    } finally {
      try { nodeFs.rmSync(tmpDir, { recursive: true, force: true }) } catch {}
    }
  }
}
