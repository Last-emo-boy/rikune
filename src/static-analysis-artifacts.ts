import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import type { ArtifactRef } from './types.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'
import { deriveArtifactSessionTag } from './artifact-inventory.js'
import { sanitizePathSegment, matchesSessionTag } from './utils/shared-helpers.js'

export const STATIC_CAPABILITY_TRIAGE_ARTIFACT_TYPE = 'static_capability_triage'
export const PE_STRUCTURE_ANALYSIS_ARTIFACT_TYPE = 'pe_structure_analysis'
export const COMPILER_PACKER_ATTRIBUTION_ARTIFACT_TYPE = 'compiler_packer_attribution'

export type StaticArtifactScope = 'all' | 'latest' | 'session'

export interface StaticArtifactSelectionOptions {
  scope?: StaticArtifactScope
  sessionTag?: string
}

export interface StaticArtifactSelection<TPayload = unknown> {
  artifacts: Array<{
    artifact_id: string
    created_at: string
    session_tags: string[]
    payload: TPayload
  }>
  latest_payload: TPayload | null
  artifact_ids: string[]
  session_tags: string[]
  earliest_created_at: string | null
  latest_created_at: string | null
  scope_note: string
}

const LATEST_STATIC_ARTIFACT_WINDOW_MS = 10 * 1000


export async function persistStaticAnalysisJsonArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  artifactType: string,
  filePrefix: string,
  payload: unknown,
  sessionTag?: string | null
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const sessionSegment = sanitizePathSegment(sessionTag || undefined, 'default')
  const reportDir = path.join(workspace.reports, 'static_analysis', sessionSegment)
  await fs.mkdir(reportDir, { recursive: true })

  const fileName = `${filePrefix}_${Date.now()}.json`
  const absolutePath = path.join(reportDir, fileName)
  const serialized = JSON.stringify(payload, null, 2)
  await fs.writeFile(absolutePath, serialized, 'utf8')

  const artifactId = randomUUID()
  const artifactSha256 = createHash('sha256').update(serialized).digest('hex')
  const relativePath = path.relative(workspace.root, absolutePath).replace(/\\/g, '/')
  const createdAt = new Date().toISOString()

  database.insertArtifact({
    id: artifactId,
    sample_id: sampleId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: 'application/json',
    created_at: createdAt,
  })

  return {
    id: artifactId,
    type: artifactType,
    path: relativePath,
    sha256: artifactSha256,
    mime: 'application/json',
  }
}


export async function loadStaticAnalysisArtifactSelection<TPayload>(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  artifactType: string,
  options: StaticArtifactSelectionOptions = {}
): Promise<StaticArtifactSelection<TPayload>> {
  const scope = options.scope || 'latest'
  const sessionTag = options.sessionTag?.trim() || null
  const artifacts = database.findArtifactsByType(sampleId, artifactType)
  if (artifacts.length === 0) {
    return {
      artifacts: [],
      latest_payload: null,
      artifact_ids: [],
      session_tags: [],
      earliest_created_at: null,
      latest_created_at: null,
      scope_note: scope === 'session' && sessionTag
        ? `No ${artifactType} artifacts matched session selector "${sessionTag}".`
        : scope === 'latest'
          ? `No ${artifactType} artifacts matched the latest selection window.`
          : `No ${artifactType} artifacts were selected.`,
    }
  }

  const workspace = await workspaceManager.getWorkspace(sampleId)
  const loaded: Array<{
    artifact_id: string
    created_at: string
    session_tags: string[]
    payload: TPayload
  }> = []

  for (const artifact of artifacts) {
    try {
      const absolutePath = workspaceManager.normalizePath(workspace.root, artifact.path)
      const content = await fs.readFile(absolutePath, 'utf8')
      const payload = JSON.parse(content) as TPayload
      const sessionTags = Array.from(
        new Set(
          [
            deriveArtifactSessionTag(artifact.path),
            typeof (payload as { session_tag?: unknown })?.session_tag === 'string'
              ? String((payload as { session_tag?: string }).session_tag).trim()
              : null,
          ].filter((item): item is string => Boolean(item && item.trim()))
        )
      )

      loaded.push({
        artifact_id: artifact.id,
        created_at: artifact.created_at,
        session_tags: sessionTags,
        payload,
      })
    } catch {
      continue
    }
  }

  let selected = loaded
  if (scope === 'session' && sessionTag) {
    selected = loaded.filter((item) => matchesSessionTag(item.session_tags, sessionTag))
  } else if (scope === 'latest' && loaded.length > 0) {
    const latestCreated = new Date(loaded[0].created_at).getTime()
    selected = loaded.filter((item) => latestCreated - new Date(item.created_at).getTime() <= LATEST_STATIC_ARTIFACT_WINDOW_MS)
  }

  const artifactIds = selected.map((item) => item.artifact_id)
  const sessionTags = Array.from(new Set(selected.flatMap((item) => item.session_tags)))
  const createdAtValues = selected.map((item) => item.created_at).filter((item) => item && item.length > 0)
  const latestCreatedAt = createdAtValues.length > 0 ? createdAtValues[0] : null
  const earliestCreatedAt = createdAtValues.length > 0 ? createdAtValues[createdAtValues.length - 1] : null
  const scopeNote = selected.length > 0
    ? `Selected ${selected.length} ${artifactType} artifact(s) using scope=${scope}${sessionTag ? ` selector=${sessionTag}` : ''}.`
    : scope === 'session' && sessionTag
      ? `No ${artifactType} artifacts matched session selector "${sessionTag}".`
      : scope === 'latest'
        ? `No ${artifactType} artifacts matched the latest selection window.`
        : `No ${artifactType} artifacts were selected.`

  return {
    artifacts: selected,
    latest_payload: selected.length > 0 ? selected[0].payload : null,
    artifact_ids: artifactIds,
    session_tags: sessionTags,
    earliest_created_at: earliestCreatedAt,
    latest_created_at: latestCreatedAt,
    scope_note: scopeNote,
  }
}
