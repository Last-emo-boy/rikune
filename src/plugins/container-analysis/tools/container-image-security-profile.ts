/**
 * container.image.security.profile — passive Docker/OCI image security profile.
 *
 * This tool reads image layout metadata and bounded layer tar headers only. It
 * never talks to a registry, starts Docker, mounts layers, extracts files,
 * installs packages, or runs image entrypoints.
 */

import crypto from 'crypto'
import fs from 'fs/promises'
import path from 'path'
import zlib from 'zlib'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'container.image.security.profile'
const ARTIFACT_TYPE = 'container_image_security_profile'
const DEFAULT_MAX_READ_BYTES = 64 * 1024 * 1024
const MAX_READ_BYTES = 128 * 1024 * 1024
const DEFAULT_MAX_LAYER_BYTES = 16 * 1024 * 1024
const MAX_LAYER_BYTES = 64 * 1024 * 1024
const MAX_TAR_MEMBERS = 4096
const MAX_LAYER_ENTRIES = 2048
const MAX_PREVIEW_ITEMS = 50

const ContainerImagePolicySchema = z.object({
  passive: z.literal(true),
  no_registry_network: z.literal(true),
  no_docker_daemon: z.literal(true),
  no_layer_extract: z.literal(true),
  no_mount: z.literal(true),
  no_install: z.literal(true),
  no_entrypoint_run: z.literal(true),
  no_mutation: z.literal(true),
})

const ContainerImageSecurityProfileDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  image_format: z.string(),
  detected_by: z.array(z.string()),
  sha256_preview: z.string(),
  selected_image: z.record(z.any()),
  config_digest: z.string().optional(),
  platform: z.record(z.any()),
  runtime_config: z.record(z.any()),
  layer_summary: z.record(z.any()),
  history_summary: z.record(z.any()),
  risk_flags: z.array(z.string()),
  risk_score: z.number(),
  policy: ContainerImagePolicySchema,
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const ContainerImageSecurityProfileInputSchema = z.object({
  sample_id: z.string().describe('Target Docker save tar or OCI layout sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(4096)
    .max(MAX_READ_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read from the image archive.'),
  max_layer_scan_bytes: z
    .number()
    .int()
    .min(4096)
    .max(MAX_LAYER_BYTES)
    .default(DEFAULT_MAX_LAYER_BYTES)
    .describe('Maximum bytes per layer blob to inspect as tar headers.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist image security profile JSON as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const ContainerImageSecurityProfileOutputSchema = z.object({
  ok: z.boolean(),
  data: ContainerImageSecurityProfileDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const containerImageSecurityProfileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively profile Docker save tar and OCI image layout metadata for root-user defaults, entrypoints, secret-like env, package manager traces, whiteouts, SUID files, and layer risk without running or mounting the image.',
  inputSchema: ContainerImageSecurityProfileInputSchema,
  outputSchema: ContainerImageSecurityProfileOutputSchema,
  aspects: {
    formats: ['container', 'docker-image', 'oci-image', 'tar', 'archive'],
    platforms: ['linux', 'windows', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'triage', 'correlation'],
    safety: [
      'passive',
      'no_network_by_default',
      'no_installer_execution',
      'no_auto_mount',
      'no_live_sample_by_default',
      'no_mutation',
    ],
    capabilities: [
      'container-security-profile',
      'image-config',
      'layer-inventory',
      'secret-detection',
      'supply-chain-risk',
      'workflow-handoff',
    ],
    evidence: ['filesystem', 'package-metadata', 'provenance', 'workflow', 'sbom'],
  },
  artifacts: [
    {
      type: ARTIFACT_TYPE,
      description:
        'Passive Docker/OCI image security profile with runtime config, history, layer header risk, and workflow handoff',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'filesystem',
      artifactTypes: [ARTIFACT_TYPE],
      description:
        'Layer tar header evidence, whiteouts, SUID/world-writable paths, and package traces',
    },
    {
      category: 'provenance',
      artifactTypes: [ARTIFACT_TYPE],
      description:
        'Image config, history, labels, repo tags, digest references, and platform metadata',
    },
    {
      category: 'package-metadata',
      artifactTypes: [ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'container.image-security-profile',
      title: 'Docker/OCI image static security profile',
      description:
        'Parse Docker save tar or OCI image layout metadata and bounded layer tar headers to identify root defaults, entrypoint risk, secret-like environment variables, package manager traces, whiteouts, and file-mode risks without registry access, Docker daemon access, layer extraction, mounting, install scripts, or entrypoint execution.',
      startsWith: ['container.image.security.profile', 'container.structure.analyze'],
      nextTools: [
        'container.structure.analyze',
        'sbom.provenance.graph',
        'sbom.generate',
        'strings.extract',
        'analysis.evidence.graph',
        'report.generate',
      ],
      requiredArtifacts: ['sample'],
      producesArtifacts: [ARTIFACT_TYPE],
      evidence: ['filesystem', 'package-metadata', 'provenance', 'workflow', 'sbom'],
      safety: [
        'passive',
        'no_network_by_default',
        'no_installer_execution',
        'no_auto_mount',
        'no_live_sample_by_default',
        'no_mutation',
      ],
    },
  ],
}

type TarMember = {
  path: string
  size: number
  mode: number
  typeflag: string
  dataOffset: number
  data: Buffer
}

type DockerManifestEntry = {
  Config?: string
  RepoTags?: string[]
  Layers?: string[]
}

type OciDescriptor = {
  mediaType?: string
  digest?: string
  size?: number
  platform?: Record<string, unknown>
  annotations?: Record<string, string>
}

type OciManifest = {
  config?: OciDescriptor
  layers?: OciDescriptor[]
}

type ImageConfig = {
  architecture?: string
  os?: string
  variant?: string
  config?: {
    User?: string
    Env?: string[]
    Entrypoint?: string[] | string | null
    Cmd?: string[] | string | null
    Shell?: string[] | null
    ExposedPorts?: Record<string, unknown>
    WorkingDir?: string
    Labels?: Record<string, string>
    Volumes?: Record<string, unknown>
    StopSignal?: string
  }
  rootfs?: {
    type?: string
    diff_ids?: string[]
  }
  history?: Array<{
    created_by?: string
    comment?: string
    empty_layer?: boolean
  }>
}

type LayerReference = {
  path: string
  mediaType?: string
  digest?: string
  size?: number
}

type LayerScan = {
  path: string
  digest?: string
  media_type?: string
  size?: number
  scanned: boolean
  compressed: boolean
  unsupported_reason?: string
  entry_count: number
  whiteout_paths: string[]
  opaque_whiteout_paths: string[]
  suid_paths: string[]
  sgid_paths: string[]
  world_writable_paths: string[]
  secret_like_paths: string[]
  package_manager_paths: string[]
  nested_binary_paths: string[]
}

export type ContainerImageSecurityProfile = z.infer<typeof ContainerImageSecurityProfileDataSchema>

function normalizePath(value: string): string {
  return value.replace(/\\/g, '/').replace(/^\.?\//, '')
}

function readTarString(block: Buffer, start: number, length: number): string {
  return block
    .subarray(start, start + length)
    .toString('utf8')
    .replace(/\0.*$/s, '')
    .trim()
}

function readTarOctal(block: Buffer, start: number, length: number): number {
  const text = readTarString(block, start, length).replace(/[^0-7]/g, '')
  if (!text) return 0
  const value = Number.parseInt(text, 8)
  return Number.isFinite(value) ? value : 0
}

function parseTarMembers(data: Buffer, limit = MAX_TAR_MEMBERS): TarMember[] {
  const members: TarMember[] = []
  let offset = 0
  while (offset + 512 <= data.length && members.length < limit) {
    const block = data.subarray(offset, offset + 512)
    if (block.every((byte) => byte === 0)) break
    const name = readTarString(block, 0, 100)
    const prefix = readTarString(block, 345, 155)
    const rawPath = prefix ? `${prefix}/${name}` : name
    const memberPath = normalizePath(rawPath)
    const size = readTarOctal(block, 124, 12)
    const mode = readTarOctal(block, 100, 8)
    const typeflag = String.fromCharCode(block[156] || 0x30)
    const dataOffset = offset + 512
    const dataEnd = dataOffset + size
    if (!memberPath || dataEnd > data.length) break
    members.push({
      path: memberPath,
      size,
      mode,
      typeflag,
      dataOffset,
      data: data.subarray(dataOffset, dataEnd),
    })
    offset = dataOffset + Math.ceil(size / 512) * 512
  }
  return members
}

function parseJson<T>(member: TarMember | undefined): T | undefined {
  if (!member || member.size > 8 * 1024 * 1024) return undefined
  try {
    return JSON.parse(member.data.toString('utf8')) as T
  } catch {
    return undefined
  }
}

function memberMap(members: TarMember[]): Map<string, TarMember> {
  const map = new Map<string, TarMember>()
  for (const member of members) map.set(member.path, member)
  return map
}

function blobPathForDigest(digest?: string): string | undefined {
  if (!digest) return undefined
  const match = /^([A-Za-z0-9_+.-]+):([A-Fa-f0-9]+)$/.exec(digest)
  if (!match) return undefined
  return `blobs/${match[1]}/${match[2]}`
}

function isDockerSave(members: Map<string, TarMember>): boolean {
  return members.has('manifest.json')
}

function isOciLayout(members: Map<string, TarMember>): boolean {
  return members.has('oci-layout') && members.has('index.json')
}

function vector(value: string[] | string | null | undefined): string[] {
  if (Array.isArray(value)) return value
  if (typeof value === 'string') return [value]
  return []
}

function isRootUser(user?: string): boolean {
  const normalized = (user ?? '').trim()
  return (
    normalized === '' || normalized === '0' || normalized === 'root' || normalized.startsWith('0:')
  )
}

function envName(value: string): string {
  const idx = value.indexOf('=')
  return idx === -1 ? value : value.slice(0, idx)
}

function looksSecretName(name: string): boolean {
  return /(token|secret|passwd|password|apikey|api_key|credential|private[_-]?key|aws_|gcp_|azure_|github_)/i.test(
    name
  )
}

function looksSecretPath(entryPath: string): boolean {
  return /(?:^|\/)(?:\.ssh\/id_rsa|\.ssh\/id_dsa|\.aws\/credentials|\.docker\/config\.json|\.npmrc|\.pypirc|kubeconfig|id_ed25519|shadow|passwd-|\.env)(?:$|\/)/i.test(
    entryPath
  )
}

function looksPackageManagerPath(entryPath: string): boolean {
  return /(?:^|\/)(?:var\/lib\/dpkg\/status|lib\/apk\/db\/installed|var\/lib\/rpm|usr\/bin\/apt(?:-get)?|usr\/bin\/apk|usr\/bin\/yum|usr\/bin\/dnf|usr\/bin\/pip|usr\/local\/bin\/pip|usr\/bin\/npm|usr\/bin\/gem)(?:$|\/)/i.test(
    entryPath
  )
}

function looksNestedBinary(entryPath: string): boolean {
  return /\.(?:so|dll|exe|sys|ko|wasm|jar|class|dylib|a|o|obj|bc|ptx|cubin)$/i.test(entryPath)
}

function historyRisk(createdBy: string): string[] {
  const risks: string[] = []
  if (/(?:curl|wget)[^|;&]*(?:\||&&|;)\s*(?:sh|bash|python|perl)/i.test(createdBy)) {
    risks.push('download-and-execute')
  }
  if (/\bADD\s+https?:\/\//i.test(createdBy)) risks.push('remote-add')
  if (/\bchmod\s+(?:777|a\+w|ugo\+w)/i.test(createdBy)) risks.push('broad-file-permissions')
  if (/\b(?:apt-get|apt|apk|yum|dnf)\s+install\b/i.test(createdBy)) {
    risks.push('package-install-history')
  }
  if (/\b(?:npm|pip|gem)\s+install\b/i.test(createdBy))
    risks.push('language-package-install-history')
  return risks
}

function riskWeight(flag: string): number {
  switch (flag) {
    case 'root-user-default':
    case 'no-user-declared':
    case 'secret-like-env':
    case 'secret-like-path':
    case 'suid-files':
      return 20
    case 'download-and-execute-history':
    case 'remote-add-history':
    case 'world-writable-files':
      return 15
    case 'shell-entrypoint':
    case 'package-manager-traces':
    case 'package-install-history':
    case 'privileged-port-exposed':
      return 10
    default:
      return 5
  }
}

function detectFormat(data: Buffer, filename?: string): { format: string; detectedBy: string[] } {
  const members = parseTarMembers(data, 32)
  const paths = new Set(members.map((member) => member.path))
  if (paths.has('oci-layout') && paths.has('index.json')) {
    return { format: 'oci-image', detectedBy: ['tar layout', 'oci-layout', 'index.json'] }
  }
  if (paths.has('manifest.json')) {
    return { format: 'docker-image', detectedBy: ['tar layout', 'manifest.json'] }
  }
  if (data.length >= 262 && data.subarray(257, 262).toString('ascii') === 'ustar') {
    return { format: 'tar', detectedBy: ['tar ustar magic'] }
  }
  const lower = (filename ?? '').toLowerCase()
  if (lower.endsWith('.oci') || lower.endsWith('.oci.tar')) {
    return { format: 'oci-image', detectedBy: ['filename extension'] }
  }
  if (lower.endsWith('.docker') || lower.endsWith('.docker.tar') || lower.endsWith('image.tar')) {
    return { format: 'docker-image', detectedBy: ['filename extension'] }
  }
  return { format: 'unknown', detectedBy: ['unknown'] }
}

function layerBytes(
  layer: TarMember,
  ref: LayerReference
): { bytes?: Buffer; compressed: boolean; reason?: string } {
  const compressed =
    /\.t?gz$/i.test(layer.path) ||
    /gzip/i.test(ref.mediaType ?? '') ||
    layer.data.subarray(0, 2).equals(Buffer.from([0x1f, 0x8b]))
  if (!compressed) return { bytes: layer.data, compressed: false }
  try {
    return { bytes: zlib.gunzipSync(layer.data), compressed: true }
  } catch (error) {
    return {
      compressed: true,
      reason: `gzip layer could not be decompressed in bounded static mode: ${
        error instanceof Error ? error.message : String(error)
      }`,
    }
  }
}

function scanLayer(
  ref: LayerReference,
  members: Map<string, TarMember>,
  maxLayerBytes: number
): LayerScan {
  const layer = members.get(ref.path)
  if (!layer) {
    return {
      path: ref.path,
      digest: ref.digest,
      media_type: ref.mediaType,
      size: ref.size,
      scanned: false,
      compressed: false,
      unsupported_reason: 'layer blob not present in archive preview',
      entry_count: 0,
      whiteout_paths: [],
      opaque_whiteout_paths: [],
      suid_paths: [],
      sgid_paths: [],
      world_writable_paths: [],
      secret_like_paths: [],
      package_manager_paths: [],
      nested_binary_paths: [],
    }
  }
  if (layer.size > maxLayerBytes) {
    return {
      path: ref.path,
      digest: ref.digest,
      media_type: ref.mediaType,
      size: layer.size,
      scanned: false,
      compressed: /\.t?gz$/i.test(layer.path) || /gzip/i.test(ref.mediaType ?? ''),
      unsupported_reason: `layer exceeds max_layer_scan_bytes (${maxLayerBytes})`,
      entry_count: 0,
      whiteout_paths: [],
      opaque_whiteout_paths: [],
      suid_paths: [],
      sgid_paths: [],
      world_writable_paths: [],
      secret_like_paths: [],
      package_manager_paths: [],
      nested_binary_paths: [],
    }
  }

  const decoded = layerBytes(layer, ref)
  if (!decoded.bytes) {
    return {
      path: ref.path,
      digest: ref.digest,
      media_type: ref.mediaType,
      size: layer.size,
      scanned: false,
      compressed: decoded.compressed,
      unsupported_reason: decoded.reason,
      entry_count: 0,
      whiteout_paths: [],
      opaque_whiteout_paths: [],
      suid_paths: [],
      sgid_paths: [],
      world_writable_paths: [],
      secret_like_paths: [],
      package_manager_paths: [],
      nested_binary_paths: [],
    }
  }

  const entries = parseTarMembers(decoded.bytes, MAX_LAYER_ENTRIES)
  const whiteoutPaths: string[] = []
  const opaqueWhiteoutPaths: string[] = []
  const suidPaths: string[] = []
  const sgidPaths: string[] = []
  const worldWritablePaths: string[] = []
  const secretLikePaths: string[] = []
  const packageManagerPaths: string[] = []
  const nestedBinaryPaths: string[] = []
  for (const entry of entries) {
    const base = path.posix.basename(entry.path)
    if (base.startsWith('.wh.')) whiteoutPaths.push(entry.path)
    if (base === '.wh..wh..opq') opaqueWhiteoutPaths.push(entry.path)
    if ((entry.mode & 0o4000) !== 0) suidPaths.push(entry.path)
    if ((entry.mode & 0o2000) !== 0) sgidPaths.push(entry.path)
    if ((entry.mode & 0o002) !== 0 && entry.typeflag !== '5') worldWritablePaths.push(entry.path)
    if (looksSecretPath(entry.path)) secretLikePaths.push(entry.path)
    if (looksPackageManagerPath(entry.path)) packageManagerPaths.push(entry.path)
    if (looksNestedBinary(entry.path)) nestedBinaryPaths.push(entry.path)
  }

  return {
    path: ref.path,
    digest: ref.digest,
    media_type: ref.mediaType,
    size: layer.size,
    scanned: true,
    compressed: decoded.compressed,
    entry_count: entries.length,
    whiteout_paths: whiteoutPaths.slice(0, MAX_PREVIEW_ITEMS),
    opaque_whiteout_paths: opaqueWhiteoutPaths.slice(0, MAX_PREVIEW_ITEMS),
    suid_paths: suidPaths.slice(0, MAX_PREVIEW_ITEMS),
    sgid_paths: sgidPaths.slice(0, MAX_PREVIEW_ITEMS),
    world_writable_paths: worldWritablePaths.slice(0, MAX_PREVIEW_ITEMS),
    secret_like_paths: secretLikePaths.slice(0, MAX_PREVIEW_ITEMS),
    package_manager_paths: packageManagerPaths.slice(0, MAX_PREVIEW_ITEMS),
    nested_binary_paths: nestedBinaryPaths.slice(0, MAX_PREVIEW_ITEMS),
  }
}

function selectDockerImage(members: Map<string, TarMember>): {
  selected: Record<string, unknown>
  config?: ImageConfig
  configDigest?: string
  layers: LayerReference[]
} {
  const manifest = parseJson<DockerManifestEntry[]>(members.get('manifest.json')) ?? []
  const first = manifest[0] ?? {}
  const configPath = first.Config
  const config = parseJson<ImageConfig>(configPath ? members.get(configPath) : undefined)
  const configDigest = configPath
    ? crypto
        .createHash('sha256')
        .update(members.get(configPath)?.data ?? Buffer.alloc(0))
        .digest('hex')
    : undefined
  return {
    selected: {
      repo_tags: first.RepoTags ?? [],
      config_path: configPath ?? null,
      layer_count: first.Layers?.length ?? 0,
    },
    config,
    configDigest: configDigest ? `sha256:${configDigest}` : undefined,
    layers: (first.Layers ?? []).map((layerPath) => ({
      path: normalizePath(layerPath),
      mediaType: 'application/vnd.docker.image.rootfs.diff.tar',
      size: members.get(normalizePath(layerPath))?.size,
    })),
  }
}

function selectOciImage(members: Map<string, TarMember>): {
  selected: Record<string, unknown>
  config?: ImageConfig
  configDigest?: string
  layers: LayerReference[]
} {
  const index = parseJson<{ manifests?: OciDescriptor[] }>(members.get('index.json')) ?? {}
  const descriptor = index.manifests?.[0]
  const manifestPath = blobPathForDigest(descriptor?.digest)
  const manifest = parseJson<OciManifest>(manifestPath ? members.get(manifestPath) : undefined)
  const configPath = blobPathForDigest(manifest?.config?.digest)
  const config = parseJson<ImageConfig>(configPath ? members.get(configPath) : undefined)
  return {
    selected: {
      manifest_digest: descriptor?.digest ?? null,
      manifest_media_type: descriptor?.mediaType ?? null,
      annotations: descriptor?.annotations ?? {},
      platform: descriptor?.platform ?? {},
      config_path: configPath ?? null,
      layer_count: manifest?.layers?.length ?? 0,
    },
    config,
    configDigest: manifest?.config?.digest,
    layers: (manifest?.layers ?? []).flatMap((layer) => {
      const layerPath = blobPathForDigest(layer.digest)
      if (!layerPath) return []
      return [
        {
          path: layerPath,
          mediaType: layer.mediaType,
          digest: layer.digest,
          size: layer.size,
        },
      ]
    }),
  }
}

function runtimeConfig(config: ImageConfig | undefined) {
  const env = config?.config?.Env ?? []
  const secretEnv = env.map(envName).filter(looksSecretName)
  const entrypoint = vector(config?.config?.Entrypoint)
  const cmd = vector(config?.config?.Cmd)
  const shell = config?.config?.Shell ?? []
  const exposedPorts = Object.keys(config?.config?.ExposedPorts ?? {})
  return {
    user: config?.config?.User ?? '',
    root_user_default: isRootUser(config?.config?.User),
    no_user_declared: !config?.config?.User,
    env_count: env.length,
    secret_like_env_names: secretEnv.slice(0, MAX_PREVIEW_ITEMS),
    entrypoint,
    cmd,
    shell,
    shell_entrypoint: entrypoint.some((item) =>
      /(?:^|\/)(?:sh|bash|dash|ash|powershell|cmd)(?:\.exe)?$/i.test(item)
    ),
    exposed_ports: exposedPorts,
    privileged_ports: exposedPorts.filter((port) => {
      const value = Number.parseInt(port, 10)
      return Number.isFinite(value) && value > 0 && value < 1024
    }),
    working_dir: config?.config?.WorkingDir ?? '',
    labels: config?.config?.Labels ?? {},
    volumes: Object.keys(config?.config?.Volumes ?? {}),
    stop_signal: config?.config?.StopSignal ?? '',
  }
}

function summarizeHistory(config: ImageConfig | undefined) {
  const history = config?.history ?? []
  const risky: Array<{ index: number; created_by: string; risks: string[] }> = []
  history.forEach((entry, index) => {
    const createdBy = entry.created_by ?? ''
    const risks = historyRisk(createdBy)
    if (risks.length > 0) risky.push({ index, created_by: createdBy.slice(0, 240), risks })
  })
  return {
    entry_count: history.length,
    empty_layer_count: history.filter((entry) => entry.empty_layer).length,
    risky_instruction_count: risky.length,
    risky_instructions: risky.slice(0, MAX_PREVIEW_ITEMS),
  }
}

function summarizeLayers(layers: LayerReference[], scans: LayerScan[]) {
  return {
    layer_count: layers.length,
    scanned_layer_count: scans.filter((scan) => scan.scanned).length,
    skipped_layer_count: scans.filter((scan) => !scan.scanned).length,
    total_recorded_size: layers.reduce((sum, layer) => sum + (layer.size ?? 0), 0),
    entry_count: scans.reduce((sum, scan) => sum + scan.entry_count, 0),
    whiteout_paths: scans.flatMap((scan) => scan.whiteout_paths).slice(0, MAX_PREVIEW_ITEMS),
    opaque_whiteout_paths: scans
      .flatMap((scan) => scan.opaque_whiteout_paths)
      .slice(0, MAX_PREVIEW_ITEMS),
    suid_paths: scans.flatMap((scan) => scan.suid_paths).slice(0, MAX_PREVIEW_ITEMS),
    sgid_paths: scans.flatMap((scan) => scan.sgid_paths).slice(0, MAX_PREVIEW_ITEMS),
    world_writable_paths: scans
      .flatMap((scan) => scan.world_writable_paths)
      .slice(0, MAX_PREVIEW_ITEMS),
    secret_like_paths: scans.flatMap((scan) => scan.secret_like_paths).slice(0, MAX_PREVIEW_ITEMS),
    package_manager_paths: scans
      .flatMap((scan) => scan.package_manager_paths)
      .slice(0, MAX_PREVIEW_ITEMS),
    nested_binary_paths: scans
      .flatMap((scan) => scan.nested_binary_paths)
      .slice(0, MAX_PREVIEW_ITEMS),
    skipped_layers: scans
      .filter((scan) => !scan.scanned)
      .map((scan) => ({
        path: scan.path,
        reason: scan.unsupported_reason,
        size: scan.size,
      }))
      .slice(0, MAX_PREVIEW_ITEMS),
  }
}

function buildRiskFlags(args: {
  runtime: ReturnType<typeof runtimeConfig>
  layers: ReturnType<typeof summarizeLayers>
  history: ReturnType<typeof summarizeHistory>
}): string[] {
  const flags: string[] = []
  if (args.runtime.root_user_default) flags.push('root-user-default')
  if (args.runtime.no_user_declared) flags.push('no-user-declared')
  if (args.runtime.secret_like_env_names.length > 0) flags.push('secret-like-env')
  if (args.runtime.entrypoint.length > 0) flags.push('entrypoint-present')
  if (args.runtime.shell_entrypoint) flags.push('shell-entrypoint')
  if (args.runtime.privileged_ports.length > 0) flags.push('privileged-port-exposed')
  if (args.layers.suid_paths.length > 0) flags.push('suid-files')
  if (args.layers.sgid_paths.length > 0) flags.push('sgid-files')
  if (args.layers.world_writable_paths.length > 0) flags.push('world-writable-files')
  if (args.layers.secret_like_paths.length > 0) flags.push('secret-like-path')
  if (args.layers.package_manager_paths.length > 0) flags.push('package-manager-traces')
  if (args.layers.whiteout_paths.length > 0) flags.push('layer-whiteouts-present')
  if (
    args.history.risky_instructions.some((entry) => entry.risks.includes('download-and-execute'))
  ) {
    flags.push('download-and-execute-history')
  }
  if (args.history.risky_instructions.some((entry) => entry.risks.includes('remote-add'))) {
    flags.push('remote-add-history')
  }
  if (
    args.history.risky_instructions.some((entry) => entry.risks.includes('package-install-history'))
  ) {
    flags.push('package-install-history')
  }
  return Array.from(new Set(flags))
}

export function buildContainerImageSecurityProfileFromBuffer(
  data: Buffer,
  options: { filename?: string; sampleId?: string; maxLayerScanBytes?: number } = {}
): ContainerImageSecurityProfile {
  const detected = detectFormat(data, options.filename)
  const members = memberMap(parseTarMembers(data))
  const image =
    isOciLayout(members) || detected.format === 'oci-image'
      ? selectOciImage(members)
      : isDockerSave(members) || detected.format === 'docker-image'
        ? selectDockerImage(members)
        : { selected: {}, config: undefined, configDigest: undefined, layers: [] }
  const runtime = runtimeConfig(image.config)
  const layerScans = image.layers.map((layer) =>
    scanLayer(layer, members, options.maxLayerScanBytes ?? DEFAULT_MAX_LAYER_BYTES)
  )
  const layerSummary = summarizeLayers(image.layers, layerScans)
  const historySummary = summarizeHistory(image.config)
  const riskFlags = buildRiskFlags({
    runtime,
    layers: layerSummary,
    history: historySummary,
  })
  const riskScore = Math.min(
    100,
    riskFlags.reduce((sum, flag) => sum + riskWeight(flag), 0)
  )
  const unsupported =
    detected.format === 'unknown'
      ? 'Input did not look like a Docker save tar or OCI image layout in the bounded preview.'
      : image.layers.length === 0
        ? 'Image layout was detected, but no layer references were resolved from manifest/config metadata.'
        : undefined
  const recommendedNextTools = Array.from(
    new Set([
      'container.structure.analyze',
      'sbom.provenance.graph',
      'sbom.generate',
      'strings.extract',
      'analysis.evidence.graph',
      'report.generate',
    ])
  )

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    image_format: detected.format,
    detected_by: detected.detectedBy,
    sha256_preview: crypto.createHash('sha256').update(data).digest('hex'),
    selected_image: image.selected,
    config_digest: image.configDigest,
    platform: {
      os:
        image.config?.os ?? (image.selected['platform'] as Record<string, unknown> | undefined)?.os,
      architecture:
        image.config?.architecture ??
        (image.selected['platform'] as Record<string, unknown> | undefined)?.architecture,
      variant: image.config?.variant,
      rootfs_type: image.config?.rootfs?.type,
      diff_id_count: image.config?.rootfs?.diff_ids?.length ?? 0,
    },
    runtime_config: runtime,
    layer_summary: {
      ...layerSummary,
      layers: layerScans,
    },
    history_summary: historySummary,
    risk_flags: riskFlags,
    risk_score: riskScore,
    policy: {
      passive: true,
      no_registry_network: true,
      no_docker_daemon: true,
      no_layer_extract: true,
      no_mount: true,
      no_install: true,
      no_entrypoint_run: true,
      no_mutation: true,
    },
    evidence_summary: {
      schema: 'rikune.container_image_security_profile.evidence.v1',
      source_tool: TOOL_NAME,
      artifact_type: ARTIFACT_TYPE,
      image_format: detected.format,
      config_digest: image.configDigest ?? null,
      layer_count: image.layers.length,
      scanned_layer_count: layerSummary.scanned_layer_count,
      risk_flags: riskFlags,
      root_user_default: runtime.root_user_default,
      secret_like_env_count: runtime.secret_like_env_names.length,
      secret_like_path_count: layerSummary.secret_like_paths.length,
      static_only: true,
    },
    workflow_handoff: {
      schema: 'rikune.container_image_security_profile.workflow_handoff.v1',
      source_tool: TOOL_NAME,
      artifact_type: ARTIFACT_TYPE,
      handoff_mode: 'container_image_to_supply_chain_and_static_evidence',
      recommended_next_tools: recommendedNextTools,
      routing: [
        {
          goal: 'container-runtime-default-review',
          priority:
            runtime.root_user_default || runtime.secret_like_env_names.length > 0
              ? 'high'
              : 'normal',
          next_tools: ['artifact.read', 'analysis.evidence.graph', 'report.generate'],
          required_evidence: ['runtime_config', 'risk_flags'],
        },
        {
          goal: 'supply-chain-package-evidence',
          priority: layerSummary.package_manager_paths.length > 0 ? 'high' : 'normal',
          next_tools: ['sbom.provenance.graph', 'sbom.generate', 'analysis.evidence.graph'],
          required_evidence: ['layer_summary', 'history_summary'],
        },
        {
          goal: 'nested-binary-routing',
          priority: layerSummary.nested_binary_paths.length > 0 ? 'high' : 'normal',
          next_tools: ['container.structure.analyze', 'strings.extract'],
          required_evidence: ['nested_binary_paths'],
        },
      ],
      dynamic_boundary: {
        registry_contacted_by_tool: false,
        docker_daemon_contacted_by_tool: false,
        image_loaded_by_tool: false,
        layer_extracted_by_tool: false,
        filesystem_mounted_by_tool: false,
        scripts_executed_by_tool: false,
        package_installed_by_tool: false,
        package_install_performed: false,
        entrypoint_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
      },
    },
    quality_gates: {
      schema: 'rikune.container_image_security_profile.quality_gates.v1',
      passive_static_inventory: true,
      bounded_archive_preview: true,
      bounded_layer_header_scan: true,
      scanned_layer_count: layerSummary.scanned_layer_count,
      skipped_layer_count: layerSummary.skipped_layer_count,
      registry_contacted_by_tool: false,
      docker_daemon_contacted_by_tool: false,
      image_loaded_by_tool: false,
      layer_extracted_by_tool: false,
      filesystem_mounted_by_tool: false,
      scripts_executed_by_tool: false,
      package_installed_by_tool: false,
      package_install_performed: false,
      entrypoint_executed_by_tool: false,
    },
    unsupported_detail: unsupported,
    summary: `Passive ${detected.format} security profile produced ${riskFlags.length} risk flag(s), scanned ${layerSummary.scanned_layer_count}/${image.layers.length} layer(s), and computed risk score ${riskScore}.`,
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review root user, entrypoint, exposed port, and secret-like environment findings before runtime testing.',
      'Use SBOM and provenance workflows on package manager evidence without installing packages.',
      'Keep dynamic validation behind explicit runtime opt-in; do not run entrypoints during static triage.',
    ],
  }
}

async function readPreview(
  filePath: string,
  maxReadBytes: number
): Promise<{ data: Buffer; size: number }> {
  const stat = await fs.stat(filePath)
  const handle = await fs.open(filePath, 'r')
  try {
    const length = Math.min(stat.size, maxReadBytes)
    const data = Buffer.alloc(length)
    await handle.read(data, 0, length, 0)
    return { data, size: stat.size }
  } finally {
    await handle.close()
  }
}

export function createContainerImageSecurityProfileHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (
    args: z.infer<typeof ContainerImageSecurityProfileInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = ContainerImageSecurityProfileInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data } = await readPreview(samplePath, input.max_read_bytes)
      const profile = buildContainerImageSecurityProfileFromBuffer(data, {
        filename: path.basename(samplePath),
        sampleId: input.sample_id,
        maxLayerScanBytes: input.max_layer_scan_bytes,
      })

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
        try {
          const artifact = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            ARTIFACT_TYPE,
            'container-image-security-profile',
            profile,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: return profile even when artifact persistence is unavailable.
        }
      }

      return {
        ok: true,
        data: profile,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${error instanceof Error ? error.message : String(error)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
