/**
 * jvm.structure.analyze — passive JVM archive/class inventory.
 *
 * This tool does not invoke Java, run bytecode, or call a decompiler. It reads
 * bounded previews and returns manifest/class/dependency/decompile-plan metadata.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'jvm.structure.analyze'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024
export const JVM_STRUCTURE_ARTIFACT_TYPE = 'jvm_structure'
export const JVM_STRUCTURE_SAFETY = [
  'passive',
  'bounded-input',
  'no_live_sample_by_default',
  'no_runtime_start',
  'no_decompiler_launch',
  'no_network_by_default',
  'no_mutation',
]
export const JVM_STRUCTURE_EVIDENCE = [
  'manifest',
  'package-metadata',
  'structure',
  'classes',
  'dependency-hints',
  'nested-binaries',
  'workflow',
  'provenance',
]
export const JVM_STRUCTURE_FOLLOW_UP_TOOLS = [
  'metadata.extract',
  'strings.extract',
  'sbom.generate',
  'analysis.evidence.graph',
  'artifact.read',
  'report.generate',
]
export const JVM_STRUCTURE_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noRuntimeStart: true,
  noDecompilerLaunch: true,
  notes: [
    'jvm.structure.analyze reads bounded local bytes and never starts a JVM.',
    'Decompiler selection is emitted as a plan-only handoff; no Java bytecode is executed by this tool.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noRuntimeStart: true
  noDecompilerLaunch: true
}

const JvmPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_runtime_start: z.literal(true),
  no_decompiler_launch: z.literal(true),
})

const JvmStructureDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  manifest: z.record(z.string(), z.string()).optional(),
  archive_members: z.array(z.string()),
  class_files: z.array(z.string()),
  packages: z.array(z.string()),
  dependency_hints: z.array(z.string()),
  nested_archive_candidates: z.array(z.string()),
  decompile_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    notes: z.array(z.string()),
  }),
  policy: JvmPolicySchema,
  unsupported_detail: z.string().optional(),
  evidence_summary: z.record(z.string(), z.any()),
  workflow_handoff: z.record(z.string(), z.any()),
  quality_gates: z.record(z.string(), z.any()),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const JvmStructureAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive JVM inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist JVM inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const JvmStructureAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: JvmStructureDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const jvmStructureAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory JVM artifacts (JAR, CLASS, WAR, AAR, JMOD, Kotlin metadata). Does not execute bytecode or launch a decompiler.',
  inputSchema: JvmStructureAnalyzeInputSchema,
  outputSchema: JvmStructureAnalyzeOutputSchema,
  aspects: {
    formats: ['jar', 'class', 'war', 'aar', 'jmod', 'kotlin-metadata'],
    platforms: ['jvm', 'android'],
    execution: ['static', 'triage', 'decompilation'],
    safety: JVM_STRUCTURE_SAFETY,
    capabilities: [
      'manifest',
      'classes',
      'dependencies',
      'dependency-hints',
      'nested-archive-routing',
      'decompile-plan',
      'metadata-only-handoff',
      'workflow-handoff',
      'routing',
    ],
    evidence: JVM_STRUCTURE_EVIDENCE,
  },
  artifacts: [
    {
      type: JVM_STRUCTURE_ARTIFACT_TYPE,
      description: 'Passive JVM manifest, class, dependency, and decompile-plan inventory',
    },
  ],
  evidence: [
    {
      category: 'manifest',
      artifactTypes: [JVM_STRUCTURE_ARTIFACT_TYPE],
    },
    {
      category: 'package-metadata',
      artifactTypes: [JVM_STRUCTURE_ARTIFACT_TYPE],
    },
    {
      category: 'structure',
      artifactTypes: [JVM_STRUCTURE_ARTIFACT_TYPE],
    },
    {
      category: 'classes',
      artifactTypes: [JVM_STRUCTURE_ARTIFACT_TYPE],
    },
    {
      category: 'dependency-hints',
      artifactTypes: [JVM_STRUCTURE_ARTIFACT_TYPE],
    },
    {
      category: 'nested-binaries',
      artifactTypes: [JVM_STRUCTURE_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [JVM_STRUCTURE_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [JVM_STRUCTURE_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'jvm.passive-structure-handoff',
      title: 'JVM passive structure inventory handoff',
      description:
        'Profile JAR, CLASS, WAR, AAR, JMOD, and Kotlin metadata inputs, then hand manifest, class, dependency, and nested archive route facts to evidence graph, SBOM, artifact, and reporting workflows without starting a JVM or decompiler.',
      startsWith: [TOOL_NAME],
      nextTools: JVM_STRUCTURE_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [JVM_STRUCTURE_ARTIFACT_TYPE],
      evidence: JVM_STRUCTURE_EVIDENCE,
      safety: JVM_STRUCTURE_SAFETY,
    },
  ],
  runtimePolicy: JVM_STRUCTURE_RUNTIME_POLICY,
}

export type JvmStructureInventory = z.infer<typeof JvmStructureDataSchema>

type ZipEntry = {
  name: string
  compressionMethod: number
  compressedSize: number
  content?: Buffer
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function detectJvmFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  if (
    data.length >= 4 &&
    data[0] === 0xca &&
    data[1] === 0xfe &&
    data[2] === 0xba &&
    data[3] === 0xbe
  ) {
    return { format: 'class', detectedBy: ['class magic'] }
  }
  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) {
    return {
      format: ext || 'zip',
      detectedBy: ext ? ['zip magic', 'filename extension'] : ['zip magic'],
    }
  }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function parseZipLocalEntries(data: Buffer): ZipEntry[] {
  const entries: ZipEntry[] = []
  let offset = 0

  while (offset + 30 <= data.length && entries.length < 500) {
    if (data.readUInt32LE(offset) !== 0x04034b50) {
      offset += 1
      continue
    }

    const compressionMethod = data.readUInt16LE(offset + 8)
    const compressedSize = data.readUInt32LE(offset + 18)
    const nameLength = data.readUInt16LE(offset + 26)
    const extraLength = data.readUInt16LE(offset + 28)
    const nameStart = offset + 30
    const nameEnd = nameStart + nameLength
    if (nameEnd > data.length) break

    const name = data.subarray(nameStart, nameEnd).toString('utf8')
    const contentStart = nameEnd + extraLength
    const contentEnd = contentStart + compressedSize
    const content =
      compressionMethod === 0 && contentEnd <= data.length
        ? data.subarray(contentStart, contentEnd)
        : undefined
    entries.push({ name, compressionMethod, compressedSize, content })

    const nextOffset = contentEnd > offset ? contentEnd : contentStart
    offset = nextOffset <= offset ? offset + 1 : nextOffset
  }

  return entries
}

function parseManifest(content?: Buffer): Record<string, string> | undefined {
  if (!content) return undefined
  const manifest: Record<string, string> = {}
  for (const line of content.toString('utf8').split(/\r?\n/)) {
    const index = line.indexOf(':')
    if (index <= 0) continue
    const key = line.slice(0, index).trim()
    const value = line.slice(index + 1).trim()
    if (key) manifest[key] = value
  }
  return Object.keys(manifest).length > 0 ? manifest : undefined
}

function packageFromClassPath(classPath: string): string | null {
  const normalized = classPath.replace(/\\/g, '/')
  if (!normalized.endsWith('.class')) return null
  const dirname = normalized.slice(0, -'.class'.length).split('/').slice(0, -1)
  if (dirname.length === 0) return null
  return dirname.join('.')
}

function dependencyHints(
  entries: ZipEntry[],
  manifest: Record<string, string> | undefined
): string[] {
  const hints = new Set<string>()
  const classPath = manifest?.['Class-Path']
  if (classPath) {
    for (const item of classPath.split(/\s+/).filter(Boolean)) hints.add(item)
  }
  for (const entry of entries) {
    const lower = entry.name.toLowerCase()
    if (lower.startsWith('lib/') || lower.includes('/lib/')) hints.add(entry.name)
    if (lower.endsWith('.pom') || lower.endsWith('pom.xml')) hints.add(entry.name)
    if (lower.includes('kotlin_module')) hints.add(entry.name)
  }
  return Array.from(hints).slice(0, 100)
}

function buildJvmEvidenceSummary(args: {
  format: string
  detectedBy: string[]
  size: number
  previewBytes: number
  manifest?: Record<string, string>
  classFiles: string[]
  packages: string[]
  dependencyHints: string[]
  nestedArchiveCandidates: string[]
}) {
  return {
    schema: 'rikune.jvm_structure.evidence_summary.v1',
    artifact_type: JVM_STRUCTURE_ARTIFACT_TYPE,
    format: args.format,
    detected_by: args.detectedBy,
    size: args.size,
    preview_bytes: args.previewBytes,
    preview_limited: args.size > args.previewBytes,
    manifest_present: Boolean(args.manifest),
    main_class: args.manifest?.['Main-Class'] ?? null,
    class_file_count: args.classFiles.length,
    package_count: args.packages.length,
    dependency_hint_count: args.dependencyHints.length,
    nested_archive_count: args.nestedArchiveCandidates.length,
    package_preview: args.packages.slice(0, 12),
    dependency_hint_preview: args.dependencyHints.slice(0, 12),
    nested_archive_preview: args.nestedArchiveCandidates.slice(0, 12),
    passive_inventory_only: true,
  }
}

function buildJvmWorkflowHandoff(args: {
  format: string
  manifest?: Record<string, string>
  classFiles: string[]
  packages: string[]
  dependencyHints: string[]
  nestedArchiveCandidates: string[]
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.jvm_structure.workflow_handoff.v1',
    artifact_contract: {
      produced_artifact_type: JVM_STRUCTURE_ARTIFACT_TYPE,
      producer_tool: TOOL_NAME,
      payload: 'passive JVM manifest, class, dependency, nested archive, and route facts',
    },
    routing: {
      starts_with: TOOL_NAME,
      recommended_next_tools: args.recommendedNextTools,
      route_candidates: [
        ...(args.classFiles.length > 0
          ? [
              {
                tool: 'strings.extract',
                reason: 'Class files can expose strings, package names, and embedded indicators.',
                evidence: ['class_files'],
              },
            ]
          : []),
        ...(args.dependencyHints.length > 0 || args.manifest?.['Class-Path']
          ? [
              {
                tool: 'sbom.generate',
                reason: 'Manifest Class-Path and package metadata can seed dependency provenance.',
                evidence: ['manifest', 'dependency_hints'],
              },
            ]
          : []),
        ...(args.nestedArchiveCandidates.length > 0
          ? [
              {
                tool: TOOL_NAME,
                reason:
                  'Nested JVM archives should be analyzed as independent passive inventory inputs.',
                evidence: ['nested_archive_candidates'],
              },
            ]
          : []),
        {
          tool: 'analysis.evidence.graph',
          reason: 'Preserve JVM route facts and provenance before cross-artifact reporting.',
          evidence: ['manifest', 'classes', 'dependency_hints', 'workflow'],
        },
      ],
    },
    dynamic_boundary: {
      sample_executed_by_tool: false,
      jvm_started_by_tool: false,
      decompiler_launched_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
    package_profile: {
      format: args.format,
      main_class: args.manifest?.['Main-Class'] ?? null,
      packages: args.packages.slice(0, 20),
      dependency_hints: args.dependencyHints.slice(0, 20),
      nested_archive_candidates: args.nestedArchiveCandidates.slice(0, 20),
    },
  }
}

function buildJvmQualityGates(args: {
  format: string
  size: number
  previewBytes: number
  manifest?: Record<string, string>
  classFiles: string[]
  dependencyHints: string[]
  nestedArchiveCandidates: string[]
}) {
  return {
    schema: 'rikune.jvm_structure.quality_gates.v1',
    passive_inventory_only: true,
    sample_executed_by_tool: false,
    jvm_started_by_tool: false,
    decompiler_launched_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
    manifest_present: Boolean(args.manifest),
    class_inventory_present: args.classFiles.length > 0,
    dependency_hints_present: args.dependencyHints.length > 0,
    nested_archive_candidates_present: args.nestedArchiveCandidates.length > 0,
    preview_limited: args.size > args.previewBytes,
    standalone_class_limited_parse: args.format === 'class',
  }
}

export function buildJvmStructureFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): JvmStructureInventory {
  const { format, detectedBy } = detectJvmFormat(data, options.filename)
  const entries = parseZipLocalEntries(data)
  const members = entries.map((entry) => entry.name)
  const manifest = parseManifest(
    entries.find((entry) => entry.name.toUpperCase() === 'META-INF/MANIFEST.MF')?.content
  )
  const classFiles =
    format === 'class' && entries.length === 0
      ? [options.filename ?? 'sample.class']
      : members.filter((member) => member.endsWith('.class'))
  const packages = Array.from(
    new Set(classFiles.map(packageFromClassPath).filter((pkg): pkg is string => Boolean(pkg)))
  ).slice(0, 100)
  const nestedArchives = members.filter((member) => /\.(?:jar|war|aar|jmod|zip)$/i.test(member))
  const deps = dependencyHints(entries, manifest)
  const size = options.size ?? data.length
  const archiveMembers = members.slice(0, 300)
  const classFilesLimited = classFiles.slice(0, 300)
  const nestedArchiveCandidates = nestedArchives.slice(0, 100)
  const recommendedNextTools = Array.from(
    new Set([
      ...JVM_STRUCTURE_FOLLOW_UP_TOOLS,
      ...nestedArchives.map(() => 'jvm.structure.analyze'),
    ])
  )
  const evidenceSummary = buildJvmEvidenceSummary({
    format,
    detectedBy,
    size,
    previewBytes: data.length,
    manifest,
    classFiles: classFilesLimited,
    packages,
    dependencyHints: deps,
    nestedArchiveCandidates,
  })
  const workflowHandoff = buildJvmWorkflowHandoff({
    format,
    manifest,
    classFiles: classFilesLimited,
    packages,
    dependencyHints: deps,
    nestedArchiveCandidates,
    recommendedNextTools,
  })
  const qualityGates = buildJvmQualityGates({
    format,
    size,
    previewBytes: data.length,
    manifest,
    classFiles: classFilesLimited,
    dependencyHints: deps,
    nestedArchiveCandidates,
  })

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format,
    detected_by: detectedBy,
    size,
    manifest,
    archive_members: archiveMembers,
    class_files: classFilesLimited,
    packages,
    dependency_hints: deps,
    nested_archive_candidates: nestedArchiveCandidates,
    decompile_plan: {
      status: 'plan_only',
      recommended_tools: JVM_STRUCTURE_FOLLOW_UP_TOOLS,
      notes: [
        'Use an explicit Java decompiler plugin or external tool after reviewing this static inventory.',
        'This tool does not execute JVM bytecode or invoke a decompiler.',
      ],
    },
    policy: {
      passive: true,
      no_execute: true,
      no_runtime_start: true,
      no_decompiler_launch: true,
    },
    unsupported_detail:
      format === 'class'
        ? 'Standalone class parsing is limited to magic detection in this lightweight inventory.'
        : undefined,
    evidence_summary: evidenceSummary,
    workflow_handoff: workflowHandoff,
    quality_gates: qualityGates,
    summary: `Passive JVM inventory detected ${format} with ${classFiles.length} class file(s), ${packages.length} package(s), and ${deps.length} dependency hint(s).`,
    recommended_next_tools: recommendedNextTools,
    next_actions: [
      'Review manifest and dependency hints before choosing a decompiler.',
      'Ingest nested archive candidates separately if they need independent analysis.',
      'Use analysis.evidence.graph to preserve JVM route facts and provenance before reporting.',
      'Do not execute JVM bytecode during static triage.',
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

export function createJvmStructureAnalyzeHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof JvmStructureAnalyzeInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = JvmStructureAnalyzeInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildJvmStructureFromBuffer(data, {
        filename: path.basename(samplePath),
        sampleId: input.sample_id,
        size,
      })

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
        try {
          const artifact = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'jvm_structure',
            'jvm-structure',
            inventory,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: inventory can still be returned without persistence.
        }
      }

      return {
        ok: true,
        data: inventory,
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
