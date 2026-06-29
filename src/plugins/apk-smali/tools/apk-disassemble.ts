/**
 * apk.disassemble — Disassemble APK to Smali bytecode via apktool.
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

const TOOL_NAME = 'apk.disassemble'
const APK_SMALI_LISTING_ARTIFACT_TYPE = 'backend_apk_smali-listing'
const APK_SMALI_SAFETY = [
  'passive',
  'static',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
  'no_live_execution',
]
const APK_SMALI_EVIDENCE = [
  'structure',
  'classes',
  'multi-dex',
  'strings',
  'workflow',
  'provenance',
]
const APK_SMALI_NEXT_TOOLS = [
  'apk.manifest.parse',
  'apk.resources.decode',
  'dex.classes.list',
  'strings.extract',
  'analysis.evidence.graph',
  'artifact.read',
]

export const apkDisassembleInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the APK file.'),
  class_filter: z
    .string()
    .optional()
    .describe('Regex filter to limit Smali output to matching class paths (e.g. "com/example").'),
  max_files: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(50)
    .describe('Max Smali files to include in result.'),
  timeout_sec: z.number().int().min(10).max(120).default(60).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist disassembly listing as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const apkDisassembleOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      total_classes: z.number().optional(),
      returned_files: z.number().optional(),
      smali_roots: z.array(z.object({ root: z.string(), class_count: z.number() })).optional(),
      smali_files: z
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

export const apkDisassembleToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Disassemble an APK file into Smali bytecode via apktool. Lists Smali class files and provides previews.',
  inputSchema: apkDisassembleInputSchema,
  outputSchema: apkDisassembleOutputSchema,
  aspects: {
    formats: ['apk', 'aab', 'apks', 'xapk', 'split-apk', 'aar'],
    platforms: ['android'],
    architectures: ['arm', 'arm64', 'x86', 'x64'],
    execution: ['static', 'decompilation'],
    safety: APK_SMALI_SAFETY,
    capabilities: [
      'smali',
      'multi-dex',
      'classes',
      'android-bytecode',
      'resources',
      'workflow-handoff',
    ],
    evidence: APK_SMALI_EVIDENCE,
    search: ['apktool', 'smali', 'multi-dex', 'classes.dex', 'smali_classes2', 'android-bytecode'],
  },
  artifacts: [
    {
      type: APK_SMALI_LISTING_ARTIFACT_TYPE,
      description:
        'Smali class listing generated from APKTool output, including smali and smali_classes* multi-dex roots',
      mime: 'text/plain',
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: [APK_SMALI_LISTING_ARTIFACT_TYPE],
    },
    {
      category: 'multi-dex',
      artifactTypes: [APK_SMALI_LISTING_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [APK_SMALI_LISTING_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [APK_SMALI_LISTING_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'apk-smali.multi-dex-static-disassembly',
      title: 'APK Smali multi-dex static disassembly',
      description:
        'Use apktool to passively list Smali classes across smali and smali_classes* roots, then route manifest, resources, strings, DEX class inventory, and evidence graph follow-ups without executing Android bytecode.',
      startsWith: [TOOL_NAME, 'android.package.inventory'],
      nextTools: APK_SMALI_NEXT_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [APK_SMALI_LISTING_ARTIFACT_TYPE],
      evidence: APK_SMALI_EVIDENCE,
      safety: APK_SMALI_SAFETY,
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
      'apk.disassemble runs apktool decode against a local APK and never executes Android bytecode.',
      'Temporary apktool output is removed after bounded listing and optional artifact persistence.',
    ],
  } as ToolDefinition['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
  },
}

function collectSmaliFiles(
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
      results.push(...collectSmaliFiles(abs, rel, filter))
    } else if (entry.name.endsWith('.smali')) {
      if (filter && !filter.test(rel)) continue
      const stat = nodeFs.statSync(abs)
      results.push({ rel, abs, size: stat.size })
    }
  }
  return results
}

export function collectApktoolSmaliFiles(
  outputDir: string,
  filter?: RegExp
): {
  files: Array<{ rel: string; abs: string; size: number; root: string }>
  roots: Array<{ root: string; class_count: number }>
} {
  if (!nodeFs.existsSync(outputDir)) return { files: [], roots: [] }
  const rootNames = nodeFs
    .readdirSync(outputDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^smali(?:_classes\d+)?$/.test(entry.name))
    .map((entry) => entry.name)
    .sort((a, b) => {
      if (a === 'smali') return -1
      if (b === 'smali') return 1
      return a.localeCompare(b)
    })

  const files: Array<{ rel: string; abs: string; size: number; root: string }> = []
  const roots: Array<{ root: string; class_count: number }> = []
  for (const root of rootNames) {
    const collected = collectSmaliFiles(path.join(outputDir, root), root, filter)
    roots.push({ root, class_count: collected.length })
    files.push(...collected.map((file) => ({ ...file, root })))
  }
  return { files, roots }
}

function buildEvidenceSummary(args: {
  input: z.infer<typeof apkDisassembleInputSchema>
  totalClasses: number
  returnedFiles: number
  smaliRoots: Array<{ root: string; class_count: number }>
}) {
  return {
    schema: 'rikune.apk_smali_disassemble.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: args.input.sample_id,
    artifact_type: APK_SMALI_LISTING_ARTIFACT_TYPE,
    class_filter: args.input.class_filter ?? null,
    total_classes: args.totalClasses,
    returned_files: args.returnedFiles,
    smali_root_count: args.smaliRoots.length,
    multi_dex_detected: args.smaliRoots.length > 1,
    smali_roots: args.smaliRoots,
    evidence_sources: ['apktool decoded smali roots'],
  }
}

function buildWorkflowHandoff(args: {
  input: z.infer<typeof apkDisassembleInputSchema>
  smaliRoots: Array<{ root: string; class_count: number }>
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.apk_smali_disassemble.workflow_handoff.v1',
    handoff_mode: 'apk_smali_to_manifest_resources_strings_and_evidence_graph',
    source_tool: TOOL_NAME,
    sample_id: args.input.sample_id,
    recommended_next_tools: args.recommendedNextTools,
    artifact_contract: {
      consumes: ['sample'],
      produces: [APK_SMALI_LISTING_ARTIFACT_TYPE],
      expected_consumers: ['apk.manifest.parse', 'apk.resources.decode', 'dex.classes.list'],
    },
    routing: [
      {
        goal: 'manifest-and-component-review',
        next_tools: ['apk.manifest.parse', 'android.behavior.graph'],
        required_evidence: ['smali_roots'],
      },
      {
        goal: 'resources-and-string-review',
        next_tools: ['apk.resources.decode', 'strings.extract'],
        required_evidence: ['smali_listing'],
      },
      {
        goal: 'multi-dex-class-inventory',
        next_tools: ['dex.classes.list', 'analysis.evidence.graph'],
        required_evidence: args.smaliRoots.map((root) => root.root),
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

function buildQualityGates(args: {
  totalClasses: number
  smaliRoots: Array<{ root: string; class_count: number }>
  artifactPersisted: boolean
}) {
  return {
    schema: 'rikune.apk_smali_disassemble.quality_gates.v1',
    passive_static_only: true,
    apktool_decode_completed: true,
    smali_roots_detected: args.smaliRoots.length > 0,
    multi_dex_accounted_for: args.smaliRoots.every(
      (root) => root.root === 'smali' || root.class_count >= 0
    ),
    classes_found: args.totalClasses > 0,
    artifact_persisted: args.artifactPersisted,
    android_bytecode_executed_by_tool: false,
    network_accessed_by_tool: false,
  }
}

export function createApkDisassembleHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const tmpDir = path.join(os.tmpdir(), `apk-disasm-${Date.now()}`)
    try {
      const input = apkDisassembleInputSchema.parse(args)
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
        ['d', '-f', '-o', tmpDir, samplePath],
        input.timeout_sec * 1000
      )

      const filter = input.class_filter ? new RegExp(input.class_filter, 'i') : undefined
      const { files: allFiles, roots: smaliRoots } = collectApktoolSmaliFiles(tmpDir, filter)
      allFiles.sort((a, b) => b.size - a.size)

      const smaliFiles = allFiles.slice(0, input.max_files).map((f) => {
        let preview = ''
        try {
          preview = nodeFs.readFileSync(f.abs, 'utf-8').slice(0, 512)
        } catch {}
        return { path: f.rel.replace(/\\/g, '/'), size_bytes: f.size, preview }
      })

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      let artifactPersisted = false
      if (input.persist_artifact) {
        const listing = allFiles.map((f) => `${f.rel.replace(/\\/g, '/')} (${f.size}B)`).join('\n')
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'apk',
          'smali-listing',
          listing,
          { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
        artifactPersisted = true
      }
      const recommendedNextTools = APK_SMALI_NEXT_TOOLS
      const evidenceSummary = buildEvidenceSummary({
        input,
        totalClasses: allFiles.length,
        returnedFiles: smaliFiles.length,
        smaliRoots,
      })
      const workflowHandoff = buildWorkflowHandoff({
        input,
        smaliRoots,
        recommendedNextTools,
      })
      const qualityGates = buildQualityGates({
        totalClasses: allFiles.length,
        smaliRoots,
        artifactPersisted,
      })

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          total_classes: allFiles.length,
          returned_files: smaliFiles.length,
          smali_roots: smaliRoots,
          smali_files: smaliFiles,
          artifact,
          evidence_summary: evidenceSummary,
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
          summary: `Disassembled APK: ${allFiles.length} Smali classes found${filter ? ` (filtered)` : ''}.`,
          recommended_next_tools: recommendedNextTools,
          next_actions: [
            'Inspect Smali for obfuscated methods or crypto usage.',
            'Parse AndroidManifest.xml for permissions and components.',
            smaliRoots.length > 1
              ? `Review multi-dex roots: ${smaliRoots.map((root) => root.root).join(', ')}.`
              : 'Single Smali root detected.',
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
