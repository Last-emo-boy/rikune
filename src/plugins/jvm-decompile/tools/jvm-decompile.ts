/**
 * jvm.decompile — Decompile JVM bytecode (.class/.jar) to Java source via CFR.
 *
 * Uses CFR (Class File Reader), a single-JAR Java decompiler, to recover Java
 * source from compiled .class files, .jar archives, .war, .aar, and .jmod
 * containers. Requires Java 8+ and the CFR jar (CFR_JAR env var). Passive and
 * read-only — CFR decompiles without executing the bytecode.
 */

import { z } from 'zod'
import type {
  WorkerResult,
  ToolDefinition,
  ToolArgs,
  ArtifactRef,
  PluginToolDeps,
} from '../../sdk.js'
import {
  ArtifactRefSchema,
  SharedMetricsSchema,
  executeCommand,
  normalizeError,
  persistBackendArtifact,
  buildMetrics,
  resolveSampleFile,
} from '../../docker-shared.js'

const TOOL_NAME = 'jvm.decompile'
const TOOL_VERSION = '0.1.0'
const ARTIFACT_TYPE = 'jvm_decompiled_source'
const RECOMMENDED_NEXT_TOOLS = [
  'jvm.structure.analyze',
  'strings.extract',
  'artifact.read',
  'workflow.search',
]

const SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]

export const jvmDecompileInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier (sha256:<hex>) of a .class/.jar file.'),
  class_filter: z
    .string()
    .optional()
    .describe(
      'Substring filter for class names to decompile (e.g. "com.example.Main"). ' +
        'When set, only matching classes are returned inline.'
    ),
  silent: z
    .boolean()
    .optional()
    .default(true)
    .describe('Suppress CFR informational stderr (progress/corruption warnings).'),
  comments: z
    .boolean()
    .optional()
    .default(false)
    .describe('Include CFR cor/etc. comments in the output source.'),
  max_output_chars: z
    .number()
    .int()
    .min(1024)
    .max(2_000_000)
    .optional()
    .default(200_000)
    .describe('Maximum decompiled source characters to return inline.'),
  timeout_sec: z
    .number()
    .int()
    .min(5)
    .max(300)
    .optional()
    .default(90)
    .describe('CFR decompilation timeout in seconds.'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist the decompiled source as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const jvmDecompileOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required', 'no_classes', 'decompile_failed']),
      backend: z
        .object({
          java_available: z.boolean(),
          cfr_jar: z.string().nullable().optional(),
        })
        .passthrough()
        .optional(),
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      class_count: z.number().int().nonnegative().optional(),
      class_filter: z.string().nullable().optional(),
      source: z.string().nullable().optional(),
      source_truncated: z.boolean().optional(),
      truncated_classes: z.array(z.string()).optional(),
      summary: z.string().optional(),
      recommended_next_tools: z.array(z.string()).optional(),
      artifact: ArtifactRefSchema.nullable().optional(),
    })
    .passthrough()
    .optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  errors: z.array(z.string()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

// CFR packs each decompiled class in a "/* Decompiled with CFR" header
// followed by "package ...;" / "class ...". We split on the CFR class marker
// to count and filter individual classes.
interface ParsedClass {
  name: string
  source: string
}

function splitCfrClasses(raw: string): ParsedClass[] {
  // CFR emits "/* Decompiled with CFR <ver>.\n */" headers before each class.
  // Split on the closing "*/\n" that precedes a "package"/"import"/class decl.
  const blocks: string[] = []
  const parts = raw.split(/(?=\/\*\s*\n \* Decompiled with CFR)/)
  for (const part of parts) {
    const trimmed = part.trim()
    if (!trimmed) continue
    blocks.push(trimmed)
  }
  const classes: ParsedClass[] = []
  for (const block of blocks) {
    // Extract class name: "class X" / "interface X" / "enum X" / "final class X"
    const m =
      block.match(
        /(?:public\s+|final\s+|abstract\s+)*(?:class|interface|enum|record)\s+([A-Za-z0-9_$]+)/
      ) || block.match(/package\s+([\w.]+);/)
    const name = m ? m[1] || 'unknown' : 'unknown'
    classes.push({ name, source: block })
  }
  return classes
}

export const jvmDecompileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Decompile JVM bytecode (.class, .jar, .war, .aar, .jmod) to Java source using CFR ' +
    '(Class File Reader), a single-JAR Java decompiler. Recovers readable Java source ' +
    'without executing the bytecode. Optional class_filter narrows output. Requires ' +
    'Java 8+ (java) and the CFR jar (CFR_JAR). Useful for supply-chain JAR analysis, ' +
    'malware applet inspection, and source-less Java application recovery.',
  inputSchema: jvmDecompileInputSchema,
  outputSchema: jvmDecompileOutputSchema,
  aspects: {
    formats: ['class', 'jar', 'war', 'aar', 'jmod', 'kotlin-metadata', 'java'],
    platforms: ['jvm', 'android', 'cross-platform'],
    execution: ['static', 'decompilation'],
    runtimes: ['cfr'],
    safety: SAFETY,
    capabilities: [
      'java-decompilation',
      'class-recovery',
      'source-recovery',
      'archive-decompilation',
      'workflow-handoff',
    ],
    evidence: ['source', 'classes', 'provenance'],
  },
  artifacts: [
    {
      type: ARTIFACT_TYPE,
      description: 'CFR-decompiled Java source with per-class breakdown',
    },
  ],
  evidence: [
    {
      category: 'source',
      artifactTypes: [ARTIFACT_TYPE],
    },
    {
      category: 'classes',
      artifactTypes: [ARTIFACT_TYPE],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    noMutation: true,
    noLiveExecution: true,
    noNetwork: true,
    notes: [
      'CFR decompiles bytecode by parsing class files; it never executes JVM bytecode.',
      'java is used only to run the CFR jar; the sample is not executed as a JVM application.',
    ],
  },
}

function resolveJava(): { available: boolean; path: string | null } {
  // Prefer configured path, then PATH 'java' (shared with ghidra's Java dep).
  const envPath = process.env.JAVA_PATH || process.env.JAVA_HOME
  if (envPath) {
    return { available: true, path: envPath.endsWith('java') ? envPath : `${envPath}/bin/java` }
  }
  // Best-effort: assume 'java' on PATH is usable (JVM plugin requires Java too).
  return { available: true, path: 'java' }
}

export function createJvmDecompileHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = jvmDecompileInputSchema.parse(args)
      const java = resolveJava()
      const cfrJar = process.env.CFR_JAR || null
      if (!cfrJar) {
        return buildSetupRequired('CFR_JAR', java, startTime)
      }
      if (!java.available || !java.path) {
        return buildSetupRequired('java', java, startTime)
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)

      const cfrArgs = ['-jar', cfrJar, samplePath]
      if (input.silent) cfrArgs.push('--silent', 'true')
      if (!input.comments) cfrArgs.push('--comments', '0')

      const result = await executeCommand(java.path, cfrArgs, input.timeout_sec * 1000)

      if (result.exitCode !== 0 && !result.stdout.trim()) {
        return {
          ok: false,
          errors: [
            `CFR exited with code ${result.exitCode}`,
            result.stderr || result.stdout || 'No decompiler output was returned.',
          ],
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }

      const rawSource = result.stdout
      const classes = splitCfrClasses(rawSource)

      let filtered = classes
      let truncatedClasses: string[] = []
      if (input.class_filter) {
        filtered = classes.filter((c) => c.name.includes(input.class_filter))
      }

      // Build the inline source, truncating to max_output_chars.
      let inlineSource = filtered.map((c) => c.source).join('\n\n')
      let sourceTruncated = false
      if (inlineSource.length > input.max_output_chars) {
        inlineSource = inlineSource.slice(0, input.max_output_chars)
        sourceTruncated = true
        truncatedClasses = filtered
          .slice(Math.ceil(input.max_output_chars / 4096))
          .map((c) => c.name)
      }

      const status = classes.length === 0 ? 'no_classes' : 'ready'

      const baseOutputData = {
        schema: `rikune.${ARTIFACT_TYPE}`,
        tool_version: TOOL_VERSION,
        status,
        backend: {
          java_available: java.available,
          cfr_jar: cfrJar,
        },
        sample_id: input.sample_id,
        class_count: classes.length,
        class_filter: input.class_filter ?? null,
        source: classes.length > 0 ? inlineSource : null,
        source_truncated: sourceTruncated,
        truncated_classes: truncatedClasses,
        summary:
          status === 'ready'
            ? `CFR decompiled ${classes.length} class(es) from ${input.sample_id}${
                input.class_filter ? ` (filtered to ${filtered.length})` : ''
              }.`
            : `CFR produced no decompiled classes for ${input.sample_id}.`,
        recommended_next_tools: RECOMMENDED_NEXT_TOOLS,
      } satisfies Record<string, unknown>

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact && classes.length > 0) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'jvm-decompile',
          'decompile',
          JSON.stringify({ ...baseOutputData, full_source: rawSource }, null, 2),
          {
            extension: 'json',
            mime: 'application/json',
            sessionTag: input.session_tag,
          }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          ...baseOutputData,
          artifact,
          recommended_next_tools: RECOMMENDED_NEXT_TOOLS,
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

function buildSetupRequired(
  missing: string,
  java: { available: boolean; path: string | null },
  startTime: number
): WorkerResult {
  return {
    ok: true,
    data: {
      status: 'setup_required',
      backend: {
        java_available: java.available,
        cfr_jar: process.env.CFR_JAR || null,
        missing,
      },
      summary:
        missing === 'CFR_JAR'
          ? 'CFR jar not configured. Set CFR_JAR to the path of cfr.jar (download from https://github.com/leibnitz27/cfr).'
          : 'Java runtime not found. Set JAVA_PATH or JAVA_HOME to a Java 8+ binary.',
      recommended_next_tools: ['system.health', 'system.setup.guide', 'tool.help'],
      next_actions: [
        'Install CFR (single JAR) and set CFR_JAR; ensure Java 8+ is on PATH.',
        'Retry jvm.decompile after the backend becomes available.',
      ],
    },
    warnings: [
      missing === 'CFR_JAR'
        ? 'CFR_JAR environment variable is not set'
        : 'Java runtime is not available',
    ],
    metrics: buildMetrics(startTime, TOOL_NAME),
  }
}
