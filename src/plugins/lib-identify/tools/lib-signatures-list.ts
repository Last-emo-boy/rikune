/**
 * lib.signatures.list — List available FLIRT signature modules applicable to a sample.
 *
 * Opens the sample in rizin (no analysis) and enumerates the sigdb signature
 * modules that could apply via `Fl`. Returns module name, architecture, bits,
 * and function count per signature. Use before lib.identify to scope the filter.
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
  BackendSchema,
  SharedMetricsSchema,
  executeCommand,
  normalizeError,
  safeJsonParse,
  persistBackendArtifact,
  buildMetrics,
  buildStaticSetupRequired,
  resolveSampleFile,
  resolveAnalysisBackends,
} from '../../docker-shared.js'

const TOOL_NAME = 'lib.signatures.list'
const TOOL_VERSION = '0.1.0'
const ARTIFACT_TYPE = 'backend_lib_signatures_list'
const RECOMMENDED_NEXT_TOOLS = ['lib.identify', 'artifact.read', 'workflow.search']

const SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]

export const libSignaturesListInputSchema = z.object({
  sample_id: z
    .string()
    .describe('Target sample identifier (sha256:<hex>). rizin opens it to scope sigdb.'),
  sigdb_path: z
    .string()
    .optional()
    .describe('Path to rizin FLIRT sigdb. Defaults to RZ_SIGDB / flirt.sigdb.path.'),
  max_items: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(100)
    .describe('Maximum signature modules to return inline.'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist the signature listing as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

const SignatureModuleSchema = z.object({
  name: z.string(),
  arch: z.string().nullable().optional(),
  bits: z.number().int().nullable().optional(),
  modules: z.number().int().nonnegative().optional(),
  details: z.string().nullable().optional(),
})

export const libSignaturesListOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required', 'no_sigdb']),
      backend: BackendSchema.optional(),
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      sigdb_path: z.string().nullable().optional(),
      module_count: z.number().int().nonnegative().optional(),
      signatures: z.array(SignatureModuleSchema).optional(),
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

interface ParsedFlirtEntry {
  bin?: string
  arch?: string
  bits?: number | string
  name?: string
  modules?: number | string
  details?: string
}

export const libSignaturesListToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'List available FLIRT signature modules in the rizin sigdb applicable to a sample. ' +
    'Returns module name, architecture, bits, and function count per signature. Use before ' +
    'lib.identify to scope the matching filter. Requires rizin (RIZIN_PATH) and a sigdb. ' +
    'Passive and read-only — never executes the sample.',
  inputSchema: libSignaturesListInputSchema,
  outputSchema: libSignaturesListOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'firmware', 'object'],
    platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    runtimes: ['rizin'],
    safety: SAFETY,
    capabilities: [
      'flirt-signature-inventory',
      'sigdb-enumeration',
      'library-function-identification',
      'workflow-handoff',
    ],
    evidence: ['signatures', 'symbols', 'provenance'],
  },
  artifacts: [
    {
      type: ARTIFACT_TYPE,
      description: 'Available FLIRT signature modules listing',
    },
  ],
  evidence: [
    {
      category: 'symbols',
      artifactTypes: [ARTIFACT_TYPE],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    noMutation: true,
    noLiveExecution: true,
    noNetwork: true,
    notes: [
      'rizin is used as a bounded read-only backend; signature listing never executes the sample.',
      'Sigdb resolution falls back to RZ_SIGDB / flirt.sigdb.path; missing sigdb returns no_sigdb.',
    ],
  },
}

// `Flj` lists sigdb signatures as JSON when available. We set the sigdb path
// (optional) then request the listing. No function analysis is performed (`-n`).
function buildFlirtListCommand(sigdbPath: string | undefined): string {
  const parts: string[] = []
  if (sigdbPath) {
    parts.push(`e flirt.sigdb.path="${sigdbPath.replace(/"/g, '\\"')}"`)
  }
  parts.push('Flj')
  parts.push('q')
  return parts.join(';')
}

function parseFlirtTable(stdout: string, maxItems: number): ParsedFlirtEntry[] {
  // Fallback table parser for `Flt`/`Fl` when `Flj` returns no JSON.
  const entries: ParsedFlirtEntry[] = []
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || /no sigdb|cannot find/i.test(trimmed)) continue
    // Table rows look like: bin  arch  bits  name  modules  details
    const cols = trimmed
      .split(/\s{2,}/)
      .map((c) => c.trim())
      .filter(Boolean)
    if (cols.length < 3) continue
    entries.push({
      bin: cols[0],
      arch: cols[1] ?? null,
      bits: cols[2] ? Number(cols[2]) : null,
      name: cols[3] ?? cols[0],
      modules: cols[4] ? Number(cols[4]) : 0,
      details: cols[5] ?? null,
    })
    if (entries.length >= maxItems) break
  }
  return entries
}

export function createLibSignaturesListHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = libSignaturesListInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = resolveAnalysisBackends()
      const backend = backends.rizin
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, TOOL_NAME)
      }

      const sigdbPath = input.sigdb_path || process.env.RZ_SIGDB || undefined
      const command = buildFlirtListCommand(sigdbPath)
      // -n: no analysis, -q0: quiet, -c: run command then quit.
      const result = await executeCommand(
        backend.path,
        ['-n', '-q0', '-c', command, samplePath],
        30_000
      )

      const sigdbMissing = /no sigdb|cannot find|sigdb.*not/i.test(result.stderr)
      let signatures: ParsedFlirtEntry[] = []
      const jsonParsed = safeJsonParse<ParsedFlirtEntry[]>(result.stdout.trim())
      if (Array.isArray(jsonParsed)) {
        signatures = jsonParsed.slice(0, input.max_items)
      } else {
        signatures = parseFlirtTable(result.stdout, input.max_items)
      }

      const status = sigdbMissing ? 'no_sigdb' : signatures.length === 0 ? 'no_sigdb' : 'ready'

      const baseOutputData = {
        schema: `rikune.${ARTIFACT_TYPE}`,
        tool_version: TOOL_VERSION,
        status,
        backend,
        sample_id: input.sample_id,
        sigdb_path: sigdbPath ?? null,
        module_count: signatures.length,
        signatures: signatures.map((s) => ({
          name: s.name ?? s.bin ?? 'unknown',
          arch: s.arch ?? null,
          bits: typeof s.bits === 'number' ? s.bits : null,
          modules: typeof s.modules === 'number' ? s.modules : 0,
          details: s.details ?? null,
        })),
        summary:
          status === 'ready'
            ? `sigdb contains ${signatures.length} signature module(s) for ${input.sample_id}.`
            : 'No FLIRT sigdb found. Set sigdb_path or RZ_SIGDB to a rizinorg/sigdb clone.',
        recommended_next_tools: RECOMMENDED_NEXT_TOOLS,
      } satisfies Record<string, unknown>

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'lib-identify',
          'signatures',
          JSON.stringify(baseOutputData, null, 2),
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
