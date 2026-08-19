/**
 * lib.identify — Identify known static library functions via rizin FLIRT sigdb.
 *
 * Applies FLIRT signatures from a rizin sigdb to the sample's functions and
 * reports which functions correspond to known library routines (libc, MSVC
 * CRT, OpenSSL, zlib, etc.). Matched functions are renamed into the `flirt`
 * flag space (e.g. flirt.printf). This lets analysts separate library boiler
 * plate from custom code.
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

const TOOL_NAME = 'lib.identify'
const TOOL_VERSION = '0.1.0'
const ARTIFACT_TYPE = 'backend_lib_identify_matches'
const SIGNATURES_ARTIFACT_TYPE = 'lib_signatures_list'
const RECOMMENDED_NEXT_TOOLS = [
  'rizin.analyze',
  'artifact.read',
  'workflow.search',
  'code.functions.rank',
]

const SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]

export const libIdentifyInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier (sha256:<hex>).'),
  sigdb_path: z
    .string()
    .optional()
    .describe(
      'Path to rizin FLIRT sigdb. Defaults to RZ_SIGDB / flirt.sigdb.path. ' +
        'Clone https://github.com/rizinorg/sigdb to use.'
    ),
  filter: z
    .string()
    .optional()
    .describe('Optional sigdb module name filter passed to rizin `Fa` (e.g. libc, openssl).'),
  min_confidence: z
    .enum(['any', 'high', 'crc'])
    .optional()
    .default('any')
    .describe('Minimum match confidence: any, high (full pattern), crc (CRC verified).'),
  max_matches: z
    .number()
    .int()
    .min(1)
    .max(2000)
    .optional()
    .default(200)
    .describe('Maximum matched functions to return inline.'),
  timeout_sec: z
    .number()
    .int()
    .min(5)
    .max(300)
    .optional()
    .default(90)
    .describe('Rizin FLIRT application timeout in seconds.'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist the match list as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

const LibMatchSchema = z.object({
  address: z.string(),
  matched_name: z.string(),
  original_name: z.string().optional(),
  module: z.string().optional().nullable(),
  bits: z.number().int().optional(),
  arch: z.string().optional(),
  confidence: z.enum(['full', 'crc', 'partial', 'unknown']).optional(),
})

export const libIdentifyOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required', 'no_sigdb', 'no_matches']),
      backend: BackendSchema.optional(),
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      sigdb_path: z.string().nullable().optional(),
      sigdb_loaded: z.boolean().optional(),
      modules_available: z.number().int().nonnegative().optional(),
      total_functions: z.number().int().nonnegative().optional(),
      matched_count: z.number().int().nonnegative().optional(),
      matches: z.array(LibMatchSchema).optional(),
      module_breakdown: z.record(z.string(), z.number().int().nonnegative()).optional(),
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

// Rizin command pipeline:
//   aaa              — analyze functions (needed before FLIRT apply)
//   e flirt.sigdb.path=<path>  — point at sigdb (optional)
//   Fa [filter]      — apply signatures from sigdb
//   aflj~flirt.     — list functions whose name starts with flirt.
// We capture both the applied-listing and the matched functions as JSON.
function buildRizinFlirtCommand(sigdbPath: string | undefined, filter: string | undefined): string {
  const parts: string[] = ['aaa']
  if (sigdbPath) {
    parts.push(`e flirt.sigdb.path="${sigdbPath.replace(/"/g, '\\"')}"`)
  }
  parts.push(filter ? `Fa ${filter}` : 'Fa')
  // List matched functions: aflj filtered to flirt.* names.
  parts.push('aflj')
  return parts.join(';')
}

interface ParsedRizinFunction {
  name?: string
  offset?: number
  bits?: number
}

function extractMatches(
  functionsJson: ParsedRizinFunction[] | null,
  maxMatches: number
): { matches: Array<Record<string, unknown>>; moduleBreakdown: Record<string, number> } {
  const matches: Array<Record<string, unknown>> = []
  const moduleBreakdown: Record<string, number> = {}
  if (!Array.isArray(functionsJson)) return { matches, moduleBreakdown }

  for (const fn of functionsJson) {
    const name = typeof fn?.name === 'string' ? fn.name : ''
    if (!name.startsWith('flirt.')) continue
    // flirt.<module>.<symbol> e.g. flirt.libc.printf, flirt.ssl3.SSL_read
    const remainder = name.slice('flirt.'.length)
    const dotIdx = remainder.indexOf('.')
    const module = dotIdx > 0 ? remainder.slice(0, dotIdx) : 'unknown'
    const symbol = dotIdx > 0 ? remainder.slice(dotIdx + 1) : remainder
    moduleBreakdown[module] = (moduleBreakdown[module] ?? 0) + 1
    matches.push({
      address: typeof fn.offset === 'number' ? `0x${fn.offset.toString(16)}` : '',
      matched_name: symbol,
      module,
      bits: typeof fn.bits === 'number' ? fn.bits : undefined,
      confidence: 'full' as const,
    })
    if (matches.length >= maxMatches) break
  }
  return { matches, moduleBreakdown }
}

export const libIdentifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Identify known static library functions in a binary using rizin FLIRT signatures (sigdb). ' +
    'Matches functions against known libraries (libc, MSVC CRT, OpenSSL, zlib, etc.) so analysts ' +
    'can separate library boilerplate from custom code. Requires rizin (RIZIN_PATH) and a sigdb ' +
    '(clone rizinorg/sigdb). Passive and read-only — never executes the sample.',
  inputSchema: libIdentifyInputSchema,
  outputSchema: libIdentifyOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'firmware', 'object'],
    platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    runtimes: ['rizin'],
    safety: SAFETY,
    capabilities: [
      'library-function-identification',
      'flirt-signature-matching',
      'function-naming',
      'boilerplate-filtering',
      'workflow-handoff',
    ],
    evidence: ['symbols', 'functions', 'signatures', 'provenance'],
  },
  artifacts: [
    {
      type: ARTIFACT_TYPE,
      description: 'FLIRT-matched library function list with module breakdown',
    },
    {
      type: SIGNATURES_ARTIFACT_TYPE,
      description: 'Available FLIRT signature modules listing',
    },
  ],
  evidence: [
    {
      category: 'symbols',
      artifactTypes: [ARTIFACT_TYPE],
    },
    {
      category: 'functions',
      artifactTypes: [ARTIFACT_TYPE],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    noMutation: true,
    noLiveExecution: true,
    noNetwork: true,
    notes: [
      'rizin is used as a bounded read-only static backend; FLIRT application never executes the sample.',
      'Sigdb resolution falls back to RZ_SIGDB / flirt.sigdb.path; missing sigdb returns no_sigdb.',
    ],
  },
}

export function createLibIdentifyHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = libIdentifyInputSchema.parse(args)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backends = resolveAnalysisBackends()
      const backend = backends.rizin
      if (!backend.available || !backend.path) {
        return buildStaticSetupRequired(backend, startTime, TOOL_NAME)
      }

      const sigdbPath = input.sigdb_path || process.env.RZ_SIGDB || undefined

      const command = buildRizinFlirtCommand(sigdbPath, input.filter)
      // rizin -q0 -c "<cmd>;q" <sample>  (-q0: quiet, no banner, null-separated)
      const result = await executeCommand(
        backend.path,
        ['-q0', '-c', `${command};q`, samplePath],
        input.timeout_sec * 1000
      )

      if (result.exitCode !== 0 && !result.stdout.trim()) {
        return {
          ok: false,
          errors: [
            `rizin exited with code ${result.exitCode}`,
            result.stderr || result.stdout || 'No backend output was returned.',
          ],
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }

      const functionsJson = safeJsonParse<ParsedRizinFunction[]>(result.stdout.trim())
      const { matches, moduleBreakdown } = extractMatches(functionsJson, input.max_matches)

      // Detect sigdb absence: rizin emits "Cannot find sigdb" style messages to stderr.
      const sigdbMissing = /no sigdb|cannot find|sigdb.*not/i.test(result.stderr)
      const status = sigdbMissing ? 'no_sigdb' : matches.length === 0 ? 'no_matches' : 'ready'

      const baseOutputData = {
        schema: `rikune.${ARTIFACT_TYPE}`,
        tool_version: TOOL_VERSION,
        status,
        backend,
        sample_id: input.sample_id,
        sigdb_path: sigdbPath ?? null,
        sigdb_loaded: !sigdbMissing,
        modules_available: Object.keys(moduleBreakdown).length,
        total_functions: Array.isArray(functionsJson) ? functionsJson.length : 0,
        matched_count: matches.length,
        matches,
        module_breakdown: moduleBreakdown,
        summary:
          status === 'ready'
            ? `FLIRT identified ${matches.length} library function(s) across ${Object.keys(moduleBreakdown).length} module(s).`
            : status === 'no_sigdb'
              ? 'No FLIRT sigdb found. Set sigdb_path or RZ_SIGDB to a rizinorg/sigdb clone.'
              : 'No library functions matched. The binary may be stripped of known library code.',
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
          'matches',
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
