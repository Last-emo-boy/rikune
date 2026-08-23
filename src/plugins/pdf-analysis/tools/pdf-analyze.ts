/**
 * pdf.analyze — Static analysis of PDF structure, embedded JS, and actions.
 *
 * Parses a PDF's object model using a standard-library Python worker: extracts
 * the object catalog, embedded JavaScript (/JS, /JavaScript actions), stream
 * contents (FlateDecode-inflated), open actions, URIs, and embedded files.
 * Passive and read-only — never executes JavaScript or opens network.
 */

import { z } from 'zod'
import { spawn } from 'child_process'
import type {
  WorkerResult,
  ToolDefinition,
  ToolArgs,
  ArtifactRef,
  PluginToolDeps,
} from '../../sdk.js'
import { getPlatformServices, requireDatabase, requireWorkspaceManager } from '../../sdk.js'
import { getPythonCommand } from '../../../utils/shared-helpers.js'
import {
  ArtifactRefSchema,
  SharedMetricsSchema,
  normalizeError,
  persistBackendArtifact,
  buildMetrics,
  resolveSampleFile,
} from '../../docker-shared.js'

const TOOL_NAME = 'pdf.analyze'
const TOOL_VERSION = '0.1.0'
const ARTIFACT_TYPE = 'pdf_static_analysis'
const MAX_WORKER_STDOUT_BYTES = 4 * 1024 * 1024
const MAX_WORKER_STDERR_BYTES = 64 * 1024
const MAX_JS_CHARS = 32_000
const MAX_TOTAL_JS_CHARS = 1024 * 1024
const MAX_URI_CHARS = 2_048
const MAX_TOTAL_URI_CHARS = 256 * 1024
const MAX_ACTIONS = 50
const MAX_ACTION_CHARS = 4_096
const MAX_TOTAL_ACTION_CHARS = 128 * 1024
const MAX_EMBEDDED_FILES = 50
const MAX_EMBEDDED_FILE_CHARS = 4_096
const MAX_TOTAL_EMBEDDED_FILE_CHARS = 128 * 1024
const MAX_WARNINGS = 50
const MAX_WARNING_CHARS = 2_048
const MAX_TOTAL_WARNING_CHARS = 64 * 1024
const RECOMMENDED_NEXT_TOOLS = [
  'metadata.extract',
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
  'no_js_execution',
]

export const pdfAnalyzeInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier (sha256:<hex>) of a PDF file.'),
  max_js_entries: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(50)
    .describe('Maximum embedded JavaScript entries to return inline.'),
  max_uris: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .default(200)
    .describe('Maximum URI entries to return inline.'),
  persist_artifact: z
    .boolean()
    .optional()
    .default(true)
    .describe('Persist the analysis result as an artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

const JsEntrySchema = z.object({
  object: z.number().int(),
  source: z.enum(['name', 'stream']),
  js: z.string(),
})

const StructureSchema = z.object({
  object_count: z.number().int(),
  page_count: z.number().int(),
  xref_count: z.number().int(),
  trailer_count: z.number().int(),
  has_encrypt: z.boolean(),
  has_js: z.boolean(),
  has_launch_action: z.boolean(),
  has_submitform: z.boolean(),
  has_goitore: z.boolean(),
})

export const pdfAnalyzeOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'invalid_pdf', 'input_too_large', 'setup_required']),
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      pdf_version: z.string().nullable().optional(),
      structure: StructureSchema.nullable().optional(),
      javascript: z.array(JsEntrySchema).optional(),
      js_count: z.number().int().nonnegative().optional(),
      uris: z.array(z.string()).optional(),
      uri_count: z.number().int().nonnegative().optional(),
      open_actions: z.array(z.string()).optional(),
      embedded_files: z.array(z.string()).optional(),
      warnings: z.array(z.string()).optional(),
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

export const pdfAnalyzeToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Static analysis of PDF structure, embedded JavaScript, and actions. Parses the ' +
    'PDF object model to extract the object catalog, embedded JavaScript (/JS, ' +
    '/JavaScript actions), FlateDecode stream contents, open actions, URIs, and ' +
    'embedded files. Useful for PDF malware triage (droppers, phishing payloads). ' +
    'Passive and read-only — never executes embedded JavaScript or opens URIs.',
  inputSchema: pdfAnalyzeInputSchema,
  outputSchema: pdfAnalyzeOutputSchema,
  aspects: {
    formats: ['pdf', 'pdf-portfolio', 'pdf-interactive'],
    platforms: ['cross-platform', 'document'],
    execution: ['static', 'triage'],
    safety: SAFETY,
    capabilities: [
      'pdf-static-analysis',
      'javascript-extraction',
      'object-model-parsing',
      'action-inventory',
      'malware-triage',
      'workflow-handoff',
    ],
    evidence: ['structure', 'javascript', 'uris', 'actions', 'provenance'],
  },
  artifacts: [
    {
      type: ARTIFACT_TYPE,
      description: 'PDF static analysis with JS, URIs, actions, and object structure',
    },
  ],
  evidence: [
    {
      category: 'structure',
      artifactTypes: [ARTIFACT_TYPE],
    },
    {
      category: 'javascript',
      artifactTypes: [ARTIFACT_TYPE],
    },
    {
      category: 'uris',
      artifactTypes: [ARTIFACT_TYPE],
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    noMutation: true,
    noLiveExecution: true,
    noNetwork: true,
    notes: [
      'PDF objects are parsed as text; streams are zlib-inflated for inspection only.',
      'Embedded JavaScript is extracted as text but never evaluated or executed.',
      'The sample is never modified; an optional JSON report artifact may be written to the workspace.',
      'No network connections are made.',
    ],
  },
}

async function callPdfWorker(
  request: Record<string, unknown>,
  pythonCmd: string,
  workerPath: string,
  timeoutMs: number
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const proc = spawn(pythonCmd, [workerPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []
    let stdoutBytes = 0
    let stderrBytes = 0
    let settled = false

    const settleReject = (error: Error): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(error)
    }

    const settleResolve = (value: Record<string, unknown>): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(value)
    }

    const timer = setTimeout(() => {
      proc.kill()
      settleReject(new Error(`Python worker timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    proc.stdout.on('data', (d: Buffer) => {
      if (settled) return
      const chunk = Buffer.isBuffer(d) ? d : Buffer.from(d)
      stdoutBytes += chunk.byteLength
      if (stdoutBytes > MAX_WORKER_STDOUT_BYTES) {
        proc.kill()
        settleReject(new Error(`PDF worker stdout exceeded ${MAX_WORKER_STDOUT_BYTES} byte limit`))
        return
      }
      stdoutChunks.push(chunk)
    })

    proc.stderr.on('data', (d: Buffer) => {
      if (settled) return
      const chunk = Buffer.isBuffer(d) ? d : Buffer.from(d)
      stderrBytes += chunk.byteLength
      if (stderrBytes > MAX_WORKER_STDERR_BYTES) {
        proc.kill()
        settleReject(new Error(`PDF worker stderr exceeded ${MAX_WORKER_STDERR_BYTES} byte limit`))
        return
      }
      stderrChunks.push(chunk)
    })

    proc.on('close', (code) => {
      if (settled) return
      const stdout = Buffer.concat(stdoutChunks, stdoutBytes).toString('utf8')
      const stderr = Buffer.concat(stderrChunks, stderrBytes).toString('utf8')
      if (code !== 0 && !stdout.trim()) {
        settleReject(new Error(`PDF worker exited ${code}: ${stderr.slice(0, 500)}`))
        return
      }
      try {
        const parsed: unknown = JSON.parse(stdout.trim())
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('worker response must be a JSON object')
        }
        settleResolve(parsed as Record<string, unknown>)
      } catch (e) {
        settleReject(
          new Error(`Parse error: ${(e as Error).message}; stderr=${stderr.slice(0, 200)}`)
        )
      }
    })

    proc.on('error', (e) => {
      settleReject(new Error(`Spawn error: ${e.message}`))
    })
    proc.stdin.on('error', (e) => {
      settleReject(new Error(`PDF worker stdin error: ${e.message}`))
    })
    proc.stdin.write(JSON.stringify(request) + '\n')
    proc.stdin.end()
  })
}

type PdfWorkerStatus = 'ready' | 'invalid_pdf' | 'input_too_large' | 'setup_required'

function parseWorkerStatus(value: unknown): PdfWorkerStatus {
  if (
    value === 'ready' ||
    value === 'invalid_pdf' ||
    value === 'input_too_large' ||
    value === 'setup_required'
  ) {
    return value
  }
  const received = typeof value === 'string' ? value : typeof value
  throw new Error(`PDF worker returned unsupported status: ${received}`)
}

function boundedStrings(
  value: unknown,
  maxItems: number,
  maxChars: number,
  maxTotalChars: number
): string[] {
  if (!Array.isArray(value)) return []

  const output: string[] = []
  const seen = new Set<string>()
  let remainingChars = maxTotalChars
  for (const candidate of value) {
    if (output.length >= maxItems || remainingChars <= 0) break
    if (typeof candidate !== 'string') continue
    const bounded = candidate.slice(0, Math.min(maxChars, remainingChars))
    if (!bounded || seen.has(bounded)) continue
    output.push(bounded)
    seen.add(bounded)
    remainingChars -= bounded.length
  }
  return output
}

function boundedJavascript(
  value: unknown,
  maxEntries: number
): Array<z.infer<typeof JsEntrySchema>> {
  if (!Array.isArray(value)) return []

  const output: Array<z.infer<typeof JsEntrySchema>> = []
  const seen = new Set<string>()
  let remainingChars = MAX_TOTAL_JS_CHARS
  for (const candidate of value) {
    if (output.length >= maxEntries || remainingChars <= 0) break
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) continue
    const entry = candidate as Record<string, unknown>
    if (typeof entry.object !== 'number' || !Number.isInteger(entry.object) || entry.object < 0)
      continue
    if (entry.source !== 'name' && entry.source !== 'stream') continue
    if (typeof entry.js !== 'string') continue

    const js = entry.js.slice(0, Math.min(MAX_JS_CHARS, remainingChars))
    if (!js) continue
    const dedupeKey = `${entry.object}:${entry.source}:${js}`
    if (seen.has(dedupeKey)) continue
    seen.add(dedupeKey)
    output.push({ object: entry.object, source: entry.source, js })
    remainingChars -= js.length
  }
  return output
}

export function createPdfAnalyzeHandler(deps: PluginToolDeps) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = pdfAnalyzeInputSchema.parse(args)
      const workspaceManager = requireWorkspaceManager(deps, TOOL_NAME)
      const database = requireDatabase(deps, TOOL_NAME)
      const resolvePackagePath = getPlatformServices(deps).resolvePackagePath
      if (!resolvePackagePath) {
        throw new Error(`package path resolver is required for ${TOOL_NAME}`)
      }

      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const pythonCmd = getPythonCommand(undefined, deps.config?.workers?.static?.pythonPath)
      const workerPath = resolvePackagePath(
        'src',
        'plugins',
        'pdf-analysis',
        'workers',
        'pdf_analyze_worker.py'
      )

      const workerResult = await callPdfWorker(
        {
          sample_path: samplePath,
          max_js_entries: input.max_js_entries,
          max_uris: input.max_uris,
        },
        pythonCmd,
        workerPath,
        90_000
      )

      const status = parseWorkerStatus(workerResult.status)
      const pdfVersion =
        typeof workerResult.pdf_version === 'string' ? workerResult.pdf_version : null
      const structureResult = StructureSchema.safeParse(workerResult.structure)
      const structure = structureResult.success ? structureResult.data : null
      const javascript = boundedJavascript(workerResult.javascript, input.max_js_entries)
      const uris = boundedStrings(
        workerResult.uris,
        input.max_uris,
        MAX_URI_CHARS,
        MAX_TOTAL_URI_CHARS
      )
      const openActions = boundedStrings(
        workerResult.open_actions,
        MAX_ACTIONS,
        MAX_ACTION_CHARS,
        MAX_TOTAL_ACTION_CHARS
      )
      const embeddedFiles = boundedStrings(
        workerResult.embedded_files,
        MAX_EMBEDDED_FILES,
        MAX_EMBEDDED_FILE_CHARS,
        MAX_TOTAL_EMBEDDED_FILE_CHARS
      )
      const warnings = boundedStrings(
        workerResult.warnings,
        MAX_WARNINGS,
        MAX_WARNING_CHARS,
        MAX_TOTAL_WARNING_CHARS
      )

      const baseOutputData = {
        schema: `rikune.${ARTIFACT_TYPE}`,
        tool_version: TOOL_VERSION,
        status,
        sample_id: input.sample_id,
        pdf_version: pdfVersion,
        structure,
        javascript,
        js_count: javascript.length,
        uris,
        uri_count: uris.length,
        open_actions: openActions,
        embedded_files: embeddedFiles,
        warnings,
        summary: buildSummary(
          status,
          pdfVersion,
          javascript.length,
          uris.length,
          structure ?? undefined
        ),
        recommended_next_tools: RECOMMENDED_NEXT_TOOLS,
      } satisfies Record<string, unknown>

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'pdf-analysis',
          'analyze',
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

function buildSummary(
  status: string,
  pdfVersion: string | null,
  jsCount: number,
  uriCount: number,
  structure: z.infer<typeof StructureSchema> | undefined
): string {
  if (status === 'invalid_pdf') {
    return 'Sample is not a valid PDF (missing %PDF- header).'
  }
  if (status === 'input_too_large') {
    return 'PDF exceeds the bounded worker input limit and was not analyzed.'
  }
  if (status === 'setup_required') {
    return 'PDF analysis worker setup is required.'
  }
  const parts: string[] = []
  parts.push(`PDF ${pdfVersion ?? 'unknown version'}`)
  if (structure) {
    parts.push(`${structure.object_count ?? 0} objects`)
    parts.push(`${structure.page_count ?? 0} pages`)
    if (structure.has_encrypt) parts.push('encrypted')
    if (structure.has_launch_action) parts.push('has /Launch action')
  }
  if (jsCount > 0) parts.push(`${jsCount} embedded JS block(s)`)
  if (uriCount > 0) parts.push(`${uriCount} URI(s)`)
  return parts.join(', ') + '.'
}
