import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import { execFileSync } from 'child_process'
import { deflateSync } from 'zlib'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import pdfAnalysisPlugin from '../../src/plugins/pdf-analysis/index.js'
import {
  createPdfAnalyzeHandler,
  pdfAnalyzeOutputSchema,
  pdfAnalyzeToolDefinition,
} from '../../src/plugins/pdf-analysis/tools/pdf-analyze.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'

const PROJECT_ROOT = process.cwd()
const WORKER_PATH = path.join(
  PROJECT_ROOT,
  'src',
  'plugins',
  'pdf-analysis',
  'workers',
  'pdf_analyze_worker.py'
)

function resetSurfaceForTest(): void {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function minimalPdf(): Buffer {
  return Buffer.from(
    [
      '%PDF-1.7',
      '1 0 obj',
      '<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>',
      'endobj',
      '2 0 obj',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      'endobj',
      '3 0 obj',
      '<< /Type /Page /Parent 2 0 R /Annots [5 0 R] >>',
      'endobj',
      '4 0 obj',
      '<< /S /JavaScript /JS (first_script) >>',
      'endobj',
      '5 0 obj',
      '<< /Subtype /Link /A << /S /URI /URI (https://one.invalid/path) >> >>',
      'endobj',
      '6 0 obj',
      '<< /S /JavaScript /JS (second_script) >>',
      'endobj',
      '7 0 obj',
      '<< /S /URI /URI (https://two.invalid/path) >>',
      'endobj',
      '8 0 obj',
      '<< /S /Launch /F (payload.exe) >>',
      'endobj',
      '9 0 obj',
      '<< /Type /Filespec /F (payload.bin) /EF << /F 10 0 R >> >>',
      'endobj',
      '10 0 obj',
      '<< /Type /EmbeddedFile /Length 0 >>',
      'stream',
      '',
      'endstream',
      'endobj',
      'xref',
      '0 11',
      'trailer',
      '<< /Root 1 0 R /Size 11 >>',
      '%%EOF',
    ].join('\n'),
    'latin1'
  )
}

describe('pdf-analysis plugin', () => {
  let tempDir: string
  let workspaceRoot: string
  let samplePath: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'d'.repeat(64)}`

  beforeEach(async () => {
    resetSurfaceForTest()
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'pdf-analysis-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    const pdf = minimalPdf()
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: 'd'.repeat(64),
      md5: 'd'.repeat(32),
      size: pdf.byteLength,
      file_type: 'PDF document',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    workspaceRoot = workspace.root
    samplePath = path.join(workspace.original, 'sample.pdf')
    await fs.writeFile(samplePath, pdf)
  })

  afterEach(async () => {
    database.close()
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  function handler(resolveWorkerPath = WORKER_PATH) {
    return createPdfAnalyzeHandler({
      workspaceManager,
      database,
      config: { workers: { static: { pythonPath: 'python3' } } },
      resolvePackagePath: () => resolveWorkerPath,
    })
  }

  test('registers pdf.analyze with PDF triage aspects', () => {
    expect(pdfAnalysisPlugin.id).toBe('pdf-analysis')
    expect(pdfAnalysisPlugin.aspects.formats).toContain('pdf')
    expect(pdfAnalysisPlugin.aspects.capabilities).toEqual(
      expect.arrayContaining([
        'pdf-static-analysis',
        'javascript-extraction',
        'object-model-parsing',
        'action-inventory',
      ])
    )
    expect(pdfAnalysisPlugin.surfaceRules).toEqual(
      expect.objectContaining({ tier: 2, category: 'malware-analysis' })
    )

    const registered: string[] = []
    const fakeServer = {
      registerTool: (definition: { name: string }) => registered.push(definition.name),
    }
    const names = pdfAnalysisPlugin.register?.(
      fakeServer as any,
      {
        workspaceManager,
        database,
        resolvePackagePath: () => WORKER_PATH,
      } as any
    )
    expect(registered).toEqual(['pdf.analyze'])
    expect(names).toEqual(['pdf.analyze'])
  })

  test('declares passive, non-mutating, no-network, no-live-execution policy', () => {
    expect(pdfAnalyzeToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        noMutation: true,
        noNetwork: true,
        noLiveExecution: true,
      })
    )
    expect(pdfAnalyzeToolDefinition.aspects.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'read_only',
        'bounded_output',
        'no_network_by_default',
        'no_js_execution',
      ])
    )
  })

  test('extracts JavaScript, URIs, Launch actions, structure, and embedded files', async () => {
    const result = await handler()({
      sample_id: sampleId,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    expect(pdfAnalyzeOutputSchema.safeParse(result).success).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('ready')
    expect(data.pdf_version).toBe('1.7')
    expect(data.structure).toEqual(
      expect.objectContaining({
        object_count: 10,
        page_count: 1,
        has_js: true,
        has_launch_action: true,
      })
    )
    expect(data.javascript.map((entry: { js: string }) => entry.js)).toEqual(
      expect.arrayContaining(['first_script', 'second_script'])
    )
    expect(data.uris).toEqual(
      expect.arrayContaining(['https://one.invalid/path', 'https://two.invalid/path'])
    )
    expect(data.open_actions).toEqual(
      expect.arrayContaining([
        expect.stringContaining('OpenAction: 4 0 R'),
        expect.stringContaining('Launch: payload.exe'),
      ])
    )
    expect(data.embedded_files.length).toBeGreaterThan(0)
  })

  test('persists the bounded JSON report as a workspace artifact', async () => {
    const result = await handler()({
      sample_id: sampleId,
      persist_artifact: true,
      session_tag: 'unit-test',
    })

    expect(result.ok).toBe(true)
    expect(result.artifacts).toHaveLength(1)
    const artifact = result.artifacts?.[0]
    expect(artifact?.type).toBe('backend_pdf-analysis_analyze')
    const artifactPath = path.join(workspaceRoot, artifact?.path ?? '')
    const persisted = JSON.parse(await fs.readFile(artifactPath, 'utf8'))
    expect(persisted.status).toBe('ready')
    expect(persisted.javascript).toHaveLength(2)
    expect(persisted.open_actions).toEqual(
      expect.arrayContaining([expect.stringContaining('Launch: payload.exe')])
    )
  })

  test('returns invalid_pdf without attempting content execution', async () => {
    await fs.writeFile(samplePath, 'not a pdf')

    const result = await handler()({
      sample_id: sampleId,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.status).toBe('invalid_pdf')
    expect(data.javascript).toEqual([])
    expect(data.uris).toEqual([])
    expect(data.warnings).toEqual([expect.stringMatching(/%PDF-/)])
  })

  test('enforces JS and URI entry limits inside the Python worker', () => {
    const stdout = execFileSync('python3', [WORKER_PATH], {
      input: JSON.stringify({
        sample_path: samplePath,
        max_js_entries: 1,
        max_uris: 1,
      }),
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
    })
    const workerResult = JSON.parse(stdout)

    expect(workerResult.javascript).toHaveLength(1)
    expect(workerResult.js_count).toBe(1)
    expect(workerResult.uris).toHaveLength(1)
    expect(workerResult.uri_count).toBe(1)
  })

  test('caps FlateDecode expansion before extracting stream JavaScript', () => {
    const compressed = deflateSync(Buffer.from('A'.repeat(1024 * 1024)))
    const bombPdf = Buffer.concat([
      Buffer.from(
        `%PDF-1.7\n1 0 obj\n<< /S /JavaScript /Filter /FlateDecode /Length ${compressed.length} >>\nstream\n`,
        'latin1'
      ),
      compressed,
      Buffer.from('\nendstream\nendobj\n%%EOF\n', 'latin1'),
    ])

    return fs.writeFile(samplePath, bombPdf).then(() => {
      const stdout = execFileSync('python3', [WORKER_PATH], {
        input: JSON.stringify({ sample_path: samplePath, max_js_entries: 10, max_uris: 10 }),
        encoding: 'utf8',
        maxBuffer: 2 * 1024 * 1024,
      })
      const workerResult = JSON.parse(stdout)

      expect(workerResult.javascript).toHaveLength(1)
      expect(workerResult.javascript[0].js).toHaveLength(32_000)
      expect(workerResult.warnings).toEqual(
        expect.arrayContaining([expect.stringMatching(/Inflated stream output truncated/)])
      )
    })
  })

  test('counts adversarial page markers without allocating a match list', async () => {
    const markerCount = 100_000
    await fs.writeFile(
      samplePath,
      Buffer.from(`%PDF-1.7\n${'/Type /Page '.repeat(markerCount)}\n%%EOF\n`, 'latin1')
    )

    const stdout = execFileSync('python3', [WORKER_PATH], {
      input: JSON.stringify({ sample_path: samplePath, max_js_entries: 1, max_uris: 1 }),
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
    })
    const workerResult = JSON.parse(stdout)
    const workerSource = await fs.readFile(WORKER_PATH, 'utf8')

    expect(workerResult.structure.page_count).toBe(markerCount)
    expect(workerSource).toContain('sum(1 for _ in re.finditer')
    expect(workerSource).not.toContain('len(re.findall(rb"/Type\\s*/Page')
  })

  test('kills a worker that exceeds the stdout byte cap and settles as an error', async () => {
    const noisyWorker = path.join(tempDir, 'noisy-worker.py')
    await fs.writeFile(noisyWorker, 'import sys\nsys.stdout.write("x" * (5 * 1024 * 1024))\n')

    const result = await handler(noisyWorker)({
      sample_id: sampleId,
      persist_artifact: false,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/stdout exceeded .* byte limit/)
  })

  test('reports a missing package path dependency instead of asserting it exists', async () => {
    const result = await createPdfAnalyzeHandler({ workspaceManager, database })({
      sample_id: sampleId,
      persist_artifact: false,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/package path resolver is required/)
  })
})
