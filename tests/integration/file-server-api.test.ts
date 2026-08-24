import { DATABASE_FIXTURE_CAPABILITY } from '../../src/database.js'
import { beforeEach, afterEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import http from 'http'
import { createHash } from 'crypto'
import { fileURLToPath } from 'url'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { PolicyGuard } from '../../src/policy-guard.js'
import { StorageManager } from '../../src/storage/storage-manager.js'
import { FileServer } from '../../src/api/file-server.js'
import { createSampleFinalizationService } from '../../src/sample/sample-finalization.js'
import { SampleOperationGate } from '../../src/sample/sample-operation-gate.js'

function httpRequest(
  url: string,
  options: {
    method?: string
    headers?: Record<string, string>
    body?: Buffer
  } = {}
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(url)
    const req = http.request(
      {
        method: options.method || 'GET',
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search}`,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        })
      }
    )

    req.on('error', reject)
    if (options.body) {
      req.write(options.body)
    }
    req.end()
  })
}

function openSse(
  url: string,
  headers: Record<string, string> = {}
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers }, (res) => {
      resolve({ statusCode: res.statusCode || 0, headers: res.headers })
      res.destroy()
      req.destroy()
    })
    req.on('error', reject)
  })
}

interface DashboardHelpers {
  esc: (value: unknown) => string
  sanitizeHttpUrl: (raw: unknown) => string | null
  renderMarkdown: (md: string) => string
}

/**
 * Extract the dashboard's pure helper functions from the served HTML and
 * evaluate them standalone so their security behavior can be tested directly.
 */
function extractDashboardHelpers(html: string): DashboardHelpers {
  const extract = (name: string): string => {
    const match = html.match(new RegExp(`function ${name}\\([\\s\\S]*?\\n}`))
    if (!match) throw new Error(`dashboard helper not found in served HTML: ${name}`)
    return match[0]
  }
  const source = ['esc', 'decodeHtmlEntity', 'canonicalizeUrl', 'sanitizeHttpUrl', 'renderMarkdown']
    .map(extract)
    .join('\n')
  return new Function(`${source}\nreturn { esc, sanitizeHttpUrl, renderMarkdown }`)() as DashboardHelpers
}

describe('file server API hardening', () => {
  let testDir: string
  let dbPath: string
  let auditLogPath: string
  let workspaceRoot: string
  let storageRoot: string
  let database: DatabaseManager
  let sampleOperationGate: SampleOperationGate
  let fileServer: FileServer
  let fileServerDependencies: ConstructorParameters<typeof FileServer>[1]
  let port: number

  beforeEach(async () => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'file-server-api-'))
    dbPath = path.join(testDir, 'test.db')
    auditLogPath = path.join(testDir, 'audit.log')
    workspaceRoot = path.join(testDir, 'workspaces')
    storageRoot = path.join(testDir, 'storage')
    port = 20080 + Math.floor(Math.random() * 1000)

    database = new DatabaseManager(dbPath)
    sampleOperationGate = new SampleOperationGate(database)

    const workspaceManager = new WorkspaceManager(workspaceRoot)
    const policyGuard = new PolicyGuard(auditLogPath)
    const storageManager = new StorageManager({
      root: storageRoot,
      maxFileSize: 32,
      retentionDays: 30,
    })
    await storageManager.initialize()

    fileServerDependencies = {
      storageManager,
      database,
      workspaceManager,
      finalizationService: createSampleFinalizationService(
        workspaceManager,
        database,
        policyGuard,
        sampleOperationGate
      ),
      sampleOperationGate,
    }
    fileServer = new FileServer(
      {
        port,
        apiKey: 'secret-key',
        maxFileSize: 32,
      },
      fileServerDependencies
    )
    await fileServer.start()
  })

  afterEach(async () => {
    await fileServer.stop()
    sampleOperationGate.close()
    database.close()
    fs.rmSync(testDir, { recursive: true, force: true })
  })

  test('should return 413 for oversized upload-session payloads', async () => {
    const session = database.createUploadSession({
      filename: 'oversized.bin',
      source: 'test',
      expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    })

    const response = await httpRequest(`http://localhost:${port}/api/v1/uploads/${session.token}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
      },
      body: Buffer.alloc(64, 0x41),
    })

    expect(response.statusCode).toBe(413)
    const payload = JSON.parse(response.body)
    expect(payload.error).toBe('Payload Too Large')
    expect(payload.message).toContain('exceeds limit')
  })

  test('should return 400 for malformed direct uploads', async () => {
    const response = await httpRequest(`http://localhost:${port}/api/v1/samples`, {
      method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data',
        'X-API-Key': 'secret-key',
      },
      body: Buffer.from('not-a-valid-multipart-body', 'utf8'),
    })

    expect(response.statusCode).toBe(400)
    const payload = JSON.parse(response.body)
    expect(payload.error).toBe('Bad Request')
    expect(payload.message).toContain('missing boundary')
  })

  test('should enforce API key policy on sample metadata reads', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 128,
      file_type: 'PE32',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const withoutKey = await httpRequest(
      `http://localhost:${port}/api/v1/samples/${encodeURIComponent(sampleId)}`
    )
    expect(withoutKey.statusCode).toBe(401)

    const wrongKey = await httpRequest(
      `http://localhost:${port}/api/v1/samples/${encodeURIComponent(sampleId)}`,
      {
        headers: {
          'X-API-Key': 'wrong-key',
        },
      }
    )
    expect(wrongKey.statusCode).toBe(403)

    const success = await httpRequest(
      `http://localhost:${port}/api/v1/samples/${encodeURIComponent(sampleId)}`,
      {
        headers: {
          'X-API-Key': 'secret-key',
        },
      }
    )
    expect(success.statusCode).toBe(200)
    const payload = JSON.parse(success.body)
    expect(payload.ok).toBe(true)
    expect(payload.data.sample_id).toBe(sampleId)
  })

  test('should refuse to start without a non-empty API key', async () => {
    for (const apiKey of [undefined, '   ']) {
      const unauthenticatedServer = new FileServer(
        { port: 0, apiKey, maxFileSize: 32 },
        fileServerDependencies
      )

      await expect(unauthenticatedServer.start()).rejects.toThrow(
        'HTTP File Server requires a non-empty API_KEY'
      )
      expect((unauthenticatedServer as any).server).toBeNull()
      await unauthenticatedServer.stop()
    }
  })

  test('should reject a malformed Origin without terminating the server', async () => {
    const malformed = await httpRequest(`http://localhost:${port}/api/v1/health`, {
      headers: { Origin: '%' },
    })
    expect(malformed.statusCode).toBe(400)
    expect(JSON.parse(malformed.body).message).toBe('Invalid Origin header')

    const health = await httpRequest(`http://localhost:${port}/api/v1/health`)
    expect(health.statusCode).toBe(200)
  })

  test('should enforce the dashboard client authentication contract', async () => {
    const page = await httpRequest(`http://localhost:${port}/dashboard?key=secret-key`)
    expect(page.statusCode).toBe(200)
    expect(page.headers['content-type']).toBe('text/html; charset=utf-8')
    expect(page.headers['cache-control']).toBe('no-store')
    expect(page.headers['referrer-policy']).toBe('no-referrer')
    expect(page.body).toContain("const dashboardKey = dashboardUrl.searchParams.get('key')")
    expect(page.body).toContain("headers.set('X-API-Key', dashboardKey)")
    expect(page.body).toContain('history.replaceState')
    expect(page.body.match(/\bfetch\(/gu)).toHaveLength(1)
    expect(page.body).not.toMatch(/(?:localStorage|sessionStorage).*dashboardKey/gu)

    const denied = await httpRequest(`http://localhost:${port}/api/v1/dashboard/overview`)
    expect(denied.statusCode).toBe(401)

    const browserHeader = await httpRequest(`http://localhost:${port}/api/v1/dashboard/overview`, {
      headers: { 'X-API-Key': 'secret-key' },
    })
    expect(browserHeader.statusCode).toBe(200)

    const proxyInjectedHeader = await httpRequest(
      `http://localhost:${port}/api/v1/dashboard/samples?limit=5`,
      { headers: { 'X-API-Key': 'secret-key' } }
    )
    expect(proxyInjectedHeader.statusCode).toBe(200)
  })

  test('should authenticate SSE and never expose a wildcard CORS origin', async () => {
    const denied = await httpRequest(`http://localhost:${port}/api/v1/events`)
    expect(denied.statusCode).toBe(401)

    const allowed = await openSse(`http://localhost:${port}/api/v1/events?key=secret-key`, {
      Origin: 'http://localhost',
    })
    expect(allowed.statusCode).toBe(200)
    expect(allowed.headers['access-control-allow-origin']).toBe('http://localhost')
    expect(allowed.headers['access-control-allow-origin']).not.toBe('*')
  })

  test('should serve a script CSP without unsafe-inline and keep the dashboard script hash synchronized', async () => {
    const page = await httpRequest(`http://localhost:${port}/dashboard?key=secret-key`)
    expect(page.statusCode).toBe(200)

    const csp = page.headers['content-security-policy'] ?? ''
    const scriptSrc = /(?:^|;)\s*script-src\s+([^;]+)/.exec(csp)?.[1] ?? ''
    expect(scriptSrc).not.toContain('unsafe-inline')
    expect(scriptSrc).not.toContain('unsafe-eval')
    expect(scriptSrc).not.toContain('unsafe-hashes')

    // Hardening directives: no inline event-handler scripts, no plugins,
    // no <base> hijack, and the dashboard itself cannot be framed
    expect(csp).toContain("script-src-attr 'none'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).toContain("base-uri 'none'")
    expect(csp).toContain("frame-ancestors 'none'")

    // Required existing directives are retained
    expect(csp).toContain("style-src 'self' 'unsafe-inline'")
    expect(csp).toContain("img-src 'self' data:")
    expect(csp).toContain("frame-src 'self'")
    expect(csp).toContain("connect-src 'self'")

    // Exactly one inline script, and the CSP hash must cover its served bytes
    expect(page.body.match(/<script[\s>]/g) ?? []).toHaveLength(1)
    const scriptMatch = page.body.match(/<script>([\s\S]*?)<\/script>/)
    expect(scriptMatch).not.toBeNull()
    const expectedHash = createHash('sha256').update(scriptMatch![1], 'utf8').digest('base64')
    expect(scriptSrc).toContain(`'sha256-${expectedHash}'`)

    // The served bytes are exactly the checked-in dashboard file
    const dashboardHtmlPath = path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../src/api/dashboard/index.html'
    )
    expect(page.body).toBe(fs.readFileSync(dashboardHtmlPath, 'utf-8'))
  })

  test('should serve dashboard HTML without inline event handlers, javascript: URLs, or srcdoc attributes', async () => {
    const page = await httpRequest(`http://localhost:${port}/dashboard?key=secret-key`)
    expect(page.statusCode).toBe(200)
    expect(page.body).not.toMatch(/\son[a-z]+\s*=/i)
    expect(page.body).not.toMatch(/javascript\s*:/i)
    expect(page.body).not.toMatch(/\ssrcdoc\s*=\s*["']/i)
    expect(page.body).not.toContain('<iframe')
    expect(page.body).not.toContain('allow-scripts')

    // Untrusted HTML and SVG render only through the shared sandbox helper:
    // a fully sandboxed iframe built via DOM APIs, srcdoc set as a property
    expect(page.body).toContain('renderSandboxedArtifact(viewer, d.content)')
    expect(page.body).toContain("document.createElement('iframe')")
    expect(page.body).toContain("frame.setAttribute('sandbox', '')")
    expect(page.body).toContain('frame.srcdoc = content')

    // No parsed-SVG insertion path into the main DOM may remain
    expect(page.body).not.toContain('DOMParser')
    expect(page.body).not.toContain('sanitizeSvg')
    expect(page.body).not.toContain('appendChild(svg)')

    // API-controlled identifiers travel in inert data attributes, never inline handlers
    expect(page.body).toContain('data-sample-link')
    expect(page.body).toContain('data-view-artifact')
    expect(page.body).toContain('data-plugin-link')
    expect(page.body).toContain('data-export-tab')
  })

  test('should neutralize executable schemes and attribute breakouts in markdown links', async () => {
    const page = await httpRequest(`http://localhost:${port}/dashboard?key=secret-key`)
    expect(page.statusCode).toBe(200)
    const { sanitizeHttpUrl, renderMarkdown } = extractDashboardHelpers(page.body)

    const hostileUrls = [
      'javascript:alert(1)',
      'JaVaScRiPt:alert(1)',
      ' javascript:alert(1)',
      'java\tscript:alert(1)',
      'java%09script:alert(1)',
      '%6a%61vascript:alert(1)',
      '%256a%2561vascript:alert(1)',
      '&#x6a;avascript:alert(1)',
      '&#106;avascript:alert(1)',
      'javascript&colon;alert(1)',
      'java&Tab;script:alert(1)',
      '&NewLine;javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'vbscript:msgbox(1)',
      'file:///etc/passwd',
      'https://example.com/" onclick="alert(1)',
      "https://example.com/' onmouseover='alert(1)",
      'https://example.com/%22%20onclick=%22alert(1)',
      'https://example.com/%3Cscript%3E',
      // Credentials and hostless/relative forms are rejected after URL parsing
      'https://user:pass@example.com',
      'https://user@example.com',
      'https:///path',
      'https://',
      'https:example.com',
    ]
    for (const url of hostileUrls) {
      expect(sanitizeHttpUrl(url)).toBeNull()
      const output = renderMarkdown(`[x](${url})`)
      expect(output).not.toMatch(/<a[\s>]/i)
      expect(output).not.toMatch(/<[a-z][a-z0-9]*[^>]*\son[a-z]+\s*=/i)
    }

    // Legitimate http/https links keep working (entities round-trip safely)
    expect(renderMarkdown('[docs](https://example.com/a?b=1&c=2)')).toContain(
      '<a href="https://example.com/a?b=1&amp;c=2" target="_blank" rel="noopener noreferrer">docs</a>'
    )
    expect(renderMarkdown('[x](http://example.com)')).toContain('href="http://example.com"')
    expect(renderMarkdown('[x](https://example.com/a%20b)')).toContain('<a href=')
    expect(sanitizeHttpUrl('https://example.com/path?q=1&r=2')).toBe(
      'https://example.com/path?q=1&r=2'
    )
    expect(sanitizeHttpUrl('http://example.com:8080/a?b=1')).toBe('http://example.com:8080/a?b=1')
  })

  test('should never interpolate API-derived scalars into innerHTML without esc()', async () => {
    const page = await httpRequest(`http://localhost:${port}/dashboard?key=secret-key`)
    expect(page.statusCode).toBe(200)

    // Raw template interpolations an API-controlled id/path/version/count
    // could weaponize — none of these may survive in the served source.
    // Patterns are anchored to innerHTML insertion contexts (a preceding `>`
    // or an unescaped ternary branch) so textContent assignments and values
    // that are escaped at insertion time do not false-positive.
    const forbiddenRawInterpolations = [
      '${shortSample}',
      '${sha}',
      '${p.version',
      '${p.tool_count}',
      '${p.tools.length}',
      '${job.attempts',
      "'—' : sem.entry_count}",
      '${d.pid}',
      '${d.memory.free_gb}',
      '${d.memory.total_gb}',
      '${d.analyses.length}',
      '${d.artifacts.length}',
      '${d.functions.total}',
      '${d.validation.summary.',
      '>${d.total}',
      '>${d.loaded}',
      '>${d.skipped}',
      '>${d.errored}',
      '${stage.artifact_count',
      '${stage.accepted_count',
      '${stage.rejected_count',
      '>${semantic.artifact_count',
      '>${semantic.name_suggestion_artifacts',
      '>${semantic.explanation_artifacts',
      '>${semantic.module_review_artifacts',
      '>${semantic.waiting_for_llm_stages',
      '>${semantic.applied_stages',
      '>${semantic.accepted_count',
      '>${semantic.rejected_count',
      '${(run.deferred_jobs',
      '${(run.recoverable_stages',
      '${(run.stages',
    ]
    for (const raw of forbiddenRawInterpolations) {
      expect(page.body).not.toContain(raw)
    }

    // The escaped forms are what remains
    expect(page.body).toContain('${esc(shortSample)}')
    expect(page.body).toContain("${esc(p.version||'—')}")
    expect(page.body).toContain('${esc(p.tool_count)}')
    expect(page.body).toContain('${esc(job.attempts ?? 0)}')
    expect(page.body).toContain("'—' : esc(sem.entry_count)}")

    // Memory percentage is coerced to a finite number and clamped to 0–100
    // before it can reach the progress-bar style width
    expect(page.body).toContain('Number(d.memory.usage_percent)')
    expect(page.body).toMatch(/Math\.min\(Math\.max\(memPctRaw, 0\), 100\)/)
    expect(page.body).not.toContain('const memPct = d.memory.usage_percent')
  })

  test('should escape quotes in esc() so attribute interpolation cannot break out', async () => {
    const page = await httpRequest(`http://localhost:${port}/dashboard?key=secret-key`)
    expect(page.statusCode).toBe(200)
    const { esc } = extractDashboardHelpers(page.body)
    expect(esc('"><img src=x onerror=alert(1)>')).toBe(
      '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;'
    )
    expect(esc("';alert(1);//")).toBe('&#39;;alert(1);//')
    expect(esc(null)).toBe('')
    expect(esc(undefined)).toBe('')
    expect(esc(42)).toBe('42')
  })
})
