/**
 * Unit tests for @rikune/shared exports.
 */

import { afterEach, describe, expect, jest, test } from '@jest/globals'
import type { LookupOptions } from 'node:dns'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  assertTrustedHttpEndpoint,
  TRUSTED_WINDOWS_POWERSHELL_MODULE_PATH_PRELUDE,
  buildWsbXml,
  canonicalHttpOrigin,
  createTrustedFetch,
  createTrustedLookup,
  createRedirectSafeFetch,
  endpointUrl,
  EndpointPolicyError,
  escapeXml,
  getPythonCommand,
  parseHttpServiceEndpoint,
} from '../../../packages/shared/src/index.js'

const activeServers = new Set<Server>()

afterEach(async () => {
  await Promise.all(
    Array.from(activeServers).map(
      (server) =>
        new Promise<void>((resolve) => {
          if (!server.listening) {
            resolve()
            return
          }
          server.close(() => resolve())
        })
    )
  )
  activeServers.clear()
})

function invokeTrustedLookup(
  lookup: ReturnType<typeof createTrustedLookup>,
  options: LookupOptions = {}
): Promise<{ address: unknown; family?: number }> {
  return new Promise((resolve, reject) => {
    lookup('test.example', options, (error, address, family) => {
      if (error) {
        reject(error)
        return
      }
      resolve({ address, family })
    })
  })
}

describe('@rikune/shared', () => {
  test('getPythonCommand prefers override and platform defaults', () => {
    expect(getPythonCommand('win32')).toBe('python')
    expect(getPythonCommand('linux')).toBe('python3')
    expect(getPythonCommand('darwin', '/custom/python')).toBe('/custom/python')
  })

  test('escapeXml escapes reserved characters', () => {
    expect(escapeXml(`a&b<test>\"quote\"'single'`)).toBe(
      'a&amp;b&lt;test&gt;&quot;quote&quot;&apos;single&apos;'
    )
  })

  test('buildWsbXml includes mapped folders, runtime auth, and optional setup folder', () => {
    const xml = buildWsbXml({
      runtimeDirHost: 'C:\\runtime & tools',
      runtimeFileName: 'index.js',
      workersDirHost: 'C:\\workers',
      inboxDir: 'C:\\inbox',
      outboxDir: 'C:\\outbox',
      readyFileSandbox: 'C:\\rikune-outbox\\ready.json',
      runtimeApiKey: 'sandbox-secret',
      setupDirHost: 'C:\\setup',
      nodeDirHost: 'C:\\Program Files\\nodejs',
      nodeFileName: 'node.exe',
      nodeModulesDirHost: 'C:\\project\\node_modules',
      pythonDirHost: 'C:\\Python312',
      pythonFileName: 'python.exe',
    })

    expect(xml).toContain('<Configuration>')
    expect(xml).toContain('&amp;')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-runtime</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-node</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\node_modules</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-python</SandboxFolder>')
    expect(xml).toContain('<SandboxFolder>C:\\rikune-setup</SandboxFolder>')
    expect(xml).toContain('powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand')
    expect(xml).not.toContain('cmd /c')

    const encoded = xml.match(/-EncodedCommand ([A-Za-z0-9+/=]+)/)?.[1]
    expect(encoded).toBeTruthy()
    const script = Buffer.from(encoded || '', 'base64').toString('utf16le')
    expect(script.startsWith(`${TRUSTED_WINDOWS_POWERSHELL_MODULE_PATH_PRELUDE}\r\n`)).toBe(true)
    expect(script).toContain(
      String.raw`$env:SystemRoot + '\System32\WindowsPowerShell\v1.0\Modules'`
    )
    expect(script).toContain("& 'C:\\rikune-setup\\setup-sandbox-env.ps1'")
    expect(script).toContain("$env:RUNTIME_API_KEY = 'sandbox-secret'")
    expect(script).toContain("$env:RUNTIME_PYTHON_PATH = 'C:\\rikune-python\\python.exe'")
    expect(script).toContain("$startupLog = 'C:\\rikune-outbox\\runtime-startup.log'")
    expect(script).toContain(
      "$defenderExclusionPaths = @('C:\\rikune-runtime', 'C:\\rikune-workers', 'C:\\rikune-inbox', 'C:\\rikune-outbox')"
    )
    expect(script).toContain('Add-MpPreference -ExclusionPath $defenderPath')
    expect(script).toContain("Set-Location -LiteralPath 'C:\\rikune-runtime'")
    expect(script).toContain("Start-Process -FilePath 'C:\\rikune-node\\node.exe'")
    expect(script).toContain("'index.js', '--host', '0.0.0.0', '--port', '18081'")
    expect(script).toContain("'--python-path', 'C:\\rikune-python\\python.exe'")
    expect(script).toContain("'--ready-file', 'C:\\rikune-outbox\\ready.json'")
  })

  test('parses only credential-safe HTTP service endpoints', () => {
    expect(canonicalHttpOrigin('HTTP://Example.com:80/')).toBe('http://example.com')
    expect(canonicalHttpOrigin('https://example.com:443')).toBe('https://example.com')
    expect(canonicalHttpOrigin('http://2130706433')).toBe('http://127.0.0.1')

    for (const value of [
      'ftp://example.com',
      'file:///tmp/secret',
      'http://user:password@example.com',
      'http://example.com/?token=secret',
    ]) {
      expect(() => parseHttpServiceEndpoint(value)).toThrow(EndpointPolicyError)
    }
    for (const value of [
      'http://169.254.169.254',
      'http://0xa9fea9fe',
      'http://0251.0376.0251.0376',
      'http://[::ffff:169.254.169.254]',
      'http://[::ffff:a9fe:a9fe]',
      'http://[0:0:0:0:0:ffff:a9fe:a9fe]',
      'http://[fe80::1]',
      'http://0.0.0.0',
    ]) {
      expect(() => assertTrustedHttpEndpoint(value)).toThrow(EndpointPolicyError)
    }
  })

  test('binds configured credentials to the configured origin and permits trusted runtime port changes', () => {
    expect(() =>
      assertTrustedHttpEndpoint('https://attacker.example', {
        configuredEndpoint: 'https://runtime.example:18081',
        credentialSource: 'configured',
      })
    ).toThrow(/configured endpoint origin/)

    expect(
      assertTrustedHttpEndpoint('http://runtime.example:18082', {
        configuredEndpoint: 'http://runtime.example:18081',
        trustedParentEndpoint: 'http://runtime.example:18081',
        allowParentPortChange: true,
        credentialSource: 'configured',
      }).origin
    ).toBe('http://runtime.example:18082')
  })

  test('redirect-safe fetch rejects disallowed origins and forces redirect errors', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: true })
    const originalFetch = globalThis.fetch
    globalThis.fetch = fetchMock as typeof fetch
    try {
      const safeFetch = createRedirectSafeFetch({ allowedOrigins: ['http://runtime.example'] })
      await safeFetch('http://runtime.example/health', {
        headers: { Authorization: 'Bearer test' },
      })
      expect(fetchMock).toHaveBeenCalledWith(
        'http://runtime.example/health',
        expect.objectContaining({ redirect: 'error' })
      )
      await expect(safeFetch('http://attacker.example/health')).rejects.toThrow(/allowlist/)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test('trusted fetch pins the resolver result while preserving the HTTP authority', async () => {
    let receivedHost: string | undefined
    const server = createServer((req, res) => {
      receivedHost = req.headers.host
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: true }))
    })
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', () => resolve())
    })
    activeServers.add(server)
    const port = (server.address() as AddressInfo).port
    const resolver = jest.fn(async () => [{ address: '127.0.0.1', family: 4 }])
    const trustedFetch = createTrustedFetch({
      allowedOrigins: [`http://runtime.test:${port}`],
      resolveEndpointAddresses: resolver,
    })

    try {
      const response = await trustedFetch(`http://runtime.test:${port}/health`, {
        headers: { Authorization: 'Bearer test' },
      })
      expect(response.status).toBe(200)
      await expect(response.json()).resolves.toEqual({ ok: true })
    } finally {
      await trustedFetch.close()
    }

    expect(receivedHost).toBe(`runtime.test:${port}`)
    expect(resolver).toHaveBeenCalledWith('runtime.test', { all: true, verbatim: true })
    await expect(trustedFetch.close()).resolves.toBeUndefined()
    await expect(trustedFetch(`http://runtime.test:${port}/health`)).rejects.toThrow(/closed/)
  })

  test('trusted fetch fails before sending a request when DNS returns metadata', async () => {
    let requests = 0
    const server = createServer((_req, res) => {
      requests += 1
      res.writeHead(200)
      res.end('unexpected')
    })
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', () => resolve())
    })
    activeServers.add(server)
    const port = (server.address() as AddressInfo).port
    const trustedFetch = createTrustedFetch({
      allowedOrigins: [`http://runtime.test:${port}`],
      resolveEndpointAddresses: async () => [{ address: '169.254.169.254', family: 4 }],
    })

    try {
      await expect(trustedFetch(`http://runtime.test:${port}/health`)).rejects.toThrow()
    } finally {
      await trustedFetch.close()
    }
    expect(requests).toBe(0)
  })

  test('treats an explicit empty origin allowlist as deny-all', async () => {
    expect(() =>
      assertTrustedHttpEndpoint('http://runtime.example', { allowedOrigins: [] })
    ).toThrow(/allowlist/)
    expect(() => assertTrustedHttpEndpoint('http://runtime.example')).not.toThrow()

    const fetchMock = jest.fn().mockResolvedValue({ ok: true })
    const originalFetch = globalThis.fetch
    globalThis.fetch = fetchMock as typeof fetch
    try {
      const safeFetch = createRedirectSafeFetch({ allowedOrigins: [] })
      await expect(safeFetch('http://runtime.example/health')).rejects.toThrow(/allowlist/)
      expect(fetchMock).not.toHaveBeenCalled()
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test('endpointUrl cannot rebind a trusted endpoint to another origin', () => {
    expect(endpointUrl('http://runtime.example:18081', '/health')).toBe(
      'http://runtime.example:18081/health'
    )
    expect(() => endpointUrl('http://runtime.example:18081', '//attacker.example/health')).toThrow(
      /must not change/
    )
    expect(() =>
      endpointUrl('http://runtime.example:18081', '\\\\attacker.example/health')
    ).toThrow(/must not change/)
  })

  test('rejects a complete DNS answer when any address is forbidden', async () => {
    const resolver = jest.fn(async () => [
      { address: '192.168.10.20', family: 4 },
      { address: '169.254.169.254', family: 4 },
    ])
    const lookup = createTrustedLookup(resolver)

    await expect(invokeTrustedLookup(lookup, { all: true })).rejects.toThrow(/forbidden/i)
    expect(resolver).toHaveBeenCalledTimes(1)
    expect(resolver).toHaveBeenCalledWith('test.example', { all: true, verbatim: true })
  })

  test('rejects mapped IPv6 answers even when the mapped IPv4 address is safe', async () => {
    const resolver = jest.fn(async () => [{ address: '::ffff:192.168.10.20', family: 6 }])

    await expect(invokeTrustedLookup(createTrustedLookup(resolver))).rejects.toThrow(/forbidden/i)
  })

  test('rejects cloud metadata IPv6 answers', async () => {
    for (const address of ['fd00:ec2::254', 'fd20:ce::254']) {
      const resolver = jest.fn(async () => [{ address, family: 6 }])
      await expect(invokeTrustedLookup(createTrustedLookup(resolver))).rejects.toThrow(/forbidden/i)
    }
  })

  test('fails closed for empty DNS answers and resolver errors', async () => {
    const emptyResolver = jest.fn(async () => [])
    await expect(invokeTrustedLookup(createTrustedLookup(emptyResolver))).rejects.toThrow(
      /no addresses/i
    )

    const resolverError = new Error('resolver unavailable')
    const failingResolver = jest.fn(async () => {
      throw resolverError
    })
    await expect(invokeTrustedLookup(createTrustedLookup(failingResolver))).rejects.toBe(
      resolverError
    )
  })

  test('honors Node family and all lookup semantics after validating the full answer', async () => {
    const addresses = [
      { address: '192.168.10.20', family: 4 },
      { address: '::1', family: 6 },
    ]
    const resolver = jest.fn(async () => addresses)
    const lookup = createTrustedLookup(resolver)

    await expect(invokeTrustedLookup(lookup, { all: true })).resolves.toEqual({
      address: addresses,
      family: undefined,
    })
    await expect(invokeTrustedLookup(lookup, { all: true, family: 4 })).resolves.toEqual({
      address: [addresses[0]],
      family: undefined,
    })
    await expect(invokeTrustedLookup(lookup, { family: 'IPv6' })).resolves.toEqual({
      address: '::1',
      family: 6,
    })
    expect(resolver).toHaveBeenCalledTimes(3)
  })
})
