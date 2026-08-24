/**
 * Unit tests for @rikune/windows-host-agent package metadata.
 */

import { afterEach, describe, expect, jest, test } from '@jest/globals'
import { execFile } from 'child_process'
import fs from 'fs'
import fsp from 'fs/promises'
import os from 'os'
import path from 'path'
import {
  addPortProxy,
  applyRestrictedWindowsAcl,
  createRestrictedSandboxWorkspace,
  createUniqueRestrictedSandboxWorkspace,
  ensureRestrictedSandboxRoot,
  normalizeServerDeadlineMs,
  parsePortProxyRows,
  ProtectedWsbLifecycleError,
  reconcileStaleRikunePortProxyRules,
  removePortProxy,
  removePortProxyAndAuditPort,
  removeSandboxDir,
  resolveRuntimeAdvertisedHost,
  resolveRuntimeApiKey,
  resolveSandboxStartRequestId,
  runProtectedWsbLifecycle,
  runSandboxStartDeadlineGuard,
  validateRuntimeAdvertisedHost,
  verifyRestrictedWindowsAcl,
  verifyWindowsPathNotReparse,
  writeRestrictedWsbFile,
} from '../../../packages/windows-host-agent/src/index.js'

const packageJsonPath = path.resolve(process.cwd(), 'packages/windows-host-agent/package.json')
const sourcePath = path.resolve(process.cwd(), 'packages/windows-host-agent/src/index.ts')
const temporaryDirectories = new Set<string>()

async function createTemporaryDirectory(): Promise<string> {
  const temporaryDirectory = await fsp.mkdtemp(path.join(os.tmpdir(), 'rikune-wsb-test-'))
  temporaryDirectories.add(temporaryDirectory)
  return temporaryDirectory
}

async function fileExists(targetPath: string): Promise<boolean> {
  try {
    await fsp.access(targetPath)
    return true
  } catch {
    return false
  }
}

afterEach(async () => {
  await Promise.all(
    Array.from(temporaryDirectories).map((temporaryDirectory) =>
      fsp.rm(temporaryDirectory, { recursive: true, force: true })
    )
  )
  temporaryDirectories.clear()
})

describe('@rikune/windows-host-agent package', () => {
  test('package scripts expose real lint and test commands', () => {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8')) as {
      scripts?: Record<string, string>
    }

    expect(pkg.scripts?.lint).toBeTruthy()
    expect(pkg.scripts?.lint).not.toContain('No lint configured')
    expect(pkg.scripts?.test).toBeTruthy()
    expect(pkg.scripts?.test).not.toContain('No tests yet')
  })

  test('host agent source exposes sandbox control endpoints and auth gate', () => {
    const source = fs.readFileSync(sourcePath, 'utf-8')

    expect(source).toContain("url.pathname === '/sandbox/start'")
    expect(source).toContain("url.pathname === '/sandbox/stop'")
    expect(source).toContain("url.pathname === '/sandbox/health'")
    expect(source).toContain("url.pathname === '/hyperv/status'")
    expect(source).toContain("url.pathname === '/hyperv/checkpoints'")
    expect(source).toContain("req.method === 'POST' && url.pathname === '/hyperv/checkpoints'")
    expect(source).toContain("url.pathname === '/hyperv/restore'")
    expect(source).toContain("url.pathname === '/hyperv/stop'")
    expect(source).toContain('function requireAuth')
    expect(source).toContain("'127.0.0.1'")
    expect(source).toContain('getHostAgentAuthDefaultError')
    expect(source).toContain('HOST_AGENT_API_KEY is required when NODE_ENV=production')
    expect(source).toContain('HOST_AGENT_BIND_HOST/HOST_AGENT_HOST binds Windows Host Agent')
    expect(source).toContain('HOST_AGENT_RUNTIME_BIND_HOST')
    expect(source).toContain('HOST_AGENT_RUNTIME_ADVERTISED_HOST')
    expect(source).toContain('HOST_AGENT_RUNTIME_API_KEY or RUNTIME_API_KEY is required')
    expect(source).toContain(
      'HOST_AGENT_RUNTIME_API_KEY or RUNTIME_API_KEY must be distinct from HOST_AGENT_API_KEY'
    )
    expect(source).not.toContain(
      'RUNTIME_API_KEY, HOST_AGENT_RUNTIME_API_KEY, or HOST_AGENT_API_KEY is required'
    )
    expect(source).toContain('listenaddress=${listenAddress}')
    expect(source).toContain('buildWsbXml')
    expect(source).toContain('HOST_AGENT_NODE_PATH')
    expect(source).toContain('HOST_AGENT_PYTHON_PATH')
    expect(source).toContain('HOST_AGENT_BACKEND')
    expect(source).toContain('HOST_AGENT_HYPERV_VM_NAME')
    expect(source).toContain('HOST_AGENT_HYPERV_RUNTIME_ENDPOINT')
    expect(source).toContain(
      "assertTrustedHttpEndpoint(endpoint, { label: 'HOST_AGENT_HYPERV_RUNTIME_ENDPOINT' })"
    )
    expect(source).toContain("endpointUrl(endpoint, '/health'")
    expect(source).toContain("redirect: 'error'")
    expect(source).toContain('if (data.ok === true)')
    expect(source).toContain('HOST_AGENT_HYPERV_RESTORE_ON_RELEASE')
    expect(source).toContain('hypervRestoreOnRelease')
    expect(source).toContain('HostAgentStartDiagnostics')
    expect(source).toContain('collectWindowsSandboxDiagnostics')
    expect(source).toContain('getHyperVRuntimeStatus')
    expect(source).toContain('restoreHyperVCheckpoint')
    expect(source).toContain('createHyperVCheckpoint')
    expect(source).toContain('listHyperVCheckpoints')
    expect(source).toContain('Get-VMSnapshot')
    expect(source).toContain('Checkpoint-VM')
    expect(source).toContain('Restore-VMSnapshot')
    expect(source).toContain('runtime-startup.log')
    expect(source).toContain('logonCommandSummary')
    expect(source).toContain('createRestrictedSandboxWorkspace')
    expect(source).toContain('writeRestrictedWsbFile')
    expect(source).toContain('runProtectedWsbLifecycle')
    expect(source).toContain('removeKeyBearingWsbFile')
    const sandboxHealthRoute = source.slice(
      source.indexOf("url.pathname === '/sandbox/health'"),
      source.indexOf("url.pathname === '/hyperv/status'")
    )
    expect(sandboxHealthRoute).not.toContain('getHyperVRuntimeStatus')
  })
})

describe('Windows Host Agent Runtime API key separation', () => {
  const hostAgentApiKey = 'host-agent-secret-that-must-not-be-reused'
  const hostAgentRuntimeApiKey = 'dedicated-host-agent-runtime-secret'
  const runtimeApiKey = 'dedicated-runtime-secret'
  const reuseError =
    'HOST_AGENT_RUNTIME_API_KEY or RUNTIME_API_KEY must be distinct from HOST_AGENT_API_KEY.'

  test('accepts dedicated request and environment Runtime API keys with the documented precedence', () => {
    expect(
      resolveRuntimeApiKey(
        { runtimeApiKey: `  ${runtimeApiKey}  ` },
        {
          HOST_AGENT_RUNTIME_API_KEY: hostAgentApiKey,
          RUNTIME_API_KEY: hostAgentApiKey,
        },
        hostAgentApiKey
      )
    ).toEqual({ runtimeApiKey })
    expect(
      resolveRuntimeApiKey(
        {},
        {
          HOST_AGENT_RUNTIME_API_KEY: hostAgentRuntimeApiKey,
          RUNTIME_API_KEY: runtimeApiKey,
        },
        hostAgentApiKey
      )
    ).toEqual({ runtimeApiKey: hostAgentRuntimeApiKey })
    expect(resolveRuntimeApiKey({}, { RUNTIME_API_KEY: runtimeApiKey }, hostAgentApiKey)).toEqual({
      runtimeApiKey,
    })
  })

  test('does not fall back to HOST_AGENT_API_KEY when no Runtime API key is configured', () => {
    const resolution = resolveRuntimeApiKey(
      {},
      { HOST_AGENT_API_KEY: hostAgentApiKey },
      hostAgentApiKey
    )

    expect(resolution.runtimeApiKey).toBeUndefined()
    expect(resolution.error).toBeUndefined()
  })

  test.each([
    [
      'request.runtimeApiKey',
      { runtimeApiKey: ` ${hostAgentApiKey} ` },
      { HOST_AGENT_RUNTIME_API_KEY: hostAgentRuntimeApiKey },
    ],
    ['HOST_AGENT_RUNTIME_API_KEY', {}, { HOST_AGENT_RUNTIME_API_KEY: hostAgentApiKey }],
    ['RUNTIME_API_KEY', {}, { RUNTIME_API_KEY: hostAgentApiKey }],
  ])('rejects Host Agent key reuse through %s', (_source, request, environment) => {
    expect(resolveRuntimeApiKey(request, environment, hostAgentApiKey)).toEqual({
      error: reuseError,
    })
  })
})

describe('Windows Host Agent sandbox start request correlation', () => {
  test('preserves a canonical requestId and generates one for legacy callers', () => {
    const requestId = 'b2d7f4c1-18aa-4a0e-8c7c-81df0eef683c'

    expect(resolveSandboxStartRequestId(requestId)).toEqual({ requestId })
    expect(resolveSandboxStartRequestId(undefined).requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
    )
  })

  test.each(['', 'not-a-uuid', ' b2d7f4c1-18aa-4a0e-8c7c-81df0eef683c ', 123])(
    'rejects an invalid explicit requestId %j',
    (requestId) => {
      expect(resolveSandboxStartRequestId(requestId)).toEqual({
        error: 'requestId must be a canonical UUID string when provided to /sandbox/start',
      })
    }
  )

  test('exposes requestId in active sandbox health records', () => {
    const source = fs.readFileSync(sourcePath, 'utf-8')

    expect(source).toContain('requestId: b.requestId')
    expect(source).toContain("const START_REQUEST_CORRELATION = 'request-id-v2'")
    expect(source).toContain("url.pathname === '/sandbox/start/status'")
    expect(source).toContain("timeoutScope: 'absolute-start-deadline'")
    expect(source).toContain('requestId?: string')
  })

  test('rejects timeout values that can overflow Node timers', () => {
    expect(() => normalizeServerDeadlineMs(Number.MAX_SAFE_INTEGER, 60_000)).toThrow(
      'Sandbox operation timeout must be an integer between 1000 and 2147483647'
    )
    expect(normalizeServerDeadlineMs(60_000, 30_000)).toBe(60_000)
  })

  test('prevents a late completion from registering after its absolute deadline', async () => {
    const requestId = '6736b177-81ee-4db3-bdec-6709e187c836'
    let releaseLateOperation: () => void = () => {}
    const lateOperation = new Promise<void>((resolve) => {
      releaseLateOperation = resolve
    })
    let registrationAttempted = false
    const guarded = runSandboxStartDeadlineGuard(requestId, 10, async (assertCanRegister) => {
      await lateOperation
      registrationAttempted = true
      assertCanRegister()
      return 'registered'
    })

    await new Promise((resolve) => setTimeout(resolve, 25))
    releaseLateOperation()

    await expect(guarded).rejects.toThrow('expired before active registration')
    expect(registrationAttempted).toBe(true)
  })

  test('retains a correlated cleanup record until failed Windows Sandbox termination settles', () => {
    const source = fs.readFileSync(sourcePath, 'utf-8')
    const cleanupHelperStart = source.indexOf('const cleanupFailedWindowsSandboxStart = async')
    const lifecycleStart = source.indexOf(
      'lifecycle = await runProtectedWsbLifecycle',
      cleanupHelperStart
    )
    const portProxyStart = source.indexOf('try {\n    await addPortProxy', lifecycleStart)
    const failedStartLifecycle = source.slice(cleanupHelperStart, portProxyStart)

    expect(failedStartLifecycle).toContain('trackWindowsSandboxForCleanup(')
    expect(failedStartLifecycle).toContain('requestId,')
    expect(failedStartLifecycle).toContain(
      'terminationAttempt: protectedFailure?.terminationAttempted'
    )
    expect(failedStartLifecycle).toContain("reason: 'runtime_not_ready'")
    expect(failedStartLifecycle).not.toContain('try {\n      sandboxProcess.kill()\n    } catch {}')
  })

  test('keeps Hyper-V active tracking when explicit cleanup fails', () => {
    const source = fs.readFileSync(sourcePath, 'utf-8')
    const stopStart = source.indexOf('async function stopSandbox(')
    const windowsCleanupStart = source.indexOf('const cleanupFailures: string[]', stopStart)
    const hyperVStop = source.slice(stopStart, windowsCleanupStart)

    expect(hyperVStop).toContain('return { ok: false, error }')
    expect(hyperVStop.indexOf('return { ok: false, error }')).toBeLessThan(
      hyperVStop.indexOf('activeSandboxes.delete(sandboxId)')
    )
  })
})

describe('Windows Sandbox advertised endpoint and portproxy hardening', () => {
  test('fails a hung netsh command within its explicit command budget', async () => {
    const hungNetsh = jest.fn(() => new Promise<never>(() => {}))

    await expect(
      reconcileStaleRikunePortProxyRules({
        runNetsh: hungNetsh,
        commandTimeoutMs: 10,
      })
    ).rejects.toThrow('timed out after 10ms')
    expect(hungNetsh).toHaveBeenCalledTimes(1)
  })

  test.each([
    ['host.docker.internal', 'host.docker.internal'],
    ['RUNTIME.EXAMPLE', 'runtime.example'],
    ['127.0.0.1', '127.0.0.1'],
    ['[2001:db8::1]', '2001:db8::1'],
    ['2001:DB8::2', '2001:db8::2'],
  ])('accepts a single advertised host %s', (raw, expected) => {
    expect(validateRuntimeAdvertisedHost(raw)).toBe(expected)
  })

  test.each([
    '',
    ' host.docker.internal',
    'host.docker.internal ',
    'https://host.docker.internal',
    'user@host.docker.internal',
    'host.docker.internal:18081',
    'host.docker.internal/path',
    'host.docker.internal?query',
    'host.docker.internal#fragment',
    'host\nname',
    '[2001:db8::1]:18081',
    'fe80::1%12',
    '999.999.999.999',
    'host..internal',
    '-host.internal',
  ])('rejects unsafe advertised host %j', (raw) => {
    expect(() => validateRuntimeAdvertisedHost(raw)).toThrow(/HOST_AGENT_RUNTIME_ADVERTISED_HOST/u)
  })

  test('uses the protected advertised host independently from the portproxy bind host', () => {
    expect(resolveRuntimeAdvertisedHost('127.0.0.1', 'host.docker.internal')).toBe(
      'host.docker.internal'
    )
    expect(resolveRuntimeAdvertisedHost('127.0.0.1', undefined)).toBe('127.0.0.1')
  })

  test('parses only concrete v4tov4 rows from localized netsh table output', () => {
    const output = [
      'Listen on ipv4:             Connect to ipv4:',
      '',
      'Address         Port        Address         Port',
      '--------------- ----------  --------------- ----------',
      '127.0.0.1       18081       172.28.64.5     18081',
      '0.0.0.0         18082       172.28.64.6     18081',
    ].join('\r\n')

    expect(parsePortProxyRows(output)).toEqual([
      {
        listenAddress: '127.0.0.1',
        listenPort: 18081,
        connectAddress: '172.28.64.5',
        connectPort: 18081,
      },
      {
        listenAddress: '0.0.0.0',
        listenPort: 18082,
        connectAddress: '172.28.64.6',
        connectPort: 18081,
      },
    ])
  })

  test('adds a portproxy only after exact readback and never passes the advertised host to netsh', async () => {
    let row = ''
    const runNetsh = jest.fn(async (args: string[]) => {
      const action = args[2]
      if (action === 'delete') {
        row = ''
      } else if (action === 'add') {
        row = '127.0.0.1 18081 172.28.64.5 18081'
      }
      return { stdout: action === 'show' ? row : '', stderr: '' }
    })

    await addPortProxy('172.28.64.5', 18081, '127.0.0.1', {
      runNetsh,
      wait: async () => {},
    })

    expect(runNetsh).toHaveBeenCalledWith([
      'interface',
      'portproxy',
      'add',
      'v4tov4',
      'listenport=18081',
      'listenaddress=127.0.0.1',
      'connectaddress=172.28.64.5',
      'connectport=18081',
    ])
    expect(runNetsh.mock.calls.flat(2).join(' ')).not.toContain('host.docker.internal')
  })

  test('removes a safely-attributable stale broad Rikune listener before adding loopback', async () => {
    let rows = ['0.0.0.0 18081 172.28.64.5 18081']
    const runNetsh = jest.fn(async (args: string[]) => {
      const action = args[2]
      const listenAddress = args.find((arg) => arg.startsWith('listenaddress='))?.split('=')[1]
      if (action === 'delete' && listenAddress) {
        rows = rows.filter((row) => !row.startsWith(`${listenAddress} 18081 `))
      } else if (action === 'add') {
        rows.push('127.0.0.1 18081 172.28.64.5 18081')
      }
      return { stdout: action === 'show' ? rows.join('\r\n') : '', stderr: '' }
    })

    await addPortProxy('172.28.64.5', 18081, '127.0.0.1', {
      runNetsh,
      wait: async () => {},
    })

    expect(
      runNetsh.mock.calls.some(
        ([args]) => args[2] === 'delete' && args.includes('listenaddress=0.0.0.0')
      )
    ).toBe(true)
    expect(rows).toEqual(['127.0.0.1 18081 172.28.64.5 18081'])
  })

  test('fails closed without deleting a broad same-port listener owned by an unknown target', async () => {
    const broadRow = '0.0.0.0 18081 172.28.64.99 18081'
    let rows = [broadRow]
    const runNetsh = jest.fn(async (args: string[]) => {
      const action = args[2]
      const listenAddress = args.find((arg) => arg.startsWith('listenaddress='))?.split('=')[1]
      if (action === 'delete' && listenAddress === '127.0.0.1') {
        rows = rows.filter((row) => !row.startsWith('127.0.0.1 18081 '))
      }
      return { stdout: action === 'show' ? rows.join('\r\n') : '', stderr: '' }
    })

    await expect(
      addPortProxy('172.28.64.5', 18081, '127.0.0.1', {
        runNetsh,
        wait: async () => {},
      })
    ).rejects.toThrow('non-exact netsh portproxy listeners')

    expect(rows).toEqual([broadRow])
    expect(runNetsh.mock.calls.some(([args]) => args[2] === 'add')).toBe(false)
    expect(
      runNetsh.mock.calls.some(
        ([args]) => args[2] === 'delete' && args.includes('listenaddress=0.0.0.0')
      )
    ).toBe(false)
  })

  test('rejects readback containing both loopback and broad listeners on the same port', async () => {
    let rows: string[] = []
    const broadRow = '0.0.0.0 18081 172.28.64.5 18081'
    const runNetsh = jest.fn(async (args: string[]) => {
      const action = args[2]
      const listenAddress = args.find((arg) => arg.startsWith('listenaddress='))?.split('=')[1]
      if (action === 'delete' && listenAddress) {
        rows = rows.filter((row) => !row.startsWith(`${listenAddress} 18081 `))
      } else if (action === 'add') {
        rows = ['127.0.0.1 18081 172.28.64.5 18081', broadRow]
      }
      return { stdout: action === 'show' ? rows.join('\r\n') : '', stderr: '' }
    })

    await expect(
      addPortProxy('172.28.64.5', 18081, '127.0.0.1', {
        runNetsh,
        wait: async () => {},
      })
    ).rejects.toThrow('exact readback mismatch')

    expect(rows).toEqual([])
  })

  test('fails and removes a partially-added proxy when exact readback mismatches', async () => {
    let added = false
    let cleanupDeleteSeen = false
    const runNetsh = jest.fn(async (args: string[]) => {
      const action = args[2]
      if (action === 'add') {
        added = true
      }
      if (action === 'delete' && added) {
        cleanupDeleteSeen = true
      }
      if (action === 'show' && added && !cleanupDeleteSeen) {
        return { stdout: '127.0.0.1 18081 172.28.64.99 18081', stderr: '' }
      }
      return { stdout: '', stderr: '' }
    })

    await expect(
      addPortProxy('172.28.64.5', 18081, '127.0.0.1', {
        runNetsh,
        wait: async () => {},
      })
    ).rejects.toThrow('exact readback mismatch')

    expect(cleanupDeleteSeen).toBe(true)
  })

  test('retries portproxy deletion until readback proves the listener is absent', async () => {
    let deleteAttempts = 0
    const wait = jest.fn(async () => {})
    const runNetsh = jest.fn(async (args: string[]) => {
      if (args[2] === 'delete') {
        deleteAttempts += 1
      }
      const stillPresent = deleteAttempts < 3
      return {
        stdout: args[2] === 'show' && stillPresent ? '127.0.0.1 18081 172.28.64.5 18081' : '',
        stderr: '',
      }
    })

    await removePortProxy(18081, '127.0.0.1', { runNetsh, wait })

    expect(deleteAttempts).toBe(3)
    expect(wait).toHaveBeenCalledTimes(2)
  })

  test('stop-style cleanup fails explicitly when an unknown broad listener remains', async () => {
    let rows = ['127.0.0.1 18081 172.28.64.5 18081', '0.0.0.0 18081 172.28.64.99 18081']
    const runNetsh = jest.fn(async (args: string[]) => {
      const action = args[2]
      const listenAddress = args.find((arg) => arg.startsWith('listenaddress='))?.split('=')[1]
      if (action === 'delete' && listenAddress) {
        rows = rows.filter((row) => !row.startsWith(`${listenAddress} 18081 `))
      }
      return { stdout: action === 'show' ? rows.join('\r\n') : '', stderr: '' }
    })

    await expect(
      removePortProxyAndAuditPort(18081, '127.0.0.1', '172.28.64.5', {
        runNetsh,
        wait: async () => {},
      })
    ).rejects.toThrow('non-exact netsh portproxy listeners')

    expect(rows).toEqual(['127.0.0.1 18081 172.28.64.5 18081', '0.0.0.0 18081 172.28.64.99 18081'])
    expect(runNetsh.mock.calls.some(([args]) => args[2] === 'delete')).toBe(false)
  })

  test('startup reconciliation removes only reserved-range private Rikune listeners', async () => {
    let rows = ['0.0.0.0 18081 172.28.64.5 18081', '127.0.0.1 19001 172.28.64.6 18081']
    const runNetsh = jest.fn(async (args: string[]) => {
      const action = args[2]
      const listenPort = args.find((arg) => arg.startsWith('listenport='))?.split('=')[1]
      const listenAddress = args.find((arg) => arg.startsWith('listenaddress='))?.split('=')[1]
      if (action === 'delete' && listenPort && listenAddress) {
        rows = rows.filter((row) => !row.startsWith(`${listenAddress} ${listenPort} `))
      }
      return { stdout: action === 'show' ? rows.join('\r\n') : '', stderr: '' }
    })

    await reconcileStaleRikunePortProxyRules({ runNetsh, wait: async () => {} })

    expect(rows).toEqual(['127.0.0.1 19001 172.28.64.6 18081'])
  })

  test('startup reconciliation does not delete unknown listeners in the reserved range', async () => {
    const row = '0.0.0.0 18081 203.0.113.8 18081'
    const runNetsh = jest.fn(async (args: string[]) => ({
      stdout: args[2] === 'show' ? row : '',
      stderr: '',
    }))

    await expect(
      reconcileStaleRikunePortProxyRules({ runNetsh, wait: async () => {} })
    ).rejects.toThrow('unknown ownership')

    expect(runNetsh.mock.calls.some(([args]) => args[2] === 'delete')).toBe(false)
  })

  test('returns an explicit failure when a portproxy survives every delete retry', async () => {
    const runNetsh = jest.fn(async (args: string[]) => ({
      stdout: args[2] === 'show' ? '127.0.0.1 18081 172.28.64.5 18081' : '',
      stderr: '',
    }))

    await expect(
      removePortProxy(18081, '127.0.0.1', {
        runNetsh,
        wait: async () => {},
      })
    ).rejects.toThrow('Unable to remove and verify netsh portproxy rule')

    expect(runNetsh.mock.calls.filter(([args]) => args[2] === 'delete')).toHaveLength(3)
  })

  test('fails closed when netsh readback is non-empty but cannot be parsed', async () => {
    const runNetsh = jest.fn(async (args: string[]) => ({
      stdout: args[2] === 'show' ? 'unexpected localized output without a table' : '',
      stderr: '',
    }))

    await expect(
      removePortProxy(18081, '127.0.0.1', {
        runNetsh,
        wait: async () => {},
      })
    ).rejects.toThrow('Unable to parse netsh portproxy show v4tov4 output')
  })
})

describe('Windows Sandbox key-bearing config hardening', () => {
  test('builds a fail-closed ACL for the current user, SYSTEM, and Administrators', async () => {
    const runCommand = jest.fn(async (command: string) => {
      if (command === 'whoami.exe') {
        return { stdout: '"DOMAIN\\user","S-1-5-21-111-222-333-1001"\r\n', stderr: '' }
      }
      if (command === 'powershell.exe') {
        return {
          stdout: JSON.stringify({
            OwnerSid: 'S-1-5-21-111-222-333-1001',
            Protected: true,
            Rules: [
              {
                Sid: 'S-1-5-21-111-222-333-1001',
                Type: 'Allow',
                Rights: 'FullControl',
                Inherited: false,
              },
              { Sid: 'S-1-5-18', Type: 'Allow', Rights: 'FullControl', Inherited: false },
              {
                Sid: 'S-1-5-32-544',
                Type: 'Allow',
                Rights: 'FullControl',
                Inherited: false,
              },
            ],
          }),
          stderr: '',
        }
      }
      return { stdout: 'Successfully processed 1 files', stderr: '' }
    })

    await applyRestrictedWindowsAcl('C:\\restricted\\runtime.wsb', false, {
      platform: 'win32',
      runCommand,
    })

    expect(runCommand).toHaveBeenNthCalledWith(1, 'whoami.exe', ['/user', '/fo', 'csv', '/nh'])
    expect(runCommand).toHaveBeenNthCalledWith(2, 'icacls.exe', [
      'C:\\restricted\\runtime.wsb',
      '/setowner',
      '*S-1-5-21-111-222-333-1001',
    ])
    expect(runCommand).toHaveBeenNthCalledWith(3, 'icacls.exe', [
      'C:\\restricted\\runtime.wsb',
      '/reset',
    ])
    expect(runCommand).toHaveBeenNthCalledWith(4, 'icacls.exe', [
      'C:\\restricted\\runtime.wsb',
      '/inheritance:r',
      '/grant:r',
      '*S-1-5-21-111-222-333-1001:(F)',
      '*S-1-5-18:(F)',
      '*S-1-5-32-544:(F)',
    ])
    expect(runCommand).toHaveBeenNthCalledWith(
      5,
      'powershell.exe',
      expect.arrayContaining(['-NoProfile', '-NonInteractive', '-Command'])
    )
  })

  test('rejects an explicit Everyone allow ACE during normalized verification', async () => {
    const runCommand = jest.fn(async () => ({
      stdout: JSON.stringify({
        OwnerSid: 'S-1-5-21-111-222-333-1001',
        Protected: true,
        Rules: [
          {
            Sid: 'S-1-5-21-111-222-333-1001',
            Type: 'Allow',
            Rights: 'FullControl',
            Inherited: false,
          },
          { Sid: 'S-1-5-18', Type: 'Allow', Rights: 'FullControl', Inherited: false },
          { Sid: 'S-1-5-32-544', Type: 'Allow', Rights: 'FullControl', Inherited: false },
          { Sid: 'S-1-1-0', Type: 'Allow', Rights: 'FullControl', Inherited: false },
        ],
      }),
      stderr: '',
    }))

    await expect(
      verifyRestrictedWindowsAcl('C:\\restricted\\runtime.wsb', false, {
        platform: 'win32',
        currentUserSid: 'S-1-5-21-111-222-333-1001',
        runCommand,
      })
    ).rejects.toThrow('exact protected three-principal allowlist')
  })

  test('checks both lstat and Windows ReparsePoint attributes', async () => {
    const runCommand = jest.fn(async () => ({ stdout: 'Directory:SAFE\r\n', stderr: '' }))

    await verifyWindowsPathNotReparse('C:\\restricted\\sandbox', true, {
      platform: 'win32',
      lstat: async () => ({ isDirectory: () => true, isSymbolicLink: () => false }),
      runCommand,
    })

    const commandArgs = runCommand.mock.calls[0]?.[1] as string[]
    expect(commandArgs.join(' ')).toContain('ReparsePoint')
    expect(commandArgs.join(' ')).toContain('Directory')
  })

  test('never accepts or removes a pre-created UUID leaf', async () => {
    const temporaryDirectory = await createTemporaryDirectory()
    const sandboxRoot = path.join(temporaryDirectory, 'sandbox')
    const sandboxDir = path.join(sandboxRoot, 'precreated-uuid')
    const markerPath = path.join(sandboxDir, 'attacker-marker')
    const acl = {
      applyRestrictedAcl: jest.fn(async () => {}),
      verifyRestrictedAcl: jest.fn(async () => {}),
    }
    await ensureRestrictedSandboxRoot(sandboxRoot, acl)
    await fsp.mkdir(sandboxDir)
    await fsp.writeFile(markerPath, 'must-survive', 'utf8')

    await expect(createRestrictedSandboxWorkspace(sandboxDir, acl)).rejects.toMatchObject({
      code: 'EEXIST',
    })

    await expect(fsp.readFile(markerPath, 'utf8')).resolves.toBe('must-survive')
  })

  test('rejects a pre-created reparse sandbox root before applying an ACL', async () => {
    const temporaryDirectory = await createTemporaryDirectory()
    const outsideDirectory = path.join(temporaryDirectory, 'outside-root')
    const sandboxRoot = path.join(temporaryDirectory, 'sandbox')
    const outsideMarker = path.join(outsideDirectory, 'marker')
    const applyRestrictedAcl = jest.fn(async () => {})
    await fsp.mkdir(outsideDirectory)
    await fsp.writeFile(outsideMarker, 'outside-root-must-survive', 'utf8')
    await fsp.symlink(outsideDirectory, sandboxRoot, 'dir')

    await expect(ensureRestrictedSandboxRoot(sandboxRoot, { applyRestrictedAcl })).rejects.toThrow(
      'symlink or reparse point'
    )

    expect(applyRestrictedAcl).not.toHaveBeenCalled()
    await expect(fsp.readFile(outsideMarker, 'utf8')).resolves.toBe('outside-root-must-survive')
  })

  test('refuses to create a leaf when the workspace parent ACL is not exact', async () => {
    const workspaceRoot = await createTemporaryDirectory()
    const sandboxRoot = path.join(workspaceRoot, 'sandbox')
    const sandboxDir = path.join(sandboxRoot, 'fresh-uuid')
    await fsp.mkdir(sandboxRoot)
    const mkdir = jest.fn(async (targetPath: string, options: { recursive: false }) => {
      await fsp.mkdir(targetPath, options)
    })

    await expect(
      createRestrictedSandboxWorkspace(sandboxDir, {
        mkdir,
        verifyRestrictedAcl: async (targetPath) => {
          if (targetPath === workspaceRoot) {
            throw new Error('workspace parent ACL denied')
          }
        },
      })
    ).rejects.toThrow('workspace parent ACL denied')

    expect(mkdir).not.toHaveBeenCalled()
    expect(await fileExists(sandboxDir)).toBe(false)
  })

  test('rotates UUIDs on EEXIST and creates only a new restricted leaf', async () => {
    const temporaryDirectory = await createTemporaryDirectory()
    const sandboxRoot = path.join(temporaryDirectory, 'sandbox')
    const collisionDir = path.join(sandboxRoot, 'collision')
    const collisionMarker = path.join(collisionDir, 'marker')
    const acl = {
      applyRestrictedAcl: jest.fn(async () => {}),
      verifyRestrictedAcl: jest.fn(async () => {}),
    }
    await ensureRestrictedSandboxRoot(sandboxRoot, acl)
    await fsp.mkdir(collisionDir)
    await fsp.writeFile(collisionMarker, 'pre-existing', 'utf8')
    const ids = ['collision', 'fresh-uuid']

    const sandboxDir = await createUniqueRestrictedSandboxWorkspace(sandboxRoot, {
      ...acl,
      randomId: () => ids.shift() || 'unexpected',
    })

    expect(sandboxDir).toBe(path.join(sandboxRoot, 'fresh-uuid'))
    await expect(fsp.readFile(collisionMarker, 'utf8')).resolves.toBe('pre-existing')
    expect(await fsp.readdir(sandboxDir)).toEqual(['inbox', 'outbox'])
  })

  test('rejects a junction-like leaf race before applying an ACL or writing a secret', async () => {
    const temporaryDirectory = await createTemporaryDirectory()
    const sandboxRoot = path.join(temporaryDirectory, 'sandbox')
    const outsideDirectory = path.join(temporaryDirectory, 'outside')
    const sandboxDir = path.join(sandboxRoot, 'raced-uuid')
    const outsideMarker = path.join(outsideDirectory, 'outside-marker')
    const applyRestrictedAcl = jest.fn(async () => {})
    const verifyRestrictedAcl = jest.fn(async () => {})
    await fsp.mkdir(outsideDirectory)
    await fsp.writeFile(outsideMarker, 'outside-must-survive', 'utf8')
    await ensureRestrictedSandboxRoot(sandboxRoot, {
      applyRestrictedAcl,
      verifyRestrictedAcl,
    })
    applyRestrictedAcl.mockClear()

    await expect(
      createRestrictedSandboxWorkspace(sandboxDir, {
        applyRestrictedAcl,
        verifyRestrictedAcl,
        mkdir: async (targetPath, options) => {
          if (targetPath === sandboxDir) {
            await fsp.symlink(outsideDirectory, targetPath, 'dir')
            return
          }
          await fsp.mkdir(targetPath, options)
        },
      })
    ).rejects.toThrow('symlink or reparse point')

    expect(applyRestrictedAcl).not.toHaveBeenCalled()
    await expect(fsp.readFile(outsideMarker, 'utf8')).resolves.toBe('outside-must-survive')
  })

  test('fails closed on a leaf reparse check before preparing the key-bearing WSB', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const prepareWsb = jest.fn(async () => undefined)
    const spawnSandbox = jest.fn(() => ({ kill: jest.fn() }))

    await expect(
      runProtectedWsbLifecycle({
        sandboxDir,
        wsbPath,
        verifyRestrictedAcl: async () => {},
        verifyNotReparse: async (targetPath) => {
          if (targetPath === sandboxDir) {
            throw new Error('symlink or reparse point')
          }
        },
        prepareWsb,
        spawnSandbox,
        waitUntilReady: async () => ({ host: '127.0.0.1' }),
      })
    ).rejects.toThrow('symlink or reparse point')

    expect(prepareWsb).not.toHaveBeenCalled()
    expect(spawnSandbox).not.toHaveBeenCalled()
    expect(await fileExists(wsbPath)).toBe(false)
  })

  test('writes the secret only after the temporary file ACL is restricted', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const secret = 'runtime-secret-sentinel'
    const aclSnapshots: Array<{ phase: string; targetPath: string; content: string }> = []
    const applyRestrictedAcl = jest.fn(async (targetPath: string) => {
      aclSnapshots.push({
        phase: 'apply',
        targetPath,
        content: await fsp.readFile(targetPath, 'utf8'),
      })
    })
    const verifyRestrictedAcl = jest.fn(async (targetPath: string) => {
      aclSnapshots.push({
        phase: 'verify',
        targetPath,
        content: await fsp.readFile(targetPath, 'utf8'),
      })
    })

    await writeRestrictedWsbFile(wsbPath, `<Command>${secret}</Command>`, {
      applyRestrictedAcl,
      verifyRestrictedAcl,
      randomId: () => 'deterministic',
    })

    expect(aclSnapshots).toHaveLength(2)
    expect(aclSnapshots[0]?.targetPath).toContain('.runtime.wsb.')
    expect(aclSnapshots[0]?.phase).toBe('apply')
    expect(aclSnapshots[0]?.content).toBe('')
    expect(aclSnapshots[1]).toEqual({
      phase: 'verify',
      targetPath: wsbPath,
      content: `<Command>${secret}</Command>`,
    })
    await expect(fsp.readFile(wsbPath, 'utf8')).resolves.toContain(secret)
  })

  test('does not create a key-bearing temp file when the leaf parent becomes a reparse point', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const open = jest.fn(async () => {
      throw new Error('open must not run')
    })

    await expect(
      writeRestrictedWsbFile(wsbPath, 'secret-must-never-land', {
        verifyParentDirectory: async () => {
          throw new Error('symlink or reparse point')
        },
        open,
      })
    ).rejects.toThrow('symlink or reparse point')

    expect(open).not.toHaveBeenCalled()
    expect(await fileExists(wsbPath)).toBe(false)
  })

  test('does not prepare or spawn when the sandbox directory ACL fails', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const prepareWsb = jest.fn(async () => undefined)
    const spawnSandbox = jest.fn(() => ({ kill: jest.fn() }))

    await expect(
      runProtectedWsbLifecycle({
        sandboxDir,
        wsbPath,
        verifyRestrictedAcl: async () => {
          throw new Error('ACL denied')
        },
        prepareWsb,
        spawnSandbox,
        waitUntilReady: async () => ({ host: '127.0.0.1' }),
      })
    ).rejects.toThrow('ACL denied')

    expect(prepareWsb).not.toHaveBeenCalled()
    expect(spawnSandbox).not.toHaveBeenCalled()
    expect(await fileExists(wsbPath)).toBe(false)
  })

  test('does not spawn or leave a temporary config when the file ACL fails', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const spawnSandbox = jest.fn(() => ({ kill: jest.fn() }))
    const applyRestrictedAcl = jest.fn(async (_targetPath: string, isDirectory: boolean) => {
      if (!isDirectory) {
        throw new Error('file ACL denied')
      }
    })

    await expect(
      runProtectedWsbLifecycle({
        sandboxDir,
        wsbPath,
        verifyRestrictedAcl: async () => {},
        prepareWsb: async () => {
          await writeRestrictedWsbFile(wsbPath, 'key-must-never-land', {
            applyRestrictedAcl,
            randomId: () => 'acl-failure',
          })
          return undefined
        },
        spawnSandbox,
        waitUntilReady: async () => ({ host: '127.0.0.1' }),
      })
    ).rejects.toThrow('file ACL denied')

    expect(spawnSandbox).not.toHaveBeenCalled()
    expect(await fsp.readdir(sandboxDir)).toEqual([])
  })

  test.each([
    ['runtime ready', { host: '127.0.0.1' }],
    ['runtime not ready', null],
  ])('removes the key-bearing WSB after %s', async (_label, readyValue) => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const applyRestrictedAcl = jest.fn(async () => {})
    const verifyRestrictedAcl = jest.fn(async () => {})
    const sandboxProcess = { kill: jest.fn(() => true) }
    const spawnSandbox = jest.fn(() => sandboxProcess)

    const result = await runProtectedWsbLifecycle({
      sandboxDir,
      wsbPath,
      verifyRestrictedAcl,
      prepareWsb: async () => {
        await writeRestrictedWsbFile(wsbPath, 'key-bearing-wsb', {
          applyRestrictedAcl,
          verifyRestrictedAcl,
        })
        return { protected: true }
      },
      spawnSandbox,
      waitUntilReady: async () => readyValue,
      killProcess: (child) => child.kill(),
    })

    expect(result.ready).toEqual(readyValue)
    expect(spawnSandbox).toHaveBeenCalledWith(wsbPath)
    expect(await fileExists(wsbPath)).toBe(false)
  })

  test('kills the Sandbox and removes the WSB when readiness throws', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const applyRestrictedAcl = jest.fn(async () => {})
    const verifyRestrictedAcl = jest.fn(async () => {})
    const sandboxProcess = { kill: jest.fn(() => true) }

    await expect(
      runProtectedWsbLifecycle({
        sandboxDir,
        wsbPath,
        verifyRestrictedAcl,
        prepareWsb: async () => {
          await writeRestrictedWsbFile(wsbPath, 'key-bearing-wsb', {
            applyRestrictedAcl,
            verifyRestrictedAcl,
          })
          return undefined
        },
        spawnSandbox: () => sandboxProcess,
        waitUntilReady: async () => {
          throw new Error('readiness failed')
        },
        killProcess: (child) => child.kill(),
      })
    ).rejects.toThrow('readiness failed')

    expect(sandboxProcess.kill).toHaveBeenCalledTimes(1)
    expect(await fileExists(wsbPath)).toBe(false)
  })

  test('reports a rejected kill signal once and preserves the unconfirmed process state', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const sandboxProcess = { kill: jest.fn(() => false) }

    let failure: unknown
    try {
      await runProtectedWsbLifecycle({
        sandboxDir,
        wsbPath,
        verifyRestrictedAcl: async () => {},
        prepareWsb: async () => {
          await fsp.writeFile(wsbPath, 'key-bearing-wsb', 'utf8')
        },
        spawnSandbox: () => sandboxProcess,
        waitUntilReady: async () => {
          throw new Error('readiness failed')
        },
        killProcess: (child) => child.kill(),
        isProcessTerminated: () => false,
      })
    } catch (error) {
      failure = error
    }

    expect(failure).toBeInstanceOf(ProtectedWsbLifecycleError)
    expect(failure).toMatchObject({
      sandboxProcess,
      terminationAttempted: true,
      terminationSignalAccepted: false,
      terminationConfirmed: false,
    })
    expect((failure as Error).message).toContain('rejected the termination signal')
    expect(sandboxProcess.kill).toHaveBeenCalledTimes(1)
    expect(await fileExists(wsbPath)).toBe(false)
  })

  test('propagates a thrown kill failure once instead of swallowing it', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const sandboxProcess = {
      kill: jest.fn((): boolean => {
        throw new Error('kill exploded')
      }),
    }

    await expect(
      runProtectedWsbLifecycle({
        sandboxDir,
        wsbPath,
        verifyRestrictedAcl: async () => {},
        prepareWsb: async () => {
          await fsp.writeFile(wsbPath, 'key-bearing-wsb', 'utf8')
        },
        spawnSandbox: () => sandboxProcess,
        waitUntilReady: async () => {
          throw new Error('readiness failed')
        },
        killProcess: (child) => child.kill(),
        isProcessTerminated: () => false,
      })
    ).rejects.toThrow('kill exploded')

    expect(sandboxProcess.kill).toHaveBeenCalledTimes(1)
    expect(await fileExists(wsbPath)).toBe(false)
  })

  test('does not retry kill when readiness and key-bearing file cleanup both fail', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const sandboxProcess = { kill: jest.fn(() => false) }

    await expect(
      runProtectedWsbLifecycle({
        sandboxDir,
        wsbPath,
        verifyRestrictedAcl: async () => {},
        prepareWsb: async () => {
          await fsp.mkdir(wsbPath)
        },
        spawnSandbox: () => sandboxProcess,
        waitUntilReady: async () => {
          throw new Error('readiness failed')
        },
        killProcess: (child) => child.kill(),
        isProcessTerminated: () => false,
      })
    ).rejects.toThrow('Key-bearing WSB cleanup failed')

    expect(sandboxProcess.kill).toHaveBeenCalledTimes(1)
  })

  test('does not kill or retain an already terminated process as unconfirmed', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const sandboxProcess = { kill: jest.fn(() => false) }

    let failure: unknown
    try {
      await runProtectedWsbLifecycle({
        sandboxDir,
        wsbPath,
        verifyRestrictedAcl: async () => {},
        prepareWsb: async () => {
          await fsp.writeFile(wsbPath, 'key-bearing-wsb', 'utf8')
        },
        spawnSandbox: () => sandboxProcess,
        waitUntilReady: async () => {
          throw new Error('readiness failed after process exit')
        },
        killProcess: (child) => child.kill(),
        isProcessTerminated: () => true,
      })
    } catch (error) {
      failure = error
    }

    expect(failure).toBeInstanceOf(ProtectedWsbLifecycleError)
    expect(failure).toMatchObject({
      sandboxProcess,
      terminationAttempted: false,
      terminationConfirmed: true,
    })
    expect((failure as Error).message).not.toContain('termination was not confirmed')
    expect(sandboxProcess.kill).not.toHaveBeenCalled()
    expect(await fileExists(wsbPath)).toBe(false)
  })

  test('KEEP_FAILED retains diagnostics but never retains runtime.wsb', async () => {
    const sandboxDir = await createTemporaryDirectory()
    const wsbPath = path.join(sandboxDir, 'runtime.wsb')
    const diagnosticPath = path.join(sandboxDir, 'diagnostic.log')
    await fsp.writeFile(wsbPath, 'long-lived-api-key', 'utf8')
    await fsp.writeFile(diagnosticPath, 'safe diagnostics', 'utf8')
    const previous = process.env.HOST_AGENT_KEEP_FAILED_SANDBOX
    process.env.HOST_AGENT_KEEP_FAILED_SANDBOX = 'true'

    try {
      await removeSandboxDir(sandboxDir, 'unit_test_failure')
    } finally {
      if (previous === undefined) {
        delete process.env.HOST_AGENT_KEEP_FAILED_SANDBOX
      } else {
        process.env.HOST_AGENT_KEEP_FAILED_SANDBOX = previous
      }
    }

    expect(await fileExists(sandboxDir)).toBe(true)
    expect(await fileExists(wsbPath)).toBe(false)
    await expect(fsp.readFile(diagnosticPath, 'utf8')).resolves.toBe('safe diagnostics')
  })

  test('cleanup refuses a swapped sandbox leaf before touching an external runtime.wsb', async () => {
    const temporaryDirectory = await createTemporaryDirectory()
    const outsideDirectory = path.join(temporaryDirectory, 'outside')
    const sandboxDir = path.join(temporaryDirectory, 'sandbox-junction')
    const externalWsb = path.join(outsideDirectory, 'runtime.wsb')
    await fsp.mkdir(outsideDirectory)
    await fsp.writeFile(externalWsb, 'external-secret-must-survive', 'utf8')
    await fsp.symlink(outsideDirectory, sandboxDir, 'dir')

    await expect(removeSandboxDir(sandboxDir, 'swapped_leaf')).rejects.toThrow(
      'symlink or reparse point'
    )

    await expect(fsp.readFile(externalWsb, 'utf8')).resolves.toBe('external-secret-must-survive')
  })

  const windowsOnlyTest = process.platform === 'win32' ? test : test.skip
  windowsOnlyTest('removes explicit Everyone ACEs from directory and file fixtures', async () => {
    const temporaryDirectory = await createTemporaryDirectory()
    const sandboxRoot = path.join(temporaryDirectory, 'sandbox')
    const sandboxDir = path.join(sandboxRoot, 'fresh-uuid')
    const runIcacls = (args: string[]) =>
      new Promise<string>((resolve, reject) => {
        execFile('icacls.exe', args, { windowsHide: true }, (error, stdout) => {
          if (error) {
            reject(error)
            return
          }
          resolve(stdout.toString())
        })
      })

    await applyRestrictedWindowsAcl(temporaryDirectory, true)
    await ensureRestrictedSandboxRoot(sandboxRoot)
    await createRestrictedSandboxWorkspace(sandboxDir)
    await runIcacls([sandboxDir, '/grant', '*S-1-1-0:(OI)(CI)F'])
    await applyRestrictedWindowsAcl(sandboxDir, true)
    await verifyRestrictedWindowsAcl(sandboxDir, true)

    const filePath = path.join(sandboxDir, 'explicit-everyone.fixture')
    await fsp.writeFile(filePath, '', 'utf8')
    await runIcacls([filePath, '/grant', '*S-1-1-0:(F)'])
    await applyRestrictedWindowsAcl(filePath, false)
    await verifyRestrictedWindowsAcl(filePath, false)

    expect(await runIcacls([sandboxDir])).not.toContain('(I)')
    expect(await runIcacls([filePath])).not.toContain('(I)')
  })
})
