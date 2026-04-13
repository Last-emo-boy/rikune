/**
 * hash.identify — Identify which hash algorithm was used to produce a given set of API hashes.
 *
 * Brute-forces all supported algorithms against the common API name list
 * and reports which algorithm yields the most matches.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  SharedMetricsSchema,
  normalizeError, runPythonJson,
  buildMetrics,
  resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'hash.identify'

export const hashIdentifyInputSchema = z.object({
  hashes: z.array(z.string()).min(1).max(50).describe('Hex hash values to test (e.g. ["0x6A4ABC5B"]).'),
  unicode: z.boolean().default(false).describe('Also try Unicode (UTF-16LE) API names.'),
})

export const hashIdentifyOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    candidates: z.array(z.object({
      algorithm: z.string(),
      matches: z.number(),
      total: z.number(),
      match_rate: z.number(),
      sample_matches: z.array(z.object({ hash: z.string(), api: z.string() })),
    })).optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const hashIdentifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Identify the hash algorithm used to produce shellcode API hashes by brute-force matching against known APIs.',
  inputSchema: hashIdentifyInputSchema,
  outputSchema: hashIdentifyOutputSchema,
}

const PYTHON_SCRIPT = `
import json, sys

COMMON_APIS = [
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc", "VirtualAllocEx",
    "VirtualProtect", "VirtualFree", "CreateProcessA", "CreateProcessW",
    "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
    "CloseHandle", "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
    "GetModuleHandleA", "GetModuleHandleW", "ExitProcess", "TerminateProcess", "Sleep",
    "WaitForSingleObject", "GetLastError", "CreateThread", "ExitThread",
    "RegOpenKeyExA", "RegSetValueExA", "RegQueryValueExA", "RegCloseKey",
    "InternetOpenA", "InternetOpenUrlA", "InternetReadFile", "InternetConnectA",
    "HttpOpenRequestA", "HttpSendRequestA", "WSAStartup", "socket", "connect",
    "send", "recv", "closesocket", "bind", "listen", "accept", "gethostbyname",
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx",
    "NtQueryInformationProcess", "LdrLoadDll", "LdrGetProcedureAddress",
    "IsDebuggerPresent", "GetComputerNameA", "GetUserNameA",
    "URLDownloadToFileA", "ShellExecuteA", "HeapAlloc", "HeapFree",
    "GetCurrentProcess", "GetCurrentProcessId",
]

COMMON_DLLS = [
    "kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll", "ws2_32.dll",
    "wininet.dll", "winhttp.dll", "shell32.dll", "ole32.dll", "urlmon.dll",
    "msvcrt.dll", "crypt32.dll",
]

def ror13_hash(name, u=False):
    h = 0
    d = name.encode('utf-16-le') if u else name.encode('ascii')
    for b in d:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + b) & 0xFFFFFFFF
    return h

def ror13_additive(dll, api, u=False):
    return (ror13_hash(dll.upper(), u) + ror13_hash(api, u)) & 0xFFFFFFFF

def crc32_hash(name, u=False):
    import binascii
    d = name.encode('utf-16-le') if u else name.encode('ascii')
    return binascii.crc32(d) & 0xFFFFFFFF

def djb2_hash(name, u=False):
    h = 5381
    d = name.encode('utf-16-le') if u else name.encode('ascii')
    for b in d:
        h = ((h * 33) + b) & 0xFFFFFFFF
    return h

def sdbm_hash(name, u=False):
    h = 0
    d = name.encode('utf-16-le') if u else name.encode('ascii')
    for b in d:
        h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h

def fnv1a_hash(name, u=False):
    h = 0x811c9dc5
    d = name.encode('utf-16-le') if u else name.encode('ascii')
    for b in d:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h

data = json.loads(sys.stdin.read())
target = set()
for hx in data['hashes']:
    hx = hx.strip().lower()
    if hx.startswith('0x'):
        hx = hx[2:]
    target.add(hx.zfill(8))

unicode_modes = [False]
if data.get('unicode', False):
    unicode_modes.append(True)

results = []

for u in unicode_modes:
    suffix = '_unicode' if u else ''
    for algo_name, fn in [('ror13', ror13_hash), ('crc32', crc32_hash), ('djb2', djb2_hash), ('sdbm', sdbm_hash), ('fnv1a', fnv1a_hash)]:
        matches = []
        for api in COMMON_APIS:
            h = format(fn(api, u), '08x')
            if h in target:
                matches.append({'hash': '0x' + h, 'api': api})
        if matches:
            results.append({
                'algorithm': algo_name + suffix,
                'matches': len(matches),
                'total': len(target),
                'match_rate': round(len(matches) / len(target), 3),
                'sample_matches': matches[:10],
            })

    # ror13_additive
    matches = []
    for dll in COMMON_DLLS:
        for api in COMMON_APIS:
            h = format(ror13_additive(dll, api, u), '08x')
            if h in target:
                matches.append({'hash': '0x' + h, 'api': dll + '!' + api})
    if matches:
        results.append({
            'algorithm': 'ror13_additive' + suffix,
            'matches': len(matches),
            'total': len(target),
            'match_rate': round(len(matches) / len(target), 3),
            'sample_matches': matches[:10],
        })

results.sort(key=lambda x: -x['match_rate'])
print(json.dumps({'candidates': results}))
`

export function createHashIdentifyHandler(
  _workspaceManager: WorkspaceManager,
  _database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = hashIdentifyInputSchema.parse(args)
      const backend = resolveExecutable({ envPath: process.env.PYTHON_PATH, pathCandidates: ['python3', 'python'], versionArgSets: [['--version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'python3', available: false, error: 'Python 3 not found' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(
        backend.path,
        PYTHON_SCRIPT,
        { hashes: input.hashes, unicode: input.unicode },
        30000,
      )

      const parsed = result.parsed as any
      const candidates = parsed?.candidates || []
      const best = candidates[0]

      return {
        ok: true,
        data: {
          candidates,
          summary: best
            ? `Best match: ${best.algorithm} (${best.matches}/${best.total} = ${Math.round(best.match_rate * 100)}% match rate).`
            : `No algorithm matched the provided hashes.`,
          recommended_next_tools: ['hash.resolve', 'disasm.quick', 'speakeasy.emulate'],
          next_actions: best
            ? [`Use hash.resolve with algorithm="${best.algorithm}" for full resolution.`]
            : ['Hash values may use a custom or uncommon algorithm.'],
        },
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
