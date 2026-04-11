/**
 * hash.resolve — Resolve shellcode API hashes against known hash databases.
 *
 * Supports ROR13, CRC32, DJB2, SDBM, FNV1a, and custom hash algorithms.
 * Uses an embedded Python-based hash table computed at runtime.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema, SharedMetricsSchema,
  normalizeError, runPythonJson,
  persistBackendArtifact, buildMetrics,
  resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'hash.resolve'

export const hashResolveInputSchema = z.object({
  hashes: z.array(z.string()).min(1).max(200).describe('Hex hash values to resolve (e.g. ["0x6A4ABC5B", "0xEC0E4E8E"]).'),
  algorithm: z.enum(['ror13', 'crc32', 'djb2', 'sdbm', 'fnv1a', 'ror13_additive', 'auto']).default('auto').describe('Hash algorithm used. "auto" tries all.'),
  unicode: z.boolean().default(false).describe('Whether to compute hashes on Unicode (UTF-16LE) API names.'),
  persist_artifact: z.boolean().default(true).describe('Persist resolution results.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const hashResolveOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    resolved_count: z.number().optional(),
    unresolved_count: z.number().optional(),
    results: z.array(z.object({
      hash: z.string(),
      algorithm: z.string().optional(),
      api_name: z.string().optional(),
      dll: z.string().optional(),
      resolved: z.boolean(),
    })).optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const hashResolveToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Resolve shellcode API hashes against known Windows API hash databases (ROR13, CRC32, DJB2, etc.).',
  inputSchema: hashResolveInputSchema,
  outputSchema: hashResolveOutputSchema,
}

const PYTHON_SCRIPT = `
import json, sys, struct

COMMON_DLLS = [
    "kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll", "ws2_32.dll",
    "wininet.dll", "winhttp.dll", "shell32.dll", "ole32.dll", "urlmon.dll",
    "msvcrt.dll", "crypt32.dll", "shlwapi.dll", "gdi32.dll", "dnsapi.dll",
    "iphlpapi.dll", "psapi.dll", "netapi32.dll", "cabinet.dll"
]

COMMON_APIS = [
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc", "VirtualAllocEx",
    "VirtualProtect", "VirtualFree", "CreateProcessA", "CreateProcessW",
    "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
    "CloseHandle", "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
    "GetModuleHandleA", "GetModuleHandleW", "GetModuleFileNameA", "GetSystemDirectoryA",
    "GetTempPathA", "GetTempFileNameA", "DeleteFileA", "MoveFileA", "CopyFileA",
    "CreateThread", "ExitThread", "ExitProcess", "TerminateProcess", "Sleep",
    "WaitForSingleObject", "GetLastError", "SetLastError",
    "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegQueryValueExA",
    "RegCreateKeyExA", "RegDeleteKeyA", "RegCloseKey",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetReadFile",
    "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    "WSAStartup", "socket", "connect", "send", "recv", "closesocket", "bind", "listen",
    "accept", "gethostbyname", "inet_addr", "htons",
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx",
    "NtQueryInformationProcess", "NtQuerySystemInformation", "NtCreateFile",
    "NtProtectVirtualMemory", "NtMapViewOfSection", "NtUnmapViewOfSection",
    "RtlInitUnicodeString", "LdrLoadDll", "LdrGetProcedureAddress",
    "GetComputerNameA", "GetUserNameA", "GetVersionExA", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "OutputDebugStringA",
    "CryptAcquireContextA", "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
    "CryptEncrypt", "CryptDecrypt", "CryptReleaseContext",
    "URLDownloadToFileA", "URLDownloadToCacheFileA",
    "ShellExecuteA", "ShellExecuteW", "CreateServiceA", "StartServiceA",
    "HeapAlloc", "HeapFree", "HeapCreate", "GlobalAlloc", "GlobalFree",
    "GetFileSize", "SetFilePointer", "FlushFileBuffers",
    "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentThreadId",
    "DuplicateHandle", "CreateMutexA", "OpenMutexA",
    "FindFirstFileA", "FindNextFileA", "FindClose",
    "GetWindowsDirectoryA", "GetEnvironmentVariableA", "ExpandEnvironmentStringsA",
    "MultiByteToWideChar", "WideCharToMultiByte",
    "CreatePipe", "PeekNamedPipe", "ConnectNamedPipe",
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
]

def ror13_hash(name, unicode=False):
    h = 0
    data = name.encode('utf-16-le') if unicode else name.encode('ascii')
    for b in data:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + b) & 0xFFFFFFFF
    return h

def ror13_additive_hash(dll, api, unicode=False):
    h = ror13_hash(dll.upper(), unicode)
    h = (h + ror13_hash(api, unicode)) & 0xFFFFFFFF
    return h

def crc32_hash(name, unicode=False):
    import binascii
    data = name.encode('utf-16-le') if unicode else name.encode('ascii')
    return binascii.crc32(data) & 0xFFFFFFFF

def djb2_hash(name, unicode=False):
    h = 5381
    data = name.encode('utf-16-le') if unicode else name.encode('ascii')
    for b in data:
        h = ((h * 33) + b) & 0xFFFFFFFF
    return h

def sdbm_hash(name, unicode=False):
    h = 0
    data = name.encode('utf-16-le') if unicode else name.encode('ascii')
    for b in data:
        h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h

def fnv1a_hash(name, unicode=False):
    h = 0x811c9dc5
    data = name.encode('utf-16-le') if unicode else name.encode('ascii')
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h

data = json.loads(sys.stdin.read())
hashes_to_find = set()
for hx in data['hashes']:
    hx = hx.strip().lower()
    if hx.startswith('0x'):
        hx = hx[2:]
    hashes_to_find.add(hx.zfill(8))

algo = data.get('algorithm', 'auto')
unicode = data.get('unicode', False)

algos = {'ror13': ror13_hash, 'crc32': crc32_hash, 'djb2': djb2_hash, 'sdbm': sdbm_hash, 'fnv1a': fnv1a_hash}
if algo == 'auto':
    check_algos = list(algos.items()) + [('ror13_additive', None)]
else:
    check_algos = [(algo, algos.get(algo))] if algo != 'ror13_additive' else [('ror13_additive', None)]

db = {}
for algo_name, fn in check_algos:
    if algo_name == 'ror13_additive':
        for dll in COMMON_DLLS:
            for api in COMMON_APIS:
                h = ror13_additive_hash(dll, api, unicode)
                key = format(h, '08x')
                if key in hashes_to_find:
                    db[key] = {'algorithm': algo_name, 'api_name': api, 'dll': dll}
    else:
        for api in COMMON_APIS:
            h = fn(api, unicode)
            key = format(h, '08x')
            if key in hashes_to_find:
                db[key] = {'algorithm': algo_name, 'api_name': api, 'dll': ''}

results = []
for hx in data['hashes']:
    norm = hx.strip().lower()
    if norm.startswith('0x'):
        norm = norm[2:]
    norm = norm.zfill(8)
    match = db.get(norm)
    if match:
        results.append({'hash': hx, 'algorithm': match['algorithm'], 'api_name': match['api_name'], 'dll': match['dll'], 'resolved': True})
    else:
        results.append({'hash': hx, 'resolved': False})

resolved = sum(1 for r in results if r['resolved'])
print(json.dumps({'resolved_count': resolved, 'unresolved_count': len(results) - resolved, 'results': results}))
`

export function createHashResolveHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = hashResolveInputSchema.parse(args)
      const backend = resolveExecutable({ envPath: process.env.PYTHON_PATH, pathCandidates: ['python3', 'python'], versionArgSets: [['--version']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'python3', available: false, error: 'Python 3 not found' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(
        backend.path,
        PYTHON_SCRIPT,
        { hashes: input.hashes, algorithm: input.algorithm, unicode: input.unicode },
        30000,
      )

      const parsed = result.parsed as any
      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact && parsed?.results?.length > 0) {
        artifact = await persistBackendArtifact(workspaceManager, database, 'api-hash', 'hash', 'resolve', JSON.stringify(parsed.results, null, 2), { extension: 'json', mime: 'application/json', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          resolved_count: parsed?.resolved_count || 0,
          unresolved_count: parsed?.unresolved_count || 0,
          results: parsed?.results || [],
          artifact,
          summary: `Resolved ${parsed?.resolved_count || 0}/${input.hashes.length} API hashes.`,
          recommended_next_tools: ['hash.identify', 'disasm.quick', 'speakeasy.emulate'],
          next_actions: [
            parsed?.resolved_count > 0 ? 'Map resolved APIs to understand shellcode behavior.' : 'Try different algorithm or check hash values.',
            'Use disasm.quick to locate hash computation in shellcode.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
