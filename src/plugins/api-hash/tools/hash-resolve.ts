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
  ArtifactRefSchema,
  SharedMetricsSchema,
  normalizeError,
  runPythonJson,
  persistBackendArtifact,
  buildMetrics,
  resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'hash.resolve'
const TOOL_VERSION = '0.2.0'
const HASH_RESOLVE_ARTIFACT_TYPE = 'backend_hash_resolve'
const HASH_RESOLVE_ALGORITHMS = [
  'ror13',
  'crc32',
  'djb2',
  'sdbm',
  'fnv1a',
  'ror13_additive',
  'auto',
] as const
const HASH_RESOLVE_RECOMMENDED_NEXT_TOOLS = ['artifact.read', 'workflow.search']
const HASH_RESOLVE_PROFILE_NEXT_TOOLS = [
  'hash.identify',
  'disasm.quick',
  'analysis.evidence.graph',
  'report.generate',
]
const HASH_API_SAFETY = [
  'passive',
  'read_only',
  'bounded_output',
  'no_live_sample_by_default',
  'no_network_by_default',
]

type ApiHashToolDependencies = {
  resolveExecutable?: typeof resolveExecutable
  runPythonJson?: typeof runPythonJson
}

export const hashResolveInputSchema = z.object({
  sample_id: z
    .string()
    .optional()
    .describe('Optional sample identifier used when persisting resolution artifacts.'),
  hashes: z
    .array(z.string())
    .min(1)
    .max(200)
    .describe('Hex hash values to resolve (e.g. ["0x6A4ABC5B", "0xEC0E4E8E"]).'),
  algorithm: z
    .enum(HASH_RESOLVE_ALGORITHMS)
    .default('auto')
    .describe('Hash algorithm used. "auto" tries all.'),
  unicode: z
    .boolean()
    .default(false)
    .describe('Whether to compute hashes on Unicode (UTF-16LE) API names.'),
  persist_artifact: z.boolean().default(true).describe('Persist resolution results.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const hashResolveOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      sample_id: z.string().optional(),
      algorithm: z.string().optional(),
      unicode: z.boolean().optional(),
      resolved_count: z.number().optional(),
      unresolved_count: z.number().optional(),
      results: z
        .array(
          z.object({
            hash: z.string(),
            algorithm: z.string().optional(),
            api_name: z.string().optional(),
            dll: z.string().optional(),
            resolved: z.boolean(),
          })
        )
        .optional(),
      raw_hash_result: z.record(z.any()).optional(),
      artifact: ArtifactRefSchema.optional(),
      evidence_summary: z.record(z.any()).optional(),
      workflow_handoff: z.record(z.any()).optional(),
      quality_gates: z.record(z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const hashResolveToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Resolve shellcode API hashes against known Windows API hash databases (ROR13, CRC32, DJB2, etc.).',
  inputSchema: hashResolveInputSchema,
  outputSchema: hashResolveOutputSchema,
  aspects: {
    formats: ['pe', 'dll', 'shellcode', 'memory', 'raw'],
    platforms: ['windows', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage'],
    runtimes: ['python'],
    safety: HASH_API_SAFETY,
    capabilities: [
      'api-hash-resolution',
      'shellcode-triage',
      'import-recovery',
      'behavior-corroboration',
      'workflow-handoff',
    ],
    evidence: ['imports', 'symbols', 'behavior', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: HASH_RESOLVE_ARTIFACT_TYPE,
      description: 'API hash resolution results for shellcode and packed binary triage',
    },
  ],
  evidence: [
    {
      category: 'imports',
      artifactTypes: [HASH_RESOLVE_ARTIFACT_TYPE],
    },
    {
      category: 'behavior',
      artifactTypes: [HASH_RESOLVE_ARTIFACT_TYPE],
    },
    {
      category: 'workflow',
      artifactTypes: [HASH_RESOLVE_ARTIFACT_TYPE],
    },
    {
      category: 'provenance',
      artifactTypes: [HASH_RESOLVE_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'api-hash.resolve-handoff',
      title: 'API hash resolution handoff',
      description:
        'Resolve suspected API hashes with a bounded passive resolver, then hand off import evidence to artifact review, disassembly corroboration, evidence graph, and reporting.',
      startsWith: [TOOL_NAME],
      nextTools: [...HASH_RESOLVE_RECOMMENDED_NEXT_TOOLS, ...HASH_RESOLVE_PROFILE_NEXT_TOOLS],
      requiredArtifacts: ['hash_values'],
      producesArtifacts: [HASH_RESOLVE_ARTIFACT_TYPE],
      evidence: ['imports', 'symbols', 'behavior', 'workflow', 'provenance'],
      safety: HASH_API_SAFETY,
      runtimeBackends: ['python'],
      algorithms: HASH_RESOLVE_ALGORITHMS,
    },
  ],
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    maxRuntimeMs: 30000,
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'hash.resolve computes API-name hashes against an embedded bounded allowlist and never executes the sample.',
      'workflow.search should route unresolved cases to disassembly or emulation planning without exposing broad runtime tools by default.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'python',
    backendKind: 'external',
    adapter: 'api_hash.resolve',
    availability: 'optional',
    envVar: 'PYTHON_PATH',
    commandHint: 'python -c "<embedded api hash resolver>"',
    versionHint: 'python --version',
    supportedModes: [...HASH_RESOLVE_ALGORITHMS],
    defaultMode: 'auto',
    inputArtifactTypes: ['hash_values'],
    outputArtifactTypes: [HASH_RESOLVE_ARTIFACT_TYPE],
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 30000,
      maxInputBytes: 64 * 1024,
      maxOutputBytes: 4 * 1024 * 1024,
      notes: ['Only bounded hash resolution results are persisted by this tool.'],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Set PYTHON_PATH or install python3/python on PATH for the embedded resolver.',
      ],
      missingBackendBehavior: 'Return setup_required without resolving hashes.',
    },
    packaging: {
      installRoute: 'installed',
      installProfile: 'default',
      envVar: 'PYTHON_PATH',
      dockerDefault: 'python3',
    },
  },
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

function buildHashResolveEvidenceSummary(args: {
  sampleId?: string
  algorithm: z.infer<typeof hashResolveInputSchema>['algorithm']
  unicode: boolean
  requestedHashCount: number
  resolvedCount: number
  unresolvedCount: number
  results: Array<Record<string, unknown>>
  artifact?: ArtifactRef
}) {
  return {
    schema: 'rikune.api_hash_resolve.evidence_summary.v1',
    source_tool: TOOL_NAME,
    tool_version: TOOL_VERSION,
    artifact_type: HASH_RESOLVE_ARTIFACT_TYPE,
    sample_id: args.sampleId ?? null,
    algorithm: args.algorithm,
    unicode: args.unicode,
    requested_hash_count: args.requestedHashCount,
    resolved_count: args.resolvedCount,
    unresolved_count: args.unresolvedCount,
    resolved_api_names: args.results
      .filter((item) => item.resolved === true && typeof item.api_name === 'string')
      .map((item) => item.api_name)
      .slice(0, 25),
    artifact_id: args.artifact?.id ?? null,
  }
}

function buildHashResolveWorkflowHandoff(args: {
  sampleId?: string
  algorithm: z.infer<typeof hashResolveInputSchema>['algorithm']
  resolvedCount: number
  artifact?: ArtifactRef
}) {
  return {
    schema: 'rikune.api_hash_resolve.workflow_handoff.v1',
    handoff_mode: 'api_hash_resolution_to_import_behavior_review',
    artifact_type: HASH_RESOLVE_ARTIFACT_TYPE,
    sample_id: args.sampleId ?? null,
    algorithm: args.algorithm,
    resolved_count: args.resolvedCount,
    recommended_next_tools: HASH_RESOLVE_RECOMMENDED_NEXT_TOOLS,
    artifact_contract: {
      type: HASH_RESOLVE_ARTIFACT_TYPE,
      suggested_read_mode: 'profile',
      artifact_id: args.artifact?.id ?? null,
      content_kind: 'api_hash_resolution_results',
    },
    routing: [
      {
        goal: 'review-api-hash-results',
        priority: args.artifact ? 'high' : 'normal',
        next_tools: ['artifact.read'],
        required_evidence: [HASH_RESOLVE_ARTIFACT_TYPE],
      },
      {
        goal: 'corroborate-hash-computation',
        priority: args.resolvedCount > 0 ? 'high' : 'normal',
        next_tools: ['disasm.quick', 'analysis.evidence.graph'],
        required_evidence: [HASH_RESOLVE_ARTIFACT_TYPE, 'hash computation site'],
      },
      {
        goal: 'report-api-resolution',
        priority: 'normal',
        next_tools: ['report.generate'],
        required_evidence: [HASH_RESOLVE_ARTIFACT_TYPE],
      },
    ],
    dynamic_boundary: {
      sample_executed_by_tool: false,
      backend_started: true,
      backend_kind: 'external-passive-script',
      live_execution_started: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildHashResolveQualityGates(args: {
  algorithm: z.infer<typeof hashResolveInputSchema>['algorithm']
  artifactPersisted: boolean
  resolvedCount: number
}) {
  return {
    schema: 'rikune.api_hash_resolve.quality_gates.v1',
    passive_static_analysis: true,
    read_only_backend: true,
    sample_executed_by_tool: false,
    backend_started_with_bounded_command: true,
    network_accessed_by_tool: false,
    mutation_performed: false,
    output_bounded_inline: true,
    artifact_persisted: args.artifactPersisted,
    analyst_review_required: true,
    algorithm: args.algorithm,
    resolved_count: args.resolvedCount,
  }
}

function buildHashResolveNextActions(args: {
  artifact?: ArtifactRef
  resolvedCount: number
  algorithm: z.infer<typeof hashResolveInputSchema>['algorithm']
}) {
  return [
    args.artifact
      ? 'Use artifact.read in profile mode to inspect the persisted API hash resolution envelope.'
      : 'Persist API hash resolution output before relying on it for import recovery evidence.',
    args.resolvedCount > 0
      ? 'Use workflow.search to select a scoped disassembly or evidence graph follow-up for hash computation corroboration.'
      : 'Use workflow.search with API hash identification or disassembly terms before escalating to emulation.',
    args.algorithm === 'auto'
      ? 'Review matched algorithms before treating resolved API names as behavior evidence.'
      : 'Cross-check the selected hash algorithm against the code site when possible.',
  ]
}

export function createHashResolveHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: ApiHashToolDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = hashResolveInputSchema.parse(args)
      const resolveExecutableImpl = dependencies?.resolveExecutable || resolveExecutable
      const backend = resolveExecutableImpl({
        envPath: process.env.PYTHON_PATH,
        pathCandidates: ['python3', 'python'],
        versionArgSets: [['--version']],
      })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(
          backend || ({ name: 'python3', available: false, error: 'Python 3 not found' } as any),
          startTime,
          TOOL_NAME
        )
      }

      const runPythonJsonImpl = dependencies?.runPythonJson || runPythonJson
      const result = await runPythonJsonImpl(
        backend.path,
        PYTHON_SCRIPT,
        { hashes: input.hashes, algorithm: input.algorithm, unicode: input.unicode },
        30000
      )

      const parsed = result.parsed && typeof result.parsed === 'object' ? result.parsed : {}
      const results = Array.isArray(parsed?.results) ? parsed.results : []
      const resolvedCount = Number(parsed?.resolved_count || 0)
      const unresolvedCount = Number(parsed?.unresolved_count || 0)
      const baseOutputData = {
        schema: 'rikune.api_hash_resolve.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        algorithm: input.algorithm,
        unicode: input.unicode,
        resolved_count: resolvedCount,
        unresolved_count: unresolvedCount,
        results,
        raw_hash_result: parsed,
        summary: `Resolved ${resolvedCount}/${input.hashes.length} API hashes.`,
      } satisfies Record<string, unknown>
      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      const warnings: string[] = []
      if (input.persist_artifact && !input.sample_id) {
        warnings.push(
          'sample_id is required to persist hash.resolve artifacts; returning inline results only.'
        )
      }
      if (input.persist_artifact && input.sample_id && results.length > 0) {
        const artifactPayload = {
          ...baseOutputData,
          evidence_summary: buildHashResolveEvidenceSummary({
            sampleId: input.sample_id,
            algorithm: input.algorithm,
            unicode: input.unicode,
            requestedHashCount: input.hashes.length,
            resolvedCount,
            unresolvedCount,
            results,
          }),
          workflow_handoff: buildHashResolveWorkflowHandoff({
            sampleId: input.sample_id,
            algorithm: input.algorithm,
            resolvedCount,
          }),
          quality_gates: buildHashResolveQualityGates({
            algorithm: input.algorithm,
            artifactPersisted: true,
            resolvedCount,
          }),
          recommended_next_tools: HASH_RESOLVE_RECOMMENDED_NEXT_TOOLS,
          next_actions: buildHashResolveNextActions({
            resolvedCount,
            algorithm: input.algorithm,
          }),
        }
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'hash',
          'resolve',
          JSON.stringify(artifactPayload, null, 2),
          { extension: 'json', mime: 'application/json', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          ...baseOutputData,
          artifact,
          evidence_summary: buildHashResolveEvidenceSummary({
            sampleId: input.sample_id,
            algorithm: input.algorithm,
            unicode: input.unicode,
            requestedHashCount: input.hashes.length,
            resolvedCount,
            unresolvedCount,
            results,
            artifact,
          }),
          workflow_handoff: buildHashResolveWorkflowHandoff({
            sampleId: input.sample_id,
            algorithm: input.algorithm,
            resolvedCount,
            artifact,
          }),
          quality_gates: buildHashResolveQualityGates({
            algorithm: input.algorithm,
            artifactPersisted: Boolean(artifact),
            resolvedCount,
          }),
          recommended_next_tools: HASH_RESOLVE_RECOMMENDED_NEXT_TOOLS,
          next_actions: buildHashResolveNextActions({
            artifact,
            resolvedCount,
            algorithm: input.algorithm,
          }),
        },
        warnings: warnings.length > 0 ? warnings : undefined,
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
