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
  normalizeError,
  runPythonJson,
  buildMetrics,
  resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'hash.identify'
const TOOL_VERSION = '0.2.0'
const HASH_IDENTIFY_RECOMMENDED_NEXT_TOOLS = ['workflow.search']
const HASH_IDENTIFY_PROFILE_NEXT_TOOLS = [
  'hash.resolve',
  'disasm.quick',
  'analysis.evidence.graph',
  'report.generate',
]
const HASH_IDENTIFY_SAFETY = [
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

export const hashIdentifyInputSchema = z.object({
  hashes: z
    .array(z.string())
    .min(1)
    .max(50)
    .describe('Hex hash values to test (e.g. ["0x6A4ABC5B"]).'),
  unicode: z.boolean().default(false).describe('Also try Unicode (UTF-16LE) API names.'),
})

export const hashIdentifyOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      schema: z.string().optional(),
      tool_version: z.string().optional(),
      unicode: z.boolean().optional(),
      requested_hash_count: z.number().int().nonnegative().optional(),
      candidates: z
        .array(
          z.object({
            algorithm: z.string(),
            matches: z.number(),
            total: z.number(),
            match_rate: z.number(),
            sample_matches: z.array(z.object({ hash: z.string(), api: z.string() })),
          })
        )
        .optional(),
      evidence_summary: z.record(z.string(), z.any()).optional(),
      workflow_handoff: z.record(z.string(), z.any()).optional(),
      quality_gates: z.record(z.string(), z.any()).optional(),
      raw_identify_result: z.record(z.string(), z.any()).optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const hashIdentifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Identify the hash algorithm used to produce shellcode API hashes by brute-force matching against known APIs.',
  inputSchema: hashIdentifyInputSchema,
  outputSchema: hashIdentifyOutputSchema,
  aspects: {
    formats: ['pe', 'dll', 'shellcode', 'memory', 'raw'],
    platforms: ['windows', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage'],
    runtimes: ['python'],
    safety: HASH_IDENTIFY_SAFETY,
    capabilities: [
      'api-hash-identification',
      'shellcode-triage',
      'hash-algorithm-candidate-ranking',
      'import-recovery-planning',
      'workflow-handoff',
    ],
    evidence: ['imports', 'symbols', 'behavior', 'workflow', 'provenance'],
  },
  evidence: [
    {
      category: 'imports',
      description: 'Candidate API hash algorithm matches for import recovery planning',
    },
    {
      category: 'workflow',
      description: 'Handoff from hash algorithm identification into hash resolution',
    },
    {
      category: 'provenance',
      description: 'Passive local Python resolver execution metadata',
    },
  ],
  workflowRecipes: [
    {
      id: 'api-hash.identify-handoff',
      title: 'API hash algorithm identification handoff',
      description:
        'Identify likely API hash algorithms from observed hash values, then route into scoped hash resolution, disassembly corroboration, evidence graph, and reporting.',
      startsWith: [TOOL_NAME],
      nextTools: [...HASH_IDENTIFY_RECOMMENDED_NEXT_TOOLS, ...HASH_IDENTIFY_PROFILE_NEXT_TOOLS],
      requiredArtifacts: ['hash_values'],
      producesArtifacts: [],
      evidence: ['imports', 'symbols', 'behavior', 'workflow', 'provenance'],
      safety: HASH_IDENTIFY_SAFETY,
      runtimeBackends: ['python'],
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
      'hash.identify only brute-forces observed hash values against an embedded API name allowlist.',
      'Use workflow.search to activate hash.resolve or disassembly follow-ups as scoped tools.',
    ],
  },
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'python',
    backendKind: 'external',
    adapter: 'api_hash.identify',
    availability: 'optional',
    envVar: 'PYTHON_PATH',
    commandHint: 'python -c "<embedded api hash identifier>"',
    versionHint: 'python --version',
    supportedModes: ['identify'],
    defaultMode: 'identify',
    inputArtifactTypes: ['hash_values'],
    outputArtifactTypes: [],
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      defaultTimeoutMs: 30000,
      maxInputBytes: 64 * 1024,
      maxOutputBytes: 4 * 1024 * 1024,
      notes: ['Only bounded candidate ranking results are returned inline by this tool.'],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [
        'Set PYTHON_PATH or install python3/python on PATH for the embedded identifier.',
      ],
      missingBackendBehavior: 'Return setup_required without identifying hash algorithms.',
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

function buildHashIdentifyEvidenceSummary(args: {
  unicode: boolean
  requestedHashCount: number
  candidates: Array<Record<string, unknown>>
}) {
  const best = args.candidates[0]
  return {
    schema: 'rikune.api_hash_identify.evidence_summary.v1',
    source_tool: TOOL_NAME,
    tool_version: TOOL_VERSION,
    unicode: args.unicode,
    requested_hash_count: args.requestedHashCount,
    candidate_count: args.candidates.length,
    best_algorithm: typeof best?.algorithm === 'string' ? best.algorithm : null,
    best_match_rate: typeof best?.match_rate === 'number' ? best.match_rate : null,
    best_match_count: typeof best?.matches === 'number' ? best.matches : null,
  }
}

function buildHashIdentifyWorkflowHandoff(args: { candidates: Array<Record<string, unknown>> }) {
  const best = args.candidates[0]
  const bestAlgorithm = typeof best?.algorithm === 'string' ? best.algorithm : null
  return {
    schema: 'rikune.api_hash_identify.workflow_handoff.v1',
    handoff_mode: 'api_hash_algorithm_identification_to_resolution',
    best_algorithm: bestAlgorithm,
    candidate_count: args.candidates.length,
    recommended_next_tools: HASH_IDENTIFY_RECOMMENDED_NEXT_TOOLS,
    routing: [
      {
        goal: 'resolve-with-identified-algorithm',
        priority: bestAlgorithm ? 'high' : 'normal',
        next_tools: ['hash.resolve'],
        required_evidence: bestAlgorithm
          ? [`algorithm:${bestAlgorithm}`, 'hash_values']
          : ['hash_values', 'algorithm candidate'],
      },
      {
        goal: 'corroborate-hash-computation',
        priority: bestAlgorithm ? 'normal' : 'high',
        next_tools: ['disasm.quick', 'analysis.evidence.graph'],
        required_evidence: ['hash computation site', 'candidate algorithm ranking'],
      },
      {
        goal: 'report-api-hash-identification',
        priority: 'normal',
        next_tools: ['report.generate'],
        required_evidence: ['candidate algorithm ranking'],
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

function buildHashIdentifyQualityGates(args: { candidateCount: number }) {
  return {
    schema: 'rikune.api_hash_identify.quality_gates.v1',
    passive_static_analysis: true,
    read_only_backend: true,
    sample_executed_by_tool: false,
    backend_started_with_bounded_command: true,
    network_accessed_by_tool: false,
    mutation_performed: false,
    output_bounded_inline: true,
    artifact_persisted: false,
    analyst_review_required: true,
    candidate_count: args.candidateCount,
  }
}

function buildHashIdentifyNextActions(args: { candidates: Array<Record<string, unknown>> }) {
  const best = args.candidates[0]
  const bestAlgorithm = typeof best?.algorithm === 'string' ? best.algorithm : null
  return [
    bestAlgorithm
      ? `Use workflow.search to activate hash.resolve with algorithm="${bestAlgorithm}" as a scoped follow-up.`
      : 'Use workflow.search with disassembly and API hash terms to locate or explain the hash computation site.',
    'Corroborate the candidate algorithm against code before treating resolved API names as behavior evidence.',
  ]
}

export function createHashIdentifyHandler(
  _workspaceManager: WorkspaceManager,
  _database: DatabaseManager,
  dependencies?: ApiHashToolDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = hashIdentifyInputSchema.parse(args)
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
        { hashes: input.hashes, unicode: input.unicode },
        30000
      )

      const parsed = result.parsed && typeof result.parsed === 'object' ? result.parsed : {}
      const candidates = Array.isArray(parsed?.candidates) ? parsed.candidates : []
      const best = candidates[0]

      return {
        ok: true,
        data: {
          schema: 'rikune.api_hash_identify.v1',
          tool_version: TOOL_VERSION,
          unicode: input.unicode,
          requested_hash_count: input.hashes.length,
          candidates,
          evidence_summary: buildHashIdentifyEvidenceSummary({
            unicode: input.unicode,
            requestedHashCount: input.hashes.length,
            candidates,
          }),
          workflow_handoff: buildHashIdentifyWorkflowHandoff({ candidates }),
          quality_gates: buildHashIdentifyQualityGates({ candidateCount: candidates.length }),
          raw_identify_result: parsed,
          summary: best
            ? `Best match: ${best.algorithm} (${best.matches}/${best.total} = ${Math.round(best.match_rate * 100)}% match rate).`
            : `No algorithm matched the provided hashes.`,
          recommended_next_tools: HASH_IDENTIFY_RECOMMENDED_NEXT_TOOLS,
          next_actions: buildHashIdentifyNextActions({ candidates }),
        },
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
