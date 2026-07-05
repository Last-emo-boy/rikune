import { z } from 'zod'

export const MemoryCorrelationInputSchema = z
  .object({
    sample_id: z.string().optional(),
    pslist: z.any().optional(),
    dlllist: z.any().optional(),
    malfind: z.any().optional(),
    netscan: z.any().optional(),
    hivelist: z.any().optional(),
    cmdline: z.any().optional(),
    sources: z.record(z.any()).optional(),
  })
  .passthrough()

export const MemoryCorrelationOutputSchema = z
  .object({
    result_mode: z.literal('memory_forensics_correlation'),
    sample_id: z.string().nullable(),
    finding_bundle: z.record(z.any()),
    ioc_candidates: z.array(z.record(z.any())),
    behavior_timeline: z.array(z.record(z.any())),
    correlation_graph: z.record(z.any()),
    provenance_graph: z.record(z.any()),
    evidence_summary: z.record(z.any()),
    workflow_handoff: z.record(z.any()),
    quality_gates: z.record(z.any()),
    recommended_next_tools: z.array(z.string()),
    safety_notes: z.array(z.string()),
  })
  .passthrough()

export const MEMORY_FORENSICS_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'ioc.export',
  'analysis.evidence.graph',
  'behavior.timeline',
  'report.generate',
]

export const MEMORY_FORENSICS_SEARCH_TERMS = [
  'memory dump',
  'volatility',
  'volatility3',
  'vmem',
  'dmp',
  'core dump',
  'malfind',
  'netscan',
  'pslist',
  'process injection',
  'hollowing',
  'memory ioc',
  'memory trace fusion',
]

export const MEMORY_FORENSICS_ROUTE_TERMS = [
  'memory_trace_fusion_profile',
  'offline_memory_correlation',
  'memory_snapshot',
  'dynamic_trace',
  'process_injection',
  'malfind',
  'netscan',
  'ioc_candidates',
  'behavior_timeline',
]

export const MEMORY_FORENSICS_QUALITY_GATES_SCHEMA =
  'rikune.memory_forensics_correlation.quality_gates.v1'

type Row = Record<string, unknown>
type MemoryCorrelationInput = z.infer<typeof MemoryCorrelationInputSchema>

function objectValue(value: unknown): Row {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Row) : {}
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function rowsFrom(value: unknown): Row[] {
  if (!value) return []
  if (Array.isArray(value)) return value.map(objectValue).filter((row) => Object.keys(row).length)

  const obj = objectValue(value)
  for (const key of ['rows', 'data', 'results', 'items', 'processes', 'connections', 'hives']) {
    const rows = rowsFrom(obj[key])
    if (rows.length > 0) return rows
  }
  return Object.keys(obj).length > 0 ? [obj] : []
}

function pickString(row: Row, keys: string[]): string | null {
  const normalized = new Map(Object.entries(row).map(([key, value]) => [normalizeKey(key), value]))
  for (const key of keys) {
    const value = normalized.get(normalizeKey(key))
    if (typeof value === 'string' && value.trim()) return value.trim()
    if (typeof value === 'number') return String(value)
  }
  return null
}

function pickNumber(row: Row, keys: string[]): number | null {
  const value = pickString(row, keys)
  if (!value) return null
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : null
}

function validRemoteAddress(value: string | null): value is string {
  if (!value) return false
  const lowered = value.toLowerCase()
  return !['*', '0.0.0.0', '::', ':::', 'localhost', '127.0.0.1'].includes(lowered)
}

function collectSources(input: MemoryCorrelationInput): Record<string, unknown> {
  return {
    ...(input.sources ?? {}),
    pslist: input.pslist ?? input.sources?.pslist,
    dlllist: input.dlllist ?? input.sources?.dlllist,
    malfind: input.malfind ?? input.sources?.malfind,
    netscan: input.netscan ?? input.sources?.netscan,
    hivelist: input.hivelist ?? input.sources?.hivelist,
    cmdline: input.cmdline ?? input.sources?.cmdline,
  }
}

export function buildMemoryForensicsCorrelation(rawInput: unknown) {
  const input = MemoryCorrelationInputSchema.parse(rawInput)
  const sources = collectSources(input)

  const processes = rowsFrom(sources.pslist).map((row) => ({
    pid: pickNumber(row, ['pid', 'processid', 'process_id']),
    ppid: pickNumber(row, ['ppid', 'parentpid', 'parent_process_id']),
    name: pickString(row, ['imagefilename', 'name', 'process', 'processname']) ?? 'unknown',
    path: pickString(row, ['path', 'imagepath', 'fileoutput']),
  }))

  const commandLines = rowsFrom(sources.cmdline).map((row) => ({
    pid: pickNumber(row, ['pid', 'processid', 'process_id']),
    process: pickString(row, ['process', 'imagefilename', 'name']) ?? 'unknown',
    command_line: pickString(row, ['commandline', 'cmdline', 'args']) ?? '',
  }))

  const suspiciousRegions = rowsFrom(sources.malfind).map((row) => ({
    pid: pickNumber(row, ['pid', 'processid', 'process_id']),
    process: pickString(row, ['process', 'imagefilename', 'name']) ?? 'unknown',
    address: pickString(row, ['startvpn', 'address', 'vad', 'base']),
    protection: pickString(row, ['protection', 'protect']),
    tag: pickString(row, ['tag', 'vadtag']),
  }))

  const networkConnections = rowsFrom(sources.netscan).map((row) => ({
    pid: pickNumber(row, ['pid', 'processid', 'ownerpid']),
    process: pickString(row, ['owner', 'process', 'name']) ?? 'unknown',
    local: pickString(row, ['localaddr', 'localaddress', 'local']),
    local_port: pickNumber(row, ['localport', 'lport']),
    remote: pickString(row, ['foreignaddr', 'remoteaddr', 'remoteaddress', 'foreignaddress']),
    remote_port: pickNumber(row, ['foreignport', 'remoteport', 'rport']),
    state: pickString(row, ['state']),
    protocol: pickString(row, ['proto', 'protocol']),
  }))

  const registryHives = rowsFrom(sources.hivelist).map((row) => ({
    path: pickString(row, ['filefullname', 'path', 'name']) ?? 'unknown',
    offset: pickString(row, ['offset', 'virtual', 'address']),
  }))

  const modules = rowsFrom(sources.dlllist).map((row) => ({
    pid: pickNumber(row, ['pid', 'processid', 'process_id']),
    process: pickString(row, ['process', 'imagefilename', 'name']) ?? 'unknown',
    module: pickString(row, ['name', 'basename', 'dll', 'module']) ?? 'unknown',
    path: pickString(row, ['path', 'fullpath', 'mappedpath']),
  }))

  const iocCandidates = networkConnections
    .filter((connection) => validRemoteAddress(connection.remote))
    .map((connection) => ({
      type: 'network',
      value: connection.remote,
      port: connection.remote_port,
      confidence: 0.7,
      source: 'memory-forensics.netscan',
      pid: connection.pid,
      process: connection.process,
    }))

  const behaviorTimeline = [
    ...commandLines.map((entry) => ({
      category: 'process',
      action: 'command_line',
      subject: entry.process,
      pid: entry.pid,
      detail: entry.command_line,
      source: 'memory-forensics.cmdline',
    })),
    ...suspiciousRegions.map((entry) => ({
      category: 'memory',
      action: 'suspicious_region',
      subject: entry.process,
      pid: entry.pid,
      detail: entry.address ?? entry.protection ?? 'suspicious memory region',
      source: 'memory-forensics.malfind',
    })),
    ...networkConnections.map((entry) => ({
      category: 'network',
      action: 'connection',
      subject: entry.process,
      pid: entry.pid,
      detail: `${entry.remote ?? 'unknown'}:${entry.remote_port ?? 'unknown'}`,
      source: 'memory-forensics.netscan',
    })),
  ]

  const processNodes = processes.map((process) => ({
    id: `process:${process.pid ?? process.name}`,
    type: 'process',
    label: process.name,
    pid: process.pid,
  }))
  const connectionNodes = networkConnections.map((connection, index) => ({
    id: `network:${index}`,
    type: 'network',
    label: `${connection.remote ?? 'unknown'}:${connection.remote_port ?? 'unknown'}`,
  }))
  const moduleNodes = modules.slice(0, 100).map((module, index) => ({
    id: `module:${index}`,
    type: 'module',
    label: module.module,
  }))
  const sourceSummaries = Object.entries(sources)
    .filter(([, value]) => rowsFrom(value).length > 0)
    .map(([source, value]) => ({
      source: `memory-forensics.${source}`,
      row_count: rowsFrom(value).length,
    }))
  const evidenceCategories = [
    processes.length > 0 ? 'process' : null,
    suspiciousRegions.length > 0 ? 'memory' : null,
    networkConnections.length > 0 ? 'network' : null,
    registryHives.length > 0 ? 'registry' : null,
    behaviorTimeline.length > 0 ? 'behavior' : null,
    'workflow',
    'provenance',
  ].filter((category): category is string => Boolean(category))
  const qualityGates = {
    schema: MEMORY_FORENSICS_QUALITY_GATES_SCHEMA,
    offline_correlation_only: true,
    volatility_invoked_by_tool: false,
    live_memory_access: false,
    dump_content_read_by_tool: false,
    network_access_performed: false,
    source_artifact_count: sourceSummaries.length,
    process_rows: processes.length,
    malfind_rows: suspiciousRegions.length,
    netscan_rows: networkConnections.length,
    registry_rows: registryHives.length,
    module_rows: modules.length,
    ioc_candidate_count: iocCandidates.length,
    behavior_event_count: behaviorTimeline.length,
    bounded_module_preview: modules.length > 100,
  }

  return {
    result_mode: 'memory_forensics_correlation' as const,
    sample_id: input.sample_id ?? null,
    finding_bundle: {
      process_count: processes.length,
      suspicious_region_count: suspiciousRegions.length,
      network_connection_count: networkConnections.length,
      registry_hive_count: registryHives.length,
      module_count: modules.length,
      processes,
      suspicious_regions: suspiciousRegions,
      network_connections: networkConnections,
      registry_hives: registryHives,
      modules: modules.slice(0, 100),
    },
    ioc_candidates: iocCandidates,
    behavior_timeline: behaviorTimeline,
    correlation_graph: {
      nodes: [...processNodes, ...connectionNodes, ...moduleNodes],
      edges: [
        ...networkConnections.map((connection, index) => ({
          source: `process:${connection.pid ?? connection.process}`,
          target: `network:${index}`,
          relation: 'opened_connection',
        })),
        ...modules.slice(0, 100).map((module, index) => ({
          source: `process:${module.pid ?? module.process}`,
          target: `module:${index}`,
          relation: 'loaded_module',
        })),
      ],
    },
    provenance_graph: {
      sources: sourceSummaries,
    },
    evidence_summary: {
      schema: 'rikune.memory_forensics_correlation.evidence_summary.v1',
      profile: 'memory.trace_fusion',
      artifact_type: 'memory_forensics_correlation',
      evidence_kind: 'offline_memory_correlation',
      sample_id: input.sample_id ?? null,
      evidence_categories: evidenceCategories,
      source_artifact_count: sourceSummaries.length,
      ioc_candidate_count: iocCandidates.length,
      behavior_event_count: behaviorTimeline.length,
      route_terms: MEMORY_FORENSICS_ROUTE_TERMS,
      recommended_next_tools: MEMORY_FORENSICS_FOLLOW_UP_TOOLS,
    },
    workflow_handoff: {
      schema: 'rikune.memory_forensics_correlation.workflow_handoff.v1',
      routing: [
        {
          goal: 'memory-trace-fusion',
          profile: 'memory.trace_fusion',
          route_terms: MEMORY_FORENSICS_ROUTE_TERMS,
          activation_boundary: 'result-scoped',
          next_tools: MEMORY_FORENSICS_FOLLOW_UP_TOOLS,
          required_evidence: ['memory_forensics_correlation'],
        },
      ],
      dynamic_boundary: {
        dynamic_imports_default_recommended: false,
        allowed_only_for_existing_artifacts: ['dynamic_trace_json', 'memory_snapshot'],
        excluded_default_tools: ['dynamic.memory.import', 'dynamic.trace.import'],
      },
      recommended_next_tools: MEMORY_FORENSICS_FOLLOW_UP_TOOLS,
      quality_gates_schema: MEMORY_FORENSICS_QUALITY_GATES_SCHEMA,
    },
    quality_gates: qualityGates,
    recommended_next_tools: MEMORY_FORENSICS_FOLLOW_UP_TOOLS,
    safety_notes: [
      'Correlation consumes existing Volatility JSON or fixture rows only.',
      'No memory dump acquisition, live process access, kernel access, or Volatility invocation is performed.',
    ],
  }
}
