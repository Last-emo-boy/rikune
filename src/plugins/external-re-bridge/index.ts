import { createHash } from 'node:crypto'
import { z } from 'zod'
import {
  WorkerResultOutputSchema,
  definePlugin,
  defineTool,
  type BackendWorkerContract,
  type PluginAspects,
  type PluginSystemDep,
  type ToolDefinition,
  type WorkerResult,
} from '../sdk.js'

const PROFILE_IDS = ['ida', 'binary-ninja', 'ghidra', 'radare2'] as const
type ExternalReProfileId = (typeof PROFILE_IDS)[number]

interface ExternalReProfile {
  id: ExternalReProfileId
  backendName: string
  endpointEnvVar: string
  installRoute: 'byo' | 'sidecar'
  installProfile: 'optional' | 'heavy' | 'license-gated'
  licenseGate: 'commercial' | 'open-source' | 'mixed'
  backendVersionHint: string
  sidecarProtocol: string
  commandAllowlist: string[]
  notes: string[]
}

const externalReProfiles: ExternalReProfile[] = [
  {
    id: 'ida',
    backendName: 'IDA Pro MCP sidecar',
    endpointEnvVar: 'IDA_MCP_ENDPOINT',
    installRoute: 'byo',
    installProfile: 'license-gated',
    licenseGate: 'commercial',
    backendVersionHint: 'IDA Pro version plus sidecar plugin commit',
    sidecarProtocol: 'ida-mcp.readonly.v1',
    commandAllowlist: [
      'comments.list',
      'symbols.list',
      'functions.list',
      'xrefs.list',
      'decompile.get',
      'notes.list',
    ],
    notes: [
      'IDA is commercial and must be supplied by the analyst.',
      'Only consume exported artifacts from a local read-only sidecar.',
    ],
  },
  {
    id: 'binary-ninja',
    backendName: 'Binary Ninja MCP sidecar',
    endpointEnvVar: 'BINARY_NINJA_MCP_ENDPOINT',
    installRoute: 'byo',
    installProfile: 'license-gated',
    licenseGate: 'commercial',
    backendVersionHint: 'Binary Ninja build plus sidecar plugin commit',
    sidecarProtocol: 'binary-ninja-mcp.readonly.v1',
    commandAllowlist: [
      'comments.list',
      'symbols.list',
      'functions.list',
      'xrefs.list',
      'decompile.get',
      'notes.list',
    ],
    notes: [
      'Binary Ninja is commercial and must be supplied by the analyst.',
      'Do not accept sidecar output without provenance and backend version metadata.',
    ],
  },
  {
    id: 'ghidra',
    backendName: 'Ghidra MCP sidecar',
    endpointEnvVar: 'GHIDRA_MCP_ENDPOINT',
    installRoute: 'sidecar',
    installProfile: 'heavy',
    licenseGate: 'open-source',
    backendVersionHint: 'Ghidra version plus MCP bridge commit',
    sidecarProtocol: 'ghidra-mcp.readonly.v1',
    commandAllowlist: [
      'comments.list',
      'symbols.list',
      'functions.list',
      'xrefs.list',
      'decompile.get',
      'notes.list',
    ],
    notes: [
      'Ghidra sidecar mode is separate from bundled Ghidra batch workers.',
      'Keep the sidecar local and read-only; do not import projects through this bridge.',
    ],
  },
  {
    id: 'radare2',
    backendName: 'radare2 MCP/r2pipe sidecar',
    endpointEnvVar: 'RADARE2_MCP_ENDPOINT',
    installRoute: 'sidecar',
    installProfile: 'optional',
    licenseGate: 'open-source',
    backendVersionHint: 'radare2 version plus sidecar wrapper commit',
    sidecarProtocol: 'radare2-mcp.readonly.v1',
    commandAllowlist: ['iIj', 'aflj', 'izzj', 'iSj', 'iij', 'axfj'],
    notes: [
      'Use radare2 sidecar output for compatibility checks, not as a trusted oracle.',
      'Keep r2pipe commands on a read-only allowlist.',
    ],
  },
]

const profileById = new Map(externalReProfiles.map((profile) => [profile.id, profile]))

const AddressedTextSchema = z
  .object({
    address: z.string().min(1),
    text: z.string().min(1),
    author: z.string().optional(),
    source: z.string().optional(),
  })
  .passthrough()

const SymbolSchema = z
  .object({
    address: z.string().min(1),
    name: z.string().min(1),
    kind: z.string().optional(),
    source: z.string().optional(),
  })
  .passthrough()

const FunctionSchema = z
  .object({
    address: z.string().min(1),
    name: z.string().optional(),
    size: z.number().nonnegative().optional(),
    signature: z.string().optional(),
    confidence: z.number().min(0).max(1).optional(),
  })
  .passthrough()

const XrefSchema = z
  .object({
    from: z.string().min(1),
    to: z.string().min(1),
    kind: z.string().optional(),
    function: z.string().optional(),
  })
  .passthrough()

const DecompileTextSchema = z
  .object({
    function_address: z.string().optional(),
    function_name: z.string().optional(),
    text: z.string().min(1),
    language: z.string().optional(),
  })
  .passthrough()

const ArtifactManifestSchema = z
  .object({
    comments: z.array(AddressedTextSchema).optional().default([]),
    symbols: z.array(SymbolSchema).optional().default([]),
    functions: z.array(FunctionSchema).optional().default([]),
    xrefs: z.array(XrefSchema).optional().default([]),
    decompile_text: z.array(DecompileTextSchema).optional().default([]),
    analysis_notes: z.array(AddressedTextSchema).optional().default([]),
  })
  .passthrough()

const ExternalReBridgeInputSchema = z.object({
  profile: z.enum(PROFILE_IDS),
  endpoint: z
    .string()
    .min(1)
    .describe('Explicit local sidecar endpoint, for example http://127.0.0.1:4011.'),
  sample_id: z.string().optional(),
  binary_id: z.string().optional(),
  backend_version: z.string().optional(),
  sidecar_version: z.string().optional(),
  requested_operations: z.array(z.string()).optional().default([]),
  artifact_manifest: ArtifactManifestSchema.optional().default({}),
})

const ARTIFACT_TYPES = [
  'external_re_bridge_artifact_bundle',
  'external_re_comments',
  'external_re_symbols',
  'external_re_function_index',
  'external_re_xref_summary',
  'external_re_decompile_text',
  'external_re_analysis_notes',
  'cross_decompiler_input_bundle',
]

const aspects: PluginAspects = {
  formats: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib', 'shellcode'],
  platforms: ['windows', 'linux', 'macos', 'ios', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
  execution: ['static', 'decompilation', 'correlation'],
  runtimes: ['ida-sidecar', 'binary-ninja-sidecar', 'ghidra-sidecar', 'radare2-sidecar'],
  safety: [
    'passive',
    'read_only',
    'no_live_sample_by_default',
    'no_network_by_default',
    'local_endpoint_only',
  ],
  capabilities: [
    'external-re-bridge',
    'sidecar-artifact-sync',
    'cross-decompiler-consensus',
    'function-discovery',
    'xref-correlation',
    'symbol-correlation',
    'comment-sync',
    'analysis-note-sync',
  ],
  evidence: ['structure', 'symbols', 'strings', 'artifact', 'workflow', 'provenance'],
}

function localEndpointStatus(endpoint: string) {
  try {
    const url = new URL(endpoint)
    const protocolAllowed = ['http:', 'ws:'].includes(url.protocol)
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
    const localHost =
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)

    return {
      ok: protocolAllowed && localHost,
      protocol: url.protocol.replace(':', ''),
      host,
      origin: `${url.protocol}//${url.host}`,
      redacted: `${url.protocol}//${url.host}`,
      reasons: [
        ...(protocolAllowed ? [] : ['endpoint_protocol_must_be_http_or_ws']),
        ...(localHost ? [] : ['endpoint_host_must_be_localhost_or_loopback']),
      ],
    }
  } catch {
    return {
      ok: false,
      protocol: null,
      host: null,
      origin: null,
      redacted: endpoint,
      reasons: ['endpoint_must_be_valid_url'],
    }
  }
}

function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, current) => {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return current
    return Object.fromEntries(
      Object.entries(current as Record<string, unknown>).sort(([left], [right]) =>
        left.localeCompare(right)
      )
    )
  })
}

function sha256(value: unknown): string {
  return createHash('sha256').update(stableJson(value)).digest('hex')
}

function countManifest(manifest: z.infer<typeof ArtifactManifestSchema>) {
  return {
    comments: manifest.comments.length,
    symbols: manifest.symbols.length,
    functions: manifest.functions.length,
    xrefs: manifest.xrefs.length,
    decompile_text: manifest.decompile_text.length,
    analysis_notes: manifest.analysis_notes.length,
  }
}

function buildConsensusBundle(
  input: z.infer<typeof ExternalReBridgeInputSchema>,
  profile: ExternalReProfile,
  manifest: z.infer<typeof ArtifactManifestSchema>
) {
  const provenance = {
    source: 'external_re_sidecar',
    profile: profile.id,
    backend: profile.backendName,
    backend_version: input.backend_version ?? 'unknown',
    sidecar_version: input.sidecar_version ?? 'unknown',
    binary_id: input.binary_id ?? input.sample_id ?? null,
    trust: 'untrusted_sidecar_data',
  }

  const artifactSummaries = [
    {
      type: 'external_re_comments',
      count: manifest.comments.length,
      fields: ['address', 'text', 'author', 'source'],
    },
    {
      type: 'external_re_symbols',
      count: manifest.symbols.length,
      fields: ['address', 'name', 'kind', 'source'],
    },
    {
      type: 'external_re_function_index',
      count: manifest.functions.length,
      fields: ['address', 'name', 'size', 'signature', 'confidence'],
    },
    {
      type: 'external_re_xref_summary',
      count: manifest.xrefs.length,
      fields: ['from', 'to', 'kind', 'function'],
    },
    {
      type: 'external_re_decompile_text',
      count: manifest.decompile_text.length,
      fields: ['function_address', 'function_name', 'text', 'language'],
    },
    {
      type: 'external_re_analysis_notes',
      count: manifest.analysis_notes.length,
      fields: ['address', 'text', 'author', 'source'],
    },
  ]

  return {
    type: 'cross_decompiler_input_bundle',
    schema_version: 'cross-decompiler-input.v1',
    compatible_tools: ['code.cross_decompiler.consensus', 'analysis.evidence.graph'],
    source_backend: profile.id,
    provenance,
    functions: manifest.functions.map((func) => ({
      backend: profile.id,
      address: func.address,
      name: func.name ?? null,
      size: func.size ?? null,
      signature: func.signature ?? null,
      confidence: func.confidence ?? null,
      provenance,
    })),
    xrefs: manifest.xrefs.map((xref) => ({ backend: profile.id, ...xref, provenance })),
    symbols: manifest.symbols.map((symbol) => ({ backend: profile.id, ...symbol, provenance })),
    decompile_text: manifest.decompile_text.map((entry) => ({
      backend: profile.id,
      ...entry,
      provenance,
    })),
    comments: manifest.comments.map((comment) => ({ backend: profile.id, ...comment, provenance })),
    analysis_notes: manifest.analysis_notes.map((note) => ({
      backend: profile.id,
      ...note,
      provenance,
    })),
    artifact_summaries: artifactSummaries,
  }
}

function buildReadiness(
  profile: ExternalReProfile,
  endpoint: ReturnType<typeof localEndpointStatus>
) {
  return {
    status: endpoint.ok ? 'sidecar_configured_not_contacted' : 'endpoint_policy_denied',
    profile: profile.id,
    backend_name: profile.backendName,
    endpoint_configured: true,
    endpoint_local_only: endpoint.ok,
    endpoint_redacted: endpoint.redacted,
    does_not_start_backend: true,
    sidecar_contacted: false,
    install_route: profile.installRoute,
    install_profile: profile.installProfile,
    requires_byo: profile.installRoute === 'byo',
    requires_sidecar: profile.installRoute === 'sidecar',
    license_gate: profile.licenseGate,
    setup_actions: [
      `Set ${profile.endpointEnvVar} to a localhost or loopback HTTP/WS sidecar endpoint.`,
      'Export artifacts from the sidecar using the read-only artifact contract.',
      'Include backend_version and sidecar_version before feeding consensus workflows.',
    ],
    denial_reasons: endpoint.reasons,
  }
}

function buildExternalBridgeResult(input: z.infer<typeof ExternalReBridgeInputSchema>) {
  const profile = profileById.get(input.profile)
  if (!profile) {
    throw new Error(`Unsupported external RE profile: ${input.profile}`)
  }

  const endpoint = localEndpointStatus(input.endpoint)
  const manifest = ArtifactManifestSchema.parse(input.artifact_manifest)
  const readiness = buildReadiness(profile, endpoint)
  const consensusBundle = buildConsensusBundle(input, profile, manifest)
  const artifactBundle = {
    type: 'external_re_bridge_artifact_bundle',
    schema_version: 'external-re-bridge.v1',
    profile: profile.id,
    backend_name: profile.backendName,
    backend_version: input.backend_version ?? 'unknown',
    sidecar_version: input.sidecar_version ?? 'unknown',
    sample_id: input.sample_id ?? null,
    binary_id: input.binary_id ?? input.sample_id ?? null,
    endpoint: {
      configured: true,
      local_only: endpoint.ok,
      redacted: endpoint.redacted,
      contacted: false,
    },
    policy: {
      passive: true,
      read_only: true,
      no_backend_start: true,
      no_remote_command_execution: true,
      no_sidecar_mutation: true,
      no_sample_execution: true,
      no_network_except_local_sidecar: true,
      sidecar_data_trust: 'untrusted_until_consensus',
    },
    supported_artifact_directions: [
      'import_from_sidecar.comments',
      'import_from_sidecar.symbols',
      'import_from_sidecar.function_list',
      'import_from_sidecar.xrefs',
      'import_from_sidecar.decompile_text',
      'import_from_sidecar.analysis_notes',
      'export_preview.comments',
      'export_preview.symbols',
      'export_preview.analysis_notes',
    ],
    command_allowlist: profile.commandAllowlist,
    requested_operations: input.requested_operations,
    artifact_counts: countManifest(manifest),
    artifact_types: ARTIFACT_TYPES,
    artifacts: {
      comments: manifest.comments,
      symbols: manifest.symbols,
      functions: manifest.functions,
      xrefs: manifest.xrefs,
      decompile_text: manifest.decompile_text,
      analysis_notes: manifest.analysis_notes,
    },
    consensus_bundle: consensusBundle,
  }

  return { endpoint, readiness, artifactBundle, consensusBundle, profile }
}

function createExternalReBridgeHandler() {
  return async (args: z.infer<typeof ExternalReBridgeInputSchema>): Promise<WorkerResult> => {
    const input = ExternalReBridgeInputSchema.parse(args)
    const { endpoint, readiness, artifactBundle, consensusBundle, profile } =
      buildExternalBridgeResult(input)

    if (!endpoint.ok) {
      return {
        ok: false,
        status: 'failed',
        data: {
          result_mode: 'external_re_bridge',
          readiness,
          policy_denied: true,
          execution_semantics: {
            requested_mode: 'artifact_sync',
            actual_mode: 'policy_denied',
            live_execution: false,
            sidecar_contacted: false,
            reason: 'External RE bridge endpoints must be explicit local HTTP/WS loopback URLs.',
          },
        },
        errors: endpoint.reasons,
        metrics: { elapsed_ms: 0, tool: 'external_re.bridge.sync' },
      }
    }

    const bundleHash = sha256(artifactBundle)
    const samplePart = input.sample_id ?? input.binary_id ?? 'unspecified'
    return {
      ok: true,
      data: {
        result_mode: 'external_re_bridge',
        bridge_contract_version: 'external-re-bridge.v1',
        profile: profile.id,
        readiness,
        artifact_bundle: artifactBundle,
        consensus_bundle: consensusBundle,
        recommended_next_tools: ['code.cross_decompiler.consensus', 'analysis.evidence.graph'],
        execution_semantics: {
          requested_mode: 'artifact_sync',
          actual_mode: 'local_contract_only',
          live_execution: false,
          sidecar_contacted: false,
          backend: profile.backendName,
          reason:
            'Bridge contract normalized provided artifact metadata without contacting sidecar.',
        },
      },
      artifacts: [
        {
          id: `external-re-bridge:${profile.id}:${samplePart}`,
          type: 'external_re_bridge_artifact_bundle',
          path: `memory://external-re-bridge/${profile.id}/${samplePart}.json`,
          sha256: bundleHash,
          mime: 'application/json',
          metadata: {
            consensus_consumable: true,
            consensus_artifact_type: 'cross_decompiler_input_bundle',
            backend: profile.id,
            backend_version: input.backend_version ?? 'unknown',
          },
        },
      ],
      evidence: [
        {
          id: `external-re-bridge:${profile.id}:provenance:${samplePart}`,
          category: 'provenance',
          source: 'external-re-bridge',
          toolName: 'external_re.bridge.sync',
          sampleId: input.sample_id,
          confidence: 0.6,
          metadata: {
            backend: profile.backendName,
            profile: profile.id,
            backend_version: input.backend_version ?? 'unknown',
            sidecar_version: input.sidecar_version ?? 'unknown',
            sidecar_contacted: false,
            trust: 'untrusted_sidecar_data',
          },
        },
      ],
      metrics: { elapsed_ms: 0, tool: 'external_re.bridge.sync' },
    }
  }
}

const workerBackend: BackendWorkerContract = {
  version: 'backend-worker.v1',
  backendName: 'External RE MCP sidecar bridge',
  backendKind: 'external',
  adapter: 'external-re-bridge.readonly-artifact-sync',
  availability: 'optional',
  envVar: 'EXTERNAL_RE_BRIDGE_ENDPOINT',
  commandHint: 'Configure a local sidecar endpoint; this bridge never starts it.',
  versionHint: 'Use backend_version and sidecar_version input fields.',
  supportedModes: ['builtin', 'external'],
  defaultMode: 'builtin',
  inputArtifactTypes: ['local_artifact', 'sidecar_artifact_manifest'],
  outputArtifactTypes: ARTIFACT_TYPES,
  policy: {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: false,
    noNetwork: false,
    noMutation: true,
    noLiveExecution: true,
    defaultTimeoutMs: 10_000,
    maxInputBytes: 2 * 1024 * 1024,
    maxOutputBytes: 10 * 1024 * 1024,
    notes: [
      'Only loopback HTTP/WS endpoints are accepted.',
      'Readiness and default execution never contact the sidecar.',
      'Sidecar output is marked untrusted until cross-decompiler consensus consumes it.',
    ],
  },
  readiness: {
    doesNotStartBackend: true,
    setupActions: externalReProfiles.map(
      (profile) => `Set ${profile.endpointEnvVar} for ${profile.backendName}.`
    ),
    missingBackendBehavior:
      'Return endpoint_policy_denied or sidecar_configured_not_contacted; never auto-start IDA, Binary Ninja, Ghidra, radare2, or an MCP sidecar.',
    sidecarProfiles: externalReProfiles,
  },
  packaging: {
    installRoute: 'sidecar',
    installProfile: 'license-gated',
    dockerFeature: 'external-re-bridge-sidecar',
    envVar: 'EXTERNAL_RE_BRIDGE_ENDPOINT',
    notes: [
      'Generic bridge metadata only; commercial IDEs and heavy RE tools are bring-your-own.',
      'Use profile-specific endpoint env vars for IDA, Binary Ninja, Ghidra, or radare2 sidecars.',
    ],
  },
}

const bridgeToolDefinition: ToolDefinition = {
  name: 'external_re.bridge.sync',
  description:
    'Normalize read-only artifact manifests from local external RE MCP sidecars into cross-decompiler consensus inputs without contacting or starting the sidecar.',
  inputSchema: ExternalReBridgeInputSchema,
  outputSchema: WorkerResultOutputSchema,
  aspects,
  artifacts: ARTIFACT_TYPES.map((type) => ({
    type,
    description:
      type === 'cross_decompiler_input_bundle'
        ? 'Consensus-ready function, xref, symbol, decompile text, comment, and note bundle'
        : 'External reverse-engineering sidecar artifact',
  })),
  evidence: [
    { category: 'structure', artifactTypes: ['external_re_function_index'] },
    { category: 'symbols', artifactTypes: ['external_re_symbols'] },
    { category: 'artifact', artifactTypes: ['external_re_bridge_artifact_bundle'] },
    { category: 'workflow', artifactTypes: ['cross_decompiler_input_bundle'] },
    { category: 'provenance', artifactTypes: ['external_re_bridge_artifact_bundle'] },
  ],
  workflowRecipes: [
    {
      id: 'external-re-bridge.cross-decompiler-consensus',
      title: 'External RE sidecar artifact consensus',
      description:
        'Import read-only external RE sidecar artifacts and feed cross-decompiler consensus without trusting the sidecar as authoritative.',
      startsWith: ['external_re.bridge.sync', 'tool.readiness'],
      nextTools: ['code.cross_decompiler.consensus', 'analysis.evidence.graph', 'report.generate'],
      requiredArtifacts: ['sidecar_artifact_manifest'],
      producesArtifacts: ARTIFACT_TYPES,
      evidence: ['structure', 'symbols', 'artifact', 'workflow', 'provenance'],
      safety: [
        'passive',
        'read_only',
        'no_live_sample_by_default',
        'local_endpoint_only',
        'no_remote_command_execution',
      ],
      runtimeBackends: aspects.runtimes,
    },
  ],
  workerBackend,
}

function systemDepForProfile(profile: ExternalReProfile): PluginSystemDep {
  return {
    type: 'env-var',
    name: profile.backendName,
    envVar: profile.endpointEnvVar,
    required: false,
    description: `${profile.backendName} local read-only endpoint`,
    dockerInstall:
      profile.installRoute === 'byo'
        ? `Provide ${profile.backendName} outside the default image and set ${profile.endpointEnvVar}.`
        : `Run a local ${profile.backendName} sidecar and set ${profile.endpointEnvVar}.`,
    dockerFeature: `${profile.id}-mcp-sidecar`,
    dockerInstallRoute: profile.installRoute,
    dockerInstallProfile: profile.installProfile,
    dockerInstallNotes: [
      `Protocol: ${profile.sidecarProtocol}.`,
      `Version hint: ${profile.backendVersionHint}.`,
      ...profile.notes,
    ],
  }
}

const externalReBridgePlugin = definePlugin({
  id: 'external-re-bridge',
  name: 'External RE Bridge',
  executionDomain: 'static',
  aspects,
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'firmware', 'object', 'static-lib', 'shellcode'],
      findings: ['cross-backend-check', 'function-gap', 'xref-gap', 'low-decompiler-confidence'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Read-only BYO/sidecar bridge contract for IDA, Binary Ninja, Ghidra, and radare2 artifact exchange.',
  version: '1.0.0',
  configSchema: externalReProfiles.map((profile) => ({
    envVar: profile.endpointEnvVar,
    description: `${profile.backendName} local endpoint, for example http://127.0.0.1:4011`,
    required: false,
    defaultValue: 'http://127.0.0.1:<port>',
  })),
  systemDeps: externalReProfiles.map(systemDepForProfile),
  tools: [
    defineTool({
      ...bridgeToolDefinition,
      handler: createExternalReBridgeHandler(),
    }),
  ],
})

export {
  ExternalReBridgeInputSchema,
  externalReProfiles,
  localEndpointStatus,
  buildExternalBridgeResult,
}
export default externalReBridgePlugin
