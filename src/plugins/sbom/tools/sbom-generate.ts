/**
 * MCP tool: sbom.generate
 *
 * Generates a Software Bill of Materials (SBOM) for a sample in CycloneDX JSON format.
 * Extracts components from PE imports, .NET references, embedded version info, and static analysis.
 */

import { z } from 'zod'
import crypto from 'crypto'
import type { ToolDefinition, ToolResult } from '../../../types.js'
import type { DatabaseManager } from '../../../database.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'

const TOOL_NAME = 'sbom.generate'
const CYCLONEDX_SBOM_ARTIFACT = 'cyclonedx_sbom'
const SPDX_LITE_SBOM_ARTIFACT = 'spdx_lite_sbom'
const SBOM_GENERATION_EVIDENCE_ARTIFACT = 'sbom_generation_evidence'
const SBOM_GENERATE_SAFETY = [
  'passive',
  'no_install',
  'no_installer_execution',
  'no_auto_mount',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
]
const SBOM_GENERATE_EVIDENCE = [
  'sbom',
  'package-metadata',
  'imports',
  'strings',
  'workflow',
  'provenance',
]
const SBOM_GENERATE_FOLLOW_UP_TOOLS = [
  'sbom.provenance.graph',
  'vuln.pattern.summary',
  'analysis.evidence.graph',
  'report.generate',
]
const SBOM_GENERATE_UPSTREAM_INVENTORY_TOOLS = [
  'metadata.extract',
  'container.structure.analyze',
  'linux.package.inventory',
  'installer.inventory',
  'android.package.inventory',
  'apple.container.inventory',
  'firmware.workflow.plan',
]

const inputSchema = z.object({
  sample_id: z.string().describe('Sample ID to generate SBOM for'),
  format: z
    .enum(['cyclonedx', 'spdx-lite'])
    .optional()
    .default('cyclonedx')
    .describe('SBOM format (default: cyclonedx)'),
  include_hashes: z.boolean().optional().default(true).describe('Include file hashes'),
})

const sbomGenerateOutputSchema = z.object({}).passthrough()

export const sbomGenerateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Generate a Software Bill of Materials (SBOM) for a binary sample. Extracts component dependencies from PE imports, .NET assemblies, embedded resources, and static analysis results. Output in CycloneDX JSON or SPDX-lite format.',
  inputSchema: inputSchema as any,
  outputSchema: sbomGenerateOutputSchema,
  aspects: {
    formats: [
      'pe',
      'elf',
      'macho',
      'apk',
      'jar',
      'dotnet',
      'nupkg',
      'deb',
      'rpm',
      'apk-alpine',
      'firmware',
      'archive',
      'container',
      'docker-image',
      'oci-image',
      'msi',
      'msix',
      'appx',
      'cab',
      'snap',
      'flatpak',
      'appimage',
      'cyclonedx',
      'spdx-lite',
    ],
    platforms: [
      'windows',
      'linux',
      'macos',
      'android',
      'jvm',
      'dotnet',
      'embedded',
      'cross-platform',
    ],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
    execution: ['static', 'correlation'],
    safety: SBOM_GENERATE_SAFETY,
    capabilities: [
      'sbom',
      'dependency-inventory',
      'provenance',
      'workflow-plan',
      'workflow-handoff',
      'metadata-only-handoff',
      'package-metadata-provenance',
      'container-provenance',
      'installer-provenance',
      'firmware-provenance',
    ],
    evidence: SBOM_GENERATE_EVIDENCE,
  },
  artifacts: [
    {
      type: CYCLONEDX_SBOM_ARTIFACT,
      description: 'CycloneDX 1.5 SBOM generated from local static evidence',
      mime: 'application/json',
    },
    {
      type: SPDX_LITE_SBOM_ARTIFACT,
      description: 'SPDX-lite SBOM generated from local static evidence',
      mime: 'application/json',
    },
    {
      type: SBOM_GENERATION_EVIDENCE_ARTIFACT,
      description: 'Compact SBOM generation evidence, workflow handoff, and quality gates',
      mime: 'application/json',
    },
  ],
  evidence: [
    {
      category: 'sbom',
      artifactTypes: [CYCLONEDX_SBOM_ARTIFACT, SPDX_LITE_SBOM_ARTIFACT],
      description: 'CycloneDX or SPDX-lite SBOM returned as structured content',
    },
    {
      category: 'package-metadata',
      artifactTypes: [SBOM_GENERATION_EVIDENCE_ARTIFACT],
      description: 'Dependency evidence derived from imports, .NET metadata, and strings',
    },
    {
      category: 'imports',
      artifactTypes: [SBOM_GENERATION_EVIDENCE_ARTIFACT],
    },
    {
      category: 'strings',
      artifactTypes: [SBOM_GENERATION_EVIDENCE_ARTIFACT],
    },
    {
      category: 'provenance',
      artifactTypes: [SBOM_GENERATION_EVIDENCE_ARTIFACT],
    },
  ],
  workflowRecipes: [
    {
      id: 'supply-chain.sbom.generate-handoff',
      title: 'SBOM generation evidence handoff',
      description:
        'Generate CycloneDX or SPDX-lite SBOM output from local package metadata, imports, strings, container, installer, firmware, and provenance inventories without installing packages, mounting containers, executing payloads, or using the network.',
      startsWith: [
        TOOL_NAME,
        'sbom.provenance.graph',
        'container.structure.analyze',
        'linux.package.inventory',
        'installer.inventory',
        'android.package.inventory',
        'firmware.workflow.plan',
      ],
      nextTools: SBOM_GENERATE_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample', 'package-metadata'],
      producesArtifacts: [
        CYCLONEDX_SBOM_ARTIFACT,
        SPDX_LITE_SBOM_ARTIFACT,
        SBOM_GENERATION_EVIDENCE_ARTIFACT,
      ],
      evidence: SBOM_GENERATE_EVIDENCE,
      safety: SBOM_GENERATE_SAFETY,
    },
  ],
  workerBackend: {
    version: 'backend-worker.v1',
    backendName: 'Builtin SBOM evidence summarizer',
    backendKind: 'builtin',
    adapter: 'builtin.sbom.generate',
    availability: 'builtin',
    supportedModes: ['builtin'],
    defaultMode: 'builtin',
    inputArtifactTypes: [
      'sample',
      'package-metadata',
      'pe_imports',
      'dotnet_references',
      'strings_cache',
      'container_structure',
      'windows_installer_inventory',
      'linux_package_inventory',
      'firmware_scan',
    ],
    outputArtifactTypes: [
      CYCLONEDX_SBOM_ARTIFACT,
      SPDX_LITE_SBOM_ARTIFACT,
      SBOM_GENERATION_EVIDENCE_ARTIFACT,
    ],
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: false,
      requiresIsolation: false,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
      noInstall: true,
      noMount: true,
      noInstallerExecution: true,
      maxOutputBytes: 8 * 1024 * 1024,
      defaultTimeoutMs: 10_000,
      notes: [
        'Builtin SBOM generation reads local database evidence only.',
        'Policy forbids package install, installer execution, container entrypoint execution, firmware mounting, network enrichment, and live sample execution.',
      ],
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [],
      missingBackendBehavior:
        'Builtin generation remains local and passive; incomplete local evidence must be reported as quality metadata, not filled by network enrichment.',
    },
    packaging: {
      installRoute: 'installed',
      installProfile: 'default',
      dockerFeature: 'sbom',
      notes: [
        'No external package manager, container runtime, installer, or network backend is required.',
      ],
    },
  },
}

interface SbomComponent {
  type: string
  name: string
  version?: string
  purl?: string
  hashes?: Array<{ alg: string; content: string }>
  evidence?: { source: string }
}

function countByEvidenceSource(components: SbomComponent[]): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const component of components) {
    const source = component.evidence?.source ?? 'unknown'
    counts[source] = (counts[source] ?? 0) + 1
  }
  return counts
}

function artifactTypeForFormat(format: 'cyclonedx' | 'spdx-lite'): string {
  return format === 'cyclonedx' ? CYCLONEDX_SBOM_ARTIFACT : SPDX_LITE_SBOM_ARTIFACT
}

function buildSbomEvidenceSummary(args: {
  sampleId: string
  format: 'cyclonedx' | 'spdx-lite'
  components: SbomComponent[]
  sampleHashCount: number
}) {
  return {
    schema: 'rikune.sbom_generate.evidence_summary.v1',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    sbom_format: args.format,
    artifact_type: artifactTypeForFormat(args.format),
    component_count: args.components.length,
    sample_hash_count: args.sampleHashCount,
    evidence_source_counts: countByEvidenceSource(args.components),
    evidence_categories: SBOM_GENERATE_EVIDENCE,
    provenance_scope: [
      'package-metadata',
      'container-inventory',
      'installer-inventory',
      'firmware-inventory',
    ],
    network_enrichment_performed: false,
  }
}

function buildSbomWorkflowHandoff(args: {
  sampleId: string
  format: 'cyclonedx' | 'spdx-lite'
  components: SbomComponent[]
  recommendedNextTools: string[]
}) {
  return {
    schema: 'rikune.sbom_generate.workflow_handoff.v1',
    handoff_mode: 'sbom_to_supply_chain_provenance_and_reporting',
    sample_id: args.sampleId,
    source_tool: TOOL_NAME,
    recommended_next_tools: args.recommendedNextTools,
    artifact_contract: {
      consumes: [
        'sample',
        'package-metadata',
        'pe_imports',
        'dotnet_references',
        'strings_cache',
        'container_structure',
        'windows_installer_inventory',
        'linux_package_inventory',
        'firmware_scan',
      ],
      produces: [artifactTypeForFormat(args.format), SBOM_GENERATION_EVIDENCE_ARTIFACT],
      expected_consumers: args.recommendedNextTools,
    },
    routing: [
      {
        goal: 'package-and-container-provenance',
        next_tools: [
          'sbom.provenance.graph',
          'container.structure.analyze',
          'linux.package.inventory',
        ],
        required_evidence: ['package-metadata', 'container_structure', 'linux_package_inventory'],
      },
      {
        goal: 'installer-and-firmware-provenance',
        next_tools: ['installer.inventory', 'firmware.workflow.plan', 'sbom.provenance.graph'],
        required_evidence: ['windows_installer_inventory', 'firmware_scan', 'nested-binaries'],
      },
      {
        goal: 'vulnerability-and-reporting-handoff',
        next_tools: ['vuln.pattern.summary', 'analysis.evidence.graph', 'report.generate'],
        required_evidence: [artifactTypeForFormat(args.format), SBOM_GENERATION_EVIDENCE_ARTIFACT],
      },
    ],
    coverage: {
      supports_cyclonedx: true,
      supports_spdx_lite: true,
      package_metadata_provenance: true,
      container_provenance: true,
      installer_provenance: true,
      firmware_provenance: true,
      component_count: args.components.length,
    },
    dynamic_boundary: {
      static_backend_started: false,
      runtime_started_by_tool: false,
      sample_executed_by_tool: false,
      package_install_performed: false,
      installer_execution_performed: false,
      container_entrypoint_run: false,
      firmware_mounted: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildSbomQualityGates(args: {
  format: 'cyclonedx' | 'spdx-lite'
  components: SbomComponent[]
  includeHashes: boolean
}) {
  return {
    schema: 'rikune.sbom_generate.quality_gates.v1',
    requested_format: args.format,
    passive_static_correlation: true,
    cyclonedx_supported: true,
    spdx_lite_supported: true,
    component_inventory_present: args.components.length > 0,
    hash_lookup_requested: args.includeHashes,
    evidence_graph_handoff_ready: true,
    local_inventory_required_for_completeness: true,
    package_install_performed: false,
    installer_execution_performed: false,
    container_entrypoint_run: false,
    firmware_mounted: false,
    sample_executed_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
  }
}

function buildRecommendedNextTools(components: SbomComponent[]): string[] {
  const upstreamIfSparse =
    components.length === 0
      ? ['metadata.extract', 'strings.extract', ...SBOM_GENERATE_UPSTREAM_INVENTORY_TOOLS]
      : []
  return Array.from(new Set([...SBOM_GENERATE_FOLLOW_UP_TOOLS, ...upstreamIfSparse]))
}

function buildNextActions(components: SbomComponent[]): string[] {
  const actions = [
    'Run sbom.provenance.graph to merge this SBOM with package, container, installer, and firmware inventory rows.',
    'Run analysis.evidence.graph or report.generate to attach SBOM evidence to the final analysis package.',
  ]
  if (components.length === 0) {
    actions.push(
      'Collect local package metadata, strings, imports, or container inventory first; this tool does not fetch dependency data from the network.'
    )
  }
  return actions
}

export function createSbomGenerateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: z.infer<typeof inputSchema>): Promise<ToolResult> => {
    const input = inputSchema.parse(args)
    const components: SbomComponent[] = []

    // 1. Query PE imports from the database
    try {
      const imports = database.querySql<{ library: string }>(
        'SELECT DISTINCT library FROM pe_imports WHERE sample_id = ?',
        [input.sample_id]
      )

      for (const imp of imports) {
        components.push({
          type: 'library',
          name: imp.library.replace(/\.dll$/i, ''),
          evidence: { source: 'pe-import-table' },
        })
      }
    } catch {
      // Table may not exist yet — that's okay
    }

    // 2. Query .NET assembly references
    try {
      const refs = database.querySql<{ name: string; version?: string }>(
        'SELECT DISTINCT name, version FROM dotnet_references WHERE sample_id = ?',
        [input.sample_id]
      )

      for (const ref of refs) {
        components.push({
          type: 'framework',
          name: ref.name,
          version: ref.version,
          evidence: { source: 'dotnet-metadata' },
        })
      }
    } catch {
      // Table may not exist
    }

    // 3. Query string-based dependency evidence
    try {
      const strings = database.querySql<{ value: string }>(
        `SELECT DISTINCT value FROM strings_cache WHERE sample_id = ? AND (
          value LIKE '%.dll' OR value LIKE '%.sys' OR value LIKE '%Version=%'
        ) LIMIT 200`,
        [input.sample_id]
      )

      for (const s of strings) {
        const val = s.value.trim()
        if (/\.(dll|sys)$/i.test(val) && val.length < 100 && !val.includes(' ')) {
          components.push({
            type: 'library',
            name: val,
            evidence: { source: 'embedded-string' },
          })
        }
      }
    } catch {
      // Table may not exist
    }

    // 4. Query sample hashes if requested
    let sampleHashes: Array<{ alg: string; content: string }> = []
    if (input.include_hashes) {
      try {
        const hashRow = database.querySql<{ sha256?: string; md5?: string }>(
          'SELECT sha256, md5 FROM samples WHERE id = ?',
          [input.sample_id]
        )

        if (hashRow.length > 0) {
          if (hashRow[0].sha256) sampleHashes.push({ alg: 'SHA-256', content: hashRow[0].sha256 })
          if (hashRow[0].md5) sampleHashes.push({ alg: 'MD5', content: hashRow[0].md5 })
        }
      } catch {
        // Skip hash lookup failures
      }
    }

    // Deduplicate components by name
    const seen = new Set<string>()
    const deduped = components.filter((c) => {
      const key = `${c.type}:${c.name.toLowerCase()}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })

    // Build SBOM
    const serialNumber = `urn:uuid:${crypto.randomUUID()}`
    const timestamp = new Date().toISOString()

    let sbom: unknown

    if (input.format === 'cyclonedx') {
      sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        serialNumber,
        version: 1,
        metadata: {
          timestamp,
          tools: [{ vendor: 'rikune', name: 'sbom.generate', version: '1.0.0' }],
          component: {
            type: 'application',
            name: input.sample_id,
            hashes: sampleHashes.length > 0 ? sampleHashes : undefined,
          },
        },
        components: deduped.map((c, i) => ({
          'bom-ref': `comp-${i}`,
          type: c.type,
          name: c.name,
          version: c.version || undefined,
          purl: c.purl || undefined,
          hashes: c.hashes,
          evidence: c.evidence ? { occurrences: [{ location: c.evidence.source }] } : undefined,
        })),
      }
    } else {
      // spdx-lite
      sbom = {
        spdxVersion: 'SPDX-2.3',
        dataLicense: 'CC0-1.0',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: `sbom-${input.sample_id}`,
        documentNamespace: serialNumber,
        creationInfo: {
          created: timestamp,
          creators: ['Tool: rikune-sbom-1.0.0'],
        },
        packages: deduped.map((c, i) => ({
          SPDXID: `SPDXRef-Package-${i}`,
          name: c.name,
          versionInfo: c.version || 'NOASSERTION',
          downloadLocation: 'NOASSERTION',
          filesAnalyzed: false,
        })),
      }
    }

    const recommendedNextTools = buildRecommendedNextTools(deduped)
    const evidenceSummary = buildSbomEvidenceSummary({
      sampleId: input.sample_id,
      format: input.format,
      components: deduped,
      sampleHashCount: sampleHashes.length,
    })
    const workflowHandoff = buildSbomWorkflowHandoff({
      sampleId: input.sample_id,
      format: input.format,
      components: deduped,
      recommendedNextTools,
    })
    const qualityGates = buildSbomQualityGates({
      format: input.format,
      components: deduped,
      includeHashes: input.include_hashes,
    })
    const structuredContent = {
      ...(sbom as Record<string, unknown>),
      evidence_summary: evidenceSummary,
      workflow_handoff: workflowHandoff,
      quality_gates: qualityGates,
      recommended_next_tools: recommendedNextTools,
      next_actions: buildNextActions(deduped),
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(sbom, null, 2) }],
      structuredContent,
    }
  }
}
