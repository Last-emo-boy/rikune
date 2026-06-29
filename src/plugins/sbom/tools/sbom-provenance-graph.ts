import { z } from 'zod'
import { type ToolDefinition, type WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'sbom.provenance.graph'

export const SbomProvenanceGraphInputSchema = z
  .object({
    sample_id: z.string().optional().describe('Optional sample ID for graph metadata.'),
    sources: z
      .record(z.string(), z.any())
      .optional()
      .default({})
      .describe('Inventory outputs keyed by source tool or inventory family.'),
    components: z
      .array(z.record(z.string(), z.any()))
      .optional()
      .default([])
      .describe('Optional explicit component rows to merge into the graph.'),
    include_vuln_handoff: z
      .boolean()
      .optional()
      .default(true)
      .describe('Include local vulnerability scanner follow-up recommendations.'),
  })
  .passthrough()

export const SbomProvenanceGraphOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.string(), z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const sbomProvenanceGraphToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a deterministic supply-chain provenance graph from local package, container, installer, Android, firmware, and SBOM inventory rows. It merges duplicate components and preserves evidence sources without installing, mounting, executing, or fetching vulnerability data.',
  inputSchema: SbomProvenanceGraphInputSchema,
  outputSchema: SbomProvenanceGraphOutputSchema,
  aspects: {
    formats: [
      'archive',
      'container',
      'docker-image',
      'oci-image',
      'deb',
      'rpm',
      'apk-alpine',
      'msi',
      'msix',
      'appx',
      'apk',
      'firmware',
      'wasm',
    ],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'wasm', 'cross-platform'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_installer_execution', 'no_auto_mount', 'no_network_by_default'],
    capabilities: ['sbom', 'provenance-graph', 'dependency-inventory', 'workflow-plan'],
    evidence: ['sbom', 'package-metadata', 'nested-binaries', 'provenance', 'workflow'],
  },
  artifacts: [
    {
      type: 'sbom_provenance_graph',
      description: 'Deterministic component provenance graph with CycloneDX and SPDX-lite views',
    },
  ],
  evidence: [
    { category: 'sbom', artifactTypes: ['sbom_provenance_graph'] },
    { category: 'package-metadata', artifactTypes: ['sbom_provenance_graph'] },
    { category: 'nested-binaries', artifactTypes: ['sbom_provenance_graph'] },
    { category: 'provenance', artifactTypes: ['sbom_provenance_graph'] },
  ],
  workflowRecipes: [
    {
      id: 'supply-chain.sbom.provenance',
      title: 'Supply-chain SBOM provenance graph',
      startsWith: [
        'container.structure.analyze',
        'linux.package.inventory',
        'installer.inventory',
        'android.package.inventory',
        'firmware.workflow.plan',
        'sbom.provenance.graph',
      ],
      nextTools: ['sbom.generate', 'vuln.pattern.summary', 'report.generate'],
      requiredArtifacts: [
        'container_structure',
        'linux_package_inventory',
        'windows_installer_inventory',
        'android_package_inventory',
        'firmware_scan',
      ],
      producesArtifacts: ['sbom_provenance_graph'],
      evidence: ['sbom', 'package-metadata', 'nested-binaries', 'provenance'],
      safety: ['passive', 'no_installer_execution', 'no_auto_mount', 'no_network_by_default'],
    },
  ],
}

type JsonRow = Record<string, unknown>

interface ComponentCandidate {
  type: string
  name: string
  version?: string
  path?: string
  source: string
  evidenceType: string
}

function objectValue(value: unknown): JsonRow {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as JsonRow) : {}
}

function rowsFrom(value: unknown): JsonRow[] {
  if (!value) return []
  if (Array.isArray(value)) return value.map(objectValue).filter((row) => Object.keys(row).length)
  const obj = objectValue(value)
  return Object.keys(obj).length > 0 ? [obj] : []
}

function stringValue(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim()) return value.trim()
  if (typeof value === 'number') return String(value)
  return undefined
}

function normalizeName(value: string): string {
  return value.replace(/\\/g, '/').replace(/^.*\//, '').trim()
}

function classifyComponent(name: string, fallback = 'file'): string {
  const lower = name.toLowerCase()
  if (/\.(?:dll|sys|exe|efi)$/.test(lower)) return 'windows-binary'
  if (/\.(?:so|elf|ko)$/.test(lower)) return 'linux-binary'
  if (/\.(?:dylib|macho)$/.test(lower) || lower.includes('.framework')) return 'apple-binary'
  if (/\.(?:apk|aab|apks|xapk|dex|aar)$/.test(lower)) return 'android-component'
  if (/\.(?:deb|rpm|appimage|snap|flatpak)$/.test(lower)) return 'linux-package'
  if (/\.(?:msi|msix|appx|cab)$/.test(lower)) return 'windows-installer'
  if (/\.(?:uimage|fit|itb|dtb|squashfs|cramfs|jffs2|ubi|ubifs|romfs|cpio)$/.test(lower)) {
    return 'firmware-component'
  }
  if (lower.endsWith('.wasm')) return 'wasm-module'
  return fallback
}

function componentFromRow(
  source: string,
  evidenceType: string,
  row: JsonRow
): ComponentCandidate | null {
  const rawName =
    stringValue(row.name) ??
    stringValue(row.component) ??
    stringValue(row.package) ??
    stringValue(row.library) ??
    stringValue(row.path) ??
    stringValue(row.description) ??
    stringValue(row.value)
  if (!rawName) return null
  const path = stringValue(row.path)
  const name = path ? normalizeName(path) : normalizeName(rawName)
  if (!name) return null
  const rowType =
    stringValue(row.type) ?? stringValue(row.type_hint) ?? stringValue(row.package_format)
  return {
    type: rowType ?? classifyComponent(name),
    name,
    version: stringValue(row.version),
    path,
    source,
    evidenceType,
  }
}

function collectRows(
  source: string,
  value: unknown
): Array<{ evidenceType: string; row: JsonRow }> {
  const obj = objectValue(value)
  const rows: Array<{ evidenceType: string; row: JsonRow }> = []

  for (const key of [
    'components',
    'packages',
    'dependencies',
    'entries',
    'archive_members',
    'nested_binary_candidates',
    'nested_payload_candidates',
    'native_library_candidates',
    'nested_package_candidates',
    'nested_macho_candidates',
    'signatures',
    'manifest_candidates',
    'maintainer_script_candidates',
    'script_candidates',
    'custom_action_candidates',
  ]) {
    const valueRows = rowsFrom(obj[key]).map((row) => ({ evidenceType: key, row }))
    if (Array.isArray(obj[key]) && obj[key]?.every((item) => typeof item === 'string')) {
      rows.push(
        ...(obj[key] as string[]).map((item) => ({
          evidenceType: key,
          row: { path: item, type: classifyComponent(item, key) },
        }))
      )
    } else {
      rows.push(...valueRows)
    }
  }

  if (rows.length === 0 && Object.keys(obj).length > 0) {
    rows.push({ evidenceType: source, row: obj })
  }
  return rows
}

function stableComponentKey(candidate: ComponentCandidate): string {
  return `${candidate.type}:${candidate.name}:${candidate.version ?? ''}`.toLowerCase()
}

function mergeCandidates(candidates: ComponentCandidate[]) {
  const merged = new Map<
    string,
    ComponentCandidate & { evidence_sources: string[]; paths: string[] }
  >()
  for (const candidate of candidates) {
    const key = stableComponentKey(candidate)
    const current = merged.get(key)
    if (!current) {
      merged.set(key, {
        ...candidate,
        evidence_sources: [`${candidate.source}:${candidate.evidenceType}`],
        paths: candidate.path ? [candidate.path] : [],
      })
      continue
    }
    current.evidence_sources = Array.from(
      new Set([...current.evidence_sources, `${candidate.source}:${candidate.evidenceType}`])
    ).sort()
    if (candidate.path)
      current.paths = Array.from(new Set([...current.paths, candidate.path])).sort()
  }
  return Array.from(merged.values()).sort((a, b) =>
    `${a.type}:${a.name}:${a.version ?? ''}`.localeCompare(`${b.type}:${b.name}:${b.version ?? ''}`)
  )
}

function buildExports(sampleId: string | null, components: ReturnType<typeof mergeCandidates>) {
  return {
    cyclonedx: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:rikune:sbom:${sampleId ?? 'unspecified'}`,
      version: 1,
      metadata: {
        tools: [{ vendor: 'rikune', name: TOOL_NAME, version: '1.0.0' }],
        component: { type: 'application', name: sampleId ?? 'unspecified-sample' },
      },
      components: components.map((component, index) => ({
        'bom-ref': `component-${index}`,
        type: component.type,
        name: component.name,
        version: component.version,
        evidence: {
          occurrences: component.evidence_sources.map((source) => ({ location: source })),
        },
      })),
    },
    spdx_lite: {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: `sbom-provenance-${sampleId ?? 'unspecified'}`,
      documentNamespace: `urn:rikune:spdx:${sampleId ?? 'unspecified'}`,
      packages: components.map((component, index) => ({
        SPDXID: `SPDXRef-Package-${index}`,
        name: component.name,
        versionInfo: component.version ?? 'NOASSERTION',
        filesAnalyzed: false,
        downloadLocation: 'NOASSERTION',
      })),
    },
  }
}

export function buildSbomProvenanceGraph(rawInput: unknown) {
  const input = SbomProvenanceGraphInputSchema.parse(rawInput)
  const candidates: ComponentCandidate[] = []

  for (const row of input.components) {
    const candidate = componentFromRow('input.components', 'component', row)
    if (candidate) candidates.push(candidate)
  }

  for (const [source, value] of Object.entries(input.sources)) {
    for (const { evidenceType, row } of collectRows(source, value)) {
      const candidate = componentFromRow(source, evidenceType, row)
      if (candidate) candidates.push(candidate)
    }
  }

  const components = mergeCandidates(candidates)
  const sourceIds = Array.from(
    new Set(components.flatMap((component) => component.evidence_sources))
  )
    .sort()
    .map((source) => ({ id: `source:${source}`, type: 'source', label: source }))
  const componentNodes = components.map((component, index) => ({
    id: `component:${index}`,
    type: 'component',
    label: component.name,
    component_type: component.type,
    version: component.version ?? null,
  }))
  const edges = components.flatMap((component, componentIndex) =>
    component.evidence_sources.map((source) => ({
      source: `source:${source}`,
      target: `component:${componentIndex}`,
      relation: 'observed_component',
    }))
  )
  const installerScriptCount = components.filter((component) =>
    /script|postinst|preinst|customaction/i.test(component.name)
  ).length
  const nestedPayloadCount = components.filter((component) => component.paths.length > 0).length

  return {
    result_mode: 'sbom_provenance_graph',
    sample_id: input.sample_id ?? null,
    component_count: components.length,
    components,
    graph: {
      nodes: [...sourceIds, ...componentNodes],
      edges,
    },
    exports: buildExports(input.sample_id ?? null, components),
    risk_summary: {
      installer_script_count: installerScriptCount,
      nested_payload_count: nestedPayloadCount,
      duplicate_component_sources: components.filter(
        (component) => component.evidence_sources.length > 1
      ).length,
      network_enrichment_performed: false,
    },
    recommended_next_tools: [
      'sbom.generate',
      ...(input.include_vuln_handoff ? ['vuln.pattern.summary'] : []),
      'report.generate',
    ],
    safety_notes: [
      'This graph is built from local inventory rows only.',
      'No package install, mount, payload execution, or network vulnerability lookup is performed.',
    ],
  }
}

export function createSbomProvenanceGraphHandler() {
  return async (args: unknown): Promise<WorkerResult> => ({
    ok: true,
    data: buildSbomProvenanceGraph(args),
    metrics: { elapsed_ms: 0, tool: TOOL_NAME },
  })
}
