/**
 * installer.inventory — passive Windows installer inventory.
 *
 * This tool does not install MSI/MSIX/APPX packages, execute custom actions,
 * run setup EXEs, or execute extracted payloads.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'installer.inventory'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024
const WINDOWS_INSTALLER_INVENTORY_FOLLOW_UP_TOOLS = [
  'pe.structure.analyze',
  'sbom.provenance.graph',
  'windows.runtime.plan',
]
const WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE = 'windows_installer_inventory'

const WindowsInstallerPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_install: z.literal(true),
  no_payload_launch: z.literal(true),
})

const NestedPayloadSchema = z.object({
  path: z.string(),
  routed_formats: z.array(z.string()),
  recommended_tools: z.array(z.string()),
})

const WindowsInstallerInventoryDataSchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  installer_format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  archive_members: z.array(z.string()),
  cab_summary: z.record(z.string(), z.any()).optional(),
  custom_action_candidates: z.array(z.string()),
  script_candidates: z.array(z.string()),
  nested_payload_candidates: z.array(NestedPayloadSchema),
  policy: WindowsInstallerPolicySchema,
  evidence_summary: z.record(z.string(), z.any()).optional(),
  workflow_handoff: z.record(z.string(), z.any()).optional(),
  quality_gates: z.record(z.string(), z.any()).optional(),
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const WindowsInstallerInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive installer inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist installer inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const WindowsInstallerInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: WindowsInstallerInventoryDataSchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const windowsInstallerInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Windows installers (MSI, MSIX, APPX, CAB, NSIS, Inno) without installing packages or executing custom actions.',
  inputSchema: WindowsInstallerInventoryInputSchema,
  outputSchema: WindowsInstallerInventoryOutputSchema,
  aspects: {
    formats: ['msi', 'msix', 'appx', 'cab', 'nsis', 'inno', 'installer'],
    platforms: ['windows'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_installer_execution', 'no_live_sample_by_default'],
    capabilities: [
      'inventory',
      'custom-actions',
      'scripts',
      'nested-binaries',
      'routing',
      'workflow-plan',
      'metadata-only-handoff',
    ],
    evidence: ['filesystem', 'registry', 'nested-binaries', 'package-metadata', 'provenance'],
  },
  artifacts: [
    {
      type: WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE,
      description: 'Passive Windows installer member, custom action, script, and payload inventory',
    },
  ],
  evidence: [
    {
      category: 'package-metadata',
      artifactTypes: [WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE],
    },
    {
      category: 'nested-binaries',
      artifactTypes: [WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [
    {
      id: 'windows-installer.passive-inventory-handoff',
      title: 'Windows installer passive inventory handoff',
      startsWith: ['installer.inventory'],
      nextTools: WINDOWS_INSTALLER_INVENTORY_FOLLOW_UP_TOOLS,
      requiredArtifacts: [WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE],
      producesArtifacts: [WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE],
      evidence: ['package-metadata', 'nested-binaries', 'filesystem', 'registry', 'provenance'],
      safety: ['passive', 'no_installer_execution', 'no_live_sample_by_default'],
    },
  ],
}

export type WindowsInstallerInventory = z.infer<typeof WindowsInstallerInventoryDataSchema>
type NestedPayloadCandidate = WindowsInstallerInventory['nested_payload_candidates'][number]

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function previewText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
}

function hasOleMagic(data: Buffer): boolean {
  return (
    data.length >= 8 &&
    data[0] === 0xd0 &&
    data[1] === 0xcf &&
    data[2] === 0x11 &&
    data[3] === 0xe0 &&
    data[4] === 0xa1 &&
    data[5] === 0xb1 &&
    data[6] === 0x1a &&
    data[7] === 0xe1
  )
}

function detectInstallerFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  if (hasOleMagic(data) && ['msi', 'msp', 'msm'].includes(ext)) {
    return { format: 'msi', detectedBy: ['OLE compound document magic', 'filename extension'] }
  }
  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'MSCF') {
    return { format: 'cab', detectedBy: ['CAB MSCF magic'] }
  }
  if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) {
    const text = previewText(data)
    if (text.includes('NullsoftInst')) return { format: 'nsis', detectedBy: ['NSIS marker'] }
    if (text.includes('Inno Setup')) return { format: 'inno', detectedBy: ['Inno Setup marker'] }
  }
  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) {
    const text = previewText(data)
    if (ext === 'msix') return { format: 'msix', detectedBy: ['zip magic', 'filename extension'] }
    if (ext === 'appx') return { format: 'appx', detectedBy: ['zip magic', 'filename extension'] }
    if (text.includes('AppxManifest.xml')) return { format: 'appx', detectedBy: ['AppX manifest'] }
    return { format: ext || 'zip', detectedBy: ['zip magic'] }
  }
  if (['msi', 'msp', 'msm', 'msix', 'appx', 'cab', 'nsis', 'inno'].includes(ext)) {
    return {
      format: ext === 'msp' || ext === 'msm' ? 'msi' : ext,
      detectedBy: ['filename extension'],
    }
  }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function parseZipLocalMembers(data: Buffer): string[] {
  const members: string[] = []
  let offset = 0

  while (offset + 30 <= data.length && members.length < 500) {
    if (data.readUInt32LE(offset) !== 0x04034b50) {
      offset += 1
      continue
    }

    const compressedSize = data.readUInt32LE(offset + 18)
    const nameLength = data.readUInt16LE(offset + 26)
    const extraLength = data.readUInt16LE(offset + 28)
    const nameStart = offset + 30
    const nameEnd = nameStart + nameLength
    if (nameEnd > data.length) break

    const name = data.subarray(nameStart, nameEnd).toString('utf8')
    if (name.length > 0) members.push(name)

    const nextOffset = nameEnd + extraLength + compressedSize
    offset = nextOffset > offset && nextOffset <= data.length ? nextOffset : nameEnd + extraLength
  }

  return Array.from(new Set(members))
}

function parseCabSummary(data: Buffer): Record<string, unknown> | undefined {
  if (data.length < 36 || data.subarray(0, 4).toString('ascii') !== 'MSCF') return undefined
  return {
    cabinet_size: data.readUInt32LE(8),
    file_table_offset: data.readUInt32LE(16),
    version: `${data[25]}.${data[24]}`,
    folder_count: data.readUInt16LE(26),
    file_count: data.readUInt16LE(28),
    flags: data.readUInt16LE(30),
  }
}

function extractPathTokens(data: Buffer): string[] {
  const matches =
    previewText(data).match(
      /[A-Za-z0-9_./@{}$+ -]{2,240}\.(?:exe|dll|sys|scr|efi|cab|msi|msix|appx|ps1|vbs|js|cmd|bat|reg|xml|json|config)/gi
    ) ?? []
  return Array.from(new Set(matches.map((item) => item.trim()).filter(Boolean))).slice(0, 300)
}

function routePayload(candidatePath: string): NestedPayloadCandidate | null {
  const lower = candidatePath.toLowerCase()
  const routedFormats: string[] = []
  const recommendedTools: string[] = []

  if (/\.(?:exe|dll|sys|scr|efi)$/.test(lower)) {
    routedFormats.push('pe')
    recommendedTools.push('pe.structure.analyze')
  }
  if (lower.endsWith('.cab')) {
    routedFormats.push('cab')
    recommendedTools.push('installer.inventory')
  }
  if (lower.endsWith('.msi') || lower.endsWith('.msix') || lower.endsWith('.appx')) {
    routedFormats.push(lower.slice(lower.lastIndexOf('.') + 1))
    recommendedTools.push('installer.inventory')
  }

  if (routedFormats.length === 0) return null
  return {
    path: candidatePath,
    routed_formats: Array.from(new Set(routedFormats)),
    recommended_tools: Array.from(new Set(recommendedTools)),
  }
}

function customActionCandidates(format: string, members: string[], tokens: string[]): string[] {
  const candidates = new Set<string>()
  const haystack = [...members, ...tokens]
  for (const item of haystack) {
    const lower = item.toLowerCase()
    if (
      lower.includes('customaction') ||
      lower.includes('installexecutesequence') ||
      lower.includes('binary.') ||
      lower.endsWith('.dll') ||
      lower.endsWith('.exe')
    ) {
      candidates.add(item)
    }
  }
  if (format === 'msi') {
    candidates.add(
      'MSI CustomAction table may be present; use optional MSI database tooling to enumerate rows safely'
    )
  }
  return Array.from(candidates).slice(0, 100)
}

function scriptCandidates(members: string[], tokens: string[]): string[] {
  return Array.from(
    new Set([...members, ...tokens].filter((item) => /\.(?:ps1|vbs|js|cmd|bat|reg)$/i.test(item)))
  ).slice(0, 100)
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)))
}

function buildEvidenceSummary(args: {
  inventory: Omit<
    WindowsInstallerInventory,
    'evidence_summary' | 'workflow_handoff' | 'quality_gates'
  >
}) {
  const { inventory } = args
  return {
    schema: 'rikune.windows_installer_inventory.evidence_summary.v1',
    source_tool: TOOL_NAME,
    sample_id: inventory.sample_id ?? null,
    artifact_type: WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE,
    installer_format: inventory.installer_format,
    detected_by: inventory.detected_by,
    member_count: inventory.archive_members.length,
    custom_action_candidate_count: inventory.custom_action_candidates.length,
    script_candidate_count: inventory.script_candidates.length,
    nested_payload_candidate_count: inventory.nested_payload_candidates.length,
    cab_summary_present: Boolean(inventory.cab_summary),
    static_only: true,
  }
}

function buildWorkflowHandoff(args: {
  inventory: Omit<
    WindowsInstallerInventory,
    'evidence_summary' | 'workflow_handoff' | 'quality_gates'
  >
}) {
  const { inventory } = args
  const nestedTools = unique(
    inventory.nested_payload_candidates.flatMap((candidate) => candidate.recommended_tools)
  )
  const routing: Array<{
    goal: string
    priority: string
    next_tools: string[]
    required_evidence: string[]
  }> = []
  if (inventory.nested_payload_candidates.length > 0) {
    routing.push({
      goal: 'nested-payload-static-analysis',
      priority: 'high',
      next_tools: nestedTools,
      required_evidence: ['nested_payload_candidates'],
    })
  }
  routing.push({
    goal: 'installer-supply-chain-provenance',
    priority: 'normal',
    next_tools: ['sbom.provenance.graph', 'analysis.evidence.graph', 'report.generate'],
    required_evidence: ['archive_members', 'custom_action_candidates', 'script_candidates'],
  })
  if (inventory.custom_action_candidates.length > 0 || inventory.script_candidates.length > 0) {
    routing.push({
      goal: 'windows-runtime-plan-only',
      priority: 'high',
      next_tools: ['windows.runtime.plan', 'analysis.evidence.graph'],
      required_evidence: ['custom_action_candidates', 'script_candidates'],
    })
  }

  return {
    schema: 'rikune.windows_installer_inventory.workflow_handoff.v1',
    handoff_mode: 'windows_installer_inventory_to_payload_supply_chain_and_runtime_planning',
    source_tool: TOOL_NAME,
    sample_id: inventory.sample_id ?? null,
    artifact_type: WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE,
    recommended_next_tools: inventory.recommended_next_tools,
    artifact_contract: {
      consumes: ['sample'],
      produces: [WINDOWS_INSTALLER_INVENTORY_ARTIFACT_TYPE],
      expected_consumers: inventory.recommended_next_tools,
    },
    routing,
    dynamic_boundary: {
      sample_executed_by_tool: false,
      installer_launched_by_tool: false,
      package_installed_by_tool: false,
      custom_action_executed_by_tool: false,
      script_executed_by_tool: false,
      payload_launched_by_tool: false,
      runtime_started_by_tool: false,
      network_accessed_by_tool: false,
      mutation_performed: false,
    },
  }
}

function buildQualityGates(args: {
  inventory: Omit<
    WindowsInstallerInventory,
    'evidence_summary' | 'workflow_handoff' | 'quality_gates'
  >
}) {
  const { inventory } = args
  return {
    schema: 'rikune.windows_installer_inventory.quality_gates.v1',
    passive_static_inventory: true,
    bounded_preview_only: true,
    format_detected: inventory.installer_format !== 'unknown',
    custom_action_candidates_present: inventory.custom_action_candidates.length > 0,
    script_candidates_present: inventory.script_candidates.length > 0,
    nested_payload_routing_present: inventory.nested_payload_candidates.length > 0,
    sample_executed_by_tool: false,
    installer_launched_by_tool: false,
    package_installed_by_tool: false,
    custom_action_executed_by_tool: false,
    script_executed_by_tool: false,
    payload_launched_by_tool: false,
    runtime_started_by_tool: false,
    network_accessed_by_tool: false,
    mutation_performed: false,
  }
}

export function buildWindowsInstallerInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): WindowsInstallerInventory {
  const { format, detectedBy } = detectInstallerFormat(data, options.filename)
  const zipMembers = parseZipLocalMembers(data)
  const tokens = extractPathTokens(data)
  const members = Array.from(new Set([...zipMembers, ...tokens])).slice(0, 500)
  const payloadCandidates = members
    .map(routePayload)
    .filter((candidate): candidate is NestedPayloadCandidate => Boolean(candidate))
    .slice(0, 150)
  const customActions = customActionCandidates(format, members, tokens)
  const scripts = scriptCandidates(members, tokens)
  const cabSummary = parseCabSummary(data)
  const unsupported =
    format === 'msi'
      ? 'Deep MSI table enumeration requires optional MSI database tooling; this tool does not run custom actions.'
      : format === 'nsis' || format === 'inno'
        ? 'NSIS/Inno payload listing requires installer unpacking; this inventory does not execute or unpack setup code.'
        : undefined

  const inventoryBase = {
    sample_id: options.sampleId,
    filename: options.filename,
    installer_format: format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    archive_members: members,
    cab_summary: cabSummary,
    custom_action_candidates: customActions,
    script_candidates: scripts,
    nested_payload_candidates: payloadCandidates,
    policy: {
      passive: true as const,
      no_execute: true as const,
      no_install: true as const,
      no_payload_launch: true as const,
    },
    unsupported_detail: unsupported,
    summary: `Passive Windows installer inventory detected ${format} with ${members.length} member/path hint(s), ${customActions.length} custom action candidate(s), ${scripts.length} script candidate(s), and ${payloadCandidates.length} nested payload candidate(s).`,
    recommended_next_tools: unique([
      'metadata.extract',
      'strings.extract',
      ...WINDOWS_INSTALLER_INVENTORY_FOLLOW_UP_TOOLS,
      ...payloadCandidates.flatMap((candidate) => candidate.recommended_tools),
    ]),
    next_actions: [
      'Review custom action and script candidates as static evidence only.',
      'Ingest nested PE or installer payload candidates separately before running format-specific tools.',
      'Do not install the package, execute setup code, or launch extracted payloads during static triage.',
    ],
  }
  return {
    ...inventoryBase,
    evidence_summary: buildEvidenceSummary({ inventory: inventoryBase }),
    workflow_handoff: buildWorkflowHandoff({ inventory: inventoryBase }),
    quality_gates: buildQualityGates({ inventory: inventoryBase }),
  }
}

async function readPreview(
  filePath: string,
  maxReadBytes: number
): Promise<{ data: Buffer; size: number }> {
  const stat = await fs.stat(filePath)
  const handle = await fs.open(filePath, 'r')
  try {
    const length = Math.min(stat.size, maxReadBytes)
    const data = Buffer.alloc(length)
    await handle.read(data, 0, length, 0)
    return { data, size: stat.size }
  } finally {
    await handle.close()
  }
}

export function createWindowsInstallerInventoryHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (
    args: z.infer<typeof WindowsInstallerInventoryInputSchema>
  ): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = WindowsInstallerInventoryInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildWindowsInstallerInventoryFromBuffer(data, {
        filename: path.basename(samplePath),
        sampleId: input.sample_id,
        size,
      })

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact && persistStaticAnalysisJsonArtifact) {
        try {
          const artifact = await persistStaticAnalysisJsonArtifact(
            workspaceManager,
            database,
            input.sample_id,
            'windows_installer_inventory',
            'windows-installer-inventory',
            inventory,
            input.session_tag ?? null
          )
          if (artifact) artifacts.push(artifact)
        } catch {
          // Non-fatal: inventory can still be returned without persistence.
        }
      }

      return {
        ok: true,
        data: inventory,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${error instanceof Error ? error.message : String(error)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
