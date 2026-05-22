/**
 * dotnet.assembly.inspect — passive .NET/NuGet/WinMD inventory.
 *
 * This tool does not execute managed code, restore packages, or launch ILSpy.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'dotnet.assembly.inspect'
const DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024
const MAX_PREVIEW_BYTES = 16 * 1024 * 1024

const DotnetPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_runtime_start: z.literal(true),
  no_package_restore: z.literal(true),
  no_decompiler_launch: z.literal(true),
})

const DotnetAssemblyInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  detected_by: z.array(z.string()),
  size: z.number().optional(),
  archive_members: z.array(z.string()),
  assembly_hints: z.array(z.string()),
  target_framework_hints: z.array(z.string()),
  dependency_hints: z.array(z.string()),
  resource_hints: z.array(z.string()),
  pinvoke_hints: z.array(z.string()),
  decompile_plan: z.object({
    status: z.literal('plan_only'),
    recommended_tools: z.array(z.string()),
    notes: z.array(z.string()),
  }),
  policy: DotnetPolicySchema,
  unsupported_detail: z.string().optional(),
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
})

export const DotnetAssemblyInspectInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive .NET inventory.'),
  persist_artifact: z.boolean().default(true).describe('Persist .NET inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const DotnetAssemblyInspectOutputSchema = z.object({
  ok: z.boolean(),
  data: DotnetAssemblyInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const dotnetAssemblyInspectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inspect .NET PE-CLR, NuGet, Mono, and WinMD metadata without executing managed code or restoring packages.',
  inputSchema: DotnetAssemblyInspectInputSchema,
  outputSchema: DotnetAssemblyInspectOutputSchema,
  aspects: {
    formats: ['dotnet', 'pe-clr', 'nupkg', 'mono', 'winmd'],
    platforms: ['dotnet', 'windows', 'linux', 'macos'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['assembly-metadata', 'resources', 'dependencies', 'decompile-plan', 'routing'],
    evidence: ['manifest', 'resources', 'package-metadata', 'provenance'],
  },
  artifacts: [
    {
      type: 'dotnet_assembly_inventory',
      description:
        'Passive .NET assembly/package metadata, dependency, and decompile-plan inventory',
    },
  ],
  evidence: [
    {
      category: 'manifest',
      artifactTypes: ['dotnet_assembly_inventory'],
    },
    {
      category: 'package-metadata',
      artifactTypes: ['dotnet_assembly_inventory'],
    },
  ],
}

export type DotnetAssemblyInventory = z.infer<typeof DotnetAssemblyInventorySchema>

type ZipEntry = {
  name: string
  content?: Buffer
}

function extensionOf(filename?: string): string {
  const normalized = (filename ?? '').replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)
  if (!base.includes('.')) return ''
  return base.slice(base.lastIndexOf('.') + 1)
}

function previewText(data: Buffer): string {
  return data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
}

function detectDotnetFormat(
  data: Buffer,
  filename?: string
): { format: string; detectedBy: string[] } {
  const ext = extensionOf(filename)
  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) {
    const text = previewText(data)
    if (ext === 'nupkg' || text.includes('.nuspec')) {
      return {
        format: 'nupkg',
        detectedBy: ext === 'nupkg' ? ['zip magic', 'filename extension'] : ['NuGet nuspec marker'],
      }
    }
    return { format: ext || 'zip', detectedBy: ['zip magic'] }
  }
  if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) {
    const text = previewText(data)
    if (ext === 'winmd') return { format: 'winmd', detectedBy: ['PE magic', 'filename extension'] }
    if (text.includes('BSJB') || text.toLowerCase().includes('mscoree.dll')) {
      return { format: 'pe-clr', detectedBy: ['PE magic', 'CLR metadata marker'] }
    }
    return { format: 'pe', detectedBy: ['PE magic'] }
  }
  if (ext === 'dll' || ext === 'exe')
    return { format: 'dotnet', detectedBy: ['filename extension'] }
  if (ext === 'winmd') return { format: 'winmd', detectedBy: ['filename extension'] }
  if (ext === 'nupkg') return { format: 'nupkg', detectedBy: ['filename extension'] }
  return { format: ext || 'unknown', detectedBy: ext ? ['filename extension'] : ['unknown'] }
}

function parseZipLocalEntries(data: Buffer): ZipEntry[] {
  const entries: ZipEntry[] = []
  let offset = 0

  while (offset + 30 <= data.length && entries.length < 500) {
    if (data.readUInt32LE(offset) !== 0x04034b50) {
      offset += 1
      continue
    }

    const compressionMethod = data.readUInt16LE(offset + 8)
    const compressedSize = data.readUInt32LE(offset + 18)
    const nameLength = data.readUInt16LE(offset + 26)
    const extraLength = data.readUInt16LE(offset + 28)
    const nameStart = offset + 30
    const nameEnd = nameStart + nameLength
    if (nameEnd > data.length) break

    const name = data.subarray(nameStart, nameEnd).toString('utf8')
    const contentStart = nameEnd + extraLength
    const contentEnd = contentStart + compressedSize
    const content =
      compressionMethod === 0 && contentEnd <= data.length
        ? data.subarray(contentStart, contentEnd)
        : undefined
    entries.push({ name, content })

    const nextOffset = contentEnd > offset && contentEnd <= data.length ? contentEnd : contentStart
    offset = nextOffset <= offset ? offset + 1 : nextOffset
  }

  return entries
}

function extractTextHints(data: Buffer, entries: ZipEntry[]): string {
  const fragments = [previewText(data)]
  for (const entry of entries.slice(0, 40)) {
    if (
      entry.content &&
      /\.(?:nuspec|deps\.json|runtimeconfig\.json|config|xml)$/i.test(entry.name)
    ) {
      fragments.push(entry.content.toString('utf8'))
    }
  }
  return fragments.join('\n')
}

function extractRegex(text: string, regex: RegExp, limit = 100): string[] {
  const values = new Set<string>()
  for (const match of text.matchAll(regex)) {
    const value = (match[1] ?? match[0]).trim()
    if (value.length > 0) values.add(value)
    if (values.size >= limit) break
  }
  return Array.from(values)
}

export function buildDotnetAssemblyInventoryFromBuffer(
  data: Buffer,
  options: { filename?: string; size?: number; sampleId?: string } = {}
): DotnetAssemblyInventory {
  const { format, detectedBy } = detectDotnetFormat(data, options.filename)
  const entries = parseZipLocalEntries(data)
  const members = entries.map((entry) => entry.name)
  const text = extractTextHints(data, entries)
  const assemblyHints = Array.from(
    new Set([
      ...members.filter((member) => /\.(?:dll|exe|winmd)$/i.test(member)),
      ...extractRegex(text, /Assembly(?:Name)?["'=:\s]+([A-Za-z0-9_.-]+)/gi, 50),
      ...extractRegex(text, /<id>([^<]+)<\/id>/gi, 20),
    ])
  ).slice(0, 100)
  const targetFrameworkHints = Array.from(
    new Set([
      ...extractRegex(text, /<targetFramework>([^<]+)<\/targetFramework>/gi, 50),
      ...extractRegex(text, /TargetFramework(?:Attribute)?["'=:\s]+([^"'\s<,]+)/gi, 50),
      ...members
        .map((member) => member.match(/(?:^|\/)(net[0-9][^/\\]*)\//i)?.[1])
        .filter((item): item is string => Boolean(item)),
    ])
  ).slice(0, 100)
  const dependencyHints = Array.from(
    new Set([
      ...extractRegex(text, /<dependency[^>]+id=["']([^"']+)["']/gi, 100),
      ...extractRegex(text, /"([^"]+)"\s*:\s*\{\s*"type"\s*:\s*"package"/gi, 100),
      ...members.filter((member) => /(?:^|\/)(?:lib|runtimes)\//i.test(member)),
    ])
  ).slice(0, 150)
  const resourceHints = Array.from(
    new Set(members.filter((member) => /\.(?:resources|resx|xaml|config|json|xml)$/i.test(member)))
  ).slice(0, 100)
  const pinvokeHints = Array.from(
    new Set([
      ...extractRegex(text, /DllImport(?:Attribute)?\W+([A-Za-z0-9_.-]+\.dll)/gi, 100),
      ...extractRegex(text, /([A-Za-z0-9_.-]+\.dll)\0/g, 100),
    ])
  ).slice(0, 100)
  const unsupported =
    format === 'pe-clr' || format === 'winmd'
      ? 'Detailed CLR metadata tables require optional managed metadata tooling; this inventory uses passive marker and string hints.'
      : undefined

  return {
    sample_id: options.sampleId,
    filename: options.filename,
    format,
    detected_by: detectedBy,
    size: options.size ?? data.length,
    archive_members: members.slice(0, 500),
    assembly_hints: assemblyHints,
    target_framework_hints: targetFrameworkHints,
    dependency_hints: dependencyHints,
    resource_hints: resourceHints,
    pinvoke_hints: pinvokeHints,
    decompile_plan: {
      status: 'plan_only',
      recommended_tools: ['dotnet.metadata.extract', 'dotnet.types.list', 'dotnet.decompile'],
      notes: [
        'Use ILSpy or dnfile-backed tools only after reviewing this static inventory.',
        'NuGet package restore and managed code execution are not performed by this tool.',
      ],
    },
    policy: {
      passive: true,
      no_execute: true,
      no_runtime_start: true,
      no_package_restore: true,
      no_decompiler_launch: true,
    },
    unsupported_detail: unsupported,
    summary: `Passive .NET inventory detected ${format} with ${assemblyHints.length} assembly hint(s), ${targetFrameworkHints.length} target framework hint(s), and ${dependencyHints.length} dependency hint(s).`,
    recommended_next_tools: Array.from(
      new Set([
        'metadata.extract',
        'strings.extract',
        'dotnet.metadata.extract',
        'dotnet.types.list',
      ])
    ),
    next_actions: [
      'Review target framework, dependency, resource, and P/Invoke hints before decompilation.',
      'Do not restore NuGet packages or execute managed code during static triage.',
      'Use managed IL xref tools only after confirming the sample is a managed assembly.',
    ],
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

export function createDotnetAssemblyInspectHandler(deps: PluginToolDeps) {
  const {
    workspaceManager,
    database,
    resolvePrimarySamplePath,
    persistStaticAnalysisJsonArtifact,
  } = deps
  return async (args: z.infer<typeof DotnetAssemblyInspectInputSchema>): Promise<WorkerResult> => {
    const t0 = Date.now()
    try {
      const input = DotnetAssemblyInspectInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      if (!resolvePrimarySamplePath) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is not available'] }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const { data, size } = await readPreview(samplePath, input.max_read_bytes)
      const inventory = buildDotnetAssemblyInventoryFromBuffer(data, {
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
            'dotnet_assembly_inventory',
            'dotnet-assembly-inventory',
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
