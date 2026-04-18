/**
 * static.resource.graph tool.
 *
 * Build a compact resource/payload graph directly from the sample bytes. The
 * first implementation focuses on PE resource directory entries and safe
 * top-level binary indicators, without executing any code.
 */

import fs from 'fs/promises'
import { createHash } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'static.resource.graph'
const TOOL_VERSION = '0.1.0'
const PE_RESOURCE_DIRECTORY_INDEX = 2

interface SectionInfo {
  name: string
  virtualAddress: number
  virtualSize: number
  rawPointer: number
  rawSize: number
  characteristics: number
}

interface PeResourceLeaf {
  path: string[]
  depth: number
  dataRva: number
  dataOffset: number | null
  size: number
  codepage: number
  sha256: string | null
  entropy: number | null
  magic: string
  stringPreview: string[]
}

interface ResourceGraphData {
  schema: 'rikune.static_resource_graph.v1'
  tool_version: string
  sample_id: string
  file: {
    size: number
    sha256: string
    magic: string
    is_pe: boolean
  }
  pe: {
    machine: string | null
    section_count: number
    resource_directory_rva: number | null
    resource_directory_size: number | null
    sections: SectionInfo[]
  }
  resources: PeResourceLeaf[]
  summary: {
    resource_count: number
    suspicious_resource_count: number
    executable_like_resource_count: number
    high_entropy_resource_count: number
    largest_resources: Array<{ path: string; size: number; magic: string }>
  }
  recommended_next_tools: string[]
}

export const StaticResourceGraphInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_resources: z.number().int().min(1).max(1000).optional().default(250),
  max_string_preview: z.number().int().min(0).max(20).optional().default(6),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const StaticResourceGraphOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const staticResourceGraphToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a compact PE resource and embedded-payload graph from sample bytes. ' +
    'Identifies resource leaf size, entropy, magic, hashes, strings, executable-like blobs, and recommended follow-up tools without executing the sample.',
  inputSchema: StaticResourceGraphInputSchema,
  outputSchema: StaticResourceGraphOutputSchema,
}

function readUInt16(buffer: Buffer, offset: number): number {
  return offset >= 0 && offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : 0
}

function readUInt32(buffer: Buffer, offset: number): number {
  return offset >= 0 && offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : 0
}

function readAscii(buffer: Buffer, offset: number, length: number): string {
  if (offset < 0 || offset >= buffer.length) return ''
  return buffer
    .subarray(offset, Math.min(buffer.length, offset + length))
    .toString('ascii')
    .replace(/\0+$/g, '')
}

function shannonEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0
  const counts = new Array<number>(256).fill(0)
  for (const byte of buffer) counts[byte] += 1
  let entropy = 0
  for (const count of counts) {
    if (count === 0) continue
    const p = count / buffer.length
    entropy -= p * Math.log2(p)
  }
  return Number(entropy.toFixed(3))
}

function magicOf(buffer: Buffer): string {
  if (buffer.length >= 2 && buffer.subarray(0, 2).toString('ascii') === 'MZ') return 'pe_or_dos'
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString('hex') === '504b0304') return 'zip'
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString('hex') === '4d534346') return 'cab'
  if (buffer.length >= 8 && buffer.subarray(0, 8).toString('hex') === '89504e470d0a1a0a') return 'png'
  if (buffer.length >= 3 && buffer.subarray(0, 3).toString('hex') === 'ffd8ff') return 'jpeg'
  if (buffer.length >= 6 && ['474946383761', '474946383961'].includes(buffer.subarray(0, 6).toString('hex'))) return 'gif'
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString('ascii') === '%PDF') return 'pdf'
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString('hex') === '7f454c46') return 'elf'
  const ascii = buffer.subarray(0, Math.min(16, buffer.length)).toString('ascii')
  if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(ascii)) return 'text'
  return 'binary'
}

function extractStringPreview(buffer: Buffer, maxItems: number): string[] {
  if (maxItems <= 0) return []
  const text = buffer.toString('latin1')
  const matches = text.match(/[\x20-\x7e]{5,120}/g) || []
  return Array.from(new Set(matches.map((item) => item.trim()).filter(Boolean))).slice(0, maxItems)
}

function rvaToOffset(rva: number, sections: SectionInfo[]): number | null {
  for (const section of sections) {
    const sectionSize = Math.max(section.virtualSize, section.rawSize)
    if (rva >= section.virtualAddress && rva < section.virtualAddress + sectionSize) {
      const offset = section.rawPointer + (rva - section.virtualAddress)
      return offset >= 0 ? offset : null
    }
  }
  return null
}

function parseUtf16ResourceName(buffer: Buffer, offset: number): string | null {
  const length = readUInt16(buffer, offset)
  if (length <= 0 || length > 512 || offset + 2 + length * 2 > buffer.length) return null
  return buffer.subarray(offset + 2, offset + 2 + length * 2).toString('utf16le')
}

function parsePe(buffer: Buffer): {
  isPe: boolean
  machine: string | null
  sections: SectionInfo[]
  resourceRva: number | null
  resourceSize: number | null
} {
  if (buffer.length < 0x40 || buffer.subarray(0, 2).toString('ascii') !== 'MZ') {
    return { isPe: false, machine: null, sections: [], resourceRva: null, resourceSize: null }
  }
  const peOffset = readUInt32(buffer, 0x3c)
  if (peOffset <= 0 || peOffset + 0x18 > buffer.length || buffer.subarray(peOffset, peOffset + 4).toString('ascii') !== 'PE\0\0') {
    return { isPe: false, machine: null, sections: [], resourceRva: null, resourceSize: null }
  }

  const coffOffset = peOffset + 4
  const machineValue = readUInt16(buffer, coffOffset)
  const sectionCount = readUInt16(buffer, coffOffset + 2)
  const optionalHeaderSize = readUInt16(buffer, coffOffset + 16)
  const optionalOffset = coffOffset + 20
  const magic = readUInt16(buffer, optionalOffset)
  const dataDirectoryOffset = magic === 0x20b ? optionalOffset + 112 : optionalOffset + 96
  const resourceDirectoryOffset = dataDirectoryOffset + PE_RESOURCE_DIRECTORY_INDEX * 8
  const resourceRva = readUInt32(buffer, resourceDirectoryOffset)
  const resourceSize = readUInt32(buffer, resourceDirectoryOffset + 4)
  const sectionTableOffset = optionalOffset + optionalHeaderSize
  const sections: SectionInfo[] = []

  for (let index = 0; index < sectionCount; index += 1) {
    const sectionOffset = sectionTableOffset + index * 40
    if (sectionOffset + 40 > buffer.length) break
    sections.push({
      name: readAscii(buffer, sectionOffset, 8),
      virtualSize: readUInt32(buffer, sectionOffset + 8),
      virtualAddress: readUInt32(buffer, sectionOffset + 12),
      rawSize: readUInt32(buffer, sectionOffset + 16),
      rawPointer: readUInt32(buffer, sectionOffset + 20),
      characteristics: readUInt32(buffer, sectionOffset + 36),
    })
  }

  return {
    isPe: true,
    machine: `0x${machineValue.toString(16).padStart(4, '0')}`,
    sections,
    resourceRva: resourceRva || null,
    resourceSize: resourceSize || null,
  }
}

function parseResourceLeaves(buffer: Buffer, pe: ReturnType<typeof parsePe>, maxResources: number, maxStringPreview: number): PeResourceLeaf[] {
  if (!pe.resourceRva || pe.resourceSize === null) return []
  const resourceBaseOffset = rvaToOffset(pe.resourceRva, pe.sections)
  if (resourceBaseOffset === null) return []

  const leaves: PeResourceLeaf[] = []
  const visited = new Set<string>()

  const walk = (directoryRelativeOffset: number, pathParts: string[], depth: number) => {
    if (leaves.length >= maxResources || depth > 8) return
    const directoryOffset = resourceBaseOffset + directoryRelativeOffset
    if (directoryOffset < 0 || directoryOffset + 16 > buffer.length) return
    const key = `${directoryRelativeOffset}:${depth}`
    if (visited.has(key)) return
    visited.add(key)

    const namedCount = readUInt16(buffer, directoryOffset + 12)
    const idCount = readUInt16(buffer, directoryOffset + 14)
    const entryCount = Math.min(namedCount + idCount, 4096)
    for (let index = 0; index < entryCount; index += 1) {
      if (leaves.length >= maxResources) return
      const entryOffset = directoryOffset + 16 + index * 8
      if (entryOffset + 8 > buffer.length) return
      const nameRaw = readUInt32(buffer, entryOffset)
      const valueRaw = readUInt32(buffer, entryOffset + 4)
      const isNamed = Boolean(nameRaw & 0x80000000)
      const name = isNamed
        ? parseUtf16ResourceName(buffer, resourceBaseOffset + (nameRaw & 0x7fffffff)) || `name_${index}`
        : `id_${nameRaw & 0xffff}`
      const isDirectory = Boolean(valueRaw & 0x80000000)
      const nextRelative = valueRaw & 0x7fffffff
      if (isDirectory) {
        walk(nextRelative, [...pathParts, name], depth + 1)
        continue
      }

      const dataEntryOffset = resourceBaseOffset + nextRelative
      if (dataEntryOffset + 16 > buffer.length) continue
      const dataRva = readUInt32(buffer, dataEntryOffset)
      const size = readUInt32(buffer, dataEntryOffset + 4)
      const codepage = readUInt32(buffer, dataEntryOffset + 8)
      const dataOffset = rvaToOffset(dataRva, pe.sections)
      const boundedSize = Math.min(size, 32 * 1024 * 1024)
      const blob = dataOffset !== null && dataOffset >= 0 && dataOffset + boundedSize <= buffer.length
        ? buffer.subarray(dataOffset, dataOffset + boundedSize)
        : null
      leaves.push({
        path: [...pathParts, name],
        depth,
        dataRva,
        dataOffset,
        size,
        codepage,
        sha256: blob ? createHash('sha256').update(blob).digest('hex') : null,
        entropy: blob ? shannonEntropy(blob.subarray(0, Math.min(blob.length, 1024 * 1024))) : null,
        magic: blob ? magicOf(blob) : 'unavailable',
        stringPreview: blob ? extractStringPreview(blob.subarray(0, Math.min(blob.length, 64 * 1024)), maxStringPreview) : [],
      })
    }
  }

  walk(0, ['resources'], 0)
  return leaves
}

function buildSummary(resources: PeResourceLeaf[]): ResourceGraphData['summary'] {
  const executableLike = new Set(['pe_or_dos', 'elf', 'zip', 'cab'])
  const highEntropy = resources.filter((resource) => (resource.entropy ?? 0) >= 7.2)
  const executableResources = resources.filter((resource) => executableLike.has(resource.magic))
  const suspicious = resources.filter((resource) =>
    executableLike.has(resource.magic) ||
    (resource.entropy ?? 0) >= 7.2 ||
    resource.size >= 1024 * 1024
  )
  return {
    resource_count: resources.length,
    suspicious_resource_count: suspicious.length,
    executable_like_resource_count: executableResources.length,
    high_entropy_resource_count: highEntropy.length,
    largest_resources: [...resources]
      .sort((a, b) => b.size - a.size)
      .slice(0, 8)
      .map((resource) => ({
        path: resource.path.join('/'),
        size: resource.size,
        magic: resource.magic,
      })),
  }
}

export function createStaticResourceGraphHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = StaticResourceGraphInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`], metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME } }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const buffer = await fs.readFile(samplePath)
      const pe = parsePe(buffer)
      const resources = parseResourceLeaves(buffer, pe, input.max_resources, input.max_string_preview)
      const data: ResourceGraphData = {
        schema: 'rikune.static_resource_graph.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        file: {
          size: buffer.length,
          sha256: createHash('sha256').update(buffer).digest('hex'),
          magic: magicOf(buffer),
          is_pe: pe.isPe,
        },
        pe: {
          machine: pe.machine,
          section_count: pe.sections.length,
          resource_directory_rva: pe.resourceRva,
          resource_directory_size: pe.resourceSize,
          sections: pe.sections,
        },
        resources,
        summary: buildSummary(resources),
        recommended_next_tools: [
          'static.config.carver',
          'entropy.analyze',
          'strings.extract',
          'dotnet.metadata.extract',
          'dynamic.deep_plan',
        ],
      }

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'static_resource_graph',
          'resource_graph',
          data,
          input.session_tag
        ))
      }

      return {
        ok: true,
        data,
        artifacts,
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
