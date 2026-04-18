/**
 * unpack.child.handoff tool.
 *
 * Carves embedded payload candidates from resource graph artifacts, raw sample
 * bytes, and imported raw dumps, then optionally registers them as child
 * samples with provenance. Static artifact workflow only; it never executes the
 * sample.
 */

import fs from 'fs/promises'
import path from 'path'
import { createHash, randomUUID } from 'crypto'
import { z } from 'zod'
import type { ArtifactRef, ToolArgs, ToolDefinition, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import {
  loadStaticAnalysisArtifactSelection,
  persistStaticAnalysisJsonArtifact,
  type StaticArtifactScope,
} from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'unpack.child.handoff'
const TOOL_VERSION = '0.1.0'

interface ResourceGraphPayload {
  resources?: Array<{
    path?: string[]
    dataOffset?: number | null
    size?: number
    magic?: string
    entropy?: number | null
    sha256?: string | null
  }>
}

type CandidateSource = 'resource_graph' | 'sample_scan' | 'raw_dump_scan'

interface PayloadCandidate {
  candidate_id: string
  source: CandidateSource
  source_artifact_id?: string
  source_artifact_path?: string
  source_path?: string
  resource_path?: string
  offset: number
  size: number
  magic: string
  sha256: string
  confidence: number
  evidence: string[]
  bytes: Buffer
}

interface RegisteredChild {
  sample_id: string
  sha256: string
  size: number
  filename: string
  existed: boolean
}

export const UnpackChildHandoffInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  include_resource_graph: z.boolean().optional().default(true),
  resource_scope: z.enum(['all', 'latest', 'session']).optional().default('latest'),
  resource_session_tag: z.string().optional(),
  include_sample_scan: z.boolean().optional().default(true),
  include_raw_dump_scan: z.boolean().optional().default(true),
  max_candidates: z.number().int().min(1).max(128).optional().default(32),
  max_children: z.number().int().min(0).max(32).optional().default(8),
  min_candidate_size: z.number().int().min(2).max(1024 * 1024).optional().default(64),
  max_child_bytes: z.number().int().min(1024).max(256 * 1024 * 1024).optional().default(32 * 1024 * 1024),
  register_children: z.boolean().optional().default(true),
  persist_payload_artifacts: z.boolean().optional().default(true),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional(),
})

export const unpackChildHandoffToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Carve embedded payload candidates from static resource graph artifacts, raw sample bytes, and imported memory/raw dump artifacts, then optionally register bounded child samples with provenance. Does not execute the sample.',
  inputSchema: UnpackChildHandoffInputSchema,
}

function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}

function md5(data: Buffer): string {
  return createHash('md5').update(data).digest('hex')
}

function readUInt16(buffer: Buffer, offset: number): number {
  return offset >= 0 && offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : 0
}

function readUInt32(buffer: Buffer, offset: number): number {
  return offset >= 0 && offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : 0
}

function shannonEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0
  const counts = new Array<number>(256).fill(0)
  for (const byte of buffer) counts[byte] += 1
  let entropy = 0
  for (const count of counts) {
    if (!count) continue
    const p = count / buffer.length
    entropy -= p * Math.log2(p)
  }
  return Number(entropy.toFixed(3))
}

function magicOf(buffer: Buffer): string {
  if (buffer.length >= 2 && buffer.subarray(0, 2).toString('ascii') === 'MZ') return 'pe_or_dos'
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString('hex') === '504b0304') return 'zip'
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString('ascii') === 'MSCF') return 'cab'
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString('hex') === '7f454c46') return 'elf'
  return 'binary'
}

function estimatePeSize(buffer: Buffer, offset: number): number | null {
  if (offset + 0x40 > buffer.length || buffer[offset] !== 0x4d || buffer[offset + 1] !== 0x5a) {
    return null
  }
  const peOffset = readUInt32(buffer, offset + 0x3c)
  const signatureOffset = offset + peOffset
  if (signatureOffset + 0x18 > buffer.length || buffer.subarray(signatureOffset, signatureOffset + 4).toString('ascii') !== 'PE\0\0') {
    return null
  }
  const coffOffset = signatureOffset + 4
  const sectionCount = readUInt16(buffer, coffOffset + 2)
  const optionalHeaderSize = readUInt16(buffer, coffOffset + 16)
  const sectionTableOffset = coffOffset + 20 + optionalHeaderSize
  if (sectionCount <= 0 || sectionCount > 96 || sectionTableOffset + sectionCount * 40 > buffer.length) {
    return null
  }
  let end = sectionTableOffset + sectionCount * 40
  for (let index = 0; index < sectionCount; index += 1) {
    const sectionOffset = sectionTableOffset + index * 40
    const rawSize = readUInt32(buffer, sectionOffset + 16)
    const rawPointer = readUInt32(buffer, sectionOffset + 20)
    if (rawPointer > 0 && rawSize > 0) {
      end = Math.max(end, offset + rawPointer + rawSize)
    }
  }
  if (end <= offset || end > buffer.length) {
    return null
  }
  return end - offset
}

function estimateZipSize(buffer: Buffer, offset: number): number | null {
  const eocdSignature = Buffer.from([0x50, 0x4b, 0x05, 0x06])
  const endSearch = buffer.indexOf(eocdSignature, offset + 4)
  if (endSearch >= 0 && endSearch + 22 <= buffer.length) {
    const commentLength = readUInt16(buffer, endSearch + 20)
    return Math.min(buffer.length - offset, endSearch + 22 + commentLength - offset)
  }
  return null
}

function nextMagicOffset(buffer: Buffer, offset: number): number {
  const signatures = ['MZ', 'PK\x03\x04', 'MSCF', '\x7fELF'].map((item) => Buffer.from(item, 'binary'))
  const offsets = signatures
    .map((signature) => buffer.indexOf(signature, offset + 2))
    .filter((item) => item > offset)
  return offsets.length > 0 ? Math.min(...offsets) : buffer.length
}

function buildCandidate(
  options: {
    source: CandidateSource
    sourcePath?: string
    sourceArtifactId?: string
    sourceArtifactPath?: string
    resourcePath?: string
    offset: number
    bytes: Buffer
    evidence: string[]
  }
): PayloadCandidate | null {
  if (options.bytes.length === 0) {
    return null
  }
  const magic = magicOf(options.bytes)
  const entropy = shannonEntropy(options.bytes.subarray(0, Math.min(options.bytes.length, 1024 * 1024)))
  const confidence =
    magic === 'pe_or_dos' ? 0.92 :
    magic === 'zip' || magic === 'cab' || magic === 'elf' ? 0.82 :
    entropy >= 7.2 ? 0.58 : 0.38
  const digest = sha256(options.bytes)
  return {
    candidate_id: `${options.source}:${digest.slice(0, 16)}:${options.offset}`,
    source: options.source,
    source_artifact_id: options.sourceArtifactId,
    source_artifact_path: options.sourceArtifactPath,
    source_path: options.sourcePath,
    resource_path: options.resourcePath,
    offset: options.offset,
    size: options.bytes.length,
    magic,
    sha256: digest,
    confidence,
    evidence: [...options.evidence, `entropy=${entropy}`],
    bytes: options.bytes,
  }
}

function scanBufferForPayloads(
  buffer: Buffer,
  source: CandidateSource,
  sourcePath: string,
  options: { minSize: number; maxBytes: number; maxCandidates: number; sourceArtifactId?: string; sourceArtifactPath?: string }
): PayloadCandidate[] {
  const candidates: PayloadCandidate[] = []
  const seenOffsets = new Set<number>()
  const signatures: Array<{ magic: string; bytes: Buffer }> = [
    { magic: 'pe_or_dos', bytes: Buffer.from('MZ', 'ascii') },
    { magic: 'zip', bytes: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
    { magic: 'cab', bytes: Buffer.from('MSCF', 'ascii') },
    { magic: 'elf', bytes: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
  ]

  for (const signature of signatures) {
    let offset = buffer.indexOf(signature.bytes, source === 'sample_scan' ? 1 : 0)
    while (offset >= 0 && candidates.length < options.maxCandidates) {
      if (!seenOffsets.has(offset)) {
        seenOffsets.add(offset)
        let size: number | null = null
        if (signature.magic === 'pe_or_dos') {
          size = estimatePeSize(buffer, offset)
        } else if (signature.magic === 'zip') {
          size = estimateZipSize(buffer, offset)
        }
        if (!size) {
          size = Math.min(options.maxBytes, nextMagicOffset(buffer, offset) - offset)
        }
        size = Math.min(size, options.maxBytes, buffer.length - offset)
        if (size >= options.minSize) {
          const candidate = buildCandidate({
            source,
            sourcePath,
            sourceArtifactId: options.sourceArtifactId,
            sourceArtifactPath: options.sourceArtifactPath,
            offset,
            bytes: buffer.subarray(offset, offset + size),
            evidence: [`${signature.magic}_signature_at_offset`],
          })
          if (candidate) {
            candidates.push(candidate)
          }
        }
      }
      offset = buffer.indexOf(signature.bytes, offset + 1)
    }
  }

  return candidates
}

function dedupeCandidates(candidates: PayloadCandidate[], maxCandidates: number): PayloadCandidate[] {
  const byHash = new Map<string, PayloadCandidate>()
  for (const candidate of candidates) {
    const existing = byHash.get(candidate.sha256)
    if (!existing || candidate.confidence > existing.confidence) {
      byHash.set(candidate.sha256, candidate)
    }
  }
  return Array.from(byHash.values())
    .sort((left, right) => {
      if (right.confidence !== left.confidence) return right.confidence - left.confidence
      return right.size - left.size
    })
    .slice(0, maxCandidates)
}

function extensionForMagic(magic: string): string {
  switch (magic) {
    case 'pe_or_dos':
      return '.bin'
    case 'zip':
      return '.zip'
    case 'cab':
      return '.cab'
    case 'elf':
      return '.elf'
    default:
      return '.bin'
  }
}

async function persistPayloadArtifact(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  sampleId: string,
  candidate: PayloadCandidate,
  sessionTag?: string
): Promise<ArtifactRef> {
  const workspace = await workspaceManager.createWorkspace(sampleId)
  const sessionSegment = (sessionTag || 'default')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'default'
  const dir = path.join(workspace.reports, 'unpack_handoff', sessionSegment)
  await fs.mkdir(dir, { recursive: true })
  const fileName = `payload_${candidate.source}_${candidate.sha256.slice(0, 12)}${extensionForMagic(candidate.magic)}`
  const absPath = path.join(dir, fileName)
  await fs.writeFile(absPath, candidate.bytes)
  const relativePath = path.relative(workspace.root, absPath).replace(/\\/g, '/')
  const artifact: ArtifactRef = {
    id: randomUUID(),
    type: 'unpack_child_payload',
    path: relativePath,
    sha256: candidate.sha256,
    mime: 'application/octet-stream',
    metadata: {
      source: candidate.source,
      candidate_id: candidate.candidate_id,
      magic: candidate.magic,
      offset: candidate.offset,
    },
  }
  database.insertArtifact({
    id: artifact.id,
    sample_id: sampleId,
    type: artifact.type,
    path: artifact.path,
    sha256: artifact.sha256,
    mime: artifact.mime || null,
    created_at: new Date().toISOString(),
  })
  return artifact
}

async function registerChildSample(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  parentId: string,
  candidate: PayloadCandidate
): Promise<RegisteredChild> {
  const childSha256 = candidate.sha256
  const sampleId = `sha256:${childSha256}`
  const existing = database.findSample(sampleId)
  const filename = `child_${candidate.source}_${childSha256.slice(0, 12)}${extensionForMagic(candidate.magic)}`

  if (!existing) {
    const workspace = await workspaceManager.createWorkspace(sampleId)
    await fs.writeFile(path.join(workspace.original, filename), candidate.bytes)
    database.insertSample({
      id: sampleId,
      sha256: childSha256,
      md5: md5(candidate.bytes),
      size: candidate.bytes.length,
      file_type: candidate.magic,
      source: `unpack_child_handoff:parent=${parentId}:source=${candidate.source}:offset=${candidate.offset}`,
      created_at: new Date().toISOString(),
    })
  }

  return {
    sample_id: sampleId,
    sha256: childSha256,
    size: candidate.bytes.length,
    filename,
    existed: Boolean(existing),
  }
}

function summarize(candidates: PayloadCandidate[], registered: RegisteredChild[]) {
  const bySource: Record<string, number> = {}
  const byMagic: Record<string, number> = {}
  for (const candidate of candidates) {
    bySource[candidate.source] = (bySource[candidate.source] || 0) + 1
    byMagic[candidate.magic] = (byMagic[candidate.magic] || 0) + 1
  }
  return {
    candidate_count: candidates.length,
    registered_child_count: registered.length,
    executable_like_count: candidates.filter((item) => ['pe_or_dos', 'elf'].includes(item.magic)).length,
    archive_like_count: candidates.filter((item) => ['zip', 'cab'].includes(item.magic)).length,
    by_source: bySource,
    by_magic: byMagic,
  }
}

export function createUnpackChildHandoffHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = UnpackChildHandoffInputSchema.parse(args || {})
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return {
          ok: false,
          errors: [`Sample not found: ${input.sample_id}`],
          metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const sampleBuffer = await fs.readFile(samplePath)
      const candidates: PayloadCandidate[] = []
      const warnings: string[] = []

      if (input.include_sample_scan) {
        candidates.push(...scanBufferForPayloads(sampleBuffer, 'sample_scan', samplePath, {
          minSize: input.min_candidate_size,
          maxBytes: input.max_child_bytes,
          maxCandidates: input.max_candidates,
        }))
      }

      let resourceArtifactIds: string[] = []
      if (input.include_resource_graph) {
        const resourceSelection = await loadStaticAnalysisArtifactSelection<ResourceGraphPayload>(
          workspaceManager,
          database,
          input.sample_id,
          'static_resource_graph',
          {
            scope: input.resource_scope as StaticArtifactScope,
            sessionTag: input.resource_session_tag,
          }
        )
        resourceArtifactIds = resourceSelection.artifact_ids
        if (resourceSelection.artifacts.length === 0) {
          warnings.push('No static_resource_graph artifacts were selected; raw sample scan is still used when enabled.')
        }
        for (const selected of resourceSelection.artifacts) {
          for (const resource of selected.payload.resources || []) {
            const offset = typeof resource.dataOffset === 'number' ? resource.dataOffset : null
            const size = typeof resource.size === 'number' ? resource.size : 0
            if (offset === null || size < input.min_candidate_size || size > input.max_child_bytes) {
              continue
            }
            if (offset < 0 || offset + size > sampleBuffer.length) {
              continue
            }
            const magic = resource.magic || magicOf(sampleBuffer.subarray(offset, offset + Math.min(size, 16)))
            const interesting = ['pe_or_dos', 'zip', 'cab', 'elf'].includes(magic) || (resource.entropy || 0) >= 7.2
            if (!interesting) {
              continue
            }
            const candidate = buildCandidate({
              source: 'resource_graph',
              sourcePath: samplePath,
              sourceArtifactId: selected.artifact_id,
              resourcePath: Array.isArray(resource.path) ? resource.path.join('/') : undefined,
              offset,
              bytes: sampleBuffer.subarray(offset, offset + size),
              evidence: [`resource_magic=${magic}`, `resource_entropy=${resource.entropy ?? 'unknown'}`],
            })
            if (candidate) {
              candidates.push(candidate)
            }
          }
        }
      }

      if (input.include_raw_dump_scan) {
        const workspace = await workspaceManager.getWorkspace(input.sample_id)
        for (const artifact of database.findArtifactsByType(input.sample_id, 'raw_dump')) {
          try {
            const absPath = workspaceManager.normalizePath(workspace.root, artifact.path)
            const rawDump = await fs.readFile(absPath)
            candidates.push(...scanBufferForPayloads(rawDump, 'raw_dump_scan', absPath, {
              minSize: input.min_candidate_size,
              maxBytes: input.max_child_bytes,
              maxCandidates: input.max_candidates,
              sourceArtifactId: artifact.id,
              sourceArtifactPath: artifact.path,
            }))
          } catch {
            warnings.push(`Failed to scan raw_dump artifact ${artifact.id}.`)
          }
        }
      }

      const selectedCandidates = dedupeCandidates(candidates, input.max_candidates)
      const registeredChildren: RegisteredChild[] = []
      const payloadArtifacts: ArtifactRef[] = []

      for (const candidate of selectedCandidates.slice(0, input.max_children)) {
        if (input.persist_payload_artifacts) {
          payloadArtifacts.push(await persistPayloadArtifact(workspaceManager, database, input.sample_id, candidate, input.session_tag))
        }
        if (input.register_children) {
          registeredChildren.push(await registerChildSample(workspaceManager, database, input.sample_id, candidate))
        }
      }

      const candidateViews = selectedCandidates.map((candidate) => {
        const registered = registeredChildren.find((child) => child.sha256 === candidate.sha256)
        const payloadArtifact = payloadArtifacts.find((artifact) => artifact.sha256 === candidate.sha256)
        return {
          candidate_id: candidate.candidate_id,
          source: candidate.source,
          source_artifact_id: candidate.source_artifact_id || null,
          source_artifact_path: candidate.source_artifact_path || null,
          resource_path: candidate.resource_path || null,
          offset: candidate.offset,
          size: candidate.size,
          magic: candidate.magic,
          sha256: candidate.sha256,
          confidence: candidate.confidence,
          evidence: candidate.evidence,
          registered_child_sample_id: registered?.sample_id || null,
          payload_artifact: payloadArtifact || null,
        }
      })

      const data = {
        schema: 'rikune.unpack_child_handoff.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        source: {
          sample_path: path.basename(samplePath),
          sample_size: sampleBuffer.length,
          sample_sha256: sha256(sampleBuffer),
        },
        summary: summarize(selectedCandidates, registeredChildren),
        resource_artifact_ids: resourceArtifactIds,
        candidates: candidateViews,
        registered_children: registeredChildren,
        recommended_next_tools: [
          'workflow.analyze.start',
          'static.resource.graph',
          'static.config.carver',
          'static.behavior.classify',
          'unpack.auto',
          'dynamic.memory.import',
        ],
        next_actions: registeredChildren.length > 0
          ? [
              'Run workflow.analyze.start on registered child sample IDs to preserve parent/child provenance.',
              'Use static.behavior.classify and static.config.carver on child payloads before dynamic execution.',
            ]
          : [
              'Run static.resource.graph and dynamic.memory.import to add richer payload sources, then retry unpack.child.handoff.',
            ],
        warnings,
      }

      const artifacts: ArtifactRef[] = [...payloadArtifacts]
      if (input.persist_artifact) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'unpack_child_handoff',
          'child_handoff',
          data,
          input.session_tag
        ))
      }

      return {
        ok: true,
        data,
        warnings: warnings.length > 0 ? warnings : undefined,
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
