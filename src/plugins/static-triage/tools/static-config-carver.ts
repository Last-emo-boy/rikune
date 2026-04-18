/**
 * static.config.carver tool.
 *
 * Generic configuration candidate extraction from raw bytes and strings. This
 * is intentionally family-agnostic: it finds URLs, hosts, mutex-like strings,
 * registry paths, user agents, encoded blobs, and high-signal resource hints.
 */

import fs from 'fs/promises'
import { createHash } from 'crypto'
import { z } from 'zod'
import type { ToolArgs, ToolDefinition, WorkerResult, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { resolvePrimarySamplePath } from '../../../sample/sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'static.config.carver'
const TOOL_VERSION = '0.1.0'

export const StaticConfigCarverInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  max_strings: z.number().int().min(50).max(5000).optional().default(1200),
  min_string_length: z.number().int().min(4).max(32).optional().default(5),
  max_blob_candidates: z.number().int().min(0).max(200).optional().default(50),
  persist_artifact: z.boolean().optional().default(true),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const StaticConfigCarverOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(z.any()).optional(),
  metrics: z.record(z.any()).optional(),
})

export const staticConfigCarverToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Carve generic malware/configuration candidates from raw sample bytes: URLs, domains, IPs, ports, registry paths, mutex-like values, user agents, encoded blobs, and suspicious configuration strings. Does not execute the sample.',
  inputSchema: StaticConfigCarverInputSchema,
  outputSchema: StaticConfigCarverOutputSchema,
}

interface ConfigCandidate {
  kind: string
  value: string
  confidence: number
  evidence: string[]
}

interface BlobCandidate {
  kind: 'base64' | 'hex'
  value_preview: string
  decoded_size: number | null
  confidence: number
  evidence: string[]
}

function extractAsciiStrings(buffer: Buffer, minLength: number, maxStrings: number): string[] {
  const regex = new RegExp(`[\\x20-\\x7e]{${minLength},240}`, 'g')
  const matches = buffer.toString('latin1').match(regex) || []
  return Array.from(new Set(matches.map((item) => item.trim()).filter(Boolean))).slice(0, maxStrings)
}

function extractUtf16Strings(buffer: Buffer, minLength: number, maxStrings: number): string[] {
  const strings: string[] = []
  let current = ''
  for (let index = 0; index + 1 < buffer.length; index += 2) {
    const lo = buffer[index]
    const hi = buffer[index + 1]
    if (hi === 0 && lo >= 0x20 && lo <= 0x7e) {
      current += String.fromCharCode(lo)
      continue
    }
    if (current.length >= minLength) strings.push(current)
    current = ''
    if (strings.length >= maxStrings) break
  }
  if (current.length >= minLength) strings.push(current)
  return Array.from(new Set(strings)).slice(0, maxStrings)
}

function pushCandidate(candidates: ConfigCandidate[], kind: string, value: string, confidence: number, evidence: string[]): void {
  const normalized = value.trim()
  if (!normalized) return
  if (candidates.some((candidate) => candidate.kind === kind && candidate.value === normalized)) return
  candidates.push({ kind, value: normalized, confidence, evidence })
}

function domainLooksUseful(value: string): boolean {
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return false
  if (/^(microsoft|windows|schemas|w3|example|localhost)\./i.test(value)) return false
  if (/\.(dll|exe|pdb|config|manifest)$/i.test(value)) return false
  return true
}

function inferConfigCandidates(strings: string[]): ConfigCandidate[] {
  const candidates: ConfigCandidate[] = []
  const joined = strings.join('\n')
  for (const match of joined.matchAll(/https?:\/\/[^\s"'<>\\]{4,240}/gi)) {
    pushCandidate(candidates, 'url', match[0], 0.9, ['http_url_string'])
  }
  for (const match of joined.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g)) {
    const parts = match[0].split(':')[0].split('.').map(Number)
    if (parts.every((part) => part >= 0 && part <= 255)) {
      pushCandidate(candidates, match[0].includes(':') ? 'ip_port' : 'ip', match[0], 0.78, ['ipv4_string'])
    }
  }
  for (const raw of strings) {
    const domainMatches = raw.match(/\b[a-z0-9][a-z0-9.-]{2,80}\.[a-z]{2,12}\b/gi) || []
    for (const domain of domainMatches) {
      if (domainLooksUseful(domain)) pushCandidate(candidates, 'domain', domain.toLowerCase(), 0.68, ['domain_like_string'])
    }
    if (/HKEY_|\\Software\\|\\Microsoft\\Windows\\CurrentVersion\\Run/i.test(raw)) {
      pushCandidate(candidates, 'registry_path', raw, 0.78, ['registry_path_string'])
    }
    if (/User-Agent|Mozilla\/|Chrome\/|curl\/|WinHTTP|WinInet/i.test(raw)) {
      pushCandidate(candidates, 'user_agent_or_http_client', raw, 0.7, ['http_client_string'])
    }
    if (/^[{(]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[)}]?$/i.test(raw)) {
      pushCandidate(candidates, 'guid_or_mutex', raw, 0.62, ['guid_like_string'])
    } else if (
      raw.length >= 8 &&
      raw.length <= 120 &&
      /mutex|global\\|local\\|session\\|_mtx|lock/i.test(raw) &&
      !/\s{3,}/.test(raw)
    ) {
      pushCandidate(candidates, 'mutex_like', raw, 0.66, ['mutex_keyword'])
    }
    if (/password|passwd|token|apikey|api_key|secret|gate|panel|campaign|botid|install_id|mutex|sleep|interval|beacon/i.test(raw)) {
      pushCandidate(candidates, 'config_keyword_string', raw, 0.58, ['configuration_keyword'])
    }
  }
  return candidates.sort((a, b) => b.confidence - a.confidence)
}

function tryDecodeBase64(value: string): Buffer | null {
  if (value.length < 24 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null
  try {
    const decoded = Buffer.from(value, 'base64')
    if (decoded.length < 12) return null
    return decoded
  } catch {
    return null
  }
}

function tryDecodeHex(value: string): Buffer | null {
  if (value.length < 32 || value.length % 2 !== 0 || !/^[a-f0-9]+$/i.test(value)) return null
  try {
    return Buffer.from(value, 'hex')
  } catch {
    return null
  }
}

function entropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0
  const counts = new Array<number>(256).fill(0)
  for (const byte of buffer) counts[byte] += 1
  let result = 0
  for (const count of counts) {
    if (!count) continue
    const p = count / buffer.length
    result -= p * Math.log2(p)
  }
  return Number(result.toFixed(3))
}

function collectBlobCandidates(strings: string[], maxBlobCandidates: number): BlobCandidate[] {
  const blobs: BlobCandidate[] = []
  for (const raw of strings) {
    if (blobs.length >= maxBlobCandidates) break
    const compact = raw.trim()
    const b64 = tryDecodeBase64(compact)
    if (b64) {
      blobs.push({
        kind: 'base64',
        value_preview: compact.slice(0, 96),
        decoded_size: b64.length,
        confidence: entropy(b64) >= 6.5 ? 0.68 : 0.48,
        evidence: [`decoded_entropy=${entropy(b64)}`],
      })
      continue
    }
    const hex = tryDecodeHex(compact)
    if (hex) {
      blobs.push({
        kind: 'hex',
        value_preview: compact.slice(0, 96),
        decoded_size: hex.length,
        confidence: entropy(hex) >= 6.5 ? 0.64 : 0.44,
        evidence: [`decoded_entropy=${entropy(hex)}`],
      })
    }
  }
  return blobs
}

function summarize(candidates: ConfigCandidate[], blobs: BlobCandidate[]) {
  const byKind: Record<string, number> = {}
  for (const candidate of candidates) byKind[candidate.kind] = (byKind[candidate.kind] || 0) + 1
  return {
    candidate_count: candidates.length,
    blob_candidate_count: blobs.length,
    kinds: byKind,
    high_confidence_count: candidates.filter((candidate) => candidate.confidence >= 0.75).length,
  }
}

export function createStaticConfigCarverHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = StaticConfigCarverInputSchema.parse(args)
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`], metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME } }
      }
      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)
      const buffer = await fs.readFile(samplePath)
      const asciiStrings = extractAsciiStrings(buffer, input.min_string_length, input.max_strings)
      const utf16Strings = extractUtf16Strings(buffer, input.min_string_length, Math.floor(input.max_strings / 2))
      const strings = Array.from(new Set([...asciiStrings, ...utf16Strings]))
      const candidates = inferConfigCandidates(strings)
      const blobCandidates = collectBlobCandidates(strings, input.max_blob_candidates)
      const data = {
        schema: 'rikune.static_config_carver.v1',
        tool_version: TOOL_VERSION,
        sample_id: input.sample_id,
        file: {
          size: buffer.length,
          sha256: createHash('sha256').update(buffer).digest('hex'),
        },
        summary: summarize(candidates, blobCandidates),
        candidates: candidates.slice(0, 300),
        blob_candidates: blobCandidates,
        recommended_next_tools: [
          'static.resource.graph',
          'strings.extract',
          'crypto.identify',
          'dynamic.deep_plan',
          'dynamic.behavior.capture',
        ],
        next_actions: [
          'Review high-confidence URLs, IPs, registry paths, and config keyword strings before live execution.',
          'Use static.resource.graph when encoded blobs or resource-backed payloads are present.',
          'Use dynamic.persona.plan before runtime execution when anti-sandbox or environment-sensitive strings are present.',
        ],
      }

      const artifacts: ArtifactRef[] = []
      if (input.persist_artifact) {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'static_config_carver',
          'config_carver',
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
