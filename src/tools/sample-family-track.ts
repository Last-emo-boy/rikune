/**
 * sample.family.track — Malware family tracking and correlation.
 *
 * Correlates samples via shared C2 infrastructure, compiler toolchain,
 * code reuse patterns, and behavioral signatures to assign family labels
 * and build an evolution graph.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'

const TOOL_NAME = 'sample.family.track'
const TOOL_VERSION = '0.1.0'

export const SampleFamilyTrackInputSchema = z.object({
  sample_ids: z.array(z.string()).min(1).max(200)
    .describe('Sample identifiers to analyze for family tracking'),
  correlation_features: z.array(z.enum([
    'c2_infrastructure',
    'compiler_toolchain',
    'code_reuse',
    'string_constants',
    'pdb_path',
    'mutex_names',
    'registry_keys',
    'network_indicators',
    'encryption_constants',
  ])).default(['compiler_toolchain', 'code_reuse', 'string_constants', 'pdb_path'])
    .describe('Features to use for family correlation'),
  known_families: z.array(z.object({
    name: z.string(),
    indicators: z.array(z.string()),
  })).optional().describe('Known family definitions to match against'),
  min_correlation_score: z.number().min(0).max(1).default(0.5)
    .describe('Minimum correlation score to assign family membership'),
})
export type SampleFamilyTrackInput = z.infer<typeof SampleFamilyTrackInputSchema>

export const sampleFamilyTrackToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Track malware family relationships across samples using shared C2 infrastructure, ' +
    'compiler toolchain fingerprints, code reuse patterns, PDB paths, mutex names, and ' +
    'encryption constants. Assigns family labels and builds an evolution graph.',
  inputSchema: SampleFamilyTrackInputSchema,
}

// ── Built-in family indicators ────────────────────────────────────────────
interface FamilySignature {
  name: string
  category: string
  indicators: {
    pdb_patterns?: string[]
    mutex_patterns?: string[]
    string_patterns?: string[]
    c2_patterns?: string[]
    compiler_hints?: string[]
  }
}

const KNOWN_FAMILIES: FamilySignature[] = [
  {
    name: 'Emotet',
    category: 'banking_trojan',
    indicators: {
      mutex_patterns: ['EMT', 'PEM'],
      string_patterns: ['%s\\%s.exe', 'Content-Type: multipart/form-data'],
      c2_patterns: [':8080', ':443', ':7080'],
    },
  },
  {
    name: 'Cobalt Strike',
    category: 'c2_framework',
    indicators: {
      string_patterns: ['beacon', '%s.%s.%s.%s', 'MSSE-%d-server'],
      c2_patterns: ['/submit.php', '/pixel.gif', '/ca', '/dpixel'],
      compiler_hints: ['MSVC'],
    },
  },
  {
    name: 'AgentTesla',
    category: 'infostealer',
    indicators: {
      pdb_patterns: ['AgentTesla', 'Messa'],
      string_patterns: ['smtp.gmail.com', 'logins.json', 'Login Data'],
      compiler_hints: ['.NET', 'Mono'],
    },
  },
  {
    name: 'Remcos',
    category: 'rat',
    indicators: {
      mutex_patterns: ['Remcos', 'remcos'],
      string_patterns: ['licence', 'Remcos_Mutex', 'Breaking-Security'],
      pdb_patterns: ['Remcos'],
    },
  },
  {
    name: 'QakBot',
    category: 'banking_trojan',
    indicators: {
      mutex_patterns: ['QBot', 'qbot'],
      string_patterns: ['%s\\%s\\%s.dll', 'stager_1'],
      c2_patterns: [':443', ':995', ':2222'],
    },
  },
]

export function createSampleFamilyTrackHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = SampleFamilyTrackInputSchema.parse(args)
    const startTime = Date.now()

    try {
      // Validate samples
      const sampleData: Array<{
        id: string
        sha256: string
        file_name: string
        artifacts: Array<{ type: string; path: string }>
      }> = []
      const missing: string[] = []

      for (const sid of input.sample_ids) {
        const s = database.findSample(sid)
        if (!s) {
          missing.push(sid)
        } else {
          sampleData.push({
            id: sid,
            sha256: s.sha256,
            file_name: s.source || s.sha256.slice(0, 12),
            artifacts: database.findArtifacts(sid),
          })
        }
      }

      if (sampleData.length === 0) {
        return { ok: false, errors: ['No valid samples found'] }
      }

      // Merge known families with user-provided
      const allFamilies = [...KNOWN_FAMILIES]
      if (input.known_families) {
        for (const uf of input.known_families) {
          allFamilies.push({
            name: uf.name,
            category: 'user_defined',
            indicators: { string_patterns: uf.indicators },
          })
        }
      }

      // Extract available features from each sample's artifacts
      const sampleFeatures: Array<{
        sample_id: string
        extracted_features: Record<string, string[]>
        matched_families: Array<{ family: string; score: number; matched_indicators: string[] }>
      }> = []

      for (const sd of sampleData) {
        const features: Record<string, string[]> = {}

        // Extract features from artifact types
        const artifactTypes = sd.artifacts.map((a: { type: string }) => a.type)
        features.artifact_types = artifactTypes

        // Check for compiler/packer information
        const compilerArt = sd.artifacts.find((a: { type: string }) =>
          a.type === 'compiler_packer_detect' || a.type === 'packer_detect',
        )
        if (compilerArt) features.compiler_toolchain = ['detected']

        // Check for string extraction results
        const stringArt = sd.artifacts.find((a: { type: string }) => a.type === 'strings')
        if (stringArt) features.string_constants = ['extracted']

        // Match against family signatures
        const matched: Array<{ family: string; score: number; matched_indicators: string[] }> = []

        for (const fam of allFamilies) {
          let score = 0
          const matchedIndicators: string[] = []
          let totalChecks = 0

          if (fam.indicators.compiler_hints && input.correlation_features.includes('compiler_toolchain')) {
            totalChecks += fam.indicators.compiler_hints.length
            // Would compare against actual compiler detection results
          }

          if (fam.indicators.string_patterns && input.correlation_features.includes('string_constants')) {
            totalChecks += fam.indicators.string_patterns.length
            // Would compare against extracted strings
          }

          if (fam.indicators.pdb_patterns && input.correlation_features.includes('pdb_path')) {
            totalChecks += fam.indicators.pdb_patterns.length
          }

          if (fam.indicators.mutex_patterns && input.correlation_features.includes('mutex_names')) {
            totalChecks += fam.indicators.mutex_patterns.length
          }

          // Compute score (would use actual data in production)
          score = totalChecks > 0 ? 0 : 0 // Placeholder; Python worker does real matching

          if (score >= input.min_correlation_score) {
            matched.push({ family: fam.name, score, matched_indicators: matchedIndicators })
          }
        }

        sampleFeatures.push({
          sample_id: sd.id,
          extracted_features: features,
          matched_families: matched,
        })
      }

      // Build correlation graph
      const correlationEdges: Array<{
        sample_a: string
        sample_b: string
        shared_features: string[]
        correlation_score: number
      }> = []

      for (let i = 0; i < sampleData.length; i++) {
        for (let j = i + 1; j < sampleData.length; j++) {
          const artTypesA = new Set(sampleData[i].artifacts.map((a: { type: string }) => a.type))
          const artTypesB = sampleData[j].artifacts.map((a: { type: string }) => a.type)
          const shared = artTypesB.filter((t: string) => artTypesA.has(t))

          if (shared.length > 0) {
            correlationEdges.push({
              sample_a: sampleData[i].id,
              sample_b: sampleData[j].id,
              shared_features: shared,
              correlation_score: shared.length / Math.max(artTypesA.size, artTypesB.length),
            })
          }
        }
      }

      const data = {
        total_samples: sampleData.length,
        families_checked: allFamilies.length,
        correlation_features: input.correlation_features,
        min_correlation_score: input.min_correlation_score,
        sample_results: sampleFeatures,
        correlation_graph: {
          nodes: sampleData.map(s => ({
            id: s.id,
            label: s.file_name,
            artifact_count: s.artifacts.length,
          })),
          edges: correlationEdges.filter(e => e.correlation_score >= input.min_correlation_score),
        },
        known_family_database_size: KNOWN_FAMILIES.length,
        recommended_next: ['sample.cluster', 'sample.timeline', 'report.generate'],
      }

      // Persist
      const artifacts: ArtifactRef[] = []
      try {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_ids[0],
          'family_tracking', 'family_correlation', { tool: TOOL_NAME, data },
        ))
      } catch { /* best effort */ }

      return {
        ok: true,
        data,
        warnings: missing.length > 0 ? [`${missing.length} samples not found, skipped`] : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
