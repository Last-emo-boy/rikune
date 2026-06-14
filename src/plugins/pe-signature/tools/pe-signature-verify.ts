/**
 * pe.signature.verify — Verify PE Authenticode digital signature.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  ArtifactRefSchema,
  SharedMetricsSchema,
  ensureSampleExists,
  normalizeError,
  executeCommand,
  persistBackendArtifact,
  buildMetrics,
  resolveSampleFile,
  resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'pe.signature.verify'
const VERIFY_ARTIFACT_TYPE = 'backend_pe-sig_verify'
const CERTIFICATE_ARTIFACT_TYPE = 'backend_pe-sig_certificate'

export const PE_SIGNATURE_TRUST_REVIEW_SAFETY = [
  'passive',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
]

export const PE_SIGNATURE_TRUST_REVIEW_EVIDENCE = [
  'signatures',
  'certificates',
  'authenticode',
  'trust',
  'workflow',
  'provenance',
]

export const PE_SIGNATURE_VERIFY_RECOMMENDED_NEXT_TOOLS = [
  'pe.certificate.extract',
  'pe.structure.analyze',
  'windows.debug.metadata.inspect',
  'analysis.evidence.graph',
  'report.generate',
  'artifact.read',
]

export const PE_SIGNATURE_AUTHENTICODE_TRUST_REVIEW_RECIPE = {
  id: 'pe-signature.authenticode-trust-review',
  title: 'PE Authenticode trust review',
  description:
    'Review PE Authenticode signature status, certificate chain metadata, PE structure context, debug metadata hints, and reporting handoff without network lookups, mutation, or live sample execution.',
  startsWith: ['pe.signature.verify'],
  nextTools: PE_SIGNATURE_VERIFY_RECOMMENDED_NEXT_TOOLS,
  requiredArtifacts: ['sample'],
  producesArtifacts: [VERIFY_ARTIFACT_TYPE, CERTIFICATE_ARTIFACT_TYPE],
  evidence: PE_SIGNATURE_TRUST_REVIEW_EVIDENCE,
  safety: PE_SIGNATURE_TRUST_REVIEW_SAFETY,
}

export const peSignatureVerifyInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the PE file.'),
  timeout_sec: z.number().int().min(5).max(30).default(15).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist verification report.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const peSignatureVerifyOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      sample_id: z.string().optional(),
      is_signed: z.boolean().optional(),
      signature_valid: z.boolean().optional(),
      signer: z.string().optional(),
      issuer: z.string().optional(),
      serial: z.string().optional(),
      timestamp: z.string().optional(),
      digest_algorithm: z.string().optional(),
      raw_output: z.string().optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const peSignatureVerifyToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Verify PE Authenticode digital signature and show signer/issuer details.',
  inputSchema: peSignatureVerifyInputSchema,
  outputSchema: peSignatureVerifyOutputSchema,
  aspects: {
    formats: ['pe', 'pe32', 'pe64', 'exe', 'dll', 'sys', 'efi', 'pe-clr'],
    platforms: ['windows'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage'],
    safety: PE_SIGNATURE_TRUST_REVIEW_SAFETY,
    capabilities: ['signatures', 'certificates', 'timestamp', 'authenticode', 'trust-review'],
    evidence: PE_SIGNATURE_TRUST_REVIEW_EVIDENCE,
  },
  artifacts: [
    {
      type: VERIFY_ARTIFACT_TYPE,
      description: 'Bounded osslsigncode Authenticode verification report',
    },
  ],
  evidence: [
    {
      category: 'signatures',
      artifactTypes: [VERIFY_ARTIFACT_TYPE],
    },
    {
      category: 'certificates',
      artifactTypes: [VERIFY_ARTIFACT_TYPE],
    },
    {
      category: 'authenticode',
      artifactTypes: [VERIFY_ARTIFACT_TYPE],
    },
    {
      category: 'trust',
      artifactTypes: [VERIFY_ARTIFACT_TYPE],
    },
  ],
  workflowRecipes: [PE_SIGNATURE_AUTHENTICODE_TRUST_REVIEW_RECIPE],
}

export function createPeSignatureVerifyHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = peSignatureVerifyInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({
        envPath: process.env.OSSLSIGNCODE_PATH,
        pathCandidates: ['osslsigncode'],
        versionArgSets: [['--version'], ['-v']],
      })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(
          backend ||
            ({
              name: 'osslsigncode',
              available: false,
              error: 'osslsigncode not installed',
            } as any),
          startTime,
          TOOL_NAME
        )
      }

      const result = await executeCommand(
        backend.path,
        ['verify', '-in', samplePath],
        input.timeout_sec * 1000
      )

      const out = result.stdout + '\n' + result.stderr
      const isSigned = !/no signature/i.test(out) && /Signature verification/i.test(out)
      const signatureValid = /Signature verification:\s*ok/i.test(out)
      const signer = out.match(/Subject:\s*(.+)/i)?.[1]?.trim() || ''
      const issuer = out.match(/Issuer\s*:\s*(.+)/i)?.[1]?.trim() || ''
      const serial = out.match(/Serial\s*:\s*(.+)/i)?.[1]?.trim() || ''
      const timestamp = out.match(/Timestamp:\s*(.+)/i)?.[1]?.trim() || ''
      const digest = out.match(/(?:Message|Hash) (?:digest|algorithm)\s*:\s*(\S+)/i)?.[1] || ''

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'pe-sig',
          'verify',
          out.slice(0, 16384),
          { extension: 'txt', mime: 'text/plain', sessionTag: input.session_tag }
        )
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          is_signed: isSigned,
          signature_valid: signatureValid,
          signer,
          issuer,
          serial,
          timestamp: timestamp || undefined,
          digest_algorithm: digest || undefined,
          raw_output: out.slice(0, 4096),
          artifact,
          summary: isSigned
            ? `Signed by "${signer || 'unknown'}", verification: ${signatureValid ? 'VALID' : 'INVALID'}.`
            : 'No Authenticode signature found.',
          recommended_next_tools: [...PE_SIGNATURE_VERIFY_RECOMMENDED_NEXT_TOOLS],
          next_actions: isSigned
            ? [
                signatureValid
                  ? 'Check if signer is a known publisher.'
                  : 'Investigate invalid signature — may be tampered.',
                'Extract the full certificate chain for pivoting.',
              ]
            : ['Unsigned PE — no further signature analysis needed.'],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    }
  }
}
