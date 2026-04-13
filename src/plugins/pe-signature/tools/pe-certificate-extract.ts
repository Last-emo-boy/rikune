/**
 * pe.certificate.extract — Extract embedded certificates from a signed PE.
 */

import { z } from 'zod'
import nodeFs from 'node:fs'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  os, path,
  ArtifactRefSchema, SharedMetricsSchema,
  ensureSampleExists, normalizeError, executeCommand,
  persistBackendArtifact, buildMetrics,
  resolveSampleFile, resolveExecutable,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'pe.certificate.extract'

export const peCertificateExtractInputSchema = z.object({
  sample_id: z.string().describe('Sample ID for the PE file.'),
  timeout_sec: z.number().int().min(5).max(30).default(15).describe('Timeout.'),
  persist_artifact: z.boolean().default(true).describe('Persist extracted certificate.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const peCertificateExtractOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    has_certificate: z.boolean().optional(),
    subject: z.string().optional(),
    issuer: z.string().optional(),
    serial: z.string().optional(),
    not_before: z.string().optional(),
    not_after: z.string().optional(),
    certificate_pem: z.string().optional(),
    artifact: ArtifactRefSchema.optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const peCertificateExtractToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description: 'Extract the Authenticode certificate chain from a signed PE file.',
  inputSchema: peCertificateExtractInputSchema,
  outputSchema: peCertificateExtractOutputSchema,
}

export function createPeCertificateExtractHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    const tmpCert = path.join(os.tmpdir(), `pe-cert-${Date.now()}.pem`)
    try {
      const input = peCertificateExtractInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolveExecutable({ envPath: process.env.OSSLSIGNCODE_PATH, pathCandidates: ['osslsigncode'], versionArgSets: [['--version'], ['-v']] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'osslsigncode', available: false, error: 'osslsigncode not installed' } as any, startTime, TOOL_NAME)
      }

      // Extract PKCS7 signature
      const result = await executeCommand(
        backend.path,
        ['extract-signature', '-pem', '-in', samplePath, '-out', tmpCert],
        input.timeout_sec * 1000,
      )

      if (!nodeFs.existsSync(tmpCert) || nodeFs.statSync(tmpCert).size === 0) {
        return {
          ok: true,
          data: {
            sample_id: input.sample_id,
            has_certificate: false,
            summary: 'No Authenticode certificate found in PE.',
            recommended_next_tools: ['pe.signature.verify', 'pe.inspect'],
            next_actions: ['The file is unsigned — no certificate to extract.'],
          },
          metrics: buildMetrics(startTime, TOOL_NAME),
        }
      }

      const pem = nodeFs.readFileSync(tmpCert, 'utf-8')

      // Try to parse certificate details using openssl if available
      let subject = '', issuer = '', serial = '', notBefore = '', notAfter = ''
      try {
        const opensslBackend = resolveExecutable({ envPath: process.env.OPENSSL_PATH, pathCandidates: ['openssl'], versionArgSets: [['version']] })
        if (opensslBackend?.available && opensslBackend?.path) {
          const info = await executeCommand(
            opensslBackend.path,
            ['pkcs7', '-in', tmpCert, '-print_certs', '-noout', '-text'],
            10000,
          )
          subject = info.stdout.match(/Subject:\s*(.+)/)?.[1]?.trim() || ''
          issuer = info.stdout.match(/Issuer:\s*(.+)/)?.[1]?.trim() || ''
          serial = info.stdout.match(/Serial Number[:\s]*\n?\s*([0-9a-fA-F: ]+)/)?.[1]?.trim() || ''
          notBefore = info.stdout.match(/Not Before\s*:\s*(.+)/)?.[1]?.trim() || ''
          notAfter = info.stdout.match(/Not After\s*:\s*(.+)/)?.[1]?.trim() || ''
        }
      } catch { /* openssl optional */ }

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(workspaceManager, database, input.sample_id, 'pe-sig', 'certificate', pem.slice(0, 32768), { extension: 'pem', mime: 'application/x-pem-file', sessionTag: input.session_tag })
        artifacts.push(artifact)
      }

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          has_certificate: true,
          subject: subject || undefined,
          issuer: issuer || undefined,
          serial: serial || undefined,
          not_before: notBefore || undefined,
          not_after: notAfter || undefined,
          certificate_pem: pem.slice(0, 4096),
          artifact,
          summary: subject
            ? `Certificate: ${subject}, issued by ${issuer}.`
            : 'Certificate extracted (PEM). Use openssl for detailed parsing.',
          recommended_next_tools: ['pe.signature.verify', 'artifact.read', 'sample.similarity'],
          next_actions: [
            'Search for other samples signed with the same certificate.',
            'Check certificate validity and revocation status.',
          ],
        },
        artifacts,
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    } finally {
      try { nodeFs.unlinkSync(tmpCert) } catch {}
    }
  }
}
