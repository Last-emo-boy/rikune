/**
 * sample.ingest tool implementation
 * Uploads and registers new samples to the system
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
 */

import { z } from 'zod'
import fs from 'fs'
import crypto from 'crypto'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { PolicyGuard } from '../policy-guard.js'
import { withLogging, logError, logWarning } from '../logger.js'

// ============================================================================
// Constants
// ============================================================================

const MAX_SAMPLE_SIZE = 500 * 1024 * 1024 // 500MB

// ============================================================================
// Input/Output Schemas
// ============================================================================

/**
 * Input schema for sample.ingest tool
 * Requirements: 1.1
 */
export const SampleIngestInputSchema = z
  .object({
    path: z
      .string()
      .trim()
      .min(1)
      .optional()
      .describe('Preferred for local files. Pass an absolute local file path when the MCP client can access the file system.'),
    bytes_b64: z
      .string()
      .trim()
      .min(1)
      .optional()
      .describe('Fallback only. Use Base64 file bytes when the MCP client cannot access the local file path. Ignored when `path` is provided.'),
    filename: z.string().optional().describe('Optional display/original filename'),
    source: z.string().optional().describe('Optional source tag, e.g. upload/email/sandbox'),
  })
  .superRefine((value, ctx) => {
    const hasPath = typeof value.path === 'string' && value.path.length > 0
    const hasBytes = typeof value.bytes_b64 === 'string' && value.bytes_b64.length > 0

    if (!hasPath && !hasBytes) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['path'],
        message: 'Provide either `path` (preferred for local files) or `bytes_b64` (fallback when the client cannot read the file path).',
      })
    }
  })
  .describe('Ingest a sample from a local file path or Base64 bytes. Prefer `path` whenever the MCP client can access the file directly.')

export type SampleIngestInput = z.infer<typeof SampleIngestInputSchema>

/**
 * Output schema for sample.ingest tool
 * Requirements: 1.5
 */
export const SampleIngestOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string(),
    size: z.number(),
    file_type: z.string().optional(),
    existed: z.boolean().optional(),
  }).optional(),
  errors: z.array(z.string()).optional(),
})

export type SampleIngestOutput = z.infer<typeof SampleIngestOutputSchema>

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool definition for sample.ingest
 */
export const sampleIngestToolDefinition: ToolDefinition = {
  name: 'sample.ingest',
  description:
    'Register a new sample from a local file path or Base64 bytes. Prefer `path` for local files; use `bytes_b64` only when the MCP client cannot read local disk.',
  inputSchema: SampleIngestInputSchema,
  outputSchema: SampleIngestOutputSchema,
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Compute SHA256 hash of data
 * Requirement: 1.1
 */
function computeSHA256(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex')
}

/**
 * Compute MD5 hash of data
 * Requirement: 1.1
 */
function computeMD5(data: Buffer): string {
  return crypto.createHash('md5').update(data).digest('hex')
}

/**
 * Detect file type from data
 * Basic implementation - can be enhanced with magic number detection
 */
function detectFileType(data: Buffer): string {
  // Check for PE signature (MZ header)
  if (data.length >= 2 && data[0] === 0x4D && data[1] === 0x5A) {
    return 'PE'
  }

  // Check for ELF signature
  if (data.length >= 4 && 
      data[0] === 0x7F && 
      data[1] === 0x45 && 
      data[2] === 0x4C && 
      data[3] === 0x46) {
    return 'ELF'
  }

  return 'unknown'
}

// ============================================================================
// Tool Handler
// ============================================================================

/**
 * Create sample.ingest tool handler
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
 */
export function createSampleIngestHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  policyGuard: PolicyGuard
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = args as SampleIngestInput

    return withLogging(
      {
        operation: 'sample.ingest',
        toolName: 'sample.ingest',
        source: input.source,
      },
      async () => {
        try {
          // 1. Read sample data
          let data: Buffer
          let originalFilename: string

          if (input.path) {
            // Read from file path
            if (!fs.existsSync(input.path)) {
              logWarning('File not found', { path: input.path })
              return {
                ok: false,
                errors: [`File not found: ${input.path}`],
              }
            }

            data = fs.readFileSync(input.path)
            // Extract just the filename, not the full path
            const pathParts = input.path.replace(/\\/g, '/').split('/')
            originalFilename = input.filename || pathParts[pathParts.length - 1] || 'sample.bin'
          } else if (input.bytes_b64) {
            // Decode from Base64
            // Validate Base64 format first
            const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/
            if (!base64Regex.test(input.bytes_b64)) {
              logWarning('Invalid Base64 encoding', { length: input.bytes_b64.length })
              return {
                ok: false,
                errors: ['Invalid Base64 encoding: contains invalid characters'],
              }
            }

            try {
              data = Buffer.from(input.bytes_b64, 'base64')
              // Verify the decoded data is not empty and makes sense
              if (data.length === 0 && input.bytes_b64.length > 0) {
                throw new Error('Base64 decoding resulted in empty buffer')
              }
            } catch (error) {
              logError(error as Error, { operation: 'base64_decode' })
              return {
                ok: false,
                errors: [`Invalid Base64 encoding: ${(error as Error).message}`],
              }
            }
            originalFilename = input.filename || 'sample.bin'
          } else {
            return {
              ok: false,
              errors: [
                'Missing input: provide `path` (preferred local file path) or `bytes_b64` (Base64 bytes fallback when the client cannot access the file path).',
              ],
            }
          }

          // 2. Check file size limit
          // Requirement: 1.3
          if (data.length > MAX_SAMPLE_SIZE) {
            logWarning('Sample size exceeds limit', {
              size: data.length,
              maxSize: MAX_SAMPLE_SIZE,
            })
            return {
              ok: false,
              errors: [
                `Sample size ${data.length} bytes exceeds maximum limit of ${MAX_SAMPLE_SIZE} bytes (500MB)`
              ],
            }
          }

          // 3. Compute hashes
          // Requirement: 1.1
          const sha256 = computeSHA256(data)
          const md5 = computeMD5(data)
          const sampleId = `sha256:${sha256}`

          // 4. Check if sample already exists
          // Requirement: 1.2
          const existingSample = database.findSampleBySha256(sha256)
          if (existingSample) {
            // Sample already exists, return existing sample_id
            await policyGuard.auditLog({
              timestamp: new Date().toISOString(),
              operation: 'sample.ingest',
              sampleId: existingSample.id,
              decision: 'allow',
              reason: 'Sample already exists (SHA256 match)',
              metadata: {
                size: data.length,
                source: input.source || 'upload',
                existed: true,
              },
            })

            return {
              ok: true,
              data: {
                sample_id: existingSample.id,
                size: existingSample.size,
                file_type: existingSample.file_type || undefined,
                existed: true,
              },
            }
          }

          // 5. Create workspace
          // Requirement: 1.4
          const workspace = await workspaceManager.createWorkspace(sampleId)

          // 6. Store sample file
          // Requirement: 1.4
          const samplePath = `${workspace.original}/${originalFilename}`
          fs.writeFileSync(samplePath, data)

          // Mark file as non-executable (security measure)
          // Requirement: 29.3
          try {
            fs.chmodSync(samplePath, 0o444) // Read-only
          } catch (error) {
            // Ignore chmod errors on Windows
            logWarning('Failed to set file permissions', {
              path: samplePath,
              error: (error as Error).message,
            })
          }

          // 7. Detect file type
          const fileType = detectFileType(data)

          // 8. Insert into database
          // Requirement: 1.5
          const sample = {
            id: sampleId,
            sha256,
            md5,
            size: data.length,
            file_type: fileType,
            created_at: new Date().toISOString(),
            source: input.source || 'upload',
          }

          try {
            database.insertSample(sample)
          } catch (error: any) {
            // Handle race condition: if another concurrent request already inserted this sample
            if (error.code === 'SQLITE_CONSTRAINT_UNIQUE' || error.message?.includes('UNIQUE constraint')) {
              // Sample was inserted by another concurrent request
              // Query it again and return
              const existingSample = database.findSampleBySha256(sha256)
              if (existingSample) {
                await policyGuard.auditLog({
                  timestamp: new Date().toISOString(),
                  operation: 'sample.ingest',
                  sampleId: existingSample.id,
                  decision: 'allow',
                  reason: 'Sample already exists (concurrent insert race condition)',
                  metadata: {
                    size: data.length,
                    source: input.source || 'upload',
                    existed: true,
                  },
                })

                return {
                  ok: true,
                  data: {
                    sample_id: existingSample.id,
                    size: existingSample.size,
                    file_type: existingSample.file_type || undefined,
                    existed: true,
                  },
                }
              }
            }
            // Re-throw if it's a different error
            throw error
          }

          // 9. Audit log
          // Requirement: 1.6
          await policyGuard.auditLog({
            timestamp: new Date().toISOString(),
            operation: 'sample.ingest',
            sampleId: sample.id,
            decision: 'allow',
            metadata: {
              size: data.length,
              source: sample.source,
              file_type: fileType,
            },
          })

          // 10. Return result
          return {
            ok: true,
            data: {
              sample_id: sampleId,
              size: data.length,
              file_type: fileType,
            },
          }
        } catch (error) {
          logError(error as Error, { operation: 'sample.ingest' })
          return {
            ok: false,
            errors: [(error as Error).message],
          }
        }
      }
    )
  }
}
