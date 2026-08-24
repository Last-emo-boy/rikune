import { z } from 'zod'
import type { ToolDefinition, ToolResult } from '../types.js'
import {
  SampleConfirmationMismatchError,
  type SampleDeletionService,
} from '../sample/sample-deletion.js'
import { SampleOperationBusyError } from '../sample/sample-operation-gate.js'

const TOOL_NAME = 'sample.delete'
const CanonicalSampleIdSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/)
const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/)

const ReclaimedSchema = z
  .object({
    files: z.number().int().nonnegative(),
    bytes: z.number().int().nonnegative(),
    db_rows: z.number().int().nonnegative(),
    kb_rows: z.number().int().nonnegative(),
    cache_entries: z.number().int().nonnegative(),
  })
  .strict()

const BlockerSchema = z
  .object({
    kind: z.enum([
      'job',
      'analysis_run',
      'analysis_stage',
      'debug_session',
      'ingest_journal',
      'context_lease',
      'operation_lease',
    ]),
    state: z.string().min(1).max(64),
    count: z.number().int().positive(),
    retry_after_ms: z.number().int().nonnegative(),
  })
  .strict()

export const sampleDeleteInputSchema = z
  .object({
    sample_id: CanonicalSampleIdSchema,
    confirm_sha256: Sha256Schema,
    reason: z.string().min(1).max(500).optional(),
  })
  .strict()

const SampleDeleteSuccessSchema = z
  .object({
    ok: z.literal(true),
    data: z
      .object({
        sample_id: CanonicalSampleIdSchema,
        outcome: z.enum(['deleted', 'already_absent']),
        deletion_id: z.string().uuid().nullable(),
        reclaimed: ReclaimedSchema,
        completed_at: z.string().datetime({ offset: true }),
      })
      .strict(),
  })
  .strict()

const SampleDeleteErrorSchema = z
  .object({
    ok: z.literal(false),
    error: z
      .object({
        code: z.enum(['E_SAMPLE_BUSY', 'E_SAMPLE_CONFIRMATION_MISMATCH', 'E_SAMPLE_DELETE_FAILED']),
        retryable: z.boolean(),
        blockers: z.array(BlockerSchema).max(16),
      })
      .strict(),
  })
  .strict()

export const sampleDeleteOutputSchema = z.union([
  SampleDeleteSuccessSchema,
  SampleDeleteErrorSchema,
])

export const sampleDeleteToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  title: 'Delete sample',
  description:
    'Permanently and idempotently delete one sample and all of its persisted analysis state. ' +
    'The caller must repeat the exact lowercase SHA-256 digest as confirmation. The tool is ' +
    'hidden by default and must be activated explicitly through workflow.search.',
  inputSchema: sampleDeleteInputSchema,
  outputSchema: sampleDeleteOutputSchema,
  annotations: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: false,
  },
  aspects: {
    execution: ['orchestration'],
    capabilities: ['sample-lifecycle', 'crash-safe-deletion'],
    safety: ['destructive', 'confirmation-required', 'journaled', 'bounded-output'],
  },
  // Deletion establishes the exclusive lease itself; acquiring the normal
  // shared wrapper before the handler would deadlock against that upgrade.
  // The reference remains explicit so validation and audit retain the exact
  // sample touched by this destructive operation.
  sampleReferences: { direct: ['sample_id'] },
  sampleLeaseMode: 'exclusive-managed',
}

function result(
  structuredContent: z.infer<typeof sampleDeleteOutputSchema>,
  isError = false
): ToolResult {
  return {
    content: [],
    structuredContent,
    ...(isError ? { isError: true } : {}),
  }
}

export function createSampleDeleteHandler(service: SampleDeletionService) {
  return async (args: unknown): Promise<ToolResult> => {
    const input = sampleDeleteInputSchema.parse(args)
    try {
      const deleted = await service.deleteSample({
        sampleId: input.sample_id,
        confirmSha256: input.confirm_sha256,
        reason: input.reason,
      })
      return result({ ok: true, data: deleted })
    } catch (error) {
      if (error instanceof SampleConfirmationMismatchError) {
        return result(
          {
            ok: false,
            error: {
              code: 'E_SAMPLE_CONFIRMATION_MISMATCH',
              retryable: false,
              blockers: [],
            },
          },
          true
        )
      }
      if (error instanceof SampleOperationBusyError) {
        return result(
          {
            ok: false,
            error: {
              code: 'E_SAMPLE_BUSY',
              retryable: true,
              blockers: error.blockers.slice(0, 16),
            },
          },
          true
        )
      }
      return result(
        {
          ok: false,
          error: {
            code: 'E_SAMPLE_DELETE_FAILED',
            retryable: true,
            blockers: [],
          },
        },
        true
      )
    }
  }
}
