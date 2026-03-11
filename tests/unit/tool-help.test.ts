import { describe, test, expect } from '@jest/globals'
import { z } from 'zod'
import type { ToolDefinition } from '../../src/types.js'
import { createToolHelpHandler } from '../../src/tools/tool-help.js'

describe('tool.help tool', () => {
  test('should summarize input and output schemas with enum/default metadata', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'sandbox.execute',
        description: 'Execute sandbox mode',
        inputSchema: z.object({
          sample_id: z.string().describe('Target sample'),
          mode: z
            .enum(['safe_simulation', 'memory_guided', 'speakeasy'])
            .default('safe_simulation')
            .describe('Dynamic backend mode'),
          network: z
            .enum(['block', 'simulate'])
            .optional()
            .describe('Network policy'),
        }),
        outputSchema: z.object({
          ok: z.boolean(),
          data: z.object({
            executed: z.boolean().optional(),
          }),
        }),
      },
      {
        name: 'workflow.reconstruct',
        description: 'Reconstruct with separate runtime and semantic scopes',
        inputSchema: z.object({
          sample_id: z.string(),
          evidence_scope: z.enum(['all', 'latest', 'session']).default('all'),
          evidence_session_tag: z.string().optional(),
          semantic_scope: z.enum(['all', 'latest', 'session']).default('all'),
          semantic_session_tag: z.string().optional(),
          session_tag: z.string().optional(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'sandbox.execute',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.count).toBe(1)
    expect(data.tools[0].name).toBe('sandbox.execute')
    expect(data.tools[0].input.field_count).toBeGreaterThan(0)

    const modeField = data.tools[0].input.fields.find((item: any) => item.path === 'mode')
    expect(modeField.type).toBe('enum')
    expect(modeField.required).toBe(false)
    expect(modeField.description).toContain('Dynamic backend mode')
    expect(modeField.default_value).toBe('safe_simulation')
    expect(modeField.enum_values).toEqual(['safe_simulation', 'memory_guided', 'speakeasy'])

    const networkField = data.tools[0].input.fields.find((item: any) => item.path === 'network')
    expect(networkField.required).toBe(false)
    expect(networkField.enum_values).toEqual(['block', 'simulate'])

    const outputField = data.tools[0].output.fields.find((item: any) => item.path === 'data.executed')
    expect(outputField.type).toBe('boolean')
    expect(outputField.required).toBe(false)
  })

  test('should include scope/session usage hints for workflow tools', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'workflow.reconstruct',
        description: 'Reconstruct with separate runtime and semantic scopes',
        inputSchema: z.object({
          sample_id: z.string(),
          evidence_scope: z.enum(['all', 'latest', 'session']).default('all'),
          evidence_session_tag: z.string().optional(),
          semantic_scope: z.enum(['all', 'latest', 'session']).default('all'),
          semantic_session_tag: z.string().optional(),
          session_tag: z.string().optional(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'workflow.reconstruct',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('runtime evidence scope'))).toBe(true)
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('naming/explanation artifacts'))).toBe(true)

    const evidenceScopeField = data.tools[0].input.fields.find((item: any) => item.path === 'evidence_scope')
    const semanticScopeField = data.tools[0].input.fields.find((item: any) => item.path === 'semantic_scope')
    const sessionTagField = data.tools[0].input.fields.find((item: any) => item.path === 'session_tag')

    expect(evidenceScopeField.help_hint).toContain('runtime evidence')
    expect(semanticScopeField.help_hint).toContain('semantic')
    expect(sessionTagField.help_hint).toContain('newly created artifacts')
  })

  test('should return not found for unknown tool names', async () => {
    const handler = createToolHelpHandler(() => [])
    const result = await handler({
      tool_name: 'missing.tool',
    })

    expect(result.ok).toBe(false)
    expect(result.errors).toContain('Tool not found: missing.tool')
  })

  test('should explain that sample.ingest prefers path over bytes_b64', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'sample.ingest',
        description:
          'Register a new sample from a local file path or Base64 bytes. Prefer path for local files.',
        inputSchema: z.object({
          path: z.string().optional().describe('Preferred local file path'),
          bytes_b64: z.string().optional().describe('Fallback Base64 bytes'),
          filename: z.string().optional(),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({
      tool_name: 'sample.ingest',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.tools[0].usage_notes.some((item: string) => item.includes('Prefer path'))).toBe(true)

    const pathField = data.tools[0].input.fields.find((item: any) => item.path === 'path')
    const bytesField = data.tools[0].input.fields.find((item: any) => item.path === 'bytes_b64')
    const filenameField = data.tools[0].input.fields.find((item: any) => item.path === 'filename')

    expect(pathField.help_hint).toContain('absolute path')
    expect(bytesField.help_hint).toContain('Fallback only')
    expect(filenameField.help_hint).toContain('bytes_b64')
  })
})
