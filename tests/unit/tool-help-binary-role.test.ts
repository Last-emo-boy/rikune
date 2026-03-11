import { describe, test, expect } from '@jest/globals'
import { z } from 'zod'
import type { ToolDefinition } from '../../src/types.js'
import { createToolHelpHandler } from '../../src/tools/tool-help.js'

describe('tool.help binary role guidance', () => {
  test('should explain binary.role.profile usage and field hints', async () => {
    const definitions: ToolDefinition[] = [
      {
        name: 'binary.role.profile',
        description: 'Summarize Windows PE role, export surface, and COM/service/plugin indicators.',
        inputSchema: z.object({
          sample_id: z.string(),
          max_exports: z.number().default(12),
          max_strings: z.number().default(120),
        }),
      },
    ]

    const handler = createToolHelpHandler(() => definitions)
    const result = await handler({ tool_name: 'binary.role.profile' })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(
      data.tools[0].usage_notes.some((item: string) =>
        item.includes('universal EXE/DLL/driver/COM/plugin role summary')
      )
    ).toBe(true)

    const maxExportsField = data.tools[0].input.fields.find((item: any) => item.path === 'max_exports')
    const maxStringsField = data.tools[0].input.fields.find((item: any) => item.path === 'max_strings')

    expect(maxExportsField.help_hint).toContain('exports/forwarders')
    expect(maxStringsField.help_hint).toContain('COM/service/plugin heuristics')
  })
})
