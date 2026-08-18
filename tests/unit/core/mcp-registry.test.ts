/**
 * Unit tests for core/mcp-registry.ts
 */

import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import { z } from 'zod'
import { MCPRegistry } from '../../../src/core/mcp-registry.js'
import type { ToolDefinition, PromptDefinition } from '../../../src/types.js'
import pino from 'pino'

describe('MCPRegistry', () => {
  let registry: MCPRegistry
  const logger = pino({ level: 'silent' })

  beforeEach(() => {
    registry = new MCPRegistry(logger)
  })

  function makeTool(name: string, requiresSample = false): ToolDefinition {
    return {
      name,
      description: `Tool ${name}`,
      inputSchema: requiresSample
        ? z.object({ sample_id: z.string() })
        : z.object({ input: z.string().optional() }),
    } as ToolDefinition
  }

  describe('registerTool / unregisterTool', () => {
    test('should register a tool and resolve canonical to transport name', () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      expect(registry.resolveToolName('sample.ingest')).toBe('sample_ingest')
      expect(registry.getToolDefinition('sample.ingest')?.name).toBe('sample.ingest')
    })

    test('should unregister a tool by canonical name', () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      registry.unregisterTool('sample.ingest')
      expect(registry.resolveToolName('sample.ingest')).toBeUndefined()
      expect(registry.getHandler('sample_ingest')).toBeUndefined()
    })

    test('should throw on tool name collision for different canonical names mapping to same transport name', () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      expect(() => {
        registry.registerTool(makeTool('sample_ingest'), async () => ({ ok: true }))
      }).toThrow(/collision/)
    })

    test('should reject exact duplicate names without replacing the original handler', async () => {
      const originalHandler = async () => ({ ok: true, data: { source: 'original' } })
      registry.registerTool(makeTool('sample.ingest'), originalHandler)

      expect(() => {
        registry.registerTool(makeTool('sample.ingest'), async () => ({
          ok: true,
          data: { source: 'replacement' },
        }))
      }).toThrow(/already registered/)

      expect(registry.getHandler('sample_ingest')).toBe(originalHandler)
      expect(registry.getToolDefinitions()).toHaveLength(1)
    })
  })

  describe('listTools', () => {
    test('should list registered tools with transport names', async () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      registry.registerTool(makeTool('ghidra.analyze', true), async () => ({ ok: true }))
      const tools = await registry.listTools()
      expect(tools.length).toBe(2)
      expect(tools.some((t) => t.name === 'sample_ingest')).toBe(true)
      expect(tools.some((t) => t.name === 'ghidra_analyze')).toBe(true)
    })

    test('should append prerequisite hint for tools requiring sample_id', async () => {
      registry.registerTool(makeTool('ghidra.analyze', true), async () => ({ ok: true }))
      const tools = await registry.listTools()
      const t = tools.find((x) => x.name === 'ghidra_analyze')
      expect(t?.description).toContain('Prerequisite')
      expect(t?.description).toContain('workflow.run action=request_upload')
    })

    test('should not append prerequisite hint for sample entry tools', async () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      const tools = await registry.listTools()
      const t = tools.find((x) => x.name === 'sample_ingest')
      expect(t?.description).not.toContain('Prerequisite')
    })

    test('should filter by visible set', async () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      registry.registerTool(makeTool('ghidra.analyze'), async () => ({ ok: true }))
      const tools = await registry.listTools(new Set(['sample.ingest']))
      expect(tools.length).toBe(1)
      expect(tools[0].name).toBe('sample_ingest')
    })

    test('should expose canonical core tools through transport names when visible', async () => {
      registry.registerTool(makeTool('plugin.list'), async () => ({ ok: true }))
      registry.registerTool(makeTool('system.config.validate'), async () => ({ ok: true }))

      const tools = await registry.listTools(new Set(['plugin.list', 'system.config.validate']))

      expect(tools.map((tool) => tool.name).sort()).toEqual([
        'plugin_list',
        'system_config_validate',
      ])
    })

    test('derives readOnlyHint from passiveByDefault runtime policy', async () => {
      const tool = makeTool('static.profile')
      tool.runtimePolicy = { passiveByDefault: true, noNetwork: true, noMutation: true, noLiveExecution: true }
      registry.registerTool(tool, async () => ({ ok: true }))
      const tools = await registry.listTools()
      const t = tools.find((x) => x.name === 'static_profile')
      expect(t?.annotations).toEqual(
        expect.objectContaining({ readOnlyHint: true, idempotentHint: true })
      )
      expect(t?.annotations?.destructiveHint).toBeUndefined()
    })

    test('derives destructiveHint when noMutation is false', async () => {
      const tool = makeTool('dynamic.patch')
      tool.runtimePolicy = { passiveByDefault: false, noNetwork: true, noMutation: false, noLiveExecution: false }
      registry.registerTool(tool, async () => ({ ok: true }))
      const tools = await registry.listTools()
      const t = tools.find((x) => x.name === 'dynamic_patch')
      expect(t?.annotations).toEqual(expect.objectContaining({ destructiveHint: true }))
      expect(t?.annotations?.readOnlyHint).toBeUndefined()
    })

    test('derives openWorldHint when noNetwork is false', async () => {
      const tool = makeTool('network.fetch')
      tool.runtimePolicy = { passiveByDefault: true, noNetwork: false, noMutation: true, noLiveExecution: true }
      registry.registerTool(tool, async () => ({ ok: true }))
      const tools = await registry.listTools()
      const t = tools.find((x) => x.name === 'network_fetch')
      expect(t?.annotations).toEqual(expect.objectContaining({ openWorldHint: true }))
    })

    test('explicit annotations override derived hints', async () => {
      const tool = makeTool('custom.tool')
      tool.runtimePolicy = { passiveByDefault: true, noNetwork: true, noMutation: true, noLiveExecution: true }
      tool.annotations = { readOnlyHint: false, title: 'Custom Tool' }
      registry.registerTool(tool, async () => ({ ok: true }))
      const tools = await registry.listTools()
      const t = tools.find((x) => x.name === 'custom_tool')
      expect(t?.annotations).toEqual(expect.objectContaining({ title: 'Custom Tool', readOnlyHint: false, idempotentHint: true }))
    })

    test('tools without runtime policy have no derived annotations', async () => {
      registry.registerTool(makeTool('plain.tool'), async () => ({ ok: true }))
      const tools = await registry.listTools()
      const t = tools.find((x) => x.name === 'plain_tool')
      expect(t?.annotations).toBeUndefined()
    })
  })

  describe('getToolDefinitions / getToolDefinition', () => {
    test('should return all canonical definitions', () => {
      registry.registerTool(makeTool('a.b'), async () => ({ ok: true }))
      registry.registerTool(makeTool('c.d'), async () => ({ ok: true }))
      expect(registry.getToolDefinitions().length).toBe(2)
    })

    test('should return undefined for unknown tool', () => {
      expect(registry.getToolDefinition('unknown.tool')).toBeUndefined()
    })
  })

  describe('prompts', () => {
    const prompt: PromptDefinition = {
      name: 'test.prompt',
      title: 'Test',
      description: 'A test prompt',
      arguments: [{ name: 'topic', description: 'Topic', required: true }],
    }

    test('should register and get prompt', () => {
      registry.registerPrompt(prompt, async (args) => ({ messages: [] }))
      expect(registry.getPromptDefinition('test.prompt')).toBeDefined()
    })

    test('should throw for missing prompt', async () => {
      await expect(registry.getPrompt('missing', {})).rejects.toThrow(/Prompt not found/)
    })

    test('should throw for missing required prompt argument', async () => {
      registry.registerPrompt(prompt, async (args) => ({ messages: [] }))
      await expect(registry.getPrompt('test.prompt', {})).rejects.toThrow(
        /Missing required prompt argument/
      )
    })
  })

  describe('resources', () => {
    test('should register and retrieve resource', async () => {
      const handler = async () => ({ uri: 'test://resource', text: 'hello' })
      registry.registerResource({ uri: 'test://resource', name: 'Test' }, handler)
      expect(registry.getResourceHandler('test://resource')).toBe(handler)
      expect(registry.getResources()).toHaveLength(1)
    })
  })

  describe('getToolNameMappings', () => {
    test('should return canonical-to-transport mappings', () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      const mappings = registry.getToolNameMappings()
      expect(mappings).toContainEqual(['sample.ingest', 'sample_ingest'])
    })
  })
})
