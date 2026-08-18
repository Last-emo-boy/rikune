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
      const { tools } = await registry.listTools()
      expect(tools.length).toBe(2)
      expect(tools.some((t) => t.name === 'sample_ingest')).toBe(true)
      expect(tools.some((t) => t.name === 'ghidra_analyze')).toBe(true)
    })

    test('should surface tool title when provided', async () => {
      const tool = makeTool('ghidra.analyze')
      tool.title = 'Ghidra Analyzer'
      registry.registerTool(tool, async () => ({ ok: true }))
      const { tools } = await registry.listTools()
      const t = tools.find((x) => x.name === 'ghidra_analyze')
      expect(t?.title).toBe('Ghidra Analyzer')
    })

    test('should omit title when not provided', async () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      const { tools } = await registry.listTools()
      const t = tools.find((x) => x.name === 'sample_ingest')
      expect(t?.title).toBeUndefined()
    })

    test('should append prerequisite hint for tools requiring sample_id', async () => {
      registry.registerTool(makeTool('ghidra.analyze', true), async () => ({ ok: true }))
      const { tools } = await registry.listTools()
      const t = tools.find((x) => x.name === 'ghidra_analyze')
      expect(t?.description).toContain('Prerequisite')
      expect(t?.description).toContain('workflow.run action=request_upload')
    })

    test('should not append prerequisite hint for sample entry tools', async () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      const { tools } = await registry.listTools()
      const t = tools.find((x) => x.name === 'sample_ingest')
      expect(t?.description).not.toContain('Prerequisite')
    })

    test('should filter by visible set', async () => {
      registry.registerTool(makeTool('sample.ingest'), async () => ({ ok: true }))
      registry.registerTool(makeTool('ghidra.analyze'), async () => ({ ok: true }))
      const { tools } = await registry.listTools(new Set(['sample.ingest']))
      expect(tools.length).toBe(1)
      expect(tools[0].name).toBe('sample_ingest')
    })

    test('should expose canonical core tools through transport names when visible', async () => {
      registry.registerTool(makeTool('plugin.list'), async () => ({ ok: true }))
      registry.registerTool(makeTool('system.config.validate'), async () => ({ ok: true }))

      const { tools } = await registry.listTools(new Set(['plugin.list', 'system.config.validate']))

      expect(tools.map((tool) => tool.name).sort()).toEqual([
        'plugin_list',
        'system_config_validate',
      ])
    })

    test('derives readOnlyHint from passiveByDefault runtime policy', async () => {
      const tool = makeTool('static.profile')
      tool.runtimePolicy = { passiveByDefault: true, noNetwork: true, noMutation: true, noLiveExecution: true }
      registry.registerTool(tool, async () => ({ ok: true }))
      const { tools } = await registry.listTools()
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
      const { tools } = await registry.listTools()
      const t = tools.find((x) => x.name === 'dynamic_patch')
      expect(t?.annotations).toEqual(expect.objectContaining({ destructiveHint: true }))
      expect(t?.annotations?.readOnlyHint).toBeUndefined()
    })

    test('derives openWorldHint when noNetwork is false', async () => {
      const tool = makeTool('network.fetch')
      tool.runtimePolicy = { passiveByDefault: true, noNetwork: false, noMutation: true, noLiveExecution: true }
      registry.registerTool(tool, async () => ({ ok: true }))
      const { tools } = await registry.listTools()
      const t = tools.find((x) => x.name === 'network_fetch')
      expect(t?.annotations).toEqual(expect.objectContaining({ openWorldHint: true }))
    })

    test('explicit annotations override derived hints', async () => {
      const tool = makeTool('custom.tool')
      tool.runtimePolicy = { passiveByDefault: true, noNetwork: true, noMutation: true, noLiveExecution: true }
      tool.annotations = { readOnlyHint: false, title: 'Custom Tool' }
      registry.registerTool(tool, async () => ({ ok: true }))
      const { tools } = await registry.listTools()
      const t = tools.find((x) => x.name === 'custom_tool')
      expect(t?.annotations).toEqual(expect.objectContaining({ title: 'Custom Tool', readOnlyHint: false, idempotentHint: true }))
    })

    test('tools without runtime policy have no derived annotations', async () => {
      registry.registerTool(makeTool('plain.tool'), async () => ({ ok: true }))
      const { tools } = await registry.listTools()
      const t = tools.find((x) => x.name === 'plain_tool')
      expect(t?.annotations).toBeUndefined()
    })

    test('returns all tools without nextCursor when cursor is omitted', async () => {
      for (let i = 0; i < 5; i++) {
        registry.registerTool(makeTool(`tool.${i}`), async () => ({ ok: true }))
      }
      const result = await registry.listTools()
      expect(result.tools.length).toBe(5)
      expect(result.nextCursor).toBeUndefined()
    })

    test('paginates tools with cursor and returns nextCursor', async () => {
      for (let i = 0; i < 250; i++) {
        registry.registerTool(makeTool(`tool.${String(i).padStart(3, '0')}`), async () => ({
          ok: true,
        }))
      }
      const page1 = await registry.listTools(null, undefined)
      expect(page1.tools.length).toBe(250)
      expect(page1.nextCursor).toBeUndefined()

      // First paginated page
      const pageA = await registry.listTools(null, MCPRegistry.encodeOffsetCursor(0))
      expect(pageA.tools.length).toBe(100)
      expect(pageA.tools[0].name).toBe('tool_000')
      expect(pageA.nextCursor).toBeDefined()

      // Second page
      const pageB = await registry.listTools(null, pageA.nextCursor!)
      expect(pageB.tools.length).toBe(100)
      expect(pageB.tools[0].name).toBe('tool_100')
      expect(pageB.nextCursor).toBeDefined()

      // Third (final) page
      const pageC = await registry.listTools(null, pageB.nextCursor!)
      expect(pageC.tools.length).toBe(50)
      expect(pageC.tools[0].name).toBe('tool_200')
      expect(pageC.nextCursor).toBeUndefined()
    })

    test('throws on invalid cursor', async () => {
      registry.registerTool(makeTool('tool.a'), async () => ({ ok: true }))
      await expect(registry.listTools(null, 'invalid-cursor')).rejects.toThrow(/Invalid tools\/list cursor/)
    })

    test('pagination respects visible set filtering', async () => {
      for (let i = 0; i < 5; i++) {
        registry.registerTool(makeTool(`tool.${i}`), async () => ({ ok: true }))
      }
      const visible = new Set(['tool.0', 'tool.1', 'tool.2'])
      const page = await registry.listTools(visible, MCPRegistry.encodeOffsetCursor(0))
      expect(page.tools.length).toBe(3)
      expect(page.nextCursor).toBeUndefined()
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

    test('should register and retrieve resource templates', () => {
      registry.registerResourceTemplate({
        uriTemplate: 'rikune://sample/{sample_id}/artifact/{artifact_id}',
        name: 'Sample Artifact',
        description: 'Parameterized artifact resource by sample and artifact ID',
        mimeType: 'application/json',
      })
      const templates = registry.getResourceTemplates()
      expect(templates).toHaveLength(1)
      expect(templates[0]).toEqual({
        uriTemplate: 'rikune://sample/{sample_id}/artifact/{artifact_id}',
        name: 'Sample Artifact',
        description: 'Parameterized artifact resource by sample and artifact ID',
        mimeType: 'application/json',
      })
    })

    test('should track resource subscriptions', () => {
      expect(registry.isSubscribedToResource('rikune://sample/abc')).toBe(false)
      registry.subscribeToResource('rikune://sample/abc')
      expect(registry.isSubscribedToResource('rikune://sample/abc')).toBe(true)
      expect(registry.getResourceSubscriptions()).toEqual(['rikune://sample/abc'])
      registry.unsubscribeFromResource('rikune://sample/abc')
      expect(registry.isSubscribedToResource('rikune://sample/abc')).toBe(false)
    })

    test('listResourceTemplates returns all templates without cursor', async () => {
      registry.registerResourceTemplate({
        uriTemplate: 'rikune://sample/{id}/artifact/{aid}',
        name: 'Artifact',
        description: 'd1',
      })
      const { resourceTemplates, nextCursor } = await registry.listResourceTemplates()
      expect(resourceTemplates).toHaveLength(1)
      expect(nextCursor).toBeUndefined()
    })

    test('listResourceTemplates paginates with cursor and sorts by uriTemplate', async () => {
      registry.registerResourceTemplate({ uriTemplate: 'rikune://zzz/{id}', name: 'Z' })
      registry.registerResourceTemplate({ uriTemplate: 'rikune://aaa/{id}', name: 'A' })
      registry.registerResourceTemplate({ uriTemplate: 'rikune://mmm/{id}', name: 'M' })

      const page1 = await registry.listResourceTemplates(MCPRegistry.encodeOffsetCursor(0))
      // pageSize = 100 so all fit on first page when starting from offset 0
      expect(page1.resourceTemplates.map((t) => t.uriTemplate)).toEqual([
        'rikune://aaa/{id}',
        'rikune://mmm/{id}',
        'rikune://zzz/{id}',
      ])
      expect(page1.nextCursor).toBeUndefined()

      // Register many templates to test multi-page pagination
      for (let i = 0; i < 105; i++) {
        registry.registerResourceTemplate({
          uriTemplate: `rikune://tpl/${String(i).padStart(3, '0')}/{id}`,
          name: `T${i}`,
        })
      }
      const bigPage1 = await registry.listResourceTemplates(MCPRegistry.encodeOffsetCursor(0))
      expect(bigPage1.resourceTemplates).toHaveLength(100)
      expect(bigPage1.nextCursor).toBeDefined()

      const bigPage2 = await registry.listResourceTemplates(bigPage1.nextCursor!)
      expect(bigPage2.resourceTemplates.length).toBeGreaterThan(0)
      expect(bigPage2.nextCursor).toBeUndefined()

      // Total across pages should equal all registered templates (3 + 105 = 108)
      expect(bigPage1.resourceTemplates.length + bigPage2.resourceTemplates.length).toBe(108)
    })

    test('listResourceTemplates throws on invalid cursor', async () => {
      await expect(registry.listResourceTemplates('!!!invalid!!!')).rejects.toThrow(
        /resources\/templates\/list cursor/
      )
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
