/**
 * Contract audit for built-in plugins.
 *
 * This test keeps the SDK contract enforceable for hand-written register()
 * plugins without requiring every plugin to use declarative tool definitions.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { validatePlugin, validateTool } from '../../../../src/plugins/sdk.js'
import { discoverBuiltInPlugins } from '../../../../src/core/plugin-system/discovery.js'
import { zodToJsonSchema } from '../../../../src/core/zod-schema-converter.js'
import { listRuntimeBackendCapabilities } from '../../../../packages/runtime-node/src/executor.js'
import { getRuntimeContractSupportMismatches } from '@rikune/shared'
import {
  getLocalDynamicToolPolicy,
  listExplicitLocalDynamicTools,
} from '../../../../src/runtime-client/dynamic-tool-policy.js'
import { listRuntimeDelegatedToolContracts } from '../../../../src/runtime-client/runtime-tool-support.js'

const logger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
}

function runtimeCapabilityKey(value: { type?: string; handler?: string }): string {
  return `${value.type ?? 'unknown'}/${value.handler ?? 'unknown'}`
}

function createDeps() {
  const deps: any = {
    workspaceManager: {},
    database: {},
    config: {
      runtime: {
        mode: 'remote-sandbox',
        hostAgentEndpoint: 'http://127.0.0.1:18082',
        apiKey: 'test-api-key',
      },
      workers: {
        ghidra: {},
        static: {},
        sandbox: {},
        frida: {},
      },
    },
    cacheManager: {},
    jobQueue: {},
    storageManager: {},
    policyGuard: {},
    sampleOperationGate: {},
    server: {},
    logger,
    resolvePackagePath: (...segments: string[]) => segments.join('/'),
    generateCacheKey: () => 'test-cache-key',
    resolvePrimarySamplePath: async (_wm: unknown, sampleId: string) => ({
      samplePath: `samples/${sampleId}.bin`,
    }),
    persistStaticAnalysisJsonArtifact: async () => ({ path: 'artifact.json' }),
    DecompilerWorker: class {},
    getGhidraDiagnostics: () => ({}),
    normalizeGhidraError: (err: unknown) => err,
    findBestGhidraAnalysis: async () => null,
    getGhidraReadiness: () => ({ ready: false }),
    parseGhidraAnalysisMetadata: () => ({}),
    buildPollingGuidance: () => ({}),
  }

  deps.services = {
    workspace: {
      manager: deps.workspaceManager,
      database: deps.database,
      storage: deps.storageManager,
      resolvePrimarySamplePath: deps.resolvePrimarySamplePath,
      persistStaticAnalysisJsonArtifact: deps.persistStaticAnalysisJsonArtifact,
    },
    platform: {
      cacheManager: deps.cacheManager,
      jobQueue: deps.jobQueue,
      logger: deps.logger,
      policyGuard: deps.policyGuard,
      resolvePackagePath: deps.resolvePackagePath,
      generateCacheKey: deps.generateCacheKey,
      server: deps.server,
    },
    runtime: {
      client: {},
      mode: 'remote-sandbox',
      sandboxDir: null,
      config: deps.config.runtime,
    },
    ghidra: {
      DecompilerWorker: deps.DecompilerWorker,
      getDiagnostics: deps.getGhidraDiagnostics,
      normalizeError: deps.normalizeGhidraError,
      findBestAnalysis: deps.findBestGhidraAnalysis,
      getReadiness: deps.getGhidraReadiness,
      parseAnalysisMetadata: deps.parseGhidraAnalysisMetadata,
      buildPollingGuidance: deps.buildPollingGuidance,
    },
  }

  return deps
}

describe('built-in plugin SDK contract', () => {
  test('all built-in plugins and registered tools satisfy SDK validation', async () => {
    const plugins = await discoverBuiltInPlugins()
    expect(plugins.length).toBeGreaterThan(50)

    const pluginErrors: string[] = []
    const toolErrors: string[] = []
    const schemaErrors: string[] = []
    const resourceErrors: string[] = []
    const runtimeErrors: string[] = []
    const localDynamicPolicyErrors: string[] = []
    const toolsByName = new Map<string, string[]>()
    const toolDefinitionsByName = new Map<string, any>()
    const dynamicToolsWithoutRuntime = new Set<string>()
    let runtimeToolCount = 0
    const deps = createDeps()
    const pluginsRoot = path.join(process.cwd(), 'src', 'plugins')
    const resourceKinds = ['workers', 'scripts', 'data'] as const
    const runtimeCapabilities = listRuntimeBackendCapabilities()

    for (const plugin of plugins) {
      const pluginValidation = validatePlugin(plugin)
      if (!pluginValidation.ok) {
        pluginErrors.push(`${plugin.id}: ${pluginValidation.errors.join('; ')}`)
        continue
      }

      const pluginDir = path.join(pluginsRoot, plugin.id)
      if (fs.existsSync(pluginDir)) {
        for (const kind of resourceKinds) {
          const conventionalDir = path.join(pluginDir, kind)
          if (fs.existsSync(conventionalDir) && fs.statSync(conventionalDir).isDirectory()) {
            const declared = plugin.resources?.[kind]
            if (!declared) {
              resourceErrors.push(`${plugin.id}: missing resources.${kind} declaration`)
              continue
            }

            const declaredDir = path.join(pluginDir, declared)
            if (!fs.existsSync(declaredDir) || !fs.statSync(declaredDir).isDirectory()) {
              resourceErrors.push(
                `${plugin.id}: resources.${kind} points to missing directory ${declared}`
              )
            }
          }
        }
      }

      const registeredTools: string[] = []
      const server = {
        registerTool(definition: any, handler: unknown) {
          registeredTools.push(definition?.name)
          const owners = toolsByName.get(definition?.name) ?? []
          owners.push(plugin.id)
          toolsByName.set(definition?.name, owners)
          toolDefinitionsByName.set(definition?.name, definition)

          const toolValidation = validateTool(definition)
          if (!toolValidation.ok) {
            toolErrors.push(`${plugin.id}:${definition?.name}: ${toolValidation.errors.join('; ')}`)
          }
          if (!definition?.outputSchema) {
            schemaErrors.push(`${plugin.id}:${definition?.name}: missing outputSchema`)
          } else {
            try {
              const inputSchema = zodToJsonSchema(definition.inputSchema)
              const outputSchema = zodToJsonSchema(definition.outputSchema)
              if (inputSchema.type !== 'object') {
                schemaErrors.push(
                  `${plugin.id}:${definition?.name}: inputSchema root must be object`
                )
              }
              if (outputSchema.type !== 'object') {
                schemaErrors.push(
                  `${plugin.id}:${definition?.name}: outputSchema root must be object`
                )
              }
            } catch (error) {
              schemaErrors.push(
                `${plugin.id}:${definition?.name}: schema conversion failed: ${
                  error instanceof Error ? error.message : String(error)
                }`
              )
            }
          }
          if (typeof handler !== 'function') {
            toolErrors.push(`${plugin.id}:${definition?.name}: handler must be a function`)
          }
          if (definition?.runtime) {
            runtimeToolCount += 1
            const key = runtimeCapabilityKey(definition.runtime)
            const supported = runtimeCapabilities.some(
              (capability) =>
                getRuntimeContractSupportMismatches(capability, definition.runtime).length === 0
            )
            if (!supported) {
              runtimeErrors.push(
                `${plugin.id}:${definition?.name}: unsupported runtime contract ${key}`
              )
            }
          } else if (plugin.executionDomain === 'dynamic') {
            dynamicToolsWithoutRuntime.add(definition?.name)
            if (!getLocalDynamicToolPolicy(definition?.name)) {
              localDynamicPolicyErrors.push(
                `${plugin.id}:${definition?.name}: dynamic-domain tool must declare runtime or explicit local policy`
              )
            }
          }
        },
        unregisterTool() {},
      }
      const ctx = {
        pluginId: plugin.id,
        logger,
        getConfig: () => undefined,
        getRequiredConfig: (name: string) => {
          throw new Error(`Missing required test config: ${name}`)
        },
        dataDir: `data/plugins/${plugin.id}`,
      }

      const returned = plugin.register?.(server, deps, ctx)
      if (Array.isArray(returned)) {
        const missing = returned.filter((name) => !registeredTools.includes(name))
        if (missing.length > 0) {
          pluginErrors.push(
            `${plugin.id}: register() returned unregistered tools: ${missing.join(', ')}`
          )
        }
      }
    }

    const duplicateTools = [...toolsByName.entries()]
      .filter(([name, owners]) => Boolean(name) && owners.length > 1)
      .map(([name, owners]) => `${name}: ${owners.join(', ')}`)
    const staleLocalDynamicPolicies = listExplicitLocalDynamicTools()
      .map((entry) => entry.name)
      .filter((name) => !dynamicToolsWithoutRuntime.has(name))
      .map((name) => `${name}: stale explicit local policy`)
    const runtimeStatusToolContracts = listRuntimeDelegatedToolContracts()
    const runtimeStatusToolContractsByName = new Map(
      runtimeStatusToolContracts.map((entry) => [entry.tool_name, entry.runtime_contract])
    )
    const missingRuntimeStatusToolContracts = [...toolDefinitionsByName.entries()]
      .filter(([, definition]) => Boolean(definition?.runtime))
      .filter(([name]) => !runtimeStatusToolContractsByName.has(name))
      .map(([name]) => `${name}: missing dynamic.runtime.status tool support contract`)
    const mismatchedRuntimeStatusToolContracts = [...toolDefinitionsByName.entries()]
      .filter(([, definition]) => Boolean(definition?.runtime))
      .filter(([name, definition]) => {
        const statusContract = runtimeStatusToolContractsByName.get(name)
        return (
          statusContract &&
          (getRuntimeContractSupportMismatches(statusContract, definition.runtime).length > 0 ||
            getRuntimeContractSupportMismatches(definition.runtime, statusContract).length > 0)
        )
      })
      .map(
        ([name, definition]) =>
          `${name}: dynamic.runtime.status contract ${
            runtimeStatusToolContractsByName.get(name)
              ? runtimeCapabilityKey(runtimeStatusToolContractsByName.get(name)!)
              : 'missing'
          } does not match tool runtime ${runtimeCapabilityKey(definition.runtime)}`
      )
    const staleRuntimeStatusToolContracts = runtimeStatusToolContracts
      .map((entry) => entry.tool_name)
      .filter((name) => !toolsByName.has(name))
      .map((name) => `${name}: stale dynamic.runtime.status tool support contract`)

    expect(pluginErrors).toEqual([])
    expect(toolErrors).toEqual([])
    expect(schemaErrors).toEqual([])
    expect(resourceErrors).toEqual([])
    expect(runtimeErrors).toEqual([])
    expect(localDynamicPolicyErrors).toEqual([])
    expect(staleLocalDynamicPolicies).toEqual([])
    expect(missingRuntimeStatusToolContracts).toEqual([])
    expect(mismatchedRuntimeStatusToolContracts).toEqual([])
    expect(staleRuntimeStatusToolContracts).toEqual([])
    expect(duplicateTools).toEqual([])
    expect(runtimeToolCount).toBeGreaterThan(20)
    expect(toolsByName.size).toBeGreaterThan(200)
  })
})
