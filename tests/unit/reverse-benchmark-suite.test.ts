import fs from 'fs'
import path from 'path'
import { describe, expect, test } from '@jest/globals'
import { createToolsDiscoverHandler } from '../../src/tools/tools-discover.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import {
  evaluateReverseBenchmarkDiscoverCase,
  selectReverseBenchmarkCases,
  summarizeReverseBenchmarkResults,
  type ReverseBenchmarkCase,
  type ReverseBenchmarkManifest,
} from '../../src/benchmarks/reverse-benchmark.js'
import type { Plugin } from '../../src/plugins/sdk.js'

const manifestPath = path.join(
  process.cwd(),
  'tests',
  'fixtures',
  'reverse-benchmark.manifest.json'
)

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function tool(
  name: string,
  aspects: Record<string, string[]>,
  extra: Partial<Plugin['tools'][number]['definition']> = {}
): Plugin['tools'][number] {
  return {
    definition: {
      name,
      description: `${name} benchmark fixture tool`,
      inputSchema: {},
      aspects,
      ...extra,
    },
    handler: async () => ({ ok: true }),
  }
}

function profileGatedWorkerBackend(backendName: string, dockerFeature: string) {
  return {
    version: 'backend-worker.v1' as const,
    backendName,
    backendKind: 'external' as const,
    adapter: `benchmark.${dockerFeature}`,
    availability: 'optional' as const,
    supportedModes: ['external'],
    defaultMode: 'external',
    policy: {
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: [`Enable ${dockerFeature} backend profile for benchmark validation.`],
    },
    packaging: {
      installRoute: 'profile-gated' as const,
      installProfile: 'optional' as const,
      dockerFeature,
      notes: ['Not installed or started by default benchmark tests.'],
    },
  }
}

function runtimeWorkerBackend() {
  return {
    version: 'backend-worker.v1' as const,
    backendName: 'BenchmarkRuntimeSandbox',
    backendKind: 'delegated-runtime' as const,
    adapter: 'benchmark.runtime.sandbox',
    availability: 'optional' as const,
    supportedModes: ['delegated-runtime'],
    defaultMode: 'delegated-runtime',
    policy: {
      passiveByDefault: true,
      requiresUserOptIn: true,
      requiresIsolation: true,
      noNetwork: true,
      noMutation: true,
    },
    readiness: {
      doesNotStartBackend: true,
      setupActions: ['Enable an isolated runtime profile before dynamic benchmark validation.'],
    },
    packaging: {
      installRoute: 'profile-gated' as const,
      installProfile: 'runtime' as const,
      dockerFeature: 'runtime-sandbox',
      notes: ['Runtime benchmark paths are opt-in and never executed by default CI.'],
    },
  }
}

function benchmarkPlugins(): Plugin[] {
  return [
    {
      id: 'benchmark-pe-static',
      name: 'Benchmark PE Static',
      description: 'Metadata-only PE structure and import recovery benchmark fixture',
      aspects: {
        formats: ['pe'],
        platforms: ['windows'],
        execution: ['static'],
        capabilities: ['imports', 'structure'],
        evidence: ['imports', 'structure'],
      },
      surfaceRules: { tier: 1, category: 'static-analysis', activateOn: { fileTypes: ['pe'] } },
      tools: [
        tool('pe.structure.analyze', {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['static'],
          evidence: ['structure'],
        }),
        tool('pe.imports.extract', {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['static'],
          evidence: ['imports'],
        }),
      ],
    },
    {
      id: 'benchmark-strings',
      name: 'Benchmark Strings',
      description: 'String extraction and decoder routing benchmark fixture',
      aspects: {
        formats: ['pe', 'pe-clr'],
        platforms: ['windows'],
        execution: ['static'],
        capabilities: ['string-recovery', 'decoder-routing'],
        evidence: ['strings'],
      },
      surfaceRules: { tier: 1, category: 'static-analysis', activateOn: { fileTypes: ['pe'] } },
      tools: [
        tool('strings.extract', {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['static'],
          evidence: ['strings'],
        }),
        tool('strings.floss.decode', {
          formats: ['pe-clr', 'dotnet', 'pe'],
          platforms: ['windows', 'dotnet'],
          execution: ['static'],
          evidence: ['strings'],
        }),
      ],
    },
    {
      id: 'benchmark-code-analysis',
      name: 'Benchmark Code Analysis',
      description: 'Function recovery routing benchmark fixture',
      aspects: {
        formats: ['pe'],
        platforms: ['windows'],
        execution: ['static'],
        capabilities: ['function-recovery', 'xrefs'],
        evidence: ['symbols', 'workflow'],
      },
      surfaceRules: {
        tier: 2,
        category: 'reverse-engineering',
        activateOn: { fileTypes: ['pe'], findings: ['function-recovery'] },
      },
      tools: [
        tool('code.functions.list', {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['static'],
          evidence: ['symbols'],
        }),
      ],
    },
    {
      id: 'benchmark-unpacking',
      name: 'Benchmark Unpacking',
      description: 'Packed binary planning benchmark fixture',
      aspects: {
        formats: ['pe'],
        platforms: ['windows'],
        execution: ['static'],
        capabilities: ['unpack-planning', 'packed-binary-routing'],
        evidence: ['workflow'],
      },
      surfaceRules: {
        tier: 2,
        category: 'unpacking',
        activateOn: { fileTypes: ['pe'], findings: ['packed'] },
      },
      tools: [
        tool('unpack.workflow.plan', {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['static'],
          evidence: ['workflow'],
        }),
      ],
    },
    {
      id: 'benchmark-ghidra',
      name: 'Benchmark Ghidra',
      description: 'Profile-gated Ghidra decompiler routing benchmark fixture',
      aspects: {
        formats: ['pe'],
        platforms: ['windows'],
        execution: ['static', 'decompilation'],
        capabilities: ['decompilation', 'function-recovery'],
        evidence: ['symbols', 'workflow'],
      },
      surfaceRules: {
        tier: 3,
        category: 'reverse-engineering',
        activateOn: { fileTypes: ['pe'] },
      },
      tools: [
        tool(
          'ghidra.analyze',
          {
            formats: ['pe'],
            platforms: ['windows'],
            execution: ['static', 'decompilation'],
            evidence: ['symbols'],
          },
          { workerBackend: profileGatedWorkerBackend('BenchmarkGhidra', 'ghidra') }
        ),
      ],
    },
    {
      id: 'benchmark-retdec',
      name: 'Benchmark RetDec',
      description: 'Profile-gated RetDec routing benchmark fixture',
      aspects: {
        formats: ['pe'],
        platforms: ['windows'],
        execution: ['static', 'decompilation'],
        capabilities: ['decompilation', 'cross-backend-consensus'],
        evidence: ['workflow'],
      },
      surfaceRules: {
        tier: 3,
        category: 'reverse-engineering',
        activateOn: { fileTypes: ['pe'] },
      },
      tools: [
        tool(
          'retdec.decompile',
          {
            formats: ['pe'],
            platforms: ['windows'],
            execution: ['static', 'decompilation'],
            evidence: ['workflow'],
          },
          { workerBackend: profileGatedWorkerBackend('BenchmarkRetDec', 'retdec') }
        ),
      ],
    },
    {
      id: 'benchmark-decompile-consensus',
      name: 'Benchmark Decompile Consensus',
      description: 'Cross-backend consensus scoring benchmark fixture',
      aspects: {
        formats: ['pe'],
        platforms: ['windows'],
        execution: ['static', 'correlation'],
        capabilities: ['cross-backend-consensus', 'decompilation-review'],
        evidence: ['correlation-graph', 'workflow'],
      },
      surfaceRules: {
        tier: 3,
        category: 'reverse-engineering',
        activateOn: { fileTypes: ['pe'] },
      },
      tools: [
        tool('decompile.consensus.compare', {
          formats: ['pe'],
          platforms: ['windows'],
          execution: ['static', 'correlation'],
          evidence: ['correlation-graph', 'workflow'],
        }),
      ],
    },
    {
      id: 'benchmark-dotnet',
      name: 'Benchmark .NET',
      description: '.NET metadata routing benchmark fixture',
      aspects: {
        formats: ['pe-clr', 'dotnet', 'pe'],
        platforms: ['windows', 'dotnet'],
        execution: ['static'],
        capabilities: ['dotnet-metadata'],
        evidence: ['structure', 'strings'],
      },
      surfaceRules: {
        tier: 1,
        category: 'dotnet-analysis',
        activateOn: { fileTypes: ['pe-clr', 'dotnet', 'pe'] },
      },
      tools: [
        tool('dotnet.metadata.extract', {
          formats: ['pe-clr', 'dotnet', 'pe'],
          platforms: ['windows', 'dotnet'],
          execution: ['static'],
          evidence: ['structure'],
        }),
      ],
    },
    {
      id: 'benchmark-malware-config',
      name: 'Benchmark Malware Config',
      description: 'Config recovery routing benchmark fixture',
      aspects: {
        formats: ['pe-clr', 'dotnet', 'pe'],
        platforms: ['windows', 'dotnet'],
        execution: ['static'],
        capabilities: ['config-recovery'],
        evidence: ['strings', 'artifact'],
      },
      surfaceRules: {
        tier: 2,
        category: 'malware-analysis',
        activateOn: { fileTypes: ['pe-clr', 'pe'], findings: ['config'] },
      },
      tools: [
        tool('malware.config.extract', {
          formats: ['pe-clr', 'dotnet', 'pe'],
          platforms: ['windows', 'dotnet'],
          execution: ['static'],
          evidence: ['strings', 'artifact'],
        }),
      ],
    },
    {
      id: 'benchmark-javascript-deobf',
      name: 'Benchmark JavaScript Deobfuscation',
      description: 'Passive JavaScript obfuscation routing benchmark fixture',
      aspects: {
        formats: ['js', 'javascript'],
        platforms: ['node', 'browser'],
        execution: ['static'],
        capabilities: ['javascript-deobfuscation'],
        evidence: ['structure', 'strings'],
      },
      surfaceRules: {
        tier: 2,
        category: 'reverse-engineering',
        activateOn: { fileTypes: ['js', 'javascript'], findings: ['obfuscated'] },
      },
      tools: [
        tool('javascript.obfuscation.profile', {
          formats: ['js', 'javascript'],
          platforms: ['node', 'browser'],
          execution: ['static'],
          evidence: ['structure', 'strings'],
        }),
      ],
    },
    {
      id: 'benchmark-jsimplifier',
      name: 'Benchmark JSimplifier',
      description: 'Static JavaScript simplification routing benchmark fixture',
      aspects: {
        formats: ['js', 'javascript'],
        platforms: ['node', 'browser'],
        execution: ['static'],
        capabilities: ['ast-simplification', 'javascript-deobfuscation'],
        evidence: ['structure', 'workflow'],
      },
      surfaceRules: {
        tier: 2,
        category: 'reverse-engineering',
        activateOn: { fileTypes: ['js', 'javascript'], findings: ['obfuscated'] },
      },
      tools: [
        tool('jsimplifier.pipeline.plan', {
          formats: ['js', 'javascript'],
          platforms: ['node', 'browser'],
          execution: ['static'],
          evidence: ['workflow'],
        }),
      ],
    },
    {
      id: 'benchmark-jsvmp',
      name: 'Benchmark JSVMP',
      description: 'JavaScript VM bytecode recovery routing benchmark fixture',
      aspects: {
        formats: ['js', 'javascript'],
        platforms: ['node', 'browser'],
        execution: ['static'],
        capabilities: ['jsvmp-bytecode-recovery', 'handler-map-recovery'],
        evidence: ['structure', 'workflow'],
      },
      surfaceRules: {
        tier: 2,
        category: 'reverse-engineering',
        activateOn: { fileTypes: ['js', 'javascript'], findings: ['jsvmp'] },
      },
      tools: [
        tool('jsvmp.bytecode.recover', {
          formats: ['js', 'javascript'],
          platforms: ['node', 'browser'],
          execution: ['static'],
          evidence: ['workflow'],
        }),
      ],
    },
    {
      id: 'benchmark-runtime-sandbox',
      name: 'Benchmark Runtime Sandbox',
      description: 'Runtime gate routing benchmark fixture',
      aspects: {
        formats: ['pe'],
        platforms: ['windows'],
        execution: ['dynamic'],
        runtimes: ['windows-sandbox'],
        safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
        capabilities: ['dynamic-behavior'],
        evidence: ['behavior'],
      },
      runtimePolicy: {
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'disabled',
      },
      surfaceRules: {
        tier: 3,
        category: 'dynamic-analysis',
        activateOn: { fileTypes: ['pe'] },
      },
      tools: [
        tool(
          'sandbox.execute',
          {
            formats: ['pe'],
            platforms: ['windows'],
            execution: ['dynamic'],
            evidence: ['behavior'],
          },
          { workerBackend: runtimeWorkerBackend() }
        ),
      ],
    },
  ]
}

function createBenchmarkDiscoverHandler(plugins: Plugin[]) {
  resetSurfaceForTest()
  const surface = getToolSurfaceManager()
  for (const plugin of plugins) {
    surface.registerPlugin(
      plugin,
      plugin.tools?.map((item) => item.definition.name) ?? []
    )
  }
  return createToolsDiscoverHandler({
    getStatuses: () =>
      plugins.map((plugin) => ({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        status: 'loaded',
        tools: plugin.tools?.map((item) => item.definition.name) ?? [],
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any)
}

function loadManifest(): ReverseBenchmarkManifest {
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as ReverseBenchmarkManifest
}

describe('reverse-engineering benchmark guard suite', () => {
  test('documents a CI-safe benchmark manifest with residual gaps', () => {
    const manifest = loadManifest()

    expect(manifest.policy).toEqual(
      expect.objectContaining({
        allows_live_malware: false,
        allows_host_execution: false,
        default_ci_static_only: true,
      })
    )

    expect(manifest.dimensions.map((dimension) => dimension.id)).toEqual(
      expect.arrayContaining([
        'tool_discovery_quality',
        'function_recovery_coverage',
        'decompile_consensus',
        'string_config_recovery',
        'js_obfuscation_routing',
        'safety_gate_correctness',
      ])
    )

    const defaultCases = selectReverseBenchmarkCases(manifest, { env: {} })
    expect(defaultCases).toHaveLength(5)
    expect(defaultCases.every((testCase) => testCase.default_ci)).toBe(true)
    expect(defaultCases.every((testCase) => testCase.fixture_mode !== 'external-corpus')).toBe(
      true
    )
    expect(defaultCases.every((testCase) => (testCase.residual_gaps ?? []).length > 0)).toBe(true)

    const externalCases = selectReverseBenchmarkCases(manifest, {
      env: { RIKUNE_REVERSE_BENCH_CRACKME: '1' },
    })
    expect(externalCases.map((testCase) => testCase.id)).toContain('external-crackme-oracle-routing')
  })

  test('validates tools.discover recommendations for representative benchmark profiles', async () => {
    const manifest = loadManifest()
    const handler = createBenchmarkDiscoverHandler(benchmarkPlugins())
    const selectedCases = selectReverseBenchmarkCases(manifest, { env: {} })

    const results = []
    for (const testCase of selectedCases) {
      const discoverResult = await handler(testCase.discover_request)
      expect(discoverResult.ok).toBe(true)

      const evaluation = evaluateReverseBenchmarkDiscoverCase(
        testCase as ReverseBenchmarkCase,
        (discoverResult.data as any) ?? {}
      )
      results.push(evaluation)
      expect(evaluation.missing).toEqual({
        recommended_tools: [],
        plugin_ids: [],
        readiness_states: {},
        blocked_tools: [],
        missing_deps: [],
        safety_gates: [],
      })
      expect(evaluation.passed).toBe(true)
    }

    const summary = summarizeReverseBenchmarkResults(results)
    expect(summary).toEqual(
      expect.objectContaining({
        total_cases: 5,
        passed_cases: 5,
        failed_cases: 0,
      })
    )
    expect(summary.residual_gaps).toEqual(
      expect.arrayContaining([
        expect.stringContaining('default CI'),
        expect.stringContaining('Runtime behavior collection'),
      ])
    )
  })

  test('reports missing recommendation expectations without executing backends', async () => {
    const manifest = loadManifest()
    const handler = createBenchmarkDiscoverHandler(benchmarkPlugins())
    const testCase = selectReverseBenchmarkCases(manifest, { env: {} })[0]
    const discoverResult = await handler(testCase.discover_request)

    const evaluation = evaluateReverseBenchmarkDiscoverCase(
      {
        ...testCase,
        expected: {
          discover: {
            ...testCase.expected.discover,
            recommended_tools: [
              ...(testCase.expected.discover.recommended_tools ?? []),
              'nonexistent.backend.run',
            ],
          },
        },
      },
      (discoverResult.data as any) ?? {}
    )

    expect(evaluation.passed).toBe(false)
    expect(evaluation.missing.recommended_tools).toEqual(['nonexistent.backend.run'])
  })
})
