import { describe, expect, test } from '@jest/globals'
import { discoverBuiltInPlugins } from '../../src/core/plugin-system/discovery.js'
import { buildPluginBackendInstallProfile } from '../../src/core/backend-install-profile.js'
import { createPluginTestHarness, type Plugin, type ToolDefinition } from '../../src/plugins/sdk.js'
import externalReBridgePlugin, {
  externalReProfiles,
  localEndpointStatus,
} from '../../src/plugins/external-re-bridge/index.js'

function registeredBridgeTool(plugin: Plugin = externalReBridgePlugin) {
  const harness = createPluginTestHarness()
  harness.registerPlugin(plugin)
  const tool = harness.registeredTools.find(
    (entry) => entry.definition.name === 'external_re.bridge.sync'
  )
  expect(tool).toBeDefined()
  return tool as NonNullable<typeof tool>
}

function bridgeDefinition(): ToolDefinition {
  return registeredBridgeTool().definition
}

describe('external RE bridge plugin', () => {
  test('discovers as a passive tier-3 built-in plugin with BYO sidecar metadata', async () => {
    const plugins = await discoverBuiltInPlugins()
    const plugin = plugins.find((candidate) => candidate.id === 'external-re-bridge')

    expect(plugin).toBeDefined()
    expect(plugin?.executionDomain).toBe('static')
    expect(plugin?.surfaceRules).toEqual(
      expect.objectContaining({
        tier: 3,
        category: 'reverse-engineering',
      })
    )
    expect(plugin?.aspects?.runtimes).toEqual(
      expect.arrayContaining([
        'ida-sidecar',
        'binary-ninja-sidecar',
        'ghidra-sidecar',
        'radare2-sidecar',
      ])
    )
    expect(plugin?.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'read_only', 'local_endpoint_only'])
    )
    expect(plugin?.systemDeps?.map((dep) => dep.envVar)).toEqual(
      expect.arrayContaining([
        'IDA_MCP_ENDPOINT',
        'BINARY_NINJA_MCP_ENDPOINT',
        'GHIDRA_MCP_ENDPOINT',
        'RADARE2_MCP_ENDPOINT',
      ])
    )

    const profile = buildPluginBackendInstallProfile(plugin!)
    expect(profile.summary.byo).toBe(2)
    expect(profile.summary.sidecar).toBe(3)
    expect(profile.summary.default_enabled).toBe(0)
    expect(profile.entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          docker_feature: 'ida-mcp-sidecar',
          install_route: 'byo',
          safety_gate: 'bring_your_own_backend',
        }),
        expect.objectContaining({
          docker_feature: 'ghidra-mcp-sidecar',
          install_route: 'sidecar',
          safety_gate: 'sidecar_required',
        }),
        expect.objectContaining({
          docker_feature: 'external-re-bridge-sidecar',
          install_route: 'sidecar',
          safety_gate: 'sidecar_required',
        }),
      ])
    )
  })

  test('declares a read-only worker contract that readiness can inspect without sidecar startup', () => {
    const definition = bridgeDefinition()

    expect(definition.workerBackend).toEqual(
      expect.objectContaining({
        version: 'backend-worker.v1',
        backendName: 'External RE MCP sidecar bridge',
        backendKind: 'external',
        adapter: 'external-re-bridge.readonly-artifact-sync',
        availability: 'optional',
        supportedModes: ['builtin', 'external'],
        defaultMode: 'builtin',
      })
    )
    expect(definition.workerBackend?.policy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(definition.workerBackend?.readiness).toEqual(
      expect.objectContaining({
        doesNotStartBackend: true,
        missingBackendBehavior: expect.stringContaining('never auto-start'),
      })
    )
    expect(definition.workerBackend?.packaging).toEqual(
      expect.objectContaining({
        installRoute: 'sidecar',
        installProfile: 'license-gated',
        dockerFeature: 'external-re-bridge-sidecar',
      })
    )
    expect(definition.artifacts?.map((artifact) => artifact.type)).toEqual(
      expect.arrayContaining([
        'external_re_bridge_artifact_bundle',
        'external_re_function_index',
        'external_re_xref_summary',
        'cross_decompiler_input_bundle',
      ])
    )
    expect(definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'external-re-bridge.cross-decompiler-consensus',
        startsWith: expect.arrayContaining(['external_re.bridge.sync', 'tool.readiness']),
        nextTools: expect.arrayContaining(['code.cross_decompiler.consensus']),
        safety: expect.arrayContaining(['read_only', 'local_endpoint_only']),
      })
    )
  })

  test.each([
    ['http://127.0.0.1:4011', true],
    ['http://localhost:4011', true],
    ['ws://127.0.0.1:4011', true],
    ['https://127.0.0.1:4011', false],
    ['http://192.168.1.5:4011', false],
    ['not a url', false],
  ])('classifies local-only endpoint policy for %s', (endpoint, expected) => {
    expect(localEndpointStatus(endpoint).ok).toBe(expected)
  })

  test('normalizes fixture artifacts into a consensus-consumable bundle without contacting sidecars', async () => {
    const tool = registeredBridgeTool()

    const result = await tool.handler({
      profile: 'ida',
      endpoint: 'http://127.0.0.1:4011',
      sample_id: 'sha256:fixture',
      binary_id: 'fixture.bin',
      backend_version: 'IDA 9.0',
      sidecar_version: 'ida-mcp fixture',
      requested_operations: ['functions.list', 'decompile.get'],
      artifact_manifest: {
        comments: [{ address: '0x401000', text: 'entry thunk', author: 'analyst' }],
        symbols: [{ address: '0x401020', name: 'WinMain', kind: 'function' }],
        functions: [
          {
            address: '0x401020',
            name: 'WinMain',
            size: 64,
            signature: 'int WinMain(...)',
            confidence: 0.85,
          },
        ],
        xrefs: [{ from: '0x401030', to: '0x402000', kind: 'data' }],
        decompile_text: [
          {
            function_address: '0x401020',
            function_name: 'WinMain',
            text: 'return MessageBoxA();',
            language: 'c',
          },
        ],
        analysis_notes: [{ address: '0x401020', text: 'Compare with Ghidra output' }],
      },
    })

    expect((result as any).ok).toBe(true)
    expect((result as any).data.execution_semantics).toEqual(
      expect.objectContaining({
        actual_mode: 'local_contract_only',
        live_execution: false,
        sidecar_contacted: false,
      })
    )
    expect((result as any).data.readiness).toEqual(
      expect.objectContaining({
        status: 'sidecar_configured_not_contacted',
        profile: 'ida',
        requires_byo: true,
        endpoint_local_only: true,
      })
    )
    expect((result as any).data.artifact_bundle).toEqual(
      expect.objectContaining({
        schema_version: 'external-re-bridge.v1',
        profile: 'ida',
        backend_version: 'IDA 9.0',
        sidecar_version: 'ida-mcp fixture',
        policy: expect.objectContaining({
          read_only: true,
          no_backend_start: true,
          no_remote_command_execution: true,
        }),
        artifact_counts: {
          comments: 1,
          symbols: 1,
          functions: 1,
          xrefs: 1,
          decompile_text: 1,
          analysis_notes: 1,
        },
      })
    )
    expect((result as any).data.consensus_bundle).toEqual(
      expect.objectContaining({
        type: 'cross_decompiler_input_bundle',
        schema_version: 'cross-decompiler-input.v1',
        compatible_tools: expect.arrayContaining(['code.cross_decompiler.consensus']),
        source_backend: 'ida',
        functions: [
          expect.objectContaining({
            backend: 'ida',
            address: '0x401020',
            name: 'WinMain',
            provenance: expect.objectContaining({
              backend_version: 'IDA 9.0',
              trust: 'untrusted_sidecar_data',
            }),
          }),
        ],
      })
    )
    expect((result as any).artifacts).toEqual([
      expect.objectContaining({
        type: 'external_re_bridge_artifact_bundle',
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        metadata: expect.objectContaining({
          consensus_consumable: true,
          consensus_artifact_type: 'cross_decompiler_input_bundle',
        }),
      }),
    ])
    expect((result as any).evidence).toEqual([
      expect.objectContaining({
        category: 'provenance',
        metadata: expect.objectContaining({
          trust: 'untrusted_sidecar_data',
          sidecar_contacted: false,
        }),
      }),
    ])
  })

  test.each(externalReProfiles.map((profile) => profile.id))(
    'represents %s profile as fixture-safe read-only sidecar contract',
    async (profile) => {
      const tool = registeredBridgeTool()
      const result = await tool.handler({
        profile,
        endpoint: 'http://127.0.0.1:4011',
        sample_id: `sha256:${profile}`,
        backend_version: `${profile} fixture version`,
        sidecar_version: 'fixture-sidecar',
        artifact_manifest: {
          functions: [{ address: '0x1000', name: `${profile}_entry` }],
          xrefs: [{ from: '0x1004', to: '0x2000', kind: 'call' }],
        },
      })

      expect((result as any).ok).toBe(true)
      expect((result as any).data.artifact_bundle.profile).toBe(profile)
      expect((result as any).data.artifact_bundle.endpoint.contacted).toBe(false)
      expect((result as any).data.artifact_bundle.policy).toEqual(
        expect.objectContaining({
          read_only: true,
          no_sidecar_mutation: true,
          sidecar_data_trust: 'untrusted_until_consensus',
        })
      )
      expect((result as any).data.consensus_bundle.functions[0]).toEqual(
        expect.objectContaining({
          backend: profile,
          address: '0x1000',
        })
      )
    }
  )

  test('rejects non-local endpoints before producing sidecar artifacts', async () => {
    const tool = registeredBridgeTool()

    const result = await tool.handler({
      profile: 'ghidra',
      endpoint: 'http://10.0.0.5:4011',
      sample_id: 'sha256:remote',
      artifact_manifest: {
        functions: [{ address: '0x1000', name: 'remote_entry' }],
      },
    })

    expect((result as any).ok).toBe(false)
    expect((result as any).data.policy_denied).toBe(true)
    expect((result as any).data.readiness).toEqual(
      expect.objectContaining({
        status: 'endpoint_policy_denied',
        endpoint_local_only: false,
        sidecar_contacted: false,
      })
    )
    expect((result as any).errors).toEqual(
      expect.arrayContaining(['endpoint_host_must_be_localhost_or_loopback'])
    )
    expect((result as any).artifacts).toBeUndefined()
  })
})
