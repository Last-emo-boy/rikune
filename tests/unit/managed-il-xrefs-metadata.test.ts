import { describe, expect, test } from '@jest/globals'

import managedIlXrefsPlugin from '../../src/plugins/managed-il-xrefs/index.js'
import {
  MANAGED_IL_XREFS_ARTIFACT_TYPES,
  MANAGED_IL_XREFS_EVIDENCE_SUMMARY_SCHEMA,
  MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
  MANAGED_IL_XREFS_PROFILE_TERMS,
  MANAGED_IL_XREFS_ROUTE_TERMS,
  MANAGED_IL_XREFS_RUNTIME_POLICY,
  MANAGED_IL_XREFS_SAFETY,
  MANAGED_IL_XREFS_SEARCH_TERMS,
  buildManagedIlXrefsEnvelope,
} from '../../src/plugins/managed-il-xrefs/managed-il-xrefs-metadata.js'
import { ilXrefsToolDefinition } from '../../src/plugins/managed-il-xrefs/tools/il-xrefs.js'
import { tokenXrefsToolDefinition } from '../../src/plugins/managed-il-xrefs/tools/token-xrefs.js'

const FORBIDDEN_NEXT_TOOLS = [
  'sandbox.execute',
  'dynamic.runtime.status',
  'dynamic.trace.import',
  'dotnet.decompile',
  'dotnet.decompile.type',
  'tools.discover',
]

describe('managed-il-xrefs metadata', () => {
  test('keeps plugin scoped to passive dotnet-triggered managed xref routing', () => {
    expect(managedIlXrefsPlugin.version).toBe('1.1.0')
    expect(managedIlXrefsPlugin.executionDomain).toBe('static')
    expect(managedIlXrefsPlugin.surfaceRules).toEqual({
      tier: 2,
      activateOn: { findings: ['dotnet'] },
      category: 'dotnet-analysis',
    })
    expect(managedIlXrefsPlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'bounded-worker',
        'no_runtime_start',
        'no_clr_start',
        'no_decompiler_launch',
        'no_network',
        'no_mutation',
      ])
    )
    expect(managedIlXrefsPlugin.aspects?.search).toEqual(
      expect.arrayContaining(MANAGED_IL_XREFS_SEARCH_TERMS)
    )
    expect(managedIlXrefsPlugin.aspects?.profile).toEqual(
      expect.arrayContaining(MANAGED_IL_XREFS_PROFILE_TERMS)
    )
    expect(managedIlXrefsPlugin.aspects?.route_terms).toEqual(
      expect.arrayContaining(MANAGED_IL_XREFS_ROUTE_TERMS)
    )
    expect(managedIlXrefsPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        ...MANAGED_IL_XREFS_RUNTIME_POLICY,
        noLiveExecution: true,
        noClrStart: true,
        noDecompilerLaunch: true,
        noPackageRestore: true,
      })
    )
    expect(managedIlXrefsPlugin.systemDeps?.map((dep) => dep.required)).toEqual([false, false])
  })

  test('declares tool metadata without widening default execution surface', () => {
    const tools = [ilXrefsToolDefinition, tokenXrefsToolDefinition]

    expect(ilXrefsToolDefinition.artifacts?.[0].type).toBe(MANAGED_IL_XREFS_ARTIFACT_TYPES.il)
    expect(ilXrefsToolDefinition.artifacts?.[0].mime).toBe('application/json')
    expect(tokenXrefsToolDefinition.artifacts?.[0].type).toBe(MANAGED_IL_XREFS_ARTIFACT_TYPES.token)
    expect(tokenXrefsToolDefinition.artifacts?.[0].mime).toBe('application/json')

    for (const tool of tools) {
      expect(tool.aspects?.safety).toEqual(expect.arrayContaining(MANAGED_IL_XREFS_SAFETY))
      expect(tool.aspects?.search).toEqual(expect.arrayContaining(MANAGED_IL_XREFS_SEARCH_TERMS))
      expect(tool.evidence?.map((entry) => entry.category)).toEqual(
        expect.arrayContaining(['managed-metadata', 'il-references', 'workflow', 'provenance'])
      )
      expect(tool.workflowRecipes?.[0]).toEqual(
        expect.objectContaining({
          startsWith: [tool.name],
          nextTools: MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
          safety: MANAGED_IL_XREFS_SAFETY,
        })
      )
      for (const forbidden of FORBIDDEN_NEXT_TOOLS) {
        expect(tool.workflowRecipes?.[0].nextTools ?? []).not.toContain(forbidden)
      }
      expect(tool.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          noLiveExecution: true,
          noClrStart: true,
          noDecompilerLaunch: true,
          networkPolicy: 'disabled',
          noPackageRestore: true,
          maxRuntimeMs: 30_000,
        })
      )
      expect(tool.workerBackend).toEqual(
        expect.objectContaining({
          backendKind: 'external',
          adapter: 'python.dnfile.managed-il-xrefs',
          supportedModes: ['local-python'],
          defaultMode: 'local-python',
          readiness: expect.objectContaining({ doesNotStartBackend: true }),
          policy: expect.objectContaining({
            noLiveExecution: true,
            noClrStart: true,
            noDecompilerLaunch: true,
            noNetwork: true,
            noMutation: true,
            noPackageRestore: true,
            defaultTimeoutMs: 30_000,
          }),
        })
      )
    }
  })

  test('builds passive envelope for managed IL xref worker results', () => {
    const envelope = buildManagedIlXrefsEnvelope({
      toolName: 'managed.token_xrefs',
      artifactType: MANAGED_IL_XREFS_ARTIFACT_TYPES.token,
      sampleId: 'sha256:abc',
      focus: 'token-graph',
      query: { token: '0x06000042', depth: 2, max_nodes: 128 },
      result: { ok: true, nodes: [], edges: [] },
    })

    expect(envelope.evidence_summary).toEqual(
      expect.objectContaining({
        schema: MANAGED_IL_XREFS_EVIDENCE_SUMMARY_SCHEMA,
        source_tool: 'managed.token_xrefs',
        artifact_type: MANAGED_IL_XREFS_ARTIFACT_TYPES.token,
        evidence_kind: 'token-graph',
        result_summary: expect.objectContaining({
          node_count: 0,
          edge_count: 0,
          truncated: false,
          root_token: null,
        }),
        recommended_next_tools: MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
      })
    )
    expect(envelope.workflow_handoff).toEqual(
      expect.objectContaining({
        artifact_contract: expect.objectContaining({
          consumes: ['sample', 'dotnet_assembly_inventory'],
          produces: [MANAGED_IL_XREFS_ARTIFACT_TYPES.token],
          mime: 'application/json',
        }),
        dynamic_boundary: expect.objectContaining({
          activation_boundary: 'result-scoped',
          sample_execution_allowed: false,
          clr_start_allowed: false,
          decompiler_launch_allowed: false,
          package_restore_allowed: false,
          network_allowed: false,
        }),
      })
    )
    expect(envelope.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          activation_boundary: 'result-scoped',
          next_tools: MANAGED_IL_XREFS_FOLLOW_UP_TOOLS,
        }),
      ])
    )
    expect(envelope.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.managed_il_xrefs.quality_gates.v1',
        passive_static_analysis: true,
        worker_backend_started: true,
        sample_executed_by_tool: false,
        clr_started_by_tool: false,
        decompiler_launched_by_tool: false,
        network_used_by_tool: false,
        mutation_performed: false,
        bounded: expect.objectContaining({ depth: 2, max_nodes: 128 }),
      })
    )
  })
})
