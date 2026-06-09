import { describe, expect, test } from '@jest/globals'
import speakeasyPlugin from '../../src/plugins/speakeasy/index.js'
import { speakeasyApiTraceToolDefinition } from '../../src/plugins/speakeasy/tools/speakeasy-api-trace.js'
import { speakeasyEmulateToolDefinition } from '../../src/plugins/speakeasy/tools/speakeasy-emulate.js'
import { speakeasyShellcodeToolDefinition } from '../../src/plugins/speakeasy/tools/speakeasy-shellcode.js'
import {
  SPEAKEASY_API_TRACE_ARTIFACT_TYPE,
  SPEAKEASY_EMULATE_ARTIFACT_TYPE,
  SPEAKEASY_RUNTIME_POLICY,
  SPEAKEASY_SHELLCODE_ARTIFACT_TYPE,
} from '../../src/plugins/speakeasy/speakeasy-metadata.js'

const SPEAKEASY_TOOL_DEFINITIONS = [
  {
    definition: speakeasyEmulateToolDefinition,
    artifactType: SPEAKEASY_EMULATE_ARTIFACT_TYPE,
    startsWith: 'speakeasy.emulate',
  },
  {
    definition: speakeasyShellcodeToolDefinition,
    artifactType: SPEAKEASY_SHELLCODE_ARTIFACT_TYPE,
    startsWith: 'speakeasy.shellcode',
  },
  {
    definition: speakeasyApiTraceToolDefinition,
    artifactType: SPEAKEASY_API_TRACE_ARTIFACT_TYPE,
    startsWith: 'speakeasy.api_trace',
  },
]

describe('speakeasy plugin metadata', () => {
  test('keeps Speakeasy as a runtime profile while using an isolation carrier policy', () => {
    expect(speakeasyPlugin.executionDomain).toBe('dynamic')
    expect(speakeasyPlugin.aspects?.runtimes).toEqual(['speakeasy'])
    expect(speakeasyPlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'opt_in_dynamic',
        'requires_isolation',
        'no_live_sample_by_default',
        'no_network_by_default',
      ])
    )
    expect(speakeasyPlugin.runtimePolicy).toEqual(SPEAKEASY_RUNTIME_POLICY)
    expect(speakeasyPlugin.runtimePolicy?.allowedBackends).toEqual(['docker'])
    expect(speakeasyPlugin.runtimePolicy?.allowedBackends).not.toContain('speakeasy')
    expect(speakeasyPlugin.systemDeps).toEqual([
      expect.objectContaining({
        type: 'python',
        name: 'speakeasy-emulator',
        importName: 'speakeasy',
        required: false,
        dockerFeature: 'dynamic-python',
      }),
    ])
  })

  test('declares tool-level artifacts, evidence, recipes, and runtime policy boundaries', () => {
    for (const { definition, artifactType, startsWith } of SPEAKEASY_TOOL_DEFINITIONS) {
      expect(definition.runtimePolicy).toEqual(SPEAKEASY_RUNTIME_POLICY)
      expect(definition.runtimePolicy?.allowedBackends).toEqual(['docker'])
      expect(definition.aspects?.runtimes).toEqual(['speakeasy'])
      expect(definition.aspects?.safety).toEqual(
        expect.arrayContaining(['requires_isolation', 'no_live_sample_by_default'])
      )
      expect(definition.artifacts).toEqual([
        expect.objectContaining({
          type: artifactType,
          mimeTypes: ['application/json'],
        }),
      ])
      expect(definition.evidence).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            category: 'api-calls',
            artifactTypes: [artifactType],
          }),
          expect.objectContaining({
            category: 'workflow',
            artifactTypes: [artifactType],
          }),
        ])
      )
      expect(definition.workflowRecipes?.[0]).toEqual(
        expect.objectContaining({
          startsWith: [startsWith],
          producesArtifacts: [artifactType],
          runtimeBackends: ['speakeasy'],
          safety: expect.arrayContaining(['requires_isolation', 'no_network_by_default']),
        })
      )
    }
  })
})
