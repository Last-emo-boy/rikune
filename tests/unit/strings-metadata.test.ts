import { describe, expect, test } from '@jest/globals'

import stringsPlugin from '../../src/plugins/strings/index.js'
import { stringsExtractToolDefinition } from '../../src/plugins/strings/tools/strings-extract.js'
import { stringsFlossDecodeToolDefinition } from '../../src/plugins/strings/tools/strings-floss-decode.js'
import { checkBackendWorkerReadiness } from '../../src/worker/backend-worker-client.js'

function expectPassiveStaticPolicy(policy: Record<string, unknown> | undefined) {
  expect(policy).toEqual(
    expect.objectContaining({
      passiveByDefault: true,
      noNetwork: true,
      noMutation: true,
      noLiveExecution: true,
    })
  )
}

describe('strings metadata deepening', () => {
  test('plugin declares FLARE-FLOSS setup metadata and workflow-aware aspects', () => {
    expect(stringsPlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'external_static_backend',
        'no_live_sample_by_default',
        'no_network_by_default',
        'no_mutation',
      ])
    )
    expect(stringsPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining(['workflow-handoff', 'evidence-correlation'])
    )
    expect(stringsPlugin.aspects?.evidence).toEqual(
      expect.arrayContaining(['encoded-config', 'workflow'])
    )
    expect(stringsPlugin.systemDeps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'python',
          name: 'flare-floss',
          importName: 'floss',
          required: false,
          dockerFeature: 'static-python',
          dockerInstallProfile: 'optional',
        }),
        expect.objectContaining({
          type: 'binary',
          name: 'floss',
          envVar: 'FLOSS_PATH',
          required: false,
          dockerFeature: 'static-python',
          dockerInstallProfile: 'optional',
        }),
      ])
    )
  })

  test('strings.extract declares passive static runtime and worker policy', () => {
    expect(stringsExtractToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['workflow-handoff', 'evidence-correlation'])
    )
    expect(stringsExtractToolDefinition.aspects?.evidence).toEqual(
      expect.arrayContaining(['encoded-config', 'workflow'])
    )
    expectPassiveStaticPolicy(stringsExtractToolDefinition.runtimePolicy as Record<string, unknown>)
    expect(stringsExtractToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        networkPolicy: 'disabled',
      })
    )
    expect(stringsExtractToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'Static Python strings extractor',
        backendKind: 'external',
        adapter: 'static_python.strings.extract',
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
        }),
      })
    )
    expectPassiveStaticPolicy(stringsExtractToolDefinition.workerBackend?.policy)
  })

  test('strings.floss.decode declares passive static runtime and worker policy', () => {
    expect(stringsFlossDecodeToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['workflow-handoff', 'evidence-correlation'])
    )
    expect(stringsFlossDecodeToolDefinition.aspects?.evidence).toEqual(
      expect.arrayContaining(['encoded-config', 'workflow'])
    )
    expectPassiveStaticPolicy(
      stringsFlossDecodeToolDefinition.runtimePolicy as Record<string, unknown>
    )
    expect(stringsFlossDecodeToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        networkPolicy: 'disabled',
      })
    )
    expect(stringsFlossDecodeToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'FLARE-FLOSS static decoder',
        backendKind: 'external',
        adapter: 'static_python.strings.floss.decode',
        envVar: 'FLOSS_PATH',
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
          setupActions: expect.arrayContaining([
            expect.stringContaining('Install FLARE-FLOSS'),
          ]),
        }),
      })
    )
    expectPassiveStaticPolicy(stringsFlossDecodeToolDefinition.workerBackend?.policy)
  })

  test('FLOSS missing backend is expressed through readiness metadata without starting it', () => {
    const previousFlossPath = process.env.FLOSS_PATH
    delete process.env.FLOSS_PATH
    try {
      const readiness = checkBackendWorkerReadiness(
        stringsFlossDecodeToolDefinition.workerBackend!,
        { mode: 'external' }
      )

      expect(readiness).toEqual(
        expect.objectContaining({
          status: 'backend_missing',
          backend_name: 'FLARE-FLOSS static decoder',
          mode: 'external',
          env_var: 'FLOSS_PATH',
          backend_path: null,
          does_not_start_backend: true,
          setup_actions: expect.arrayContaining([
            expect.stringContaining('Install FLARE-FLOSS'),
            expect.stringContaining('FLOSS_PATH'),
          ]),
          reasons: expect.arrayContaining(['backend_path_missing']),
        })
      )
    } finally {
      if (previousFlossPath === undefined) {
        delete process.env.FLOSS_PATH
      } else {
        process.env.FLOSS_PATH = previousFlossPath
      }
    }
  })
})
