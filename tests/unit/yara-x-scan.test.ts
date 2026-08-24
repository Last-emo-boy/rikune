import { DATABASE_FIXTURE_CAPABILITY } from '../../src/database.js'
import { afterEach, beforeEach, describe, expect, test, jest } from '@jest/globals'
import { createHash } from 'crypto'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import type { ToolchainBackendResolution } from '../../src/static-backend-discovery.js'
import {
  createYaraXScanHandler,
  yaraXScanToolDefinition,
} from '../../src/plugins/yara-x/tools/yara-x-scan.js'
import yaraXPlugin from '../../src/plugins/yara-x/index.js'
import { checkBackendWorkerReadiness } from '../../src/worker/backend-worker-client.js'
import { persistBackendPreviewEvidence } from '../../src/plugins/docker-shared.js'
import { createWorkflowSearchHandler } from '../../src/tools/workflow-search.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'

const SAMPLE_HASH = '6'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

function resetSurfaceForSearchTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function createPluginManager(plugins: any[]) {
  return {
    getStatuses: () =>
      plugins.map((plugin) => ({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        status: 'loaded',
        tools: plugin.tools.map((tool: any) => tool.definition.name),
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any
}

function createBackendResolution(): ToolchainBackendResolution {
  return {
    capa_cli: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    capa_rules: { available: false, source: 'none', path: null, error: null },
    die: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    graphviz: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    rizin: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    upx: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    wine: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    winedbg: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    frida_cli: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    yara_x: {
      available: true,
      source: 'config',
      path: '/opt/yara-x/bin/python',
      version: '0.13.0',
      checked_candidates: ['python3'],
      error: null,
    },
    qiling: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    angr: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    panda: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
    retdec: {
      available: false,
      source: 'none',
      path: null,
      version: null,
      checked_candidates: [],
      error: null,
    },
  }
}

describe('yara_x.scan tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-yara-x-scan-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))

    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '7'.repeat(32),
      size: 64,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const workspace = await workspaceManager.createWorkspace(SAMPLE_ID)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), Buffer.from('MZunit-test'))
  })

  afterEach(() => {
    database.close()
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('returns structured handoff, quality gates, and persisted artifact', async () => {
    const rulesText = 'rule SuspiciousUnitRule { strings: $a = "unit" condition: $a }'
    const handler = createYaraXScanHandler(workspaceManager, database, {
      resolveBackends: createBackendResolution,
      runPythonJson: async () => ({
        stdout: '',
        stderr: '',
        parsed: {
          match_count: 1,
          matching_rules: [
            {
              identifier: 'SuspiciousUnitRule',
              namespace: 'default',
              patterns: [
                { identifier: '$a', matches: [{ offset: 16, length: 4 }] },
                { identifier: '$b', matches: [{ offset: 32, length: 8 }] },
              ],
            },
          ],
          module_outputs: { pe: { imphash: 'abc' } },
        },
      }),
    })

    const result = await handler({
      sample_id: SAMPLE_ID,
      rules_text: rulesText,
      persist_artifact: true,
      timeout_sec: 15,
      max_matches_per_pattern: 250,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.yara_x_scan.v1')
    expect(data.tool_version).toBe('0.1.0')
    expect(data.rules_digest).toBe(createHash('sha256').update(rulesText).digest('hex'))
    expect(data.rules_source).toBe('inline')
    expect(data.match_count).toBe(1)
    expect(data.pattern_match_count).toBe(2)
    expect(data.matching_rules).toHaveLength(1)
    expect(data.matches).toHaveLength(1)
    expect(data.module_outputs.pe.imphash).toBe('abc')
    expect(data.backend_semantics).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.backend_semantics.v1',
        backend_engine: 'YARA-X',
        adapter: 'python.yara_x.scan',
        python_import: 'yara_x',
        no_network: true,
        no_mutation: true,
        no_live_execution: true,
      })
    )
    expect(data.ruleset_provenance).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.ruleset_provenance.v1',
        rules_source: 'inline',
        rules_digest: createHash('sha256').update(rulesText).digest('hex'),
        default_rules: expect.objectContaining({
          applied: false,
          network_rule_fetch_performed: false,
        }),
        provenance_terms: expect.arrayContaining(['ruleset', 'provenance', 'yara-x', 'yara']),
      })
    )
    expect(data.validation_semantics).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.validation_semantics.v1',
        rule_engine: 'YARA-X',
        compile_backend: 'yara_x.compile',
        scan_backend: 'yara_x.Scanner',
        default_rules_applied: false,
        legacy_yara_comparison_recommended: true,
        search_terms: expect.arrayContaining(['yara-x', 'yara', 'ruleset', 'corroboration']),
      })
    )
    expect(data.corroboration_plan).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.corroboration_plan.v1',
        primary_tool: 'yara_x.scan',
        primary_engine: 'YARA-X',
        comparison_tool: 'yara.scan',
        comparison_engine: 'legacy YARA',
        comparison_status: 'recommended_not_automatically_run',
      })
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.evidence_summary.v1',
        artifact_type: 'backend_yara_x_scan',
        backend_engine: 'YARA-X',
        match_count: 1,
        pattern_match_count: 2,
        default_rules: expect.objectContaining({ applied: false }),
        corroboration: expect.objectContaining({
          comparison_tool: 'yara.scan',
          legacy_yara_comparison_recommended: true,
        }),
        search_terms: expect.arrayContaining(['yara-x', 'ruleset', 'provenance']),
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.workflow_handoff.v1',
        handoff_mode: 'yara_x_scan_to_rule_validation_and_reporting',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'evidence-graph-and-reporting',
            next_tools: expect.arrayContaining(['analysis.evidence.graph', 'report.generate']),
          }),
          expect.objectContaining({
            goal: 'ruleset-provenance-and-rule-validation',
            next_tools: expect.arrayContaining(['artifact.read', 'yara.scan']),
          }),
        ]),
        ruleset_provenance: expect.objectContaining({
          default_rules: expect.objectContaining({ applied: false }),
        }),
        corroboration: expect.objectContaining({
          comparison_tool: 'yara.scan',
        }),
      })
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        passive_scan_only: true,
        network_policy: 'disabled',
        no_network: true,
        no_mutation: true,
        no_live_execution: true,
        sample_executed_by_tool: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_x_scan.quality_gates.v1',
        passive_scan_only: true,
        passive_static_backend: true,
        backend_started: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        no_network: true,
        no_mutation: true,
        no_live_execution: true,
        no_implicit_default_rules: true,
        rule_validation_performed_by_yara_x: true,
        yara_x_corroboration_ready: true,
        legacy_yara_comparison_recommended: true,
        engine_comparison_required_before_publication: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'artifact.read',
        'yara.scan',
        'yara.generate',
        'analysis.evidence.graph',
      ])
    )
    expect(result.artifacts).toHaveLength(1)
    expect(data.artifact).toEqual(result.artifacts?.[0])
    expect(data.artifact.type).toBe('backend_yara_x_scan')

    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    const artifactPayload = JSON.parse(
      fs.readFileSync(path.join(workspace.root, data.artifact.path), 'utf8')
    )
    expect(artifactPayload.schema).toBe('rikune.yara_x_scan.v1')
    expect(artifactPayload.backend_semantics.backend_engine).toBe('YARA-X')
    expect(artifactPayload.ruleset_provenance.default_rules.applied).toBe(false)
    expect(artifactPayload.corroboration_plan.comparison_tool).toBe('yara.scan')
    expect(artifactPayload.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ goal: 'ruleset-provenance-and-rule-validation' }),
        expect.objectContaining({ goal: 'legacy-yara-comparison' }),
        expect.objectContaining({ goal: 'evidence-graph-and-reporting' }),
      ])
    )
  })

  test('hydrates reused preview evidence with YARA-X metadata and comparison handoff', async () => {
    const rulesText = 'rule CachedUnitRule { strings: $a = "unit" condition: $a }'
    const rulesDigest = createHash('sha256').update(rulesText).digest('hex')
    const sample = database.findSample(SAMPLE_ID)
    expect(sample).toBeDefined()

    persistBackendPreviewEvidence(
      database,
      sample!,
      'yara_x',
      'scan',
      {
        rules_digest: rulesDigest,
        max_matches_per_pattern: 250,
      },
      {
        status: 'ready',
        backend: createBackendResolution().yara_x,
        schema: 'rikune.yara_x_scan.v1',
        tool_version: '0.1.0',
        sample_id: SAMPLE_ID,
        rules_digest: rulesDigest,
        rules_source: 'inline',
        timeout_sec: 15,
        max_matches_per_pattern: 250,
        match_count: 1,
        matching_rules: [
          {
            identifier: 'CachedUnitRule',
            namespace: 'default',
            patterns: [{ identifier: '$a', matches: [{ offset: 4, length: 4 }] }],
          },
        ],
        module_outputs: {},
        pattern_match_count: 1,
        evidence_summary: {
          schema: 'rikune.yara_x_scan.evidence_summary.v1',
          artifact_type: 'backend_yara_x_scan',
          match_count: 1,
          pattern_match_count: 1,
        },
        workflow_handoff: {
          schema: 'rikune.yara_x_scan.workflow_handoff.v1',
          handoff_mode: 'yara_x_scan_to_rule_validation_and_reporting',
          dynamic_boundary: {
            passive_scan_only: true,
            backend_started: true,
            sample_executed_by_tool: false,
            network_accessed_by_tool: false,
            live_sample_mutation_performed: false,
          },
          routing: [{ goal: 'legacy-yara-comparison', next_tools: ['yara.scan'] }],
        },
        quality_gates: {
          schema: 'rikune.yara_x_scan.quality_gates.v1',
          passive_scan_only: true,
          backend_started: true,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          legacy_yara_comparison_recommended: true,
        },
        summary: 'cached legacy YARA-X scan result',
        recommended_next_tools: ['artifact.read'],
        next_actions: ['old cached action'],
      },
      [],
      { backend_version: '0.13.0' }
    )

    const handler = createYaraXScanHandler(workspaceManager, database, {
      resolveBackends: () => {
        throw new Error('backend resolution should not run when preview evidence is reused')
      },
      runPythonJson: async () => {
        throw new Error('YARA-X backend should not run when preview evidence is reused')
      },
    })

    const result = await handler({
      sample_id: SAMPLE_ID,
      rules_text: rulesText,
      persist_artifact: true,
      timeout_sec: 15,
      max_matches_per_pattern: 250,
    })

    expect(result.ok).toBe(true)
    expect(result.warnings).toEqual(expect.arrayContaining([expect.stringContaining('Reused')]))
    const data = result.data as any
    expect(data.summary).toBe('cached legacy YARA-X scan result')
    expect(data.backend_semantics).toEqual(
      expect.objectContaining({
        backend_engine: 'YARA-X',
        no_network: true,
        no_mutation: true,
        no_live_execution: true,
      })
    )
    expect(data.ruleset_provenance).toEqual(
      expect.objectContaining({
        rules_digest: rulesDigest,
        default_rules: expect.objectContaining({ applied: false }),
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        handoff_mode: 'yara_x_scan_to_rule_validation_and_reporting',
        dynamic_boundary: expect.objectContaining({
          no_network: true,
          no_mutation: true,
          no_live_execution: true,
        }),
        routing: expect.arrayContaining([
          expect.objectContaining({ goal: 'ruleset-provenance-and-rule-validation' }),
          expect.objectContaining({ goal: 'legacy-yara-comparison' }),
        ]),
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        no_implicit_default_rules: true,
        rule_validation_performed_by_yara_x: true,
        legacy_yara_comparison_recommended: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['artifact.read', 'yara.scan', 'analysis.evidence.graph'])
    )
  })

  test('declares metadata, readiness policy, and workflow search terms for validation handoff', () => {
    expect(yaraXPlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'external_static_backend',
        'no_live_sample_by_default',
        'no_live_execution',
        'no_network_by_default',
        'no_mutation',
      ])
    )
    expect(yaraXPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'ruleset-provenance',
        'default-rules-semantics',
        'rule-validation',
        'engine-comparison',
        'legacy-yara-comparison',
        'yara-x-corroboration',
      ])
    )
    expect(yaraXPlugin.aspects?.evidence).toEqual(
      expect.arrayContaining(['ruleset', 'rule-validation', 'corroboration', 'provenance'])
    )
    expect(yaraXPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )

    expect(yaraXScanToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'ruleset-provenance',
        'default-rules-semantics',
        'rule-validation',
        'engine-comparison',
        'legacy-yara-comparison',
        'yara-x-corroboration',
      ])
    )
    expect(yaraXScanToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_network_by_default',
        'no_mutation',
        'no_live_execution',
      ])
    )
    expect(yaraXScanToolDefinition.aspects?.search).toEqual(
      expect.arrayContaining(['yara-x', 'yara', 'ruleset', 'provenance', 'corroboration'])
    )
    expect(yaraXScanToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'ruleset' }),
        expect.objectContaining({ category: 'rule-validation' }),
        expect.objectContaining({ category: 'engine-comparison' }),
        expect.objectContaining({ category: 'corroboration' }),
      ])
    )
    expect(yaraXScanToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'yara-x.scan-validation-handoff',
          startsWith: expect.arrayContaining(['yara_x.scan', 'yara.generate', 'yara.scan']),
          nextTools: expect.arrayContaining([
            'artifact.read',
            'yara.scan',
            'yara.generate',
            'analysis.evidence.graph',
          ]),
          producesArtifacts: expect.arrayContaining(['backend_yara_x_scan']),
          evidence: expect.arrayContaining([
            'signatures',
            'ruleset',
            'rule-validation',
            'corroboration',
            'workflow',
            'provenance',
          ]),
          safety: expect.arrayContaining([
            'passive',
            'no_live_sample_by_default',
            'no_network_by_default',
            'no_mutation',
            'no_live_execution',
          ]),
          backend: expect.objectContaining({
            engine: 'YARA-X',
            pythonImport: 'yara_x',
            defaultRules: expect.stringContaining('rules_text or rules_path'),
          }),
          engineComparison: expect.objectContaining({
            primary: 'yara_x.scan',
            comparison: 'yara.scan',
          }),
          searchTags: expect.arrayContaining([
            'yara-x',
            'yara',
            'ruleset',
            'provenance',
            'corroboration',
          ]),
        }),
      ])
    )
    expect(yaraXScanToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(yaraXScanToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'YARA-X Python scanner backend',
        backendKind: 'external',
        adapter: 'python.yara_x.scan',
        envVar: 'YARAX_PYTHON',
        inputArtifactTypes: expect.arrayContaining(['sample', 'ruleset']),
        outputArtifactTypes: expect.arrayContaining(['backend_yara_x_scan']),
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
          defaultRules: expect.stringContaining('none'),
          comparisonBackend: 'legacy yara.scan',
        }),
      })
    )
    expect(yaraXScanToolDefinition.workerBackend?.policy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )

    const readiness = checkBackendWorkerReadiness(yaraXScanToolDefinition.workerBackend!, {
      mode: 'external-python',
    })
    expect(readiness).toEqual(
      expect.objectContaining({
        backend_name: 'YARA-X Python scanner backend',
        backend_kind: 'external',
        adapter: 'python.yara_x.scan',
        env_var: 'YARAX_PYTHON',
        does_not_start_backend: true,
        setup_actions: expect.arrayContaining([
          expect.stringContaining('yara-x'),
          expect.stringContaining('rules_text or rules_path'),
        ]),
      })
    )
  })

  test('workflow.search can match YARA-X ruleset provenance and corroboration terms', async () => {
    resetSurfaceForSearchTest()
    const pluginForSearch = {
      ...yaraXPlugin,
      tools: [
        {
          definition: yaraXScanToolDefinition,
          handler: async () => ({ ok: true }),
        },
      ],
    }
    getToolSurfaceManager().registerPlugin(pluginForSearch as any, ['yara_x.scan'])

    const handler = createWorkflowSearchHandler(createPluginManager([pluginForSearch]))
    const result = await handler({
      query: 'yara-x yara ruleset provenance corroboration',
      goal: 'static',
      top_k: 5,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const yaraXResult = data.results.find((item: any) => item.plugin_id === 'yara-x')

    expect(yaraXResult).toEqual(
      expect.objectContaining({
        plugin_id: 'yara-x',
        recommended_tools: expect.arrayContaining(['yara_x.scan']),
      })
    )
    expect(yaraXResult.score_breakdown.query_score).toBeGreaterThan(0)
    expect(yaraXResult.matched_profile_fields.join(' ')).toContain('query terms')
  })

  test('forwards abort to YARA-X Python and prevents late artifact persistence', async () => {
    let resolveStarted!: (signal: AbortSignal) => void
    const started = new Promise<AbortSignal>((resolve) => {
      resolveStarted = resolve
    })
    let resolveTeardown!: () => void
    const teardown = new Promise<void>((resolve) => {
      resolveTeardown = resolve
    })
    const runPythonJson = jest.fn(
      async (
        _pythonPath: string,
        _script: string,
        _payload: unknown,
        _timeoutMs: number,
        options?: { abortSignal?: AbortSignal }
      ) => {
        const signal = options?.abortSignal
        if (!signal) throw new Error('missing AbortSignal')
        resolveStarted(signal)
        await new Promise<void>((resolve) => {
          signal.addEventListener('abort', () => resolve(), { once: true })
        })
        await teardown
        return {
          stdout: '',
          stderr: '',
          parsed: { match_count: 0, matching_rules: [], module_outputs: {} },
        }
      }
    )
    const handler = createYaraXScanHandler(workspaceManager, database, {
      resolveBackends: createBackendResolution,
      runPythonJson,
    })
    const controller = new AbortController()
    let settled = false
    const running = handler(
      {
        sample_id: SAMPLE_ID,
        rules_text: 'rule Cancelled { condition: true }',
        persist_artifact: true,
      },
      controller.signal
    ).finally(() => {
      settled = true
    })

    const receivedSignal = await started
    controller.abort(new Error('cancel YARA-X'))
    await Promise.resolve()

    expect(receivedSignal).toBe(controller.signal)
    expect(settled).toBe(false)

    resolveTeardown()
    await expect(running).rejects.toMatchObject({ name: 'AbortError' })
    expect(database.findArtifacts(SAMPLE_ID)).toHaveLength(0)
  })
})
