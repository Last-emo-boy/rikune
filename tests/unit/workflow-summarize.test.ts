import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import { createHash } from 'crypto'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { CacheManager } from '../../src/cache-manager.js'
import {
  WorkflowSummarizeOutputSchema,
  createWorkflowSummarizeHandler,
  workflowSummarizeToolDefinition,
} from '../../src/workflows/summarize.js'
import { FinalStageDigestSchema } from '../../src/artifacts/summary-digests.js'
import { persistSummaryDigestArtifact } from '../../src/artifacts/summary-artifacts.js'
import { reportSummarizeToolDefinition } from '../../src/plugins/reporting/tools/report-summarize.js'
import { reportGenerateToolDefinition } from '../../src/plugins/reporting/tools/report-generate.js'
import { createAnalysisClaimsApplyHandler } from '../../src/plugins/kb-collaboration/tools/analysis-claims-apply.js'
import {
  ANALYSIS_CASE_STATE_SCHEMA,
  persistAnalysisCaseStateArtifact,
} from '../../src/artifacts/analysis-case-artifacts.js'
import type { ToolArgs, WorkerResult } from '../../src/types.js'
import { seedAnalysisClaimLedgerFixture } from '../helpers/analysis-claim-ledger-fixture.js'

describe('workflow.summarize', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let cacheManager: CacheManager
  let testWorkspaceRoot: string
  let testDbPath: string
  let testCachePath: string

  beforeEach(() => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-workflow-summarize')
    testDbPath = path.join(process.cwd(), 'test-workflow-summarize.db')
    testCachePath = path.join(process.cwd(), 'test-cache-workflow-summarize')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    cacheManager = new CacheManager(testCachePath, database)
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }
    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
    if (fs.existsSync(testCachePath)) {
      fs.rmSync(testCachePath, { recursive: true, force: true })
    }
  })

  function createCompactReportResult(sampleId: string): WorkerResult {
    return {
      ok: true,
      data: {
        detail_level: 'compact',
        tool_surface_role: 'compatibility',
        preferred_primary_tools: ['workflow.summarize'],
        coverage_level: 'static_core',
        completion_state: 'bounded',
        sample_size_tier: 'medium',
        analysis_budget_profile: 'balanced',
        downgrade_reasons: ['Static summary stops before final synthesis.'],
        coverage_gaps: [
          {
            domain: 'summary_synthesis',
            status: 'missing',
            reason: 'Final synthesis has not run yet.',
          },
        ],
        confidence_by_domain: {
          imports: 0.82,
          strings: 0.76,
          capabilities: 0.79,
        },
        known_findings: ['Observed suspicious process APIs.'],
        suspected_findings: ['Potential operator tooling behavior.'],
        unverified_areas: ['Runtime behavior is still unverified.'],
        upgrade_paths: [
          {
            tool: 'workflow.summarize',
            purpose: 'Continue to final synthesis.',
            closes_gaps: ['summary_synthesis'],
            expected_coverage_gain: 'Adds final known/suspected/unverified synthesis.',
            cost_tier: 'medium',
            availability: 'ready',
            prerequisites: [],
            blockers: [],
            requires_approval: false,
          },
        ],
        summary: 'Compact triage summary for staged reporting.',
        confidence: 0.77,
        threat_level: 'suspicious',
        iocs: {
          suspicious_imports: ['OpenProcess', 'WriteProcessMemory'],
          suspicious_strings: ['akasha --pid 42'],
          yara_matches: ['rule_process_tooling'],
        },
        evidence: ['Process APIs are present.', 'Runtime hints suggest process injection staging.'],
        recommendation: 'Inspect staged digests before requesting a final narrative.',
        binary_profile_summary: {
          binary_role: 'dll',
          role_confidence: 0.91,
          packed: false,
          packing_confidence: 0.1,
          export_count: 2,
          notable_exports: ['DllRegisterServer'],
          dispatch_model: 'com_registration_and_class_factory',
          host_hints: ['Plugin host extension'],
          analysis_priorities: ['trace_export_surface_first'],
          summary: 'Binary role profile suggests dll.',
        },
        rust_profile_summary: {
          suspected_rust: false,
          confidence: 0.11,
          primary_runtime: null,
          top_crates: [],
          recovered_symbol_count: 0,
          recovered_function_count: 0,
          analysis_priorities: [],
          summary: 'Rust-focused analysis did not strongly confirm Rust.',
        },
        static_capability_summary: {
          status: 'ready',
          capability_count: 3,
          top_groups: ['network', 'execution'],
          top_capabilities: ['send HTTP request', 'execute command'],
          summary: 'Capability triage matched 3 finding(s) across network, execution.',
        },
        pe_structure_summary: {
          status: 'ready',
          section_count: 6,
          import_function_count: 148,
          export_count: 0,
          resource_count: 2,
          overlay_present: false,
          parser_preference: 'lief',
          summary: 'PE structure recovered 6 section(s).',
        },
        compiler_packer_summary: {
          status: 'ready',
          compiler_names: ['MSVC'],
          packer_names: ['UPX'],
          protector_names: [],
          likely_primary_file_type: 'PE32 executable',
          summary: 'Toolchain attribution suggests packer/protector signals (UPX).',
        },
        semantic_explanation_summary: {
          count: 1,
          top_behaviors: ['dispatch_process_control'],
          top_summaries: ['Dispatches process-control operations.'],
          summary: 'Semantic explanations are available for 1 function(s).',
        },
        artifact_refs: {
          supporting: [],
          explanation_graphs: [
            {
              id: 'artifact-runtime-graph',
              type: 'analysis_explanation_graph',
              path: 'reports/explanation/runtime_graph.json',
              sha256: 'a'.repeat(64),
              mime: 'application/json',
              metadata: { surface_role: 'runtime_stage_view' },
            },
          ],
        },
        explanation_graphs: [
          {
            graph_type: 'runtime_stage',
            surface_role: 'runtime_stage_view',
            title: 'Staged Analysis Runtime View',
            semantic_summary: 'Bounded staged-runtime explanation graph.',
            confidence_state: 'observed',
            confidence_states_present: ['observed', 'inferred'],
            node_count: 4,
            edge_count: 3,
            bounded: true,
            recommended_next_tools: ['workflow.analyze.status', 'workflow.analyze.promote'],
            artifact_ref: {
              id: 'artifact-runtime-graph',
              type: 'analysis_explanation_graph',
              path: 'reports/explanation/runtime_graph.json',
              sha256: 'a'.repeat(64),
              mime: 'application/json',
            },
          },
        ],
        ghidra_execution: {
          analysis_id: 'analysis-ghidra',
          selected_source: 'latest_attempt',
          backend: 'ghidra',
          status: 'done',
          function_count: 12,
          finished_at: '2026-03-23T00:00:00.000Z',
          project_path: null,
          project_key: null,
          project_root: null,
          log_root: null,
          function_extraction_status: 'done',
          function_extraction_script: 'ExtractFunctions.java',
          command_log_paths: [],
          runtime_log_paths: [],
          progress_stages: [],
          readiness_status: {
            function_index: 'ready',
            decompile: 'ready',
            cfg: 'ready',
          },
          java_exception: null,
          warnings: [],
        },
        provenance: {
          runtime: {
            scope: 'all',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No runtime artifacts.',
          },
          static_capabilities: {
            scope: 'latest',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No static capability artifacts.',
          },
          pe_structure: {
            scope: 'latest',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No PE structure artifacts.',
          },
          compiler_packer: {
            scope: 'latest',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No compiler/packer artifacts.',
          },
          semantic_explanations: {
            scope: 'all',
            session_selector: null,
            session_tags: [],
            artifact_count: 0,
            artifact_ids: [],
            earliest_artifact_at: null,
            latest_artifact_at: null,
            scope_note: 'No semantic explanation artifacts.',
          },
        },
        selection_diffs: undefined,
      },
    }
  }

  test('advertises summary and report outputs as context-only artifacts', () => {
    for (const definition of [
      workflowSummarizeToolDefinition,
      reportSummarizeToolDefinition,
      reportGenerateToolDefinition,
    ]) {
      expect(definition.evidence).toBeUndefined()
      expect(definition.aspects?.evidence).toBeUndefined()
      expect(definition.description).toContain('context-only')
      expect(definition.description).toContain('cannot be used as Claim evidence')
    }

    expect(workflowSummarizeToolDefinition.artifacts?.map((artifact) => artifact.type)).toEqual([
      'summary_triage_digest',
      'summary_static_digest',
      'summary_deep_digest',
      'summary_final_digest',
    ])
  })

  test('should stop after static stage and persist triage/static digests', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    database.insertFunction({
      sample_id: sampleId,
      address: '0x401000',
      name: 'entry_main',
      size: 64,
      score: 0.91,
      tags: JSON.stringify(['entry']),
      summary: 'Entry point summary.',
      caller_count: 0,
      callee_count: 1,
      is_entry_point: 1,
      is_exported: 0,
      callees: JSON.stringify(['sub_401050']),
    })

    let reportCallCount = 0
    const reportSummarizeHandler = async (_args: ToolArgs): Promise<WorkerResult> => {
      reportCallCount += 1
      return createCompactReportResult(sampleId)
    }

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      { reportSummarizeHandler }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'static',
      session_tag: 'summary-alpha',
    })

    expect(result.ok).toBe(true)
    expect(() => WorkflowSummarizeOutputSchema.parse(result)).not.toThrow()
    const data = result.data as any
    expect(reportCallCount).toBe(1)
    expect(data.completed_stages).toEqual(['triage', 'static'])
    expect(data.tool_surface_role).toBe('compatibility')
    expect(data.preferred_primary_tools).toEqual(['workflow.search', 'artifact.read'])
    expect(data.coverage_level).toBe('static_core')
    expect(data.known_findings).toContain('Observed suspicious process APIs.')
    expect(data.stages.triage.summary).toContain('Compact triage summary')
    expect(data.stages.static.key_findings.length).toBeGreaterThan(0)
    expect(data.stages.deep).toBeUndefined()
    expect(data.stages.final).toBeUndefined()
    expect(data.stage_artifacts.triage.path).toContain('reports/summary/summary-alpha')
    expect(data.stage_artifacts.static.path).toContain('reports/summary/summary-alpha')
  })

  test('should reuse persisted stage digests without rebuilding compact report', async () => {
    const sampleId = 'sha256:' + '2'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '2'.repeat(64),
      md5: '2'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    let reportCallCount = 0
    const reportSummarizeHandler = async (_args: ToolArgs): Promise<WorkerResult> => {
      reportCallCount += 1
      return createCompactReportResult(sampleId)
    }

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      { reportSummarizeHandler }
    )

    const first = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'reuse-session',
    })
    expect(first.ok).toBe(true)
    expect(reportCallCount).toBe(1)

    const second = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'reuse-session',
      reuse_digests: true,
    })
    expect(second.ok).toBe(true)
    expect(reportCallCount).toBe(1)
    const data = second.data as any
    expect(data.synthesis.used_existing_stage_artifacts).toBe(true)
    expect(data.stage_artifacts.final.path).toContain('reports/summary/reuse-session')
  })

  test('does not reuse a legacy digest without a fingerprint', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'd'.repeat(64),
      md5: 'd'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )
    const seed = await handler({
      sample_id: sampleId,
      through_stage: 'triage',
      session_tag: 'fingerprint-seed',
    })
    expect(seed.ok).toBe(true)

    const legacyDigest = structuredClone((seed.data as any).stages.triage)
    delete legacyDigest.reuse_fingerprint
    const legacyArtifact = await persistSummaryDigestArtifact(
      workspaceManager,
      database,
      sampleId,
      'triage',
      legacyDigest,
      'legacy-fingerprint'
    )
    const rebuilt = await handler({
      sample_id: sampleId,
      through_stage: 'triage',
      session_tag: 'legacy-fingerprint',
      reuse_digests: true,
    })

    expect(rebuilt.ok).toBe(true)
    expect((rebuilt.data as any).stage_artifacts.triage.id).not.toBe(legacyArtifact.id)
    expect(rebuilt.warnings).toContain(
      'Skipped persisted triage summary digest because it has no compatible reuse fingerprint.'
    )
    expect(reportCallCount).toBe(2)
  })

  test('does not reuse a sampling final digest for a deterministic request', async () => {
    const sampleId = 'sha256:' + '8'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '8'.repeat(64),
      md5: '8'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    let reportCallCount = 0
    let samplingCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
        clientCapabilitiesProvider: () => ({ sampling: {} }),
        samplingRequester: async () => {
          samplingCallCount += 1
          return {
            model: 'gpt-test',
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  executive_summary: 'Sampled summary.',
                  analyst_summary: 'Sampled analyst summary.',
                  key_findings: [],
                  next_steps: [],
                  unresolved_unknowns: [],
                }),
              },
            ],
          }
        },
      }
    )

    const sampled = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'mode-fingerprint',
      synthesis_mode: 'sampling',
    })
    expect(sampled.ok).toBe(true)
    expect((sampled.data as any).synthesis.resolved_mode).toBe('sampling')

    const deterministic = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'mode-fingerprint',
      synthesis_mode: 'deterministic',
      reuse_digests: true,
    })
    expect(deterministic.ok).toBe(true)
    expect((deterministic.data as any).synthesis.resolved_mode).toBe('deterministic')
    expect((deterministic.data as any).stage_artifacts.final.id).not.toBe(
      (sampled.data as any).stage_artifacts.final.id
    )
    expect(deterministic.warnings).toContain(
      'Skipped persisted final summary digest because its input/source fingerprint is stale.'
    )
    expect(samplingCallCount).toBe(1)
    expect(reportCallCount).toBe(2)
  })

  test('does not reuse summary digests across evidence selectors', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '9'.repeat(64),
      md5: '9'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )

    const selectorA = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'selector-fingerprint',
      synthesis_mode: 'deterministic',
      evidence_scope: 'session',
      evidence_session_tag: 'evidence-a',
    })
    expect(selectorA.ok).toBe(true)

    const selectorB = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'selector-fingerprint',
      synthesis_mode: 'deterministic',
      evidence_scope: 'session',
      evidence_session_tag: 'evidence-b',
      reuse_digests: true,
    })
    expect(selectorB.ok).toBe(true)
    expect((selectorB.data as any).stage_artifacts.final.id).not.toBe(
      (selectorA.data as any).stage_artifacts.final.id
    )
    expect(
      selectorB.warnings?.some((item) => item.includes('input/source fingerprint is stale'))
    ).toBe(true)
    expect(reportCallCount).toBe(2)
  })

  test('invalidates summary digest reuse when new evidence is persisted', async () => {
    const sampleHash = 'a'.repeat(64)
    const sampleId = `sha256:${sampleHash}`
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: 'a'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )

    const beforeEvidence = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'evidence-fingerprint',
      synthesis_mode: 'deterministic',
    })
    expect(beforeEvidence.ok).toBe(true)

    const createdAt = new Date().toISOString()
    const evidenceArtifactId = 'new-strings-evidence-artifact'
    const evidenceContent = JSON.stringify({ strings: ['new-evidence-value'] })
    const evidenceSha256 = createHash('sha256').update(evidenceContent).digest('hex')
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const evidencePath = path.join(workspace.root, 'reports/strings/new-evidence.json')
    fs.mkdirSync(path.dirname(evidencePath), { recursive: true })
    fs.writeFileSync(evidencePath, evidenceContent)
    database.insertArtifact({
      id: evidenceArtifactId,
      sample_id: sampleId,
      type: 'strings_report',
      path: 'reports/strings/new-evidence.json',
      sha256: evidenceSha256,
      mime: 'application/json',
      created_at: createdAt,
    })
    database.insertAnalysisEvidence({
      id: 'new-strings-evidence',
      sample_id: sampleId,
      sample_sha256: sampleHash,
      evidence_family: 'strings',
      backend: 'strings.extract',
      mode: 'full',
      compatibility_marker: 'new-evidence-marker',
      freshness_marker: null,
      provenance_json: JSON.stringify({ tool: 'strings.extract' }),
      metadata_json: '{}',
      result_json: JSON.stringify({ strings: ['new-evidence-value'] }),
      artifact_refs_json: JSON.stringify([
        {
          id: evidenceArtifactId,
          type: 'strings_report',
          path: 'reports/strings/new-evidence.json',
          sha256: evidenceSha256,
        },
      ]),
      created_at: createdAt,
      updated_at: createdAt,
      last_accessed_at: createdAt,
    })

    const afterEvidence = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'evidence-fingerprint',
      synthesis_mode: 'deterministic',
      reuse_digests: true,
    })
    expect(afterEvidence.ok).toBe(true)
    expect((afterEvidence.data as any).stage_artifacts.final.id).not.toBe(
      (beforeEvidence.data as any).stage_artifacts.final.id
    )
    expect(
      afterEvidence.warnings?.some((item) => item.includes('input/source fingerprint is stale'))
    ).toBe(true)
    expect(reportCallCount).toBe(2)
  })

  test('invalidates summary digest reuse when persisted Function state changes', async () => {
    const sampleHash = 'e'.repeat(64)
    const sampleId = `sha256:${sampleHash}`
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: 'e'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )

    const beforeFunction = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'function-state-fingerprint',
      synthesis_mode: 'deterministic',
    })
    expect(beforeFunction.ok).toBe(true)

    database.insertFunction({
      sample_id: sampleId,
      address: '0x401000',
      name: 'new_high_value_function',
      size: 64,
      score: 0.99,
      tags: JSON.stringify(['new']),
      summary: 'Newly persisted function state.',
      caller_count: 0,
      callee_count: 0,
      is_entry_point: 1,
      is_exported: 0,
      callees: '[]',
    })

    const afterFunction = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'function-state-fingerprint',
      synthesis_mode: 'deterministic',
      reuse_digests: true,
    })
    expect(afterFunction.ok).toBe(true)
    expect((afterFunction.data as any).stages.deep.top_functions).toContainEqual(
      expect.objectContaining({ address: '0x401000', name: 'new_high_value_function' })
    )
    expect((afterFunction.data as any).stage_artifacts.final.id).not.toBe(
      (beforeFunction.data as any).stage_artifacts.final.id
    )
    expect(
      afterFunction.warnings?.some((item) => item.includes('input/source fingerprint is stale'))
    ).toBe(true)
    expect(reportCallCount).toBe(2)
  })

  test('refreshes the memoized fingerprint after a rebuilt report persists source artifacts', async () => {
    const sampleHash = '7'.repeat(64)
    const sampleId = `sha256:${sampleHash}`
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: '7'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          const workspace = await workspaceManager.createWorkspace(sampleId)
          const artifactId = `memoized-report-source-${reportCallCount}`
          const relativePath = `reports/explanations/${artifactId}.json`
          const absolutePath = path.join(workspace.root, relativePath)
          const content = JSON.stringify({ report_call: reportCallCount })
          fs.mkdirSync(path.dirname(absolutePath), { recursive: true })
          fs.writeFileSync(absolutePath, content)
          database.insertArtifact({
            id: artifactId,
            sample_id: sampleId,
            type: 'analysis_explanation_graph',
            path: relativePath,
            sha256: createHash('sha256').update(content).digest('hex'),
            mime: 'application/json',
            created_at: new Date().toISOString(),
          })
          return createCompactReportResult(sampleId)
        },
      }
    )
    const summarize = () =>
      handler({
        sample_id: sampleId,
        through_stage: 'triage',
        session_tag: 'memoized-report-source',
        reuse_digests: true,
      })

    const first = await summarize()
    expect(first.ok).toBe(true)
    expect(reportCallCount).toBe(1)

    database.insertFunction({
      sample_id: sampleId,
      address: '0x407000',
      name: 'newly_persisted_function',
      size: 32,
      score: 0.8,
      tags: '[]',
      summary: null,
      caller_count: 0,
      callee_count: 0,
      is_entry_point: 0,
      is_exported: 0,
      callees: '[]',
    })

    const rebuilt = await summarize()
    expect(rebuilt.ok).toBe(true)
    expect(reportCallCount).toBe(2)
    expect((rebuilt.data as any).stage_artifacts.triage.id).not.toBe(
      (first.data as any).stage_artifacts.triage.id
    )
    expect(
      (rebuilt.data as any).stages.triage.reuse_fingerprint.source_artifacts.map(
        (artifact: { id: string }) => artifact.id
      )
    ).toEqual(expect.arrayContaining(['memoized-report-source-1', 'memoized-report-source-2']))

    const reused = await summarize()
    expect(reused.ok).toBe(true)
    expect(reportCallCount).toBe(2)
    expect((reused.data as any).stage_artifacts.triage.id).toBe(
      (rebuilt.data as any).stage_artifacts.triage.id
    )
    expect(database.findArtifactsByType(sampleId, 'analysis_explanation_graph')).toHaveLength(2)
  })

  test('invalidates summary digest reuse when AnalysisRun and RunStage state change', async () => {
    const sampleHash = 'f'.repeat(64)
    const sampleId = `sha256:${sampleHash}`
    const createdAt = '2026-07-14T13:00:00.000Z'
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: 'f'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: createdAt,
      source: 'unit-test',
    })
    database.insertAnalysisRun({
      id: 'fingerprint-run',
      sample_id: sampleId,
      sample_sha256: sampleHash,
      goal: 'triage',
      depth: 'fast',
      backend_policy: 'local',
      compatibility_marker: 'fingerprint-v1',
      pipeline_version: '1',
      sample_size_tier: 'small',
      analysis_budget_profile: 'balanced',
      status: 'running',
      latest_stage: 'fast_profile',
      stage_plan_json: JSON.stringify(['fast_profile']),
      artifact_refs_json: null,
      metadata_json: null,
      created_at: createdAt,
      updated_at: createdAt,
      finished_at: null,
      reused_from_run_id: null,
      last_accessed_at: createdAt,
    })
    database.upsertAnalysisRunStage({
      run_id: 'fingerprint-run',
      stage: 'fast_profile',
      status: 'running',
      execution_state: 'active',
      tool: 'workflow.triage',
      job_id: null,
      result_json: JSON.stringify({ revision: 1 }),
      artifact_refs_json: null,
      coverage_json: null,
      metadata_json: null,
      created_at: createdAt,
      updated_at: createdAt,
      started_at: createdAt,
      finished_at: null,
    })
    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )

    const beforeRunUpdate = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'run-state-fingerprint',
      synthesis_mode: 'deterministic',
    })
    expect(beforeRunUpdate.ok).toBe(true)

    const updatedAt = '2026-07-14T13:01:00.000Z'
    database.updateAnalysisRun('fingerprint-run', {
      status: 'completed',
      updated_at: updatedAt,
      finished_at: updatedAt,
    })
    database.upsertAnalysisRunStage({
      run_id: 'fingerprint-run',
      stage: 'fast_profile',
      status: 'completed',
      execution_state: 'completed',
      tool: 'workflow.triage',
      job_id: null,
      result_json: JSON.stringify({ revision: 2 }),
      artifact_refs_json: null,
      coverage_json: JSON.stringify({ coverage_level: 'quick' }),
      metadata_json: null,
      created_at: createdAt,
      updated_at: updatedAt,
      started_at: createdAt,
      finished_at: updatedAt,
    })

    const afterRunUpdate = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'run-state-fingerprint',
      synthesis_mode: 'deterministic',
      reuse_digests: true,
    })
    expect(afterRunUpdate.ok).toBe(true)
    expect((afterRunUpdate.data as any).stage_artifacts.final.id).not.toBe(
      (beforeRunUpdate.data as any).stage_artifacts.final.id
    )
    expect(
      afterRunUpdate.warnings?.some((item) => item.includes('input/source fingerprint is stale'))
    ).toBe(true)
    expect(reportCallCount).toBe(2)
  })

  test('rejects digest reuse when a fingerprinted source Artifact file is corrupted', async () => {
    const sampleHash = '0'.repeat(64)
    const sampleId = `sha256:${sampleHash}`
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: '0'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    const sourceRelativePath = 'reports/static/fingerprinted-source.json'
    const sourcePath = path.join(workspace.root, sourceRelativePath)
    const sourceContent = JSON.stringify({ finding: 'original' })
    fs.mkdirSync(path.dirname(sourcePath), { recursive: true })
    fs.writeFileSync(sourcePath, sourceContent)
    database.insertArtifact({
      id: 'fingerprinted-source-artifact',
      sample_id: sampleId,
      type: 'static_behavior_profile',
      path: sourceRelativePath,
      sha256: createHash('sha256').update(sourceContent).digest('hex'),
      mime: 'application/json',
      created_at: new Date().toISOString(),
    })
    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )

    const beforeCorruption = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'source-integrity-fingerprint',
      synthesis_mode: 'deterministic',
    })
    expect(beforeCorruption.ok).toBe(true)
    fs.appendFileSync(sourcePath, '\ncorrupted')

    const afterCorruption = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      session_tag: 'source-integrity-fingerprint',
      synthesis_mode: 'deterministic',
      reuse_digests: true,
    })
    expect(afterCorruption.ok).toBe(true)
    expect((afterCorruption.data as any).stage_artifacts.final.id).not.toBe(
      (beforeCorruption.data as any).stage_artifacts.final.id
    )
    expect(afterCorruption.warnings).toContain(
      'Summary digest source artifact fingerprinted-source-artifact failed integrity validation: actual SHA-256 does not match the artifact record.'
    )
    expect(
      afterCorruption.warnings?.some((item) =>
        item.includes('source artifact integrity validation failed')
      )
    ).toBe(true)
    expect(reportCallCount).toBe(2)
  })

  test('surfaces source Artifact integrity failures during initial digest persistence', async () => {
    const sampleHash = 'a'.repeat(64)
    const sampleId = `sha256:${sampleHash}`
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: 'a'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    database.insertArtifact({
      id: 'missing-source-artifact',
      sample_id: sampleId,
      type: 'static_behavior_profile',
      path: 'reports/static/missing-source.json',
      sha256: 'b'.repeat(64),
      mime: 'application/json',
      created_at: new Date().toISOString(),
    })
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      { reportSummarizeHandler: async () => createCompactReportResult(sampleId) }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'triage',
      session_tag: 'initial-source-integrity-failure',
    })

    expect(result.ok).toBe(true)
    expect(
      result.warnings?.some((item) =>
        item.includes(
          'Summary digest source artifact missing-source-artifact failed integrity validation:'
        )
      )
    ).toBe(true)
    expect((result.data as any).stages.triage.reuse_fingerprint.source_integrity_valid).toBe(false)
  })

  test('should produce deterministic final synthesis when sampling is unavailable', async () => {
    const sampleId = 'sha256:' + '3'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '3'.repeat(64),
      md5: '3'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => createCompactReportResult(sampleId),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.synthesis.resolved_mode).toBe('deterministic')
    expect(data.explanation_graphs[0].graph_type).toBe('runtime_stage')
    expect(data.explanation_artifacts[0].type).toBe('analysis_explanation_graph')
    expect(data.stages.final.executive_summary).toContain('Compact triage summary')
    expect(data.stages.final.next_steps.length).toBeGreaterThan(0)
    expect(data.known_findings.length).toBeGreaterThan(0)
    expect(Array.isArray(data.suspected_findings)).toBe(true)
    expect(Array.isArray(data.unverified_areas)).toBe(true)
  })

  test('should consume a bounded Claim Ledger context without promoting it to evidence', async () => {
    const sampleId = 'sha256:' + '6'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '6'.repeat(64),
      md5: '6'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const initialClaimIds = Array.from({ length: 10 }, (_, index) => `claim-open-question-${index}`)
    const claimResult = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: sampleId,
      session_tag: 'summary-context',
      producer: { kind: 'llm', client_name: 'unit-test', model_name: 'test-model' },
      claims: initialClaimIds.map((claimId, index) => ({
        claim_id: claimId,
        category: index < 2 ? 'open_question' : 'hypothesis',
        subject: index < 2 ? `Open question ${index}` : `Hypothesis ${index}`,
        statement:
          index < 2
            ? `Does behavior ${index} execute at runtime?`
            : index === 2
              ? 'H'.repeat(5000)
              : `Behavior ${index} may execute at runtime.`,
        status: 'inferred',
      })),
    })
    expect(claimResult.ok).toBe(true)
    const claimArtifact = (claimResult.data as any).artifact
    const caseArtifact = await persistAnalysisCaseStateArtifact(workspaceManager, database, {
      schema: ANALYSIS_CASE_STATE_SCHEMA,
      schema_version: 1,
      artifact_role: 'context_only',
      sample_id: sampleId,
      case_id: 'case-summary-context',
      revision: 1,
      parent_artifact_id: null,
      created_at: new Date().toISOString(),
      session_tag: 'summary-context',
      objective: 'O'.repeat(2000),
      decisions: Array.from({ length: 7 }, (_, index) => `Decision ${index}`),
      open_questions: Array.from(
        { length: 10 },
        (_, index) => `Case question ${index}: what happens next?`
      ),
      attempted_actions: Array.from({ length: 7 }, (_, index) => ({
        tool: `analysis.tool.${index}`,
        args_fingerprint: `${index}`.repeat(64),
        outcome: index % 2 === 0 ? ('completed' as const) : ('failed' as const),
        result_artifacts: [],
        summary: `Attempt ${index} summary.`,
      })),
      active_claim_ids: initialClaimIds,
      pinned_artifacts: [],
      next_actions: Array.from({ length: 7 }, (_, index) => `Next action ${index}`),
      producer: { kind: 'external_agent', agent_name: 'unit-test' },
    })

    let reportCallCount = 0
    const contextOnlyReportRefs = [
      {
        id: 'context-summary-final',
        type: 'summary_final_digest',
        path: 'reports/summary/default/final.json',
        sha256: 'c'.repeat(64),
      },
      {
        id: 'context-report-summary',
        type: 'report_summary',
        path: 'reports/summary/default/report.json',
        sha256: 'd'.repeat(64),
      },
    ]
    const deterministicEvidenceRef = {
      id: 'deterministic-static-evidence',
      type: 'static_behavior_profile',
      path: 'reports/static/behavior.json',
      sha256: 'e'.repeat(64),
    }
    const reportSummarizeHandler = async (): Promise<WorkerResult> => {
      reportCallCount += 1
      const report = createCompactReportResult(sampleId)
      const data = report.data as any
      data.artifact_refs.supporting = [
        claimArtifact,
        caseArtifact,
        ...contextOnlyReportRefs,
        deterministicEvidenceRef,
      ]
      return report
    }
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      { reportSummarizeHandler }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      force_refresh: true,
    })

    expect(result.ok).toBe(true)
    expect(() => WorkflowSummarizeOutputSchema.parse(result)).not.toThrow()
    const data = result.data as any
    expect(data.claim_context).toMatchObject({
      artifact_role: 'context_only',
      active_claim_count: 10,
      included_claim_count: 8,
      truncated: true,
    })
    expect(data.claim_context.claims).toHaveLength(8)
    expect(data.claim_context.claims.every((claim: any) => claim.statement.length <= 1200)).toBe(
      true
    )
    expect(data.case_context).toMatchObject({
      artifact_role: 'context_only',
      available: true,
      case_id: 'case-summary-context',
      revision: 1,
      decision_count: 7,
      open_question_count: 10,
      attempted_action_count: 7,
      next_action_count: 7,
      active_claim_count: 10,
      pinned_artifact_count: 0,
      truncated: true,
    })
    expect(data.case_context.decisions).toHaveLength(5)
    expect(data.case_context.objective).toHaveLength(1200)
    expect(data.case_context.open_questions).toHaveLength(8)
    expect(data.case_context.attempted_actions).toHaveLength(5)
    expect(data.case_context.next_actions).toHaveLength(5)
    expect(data.case_context.attempted_actions[0]).not.toContain('args_fingerprint')
    expect(data.review_required).toBe(true)
    expect(data.unresolved_questions).toHaveLength(8)
    expect(data.unresolved_questions).toContain('Does behavior 0 execute at runtime?')
    expect(data.unresolved_questions).toContain('Case question 0: what happens next?')
    expect(data.stages.final.claim_context).toEqual(data.claim_context)
    expect(data.stages.final.case_context).toEqual(data.case_context)
    expect(data.stages.final.review_required).toBe(true)
    expect(data.stages.final.unresolved_questions).toEqual(data.unresolved_questions)
    for (const stage of ['triage', 'static', 'deep', 'final']) {
      expect(
        data.stages[stage].source_artifact_refs.some((ref: any) =>
          [
            'analysis_claim_set',
            'analysis_case_state',
            'summary_final_digest',
            'report_summary',
          ].includes(ref.type)
        )
      ).toBe(false)
      expect(data.stages[stage].source_artifact_refs).toContainEqual(deterministicEvidenceRef)
    }
    expect(data.stages.triage.evidence).not.toContain('Does behavior 0 execute at runtime?')
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persistedFinal = JSON.parse(
      fs.readFileSync(path.join(workspace.root, data.stage_artifacts.final.path), 'utf8')
    )
    expect(persistedFinal.claim_context).toEqual(data.claim_context)
    expect(persistedFinal.case_context).toEqual(data.case_context)

    const legacyFinal = structuredClone(persistedFinal)
    delete legacyFinal.reuse_fingerprint
    delete legacyFinal.claim_context
    delete legacyFinal.case_context
    delete legacyFinal.review_required
    delete legacyFinal.unresolved_questions
    const parsedLegacyFinal = FinalStageDigestSchema.parse(legacyFinal)
    expect(parsedLegacyFinal.claim_context).toMatchObject({
      artifact_role: 'context_only',
      marker: 'none',
      active_claim_count: 0,
    })
    expect(parsedLegacyFinal.case_context).toMatchObject({
      artifact_role: 'context_only',
      marker: 'none',
      available: false,
    })
    expect(parsedLegacyFinal.review_required).toBe(false)
    expect(parsedLegacyFinal.unresolved_questions).toEqual([])
    expect(parsedLegacyFinal.reuse_fingerprint).toBeUndefined()

    const lateClaim = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: sampleId,
      session_tag: 'summary-context',
      producer: { kind: 'llm', client_name: 'unit-test', model_name: 'test-model' },
      claims: [
        {
          claim_id: 'claim-late-question',
          category: 'open_question',
          subject: 'Late question',
          statement: 'Was the late-discovered branch executed?',
          status: 'inferred',
        },
      ],
    })
    expect(lateClaim.ok).toBe(true)
    await persistAnalysisCaseStateArtifact(workspaceManager, database, {
      schema: ANALYSIS_CASE_STATE_SCHEMA,
      schema_version: 1,
      artifact_role: 'context_only',
      sample_id: sampleId,
      case_id: 'case-summary-context',
      revision: 2,
      parent_artifact_id: caseArtifact.id,
      created_at: new Date().toISOString(),
      session_tag: 'summary-context',
      objective: 'O'.repeat(2000),
      decisions: Array.from({ length: 7 }, (_, index) => `Decision ${index}`),
      open_questions: Array.from(
        { length: 10 },
        (_, index) => `Case question ${index}: what happens next?`
      ),
      attempted_actions: Array.from({ length: 7 }, (_, index) => ({
        tool: `analysis.tool.${index}`,
        args_fingerprint: `${index}`.repeat(64),
        outcome: index % 2 === 0 ? ('completed' as const) : ('failed' as const),
        result_artifacts: [],
        summary: `Attempt ${index} summary.`,
      })),
      active_claim_ids: [...initialClaimIds, 'claim-late-question'],
      pinned_artifacts: [],
      next_actions: Array.from({ length: 7 }, (_, index) => `Next action ${index}`),
      producer: { kind: 'external_agent', agent_name: 'unit-test' },
    })
    const refreshed = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      reuse_digests: true,
    })
    expect(refreshed.ok).toBe(true)
    const refreshedData = refreshed.data as any
    expect(refreshedData.claim_context.active_claim_count).toBe(11)
    expect(refreshedData.unresolved_questions).toContain('Was the late-discovered branch executed?')
    expect(refreshedData.stage_artifacts.final.id).not.toBe(data.stage_artifacts.final.id)
    expect(refreshed.warnings).toContain(
      'Skipped persisted final summary digest because its context marker is stale.'
    )
    expect(reportCallCount).toBe(2)
  })

  test('should isolate final summaries and digest reuse by selected case', async () => {
    const sampleId = 'sha256:' + '7'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '7'.repeat(64),
      md5: '7'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: '2026-07-14T10:00:00.000Z',
      source: 'unit-test',
    })

    const claimsHandler = createAnalysisClaimsApplyHandler(workspaceManager, database)
    const seededClaims = await claimsHandler({
      sample_id: sampleId,
      producer: { kind: 'llm', model_name: 'unit-test' },
      claims: [
        {
          claim_id: 'claim-summary-case-a',
          category: 'open_question',
          subject: 'Case A summary question',
          statement: 'Case A summary must retain only this Claim.',
          status: 'inferred',
        },
        {
          claim_id: 'claim-summary-case-b',
          category: 'open_question',
          subject: 'Case B summary question',
          statement: 'Case B summary must retain only this Claim.',
          status: 'inferred',
        },
      ],
    })
    expect(seededClaims.ok).toBe(true)

    const persistCase = async (caseId: string, activeClaimId: string, createdAt: string) =>
      await persistAnalysisCaseStateArtifact(workspaceManager, database, {
        schema: ANALYSIS_CASE_STATE_SCHEMA,
        schema_version: 1,
        artifact_role: 'context_only',
        sample_id: sampleId,
        case_id: caseId,
        revision: 1,
        parent_artifact_id: null,
        created_at: createdAt,
        session_tag: 'case-isolation',
        objective: `Investigate ${caseId} only.`,
        decisions: [`Decision for ${caseId}.`],
        open_questions: [`Question for ${caseId}?`],
        attempted_actions: [],
        active_claim_ids: [activeClaimId],
        pinned_artifacts: [],
        next_actions: [`Next action for ${caseId}.`],
        producer: { kind: 'external_agent', agent_name: 'unit-test' },
      })

    await persistCase('case-a', 'claim-summary-case-a', '2026-07-14T10:01:00.000Z')
    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )

    const caseAFirst = await handler({
      sample_id: sampleId,
      case_id: 'case-a',
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-isolation',
    })
    expect(caseAFirst.ok).toBe(true)
    expect((caseAFirst.data as any).case_context).toMatchObject({
      case_id: 'case-a',
      objective: 'Investigate case-a only.',
    })
    expect((caseAFirst.data as any).claim_context.claims).toEqual([
      expect.objectContaining({
        claim_id: 'claim-summary-case-a',
        statement: 'Case A summary must retain only this Claim.',
      }),
    ])
    const caseAArtifactId = (caseAFirst.data as any).stage_artifacts.final.id
    expect(reportCallCount).toBe(1)

    await persistCase('case-b', 'claim-summary-case-b', '2026-07-14T10:02:00.000Z')
    const ambiguous = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-isolation',
    })
    expect(ambiguous.ok).toBe(false)
    expect(ambiguous.errors?.join('\n')).toMatch(/multiple analysis cases.*case_id/i)

    const caseAReused = await handler({
      sample_id: sampleId,
      case_id: 'case-a',
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-isolation',
      reuse_digests: true,
    })
    expect(caseAReused.ok).toBe(true)
    expect((caseAReused.data as any).stage_artifacts.final.id).toBe(caseAArtifactId)
    expect((caseAReused.data as any).case_context.case_id).toBe('case-a')
    expect((caseAReused.data as any).synthesis.used_existing_stage_artifacts).toBe(true)
    expect(reportCallCount).toBe(1)

    const caseBFirst = await handler({
      sample_id: sampleId,
      case_id: 'case-b',
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-isolation',
      reuse_digests: true,
    })
    expect(caseBFirst.ok).toBe(true)
    expect((caseBFirst.data as any).case_context).toMatchObject({
      case_id: 'case-b',
      objective: 'Investigate case-b only.',
    })
    expect((caseBFirst.data as any).claim_context.claims).toEqual([
      expect.objectContaining({
        claim_id: 'claim-summary-case-b',
        statement: 'Case B summary must retain only this Claim.',
      }),
    ])
    expect((caseBFirst.data as any).stage_artifacts.final.id).not.toBe(caseAArtifactId)
    expect(caseBFirst.warnings).toContain(
      'Skipped persisted final summary digest because its context marker is stale.'
    )
    expect(reportCallCount).toBe(2)

    const revisedCaseBClaim = await claimsHandler({
      sample_id: sampleId,
      producer: { kind: 'llm', model_name: 'unit-test-v2' },
      claims: [
        {
          claim_id: 'claim-summary-case-b',
          category: 'open_question',
          subject: 'Case B revised summary question',
          statement: 'Revised Case B Claim must not invalidate or contaminate Case A.',
          status: 'inferred',
        },
      ],
    })
    expect(revisedCaseBClaim.ok).toBe(true)

    const caseAReusedAfterB = await handler({
      sample_id: sampleId,
      case_id: 'case-a',
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-isolation',
      reuse_digests: true,
    })
    expect(caseAReusedAfterB.ok).toBe(true)
    expect((caseAReusedAfterB.data as any).stage_artifacts.final.id).toBe(caseAArtifactId)
    expect((caseAReusedAfterB.data as any).case_context.case_id).toBe('case-a')
    expect(JSON.stringify((caseAReusedAfterB.data as any).claim_context)).not.toContain(
      'Revised Case B Claim must not invalidate or contaminate Case A.'
    )
    expect(reportCallCount).toBe(2)

    const caseBRefreshed = await handler({
      sample_id: sampleId,
      case_id: 'case-b',
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-isolation',
      reuse_digests: true,
    })
    expect(caseBRefreshed.ok).toBe(true)
    expect((caseBRefreshed.data as any).stage_artifacts.final.id).not.toBe(
      (caseBFirst.data as any).stage_artifacts.final.id
    )
    expect((caseBRefreshed.data as any).claim_context.claims).toEqual([
      expect.objectContaining({
        claim_id: 'claim-summary-case-b',
        statement: 'Revised Case B Claim must not invalidate or contaminate Case A.',
      }),
    ])
    expect(reportCallCount).toBe(3)
  })

  test('preserves a Case-active Claim and final reuse through 65 cross-Case ledger revisions', async () => {
    const sampleId = 'sha256:' + '9'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '9'.repeat(64),
      md5: '9'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: '2026-07-14T10:30:00.000Z',
      source: 'unit-test',
    })
    const [caseAClaimArtifact] = await seedAnalysisClaimLedgerFixture({
      workspaceManager,
      database,
      sampleId,
      revisionCount: 1,
      artifactIdPrefix: 'summary-churn-65',
      createdAtBase: '2026-07-14T10:30:00.000Z',
      claimForRevision: () => ({
        claim_id: 'claim-summary-case-a-old',
        subject: 'Case A retained question',
        statement: 'Case A question must survive unrelated Case B Claim churn.',
      }),
    })
    await persistAnalysisCaseStateArtifact(workspaceManager, database, {
      schema: ANALYSIS_CASE_STATE_SCHEMA,
      schema_version: 1,
      artifact_role: 'context_only',
      sample_id: sampleId,
      case_id: 'case-a-churn',
      revision: 1,
      parent_artifact_id: null,
      created_at: '2026-07-14T10:32:00.000Z',
      session_tag: 'case-a-churn',
      objective: 'Keep Case A isolated from Case B Claim churn.',
      decisions: [],
      open_questions: [],
      attempted_actions: [],
      active_claim_ids: ['claim-summary-case-a-old'],
      pinned_artifacts: [],
      next_actions: [],
      producer: { kind: 'external_agent', agent_name: 'unit-test' },
    })

    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )
    const first = await handler({
      sample_id: sampleId,
      case_id: 'case-a-churn',
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-a-churn',
      reuse_digests: true,
    })
    expect(first.ok).toBe(true)
    expect((first.data as any).claim_context.claims).toEqual([
      expect.objectContaining({
        claim_id: 'claim-summary-case-a-old',
        statement: 'Case A question must survive unrelated Case B Claim churn.',
      }),
    ])
    const firstMarker = (first.data as any).claim_context.marker
    const firstFinalArtifactId = (first.data as any).stage_artifacts.final.id

    await seedAnalysisClaimLedgerFixture({
      workspaceManager,
      database,
      sampleId,
      revisionCount: 64,
      startRevision: 2,
      parentArtifactId: caseAClaimArtifact.id,
      artifactIdPrefix: 'summary-churn-65',
      createdAtBase: '2026-07-14T10:30:00.000Z',
      claimForRevision: (revision) => ({
        claim_id: 'claim-summary-case-b-churn',
        subject: 'Case B churn',
        statement: `Case B unrelated Claim revision ${revision}.`,
      }),
    })

    const afterChurn = await handler({
      sample_id: sampleId,
      case_id: 'case-a-churn',
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-a-churn',
      reuse_digests: true,
    })
    expect(afterChurn.ok).toBe(true)
    expect((afterChurn.data as any).claim_context.marker).toBe(firstMarker)
    expect((afterChurn.data as any).claim_context.claims).toEqual(
      (first.data as any).claim_context.claims
    )
    expect((afterChurn.data as any).unresolved_questions).toEqual(
      (first.data as any).unresolved_questions
    )
    expect((afterChurn.data as any).stage_artifacts.final.id).toBe(firstFinalArtifactId)
    expect(afterChurn.warnings?.join('\n') || '').not.toMatch(
      /scan is incomplete|could not be resolved|withheld/i
    )
    expect(reportCallCount).toBe(1)
  })

  test('invalidates final reuse when Claim Ledger integrity degrades', async () => {
    const sampleId = 'sha256:' + 'b'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: '2026-07-14T11:00:00.000Z',
      source: 'unit-test',
    })

    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )

    const first = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'claim-integrity-review',
    })
    expect(first.ok).toBe(true)
    expect((first.data as any).claim_context.marker).toBe('none')
    expect((first.data as any).review_required).toBe(false)

    database.insertArtifact({
      id: 'unreadable-claim-set',
      sample_id: sampleId,
      type: 'analysis_claim_set',
      path: 'reports/claims/missing/claim_set.json',
      sha256: 'e'.repeat(64),
      mime: 'application/json',
      created_at: '2026-07-14T11:01:00.000Z',
    })

    const degraded = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'claim-integrity-review',
      reuse_digests: true,
    })
    expect(degraded.ok).toBe(true)
    expect((degraded.data as any).claim_context.marker).not.toBe(
      (first.data as any).claim_context.marker
    )
    expect((degraded.data as any).review_required).toBe(true)
    expect((degraded.data as any).stage_artifacts.final.id).not.toBe(
      (first.data as any).stage_artifacts.final.id
    )
    expect(degraded.warnings).toContain(
      'Claim Ledger context: Skipped unreadable claim set artifact: unreadable-claim-set'
    )
    expect(degraded.warnings?.some((item) => item.includes('context marker is stale'))).toBe(true)
    expect(reportCallCount).toBe(2)
  })

  test('does not reuse a final digest when an unreadable Claim head appears after review was already required', async () => {
    const sampleId = 'sha256:' + '1'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '1'.repeat(64),
      md5: '1'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: '2026-07-14T11:15:00.000Z',
      source: 'unit-test',
    })
    const claimResult = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: sampleId,
      producer: { kind: 'llm', model_name: 'unit-test' },
      claims: [
        {
          claim_id: 'claim-review-already-required',
          category: 'open_question',
          subject: 'Existing review boundary',
          statement: 'This inferred Claim already requires review before integrity degrades.',
          status: 'inferred',
        },
      ],
    })
    expect(claimResult.ok).toBe(true)

    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )
    const request = {
      sample_id: sampleId,
      through_stage: 'final' as const,
      synthesis_mode: 'deterministic' as const,
      session_tag: 'claim-integrity-marker',
      reuse_digests: true,
    }
    const first = await handler(request)
    expect(first.ok).toBe(true)
    expect((first.data as any).review_required).toBe(true)
    expect((first.data as any).claim_context.claims).toEqual([
      expect.objectContaining({ claim_id: 'claim-review-already-required' }),
    ])

    database.insertArtifact({
      id: 'unreadable-claim-head-after-review',
      sample_id: sampleId,
      type: 'analysis_claim_set',
      path: 'reports/claims/missing/unreadable-head.json',
      sha256: 'f'.repeat(64),
      mime: 'application/json',
      created_at: '2099-07-14T11:16:00.000Z',
    })

    const degraded = await handler(request)
    expect(degraded.ok).toBe(true)
    expect((degraded.data as any).review_required).toBe(true)
    expect((degraded.data as any).claim_context.marker).not.toBe(
      (first.data as any).claim_context.marker
    )
    expect((degraded.data as any).stage_artifacts.final.id).not.toBe(
      (first.data as any).stage_artifacts.final.id
    )
    expect(degraded.warnings).toContain(
      'Claim Ledger context: Skipped unreadable claim set artifact: unreadable-claim-head-after-review'
    )
    expect(degraded.warnings).toContain(
      'Skipped persisted final summary digest because its context marker is stale.'
    )
    expect(reportCallCount).toBe(2)
  })

  test('requires review when the only Case state is unreadable and no case_id was requested', async () => {
    const sampleId = 'sha256:' + 'd'.repeat(64)
    const unassignedClaimStatement =
      'This sample-level Claim must be withheld when the only Case cannot be loaded.'
    database.insertSample({
      id: sampleId,
      sha256: 'd'.repeat(64),
      md5: 'd'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: '2026-07-14T11:30:00.000Z',
      source: 'unit-test',
    })
    const caseArtifact = await persistAnalysisCaseStateArtifact(workspaceManager, database, {
      schema: ANALYSIS_CASE_STATE_SCHEMA,
      schema_version: 1,
      artifact_role: 'context_only',
      sample_id: sampleId,
      case_id: 'case-only',
      revision: 1,
      parent_artifact_id: null,
      created_at: '2026-07-14T11:31:00.000Z',
      session_tag: 'case-unreadable-review',
      objective: 'Investigate the only Case.',
      decisions: [],
      open_questions: [],
      attempted_actions: [],
      active_claim_ids: [],
      pinned_artifacts: [],
      next_actions: [],
      producer: { kind: 'external_agent', agent_name: 'unit-test' },
    })
    const claimResult = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: sampleId,
      producer: { kind: 'llm', model_name: 'unit-test' },
      claims: [
        {
          claim_id: 'claim-unassigned-to-unreadable-case',
          category: 'open_question',
          subject: 'Unassigned sample-level Claim',
          statement: unassignedClaimStatement,
          status: 'inferred',
        },
      ],
    })
    expect(claimResult.ok).toBe(true)

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      { reportSummarizeHandler: async () => createCompactReportResult(sampleId) }
    )
    const before = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-unreadable-review',
    })
    expect(before.ok).toBe(true)
    expect((before.data as any).case_context).toMatchObject({
      available: true,
      case_id: 'case-only',
    })
    expect((before.data as any).claim_context.active_claim_count).toBe(0)
    expect(JSON.stringify(before.data)).not.toContain(unassignedClaimStatement)
    expect((before.data as any).review_required).toBe(false)

    const workspace = await workspaceManager.getWorkspace(sampleId)
    fs.appendFileSync(path.join(workspace.root, caseArtifact.path), '\ncorrupted')

    const degraded = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'deterministic',
      session_tag: 'case-unreadable-review',
      reuse_digests: true,
    })
    expect(degraded.ok).toBe(true)
    expect((degraded.data as any).case_context).toMatchObject({
      available: false,
      case_id: null,
    })
    expect((degraded.data as any).claim_context.active_claim_count).toBe(0)
    expect(JSON.stringify(degraded.data)).not.toContain(unassignedClaimStatement)
    expect((degraded.data as any).review_required).toBe(true)
    expect(degraded.warnings).toContain(
      `Case State context: Skipped case state with SHA-256 mismatch: ${caseArtifact.id}`
    )
  })

  test('requires review for selected Case corruption without contaminating another Case', async () => {
    const sampleId = 'sha256:' + 'c'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: 'c'.repeat(64),
      md5: 'c'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: '2026-07-14T12:00:00.000Z',
      source: 'unit-test',
    })

    const claimResult = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: sampleId,
      producer: { kind: 'llm', model_name: 'unit-test' },
      claims: [
        {
          claim_id: 'claim-case-b-integrity',
          category: 'open_question',
          subject: 'Case B integrity question',
          statement: 'This Claim must be withheld when the selected Case history is untrusted.',
          status: 'inferred',
        },
      ],
    })
    expect(claimResult.ok).toBe(true)

    const persistCase = async (
      caseId: string,
      revision: number,
      parentArtifactId: string | null,
      createdAt: string,
      activeClaimIds: string[] = []
    ) =>
      await persistAnalysisCaseStateArtifact(workspaceManager, database, {
        schema: ANALYSIS_CASE_STATE_SCHEMA,
        schema_version: 1,
        artifact_role: 'context_only',
        sample_id: sampleId,
        case_id: caseId,
        revision,
        parent_artifact_id: parentArtifactId,
        created_at: createdAt,
        session_tag: 'case-integrity-review',
        objective: `Investigate ${caseId}.`,
        decisions: [],
        open_questions: [],
        attempted_actions: [],
        active_claim_ids: activeClaimIds,
        pinned_artifacts: [],
        next_actions: [],
        producer: { kind: 'external_agent', agent_name: 'unit-test' },
      })

    await persistCase('case-a', 1, null, '2026-07-14T12:01:00.000Z')
    const caseBRevision1 = await persistCase('case-b', 1, null, '2026-07-14T12:02:00.000Z', [
      'claim-case-b-integrity',
    ])
    await persistCase('case-b', 2, caseBRevision1.id, '2026-07-14T12:03:00.000Z', [
      'claim-case-b-integrity',
    ])

    let reportCallCount = 0
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => {
          reportCallCount += 1
          return createCompactReportResult(sampleId)
        },
      }
    )
    const summarizeCase = async (caseId: string) =>
      await handler({
        sample_id: sampleId,
        case_id: caseId,
        through_stage: 'final',
        synthesis_mode: 'deterministic',
        session_tag: 'case-integrity-review',
        reuse_digests: true,
      })

    const caseABefore = await summarizeCase('case-a')
    const caseBBefore = await summarizeCase('case-b')
    expect(caseABefore.ok).toBe(true)
    expect(caseBBefore.ok).toBe(true)
    expect((caseABefore.data as any).review_required).toBe(false)
    expect((caseBBefore.data as any).review_required).toBe(true)
    expect((caseBBefore.data as any).claim_context.claims).toEqual([
      expect.objectContaining({ claim_id: 'claim-case-b-integrity' }),
    ])

    const workspace = await workspaceManager.getWorkspace(sampleId)
    fs.appendFileSync(path.join(workspace.root, caseBRevision1.path), '\ncorrupted')

    const caseAAfter = await summarizeCase('case-a')
    expect(caseAAfter.ok).toBe(true)
    expect((caseAAfter.data as any).review_required).toBe(false)
    expect((caseAAfter.data as any).stage_artifacts.final.id).toBe(
      (caseABefore.data as any).stage_artifacts.final.id
    )
    expect((caseAAfter.data as any).case_context.marker).toBe(
      (caseABefore.data as any).case_context.marker
    )
    expect(caseAAfter.warnings).toContain(
      `Case State context: Skipped case state with SHA-256 mismatch: ${caseBRevision1.id}`
    )

    const caseBAfter = await summarizeCase('case-b')
    expect(caseBAfter.ok).toBe(true)
    expect((caseBAfter.data as any).case_context.revision).toBe(2)
    expect((caseBAfter.data as any).review_required).toBe(true)
    expect((caseBAfter.data as any).claim_context.active_claim_count).toBe(0)
    expect((caseBAfter.data as any).claim_context.claims).toEqual([])
    expect((caseBAfter.data as any).case_context.marker).not.toBe(
      (caseBBefore.data as any).case_context.marker
    )
    expect((caseBAfter.data as any).stage_artifacts.final.id).not.toBe(
      (caseBBefore.data as any).stage_artifacts.final.id
    )
    expect(caseBAfter.warnings).toContain(
      'Skipped persisted final summary digest because its context marker is stale.'
    )
    expect(reportCallCount).toBe(3)
  })

  test('should use client-mediated sampling for final synthesis when available', async () => {
    const sampleId = 'sha256:' + '4'.repeat(64)
    const claimOnlyFinding = 'Claim-only hypothesis must not become an evidence-backed finding.'
    database.insertSample({
      id: sampleId,
      sha256: '4'.repeat(64),
      md5: '4'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const claimResult = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: sampleId,
      producer: { kind: 'llm', model_name: 'test-model' },
      claims: [
        {
          claim_id: 'claim-sampling-boundary',
          category: 'hypothesis',
          subject: 'Sampling boundary',
          statement: claimOnlyFinding,
          status: 'inferred',
        },
      ],
    })
    expect(claimResult.ok).toBe(true)

    let capturedSamplingRequest: any = null
    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => createCompactReportResult(sampleId),
        clientCapabilitiesProvider: () => ({ sampling: {} }),
        samplingRequester: async (request) => {
          capturedSamplingRequest = request
          return {
            model: 'gpt-5.4',
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  executive_summary: 'Sampling executive summary.',
                  analyst_summary: 'Sampling analyst summary.',
                  key_findings: [claimOnlyFinding],
                  next_steps: ['step-a'],
                  unresolved_unknowns: ['unknown-a'],
                }),
              },
            ],
          }
        },
      }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'sampling',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.synthesis.resolved_mode).toBe('sampling')
    expect(data.synthesis.model_name).toBe('gpt-5.4')
    expect(data.stages.final.executive_summary).toBe('Sampling executive summary.')
    expect(capturedSamplingRequest.messages[0].content.text).toContain('analysis_context')
    expect(capturedSamplingRequest.messages[0].content.text).toContain('context_only')
    expect(data.stages.final.claim_context.claims[0].statement).toBe(claimOnlyFinding)
    expect(data.stages.final.key_findings).not.toContain(claimOnlyFinding)
    expect(data.stages.final.known_findings).not.toContain(claimOnlyFinding)
    expect(data.stages.final.review_required).toBe(true)
  })

  test('rejects sampling payloads that attempt to inject source artifact references', async () => {
    const sampleId = 'sha256:' + '7'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '7'.repeat(64),
      md5: '7'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => createCompactReportResult(sampleId),
        clientCapabilitiesProvider: () => ({ sampling: {} }),
        samplingRequester: async () => ({
          model: 'gpt-5.4',
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                executive_summary: 'Attempted source injection.',
                analyst_summary: 'Attempted source injection.',
                key_findings: ['Case context presented as observed evidence.'],
                next_steps: [],
                unresolved_unknowns: [],
                source_artifact_refs: [
                  {
                    id: 'forged-case-ref',
                    type: 'analysis_case_state',
                    path: 'reports/cases/forged.json',
                    sha256: 'f'.repeat(64),
                  },
                ],
              }),
            },
          ],
        }),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'sampling',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.synthesis.resolved_mode).toBe('deterministic')
    expect(data.stages.final.executive_summary).not.toBe('Attempted source injection.')
    expect(data.stages.final.key_findings).not.toContain(
      'Case context presented as observed evidence.'
    )
    expect(data.stages.final.source_artifact_refs).not.toContainEqual(
      expect.objectContaining({ id: 'forged-case-ref' })
    )
    expect(
      result.warnings?.some((item) => item.includes('Falling back to deterministic synthesis'))
    ).toBe(true)
  })

  test('should fall back to deterministic synthesis when sampling response is invalid', async () => {
    const sampleId = 'sha256:' + '5'.repeat(64)
    database.insertSample({
      id: sampleId,
      sha256: '5'.repeat(64),
      md5: '5'.repeat(32),
      size: 4096,
      file_type: 'PE',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const handler = createWorkflowSummarizeHandler(
      workspaceManager,
      database,
      cacheManager,
      undefined,
      {
        reportSummarizeHandler: async () => createCompactReportResult(sampleId),
        clientCapabilitiesProvider: () => ({ sampling: {} }),
        samplingRequester: async () => ({
          model: 'gpt-5.4',
          content: [
            {
              type: 'text',
              text: 'not-json',
            },
          ],
        }),
      }
    )

    const result = await handler({
      sample_id: sampleId,
      through_stage: 'final',
      synthesis_mode: 'sampling',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.synthesis.resolved_mode).toBe('deterministic')
    expect(
      result.warnings?.some((item) => item.includes('Falling back to deterministic synthesis'))
    ).toBe(true)
  })
})
