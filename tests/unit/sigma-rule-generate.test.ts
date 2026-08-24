import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import os from 'os'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createSigmaRuleGenerateHandler,
  sigmaRuleGenerateToolDefinition,
} from '../../src/plugins/threat-intel/tools/sigma-rule-generate.js'

describe('sigma.rule.generate tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleHash = '9'.repeat(64)
  const sampleId = `sha256:${sampleHash}`

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-sigma-rule-generate-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: sampleId,
      sha256: sampleHash,
      md5: '9'.repeat(32),
      size: 12288,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    const now = new Date().toISOString()
    database.insertAnalysisEvidence({
      id: 'analysis-evidence-sigma-source',
      sample_id: sampleId,
      sample_sha256: sampleHash,
      evidence_family: 'strings_imports',
      backend: 'unit-test',
      mode: 'static',
      compatibility_marker: 'unit-test-sigma-source',
      freshness_marker: null,
      provenance_json: JSON.stringify({ tool: 'unit-test' }),
      metadata_json: null,
      result_json: JSON.stringify({
        strings: [
          'http://sigma.example.net/c2',
          'sigma.example.net',
          '192.0.2.10',
          'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          'C:\\Users\\Public\\dropper.exe',
          'dropper.exe',
        ],
        imports: [
          { dll: 'kernel32.dll', functions: ['CreateProcessW'] },
          { dll: 'winhttp.dll', functions: ['WinHttpOpen'] },
        ],
      }),
      artifact_refs_json: null,
      created_at: now,
      updated_at: now,
      last_accessed_at: null,
    })
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore cleanup races in failed tests
    }
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('should return error for unknown sample', async () => {
    const result = await createSigmaRuleGenerateHandler(workspaceManager, database)({
      sample_id: `sha256:${'a'.repeat(64)}`,
    })

    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toContain('Sample not found')
  })

  test('should expose Sigma generation handoff recipe metadata', () => {
    expect(sigmaRuleGenerateToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'threat-intel.sigma-rule-generation-handoff',
        startsWith: expect.arrayContaining(['sigma.rule.generate', 'strings.extract']),
        nextTools: expect.arrayContaining([
          'analysis.evidence.graph',
          'attack.map',
          'ioc.export',
          'yara.generate',
          'report.generate',
        ]),
        producesArtifacts: ['sigma_rules'],
        evidence: expect.arrayContaining(['behavior', 'network', 'workflow', 'provenance']),
        safety: expect.arrayContaining(['passive', 'no_live_sample_by_default']),
      })
    )
  })

  test('should return structured handoff, quality gates, and persisted Sigma artifact', async () => {
    const result = await createSigmaRuleGenerateHandler(workspaceManager, database)({
      sample_id: sampleId,
      level: 'high',
      deploy: true,
      rule_types: [
        'process_creation',
        'file_event',
        'registry_event',
        'network_connection',
        'dns_query',
        'image_load',
      ],
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.sigma_rule_generation.v1')
    expect(data.tool_version).toBe('0.1.0')
    expect(data.sample_id).toBe(sampleId)
    expect(data.level).toBe('high')
    expect(data.deploy_requested).toBe(true)
    expect(data.rules.map((rule: any) => rule.type)).toEqual(
      expect.arrayContaining([
        'process_creation',
        'file_event',
        'registry_event',
        'network_connection',
        'dns_query',
        'image_load',
      ])
    )
    expect(data.total_rules).toBe(6)
    expect(data.total_indicators).toBeGreaterThan(0)
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.sigma_rule_generation.evidence_summary.v1',
        artifact_type: 'sigma_rules',
        rules_generated: 6,
        evidence_counts: expect.objectContaining({
          strings: 6,
          imports: 2,
          registry_keys: 1,
        }),
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.sigma_rule_generation.workflow_handoff.v1',
        handoff_mode: 'sigma_rule_generation_to_validation_attack_mapping_and_reporting',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'evidence-graph-and-reporting',
            next_tools: expect.arrayContaining(['analysis.evidence.graph']),
          }),
          expect.objectContaining({
            goal: 'attack-and-ioc-feedback-loop',
            next_tools: expect.arrayContaining(['attack.map', 'ioc.export', 'yara.generate']),
          }),
        ]),
      })
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        backend_started: false,
        network_accessed_by_tool: false,
        siem_deployment_performed: false,
        deployment_mutation_requested: true,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.sigma_rule_generation.quality_gates.v1',
        passive_generation_only: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        deployment_mutation_requested: true,
        deployment_performed_by_tool: false,
        false_positive_review_required: true,
        siem_validation_required: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['analysis.evidence.graph', 'attack.map', 'report.generate'])
    )
    expect(data.next_actions.join('\n')).toContain('deployment request only')
    expect(result.artifacts?.[0]?.type).toBe('sigma_rules')

    const artifacts = database.findArtifactsByType(sampleId, 'sigma_rules')
    expect(artifacts).toHaveLength(1)
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persisted = JSON.parse(
      fs.readFileSync(path.join(workspace.root, artifacts[0].path), 'utf8')
    )
    expect(persisted.schema).toBe('rikune.sigma_rule_generation.v1')
    expect(persisted.workflow_handoff.schema).toBe(
      'rikune.sigma_rule_generation.workflow_handoff.v1'
    )
    expect(persisted.quality_gates.deployment_performed_by_tool).toBe(false)
  })
})
