/**
 * Unit tests for yara-rule-builder
 */

import fs from 'fs'
import os from 'os'
import path from 'path'
import {
  buildStringRule,
  buildImportRule,
  buildBytePatternRule,
  buildHybridRule,
  extractRuleEvidence,
  scoreRule,
  type RuleMeta,
  type RuleEvidence,
} from '../../src/plugins/yara/yara-rule-builder.js'
import {
  createYaraGenerateHandler,
  yaraGenerateToolDefinition,
} from '../../src/plugins/yara/tools/yara-generate.js'
import {
  createYaraGenerateBatchHandler,
  yaraGenerateBatchToolDefinition,
} from '../../src/plugins/yara/tools/yara-generate-batch.js'
import { DatabaseManager } from '../../src/database.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'

const baseMeta: RuleMeta = {
  sample_id: 'sha256:abcd1234',
  description: 'Test rule',
  author: 'test',
  date: '2025-01-01',
}

describe('yara-rule-builder', () => {
  describe('buildStringRule', () => {
    it('generates valid YARA rule with string conditions', () => {
      const rule = buildStringRule(
        ['malware_payload', 'cmd.exe /c', 'HKEY_LOCAL_MACHINE'],
        baseMeta
      )
      expect(rule).toContain('rule ')
      expect(rule).toContain('strings:')
      expect(rule).toContain('malware_payload')
      expect(rule).toContain('condition:')
    })

    it('returns empty string for empty strings array', () => {
      const rule = buildStringRule([], baseMeta)
      expect(rule).toBe('')
    })
  })

  describe('buildImportRule', () => {
    it('generates rule with PE import conditions', () => {
      const rule = buildImportRule(
        ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
        baseMeta
      )
      expect(rule).toContain('rule ')
      expect(rule).toContain('VirtualAllocEx')
      expect(rule).toContain('condition:')
    })
  })

  describe('buildBytePatternRule', () => {
    it('generates rule with hex byte patterns', () => {
      const rule = buildBytePatternRule(
        [
          { offset: 0, hex: '4D5A', description: 'MZ header' },
          { offset: 0x80, hex: 'FF15', description: 'indirect call' },
        ],
        baseMeta
      )
      expect(rule).toContain('4D5A')
      expect(rule).toContain('FF15')
      expect(rule).toContain('condition:')
    })
  })

  describe('buildHybridRule', () => {
    const evidence: RuleEvidence = {
      unique_strings: ['malware_c2', 'beacon_config'],
      suspicious_imports: ['VirtualAllocEx', 'WriteProcessMemory'],
      all_imports: ['VirtualAllocEx', 'WriteProcessMemory', 'GetProcAddress', 'LoadLibraryA'],
      byte_patterns: [],
      pe_imphash: 'aabbccdd',
      file_size: 102400,
    }

    it('generates hybrid rule with tight strictness', () => {
      const rule = buildHybridRule(evidence, 'tight', baseMeta)
      expect(rule).toContain('rule ')
      expect(rule).toContain('condition:')
    })

    it('generates hybrid rule with balanced strictness', () => {
      const rule = buildHybridRule(evidence, 'balanced', baseMeta)
      expect(rule).toContain('rule ')
    })

    it('generates hybrid rule with loose strictness', () => {
      const rule = buildHybridRule(evidence, 'loose', baseMeta)
      expect(rule).toContain('rule ')
    })
  })

  describe('extractRuleEvidence', () => {
    it('extracts evidence from artifact data', () => {
      const data = {
        strings: ['Hello', 'cmd.exe', 'calc.exe'],
        imports: ['CreateFileA', 'VirtualAlloc'],
        imphash: 'deadbeef',
        file_size: 50000,
      }
      const evidence = extractRuleEvidence(data)
      expect(evidence.all_imports.length).toBeGreaterThan(0)
      expect(evidence).toHaveProperty('unique_strings')
      expect(evidence).toHaveProperty('suspicious_imports')
    })

    it('handles empty artifact data', () => {
      const evidence = extractRuleEvidence({})
      expect(evidence.unique_strings).toEqual([])
      expect(evidence.all_imports).toEqual([])
    })
  })

  describe('scoreRule', () => {
    it('scores a rule with good evidence higher', () => {
      const evidence: RuleEvidence = {
        unique_strings: ['custom_mutex_name', 'rare_encryption_key'],
        suspicious_imports: ['VirtualAllocEx', 'NtCreateThread'],
        all_imports: ['VirtualAllocEx', 'NtCreateThread', 'GetProcAddress'],
        byte_patterns: [{ offset: 0, hex: 'DEADBEEF' }],
        pe_imphash: 'aabb',
        file_size: 100000,
      }
      const rule = buildHybridRule(evidence, 'balanced', baseMeta)
      const { score } = scoreRule(rule, evidence)
      expect(score).toBeGreaterThan(0)
      expect(score).toBeLessThanOrEqual(100)
    })

    it('scores a rule with minimal evidence lower', () => {
      const evidence: RuleEvidence = {
        unique_strings: [],
        suspicious_imports: [],
        all_imports: [],
        byte_patterns: [],
      }
      const rule = buildStringRule(['kernel32.dll'], baseMeta)
      const { score } = scoreRule(rule, evidence)
      expect(score).toBeLessThan(50)
    })
  })
})

describe('yara.generate tool', () => {
  let tempRoot: string
  let database: DatabaseManager
  let workspaceManager: WorkspaceManager
  const sampleHash = '5'.repeat(64)
  const sampleId = `sha256:${sampleHash}`

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-yara-generate-'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: '5'.repeat(32),
      size: 8192,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const now = new Date().toISOString()
    database.insertAnalysisEvidence({
      id: 'analysis-evidence-yara-source',
      sample_id: sampleId,
      sample_sha256: sampleHash,
      evidence_family: 'strings_imports',
      backend: 'unit-test',
      mode: 'static',
      compatibility_marker: 'unit-test-yara-source',
      freshness_marker: null,
      provenance_json: JSON.stringify({ tool: 'unit-test' }),
      metadata_json: null,
      result_json: JSON.stringify({
        strings: ['custom_mutex_name_12345', 'rare_campaign_token_alpha', 'kernel32.dll'],
        imports: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'GetProcAddress'],
        pe_imphash: 'aabbccdd',
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

  it('declares workflow recipe metadata for validation and reporting handoff', () => {
    expect(yaraGenerateToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'yara.rule-generation-handoff',
        startsWith: expect.arrayContaining(['yara.generate', 'strings.extract']),
        nextTools: expect.arrayContaining(['yara.scan', 'analysis.evidence.graph']),
        producesArtifacts: ['yara_rule_generation'],
        evidence: expect.arrayContaining(['signatures', 'workflow', 'provenance']),
        safety: expect.arrayContaining(['passive', 'no_live_sample_by_default']),
      })
    )
  })

  it('returns structured handoff, quality gates, and persisted rule artifact', async () => {
    const result = await createYaraGenerateHandler(workspaceManager, database)({
      sample_id: sampleId,
      strictness: 'balanced',
      deploy: false,
      rule_types: ['hybrid', 'import'],
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.yara_rule_generation.v1')
    expect(data.rules).toHaveLength(2)
    expect(data.best_rule).toEqual(expect.objectContaining({ rule_text: expect.any(String) }))
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_rule_generation.evidence_summary.v1',
        rules_generated: 2,
        evidence_counts: expect.objectContaining({
          unique_strings: expect.any(Number),
          suspicious_imports: 3,
        }),
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_generate.workflow_handoff.v1',
        handoff_mode: 'yara_rule_generation_to_validation_and_reporting',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'rule-validation-and-false-positive-review',
            next_tools: expect.arrayContaining(['yara.scan']),
          }),
          expect.objectContaining({
            goal: 'evidence-graph-and-reporting',
            next_tools: expect.arrayContaining(['analysis.evidence.graph']),
          }),
        ]),
      })
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        backend_started: false,
        network_accessed_by_tool: false,
        live_scan_started: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_generate.quality_gates.v1',
        passive_generation_only: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        corpus_validation_required: true,
        false_positive_review_required: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['yara.scan', 'analysis.evidence.graph', 'report.generate'])
    )
    expect(data.next_actions.join('\n')).toContain('benign corpus')
    expect(result.artifacts?.[0]?.type).toBe('yara_rule_generation')

    const artifacts = database.findArtifactsByType(sampleId, 'yara_rule_generation')
    expect(artifacts).toHaveLength(1)
    const workspace = await workspaceManager.getWorkspace(sampleId)
    const persisted = JSON.parse(
      fs.readFileSync(path.join(workspace.root, artifacts[0].path), 'utf8')
    )
    expect(persisted.workflow_handoff.schema).toBe('rikune.yara_generate.workflow_handoff.v1')
    expect(persisted.quality_gates.passive_generation_only).toBe(true)
  })
})

describe('yara.generate.batch tool', () => {
  let tempRoot: string
  let database: DatabaseManager
  let workspaceManager: WorkspaceManager
  const sampleHashes = ['6'.repeat(64), '7'.repeat(64), '8'.repeat(64)]
  const sampleIds = sampleHashes.map((hash) => `sha256:${hash}`)

  function insertSampleWithEvidence(sampleId: string, sampleHash: string, index: number) {
    database.insertSample({
      id: sampleId,
      sha256: sampleHash,
      md5: String(index).repeat(32).slice(0, 32),
      size: 8192 + index,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const now = new Date().toISOString()
    database.insertAnalysisEvidence({
      id: `analysis-evidence-yara-family-${index}`,
      sample_id: sampleId,
      sample_sha256: sampleHash,
      evidence_family: 'strings_imports',
      backend: 'unit-test',
      mode: 'static',
      compatibility_marker: `unit-test-yara-family-${index}`,
      freshness_marker: null,
      provenance_json: JSON.stringify({ tool: 'unit-test' }),
      metadata_json: null,
      result_json: JSON.stringify({
        strings: [
          'shared_family_mutex_alpha',
          'shared_campaign_token_beta',
          `unique_sample_${index}_marker`,
        ],
        imports: [
          'VirtualAllocEx',
          'WriteProcessMemory',
          'CreateRemoteThread',
          `UniqueImport${index}`,
        ],
      }),
      artifact_refs_json: null,
      created_at: now,
      updated_at: now,
      last_accessed_at: null,
    })
  }

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-yara-generate-batch-'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    sampleIds.forEach((sampleId, index) => {
      insertSampleWithEvidence(sampleId, sampleHashes[index], index + 1)
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

  it('declares workflow recipe metadata for family validation and reporting handoff', () => {
    expect(yaraGenerateBatchToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'yara.family-rule-generation-handoff',
        startsWith: expect.arrayContaining(['yara.generate.batch', 'sample.family.cluster']),
        nextTools: expect.arrayContaining([
          'yara.scan',
          'sample.family.cluster',
          'analysis.evidence.graph',
        ]),
        producesArtifacts: ['yara_family_rule'],
        evidence: expect.arrayContaining(['signatures', 'workflow', 'provenance']),
        safety: expect.arrayContaining(['passive', 'no_live_sample_by_default']),
      })
    )
  })

  it('returns structured family handoff, quality gates, and persisted artifact', async () => {
    const result = await createYaraGenerateBatchHandler(workspaceManager, database)({
      sample_ids: sampleIds,
      strictness: 'balanced',
      family_name: 'unit_family',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.yara_family_rule.v1')
    expect(data.family_rule).toEqual(
      expect.objectContaining({
        type: 'family_hybrid',
        rule_text: expect.stringContaining('rule '),
        score: expect.any(Number),
      })
    )
    expect(data.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_family_rule.evidence_summary.v1',
        sample_count: 3,
        family_name: 'unit_family',
        common_feature_counts: expect.objectContaining({
          strings: expect.any(Number),
          imports: 3,
          min_occurrence: 2,
        }),
      })
    )
    expect(data.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_generate_batch.workflow_handoff.v1',
        handoff_mode: 'yara_family_rule_to_cluster_validation_and_reporting',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'family-rule-validation-and-false-positive-review',
            next_tools: expect.arrayContaining(['yara.scan']),
          }),
          expect.objectContaining({
            goal: 'family-cluster-corroboration',
            next_tools: expect.arrayContaining(['sample.family.cluster']),
          }),
        ]),
      })
    )
    expect(data.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        backend_started: false,
        network_accessed_by_tool: false,
        live_scan_started: false,
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.yara_generate_batch.quality_gates.v1',
        passive_generation_only: true,
        family_sample_count: 3,
        minimum_family_size_met: true,
        corpus_validation_required: true,
        family_cluster_review_required: true,
      })
    )
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['yara.scan', 'sample.family.cluster', 'analysis.evidence.graph'])
    )
    expect(data.next_actions.join('\n')).toContain('family rule')
    expect(result.artifacts?.[0]?.type).toBe('yara_family_rule')

    const artifacts = database.findArtifactsByType(sampleIds[0], 'yara_family_rule')
    expect(artifacts).toHaveLength(1)
    const workspace = await workspaceManager.getWorkspace(sampleIds[0])
    const persisted = JSON.parse(
      fs.readFileSync(path.join(workspace.root, artifacts[0].path), 'utf8')
    )
    expect(persisted.workflow_handoff.schema).toBe(
      'rikune.yara_generate_batch.workflow_handoff.v1'
    )
    expect(persisted.quality_gates.passive_generation_only).toBe(true)
  })
})
